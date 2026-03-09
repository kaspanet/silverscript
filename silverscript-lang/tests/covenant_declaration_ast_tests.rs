use silverscript_lang::ast::visit::{AstVisitorMut, NameKind, visit_contract_mut};
use silverscript_lang::ast::{ContractAst, Expr, FunctionAst};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::span::Span;
use std::collections::HashSet;

fn canonicalize_generated_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("__covenant_policy_") {
        return format!("covenant_policy_{rest}");
    }
    if let Some(rest) = name.strip_prefix("__cov_") {
        return format!("cov_{rest}");
    }
    if let Some(rest) = name.strip_prefix("__") {
        return rest.to_string();
    }
    name.to_string()
}

struct GeneratedNameCanonicalizer;

impl<'i> AstVisitorMut<'i> for GeneratedNameCanonicalizer {
    fn visit_name(&mut self, name: &mut String, _kind: NameKind) {
        *name = canonicalize_generated_name(name);
    }

    fn visit_span(&mut self, span: &mut Span<'i>) {
        *span = Span::default();
    }
}

fn normalize_contract(contract: &mut ContractAst<'_>) {
    visit_contract_mut(&mut GeneratedNameCanonicalizer, contract);
}

fn compile_and_normalize_contract<'i>(source: &'i str, constructor_args: &[Expr<'i>]) -> ContractAst<'i> {
    let compiled = compile_contract(source, constructor_args, CompileOptions::default()).expect("compile succeeds");
    let mut contract = compiled.ast;
    normalize_contract(&mut contract);
    contract
}

fn assert_lowers_to_expected_ast<'i>(source: &'i str, expected_lowered_source: &'i str, constructor_args: &[Expr<'i>]) {
    let actual = compile_and_normalize_contract(source, constructor_args);
    let expected = compile_and_normalize_contract(expected_lowered_source, constructor_args);
    assert_eq!(actual, expected);
}

fn function_by_name<'a, 'i>(functions: &'a [FunctionAst<'i>], name: &str) -> &'a FunctionAst<'i> {
    functions.iter().find(|function| function.name == name).unwrap_or_else(|| panic!("missing function '{}'", name))
}

fn assert_param_names(function: &FunctionAst<'_>, expected: &[&str]) {
    let actual: Vec<&str> = function.params.iter().map(|param| param.name.as_str()).collect();
    assert_eq!(actual, expected, "unexpected params for '{}'", function.name);
}

#[test]
fn lowers_auth_groups_single_to_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_outs) {
            int value = 0;

            #[covenant(binding = auth, from = 1, to = max_outs, groups = single)]
            function split(State prev_state, State[] new_states, int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_outs) {
            int value = 0;

            function covenant_policy_split(int prev_value, int[] new_value, int amount) {
                require(amount >= 0);
            }

            entrypoint function split(int[] new_value, int amount) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                int cov_shared_out_count = OpCovOutCount(cov_id);
                require(cov_shared_out_count == cov_out_count);
                require(cov_out_count == new_value.length);

                covenant_policy_split(value, new_value, amount);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: new_value[cov_k] });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4)]);
}

#[test]
fn lowers_cov_to_leader_and_delegate_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            int value = 0;

            #[covenant(from = max_ins, to = max_outs, mode = verification)]
            function transition_ok(State[] prev_states, State[] new_states, int delta) {
                require(delta >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_ins, int max_outs) {
            int value = 0;

            function covenant_policy_transition_ok(int[] prev_value, int[] new_value, int delta) {
                require(delta >= 0);
            }

            entrypoint function leader_transition_ok(int[] new_value, int delta) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_value;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        { value: int cov_prev_value } = readInputState(cov_in_idx);
                        prev_value.push(cov_prev_value);
                    }
                }

                require(cov_out_count == new_value.length);
                covenant_policy_transition_ok(prev_value, new_value, delta);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, { value: new_value[cov_k] });
                    }
                }
            }

            entrypoint function delegate_transition_ok() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(3)]);
}

#[test]
fn lowers_singleton_transition_uses_returned_state_in_validation() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = transition)]
            function bump(State prev_state, int delta) : (State) {
                return({ value: prev_state.value + delta });
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int init_value) {
            int value = init_value;

            function covenant_policy_bump(int prev_value, int delta) : (int) {
                return(prev_value + delta);
            }

            entrypoint function bump(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_value) = covenant_policy_bump(value, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, { value: cov_new_value });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(7)]);
}

#[test]
fn lowers_transition_array_return_to_exact_output_count_match() {
    let source = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            #[covenant(from = 1, to = max_outs, mode = transition)]
            function fanout(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            function covenant_policy_fanout(int prev_value, int[] next_value) : (int[]) {
                return(next_value);
            }

            entrypoint function fanout(int[] next_value) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_value) = covenant_policy_fanout(value, next_value);
                require(cov_out_count <= max_outs);
                require(cov_out_count == cov_new_value.length);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: cov_new_value[cov_k] });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10)]);
}

#[test]
fn lowers_singleton_transition_with_termination_allowed_to_array_cardinality_checks() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = transition, termination = allowed)]
            function bump_or_terminate(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int init_value) {
            int value = init_value;

            function covenant_policy_bump_or_terminate(int prev_value, int[] next_value) : (int[]) {
                return(next_value);
            }

            entrypoint function bump_or_terminate(int[] next_value) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_value) = covenant_policy_bump_or_terminate(value, next_value);
                require(cov_out_count <= 1);
                require(cov_out_count == cov_new_value.length);

                for(cov_k, 0, 1) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: cov_new_value[cov_k] });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10)]);
}

#[test]
fn lowers_auth_verification_groups_multiple_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function step(State prev_state, State[] new_states, int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner, int nonce) {
                require(nonce >= 0);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner, int nonce) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_step(amount, owner, new_amount, new_owner, nonce);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_auth_verification_groups_single_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function step(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                int cov_shared_out_count = OpCovOutCount(cov_id);
                require(cov_shared_out_count == cov_out_count);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_step(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_auth_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function step(State prev_state, int fee) : (State) {
                return({
                    amount: prev_state.amount - fee,
                    owner: prev_state.owner
                });
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int fee) : (int, byte[32]) {
                return(prev_amount - fee, prev_owner);
            }

            entrypoint function step(int fee) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_step(amount, owner, fee);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_cov_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function step(State[] prev_states, State[] new_states, int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int[] prev_amount, byte[32][] prev_owner, int[] new_amount, byte[32][] new_owner, int nonce) {
                require(nonce >= 0);
            }

            entrypoint function leader_step(int[] new_amount, byte[32][] new_owner, int nonce) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_amount;
                byte[32][] prev_owner;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                        prev_amount.push(cov_prev_amount);
                        prev_owner.push(cov_prev_owner);
                    }
                }

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_step(prev_amount, prev_owner, new_amount, new_owner, nonce);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function delegate_step() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_cov_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function step(State[] prev_states, int fee) : (State[]) {
                require(fee >= 0);
                return(prev_states);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int[] prev_amount, byte[32][] prev_owner, int fee) : (int[], byte[32][]) {
                require(fee >= 0);
                return(prev_amount, prev_owner);
            }

            entrypoint function leader_step(int[] prev_amount, byte[32][] prev_owner, int fee) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                    }
                }

                (int[] cov_new_amount, byte[32][] cov_new_owner) = covenant_policy_step(prev_amount, prev_owner, fee);
                require(cov_new_owner.length == cov_new_amount.length);
                require(cov_out_count <= max_outs);
                require(cov_out_count == cov_new_amount.length);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: cov_new_amount[cov_k],
                            owner: cov_new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function delegate_step() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_inferred_auth_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(from = 1, to = max_outs)]
            function step(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_step(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_inferred_cov_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(from = max_ins, to = max_outs)]
            function step(State[] prev_states, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int[] prev_amount, byte[32][] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function leader_step(int[] new_amount, byte[32][] new_owner) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_amount;
                byte[32][] prev_owner;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                        prev_amount.push(cov_prev_amount);
                        prev_owner.push(cov_prev_owner);
                    }
                }

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_step(prev_amount, prev_owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function delegate_step() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_inferred_singleton_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(from = 1, to = 1)]
            function step(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            entrypoint function step(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_step(amount, owner, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_singleton_sugar_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.singleton(mode = transition)]
            function step(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            entrypoint function step(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_step(amount, owner, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_singleton_sugar_transition_termination_allowed_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.singleton(mode = transition, termination = allowed)]
            function step(
                State prev_state,
                State[] next_states
            ) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(
                int prev_amount,
                byte[32] prev_owner,
                int[] next_amount,
                byte[32][] next_owner
            ) : (int[], byte[32][]) {
                return(next_amount, next_owner);
            }

            entrypoint function step(int[] next_amount, byte[32][] next_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_amount, byte[32][] cov_new_owner) = covenant_policy_step(amount, owner, next_amount, next_owner);
                require(cov_new_owner.length == cov_new_amount.length);
                require(cov_out_count <= 1);
                require(cov_out_count == cov_new_amount.length);

                for(cov_k, 0, 1) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: cov_new_amount[cov_k],
                            owner: cov_new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_fanout_sugar_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.fanout(to = max_outs, mode = verification)]
            function step(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_step(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_many_covenant_declarations_in_one_contract_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function auth_verification_multi(
                State prev_state,
                State[] new_states,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function auth_verification_single(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function auth_transition(State prev_state, int fee) : (State) {
                return({ amount: prev_state.amount - fee, owner: prev_state.owner });
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function cov_verification(
                State[] prev_states,
                State[] new_states,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function cov_transition(State[] prev_states, int fee) : (State[]) {
                require(fee >= 0);
                return(prev_states);
            }

            #[covenant(from = 1, to = max_outs)]
            function inferred_auth(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = max_ins, to = max_outs)]
            function inferred_cov(State[] prev_states, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = 1, to = 1)]
            function inferred_transition(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition)]
            function singleton_transition(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition, termination = allowed)]
            function singleton_terminate(State prev_state, State[] next_states) : (State[]) {
                require(prev_state.amount >= 0);
                return(next_states);
            }

            #[covenant.fanout(to = max_outs, mode = verification)]
            function fanout_verification(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_auth_verification_multi(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }

            entrypoint function auth_verification_multi(int[] new_amount, byte[32][] new_owner, int nonce) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_auth_verification_multi(amount, owner, new_amount, new_owner, nonce);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            function covenant_policy_auth_verification_single(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function auth_verification_single(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                int cov_shared_out_count = OpCovOutCount(cov_id);
                require(cov_shared_out_count == cov_out_count);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_auth_verification_single(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            function covenant_policy_auth_transition(int prev_amount, byte[32] prev_owner, int fee) : (int, byte[32]) {
                return(prev_amount - fee, prev_owner);
            }

            entrypoint function auth_transition(int fee) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_auth_transition(amount, owner, fee);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }

            function covenant_policy_cov_verification(
                int[] prev_amount,
                byte[32][] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }

            entrypoint function leader_cov_verification(int[] new_amount, byte[32][] new_owner, int nonce) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_amount;
                byte[32][] prev_owner;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                        prev_amount.push(cov_prev_amount);
                        prev_owner.push(cov_prev_owner);
                    }
                }

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_cov_verification(prev_amount, prev_owner, new_amount, new_owner, nonce);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function delegate_cov_verification() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }

            function covenant_policy_cov_transition(int[] prev_amount, byte[32][] prev_owner, int fee) : (int[], byte[32][]) {
                require(fee >= 0);
                return(prev_amount, prev_owner);
            }

            entrypoint function leader_cov_transition(int[] prev_amount, byte[32][] prev_owner, int fee) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                    }
                }

                (int[] cov_new_amount, byte[32][] cov_new_owner) = covenant_policy_cov_transition(prev_amount, prev_owner, fee);
                require(cov_new_owner.length == cov_new_amount.length);
                require(cov_out_count <= max_outs);
                require(cov_out_count == cov_new_amount.length);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: cov_new_amount[cov_k],
                            owner: cov_new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function delegate_cov_transition() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }

            function covenant_policy_inferred_auth(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function inferred_auth(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_inferred_auth(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            function covenant_policy_inferred_cov(int[] prev_amount, byte[32][] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function leader_inferred_cov(int[] new_amount, byte[32][] new_owner) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_amount;
                byte[32][] prev_owner;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                        prev_amount.push(cov_prev_amount);
                        prev_owner.push(cov_prev_owner);
                    }
                }

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_inferred_cov(prev_amount, prev_owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function delegate_inferred_cov() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }

            function covenant_policy_inferred_transition(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            entrypoint function inferred_transition(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_inferred_transition(amount, owner, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }

            function covenant_policy_singleton_transition(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            entrypoint function singleton_transition(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_singleton_transition(amount, owner, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }

            function covenant_policy_singleton_terminate(int prev_amount, byte[32] prev_owner, int[] next_amount, byte[32][] next_owner) : (int[], byte[32][]) {
                require(prev_amount >= 0);
                return(next_amount, next_owner);
            }

            entrypoint function singleton_terminate(int[] next_amount, byte[32][] next_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_amount, byte[32][] cov_new_owner) = covenant_policy_singleton_terminate(amount, owner, next_amount, next_owner);
                require(cov_new_owner.length == cov_new_amount.length);
                require(cov_out_count <= 1);
                require(cov_out_count == cov_new_amount.length);

                for(cov_k, 0, 1) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: cov_new_amount[cov_k],
                            owner: cov_new_owner[cov_k]
                        });
                    }
                }
            }

            function covenant_policy_fanout_verification(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_amount.length);
            }

            entrypoint function fanout_verification(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                require(new_owner.length == new_amount.length);
                require(cov_out_count == new_amount.length);
                covenant_policy_fanout_verification(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn covers_attribute_config_combinations_with_two_field_state() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function auth_verification_multi(
                State prev_state,
                State[] new_states,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function auth_verification_single(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function auth_transition(State prev_state, int fee) : (State) {
                return({ amount: prev_state.amount - fee, owner: prev_state.owner });
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function cov_verification(
                State[] prev_states,
                State[] new_states,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function cov_transition(State[] prev_states, int fee) : (State[]) {
                require(fee >= 0);
                return(prev_states);
            }

            #[covenant(from = 1, to = max_outs)]
            function inferred_auth(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = max_ins, to = max_outs)]
            function inferred_cov(State[] prev_states, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = 1, to = 1)]
            function inferred_transition(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition)]
            function singleton_transition(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition, termination = allowed)]
            function singleton_terminate(State prev_state, State[] next_states) : (State[]) {
                require(prev_state.amount >= 0);
                return(next_states);
            }

            #[covenant.fanout(to = max_outs, mode = verification)]
            function fanout_verification(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let contract = compile_and_normalize_contract(source, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
    let functions = &contract.functions;

    let expected_entrypoints: HashSet<&str> = vec![
        "auth_verification_multi",
        "auth_verification_single",
        "auth_transition",
        "leader_cov_verification",
        "delegate_cov_verification",
        "leader_cov_transition",
        "delegate_cov_transition",
        "inferred_auth",
        "leader_inferred_cov",
        "delegate_inferred_cov",
        "inferred_transition",
        "singleton_transition",
        "singleton_terminate",
        "fanout_verification",
    ]
    .into_iter()
    .collect();
    let actual_entrypoints: HashSet<&str> =
        functions.iter().filter(|function| function.entrypoint).map(|function| function.name.as_str()).collect();
    assert_eq!(actual_entrypoints, expected_entrypoints);

    for policy_name in [
        "covenant_policy_auth_verification_multi",
        "covenant_policy_auth_verification_single",
        "covenant_policy_auth_transition",
        "covenant_policy_cov_verification",
        "covenant_policy_cov_transition",
        "covenant_policy_inferred_auth",
        "covenant_policy_inferred_cov",
        "covenant_policy_inferred_transition",
        "covenant_policy_singleton_transition",
        "covenant_policy_singleton_terminate",
        "covenant_policy_fanout_verification",
    ] {
        let policy = function_by_name(functions, policy_name);
        assert!(!policy.entrypoint, "policy '{}' must not be an entrypoint", policy_name);
    }

    assert_param_names(function_by_name(functions, "auth_verification_multi"), &["new_amount", "new_owner", "nonce"]);
    assert_param_names(function_by_name(functions, "auth_verification_single"), &["new_amount", "new_owner"]);
    assert_param_names(function_by_name(functions, "auth_transition"), &["fee"]);
    assert_param_names(function_by_name(functions, "leader_cov_verification"), &["new_amount", "new_owner", "nonce"]);
    assert_param_names(function_by_name(functions, "delegate_cov_verification"), &[]);
    assert_param_names(function_by_name(functions, "leader_cov_transition"), &["prev_amount", "prev_owner", "fee"]);
    assert_param_names(function_by_name(functions, "delegate_cov_transition"), &[]);
    assert_param_names(function_by_name(functions, "inferred_auth"), &["new_amount", "new_owner"]);
    assert_param_names(function_by_name(functions, "leader_inferred_cov"), &["new_amount", "new_owner"]);
    assert_param_names(function_by_name(functions, "delegate_inferred_cov"), &[]);
    assert_param_names(function_by_name(functions, "inferred_transition"), &["delta"]);
    assert_param_names(function_by_name(functions, "singleton_transition"), &["delta"]);
    assert_param_names(function_by_name(functions, "singleton_terminate"), &["next_amount", "next_owner"]);
    assert_param_names(function_by_name(functions, "fanout_verification"), &["new_amount", "new_owner"]);
}
