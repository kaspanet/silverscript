use kaspa_txscript::opcodes::codes::{OpAuthOutputCount, OpCovInputCount, OpCovInputIdx, OpCovOutputCount, OpInputCovenantId};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract, generated_covenant_auth_entrypoint_name};

#[test]
fn lowers_auth_covenant_declaration_to_hidden_entrypoint_name() {
    let source = r#"
        contract Decls(int max_outs) {
            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification)]
            function spend(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(compiled.abi.len(), 1);
    assert_eq!(compiled.abi[0].name, generated_covenant_auth_entrypoint_name("spend"));
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_spend" && !f.entrypoint));
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("spend") && f.entrypoint));
    assert!(compiled.bytecode.contains(&OpAuthOutputCount));
}

#[test]
fn infers_auth_binding_from_from_equal_one_when_binding_omitted() {
    let source = r#"
        contract Decls(int max_outs) {
            #[covenant(from = 1, to = max_outs)]
            function spend(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(compiled.abi.len(), 1);
    assert_eq!(compiled.abi[0].name, generated_covenant_auth_entrypoint_name("spend"));
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_spend" && !f.entrypoint));
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("spend") && f.entrypoint));
    assert!(compiled.bytecode.contains(&OpAuthOutputCount));
}

#[test]
fn lowers_cov_covenant_to_leader_and_delegate_entrypoints() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function transition_ok(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default()).expect("compile succeeds");
    let abi_names: Vec<&str> = compiled.abi.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(abi_names, vec!["__leader_transition_ok", "__delegate"]);
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_transition_ok" && !f.entrypoint));
    assert!(compiled.bytecode.contains(&OpCovInputCount));
    assert!(compiled.bytecode.contains(&OpCovOutputCount));
    assert!(compiled.bytecode.contains(&OpCovInputIdx));
}

#[test]
fn infers_cov_binding_from_from_greater_than_one_when_binding_omitted() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(from = max_ins, to = max_outs)]
            function transition_ok(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default()).expect("compile succeeds");
    let abi_names: Vec<&str> = compiled.abi.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(abi_names, vec!["__leader_transition_ok", "__delegate"]);
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_transition_ok" && !f.entrypoint));
    assert!(compiled.bytecode.contains(&OpCovInputCount));
    assert!(compiled.bytecode.contains(&OpCovOutputCount));
    assert!(compiled.bytecode.contains(&OpCovInputIdx));
}

#[test]
fn rejects_cov_verification_without_prev_new_field_arrays() {
    let source = r#"
        contract Decls() {
            int value = 0;

            #[covenant(from = 2, to = 2, mode = verification)]
            function transition_ok(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("cov verification with state fields should require prev/new field arrays");
    assert!(err.to_string().contains("expects parameters '(State[] prev_states, State[] new_states, ...)'"));
}

#[test]
fn rejects_cov_transition_without_prev_field_arrays() {
    let source = r#"
        contract Decls() {
            int value = 0;

            #[covenant(from = 2, to = 2, mode = transition)]
            function transition_ok(int nonce) : (int) {
                return(value + nonce);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("cov transition with state fields should require prev-state field arrays");
    assert!(err.to_string().contains("expects parameters '(State[] prev_states, ...)'"));
}

#[test]
fn rejects_auth_verification_without_prev_new_state_shape() {
    let source = r#"
        contract Decls() {
            int value = 0;

            #[covenant(binding = auth, from = 1, to = 2, mode = verification)]
            function split(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("auth verification with state fields should require prev/new state params");
    assert!(err.to_string().contains("mode=verification with binding=auth"));
}

#[test]
fn rejects_auth_transition_without_prev_state_shape() {
    let source = r#"
        contract Decls() {
            int value = 0;

            #[covenant(binding = auth, from = 1, to = 2, mode = transition)]
            function split(int[] nonce) : (int[]) {
                return(nonce);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("auth transition with state fields should require prev-state params");
    assert!(err.to_string().contains("mode=transition with binding=auth"));
}

#[test]
fn rejects_auth_transition_when_contract_state_is_empty() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = auth, from = 1, to = 1, mode = transition)]
            function roll(int nonce) : (int) {
                return(nonce);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("auth transition should be unsupported when contract state is empty");
    assert!(err.to_string().contains("mode=tranisition is not supported when contract state is empty"));
}

#[test]
fn rejects_cov_transition_when_contract_state_is_empty() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = cov, from = 2, to = 2, mode = transition)]
            function roll(int nonce) : (int) {
                return(nonce);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("cov transition should be unsupported when contract state is empty");
    assert!(err.to_string().contains("mode=tranisition is not supported when contract state is empty"));
}

#[test]
fn rejects_old_per_field_covenant_state_syntax() {
    let source = r#"
        contract Decls() {
            int value = 0;

            #[covenant(binding = auth, from = 1, to = 2, mode = verification)]
            function split(int prev_value, int[] new_values) {
                require(prev_value >= 0);
                require(new_values.length >= 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("old per-field covenant syntax should be rejected for stateful contracts");
    assert!(err.to_string().contains("expects parameters '(State prev_state, State[] new_states, ...)'"));
}

#[test]
fn rejects_canonical_one_to_one_auth_verification_with_scalar_new_state() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant(binding = auth, from = 1, to = 1, groups = single)]
            function step(State prev_state, State new_state) {
                require(new_state.value >= prev_state.value);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(7)], CompileOptions::default())
        .expect_err("canonical one-to-one auth verification should require State[] new_states");
    assert!(err.to_string().contains(
        "mode=verification with binding=auth on function 'step' expects parameters '(State prev_state, State[] new_states, ...)'"
    ));
}

#[test]
fn lowers_singleton_sugar_to_auth_one_to_one_defaults() {
    let source = r#"
        contract Decls() {
            #[covenant.singleton]
            function spend(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(compiled.abi[0].name, generated_covenant_auth_entrypoint_name("spend"));
    assert!(compiled.bytecode.contains(&OpAuthOutputCount));
}

#[test]
fn lowers_fanout_sugar_to_auth_with_to_bound() {
    let source = r#"
        contract Decls(int max_outs) {
            #[covenant.fanout(to = max_outs)]
            function split(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(compiled.abi[0].name, generated_covenant_auth_entrypoint_name("split"));
    assert!(compiled.bytecode.contains(&OpAuthOutputCount));
}

#[test]
fn rejects_fanout_sugar_without_to_argument() {
    let source = r#"
        contract Decls() {
            #[covenant.fanout]
            function split() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("fanout sugar requires to");
    assert!(err.to_string().contains("missing covenant attribute argument 'to'"));
}

#[test]
fn rejects_singleton_sugar_with_from_or_to_arguments() {
    let source = r#"
        contract Decls() {
            #[covenant.singleton(to = 2)]
            function split() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("singleton sugar should reject from/to");
    assert!(err.to_string().contains("covenant.singleton is sugar and does not accept 'from' or 'to' arguments"));
}

#[test]
fn rejects_auth_covenant_with_from_not_equal_one() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = auth, from = 2, to = 4, mode = verification)]
            function split() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("auth binding must require from=1");
    assert!(err.to_string().contains("binding=auth requires from = 1"));
}

#[test]
fn rejects_cov_covenant_groups_multiple_for_now() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = cov, from = 2, to = 4, mode = verification, groups = multiple)]
            function step() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("cov groups=multiple should be rejected");
    assert!(err.to_string().contains("binding=cov with groups=multiple is not supported yet"));
}

#[test]
fn infers_verification_mode_when_mode_omitted_and_no_returns() {
    let source = r#"
        contract Decls() {
            #[covenant(from = 1, to = 2)]
            function check(int x) {
                require(x >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("check") && f.entrypoint));
}

#[test]
fn infers_transition_mode_when_mode_omitted_and_has_returns() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant(from = 1, to = 1)]
            function roll(State prev_state, int x) : (State) {
                return(State { value: prev_state.value + x });
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("roll") && f.entrypoint));
}

#[test]
fn rejects_auth_transition_single_state_return_when_to_is_not_literal_one() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function step(State prev_state, int fee) : (State) {
                return(State {
                    amount: prev_state.amount - fee,
                    owner: prev_state.owner
                });
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])], CompileOptions::default())
        .expect_err("auth transition returning one State must not accept dynamic to bounds");
    assert!(err.to_string().contains("may return a single State only when 'to' is the literal 1 or omitted"));
}

#[test]
fn rejects_auth_transition_single_state_return_when_to_is_constant_one() {
    let source = r#"
        contract Decls(int init_value) {
            int constant ONE = 1;
            int value = init_value;

            #[covenant(binding = auth, from = 1, to = ONE, mode = transition)]
            function roll(State prev_state, int x) : (State) {
                return(State { value: prev_state.value + x });
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(3)], CompileOptions::default())
        .expect_err("auth transition returning one State should require literal to=1");
    assert!(err.to_string().contains("may return a single State only when 'to' is the literal 1 or omitted"));
}

#[test]
fn allows_auth_transition_single_state_return_when_to_is_literal_one() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant(binding = auth, from = 1, to = 1, mode = transition)]
            function roll(State prev_state, int x) : (State) {
                return(State { value: prev_state.value + x });
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("roll") && f.entrypoint));
}

#[test]
fn allows_auth_transition_single_state_return_when_to_is_omitted() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant(binding = auth, from = 1, mode = transition)]
            function roll(State prev_state, int x) : (State) {
                return(State { value: prev_state.value + x });
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("roll") && f.entrypoint));
}

#[test]
fn rejects_omitted_to_for_auth_transition_array_state_return() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant(binding = auth, from = 1, mode = transition)]
            function fanout(State prev_state, State[] next_states) : (State[]) {
                require(prev_state.value >= 0);
                return(next_states);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(3)], CompileOptions::default())
        .expect_err("omitted to should only infer literal 1 for single State returns");
    assert!(err.to_string().contains("missing covenant attribute argument 'to'"));
}

#[test]
fn rejects_singleton_transition_array_returns_without_termination_allowed() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = transition)]
            function roll(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(3)], CompileOptions::default())
        .expect_err("singleton transition arrays should require termination=allowed");
    assert!(err.to_string().contains("arrays are not allowed unless termination=allowed"));
}

#[test]
fn allows_singleton_transition_array_returns_with_termination_allowed() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = transition, termination = allowed)]
            function roll(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("roll") && f.entrypoint));
}

#[test]
fn rejects_termination_allowed_for_non_singleton() {
    let source = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            #[covenant(from = 1, to = max_outs, mode = transition, termination = allowed)]
            function roll(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(3), Expr::int(10)], CompileOptions::default())
        .expect_err("termination=allowed should be singleton-only");
    assert!(err.to_string().contains("termination is only supported for singleton covenants"));
}

#[test]
fn rejects_termination_disallowed_for_non_singleton() {
    let source = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            #[covenant(from = 1, to = max_outs, mode = transition, termination = disallowed)]
            function roll(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(3), Expr::int(10)], CompileOptions::default())
        .expect_err("termination arg should be singleton-only regardless of value");
    assert!(err.to_string().contains("termination is only supported for singleton covenants"));
}

#[test]
fn allows_termination_in_singleton_verification_mode() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = verification, termination = allowed)]
            function check(State prev_state, State[] new_states) {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == generated_covenant_auth_entrypoint_name("check") && f.entrypoint));
}

#[test]
fn rejects_transition_mode_without_return_values() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = auth, from = 1, to = 1, mode = transition)]
            function roll() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("transition policy must return values");
    assert!(err.to_string().contains("transition mode policy functions must declare return values"));
}

#[test]
fn rejects_verification_mode_with_return_values() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = auth, from = 1, to = 1, mode = verification)]
            function check() : (int) {
                return(1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("verification policy must not return values");
    assert!(err.to_string().contains("verification mode policy functions must not declare return values"));
}

#[test]
fn auth_covenant_groups_single_injects_shared_count_check() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = auth, from = 1, to = 4, mode = verification, groups = single)]
            function spend() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.bytecode.contains(&OpInputCovenantId));
    assert!(compiled.bytecode.contains(&OpCovOutputCount));
    assert!(compiled.bytecode.contains(&OpAuthOutputCount));
}

#[test]
fn rejects_mixed_auth_and_cov_covenant_declarations() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(binding = cov, from = max_ins, to = max_outs)]
            function merge(int nonce) {
                require(nonce >= 0);
            }

            #[covenant(binding = auth, from = 1, to = max_outs)]
            function split(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default())
        .expect_err("auth-bound declarations must not coexist with generated delegates");
    let message = err.to_string();
    assert!(message.contains("binding=cov"), "unexpected error: {message}");
    assert!(message.contains("merge"), "unexpected error: {message}");
    assert!(message.contains("split"), "unexpected error: {message}");
    assert!(message.contains("binding=auth"), "unexpected error: {message}");
}

#[test]
fn rejects_mixed_inferred_auth_and_cov_covenant_declarations() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(from = max_ins, to = max_outs)]
            function merge(int nonce) {
                require(nonce >= 0);
            }

            #[covenant(from = 1, to = max_outs)]
            function split(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default())
        .expect_err("inferred auth and cov declarations must not coexist");
    assert!(err.to_string().contains("cannot use binding=auth"), "unexpected error: {err}");
}

#[test]
fn leader_contract_rejects_unacknowledged_manual_entrypoint() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(binding = cov, from = max_ins, to = max_outs)]
            function merge(int nonce) {
                require(nonce >= 0);
            }

            entry recover() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default())
        .expect_err("manual entrypoints in leader contracts require acknowledgment");
    let message = err.to_string();
    assert!(message.contains("manual entrypoint 'recover'"), "unexpected error: {message}");
    assert!(message.contains("manual_entrypoint_in_leader_contract"), "unexpected error: {message}");
}

#[test]
fn leader_contract_allows_acknowledged_manual_entrypoint() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(binding = cov, from = max_ins, to = max_outs)]
            function merge(int nonce) {
                require(nonce >= 0);
            }

            #[covenant.allow(rule = manual_entrypoint_in_leader_contract)]
            entry recover() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                require(OpCovInputCount(cov_id) == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default())
        .expect("acknowledged manual entrypoint compiles");
    assert!(compiled.entry_by_name("recover").is_some());
    let recover = compiled.ast.functions.iter().find(|function| function.name == "recover").expect("recover remains an entrypoint");
    assert!(recover.attributes.is_empty(), "allow acknowledgment must not survive lowering");
}

#[test]
fn allows_multiple_cov_covenant_declarations() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(binding = cov, from = max_ins, to = max_outs)]
            function merge(int nonce) {
                require(nonce >= 0);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs)]
            function rebalance(int nonce) {
                require(nonce >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(2), Expr::int(4)], CompileOptions::default())
        .expect("multiple cov-bound declarations compile");
    let abi_names: Vec<&str> = compiled.abi.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(abi_names, vec!["__leader_merge", "__leader_rebalance", "__delegate"]);
    assert_eq!(compiled.cov_decl_to_abi.get("merge"), compiled.entry_by_name("__leader_merge"));
    assert_eq!(compiled.cov_decl_to_abi.get("rebalance"), compiled.entry_by_name("__leader_rebalance"));
    assert_eq!(compiled.delegate_entry_abi.as_ref(), compiled.entry_by_name("__delegate"));

    let merge_delegate =
        compiled.build_sig_script_for_covenant_decl("merge", vec![], Default::default()).expect("merge routes to the shared delegate");
    let rebalance_delegate = compiled
        .build_sig_script_for_covenant_decl("rebalance", vec![], Default::default())
        .expect("rebalance routes to the shared delegate");
    let shared_delegate = compiled.build_sig_script("__delegate", vec![]).expect("shared delegate sigscript builds");
    assert_eq!(merge_delegate, shared_delegate);
    assert_eq!(rebalance_delegate, shared_delegate);
}

#[test]
fn lowers_kcc20_shaped_public_names_and_shared_delegate_body() {
    let source = r#"
        contract Token(byte[1] initial_owner, int initial_amount) {
            byte[1] owner = initial_owner;
            int amount = initial_amount;

            function verifyOwner(byte[1] expected_owner, byte[] witness) {
                require(witness.length == 1);
                require(expected_owner == byte[1](witness));
            }

            #[covenant(
                binding = cov,
                from = 2,
                to = 2,
                mode = verification,
                name = transfer,
                delegate_name = transfer_delegator
            )]
            function transferPolicy(State[] prev_states, State[] next_states, byte[] witness) {
                require(prev_states.length == 2);
                require(next_states.length == 2);
                verifyOwner(owner, witness);
            }

            #[covenant.delegate]
            function authorizeDelegate(byte[] witness) {
                verifyOwner(owner, witness);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::bytes(vec![7]), Expr::int(10)], CompileOptions::default())
        .expect("KCC20-shaped declaration compiles");

    let abi = compiled
        .abi
        .iter()
        .map(|entry| (entry.name.as_str(), entry.inputs.iter().map(|input| input.type_name.as_str()).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    assert_eq!(abi, vec![("transfer", vec!["State[]", "byte[]"]), ("transfer_delegator", vec!["byte[]"]),]);

    let transfer = compiled.entry_by_name("transfer").expect("public transfer exists");
    let expected_hash = blake3::hash(b"transfer(State[],byte[])");
    assert_eq!(transfer.dispatch_tag(), expected_hash.as_bytes()[..4]);

    let delegate_args = vec![Expr::dynamic_bytes(vec![7])];
    let routed = compiled
        .build_sig_script_for_covenant_decl("transferPolicy", delegate_args.clone(), Default::default())
        .expect("declaration helper resolves the overridden delegate name");
    let direct = compiled.build_sig_script("transfer_delegator", delegate_args).expect("public delegate sigscript builds");
    assert_eq!(routed, direct);
    assert_eq!(compiled.cov_decl_to_abi.get("transferPolicy"), compiled.entry_by_name("transfer"));
    assert_eq!(compiled.delegate_entry_abi.as_ref(), compiled.entry_by_name("transfer_delegator"));
    assert_eq!(compiled.covenant_decl_entrypoint_name("transferPolicy", true), Some("transfer"));
    assert_eq!(compiled.covenant_decl_entrypoint_name("transferPolicy", false), Some("transfer_delegator"));
}

#[test]
fn supports_public_name_override_for_auth_bound_declaration() {
    let source = r#"
        contract Decls() {
            #[covenant.singleton(name = spend)]
            function spendPolicy(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(compiled.abi[0].name, "spend");
    assert_eq!(compiled.cov_decl_to_abi.get("spendPolicy"), compiled.entry_by_name("spend"));
    assert_eq!(compiled.delegate_entry_abi, None);
    assert_eq!(compiled.covenant_decl_entrypoint_name("spendPolicy", false), Some("spend"));
}

#[test]
fn rejects_duplicate_delegate_bodies() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = cov, from = 2, to = 2)]
            function merge(int nonce) { require(nonce >= 0); }

            #[covenant.delegate]
            function authorizeA(byte[] witness) { require(witness.length >= 0); }

            #[covenant.delegate]
            function authorizeB(byte[] witness) { require(witness.length >= 0); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("duplicate delegate bodies must fail");
    assert!(err.to_string().contains("more than one #[covenant.delegate] body"), "unexpected error: {err}");
}

#[test]
fn rejects_delegate_body_without_cov_bound_declaration() {
    let source = r#"
        contract Decls() {
            #[covenant.delegate]
            function authorize(byte[] witness) { require(witness.length >= 0); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("unused delegate body must fail");
    assert!(err.to_string().contains("requires at least one binding=cov"), "unexpected error: {err}");
}

#[test]
fn delegate_and_leader_internal_policy_names_use_disjoint_namespaces() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = cov, from = 2, to = 2)]
            function delegate_authorize(int nonce) { require(nonce >= 0); }

            #[covenant.delegate]
            function authorize(byte[] witness) { require(witness.length >= 0); }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("internal policy names do not collide");
    assert!(compiled.ast.functions.iter().any(|function| function.name == "__covenant_policy_delegate_authorize"));
    assert!(compiled.ast.functions.iter().any(|function| function.name == "__covenant_delegate_policy_authorize"));
}

#[test]
fn rejects_conflicting_shared_delegate_names() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = cov, from = 2, to = 2, delegate_name = merge_delegator)]
            function merge(int nonce) { require(nonce >= 0); }

            #[covenant(binding = cov, from = 2, to = 2, delegate_name = rebalance_delegator)]
            function rebalance(int nonce) { require(nonce >= 0); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("delegate names must agree");
    assert!(err.to_string().contains("conflicting shared delegate entrypoint names"), "unexpected error: {err}");
}

#[test]
fn rejects_invalid_delegate_body_signatures() {
    let cases = [
        r#"
            contract Decls() {
                #[covenant(binding = cov, from = 2, to = 2)]
                function merge(int nonce) { require(nonce >= 0); }
                #[covenant.delegate]
                entry authorize(byte[] witness) { require(witness.length >= 0); }
            }
        "#,
        r#"
            contract Decls() {
                #[covenant(binding = cov, from = 2, to = 2)]
                function merge(int nonce) { require(nonce >= 0); }
                #[covenant.delegate]
                function authorize(byte[] witness) : (int) { return(witness.length); }
            }
        "#,
        r#"
            contract Decls() {
                #[covenant(binding = cov, from = 2, to = 2)]
                function merge(int nonce) { require(nonce >= 0); }
                #[covenant.delegate(name = delegated)]
                function authorize(byte[] witness) { require(witness.length >= 0); }
            }
        "#,
    ];

    for source in cases {
        let err = compile_contract(source, &[], CompileOptions::default()).expect_err("invalid delegate signature must fail");
        assert!(err.to_string().contains("#[covenant.delegate]"), "unexpected error: {err}");
    }
}

#[test]
fn rejects_generated_public_name_collision() {
    let source = r#"
        contract Decls() {
            #[covenant(binding = cov, from = 2, to = 2, name = transfer)]
            function transferPolicy(int nonce) { require(nonce >= 0); }

            #[covenant.allow(rule = manual_entrypoint_in_leader_contract)]
            entry transfer() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                require(OpCovInputCount(cov_id) == 1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("generated public name collision must fail");
    assert!(err.to_string().contains("duplicate function name 'transfer'"), "unexpected error: {err}");
}

#[test]
fn rejects_generated_public_name_collisions_with_helpers() {
    let cases = [
        r#"
            contract Decls() {
                function spend() {}

                #[covenant.singleton(name = spend)]
                function transfer(int nonce) { require(nonce >= 0); }
            }
        "#,
        r#"
            contract Decls() {
                function spend() {}

                #[covenant(binding = cov, from = 2, to = 2, delegate_name = spend)]
                function transfer(int nonce) { require(nonce >= 0); }
            }
        "#,
    ];

    for source in cases {
        let err = compile_contract(source, &[], CompileOptions::default())
            .expect_err("generated public names must not collide with helper functions");
        assert!(err.to_string().contains("duplicate function name 'spend'"), "unexpected error: {err}");
    }
}

#[test]
fn rejects_per_leader_delegate_policy_selection() {
    let source = r#"
        contract Decls() {
            function weak(byte[] witness) { require(witness.length >= 0); }

            #[covenant(binding = cov, from = 2, to = 2, delegate_policy = weak)]
            function merge(int nonce) { require(nonce >= 0); }

            #[covenant.delegate]
            function strong(byte[] witness) { require(witness.length > 0); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("leaders cannot select delegate policies");
    assert!(err.to_string().contains("unknown covenant attribute argument 'delegate_policy'"), "unexpected error: {err}");
}
