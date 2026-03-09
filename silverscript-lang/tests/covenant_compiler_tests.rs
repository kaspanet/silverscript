use kaspa_txscript::opcodes::codes::{OpAuthOutputCount, OpCovInputCount, OpCovInputIdx, OpCovOutCount, OpInputCovenantId};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};

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
    assert!(compiled.without_selector);
    assert_eq!(compiled.abi.len(), 1);
    assert_eq!(compiled.abi[0].name, "__spend");
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_spend" && !f.entrypoint));
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__spend" && f.entrypoint));
    assert!(compiled.script.contains(&OpAuthOutputCount));
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
    assert!(compiled.without_selector);
    assert_eq!(compiled.abi.len(), 1);
    assert_eq!(compiled.abi[0].name, "__spend");
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_spend" && !f.entrypoint));
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__spend" && f.entrypoint));
    assert!(compiled.script.contains(&OpAuthOutputCount));
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
    assert_eq!(abi_names, vec!["__leader_transition_ok", "__delegate_transition_ok"]);
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_transition_ok" && !f.entrypoint));
    assert!(compiled.script.contains(&OpCovInputCount));
    assert!(compiled.script.contains(&OpCovOutCount));
    assert!(compiled.script.contains(&OpCovInputIdx));
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
    assert_eq!(abi_names, vec!["__leader_transition_ok", "__delegate_transition_ok"]);
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_transition_ok" && !f.entrypoint));
    assert!(compiled.script.contains(&OpCovInputCount));
    assert!(compiled.script.contains(&OpCovOutCount));
    assert!(compiled.script.contains(&OpCovInputIdx));
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
    assert!(compiled.without_selector);
    assert_eq!(compiled.abi[0].name, "__spend");
    assert!(compiled.script.contains(&OpAuthOutputCount));
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
    assert!(compiled.without_selector);
    assert_eq!(compiled.abi[0].name, "__split");
    assert!(compiled.script.contains(&OpAuthOutputCount));
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
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__check" && f.entrypoint));
}

#[test]
fn infers_transition_mode_when_mode_omitted_and_has_returns() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant(from = 1, to = 1)]
            function roll(State prev_state, int x) : (State) {
                return({ value: prev_state.value + x });
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(3)], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__roll" && f.entrypoint));
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
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__roll" && f.entrypoint));
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
fn rejects_termination_in_verification_mode() {
    let source = r#"
        contract Decls() {
            #[covenant.singleton(mode = verification, termination = allowed)]
            function check() {
                require(true);
            }
        }
    "#;

    let err =
        compile_contract(source, &[], CompileOptions::default()).expect_err("termination should not be allowed in verification mode");
    assert!(err.to_string().contains("termination is only supported in mode=transition"));
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
    assert!(compiled.script.contains(&OpInputCovenantId));
    assert!(compiled.script.contains(&OpCovOutCount));
    assert!(compiled.script.contains(&OpAuthOutputCount));
}
