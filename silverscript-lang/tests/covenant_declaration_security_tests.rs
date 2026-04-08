use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{
    CovenantBinding, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript_errors::TxScriptError;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, CovenantDeclCallOptions, compile_contract, struct_object};

mod common;

use common::{
    COV_A, COV_B, assert_verify_like_error, covenant_decl_sigscript, covenant_utxo, execute_input_with_covenants,
    plain_covenant_output, plain_utxo, push_redeem_script,
};

const AUTH_SINGLETON_SOURCE: &str = r#"
    contract Counter(int init_value) {
        int value = init_value;

        #[covenant.singleton]
        function step(State prev_state, State[] new_states) {
            require(prev_state.value >= 0);
            require(new_states.length <= 1);
            require(OpAuthOutputIdx(this.activeInputIndex, 0) >= 0);
        }
    }
"#;

const AUTH_SINGLE_GROUP_SOURCE: &str = r#"
    contract Counter(int init_value) {
        int value = init_value;

        #[covenant(binding = auth, from = 1, to = 1, groups = single)]
        function step(State prev_state, State[] new_states) {
            require(prev_state.value >= 0);
            require(new_states.length <= 1);
            require(OpAuthOutputIdx(this.activeInputIndex, 0) >= 0);
        }
    }
"#;

const AUTH_SINGLETON_TRANSITION_SOURCE: &str = r#"
    contract Decls(int init_value) {
        int value = init_value;

        #[covenant.singleton(mode = transition)]
        function bump(State prev_state, int delta) : (State) {
            return({ value: prev_state.value + delta });
        }
    }
"#;

const AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE: &str = r#"
    contract Decls(int init_value) {
        int value = init_value;

        #[covenant.singleton(mode = transition, termination = allowed)]
        function bump_or_terminate(State prev_state, State[] next_states) : (State[]) {
            return(next_states);
        }
    }
"#;

const COV_N_TO_M_SOURCE: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        #[covenant(from = 2, to = 2)]
        function rebalance(State[] prev_states, State[] new_states) {
            require(true);
        }
    }
"#;

const COV_N_TO_M_TRANSITION_SOURCE: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        #[covenant(from = 2, to = 2, mode = transition)]
        function carry_forward(State[] prev_states) : (State[]) {
            return(prev_states);
        }
    }
"#;

const COV_N_TO_M_DIFFERENT_SCRIPT_SOURCE: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        #[covenant(from = 2, to = 2)]
        function rebalance(State[] prev_states, State[] new_states) {
            require(new_states.length == 2);
        }
    }
"#;

const AUTH_SINGLETON_ARRAY_RUNTIME_SOURCE: &str = r#"
    contract Counter(int init_value) {
        int value = init_value;

        #[covenant.singleton]
        function step(State prev_state, State[] new_states) {
            require(new_states.length == 1);
            require(new_states[0].value == prev_state.value + 1);
            require(OpAuthOutputIdx(this.activeInputIndex, 0) >= 0);
        }
    }
"#;

const AUTH_VERIFICATION_CARDINALITY_SOURCE: &str = r#"
    contract Counter(int init_value) {
        int value = init_value;

        #[covenant(binding = auth, from = 1, to = 2)]
        function step(State prev_state, State[] new_states) {
            require(prev_state.value >= 0);
        }
    }
"#;

fn compile_state(source: &'static str, value: i64) -> CompiledContract<'static> {
    compile_contract(source, &[Expr::int(value)], CompileOptions::default()).expect("compile succeeds")
}

fn function_param_type_names(compiled: &CompiledContract<'_>, function_name: &str) -> Vec<String> {
    compiled
        .ast
        .functions
        .iter()
        .find(|function| function.name == function_name)
        .unwrap_or_else(|| panic!("missing function '{function_name}'"))
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect()
}

fn generated_auth_entrypoint_name(function_name: &str) -> String {
    format!("__{function_name}")
}

fn state_array_arg(values: Vec<i64>) -> Expr<'static> {
    values.into_iter().map(|value| struct_object(vec![("value", Expr::int(value))])).collect::<Vec<_>>().into()
}

fn cov_decl_nm_leader_sigscript(compiled: &CompiledContract<'_>, next_values: Vec<i64>) -> Vec<u8> {
    covenant_decl_sigscript(compiled, "rebalance", vec![state_array_arg(next_values)], true)
}

fn redeem_only_sigscript(compiled: &CompiledContract<'_>) -> Vec<u8> {
    push_redeem_script(&compiled.script)
}

fn tx_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        0,
        0,
    )
}

fn covenant_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

#[test]
fn singleton_allows_exactly_one_authorized_output() {
    let active = compile_state(AUTH_SINGLETON_SOURCE, 10);
    let out = compile_state(AUTH_SINGLETON_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![10])], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "singleton transition should succeed: {}", result.unwrap_err());
}

#[test]
fn singleton_rejects_two_authorized_outputs_from_same_input() {
    let active = compile_state(AUTH_SINGLETON_SOURCE, 10);
    let out0 = compile_state(AUTH_SINGLETON_SOURCE, 10);
    let out1 = compile_state(AUTH_SINGLETON_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![10])], false));
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton must reject two auth outputs from one input");
    assert_verify_like_error(err);
}

#[test]
fn singleton_transition_allows_correct_state_update() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 10);
    let out = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 13);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump", vec![Expr::int(3)], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "singleton transition should accept the correct new state: {}", result.unwrap_err());
}

#[test]
fn singleton_transition_rejects_mismatched_output_state() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 10);
    let wrong_out = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 12);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump", vec![Expr::int(3)], false));
    let outputs = vec![covenant_output(&wrong_out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton transition must reject mismatched next state");
    assert_verify_like_error(err);
}

#[test]
fn singleton_transition_rejects_two_authorized_outputs() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 10);
    let out0 = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 13);
    let out1 = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 13);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump", vec![Expr::int(3)], false));
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton transition must reject two authorized outputs");
    assert_verify_like_error(err);
}

#[test]
fn singleton_transition_rejects_missing_authorized_output() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump", vec![Expr::int(3)], false));
    let tx = Transaction::new(1, vec![input0], vec![], 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton transition must reject missing authorized output");
    assert_verify_like_error(err);
}

#[test]
fn singleton_transition_termination_allowed_accepts_zero_outputs() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump_or_terminate", vec![state_array_arg(vec![])], false));
    let tx = Transaction::new(1, vec![input0], vec![], 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "singleton transition with termination=allowed should accept empty successor set: {}",
        result.unwrap_err()
    );
}

#[test]
fn singleton_transition_termination_allowed_accepts_one_output() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 10);
    let out = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 13);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump_or_terminate", vec![state_array_arg(vec![13])], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "singleton transition with one successor should succeed: {}", result.unwrap_err());
}

#[test]
fn singleton_transition_termination_allowed_rejects_two_outputs() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 10);
    let out0 = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 13);
    let out1 = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 14);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "bump_or_terminate", vec![state_array_arg(vec![13, 14])], false));
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("singleton transition with termination=allowed must still reject >1 authorized outputs");
    assert_verify_like_error(err);
}

#[test]
fn singleton_missing_authorized_output_returns_invalid_auth_index_error() {
    let active = compile_state(AUTH_SINGLETON_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![])], false));
    let tx = Transaction::new(1, vec![input0], vec![], 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("policy must fail when auth output slot 0 does not exist");
    assert!(
        matches!(err, TxScriptError::CovenantsError(kaspa_txscript_errors::CovenantsError::InvalidAuthCovOutIndex(0, 0, 0))),
        "unexpected error: {err:?}"
    );
}

#[test]
fn auth_groups_single_rejects_parallel_group_with_same_covenant_id() {
    let active = compile_state(AUTH_SINGLE_GROUP_SOURCE, 10);
    let out = compile_state(AUTH_SINGLE_GROUP_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![10])], false));
    let input1 = tx_input(1, vec![]);
    let outputs = vec![covenant_output(&out, 0, COV_A), plain_covenant_output(1, COV_A)];
    let tx = Transaction::new(1, vec![input0, input1], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A), plain_utxo(COV_A)];

    let err =
        execute_input_with_covenants(tx, entries, 0).expect_err("groups=single must reject a second auth group for same covenant id");
    assert_verify_like_error(err);
}

#[test]
fn auth_groups_single_allows_other_covenant_id() {
    let active = compile_state(AUTH_SINGLE_GROUP_SOURCE, 10);
    let out = compile_state(AUTH_SINGLE_GROUP_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![10])], false));
    let input1 = tx_input(1, vec![]);
    let outputs = vec![covenant_output(&out, 0, COV_A), plain_covenant_output(1, COV_B)];
    let tx = Transaction::new(1, vec![input0, input1], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A), plain_utxo(COV_B)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "groups=single should not reject unrelated covenant ids: {}", result.unwrap_err());
}

fn build_nm_tx_for_source(
    source: &'static str,
    input0_sigscript: Vec<u8>,
    input1_sigscript: Vec<u8>,
    outputs: Vec<TransactionOutput>,
) -> (Transaction, Vec<UtxoEntry>) {
    let in0 = compile_state(source, 10);
    let in1 = compile_state(source, 7);
    let tx = Transaction::new(
        1,
        vec![tx_input(0, input0_sigscript), tx_input(1, input1_sigscript)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![covenant_utxo(&in0, COV_A), covenant_utxo(&in1, COV_A)];
    (tx, entries)
}

fn build_nm_tx(
    input0_sigscript: Vec<u8>,
    input1_sigscript: Vec<u8>,
    outputs: Vec<TransactionOutput>,
) -> (Transaction, Vec<UtxoEntry>) {
    build_nm_tx_for_source(COV_N_TO_M_SOURCE, input0_sigscript, input1_sigscript, outputs)
}

#[test]
fn many_to_many_rejects_wrong_entrypoint_role() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 0, COV_A)];

    let delegate_on_leader = {
        let input0_sigscript = covenant_decl_sigscript(&in0, "rebalance", vec![], false);
        let input1_sigscript = covenant_decl_sigscript(&in1, "rebalance", vec![], false);
        let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs.clone());
        execute_input_with_covenants(tx, entries, 0).expect_err("leader input must reject delegate entrypoint")
    };
    assert_verify_like_error(delegate_on_leader);

    let leader_on_delegate = {
        let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10, 10]);
        let input1_sigscript = cov_decl_nm_leader_sigscript(&in1, vec![10, 10]);
        let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);
        execute_input_with_covenants(tx, entries, 1).expect_err("delegate input must reject leader entrypoint")
    };
    assert_verify_like_error(leader_on_delegate);
}

#[test]
fn many_to_many_happy_path_succeeds() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);
    assert_eq!(in0.script, out0.script, "leader input and output[0] script should match");
    assert_eq!(in0.script, out1.script, "leader input and output[1] script should match");

    // Intended valid shape: two covenant inputs in the same id, two covenant outputs in the same id,
    // leader path on input 0 and delegate path on input 1.
    let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10, 10]);
    let input1_sigscript = covenant_decl_sigscript(&in1, "rebalance", vec![], false);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    execute_input_with_covenants(tx.clone(), entries.clone(), 0).expect("leader path should accept valid many-to-many transition");
    execute_input_with_covenants(tx, entries, 1).expect("delegate path should accept valid many-to-many transition");
}

#[test]
fn many_to_many_rejects_input_count_above_from_bound() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let in2 = compile_state(COV_N_TO_M_SOURCE, 6);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);

    let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10, 10]);
    let input1_sigscript = redeem_only_sigscript(&in1);
    let input2_sigscript = redeem_only_sigscript(&in2);
    let tx = Transaction::new(
        1,
        vec![tx_input(0, input0_sigscript), tx_input(1, input1_sigscript), tx_input(2, input2_sigscript)],
        vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![covenant_utxo(&in0, COV_A), covenant_utxo(&in1, COV_A), covenant_utxo(&in2, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("wrapper must reject cov input count above from bound");
    assert_verify_like_error(err);
}

#[test]
fn many_to_many_rejects_output_count_above_to_bound() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);

    let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10, 11]);
    let input1_sigscript = covenant_decl_sigscript(&in1, "rebalance", vec![], false);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A), plain_covenant_output(0, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("wrapper must reject cov output count above to bound");
    assert_verify_like_error(err);
}

#[test]
fn singleton_rejects_authorized_output_with_different_script() {
    let active = compile_state(AUTH_SINGLETON_SOURCE, 10);
    let different = compile_state(AUTH_SINGLETON_SOURCE, 11);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![10])], false));
    let tx = Transaction::new(1, vec![input0], vec![covenant_output(&different, 0, COV_A)], 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("wrapper should reject authorized output with different script");
    assert_verify_like_error(err);
}

#[test]
fn many_to_many_leader_rejects_cov_output_with_different_script() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1_different = compile_state(COV_N_TO_M_DIFFERENT_SCRIPT_SOURCE, 11);

    let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10, 11]);
    let input1_sigscript = covenant_decl_sigscript(&in1, "rebalance", vec![], false);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1_different, 1, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("leader wrapper should reject cov output with different script");
    assert_verify_like_error(err);
}

#[test]
fn many_to_many_transition_leader_rejects_spoofed_prev_states() {
    let in0 = compile_state(COV_N_TO_M_TRANSITION_SOURCE, 10);
    let honest = in0
        .build_sig_script_for_covenant_decl("carry_forward", vec![], CovenantDeclCallOptions { is_leader: true })
        .expect("leader transition call should succeed without caller-supplied prev_states");
    assert!(!honest.is_empty(), "leader transition sigscript should not be empty");

    let err = in0
        .build_sig_script_for_covenant_decl(
            "carry_forward",
            vec![state_array_arg(vec![42, 43])],
            CovenantDeclCallOptions { is_leader: true },
        )
        .expect_err("spoofed prev_states should no longer be accepted through the leader ABI");
    assert!(matches!(err, silverscript_lang::compiler::CompilerError::Unsupported(_)), "unexpected error: {err:?}");
}

#[test]
fn many_to_many_transition_happy_path_succeeds() {
    let in0 = compile_state(COV_N_TO_M_TRANSITION_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_TRANSITION_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_TRANSITION_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_TRANSITION_SOURCE, 7);

    let input0_sigscript = covenant_decl_sigscript(&in0, "carry_forward", vec![], true);
    let input1_sigscript = covenant_decl_sigscript(&in1, "carry_forward", vec![], false);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx_for_source(COV_N_TO_M_TRANSITION_SOURCE, input0_sigscript, input1_sigscript, outputs);

    execute_input_with_covenants(tx.clone(), entries.clone(), 0).expect("leader transition should accept honest prev_states");
    execute_input_with_covenants(tx, entries, 1).expect("delegate transition should accept valid many-to-many transition");
}

#[test]
fn runtime_accepts_state_array_entrypoint_argument_for_generated_wrapper() {
    let active = compile_state(AUTH_SINGLETON_ARRAY_RUNTIME_SOURCE, 10);
    let out = compile_state(AUTH_SINGLETON_ARRAY_RUNTIME_SOURCE, 11);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![11])], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "generated wrapper should accept State[] entrypoint args at runtime: {}", result.unwrap_err());
}

#[test]
fn runtime_passes_state_array_into_generated_policy_function() {
    let active = compile_state(AUTH_SINGLETON_ARRAY_RUNTIME_SOURCE, 10);
    let out = compile_state(AUTH_SINGLETON_ARRAY_RUNTIME_SOURCE, 11);

    let wrapper_name = generated_auth_entrypoint_name("step");
    let wrapper_param_types = function_param_type_names(&active, &wrapper_name);
    assert_eq!(wrapper_param_types, vec!["State[]".to_string()]);

    let policy = active
        .ast
        .functions
        .iter()
        .find(|function| !function.entrypoint && function.name == "__covenant_policy_step")
        .expect("generated covenant policy exists");
    assert!(!policy.entrypoint, "generated covenant policy must remain non-entrypoint");
    let policy_param_types: Vec<String> = policy.params.iter().map(|param| param.type_ref.type_name()).collect();
    assert_eq!(policy_param_types, vec!["State".to_string(), "State[]".to_string()]);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![12])], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("generated policy should reject when the State[] argument content is wrong");
    assert_verify_like_error(err);
}

#[test]
fn auth_verification_rejects_underprovided_new_states() {
    let active = compile_state(AUTH_VERIFICATION_CARDINALITY_SOURCE, 10);
    let out = compile_state(AUTH_VERIFICATION_CARDINALITY_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![])], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("auth verification wrapper must reject when new_states under-provides outputs");
    assert_verify_like_error(err);
}

#[test]
fn auth_verification_rejects_overprovided_new_states() {
    let active = compile_state(AUTH_VERIFICATION_CARDINALITY_SOURCE, 10);
    let out = compile_state(AUTH_VERIFICATION_CARDINALITY_SOURCE, 10);

    let input0 = tx_input(0, covenant_decl_sigscript(&active, "step", vec![state_array_arg(vec![10, 11])], false));
    let outputs = vec![covenant_output(&out, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("auth verification wrapper must reject when new_states over-provides outputs");
    assert_verify_like_error(err);
}

#[test]
fn many_to_many_verification_rejects_underprovided_new_states() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);

    let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10]);
    let input1_sigscript = covenant_decl_sigscript(&in1, "rebalance", vec![], false);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("cov verification wrapper must reject when new_states under-provides outputs");
    assert_verify_like_error(err);
}

#[test]
fn many_to_many_verification_rejects_overprovided_new_states() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);

    let input0_sigscript = cov_decl_nm_leader_sigscript(&in0, vec![10, 10, 10]);
    let input1_sigscript = covenant_decl_sigscript(&in1, "rebalance", vec![], false);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("cov verification wrapper must reject when new_states over-provides outputs");
    assert_verify_like_error(err);
}
