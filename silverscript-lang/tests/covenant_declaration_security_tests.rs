use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::opcodes::codes::OpTrue;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script};
use kaspa_txscript_errors::TxScriptError;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract};

const COV_A: Hash = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
const COV_B: Hash = Hash::from_bytes(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

const AUTH_SINGLETON_SOURCE: &str = r#"
    contract Counter(int init_value) {
        int value = init_value;

        #[covenant.singleton]
        function step() {
            require(OpAuthOutputIdx(this.activeInputIndex, 0) >= 0);
        }
    }
"#;

const AUTH_SINGLE_GROUP_SOURCE: &str = r#"
    contract Counter(int init_value) {
        int value = init_value;

        #[covenant(binding = auth, from = 1, to = 1, groups = single)]
        function step() {
            require(OpAuthOutputIdx(this.activeInputIndex, 0) >= 0);
        }
    }
"#;

const AUTH_SINGLETON_TRANSITION_SOURCE: &str = r#"
    contract Decls(int init_value) {
        int value = init_value;

        #[covenant.singleton(mode = transition)]
        function bump(int delta) : (int) {
            return(value + delta);
        }
    }
"#;

const AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE: &str = r#"
    contract Decls(int init_value) {
        int value = init_value;

        #[covenant.singleton(mode = transition, termination = allowed)]
        function bump_or_terminate(int[] next_values) : (int[]) {
            return(next_values);
        }
    }
"#;

const COV_N_TO_M_SOURCE: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        #[covenant(from = 2, to = 2)]
        function rebalance() {
            require(true);
        }
    }
"#;

const MANUAL_COV_N_TO_M_LOWERED_SOURCE: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);

            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);

            require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);

            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);

            require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
        }
    }
"#;

const MANUAL_COV_N_TO_M_NO_IN_COUNT_CHECK: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);
            require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);
            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);
            require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
        }
    }
"#;

const MANUAL_COV_N_TO_M_NO_OUT_COUNT_CHECK: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);
            int cov_out_count = OpCovOutCount(cov_id);
            require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);
            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);
            int cov_out_count = OpCovOutCount(cov_id);
            require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
        }
    }
"#;

const MANUAL_COV_N_TO_M_NO_LEADER_ROLE_CHECK: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);
            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);
            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);
            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);
            require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
        }
    }
"#;

const MANUAL_COV_N_TO_M_NO_DELEGATE_ROLE_CHECK: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);
            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);
            require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);
            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

            int cov_in_count = OpCovInputCount(cov_id);
            require(cov_in_count <= 2);
            int cov_out_count = OpCovOutCount(cov_id);
            require(cov_out_count <= 2);
        }
    }
"#;

const MANUAL_COV_N_TO_M_NO_COV_CHECKS: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            require(true);
        }
    }
"#;

const MANUAL_COV_N_TO_M_NO_FIELDS_NO_COV_CHECKS: &str = r#"
    contract Pair(int init_value) {
        function policy_rebalance() {
            require(true);
        }

        entrypoint function rebalance_leader() {
            policy_rebalance();
        }

        entrypoint function rebalance_delegate() {
            require(true);
        }
    }
"#;

fn compile_state(source: &'static str, value: i64) -> CompiledContract<'static> {
    compile_contract(source, &[Expr::int(value)], CompileOptions::default()).expect("compile succeeds")
}

fn push_redeem_script(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_data(script).expect("push redeem script").drain()
}

fn covenant_sigscript(compiled: &CompiledContract<'_>, entrypoint: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled.build_sig_script(entrypoint, args).expect("build sigscript");
    sigscript.extend_from_slice(&push_redeem_script(&compiled.script));
    sigscript
}

fn redeem_only_sigscript(compiled: &CompiledContract<'_>) -> Vec<u8> {
    push_redeem_script(&compiled.script)
}

fn tx_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count: 0,
    }
}

fn covenant_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn plain_covenant_output(authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    TransactionOutput {
        value: 1_000,
        script_public_key: ScriptPublicKey::new(0, vec![OpTrue].into()),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn covenant_utxo(compiled: &CompiledContract<'_>, covenant_id: Hash) -> UtxoEntry {
    UtxoEntry::new(1_500, pay_to_script_hash_script(&compiled.script), 0, false, Some(covenant_id))
}

fn plain_utxo(covenant_id: Hash) -> UtxoEntry {
    UtxoEntry::new(1_500, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, Some(covenant_id))
}

fn execute_input_with_covenants(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn assert_verify_like_error(err: TxScriptError) {
    assert!(matches!(err, TxScriptError::VerifyError | TxScriptError::EvalFalse), "expected verify/eval-false, got {err:?}");
}

#[test]
fn singleton_allows_exactly_one_authorized_output() {
    let active = compile_state(AUTH_SINGLETON_SOURCE, 10);
    let out = compile_state(AUTH_SINGLETON_SOURCE, 10);

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "bump", vec![Expr::int(3)]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "bump", vec![Expr::int(3)]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "bump", vec![Expr::int(3)]));
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton transition must reject two authorized outputs");
    assert_verify_like_error(err);
}

#[test]
fn singleton_transition_rejects_missing_authorized_output() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_SOURCE, 10);

    let input0 = tx_input(0, covenant_sigscript(&active, "bump", vec![Expr::int(3)]));
    let tx = Transaction::new(1, vec![input0], vec![], 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton transition must reject missing authorized output");
    assert_verify_like_error(err);
}

#[test]
fn singleton_transition_termination_allowed_accepts_zero_outputs() {
    let active = compile_state(AUTH_SINGLETON_TRANSITION_TERMINATION_ALLOWED_SOURCE, 10);

    let input0 = tx_input(0, covenant_sigscript(&active, "bump_or_terminate", vec![Vec::<i64>::new().into()]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "bump_or_terminate", vec![vec![13i64].into()]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "bump_or_terminate", vec![vec![13i64, 14i64].into()]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
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

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
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
        let input0_sigscript = covenant_sigscript(&in0, "rebalance_delegate", vec![]);
        let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
        let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs.clone());
        execute_input_with_covenants(tx, entries, 0).expect_err("leader input must reject delegate entrypoint")
    };
    assert_verify_like_error(delegate_on_leader);

    let leader_on_delegate = {
        let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
        let input1_sigscript = covenant_sigscript(&in1, "rebalance_leader", vec![]);
        let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);
        execute_input_with_covenants(tx, entries, 1).expect_err("delegate input must reject leader entrypoint")
    };
    assert_verify_like_error(leader_on_delegate);
}

#[test]
fn many_to_many_happy_path_currently_fails_with_validate_output_state() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);
    assert_eq!(in0.script, out0.script, "leader input and output[0] script should match");
    assert_eq!(in0.script, out1.script, "leader input and output[1] script should match");

    // Intended valid shape: two covenant inputs in the same id, two covenant outputs in the same id,
    // leader path on input 0 and delegate path on input 1.
    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
    let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let leader_err = execute_input_with_covenants(tx.clone(), entries.clone(), 0)
        .expect_err("leader path is expected to fail until validateOutputState fully supports selector-dispatched scripts");
    assert_verify_like_error(leader_err);

    let delegate_result = execute_input_with_covenants(tx, entries, 1);
    assert!(delegate_result.is_ok(), "delegate path unexpectedly failed: {}", delegate_result.unwrap_err());
}

#[test]
fn many_to_many_happy_path_manual_lowered_script_succeeds() {
    let in0 = compile_state(MANUAL_COV_N_TO_M_LOWERED_SOURCE, 10);
    let in1 = compile_state(MANUAL_COV_N_TO_M_LOWERED_SOURCE, 7);
    let out0 = compile_state(MANUAL_COV_N_TO_M_LOWERED_SOURCE, 12);
    let out1 = compile_state(MANUAL_COV_N_TO_M_LOWERED_SOURCE, 5);

    // Same intended valid tx shape as the macro-lowered repro, but with manually written wrappers.
    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
    let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx_for_source(MANUAL_COV_N_TO_M_LOWERED_SOURCE, input0_sigscript, input1_sigscript, outputs);

    let leader_result = execute_input_with_covenants(tx.clone(), entries.clone(), 0);
    assert!(leader_result.is_ok(), "manual lowered leader path unexpectedly failed: {}", leader_result.unwrap_err());

    let delegate_result = execute_input_with_covenants(tx, entries, 1);
    assert!(delegate_result.is_ok(), "manual lowered delegate path unexpectedly failed: {}", delegate_result.unwrap_err());
}

fn run_nm_manual_happy_path(source: &'static str) -> (Result<(), TxScriptError>, Result<(), TxScriptError>) {
    let in0 = compile_state(source, 10);
    let in1 = compile_state(source, 7);
    let out0 = compile_state(source, 12);
    let out1 = compile_state(source, 5);

    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
    let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];
    let (tx, entries) = build_nm_tx_for_source(source, input0_sigscript, input1_sigscript, outputs);

    let leader_result = execute_input_with_covenants(tx.clone(), entries.clone(), 0);
    let delegate_result = execute_input_with_covenants(tx, entries, 1);
    (leader_result, delegate_result)
}

#[test]
#[ignore = "isolation helper for N:M happy-path VerifyError"]
fn isolate_many_to_many_manual_problematic_require() {
    let variants = vec![
        ("full_manual_wrapper", MANUAL_COV_N_TO_M_LOWERED_SOURCE),
        ("no_in_count_check", MANUAL_COV_N_TO_M_NO_IN_COUNT_CHECK),
        ("no_out_count_check", MANUAL_COV_N_TO_M_NO_OUT_COUNT_CHECK),
        ("no_leader_role_check", MANUAL_COV_N_TO_M_NO_LEADER_ROLE_CHECK),
        ("no_delegate_role_check", MANUAL_COV_N_TO_M_NO_DELEGATE_ROLE_CHECK),
        ("no_cov_checks", MANUAL_COV_N_TO_M_NO_COV_CHECKS),
        ("no_fields_no_cov_checks", MANUAL_COV_N_TO_M_NO_FIELDS_NO_COV_CHECKS),
    ];

    for (name, source) in variants {
        let (leader_result, delegate_result) = run_nm_manual_happy_path(source);
        eprintln!(
            "variant={name} leader_ok={} delegate_ok={} leader_err={:?} delegate_err={:?}",
            leader_result.is_ok(),
            delegate_result.is_ok(),
            leader_result.as_ref().err(),
            delegate_result.as_ref().err()
        );
    }
}

#[test]
fn many_to_many_rejects_input_count_above_from_bound() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let in2 = compile_state(COV_N_TO_M_SOURCE, 6);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 10);

    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
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

    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
    let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A), plain_covenant_output(0, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("wrapper must reject cov output count above to bound");
    assert_verify_like_error(err);
}

#[test]
fn singleton_rejects_authorized_output_with_different_script() {
    let active = compile_state(AUTH_SINGLETON_SOURCE, 10);
    let different = compile_state(AUTH_SINGLETON_SOURCE, 11);

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
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
    let out1_different = compile_state(COV_N_TO_M_SOURCE, 11);

    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
    let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1_different, 1, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("leader wrapper should reject cov output with different script");
    assert_verify_like_error(err);
}
