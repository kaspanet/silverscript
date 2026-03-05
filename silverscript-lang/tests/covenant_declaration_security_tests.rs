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

const COV_N_TO_M_SOURCE: &str = r#"
    contract Pair(int init_value) {
        int value = init_value;

        #[covenant(from = 2, to = 2)]
        function rebalance() {
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
    let out = compile_state(AUTH_SINGLETON_SOURCE, 11);

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
    let out0 = compile_state(AUTH_SINGLETON_SOURCE, 11);
    let out1 = compile_state(AUTH_SINGLETON_SOURCE, 12);

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 0, COV_A)];
    let tx = Transaction::new(1, vec![input0], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A)];

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("singleton must reject two auth outputs from one input");
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
    let out = compile_state(AUTH_SINGLE_GROUP_SOURCE, 11);

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
    let out = compile_state(AUTH_SINGLE_GROUP_SOURCE, 11);

    let input0 = tx_input(0, covenant_sigscript(&active, "step", vec![]));
    let input1 = tx_input(1, vec![]);
    let outputs = vec![covenant_output(&out, 0, COV_A), plain_covenant_output(1, COV_B)];
    let tx = Transaction::new(1, vec![input0, input1], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![covenant_utxo(&active, COV_A), plain_utxo(COV_B)];

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "groups=single should not reject unrelated covenant ids: {}", result.unwrap_err());
}

fn build_nm_tx(
    input0_sigscript: Vec<u8>,
    input1_sigscript: Vec<u8>,
    outputs: Vec<TransactionOutput>,
) -> (Transaction, Vec<UtxoEntry>) {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
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

#[test]
fn many_to_many_rejects_wrong_entrypoint_role() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 12);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 5);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A)];

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
fn many_to_many_rejects_input_count_above_from_bound() {
    let in0 = compile_state(COV_N_TO_M_SOURCE, 10);
    let in1 = compile_state(COV_N_TO_M_SOURCE, 7);
    let in2 = compile_state(COV_N_TO_M_SOURCE, 6);
    let out0 = compile_state(COV_N_TO_M_SOURCE, 11);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 12);

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
    let out0 = compile_state(COV_N_TO_M_SOURCE, 12);
    let out1 = compile_state(COV_N_TO_M_SOURCE, 5);

    let input0_sigscript = covenant_sigscript(&in0, "rebalance_leader", vec![]);
    let input1_sigscript = covenant_sigscript(&in1, "rebalance_delegate", vec![]);
    let outputs = vec![covenant_output(&out0, 0, COV_A), covenant_output(&out1, 1, COV_A), plain_covenant_output(0, COV_A)];
    let (tx, entries) = build_nm_tx(input0_sigscript, input1_sigscript, outputs);

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("wrapper must reject cov output count above to bound");
    assert_verify_like_error(err);
}
