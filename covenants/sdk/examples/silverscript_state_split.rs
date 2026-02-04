use kaspa_consensus_core::{
    Hash,
    constants::{SOMPI_PER_KASPA, TX_VERSION},
    hashing::sighash::SigHashReusedValuesUnsync,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        CovenantBinding, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine,
    caches::Cache,
    covenants::CovenantsContext,
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

const ACTION_LEN_BYTES: usize = 4;
const STATE_LEN_BYTES: usize = 8;
const ACTION_PUSH_TOTAL: i64 = 1 + ACTION_LEN_BYTES as i64;
const STATE_PUSH_TOTAL: i64 = 1 + STATE_LEN_BYTES as i64;

fn compute_push_size(data: &[u8]) -> i64 {
    ScriptBuilder::new().add_data(data).unwrap().drain().len() as i64
}

fn build_split_covenant_script(state: &[u8]) -> Vec<u8> {
    let source = format!(
        r#"
        pragma silverscript ^0.1.0;

        contract SplitState(bytes8 state) {{
            entrypoint function spend() {{
                int inputIdx = this.activeInputIndex;

                // Ensure this input authorizes exactly two covenant outputs.
                require(OpAuthOutputCount(inputIdx) == 2);

                // ScriptSig layout: <action> <redeem_script>
                // end = action_push_total + redeem_push_header_len + redeem_script_len
                int end = {ACTION_PUSH_TOTAL} + this.scriptSizeDataPrefix + this.scriptSize;
                require(OpTxInputScriptSigLen(inputIdx) == end);

                // Action bytes are pushed first in the scriptSig (1-byte header + 4 bytes data).
                int actionStart = 1;
                int actionEnd = actionStart + 4;
                bytes action = OpTxInputScriptSigSubstr(inputIdx, actionStart, actionEnd);

                // Convert state + action to integers and compute split.
                int s = OpBin2Num(state);
                int a = OpBin2Num(action);
                require(0 <= a);
                require(a <= s);

                bytes8 newLeft = OpNum2Bin(a, 8);
                bytes8 newRight = OpNum2Bin(s - a, 8);

                // Rebuild the redeem script by swapping the embedded state.
                // startOffset = action_push_total + redeem_push_header_len + state_push_total
                int startOffset = {ACTION_PUSH_TOTAL} + this.scriptSizeDataPrefix + {STATE_PUSH_TOTAL};
                bytes suffix = OpTxInputScriptSigSubstr(inputIdx, startOffset, end);
                bytes stateHeader = bytes(8, 1); // push header for 8-byte state

                bytes leftRedeem = stateHeader + newLeft + suffix;
                bytes rightRedeem = stateHeader + newRight + suffix;

                // bytes35 leftSpk = new LockingBytecodeP2SHFromRedeemScript(leftRedeem);
                // bytes35 rightSpk = new LockingBytecodeP2SHFromRedeemScript(rightRedeem);

                // int out0 = OpAuthOutputIdx(inputIdx, 0);
                // int out1 = OpAuthOutputIdx(inputIdx, 1);

                // require(tx.outputs[out0].lockingBytecode == leftSpk);
                // require(tx.outputs[out1].lockingBytecode == rightSpk);
            }}
        }}
    "#,
        ACTION_PUSH_TOTAL = ACTION_PUSH_TOTAL,
        STATE_PUSH_TOTAL = STATE_PUSH_TOTAL,
    );

    let constructor_args = vec![state.to_vec().into()];
    compile_contract(&source, &constructor_args, CompileOptions::default())
        .expect("compile succeeds")
        .script
}

fn main() {
    let current_state_value: i64 = 1_000;
    let action_value: i32 = 245;
    assert!(action_value as i64 <= current_state_value, "action value must not exceed state");

    let old_state = current_state_value.to_le_bytes();
    let action_data = action_value.to_le_bytes();

    let new_left_state = (action_value as i64).to_le_bytes();
    let new_right_state = (current_state_value - action_value as i64).to_le_bytes();

    let input_redeem_script = build_split_covenant_script(old_state.as_slice());
    let left_output_redeem_script = build_split_covenant_script(new_left_state.as_slice());
    let right_output_redeem_script = build_split_covenant_script(new_right_state.as_slice());

    let input_spk = pay_to_script_hash_script(&input_redeem_script);
    let left_output_spk = pay_to_script_hash_script(&left_output_redeem_script);
    let right_output_spk = pay_to_script_hash_script(&right_output_redeem_script);

    let dummy_prev_out = TransactionOutpoint::new(Hash::from_u64_word(7), 0);
    let covenant_id = Hash::from_u64_word(77);
    let tx_input = TransactionInput::new(dummy_prev_out, vec![], 0, 0);

    let mut left_output = TransactionOutput::new(SOMPI_PER_KASPA, left_output_spk);
    left_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });
    let mut right_output = TransactionOutput::new(SOMPI_PER_KASPA, right_output_spk);
    right_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });

    let mut tx = Transaction::new(
        TX_VERSION,
        vec![tx_input],
        vec![left_output, right_output],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    // ScriptSig layout: <action_data> <input_redeem_script>
    let sig_script = ScriptBuilder::new()
        .add_data(action_data.as_slice())
        .unwrap()
        .add_data(&input_redeem_script)
        .unwrap()
        .drain();

    let expected_scriptsig_len = compute_push_size(action_data.as_slice()) + compute_push_size(&input_redeem_script);
    assert_eq!(sig_script.len() as i64, expected_scriptsig_len, "ScriptSig length should match expectations");
    tx.inputs[0].signature_script = sig_script;

    let utxo_entry = UtxoEntry::new(SOMPI_PER_KASPA, input_spk, 0, false, Some(covenant_id));
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let flags = EngineFlags { covenants_enabled: true };

    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
    let covenants_ctx = CovenantsContext::from_tx(&populated_tx).expect("covenants context");
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&covenants_ctx);
    let mut engine = TxScriptEngine::from_transaction_input(&populated_tx, &tx.inputs[0], 0, &utxo_entry, ctx, flags);

    engine.execute().expect("split covenant should validate");
}
