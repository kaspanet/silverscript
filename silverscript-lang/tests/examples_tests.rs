use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use rand::{RngCore, thread_rng};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use silverscript_lang::compiler::{CompileOptions, CompiledContract, Expr, compile_contract, function_branch_index};
use std::fs;

fn build_null_data_script(tag: i64, message: &str) -> Vec<u8> {
    ScriptBuilder::new().add_op(OpReturn).unwrap().add_i64(tag).unwrap().add_data(message.as_bytes()).unwrap().drain()
}

fn load_example_source(name: &str) -> String {
    let path = format!("{}/tests/examples/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn selector_for(compiled: &CompiledContract, function_name: &str) -> i64 {
    function_branch_index(&compiled.ast, function_name).expect("selector resolved")
}

fn random_keypair() -> Keypair {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let mut sk_bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut sk_bytes);
        if let Ok(secret_key) = SecretKey::from_slice(&sk_bytes) {
            return Keypair::from_secret_key(&secp, &secret_key);
        }
    }
}

fn run_contract_with_tx(
    script: Vec<u8>,
    output0_script: Vec<u8>,
    output1_script: Vec<u8>,
    input_value: u64,
    output0_value: u64,
    output1_value: u64,
    sigscript: Vec<u8>,
    lock_time: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    run_contract_with_tx_sequence(
        script,
        output0_script,
        output1_script,
        input_value,
        output0_value,
        output1_value,
        sigscript,
        lock_time,
        0,
    )
}

fn run_contract_with_tx_sequence(
    script: Vec<u8>,
    output0_script: Vec<u8>,
    output1_script: Vec<u8>,
    input_value: u64,
    output0_value: u64,
    output1_value: u64,
    sigscript: Vec<u8>,
    lock_time: u64,
    sequence: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence,
        sig_op_count: 0,
    };
    let output0 =
        TransactionOutput { value: output0_value, script_public_key: ScriptPublicKey::new(0, output0_script.into()), covenant: None };
    let output1 =
        TransactionOutput { value: output1_value, script_public_key: ScriptPublicKey::new(0, output1_script.into()), covenant: None };

    let tx =
        Transaction::new(1, vec![input.clone()], vec![output0.clone(), output1.clone()], lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(input_value, ScriptPublicKey::new(0, script.clone().into()), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn run_contract_with_outputs(
    script: Vec<u8>,
    outputs: Vec<(u64, Vec<u8>)>,
    input_value: u64,
    sigscript: Vec<u8>,
    lock_time: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        sig_op_count: 0,
    };

    let tx_outputs = outputs
        .into_iter()
        .map(|(value, script)| TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, script.into()), covenant: None })
        .collect::<Vec<_>>();

    let tx = Transaction::new(1, vec![input.clone()], tx_outputs.clone(), lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(input_value, ScriptPublicKey::new(0, script.clone().into()), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn script_with_return_checks(script: Vec<u8>, expected: &[i64]) -> Vec<u8> {
    let mut builder = ScriptBuilder::new();
    builder.add_ops(&script).unwrap();
    for value in expected.iter().rev() {
        builder.add_i64(*value).unwrap();
        builder.add_op(OpEqualVerify).unwrap();
    }
    builder.add_op(OpTrue).unwrap();
    builder.drain()
}

#[test]
fn compiles_announcement_example_and_verifies() {
    let source = load_example_source("announcement.sil");

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "announce");
    let message = "A contract may not injure a human being or, through inaction, allow a human being to come to harm.";
    let announcement_script = build_null_data_script(27906, message);

    // Test announce() with changeAmount >= minerFee (else branch).
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 3000u64;
    let output1_value = input_value - 1000;
    let result = run_contract_with_tx(
        compiled.script.clone(),
        announcement_script.clone(),
        compiled.script.clone(),
        input_value,
        0,
        output1_value,
        sigscript.clone(),
        0,
    );
    assert!(result.is_ok(), "announcement example failed: {}", result.unwrap_err());

    // Test announce() with changeAmount < minerFee (if branch).
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 1500u64;
    let output1_value = 1u64;
    let result = run_contract_with_tx(
        compiled.script.clone(),
        announcement_script,
        compiled.script,
        input_value,
        0,
        output1_value,
        sigscript,
        0,
    );
    assert!(result.is_ok(), "announcement small change failed: {}", result.unwrap_err());
}

#[test]
fn compiles_constant_budget_example_and_verifies() {
    let source = load_example_source("constant_budget.sil");

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "spend");
    let recipient0 = [2u8; 20];
    let recipient1 = [3u8; 20];
    let output0_script = build_p2pkh_script(&recipient0);
    let output1_script = build_p2pkh_script(&recipient1);

    // Test spend() with output1 >= MIN_CHANGE (if branch).
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 4000u64;
    let output0_value = 1500u64;
    let output1_value = 1200u64;
    let result = run_contract_with_tx(
        compiled.script.clone(),
        output0_script.clone(),
        output1_script.clone(),
        input_value,
        output0_value,
        output1_value,
        sigscript,
        0,
    );
    assert!(result.is_ok(), "constant_budget if branch failed: {}", result.unwrap_err());

    // Test spend() with output1 < MIN_CHANGE (else branch).
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 3000u64;
    let output0_value = 1300u64;
    let output1_value = 500u64;
    let result =
        run_contract_with_tx(compiled.script, output0_script, output1_script, input_value, output0_value, output1_value, sigscript, 0);
    assert!(result.is_ok(), "constant_budget else branch failed: {}", result.unwrap_err());
}

#[test]
fn compiles_for_loop_example_and_verifies() {
    let source = load_example_source("for_loop.sil");

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "check");
    let recipient0 = [5u8; 20];
    let recipient1 = [6u8; 20];
    let recipient2 = [7u8; 20];
    let recipient3 = [8u8; 20];
    let output0_script = build_p2pkh_script(&recipient0);
    let output1_script = build_p2pkh_script(&recipient1);
    let output2_script = build_p2pkh_script(&recipient2);
    let output3_script = build_p2pkh_script(&recipient3);

    // Test check() with loop bounds START..END.
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 10_000u64;
    let outputs = vec![
        (1000u64, output0_script.clone()),
        (1001u64, output1_script.clone()),
        (1002u64, output2_script.clone()),
        (1003u64, output3_script.clone()),
    ];
    let result = run_contract_with_outputs(compiled.script.clone(), outputs, input_value, sigscript, 0);
    assert!(result.is_ok(), "for_loop example failed: {}", result.unwrap_err());

    // Test check() failure when require fails in the loop.
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 10_000u64;
    let outputs = vec![
        (1000u64, output0_script.clone()),
        (1001u64, output1_script.clone()),
        (999u64, output2_script.clone()),
        (1003u64, output3_script.clone()),
    ];
    let result = run_contract_with_outputs(compiled.script.clone(), outputs, input_value, sigscript, 0);
    assert!(result.is_err(), "for_loop require failure should error");

    // Test check() failure when there are fewer than 4 outputs.
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 10_000u64;
    let outputs = vec![(1000u64, output0_script), (1001u64, output1_script), (1002u64, output2_script)];
    let result = run_contract_with_outputs(compiled.script, outputs, input_value, sigscript, 0);
    assert!(result.is_err(), "for_loop with too few outputs should error");
}

#[test]
fn compiles_for_loop_ctor_example_with_constructor_bounds() {
    let source = load_example_source("for_loop_ctor.sil");

    let constructor_args = [Expr::Int(0), Expr::Int(4)];
    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "check");
    let recipient0 = [5u8; 20];
    let recipient1 = [6u8; 20];
    let recipient2 = [7u8; 20];
    let recipient3 = [8u8; 20];
    let output0_script = build_p2pkh_script(&recipient0);
    let output1_script = build_p2pkh_script(&recipient1);
    let output2_script = build_p2pkh_script(&recipient2);
    let output3_script = build_p2pkh_script(&recipient3);

    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let input_value = 10_000u64;
    let outputs = vec![
        (1000u64, output0_script.clone()),
        (1001u64, output1_script.clone()),
        (1002u64, output2_script.clone()),
        (1003u64, output3_script.clone()),
    ];
    let result = run_contract_with_outputs(compiled.script, outputs, input_value, sigscript, 0);
    assert!(result.is_ok(), "for_loop_ctor example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_yield_basic_example_and_verifies() {
    let source = load_example_source("yield_basic.sil");

    let constructor_args = [Expr::Int(8)];
    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let script = script_with_return_checks(compiled.script, &[12, 8]);
    let recipient0 = [9u8; 20];
    let recipient1 = [10u8; 20];
    let output0_script = build_p2pkh_script(&recipient0);
    let output1_script = build_p2pkh_script(&recipient1);

    // Test main(b=8) returns [12, 8] on stack.
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let result = run_contract_with_tx(script, output0_script, output1_script, 2000, 500, 500, sigscript, 0);
    assert!(result.is_ok(), "yield basic failed: {}", result.unwrap_err());
}

#[test]
fn compiles_yield_loop_example_and_verifies() {
    let source = load_example_source("yield_loop.sil");

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let script = script_with_return_checks(compiled.script, &[1, 2, 3, 4]);
    let recipient0 = [11u8; 20];
    let recipient1 = [12u8; 20];
    let output0_script = build_p2pkh_script(&recipient0);
    let output1_script = build_p2pkh_script(&recipient1);

    // Test main() returns loop values [1,2,3,4] on stack.
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    let result = run_contract_with_tx(script, output0_script, output1_script, 2000, 500, 500, sigscript, 0);
    assert!(result.is_ok(), "yield loop failed: {}", result.unwrap_err());
}

fn build_p2pkh_script(hash: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_op(OpBlake2b).unwrap().add_data(hash).unwrap().add_op(OpEqual).unwrap().drain()
}

fn build_p2sh20_script(hash: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_op(OpBlake2b).unwrap().add_data(hash).unwrap().add_op(OpEqual).unwrap().drain()
}

#[test]
fn compiles_hodl_vault_example_and_verifies() {
    let source = load_example_source("hodl_vault.sil");
    let owner = random_keypair();
    let oracle = random_keypair();
    let owner_pk = owner.x_only_public_key().0.serialize();
    let oracle_pk = oracle.x_only_public_key().0.serialize();

    let min_block = 900i64;
    let price_target = 10i64;
    let block_height = 1000u32;
    let price = 20u32;
    let oracle_message = [block_height.to_le_bytes(), price.to_le_bytes()].concat();

    let constructor_args = vec![
        Expr::Bytes(owner_pk.to_vec()),
        Expr::Bytes(oracle_pk.to_vec()),
        Expr::Int(min_block),
        Expr::Int(price_target),
    ];
    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "spend");

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([7u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 5000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], block_height as u64, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = owner.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test spend() function call (build sigscript for spend()).
    let mut builder = ScriptBuilder::new();
    builder.add_data(&signature).unwrap();
    builder.add_data(b"oracle").unwrap();
    builder.add_data(&oracle_message).unwrap();
    builder.add_i64(selector).unwrap();
    tx.tx.inputs[0].signature_script = builder.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "hodl_vault example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_mecenas_example_and_verifies() {
    let source = load_example_source("mecenas.sil");

    let recipient = [1u8; 20];
    let funder_key = random_keypair();
    let funder_pk = funder_key.x_only_public_key().0.serialize();
    let mut funder_hash =
        blake2b_simd::Params::new().hash_length(32).to_state().update(funder_pk.as_slice()).finalize().as_bytes().to_vec();
    funder_hash.truncate(20);
    let pledge = 2000i64;
    let constructor_args = vec![Expr::Bytes(recipient.to_vec()), Expr::Bytes(funder_hash.clone()), Expr::Int(pledge)];

    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let receive_selector = selector_for(&compiled, "receive");
    let reclaim_selector = selector_for(&compiled, "reclaim");

    // Test receive() with changeValue > pledge + minerFee (else branch).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_i64(receive_selector).unwrap();
    let input_value = 10000u64;
    let output0_value = pledge as u64;
    let output1_value = input_value - pledge as u64 - 1000;
    let output0_script = build_p2pkh_script(&recipient);

    let result = run_contract_with_tx(
        compiled.script.clone(),
        output0_script,
        compiled.script.clone(),
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        0,
    );
    assert!(result.is_ok(), "mecenas example failed: {}", result.unwrap_err());

    // Test receive() with changeValue <= pledge + minerFee (if branch).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_i64(receive_selector).unwrap();

    let input_value = 6000u64;
    let output0_value = input_value - 1000;
    let output1_value = 0u64;
    let output0_script = build_p2pkh_script(&recipient);

    let result = run_contract_with_tx(
        compiled.script.clone(),
        output0_script,
        compiled.script.clone(),
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        0,
    );
    assert!(result.is_ok(), "mecenas small change failed: {}", result.unwrap_err());

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([15u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 5000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = funder_key.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test reclaim() function call (build sigscript for reclaim()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(funder_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(reclaim_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "mecenas reclaim failed: {}", result.unwrap_err());
}

#[test]
fn compiles_mecenas_locktime_example_and_verifies() {
    let source = load_example_source("mecenas_locktime.sil");

    let recipient = [3u8; 20];
    let funder_key = random_keypair();
    let funder_pk = funder_key.x_only_public_key().0.serialize();
    let mut funder_hash =
        blake2b_simd::Params::new().hash_length(32).to_state().update(funder_pk.as_slice()).finalize().as_bytes().to_vec();
    funder_hash.truncate(20);
    let pledge_per_block = 100i64;
    let initial_block = 900u64;
    let lock_time = 1000u64;
    let constructor_args = vec![
        Expr::Bytes(recipient.to_vec()),
        Expr::Bytes(funder_hash.clone()),
        Expr::Int(pledge_per_block),
        Expr::Bytes(initial_block.to_le_bytes().to_vec()),
    ];

    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let receive_selector = selector_for(&compiled, "receive");
    let reclaim_selector = selector_for(&compiled, "reclaim");
    let passed_blocks = lock_time - initial_block;
    let pledge = passed_blocks as i64 * pledge_per_block;

    let output0_script = build_p2pkh_script(&recipient);
    let mut active_bytecode = Vec::with_capacity(2 + compiled.script.len());
    active_bytecode.extend_from_slice(&0u16.to_be_bytes());
    active_bytecode.extend_from_slice(&compiled.script);
    let mut bc_value = Vec::new();
    bc_value.push(8u8);
    bc_value.extend_from_slice(&lock_time.to_le_bytes());
    bc_value.extend_from_slice(&active_bytecode[9..]);
    let mut hash = blake2b_simd::Params::new().hash_length(32).to_state().update(&bc_value).finalize().as_bytes().to_vec();
    hash.truncate(20);
    let output1_script = build_p2sh20_script(&hash);

    // Test receive() with changeValue > pledgePerBlock + minerFee (else branch).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_i64(receive_selector).unwrap();
    let input_value = 20000u64;
    let output0_value = pledge as u64;
    let output1_value = input_value - pledge as u64 - 1000;

    let result = run_contract_with_tx(
        compiled.script.clone(),
        output0_script.clone(),
        output1_script,
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        lock_time,
    );
    assert!(result.is_ok(), "mecenas_locktime example failed: {}", result.unwrap_err());

    // Test receive() with changeValue <= pledgePerBlock + minerFee (if branch).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_i64(receive_selector).unwrap();

    let input_value = 11000u64;
    let output0_value = input_value - 1000;
    let output1_value = 0u64;

    let result = run_contract_with_tx(
        compiled.script.clone(),
        output0_script,
        compiled.script.clone(),
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        lock_time,
    );
    assert!(result.is_ok(), "mecenas_locktime small change failed: {}", result.unwrap_err());

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([16u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 6000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = funder_key.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test reclaim() function call (build sigscript for reclaim()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(funder_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(reclaim_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "mecenas_locktime reclaim failed: {}", result.unwrap_err());
}

#[test]
fn compiles_p2pkh_example_and_verifies() {
    let source = load_example_source("p2pkh.sil");

    let owner = random_keypair();
    let pubkey_bytes = owner.x_only_public_key().0.serialize();
    let mut pkh =
        blake2b_simd::Params::new().hash_length(32).to_state().update(pubkey_bytes.as_slice()).finalize().as_bytes().to_vec();
    pkh.truncate(20);
    let constructor_args = [Expr::Bytes(pkh.clone())];

    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "spend");

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([5u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 7000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = owner.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test spend() function call (build sigscript for spend()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(pubkey_bytes.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "p2pkh example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_transfer_with_timeout_and_verifies() {
    let source = load_example_source("transfer_with_timeout.sil");

    let sender = random_keypair();
    let recipient = random_keypair();
    let sender_pk = sender.x_only_public_key().0.serialize();
    let recipient_pk = recipient.x_only_public_key().0.serialize();
    let timeout = 1_000i64;
    let constructor_args = vec![Expr::Bytes(sender_pk.to_vec()), Expr::Bytes(recipient_pk.to_vec()), Expr::Int(timeout)];

    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let transfer_selector = selector_for(&compiled, "transfer");
    let timeout_selector = selector_for(&compiled, "timeout");

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([6u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 8_000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = recipient.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test transfer() function call (build sigscript for transfer()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(transfer_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "transfer_with_timeout transfer failed: {}", result.unwrap_err());

    let lock_time = timeout as u64;
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([8u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 9_000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = sender.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test timeout() function call (build sigscript for timeout()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(timeout_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "transfer_with_timeout timeout failed: {}", result.unwrap_err());
}

#[test]
fn compiles_covenant_escrow_example_and_verifies() {
    let source = load_example_source("covenant_escrow.sil");

    let arbiter = random_keypair();
    let arbiter_pk = arbiter.x_only_public_key().0.serialize();
    let mut arbiter_hash =
        blake2b_simd::Params::new().hash_length(32).to_state().update(arbiter_pk.as_slice()).finalize().as_bytes().to_vec();
    arbiter_hash.truncate(20);
    let buyer = [10u8; 20];
    let seller = [11u8; 20];
    let constructor_args = vec![Expr::Bytes(arbiter_hash.clone()), Expr::Bytes(buyer.to_vec()), Expr::Bytes(seller.to_vec())];

    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "spend");

    let input_value = 12_000u64;
    let output0_value = input_value - 1000;
    let output0_script = build_p2pkh_script(&buyer);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([10u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output0 =
        TransactionOutput { value: output0_value, script_public_key: ScriptPublicKey::new(0, output0_script.into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output0.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(input_value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = arbiter.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test spend() function call (build sigscript for spend()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(arbiter_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "covenant escrow example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_covenant_last_will_and_verifies() {
    let source = load_example_source("covenant_last_will.sil");

    let inheritor = random_keypair();
    let cold = random_keypair();
    let hot = random_keypair();
    let inheritor_pk = inheritor.x_only_public_key().0.serialize();
    let cold_pk = cold.x_only_public_key().0.serialize();
    let hot_pk = hot.x_only_public_key().0.serialize();

    let mut inheritor_hash =
        blake2b_simd::Params::new().hash_length(32).to_state().update(inheritor_pk.as_slice()).finalize().as_bytes().to_vec();
    inheritor_hash.truncate(20);
    let mut cold_hash =
        blake2b_simd::Params::new().hash_length(32).to_state().update(cold_pk.as_slice()).finalize().as_bytes().to_vec();
    cold_hash.truncate(20);
    let mut hot_hash = blake2b_simd::Params::new().hash_length(32).to_state().update(hot_pk.as_slice()).finalize().as_bytes().to_vec();
    hot_hash.truncate(20);

    let constructor_args = vec![Expr::Bytes(inheritor_hash.clone()), Expr::Bytes(cold_hash.clone()), Expr::Bytes(hot_hash.clone())];
    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let inherit_selector = selector_for(&compiled, "inherit");
    let cold_selector = selector_for(&compiled, "cold");
    let refresh_selector = selector_for(&compiled, "refresh");

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([12u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 180,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 5_000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = inheritor.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test inherit() function call (build sigscript for inherit()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(inheritor_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(inherit_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "covenant last will inherit failed: {}", result.unwrap_err());

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([13u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 4_000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = cold.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test cold() function call (build sigscript for cold()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(cold_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(cold_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "covenant last will cold failed: {}", result.unwrap_err());

    let input_value = 10_000u64;
    let output0_value = input_value - 1000;

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([14u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output0 = TransactionOutput {
        value: output0_value,
        script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()),
        covenant: None,
    };

    let tx = Transaction::new(1, vec![input.clone()], vec![output0.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(input_value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = hot.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test refresh() function call (build sigscript for refresh()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(hot_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(refresh_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "covenant last will refresh failed: {}", result.unwrap_err());
}

#[test]
fn compiles_covenant_mecenas_example_and_verifies() {
    let source = load_example_source("covenant_mecenas.sil");

    let recipient = [21u8; 20];
    let funder_key = random_keypair();
    let funder_pk = funder_key.x_only_public_key().0.serialize();
    let mut funder_hash =
        blake2b_simd::Params::new().hash_length(32).to_state().update(funder_pk.as_slice()).finalize().as_bytes().to_vec();
    funder_hash.truncate(20);
    let pledge = 2_000i64;
    let period = 10i64;
    let constructor_args = vec![
        Expr::Bytes(recipient.to_vec()),
        Expr::Bytes(funder_hash.clone()),
        Expr::Int(pledge),
        Expr::Int(period),
    ];

    let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
    let receive_selector = selector_for(&compiled, "receive");
    let reclaim_selector = selector_for(&compiled, "reclaim");

    // Test receive() with changeValue > pledge + minerFee (else branch).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_i64(receive_selector).unwrap();

    let input_value = 10000u64;
    let output0_value = pledge as u64;
    let output1_value = input_value - pledge as u64 - 1000;
    let output0_script = build_p2pkh_script(&recipient);

    let result = run_contract_with_tx_sequence(
        compiled.script.clone(),
        output0_script,
        compiled.script.clone(),
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        0,
        period as u64,
    );
    assert!(result.is_ok(), "covenant mecenas example failed: {}", result.unwrap_err());
    // Test receive() with changeValue <= pledge + minerFee (if branch).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_i64(receive_selector).unwrap();

    let input_value = 6000u64;
    let output0_value = input_value - 1000;
    let output1_value = 0u64;
    let output0_script = build_p2pkh_script(&recipient);

    let result = run_contract_with_tx_sequence(
        compiled.script.clone(),
        output0_script,
        compiled.script.clone(),
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        0,
        period as u64,
    );
    assert!(result.is_ok(), "covenant mecenas small change failed: {}", result.unwrap_err());

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([17u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 7_000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = funder_key.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // Test reclaim() function call (build sigscript for reclaim()).
    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(funder_pk.as_slice()).unwrap();
    sigscript.add_data(&signature).unwrap();
    sigscript.add_i64(reclaim_selector).unwrap();
    tx.tx.inputs[0].signature_script = sigscript.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "covenant mecenas reclaim failed: {}", result.unwrap_err());
}
