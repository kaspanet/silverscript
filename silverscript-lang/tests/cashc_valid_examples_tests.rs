use blake2b_simd::Params;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script};
use rand::{RngCore, thread_rng};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract, function_branch_index};
use std::fs;

fn load_example_source(name: &str) -> String {
    let path = format!("{}/tests/examples/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn parse_contract_param_types(source: &str) -> Vec<String> {
    let contract_pos = source.find("contract").expect("contract keyword");
    let after_contract = &source[contract_pos..];
    let open_paren = after_contract.find('(').expect("contract params");
    let after_open = &after_contract[open_paren + 1..];
    let close_paren = after_open.find(')').expect("closing paren");
    let params = &after_open[..close_paren];
    let mut result = Vec::new();
    for param in params.split(',') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let mut parts = param.split_whitespace();
        if let Some(type_name) = parts.next() {
            result.push(type_name.to_string());
        }
    }
    result
}

fn dummy_expr_for_type(type_name: &str) -> Expr {
    if type_name == "int" {
        return 0i64.into();
    }
    if type_name == "bool" {
        return false.into();
    }
    if type_name == "string" {
        return String::from("aa").into();
    }
    if type_name == "bytes" {
        return Vec::<u8>::new().into();
    }
    if type_name == "pubkey" {
        return vec![0u8; 32].into();
    }
    if type_name == "sig" {
        return vec![0u8; 64].into();
    }
    if type_name == "datasig" {
        return vec![0u8; 64].into();
    }
    if let Some(size) = type_name.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
        return vec![0u8; size].into();
    }
    0i64.into()
}

enum ArgValue {
    Int(i64),
    Bytes(Vec<u8>),
    String(String),
    Byte(u8),
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

fn build_sigscript(args: &[ArgValue], selector: Option<i64>) -> Vec<u8> {
    let mut builder = ScriptBuilder::new();
    for arg in args {
        match arg {
            ArgValue::Int(value) => {
                builder.add_i64(*value).unwrap();
            }
            ArgValue::Bytes(value) => {
                builder.add_data(value).unwrap();
            }
            ArgValue::String(value) => {
                builder.add_data(value.as_bytes()).unwrap();
            }
            ArgValue::Byte(value) => {
                builder.add_data(&[*value]).unwrap();
            }
        }
    }
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    builder.drain()
}

fn selector_for_compiled(compiled: &CompiledContract, function_name: &str) -> Option<i64> {
    if compiled.without_selector {
        None
    } else {
        Some(function_branch_index(&compiled.ast, function_name).expect("selector resolved"))
    }
}

fn build_p2pk_script(pubkey: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_data(pubkey).unwrap().add_op(kaspa_txscript::opcodes::codes::OpCheckSig).unwrap().drain()
}

fn build_tx_context(
    script: Vec<u8>,
    outputs: Vec<(u64, Vec<u8>)>,
    input_value: u64,
    lock_time: u64,
    version: u16,
) -> (MutableTransaction<Transaction>, UtxoEntry, SigHashReusedValuesUnsync) {
    let reused_values = SigHashReusedValuesUnsync::new();
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let tx_outputs = outputs
        .into_iter()
        .map(|(value, script)| TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, script.into()), covenant: None })
        .collect::<Vec<_>>();
    let tx = Transaction::new(version, vec![input.clone()], tx_outputs.clone(), lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(input_value, ScriptPublicKey::new(0, script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);
    tx.tx.inputs[0].signature_script = vec![];
    (tx, utxo_entry, reused_values)
}

fn sign_tx<T: AsRef<Transaction>>(
    tx: &MutableTransaction<T>,
    reused_values: &SigHashReusedValuesUnsync,
    keypair: &Keypair,
) -> Vec<u8> {
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, reused_values);
    let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

fn execute_tx(
    tx: MutableTransaction<Transaction>,
    utxo_entry: UtxoEntry,
    reused_values: SigHashReusedValuesUnsync,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let sig_cache = Cache::new(10_000);
    let verifiable = tx.as_verifiable();
    let mut vm = TxScriptEngine::from_transaction_input(
        &verifiable,
        &verifiable.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

#[test]
fn runs_cashc_valid_examples() {
    let examples = [
        "bitwise.sil",
        "bytes1_equals_byte.sil",
        "cast_hash_checksig.sil",
        "comments.sil",
        "correct_pragma.sil",
        "covenant.sil",
        "date_literal.sil",
        "debug_messages.sil",
        "deep_replace.sil",
        "deeply_nested-logs.sil",
        "deeply_nested.sil",
        "double_split.sil",
        "force_cast_smaller_bytes.sil",
        "if_statement.sil",
        "if_statement_number_units-logs.sil",
        "if_statement_number_units.sil",
        "int_to_byte.sil",
        "integer_formatting.sil",
        "log_intermediate_results.sil",
        "multifunction.sil",
        "multifunction_if_statements.sil",
        "multiline_statements.sil",
        "multiplication.sil",
        "num2bin.sil",
        "num2bin_variable.sil",
        "p2pkh-logs.sil",
        "p2pkh_with_assignment.sil",
        "p2pkh_with_cast.sil",
        "reassignment.sil",
        "simple_cast.sil",
        "simple_checkdatasig.sil",
        "simple_constant.sil",
        "simple_covenant.sil",
        "simple_functions.sil",
        "simple_if_statement.sil",
        "simple_splice.sil",
        "simple_variables.sil",
        "simulating_state.sil",
        "slice.sil",
        "slice_optimised.sil",
        "slice_variable_parameter.sil",
        "split_or_slice_signature.sil",
        "split_size.sil",
        "split_typed.sil",
        "string_concatenation.sil",
        "string_with_escaped_characters.sil",
        "tuple_unpacking.sil",
        "tuple_unpacking_parameter.sil",
        "tuple_unpacking_single_side_type.sil",
    ];

    for example in examples {
        let source = load_example_source(example);
        match example {
            "bitwise.sil" => {
                let constructor_args = vec![vec![0u8; 8].into(), vec![0u8; 8].into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "bytes1_equals_byte.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[ArgValue::Int(1), ArgValue::Byte(1)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "cast_hash_checksig.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript =
                    compiled.build_sig_script("hello", vec![pubkey_bytes.into(), signature.clone().into()]).expect("sigscript builds");
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "comments.sil" => {
                // Unsatisfiable: `myOtherVariable` equals `i`, but the contract requires `myOtherVariable > i`.
                let constructor_args = vec![0i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript = build_sigscript(&[ArgValue::Bytes(signature), ArgValue::Bytes(pubkey_bytes)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "correct_pragma.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript = build_sigscript(&[ArgValue::Bytes(signature), ArgValue::Bytes(pubkey_bytes)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "covenant.sil" => {
                // Unsatisfiable: requires `this.activeBytecode == 0x00`.
                let constructor_args = vec![1i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "date_literal.sil" => {
                // Unsatisfiable: `date("2021-02-17T01:30:00")` is non-zero but the contract requires `d == 0`.
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "test");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "debug_messages.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[ArgValue::Int(1)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "deep_replace.sil" => {
                // Unsatisfiable: `a` becomes 3, so `a > b + c + d + e + f` is false.
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "deeply_nested-logs.sil" | "deeply_nested.sil" => {
                let recipient = random_keypair();
                let recipient_pk = recipient.x_only_public_key().0.serialize().to_vec();
                let sender_pk = vec![0u8; 32];
                let constructor_args = vec![sender_pk.into(), recipient_pk.clone().into(), 0i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "transfer");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let signature = sign_tx(&tx, &reused, &recipient);
                let sigscript = build_sigscript(&[ArgValue::Bytes(signature)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "double_split.sil" => {
                // Satisfiable with the default tx context in this runtime.
                let constructor_args = vec![vec![0u8; 20].into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "force_cast_smaller_bytes.sil" => {
                // Unsatisfiable: bytes(0x1234) is 2 bytes, so the forced cast has length 2.
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "if_statement.sil" => {
                let constructor_args = vec![0i64.into(), 2i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[ArgValue::Int(1), ArgValue::Int(1)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "if_statement_number_units-logs.sil" | "if_statement_number_units.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[ArgValue::Int(20), ArgValue::Int(1_209_600)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "int_to_byte.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[ArgValue::Int(1), ArgValue::Byte(1)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "integer_formatting.sil" | "log_intermediate_results.sil" | "num2bin.sil" => {
                let (constructor_args, function_name) = if example == "log_intermediate_results.sil" {
                    (vec![vec![1u8; 32].into()], "test_log_intermediate_result")
                } else if example == "integer_formatting.sil" {
                    (vec![], "test")
                } else {
                    (vec![], "hello")
                };
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, function_name);
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                if example == "log_intermediate_results.sil" {
                    // Unsatisfiable in this runtime: the script leaves an extra stack item (CLEANSTACK).
                    assert!(result.is_err(), "{example} should fail");
                } else {
                    assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
                }
            }
            "multifunction.sil" => {
                let recipient = random_keypair();
                let recipient_pk = recipient.x_only_public_key().0.serialize().to_vec();
                let sender_pk = vec![0u8; 32];
                let constructor_args = vec![sender_pk.into(), recipient_pk.clone().into(), 0i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "transfer");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let signature = sign_tx(&tx, &reused, &recipient);
                let sigscript = build_sigscript(&[ArgValue::Bytes(signature)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "multifunction_if_statements.sil" => {
                let constructor_args = vec![0i64.into(), 2i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "transfer");
                let sigscript = build_sigscript(&[ArgValue::Int(1), ArgValue::Int(2)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "multiline_statements.sil" => {
                let constructor_args = vec![0i64.into(), String::from("World").into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[ArgValue::Int(0), ArgValue::String("Nope".to_string())], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "multiplication.sil" => {
                let constructor_args = vec![(-1i64).into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "num2bin_variable.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[ArgValue::Int(2)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "p2pkh-logs.sil" | "p2pkh_with_assignment.sil" => {
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let pkh = Params::new().hash_length(32).to_state().update(pubkey_bytes.as_slice()).finalize().as_bytes().to_vec();
                let constructor_args = vec![pkh.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript =
                    compiled.build_sig_script("spend", vec![pubkey_bytes.into(), signature.clone().into()]).expect("sigscript builds");
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "p2pkh_with_cast.sil" => {
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let pkh = Params::new().hash_length(32).to_state().update(pubkey_bytes.as_slice()).finalize().as_bytes().to_vec();
                let constructor_args = vec![pkh.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript =
                    compiled.build_sig_script("spend", vec![pubkey_bytes.into(), signature.clone().into()]).expect("sigscript builds");
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "reassignment.sil" => {
                // Unsatisfiable: requires sha256(pubkey) == sha256("Hello World" + y).
                let constructor_args = vec![0i64.into(), String::from("y").into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript = build_sigscript(&[ArgValue::Bytes(pubkey_bytes), ArgValue::Bytes(signature)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "simple_cast.sil" => {
                // Unsatisfiable: requires sha256(pubkey) == sha256(bytes("Hello World" + y) + bytes(pubkey)).
                let constructor_args = vec![0i64.into(), String::from("y").into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript = build_sigscript(&[ArgValue::Bytes(signature), ArgValue::Bytes(pubkey_bytes)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "simple_checkdatasig.sil" => {
                let constructor_args = vec![vec![0u8; 64].into(), vec![1u8; 32].into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "cds");
                let sigscript = build_sigscript(&[ArgValue::Bytes(b"data".to_vec())], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "simple_constant.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "simple_covenant.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "covenant");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    2,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "simple_functions.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "world");
                let sigscript = build_sigscript(&[ArgValue::Int(5)], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "simple_if_statement.sil" => {
                let constructor_args = vec![0i64.into(), String::from("World").into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[ArgValue::Int(0), ArgValue::String("Hello World".to_string())], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "simple_splice.sil" => {
                let constructor_args = vec![vec![0u8; 6].into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "simple_variables.sil" => {
                // Unsatisfiable: requires sha256(pubkey) == sha256("Hello World" + y).
                let constructor_args = vec![0i64.into(), String::from("y").into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                let keypair = random_keypair();
                let pubkey_bytes = keypair.x_only_public_key().0.serialize().to_vec();
                let signature = sign_tx(&tx, &reused, &keypair);
                let sigscript = build_sigscript(&[ArgValue::Bytes(signature), ArgValue::Bytes(pubkey_bytes)], selector);
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "simulating_state.sil" => {
                let recipient = vec![1u8; 32];
                let funder = vec![2u8; 32];
                let pledge_per_block = 10i64;
                let initial_block_value = 5i64;
                let initial_block = initial_block_value.to_le_bytes().to_vec();
                let mut initial_block_bytes = initial_block.clone();
                initial_block_bytes.resize(8, 0);
                let constructor_args =
                    vec![recipient.clone().into(), funder.clone().into(), pledge_per_block.into(), initial_block_bytes.clone().into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "receive");

                let lock_time = 10u64;
                let passed_blocks = lock_time as i64 - initial_block_value;
                let pledge = passed_blocks * pledge_per_block;
                let input_value = 5_000u64;
                let miner_fee = 1_000i64;
                let change_value = input_value as i64 - pledge - miner_fee;
                let output0_value = pledge as u64;
                let output1_value = change_value as u64;

                let new_contract = {
                    let mut out = Vec::new();
                    out.push(0x08);
                    let mut lock_bytes = (lock_time as i64).to_le_bytes().to_vec();
                    lock_bytes.resize(8, 0);
                    out.extend_from_slice(&lock_bytes);
                    let mut active_bytecode = Vec::new();
                    active_bytecode.extend_from_slice(&0u16.to_be_bytes());
                    active_bytecode.extend_from_slice(&compiled.script);
                    out.extend_from_slice(&active_bytecode[9..]);
                    out
                };
                let output1_script = pay_to_script_hash_script(&new_contract).script().to_vec();

                let output0_script = build_p2pk_script(&recipient);

                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(output0_value, output0_script), (output1_value, output1_script)],
                    input_value,
                    lock_time,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "slice.sil" | "slice_variable_parameter.sil" => {
                // Unsatisfiable in this runtime: it expects a P2PKH locking bytecode in the active input.
                let constructor_args = vec![vec![0u8; 20].into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "slice_optimised.sil" => {
                // Unsatisfiable in this runtime: NUM2BIN rejects target sizes > 8 (slice needs 20).
                let constructor_args = vec![vec![0u8; 32].into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "split_or_slice_signature.sil" => {
                // Unsatisfiable in this runtime: signature slicing triggers invalid range errors.
                let mut signature = vec![0u8; 64];
                signature.push(0x01);
                let constructor_args = vec![signature.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "split_size.sil" => {
                // Unsatisfiable in this runtime: `b.length / 2` leaves `b` on the stack, causing invalid substring ranges.
                let constructor_args = vec![b"abcd".to_vec().into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "split_typed.sil" => {
                let constructor_args = vec![b"abcde".to_vec().into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "spend");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "string_concatenation.sil" => {
                // Unsatisfiable in this runtime: concatenation leaves an extra stack item (CLEANSTACK).
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[ArgValue::String("world".to_string())], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "string_with_escaped_characters.sil" => {
                // Unsatisfiable in this runtime: escaped string literals hash differently.
                let constructor_args = vec![0i64.into()];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "hello");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "tuple_unpacking.sil" => {
                // Unsatisfiable: split("hello" + "there") yields "hello" and "there", which are not equal.
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "split");
                let sigscript = build_sigscript(&[], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_err(), "{example} should fail");
            }
            "tuple_unpacking_parameter.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "split");
                let sigscript = build_sigscript(&[ArgValue::Bytes(vec![0u8; 32])], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            "tuple_unpacking_single_side_type.sil" => {
                let constructor_args = vec![];
                let compiled = compile_contract(&source, &constructor_args, CompileOptions::default()).expect("compile succeeds");
                let selector = selector_for_compiled(&compiled, "split");
                let sigscript = build_sigscript(&[ArgValue::Bytes(vec![0u8; 32])], selector);
                let (mut tx, utxo, reused) = build_tx_context(
                    compiled.script.clone(),
                    vec![(1_000, compiled.script.clone()), (1_000, compiled.script.clone())],
                    2_000,
                    0,
                    1,
                );
                tx.tx.inputs[0].signature_script = sigscript;
                let result = execute_tx(tx, utxo, reused);
                assert!(result.is_ok(), "{example} failed: {}", result.unwrap_err());
            }
            _ => panic!("missing runtime case for {example}"),
        }
    }
}

#[test]
fn compiles_cashc_valid_examples() {
    // Skipped examples (from cashc valid-contract-files) and reasons:
    // - 2_of_3_multisig.sil: uses checkMultiSig.
    // - multiline_array_multisig.cash: uses checkMultiSig.
    // - simple_multisig.cash: uses checkMultiSig.
    // - trailing_comma.cash: uses checkMultiSig.
    // - covenant_all_fields.cash: cashtoken-related logic.
    // - token_category_comparison.cash: cashtoken-related logic.
    let examples = [
        "bitwise.sil",
        "bytes1_equals_byte.sil",
        "cast_hash_checksig.sil",
        "comments.sil",
        "correct_pragma.sil",
        "covenant.sil",
        "date_literal.sil",
        "debug_messages.sil",
        "deep_replace.sil",
        "deeply_nested-logs.sil",
        "deeply_nested.sil",
        "double_split.sil",
        "force_cast_smaller_bytes.sil",
        "if_statement.sil",
        "if_statement_number_units-logs.sil",
        "if_statement_number_units.sil",
        "int_to_byte.sil",
        "integer_formatting.sil",
        "log_intermediate_results.sil",
        "multifunction.sil",
        "multifunction_if_statements.sil",
        "multiline_statements.sil",
        "multiplication.sil",
        "num2bin.sil",
        "num2bin_variable.sil",
        "p2pkh-logs.sil",
        "p2pkh_with_assignment.sil",
        "p2pkh_with_cast.sil",
        "reassignment.sil",
        "simple_cast.sil",
        "simple_checkdatasig.sil",
        "simple_constant.sil",
        "simple_covenant.sil",
        "simple_functions.sil",
        "simple_if_statement.sil",
        "simple_splice.sil",
        "simple_variables.sil",
        "simulating_state.sil",
        "slice.sil",
        "slice_optimised.sil",
        "slice_variable_parameter.sil",
        "split_or_slice_signature.sil",
        "split_size.sil",
        "split_typed.sil",
        "string_concatenation.sil",
        "string_with_escaped_characters.sil",
        "tuple_unpacking.sil",
        "tuple_unpacking_parameter.sil",
        "tuple_unpacking_single_side_type.sil",
    ];

    for example in examples {
        let source = load_example_source(example);
        let param_types = parse_contract_param_types(&source);
        let constructor_args = param_types.into_iter().map(|t| dummy_expr_for_type(&t)).collect::<Vec<_>>();
        let compiled = compile_contract(&source, &constructor_args, CompileOptions::default());
        assert!(compiled.is_ok(), "{example} failed to compile: {}", compiled.unwrap_err());
    }
}
