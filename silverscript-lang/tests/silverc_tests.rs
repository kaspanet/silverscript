use std::fs;
use std::path::PathBuf;
use std::process::Command;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use rand::RngCore;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompiledContract, function_branch_index};

fn temp_dir(name: &str) -> PathBuf {
    let mut rng = rand::thread_rng();
    let dir = std::env::temp_dir().join(format!("silverc_test_{name}_{}", rng.next_u64()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_script_with_selector(script: Vec<u8>, selector: Option<i64>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let mut builder = ScriptBuilder::new();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    let sigscript = builder.drain();
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
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

#[test]
fn silverc_defaults_output_path_and_empty_ctor_args() {
    let dir = temp_dir("default");
    let src_path = dir.join("basic.sil");
    let source = r#"
        contract Basic() {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    fs::write(&src_path, source).expect("write source");

    let status = Command::new(env!("CARGO_BIN_EXE_silverc")).arg(src_path.to_str().unwrap()).status().expect("run silverc");
    assert!(status.success());

    let out_path = dir.join("basic.json");
    let json = fs::read_to_string(&out_path).expect("read output");
    let compiled: CompiledContract = serde_json::from_str(&json).expect("parse compiled contract");
    assert_eq!(compiled.contract_name, "Basic");
}

#[test]
fn silverc_accepts_constructor_args_and_output_flag() {
    let dir = temp_dir("ctor");
    let src_path = dir.join("with_ctor.sil");
    let out_path = dir.join("out.json");
    let ctor_path = dir.join("ctor.json");
    let source = r#"
        contract WithCtor(int a) {
            entrypoint function main() {
                require(a == 7);
            }
        }
    "#;
    fs::write(&src_path, source).expect("write source");
    let ctor_args = vec![Expr::Int(7)];
    fs::write(&ctor_path, serde_json::to_string(&ctor_args).expect("serialize ctor args")).expect("write ctor args");

    let status = Command::new(env!("CARGO_BIN_EXE_silverc"))
        .arg(src_path.to_str().unwrap())
        .arg("--constructor-args")
        .arg(ctor_path.to_str().unwrap())
        .arg("-o")
        .arg(out_path.to_str().unwrap())
        .status()
        .expect("run silverc");
    assert!(status.success());

    let json = fs::read_to_string(&out_path).expect("read output");
    let compiled: CompiledContract = serde_json::from_str(&json).expect("parse compiled contract");
    assert_eq!(compiled.contract_name, "WithCtor");
    let selector =
        if compiled.without_selector { None } else { Some(function_branch_index(&compiled.ast, "main").expect("selector resolved")) };
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}
