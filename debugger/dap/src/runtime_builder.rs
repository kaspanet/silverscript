use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::ptr::NonNull;

use debugger_session::args::{parse_call_args, parse_ctor_args, parse_hex_bytes};
use debugger_session::session::{DebugEngine, DebugSession, ShadowTxContext};
use debugger_session::test_runner::{TestTxInputScenarioResolved, TestTxOutputScenarioResolved, TestTxScenarioResolved};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, SigCacheKey, pay_to_script_hash_script};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_lang::ast::{ContractAst, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

use crate::launch_config::{ResolvedLaunchConfig, resolve_arg_input};

pub struct BuiltLaunch {
    pub runtime: OwnedRuntime,
    pub source_path: PathBuf,
    pub source_name: String,
    pub stop_on_entry: bool,
    pub no_debug: bool,
}

pub fn build_launch(config: ResolvedLaunchConfig) -> Result<BuiltLaunch, String> {
    let source_owned = fs::read_to_string(&config.script_path)
        .map_err(|err| format!("failed to read source '{}': {err}", config.script_path.display()))?;
    let source_box = source_owned.into_boxed_str();
    let source_ptr = Box::into_raw(source_box);
    let source: &'static str = unsafe { &*source_ptr };

    let parsed_contract = parse_contract_ast(source).map_err(|err| format!("parse error: {err}"))?;
    let ctor_param_names = parsed_contract.params.iter().map(|param| param.name.clone()).collect::<Vec<_>>();
    let raw_ctor_args = resolve_arg_input(config.constructor_args.as_ref(), &ctor_param_names, "constructor arguments")?;
    let ctor_args = parse_ctor_args(&parsed_contract, &raw_ctor_args)?;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &ctor_args, compile_opts).map_err(|err| format!("compile error: {err}"))?;
    let selected_name = resolve_entrypoint_name(&compiled.abi, config.function)?;
    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| format!("function '{}' not found", selected_name))?;

    let input_types = entry.inputs.iter().map(|input| input.type_name.clone()).collect::<Vec<_>>();
    let input_names = entry.inputs.iter().map(|input| input.name.clone()).collect::<Vec<_>>();
    let raw_args = resolve_arg_input(config.args.as_ref(), &input_names, "function arguments")?;
    let tx = config.tx.unwrap_or_else(default_tx_scenario);

    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    ctor_script_cache.insert(raw_ctor_args.clone(), compiled.script.clone());

    let resolved_raw_args = resolve_auto_sign_args(
        &input_types,
        &input_names,
        &raw_args,
        source,
        &parsed_contract,
        &raw_ctor_args,
        &tx,
        &mut ctor_script_cache,
    )?;
    let typed_args = parse_call_args(&input_types, &resolved_raw_args)?;
    let sigscript =
        compiled.build_sig_script(&selected_name, typed_args).map_err(|err| format!("failed to build sigscript: {err}"))?;

    let tx_context = build_tx_context(source, &parsed_contract, &raw_ctor_args, &tx, Some(&sigscript), &mut ctor_script_cache)?;
    let BuiltTxContext {
        transaction,
        populated_tx,
        populated_tx_ptr,
        covenants_ctx,
        covenants_ctx_ptr,
        active_input,
        active_utxo,
        reused_values,
        reused_values_ptr,
    } = tx_context;

    let cache_ptr = Box::into_raw(Box::new(Cache::new(10_000)));
    let cache = unsafe { &*cache_ptr };
    let flags = EngineFlags { covenants_enabled: true };
    let ctx = EngineCtx::new(cache).with_reused(reused_values).with_covenants_ctx(covenants_ctx);
    let engine = DebugEngine::from_transaction_input(populated_tx, active_input, tx.active_input_index, active_utxo, ctx, flags);
    let shadow_tx_context = ShadowTxContext {
        tx: populated_tx,
        input: active_input,
        input_index: tx.active_input_index,
        utxo_entry: active_utxo,
        covenants_ctx,
    };
    let session = DebugSession::full(&sigscript, &compiled.script, source, compiled.debug_info.clone(), engine)
        .map_err(|err| format!("failed to create debug session: {err}"))?
        .with_shadow_tx_context(shadow_tx_context);
    let runtime = OwnedRuntime {
        session,
        _backing: RuntimeBacking {
            source: Some(unsafe { NonNull::new_unchecked(source_ptr) }),
            cache: Some(unsafe { NonNull::new_unchecked(cache_ptr) }),
            transaction,
            populated_tx: populated_tx_ptr,
            covenants_ctx: covenants_ctx_ptr,
            reused_values: reused_values_ptr,
        },
    };

    let source_name = config
        .script_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| config.script_path.to_string_lossy().to_string());

    Ok(BuiltLaunch {
        runtime,
        source_path: config.script_path,
        source_name,
        stop_on_entry: config.stop_on_entry,
        no_debug: config.no_debug,
    })
}

fn resolve_entrypoint_name(
    abi: &[silverscript_lang::compiler::FunctionAbiEntry],
    requested: Option<String>,
) -> Result<String, String> {
    if let Some(function) = requested {
        return Ok(function);
    }

    match abi {
        [] => Err("contract has no functions".to_string()),
        [entry] => Ok(entry.name.clone()),
        entries => {
            let names = entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>().join(", ");
            Err(format!("launch config must include 'function' for multi-entrypoint contract (available: {names})"))
        }
    }
}

fn default_tx_scenario() -> TestTxScenarioResolved {
    TestTxScenarioResolved {
        version: 1,
        lock_time: 0,
        active_input_index: 0,
        inputs: vec![TestTxInputScenarioResolved {
            prev_txid: None,
            prev_index: 0,
            sequence: 0,
            sig_op_count: 100,
            utxo_value: 5000,
            covenant_id: None,
            constructor_args: None,
            signature_script_hex: None,
            utxo_script_hex: None,
        }],
        outputs: vec![TestTxOutputScenarioResolved {
            value: 5000,
            covenant_id: None,
            authorizing_input: None,
            constructor_args: None,
            script_hex: None,
            p2pk_pubkey: None,
        }],
    }
}

fn resolve_auto_sign_args(
    input_types: &[String],
    input_names: &[String],
    raw_args: &[String],
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    tx: &TestTxScenarioResolved,
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<Vec<String>, String> {
    let mut resolved = raw_args.to_vec();
    let mut has_secret_sig = false;

    for (index, (type_name, raw)) in input_types.iter().zip(raw_args.iter()).enumerate() {
        if type_name != "sig" && type_name != "datasig" {
            continue;
        }
        let bytes = parse_hex_bytes(raw)?;
        if type_name == "sig" && bytes.len() == 32 {
            has_secret_sig = true;
            continue;
        }
        if type_name == "datasig" && bytes.len() == 32 {
            return Err(format!(
                "function argument '{}' uses a 32-byte secret key for datasig, but debugger launch only auto-signs 'sig' arguments",
                input_names[index]
            ));
        }
    }

    if !has_secret_sig {
        return Ok(resolved);
    }

    let signing_tx = build_tx_context(source, parsed_contract, raw_ctor_args, tx, None, ctor_script_cache)?;

    for (index, type_name) in input_types.iter().enumerate() {
        if type_name != "sig" {
            continue;
        }
        let secret_bytes = parse_hex_bytes(&resolved[index])?;
        if secret_bytes.len() != 32 {
            continue;
        }
        resolved[index] = sign_tx_input(&secret_bytes, signing_tx.populated_tx, tx.active_input_index, signing_tx.reused_values)
            .map_err(|err| format!("failed to auto-sign argument '{}': {err}", input_names[index]))?;
    }

    Ok(resolved)
}

struct BuiltTxContext {
    transaction: NonNull<Transaction>,
    populated_tx: &'static PopulatedTransaction<'static>,
    populated_tx_ptr: NonNull<PopulatedTransaction<'static>>,
    covenants_ctx: &'static CovenantsContext,
    covenants_ctx_ptr: NonNull<CovenantsContext>,
    active_input: &'static TransactionInput,
    active_utxo: &'static UtxoEntry,
    reused_values: &'static SigHashReusedValuesUnsync,
    reused_values_ptr: NonNull<SigHashReusedValuesUnsync>,
}

pub struct OwnedRuntime {
    pub session: DebugSession<'static, 'static>,
    _backing: RuntimeBacking,
}

struct RuntimeBacking {
    source: Option<NonNull<str>>,
    cache: Option<NonNull<Cache<SigCacheKey, bool>>>,
    transaction: NonNull<Transaction>,
    populated_tx: NonNull<PopulatedTransaction<'static>>,
    covenants_ctx: NonNull<CovenantsContext>,
    reused_values: NonNull<SigHashReusedValuesUnsync>,
}

impl OwnedRuntime {
    pub fn session(&self) -> &DebugSession<'static, 'static> {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut DebugSession<'static, 'static> {
        &mut self.session
    }
}

impl Drop for RuntimeBacking {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.covenants_ctx.as_ptr()));
            drop(Box::from_raw(self.populated_tx.as_ptr()));
            drop(Box::from_raw(self.transaction.as_ptr()));
            drop(Box::from_raw(self.reused_values.as_ptr()));
            if let Some(cache) = self.cache.take() {
                drop(Box::from_raw(cache.as_ptr()));
            }
            if let Some(source) = self.source.take() {
                drop(Box::from_raw(source.as_ptr()));
            }
        }
    }
}

fn build_tx_context(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    tx: &TestTxScenarioResolved,
    active_sigscript: Option<&[u8]>,
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<BuiltTxContext, String> {
    if tx.inputs.is_empty() {
        return Err("tx.inputs must contain at least one input".to_string());
    }
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()));
    }

    let mut tx_inputs = Vec::with_capacity(tx.inputs.len());
    let mut utxo_specs = Vec::with_capacity(tx.inputs.len());

    for (input_idx, input) in tx.inputs.iter().enumerate() {
        let mut default_prev_txid = [0u8; 32];
        default_prev_txid.fill(input_idx as u8);
        let prev_txid = if let Some(raw_txid) = input.prev_txid.as_deref() {
            parse_txid32(raw_txid)?
        } else {
            TransactionId::from_bytes(default_prev_txid)
        };

        let input_ctor_raw = input.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
        let redeem_script = if input.utxo_script_hex.is_none() {
            Some(compile_script_for_ctor_args(source, parsed_contract, &input_ctor_raw, ctor_script_cache)?)
        } else {
            None
        };

        let signature_script = if let Some(raw_sig) = input.signature_script_hex.as_deref() {
            parse_hex_bytes(raw_sig)?
        } else if input_idx == tx.active_input_index {
            match (active_sigscript, redeem_script.as_ref()) {
                (Some(action), Some(redeem)) => combine_action_and_redeem(action, redeem)?,
                (Some(action), None) => action.to_vec(),
                (None, _) => vec![],
            }
        } else if let Some(redeem) = redeem_script.as_ref() {
            sigscript_push_script(redeem)
        } else {
            vec![]
        };

        let utxo_spk = if let Some(raw_script) = input.utxo_script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
        } else {
            let redeem = redeem_script
                .as_ref()
                .ok_or_else(|| "internal error: missing redeem script for tx input without utxo_script_hex".to_string())?;
            pay_to_script_hash_script(redeem)
        };

        let covenant_id = input.covenant_id.as_deref().map(parse_hash32).transpose()?;

        tx_inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: prev_txid, index: input.prev_index },
            signature_script,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
        });
        utxo_specs.push((input.utxo_value, utxo_spk, covenant_id));
    }

    let mut tx_outputs = Vec::with_capacity(tx.outputs.len());
    for output in tx.outputs.iter() {
        tx_outputs.push(build_output(source, parsed_contract, output, raw_ctor_args, tx.active_input_index, ctor_script_cache)?);
    }

    let transaction =
        Box::into_raw(Box::new(Transaction::new(tx.version, tx_inputs, tx_outputs, tx.lock_time, Default::default(), 0, vec![])));
    let transaction_ref = unsafe { &*transaction };
    let reused_values = Box::into_raw(Box::new(SigHashReusedValuesUnsync::new()));
    let reused_values_ref = unsafe { &*reused_values };
    let utxos = utxo_specs
        .into_iter()
        .map(|(value, spk, covenant_id)| UtxoEntry::new(value, spk, 0, transaction_ref.is_coinbase(), covenant_id))
        .collect::<Vec<_>>();
    let populated_tx = Box::into_raw(Box::new(PopulatedTransaction::new(transaction_ref, utxos)));
    let populated_tx_ref = unsafe { &*populated_tx };
    let covenants_ctx = Box::into_raw(Box::new(
        CovenantsContext::from_tx(populated_tx_ref).map_err(|err| format!("failed to build covenant context: {err}"))?,
    ));
    let covenants_ctx_ref = unsafe { &*covenants_ctx };
    let active_input = transaction_ref
        .inputs
        .get(tx.active_input_index)
        .ok_or_else(|| format!("missing tx input at index {}", tx.active_input_index))?;
    let active_utxo = populated_tx_ref
        .utxo(tx.active_input_index)
        .ok_or_else(|| format!("missing utxo entry for input {}", tx.active_input_index))?;

    Ok(BuiltTxContext {
        transaction: unsafe { NonNull::new_unchecked(transaction) },
        populated_tx: populated_tx_ref,
        populated_tx_ptr: unsafe { NonNull::new_unchecked(populated_tx) },
        covenants_ctx: covenants_ctx_ref,
        covenants_ctx_ptr: unsafe { NonNull::new_unchecked(covenants_ctx) },
        active_input,
        active_utxo,
        reused_values: reused_values_ref,
        reused_values_ptr: unsafe { NonNull::new_unchecked(reused_values) },
    })
}

fn build_output(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    output: &TestTxOutputScenarioResolved,
    raw_ctor_args: &[String],
    active_input_index: usize,
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<TransactionOutput, String> {
    let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
        ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
    } else if let Some(raw_pubkey) = output.p2pk_pubkey.as_deref() {
        let pubkey_bytes = parse_hex_bytes(raw_pubkey)?;
        ScriptPublicKey::new(0, build_p2pk_script(&pubkey_bytes).into())
    } else {
        let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
        let output_script = compile_script_for_ctor_args(source, parsed_contract, &output_ctor_raw, ctor_script_cache)?;
        pay_to_script_hash_script(&output_script)
    };

    let covenant = output
        .covenant_id
        .as_deref()
        .map(|raw| -> Result<CovenantBinding, String> {
            Ok(CovenantBinding {
                authorizing_input: output.authorizing_input.unwrap_or(active_input_index as u16),
                covenant_id: parse_hash32(raw)?,
            })
        })
        .transpose()?;

    Ok(TransactionOutput { value: output.value, script_public_key, covenant })
}

fn compile_script_for_ctor_args(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    if let Some(script) = cache.get(raw_ctor_args) {
        return Ok(script.clone());
    }
    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    let compiled = compile_contract(source, &ctor_args, CompileOptions::default()).map_err(|err| format!("compile error: {err}"))?;
    cache.insert(raw_ctor_args.to_vec(), compiled.script.clone());
    Ok(compiled.script)
}

fn parse_hash32(raw: &str) -> Result<Hash, String> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() != 32 {
        return Err(format!("hash expects 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(Hash::from_bytes(array))
}

fn parse_txid32(raw: &str) -> Result<TransactionId, String> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() != 32 {
        return Err(format!("txid expects 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(TransactionId::from_bytes(array))
}

fn build_p2pk_script(pubkey: &[u8]) -> Vec<u8> {
    ScriptBuilder::new()
        .add_data(pubkey)
        .expect("push pubkey")
        .add_op(kaspa_txscript::opcodes::codes::OpCheckSig)
        .expect("add OpCheckSig")
        .drain()
}

fn sigscript_push_script(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_data(script).expect("push script data").drain()
}

fn combine_action_and_redeem(action: &[u8], redeem_script: &[u8]) -> Result<Vec<u8>, String> {
    let mut builder = ScriptBuilder::new();
    builder.add_ops(action).map_err(|err| err.to_string())?;
    builder.add_data(redeem_script).map_err(|err| err.to_string())?;
    Ok(builder.drain())
}

fn sign_tx_input(
    secret_key_bytes: &[u8],
    tx: &PopulatedTransaction<'_>,
    input_index: usize,
    reused_values: &SigHashReusedValuesUnsync,
) -> Result<String, String> {
    let secret_key = SecretKey::from_slice(secret_key_bytes).map_err(|err| format!("invalid secret key: {err}"))?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let sig_hash = calc_schnorr_signature_hash(tx, input_index, SIG_HASH_ALL, reused_values);
    let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice()).map_err(|err| format!("invalid sighash digest: {err}"))?;
    let sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());
    Ok(format!("0x{}", encode_hex(&signature)))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::launch_config::ResolvedLaunchConfig;
    use debugger_session::test_runner::{TestTxInputScenarioResolved, TestTxOutputScenarioResolved, TestTxScenarioResolved};

    use super::build_launch;

    const SIMPLE_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract Simple() {
    entrypoint function main() {
        int a = 1;
        require(a == 1);
    }
}
"#;

    struct TempScript {
        path: PathBuf,
    }

    impl TempScript {
        fn new(source: &str) -> Self {
            let unique = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or_default();
            let path = std::env::temp_dir().join(format!("silverscript-runtime-builder-{unique}.sil"));
            fs::write(&path, source).expect("failed to write temp script");
            Self { path }
        }
    }

    impl Drop for TempScript {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn build_launch_rejects_invalid_tx_override() {
        let script = TempScript::new(SIMPLE_SCRIPT);
        let config = ResolvedLaunchConfig {
            script_path: script.path.clone(),
            function: Some("main".to_string()),
            constructor_args: None,
            args: None,
            tx: Some(TestTxScenarioResolved {
                version: 1,
                lock_time: 0,
                active_input_index: 1,
                inputs: vec![TestTxInputScenarioResolved {
                    prev_txid: None,
                    prev_index: 0,
                    sequence: 0,
                    sig_op_count: 100,
                    utxo_value: 5000,
                    covenant_id: None,
                    constructor_args: None,
                    signature_script_hex: None,
                    utxo_script_hex: None,
                }],
                outputs: vec![TestTxOutputScenarioResolved {
                    value: 5000,
                    covenant_id: None,
                    authorizing_input: None,
                    constructor_args: None,
                    script_hex: None,
                    p2pk_pubkey: None,
                }],
            }),
            no_debug: false,
            stop_on_entry: true,
        };

        let err = match build_launch(config) {
            Ok(_) => panic!("invalid tx override should fail"),
            Err(err) => err,
        };
        assert!(err.contains("active_input_index 1 out of range"), "unexpected error: {err}");
    }
}
