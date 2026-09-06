use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::ptr::NonNull;

use debugger_session::args::{parse_call_args, parse_call_args_with_prefix, parse_ctor_args, parse_hex_bytes, parse_state_value};
use debugger_session::covenant::{CovenantBinding as DebugCovenantBinding, ResolvedCovenantCallTarget, resolve_covenant_call_target};
use debugger_session::session::{DebugEngine, DebugSession, DebugValue, ShadowTxContext};
use debugger_session::test_runner::{TestTxInputScenarioResolved, TestTxOutputScenarioResolved, TestTxScenarioResolved};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, TxInputMass, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, SigCacheKey, pay_to_script_hash_script};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, rand::thread_rng};
use serde_json::Value;
use silverscript_lang::ast::{ContractAst, Expr, ExprKind, StateFieldExpr, TypeBase, TypeRef, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract, compile_contract_ast};

use crate::launch_config::{ArgInput, ResolvedLaunchConfig, resolve_arg_input};

pub struct BuiltLaunch {
    pub runtime: OwnedRuntime,
    pub source_path: PathBuf,
    pub source_name: String,
    pub stop_on_entry: bool,
    pub no_debug: bool,
}

pub fn build_launch(mut config: ResolvedLaunchConfig) -> Result<BuiltLaunch, String> {
    resolve_launch_identities(&mut config)?;

    let source_owned = fs::read_to_string(&config.script_path)
        .map_err(|err| format!("failed to read source '{}': {err}", config.script_path.display()))?;
    let source_box = source_owned.into_boxed_str();
    let source_ptr = Box::into_raw(source_box);
    let source: &'static str = unsafe { &*source_ptr };

    let parsed_contract = parse_contract_ast(source).map_err(|err| format!("parse error: {err}"))?;
    let ctor_param_names = parsed_contract.params.iter().map(|param| param.name.clone()).collect::<Vec<_>>();
    let mut raw_ctor_args = resolve_arg_input(config.constructor_args.as_ref(), &ctor_param_names, "constructor arguments")?;
    let tx = config.tx.unwrap_or_else(default_tx_scenario);
    if raw_ctor_args.is_empty()
        && let Some(active_input_ctor_args) = tx.inputs.get(tx.active_input_index).and_then(|input| input.constructor_args.clone())
    {
        raw_ctor_args = active_input_ctor_args;
    }
    let ctor_args = parse_ctor_args(&parsed_contract, &raw_ctor_args)?;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &ctor_args, compile_opts).map_err(|err| format!("compile error: {err}"))?;
    let selected_name = resolve_entrypoint_name(&compiled.abi, config.function)?;
    let selected_function = parsed_contract
        .functions
        .iter()
        .find(|function| function.name == selected_name)
        .ok_or_else(|| format!("function '{selected_name}' not found"))?;
    let input_names = selected_function.params.iter().map(|param| param.name.clone()).collect::<Vec<_>>();
    let raw_args = resolve_arg_input(config.args.as_ref(), &input_names, "function arguments")?;

    if tx.inputs.is_empty() {
        return Err("tx.inputs must contain at least one input".to_string());
    }
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()));
    }

    let covenant_target = resolve_covenant_call_target(&parsed_contract, &compiled, &selected_name);
    let covenant_binding = covenant_target.as_ref().map(|target| target.binding);
    let enable_covenant_session_mode = covenant_target.is_some();

    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    let mut ctor_state_cache = HashMap::<Vec<String>, DebugValue>::new();
    let mut explicit_state_cache = HashMap::<String, DebugValue>::new();
    ctor_script_cache.insert(raw_ctor_args.clone(), compiled.script.clone());
    if !parsed_contract.fields.is_empty() {
        let root_state = resolve_state_for_ctor_args(&parsed_contract, &raw_ctor_args, &mut ctor_state_cache)?;
        ctor_state_cache.insert(raw_ctor_args.clone(), root_state);
    }

    let mut input_prev_outpoints = Vec::with_capacity(tx.inputs.len());
    let mut input_sequences = Vec::with_capacity(tx.inputs.len());
    let mut input_sig_op_counts = Vec::with_capacity(tx.inputs.len());
    let mut explicit_input_sigs = Vec::with_capacity(tx.inputs.len());
    let mut utxo_specs = Vec::with_capacity(tx.inputs.len());
    let mut input_covenant_ids = Vec::with_capacity(tx.inputs.len());
    let mut input_covenant_states = Vec::with_capacity(tx.inputs.len());
    let mut input_redeem_scripts = Vec::with_capacity(tx.inputs.len());
    for (input_idx, input) in tx.inputs.iter().enumerate() {
        let mut default_prev_txid = [0u8; 32];
        default_prev_txid.fill(input_idx as u8);
        let prev_txid = if let Some(raw_txid) = input.prev_txid.as_deref() {
            parse_txid32(raw_txid)?
        } else {
            TransactionId::from_bytes(default_prev_txid)
        };

        let input_ctor_raw = input.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
        let input_covenant_state = if let Some(raw_state) = input.state.as_deref() {
            Some(resolve_state_from_raw(&parsed_contract, raw_state, &mut explicit_state_cache)?)
        } else if input.utxo_script_hex.is_none() || input.constructor_args.is_some() {
            Some(resolve_state_for_ctor_args(&parsed_contract, &input_ctor_raw, &mut ctor_state_cache)?)
        } else {
            None
        };
        let redeem_script = if input.utxo_script_hex.is_none() {
            if let Some(raw_state) = input.state.as_deref() {
                Some(materialize_script_for_explicit_state(source, &parsed_contract, &input_ctor_raw, raw_state)?)
            } else {
                Some(compile_script_for_ctor_args(source, &parsed_contract, &input_ctor_raw, &mut ctor_script_cache)?)
            }
        } else {
            None
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
        input_prev_outpoints.push(TransactionOutpoint { transaction_id: prev_txid, index: input.prev_index });
        input_sequences.push(input.sequence);
        input_sig_op_counts.push(input.sig_op_count);
        explicit_input_sigs.push(input.signature_script_hex.as_deref().map(parse_hex_bytes).transpose()?);
        utxo_specs.push((input.utxo_value, utxo_spk, covenant_id));
        input_covenant_ids.push(covenant_id);
        input_covenant_states.push(input_covenant_state);
        input_redeem_scripts.push(redeem_script);
    }

    let mut tx_outputs = Vec::with_capacity(tx.outputs.len());
    let mut output_covenant_ids = Vec::with_capacity(tx.outputs.len());
    let mut output_covenant_states = Vec::with_capacity(tx.outputs.len());
    for output in tx.outputs.iter() {
        let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
        let output_state = if let Some(raw_state) = output.state.as_deref() {
            Some(resolve_state_from_raw(&parsed_contract, raw_state, &mut explicit_state_cache)?)
        } else if output.script_hex.is_none() || output.constructor_args.is_some() {
            Some(resolve_state_for_ctor_args(&parsed_contract, &output_ctor_raw, &mut ctor_state_cache)?)
        } else {
            None
        };
        let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
        } else if let Some(raw_pubkey) = output.p2pk_pubkey.as_deref() {
            let pubkey_bytes = parse_hex_bytes(raw_pubkey)?;
            ScriptPublicKey::new(0, build_p2pk_script(&pubkey_bytes).into())
        } else {
            let output_script = if let Some(raw_state) = output.state.as_deref() {
                materialize_script_for_explicit_state(source, &parsed_contract, &output_ctor_raw, raw_state)?
            } else {
                compile_script_for_ctor_args(source, &parsed_contract, &output_ctor_raw, &mut ctor_script_cache)?
            };
            pay_to_script_hash_script(&output_script)
        };

        let covenant = output
            .covenant_id
            .as_deref()
            .map(|raw| -> Result<CovenantBinding, String> {
                Ok(CovenantBinding {
                    authorizing_input: output.authorizing_input.unwrap_or(tx.active_input_index as u16),
                    covenant_id: parse_hash32(raw)?,
                })
            })
            .transpose()?;
        let output_covenant_id = covenant.as_ref().map(|binding| binding.covenant_id);
        tx_outputs.push(TransactionOutput { value: output.value, script_public_key, covenant });
        output_covenant_ids.push(output_covenant_id);
        output_covenant_states.push(output_state);
    }

    let active_covenant_id = input_covenant_ids.get(tx.active_input_index).copied().flatten();
    let companion_leader_index = if covenant_target.as_ref().is_some_and(|target| target.binding == DebugCovenantBinding::Cov) {
        active_covenant_id.and_then(|covenant_id| {
            input_covenant_ids
                .iter()
                .enumerate()
                .filter_map(|(index, input_covenant_id)| (*input_covenant_id == Some(covenant_id)).then_some(index))
                .min()
        })
    } else {
        None
    };
    let active_authorized_output_states = tx
        .outputs
        .iter()
        .zip(output_covenant_states.iter())
        .filter_map(|(output, output_state)| {
            (output.authorizing_input.unwrap_or(tx.active_input_index as u16) == tx.active_input_index as u16)
                .then_some(output_state.clone())
        })
        .collect::<Option<Vec<_>>>();
    let covenant_group_output_states = active_covenant_id.and_then(|covenant_id| {
        output_covenant_ids
            .iter()
            .zip(output_covenant_states.iter())
            .filter_map(|(output_covenant_id, output_state)| {
                (*output_covenant_id == Some(covenant_id)).then_some(output_state.clone())
            })
            .collect::<Option<Vec<_>>>()
    });

    let active_input_ctor_raw = tx.inputs[tx.active_input_index].constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
    let active_compiled = compile_contract_for_raw_ctor_args(source, &parsed_contract, &active_input_ctor_raw)?;
    let active_is_cov_leader = companion_leader_index.map(|index| index == tx.active_input_index).unwrap_or(true);
    let active_sigscript = if let Some(target) = covenant_target.as_ref() {
        match target.binding {
            DebugCovenantBinding::Auth => {
                build_covenant_input_sigscript(&active_compiled, target, true, &raw_args, active_authorized_output_states.as_deref())?
            }
            DebugCovenantBinding::Cov => build_covenant_input_sigscript(
                &active_compiled,
                target,
                active_is_cov_leader,
                &raw_args,
                covenant_group_output_states.as_deref(),
            )?,
        }
    } else {
        let active_raw_args =
            resolve_auto_sign_args(&selected_name, &raw_args, source, &parsed_contract, &raw_ctor_args, &tx, &mut ctor_script_cache)?;
        let typed_args = parse_call_args(&parsed_contract, &selected_name, &active_raw_args)?;
        active_compiled.build_sig_script(&selected_name, typed_args).map_err(|err| format!("failed to build sigscript: {err}"))?
    };

    let mut tx_inputs = Vec::with_capacity(tx.inputs.len());
    for input_idx in 0..tx.inputs.len() {
        let signature_script = if let Some(signature_script) = explicit_input_sigs[input_idx].clone() {
            signature_script
        } else if input_idx == tx.active_input_index {
            if let Some(redeem) = input_redeem_scripts[input_idx].as_ref() {
                combine_action_and_redeem(&active_sigscript, redeem)?
            } else {
                active_sigscript.clone()
            }
        } else if let Some(target) = covenant_target.as_ref()
            && target.binding == DebugCovenantBinding::Cov
            && input_covenant_ids[input_idx] == active_covenant_id
            && input_redeem_scripts[input_idx].is_some()
        {
            let is_leader = Some(input_idx) == companion_leader_index;
            let input_ctor_raw = tx.inputs[input_idx].constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
            let input_compiled = compile_contract_for_raw_ctor_args(source, &parsed_contract, &input_ctor_raw)?;
            let auto_action = build_covenant_input_sigscript(
                &input_compiled,
                target,
                is_leader,
                &raw_args,
                covenant_group_output_states.as_deref(),
            )?;
            combine_action_and_redeem(&auto_action, input_redeem_scripts[input_idx].as_ref().expect("checked is_some above"))?
        } else if let Some(redeem) = input_redeem_scripts[input_idx].as_ref() {
            sigscript_push_script(redeem)
        } else {
            vec![]
        };

        tx_inputs.push(TransactionInput {
            previous_outpoint: input_prev_outpoints[input_idx],
            signature_script,
            sequence: input_sequences[input_idx],
            mass: TxInputMass::SigopCount(input_sig_op_counts[input_idx].into()),
        });
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
    let active_covenant_input_state = input_covenant_states.get(tx.active_input_index).cloned().flatten();
    let active_lockscript =
        input_redeem_scripts.get(tx.active_input_index).cloned().flatten().unwrap_or_else(|| compiled.script.clone());
    let covenant_input_states = active_utxo.covenant_id.and_then(|covenant_id| {
        let mut values = Vec::new();
        for (input_covenant_id, covenant_input_state) in input_covenant_ids.iter().zip(input_covenant_states.iter()) {
            if *input_covenant_id != Some(covenant_id) {
                continue;
            }
            values.push(covenant_input_state.clone()?);
        }
        Some(values)
    });
    let covenant_param_value = match covenant_binding {
        Some(DebugCovenantBinding::Auth) => active_covenant_input_state.clone(),
        Some(DebugCovenantBinding::Cov) => covenant_input_states.clone().map(DebugValue::Array),
        None => None,
    };

    let cache_ptr = Box::into_raw(Box::new(Cache::new(10_000)));
    let cache = unsafe { &*cache_ptr };
    let flags = EngineFlags { covenants_enabled: true, ..Default::default() };
    let ctx = EngineCtx::new(cache).with_reused(reused_values_ref).with_covenants_ctx(covenants_ctx_ref);
    let engine = DebugEngine::from_transaction_input(populated_tx_ref, active_input, tx.active_input_index, active_utxo, ctx, flags);
    let shadow_tx_context = ShadowTxContext {
        tx: populated_tx_ref,
        input: active_input,
        input_index: tx.active_input_index,
        utxo_entry: active_utxo,
        covenants_ctx: covenants_ctx_ref,
    };
    let mut session = DebugSession::full(&active_sigscript, &active_lockscript, source, compiled.debug_info.clone(), engine)
        .map_err(|err| format!("failed to create debug session: {err}"))?
        .with_shadow_tx_context(shadow_tx_context);
    if enable_covenant_session_mode {
        session = session.with_covenant_mode(covenant_param_value, covenant_target);
    }
    let runtime = OwnedRuntime {
        session,
        _backing: RuntimeBacking {
            source: Some(unsafe { NonNull::new_unchecked(source_ptr) }),
            cache: Some(unsafe { NonNull::new_unchecked(cache_ptr) }),
            transaction: unsafe { NonNull::new_unchecked(transaction) },
            populated_tx: unsafe { NonNull::new_unchecked(populated_tx) },
            covenants_ctx: unsafe { NonNull::new_unchecked(covenants_ctx) },
            reused_values: unsafe { NonNull::new_unchecked(reused_values) },
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
            state: None,
            signature_script_hex: None,
            utxo_script_hex: None,
        }],
        outputs: vec![TestTxOutputScenarioResolved {
            value: 5000,
            covenant_id: None,
            authorizing_input: None,
            constructor_args: None,
            state: None,
            script_hex: None,
            p2pk_pubkey: None,
        }],
    }
}

fn resolve_auto_sign_args(
    function_name: &str,
    raw_args: &[String],
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    tx: &TestTxScenarioResolved,
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<Vec<String>, String> {
    let mut resolved = raw_args.to_vec();
    let mut has_secret_sig = false;
    let function = parsed_contract
        .functions
        .iter()
        .find(|function| function.name == function_name)
        .ok_or_else(|| format!("function '{function_name}' not found"))?;

    for (param, raw) in function.params.iter().zip(raw_args.iter()) {
        let type_name = param.type_ref.type_name();
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
                param.name
            ));
        }
    }

    if !has_secret_sig {
        return Ok(resolved);
    }

    let (signing_transaction, signing_utxos, signing_reused_values) =
        build_signing_tx_parts(source, parsed_contract, raw_ctor_args, tx, ctor_script_cache)?;
    let signing_populated = PopulatedTransaction::new(&signing_transaction, signing_utxos);

    for (index, param) in function.params.iter().enumerate() {
        let type_name = param.type_ref.type_name();
        if type_name != "sig" {
            continue;
        }
        let secret_bytes = parse_hex_bytes(&resolved[index])?;
        if secret_bytes.len() != 32 {
            continue;
        }
        resolved[index] = sign_tx_input(&secret_bytes, &signing_populated, tx.active_input_index, &signing_reused_values)
            .map_err(|err| format!("failed to auto-sign argument '{}': {err}", param.name))?;
    }

    Ok(resolved)
}

#[derive(Debug, Clone)]
struct IdentityMaterial {
    pubkey: String,
    secret: String,
    pkh: String,
}

#[derive(Default)]
struct IdentityResolver {
    cache: HashMap<u32, IdentityMaterial>,
}

impl IdentityResolver {
    fn resolve_string(&mut self, raw: &str) -> Result<String, String> {
        let Some((index, field)) = parse_identity_token(raw)? else {
            return Ok(raw.to_string());
        };
        let identity = self.cache.entry(index).or_insert_with(generate_identity_material);
        Ok(match field {
            IdentityField::Pubkey => identity.pubkey.clone(),
            IdentityField::Secret => identity.secret.clone(),
            IdentityField::Pkh => identity.pkh.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum IdentityField {
    Pubkey,
    Secret,
    Pkh,
}

fn resolve_launch_identities(config: &mut ResolvedLaunchConfig) -> Result<(), String> {
    let mut resolver = IdentityResolver::default();

    if let Some(input) = config.constructor_args.as_mut() {
        resolve_arg_input_identities(input, &mut resolver)?;
    }
    if let Some(input) = config.args.as_mut() {
        resolve_arg_input_identities(input, &mut resolver)?;
    }
    if let Some(tx) = config.tx.as_mut() {
        resolve_tx_identities(tx, &mut resolver)?;
    }

    Ok(())
}

fn resolve_arg_input_identities(input: &mut ArgInput, resolver: &mut IdentityResolver) -> Result<(), String> {
    match input {
        ArgInput::Values(values) => {
            for value in values {
                resolve_json_value_identities(value, resolver)?;
            }
        }
        ArgInput::Named(named) => {
            for value in named.values_mut() {
                resolve_json_value_identities(value, resolver)?;
            }
        }
    }
    Ok(())
}

fn resolve_json_value_identities(value: &mut Value, resolver: &mut IdentityResolver) -> Result<(), String> {
    match value {
        Value::String(raw) => {
            *raw = resolver.resolve_string(raw)?;
        }
        Value::Array(items) => {
            for item in items {
                resolve_json_value_identities(item, resolver)?;
            }
        }
        Value::Object(entries) => {
            for entry in entries.values_mut() {
                resolve_json_value_identities(entry, resolver)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn resolve_tx_identities(tx: &mut TestTxScenarioResolved, resolver: &mut IdentityResolver) -> Result<(), String> {
    for input in &mut tx.inputs {
        resolve_optional_string(&mut input.prev_txid, resolver)?;
        resolve_optional_string(&mut input.covenant_id, resolver)?;
        resolve_optional_strings(&mut input.constructor_args, resolver)?;
        resolve_optional_string(&mut input.signature_script_hex, resolver)?;
        resolve_optional_string(&mut input.utxo_script_hex, resolver)?;
    }

    for output in &mut tx.outputs {
        resolve_optional_string(&mut output.covenant_id, resolver)?;
        resolve_optional_strings(&mut output.constructor_args, resolver)?;
        resolve_optional_string(&mut output.script_hex, resolver)?;
        resolve_optional_string(&mut output.p2pk_pubkey, resolver)?;
    }

    Ok(())
}

fn resolve_optional_string(raw: &mut Option<String>, resolver: &mut IdentityResolver) -> Result<(), String> {
    if let Some(value) = raw.as_mut() {
        *value = resolver.resolve_string(value)?;
    }
    Ok(())
}

fn resolve_optional_strings(values: &mut Option<Vec<String>>, resolver: &mut IdentityResolver) -> Result<(), String> {
    if let Some(entries) = values.as_mut() {
        for value in entries {
            *value = resolver.resolve_string(value)?;
        }
    }
    Ok(())
}

fn parse_identity_token(raw: &str) -> Result<Option<(u32, IdentityField)>, String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("keypair") && !trimmed.starts_with("identity") {
        return Ok(None);
    }

    let Some((head, suffix)) = trimmed.split_once('.') else {
        return Err(format!("invalid identity token '{raw}'; expected keypair<N>.pubkey, keypair<N>.secret, or keypair<N>.pkh"));
    };

    let index_raw = if let Some(value) = head.strip_prefix("keypair") {
        value
    } else if let Some(value) = head.strip_prefix("identity") {
        value
    } else {
        return Err(format!("invalid identity token '{raw}'; expected keypair<N>.pubkey, keypair<N>.secret, or keypair<N>.pkh"));
    };

    if index_raw.is_empty() {
        return Err(format!("invalid identity token '{raw}'; expected keypair<N>.pubkey, keypair<N>.secret, or keypair<N>.pkh"));
    }

    let index = index_raw
        .parse::<u32>()
        .map_err(|_| format!("invalid identity token '{raw}'; expected keypair<N>.pubkey, keypair<N>.secret, or keypair<N>.pkh"))?;
    if index == 0 {
        return Err(format!("invalid identity token '{raw}'; keypair index must be >= 1"));
    }

    let field = match suffix {
        "pubkey" => IdentityField::Pubkey,
        "secret" => IdentityField::Secret,
        "pkh" => IdentityField::Pkh,
        _ => {
            return Err(format!("invalid identity token '{raw}'; expected keypair<N>.pubkey, keypair<N>.secret, or keypair<N>.pkh"));
        }
    };

    Ok(Some((index, field)))
}

fn generate_identity_material() -> IdentityMaterial {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut thread_rng());
    let (xonly, _parity) = keypair.x_only_public_key();
    let secret_bytes = keypair.secret_key().secret_bytes();
    let pubkey_bytes = xonly.serialize();
    let pkh = blake2b_simd::Params::new().hash_length(32).hash(&pubkey_bytes);

    IdentityMaterial {
        pubkey: format!("0x{}", encode_hex(&pubkey_bytes)),
        secret: format!("0x{}", encode_hex(&secret_bytes)),
        pkh: format!("0x{}", encode_hex(pkh.as_bytes())),
    }
}

fn expr_to_debug_value(expr: &Expr<'_>) -> Result<DebugValue, String> {
    match &expr.kind {
        ExprKind::Int(value) => Ok(DebugValue::Int(*value)),
        ExprKind::Bool(value) => Ok(DebugValue::Bool(*value)),
        ExprKind::Byte(value) => Ok(DebugValue::Bytes(vec![*value])),
        ExprKind::String(value) => Ok(DebugValue::String(value.clone())),
        ExprKind::Array(values) => {
            if values.iter().all(|value| matches!(value.kind, ExprKind::Byte(_))) {
                return Ok(DebugValue::Bytes(
                    values
                        .iter()
                        .map(|value| match value.kind {
                            ExprKind::Byte(byte) => byte,
                            _ => unreachable!("checked"),
                        })
                        .collect(),
                ));
            }
            Ok(DebugValue::Array(values.iter().map(expr_to_debug_value).collect::<Result<Vec<_>, _>>()?))
        }
        ExprKind::StateObject(fields) => Ok(DebugValue::Object(
            fields
                .iter()
                .map(|field| Ok((field.name.clone(), expr_to_debug_value(&field.expr)?)))
                .collect::<Result<Vec<_>, String>>()?,
        )),
        other => Err(format!("unsupported resolved state expression in debugger: {other:?}")),
    }
}

fn debug_value_to_expr(value: &DebugValue) -> Option<Expr<'static>> {
    Some(match value {
        DebugValue::Int(value) => Expr::int(*value),
        DebugValue::Bool(value) => Expr::new(ExprKind::Bool(*value), Default::default()),
        DebugValue::Bytes(bytes) => Expr::new(
            ExprKind::Array(bytes.iter().map(|byte| Expr::new(ExprKind::Byte(*byte), Default::default())).collect()),
            Default::default(),
        ),
        DebugValue::String(value) => Expr::new(ExprKind::String(value.clone()), Default::default()),
        DebugValue::Array(values) => {
            Expr::new(ExprKind::Array(values.iter().map(debug_value_to_expr).collect::<Option<Vec<_>>>()?), Default::default())
        }
        DebugValue::Object(fields) => Expr::new(
            ExprKind::StateObject(
                fields
                    .iter()
                    .map(|(name, value)| {
                        Some(StateFieldExpr {
                            name: name.clone(),
                            expr: debug_value_to_expr(value)?,
                            span: Default::default(),
                            name_span: Default::default(),
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
            Default::default(),
        ),
        DebugValue::Unknown(_) => return None,
    })
}

fn is_state_type_ref(type_ref: &TypeRef) -> bool {
    !type_ref.is_array() && matches!(&type_ref.base, TypeBase::Custom(name) if name == "State")
}

fn is_state_array_type_ref(type_ref: &TypeRef) -> bool {
    type_ref.is_array() && matches!(&type_ref.base, TypeBase::Custom(name) if name == "State")
}

fn synthesized_covenant_prefix_args(
    compiled: &CompiledContract<'_>,
    entrypoint_name: &str,
    target: &ResolvedCovenantCallTarget,
    output_states: Option<&[DebugValue]>,
) -> Result<Vec<Expr<'static>>, String> {
    if target.binding == DebugCovenantBinding::Cov && entrypoint_name.starts_with("__delegate_") {
        return Ok(Vec::new());
    }

    let function = compiled
        .ast
        .functions
        .iter()
        .find(|function| function.name == entrypoint_name)
        .ok_or_else(|| "generated covenant entrypoint not found".to_string())?;
    let Some(first_param) = function.params.first() else {
        return Ok(Vec::new());
    };

    let states =
        output_states.ok_or_else(|| "missing output states needed to synthesize covenant verification arguments".to_string())?;
    if is_state_type_ref(&first_param.type_ref) {
        if states.len() != 1 {
            return Err(format!("expected exactly 1 output State for '{entrypoint_name}', got {}", states.len()));
        }
        return Ok(vec![debug_value_to_expr(&states[0]).ok_or_else(|| "failed to materialize synthesized output State".to_string())?]);
    }
    if is_state_array_type_ref(&first_param.type_ref) {
        return Ok(vec![Expr::new(
            ExprKind::Array(
                states
                    .iter()
                    .map(debug_value_to_expr)
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| "failed to materialize synthesized output State[]".to_string())?,
            ),
            Default::default(),
        )]);
    }

    Ok(Vec::new())
}

fn build_covenant_input_sigscript<'i>(
    compiled: &CompiledContract<'i>,
    target: &ResolvedCovenantCallTarget,
    is_leader: bool,
    raw_args: &[String],
    output_states: Option<&[DebugValue]>,
) -> Result<Vec<u8>, String> {
    let entrypoint_name = target.generated_entrypoint_name_for(is_leader);
    let typed_args = if target.binding == DebugCovenantBinding::Cov && !is_leader {
        Vec::new()
    } else {
        let function = compiled
            .ast
            .functions
            .iter()
            .find(|function| function.name == entrypoint_name)
            .ok_or_else(|| "generated covenant entrypoint not found".to_string())?;
        if raw_args.len() == function.params.len() {
            parse_call_args(&compiled.ast, &entrypoint_name, raw_args)?
        } else {
            let prefix_args = synthesized_covenant_prefix_args(compiled, &entrypoint_name, target, output_states)?;
            parse_call_args_with_prefix(&compiled.ast, &entrypoint_name, prefix_args, raw_args)?
        }
    };
    compiled.build_sig_script(&entrypoint_name, typed_args).map_err(|err| format!("failed to build covenant sigscript: {err}"))
}

fn resolve_state_for_ctor_args(
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, DebugValue>,
) -> Result<DebugValue, String> {
    if let Some(value) = cache.get(raw_ctor_args) {
        return Ok(value.clone());
    }

    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    let state_fields = parsed_contract.resolve_contract_state_values(&ctor_args).map_err(|err| err.to_string())?;
    let value = DebugValue::Object(
        state_fields
            .iter()
            .map(|field| Ok((field.name.clone(), expr_to_debug_value(&field.value)?)))
            .collect::<Result<Vec<_>, String>>()?,
    );
    cache.insert(raw_ctor_args.to_vec(), value.clone());
    Ok(value)
}

fn resolve_state_from_raw(
    parsed_contract: &ContractAst<'_>,
    raw_state: &str,
    cache: &mut HashMap<String, DebugValue>,
) -> Result<DebugValue, String> {
    if let Some(value) = cache.get(raw_state) {
        return Ok(value.clone());
    }

    let expr = parse_state_value(parsed_contract, raw_state)?;
    let value = expr_to_debug_value(&expr)?;
    cache.insert(raw_state.to_string(), value.clone());
    Ok(value)
}

fn materialize_script_for_explicit_state(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_instance_args: &[String],
    raw_state: &str,
) -> Result<Vec<u8>, String> {
    let instance_args = parse_ctor_args(parsed_contract, raw_instance_args)?;
    let state = parse_state_value(parsed_contract, raw_state)?;
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let base_compiled = compile_contract(source, &instance_args, compile_opts).map_err(|err| format!("compile error: {err}"))?;
    let materialized_contract = contract_with_explicit_state(parsed_contract, &state)?;
    let materialized =
        compile_contract_ast(&materialized_contract, &instance_args, compile_opts).map_err(|err| format!("compile error: {err}"))?;

    let base_start = base_compiled.state_layout.start;
    let base_end = base_start + base_compiled.state_layout.len;
    let materialized_start = materialized.state_layout.start;
    let materialized_end = materialized_start + materialized.state_layout.len;
    if base_compiled.state_layout.len != materialized.state_layout.len {
        return Err("explicit state changes encoded script size; provide raw script_hex instead".to_string());
    }
    if base_compiled.script.len() < base_end || materialized.script.len() < materialized_end {
        return Err("state layout exceeds compiled script length".to_string());
    }
    if base_compiled.script[..base_start] != materialized.script[..materialized_start]
        || base_compiled.script[base_end..] != materialized.script[materialized_end..]
    {
        return Err("explicit state changed non-state bytecode; provide raw script_hex instead".to_string());
    }

    let mut script = base_compiled.script;
    script[base_start..base_end].copy_from_slice(&materialized.script[materialized_start..materialized_end]);
    Ok(script)
}

fn contract_with_explicit_state<'i>(contract: &ContractAst<'i>, state: &Expr<'i>) -> Result<ContractAst<'i>, String> {
    let ExprKind::StateObject(entries) = &state.kind else {
        return Err("State value must be an object literal".to_string());
    };

    let mut provided = entries.iter().map(|entry| (entry.name.as_str(), entry.expr.clone())).collect::<HashMap<_, _>>();
    if provided.len() != contract.fields.len() {
        return Err("State value must include all contract fields exactly once".to_string());
    }

    let mut materialized = contract.clone();
    for field in &mut materialized.fields {
        field.expr = provided.remove(field.name.as_str()).ok_or_else(|| format!("missing state field '{}'", field.name))?;
    }
    if let Some(extra) = provided.keys().next() {
        return Err(format!("unknown state field '{}'", extra));
    }
    Ok(materialized)
}

fn compile_contract_for_raw_ctor_args<'i>(
    source: &'i str,
    parsed_contract: &ContractAst<'i>,
    raw_ctor_args: &[String],
) -> Result<CompiledContract<'i>, String> {
    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    compile_contract(source, &ctor_args, CompileOptions { record_debug_infos: true, ..Default::default() })
        .map_err(|err| format!("compile error: {err}"))
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

fn build_signing_tx_parts(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    tx: &TestTxScenarioResolved,
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<(Transaction, Vec<UtxoEntry>, SigHashReusedValuesUnsync), String> {
    let mut tx_inputs = Vec::with_capacity(tx.inputs.len());
    let mut utxo_specs = Vec::with_capacity(tx.inputs.len());
    let mut explicit_state_cache = HashMap::<String, DebugValue>::new();

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
            if let Some(raw_state) = input.state.as_deref() {
                Some(materialize_script_for_explicit_state(source, parsed_contract, &input_ctor_raw, raw_state)?)
            } else {
                Some(compile_script_for_ctor_args(source, parsed_contract, &input_ctor_raw, ctor_script_cache)?)
            }
        } else {
            None
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
            signature_script: vec![],
            sequence: input.sequence,
            mass: TxInputMass::SigopCount(input.sig_op_count.into()),
        });
        utxo_specs.push((input.utxo_value, utxo_spk, covenant_id));
        if let Some(raw_state) = input.state.as_deref() {
            let _ = resolve_state_from_raw(parsed_contract, raw_state, &mut explicit_state_cache)?;
        }
    }

    let mut tx_outputs = Vec::with_capacity(tx.outputs.len());
    for output in &tx.outputs {
        let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
        let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
        } else if let Some(raw_pubkey) = output.p2pk_pubkey.as_deref() {
            let pubkey_bytes = parse_hex_bytes(raw_pubkey)?;
            ScriptPublicKey::new(0, build_p2pk_script(&pubkey_bytes).into())
        } else {
            let output_script = if let Some(raw_state) = output.state.as_deref() {
                materialize_script_for_explicit_state(source, parsed_contract, &output_ctor_raw, raw_state)?
            } else {
                compile_script_for_ctor_args(source, parsed_contract, &output_ctor_raw, ctor_script_cache)?
            };
            pay_to_script_hash_script(&output_script)
        };
        let covenant = output
            .covenant_id
            .as_deref()
            .map(|raw| -> Result<CovenantBinding, String> {
                Ok(CovenantBinding {
                    authorizing_input: output.authorizing_input.unwrap_or(tx.active_input_index as u16),
                    covenant_id: parse_hash32(raw)?,
                })
            })
            .transpose()?;
        tx_outputs.push(TransactionOutput { value: output.value, script_public_key, covenant });
    }

    let transaction = Transaction::new(tx.version, tx_inputs, tx_outputs, tx.lock_time, Default::default(), 0, vec![]);
    let utxos = utxo_specs
        .into_iter()
        .map(|(value, spk, covenant_id)| UtxoEntry::new(value, spk, 0, transaction.is_coinbase(), covenant_id))
        .collect::<Vec<_>>();
    Ok((transaction, utxos, SigHashReusedValuesUnsync::new()))
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
                    state: None,
                    signature_script_hex: None,
                    utxo_script_hex: None,
                }],
                outputs: vec![TestTxOutputScenarioResolved {
                    value: 5000,
                    covenant_id: None,
                    authorizing_input: None,
                    constructor_args: None,
                    state: None,
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
