use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use debugger_session::args::{parse_call_args, parse_ctor_args, parse_hex_bytes};
use debugger_session::format_failure_report;
use debugger_session::session::{DebugEngine, DebugSession, ShadowTxContext, Variable};
use debugger_session::test_runner::{
    TestExpectation, TestTxInputScenarioResolved, TestTxOutputScenarioResolved, TestTxScenarioResolved, discover_sidecar_path,
    resolve_contract_test,
};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, pay_to_script_hash_script};
use silverscript_lang::ast::{ContractAst, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

const PROMPT: &str = "(sdb) ";

#[derive(Debug, Parser)]
#[command(name = "cli-debugger", about = "SilverScript debugger")]
struct CliArgs {
    script_path: Option<String>,
    #[arg(long = "test-file")]
    test_file: Option<String>,
    #[arg(long = "test-name")]
    test_name: Option<String>,
    /// Run non-interactively: execute and report pass/fail
    #[arg(long = "run", short = 'r')]
    run: bool,
    /// Run all tests in a test file
    #[arg(long = "run-all")]
    run_all: bool,
    #[arg(long = "function", short = 'f')]
    function_name: Option<String>,
    #[arg(long = "ctor-arg")]
    raw_ctor_args: Vec<String>,
    #[arg(long = "arg", short = 'a')]
    raw_args: Vec<String>,
}

fn compile_script_for_ctor_args(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(script) = cache.get(raw_ctor_args) {
        return Ok(script.clone());
    }
    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    let compiled = compile_contract(source, &ctor_args, CompileOptions::default())?;
    cache.insert(raw_ctor_args.to_vec(), compiled.script.clone());
    Ok(compiled.script)
}

fn parse_hex_32(raw: &str, name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() != 32 {
        return Err(format!("{name} expects 32 bytes, got {}", bytes.len()).into());
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn parse_hash32(raw: &str) -> Result<Hash, Box<dyn std::error::Error>> {
    Ok(Hash::from_bytes(parse_hex_32(raw, "hash")?))
}

fn parse_txid32(raw: &str) -> Result<TransactionId, Box<dyn std::error::Error>> {
    Ok(TransactionId::from_bytes(parse_hex_32(raw, "txid")?))
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

fn combine_action_and_redeem(action: &[u8], redeem_script: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut builder = ScriptBuilder::new();
    builder.add_ops(action)?;
    builder.add_data(redeem_script)?;
    Ok(builder.drain())
}

fn show_stack(session: &DebugSession<'_, '_>) {
    println!("Stack:");
    let stack = session.stack();
    for (i, item) in stack.iter().enumerate().rev() {
        println!("[{i}] {item}");
    }
}

fn show_source_context(session: &DebugSession<'_, '_>) {
    let Some(context) = session.source_context() else {
        println!("No source context available.");
        return;
    };

    for line in context.lines {
        let marker = if line.is_active { "→" } else { " " };
        println!("{marker} {:>4} | {}", line.line, line.text);
    }
}

fn print_variable(session: &DebugSession<'_, '_>, var: &Variable) {
    let constant_suffix = if var.is_constant { " (const)" } else { "" };
    println!("{}{} ({}) = {}", var.name, constant_suffix, var.type_name, session.format_value(&var.type_name, &var.value));
}

fn show_vars(session: &DebugSession<'_, '_>) {
    match session.list_variables() {
        Ok(variables) => {
            if variables.is_empty() {
                println!("No variables in scope.");
            } else {
                for var in variables {
                    print_variable(session, &var);
                }
            }
        }
        Err(err) => println!("ERROR: {err}"),
    }
}

fn show_step_view(session: &DebugSession<'_, '_>) {
    show_source_context(session);
    show_vars(session);
}

fn print_failure(session: &DebugSession<'_, '_>, err: kaspa_txscript_errors::TxScriptError) {
    let report = session.build_failure_report(&err);
    let formatted = format_failure_report(&report, &|type_name, value| session.format_value(type_name, value));
    eprintln!("{formatted}");
}

fn run_repl(session: &mut DebugSession<'_, '_>) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    loop {
        print!("{PROMPT}");
        io::stdout().flush().ok();

        let mut cmd = String::new();
        if stdin.lock().read_line(&mut cmd).is_err() {
            println!("Failed to read input.");
            continue;
        }

        let cmd = cmd.trim();
        if cmd.is_empty() || cmd == "n" || cmd == "next" {
            match session.step_over() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            }
            continue;
        }

        let mut parts = cmd.split_whitespace();
        match parts.next().unwrap_or("") {
            "step" | "s" => match session.step_into() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "si" => match session.step_opcode() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "finish" | "out" => match session.step_out() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "c" | "continue" => match session.continue_to_breakpoint() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "b" | "break" => {
                if let Some(arg) = parts.next() {
                    match arg.parse::<u32>() {
                        Ok(line) => {
                            if session.add_breakpoint(line) {
                                println!("Breakpoint set at line {line}");
                            } else {
                                println!("Warning: no statement at line {line}, breakpoint not set");
                            }
                        }
                        Err(_) => println!("Invalid line number."),
                    }
                } else {
                    let lines = session.breakpoints();
                    if lines.is_empty() {
                        println!("No breakpoints set.");
                    } else {
                        println!("Breakpoints: {}", lines.iter().map(|line| line.to_string()).collect::<Vec<_>>().join(", "));
                    }
                }
            }
            "l" | "list" => show_source_context(session),
            "vars" => show_vars(session),
            "print" | "p" => {
                if let Some(name) = parts.next() {
                    match session.variable_by_name(name) {
                        Ok(var) => print_variable(session, &var),
                        Err(err) => println!("ERROR: {err}"),
                    }
                } else {
                    println!("Usage: print <name>");
                }
            }
            "stack" => show_stack(session),
            "q" | "quit" => break,
            "help" | "h" | "?" => {
                println!(
                    "Commands: next/over (n), step/into (s), step opcode (si), finish/out, continue (c), break (b <line>), list (l), vars, print <name>, stack, quit (q)"
                )
            }
            _ => println!(
                "Commands: next/over (n), step/into (s), step opcode (si), finish/out, continue (c), break (b <line>), list (l), vars, print <name>, stack, quit (q)"
            ),
        }
    }
    Ok(())
}

fn run_all_tests(test_file: &str, script_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    use debugger_session::test_runner::read_contract_test_file;
    let test_file_path = Path::new(test_file);
    let parsed = read_contract_test_file(test_file_path)?;
    let test_names: Vec<String> = parsed.tests.iter().map(|t| t.name.clone()).collect();
    let total = test_names.len();
    let mut passed = 0;
    let mut failed = 0;
    for name in &test_names {
        let mut args = vec!["--run", "--test-file", test_file, "--test-name", name];
        if let Some(path) = script_path {
            args.push(path);
        }
        let result = std::process::Command::new(std::env::current_exe()?).args(&args).output()?;
        let stderr = String::from_utf8_lossy(&result.stderr);
        if result.status.success() {
            passed += 1;
            println!("  PASS  {name}");
        } else {
            failed += 1;
            println!("  FAIL  {name}");
            if !stderr.is_empty() {
                for line in stderr.lines() {
                    println!("        {line}");
                }
            }
        }
    }
    println!("\n{total} tests: {passed} passed, {failed} failed");
    if failed > 0 { Err("some tests failed".into()) } else { Ok(()) }
}

fn resolve_test_file_path(
    test_file: Option<&str>,
    script_path: Option<&str>,
    mode: &str,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    match (test_file, script_path) {
        (Some(path), _) => Ok(Some(PathBuf::from(path))),
        (None, Some(path)) if mode == "run-all" || mode == "run-test" => {
            Ok(Some(discover_sidecar_path(Path::new(path)).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?))
        }
        (None, _) => Ok(None),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();

    if !cli.run_all && cli.test_file.is_some() && cli.test_name.is_none() {
        return Err("--test-file requires --test-name".into());
    }
    if !cli.run_all && cli.test_name.is_some() && cli.test_file.is_none() && cli.script_path.is_none() {
        return Err("--test-name requires --test-file or SCRIPT_PATH".into());
    }

    if cli.run_all {
        let test_file = resolve_test_file_path(cli.test_file.as_deref(), cli.script_path.as_deref(), "run-all")?
            .ok_or("--run-all requires SCRIPT_PATH or --test-file")?;
        let test_file = test_file.to_string_lossy().into_owned();
        return run_all_tests(&test_file, cli.script_path.as_deref());
    }

    // Resolve source, ctor args, function, call args, and tx from test file or CLI flags
    let inferred_test_file = if cli.test_file.is_some() || cli.test_name.is_some() {
        resolve_test_file_path(cli.test_file.as_deref(), cli.script_path.as_deref(), "run-test")?
    } else {
        None
    };
    let (script_path, raw_ctor_args, selected_name, raw_args, tx_scenario, expect) =
        if let Some(test_file) = inferred_test_file.as_deref() {
            let test_name = cli.test_name.as_deref().ok_or("--test-name requires --test-file or SCRIPT_PATH")?;
            let script_override = cli.script_path.as_deref().map(Path::new);
            let resolved = resolve_contract_test(test_file, test_name, script_override)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let ctor = if !cli.raw_ctor_args.is_empty() { cli.raw_ctor_args.clone() } else { resolved.test.constructor_args };
            let fname = cli.function_name.clone().unwrap_or(resolved.test.function);
            let args = if !cli.raw_args.is_empty() { cli.raw_args.clone() } else { resolved.test.args };
            let expect = Some(resolved.test.expect);
            (resolved.script_path, ctor, fname, args, resolved.test.tx, expect)
        } else {
            let path = cli.script_path.as_deref().ok_or("missing script path: pass SCRIPT_PATH or --test-file")?;
            let ctor = cli.raw_ctor_args.clone();
            let args = cli.raw_args.clone();
            (PathBuf::from(path), ctor, cli.function_name.clone().unwrap_or_default(), args, None, None)
        };

    let source = fs::read_to_string(&script_path)?;
    let parsed_contract = parse_contract_ast(&source)?;

    let ctor_args = parse_ctor_args(&parsed_contract, &raw_ctor_args)?;
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();
    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    ctor_script_cache.insert(raw_ctor_args.clone(), compiled.script.clone());

    let selected_name = if selected_name.is_empty() {
        compiled.abi.first().map(|entry| entry.name.clone()).ok_or("contract has no functions")?
    } else {
        selected_name
    };
    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| format!("function '{selected_name}' not found"))?;

    let input_types = entry.inputs.iter().map(|input| input.type_name.clone()).collect::<Vec<_>>();
    let typed_args = parse_call_args(&input_types, &raw_args)?;
    let sigscript = compiled.build_sig_script(&selected_name, typed_args)?;

    let tx = tx_scenario.unwrap_or_else(|| TestTxScenarioResolved {
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
    });

    if tx.inputs.is_empty() {
        return Err("tx.inputs must contain at least one input".into());
    }
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()).into());
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

        let input_ctor_raw = input.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
        let redeem_script = if input.utxo_script_hex.is_none() {
            Some(compile_script_for_ctor_args(&source, &parsed_contract, &input_ctor_raw, &mut ctor_script_cache)?)
        } else {
            None
        };

        let signature_script = if let Some(raw_sig) = input.signature_script_hex.as_deref() {
            parse_hex_bytes(raw_sig)?
        } else if input_idx == tx.active_input_index {
            if let Some(redeem) = redeem_script.as_ref() { combine_action_and_redeem(&sigscript, redeem)? } else { sigscript.clone() }
        } else if let Some(redeem) = redeem_script.as_ref() {
            sigscript_push_script(redeem)
        } else {
            vec![]
        };

        let utxo_spk = if let Some(raw_script) = input.utxo_script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
        } else {
            let redeem = redeem_script.as_ref().ok_or("internal error: missing redeem script for tx input without utxo_script_hex")?;
            pay_to_script_hash_script(redeem)
        };

        let covenant_id = if let Some(raw) = input.covenant_id.as_deref() { Some(parse_hash32(raw)?) } else { None };

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
        let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
        } else if let Some(raw_pubkey) = output.p2pk_pubkey.as_deref() {
            let pubkey_bytes = parse_hex_bytes(raw_pubkey)?;
            let p2pk_script = build_p2pk_script(&pubkey_bytes);
            ScriptPublicKey::new(0, p2pk_script.into())
        } else {
            let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
            let output_script = compile_script_for_ctor_args(&source, &parsed_contract, &output_ctor_raw, &mut ctor_script_cache)?;
            pay_to_script_hash_script(&output_script)
        };

        let covenant = if let Some(raw) = output.covenant_id.as_deref() {
            Some(CovenantBinding {
                authorizing_input: output.authorizing_input.unwrap_or(tx.active_input_index as u16),
                covenant_id: parse_hash32(raw)?,
            })
        } else {
            None
        };

        tx_outputs.push(TransactionOutput { value: output.value, script_public_key, covenant });
    }

    let kas_tx = Transaction::new(tx.version, tx_inputs, tx_outputs, tx.lock_time, Default::default(), 0, vec![]);

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let flags = EngineFlags { covenants_enabled: true };

    let utxos = utxo_specs
        .into_iter()
        .map(|(value, spk, covenant_id)| UtxoEntry::new(value, spk, 0, kas_tx.is_coinbase(), covenant_id))
        .collect::<Vec<_>>();
    let populated_tx = PopulatedTransaction::new(&kas_tx, utxos);
    let cov_ctx = CovenantsContext::from_tx(&populated_tx)?;
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx);
    let active_input =
        kas_tx.inputs.get(tx.active_input_index).ok_or_else(|| format!("missing tx input at index {}", tx.active_input_index))?;
    let active_utxo =
        populated_tx.utxo(tx.active_input_index).ok_or_else(|| format!("missing utxo entry for input {}", tx.active_input_index))?;
    let engine = DebugEngine::from_transaction_input(&populated_tx, active_input, tx.active_input_index, active_utxo, ctx, flags);
    let shadow_tx_context = ShadowTxContext {
        tx: &populated_tx,
        input: active_input,
        input_index: tx.active_input_index,
        utxo_entry: active_utxo,
        covenants_ctx: &cov_ctx,
    };
    let mut session =
        DebugSession::full(&sigscript, &compiled.script, &source, debug_info, engine)?.with_shadow_tx_context(shadow_tx_context);

    if cli.run {
        let expect_fail = expect == Some(TestExpectation::Fail);
        match session.continue_to_breakpoint() {
            Ok(_) if expect_fail => {
                eprintln!("FAIL: expected failure but script passed");
                Err("FAIL".into())
            }
            Ok(_) => {
                println!("PASS");
                Ok(())
            }
            Err(_) if expect_fail => {
                println!("PASS (expected failure)");
                Ok(())
            }
            Err(err) => {
                print_failure(&session, err);
                Err("FAIL".into())
            }
        }
    } else {
        println!("Stepping through {} bytes of script", compiled.script.len());
        session.run_to_first_executed_statement()?;
        show_source_context(&session);
        run_repl(&mut session)?;
        Ok(())
    }
}
