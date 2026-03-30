use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use debugger_session::args::{parse_call_args, parse_ctor_args, parse_hex_bytes, parse_state_value};
use debugger_session::session::{
    DebugEngine, DebugSession, DebugValue, ShadowTxContext, Variable, VariableOrigin, expr_to_debug_value,
};
use debugger_session::test_runner::{
    TestExpectation, TestTxInputScenarioResolved, TestTxOutputScenarioResolved, TestTxScenarioResolved,
    build_covenants_context_for_test_tx, discover_sidecar_path, resolve_contract_test,
};
use debugger_session::{format_failure_report, format_value};
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
use silverscript_lang::compiler::{
    CompileOptions, CompiledContract, CovenantDeclBinding, CovenantDeclCallOptions, ResolvedCovenantCallTarget, compile_contract,
    resolve_contract_state_expr,
};

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
    #[arg(long = "delegate")]
    delegate: bool,
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
    let compiled = compile_contract_for_ctor_args(source, parsed_contract, raw_ctor_args, CompileOptions::default())?;
    cache.insert(raw_ctor_args.to_vec(), compiled.script.clone());
    Ok(compiled.script)
}

fn compile_contract_for_ctor_args<'i>(
    source: &'i str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    compile_opts: CompileOptions,
) -> Result<CompiledContract<'i>, Box<dyn std::error::Error>> {
    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    Ok(compile_contract(source, &ctor_args, compile_opts)?)
}

fn encode_state_script_for_ctor_args(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    raw_state: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let compiled = compile_contract_for_ctor_args(
        source,
        parsed_contract,
        raw_ctor_args,
        CompileOptions { record_debug_infos: true, ..Default::default() },
    )?;
    let state = parse_state_value(parsed_contract, raw_state)?;
    Ok(compiled.encode_state(&state)?)
}

fn resolve_state_for_ctor_args(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, debugger_session::session::DebugValue>,
) -> Result<debugger_session::session::DebugValue, Box<dyn std::error::Error>> {
    if let Some(value) = cache.get(raw_ctor_args) {
        return Ok(value.clone());
    }

    let compiled = compile_contract_for_ctor_args(
        source,
        parsed_contract,
        raw_ctor_args,
        CompileOptions { record_debug_infos: true, ..Default::default() },
    )?;
    let debug_info = compiled
        .debug_info
        .as_ref()
        .ok_or_else(|| "state resolution requires debug-enabled compilation".to_string())
        .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?;
    let expr = resolve_contract_state_expr(&compiled.ast, &debug_info.constructor_args, &debug_info.constants)
        .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?;
    let value = expr_to_debug_value(&expr).map_err(|err| -> Box<dyn std::error::Error> { err.into() })?;
    cache.insert(raw_ctor_args.to_vec(), value.clone());
    Ok(value)
}

fn resolve_state_from_raw(
    parsed_contract: &ContractAst<'_>,
    raw_state: &str,
    cache: &mut HashMap<String, debugger_session::session::DebugValue>,
) -> Result<debugger_session::session::DebugValue, Box<dyn std::error::Error>> {
    if let Some(value) = cache.get(raw_state) {
        return Ok(value.clone());
    }

    let expr = parse_state_value(parsed_contract, raw_state)?;
    let value = expr_to_debug_value(&expr)?;
    cache.insert(raw_state.to_string(), value.clone());
    Ok(value)
}

fn infer_omitted_covenant_args(
    contract: &ContractAst<'_>,
    target: &ResolvedCovenantCallTarget,
    tx: &TestTxScenarioResolved,
) -> Result<Vec<String>, String> {
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()));
    }

    let generated_entrypoint_name = target.generated_entrypoint_name();
    let function = contract
        .functions
        .iter()
        .find(|function| function.name == generated_entrypoint_name)
        .ok_or_else(|| format!("generated covenant entrypoint '{}' not found", generated_entrypoint_name))?;
    let output_states = matching_covenant_output_states(target, tx)?;

    let mut inferred = Vec::with_capacity(function.params.len());
    let mut unresolved = Vec::new();
    for param in &function.params {
        let type_name = param.type_ref.type_name();
        if type_name == "State" {
            if output_states.len() == 1 {
                inferred.push(output_states[0].to_string());
            } else {
                unresolved.push(format!(
                    "{} ({}) requires exactly 1 matching tx.outputs[*].state, found {}",
                    param.name,
                    type_name,
                    output_states.len()
                ));
            }
            continue;
        }

        if type_name.starts_with("State[") {
            inferred.push(encode_state_array_arg(&output_states)?);
            continue;
        }

        unresolved.push(format!("{} ({})", param.name, type_name));
    }

    if unresolved.is_empty() {
        Ok(inferred)
    } else {
        Err(format!(
            "cannot infer omitted args for covenant '{}'; provide explicit args for {}",
            target.info.source_name,
            unresolved.join(", ")
        ))
    }
}

fn matching_covenant_output_states<'a>(
    target: &ResolvedCovenantCallTarget,
    tx: &'a TestTxScenarioResolved,
) -> Result<Vec<&'a str>, String> {
    let covenants_ctx = build_covenants_context_for_test_tx(tx)?;
    let output_indexes = match target.info.binding {
        CovenantDeclBinding::Auth => {
            covenants_ctx.input_ctxs.get(&tx.active_input_index).map(|ctx| ctx.auth_outputs.clone()).unwrap_or_default()
        }
        CovenantDeclBinding::Cov => {
            let active_covenant_id = tx.inputs[tx.active_input_index].covenant_id.as_ref().ok_or_else(|| {
                format!(
                    "cannot infer omitted args for covenant '{}'; tx.inputs[{}].covenant_id is required",
                    target.info.source_name, tx.active_input_index
                )
            })?;
            let active_covenant_id = parse_hash32(active_covenant_id)
                .map_err(|err| format!("cannot infer omitted args for covenant '{}': {err}", target.info.source_name))?;
            covenants_ctx.shared_ctxs.get(&active_covenant_id).map(|ctx| ctx.output_indices.clone()).unwrap_or_default()
        }
    };

    let mut states = Vec::with_capacity(output_indexes.len());
    let mut missing_state_indexes = Vec::new();
    for index in output_indexes {
        let output = tx.outputs.get(index).ok_or_else(|| format!("covenant context returned invalid output index {index}"))?;
        if let Some(state) = output.state.as_deref() {
            states.push(state);
        } else {
            missing_state_indexes.push(index);
        }
    }

    if missing_state_indexes.is_empty() {
        Ok(states)
    } else {
        Err(format!(
            "cannot infer omitted args for covenant '{}'; add tx.outputs[*].state for output indexes {}",
            target.info.source_name,
            missing_state_indexes.iter().map(|index| index.to_string()).collect::<Vec<_>>().join(", ")
        ))
    }
}

fn encode_state_array_arg(output_states: &[&str]) -> Result<String, String> {
    Ok(format!("[{}]", output_states.join(",")))
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
    if raw.starts_with("0x") || raw.starts_with("0X") {
        return Ok(Hash::from_bytes(parse_short_or_full_hex_32(raw, "hash")?));
    }

    if let Ok(value) = raw.parse::<u64>() {
        return Ok(Hash::from_bytes(u64_to_hash_bytes(value)));
    }

    Ok(Hash::from_bytes(parse_hex_32(raw, "hash")?))
}

fn parse_txid32(raw: &str) -> Result<TransactionId, Box<dyn std::error::Error>> {
    Ok(TransactionId::from_bytes(parse_hex_32(raw, "txid")?))
}

fn parse_short_or_full_hex_32(raw: &str, name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() > 32 {
        return Err(format!("{name} expects at most 32 bytes, got {}", bytes.len()).into());
    }
    let mut array = [0u8; 32];
    array[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(array)
}

fn u64_to_hash_bytes(value: u64) -> [u8; 32] {
    let mut array = [0u8; 32];
    array[24..].copy_from_slice(&value.to_be_bytes());
    array
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

fn show_vars(session: &DebugSession<'_, '_>) {
    match session.list_variables() {
        Ok(variables) => {
            if variables.is_empty() {
                println!("No variables in scope.");
            } else {
                print_variable_section("Contract Constants", &variables, |origin| {
                    matches!(origin, VariableOrigin::ConstructorArg | VariableOrigin::Constant)
                });
                print_variable_section("Contract State", &variables, |origin| origin == VariableOrigin::ContractField);
                print_variable_section("Call Arguments", &variables, |origin| origin == VariableOrigin::Param);
                print_variable_section("Locals", &variables, |origin| origin == VariableOrigin::Local);
            }
        }
        Err(err) => println!("ERROR: {err}"),
    }
}

fn print_variable_section(title: &str, variables: &[Variable], matches_origin: impl Fn(VariableOrigin) -> bool) {
    let section_vars: Vec<_> = variables.iter().filter(|var| matches_origin(var.origin)).collect();
    if section_vars.is_empty() {
        return;
    }
    println!("{title}:");
    for var in section_vars {
        println!("  {} ({}) = {}", var.name, var.type_name, format_value(&var.type_name, &var.value));
    }
}

fn print_console_messages(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

fn print_non_status_stdout(stdout: &str) {
    for line in stdout.lines() {
        if line == "PASS" || line == "PASS (expected failure)" {
            continue;
        }
        println!("{line}");
    }
    if stdout.ends_with('\n') || stdout.is_empty() {
        return;
    }
    println!();
}

fn show_step_view(session: &DebugSession<'_, '_>, console_lines: &[String]) {
    show_source_context(session);
    show_vars(session);
    if !console_lines.is_empty() {
        println!("Console:");
        print_console_messages(console_lines);
    }
}

fn print_failure(session: &DebugSession<'_, '_>, err: kaspa_txscript_errors::TxScriptError) {
    let report = session.build_failure_report(&err);
    let formatted = format_failure_report(&report, &format_value);
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
        if cmd.is_empty() || cmd == "n" || cmd == "next" || cmd == "over" {
            match session.step_over() {
                Ok(Some(_)) => {
                    let console_output = session.take_console_output();
                    show_step_view(session, &console_output);
                }
                Ok(_) => {
                    print_console_messages(&session.take_console_output());
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

        let mut parts = cmd.splitn(2, char::is_whitespace);
        let command = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match command {
            "step" | "s" | "into" => match session.step_into() {
                Ok(Some(_)) => {
                    let console_output = session.take_console_output();
                    show_step_view(session, &console_output);
                }
                Ok(_) => {
                    print_console_messages(&session.take_console_output());
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "si" => match session.step_opcode() {
                Ok(Some(_)) => {
                    let console_output = session.take_console_output();
                    show_step_view(session, &console_output);
                }
                Ok(_) => {
                    print_console_messages(&session.take_console_output());
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "finish" | "out" | "so" => match session.step_out() {
                Ok(Some(_)) => {
                    let console_output = session.take_console_output();
                    show_step_view(session, &console_output);
                }
                Ok(_) => {
                    print_console_messages(&session.take_console_output());
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "c" | "continue" => match session.continue_to_breakpoint() {
                Ok(Some(_)) => {
                    let console_output = session.take_console_output();
                    show_step_view(session, &console_output);
                }
                Ok(None) => {
                    print_console_messages(&session.take_console_output());
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "b" | "break" => {
                if !rest.is_empty() {
                    match rest.parse::<u32>() {
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
            "eval" | "e" => {
                if rest.is_empty() {
                    println!("Usage: eval <expr>");
                } else {
                    match session.evaluate_expression(rest) {
                        Ok((type_name, value)) => {
                            println!("{rest} = ({type_name}) {}", format_value(&type_name, &value));
                        }
                        Err(err) => println!("ERROR: {err}"),
                    }
                }
            }
            "print" | "p" => {
                if let Some(name) = rest.split_whitespace().next().filter(|_| !rest.is_empty()) {
                    match session.variable_by_name(name) {
                        Ok(var) => {
                            println!("{} ({}) = {}", var.name, var.type_name, format_value(&var.type_name, &var.value));
                        }
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
                    "Commands: next/over (n), step/into (s), step opcode (si), finish/out/so, continue (c), break (b <line>), list (l), vars, eval <expr> (e), print <name>, stack, quit (q)"
                )
            }
            _ => println!(
                "Commands: next/over (n), step/into (s), step opcode (si), finish/out/so, continue (c), break (b <line>), list (l), vars, eval <expr> (e), print <name>, stack, quit (q)"
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
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        println!("  RUN   {name}");
        if !stdout.is_empty() {
            print_non_status_stdout(&stdout);
        }
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

    // Resolve source, constructor args, function, call args, and tx from test file or CLI flags
    let inferred_test_file = if cli.test_file.is_some() || cli.test_name.is_some() {
        resolve_test_file_path(cli.test_file.as_deref(), cli.script_path.as_deref(), "run-test")?
    } else {
        None
    };
    let (script_path, raw_constructor_args, selected_name, raw_args, allow_omitted_test_args_inference, delegate, tx_scenario, expect) =
        if let Some(test_file) = inferred_test_file.as_deref() {
            let test_name = cli.test_name.as_deref().ok_or("--test-name requires --test-file or SCRIPT_PATH")?;
            let script_override = cli.script_path.as_deref().map(Path::new);
            let resolved = resolve_contract_test(test_file, test_name, script_override)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let constructor_args =
                if !cli.raw_ctor_args.is_empty() { cli.raw_ctor_args.clone() } else { resolved.test.constructor_args };
            let fname = cli.function_name.clone().unwrap_or(resolved.test.function);
            let (args, allow_inference) = if !cli.raw_args.is_empty() {
                (cli.raw_args.clone(), false)
            } else if let Some(args) = resolved.test.args {
                (args, false)
            } else {
                (Vec::new(), true)
            };
            let expect = Some(resolved.test.expect);
            (
                resolved.script_path,
                constructor_args,
                fname,
                args,
                allow_inference,
                cli.delegate || resolved.test.delegate,
                resolved.test.tx,
                expect,
            )
        } else {
            let path = cli.script_path.as_deref().ok_or("missing script path: pass SCRIPT_PATH or --test-file")?;
            let constructor_args = cli.raw_ctor_args.clone();
            let entrypoint_args = cli.raw_args.clone();
            (
                PathBuf::from(path),
                constructor_args,
                cli.function_name.clone().unwrap_or_default(),
                entrypoint_args,
                false,
                cli.delegate,
                None,
                None,
            )
        };

    let source = fs::read_to_string(&script_path)?;
    let parsed_contract = parse_contract_ast(&source)?;

    let ctor_args = parse_ctor_args(&parsed_contract, &raw_constructor_args)?;
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();
    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    let mut ctor_state_cache = HashMap::<Vec<String>, debugger_session::session::DebugValue>::new();
    let mut explicit_state_cache = HashMap::<String, debugger_session::session::DebugValue>::new();
    ctor_script_cache.insert(raw_constructor_args.clone(), compiled.script.clone());
    if !parsed_contract.fields.is_empty() {
        let root_state = if let Some(debug_info) = debug_info.as_ref() {
            let expr = resolve_contract_state_expr(&compiled.ast, &debug_info.constructor_args, &debug_info.constants)
                .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?;
            expr_to_debug_value(&expr).map_err(|err| -> Box<dyn std::error::Error> { err.into() })?
        } else {
            resolve_state_for_ctor_args(&source, &parsed_contract, &raw_constructor_args, &mut ctor_state_cache)?
        };
        ctor_state_cache.insert(raw_constructor_args.clone(), root_state);
    }

    let selected_name = if selected_name.is_empty() {
        compiled.abi.first().map(|entry| entry.name.clone()).ok_or("contract has no functions")?
    } else {
        selected_name
    };

    let covenant_target = compiled
        .covenant_infos
        .iter()
        .find(|info| info.source_name == selected_name)
        .cloned()
        .map(|info| ResolvedCovenantCallTarget { info, is_leader: !delegate });
    let covenant_binding = covenant_target.as_ref().map(|target| target.info.binding);
    let raw_args = if allow_omitted_test_args_inference {
        if let (Some(target), Some(tx)) = (covenant_target.as_ref(), tx_scenario.as_ref()) {
            infer_omitted_covenant_args(&compiled.ast, target, tx).map_err(|err| -> Box<dyn std::error::Error> { err.into() })?
        } else {
            raw_args
        }
    } else {
        raw_args
    };
    let sigscript = if let Some(target) = covenant_target.as_ref() {
        if delegate && target.info.binding != CovenantDeclBinding::Cov {
            return Err("--delegate only applies to binding=cov covenant declarations".into());
        }
        let generated_entrypoint_name = target.generated_entrypoint_name();
        let typed_args = parse_call_args(&compiled.ast, &generated_entrypoint_name, &raw_args)?;
        compiled.build_sig_script_for_covenant_decl(&selected_name, typed_args, CovenantDeclCallOptions { is_leader: !delegate })?
    } else {
        if delegate {
            return Err("--delegate only applies when --function names a source-level binding=cov covenant declaration".into());
        }
        let typed_args = parse_call_args(&compiled.ast, &selected_name, &raw_args)?;
        compiled.build_sig_script(&selected_name, typed_args)?
    };

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
            state: None,
            signature_script_hex: None,
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
    });

    if tx.inputs.is_empty() {
        return Err("tx.inputs must contain at least one input".into());
    }
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()).into());
    }

    let mut tx_inputs = Vec::with_capacity(tx.inputs.len());
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

        let input_constructor_args = input.constructor_args.clone().unwrap_or_else(|| raw_constructor_args.clone());
        let input_covenant_state = if let Some(raw_state) = input.state.as_deref() {
            Some(resolve_state_from_raw(&parsed_contract, raw_state, &mut explicit_state_cache)?)
        } else {
            Some(resolve_state_for_ctor_args(&source, &parsed_contract, &input_constructor_args, &mut ctor_state_cache)?)
        };
        let redeem_script = if let Some(raw_state) = input.state.as_deref() {
            encode_state_script_for_ctor_args(&source, &parsed_contract, &input_constructor_args, raw_state)?
        } else {
            compile_script_for_ctor_args(&source, &parsed_contract, &input_constructor_args, &mut ctor_script_cache)?
        };

        let signature_script = if let Some(raw_sig) = input.signature_script_hex.as_deref() {
            parse_hex_bytes(raw_sig)?
        } else if input_idx == tx.active_input_index {
            combine_action_and_redeem(&sigscript, &redeem_script)?
        } else {
            sigscript_push_script(&redeem_script)
        };

        let utxo_spk = pay_to_script_hash_script(&redeem_script);

        let covenant_id = if let Some(raw) = input.covenant_id.as_deref() { Some(parse_hash32(raw)?) } else { None };

        tx_inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: prev_txid, index: input.prev_index },
            signature_script,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
        });
        utxo_specs.push((input.utxo_value, utxo_spk, covenant_id));
        input_covenant_ids.push(covenant_id);
        input_covenant_states.push(input_covenant_state);
        input_redeem_scripts.push(Some(redeem_script));
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
            let output_constructor_args = output.constructor_args.clone().unwrap_or_else(|| raw_constructor_args.clone());
            let output_script = if let Some(raw_state) = output.state.as_deref() {
                encode_state_script_for_ctor_args(&source, &parsed_contract, &output_constructor_args, raw_state)?
            } else {
                compile_script_for_ctor_args(&source, &parsed_contract, &output_constructor_args, &mut ctor_script_cache)?
            };
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
    let active_input_state = input_covenant_states.get(tx.active_input_index).cloned().flatten();
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
        Some(CovenantDeclBinding::Auth) => active_input_state.clone(),
        Some(CovenantDeclBinding::Cov) => covenant_input_states.clone().map(DebugValue::Array),
        None => None,
    };
    let engine = DebugEngine::from_transaction_input(&populated_tx, active_input, tx.active_input_index, active_utxo, ctx, flags);
    let shadow_tx_context =
        ShadowTxContext { tx: &populated_tx, input: active_input, input_index: tx.active_input_index, utxo_entry: active_utxo };
    let mut session = DebugSession::full(&sigscript, &active_lockscript, &source, debug_info, engine)?
        .with_shadow_tx_context(shadow_tx_context)
        .with_active_contract_state(active_input_state.clone());
    if let Some(covenant_target) = covenant_target {
        session = session.with_covenant_mode(covenant_param_value, covenant_target);
    }

    if cli.run {
        let expect_fail = expect == Some(TestExpectation::Fail);
        match session.run_to_completion() {
            Ok(()) if expect_fail => {
                print_console_messages(&session.take_console_output());
                eprintln!("FAIL: expected failure but script passed");
                Err("FAIL".into())
            }
            Ok(()) => {
                print_console_messages(&session.take_console_output());
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
        let console_output = session.take_console_output();
        show_step_view(&session, &console_output);
        run_repl(&mut session)?;
        Ok(())
    }
}
