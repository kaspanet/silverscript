use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use debugger_session::args::{parse_call_args, parse_call_args_with_prefix, parse_ctor_args, parse_hex_bytes, parse_state_value};
use debugger_session::covenant::{CovenantBinding as DebugCovenantBinding, ResolvedCovenantCallTarget, resolve_covenant_call_target};
use debugger_session::session::{DebugEngine, DebugSession, DebugValue, ShadowTxContext, Variable, VariableOrigin};
use debugger_session::test_runner::{
    TestExpectation, TestTxInputScenarioResolved, TestTxOutputScenarioResolved, TestTxScenarioResolved, discover_sidecar_path,
    resolve_contract_test,
};
use debugger_session::{format_failure_report, format_value};
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
use kaspa_txscript::{EngineCtx, EngineFlags, pay_to_script_hash_script};
use secp256k1::{Keypair, Message, SecretKey, Secp256k1};
use silverscript_lang::ast::{ContractAst, Expr, ExprKind, StateFieldExpr, TypeBase, TypeRef, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract, compile_contract_ast};

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
    let compiled = compile_contract(source, &ctor_args, CompileOptions { record_debug_infos: true, ..Default::default() })?;
    cache.insert(raw_ctor_args.to_vec(), compiled.script.clone());
    Ok(compiled.script)
}

fn compile_contract_for_raw_ctor_args<'i>(
    source: &'i str,
    parsed_contract: &ContractAst<'i>,
    raw_ctor_args: &[String],
) -> Result<CompiledContract<'i>, Box<dyn std::error::Error>> {
    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    Ok(compile_contract(source, &ctor_args, CompileOptions { record_debug_infos: true, ..Default::default() })?)
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
) -> Result<Vec<Expr<'static>>, Box<dyn std::error::Error>> {
    if target.binding == DebugCovenantBinding::Cov && entrypoint_name.starts_with("__delegate_") {
        return Ok(Vec::new());
    }

    let function = compiled
        .ast
        .functions
        .iter()
        .find(|function| function.name == entrypoint_name)
        .ok_or("generated covenant entrypoint not found")?;
    let Some(first_param) = function.params.first() else {
        return Ok(Vec::new());
    };

    let states = output_states.ok_or("missing output states needed to synthesize covenant verification arguments")?;
    if is_state_type_ref(&first_param.type_ref) {
        if states.len() != 1 {
            return Err(format!("expected exactly 1 output State for '{entrypoint_name}', got {}", states.len()).into());
        }
        return Ok(vec![debug_value_to_expr(&states[0]).ok_or("failed to materialize synthesized output State")?]);
    }
    if is_state_array_type_ref(&first_param.type_ref) {
        return Ok(vec![Expr::new(
            ExprKind::Array(
                states
                    .iter()
                    .map(debug_value_to_expr)
                    .collect::<Option<Vec<_>>>()
                    .ok_or("failed to materialize synthesized output State[]")?,
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
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let entrypoint_name = target.generated_entrypoint_name_for(is_leader);
    let typed_args = if target.binding == DebugCovenantBinding::Cov && !is_leader {
        Vec::new()
    } else {
        let function = compiled
            .ast
            .functions
            .iter()
            .find(|function| function.name == entrypoint_name)
            .ok_or("generated covenant entrypoint not found")?;
        if raw_args.len() == function.params.len() {
            parse_call_args(&compiled.ast, &entrypoint_name, raw_args)?
        } else {
            let prefix_args = synthesized_covenant_prefix_args(compiled, &entrypoint_name, target, output_states)?;
            parse_call_args_with_prefix(&compiled.ast, &entrypoint_name, prefix_args, raw_args)?
        }
    };
    Ok(compiled.build_sig_script(&entrypoint_name, typed_args)?)
}

fn resolve_state_for_ctor_args(
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, DebugValue>,
) -> Result<DebugValue, Box<dyn std::error::Error>> {
    if let Some(value) = cache.get(raw_ctor_args) {
        return Ok(value.clone());
    }

    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    let state_fields = parsed_contract.resolve_contract_state_values(&ctor_args)?;
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
) -> Result<DebugValue, Box<dyn std::error::Error>> {
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
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let instance_args = parse_ctor_args(parsed_contract, raw_instance_args)?;
    let state = parse_state_value(parsed_contract, raw_state)?;
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let base_compiled = compile_contract(source, &instance_args, compile_opts)?;
    let materialized_contract = contract_with_explicit_state(parsed_contract, &state)?;
    let materialized = compile_contract_ast(&materialized_contract, &instance_args, compile_opts)?;

    let base_start = base_compiled.state_layout.start;
    let base_end = base_start + base_compiled.state_layout.len;
    let materialized_start = materialized.state_layout.start;
    let materialized_end = materialized_start + materialized.state_layout.len;
    if base_compiled.state_layout.len != materialized.state_layout.len {
        return Err("explicit state changes encoded script size; provide raw script_hex instead".into());
    }
    if base_compiled.script.len() < base_end || materialized.script.len() < materialized_end {
        return Err("state layout exceeds compiled script length".into());
    }
    if base_compiled.script[..base_start] != materialized.script[..materialized_start]
        || base_compiled.script[base_end..] != materialized.script[materialized_end..]
    {
        return Err("explicit state changed non-state bytecode; provide raw script_hex instead".into());
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

fn materialize_auto_sig_args(
    ast: &ContractAst<'_>,
    function_name: &str,
    raw_args: &mut [String],
    tx: &Transaction,
    utxos: &[UtxoEntry],
    input_idx: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(function) = ast.functions.iter().find(|function| function.name == function_name) else {
        return Ok(());
    };
    let populated = PopulatedTransaction::new(tx, utxos.to_vec());
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&populated, input_idx, SIG_HASH_ALL, &reused_values);
    let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice())?;
    let secp = Secp256k1::new();
    let raw_arg_offset = function.params.len().saturating_sub(raw_args.len());
    for (idx, param) in function.params.iter().enumerate() {
        if !matches!(param.type_ref.base, TypeBase::Sig | TypeBase::Datasig) || idx < raw_arg_offset {
            continue;
        }
        let raw_idx = idx - raw_arg_offset;
        if raw_idx >= raw_args.len() {
            continue;
        }
        let bytes = parse_hex_bytes(&raw_args[raw_idx])?;
        if bytes.len() != 32 {
            continue;
        }
        let secret = SecretKey::from_slice(&bytes)?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let sig = keypair.sign_schnorr(msg);
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(sig.as_ref());
        signature.push(SIG_HASH_ALL.to_u8());
        raw_args[raw_idx] = signature.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    }
    Ok(())
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
                print_variable_section("Constructor Args", &variables, |origin| origin == VariableOrigin::ConstructorArg);
                print_variable_section("Constants", &variables, |origin| origin == VariableOrigin::Constant);
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

fn print_console_section(lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    println!("Console:");
    print_console_messages(lines);
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
    print_console_section(console_lines);
}

fn print_failure(session: &DebugSession<'_, '_>, err: kaspa_txscript_errors::TxScriptError) {
    let report = session.build_failure_report(&err);
    let formatted = format_failure_report(&report, &format_value);
    eprintln!("{formatted}");
}

fn take_console_output_for_stop(session: &mut DebugSession<'_, '_>, pending_console_output: &mut Vec<String>) -> Vec<String> {
    let console_output = std::mem::take(pending_console_output);
    *pending_console_output = session.take_console_output();
    console_output
}

fn take_console_output_for_completion(session: &mut DebugSession<'_, '_>, pending_console_output: &mut Vec<String>) -> Vec<String> {
    let mut console_output = std::mem::take(pending_console_output);
    console_output.extend(session.take_console_output());
    console_output
}

fn handle_repl_step_result<T>(
    session: &mut DebugSession<'_, '_>,
    result: Result<Option<T>, kaspa_txscript_errors::TxScriptError>,
    pending_console_output: &mut Vec<String>,
) -> bool {
    match result {
        Ok(Some(_)) => {
            let console_output = take_console_output_for_stop(session, pending_console_output);
            show_step_view(session, &console_output);
            false
        }
        Ok(None) => {
            let console_output = take_console_output_for_completion(session, pending_console_output);
            print_console_section(&console_output);
            println!("Done.");
            true
        }
        Err(err) => {
            print_failure(session, err);
            true
        }
    }
}

fn run_repl(session: &mut DebugSession<'_, '_>, pending_console_output: &mut Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
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
            let result = session.step_over();
            if handle_repl_step_result(session, result, pending_console_output) {
                break;
            }
            continue;
        }

        let mut parts = cmd.splitn(2, char::is_whitespace);
        let command = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match command {
            "step" | "s" => {
                let result = session.step_into();
                if handle_repl_step_result(session, result, pending_console_output) {
                    break;
                }
            }
            "si" => {
                let result = session.step_opcode();
                if handle_repl_step_result(session, result, pending_console_output) {
                    break;
                }
            }
            "finish" | "out" => {
                let result = session.step_out();
                if handle_repl_step_result(session, result, pending_console_output) {
                    break;
                }
            }
            "c" | "continue" => {
                let result = session.continue_to_breakpoint();
                if handle_repl_step_result(session, result, pending_console_output) {
                    break;
                }
            }
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
                    "Commands: next/over (n), step/into (s), step opcode (si), finish/out, continue (c), break (b <line>), list (l), vars, eval <expr> (e), print <name>, stack, quit (q)"
                )
            }
            _ => println!(
                "Commands: next/over (n), step/into (s), step opcode (si), finish/out, continue (c), break (b <line>), list (l), vars, eval <expr> (e), print <name>, stack, quit (q)"
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

    // Resolve source, ctor args, function, call args, and tx from test file or CLI flags.
    let inferred_test_file = if cli.test_file.is_some() || cli.test_name.is_some() {
        resolve_test_file_path(cli.test_file.as_deref(), cli.script_path.as_deref(), "run-test")?
    } else {
        None
    };
    let (script_path, mut raw_ctor_args, selected_name, mut raw_args, tx_scenario, expect) =
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
    });

    if tx.inputs.is_empty() {
        return Err("tx.inputs must contain at least one input".into());
    }
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()).into());
    }

    if raw_ctor_args.is_empty()
        && let Some(active_input_ctor_args) = tx.inputs.get(tx.active_input_index).and_then(|input| input.constructor_args.clone())
    {
        raw_ctor_args = active_input_ctor_args;
    }

    let ctor_args = parse_ctor_args(&parsed_contract, &raw_ctor_args)?;
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();
    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    let mut ctor_state_cache = HashMap::<Vec<String>, DebugValue>::new();
    let mut explicit_state_cache = HashMap::<String, DebugValue>::new();
    ctor_script_cache.insert(raw_ctor_args.clone(), compiled.script.clone());
    if !parsed_contract.fields.is_empty() {
        let root_state = resolve_state_for_ctor_args(&parsed_contract, &raw_ctor_args, &mut ctor_state_cache)?;
        ctor_state_cache.insert(raw_ctor_args.clone(), root_state);
    }

    let selected_name = if selected_name.is_empty() {
        compiled.abi.first().map(|entry| entry.name.clone()).ok_or("contract has no functions")?
    } else {
        selected_name
    };

    let covenant_target = resolve_covenant_call_target(&parsed_contract, &compiled, &selected_name);
    let covenant_binding = covenant_target.as_ref().map(|target| target.binding);
    let enable_covenant_session_mode = covenant_target.is_some();

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
                Some(materialize_script_for_explicit_state(&source, &parsed_contract, &input_ctor_raw, raw_state)?)
            } else {
                Some(compile_script_for_ctor_args(&source, &parsed_contract, &input_ctor_raw, &mut ctor_script_cache)?)
            }
        } else {
            None
        };

        let utxo_spk = if let Some(raw_script) = input.utxo_script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
        } else {
            let redeem = redeem_script.as_ref().ok_or("internal error: missing redeem script for tx input without utxo_script_hex")?;
            pay_to_script_hash_script(redeem)
        };

        let covenant_id = if let Some(raw) = input.covenant_id.as_deref() { Some(parse_hash32(raw)?) } else { None };

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
            let p2pk_script = build_p2pk_script(&pubkey_bytes);
            ScriptPublicKey::new(0, p2pk_script.into())
        } else {
            let output_script = if let Some(raw_state) = output.state.as_deref() {
                materialize_script_for_explicit_state(&source, &parsed_contract, &output_ctor_raw, raw_state)?
            } else {
                compile_script_for_ctor_args(&source, &parsed_contract, &output_ctor_raw, &mut ctor_script_cache)?
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
    let provisional_inputs = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(input_idx, _)| TransactionInput {
            previous_outpoint: input_prev_outpoints[input_idx],
            signature_script: explicit_input_sigs[input_idx].clone().unwrap_or_default(),
            sequence: input_sequences[input_idx],
            mass: TxInputMass::SigopCount(input_sig_op_counts[input_idx].into()),
        })
        .collect::<Vec<_>>();
    let provisional_tx = Transaction::new(tx.version, provisional_inputs, tx_outputs.clone(), tx.lock_time, Default::default(), 0, vec![]);
    let provisional_utxos = utxo_specs
        .iter()
        .map(|(value, spk, covenant_id)| UtxoEntry::new(*value, spk.clone(), 0, provisional_tx.is_coinbase(), *covenant_id))
        .collect::<Vec<_>>();
    materialize_auto_sig_args(&parsed_contract, &selected_name, &mut raw_args, &provisional_tx, &provisional_utxos, tx.active_input_index)?;

    let active_input_ctor_raw = tx.inputs[tx.active_input_index].constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
    let active_compiled = compile_contract_for_raw_ctor_args(&source, &parsed_contract, &active_input_ctor_raw)?;
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
        let typed_args = parse_call_args(&active_compiled.ast, &selected_name, &raw_args)?;
        active_compiled.build_sig_script(&selected_name, typed_args)?
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
            let input_compiled = compile_contract_for_raw_ctor_args(&source, &parsed_contract, &input_ctor_raw)?;
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

    let kas_tx = Transaction::new(tx.version, tx_inputs, tx_outputs, tx.lock_time, Default::default(), 0, vec![]);

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let flags = EngineFlags { covenants_enabled: true, ..Default::default() };

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
    let engine = DebugEngine::from_transaction_input(&populated_tx, active_input, tx.active_input_index, active_utxo, ctx, flags);
    let shadow_tx_context = ShadowTxContext {
        tx: &populated_tx,
        input: active_input,
        input_index: tx.active_input_index,
        utxo_entry: active_utxo,
        covenants_ctx: &cov_ctx,
    };
    let mut session = DebugSession::full(&active_sigscript, &active_lockscript, &source, debug_info, engine)?
        .with_shadow_tx_context(shadow_tx_context);
    if enable_covenant_session_mode {
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
        let mut pending_console_output = session.take_console_output();
        let console_output = Vec::new();
        show_step_view(&session, &console_output);
        run_repl(&mut session, &mut pending_console_output)?;
        Ok(())
    }
}
