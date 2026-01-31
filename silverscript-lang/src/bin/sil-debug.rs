use std::env;
use std::fs;
use std::io::{self, BufRead, Write};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags};

use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::debug::MappingKind;
use silverscript_lang::debug::session::{DebugEngine, DebugSession};

const PROMPT: &str = "(sdb) ";

fn print_usage() {
    eprintln!(
        "Usage: sil-debug <contract.sil> [--no-selector] [--function <name>] [--ctor-arg <value> ...] [--arg <value> ...]\n\n  --ctor-arg is typed by the contract constructor params.\n  --arg is typed by the selected function ABI.\n\nExamples:\n  # constructor (int x, int y), function hello(int a, int b)\n  sil-debug if_statement.sil --function hello --ctor-arg 3 --ctor-arg 10 --arg 1 --arg 2\n\nValue formats:\n  int:        123 (or 0x7b)\n  bool:       true|false\n  string:     hello (shell quoting handles spaces)\n  bytes*:     0xdeadbeef\n"
    );
}

fn parse_int_arg(raw: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let cleaned = raw.replace('_', "");
    if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        return Ok(i64::from_str_radix(hex, 16)?);
    }
    Ok(cleaned.parse::<i64>()?)
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let trimmed = raw.trim();
    let hex_str = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if hex_str.is_empty() {
        return Ok(vec![]);
    }
    // Allow odd length by implicitly left-padding with 0
    let normalized = if hex_str.len() % 2 != 0 { format!("0{hex_str}") } else { hex_str.to_string() };
    Ok(hex::decode(normalized)?)
}

fn parse_typed_arg(type_name: &str, raw: &str) -> Result<Expr, Box<dyn std::error::Error>> {
    match type_name {
        "int" => Ok(Expr::Int(parse_int_arg(raw)?)),
        "bool" => match raw {
            "true" => Ok(Expr::Bool(true)),
            "false" => Ok(Expr::Bool(false)),
            _ => Err(format!("invalid bool '{raw}' (expected true/false)").into()),
        },
        "string" => Ok(Expr::String(raw.to_string())),
        "bytes" | "byte" | "pubkey" | "sig" | "datasig" => Ok(Expr::Bytes(parse_hex_bytes(raw)?)),
        other => {
            if let Some(size) = other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
                let bytes = parse_hex_bytes(raw)?;
                if bytes.len() != size {
                    return Err(format!("{other} expects {size} bytes, got {}", bytes.len()).into());
                }
                Ok(Expr::Bytes(bytes))
            } else {
                Err(format!("unsupported arg type '{other}'").into())
            }
        }
    }
}

fn show_state(session: &DebugSession<'_>) {
    let state = session.state();
    if let Some(op) = state.opcode {
        println!("[{}/{}] {op}", state.pc, session.opcode_count());
    }
    if let Some(mapping) = state.mapping {
        match &mapping.kind {
            MappingKind::Statement { stmt_type } => {
                if let Some(span) = mapping.span {
                    println!("Line {} ({})", span.line, stmt_type);
                } else {
                    println!("Statement ({})", stmt_type);
                }
            }
            MappingKind::Synthetic { label } => println!("Synthetic ({label})"),
        }
    }
    println!("Stack: {:?}", state.stack);
}

fn show_stack(session: &DebugSession<'_>) {
    let stack = session.stack();
    for (i, item) in stack.iter().enumerate().rev() {
        println!("[{i}] {item}");
    }
}

fn show_source_context(session: &DebugSession<'_>) {
    let Some(context) = session.source_context() else {
        println!("No source context available.");
        return;
    };

    for line in context.lines {
        let marker = if line.is_active { "→" } else { " " };
        println!("{marker} {:>4} | {}", line.line, line.text);
    }
}

fn run_repl(session: &mut DebugSession<'_>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
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
            match session.step_statement()? {
                Some(_) => show_state(session),
                None => {
                    println!("Done.");
                    break;
                }
            }
            continue;
        }

        let mut parts = cmd.split_whitespace();
        match parts.next().unwrap_or("") {
            "si" | "step" | "s" => match session.step_opcode()? {
                Some(_) => show_state(session),
                None => {
                    println!("Done.");
                    break;
                }
            },
            "c" | "continue" => match session.continue_to_breakpoint()? {
                Some(_) => show_state(session),
                None => {
                    println!("Done.");
                    break;
                }
            },
            "b" | "break" => {
                if let Some(arg) = parts.next() {
                    match arg.parse::<u32>() {
                        Ok(line) => {
                            session.add_breakpoint(line);
                            println!("Breakpoint set at line {line}");
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
            "vars" => match session.list_variables() {
                Ok(variables) => {
                    if variables.is_empty() {
                        println!("No variables in scope.");
                    } else {
                        for var in variables {
                            println!("{} ({}) = {}", var.name, var.type_name, session.format_value(&var.type_name, &var.value));
                        }
                    }
                }
                Err(err) => println!("ERROR: {err}"),
            },
            "print" | "p" => {
                if let Some(name) = parts.next() {
                    match session.variable_by_name(name) {
                        Ok(var) => println!("{} ({}) = {}", var.name, var.type_name, session.format_value(&var.type_name, &var.value)),
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
                    "Commands: next (n), step opcode (si), continue (c), break (b <line>), list (l), vars, print <name>, stack, quit (q)"
                )
            }
            _ => println!(
                "Commands: next (n), step opcode (si), continue (c), break (b <line>), list (l), vars, print <name>, stack, quit (q)"
            ),
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut script_path: Option<String> = None;
    let mut without_selector = false;
    let mut function_name: Option<String> = None;
    let mut raw_ctor_args: Vec<String> = Vec::new();
    let mut raw_args: Vec<String> = Vec::new();

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-selector" => without_selector = true,
            "--function" | "-f" => {
                function_name = args.next();
                if function_name.is_none() {
                    print_usage();
                    return Err("missing function name".into());
                }
            }
            "--ctor-arg" => {
                let value = args.next();
                if value.is_none() {
                    print_usage();
                    return Err("missing --ctor-arg value".into());
                }
                raw_ctor_args.push(value.expect("checked"));
            }
            "--arg" | "-a" => {
                let value = args.next();
                if value.is_none() {
                    print_usage();
                    return Err("missing --arg value".into());
                }
                raw_args.push(value.expect("checked"));
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            _ => {
                if script_path.is_some() {
                    print_usage();
                    return Err("unexpected extra argument".into());
                }
                script_path = Some(arg);
            }
        }
    }

    let script_path = match script_path {
        Some(path) => path,
        None => {
            print_usage();
            return Err("missing contract path".into());
        }
    };

    let source = fs::read_to_string(&script_path)?;
    let parsed_contract = parse_contract_ast(&source)?;

    if parsed_contract.params.len() != raw_ctor_args.len() {
        return Err(format!("constructor expects {} arguments, got {}", parsed_contract.params.len(), raw_ctor_args.len()).into());
    }

    let mut ctor_args = Vec::with_capacity(raw_ctor_args.len());
    for (param, raw) in parsed_contract.params.iter().zip(raw_ctor_args.iter()) {
        ctor_args.push(parse_typed_arg(&param.type_name, raw)?);
    }

    let compile_opts = CompileOptions { covenants_enabled: true, without_selector, record_debug_spans: true };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let flags = EngineFlags { covenants_enabled: compile_opts.covenants_enabled };
    let engine = DebugEngine::new(ctx, flags);

    // Seed the stack like a real spend: run sigscript pushes before locking script.
    let default_name = compiled.abi.first().map(|entry| entry.name.clone()).ok_or("contract has no functions")?;
    let selected_name = function_name.unwrap_or(default_name);
    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| format!("function '{selected_name}' not found"))?;

    if entry.inputs.len() != raw_args.len() {
        return Err(format!("function '{selected_name}' expects {} arguments, got {}", entry.inputs.len(), raw_args.len()).into());
    }

    let mut typed_args = Vec::with_capacity(raw_args.len());
    for (input, raw) in entry.inputs.iter().zip(raw_args.iter()) {
        typed_args.push(parse_typed_arg(&input.type_name, raw)?);
    }

    // Always seed: even in --no-selector mode the function params must be pushed.
    let sigscript = compiled.build_sig_script(&selected_name, typed_args)?;
    let mut session = DebugSession::full(&sigscript, &compiled.script, &source, debug_info, engine)?;

    println!("Stepping through {} bytes of script", compiled.script.len());
    session.run_to_first_executed_statement()?;
    show_source_context(&session);
    run_repl(&mut session)?;

    Ok(())
}
