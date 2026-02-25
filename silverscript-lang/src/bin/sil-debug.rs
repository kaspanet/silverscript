use std::fs;
use std::io::{self, BufRead, Write};

use clap::Parser;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags};

use silverscript_lang::ast::{Expr, ExprKind, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::debug::session::{DebugEngine, DebugSession};
use silverscript_lang::span;

const PROMPT: &str = "(sdb) ";

#[derive(Debug, Parser)]
#[command(name = "sil-debug", about = "SilverScript debugger")]
struct CliArgs {
    script_path: String,
    #[arg(long = "no-selector")]
    without_selector: bool,
    #[arg(long = "function", short = 'f')]
    function_name: Option<String>,
    #[arg(long = "ctor-arg")]
    raw_ctor_args: Vec<String>,
    #[arg(long = "arg", short = 'a')]
    raw_args: Vec<String>,
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
    // Allow odd length by implicitly left-padding with 0.
    let normalized = if hex_str.len() % 2 != 0 { format!("0{hex_str}") } else { hex_str.to_string() };
    let mut out = vec![0u8; normalized.len() / 2];
    faster_hex::hex_decode(normalized.as_bytes(), &mut out)?;
    Ok(out)
}

fn bytes_expr(bytes: Vec<u8>) -> Expr<'static> {
    Expr::new(ExprKind::Array(bytes.into_iter().map(Expr::byte).collect()), span::Span::default())
}

fn parse_typed_arg(type_name: &str, raw: &str) -> Result<Expr<'static>, Box<dyn std::error::Error>> {
    if let Some(element_type) = type_name.strip_suffix("[]") {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') {
            let values = serde_json::from_str::<Vec<serde_json::Value>>(trimmed)?;
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let expr = match value {
                    serde_json::Value::Number(n) => Expr::int(n.as_i64().ok_or("invalid int in array")?),
                    serde_json::Value::Bool(b) => Expr::bool(b),
                    serde_json::Value::String(s) => parse_typed_arg(element_type, &s)?,
                    _ => return Err("unsupported array element (expected number/bool/string)".into()),
                };
                out.push(expr);
            }
            return Ok(Expr::new(ExprKind::Array(out), span::Span::default()));
        }
        if element_type == "byte" {
            return Ok(bytes_expr(parse_hex_bytes(trimmed)?));
        }
        return Err(format!("unsupported array literal format for '{type_name}'").into());
    }

    match type_name {
        "int" => Ok(Expr::int(parse_int_arg(raw)?)),
        "bool" => match raw {
            "true" => Ok(Expr::bool(true)),
            "false" => Ok(Expr::bool(false)),
            _ => Err(format!("invalid bool '{raw}' (expected true/false)").into()),
        },
        "string" => Ok(Expr::string(raw.to_string())),
        "byte" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() == 1 { Ok(Expr::byte(bytes[0])) } else { Err(format!("byte expects 1 byte, got {}", bytes.len()).into()) }
        }
        "bytes" => Ok(bytes_expr(parse_hex_bytes(raw)?)),
        "pubkey" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 32 {
                return Err(format!("pubkey expects 32 bytes, got {}", bytes.len()).into());
            }
            Ok(bytes_expr(bytes))
        }
        "sig" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 65 {
                return Err(format!("sig expects 65 bytes, got {}", bytes.len()).into());
            }
            Ok(bytes_expr(bytes))
        }
        "datasig" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 64 {
                return Err(format!("datasig expects 64 bytes, got {}", bytes.len()).into());
            }
            Ok(bytes_expr(bytes))
        }
        other => {
            let size = other
                .strip_prefix("bytes")
                .and_then(|v| v.parse::<usize>().ok())
                .or_else(|| other.strip_prefix("byte[").and_then(|v| v.strip_suffix(']')).and_then(|v| v.parse::<usize>().ok()));
            if let Some(size) = size {
                let bytes = parse_hex_bytes(raw)?;
                if bytes.len() != size {
                    return Err(format!("{other} expects {size} bytes, got {}", bytes.len()).into());
                }
                Ok(bytes_expr(bytes))
            } else {
                Err(format!("unsupported arg type '{other}'").into())
            }
        }
    }
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
                for var in variables {
                    let constant_suffix = if var.is_constant { " (const)" } else { "" };
                    println!(
                        "{}{} ({}) = {}",
                        var.name,
                        constant_suffix,
                        var.type_name,
                        session.format_value(&var.type_name, &var.value)
                    );
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

fn run_repl(session: &mut DebugSession<'_, '_>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
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
            match session.step_over()? {
                Some(_) => show_step_view(session),
                None => {
                    println!("Done.");
                    break;
                }
            }
            continue;
        }

        let mut parts = cmd.split_whitespace();
        match parts.next().unwrap_or("") {
            "step" | "s" => match session.step_into()? {
                Some(_) => show_step_view(session),
                None => {
                    println!("Done.");
                    break;
                }
            },
            "si" => match session.step_opcode()? {
                Some(_) => show_step_view(session),
                None => {
                    println!("Done.");
                    break;
                }
            },
            "finish" | "out" => match session.step_out()? {
                Some(_) => show_step_view(session),
                None => {
                    println!("Done.");
                    break;
                }
            },
            "c" | "continue" => match session.continue_to_breakpoint()? {
                Some(_) => show_step_view(session),
                None => {
                    println!("Done.");
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
                        Ok(var) => {
                            let constant_suffix = if var.is_constant { " (const)" } else { "" };
                            println!(
                                "{}{} ({}) = {}",
                                var.name,
                                constant_suffix,
                                var.type_name,
                                session.format_value(&var.type_name, &var.value)
                            );
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();
    let script_path = cli.script_path;
    let without_selector = cli.without_selector;
    let function_name = cli.function_name;
    let raw_ctor_args = cli.raw_ctor_args;
    let raw_args = cli.raw_args;

    let source = fs::read_to_string(&script_path)?;
    let parsed_contract = parse_contract_ast(&source)?;

    let entrypoint_count = parsed_contract.functions.iter().filter(|func| func.entrypoint).count();
    if without_selector && entrypoint_count != 1 {
        return Err("--no-selector requires exactly one entrypoint function".into());
    }

    if parsed_contract.params.len() != raw_ctor_args.len() {
        return Err(format!("constructor expects {} arguments, got {}", parsed_contract.params.len(), raw_ctor_args.len()).into());
    }

    let mut ctor_args = Vec::with_capacity(raw_ctor_args.len());
    for (param, raw) in parsed_contract.params.iter().zip(raw_ctor_args.iter()) {
        ctor_args.push(parse_typed_arg(&param.type_ref.type_name(), raw)?);
    }

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let flags = EngineFlags { covenants_enabled: true };
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
