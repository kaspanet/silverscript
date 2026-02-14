#![allow(dead_code)]

use std::env;
use std::error::Error;

use silverscript_lang::ast::Expr;

pub struct DebugCliArgs {
    pub script_path: String,
    pub without_selector: bool,
    pub function_name: Option<String>,
    pub raw_ctor_args: Vec<String>,
    pub raw_args: Vec<String>,
}

pub fn print_usage(bin_name: &str) {
    eprintln!(
        "Usage: {bin_name} <contract.sil> [--no-selector] [--function <name>] [--ctor-arg <value> ...] [--arg <value> ...]\n\n  --ctor-arg is typed by the contract constructor params.\n  --arg is typed by the selected function ABI.\n\nExamples:\n  # constructor (int x, int y), function hello(int a, int b)\n  {bin_name} if_statement.sil --function hello --ctor-arg 3 --ctor-arg 10 --arg 1 --arg 2\n\nValue formats:\n  int:        123 (or 0x7b)\n  bool:       true|false\n  string:     hello (shell quoting handles spaces)\n  bytes*:     0xdeadbeef\n"
    );
}

pub fn parse_cli_args_or_help(bin_name: &str) -> Result<Option<DebugCliArgs>, Box<dyn Error>> {
    parse_cli_args_or_help_from(bin_name, env::args().skip(1))
}

fn parse_cli_args_or_help_from(
    bin_name: &str,
    mut args: impl Iterator<Item = String>,
) -> Result<Option<DebugCliArgs>, Box<dyn Error>> {
    let mut script_path: Option<String> = None;
    let mut without_selector = false;
    let mut function_name: Option<String> = None;
    let mut raw_ctor_args: Vec<String> = Vec::new();
    let mut raw_args: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-selector" => without_selector = true,
            "--function" | "-f" => {
                function_name = args.next();
                if function_name.is_none() {
                    print_usage(bin_name);
                    return Err("missing function name".into());
                }
            }
            "--ctor-arg" => {
                let value = args.next();
                if value.is_none() {
                    print_usage(bin_name);
                    return Err("missing --ctor-arg value".into());
                }
                raw_ctor_args.push(value.expect("checked"));
            }
            "--arg" | "-a" => {
                let value = args.next();
                if value.is_none() {
                    print_usage(bin_name);
                    return Err("missing --arg value".into());
                }
                raw_args.push(value.expect("checked"));
            }
            "-h" | "--help" => {
                print_usage(bin_name);
                return Ok(None);
            }
            _ => {
                if script_path.is_some() {
                    print_usage(bin_name);
                    return Err("unexpected extra argument".into());
                }
                script_path = Some(arg);
            }
        }
    }

    let script_path = match script_path {
        Some(path) => path,
        None => {
            print_usage(bin_name);
            return Err("missing contract path".into());
        }
    };

    Ok(Some(DebugCliArgs { script_path, without_selector, function_name, raw_ctor_args, raw_args }))
}

fn parse_int_arg(raw: &str) -> Result<i64, Box<dyn Error>> {
    let cleaned = raw.replace('_', "");
    if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        return Ok(i64::from_str_radix(hex, 16)?);
    }
    Ok(cleaned.parse::<i64>()?)
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let trimmed = raw.trim();
    let hex_str = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if hex_str.is_empty() {
        return Ok(vec![]);
    }
    // Allow odd length by implicitly left-padding with 0
    let normalized = if hex_str.len() % 2 != 0 { format!("0{hex_str}") } else { hex_str.to_string() };
    Ok(hex::decode(normalized)?)
}

pub fn parse_typed_arg(type_name: &str, raw: &str) -> Result<Expr, Box<dyn Error>> {
    // Support array inputs until the LSP exists by allowing:
    // - JSON arrays: [1,2,3] or ["0x01","0x02"]
    // - raw hex bytes: 0x... (treated as encoded array bytes)
    if let Some(element_type) = type_name.strip_suffix("[]") {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') {
            let values = serde_json::from_str::<Vec<serde_json::Value>>(trimmed)?;
            let mut out = Vec::with_capacity(values.len());
            for v in values {
                let expr = match v {
                    serde_json::Value::Number(n) => Expr::Int(n.as_i64().ok_or("invalid int in array")?),
                    serde_json::Value::Bool(b) => Expr::Bool(b),
                    serde_json::Value::String(s) => parse_typed_arg(element_type, &s)?,
                    _ => return Err("unsupported array element (expected number/bool/string)".into()),
                };
                out.push(expr);
            }
            return Ok(Expr::Array(out));
        }
        // If not JSON, accept hex bytes for already-encoded arrays.
        return Ok(Expr::Bytes(parse_hex_bytes(trimmed)?));
    }

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
