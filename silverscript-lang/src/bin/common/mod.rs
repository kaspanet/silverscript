use std::error::Error;

use clap::{Parser, error::ErrorKind};
use silverscript_lang::ast::Expr;

#[derive(Debug, Parser)]
#[command(
    name = "sil-debug",
    about = "Debug a SilverScript contract",
    after_help = "Examples:\n  # constructor (int x, int y), function hello(int a, int b)\n  sil-debug if_statement.sil --function hello --ctor-arg 3 --ctor-arg 10 --arg 1 --arg 2\n\nValue formats:\n  int:        123 (or 0x7b)\n  bool:       true|false\n  string:     hello (shell quoting handles spaces)\n  bytes*:     0xdeadbeef"
)]
pub struct DebugCliArgs {
    #[arg(value_name = "contract.sil")]
    pub script_path: String,
    #[arg(long = "no-selector")]
    pub without_selector: bool,
    #[arg(short = 'f', long = "function")]
    pub function_name: Option<String>,
    #[arg(long = "ctor-arg", value_name = "value", allow_hyphen_values = true)]
    pub raw_ctor_args: Vec<String>,
    #[arg(short = 'a', long = "arg", value_name = "value", allow_hyphen_values = true)]
    pub raw_args: Vec<String>,
}

pub fn parse_cli_args_or_help(bin_name: &str) -> Result<Option<DebugCliArgs>, Box<dyn Error>> {
    match DebugCliArgs::try_parse() {
        Ok(args) => Ok(Some(args)),
        Err(err) => match err.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                err.print()?;
                Ok(None)
            }
            _ => {
                eprintln!("{bin_name}: {err}");
                Err(Box::new(err))
            }
        },
    }
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
    let mut decoded = vec![0_u8; normalized.len() / 2];
    faster_hex::hex_decode(normalized.as_bytes(), &mut decoded)?;
    Ok(decoded)
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
