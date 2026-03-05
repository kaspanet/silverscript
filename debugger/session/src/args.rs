use silverscript_lang::ast::{ContractAst, Expr, ExprKind};
use silverscript_lang::span;

pub fn parse_int_arg(raw: &str) -> Result<i64, String> {
    let cleaned = raw.replace('_', "");
    if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).map_err(|err| format!("invalid hex int '{raw}': {err}"));
    }
    cleaned.parse::<i64>().map_err(|err| format!("invalid int '{raw}': {err}"))
}

pub fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    let hex_str = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if hex_str.is_empty() {
        return Ok(vec![]);
    }
    let normalized = if hex_str.len() % 2 != 0 { format!("0{hex_str}") } else { hex_str.to_string() };
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("invalid hex bytes '{raw}'"));
    }
    let mut out = vec![0u8; normalized.len() / 2];
    faster_hex::hex_decode(normalized.as_bytes(), &mut out).map_err(|err| format!("invalid hex '{raw}': {err}"))?;
    Ok(out)
}

pub fn bytes_expr(bytes: Vec<u8>) -> Expr<'static> {
    Expr::new(ExprKind::Array(bytes.into_iter().map(Expr::byte).collect()), span::Span::default())
}

pub fn parse_typed_arg(type_name: &str, raw: &str) -> Result<Expr<'static>, String> {
    if let Some(element_type) = type_name.strip_suffix("[]") {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') {
            let values =
                serde_json::from_str::<Vec<serde_json::Value>>(trimmed).map_err(|err| format!("invalid array arg '{raw}': {err}"))?;
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let expr = match value {
                    serde_json::Value::Number(n) => Expr::int(n.as_i64().ok_or_else(|| "invalid int in array".to_string())?),
                    serde_json::Value::Bool(b) => Expr::bool(b),
                    serde_json::Value::String(s) => parse_typed_arg(element_type, &s)?,
                    _ => return Err("unsupported array element (expected number/bool/string)".to_string()),
                };
                out.push(expr);
            }
            return Ok(Expr::new(ExprKind::Array(out), span::Span::default()));
        }
        if element_type == "byte" {
            return Ok(bytes_expr(parse_hex_bytes(trimmed)?));
        }
        return Err(format!("unsupported array literal format for '{type_name}'"));
    }

    match type_name {
        "int" => Ok(Expr::int(parse_int_arg(raw)?)),
        "bool" => match raw {
            "true" => Ok(Expr::bool(true)),
            "false" => Ok(Expr::bool(false)),
            _ => Err(format!("invalid bool '{raw}' (expected true/false)")),
        },
        "string" => Ok(Expr::string(raw.to_string())),
        "byte" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() == 1 { Ok(Expr::byte(bytes[0])) } else { Err(format!("byte expects 1 byte, got {}", bytes.len())) }
        }
        "bytes" => Ok(bytes_expr(parse_hex_bytes(raw)?)),
        "pubkey" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 32 {
                return Err(format!("pubkey expects 32 bytes, got {}", bytes.len()));
            }
            Ok(bytes_expr(bytes))
        }
        "sig" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 65 && bytes.len() != 32 {
                return Err(format!("sig expects 65 bytes (or 32-byte secret key for auto-sign), got {}", bytes.len()));
            }
            Ok(bytes_expr(bytes))
        }
        "datasig" => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 64 && bytes.len() != 32 {
                return Err(format!("datasig expects 64 bytes (or 32-byte secret key for auto-sign), got {}", bytes.len()));
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
                    return Err(format!("{other} expects {size} bytes, got {}", bytes.len()));
                }
                Ok(bytes_expr(bytes))
            } else {
                Err(format!("unsupported arg type '{other}'"))
            }
        }
    }
}

pub fn parse_ctor_args(parsed_contract: &ContractAst<'_>, raw_ctor_args: &[String]) -> Result<Vec<Expr<'static>>, String> {
    if parsed_contract.params.len() != raw_ctor_args.len() {
        return Err(format!("constructor expects {} arguments, got {}", parsed_contract.params.len(), raw_ctor_args.len()));
    }

    let mut out = Vec::with_capacity(raw_ctor_args.len());
    for (param, raw) in parsed_contract.params.iter().zip(raw_ctor_args.iter()) {
        out.push(parse_typed_arg(&param.type_ref.type_name(), raw)?);
    }
    Ok(out)
}

pub fn parse_call_args(input_types: &[String], raw_args: &[String]) -> Result<Vec<Expr<'static>>, String> {
    if input_types.len() != raw_args.len() {
        return Err(format!("function expects {} arguments, got {}", input_types.len(), raw_args.len()));
    }

    let mut typed_args = Vec::with_capacity(raw_args.len());
    for (input_type, raw) in input_types.iter().zip(raw_args.iter()) {
        typed_args.push(parse_typed_arg(input_type, raw)?);
    }
    Ok(typed_args)
}
