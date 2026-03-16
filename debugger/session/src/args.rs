use serde_json::Value;
use silverscript_lang::ast::{ContractAst, Expr, ExprKind};
use silverscript_lang::compiler::struct_object;
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

fn json_value_to_untyped_expr(value: &Value) -> Result<Expr<'static>, String> {
    match value {
        Value::Number(n) => Ok(Expr::int(n.as_i64().ok_or_else(|| "invalid int value".to_string())?)),
        Value::Bool(b) => Ok(Expr::bool(*b)),
        Value::String(s) => {
            if s.starts_with("0x") || s.starts_with("0X") {
                let bytes = parse_hex_bytes(s)?;
                if bytes.len() == 1 { Ok(Expr::byte(bytes[0])) } else { Ok(bytes_expr(bytes)) }
            } else {
                Ok(Expr::string(s.clone()))
            }
        }
        Value::Array(values) => values
            .iter()
            .map(json_value_to_untyped_expr)
            .collect::<Result<Vec<_>, _>>()
            .map(|values| Expr::new(ExprKind::Array(values), span::Span::default())),
        Value::Object(fields) => {
            let mut expr_fields = Vec::with_capacity(fields.len());
            for (name, value) in fields {
                expr_fields.push((Box::leak(name.clone().into_boxed_str()) as &'static str, json_value_to_untyped_expr(value)?));
            }
            Ok(struct_object(expr_fields))
        }
        Value::Null => Err("null is not supported in structured args".to_string()),
    }
}

fn json_value_to_typed_expr(type_name: &str, value: &Value) -> Result<Expr<'static>, String> {
    if let Some(element_type) = type_name.strip_suffix("[]") {
        match value {
            Value::Array(values) => values
                .iter()
                .map(|value| json_value_to_typed_expr(element_type, value))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| Expr::new(ExprKind::Array(values), span::Span::default())),
            Value::String(raw) if element_type == "byte" => Ok(bytes_expr(parse_hex_bytes(raw)?)),
            _ => Err(format!("unsupported array literal format for '{type_name}'")),
        }
    } else {
        match value {
            Value::String(raw) => parse_typed_arg(type_name, raw),
            Value::Number(raw) if type_name == "int" => Ok(Expr::int(raw.as_i64().ok_or_else(|| "invalid int value".to_string())?)),
            Value::Number(raw) if type_name == "byte" => {
                let value = raw.as_u64().ok_or_else(|| "invalid byte value".to_string())?;
                let byte = u8::try_from(value).map_err(|_| format!("byte expects value in 0..=255, got {value}"))?;
                Ok(Expr::byte(byte))
            }
            Value::Bool(raw) if type_name == "bool" => Ok(Expr::bool(*raw)),
            Value::Object(_) => json_value_to_untyped_expr(value),
            _ => Err(format!("unsupported arg value for '{type_name}'")),
        }
    }
}

pub fn parse_typed_arg(type_name: &str, raw: &str) -> Result<Expr<'static>, String> {
    let trimmed = raw.trim();

    if let Some(element_type) = type_name.strip_suffix("[]") {
        if trimmed.starts_with('[') {
            let values = serde_json::from_str::<Vec<Value>>(trimmed).map_err(|err| format!("invalid array arg '{raw}': {err}"))?;
            return values
                .iter()
                .map(|value| json_value_to_typed_expr(element_type, value))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| Expr::new(ExprKind::Array(values), span::Span::default()));
        }
        if element_type == "byte" {
            return Ok(bytes_expr(parse_hex_bytes(trimmed)?));
        }
        return Err(format!("unsupported array literal format for '{type_name}'"));
    }

    if trimmed == "null" {
        return Err("null is not supported in structured args".to_string());
    }

    if trimmed.starts_with('{') {
        let value = serde_json::from_str::<Value>(trimmed).map_err(|err| format!("invalid {type_name} arg '{raw}': {err}"))?;
        return json_value_to_untyped_expr(&value);
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

#[cfg(test)]
mod tests {
    use super::{parse_ctor_args, parse_typed_arg};
    use silverscript_lang::ast::{ExprKind, parse_contract_ast};

    #[test]
    fn parses_state_object_arg() {
        let parsed = parse_typed_arg("State", r#"{"amount": 7, "owner": "0x11"}"#).expect("parse State");
        assert!(matches!(parsed.kind, ExprKind::StateObject(_)));
    }

    #[test]
    fn parses_declared_struct_object_arg() {
        let parsed = parse_typed_arg("Pair", r#"{"amount": 7, "owner": "0x11"}"#).expect("parse struct");
        assert!(matches!(parsed.kind, ExprKind::StateObject(_)));
    }

    #[test]
    fn parses_state_object_array_arg() {
        let parsed = parse_typed_arg("State[]", r#"[{"amount": 7}, {"amount": 9}]"#).expect("parse State[]");
        assert!(matches!(parsed.kind, ExprKind::Array(_)));
    }

    #[test]
    fn parses_struct_array_arg_with_fixed_bytes_fields() {
        let parsed = parse_typed_arg("Pair[]", r#"[{"amount": 7, "code": "0x0102"}]"#).expect("parse struct[]");
        let ExprKind::Array(values) = parsed.kind else {
            panic!("expected array expr");
        };
        assert_eq!(values.len(), 1);
        assert!(matches!(values[0].kind, ExprKind::StateObject(_)));
    }

    #[test]
    fn rejects_null_in_structured_args() {
        let error = parse_typed_arg("State", "null").expect_err("null should be rejected");
        assert!(error.contains("null"));
    }

    #[test]
    fn rejects_malformed_json_structured_args() {
        let error = parse_typed_arg("State[]", "[{]").expect_err("malformed JSON should fail");
        assert!(error.contains("invalid array arg"));
    }

    #[test]
    fn parses_struct_constructor_arg() {
        let contract = parse_contract_ast(
            r#"
            contract Demo(Pair seed) {
                struct Pair {
                    int amount;
                    byte[2] code;
                }

                entrypoint function inspect() {
                    require(true);
                }
            }
            "#,
        )
        .expect("parse contract");

        let args = parse_ctor_args(&contract, &[r#"{"amount": 7, "code": "0x1234"}"#.to_string()]).expect("parse ctor args");
        assert_eq!(args.len(), 1);
        assert!(matches!(args[0].kind, ExprKind::StateObject(_)));
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
