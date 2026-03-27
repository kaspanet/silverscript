use std::collections::HashMap;

use serde_json::Value;
use silverscript_lang::ast::{ArrayDim, ContractAst, Expr, ExprKind, ParamAst, StateFieldExpr, TypeBase, TypeRef};
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

pub fn bytes_expr<'i>(bytes: Vec<u8>) -> Expr<'i> {
    Expr::new(ExprKind::Array(bytes.into_iter().map(Expr::byte).collect()), span::Span::default())
}

#[derive(Debug, Clone)]
struct StructShapeField {
    name: String,
    type_ref: TypeRef,
}

#[derive(Debug, Clone, Default)]
struct StructShapeRegistry {
    shapes: HashMap<String, Vec<StructShapeField>>,
}

impl StructShapeRegistry {
    fn from_contract(contract: &ContractAst<'_>) -> Self {
        let mut shapes = HashMap::new();
        shapes.insert(
            "State".to_string(),
            contract
                .fields
                .iter()
                .map(|field| StructShapeField { name: field.name.clone(), type_ref: field.type_ref.clone() })
                .collect(),
        );
        for item in &contract.structs {
            shapes.insert(
                item.name.clone(),
                item.fields
                    .iter()
                    .map(|field| StructShapeField { name: field.name.clone(), type_ref: field.type_ref.clone() })
                    .collect(),
            );
        }
        Self { shapes }
    }

    fn fields_for_type(&self, type_ref: &TypeRef) -> Option<&[StructShapeField]> {
        if type_ref.is_array() {
            return None;
        }
        match &type_ref.base {
            TypeBase::Custom(name) => self.shapes.get(name).map(Vec::as_slice),
            _ => None,
        }
    }
}

fn is_one_dim_byte_array_type(type_ref: &TypeRef) -> bool {
    matches!(type_ref.base, TypeBase::Byte) && type_ref.array_dims.len() == 1
}

fn validate_byte_array_len(type_ref: &TypeRef, len: usize) -> Result<(), String> {
    if let Some(ArrayDim::Fixed(size)) = type_ref.array_size()
        && len != *size
    {
        return Err(format!("{} expects {} bytes, got {}", type_ref.type_name(), size, len));
    }
    Ok(())
}

fn validate_array_len(type_ref: &TypeRef, len: usize) -> Result<(), String> {
    if let Some(ArrayDim::Fixed(size)) = type_ref.array_size()
        && len != *size
    {
        return Err(format!("{} expects {} elements, got {}", type_ref.type_name(), size, len));
    }
    Ok(())
}

fn parse_byte_array_arg<'i>(type_ref: &TypeRef, raw: &str) -> Result<Expr<'i>, String> {
    let bytes = parse_hex_bytes(raw)?;
    validate_byte_array_len(type_ref, bytes.len())?;
    Ok(bytes_expr(bytes))
}

fn parse_scalar_arg<'i>(type_ref: &TypeRef, raw: &str) -> Result<Expr<'i>, String> {
    match type_ref.base {
        TypeBase::Int => Ok(Expr::int(parse_int_arg(raw)?)),
        TypeBase::Bool => match raw {
            "true" => Ok(Expr::bool(true)),
            "false" => Ok(Expr::bool(false)),
            _ => Err(format!("invalid bool '{raw}' (expected true/false)")),
        },
        TypeBase::String => Ok(Expr::string(raw.to_string())),
        TypeBase::Byte if type_ref.is_array() => parse_byte_array_arg(type_ref, raw),
        TypeBase::Byte => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() == 1 { Ok(Expr::byte(bytes[0])) } else { Err(format!("byte expects 1 byte, got {}", bytes.len())) }
        }
        TypeBase::Pubkey => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 32 {
                return Err(format!("pubkey expects 32 bytes, got {}", bytes.len()));
            }
            Ok(bytes_expr(bytes))
        }
        TypeBase::Sig => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 65 && bytes.len() != 32 {
                return Err(format!("sig expects 65 bytes (or 32-byte secret key for auto-sign), got {}", bytes.len()));
            }
            Ok(bytes_expr(bytes))
        }
        TypeBase::Datasig => {
            let bytes = parse_hex_bytes(raw)?;
            if bytes.len() != 64 && bytes.len() != 32 {
                return Err(format!("datasig expects 64 bytes (or 32-byte secret key for auto-sign), got {}", bytes.len()));
            }
            Ok(bytes_expr(bytes))
        }
        TypeBase::Custom(_) => Err(format!("unsupported arg type '{}'", type_ref.type_name())),
    }
}

fn parse_struct_arg<'i>(
    entries: &serde_json::Map<String, Value>,
    declared_fields: &[StructShapeField],
    shapes: &StructShapeRegistry,
) -> Result<Expr<'i>, String> {
    let mut provided = entries.iter().collect::<HashMap<_, _>>();

    let mut out = Vec::with_capacity(declared_fields.len());
    for field in declared_fields {
        let value = provided.remove(&field.name).ok_or_else(|| format!("struct field '{}' must be initialized", field.name))?;
        out.push(StateFieldExpr {
            name: field.name.clone(),
            expr: parse_json_value_for_type(value, &field.type_ref, shapes)?,
            span: span::Span::default(),
            name_span: span::Span::default(),
        });
    }

    if let Some(extra) = provided.keys().next() {
        return Err(format!("unknown struct field '{}'", extra));
    }

    Ok(Expr::new(ExprKind::StateObject(out), span::Span::default()))
}

fn parse_array_arg<'i>(values: &[Value], type_ref: &TypeRef, shapes: &StructShapeRegistry) -> Result<Expr<'i>, String> {
    validate_array_len(type_ref, values.len())?;
    let element_type = type_ref.element_type().ok_or_else(|| format!("unsupported arg type '{}'", type_ref.type_name()))?;
    values
        .iter()
        .map(|value| parse_json_value_for_type(value, &element_type, shapes))
        .collect::<Result<Vec<_>, _>>()
        .map(|values| Expr::new(ExprKind::Array(values), span::Span::default()))
}

fn parse_json_value_for_type<'i>(value: &Value, type_ref: &TypeRef, shapes: &StructShapeRegistry) -> Result<Expr<'i>, String> {
    if matches!(value, Value::Null) {
        return Err("null is not supported in structured args".to_string());
    }

    if type_ref.is_array() {
        if let Value::String(raw) = value
            && is_one_dim_byte_array_type(type_ref)
        {
            return parse_byte_array_arg(type_ref, raw);
        }

        let Value::Array(values) = value else {
            return Err(format!("unsupported array literal format for '{}'", type_ref.type_name()));
        };
        return parse_array_arg(values, type_ref, shapes);
    }

    if let Some(fields) = shapes.fields_for_type(type_ref) {
        let Value::Object(entries) = value else {
            return Err(format!("unsupported object literal format for '{}'", type_ref.type_name()));
        };
        return parse_struct_arg(entries, fields, shapes);
    }

    match value {
        Value::String(raw) => parse_scalar_arg(type_ref, raw),
        Value::Number(raw) if matches!(type_ref.base, TypeBase::Int) => {
            Ok(Expr::int(raw.as_i64().ok_or_else(|| "invalid int value".to_string())?))
        }
        Value::Number(raw) if matches!(type_ref.base, TypeBase::Byte) => {
            let byte_value = raw.as_u64().ok_or_else(|| "invalid byte value".to_string())?;
            let byte = u8::try_from(byte_value).map_err(|_| format!("byte expects value in 0..=255, got {byte_value}"))?;
            Ok(Expr::byte(byte))
        }
        Value::Bool(raw) if matches!(type_ref.base, TypeBase::Bool) => Ok(Expr::bool(*raw)),
        _ => Err(format!("unsupported arg value for '{}'", type_ref.type_name())),
    }
}

fn parse_typed_arg<'i>(type_ref: &TypeRef, shapes: &StructShapeRegistry, raw: &str) -> Result<Expr<'i>, String> {
    let trimmed = raw.trim();
    if trimmed == "null" {
        return Err("null is not supported in structured args".to_string());
    }

    if trimmed.starts_with('[') {
        let value = serde_json::from_str::<Value>(trimmed).map_err(|err| format!("invalid array arg '{raw}': {err}"))?;
        return parse_json_value_for_type(&value, type_ref, shapes);
    }

    if trimmed.starts_with('{') {
        let value =
            serde_json::from_str::<Value>(trimmed).map_err(|err| format!("invalid {} arg '{raw}': {err}", type_ref.type_name()))?;
        return parse_json_value_for_type(&value, type_ref, shapes);
    }

    if type_ref.is_array() {
        if is_one_dim_byte_array_type(type_ref) {
            return parse_byte_array_arg(type_ref, trimmed);
        }
        return Err(format!("unsupported array literal format for '{}'", type_ref.type_name()));
    }

    parse_scalar_arg(type_ref, trimmed)
}

fn parse_params<'i>(params: &[ParamAst<'_>], shapes: &StructShapeRegistry, raw_args: &[String]) -> Result<Vec<Expr<'i>>, String> {
    if params.len() != raw_args.len() {
        return Err(format!("function expects {} arguments, got {}", params.len(), raw_args.len()));
    }

    let mut typed_args = Vec::with_capacity(raw_args.len());
    for (param, raw) in params.iter().zip(raw_args.iter()) {
        typed_args.push(parse_typed_arg(&param.type_ref, shapes, raw)?);
    }
    Ok(typed_args)
}

pub fn parse_ctor_args<'i>(parsed_contract: &ContractAst<'_>, raw_ctor_args: &[String]) -> Result<Vec<Expr<'i>>, String> {
    let shapes = StructShapeRegistry::from_contract(parsed_contract);
    if parsed_contract.params.len() != raw_ctor_args.len() {
        return Err(format!("constructor expects {} arguments, got {}", parsed_contract.params.len(), raw_ctor_args.len()));
    }
    parse_params(&parsed_contract.params, &shapes, raw_ctor_args)
}

pub fn parse_call_args<'i>(contract: &ContractAst<'_>, function_name: &str, raw_args: &[String]) -> Result<Vec<Expr<'i>>, String> {
    let function = contract
        .functions
        .iter()
        .find(|function| function.name == function_name)
        .ok_or_else(|| format!("function '{function_name}' not found"))?;
    let shapes = StructShapeRegistry::from_contract(contract);
    parse_params(&function.params, &shapes, raw_args)
}

pub fn parse_state_value<'i>(contract: &ContractAst<'_>, raw_state: &str) -> Result<Expr<'i>, String> {
    let value =
        serde_json::from_str::<Value>(raw_state).map_err(|err| format!("invalid State value '{raw_state}': {err}"))?;
    let Value::Object(entries) = value else {
        return Err("State value must be a JSON object".to_string());
    };

    let shapes = StructShapeRegistry::from_contract(contract);
    let declared_fields = contract
        .fields
        .iter()
        .map(|field| StructShapeField { name: field.name.clone(), type_ref: field.type_ref.clone() })
        .collect::<Vec<_>>();
    parse_struct_arg(&entries, &declared_fields, &shapes)
}

#[cfg(test)]
mod tests {
    use super::{parse_call_args, parse_ctor_args, parse_state_value};
    use silverscript_lang::ast::{ExprKind, parse_contract_ast};

    fn debug_shapes_contract() -> silverscript_lang::ast::ContractAst<'static> {
        parse_contract_ast(
            r#"
            contract Demo(Pair seed) {
                struct Pair {
                    int amount;
                    byte[1] tag;
                }

                int amount = 1;
                bool active = true;
                byte[1] tag = 0xaa;

                entrypoint function inspect_state(State next) {
                    require(next.active == active);
                }

                entrypoint function inspect_state_array(State[] next_states) {
                    require(next_states.length == 2);
                }
            }
            "#,
        )
        .expect("parse contract")
    }

    #[test]
    fn parses_state_object_arg_with_byte_one_field() {
        let contract = debug_shapes_contract();
        let args = parse_call_args(&contract, "inspect_state", &[r#"{"amount":5,"active":true,"tag":"0xaa"}"#.to_string()])
            .expect("parse State arg");
        let ExprKind::StateObject(fields) = &args[0].kind else {
            panic!("expected state object");
        };
        assert_eq!(fields.len(), 3);
        let tag = fields.iter().find(|field| field.name == "tag").expect("tag field");
        assert!(matches!(tag.expr.kind, ExprKind::Array(ref values) if values.len() == 1));
    }

    #[test]
    fn parses_state_object_array_arg_with_byte_one_field() {
        let contract = debug_shapes_contract();
        let args = parse_call_args(
            &contract,
            "inspect_state_array",
            &[r#"[{"amount":5,"active":true,"tag":"0xaa"},{"amount":7,"active":false,"tag":"0xbb"}]"#.to_string()],
        )
        .expect("parse State[] arg");
        let ExprKind::Array(values) = &args[0].kind else {
            panic!("expected array expr");
        };
        assert_eq!(values.len(), 2);
        assert!(matches!(values[0].kind, ExprKind::StateObject(_)));
    }

    #[test]
    fn parses_declared_struct_constructor_arg_with_byte_one_field() {
        let contract = debug_shapes_contract();
        let args = parse_ctor_args(&contract, &[r#"{"amount":7,"tag":"0xaa"}"#.to_string()]).expect("parse ctor args");
        assert_eq!(args.len(), 1);
        let ExprKind::StateObject(fields) = &args[0].kind else {
            panic!("expected struct object");
        };
        let tag = fields.iter().find(|field| field.name == "tag").expect("tag field");
        assert!(matches!(tag.expr.kind, ExprKind::Array(ref values) if values.len() == 1));
    }

    #[test]
    fn parses_explicit_state_value() {
        let contract = debug_shapes_contract();
        let value = parse_state_value(&contract, r#"{"amount":9,"active":false,"tag":"0xcc"}"#).expect("parse State value");
        let ExprKind::StateObject(fields) = &value.kind else {
            panic!("expected state object");
        };
        assert_eq!(fields.len(), 3);
        assert!(fields.iter().any(|field| field.name == "amount"));
        assert!(fields.iter().any(|field| field.name == "active"));
        assert!(fields.iter().any(|field| field.name == "tag"));
    }

    #[test]
    fn rejects_missing_struct_field() {
        let contract = debug_shapes_contract();
        let error = parse_call_args(&contract, "inspect_state", &[r#"{"amount":5,"active":true}"#.to_string()])
            .expect_err("missing tag should fail");
        assert!(error.contains("struct field 'tag' must be initialized"));
    }

    #[test]
    fn rejects_unknown_struct_field() {
        let contract = debug_shapes_contract();
        let error = parse_call_args(&contract, "inspect_state", &[r#"{"amount":5,"active":true,"tag":"0xaa","extra":1}"#.to_string()])
            .expect_err("extra field should fail");
        assert!(error.contains("unknown struct field 'extra'"));
    }

    #[test]
    fn rejects_wrong_typed_struct_field() {
        let contract = debug_shapes_contract();
        let error = parse_call_args(&contract, "inspect_state", &[r#"{"amount":5,"active":1,"tag":"0xaa"}"#.to_string()])
            .expect_err("wrong typed field should fail");
        assert!(error.contains("unsupported arg value for 'bool'"));
    }

    #[test]
    fn rejects_null_in_structured_args() {
        let contract = debug_shapes_contract();
        let error = parse_call_args(&contract, "inspect_state", &[r#"null"#.to_string()]).expect_err("null should be rejected");
        assert!(error.contains("null"));
    }

    #[test]
    fn rejects_malformed_json_structured_args() {
        let contract = debug_shapes_contract();
        let error =
            parse_call_args(&contract, "inspect_state_array", &[r#"[{]"#.to_string()]).expect_err("malformed JSON should fail");
        assert!(error.contains("invalid array arg"));
    }
}
