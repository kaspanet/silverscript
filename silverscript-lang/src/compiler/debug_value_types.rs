use std::collections::{HashMap, HashSet};

use crate::ast::{BinaryOp, Expr, ExprKind, TypeBase, UnaryOp, UnarySuffixKind};
use crate::errors::CompilerError;

use super::builtin_types::{builtin_return_type, constructor_return_type, introspection_type, nullary_type};
use super::{array_element_type, concat_types, is_bytes_type, parse_type_ref};

fn is_builtin_cast_type_name(name: &str) -> bool {
    if matches!(name, "int" | "bool" | "byte" | "string" | "pubkey" | "sig" | "datasig") {
        return true;
    }
    if !name.contains('[') {
        return false;
    }
    let Ok(type_ref) = parse_type_ref(name) else {
        return false;
    };

    !matches!(type_ref.base, TypeBase::Custom(_))
}

fn concatenated_array_type<'i>(left: &str, right: &str, constants: &HashMap<String, Expr<'i>>) -> Option<String> {
    let left = parse_type_ref(left).ok()?;
    let right = parse_type_ref(right).ok()?;
    concat_types(&left, &right, constants).map(|type_ref| type_ref.type_name())
}

pub(super) fn infer_debug_expr_value_type<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    types: &HashMap<String, String>,
    visiting: &mut HashSet<String>,
) -> Result<String, CompilerError> {
    match &expr.kind {
        ExprKind::Int(_) | ExprKind::DateLiteral(_) | ExprKind::NumberWithUnit { .. } => Ok("int".to_string()),
        ExprKind::Bool(_) => Ok("bool".to_string()),
        ExprKind::Byte(_) => Ok("byte".to_string()),
        ExprKind::String(_) => Ok("string".to_string()),
        ExprKind::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return Err(CompilerError::CyclicIdentifier(name.clone()));
            }
            let result = if let Some(type_name) = types.get(name) {
                Ok(type_name.clone())
            } else if let Some(value) = env.get(name) {
                infer_debug_expr_value_type(value, env, types, visiting)
            } else {
                Err(CompilerError::UndefinedIdentifier(name.clone()))
            };
            visiting.remove(name);
            result
        }
        ExprKind::Unary { op: UnaryOp::Not, .. } => Ok("bool".to_string()),
        ExprKind::Unary { op: UnaryOp::Neg, .. } => Ok("int".to_string()),
        ExprKind::Binary { op, left, right } => match op {
            BinaryOp::Or | BinaryOp::And | BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                Ok("bool".to_string())
            }
            BinaryOp::Add => {
                let left_type = infer_debug_expr_value_type(left, env, types, visiting)?;
                let right_type = infer_debug_expr_value_type(right, env, types, visiting)?;
                if left_type == "string" || right_type == "string" {
                    Ok("string".to_string())
                } else if left_type == "byte" || right_type == "byte" {
                    Ok("int".to_string())
                } else if let Some(concatenated) = concatenated_array_type(&left_type, &right_type, env) {
                    Ok(concatenated)
                } else if is_bytes_type(&left_type) {
                    Ok(left_type)
                } else if is_bytes_type(&right_type) {
                    Ok(right_type)
                } else if array_element_type(&left_type).is_some() {
                    Ok(left_type)
                } else if array_element_type(&right_type).is_some() {
                    Ok(right_type)
                } else {
                    Ok("int".to_string())
                }
            }
            BinaryOp::BitOr | BinaryOp::BitXor | BinaryOp::BitAnd => {
                let left_type = infer_debug_expr_value_type(left, env, types, visiting)?;
                let right_type = infer_debug_expr_value_type(right, env, types, visiting)?;
                if left_type == right_type && is_bytes_type(&left_type) { Ok(left_type) } else { Ok("int".to_string()) }
            }
            BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => Ok("int".to_string()),
        },
        ExprKind::IfElse { then_expr, else_expr, .. } => {
            let then_type = infer_debug_expr_value_type(then_expr, env, types, visiting)?;
            let else_type = infer_debug_expr_value_type(else_expr, env, types, visiting)?;
            if then_type == else_type || (is_bytes_type(&then_type) && is_bytes_type(&else_type)) {
                Ok(then_type)
            } else {
                Ok("byte[]".to_string())
            }
        }
        ExprKind::Array(values) => {
            if values.iter().all(|value| matches!(value.kind, ExprKind::Byte(_))) {
                Ok(format!("byte[{}]", values.len()))
            } else {
                Ok("byte[]".to_string())
            }
        }
        ExprKind::Split { .. } | ExprKind::Slice { .. } => Ok("byte[]".to_string()),
        ExprKind::New { name, .. } => Ok(constructor_return_type(name).map_or_else(|| "byte[]".to_string(), |ty| ty.type_name())),
        ExprKind::Append { source, .. } => infer_debug_expr_value_type(source, env, types, visiting),
        ExprKind::ArrayIndex { source, .. } => {
            let source_type = infer_debug_expr_value_type(source, env, types, visiting)?;
            Ok(array_element_type(&source_type).unwrap_or_else(|| "byte[]".to_string()))
        }
        ExprKind::Nullary(kind) => Ok(nullary_type(*kind).type_name()),
        ExprKind::Introspection { kind, .. } => Ok(introspection_type(*kind).type_name()),
        ExprKind::Call { name, .. } => {
            if is_builtin_cast_type_name(name) {
                Ok(name.clone())
            } else {
                Ok(builtin_return_type(name).map_or_else(|| "byte[]".to_string(), |ty| ty.type_name()))
            }
        }
        ExprKind::UnarySuffix { source, kind, .. } => match kind {
            UnarySuffixKind::Length => Ok("int".to_string()),
            UnarySuffixKind::Reverse => infer_debug_expr_value_type(source, env, types, visiting),
        },
        ExprKind::FieldAccess { .. } => {
            Err(CompilerError::Unsupported("struct field access should be lowered before compilation".to_string()))
        }
        ExprKind::StructLiteral(_) => Err(CompilerError::Unsupported(
            "state object literals are only supported in validateOutputState-style builtins".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::ast::{BinaryOp, Expr, ExprKind, IntrospectionKind, NullaryOp, UnarySuffixKind};
    use crate::span;

    use super::infer_debug_expr_value_type;

    fn infer(expr: Expr<'static>, env: HashMap<String, Expr<'static>>, types: HashMap<String, String>) -> String {
        infer_debug_expr_value_type(&expr, &env, &types, &mut HashSet::new()).expect("infer type")
    }

    #[test]
    fn infers_literal_and_identifier_value_types() {
        assert_eq!(infer(Expr::int(1), HashMap::new(), HashMap::new()), "int");
        assert_eq!(infer(Expr::bool(true), HashMap::new(), HashMap::new()), "bool");
        assert_eq!(infer(Expr::byte(0xaa), HashMap::new(), HashMap::new()), "byte");
        assert_eq!(infer(Expr::string("hi"), HashMap::new(), HashMap::new()), "string");

        let mut types = HashMap::new();
        types.insert("x".to_string(), "int".to_string());
        assert_eq!(infer(Expr::identifier("x"), HashMap::new(), types), "int");
    }

    #[test]
    fn infers_addition_and_array_index_value_types() {
        let add = Expr::new(
            ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier("a")), right: Box::new(Expr::identifier("b")) },
            span::Span::default(),
        );
        let mut types = HashMap::new();
        types.insert("a".to_string(), "int".to_string());
        types.insert("b".to_string(), "int".to_string());
        assert_eq!(infer(add, HashMap::new(), types), "int");

        let concat = Expr::new(
            ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier("a")), right: Box::new(Expr::identifier("b")) },
            span::Span::default(),
        );
        let mut types = HashMap::new();
        types.insert("a".to_string(), "int[2]".to_string());
        types.insert("b".to_string(), "int[3]".to_string());
        assert_eq!(infer(concat, HashMap::new(), types), "int[5]");

        let dynamic_concat = Expr::new(
            ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier("a")), right: Box::new(Expr::identifier("b")) },
            span::Span::default(),
        );
        let mut types = HashMap::new();
        types.insert("a".to_string(), "int[]".to_string());
        types.insert("b".to_string(), "int[3]".to_string());
        assert_eq!(infer(dynamic_concat, HashMap::new(), types), "int[]");

        let index = Expr::new(
            ExprKind::ArrayIndex { source: Box::new(Expr::identifier("items")), index: Box::new(Expr::int(0)) },
            span::Span::default(),
        );
        let mut types = HashMap::new();
        types.insert("items".to_string(), "byte[32][]".to_string());
        assert_eq!(infer(index, HashMap::new(), types), "byte[32]");
    }

    #[test]
    fn infers_known_builtin_and_unknown_call_value_types() {
        let input_covenant_id = Expr::new(
            ExprKind::Call {
                name: "OpInputCovenantId".to_string(),
                args: vec![Expr::identifier("idx")],
                name_span: span::Span::default(),
            },
            span::Span::default(),
        );
        let mut types = HashMap::new();
        types.insert("idx".to_string(), "int".to_string());
        assert_eq!(infer(input_covenant_id, HashMap::new(), types.clone()), "byte[32]");

        let output_covenant_id = Expr::new(
            ExprKind::Call {
                name: "OpOutputCovenantId".to_string(),
                args: vec![Expr::identifier("idx")],
                name_span: span::Span::default(),
            },
            span::Span::default(),
        );
        assert_eq!(infer(output_covenant_id, HashMap::new(), types), "byte[32]");

        let unknown = Expr::new(
            ExprKind::Call { name: "someUserFn".to_string(), args: vec![Expr::int(1)], name_span: span::Span::default() },
            span::Span::default(),
        );
        assert_eq!(infer(unknown, HashMap::new(), HashMap::new()), "byte[]");
    }

    #[test]
    fn infers_nullary_introspection_and_suffix_value_types() {
        let nullary = Expr::new(ExprKind::Nullary(NullaryOp::ActiveScriptPubKey), span::Span::default());
        assert_eq!(infer(nullary, HashMap::new(), HashMap::new()), "byte[]");

        let intro = Expr::new(
            ExprKind::Introspection {
                kind: IntrospectionKind::OutputValue,
                index: Box::new(Expr::int(0)),
                field_span: span::Span::default(),
            },
            span::Span::default(),
        );
        assert_eq!(infer(intro, HashMap::new(), HashMap::new()), "int");

        let length = Expr::new(
            ExprKind::UnarySuffix {
                source: Box::new(Expr::identifier("buf")),
                kind: UnarySuffixKind::Length,
                span: span::Span::default(),
            },
            span::Span::default(),
        );
        let mut types = HashMap::new();
        types.insert("buf".to_string(), "byte[]".to_string());
        assert_eq!(infer(length, HashMap::new(), types), "int");
    }
}
