use std::collections::{HashMap, HashSet};

use crate::ast::{ArrayDim, BinaryOp, Expr, ExprKind, TypeBase, TypeRef, UnaryOp, UnarySuffixKind};
use crate::errors::CompilerError;

use super::builtin_types::{builtin_return_type, constructor_return_type, introspection_type, nullary_type};
use super::{TypeMap, concat_types, parse_type_ref};

// TODO: Define these constructor functions in a more central location.
fn scalar(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn dynamic_bytes() -> TypeRef {
    TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Dynamic] }
}

fn builtin_cast_type(name: &str) -> Option<TypeRef> {
    let type_ref = parse_type_ref(name).ok()?;
    (!matches!(type_ref.base, TypeBase::Custom(_))).then_some(type_ref)
}

fn is_bytes_type(type_ref: &TypeRef) -> bool {
    type_ref.is_array()
        || type_ref.is_byte()
        || type_ref.is_string()
        || type_ref.is_pubkey()
        || type_ref.is_sig()
        || type_ref.is_datasig()
}

pub(super) fn infer_debug_expr_value_type<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    types: &TypeMap,
    visiting: &mut HashSet<String>,
) -> Result<TypeRef, CompilerError> {
    match &expr.kind {
        ExprKind::Int(_) | ExprKind::DateLiteral(_) | ExprKind::NumberWithUnit { .. } => Ok(scalar(TypeBase::Int)),
        ExprKind::Bool(_) => Ok(scalar(TypeBase::Bool)),
        ExprKind::Byte(_) => Ok(scalar(TypeBase::Byte)),
        ExprKind::String(_) => Ok(scalar(TypeBase::String)),
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
        ExprKind::Unary { op: UnaryOp::Not, .. } => Ok(scalar(TypeBase::Bool)),
        ExprKind::Unary { op: UnaryOp::Neg, .. } => Ok(scalar(TypeBase::Int)),
        ExprKind::Binary { op, left, right } => match op {
            BinaryOp::Or | BinaryOp::And | BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                Ok(scalar(TypeBase::Bool))
            }
            BinaryOp::Add => {
                let left_type = infer_debug_expr_value_type(left, env, types, visiting)?;
                let right_type = infer_debug_expr_value_type(right, env, types, visiting)?;
                if left_type.is_string() || right_type.is_string() {
                    Ok(scalar(TypeBase::String))
                } else if left_type.is_byte() || right_type.is_byte() {
                    Ok(scalar(TypeBase::Int))
                } else if let Some(concatenated) = concat_types(&left_type, &right_type, env) {
                    Ok(concatenated)
                } else if is_bytes_type(&left_type) {
                    Ok(left_type)
                } else if is_bytes_type(&right_type) {
                    Ok(right_type)
                } else if left_type.is_array() {
                    Ok(left_type)
                } else if right_type.is_array() {
                    Ok(right_type)
                } else {
                    Ok(scalar(TypeBase::Int))
                }
            }
            BinaryOp::BitOr | BinaryOp::BitXor | BinaryOp::BitAnd => {
                let left_type = infer_debug_expr_value_type(left, env, types, visiting)?;
                let right_type = infer_debug_expr_value_type(right, env, types, visiting)?;
                if left_type == right_type && is_bytes_type(&left_type) { Ok(left_type) } else { Ok(scalar(TypeBase::Int)) }
            }
            BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => Ok(scalar(TypeBase::Int)),
        },
        ExprKind::IfElse { then_expr, else_expr, .. } => {
            let then_type = infer_debug_expr_value_type(then_expr, env, types, visiting)?;
            let else_type = infer_debug_expr_value_type(else_expr, env, types, visiting)?;
            if then_type == else_type || (is_bytes_type(&then_type) && is_bytes_type(&else_type)) {
                Ok(then_type)
            } else {
                Ok(dynamic_bytes())
            }
        }
        ExprKind::Array(values) => {
            if values.iter().all(|value| matches!(value.kind, ExprKind::Byte(_))) {
                Ok(TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(values.len())] })
            } else {
                Ok(dynamic_bytes())
            }
        }
        ExprKind::Split { .. } | ExprKind::Slice { .. } => Ok(dynamic_bytes()),
        ExprKind::New { name, .. } => Ok(constructor_return_type(name).unwrap_or_else(dynamic_bytes)),
        ExprKind::Append { source, .. } => infer_debug_expr_value_type(source, env, types, visiting),
        ExprKind::ArrayIndex { source, .. } => {
            let source_type = infer_debug_expr_value_type(source, env, types, visiting)?;
            Ok(source_type.array_element_type().unwrap_or_else(dynamic_bytes))
        }
        ExprKind::Nullary(kind) => Ok(nullary_type(*kind)),
        ExprKind::Introspection { kind, .. } => Ok(introspection_type(*kind)),
        ExprKind::Call { name, .. } => {
            if let Some(type_ref) = builtin_cast_type(name) {
                Ok(type_ref)
            } else {
                Ok(builtin_return_type(name).unwrap_or_else(dynamic_bytes))
            }
        }
        ExprKind::UnarySuffix { source, kind, .. } => match kind {
            UnarySuffixKind::Length => Ok(scalar(TypeBase::Int)),
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

    use crate::ast::{BinaryOp, Expr, ExprKind, IntrospectionKind, NullaryOp, UnarySuffixKind, parse_type_ref};
    use crate::span;

    use super::infer_debug_expr_value_type;

    fn infer(expr: Expr<'static>, env: HashMap<String, Expr<'static>>, types: HashMap<String, String>) -> String {
        let types = types.into_iter().map(|(name, type_name)| (name, parse_type_ref(&type_name).expect("valid test type"))).collect();
        infer_debug_expr_value_type(&expr, &env, &types, &mut HashSet::new()).expect("infer type").type_name()
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
