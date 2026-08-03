use std::collections::HashMap;

use crate::ast::{
    ArrayDim, BinaryOp, ContractFieldAst, Expr, ExprKind, FunctionAst, TypeBase, TypeRef, UnaryOp, UnarySuffixKind, as_cast_type,
};

use super::builtin_types::{
    BuiltinReturn, builtin_parameters, builtin_return, constructor_parameters, constructor_return_type, g16_verify_parameter_types,
    indexed_introspection_type, introspection_type,
};
use super::structs::{StructRegistry, flattened_struct_field_specs_for_type, is_struct, struct_name};
use super::{CompilerError, STATE_TYPE_NAME, TypeMap, append_type, array_type_size, concat_types, parse_type_ref, type_refs_equal};

pub(super) struct TypeCheckContext<'a, 'i> {
    pub types: &'a TypeMap,
    pub structs: &'a StructRegistry,
    pub constants: &'a HashMap<String, Expr<'i>>,
    pub functions: &'a HashMap<String, &'a FunctionAst<'i>>,
    pub contract_fields: &'a [ContractFieldAst<'i>],
}

pub(super) fn check_expr<'i>(
    expr: &Expr<'i>,
    expected: Option<&TypeRef>,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<TypeRef, CompilerError> {
    let actual = match &expr.kind {
        ExprKind::Int(value) if expected.is_some_and(TypeRef::is_byte) && (0..=255).contains(value) => scalar_type(TypeBase::Byte),
        ExprKind::Int(_) | ExprKind::DateLiteral(_) | ExprKind::NumberWithUnit { .. } => scalar_type(TypeBase::Int),
        ExprKind::Bool(_) => scalar_type(TypeBase::Bool),
        ExprKind::Byte(_) => scalar_type(TypeBase::Byte),
        ExprKind::String(_) => scalar_type(TypeBase::String),
        ExprKind::Identifier(name) => ctx.types.get(name).cloned().ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?,
        ExprKind::Array { type_ref, values } => check_typed_array_literal(values, type_ref, expected, ctx)?,
        ExprKind::Call { name, args, .. } => check_call(name, args, expected, ctx)?
            .ok_or_else(|| CompilerError::Unsupported(format!("function '{name}' does not return a value")))?,
        ExprKind::New { name, args, .. } => check_constructor(name, args, ctx)?,
        ExprKind::Split { source, index, .. } => {
            let source_type = check_expr(source, None, ctx)?;
            check_expr(index, Some(&scalar_type(TypeBase::Int)), ctx)?;
            sequence_part_type(&source_type, "split")?
        }
        ExprKind::Slice { source, start, end, .. } => {
            let source_type = check_expr(source, None, ctx)?;
            let int_type = scalar_type(TypeBase::Int);
            check_expr(start, Some(&int_type), ctx)?;
            check_expr(end, Some(&int_type), ctx)?;
            sequence_part_type(&source_type, "slice")?
        }
        ExprKind::Append { source, args, .. } => {
            let source_type = check_expr(source, None, ctx)?;
            let element_type = source_type
                .array_element_type()
                .ok_or_else(|| CompilerError::Unsupported("append target must be an array".to_string()))?;
            for arg in args {
                check_expr(arg, Some(&element_type), ctx).map_err(|_| {
                    CompilerError::Unsupported(format!("array append element type mismatch: expected {}", element_type.type_name()))
                })?;
            }
            append_type(&source_type, args.len(), ctx.constants)
                .ok_or_else(|| CompilerError::Unsupported("cannot determine appended array type".to_string()))?
        }
        ExprKind::ArrayIndex { source, index } => {
            let source_type = check_expr(source, None, ctx)?;
            check_expr(index, Some(&scalar_type(TypeBase::Int)), ctx)?;
            source_type
                .array_element_type()
                .ok_or_else(|| CompilerError::Unsupported("array index source must be an array".to_string()))?
        }
        ExprKind::Unary { op, expr } => match op {
            UnaryOp::Not => {
                let bool_type = scalar_type(TypeBase::Bool);
                check_expr(expr, Some(&bool_type), ctx)?;
                bool_type
            }
            UnaryOp::Neg => {
                let int_type = scalar_type(TypeBase::Int);
                check_expr(expr, Some(&int_type), ctx)?;
                int_type
            }
        },
        ExprKind::Binary { op, left, right } => check_binary(*op, left, right, ctx)?,
        ExprKind::Ternary { condition, then_expr, else_expr } => {
            check_expr(condition, Some(&scalar_type(TypeBase::Bool)), ctx)?;
            if let Some(expected) = expected {
                check_expr(then_expr, Some(expected), ctx)?;
                check_expr(else_expr, Some(expected), ctx)?;
                expected.clone()
            } else {
                let then_type = check_expr(then_expr, None, ctx)?;
                let else_type = check_expr(else_expr, None, ctx)?;
                if !type_refs_equal(&then_type, &else_type, ctx.constants) {
                    return Err(CompilerError::Unsupported(format!(
                        "ternary branch type mismatch: then expression is {}, else expression is {}",
                        then_type.type_name(),
                        else_type.type_name()
                    )));
                }
                then_type
            }
        }
        ExprKind::Introspection(kind) => introspection_type(*kind),
        ExprKind::IndexedIntrospection { kind, index, .. } => {
            check_expr(index, Some(&scalar_type(TypeBase::Int)), ctx)?;
            indexed_introspection_type(*kind)
        }
        ExprKind::StructLiteral { .. } => check_struct_literal(expr, expected, ctx)?,
        ExprKind::FieldAccess { source, field, .. } => {
            let source_type = check_expr(source, None, ctx)?;
            if let Some(elements) = source_type.tuple_elements() {
                let index = tuple_index(field)?;
                elements.get(index).cloned().ok_or_else(|| CompilerError::Unsupported(format!("tuple index {index} out of bounds")))?
            } else {
                if field.chars().all(|character| character.is_ascii_digit()) {
                    return Err(CompilerError::Unsupported("function does not return a tuple".to_string()));
                }
                let struct_name = struct_name(&source_type, ctx.structs)
                    .ok_or_else(|| CompilerError::Unsupported("field access requires a struct or tuple value".to_string()))?;
                ctx.structs
                    .get(struct_name)
                    .and_then(|item| item.fields.iter().find(|candidate| candidate.name == *field))
                    .map(|field| field.type_ref.clone())
                    .ok_or_else(|| CompilerError::Unsupported(format!("struct '{struct_name}' has no field '{field}'")))?
            }
        }
        ExprKind::UnarySuffix { source, kind, .. } => {
            let source_type = check_expr(source, None, ctx)?;
            match kind {
                UnarySuffixKind::Length if is_sequence_type(&source_type) => scalar_type(TypeBase::Int),
                UnarySuffixKind::Length => {
                    return Err(CompilerError::Unsupported("length requires an array or string".to_string()));
                }
            }
        }
    };

    ensure_expected(&actual, expected, ctx.constants)?;
    Ok(actual)
}

fn check_array_literal_with_element_type<'i>(
    values: &[Expr<'i>],
    element_type: &TypeRef,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<TypeRef, CompilerError> {
    for value in values {
        check_expr(value, Some(element_type), ctx)?;
    }
    let mut result = element_type.clone();
    result.array_dims.push(ArrayDim::Fixed(values.len()));
    Ok(result)
}

fn check_typed_array_literal<'i>(
    values: &[Expr<'i>],
    literal_type: &TypeRef,
    expected: Option<&TypeRef>,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<TypeRef, CompilerError> {
    let literal_element_type = literal_type
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported("array literal requires an array type".to_string()))?;
    check_array_literal_with_element_type(values, &literal_element_type, ctx)
        .map_err(|_| CompilerError::Unsupported("array element type mismatch".to_string()))?;
    if let Some(literal_size) = array_type_size(literal_type, ctx.constants)
        && literal_size != values.len()
    {
        return Err(CompilerError::Unsupported("size mismatch".to_string()));
    }

    if let Some(expected) = expected {
        if !expected.is_array() {
            if expected.base.fixed_byte_sequence_len() == Some(values.len())
                && matches!(literal_type.base, TypeBase::Byte)
                && literal_type.array_dims.len() == 1
                && values.iter().all(|value| matches!(value.kind, ExprKind::Byte(_)))
            {
                return Ok(expected.clone());
            }
            return Err(CompilerError::Unsupported("type mismatch".to_string()));
        }
        let expected_element_type =
            expected.array_element_type().ok_or_else(|| CompilerError::Unsupported("type mismatch".to_string()))?;
        if !type_refs_equal(&literal_element_type, &expected_element_type, ctx.constants) {
            if let (TypeBase::Custom(expected_name), TypeBase::Custom(actual_name)) =
                (&expected_element_type.base, &literal_element_type.base)
            {
                return Err(CompilerError::Unsupported(format!("expected struct '{expected_name}', got '{actual_name}'")));
            }
            return Err(CompilerError::Unsupported("array element type mismatch".to_string()));
        }
        if matches!(expected.array_size(), Some(ArrayDim::Dynamic)) && !matches!(literal_type.array_size(), Some(ArrayDim::Dynamic)) {
            return Err(CompilerError::Unsupported("type mismatch".to_string()));
        }
        if array_type_size(expected, ctx.constants).is_some() && matches!(literal_type.array_size(), Some(ArrayDim::Dynamic)) {
            return Err(CompilerError::Unsupported("type mismatch".to_string()));
        }
        if let Some(expected_size) = array_type_size(expected, ctx.constants)
            && expected_size != values.len()
        {
            return Err(CompilerError::Unsupported("size mismatch".to_string()));
        }
        return Ok(expected.clone());
    }

    Ok(literal_type.clone())
}

pub(super) fn check_call<'i>(
    name: &str,
    args: &[Expr<'i>],
    expected: Option<&TypeRef>,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<Option<TypeRef>, CompilerError> {
    if name == "readInputState" && !ctx.contract_fields.is_empty() {
        check_arity(name, args, 1)?;
        check_expr(&args[0], Some(&scalar_type(TypeBase::Int)), ctx)?;
        let return_type = TypeRef { base: TypeBase::Custom(STATE_TYPE_NAME.to_string()), array_dims: Vec::new() };
        ensure_expected(&return_type, expected, ctx.constants)?;
        return Ok(Some(return_type));
    }
    if name == "readInputStateWithTemplate" {
        let expected = expected.ok_or_else(|| {
            CompilerError::Unsupported("readInputStateWithTemplate must be assigned to an explicitly typed struct".to_string())
        })?;
        if !is_struct(expected, ctx.structs) {
            return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
        }
        check_builtin_args(name, args, builtin_parameters(name).expect("readInputStateWithTemplate signature exists"), ctx)?;
        if flattened_struct_field_specs_for_type(expected, ctx.structs)?.is_empty() {
            return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a non-empty struct type".to_string()));
        }
        return Ok(Some(expected.clone()));
    }
    if let Some(cast_type) = as_cast_type(name) {
        check_arity("as", args, 1)?;
        if !matches!(cast_type.base, TypeBase::Byte)
            || !matches!(cast_type.array_dims.as_slice(), [ArrayDim::Fixed(_) | ArrayDim::Constant(_)])
        {
            return Err(CompilerError::Unsupported("'as' conversion requires a fixed byte[N] target".to_string()));
        }
        check_expr(&args[0], Some(&scalar_type(TypeBase::Int)), ctx)
            .map_err(|_| CompilerError::Unsupported("'as byte[N]' source must be int".to_string()))?;
        let size = array_type_size(&cast_type, ctx.constants)
            .ok_or_else(|| CompilerError::Unsupported("byte size in 'as byte[N]' must be known at compile time".to_string()))?;
        if size == 0 || size > 8 {
            return Err(CompilerError::Unsupported("byte size in 'as byte[N]' must be between 1 and 8".to_string()));
        }
        return Ok(Some(cast_type));
    }
    if let Some(function) = ctx.functions.get(name).copied() {
        if function.entrypoint {
            return Err(CompilerError::Unsupported(format!("entry '{name}' cannot be called")));
        }
        if function.params.len() != args.len() {
            return Err(CompilerError::Unsupported(format!("function '{name}' expects {} arguments", function.params.len())));
        }
        for (param, arg) in function.params.iter().zip(args) {
            if matches!(&arg.kind, ExprKind::Call { name, .. } if name == "readInputStateWithTemplate") {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
                ));
            }
            check_expr(arg, Some(&param.type_ref), ctx).map_err(|_| {
                CompilerError::Unsupported(format!("function argument '{}' expects {}", param.name, param.type_ref.type_name()))
            })?;
        }
        return Ok(function.return_type());
    }
    if let Ok(cast_type) = parse_type_ref(name)
        && !matches!(cast_type.base, TypeBase::Custom(_))
    {
        check_arity(name, args, 1)?;
        let source_type = check_expr(&args[0], None, ctx)?;
        if matches!(cast_type.base, TypeBase::Byte) && cast_type.is_array() && source_type.is_int() {
            return Err(CompilerError::Unsupported(format!(
                "cannot cast int to {}; use 'value as byte[N]' instead",
                cast_type.type_name()
            )));
        }
        if cast_type.is_array()
            && source_type.is_array()
            && let (Some(target_size), Some(source_size)) =
                (array_type_size(&cast_type, ctx.constants), array_type_size(&source_type, ctx.constants))
            && target_size != source_size
        {
            return Err(CompilerError::Unsupported(format!("cannot cast {} to {}", source_type.type_name(), cast_type.type_name())));
        }
        return Ok(Some(cast_type));
    }
    let Some(return_type) = builtin_return(name) else {
        return Err(CompilerError::Unsupported(format!("function '{name}' not found")));
    };
    if name == "g16.verify" {
        check_g16_verify_args(args, ctx)?;
    } else {
        let parameters = builtin_parameters(name)
            .ok_or_else(|| CompilerError::Unsupported(format!("builtin function '{name}' has no parameter types")))?;
        check_builtin_args(name, args, parameters, ctx)?;
    }
    match return_type {
        BuiltinReturn::Value(type_ref) => Ok(Some(type_ref)),
        BuiltinReturn::Void => Ok(None),
    }
}

fn check_g16_verify_args<'i>(args: &[Expr<'i>], ctx: &TypeCheckContext<'_, 'i>) -> Result<(), CompilerError> {
    if args.len() < 2 {
        return Err(CompilerError::Unsupported("g16.verify() expects at least 2 arguments".to_string()));
    }

    let parameters = g16_verify_parameter_types();
    check_builtin_arg("g16.verify", "verifyingKey", &args[0], &parameters.verifying_key, ctx)?;
    check_builtin_arg("g16.verify", "proof", &args[1], &parameters.proof, ctx)?;
    for (index, arg) in args[2..].iter().enumerate() {
        check_builtin_arg("g16.verify", &format!("publicInput{index}"), arg, &parameters.public_input, ctx)?;
    }
    Ok(())
}

fn check_builtin_args<'i>(
    name: &str,
    args: &[Expr<'i>],
    parameters: Vec<(&str, TypeRef)>,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<(), CompilerError> {
    if parameters.len() != args.len() {
        return Err(CompilerError::Unsupported(format!("{name}() expects {} arguments", parameters.len())));
    }
    for (arg, (parameter, expected)) in args.iter().zip(parameters) {
        check_builtin_arg(name, parameter, arg, &expected, ctx)?;
    }
    Ok(())
}

fn check_builtin_arg<'i>(
    name: &str,
    parameter: &str,
    arg: &Expr<'i>,
    expected: &TypeRef,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<(), CompilerError> {
    if check_expr(arg, Some(expected), ctx).is_err() {
        let actual = check_expr(arg, None, ctx).map(|type_ref| type_ref.type_name()).unwrap_or_else(|_| "unknown".to_string());
        return Err(CompilerError::Unsupported(format!(
            "{name}() argument '{parameter}' expects {}, got {actual}",
            expected.type_name()
        )));
    }
    Ok(())
}

fn check_binary<'i>(
    op: BinaryOp,
    left: &Expr<'i>,
    right: &Expr<'i>,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<TypeRef, CompilerError> {
    let left_type = check_expr(left, None, ctx)?;
    if left_type.tuple_elements().is_some() {
        return Err(CompilerError::Unsupported(
            "function returns a tuple and cannot be used directly in expressions; access a tuple field instead".to_string(),
        ));
    }
    let right_type = if matches!(op, BinaryOp::Add)
        && let Some(element_type) = left_type.array_element_type()
        && let ExprKind::Array { values, .. } = &right.kind
    {
        check_array_literal_with_element_type(values, &element_type, ctx)?
    } else {
        let right_expected = matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge)
            .then_some(&left_type);
        check_expr(right, right_expected, ctx).map_err(|_| {
            let actual = check_expr(right, None, ctx).map(|type_ref| type_ref.type_name()).unwrap_or_else(|_| "unknown".to_string());
            CompilerError::Unsupported(format!("type mismatch: cannot compare {} and {actual}", left_type.type_name()))
        })?
    };
    match op {
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => Ok(scalar_type(TypeBase::Bool)),
        BinaryOp::Or | BinaryOp::And => {
            let bool_type = scalar_type(TypeBase::Bool);
            ensure_expected(&left_type, Some(&bool_type), ctx.constants)?;
            ensure_expected(&right_type, Some(&bool_type), ctx.constants)?;
            Ok(bool_type)
        }
        BinaryOp::Add if left_type.is_array() && right_type.is_array() => concat_types(&left_type, &right_type, ctx.constants)
            .ok_or_else(|| CompilerError::Unsupported("array concatenation requires identical element types".to_string())),
        BinaryOp::Add if left_type.is_byte() || right_type.is_byte() => {
            Err(CompilerError::Unsupported("byte values do not support '+'".to_string()))
        }
        BinaryOp::Add if left_type.is_string() && right_type.is_string() => Ok(scalar_type(TypeBase::String)),
        BinaryOp::BitOr | BinaryOp::BitXor | BinaryOp::BitAnd => {
            if left_type.is_byte() && right_type.is_byte() {
                return Ok(left_type);
            }
            let left_is_byte_array = matches!(left_type.base, TypeBase::Byte) && left_type.is_array();
            let right_is_byte_array = matches!(right_type.base, TypeBase::Byte) && right_type.is_array();
            if !left_is_byte_array || !right_is_byte_array {
                return Err(CompilerError::Unsupported(format!(
                    "bitwise operations require bytes or byte arrays, got {} and {}",
                    left_type.type_name(),
                    right_type.type_name()
                )));
            }
            if !type_refs_equal(&left_type, &right_type, ctx.constants) {
                return Err(CompilerError::Unsupported(format!(
                    "bitwise operations require byte arrays of equal size, got {} and {}",
                    left_type.type_name(),
                    right_type.type_name()
                )));
            }
            Ok(left_type)
        }
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
            let int_type = scalar_type(TypeBase::Int);
            ensure_expected(&left_type, Some(&int_type), ctx.constants)?;
            ensure_expected(&right_type, Some(&int_type), ctx.constants)?;
            Ok(int_type)
        }
    }
}

fn check_struct_literal<'i>(
    expr: &Expr<'i>,
    expected: Option<&TypeRef>,
    ctx: &TypeCheckContext<'_, 'i>,
) -> Result<TypeRef, CompilerError> {
    let ExprKind::StructLiteral { name, fields, .. } = &expr.kind else { unreachable!() };
    let actual = TypeRef { base: TypeBase::Custom(name.clone()), array_dims: Vec::new() };
    let item = ctx.structs.get(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
    if let Some(expected_name) = expected.and_then(|expected| struct_name(expected, ctx.structs))
        && expected_name != name
    {
        return Err(CompilerError::Unsupported(format!("expected struct '{expected_name}', got '{name}'")));
    }
    ensure_expected(&actual, expected, ctx.constants)?;
    let mut provided = HashMap::new();
    for field in fields {
        if provided.insert(field.name.as_str(), &field.expr).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", field.name)));
        }
    }
    for field in &item.fields {
        let value = provided
            .remove(field.name.as_str())
            .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))?;
        check_expr(value, Some(&field.type_ref), ctx).map_err(|_| {
            CompilerError::Unsupported(format!("struct field '{}' expects {}", field.name, field.type_ref.type_name()))
        })?;
    }
    if let Some(extra) = provided.keys().next() {
        return Err(CompilerError::Unsupported(format!("unknown struct field '{extra}'")));
    }
    Ok(actual)
}

fn ensure_expected<'i>(
    actual: &TypeRef,
    expected: Option<&TypeRef>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if expected.is_none_or(|expected| type_refs_equal(actual, expected, constants)) {
        Ok(())
    } else {
        Err(CompilerError::Unsupported("type mismatch".to_string()))
    }
}

fn scalar_type(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn dynamic_array_of(type_ref: &TypeRef) -> Result<TypeRef, CompilerError> {
    let mut element =
        type_ref.array_element_type().ok_or_else(|| CompilerError::Unsupported("operation requires an array".to_string()))?;
    element.array_dims.push(crate::ast::ArrayDim::Dynamic);
    Ok(element)
}

fn sequence_part_type(type_ref: &TypeRef, operation: &str) -> Result<TypeRef, CompilerError> {
    if type_ref.is_array() {
        return dynamic_array_of(type_ref);
    }
    if type_ref.is_string() {
        return Ok(type_ref.clone());
    }
    if !type_ref.is_array() && type_ref.base.fixed_byte_sequence_len().is_some() {
        return Ok(TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Dynamic] });
    }
    Err(CompilerError::Unsupported(format!("{operation} source must be an array, string, or fixed-byte type")))
}

fn check_constructor<'i>(name: &str, args: &[Expr<'i>], ctx: &TypeCheckContext<'_, 'i>) -> Result<TypeRef, CompilerError> {
    let parameters =
        constructor_parameters(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown constructor '{name}'")))?;
    if parameters.len() != args.len() {
        return Err(CompilerError::Unsupported(format!("{name} constructor expects {} arguments", parameters.len())));
    }
    for (arg, (parameter, expected)) in args.iter().zip(parameters) {
        check_expr(arg, Some(&expected), ctx).map_err(|_| {
            CompilerError::Unsupported(format!("{name} constructor argument '{parameter}' expects {}", expected.type_name()))
        })?;
    }
    constructor_return_type(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown constructor '{name}'")))
}

fn is_sequence_type(type_ref: &TypeRef) -> bool {
    type_ref.is_array() || type_ref.is_string() || type_ref.is_pubkey() || type_ref.is_sig() || type_ref.is_datasig()
}

fn tuple_index(field: &str) -> Result<usize, CompilerError> {
    if field.is_empty() || !field.chars().all(|character| character.is_ascii_digit()) {
        return Err(CompilerError::Unsupported(format!("invalid tuple field '{field}'")));
    }
    field.parse().map_err(|_| CompilerError::Unsupported(format!("invalid tuple field '{field}'")))
}

fn check_arity(name: &str, args: &[Expr<'_>], expected: usize) -> Result<(), CompilerError> {
    if args.len() == expected { Ok(()) } else { Err(CompilerError::Unsupported(format!("{name}() expects {expected} arguments"))) }
}
