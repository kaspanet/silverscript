use std::collections::{HashMap, HashSet};

use super::compile::{byte_sequence_cast_size, read_input_state_field_expr_symbolic};
use super::debug_value_types::infer_debug_expr_value_type;
use super::*;
use crate::ast::{
    ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, ParamAst, StateBindingAst, StateFieldExpr, Statement,
    TypeBase, TypeRef, parse_type_ref,
};
use crate::span;

#[derive(Clone, Default)]
pub(crate) struct LoweringScope {
    pub(crate) vars: HashMap<String, TypeRef>,
}

#[derive(Clone)]
pub(crate) struct StructFieldSpec {
    pub(crate) name: String,
    pub(crate) type_ref: TypeRef,
}

#[derive(Clone)]
pub(crate) struct StructSpec {
    pub(crate) fields: Vec<StructFieldSpec>,
}

pub(crate) type StructRegistry = HashMap<String, StructSpec>;

pub(crate) fn build_struct_registry<'i>(contract: &ContractAst<'i>) -> Result<StructRegistry, CompilerError> {
    let mut registry = HashMap::new();
    for item in &contract.structs {
        if item.name == "State" {
            return Err(CompilerError::Unsupported("'State' is a reserved struct name".to_string()));
        }
        let mut names = HashSet::new();
        let fields = item
            .fields
            .iter()
            .map(|field| {
                if !names.insert(field.name.clone()) {
                    return Err(CompilerError::Unsupported(format!("duplicate struct field '{}.{}'", item.name, field.name)));
                }
                Ok(StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
            })
            .collect::<Result<Vec<_>, CompilerError>>()?;
        if registry.insert(item.name.clone(), StructSpec { fields }).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate struct name: {}", item.name)));
        }
    }

    let mut state_field_names = HashSet::new();
    let state_fields = contract
        .fields
        .iter()
        .map(|field| {
            if !state_field_names.insert(field.name.clone()) {
                return Err(CompilerError::Unsupported(format!("duplicate contract field name: {}", field.name)));
            }
            Ok(StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
        })
        .collect::<Result<Vec<_>, CompilerError>>()?;
    registry.insert("State".to_string(), StructSpec { fields: state_fields });

    Ok(registry)
}

pub(crate) fn struct_name_from_type_ref<'a>(type_ref: &'a TypeRef, structs: &'a StructRegistry) -> Option<&'a str> {
    if !type_ref.array_dims.is_empty() {
        return None;
    }
    match &type_ref.base {
        TypeBase::Custom(name) if structs.contains_key(name) => Some(name.as_str()),
        _ => None,
    }
}

pub(crate) fn struct_array_name_from_type_ref(type_ref: &TypeRef, structs: &StructRegistry) -> Option<String> {
    let element_type = type_ref.element_type()?;
    struct_name_from_type_ref(&element_type, structs).map(ToOwned::to_owned)
}

pub(crate) fn ensure_known_or_builtin_type(type_ref: &TypeRef, structs: &StructRegistry, context: &str) -> Result<(), CompilerError> {
    if type_ref.array_dims.is_empty() {
        match &type_ref.base {
            TypeBase::Custom(name) if !structs.contains_key(name) => {
                return Err(CompilerError::Unsupported(format!("unknown type '{}' in {context}", name)));
            }
            _ => {}
        }
    } else if let TypeBase::Custom(name) = &type_ref.base {
        if structs.contains_key(name) {
            return Err(CompilerError::Unsupported(format!("arrays of struct type '{}' are not supported", name)));
        }
        return Err(CompilerError::Unsupported(format!("unknown type '{}' in {context}", name)));
    }
    Ok(())
}

pub(crate) fn validate_struct_graph(structs: &StructRegistry) -> Result<(), CompilerError> {
    fn visit(
        name: &str,
        structs: &StructRegistry,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> Result<(), CompilerError> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_string()) {
            return Err(CompilerError::Unsupported(format!("cyclic struct definition involving '{name}'")));
        }
        let item = structs.get(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
        for field in &item.fields {
            ensure_known_or_builtin_type(&field.type_ref, structs, "struct field")?;
            if let Some(child) = struct_name_from_type_ref(&field.type_ref, structs) {
                visit(child, structs, visiting, visited)?;
            }
        }
        visiting.remove(name);
        visited.insert(name.to_string());
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for name in structs.keys() {
        visit(name, structs, &mut visiting, &mut visited)?;
    }
    Ok(())
}

pub(crate) fn flattened_struct_name(base: &str, path: &[String]) -> String {
    let mut out = format!("__struct_{base}");
    for part in path {
        out.push('_');
        out.push_str(part);
    }
    out
}

fn flatten_struct_fields(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    prefix: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, TypeRef)>,
) -> Result<(), CompilerError> {
    if let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) {
        let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        for field in &item.fields {
            prefix.push(field.name.clone());
            flatten_struct_fields(&field.type_ref, structs, prefix, out)?;
            prefix.pop();
        }
    } else {
        out.push((prefix.clone(), type_ref.clone()));
    }
    Ok(())
}

pub(crate) fn resolve_struct_access<'i>(
    expr: &Expr<'i>,
    scope: &LoweringScope,
    structs: &StructRegistry,
) -> Result<(String, Vec<String>, TypeRef), CompilerError> {
    match &expr.kind {
        ExprKind::Identifier(name) => {
            let type_ref = scope.vars.get(name).cloned().ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?;
            Ok((name.clone(), Vec::new(), type_ref))
        }
        ExprKind::FieldAccess { source, field, .. } => {
            let (base, mut path, current_type) = resolve_struct_access(source, scope, structs)?;
            let struct_name = struct_name_from_type_ref(&current_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("field access requires a struct value".to_string()))?;
            let item =
                structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            let field_type = item
                .fields
                .iter()
                .find(|candidate| candidate.name == *field)
                .map(|candidate| candidate.type_ref.clone())
                .ok_or_else(|| CompilerError::Unsupported(format!("struct '{}' has no field '{}'", struct_name, field)))?;
            path.push(field.clone());
            Ok((base, path, field_type))
        }
        _ => Err(CompilerError::Unsupported("struct field access requires a struct variable".to_string())),
    }
}

pub(crate) fn flattened_struct_field_specs_for_type(
    type_ref: &TypeRef,
    structs: &StructRegistry,
) -> Result<Vec<StructFieldSpec>, CompilerError> {
    let mut leaves = Vec::new();
    flatten_struct_fields(type_ref, structs, &mut Vec::new(), &mut leaves)?;
    Ok(leaves
        .into_iter()
        .map(|(path, type_ref)| StructFieldSpec { name: path.last().cloned().unwrap_or_default(), type_ref })
        .collect())
}

fn lower_expr<'i>(expr: &Expr<'i>, scope: &LoweringScope, structs: &StructRegistry) -> Result<Expr<'i>, CompilerError> {
    let span = expr.span;
    match &expr.kind {
        ExprKind::FieldAccess { .. } => {
            if let ExprKind::FieldAccess { source, field, .. } = &expr.kind {
                if let ExprKind::ArrayIndex { source: array_source, index } = &source.as_ref().kind {
                    let (base, mut path, array_type) = resolve_struct_access(array_source, scope, structs)?;
                    let struct_name = struct_array_name_from_type_ref(&array_type, structs)
                        .ok_or_else(|| CompilerError::Unsupported("field access requires a struct value".to_string()))?;
                    let item = structs
                        .get(&struct_name)
                        .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
                    let field_type = item
                        .fields
                        .iter()
                        .find(|candidate| candidate.name == *field)
                        .map(|candidate| candidate.type_ref.clone())
                        .ok_or_else(|| CompilerError::Unsupported(format!("struct '{}' has no field '{}'", struct_name, field)))?;
                    if struct_name_from_type_ref(&field_type, structs).is_some()
                        || struct_array_name_from_type_ref(&field_type, structs).is_some()
                    {
                        return Err(CompilerError::Unsupported("nested struct array field access is not supported".to_string()));
                    }
                    path.push(field.clone());
                    return Ok(Expr::new(
                        ExprKind::ArrayIndex {
                            source: Box::new(Expr::identifier(flattened_struct_name(&base, &path))),
                            index: Box::new(lower_expr(index, scope, structs)?),
                        },
                        span,
                    ));
                }
            }
            let (base, path, type_ref) = resolve_struct_access(expr, scope, structs)?;
            if struct_name_from_type_ref(&type_ref, structs).is_some() {
                return Err(CompilerError::Unsupported("struct value must be used in a struct-typed position".to_string()));
            }
            Ok(Expr::new(ExprKind::Identifier(flattened_struct_name(&base, &path)), span))
        }
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op: *op, expr: Box::new(lower_expr(expr, scope, structs)?) }, span))
        }
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op: *op,
                left: Box::new(lower_expr(left, scope, structs)?),
                right: Box::new(lower_expr(right, scope, structs)?),
            },
            span,
        )),
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(lower_expr(condition, scope, structs)?),
                then_expr: Box::new(lower_expr(then_expr, scope, structs)?),
                else_expr: Box::new(lower_expr(else_expr, scope, structs)?),
            },
            span,
        )),
        ExprKind::Array(values) => Ok(Expr::new(
            ExprKind::Array(values.iter().map(|value| lower_expr(value, scope, structs)).collect::<Result<Vec<_>, _>>()?),
            span,
        )),
        ExprKind::StateObject(_) => {
            Err(CompilerError::Unsupported("struct literals are only supported in struct-typed positions".to_string()))
        }
        ExprKind::Call { name, args, name_span } => {
            let lowered_args = args.iter().map(|arg| lower_expr(arg, scope, structs)).collect::<Result<Vec<_>, _>>()?;
            if name.starts_with("byte[") && name.ends_with(']') {
                let size_part = &name[5..name.len() - 1];
                if !size_part.is_empty() && lowered_args.len() == 1 {
                    let size =
                        size_part.parse::<i64>().map_err(|_| CompilerError::Unsupported(format!("{name}() is not supported")))?;
                    if let Some(source_type) = infer_lowered_expr_type_name(&lowered_args[0], scope)
                        && let Some(source_size) = byte_sequence_cast_size(&source_type)
                        && let Some(source_size) = source_size
                        && source_size != size
                    {
                        return Err(CompilerError::Unsupported(format!("cannot cast {source_type} to {name}")));
                    }
                }
            }
            Ok(Expr::new(ExprKind::Call { name: name.clone(), args: lowered_args, name_span: *name_span }, span))
        }
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(|arg| lower_expr(arg, scope, structs)).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(lower_expr(source, scope, structs)?),
                index: Box::new(lower_expr(index, scope, structs)?),
                part: *part,
                span: *split_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(lower_expr(source, scope, structs)?),
                start: Box::new(lower_expr(start, scope, structs)?),
                end: Box::new(lower_expr(end, scope, structs)?),
                span: *slice_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(lower_expr(source, scope, structs)?),
                index: Box::new(lower_expr(index, scope, structs)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::Introspection { kind: *kind, index: Box::new(lower_expr(index, scope, structs)?), field_span: *field_span },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
            if matches!(kind, crate::ast::UnarySuffixKind::Length)
                && let ExprKind::Identifier(name) = &source.kind
                && let Some(type_ref) = scope.vars.get(name)
                && struct_array_name_from_type_ref(type_ref, structs).is_some()
            {
                let first_leaf = flatten_type_ref_leaves(type_ref, structs)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| CompilerError::Unsupported("struct array must contain fields".to_string()))?;
                return Ok(Expr::new(
                    ExprKind::UnarySuffix {
                        source: Box::new(Expr::identifier(flattened_struct_name(name, &first_leaf.0))),
                        kind: *kind,
                        span: *suffix_span,
                    },
                    span,
                ));
            }
            Ok(Expr::new(
                ExprKind::UnarySuffix { source: Box::new(lower_expr(source, scope, structs)?), kind: *kind, span: *suffix_span },
                span,
            ))
        }
        _ => Ok(expr.clone()),
    }
}

pub(crate) fn lower_struct_value_to_state_object_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Expr<'i>, CompilerError> {
    let lowered_values =
        lower_struct_value_expr(expr, expected_type, scope, structs, contract_fields, contract_constants, contract_field_prefix_len)?;
    let mut paths = Vec::new();
    flatten_struct_fields(expected_type, structs, &mut Vec::new(), &mut paths)?;
    let expected_struct_name = struct_name_from_type_ref(expected_type, structs);
    let fields = paths
        .into_iter()
        .zip(lowered_values)
        .map(|((path, _), value)| StateFieldExpr {
            name: if expected_struct_name == Some("State") {
                match path.as_slice() {
                    [root] => root.clone(),
                    [root, rest @ ..] => flattened_struct_name(root, rest),
                    [] => String::new(),
                }
            } else {
                path.last().cloned().unwrap_or_default()
            },
            expr: value,
            span: expr.span,
            name_span: span::Span::default(),
        })
        .collect();
    Ok(Expr::new(ExprKind::StateObject(fields), expr.span))
}

pub(crate) fn lower_struct_value_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let expected_struct_name = struct_name_from_type_ref(expected_type, structs)
        .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;
    match &expr.kind {
        ExprKind::Call { name, args, .. } if name == "readInputState" => {
            if expected_struct_name != "State" {
                return Err(CompilerError::Unsupported("readInputState returns State".to_string()));
            }
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("readInputState(input_idx) expects 1 argument".to_string()));
            }
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            let mut field_chunk_offset = 0usize;
            let mut lowered = Vec::with_capacity(contract_fields.len());
            for field in contract_fields {
                lowered.push(read_input_state_field_expr_symbolic(
                    &args[0],
                    field,
                    contract_fields,
                    contract_field_prefix_len,
                    field_chunk_offset,
                    contract_constants,
                )?);
                field_chunk_offset += super::compile::encoded_field_chunk_size(field, contract_constants)?;
            }
            Ok(lowered)
        }
        ExprKind::Call { name, .. } if name == "readInputStateWithTemplate" => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
        )),
        ExprKind::Identifier(_) | ExprKind::FieldAccess { .. } => {
            let (base, path, actual_type) = resolve_struct_access(expr, scope, structs)?;
            let actual_struct_name = struct_name_from_type_ref(&actual_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("expression is not a struct".to_string()))?;
            if actual_struct_name != expected_struct_name {
                return Err(CompilerError::Unsupported(format!(
                    "struct expression expects {}, got {}",
                    expected_type.type_name(),
                    actual_type.type_name()
                )));
            }
            let mut flattened = Vec::new();
            let mut leaves = Vec::new();
            let mut prefix = path.clone();
            flatten_struct_fields(&actual_type, structs, &mut prefix, &mut leaves)?;
            for (leaf_path, _) in leaves {
                flattened.push(Expr::identifier(flattened_struct_name(&base, &leaf_path)));
            }
            Ok(flattened)
        }
        ExprKind::ArrayIndex { source, index } => {
            let source_type = match &source.kind {
                ExprKind::Identifier(name) => scope
                    .vars
                    .get(name)
                    .cloned()
                    .ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?,
                _ => return Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
            };
            let actual_struct_name = struct_array_name_from_type_ref(&source_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("expression is not a struct".to_string()))?;
            if actual_struct_name != expected_struct_name {
                return Err(CompilerError::Unsupported(format!(
                    "struct expression expects {}, got {}",
                    expected_type.type_name(),
                    source_type.type_name()
                )));
            }
            let lowered_index = lower_expr(index, scope, structs)?;
            let source_leaves = lower_struct_array_value_expr(
                source,
                &source_type,
                scope,
                structs,
                contract_fields,
                contract_constants,
                contract_field_prefix_len,
            )?;
            Ok(source_leaves
                .into_iter()
                .map(|leaf| {
                    Expr::new(ExprKind::ArrayIndex { source: Box::new(leaf), index: Box::new(lowered_index.clone()) }, expr.span)
                })
                .collect())
        }
        ExprKind::StateObject(entries) => {
            let item = structs
                .get(expected_struct_name)
                .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{expected_struct_name}'")))?;
            let mut provided = HashMap::new();
            for entry in entries {
                if provided.insert(entry.name.clone(), &entry.expr).is_some() {
                    return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", entry.name)));
                }
            }
            let mut lowered = Vec::new();
            for field in &item.fields {
                let field_expr = provided
                    .remove(&field.name)
                    .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))?;
                if struct_name_from_type_ref(&field.type_ref, structs).is_some() {
                    lowered.extend(lower_struct_value_expr(
                        field_expr,
                        &field.type_ref,
                        scope,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?);
                } else {
                    lowered.push(lower_expr(field_expr, scope, structs)?);
                }
            }
            if let Some(extra) = provided.keys().next() {
                return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
            }
            Ok(lowered)
        }
        _ => Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
    }
}

pub(crate) fn infer_struct_expr_type<'i>(
    expr: &Expr<'i>,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<TypeRef, CompilerError> {
    match &expr.kind {
        ExprKind::Identifier(_) | ExprKind::FieldAccess { .. } => {
            let (_, _, type_ref) = resolve_struct_access(expr, scope, structs)?;
            Ok(type_ref)
        }
        ExprKind::ArrayIndex { source, .. } => match &source.kind {
            ExprKind::Identifier(name) => scope
                .vars
                .get(name)
                .cloned()
                .ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?
                .element_type()
                .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
            _ => Err(CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
        },
        ExprKind::Call { name, .. } if name == "readInputState" => {
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            Ok(TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() })
        }
        ExprKind::Call { name, .. } if name == "readInputStateWithTemplate" => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
        )),
        _ => Err(CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
    }
}

pub(crate) fn lower_struct_destructure_statement<'i>(
    bindings: &[StateBindingAst<'i>],
    expr: &Expr<'i>,
    span: crate::span::Span<'i>,
    scope: &mut LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let expr_type = infer_struct_expr_type(expr, scope, structs, contract_fields)?;
    let struct_name = struct_name_from_type_ref(&expr_type, structs)
        .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string()))?;
    let struct_ast = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let direct_field_values = if matches!(&expr.kind, ExprKind::Call { name, .. } if name == "readInputState") {
        Some(
            struct_ast
                .fields
                .iter()
                .map(|field| field.name.clone())
                .zip(lower_struct_value_expr(
                    expr,
                    &expr_type,
                    scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?)
                .collect::<HashMap<_, _>>(),
        )
    } else {
        None
    };

    let mut binding_map = HashMap::new();
    for binding in bindings {
        let replaced = binding_map.insert(binding.field_name.clone(), binding);
        debug_assert!(replaced.is_none(), "type_check must validate duplicate struct destructuring fields");
    }

    let mut lowered = Vec::new();
    for field in &struct_ast.fields {
        let binding = binding_map.remove(&field.name).expect("type_check must validate exact struct destructuring coverage");
        debug_assert_eq!(binding.type_ref, field.type_ref, "type_check must validate struct destructuring field types");

        if let Some(field_expr) = direct_field_values.as_ref().and_then(|fields| fields.get(&field.name)) {
            debug_assert!(
                struct_name_from_type_ref(&binding.type_ref, structs).is_none(),
                "type_check must reject nested struct destructuring from readInputState"
            );
            scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
            lowered.push(Statement::VariableDefinition {
                type_ref: binding.type_ref.clone(),
                modifiers: Vec::new(),
                name: binding.name.clone(),
                expr: Some(field_expr.clone()),
                span: binding.span,
                type_span: binding.type_span,
                modifier_spans: Vec::new(),
                name_span: binding.name_span,
            });
        } else {
            let projected_expr = Expr::new(
                ExprKind::FieldAccess { source: Box::new(expr.clone()), field: field.name.clone(), field_span: binding.field_span },
                span,
            );

            if struct_name_from_type_ref(&binding.type_ref, structs).is_some() {
                let lowered_values = lower_struct_value_expr(
                    &projected_expr,
                    &binding.type_ref,
                    scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                let mut paths = Vec::new();
                flatten_struct_fields(&binding.type_ref, structs, &mut Vec::new(), &mut paths)?;
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                lowered.extend(paths.into_iter().zip(lowered_values).map(|((path, field_type), field_expr)| {
                    Statement::VariableDefinition {
                        type_ref: field_type,
                        modifiers: Vec::new(),
                        name: flattened_struct_name(&binding.name, &path),
                        expr: Some(field_expr),
                        span: binding.span,
                        type_span: binding.type_span,
                        modifier_spans: Vec::new(),
                        name_span: binding.name_span,
                    }
                }));
            } else {
                let lowered_expr = lower_expr(&projected_expr, scope, structs)?;
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                lowered.push(Statement::VariableDefinition {
                    type_ref: binding.type_ref.clone(),
                    modifiers: Vec::new(),
                    name: binding.name.clone(),
                    expr: Some(lowered_expr),
                    span: binding.span,
                    type_span: binding.type_span,
                    modifier_spans: Vec::new(),
                    name_span: binding.name_span,
                });
            }
        }
    }

    debug_assert!(binding_map.is_empty(), "type_check must validate exact struct destructuring coverage");

    Ok(lowered)
}

pub(crate) fn flatten_type_ref_leaves(type_ref: &TypeRef, structs: &StructRegistry) -> Result<Vec<(Vec<String>, TypeRef)>, CompilerError> {
    if let Some(struct_name) = struct_array_name_from_type_ref(type_ref, structs) {
        let outer_dims = type_ref.array_dims.clone();
        let item = structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        let mut leaves = Vec::new();
        for field in &item.fields {
            let mut field_type = field.type_ref.clone();
            field_type.array_dims.extend(outer_dims.iter().cloned());
            for (mut path, leaf_type) in flatten_type_ref_leaves(&field_type, structs)? {
                path.insert(0, field.name.clone());
                leaves.push((path, leaf_type));
            }
        }
        return Ok(leaves);
    }

    let mut leaves = Vec::new();
    flatten_struct_fields(type_ref, structs, &mut Vec::new(), &mut leaves)?;
    Ok(leaves)
}

pub(crate) fn lowering_scope_from_types(types: &HashMap<String, String>) -> Result<LoweringScope, CompilerError> {
    let mut scope = LoweringScope::default();
    for (name, type_name) in types {
        scope.vars.insert(name.clone(), parse_type_ref(type_name)?);
    }
    Ok(scope)
}

pub(crate) fn lower_runtime_expr<'i>(
    expr: &Expr<'i>,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
) -> Result<Expr<'i>, CompilerError> {
    let scope = lowering_scope_from_types(types)?;
    lower_expr(expr, &scope, structs)
}

fn infer_lowered_expr_type_name<'i>(expr: &Expr<'i>, scope: &LoweringScope) -> Option<String> {
    let types = scope.vars.iter().map(|(name, type_ref)| (name.clone(), type_name_from_ref(type_ref))).collect::<HashMap<_, _>>();
    infer_debug_expr_value_type(expr, &HashMap::new(), &types, &mut HashSet::new()).ok()
}

pub(crate) fn lower_runtime_struct_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let scope = lowering_scope_from_types(types)?;
    if struct_name_from_type_ref(expected_type, structs).is_some() {
        return lower_struct_value_expr(
            expr,
            expected_type,
            &scope,
            structs,
            contract_fields,
            contract_constants,
            contract_field_prefix_len,
        );
    }
    if struct_array_name_from_type_ref(expected_type, structs).is_some() {
        return lower_struct_array_value_expr(
            expr,
            expected_type,
            &scope,
            structs,
            contract_fields,
            contract_constants,
            contract_field_prefix_len,
        );
    }
    Err(CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))
}

fn lower_struct_array_value_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let Some(struct_name) = struct_array_name_from_type_ref(expected_type, structs) else {
        return Err(CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())));
    };

    match &expr.kind {
        ExprKind::Identifier(name) => {
            let actual_type =
                scope.vars.get(name).ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?;
            let actual_struct_name = struct_array_name_from_type_ref(actual_type, structs)
                .ok_or_else(|| CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name())))?;
            if actual_struct_name != struct_name || !super::compile::is_type_assignable_ref(actual_type, expected_type, contract_constants)
            {
                return Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name())));
            }
            let leaves = flatten_type_ref_leaves(expected_type, structs)?;
            Ok(leaves
                .into_iter()
                .map(|(path, _)| Expr::new(ExprKind::Identifier(flattened_struct_name(name, &path)), span::Span::default()))
                .collect())
        }
        ExprKind::Array(values) => {
            let element_type = expected_type
                .element_type()
                .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;
            let leaf_specs = flatten_type_ref_leaves(&element_type, structs)?;
            let mut grouped: Vec<Vec<Expr<'i>>> = vec![Vec::with_capacity(values.len()); leaf_specs.len()];
            for value in values {
                let lowered = lower_struct_value_expr(
                    value,
                    &element_type,
                    scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                for (idx, expr) in lowered.into_iter().enumerate() {
                    grouped[idx].push(expr);
                }
            }
            Ok(grouped.into_iter().map(|entries| Expr::new(ExprKind::Array(entries), span::Span::default())).collect())
        }
        _ => Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
    }
}

pub(crate) fn flatten_runtime_return_exprs<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let mut flattened = Vec::new();
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        if struct_name_from_type_ref(return_type, structs).is_some()
            || struct_array_name_from_type_ref(return_type, structs).is_some()
        {
            flattened.extend(lower_runtime_struct_expr(
                expr,
                return_type,
                types,
                structs,
                contract_fields,
                contract_constants,
                contract_field_prefix_len,
            )?);
        } else {
            flattened.push(lower_runtime_expr(expr, types, structs)?);
        }
    }
    Ok(flattened)
}

fn scope_type_names(scope: &LoweringScope) -> HashMap<String, String> {
    scope.vars.iter().map(|(name, type_ref)| (name.clone(), type_name_from_ref(type_ref))).collect()
}

fn flatten_named_type_like<'i>(name: &str, type_ref: &TypeRef, structs: &StructRegistry) -> Result<Vec<(String, TypeRef)>, CompilerError> {
    if struct_name_from_type_ref(type_ref, structs).is_some() || struct_array_name_from_type_ref(type_ref, structs).is_some() {
        Ok(flatten_type_ref_leaves(type_ref, structs)?
            .into_iter()
            .map(|(path, leaf_type)| (flattened_struct_name(name, &path), leaf_type))
            .collect())
    } else {
        Ok(vec![(name.to_string(), type_ref.clone())])
    }
}

fn lower_value_for_named_type<'i>(
    name: &str,
    type_ref: &TypeRef,
    expr: &Expr<'i>,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<(String, TypeRef, Expr<'i>)>, CompilerError> {
    let scope_types = scope_type_names(scope);
    if struct_name_from_type_ref(type_ref, structs).is_some() || struct_array_name_from_type_ref(type_ref, structs).is_some() {
        let lowered = lower_runtime_struct_expr(
            expr,
            type_ref,
            &scope_types,
            structs,
            contract_fields,
            contract_constants,
            contract_field_prefix_len,
        )?;
        Ok(flatten_type_ref_leaves(type_ref, structs)?
            .into_iter()
            .zip(lowered)
            .map(|((path, leaf_type), lowered_expr)| (flattened_struct_name(name, &path), leaf_type, lowered_expr))
            .collect())
    } else {
        Ok(vec![(name.to_string(), type_ref.clone(), lower_runtime_expr(expr, &scope_types, structs)?)])
    }
}

fn lower_call_args<'i>(
    name: &str,
    args: &[Expr<'i>],
    functions: &HashMap<String, FunctionAst<'i>>,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    if name == "validateOutputState" || name == "validateOutputStateWithTemplate" {
        let mut lowered = Vec::with_capacity(args.len());
        for (index, arg) in args.iter().enumerate() {
            if index == 1 {
                if let ExprKind::StateObject(fields) = &arg.kind {
                    let lowered_fields = fields
                        .iter()
                        .map(|field| {
                            Ok(StateFieldExpr {
                                name: field.name.clone(),
                                expr: lower_runtime_expr(&field.expr, &scope_type_names(scope), structs)?,
                                span: field.span,
                                name_span: field.name_span,
                            })
                        })
                        .collect::<Result<Vec<_>, CompilerError>>()?;
                    lowered.push(Expr::new(ExprKind::StateObject(lowered_fields), arg.span));
                } else {
                    let state_type = if name == "validateOutputState" {
                        TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() }
                    } else {
                        infer_struct_expr_type(arg, scope, structs, contract_fields)?
                    };
                    lowered.push(lower_struct_value_to_state_object_expr(
                        arg,
                        &state_type,
                        scope,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?);
                }
            } else {
                lowered.push(lower_runtime_expr(arg, &scope_type_names(scope), structs)?);
            }
        }
        return Ok(lowered);
    }

    let Some(function) = functions.get(name) else {
        return args.iter().map(|arg| lower_runtime_expr(arg, &scope_type_names(scope), structs)).collect();
    };

    let mut lowered = Vec::new();
    for (arg, param) in args.iter().zip(function.params.iter()) {
        if struct_name_from_type_ref(&param.type_ref, structs).is_some() || struct_array_name_from_type_ref(&param.type_ref, structs).is_some()
        {
            lowered.extend(lower_runtime_struct_expr(
                arg,
                &param.type_ref,
                &scope_type_names(scope),
                structs,
                contract_fields,
                contract_constants,
                contract_field_prefix_len,
            )?);
        } else {
            lowered.push(lower_runtime_expr(arg, &scope_type_names(scope), structs)?);
        }
    }
    Ok(lowered)
}

fn lower_function_call_bindings<'i>(
    bindings: &[ParamAst<'i>],
    callee_return_types: &[TypeRef],
    structs: &StructRegistry,
) -> Result<Vec<ParamAst<'i>>, CompilerError> {
    let mut lowered = Vec::new();
    for (binding, return_type) in bindings.iter().zip(callee_return_types.iter()) {
        if struct_name_from_type_ref(return_type, structs).is_some() || struct_array_name_from_type_ref(return_type, structs).is_some() {
            for (path, leaf_type) in flatten_type_ref_leaves(return_type, structs)? {
                lowered.push(ParamAst {
                    type_ref: leaf_type,
                    name: flattened_struct_name(&binding.name, &path),
                    span: binding.span,
                    type_span: binding.type_span,
                    name_span: binding.name_span,
                });
            }
        } else {
            lowered.push(binding.clone());
        }
    }
    Ok(lowered)
}

fn merge_scopes(target: &mut LoweringScope, source: &LoweringScope) {
    for (name, type_ref) in &source.vars {
        target.vars.entry(name.clone()).or_insert_with(|| type_ref.clone());
    }
}

fn lower_statements<'i>(
    statements: &[Statement<'i>],
    scope: &mut LoweringScope,
    functions: &HashMap<String, FunctionAst<'i>>,
    return_types: &[TypeRef],
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let mut lowered = Vec::new();
    for stmt in statements {
        match stmt {
            Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
                scope.vars.insert(name.clone(), type_ref.clone());
                if struct_name_from_type_ref(type_ref, structs).is_some() || struct_array_name_from_type_ref(type_ref, structs).is_some() {
                    if let Some(Expr { kind: ExprKind::Call { name: builtin_name, args, .. }, .. }) = expr
                        && matches!(builtin_name.as_str(), "readInputState" | "readInputStateWithTemplate")
                        && let Some(struct_name) = struct_name_from_type_ref(type_ref, structs)
                        && let Some(item) = structs.get(struct_name)
                        && item.fields.iter().all(|field| {
                            struct_name_from_type_ref(&field.type_ref, structs).is_none()
                                && struct_array_name_from_type_ref(&field.type_ref, structs).is_none()
                        })
                    {
                        lowered.push(Statement::StateFunctionCallAssign {
                            bindings: item
                                .fields
                                .iter()
                                .map(|field| StateBindingAst {
                                    field_name: field.name.clone(),
                                    type_ref: field.type_ref.clone(),
                                    name: flattened_struct_name(name, std::slice::from_ref(&field.name)),
                                    span: *span,
                                    field_span: *name_span,
                                    type_span: *type_span,
                                    name_span: *name_span,
                                })
                                .collect(),
                            name: builtin_name.clone(),
                            args: args
                                .iter()
                                .map(|arg| lower_runtime_expr(arg, &scope_type_names(scope), structs))
                                .collect::<Result<Vec<_>, _>>()?,
                            span: *span,
                            name_span: *name_span,
                        });
                        continue;
                    }
                    if let Some(expr) = expr {
                        for (leaf_name, leaf_type, leaf_expr) in lower_value_for_named_type(
                            name,
                            type_ref,
                            expr,
                            scope,
                            structs,
                            contract_fields,
                            contract_constants,
                            contract_field_prefix_len,
                        )? {
                            lowered.push(Statement::VariableDefinition {
                                type_ref: leaf_type,
                                modifiers: modifiers.clone(),
                                name: leaf_name,
                                expr: Some(leaf_expr),
                                span: *span,
                                type_span: *type_span,
                                modifier_spans: modifier_spans.clone(),
                                name_span: *name_span,
                            });
                        }
                    } else {
                        for (leaf_name, leaf_type) in flatten_named_type_like(name, type_ref, structs)? {
                            lowered.push(Statement::VariableDefinition {
                                type_ref: leaf_type,
                                modifiers: modifiers.clone(),
                                name: leaf_name,
                                expr: None,
                                span: *span,
                                type_span: *type_span,
                                modifier_spans: modifier_spans.clone(),
                                name_span: *name_span,
                            });
                        }
                    }
                } else {
                    lowered.push(Statement::VariableDefinition {
                        type_ref: type_ref.clone(),
                        modifiers: modifiers.clone(),
                        name: name.clone(),
                        expr: expr
                            .as_ref()
                            .map(|expr| lower_runtime_expr(expr, &scope_type_names(scope), structs))
                            .transpose()?,
                        span: *span,
                        type_span: *type_span,
                        modifier_spans: modifier_spans.clone(),
                        name_span: *name_span,
                    });
                }
            }
            Statement::TupleAssignment { left_type_ref, left_name, right_type_ref, right_name, expr, span, left_type_span, left_name_span, right_type_span, right_name_span } => {
                scope.vars.insert(left_name.clone(), left_type_ref.clone());
                scope.vars.insert(right_name.clone(), right_type_ref.clone());
                lowered.push(Statement::TupleAssignment {
                    left_type_ref: left_type_ref.clone(),
                    left_name: left_name.clone(),
                    right_type_ref: right_type_ref.clone(),
                    right_name: right_name.clone(),
                    expr: lower_runtime_expr(expr, &scope_type_names(scope), structs)?,
                    span: *span,
                    left_type_span: *left_type_span,
                    left_name_span: *left_name_span,
                    right_type_span: *right_type_span,
                    right_name_span: *right_name_span,
                });
            }
            Statement::ArrayPush { name, expr, span, name_span } => {
                let Some(type_ref) = scope.vars.get(name).cloned() else {
                    lowered.push(stmt.clone());
                    continue;
                };
                if struct_array_name_from_type_ref(&type_ref, structs).is_some() {
                    let element_type = type_ref
                        .element_type()
                        .ok_or_else(|| CompilerError::Unsupported("array element type not supported".to_string()))?;
                    if let ExprKind::Call { name: builtin_name, args, .. } = &expr.kind
                        && matches!(builtin_name.as_str(), "readInputState" | "readInputStateWithTemplate")
                    {
                        let temp_base = format!("push_{}_{}", name, lowered.len());
                        let leaf_bindings = flatten_type_ref_leaves(&element_type, structs)?;
                        let state_bindings = leaf_bindings
                            .iter()
                            .map(|(path, leaf_type)| StateBindingAst {
                                field_name: path.last().cloned().unwrap_or_default(),
                                type_ref: leaf_type.clone(),
                                name: flattened_struct_name(&temp_base, path),
                                span: *span,
                                field_span: *name_span,
                                type_span: *name_span,
                                name_span: *name_span,
                            })
                            .collect::<Vec<_>>();
                        lowered.push(Statement::StateFunctionCallAssign {
                            bindings: state_bindings.clone(),
                            name: builtin_name.clone(),
                            args: args
                                .iter()
                                .map(|arg| lower_runtime_expr(arg, &scope_type_names(scope), structs))
                                .collect::<Result<Vec<_>, _>>()?,
                            span: *span,
                            name_span: *name_span,
                        });
                        for ((path, leaf_type), binding) in leaf_bindings.into_iter().zip(state_bindings.into_iter()) {
                            scope.vars.insert(binding.name.clone(), leaf_type);
                            lowered.push(Statement::ArrayPush {
                                name: flattened_struct_name(name, &path),
                                expr: Expr::identifier(binding.name),
                                span: *span,
                                name_span: *name_span,
                            });
                        }
                        continue;
                    }
                    for ((path, leaf_type), leaf_expr) in flatten_type_ref_leaves(&element_type, structs)?
                        .into_iter()
                        .zip(lower_runtime_struct_expr(
                            expr,
                            &element_type,
                            &scope_type_names(scope),
                            structs,
                            contract_fields,
                            contract_constants,
                            contract_field_prefix_len,
                        )?)
                    {
                        lowered.push(Statement::ArrayPush {
                            name: flattened_struct_name(name, &path),
                            expr: leaf_expr,
                            span: *span,
                            name_span: *name_span,
                        });
                        let _ = leaf_type;
                    }
                } else {
                    lowered.push(Statement::ArrayPush {
                        name: name.clone(),
                        expr: lower_runtime_expr(expr, &scope_type_names(scope), structs)?,
                        span: *span,
                        name_span: *name_span,
                    });
                }
            }
            Statement::FunctionCall { name, args, span, name_span } => {
            lowered.push(Statement::FunctionCall {
                name: name.clone(),
                    args: lower_call_args(
                        name,
                        args,
                        functions,
                        scope,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
                let lowered_bindings = if let Some(function) = functions.get(name) {
                    if function
                        .return_types
                        .iter()
                        .any(|type_ref| struct_name_from_type_ref(type_ref, structs).is_some() || struct_array_name_from_type_ref(type_ref, structs).is_some())
                    {
                        lower_function_call_bindings(bindings, &function.return_types, structs)?
                    } else {
                        bindings.clone()
                    }
                } else {
                    bindings.clone()
                };
                for binding in bindings {
                    scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::FunctionCallAssign {
                    bindings: lowered_bindings,
                    name: name.clone(),
                    args: lower_call_args(
                        name,
                        args,
                        functions,
                        scope,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => {
                for binding in bindings {
                    scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::StateFunctionCallAssign {
                    bindings: bindings.clone(),
                    name: name.clone(),
                    args: args
                        .iter()
                        .map(|arg| lower_runtime_expr(arg, &scope_type_names(scope), structs))
                        .collect::<Result<Vec<_>, _>>()?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StructDestructure { bindings, expr, span } => {
                for binding in bindings {
                    scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                }
                let mut destruct_scope = scope.clone();
                lowered.extend(lower_struct_destructure_statement(
                    bindings,
                    expr,
                    *span,
                    &mut destruct_scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?);
                merge_scopes(scope, &destruct_scope);
            }
            Statement::Assign { name, expr, span, name_span } => {
                let Some(type_ref) = scope.vars.get(name).cloned() else {
                    lowered.push(Statement::Assign {
                        name: name.clone(),
                        expr: lower_runtime_expr(expr, &scope_type_names(scope), structs)?,
                        span: *span,
                        name_span: *name_span,
                    });
                    continue;
                };
                if struct_name_from_type_ref(&type_ref, structs).is_some() || struct_array_name_from_type_ref(&type_ref, structs).is_some() {
                    for (leaf_name, _leaf_type, leaf_expr) in lower_value_for_named_type(
                        name,
                        &type_ref,
                        expr,
                        scope,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )? {
                        lowered.push(Statement::Assign { name: leaf_name, expr: leaf_expr, span: *span, name_span: *name_span });
                    }
                } else {
                    lowered.push(Statement::Assign {
                        name: name.clone(),
                        expr: lower_runtime_expr(expr, &scope_type_names(scope), structs)?,
                        span: *span,
                        name_span: *name_span,
                    });
                }
            }
            Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => lowered.push(Statement::TimeOp {
                tx_var: *tx_var,
                expr: lower_runtime_expr(expr, &scope_type_names(scope), structs)?,
                message: message.clone(),
                span: *span,
                tx_var_span: *tx_var_span,
                message_span: *message_span,
            }),
            Statement::Require { expr, message, span, message_span } => lowered.push(Statement::Require {
                expr: lower_runtime_expr(expr, &scope_type_names(scope), structs)?,
                message: message.clone(),
                span: *span,
                message_span: *message_span,
            }),
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
                let mut then_scope = scope.clone();
                let lowered_then = lower_statements(
                    then_branch,
                    &mut then_scope,
                    functions,
                    return_types,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                let (lowered_else, else_scope) = if let Some(else_branch) = else_branch {
                    let mut else_scope = scope.clone();
                    let lowered_else = lower_statements(
                        else_branch,
                        &mut else_scope,
                        functions,
                        return_types,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?;
                    (Some(lowered_else), Some(else_scope))
                } else {
                    (None, None)
                };
                merge_scopes(scope, &then_scope);
                if let Some(else_scope) = &else_scope {
                    merge_scopes(scope, else_scope);
                }
                lowered.push(Statement::If {
                    condition: lower_runtime_expr(condition, &scope_type_names(scope), structs)?,
                    then_branch: lowered_then,
                    else_branch: lowered_else,
                    span: *span,
                    then_span: *then_span,
                    else_span: *else_span,
                });
            }
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                let mut body_scope = scope.clone();
                body_scope.vars.insert(ident.clone(), TypeRef { base: TypeBase::Int, array_dims: Vec::new() });
                let lowered_body = lower_statements(
                    body,
                    &mut body_scope,
                    functions,
                    return_types,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                merge_scopes(scope, &body_scope);
                lowered.push(Statement::For {
                    ident: ident.clone(),
                    start: lower_runtime_expr(start, &scope_type_names(scope), structs)?,
                    end: lower_runtime_expr(end, &scope_type_names(scope), structs)?,
                    max_iterations: lower_runtime_expr(max_iterations, &scope_type_names(scope), structs)?,
                    body: lowered_body,
                    span: *span,
                    ident_span: *ident_span,
                    body_span: *body_span,
                });
            }
            Statement::Return { exprs, span } => lowered.push(Statement::Return {
                exprs: flatten_runtime_return_exprs(
                    exprs,
                    return_types,
                    &scope_type_names(scope),
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?,
                span: *span,
            }),
            Statement::Console { args, span } => lowered.push(Statement::Console {
                args: args
                    .iter()
                    .map(|arg| lower_runtime_expr(arg, &scope_type_names(scope), structs))
                    .collect::<Result<Vec<_>, _>>()?,
                span: *span,
            }),
        }
    }
    Ok(lowered)
}

fn initial_contract_scope<'i>(contract: &ContractAst<'i>) -> LoweringScope {
    let mut scope = LoweringScope::default();
    for param in &contract.params {
        scope.vars.insert(param.name.clone(), param.type_ref.clone());
    }
    for constant in &contract.constants {
        scope.vars.insert(constant.name.clone(), constant.type_ref.clone());
    }
    for field in &contract.fields {
        scope.vars.insert(field.name.clone(), field.type_ref.clone());
    }
    scope
}

pub(crate) fn flatten_constructor_args_env<'i>(
    params: &[ParamAst<'i>],
    constructor_args: &[Expr<'i>],
    structs: &StructRegistry,
) -> Result<HashMap<String, Expr<'i>>, CompilerError> {
    let scope = LoweringScope::default();
    let mut env = HashMap::new();
    for (param, arg) in params.iter().zip(constructor_args.iter()) {
        for (name, _, expr) in lower_value_for_named_type(param.name.as_str(), &param.type_ref, arg, &scope, structs, &[], &HashMap::new(), 0)? {
            env.insert(name, expr);
        }
    }
    Ok(env)
}

pub(crate) fn lower_structs_contract<'i>(
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let mut scope = LoweringScope::default();
    let mut lowered_params = Vec::new();
    for param in &contract.params {
        scope.vars.insert(param.name.clone(), param.type_ref.clone());
        for (name, type_ref) in flatten_named_type_like(&param.name, &param.type_ref, structs)? {
            lowered_params.push(ParamAst { type_ref, name, span: param.span, type_span: param.type_span, name_span: param.name_span });
        }
    }

    let mut lowered_constants = Vec::new();
    for constant in &contract.constants {
        scope.vars.insert(constant.name.clone(), constant.type_ref.clone());
        if struct_name_from_type_ref(&constant.type_ref, structs).is_some()
            || struct_array_name_from_type_ref(&constant.type_ref, structs).is_some()
        {
            for (name, type_ref, expr) in lower_value_for_named_type(
                &constant.name,
                &constant.type_ref,
                &constant.expr,
                &scope,
                structs,
                &contract.fields,
                contract_constants,
                0,
            )? {
                lowered_constants.push(ConstantAst {
                    type_ref,
                    name,
                    expr,
                    span: constant.span,
                    type_span: constant.type_span,
                    name_span: constant.name_span,
                });
            }
        } else {
            lowered_constants.push(ConstantAst {
                type_ref: constant.type_ref.clone(),
                name: constant.name.clone(),
                expr: lower_runtime_expr(&constant.expr, &scope_type_names(&scope), structs)?,
                span: constant.span,
                type_span: constant.type_span,
                name_span: constant.name_span,
            });
        }
    }

    let mut lowered_fields = Vec::new();
    for field in &contract.fields {
        scope.vars.insert(field.name.clone(), field.type_ref.clone());
        if struct_name_from_type_ref(&field.type_ref, structs).is_some() || struct_array_name_from_type_ref(&field.type_ref, structs).is_some()
        {
            for (name, type_ref, expr) in lower_value_for_named_type(
                &field.name,
                &field.type_ref,
                &field.expr,
                &scope,
                structs,
                &contract.fields,
                contract_constants,
                0,
            )? {
                lowered_fields.push(ContractFieldAst {
                    type_ref,
                    name,
                    expr,
                    span: field.span,
                    type_span: field.type_span,
                    name_span: field.name_span,
                });
            }
        } else {
            lowered_fields.push(ContractFieldAst {
                type_ref: field.type_ref.clone(),
                name: field.name.clone(),
                expr: lower_runtime_expr(&field.expr, &scope_type_names(&scope), structs)?,
                span: field.span,
                type_span: field.type_span,
                name_span: field.name_span,
            });
        }
    }

    let functions_map = contract.functions.iter().cloned().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let mut lowered_functions = Vec::new();
    for function in &contract.functions {
        let mut function_scope = initial_contract_scope(contract);
        for param in &function.params {
            function_scope.vars.insert(param.name.clone(), param.type_ref.clone());
        }

        let mut lowered_function_params = Vec::new();
        for param in &function.params {
            for (name, type_ref) in flatten_named_type_like(&param.name, &param.type_ref, structs)? {
                lowered_function_params.push(ParamAst {
                    type_ref,
                    name,
                    span: param.span,
                    type_span: param.type_span,
                    name_span: param.name_span,
                });
            }
        }

        let mut lowered_return_types = Vec::new();
        for return_type in &function.return_types {
            for (_path, leaf_type) in flatten_type_ref_leaves(return_type, structs)? {
                lowered_return_types.push(leaf_type);
            }
        }

        let lowered_body = lower_statements(
            &function.body,
            &mut function_scope,
            &functions_map,
            &function.return_types,
            structs,
            &contract.fields,
            contract_constants,
            0,
        )?;

        lowered_functions.push(FunctionAst {
            name: function.name.clone(),
            attributes: function.attributes.clone(),
            params: lowered_function_params,
            entrypoint: function.entrypoint,
            return_types: lowered_return_types,
            body: lowered_body,
            return_type_spans: function.return_type_spans.clone(),
            span: function.span,
            name_span: function.name_span,
            body_span: function.body_span,
        });
    }

    Ok(ContractAst {
        name: contract.name.clone(),
        params: lowered_params,
        structs: Vec::new(),
        fields: lowered_fields,
        constants: lowered_constants,
        functions: lowered_functions,
        span: contract.span,
        name_span: contract.name_span,
    })
}
