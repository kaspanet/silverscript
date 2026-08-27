use super::*;

pub(super) fn lower_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    if is_struct(expected_type, lowerer.structs) {
        return lower_struct_expr(expr, expected_type, scope, lowerer);
    }
    if is_struct_array(expected_type, lowerer.structs) {
        return lower_struct_array_expr(expr, expected_type, scope, lowerer);
    }
    Ok(vec![lower_scalar_expr(expr, scope, lowerer)?])
}

pub(super) fn lower_struct_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let structs = lowerer.structs;
    let contract_fields = lowerer.contract_fields;
    let contract_constants = lowerer.contract_constants;
    let state_end = lowerer.state_end;
    let expected_struct_name = struct_name(expected_type, structs)
        .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;
    match &expr.kind {
        ExprKind::Call { name, args, .. } if name == "readInputState" => {
            if expected_struct_name != STATE_TYPE_NAME {
                return Err(CompilerError::Unsupported(format!("readInputState returns {}", STATE_TYPE_NAME)));
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
                    state_end,
                    field_chunk_offset,
                    contract_constants,
                )?);
                field_chunk_offset += super::compile::encoded_type_chunk_size(&field.type_ref, contract_constants)?;
            }
            Ok(lowered)
        }
        ExprKind::Call { name, .. } if name == "readInputStateWithTemplate" => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
        )),
        ExprKind::Identifier(_) | ExprKind::FieldAccess { .. } => {
            let (base, path, actual_type) = resolve_struct_access(expr, scope, structs)?;
            let actual_struct_name = struct_name(&actual_type, structs)
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
            for leaf in leaves {
                flattened.push(Expr::identifier(flattened_struct_name(&base, &leaf.path)));
            }
            Ok(flattened)
        }
        ExprKind::ArrayIndex { source, index } => {
            // TODO: Support indexing any struct-array expression, not only an identifier.
            let source_type = match &source.kind {
                ExprKind::Identifier(name) => scope
                    .vars
                    .get(name)
                    .cloned()
                    .ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?,
                _ => return Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
            };
            let actual_struct_name = struct_array_name(&source_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("expression is not a struct".to_string()))?;
            if actual_struct_name != expected_struct_name {
                return Err(CompilerError::Unsupported(format!(
                    "struct expression expects {}, got {}",
                    expected_type.type_name(),
                    source_type.type_name()
                )));
            }
            let lowered_index = lower_scalar_expr(index, scope, lowerer)?;
            let source_leaves = lower_struct_array_expr(source, &source_type, scope, lowerer)?;
            Ok(source_leaves
                .into_iter()
                .map(|leaf| {
                    Expr::new(ExprKind::ArrayIndex { source: Box::new(leaf), index: Box::new(lowered_index.clone()) }, expr.span)
                })
                .collect())
        }
        ExprKind::StructLiteral { name, fields: entries, .. } => {
            if name != expected_struct_name {
                return Err(CompilerError::Unsupported(format!("struct expression expects {}, got {}", expected_struct_name, name)));
            }
            let item = structs.get(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
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
                lowered.extend(lower_expr(field_expr, &field.type_ref, scope, lowerer)?);
            }
            if let Some(extra) = provided.keys().next() {
                return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
            }
            Ok(lowered)
        }
        _ => Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
    }
}

pub(super) fn lower_struct_array_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let structs = lowerer.structs;
    match &expr.kind {
        ExprKind::Identifier(name) => {
            let leaves = flatten_type_leaves(expected_type, structs)?;
            Ok(leaves
                .into_iter()
                .map(|leaf| Expr::new(ExprKind::Identifier(flattened_struct_name(name, &leaf.path)), span::Span::default()))
                .collect())
        }
        ExprKind::Array { values, .. } => {
            let element_type = expected_type
                .array_element_type()
                .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;
            let leaf_specs = flatten_type_leaves(&element_type, structs)?;
            let outer_dim = expected_type
                .array_size()
                .cloned()
                .ok_or_else(|| CompilerError::Unsupported(format!("expected array type '{}'", expected_type.type_name())))?;
            let mut grouped: Vec<Vec<Expr<'i>>> = vec![Vec::with_capacity(values.len()); leaf_specs.len()];
            for value in values {
                let lowered = lower_struct_expr(value, &element_type, scope, lowerer)?;
                for (idx, expr) in lowered.into_iter().enumerate() {
                    grouped[idx].push(expr);
                }
            }
            Ok(leaf_specs
                .into_iter()
                .zip(grouped)
                .map(|(mut leaf, entries)| {
                    leaf.type_ref.array_dims.push(outer_dim.clone());
                    Expr::array(leaf.type_ref, entries)
                })
                .collect())
        }
        ExprKind::Append { source, args, .. } => {
            let left = lower_struct_array_expr(source, expected_type, scope, lowerer)?;
            let right = lower_struct_array_expr(&Expr::array(expected_type.clone(), args.clone()), expected_type, scope, lowerer)?;
            Ok(left
                .into_iter()
                .zip(right)
                .map(|(left, right)| {
                    Expr::new(
                        ExprKind::Binary { op: BinaryOp::Add, left: Box::new(left), right: Box::new(right) },
                        span::Span::default(),
                    )
                })
                .collect())
        }
        ExprKind::Split { source, index, part, span } => {
            let sources = lower_struct_array_expr(source, expected_type, scope, lowerer)?;
            let index = lower_scalar_expr(index, scope, lowerer)?;
            Ok(sources
                .into_iter()
                .map(|source| {
                    Expr::new(
                        ExprKind::Split { source: Box::new(source), index: Box::new(index.clone()), part: *part, span: *span },
                        expr.span,
                    )
                })
                .collect())
        }
        ExprKind::Slice { source, start, end, span } => {
            let sources = lower_struct_array_expr(source, expected_type, scope, lowerer)?;
            let start = lower_scalar_expr(start, scope, lowerer)?;
            let end = lower_scalar_expr(end, scope, lowerer)?;
            Ok(sources
                .into_iter()
                .map(|source| {
                    Expr::new(
                        ExprKind::Slice {
                            source: Box::new(source),
                            start: Box::new(start.clone()),
                            end: Box::new(end.clone()),
                            span: *span,
                        },
                        expr.span,
                    )
                })
                .collect())
        }
        _ => Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
    }
}

pub(crate) fn flatten_runtime_return_exprs<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let mut flattened = Vec::new();
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        flattened.extend(lower_expr(expr, return_type, scope, lowerer)?);
    }
    Ok(flattened)
}

pub(super) fn flatten_named_type(
    name: &str,
    type_ref: &TypeRef,
    structs: &StructRegistry,
) -> Result<Vec<(String, TypeRef)>, CompilerError> {
    if is_struct_like(type_ref, structs) {
        Ok(flatten_type_leaves(type_ref, structs)?
            .into_iter()
            .map(|leaf| (flattened_struct_name(name, &leaf.path), leaf.type_ref))
            .collect())
    } else {
        Ok(vec![(name.to_string(), type_ref.clone())])
    }
}

pub(super) fn lower_named_expr<'i>(
    name: &str,
    type_ref: &TypeRef,
    expr: &Expr<'i>,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<(String, TypeRef, Expr<'i>)>, CompilerError> {
    let names_and_types = flatten_named_type(name, type_ref, lowerer.structs)?;
    let lowered = lower_expr(expr, type_ref, scope, lowerer)?;
    if names_and_types.len() != lowered.len() {
        return Err(CompilerError::Unsupported("internal error: flattened expression does not match its type layout".to_string()));
    }
    Ok(names_and_types.into_iter().zip(lowered).map(|((name, type_ref), expr)| (name, type_ref, expr)).collect())
}

pub(super) fn lower_call_args<'i>(
    name: &str,
    args: &[Expr<'i>],
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let Some(function) = lowerer.functions.get(name) else {
        return args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect();
    };

    let mut lowered = Vec::new();
    for (arg, param) in args.iter().zip(function.params.iter()) {
        lowered.extend(lower_expr(arg, &param.type_ref, scope, lowerer)?);
    }
    Ok(lowered)
}

pub(super) fn lower_function_call_bindings<'i>(
    bindings: &[ParamAst<'i>],
    callee_return_types: &[TypeRef],
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<ParamAst<'i>>, CompilerError> {
    let mut lowered = Vec::new();
    for (binding, return_type) in bindings.iter().zip(callee_return_types.iter()) {
        for (name, type_ref) in flatten_named_type(&binding.name, return_type, lowerer.structs)? {
            lowered.push(ParamAst { type_ref, name, span: binding.span, type_span: binding.type_span, name_span: binding.name_span });
        }
    }
    Ok(lowered)
}
