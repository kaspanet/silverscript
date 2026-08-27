use super::*;

/// Resolves a struct field-access chain into the base variable, accessed field path,
/// and final type. For example, `box.top_left.x` resolves to `("box",
/// ["top_left", "x"], int)`, which callers can then lower to a flattened name.
pub(crate) fn resolve_struct_access<'i>(
    expr: &Expr<'i>,
    scope: &LoweringScope,
    structs: &StructRegistry,
) -> Result<(String, Vec<String>, TypeRef), CompilerError> {
    match &expr.kind {
        ExprKind::Identifier(name) => {
            let type_ref = scope.type_of(name).cloned().ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?;
            Ok((name.clone(), Vec::new(), type_ref))
        }
        ExprKind::FieldAccess { source, field, .. } => {
            let (base, mut path, current_type) = resolve_struct_access(source, scope, structs)?;
            let struct_name = struct_name(&current_type, structs)
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

pub(super) fn lower_scalar_expr<'i>(
    expr: &Expr<'i>,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Expr<'i>, CompilerError> {
    let structs = lowerer.structs;
    let span = expr.span;
    match &expr.kind {
        ExprKind::FieldAccess { source, field, .. } => {
            if let ExprKind::ArrayIndex { source: array_source, index } = &source.as_ref().kind {
                let (base, mut path, array_type) = resolve_struct_access(array_source, scope, structs)?;
                let struct_name = struct_array_name(&array_type, structs)
                    .ok_or_else(|| CompilerError::Unsupported("field access requires a struct value".to_string()))?;
                let item =
                    structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
                let field_type = item
                    .fields
                    .iter()
                    .find(|candidate| candidate.name == *field)
                    .map(|candidate| candidate.type_ref.clone())
                    .ok_or_else(|| CompilerError::Unsupported(format!("struct '{}' has no field '{}'", struct_name, field)))?;
                if is_struct_like(&field_type, structs) {
                    return Err(CompilerError::Unsupported("nested struct array field access is not supported".to_string()));
                }
                path.push(field.clone());
                return Ok(Expr::new(
                    ExprKind::ArrayIndex {
                        source: Box::new(Expr::identifier(flattened_struct_name(&base, &path))),
                        index: Box::new(lower_scalar_expr(index, scope, lowerer)?),
                    },
                    span,
                ));
            }

            let (base, path, type_ref) = resolve_struct_access(expr, scope, structs)?;
            if is_struct(&type_ref, structs) {
                return Err(CompilerError::Unsupported("struct value must be used in a struct-typed position".to_string()));
            }
            Ok(Expr::new(ExprKind::Identifier(flattened_struct_name(&base, &path)), span))
        }
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op: *op, expr: Box::new(lower_scalar_expr(expr, scope, lowerer)?) }, span))
        }
        ExprKind::Binary { op, left, right } => {
            if matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
                let left_type = scalar_struct_expr_type(left, scope, structs);
                let right_type = scalar_struct_expr_type(right, scope, structs);
                if let Some(expected_type) = left_type.as_ref().or(right_type.as_ref()) {
                    if let Some((left, right)) = left_type.as_ref().zip(right_type.as_ref()) {
                        if !type_refs_equal(left, right, lowerer.contract_constants)? {
                            return Err(CompilerError::Unsupported("struct comparison requires matching types".to_string()));
                        }
                    }
                    let left_leaves = lower_struct_expr(left, expected_type, scope, lowerer)?;
                    let right_leaves = lower_struct_expr(right, expected_type, scope, lowerer)?;
                    let comparison_op = *op;
                    let combination_op = if *op == BinaryOp::Eq { BinaryOp::And } else { BinaryOp::Or };
                    let comparisons = left_leaves.into_iter().zip(right_leaves).map(|(left, right)| {
                        Expr::new(ExprKind::Binary { op: comparison_op, left: Box::new(left), right: Box::new(right) }, span)
                    });
                    return comparisons
                        .reduce(|left, right| {
                            Expr::new(ExprKind::Binary { op: combination_op, left: Box::new(left), right: Box::new(right) }, span)
                        })
                        .ok_or_else(|| CompilerError::Unsupported("cannot compare empty structs".to_string()));
                }
            }

            Ok(Expr::new(
                ExprKind::Binary {
                    op: *op,
                    left: Box::new(lower_scalar_expr(left, scope, lowerer)?),
                    right: Box::new(lower_scalar_expr(right, scope, lowerer)?),
                },
                span,
            ))
        }
        ExprKind::Append { source, args, span: append_span } => Ok(Expr::new(
            ExprKind::Append {
                source: Box::new(lower_scalar_expr(source, scope, lowerer)?),
                args: args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect::<Result<Vec<_>, _>>()?,
                span: *append_span,
            },
            span,
        )),
        ExprKind::Ternary { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::Ternary {
                condition: Box::new(lower_scalar_expr(condition, scope, lowerer)?),
                then_expr: Box::new(lower_scalar_expr(then_expr, scope, lowerer)?),
                else_expr: Box::new(lower_scalar_expr(else_expr, scope, lowerer)?),
            },
            span,
        )),
        ExprKind::Array { type_ref, values } => Ok(Expr::new(
            ExprKind::Array {
                type_ref: type_ref.clone(),
                values: values.iter().map(|value| lower_scalar_expr(value, scope, lowerer)).collect::<Result<Vec<_>, _>>()?,
            },
            span,
        )),
        ExprKind::StructLiteral { .. } => {
            Err(CompilerError::Unsupported("struct literals are only supported in struct-typed positions".to_string()))
        }
        ExprKind::Call { name, args, name_span } => {
            let lowered_args = args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect::<Result<Vec<_>, _>>()?;
            Ok(Expr::new(ExprKind::Call { name: name.clone(), args: lowered_args, name_span: *name_span }, span))
        }
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(lower_scalar_expr(source, scope, lowerer)?),
                index: Box::new(lower_scalar_expr(index, scope, lowerer)?),
                part: *part,
                span: *split_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(lower_scalar_expr(source, scope, lowerer)?),
                start: Box::new(lower_scalar_expr(start, scope, lowerer)?),
                end: Box::new(lower_scalar_expr(end, scope, lowerer)?),
                span: *slice_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(lower_scalar_expr(source, scope, lowerer)?),
                index: Box::new(lower_scalar_expr(index, scope, lowerer)?),
            },
            span,
        )),
        ExprKind::IndexedIntrospection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::IndexedIntrospection {
                kind: *kind,
                index: Box::new(lower_scalar_expr(index, scope, lowerer)?),
                field_span: *field_span,
            },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
            if matches!(kind, crate::ast::UnarySuffixKind::Length)
                && let Some(type_ref) = struct_array_expr_type(source, scope, structs, lowerer.contract_constants)?
            {
                let first_leaf = lower_struct_array_expr(source, &type_ref, scope, lowerer)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| CompilerError::Unsupported("struct array must contain fields".to_string()))?;
                return Ok(Expr::new(ExprKind::UnarySuffix { source: Box::new(first_leaf), kind: *kind, span: *suffix_span }, span));
            }
            Ok(Expr::new(
                ExprKind::UnarySuffix {
                    source: Box::new(lower_scalar_expr(source, scope, lowerer)?),
                    kind: *kind,
                    span: *suffix_span,
                },
                span,
            ))
        }
        _ => Ok(expr.clone()),
    }
}

fn scalar_struct_expr_type(expr: &Expr<'_>, scope: &LoweringScope, structs: &StructRegistry) -> Option<TypeRef> {
    let type_ref = match &expr.kind {
        ExprKind::Identifier(name) => scope.type_of(name).cloned(),
        ExprKind::StructLiteral { name, .. } => Some(TypeRef { base: TypeBase::Custom(name.clone()), array_dims: Vec::new() }),
        ExprKind::FieldAccess { .. } => resolve_struct_access(expr, scope, structs).ok().map(|(_, _, type_ref)| type_ref),
        // TODO: Support indexing any struct-array expression, not only an identifier.
        ExprKind::ArrayIndex { source, .. } => match &source.kind {
            ExprKind::Identifier(name) => scope.type_of(name).and_then(TypeRef::array_element_type),
            _ => None,
        },
        _ => None,
    };
    type_ref.filter(|type_ref| is_struct(type_ref, structs))
}

fn struct_array_expr_type(
    expr: &Expr<'_>,
    scope: &LoweringScope,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'_>>,
) -> Result<Option<TypeRef>, CompilerError> {
    let type_ref = match &expr.kind {
        ExprKind::Identifier(name) => scope.type_of(name).cloned(),
        ExprKind::Array { type_ref, .. } => Some(type_ref.clone()),
        ExprKind::Append { source, args, .. } => {
            let Some(source_type) = struct_array_expr_type(source, scope, structs, constants)? else { return Ok(None) };
            append_type(&source_type, args.len(), constants)?
        }
        ExprKind::Split { source, index, part, .. } => struct_array_expr_type(source, scope, structs, constants)?
            .map(|source_type| crate::compiler::type_check::split_part_type(&source_type, index, *part, constants))
            .transpose()?,
        ExprKind::Slice { source, .. } => struct_array_expr_type(source, scope, structs, constants)?.and_then(|source_type| {
            let mut element_type = source_type.array_element_type()?;
            element_type.array_dims.push(ArrayDim::Dynamic);
            Some(element_type)
        }),
        _ => None,
    };
    Ok(type_ref.filter(|type_ref| is_struct_array(type_ref, structs)))
}
