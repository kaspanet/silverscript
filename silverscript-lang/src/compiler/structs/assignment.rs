use super::*;

pub(super) fn lower_assignment<'i>(
    statement: &Statement<'i>,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let Statement::Assign { name, expr, span, name_span } = statement else { unreachable!("expected assignment") };
    let Some(type_ref) = scope.type_of(name).cloned() else {
        return Ok(vec![Statement::Assign {
            name: name.clone(),
            expr: lower_scalar_expr(expr, scope, lowerer)?,
            span: *span,
            name_span: *name_span,
        }]);
    };

    if is_struct_array(&type_ref, lowerer.structs)
        && let ExprKind::Append { source, args, .. } = &expr.kind
        && matches!(&source.kind, ExprKind::Identifier(source_name) if source_name == name)
    {
        return lower_struct_array_append(name, &type_ref, args, *span, *name_span, scope, lowerer);
    }

    Ok(lower_named_expr(name, &type_ref, expr, scope, lowerer)?
        .into_iter()
        .map(|(name, _, expr)| Statement::Assign { name, expr, span: *span, name_span: *name_span })
        .collect())
}

fn lower_struct_array_append<'i>(
    name: &str,
    array_type: &TypeRef,
    args: &[Expr<'i>],
    statement_span: span::Span<'i>,
    name_span: span::Span<'i>,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let element_type =
        array_type.array_element_type().ok_or_else(|| CompilerError::Unsupported("array element type not supported".to_string()))?;
    let leaves = flatten_type_leaves(&element_type, lowerer.structs)?;
    let mut args_by_leaf = vec![Vec::with_capacity(args.len()); leaves.len()];

    for arg in args {
        let lowered_arg = lower_expr(arg, &element_type, scope, lowerer)?;
        if lowered_arg.len() != leaves.len() {
            return Err(CompilerError::Unsupported("internal error: flattened struct value does not match its type".to_string()));
        }
        for (leaf_args, leaf_expr) in args_by_leaf.iter_mut().zip(lowered_arg) {
            leaf_args.push(leaf_expr);
        }
    }

    leaves
        .into_iter()
        .zip(args_by_leaf)
        .map(|(leaf, args)| {
            let leaf_name = flattened_struct_name(name, &leaf.path);
            Ok(Statement::Assign {
                name: leaf_name.clone(),
                expr: Expr::new(
                    ExprKind::Append { source: Box::new(Expr::identifier(&leaf_name)), args, span: span::Span::default() },
                    statement_span,
                ),
                span: statement_span,
                name_span,
            })
        })
        .collect()
}
