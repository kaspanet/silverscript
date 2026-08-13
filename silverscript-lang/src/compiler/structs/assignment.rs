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
        let lowered = lower_struct_array_append(name, &type_ref, args, *span, scope, lowerer)?;
        return Ok(lower_atomic_reassignment(lowered, *span, *name_span));
    }

    let lowered = lower_named_expr(name, &type_ref, expr, scope, lowerer)?;
    Ok(lower_atomic_reassignment(lowered, *span, *name_span))
}

fn lower_struct_array_append<'i>(
    name: &str,
    array_type: &TypeRef,
    args: &[Expr<'i>],
    statement_span: span::Span<'i>,
    scope: &LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<(String, TypeRef, Expr<'i>)>, CompilerError> {
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

    let targets = flatten_named_type(name, array_type, lowerer.structs)?;
    if targets.len() != args_by_leaf.len() {
        return Err(CompilerError::Unsupported("internal error: flattened struct array does not match its type".to_string()));
    }

    targets
        .into_iter()
        .zip(args_by_leaf)
        .map(|((leaf_name, leaf_type), args)| {
            let expr = Expr::new(
                ExprKind::Append { source: Box::new(Expr::identifier(&leaf_name)), args, span: span::Span::default() },
                statement_span,
            );
            Ok((leaf_name, leaf_type, expr))
        })
        .collect()
}

fn lower_atomic_reassignment<'i>(
    lowered_assignments: Vec<(String, TypeRef, Expr<'i>)>,
    statement_span: span::Span<'i>,
    name_span: span::Span<'i>,
) -> Vec<Statement<'i>> {
    if lowered_assignments.len() <= 1 {
        return lowered_assignments.into_iter().map(|(name, _, expr)| Statement::Assign { name, expr, span: statement_span, name_span }).collect();
    }

    let mut body = Vec::with_capacity(lowered_assignments.len() * 2);
    let mut rebindings = Vec::with_capacity(lowered_assignments.len());
    for (index, (name, type_ref, expr)) in lowered_assignments.into_iter().enumerate() {
        let temporary = format!("__struct_assignment_{index}");
        body.push(Statement::VariableDefinition {
            type_ref,
            modifiers: Vec::new(),
            name: temporary.clone(),
            expr: Some(expr),
            span: statement_span,
            type_span: span::Span::default(),
            modifier_spans: Vec::new(),
            name_span: span::Span::default(),
        });
        rebindings.push(Statement::Assign { name, expr: Expr::identifier(&temporary), span: statement_span, name_span });
    }
    body.extend(rebindings);

    vec![Statement::Block { body, span: statement_span }]
}
