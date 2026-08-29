use super::*;

pub(super) fn lower_variable_definition<'i>(
    statement: &Statement<'i>,
    scope: &mut LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } = statement
    else {
        unreachable!("expected variable definition")
    };
    let structs = lowerer.structs;
    scope.declare(name.clone(), type_ref.clone());

    if is_struct_like(type_ref, structs)
        && let Some(Expr { kind: ExprKind::Call { name: builtin_name, args, .. }, .. }) = expr
        && matches!(builtin_name.as_str(), "readInputState" | "readInputStateWithTemplate")
        && let Some(struct_name) = struct_name(type_ref, structs)
        && let Some(item) = structs.get(struct_name)
        && item.fields.iter().all(|field| !is_struct_like(&field.type_ref, structs))
    {
        return Ok(vec![Statement::StateFunctionCallAssign {
            target_struct: struct_name.to_string(),
            bindings: item
                .fields
                .iter()
                .map(|field| StructBindingAst {
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
            args: args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect::<Result<Vec<_>, _>>()?,
            span: *span,
            target_struct_span: *type_span,
            name_span: *name_span,
        }]);
    }

    let values: Vec<(String, TypeRef, Option<Expr<'i>>)> = if let Some(expr) = expr {
        lower_named_expr(name, type_ref, expr, scope, lowerer)?
            .into_iter()
            .map(|(name, type_ref, expr)| (name, type_ref, Some(expr)))
            .collect()
    } else {
        flatten_named_type(name, type_ref, structs)?.into_iter().map(|(name, type_ref)| (name, type_ref, None)).collect()
    };

    Ok(values
        .into_iter()
        .map(|(name, type_ref, expr)| Statement::VariableDefinition {
            type_ref,
            modifiers: modifiers.clone(),
            name,
            expr,
            span: *span,
            type_span: *type_span,
            modifier_spans: modifier_spans.clone(),
            name_span: *name_span,
        })
        .collect())
}
