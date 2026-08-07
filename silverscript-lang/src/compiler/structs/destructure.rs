use super::*;

pub(crate) fn lower_struct_destructure_statement<'i>(
    expected_struct_name: &str,
    bindings: &[StructBindingAst<'i>],
    expr: &Expr<'i>,
    span: crate::span::Span<'i>,
    scope: &mut LoweringScope,
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let structs = lowerer.structs;
    let expr_type = TypeRef { base: TypeBase::Custom(expected_struct_name.to_string()), array_dims: Vec::new() };
    let struct_ast = structs
        .get(expected_struct_name)
        .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{expected_struct_name}'")))?;
    let direct_field_values = if matches!(&expr.kind, ExprKind::Call { name, .. } if name == "readInputState") {
        Some(
            struct_ast
                .fields
                .iter()
                .map(|field| field.name.clone())
                .zip(lower_expr(expr, &expr_type, scope, lowerer)?)
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

        let values = if let Some(field_expr) = direct_field_values.as_ref().and_then(|fields| fields.get(&field.name)) {
            debug_assert!(
                !is_struct_like(&binding.type_ref, structs),
                "type_check must reject nested struct destructuring from readInputState"
            );
            vec![(binding.name.clone(), binding.type_ref.clone(), field_expr.clone())]
        } else {
            let projected_expr = Expr::new(
                ExprKind::FieldAccess { source: Box::new(expr.clone()), field: field.name.clone(), field_span: binding.field_span },
                span,
            );
            lower_named_expr(&binding.name, &binding.type_ref, &projected_expr, scope, lowerer)?
        };

        scope.declare(binding.name.clone(), binding.type_ref.clone());
        lowered.extend(values.into_iter().map(|(name, type_ref, expr)| Statement::VariableDefinition {
            type_ref,
            modifiers: Vec::new(),
            name,
            expr: Some(expr),
            span: binding.span,
            type_span: binding.type_span,
            modifier_spans: Vec::new(),
            name_span: binding.name_span,
        }));
    }

    debug_assert!(binding_map.is_empty(), "type_check must validate exact struct destructuring coverage");
    Ok(lowered)
}
