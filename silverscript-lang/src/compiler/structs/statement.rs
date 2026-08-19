use super::*;

pub(super) fn lower_statements<'i>(
    statements: &[Statement<'i>],
    scope: &mut LoweringScope,
    return_types: &[TypeRef],
    lowerer: &StructLowerer<'_, 'i>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let functions = lowerer.functions;
    let mut lowered = Vec::new();
    for stmt in statements {
        match stmt {
            Statement::Block { body, span } => {
                let mut block_scope = scope.child();
                let lowered_body = lower_statements(body, &mut block_scope, return_types, lowerer)?;
                lowered.push(Statement::Block { body: lowered_body, span: *span });
            }
            Statement::VariableDefinition { .. } => lowered.extend(lower_variable_definition(stmt, scope, lowerer)?),
            Statement::TupleAssignment {
                left_type_ref,
                left_name,
                right_type_ref,
                right_name,
                expr,
                span,
                left_type_span,
                left_name_span,
                right_type_span,
                right_name_span,
            } => {
                scope.declare(left_name.clone(), left_type_ref.clone());
                scope.declare(right_name.clone(), right_type_ref.clone());
                lowered.push(Statement::TupleAssignment {
                    left_type_ref: left_type_ref.clone(),
                    left_name: left_name.clone(),
                    right_type_ref: right_type_ref.clone(),
                    right_name: right_name.clone(),
                    expr: lower_scalar_expr(expr, scope, lowerer)?,
                    span: *span,
                    left_type_span: *left_type_span,
                    left_name_span: *left_name_span,
                    right_type_span: *right_type_span,
                    right_name_span: *right_name_span,
                });
            }
            Statement::FunctionCall { name, args, span, name_span } => {
                lowered.push(Statement::FunctionCall {
                    name: name.clone(),
                    args: lower_call_args(name, args, scope, lowerer)?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
                let lowered_bindings = if let Some(function) = functions.get(name) {
                    lower_function_call_bindings(bindings, &function.return_types, lowerer)?
                } else {
                    bindings.clone()
                };
                for binding in bindings {
                    scope.declare(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::FunctionCallAssign {
                    bindings: lowered_bindings,
                    name: name.clone(),
                    args: lower_call_args(name, args, scope, lowerer)?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StateFunctionCallAssign { target_struct, bindings, name, args, span, name_span } => {
                for binding in bindings {
                    scope.declare(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::StateFunctionCallAssign {
                    target_struct: target_struct.clone(),
                    bindings: bindings.clone(),
                    name: name.clone(),
                    args: args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect::<Result<Vec<_>, _>>()?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StructDestructure { struct_name, bindings, expr, span } => {
                for binding in bindings {
                    scope.declare(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.extend(lower_struct_destructure_statement(struct_name, bindings, expr, *span, scope, lowerer)?);
            }
            Statement::Assign { .. } => lowered.extend(lower_assignment(stmt, scope, lowerer)?),
            Statement::RequireAgeDaa { expr, message, span, target_span, message_span } => lowered.push(Statement::RequireAgeDaa {
                expr: lower_scalar_expr(expr, scope, lowerer)?,
                message: message.clone(),
                span: *span,
                target_span: *target_span,
                message_span: *message_span,
            }),
            Statement::RequireTxDaa { expr, message, span, target_span, message_span } => lowered.push(Statement::RequireTxDaa {
                expr: lower_scalar_expr(expr, scope, lowerer)?,
                message: message.clone(),
                span: *span,
                target_span: *target_span,
                message_span: *message_span,
            }),
            Statement::RequireTxTime { expr, message, span, target_span, message_span } => lowered.push(Statement::RequireTxTime {
                expr: lower_scalar_expr(expr, scope, lowerer)?,
                message: message.clone(),
                span: *span,
                target_span: *target_span,
                message_span: *message_span,
            }),
            Statement::Require { expr, message, span, message_span } => lowered.push(Statement::Require {
                expr: lower_scalar_expr(expr, scope, lowerer)?,
                message: message.clone(),
                span: *span,
                message_span: *message_span,
            }),
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
                let mut then_scope = scope.child();
                let lowered_then = lower_statements(then_branch, &mut then_scope, return_types, lowerer)?;
                let lowered_else = if let Some(else_branch) = else_branch {
                    let mut else_scope = scope.child();
                    let lowered_else = lower_statements(else_branch, &mut else_scope, return_types, lowerer)?;
                    Some(lowered_else)
                } else {
                    None
                };
                lowered.push(Statement::If {
                    condition: lower_scalar_expr(condition, scope, lowerer)?,
                    then_branch: lowered_then,
                    else_branch: lowered_else,
                    span: *span,
                    then_span: *then_span,
                    else_span: *else_span,
                });
            }
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                let mut body_scope = scope.child();
                body_scope.declare(ident.clone(), TypeRef { base: TypeBase::Int, array_dims: Vec::new() });
                let lowered_body = lower_statements(body, &mut body_scope, return_types, lowerer)?;
                lowered.push(Statement::For {
                    ident: ident.clone(),
                    start: lower_scalar_expr(start, scope, lowerer)?,
                    end: lower_scalar_expr(end, scope, lowerer)?,
                    max_iterations: lower_scalar_expr(max_iterations, scope, lowerer)?,
                    body: lowered_body,
                    span: *span,
                    ident_span: *ident_span,
                    body_span: *body_span,
                });
            }
            Statement::Return { exprs, span } => lowered
                .push(Statement::Return { exprs: flatten_runtime_return_exprs(exprs, return_types, scope, lowerer)?, span: *span }),
            Statement::Console { args, span } => lowered.push(Statement::Console {
                args: args.iter().map(|arg| lower_scalar_expr(arg, scope, lowerer)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
            }),
        }
    }
    Ok(lowered)
}
