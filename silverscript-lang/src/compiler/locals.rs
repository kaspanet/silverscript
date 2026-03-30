use std::collections::{HashMap, HashSet};

use crate::ast::{ContractAst, Expr, ExprKind, FunctionAst, Statement, StateFieldExpr, TypeBase, TypeRef};

use super::CompilerError;

pub(super) fn lower_local_aliases<'i>(contract: &ContractAst<'i>) -> Result<ContractAst<'i>, CompilerError> {
    let functions = contract
        .functions
        .iter()
        .map(lower_function_local_aliases)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst { functions, ..contract.clone() })
}

fn lower_function_local_aliases<'i>(function: &FunctionAst<'i>) -> Result<FunctionAst<'i>, CompilerError> {
    let assigned_names = collect_assigned_names(&function.body);
    let identifier_uses = collect_identifier_uses(&function.body);
    let body = lower_statements(&function.body, &assigned_names, &identifier_uses, &HashMap::new())?;
    Ok(FunctionAst { body, ..function.clone() })
}

fn lower_statements<'i>(
    statements: &[Statement<'i>],
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    aliases: &HashMap<String, Expr<'i>>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let mut lowered = Vec::with_capacity(statements.len());
    let mut local_aliases = aliases.clone();

    for stmt in statements {
        match stmt {
            Statement::VariableDefinition { type_ref, modifiers, name, expr: Some(expr), span, type_span, modifier_spans, name_span }
                if !assigned_names.contains(name)
                    && identifier_uses.get(name).copied().unwrap_or(0) <= 1
                    && !expr_references_any(expr, assigned_names) =>
            {
                let lowered_expr = coerce_expr_for_declared_scalar_type(substitute_expr(expr, &local_aliases)?, type_ref);
                local_aliases.insert(name.clone(), lowered_expr);
                let _ = (type_ref, modifiers, span, type_span, modifier_spans, name_span);
            }
            Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
                local_aliases.remove(name);
                lowered.push(Statement::VariableDefinition {
                    type_ref: type_ref.clone(),
                    modifiers: modifiers.clone(),
                    name: name.clone(),
                    expr: expr.as_ref().map(|expr| substitute_expr(expr, &local_aliases)).transpose()?,
                    span: *span,
                    type_span: *type_span,
                    modifier_spans: modifier_spans.clone(),
                    name_span: *name_span,
                });
            }
            Statement::TupleAssignment { left_type_ref, left_name, right_type_ref, right_name, expr, span, left_type_span, left_name_span, right_type_span, right_name_span } => {
                local_aliases.remove(left_name);
                local_aliases.remove(right_name);
                lowered.push(Statement::TupleAssignment {
                    left_type_ref: left_type_ref.clone(),
                    left_name: left_name.clone(),
                    right_type_ref: right_type_ref.clone(),
                    right_name: right_name.clone(),
                    expr: substitute_expr(expr, &local_aliases)?,
                    span: *span,
                    left_type_span: *left_type_span,
                    left_name_span: *left_name_span,
                    right_type_span: *right_type_span,
                    right_name_span: *right_name_span,
                });
            }
            Statement::ArrayPush { name, expr, span, name_span } => {
                local_aliases.remove(name);
                lowered.push(Statement::ArrayPush {
                    name: name.clone(),
                    expr: substitute_expr(expr, &local_aliases)?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::FunctionCall { name, args, span, name_span } => lowered.push(Statement::FunctionCall {
                name: name.clone(),
                args: args.iter().map(|arg| substitute_expr(arg, &local_aliases)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
                name_span: *name_span,
            }),
            Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
                for binding in bindings {
                    local_aliases.remove(&binding.name);
                }
                lowered.push(Statement::FunctionCallAssign {
                    bindings: bindings.clone(),
                    name: name.clone(),
                    args: args.iter().map(|arg| substitute_expr(arg, &local_aliases)).collect::<Result<Vec<_>, _>>()?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => {
                for binding in bindings {
                    local_aliases.remove(&binding.name);
                }
                lowered.push(Statement::StateFunctionCallAssign {
                    bindings: bindings.clone(),
                    name: name.clone(),
                    args: args.iter().map(|arg| substitute_expr(arg, &local_aliases)).collect::<Result<Vec<_>, _>>()?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StructDestructure { bindings, expr, span } => {
                for binding in bindings {
                    local_aliases.remove(&binding.name);
                }
                lowered.push(Statement::StructDestructure { bindings: bindings.clone(), expr: substitute_expr(expr, &local_aliases)?, span: *span });
            }
            Statement::Assign { name, expr, span, name_span } => {
                local_aliases.remove(name);
                lowered.push(Statement::Assign {
                    name: name.clone(),
                    expr: substitute_expr(expr, &local_aliases)?,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => lowered.push(Statement::TimeOp {
                tx_var: *tx_var,
                expr: substitute_expr(expr, &local_aliases)?,
                message: message.clone(),
                span: *span,
                tx_var_span: *tx_var_span,
                message_span: *message_span,
            }),
            Statement::Require { expr, message, span, message_span } => lowered.push(Statement::Require {
                expr: substitute_expr(expr, &local_aliases)?,
                message: message.clone(),
                span: *span,
                message_span: *message_span,
            }),
            Statement::Block { body, span } => lowered.push(Statement::Block {
                body: lower_statements(body, assigned_names, identifier_uses, &local_aliases)?,
                span: *span,
            }),
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => lowered.push(Statement::If {
                condition: substitute_expr(condition, &local_aliases)?,
                then_branch: lower_statements(then_branch, assigned_names, identifier_uses, &local_aliases)?,
                else_branch: else_branch
                    .as_ref()
                    .map(|branch| lower_statements(branch, assigned_names, identifier_uses, &local_aliases))
                    .transpose()?,
                span: *span,
                then_span: *then_span,
                else_span: *else_span,
            }),
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                local_aliases.remove(ident);
                lowered.push(Statement::For {
                    ident: ident.clone(),
                    start: substitute_expr(start, &local_aliases)?,
                    end: substitute_expr(end, &local_aliases)?,
                    max_iterations: substitute_expr(max_iterations, &local_aliases)?,
                    body: lower_statements(body, assigned_names, identifier_uses, &local_aliases)?,
                    span: *span,
                    ident_span: *ident_span,
                    body_span: *body_span,
                });
            }
            Statement::Return { exprs, span } => lowered.push(Statement::Return {
                exprs: exprs.iter().map(|expr| substitute_expr(expr, &local_aliases)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
            }),
            Statement::Console { args, span } => lowered.push(Statement::Console {
                args: args.iter().map(|arg| substitute_expr(arg, &local_aliases)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
            }),
        }
    }

    Ok(lowered)
}

fn coerce_expr_for_declared_scalar_type<'i>(expr: Expr<'i>, type_ref: &TypeRef) -> Expr<'i> {
    if matches!(type_ref.base, TypeBase::Byte)
        && type_ref.array_dims.is_empty()
        && let ExprKind::Int(value) = expr.kind
        && (0..=255).contains(&value)
    {
        return Expr::new(ExprKind::Byte(value as u8), expr.span);
    }
    expr
}

fn substitute_expr<'i>(expr: &Expr<'i>, aliases: &HashMap<String, Expr<'i>>) -> Result<Expr<'i>, CompilerError> {
    let Expr { kind, span } = expr.clone();
    Ok(match kind {
        ExprKind::Identifier(name) => aliases.get(&name).cloned().unwrap_or_else(|| Expr::new(ExprKind::Identifier(name), span)),
        ExprKind::Unary { op, expr } => Expr::new(ExprKind::Unary { op, expr: Box::new(substitute_expr(&expr, aliases)?) }, span),
        ExprKind::Binary { op, left, right } => Expr::new(
            ExprKind::Binary {
                op,
                left: Box::new(substitute_expr(&left, aliases)?),
                right: Box::new(substitute_expr(&right, aliases)?),
            },
            span,
        ),
        ExprKind::IfElse { condition, then_expr, else_expr } => Expr::new(
            ExprKind::IfElse {
                condition: Box::new(substitute_expr(&condition, aliases)?),
                then_expr: Box::new(substitute_expr(&then_expr, aliases)?),
                else_expr: Box::new(substitute_expr(&else_expr, aliases)?),
            },
            span,
        ),
        ExprKind::Array(values) => {
            Expr::new(ExprKind::Array(values.iter().map(|value| substitute_expr(value, aliases)).collect::<Result<Vec<_>, _>>()?), span)
        }
        ExprKind::StateObject(fields) => Expr::new(
            ExprKind::StateObject(
                fields
                    .into_iter()
                    .map(|field| {
                        Ok(StateFieldExpr {
                            name: field.name,
                            expr: substitute_expr(&field.expr, aliases)?,
                            span: field.span,
                            name_span: field.name_span,
                        })
                    })
                    .collect::<Result<Vec<_>, CompilerError>>()?,
            ),
            span,
        ),
        ExprKind::FieldAccess { source, field, field_span } => Expr::new(
            ExprKind::FieldAccess { source: Box::new(substitute_expr(&source, aliases)?), field, field_span },
            span,
        ),
        ExprKind::Call { name, args, name_span } => Expr::new(
            ExprKind::Call {
                name,
                args: args.iter().map(|arg| substitute_expr(arg, aliases)).collect::<Result<Vec<_>, _>>()?,
                name_span,
            },
            span,
        ),
        ExprKind::New { name, args, name_span } => Expr::new(
            ExprKind::New {
                name,
                args: args.iter().map(|arg| substitute_expr(arg, aliases)).collect::<Result<Vec<_>, _>>()?,
                name_span,
            },
            span,
        ),
        ExprKind::Split { source, index, part, span: split_span } => Expr::new(
            ExprKind::Split {
                source: Box::new(substitute_expr(&source, aliases)?),
                index: Box::new(substitute_expr(&index, aliases)?),
                part,
                span: split_span,
            },
            span,
        ),
        ExprKind::ArrayIndex { source, index } => Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(substitute_expr(&source, aliases)?),
                index: Box::new(substitute_expr(&index, aliases)?),
            },
            span,
        ),
        ExprKind::Introspection { kind, index, field_span } => {
            Expr::new(ExprKind::Introspection { kind, index: Box::new(substitute_expr(&index, aliases)?), field_span }, span)
        }
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Expr::new(
            ExprKind::UnarySuffix { source: Box::new(substitute_expr(&source, aliases)?), kind, span: suffix_span },
            span,
        ),
        ExprKind::Slice { source, start, end, span: slice_span } => Expr::new(
            ExprKind::Slice {
                source: Box::new(substitute_expr(&source, aliases)?),
                start: Box::new(substitute_expr(&start, aliases)?),
                end: Box::new(substitute_expr(&end, aliases)?),
                span: slice_span,
            },
            span,
        ),
        other => Expr::new(other, span),
    })
}

fn collect_assigned_names<'i>(statements: &[Statement<'i>]) -> HashSet<String> {
    let mut assigned = HashSet::new();
    collect_assigned_names_into(statements, &mut assigned);
    assigned
}

fn collect_identifier_uses<'i>(statements: &[Statement<'i>]) -> HashMap<String, usize> {
    let mut uses = HashMap::new();
    for stmt in statements {
        collect_statement_identifier_uses(stmt, &mut uses);
    }
    uses
}

fn bump_identifier_use(uses: &mut HashMap<String, usize>, name: &str) {
    *uses.entry(name.to_string()).or_insert(0) += 1;
}

fn collect_statement_identifier_uses<'i>(stmt: &Statement<'i>, uses: &mut HashMap<String, usize>) {
    match stmt {
        Statement::VariableDefinition { expr, .. } => {
            if let Some(expr) = expr {
                collect_expr_identifier_uses(expr, uses);
            }
        }
        Statement::TupleAssignment { expr, .. }
        | Statement::Assign { expr, .. }
        | Statement::TimeOp { expr, .. }
        | Statement::Require { expr, .. }
        | Statement::StructDestructure { expr, .. } => collect_expr_identifier_uses(expr, uses),
        Statement::Block { body, .. } => {
            for stmt in body {
                collect_statement_identifier_uses(stmt, uses);
            }
        }
        Statement::ArrayPush { expr, .. } => collect_expr_identifier_uses(expr, uses),
        Statement::FunctionCall { args, .. }
        | Statement::FunctionCallAssign { args, .. }
        | Statement::StateFunctionCallAssign { args, .. } => {
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
        }
        Statement::If { condition, then_branch, else_branch, .. } => {
            collect_expr_identifier_uses(condition, uses);
            for stmt in then_branch {
                collect_statement_identifier_uses(stmt, uses);
            }
            if let Some(else_branch) = else_branch {
                for stmt in else_branch {
                    collect_statement_identifier_uses(stmt, uses);
                }
            }
        }
        Statement::For { start, end, max_iterations, body, .. } => {
            collect_expr_identifier_uses(start, uses);
            collect_expr_identifier_uses(end, uses);
            collect_expr_identifier_uses(max_iterations, uses);
            for stmt in body {
                collect_statement_identifier_uses(stmt, uses);
            }
        }
        Statement::Return { exprs, .. } => {
            for expr in exprs {
                collect_expr_identifier_uses(expr, uses);
            }
        }
        Statement::Console { args, .. } => {
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
        }
    }
}

fn collect_expr_identifier_uses<'i>(expr: &Expr<'i>, uses: &mut HashMap<String, usize>) {
    match &expr.kind {
        ExprKind::Identifier(name) => bump_identifier_use(uses, name),
        ExprKind::Unary { expr, .. } => collect_expr_identifier_uses(expr, uses),
        ExprKind::Binary { left, right, .. } => {
            collect_expr_identifier_uses(left, uses);
            collect_expr_identifier_uses(right, uses);
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            collect_expr_identifier_uses(condition, uses);
            collect_expr_identifier_uses(then_expr, uses);
            collect_expr_identifier_uses(else_expr, uses);
        }
        ExprKind::Array(values) => {
            for value in values {
                collect_expr_identifier_uses(value, uses);
            }
        }
        ExprKind::StateObject(fields) => {
            for field in fields {
                collect_expr_identifier_uses(&field.expr, uses);
            }
        }
        ExprKind::Call { args, .. } | ExprKind::New { args, .. } => {
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
        }
        ExprKind::Split { source, index, .. } | ExprKind::ArrayIndex { source, index } => {
            collect_expr_identifier_uses(source, uses);
            collect_expr_identifier_uses(index, uses);
        }
        ExprKind::Slice { source, start, end, .. } => {
            collect_expr_identifier_uses(source, uses);
            collect_expr_identifier_uses(start, uses);
            collect_expr_identifier_uses(end, uses);
        }
        ExprKind::Introspection { index, .. } => collect_expr_identifier_uses(index, uses),
        ExprKind::UnarySuffix { source, .. } | ExprKind::FieldAccess { source, .. } => collect_expr_identifier_uses(source, uses),
        ExprKind::Int(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::Nullary(_)
        | ExprKind::NumberWithUnit { .. } => {}
    }
}

fn expr_references_any(expr: &Expr<'_>, names: &HashSet<String>) -> bool {
    match &expr.kind {
        ExprKind::Identifier(name) => names.contains(name),
        ExprKind::Unary { expr, .. } => expr_references_any(expr, names),
        ExprKind::Binary { left, right, .. } => expr_references_any(left, names) || expr_references_any(right, names),
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            expr_references_any(condition, names) || expr_references_any(then_expr, names) || expr_references_any(else_expr, names)
        }
        ExprKind::Array(values) => values.iter().any(|value| expr_references_any(value, names)),
        ExprKind::StateObject(fields) => fields.iter().any(|field| expr_references_any(&field.expr, names)),
        ExprKind::Call { args, .. } | ExprKind::New { args, .. } => args.iter().any(|arg| expr_references_any(arg, names)),
        ExprKind::Split { source, index, .. } | ExprKind::ArrayIndex { source, index } => {
            expr_references_any(source, names) || expr_references_any(index, names)
        }
        ExprKind::Slice { source, start, end, .. } => {
            expr_references_any(source, names) || expr_references_any(start, names) || expr_references_any(end, names)
        }
        ExprKind::Introspection { index, .. } => expr_references_any(index, names),
        ExprKind::UnarySuffix { source, .. } | ExprKind::FieldAccess { source, .. } => expr_references_any(source, names),
        ExprKind::Int(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::Nullary(_)
        | ExprKind::NumberWithUnit { .. } => false,
    }
}

fn collect_assigned_names_into<'i>(statements: &[Statement<'i>], assigned: &mut HashSet<String>) {
    for stmt in statements {
        match stmt {
            Statement::Assign { name, .. } | Statement::ArrayPush { name, .. } => {
                assigned.insert(name.clone());
            }
            Statement::Block { body, .. } => collect_assigned_names_into(body, assigned),
            Statement::If { then_branch, else_branch, .. } => {
                collect_assigned_names_into(then_branch, assigned);
                if let Some(else_branch) = else_branch {
                    collect_assigned_names_into(else_branch, assigned);
                }
            }
            Statement::For { ident, body, .. } => {
                assigned.insert(ident.clone());
                collect_assigned_names_into(body, assigned);
            }
            _ => {}
        }
    }
}
