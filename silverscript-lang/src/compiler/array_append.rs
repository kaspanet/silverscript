use super::*;
use crate::ast::{ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, StateFieldExpr, Statement};
use crate::span;

pub(super) fn lower_array_appends<'i>(contract: &ContractAst<'i>) -> Result<ContractAst<'i>, CompilerError> {
    let fields = contract.fields.iter().map(lower_contract_field).collect::<Result<Vec<_>, _>>()?;
    let constants = contract.constants.iter().map(lower_constant).collect::<Result<Vec<_>, _>>()?;
    let functions = contract.functions.iter().map(lower_function).collect::<Result<Vec<_>, _>>()?;
    Ok(ContractAst { fields, constants, functions, ..contract.clone() })
}

fn lower_contract_field<'i>(field: &ContractFieldAst<'i>) -> Result<ContractFieldAst<'i>, CompilerError> {
    Ok(ContractFieldAst { expr: lower_expr(&field.expr)?, ..field.clone() })
}

fn lower_constant<'i>(constant: &ConstantAst<'i>) -> Result<ConstantAst<'i>, CompilerError> {
    Ok(ConstantAst { expr: lower_expr(&constant.expr)?, ..constant.clone() })
}

fn lower_function<'i>(function: &FunctionAst<'i>) -> Result<FunctionAst<'i>, CompilerError> {
    Ok(FunctionAst { body: lower_block(&function.body)?, ..function.clone() })
}

fn lower_block<'i>(statements: &[Statement<'i>]) -> Result<Vec<Statement<'i>>, CompilerError> {
    statements.iter().map(lower_statement).collect()
}

fn lower_statement<'i>(statement: &Statement<'i>) -> Result<Statement<'i>, CompilerError> {
    match statement {
        Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
            Ok(Statement::VariableDefinition {
                type_ref: type_ref.clone(),
                modifiers: modifiers.clone(),
                name: name.clone(),
                expr: expr.as_ref().map(lower_expr).transpose()?,
                span: *span,
                type_span: *type_span,
                modifier_spans: modifier_spans.clone(),
                name_span: *name_span,
            })
        }
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
        } => Ok(Statement::TupleAssignment {
            left_type_ref: left_type_ref.clone(),
            left_name: left_name.clone(),
            right_type_ref: right_type_ref.clone(),
            right_name: right_name.clone(),
            expr: lower_expr(expr)?,
            span: *span,
            left_type_span: *left_type_span,
            left_name_span: *left_name_span,
            right_type_span: *right_type_span,
            right_name_span: *right_name_span,
        }),
        Statement::FunctionCall { name, args, span, name_span } => Ok(Statement::FunctionCall {
            name: name.clone(),
            args: args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?,
            span: *span,
            name_span: *name_span,
        }),
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => Ok(Statement::FunctionCallAssign {
            bindings: bindings.clone(),
            name: name.clone(),
            args: args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?,
            span: *span,
            name_span: *name_span,
        }),
        Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => Ok(Statement::StateFunctionCallAssign {
            bindings: bindings.clone(),
            name: name.clone(),
            args: args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?,
            span: *span,
            name_span: *name_span,
        }),
        Statement::StructDestructure { bindings, expr, span } => {
            Ok(Statement::StructDestructure { bindings: bindings.clone(), expr: lower_expr(expr)?, span: *span })
        }
        Statement::Assign { name, expr, span, name_span } => {
            Ok(Statement::Assign { name: name.clone(), expr: lower_expr(expr)?, span: *span, name_span: *name_span })
        }
        Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => Ok(Statement::TimeOp {
            tx_var: *tx_var,
            expr: lower_expr(expr)?,
            message: message.clone(),
            span: *span,
            tx_var_span: *tx_var_span,
            message_span: *message_span,
        }),
        Statement::Require { expr, message, span, message_span } => {
            Ok(Statement::Require { expr: lower_expr(expr)?, message: message.clone(), span: *span, message_span: *message_span })
        }
        Statement::Block { body, span } => Ok(Statement::Block { body: lower_block(body)?, span: *span }),
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => Ok(Statement::If {
            condition: lower_expr(condition)?,
            then_branch: lower_block(then_branch)?,
            else_branch: else_branch.as_ref().map(|branch| lower_block(branch)).transpose()?,
            span: *span,
            then_span: *then_span,
            else_span: *else_span,
        }),
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => Ok(Statement::For {
            ident: ident.clone(),
            start: lower_expr(start)?,
            end: lower_expr(end)?,
            max_iterations: lower_expr(max_iterations)?,
            body: lower_block(body)?,
            span: *span,
            ident_span: *ident_span,
            body_span: *body_span,
        }),
        Statement::Return { exprs, span } => {
            Ok(Statement::Return { exprs: exprs.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?, span: *span })
        }
        Statement::Console { args, span } => {
            Ok(Statement::Console { args: args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?, span: *span })
        }
    }
}

fn lower_expr<'i>(expr: &Expr<'i>) -> Result<Expr<'i>, CompilerError> {
    let span = expr.span;
    match &expr.kind {
        ExprKind::Append { source, args, .. } => Ok(Expr::new(
            ExprKind::Binary {
                op: BinaryOp::Add,
                left: Box::new(lower_expr(source)?),
                right: Box::new(Expr::new(
                    ExprKind::Array(args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?),
                    span::Span::default(),
                )),
            },
            span,
        )),
        ExprKind::Array(values) => Ok(Expr::new(ExprKind::Array(values.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?), span)),
        ExprKind::Call { name, args, name_span } => Ok(Expr::new(
            ExprKind::Call {
                name: name.clone(),
                args: args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(lower_expr).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(lower_expr(source)?),
                index: Box::new(lower_expr(index)?),
                part: *part,
                span: *split_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(lower_expr(source)?),
                start: Box::new(lower_expr(start)?),
                end: Box::new(lower_expr(end)?),
                span: *slice_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => {
            Ok(Expr::new(ExprKind::ArrayIndex { source: Box::new(lower_expr(source)?), index: Box::new(lower_expr(index)?) }, span))
        }
        ExprKind::Unary { op, expr } => Ok(Expr::new(ExprKind::Unary { op: *op, expr: Box::new(lower_expr(expr)?) }, span)),
        ExprKind::Binary { op, left, right } => {
            Ok(Expr::new(ExprKind::Binary { op: *op, left: Box::new(lower_expr(left)?), right: Box::new(lower_expr(right)?) }, span))
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(lower_expr(condition)?),
                then_expr: Box::new(lower_expr(then_expr)?),
                else_expr: Box::new(lower_expr(else_expr)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => {
            Ok(Expr::new(ExprKind::Introspection { kind: *kind, index: Box::new(lower_expr(index)?), field_span: *field_span }, span))
        }
        ExprKind::StateObject(fields) => Ok(Expr::new(
            ExprKind::StateObject(
                fields
                    .iter()
                    .map(|field| {
                        Ok(StateFieldExpr {
                            name: field.name.clone(),
                            expr: lower_expr(&field.expr)?,
                            span: field.span,
                            name_span: field.name_span,
                        })
                    })
                    .collect::<Result<Vec<_>, CompilerError>>()?,
            ),
            span,
        )),
        ExprKind::FieldAccess { source, field, field_span } => Ok(Expr::new(
            ExprKind::FieldAccess { source: Box::new(lower_expr(source)?), field: field.clone(), field_span: *field_span },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
            Ok(Expr::new(ExprKind::UnarySuffix { source: Box::new(lower_expr(source)?), kind: *kind, span: *suffix_span }, span))
        }
        _ => Ok(expr.clone()),
    }
}
