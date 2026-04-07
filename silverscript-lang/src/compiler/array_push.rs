use super::*;
use crate::ast::{ContractAst, Expr, ExprKind, FunctionAst, Statement};
use crate::span;

pub(super) fn lower_array_pushes<'i>(contract: &ContractAst<'i>) -> Result<ContractAst<'i>, CompilerError> {
    let functions = contract.functions.iter().map(lower_function).collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst {
        name: contract.name.clone(),
        params: contract.params.clone(),
        structs: contract.structs.clone(),
        fields: contract.fields.clone(),
        constants: contract.constants.clone(),
        functions,
        span: contract.span,
        name_span: contract.name_span,
    })
}

fn lower_function<'i>(function: &FunctionAst<'i>) -> Result<FunctionAst<'i>, CompilerError> {
    Ok(FunctionAst { body: lower_block(&function.body)?, ..function.clone() })
}

fn lower_block<'i>(statements: &[Statement<'i>]) -> Result<Vec<Statement<'i>>, CompilerError> {
    statements.iter().map(lower_statement).collect()
}

fn lower_statement<'i>(statement: &Statement<'i>) -> Result<Statement<'i>, CompilerError> {
    match statement {
        Statement::ArrayPush { name, expr, span, name_span } => Ok(Statement::Assign {
            name: name.clone(),
            expr: Expr::new(
                ExprKind::Binary {
                    op: BinaryOp::Add,
                    left: Box::new(Expr::identifier(name)),
                    right: Box::new(Expr::new(ExprKind::Array(vec![expr.clone()]), span::Span::default())),
                },
                *span,
            ),
            span: *span,
            name_span: *name_span,
        }),
        Statement::Block { body, span } => Ok(Statement::Block { body: lower_block(body)?, span: *span }),
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => Ok(Statement::If {
            condition: condition.clone(),
            then_branch: lower_block(then_branch)?,
            else_branch: else_branch.as_ref().map(|branch| lower_block(branch)).transpose()?,
            span: *span,
            then_span: *then_span,
            else_span: *else_span,
        }),
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => Ok(Statement::For {
            ident: ident.clone(),
            start: start.clone(),
            end: end.clone(),
            max_iterations: max_iterations.clone(),
            body: lower_block(body)?,
            span: *span,
            ident_span: *ident_span,
            body_span: *body_span,
        }),
        _ => Ok(statement.clone()),
    }
}
