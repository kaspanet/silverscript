use super::*;

pub(super) fn contract_uses_script_size<'i>(contract: &ContractAst<'i>) -> bool {
    if contract.constants.iter().any(|constant| expr_uses_script_size(&constant.expr)) {
        return true;
    }
    if contract.fields.iter().any(|field| expr_uses_script_size(&field.expr)) {
        return true;
    }
    contract.functions.iter().any(|func| func.body.iter().any(statement_uses_script_size))
}

pub(super) fn statement_uses_script_size(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::VariableDefinition { expr, .. } => expr.as_ref().is_some_and(expr_uses_script_size),
        Statement::TupleAssignment { expr, .. } => expr_uses_script_size(expr),
        Statement::FunctionCall { name, args, .. } => {
            name == "validateOutputState"
                || name == super::validate_output_state::VALIDATE_OUTPUT_STATE_INNER
                || name == "validateOutputStateWithTemplate"
                || name == super::validate_output_state::VALIDATE_OUTPUT_STATE_WITH_TEMPLATE_INNER
                || args.iter().any(expr_uses_script_size)
        }
        Statement::FunctionCallAssign { args, .. } => args.iter().any(expr_uses_script_size),
        Statement::StateFunctionCallAssign { name, args, .. } => name == "readInputState" || args.iter().any(expr_uses_script_size),
        Statement::StructDestructure { expr, .. } => expr_uses_script_size(expr),
        Statement::Assign { expr, .. } => expr_uses_script_size(expr),
        Statement::TimeOp { expr, .. } => expr_uses_script_size(expr),
        Statement::Require { expr, .. } => expr_uses_script_size(expr),
        Statement::Block { body, .. } => body.iter().any(statement_uses_script_size),
        Statement::If { condition, then_branch, else_branch, .. } => {
            expr_uses_script_size(condition)
                || then_branch.iter().any(statement_uses_script_size)
                || else_branch.as_ref().is_some_and(|branch| branch.iter().any(statement_uses_script_size))
        }
        Statement::For { start, end, max_iterations, body, .. } => {
            expr_uses_script_size(start)
                || expr_uses_script_size(end)
                || expr_uses_script_size(max_iterations)
                || body.iter().any(statement_uses_script_size)
        }
        Statement::Return { exprs, .. } => exprs.iter().any(expr_uses_script_size),
        Statement::Console { args, .. } => args.iter().any(expr_uses_script_size),
    }
}

pub(super) fn expr_uses_script_size<'i>(expr: &Expr<'i>) -> bool {
    match &expr.kind {
        ExprKind::Nullary(NullaryOp::ThisScriptSize) => true,
        ExprKind::Nullary(NullaryOp::ThisScriptSizeDataPrefix) => true,
        ExprKind::Unary { expr, .. } => expr_uses_script_size(expr),
        ExprKind::Binary { left, right, .. } => expr_uses_script_size(left) || expr_uses_script_size(right),
        ExprKind::Append { source, args, .. } => expr_uses_script_size(source) || args.iter().any(expr_uses_script_size),
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            expr_uses_script_size(condition) || expr_uses_script_size(then_expr) || expr_uses_script_size(else_expr)
        }
        ExprKind::Array { values, .. } => values.iter().any(expr_uses_script_size),
        ExprKind::StructLiteral { fields, .. } => fields.iter().any(|field| expr_uses_script_size(&field.expr)),
        ExprKind::Call { name, args, .. } => name == "readInputState" || args.iter().any(expr_uses_script_size),
        ExprKind::New { args, .. } => args.iter().any(expr_uses_script_size),
        ExprKind::Split { source, index, .. } => expr_uses_script_size(source) || expr_uses_script_size(index),
        ExprKind::Slice { source, start, end, .. } => {
            expr_uses_script_size(source) || expr_uses_script_size(start) || expr_uses_script_size(end)
        }
        ExprKind::FieldAccess { source, .. } => expr_uses_script_size(source),
        ExprKind::UnarySuffix { source, .. } => expr_uses_script_size(source),
        ExprKind::ArrayIndex { source, index } => expr_uses_script_size(source) || expr_uses_script_size(index),
        ExprKind::Introspection { index, .. } => expr_uses_script_size(index),
        ExprKind::Int(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::Identifier(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::NumberWithUnit { .. }
        | ExprKind::Nullary(_) => false,
    }
}
