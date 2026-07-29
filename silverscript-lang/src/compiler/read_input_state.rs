use std::collections::HashSet;

use super::*;
use crate::ast::{ContractAst, Expr, ExprKind, FunctionAst, STATE_TYPE_NAME, StateFieldExpr, Statement, TypeBase, TypeRef};
use crate::span;

/// Lift struct-valued `readInputState(...)` call arguments into local variables.
///
/// Later lowering stages represent structs as several scalar stack values. Giving
/// a state read its own binding before it is used as a call argument lets those
/// stages flatten the value through the normal local-variable path.
///
/// For example:
///
/// ```silverscript
/// checkState(1, readInputState(inputIndex), true);
/// ```
///
/// is lowered to:
///
/// ```silverscript
/// State __read_input_state_0 = readInputState(inputIndex);
/// checkState(1, __read_input_state_0, true);
/// ```
pub(super) fn lower_read_input_state_calls<'i>(contract: &ContractAst<'i>) -> Result<ContractAst<'i>, CompilerError> {
    let contract_names = contract
        .params
        .iter()
        .map(|param| param.name.clone())
        .chain(contract.fields.iter().map(|field| field.name.clone()))
        .chain(contract.constants.iter().map(|constant| constant.name.clone()))
        .collect::<HashSet<_>>();

    let functions = contract
        .functions
        .iter()
        .map(|function| {
            let mut used_names = contract_names.clone();
            used_names.extend(function.params.iter().map(|param| param.name.clone()));
            collect_local_names(&function.body, &mut used_names);
            let mut context = LoweringContext { used_names, temp_index: 0 };
            Ok(FunctionAst { body: lower_block(&function.body, &mut context), ..function.clone() })
        })
        .collect::<Result<Vec<_>, CompilerError>>()?;

    Ok(ContractAst { functions, ..contract.clone() })
}

struct LoweringContext {
    used_names: HashSet<String>,
    temp_index: usize,
}

impl LoweringContext {
    fn next_temp_name(&mut self) -> String {
        loop {
            let name = format!("__read_input_state_{}", self.temp_index);
            self.temp_index += 1;
            if self.used_names.insert(name.clone()) {
                return name;
            }
        }
    }
}

fn collect_local_names(statements: &[Statement<'_>], names: &mut HashSet<String>) {
    for statement in statements {
        match statement {
            Statement::VariableDefinition { name, .. } | Statement::Assign { name, .. } => {
                names.insert(name.clone());
            }
            Statement::TupleAssignment { left_name, right_name, .. } => {
                names.insert(left_name.clone());
                names.insert(right_name.clone());
            }
            Statement::FunctionCallAssign { bindings, .. } => {
                names.extend(bindings.iter().map(|binding| binding.name.clone()));
            }
            Statement::StateFunctionCallAssign { bindings, .. } | Statement::StructDestructure { bindings, .. } => {
                names.extend(bindings.iter().map(|binding| binding.name.clone()));
            }
            Statement::Block { body, .. } => collect_local_names(body, names),
            Statement::If { then_branch, else_branch, .. } => {
                collect_local_names(then_branch, names);
                if let Some(else_branch) = else_branch {
                    collect_local_names(else_branch, names);
                }
            }
            Statement::For { ident, body, .. } => {
                names.insert(ident.clone());
                collect_local_names(body, names);
            }
            _ => {}
        }
    }
}

fn lower_block<'i>(statements: &[Statement<'i>], context: &mut LoweringContext) -> Vec<Statement<'i>> {
    let mut lowered = Vec::new();
    for statement in statements {
        let (mut prefix, statement) = lower_statement(statement, context);
        lowered.append(&mut prefix);
        lowered.push(statement);
    }
    lowered
}

fn lower_statement<'i>(statement: &Statement<'i>, context: &mut LoweringContext) -> (Vec<Statement<'i>>, Statement<'i>) {
    let mut prefix = Vec::new();
    let lowered = match statement {
        Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
            Statement::VariableDefinition {
                type_ref: type_ref.clone(),
                modifiers: modifiers.clone(),
                name: name.clone(),
                expr: expr.as_ref().map(|expr| lower_expr(expr, &mut prefix, context)),
                span: *span,
                type_span: *type_span,
                modifier_spans: modifier_spans.clone(),
                name_span: *name_span,
            }
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
        } => Statement::TupleAssignment {
            left_type_ref: left_type_ref.clone(),
            left_name: left_name.clone(),
            right_type_ref: right_type_ref.clone(),
            right_name: right_name.clone(),
            expr: lower_expr(expr, &mut prefix, context),
            span: *span,
            left_type_span: *left_type_span,
            left_name_span: *left_name_span,
            right_type_span: *right_type_span,
            right_name_span: *right_name_span,
        },
        Statement::FunctionCall { name, args, span, name_span } => Statement::FunctionCall {
            name: name.clone(),
            args: lower_call_args(args, &mut prefix, context),
            span: *span,
            name_span: *name_span,
        },
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => Statement::FunctionCallAssign {
            bindings: bindings.clone(),
            name: name.clone(),
            args: lower_call_args(args, &mut prefix, context),
            span: *span,
            name_span: *name_span,
        },
        Statement::StateFunctionCallAssign { target_struct, bindings, name, args, span, name_span } => {
            Statement::StateFunctionCallAssign {
                target_struct: target_struct.clone(),
                bindings: bindings.clone(),
                name: name.clone(),
                args: lower_call_args(args, &mut prefix, context),
                span: *span,
                name_span: *name_span,
            }
        }
        Statement::StructDestructure { bindings, expr, span } => {
            Statement::StructDestructure { bindings: bindings.clone(), expr: lower_expr(expr, &mut prefix, context), span: *span }
        }
        Statement::Assign { name, expr, span, name_span } => {
            Statement::Assign { name: name.clone(), expr: lower_expr(expr, &mut prefix, context), span: *span, name_span: *name_span }
        }
        Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => Statement::TimeOp {
            tx_var: *tx_var,
            expr: lower_expr(expr, &mut prefix, context),
            message: message.clone(),
            span: *span,
            tx_var_span: *tx_var_span,
            message_span: *message_span,
        },
        Statement::Require { expr, message, span, message_span } => Statement::Require {
            expr: lower_expr(expr, &mut prefix, context),
            message: message.clone(),
            span: *span,
            message_span: *message_span,
        },
        Statement::Block { body, span } => Statement::Block { body: lower_block(body, context), span: *span },
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => Statement::If {
            condition: lower_expr(condition, &mut prefix, context),
            then_branch: lower_block(then_branch, context),
            else_branch: else_branch.as_ref().map(|branch| lower_block(branch, context)),
            span: *span,
            then_span: *then_span,
            else_span: *else_span,
        },
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => Statement::For {
            ident: ident.clone(),
            start: lower_expr(start, &mut prefix, context),
            end: lower_expr(end, &mut prefix, context),
            max_iterations: lower_expr(max_iterations, &mut prefix, context),
            body: lower_block(body, context),
            span: *span,
            ident_span: *ident_span,
            body_span: *body_span,
        },
        Statement::Return { exprs, span } => {
            Statement::Return { exprs: exprs.iter().map(|expr| lower_expr(expr, &mut prefix, context)).collect(), span: *span }
        }
        Statement::Console { args, span } => Statement::Console { args: lower_call_args(args, &mut prefix, context), span: *span },
    };
    (prefix, lowered)
}

fn lower_call_args<'i>(args: &[Expr<'i>], prefix: &mut Vec<Statement<'i>>, context: &mut LoweringContext) -> Vec<Expr<'i>> {
    args.iter().map(|arg| lower_call_arg(arg, prefix, context)).collect()
}

fn lower_call_arg<'i>(arg: &Expr<'i>, prefix: &mut Vec<Statement<'i>>, context: &mut LoweringContext) -> Expr<'i> {
    if matches!(&arg.kind, ExprKind::Call { name, .. } if name == "readInputState") {
        let expr = lower_expr(arg, prefix, context);
        let temp_name = context.next_temp_name();
        prefix.push(Statement::VariableDefinition {
            type_ref: TypeRef { base: TypeBase::Custom(STATE_TYPE_NAME.to_string()), array_dims: Vec::new() },
            modifiers: Vec::new(),
            name: temp_name.clone(),
            expr: Some(expr),
            span: arg.span,
            type_span: span::Span::default(),
            modifier_spans: Vec::new(),
            name_span: span::Span::default(),
        });
        Expr::new(ExprKind::Identifier(temp_name), arg.span)
    } else {
        lower_expr(arg, prefix, context)
    }
}

fn lower_expr<'i>(expr: &Expr<'i>, prefix: &mut Vec<Statement<'i>>, context: &mut LoweringContext) -> Expr<'i> {
    let kind = match &expr.kind {
        ExprKind::Array(values) => ExprKind::Array(values.iter().map(|value| lower_expr(value, prefix, context)).collect()),
        ExprKind::Call { name, args, name_span } => {
            ExprKind::Call { name: name.clone(), args: lower_call_args(args, prefix, context), name_span: *name_span }
        }
        ExprKind::New { name, args, name_span } => {
            ExprKind::New { name: name.clone(), args: lower_call_args(args, prefix, context), name_span: *name_span }
        }
        ExprKind::Split { source, index, part, span } => ExprKind::Split {
            source: Box::new(lower_expr(source, prefix, context)),
            index: Box::new(lower_expr(index, prefix, context)),
            part: *part,
            span: *span,
        },
        ExprKind::Slice { source, start, end, span } => ExprKind::Slice {
            source: Box::new(lower_expr(source, prefix, context)),
            start: Box::new(lower_expr(start, prefix, context)),
            end: Box::new(lower_expr(end, prefix, context)),
            span: *span,
        },
        ExprKind::Append { source, args, span } => ExprKind::Append {
            source: Box::new(lower_expr(source, prefix, context)),
            args: lower_call_args(args, prefix, context),
            span: *span,
        },
        ExprKind::ArrayIndex { source, index } => ExprKind::ArrayIndex {
            source: Box::new(lower_expr(source, prefix, context)),
            index: Box::new(lower_expr(index, prefix, context)),
        },
        ExprKind::Unary { op, expr } => ExprKind::Unary { op: *op, expr: Box::new(lower_expr(expr, prefix, context)) },
        ExprKind::Binary { op, left, right } => ExprKind::Binary {
            op: *op,
            left: Box::new(lower_expr(left, prefix, context)),
            right: Box::new(lower_expr(right, prefix, context)),
        },
        ExprKind::IfElse { condition, then_expr, else_expr } => ExprKind::IfElse {
            condition: Box::new(lower_expr(condition, prefix, context)),
            then_expr: Box::new(lower_expr(then_expr, prefix, context)),
            else_expr: Box::new(lower_expr(else_expr, prefix, context)),
        },
        ExprKind::Introspection { kind, index, field_span } => {
            ExprKind::Introspection { kind: *kind, index: Box::new(lower_expr(index, prefix, context)), field_span: *field_span }
        }
        ExprKind::StructLiteral(fields) => ExprKind::StructLiteral(
            fields
                .iter()
                .map(|field| StateFieldExpr {
                    name: field.name.clone(),
                    expr: lower_expr(&field.expr, prefix, context),
                    span: field.span,
                    name_span: field.name_span,
                })
                .collect(),
        ),
        ExprKind::FieldAccess { source, field, field_span } => ExprKind::FieldAccess {
            source: Box::new(lower_expr(source, prefix, context)),
            field: field.clone(),
            field_span: *field_span,
        },
        ExprKind::UnarySuffix { source, kind, span } => {
            ExprKind::UnarySuffix { source: Box::new(lower_expr(source, prefix, context)), kind: *kind, span: *span }
        }
        _ => return expr.clone(),
    };
    Expr::new(kind, expr.span)
}
