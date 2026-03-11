use super::{
    ConsoleArg, ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, FunctionAttributeArgAst,
    FunctionAttributeAst, ParamAst, StateBindingAst, Statement,
};
use crate::span::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    Contract,
    ContractField,
    Constant,
    Function,
    Parameter,
    AttributePathSegment,
    AttributeArg,
    LocalBinding,
    AssignmentTarget,
    LoopBinding,
    StateField,
    StateBinding,
    CallTarget,
    IdentifierExpr,
    ConsoleIdentifier,
}

pub trait AstVisitorMut<'i> {
    fn visit_name(&mut self, _name: &mut String, _kind: NameKind) {}
    fn visit_span(&mut self, _span: &mut Span<'i>) {}

    fn visit_contract(&mut self, contract: &mut ContractAst<'i>) {
        walk_contract_mut(self, contract);
    }

    fn visit_contract_field(&mut self, field: &mut ContractFieldAst<'i>) {
        walk_contract_field_mut(self, field);
    }

    fn visit_constant(&mut self, constant: &mut ConstantAst<'i>) {
        walk_constant_mut(self, constant);
    }

    fn visit_function(&mut self, function: &mut FunctionAst<'i>) {
        walk_function_mut(self, function);
    }

    fn visit_function_attribute(&mut self, attribute: &mut FunctionAttributeAst<'i>) {
        walk_function_attribute_mut(self, attribute);
    }

    fn visit_function_attribute_arg(&mut self, arg: &mut FunctionAttributeArgAst<'i>) {
        walk_function_attribute_arg_mut(self, arg);
    }

    fn visit_param(&mut self, param: &mut ParamAst<'i>) {
        walk_param_mut(self, param);
    }

    fn visit_state_binding(&mut self, binding: &mut StateBindingAst<'i>) {
        walk_state_binding_mut(self, binding);
    }

    fn visit_statement(&mut self, statement: &mut Statement<'i>) {
        walk_statement_mut(self, statement);
    }

    fn visit_console_arg(&mut self, arg: &mut ConsoleArg<'i>) {
        walk_console_arg_mut(self, arg);
    }

    fn visit_expr(&mut self, expr: &mut Expr<'i>) {
        walk_expr_mut(self, expr);
    }
}

pub fn visit_contract_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, contract: &mut ContractAst<'i>) {
    visitor.visit_contract(contract);
}

pub fn walk_contract_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, contract: &mut ContractAst<'i>) {
    visitor.visit_name(&mut contract.name, NameKind::Contract);
    visitor.visit_span(&mut contract.span);
    visitor.visit_span(&mut contract.name_span);
    for param in &mut contract.params {
        visitor.visit_param(param);
    }
    for field in &mut contract.fields {
        visitor.visit_contract_field(field);
    }
    for constant in &mut contract.constants {
        visitor.visit_constant(constant);
    }
    for function in &mut contract.functions {
        visitor.visit_function(function);
    }
}

pub fn walk_contract_field_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, field: &mut ContractFieldAst<'i>) {
    visitor.visit_name(&mut field.name, NameKind::ContractField);
    visitor.visit_span(&mut field.span);
    visitor.visit_span(&mut field.type_span);
    visitor.visit_span(&mut field.name_span);
    visitor.visit_expr(&mut field.expr);
}

pub fn walk_constant_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, constant: &mut ConstantAst<'i>) {
    visitor.visit_name(&mut constant.name, NameKind::Constant);
    visitor.visit_span(&mut constant.span);
    visitor.visit_span(&mut constant.type_span);
    visitor.visit_span(&mut constant.name_span);
    visitor.visit_expr(&mut constant.expr);
}

pub fn walk_function_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, function: &mut FunctionAst<'i>) {
    visitor.visit_name(&mut function.name, NameKind::Function);
    visitor.visit_span(&mut function.span);
    visitor.visit_span(&mut function.name_span);
    visitor.visit_span(&mut function.body_span);
    for span in &mut function.return_type_spans {
        visitor.visit_span(span);
    }
    for attribute in &mut function.attributes {
        visitor.visit_function_attribute(attribute);
    }
    for param in &mut function.params {
        visitor.visit_param(param);
    }
    for statement in &mut function.body {
        visitor.visit_statement(statement);
    }
}

pub fn walk_function_attribute_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, attribute: &mut FunctionAttributeAst<'i>) {
    visitor.visit_span(&mut attribute.span);
    for span in &mut attribute.path_spans {
        visitor.visit_span(span);
    }
    for segment in &mut attribute.path {
        visitor.visit_name(segment, NameKind::AttributePathSegment);
    }
    for arg in &mut attribute.args {
        visitor.visit_function_attribute_arg(arg);
    }
}

pub fn walk_function_attribute_arg_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, arg: &mut FunctionAttributeArgAst<'i>) {
    visitor.visit_name(&mut arg.name, NameKind::AttributeArg);
    visitor.visit_span(&mut arg.span);
    visitor.visit_span(&mut arg.name_span);
    visitor.visit_expr(&mut arg.expr);
}

pub fn walk_param_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, param: &mut ParamAst<'i>) {
    visitor.visit_name(&mut param.name, NameKind::Parameter);
    visitor.visit_span(&mut param.span);
    visitor.visit_span(&mut param.type_span);
    visitor.visit_span(&mut param.name_span);
}

pub fn walk_state_binding_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, binding: &mut StateBindingAst<'i>) {
    visitor.visit_name(&mut binding.field_name, NameKind::StateField);
    visitor.visit_name(&mut binding.name, NameKind::StateBinding);
    visitor.visit_span(&mut binding.span);
    visitor.visit_span(&mut binding.field_span);
    visitor.visit_span(&mut binding.type_span);
    visitor.visit_span(&mut binding.name_span);
}

pub fn walk_statement_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, statement: &mut Statement<'i>) {
    match statement {
        Statement::VariableDefinition { name, expr, span, type_span, modifier_spans, name_span, .. } => {
            visitor.visit_span(span);
            visitor.visit_span(type_span);
            for span in modifier_spans {
                visitor.visit_span(span);
            }
            visitor.visit_span(name_span);
            visitor.visit_name(name, NameKind::LocalBinding);
            if let Some(expr) = expr {
                visitor.visit_expr(expr);
            }
        }
        Statement::TupleAssignment {
            left_name,
            right_name,
            expr,
            span,
            left_type_span,
            left_name_span,
            right_type_span,
            right_name_span,
            ..
        } => {
            visitor.visit_span(span);
            visitor.visit_span(left_type_span);
            visitor.visit_span(left_name_span);
            visitor.visit_span(right_type_span);
            visitor.visit_span(right_name_span);
            visitor.visit_name(left_name, NameKind::AssignmentTarget);
            visitor.visit_name(right_name, NameKind::AssignmentTarget);
            visitor.visit_expr(expr);
        }
        Statement::ArrayPush { name, expr, span, name_span } => {
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            visitor.visit_name(name, NameKind::AssignmentTarget);
            visitor.visit_expr(expr);
        }
        Statement::FunctionCall { name, args, span, name_span } => {
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            visitor.visit_name(name, NameKind::CallTarget);
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            for binding in bindings {
                visitor.visit_param(binding);
            }
            visitor.visit_name(name, NameKind::CallTarget);
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => {
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            for binding in bindings {
                visitor.visit_state_binding(binding);
            }
            visitor.visit_name(name, NameKind::CallTarget);
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Statement::StructDestructure { bindings, expr, span } => {
            visitor.visit_span(span);
            for binding in bindings {
                visitor.visit_state_binding(binding);
            }
            visitor.visit_expr(expr);
        }
        Statement::Assign { name, expr, span, name_span } => {
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            visitor.visit_name(name, NameKind::AssignmentTarget);
            visitor.visit_expr(expr);
        }
        Statement::TimeOp { expr, span, tx_var_span, message_span, .. } => {
            visitor.visit_span(span);
            visitor.visit_span(tx_var_span);
            if let Some(span) = message_span {
                visitor.visit_span(span);
            }
            visitor.visit_expr(expr);
        }
        Statement::Require { expr, span, message_span, .. } => {
            visitor.visit_span(span);
            if let Some(span) = message_span {
                visitor.visit_span(span);
            }
            visitor.visit_expr(expr);
        }
        Statement::Yield { expr, span } => {
            visitor.visit_span(span);
            visitor.visit_expr(expr);
        }
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
            visitor.visit_span(span);
            visitor.visit_span(then_span);
            if let Some(span) = else_span {
                visitor.visit_span(span);
            }
            visitor.visit_expr(condition);
            for statement in then_branch {
                visitor.visit_statement(statement);
            }
            if let Some(else_branch) = else_branch {
                for statement in else_branch {
                    visitor.visit_statement(statement);
                }
            }
        }
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
            visitor.visit_span(span);
            visitor.visit_span(ident_span);
            visitor.visit_span(body_span);
            visitor.visit_name(ident, NameKind::LoopBinding);
            visitor.visit_expr(start);
            visitor.visit_expr(end);
            visitor.visit_expr(max_iterations);
            for statement in body {
                visitor.visit_statement(statement);
            }
        }
        Statement::Return { exprs, span } => {
            visitor.visit_span(span);
            for expr in exprs {
                visitor.visit_expr(expr);
            }
        }
        Statement::Console { args, span } => {
            visitor.visit_span(span);
            for arg in args {
                visitor.visit_console_arg(arg);
            }
        }
    }
}

pub fn walk_console_arg_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, arg: &mut ConsoleArg<'i>) {
    match arg {
        ConsoleArg::Identifier(name, span) => {
            visitor.visit_name(name, NameKind::ConsoleIdentifier);
            visitor.visit_span(span);
        }
        ConsoleArg::Literal(expr) => visitor.visit_expr(expr),
    }
}

pub fn walk_expr_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, expr: &mut Expr<'i>) {
    visitor.visit_span(&mut expr.span);
    match &mut expr.kind {
        ExprKind::Identifier(name) => visitor.visit_name(name, NameKind::IdentifierExpr),
        ExprKind::Array(items) => {
            for item in items {
                visitor.visit_expr(item);
            }
        }
        ExprKind::Call { name, args, name_span } | ExprKind::New { name, args, name_span } => {
            visitor.visit_span(name_span);
            visitor.visit_name(name, NameKind::CallTarget);
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        ExprKind::Split { source, index, span, .. } => {
            visitor.visit_span(span);
            visitor.visit_expr(source);
            visitor.visit_expr(index);
        }
        ExprKind::ArrayIndex { source, index } => {
            visitor.visit_expr(source);
            visitor.visit_expr(index);
        }
        ExprKind::Slice { source, start, end, span } => {
            visitor.visit_span(span);
            visitor.visit_expr(source);
            visitor.visit_expr(start);
            visitor.visit_expr(end);
        }
        ExprKind::Unary { expr, .. } => {
            visitor.visit_expr(expr);
        }
        ExprKind::UnarySuffix { source, span, .. } => {
            visitor.visit_span(span);
            visitor.visit_expr(source);
        }
        ExprKind::Binary { left, right, .. } => {
            visitor.visit_expr(left);
            visitor.visit_expr(right);
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            visitor.visit_expr(condition);
            visitor.visit_expr(then_expr);
            visitor.visit_expr(else_expr);
        }
        ExprKind::Introspection { index, field_span, .. } => {
            visitor.visit_span(field_span);
            visitor.visit_expr(index);
        }
        ExprKind::StateObject(fields) => {
            for field in fields {
                visitor.visit_name(&mut field.name, NameKind::StateField);
                visitor.visit_span(&mut field.span);
                visitor.visit_span(&mut field.name_span);
                visitor.visit_expr(&mut field.expr);
            }
        }
        ExprKind::FieldAccess { source, field, field_span } => {
            visitor.visit_expr(source);
            visitor.visit_name(field, NameKind::StateField);
            visitor.visit_span(field_span);
        }
        ExprKind::Int(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::Nullary(_)
        | ExprKind::NumberWithUnit { .. } => {}
    }
}
