use super::{
    ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, FunctionAttributeArgAst, FunctionAttributeAst, ParamAst,
    Statement, StructAst, StructBindingAst, StructFieldAst, TypeBase, TypeRef,
};
use crate::span::Span;

fn visit_type_ref<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, type_ref: &TypeRef, span: Span<'i>) {
    visitor.visit_type(type_ref, span);
}

fn visit_struct_type_name<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, name: &str, span: Span<'i>) {
    let type_ref = TypeRef { base: TypeBase::Custom(name.to_string()), array_dims: Vec::new() };
    visitor.visit_type(&type_ref, span);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    Contract,
    Struct,
    StructField,
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
}

pub trait AstVisitorMut<'i> {
    /// Visits a classified name together with its exact source span.
    fn visit_name(&mut self, _name: &mut String, _kind: NameKind, _span: Span<'i>) {}
    /// Visits a classified type. For parsed ASTs, its base type name starts at
    /// `span.start()`.
    fn visit_type(&mut self, _type_ref: &TypeRef, _span: Span<'i>) {}
    /// Visits a stored source span without classifying what it belongs to.
    ///
    /// The span is mutable so visitors can relocate or reset every span reached
    /// by the walker, for example after embedding a parsed fragment at a source
    /// offset. Synthetic AST nodes may carry an empty `Span::default()` value.
    fn visit_span(&mut self, _span: &mut Span<'i>) {}

    fn visit_contract(&mut self, contract: &mut ContractAst<'i>) {
        walk_contract_mut(self, contract);
    }

    fn visit_contract_field(&mut self, field: &mut ContractFieldAst<'i>) {
        walk_contract_field_mut(self, field);
    }

    fn visit_struct(&mut self, item: &mut StructAst<'i>) {
        walk_struct_mut(self, item);
    }

    fn visit_struct_field(&mut self, field: &mut StructFieldAst<'i>) {
        walk_struct_field_mut(self, field);
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

    fn visit_state_binding(&mut self, binding: &mut StructBindingAst<'i>) {
        walk_state_binding_mut(self, binding);
    }

    fn visit_statement(&mut self, statement: &mut Statement<'i>) {
        walk_statement_mut(self, statement);
    }

    fn visit_expr(&mut self, expr: &mut Expr<'i>) {
        walk_expr_mut(self, expr);
    }
}

pub fn visit_contract_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, contract: &mut ContractAst<'i>) {
    visitor.visit_contract(contract);
}

pub fn visit_function_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, function: &mut FunctionAst<'i>) {
    visitor.visit_function(function);
}

pub fn walk_contract_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, contract: &mut ContractAst<'i>) {
    visitor.visit_name(&mut contract.name, NameKind::Contract, contract.name_span);
    visitor.visit_span(&mut contract.span);
    visitor.visit_span(&mut contract.name_span);
    for param in &mut contract.params {
        visitor.visit_param(param);
    }
    for item in &mut contract.structs {
        visitor.visit_struct(item);
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

pub fn walk_struct_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, item: &mut StructAst<'i>) {
    visitor.visit_name(&mut item.name, NameKind::Struct, item.name_span);
    visitor.visit_span(&mut item.span);
    visitor.visit_span(&mut item.name_span);
    for field in &mut item.fields {
        visitor.visit_struct_field(field);
    }
}

pub fn walk_struct_field_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, field: &mut StructFieldAst<'i>) {
    visit_type_ref(visitor, &field.type_ref, field.type_span);
    visitor.visit_name(&mut field.name, NameKind::StructField, field.name_span);
    visitor.visit_span(&mut field.span);
    visitor.visit_span(&mut field.type_span);
    visitor.visit_span(&mut field.name_span);
}

pub fn walk_contract_field_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, field: &mut ContractFieldAst<'i>) {
    visit_type_ref(visitor, &field.type_ref, field.type_span);
    visitor.visit_name(&mut field.name, NameKind::ContractField, field.name_span);
    visitor.visit_span(&mut field.span);
    visitor.visit_span(&mut field.type_span);
    visitor.visit_span(&mut field.name_span);
    visitor.visit_expr(&mut field.expr);
}

pub fn walk_constant_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, constant: &mut ConstantAst<'i>) {
    visit_type_ref(visitor, &constant.type_ref, constant.type_span);
    visitor.visit_name(&mut constant.name, NameKind::Constant, constant.name_span);
    visitor.visit_span(&mut constant.span);
    visitor.visit_span(&mut constant.type_span);
    visitor.visit_span(&mut constant.name_span);
    visitor.visit_expr(&mut constant.expr);
}

pub fn walk_function_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, function: &mut FunctionAst<'i>) {
    visitor.visit_name(&mut function.name, NameKind::Function, function.name_span);
    visitor.visit_span(&mut function.span);
    visitor.visit_span(&mut function.name_span);
    visitor.visit_span(&mut function.body_span);
    for (type_ref, span) in
        function.return_types.iter().zip(function.return_type_spans.iter().copied().chain(std::iter::repeat(Span::default())))
    {
        visit_type_ref(visitor, type_ref, span);
    }
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
    for (segment, span) in
        attribute.path.iter_mut().zip(attribute.path_spans.iter().copied().chain(std::iter::repeat(Span::default())))
    {
        visitor.visit_name(segment, NameKind::AttributePathSegment, span);
    }
    for span in &mut attribute.path_spans {
        visitor.visit_span(span);
    }
    for arg in &mut attribute.args {
        visitor.visit_function_attribute_arg(arg);
    }
}

pub fn walk_function_attribute_arg_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, arg: &mut FunctionAttributeArgAst<'i>) {
    visitor.visit_name(&mut arg.name, NameKind::AttributeArg, arg.name_span);
    visitor.visit_span(&mut arg.span);
    visitor.visit_span(&mut arg.name_span);
    visitor.visit_expr(&mut arg.expr);
}

pub fn walk_param_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, param: &mut ParamAst<'i>) {
    walk_param_with_kind_mut(visitor, param, NameKind::Parameter);
}

fn walk_param_with_kind_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, param: &mut ParamAst<'i>, kind: NameKind) {
    visit_type_ref(visitor, &param.type_ref, param.type_span);
    visitor.visit_name(&mut param.name, kind, param.name_span);
    visitor.visit_span(&mut param.span);
    visitor.visit_span(&mut param.type_span);
    visitor.visit_span(&mut param.name_span);
}

pub fn walk_state_binding_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, binding: &mut StructBindingAst<'i>) {
    visit_type_ref(visitor, &binding.type_ref, binding.type_span);
    visitor.visit_name(&mut binding.field_name, NameKind::StateField, binding.field_span);
    visitor.visit_name(&mut binding.name, NameKind::StateBinding, binding.name_span);
    visitor.visit_span(&mut binding.span);
    visitor.visit_span(&mut binding.field_span);
    visitor.visit_span(&mut binding.type_span);
    visitor.visit_span(&mut binding.name_span);
}

pub fn walk_statement_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, statement: &mut Statement<'i>) {
    match statement {
        Statement::VariableDefinition { type_ref, name, expr, span, type_span, modifier_spans, name_span, .. } => {
            visit_type_ref(visitor, type_ref, *type_span);
            visitor.visit_name(name, NameKind::LocalBinding, *name_span);
            visitor.visit_span(span);
            visitor.visit_span(type_span);
            for span in modifier_spans {
                visitor.visit_span(span);
            }
            visitor.visit_span(name_span);
            if let Some(expr) = expr {
                visitor.visit_expr(expr);
            }
        }
        Statement::TupleAssignment {
            left_name,
            left_type_ref,
            right_name,
            right_type_ref,
            expr,
            span,
            left_type_span,
            left_name_span,
            right_type_span,
            right_name_span,
            ..
        } => {
            visit_type_ref(visitor, left_type_ref, *left_type_span);
            visit_type_ref(visitor, right_type_ref, *right_type_span);
            visitor.visit_name(left_name, NameKind::LocalBinding, *left_name_span);
            visitor.visit_name(right_name, NameKind::LocalBinding, *right_name_span);
            visitor.visit_span(span);
            visitor.visit_span(left_type_span);
            visitor.visit_span(left_name_span);
            visitor.visit_span(right_type_span);
            visitor.visit_span(right_name_span);
            visitor.visit_expr(expr);
        }
        Statement::FunctionCall { name, args, span, name_span } => {
            visitor.visit_name(name, NameKind::CallTarget, *name_span);
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
            visitor.visit_name(name, NameKind::CallTarget, *name_span);
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            for binding in bindings {
                walk_param_with_kind_mut(visitor, binding, NameKind::LocalBinding);
            }
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Statement::StateFunctionCallAssign { target_struct, bindings, name, args, span, target_struct_span, name_span } => {
            visit_struct_type_name(visitor, target_struct, *target_struct_span);
            visitor.visit_name(name, NameKind::CallTarget, *name_span);
            visitor.visit_span(span);
            visitor.visit_span(target_struct_span);
            visitor.visit_span(name_span);
            for binding in bindings {
                visitor.visit_state_binding(binding);
            }
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Statement::StructDestructure { struct_name, bindings, expr, span, struct_name_span } => {
            visit_struct_type_name(visitor, struct_name, *struct_name_span);
            visitor.visit_span(span);
            visitor.visit_span(struct_name_span);
            for binding in bindings {
                visitor.visit_state_binding(binding);
            }
            visitor.visit_expr(expr);
        }
        Statement::Assign { name, expr, span, name_span } => {
            visitor.visit_name(name, NameKind::AssignmentTarget, *name_span);
            visitor.visit_span(span);
            visitor.visit_span(name_span);
            visitor.visit_expr(expr);
        }
        Statement::RequireAgeDaa { expr, span, target_span, message_span, .. }
        | Statement::RequireTxDaa { expr, span, target_span, message_span, .. }
        | Statement::RequireTxTime { expr, span, target_span, message_span, .. } => {
            visitor.visit_span(span);
            visitor.visit_span(target_span);
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
        Statement::Block { body, span } => {
            visitor.visit_span(span);
            for statement in body {
                visitor.visit_statement(statement);
            }
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
            visitor.visit_name(ident, NameKind::LoopBinding, *ident_span);
            visitor.visit_span(span);
            visitor.visit_span(ident_span);
            visitor.visit_span(body_span);
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
                visitor.visit_expr(arg);
            }
        }
    }
}

pub fn walk_expr_mut<'i, V: AstVisitorMut<'i> + ?Sized>(visitor: &mut V, expr: &mut Expr<'i>) {
    let expr_span = expr.span;
    visitor.visit_span(&mut expr.span);
    match &mut expr.kind {
        ExprKind::Identifier(name) => visitor.visit_name(name, NameKind::IdentifierExpr, expr_span),
        ExprKind::Array { type_ref, values: items, type_span } => {
            visit_type_ref(visitor, type_ref, *type_span);
            visitor.visit_span(type_span);
            for item in items {
                visitor.visit_expr(item);
            }
        }
        ExprKind::Call { name, args, name_span } | ExprKind::New { name, args, name_span } => {
            visitor.visit_name(name, NameKind::CallTarget, *name_span);
            visitor.visit_span(name_span);
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
        ExprKind::Append { source, args, span } => {
            visitor.visit_span(span);
            visitor.visit_expr(source);
            for arg in args {
                visitor.visit_expr(arg);
            }
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
        ExprKind::Ternary { condition, then_expr, else_expr } => {
            visitor.visit_expr(condition);
            visitor.visit_expr(then_expr);
            visitor.visit_expr(else_expr);
        }
        ExprKind::IndexedIntrospection { index, field_span, .. } => {
            visitor.visit_span(field_span);
            visitor.visit_expr(index);
        }
        ExprKind::StructLiteral { name, fields, name_span } => {
            visit_struct_type_name(visitor, name, *name_span);
            visitor.visit_span(name_span);
            for field in fields {
                visitor.visit_name(&mut field.name, NameKind::StateField, field.name_span);
                visitor.visit_span(&mut field.span);
                visitor.visit_span(&mut field.name_span);
                visitor.visit_expr(&mut field.expr);
            }
        }
        ExprKind::FieldAccess { source, field, field_span } => {
            visitor.visit_expr(source);
            visitor.visit_name(field, NameKind::StateField, *field_span);
            visitor.visit_span(field_span);
        }
        ExprKind::Int(_)
        | ExprKind::Temporal(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::Introspection(_)
        | ExprKind::NumberWithUnit { .. } => {}
    }
}
