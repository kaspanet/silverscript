use std::collections::HashMap;

use super::*;

const INLINE_LOCAL_PREFIX: &str = "__inline";

pub(super) fn lower_inline_functions<'i>(contract: &ContractAst<'i>) -> Result<ContractAst<'i>, CompilerError> {
    let functions = contract.functions.iter().cloned().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let function_order =
        contract.functions.iter().enumerate().map(|(index, function)| (function.name.clone(), index)).collect::<HashMap<_, _>>();
    let mut inliner = Inliner { functions, function_order, fresh_counter: 0 };

    let lowered_functions = contract
        .functions
        .iter()
        .enumerate()
        .filter(|(_, function)| function.entrypoint)
        .map(|(index, function)| inliner.lower_entrypoint_function(function, index))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst {
        name: contract.name.clone(),
        params: contract.params.clone(),
        structs: contract.structs.clone(),
        fields: contract.fields.clone(),
        constants: contract.constants.clone(),
        functions: lowered_functions,
        span: contract.span,
        name_span: contract.name_span,
    })
}

struct Inliner<'i> {
    functions: HashMap<String, FunctionAst<'i>>,
    function_order: HashMap<String, usize>,
    fresh_counter: usize,
}

impl<'i> Inliner<'i> {
    fn fresh_name(&mut self, base: &str) -> String {
        let name = format!("{}_{}_{}", INLINE_LOCAL_PREFIX, self.fresh_counter, base);
        self.fresh_counter += 1;
        name
    }

    fn lower_entrypoint_function(
        &mut self,
        function: &FunctionAst<'i>,
        function_index: usize,
    ) -> Result<FunctionAst<'i>, CompilerError> {
        let mut scope = HashMap::new();
        for param in &function.params {
            scope.insert(param.name.clone(), param.name.clone());
        }

        Ok(FunctionAst {
            body: self.lower_block(&function.body, &mut scope, function_index)?,
            ..function.clone()
        })
    }

    fn lower_block(
        &mut self,
        statements: &[Statement<'i>],
        scope: &mut HashMap<String, String>,
        function_index: usize,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let mut lowered = Vec::new();
        for statement in statements {
            lowered.extend(self.lower_statement(statement, scope, function_index)?);
        }
        Ok(lowered)
    }

    fn predeclare_branch_bindings(&mut self, statements: &[Statement<'i>], scope: &mut HashMap<String, String>) {
        for statement in statements {
            match statement {
                Statement::VariableDefinition { name, .. } => {
                    scope.entry(name.clone()).or_insert_with(|| self.fresh_name(name));
                }
                Statement::TupleAssignment { left_name, right_name, .. } => {
                    scope.entry(left_name.clone()).or_insert_with(|| self.fresh_name(left_name));
                    scope.entry(right_name.clone()).or_insert_with(|| self.fresh_name(right_name));
                }
                Statement::FunctionCallAssign { bindings, .. } => {
                    for binding in bindings {
                        scope.entry(binding.name.clone()).or_insert_with(|| self.fresh_name(&binding.name));
                    }
                }
                Statement::StateFunctionCallAssign { bindings, .. } | Statement::StructDestructure { bindings, .. } => {
                    for binding in bindings {
                        scope.entry(binding.name.clone()).or_insert_with(|| self.fresh_name(&binding.name));
                    }
                }
                _ => {}
            }
        }
    }

    fn lower_statement(
        &mut self,
        statement: &Statement<'i>,
        scope: &mut HashMap<String, String>,
        function_index: usize,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        Ok(match statement {
            Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
                let fresh = scope.entry(name.clone()).or_insert_with(|| self.fresh_name(name)).clone();
                vec![Statement::VariableDefinition {
                    type_ref: type_ref.clone(),
                    modifiers: modifiers.clone(),
                    name: fresh,
                    expr: expr.as_ref().map(|expr| self.rename_expr(expr, scope)).transpose()?,
                    span: *span,
                    type_span: *type_span,
                    modifier_spans: modifier_spans.clone(),
                    name_span: *name_span,
                }]
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
            } => {
                let left_fresh = scope.entry(left_name.clone()).or_insert_with(|| self.fresh_name(left_name)).clone();
                let right_fresh = scope.entry(right_name.clone()).or_insert_with(|| self.fresh_name(right_name)).clone();
                vec![Statement::TupleAssignment {
                    left_type_ref: left_type_ref.clone(),
                    left_name: left_fresh,
                    right_type_ref: right_type_ref.clone(),
                    right_name: right_fresh,
                    expr: self.rename_expr(expr, scope)?,
                    span: *span,
                    left_type_span: *left_type_span,
                    left_name_span: *left_name_span,
                    right_type_span: *right_type_span,
                    right_name_span: *right_name_span,
                }]
            }
            Statement::ArrayPush { name, expr, span, name_span } => vec![Statement::ArrayPush {
                name: self.rename_name(name, scope),
                expr: self.rename_expr(expr, scope)?,
                span: *span,
                name_span: *name_span,
            }],
            Statement::FunctionCall { name, args, span, name_span } => {
                if let Some(function) = self.inline_target(name).filter(|function| function.return_types.is_empty()) {
                    self.inline_call(&function, args, None, scope, function_index, *span)?
                } else {
                    vec![Statement::FunctionCall {
                        name: name.clone(),
                        args: args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?,
                        span: *span,
                        name_span: *name_span,
                    }]
                }
            }
            Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
                if let Some(function) = self.inline_target(name) {
                    let renamed_bindings = bindings
                        .iter()
                        .map(|binding| {
                            let fresh = scope.entry(binding.name.clone()).or_insert_with(|| self.fresh_name(&binding.name)).clone();
                            ParamAst { name: fresh, ..binding.clone() }
                        })
                        .collect::<Vec<_>>();
                    self.inline_call(&function, args, Some(&renamed_bindings), scope, function_index, *span)?
                } else {
                    let renamed_bindings = bindings
                        .iter()
                        .map(|binding| {
                            let fresh = scope.entry(binding.name.clone()).or_insert_with(|| self.fresh_name(&binding.name)).clone();
                            ParamAst { name: fresh, ..binding.clone() }
                        })
                        .collect::<Vec<_>>();
                    vec![Statement::FunctionCallAssign {
                        bindings: renamed_bindings,
                        name: name.clone(),
                        args: args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?,
                        span: *span,
                        name_span: *name_span,
                    }]
                }
            }
            Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => vec![Statement::StateFunctionCallAssign {
                bindings: bindings
                    .iter()
                    .map(|binding| {
                        let fresh = scope.entry(binding.name.clone()).or_insert_with(|| self.fresh_name(&binding.name)).clone();
                        StateBindingAst { name: fresh, ..binding.clone() }
                    })
                    .collect(),
                name: name.clone(),
                args: args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
                name_span: *name_span,
            }],
            Statement::StructDestructure { bindings, expr, span } => vec![Statement::StructDestructure {
                bindings: bindings
                    .iter()
                    .map(|binding| {
                        let fresh = scope.entry(binding.name.clone()).or_insert_with(|| self.fresh_name(&binding.name)).clone();
                        StateBindingAst { name: fresh, ..binding.clone() }
                    })
                    .collect(),
                expr: self.rename_expr(expr, scope)?,
                span: *span,
            }],
            Statement::Assign { name, expr, span, name_span } => vec![Statement::Assign {
                name: self.rename_name(name, scope),
                expr: self.rename_expr(expr, scope)?,
                span: *span,
                name_span: *name_span,
            }],
            Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => vec![Statement::TimeOp {
                tx_var: *tx_var,
                expr: self.rename_expr(expr, scope)?,
                message: message.clone(),
                span: *span,
                tx_var_span: *tx_var_span,
                message_span: *message_span,
            }],
            Statement::Require { expr, message, span, message_span } => vec![Statement::Require {
                expr: self.rename_expr(expr, scope)?,
                message: message.clone(),
                span: *span,
                message_span: *message_span,
            }],
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
                let renamed_condition = self.rename_expr(condition, scope)?;
                let mut then_scope = scope.clone();
                self.predeclare_branch_bindings(then_branch, &mut then_scope);
                let lowered_then = self.lower_block(then_branch, &mut then_scope, function_index)?;

                let (lowered_else, merged_scope) = if let Some(else_branch) = else_branch {
                    let mut else_scope = scope.clone();
                    self.predeclare_branch_bindings(else_branch, &mut else_scope);
                    let lowered_else = self.lower_block(else_branch, &mut else_scope, function_index)?;
                    let mut merged_scope = then_scope;
                    merged_scope.extend(else_scope);
                    (Some(lowered_else), merged_scope)
                } else {
                    (None, then_scope)
                };
                *scope = merged_scope;
                vec![Statement::If {
                    condition: renamed_condition,
                    then_branch: lowered_then,
                    else_branch: lowered_else,
                    span: *span,
                    then_span: *then_span,
                    else_span: *else_span,
                }]
            }
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                let mut body_scope = scope.clone();
                body_scope.insert(ident.clone(), self.fresh_name(ident));
                let lowered_body = self.lower_block(body, &mut body_scope, function_index)?;
                vec![Statement::For {
                    ident: body_scope.get(ident).cloned().expect("loop ident inserted"),
                    start: self.rename_expr(start, scope)?,
                    end: self.rename_expr(end, scope)?,
                    max_iterations: self.rename_expr(max_iterations, scope)?,
                    body: lowered_body,
                    span: *span,
                    ident_span: *ident_span,
                    body_span: *body_span,
                }]
            }
            Statement::Return { exprs, span } => vec![Statement::Return {
                exprs: exprs.iter().map(|expr| self.rename_expr(expr, scope)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
            }],
            Statement::Console { args, span } => vec![Statement::Console {
                args: args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?,
                span: *span,
            }],
        })
    }

    fn inline_target(&self, name: &str) -> Option<FunctionAst<'i>> {
        self.functions.get(name).cloned().filter(|function| !function.entrypoint)
    }

    fn inline_call(
        &mut self,
        function: &FunctionAst<'i>,
        args: &[Expr<'i>],
        bindings: Option<&[ParamAst<'i>]>,
        caller_scope: &HashMap<String, String>,
        caller_index: usize,
        span: span::Span<'i>,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let callee_index = self
            .function_order
            .get(&function.name)
            .copied()
            .ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", function.name)))?;
        if callee_index >= caller_index {
            return Err(CompilerError::Unsupported("functions may only call earlier-defined functions".to_string()));
        }
        if function.params.len() != args.len() {
            return Err(CompilerError::Unsupported(format!("function '{}' expects {} arguments", function.name, function.params.len())));
        }

        let mut local_scope = HashMap::new();
        let mut lowered = Vec::new();
        for (param, arg) in function.params.iter().zip(args.iter()) {
            let fresh = self.fresh_name(&param.name);
            local_scope.insert(param.name.clone(), fresh.clone());
            lowered.push(Statement::VariableDefinition {
                type_ref: param.type_ref.clone(),
                modifiers: Vec::new(),
                name: fresh,
                expr: Some(self.rename_expr(arg, caller_scope)?),
                span,
                type_span: param.type_span,
                modifier_spans: Vec::new(),
                name_span: param.name_span,
            });
        }

        let body_len = function.body.len();
        for (index, statement) in function.body.iter().enumerate() {
            if let Statement::Return { exprs, .. } = statement {
                debug_assert_eq!(index, body_len - 1, "type_check must keep returns last");
                if let Some(bindings) = bindings {
                    for (binding, expr) in bindings.iter().zip(exprs.iter()) {
                        lowered.push(Statement::VariableDefinition {
                            type_ref: binding.type_ref.clone(),
                            modifiers: Vec::new(),
                            name: binding.name.clone(),
                            expr: Some(self.rename_expr(expr, &local_scope)?),
                            span: statement.span(),
                            type_span: binding.type_span,
                            modifier_spans: Vec::new(),
                            name_span: binding.name_span,
                        });
                    }
                }
            } else {
                lowered.extend(self.lower_statement(statement, &mut local_scope, callee_index)?);
            }
        }
        Ok(lowered)
    }

    fn rename_name(&self, name: &str, scope: &HashMap<String, String>) -> String {
        scope.get(name).cloned().unwrap_or_else(|| name.to_string())
    }

    fn rename_expr(&mut self, expr: &Expr<'i>, scope: &HashMap<String, String>) -> Result<Expr<'i>, CompilerError> {
        let span = expr.span;
        Ok(Expr::new(
            match &expr.kind {
                ExprKind::Int(value) => ExprKind::Int(*value),
                ExprKind::Bool(value) => ExprKind::Bool(*value),
                ExprKind::Byte(value) => ExprKind::Byte(*value),
                ExprKind::String(value) => ExprKind::String(value.clone()),
                ExprKind::DateLiteral(value) => ExprKind::DateLiteral(*value),
                ExprKind::Identifier(name) => ExprKind::Identifier(self.rename_name(name, scope)),
                ExprKind::Array(values) => {
                    ExprKind::Array(values.iter().map(|value| self.rename_expr(value, scope)).collect::<Result<Vec<_>, _>>()?)
                }
                ExprKind::Call { name, args, name_span } => ExprKind::Call {
                    name: name.clone(),
                    args: args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?,
                    name_span: *name_span,
                },
                ExprKind::New { name, args, name_span } => ExprKind::New {
                    name: name.clone(),
                    args: args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?,
                    name_span: *name_span,
                },
                ExprKind::Split { source, index, part, span } => ExprKind::Split {
                    source: Box::new(self.rename_expr(source, scope)?),
                    index: Box::new(self.rename_expr(index, scope)?),
                    part: *part,
                    span: *span,
                },
                ExprKind::Slice { source, start, end, span } => ExprKind::Slice {
                    source: Box::new(self.rename_expr(source, scope)?),
                    start: Box::new(self.rename_expr(start, scope)?),
                    end: Box::new(self.rename_expr(end, scope)?),
                    span: *span,
                },
                ExprKind::ArrayIndex { source, index } => ExprKind::ArrayIndex {
                    source: Box::new(self.rename_expr(source, scope)?),
                    index: Box::new(self.rename_expr(index, scope)?),
                },
                ExprKind::Unary { op, expr } => ExprKind::Unary { op: *op, expr: Box::new(self.rename_expr(expr, scope)?) },
                ExprKind::Binary { op, left, right } => ExprKind::Binary {
                    op: *op,
                    left: Box::new(self.rename_expr(left, scope)?),
                    right: Box::new(self.rename_expr(right, scope)?),
                },
                ExprKind::IfElse { condition, then_expr, else_expr } => ExprKind::IfElse {
                    condition: Box::new(self.rename_expr(condition, scope)?),
                    then_expr: Box::new(self.rename_expr(then_expr, scope)?),
                    else_expr: Box::new(self.rename_expr(else_expr, scope)?),
                },
                ExprKind::Nullary(op) => ExprKind::Nullary(*op),
                ExprKind::Introspection { kind, index, field_span } => ExprKind::Introspection {
                    kind: *kind,
                    index: Box::new(self.rename_expr(index, scope)?),
                    field_span: *field_span,
                },
                ExprKind::StateObject(fields) => ExprKind::StateObject(
                    fields
                        .iter()
                        .map(|field| {
                            Ok(StateFieldExpr {
                                name: field.name.clone(),
                                expr: self.rename_expr(&field.expr, scope)?,
                                span: field.span,
                                name_span: field.name_span,
                            })
                        })
                        .collect::<Result<Vec<_>, CompilerError>>()?,
                ),
                ExprKind::FieldAccess { source, field, field_span } => ExprKind::FieldAccess {
                    source: Box::new(self.rename_expr(source, scope)?),
                    field: field.clone(),
                    field_span: *field_span,
                },
                ExprKind::NumberWithUnit { value, unit } => ExprKind::NumberWithUnit { value: *value, unit: unit.clone() },
                ExprKind::UnarySuffix { source, kind, span } => ExprKind::UnarySuffix {
                    source: Box::new(self.rename_expr(source, scope)?),
                    kind: *kind,
                    span: *span,
                },
            },
            span,
        ))
    }
}
