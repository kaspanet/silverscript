use std::collections::HashMap;

use crate::debug_info::SourceSpan;

use super::*;

pub(crate) const INLINE_LOCAL_PREFIX: &str = "__inline";

pub(super) fn lower_inline_functions<'i>(
    contract: &ContractAst<'i>,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions = contract.functions.iter().cloned().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let function_order =
        contract.functions.iter().enumerate().map(|(index, function)| (function.name.clone(), index)).collect::<HashMap<_, _>>();
    let mut inliner = Inliner { functions, function_order, fresh_counter: 0, inline_depth: 0, debug_recorder };

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

struct Inliner<'i, 'd> {
    functions: HashMap<String, FunctionAst<'i>>,
    function_order: HashMap<String, usize>,
    fresh_counter: usize,
    inline_depth: usize,
    debug_recorder: &'d mut DebugRecorder<'i>,
}

impl<'i, 'd> Inliner<'i, 'd> {
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
        self.debug_recorder.begin_source_function(&function.name);
        let body = self.lower_block(&function.body, &mut scope, function_index)?;
        self.debug_recorder.finish_source_function();
        Ok(FunctionAst { body, ..function.clone() })
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

    fn bind_visible_name(&mut self, source_name: &str, scope: &mut HashMap<String, String>) -> String {
        if let Some(existing) = scope.get(source_name) {
            return existing.clone();
        }

        let lowered_name = if self.inline_depth == 0 {
            source_name.to_string()
        } else {
            let fresh = self.fresh_name(source_name);
            self.debug_recorder.record_visible_name(&fresh, source_name);
            fresh
        };
        scope.insert(source_name.to_string(), lowered_name.clone());
        lowered_name
    }

    fn predeclare_branch_bindings(&mut self, statements: &[Statement<'i>], scope: &mut HashMap<String, String>) {
        for statement in statements {
            match statement {
                Statement::VariableDefinition { name, .. } => {
                    self.bind_visible_name(name, scope);
                }
                Statement::TupleAssignment { left_name, right_name, .. } => {
                    self.bind_visible_name(left_name, scope);
                    self.bind_visible_name(right_name, scope);
                }
                Statement::FunctionCallAssign { bindings, .. } => {
                    for binding in bindings {
                        self.bind_visible_name(&binding.name, scope);
                    }
                }
                Statement::StateFunctionCallAssign { bindings, .. } | Statement::StructDestructure { bindings, .. } => {
                    for binding in bindings {
                        self.bind_visible_name(&binding.name, scope);
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
        let mut lowered = Vec::new();
        match statement {
            Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
                let fresh = self.bind_visible_name(name, scope);
                let renamed_expr = expr.as_ref().map(|expr| self.rename_expr(expr, scope)).transpose()?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::VariableDefinition {
                        type_ref: type_ref.clone(),
                        modifiers: modifiers.clone(),
                        name: fresh,
                        expr: renamed_expr,
                        span: *span,
                        type_span: *type_span,
                        modifier_spans: modifier_spans.clone(),
                        name_span: *name_span,
                    },
                );
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
                let left_fresh = self.bind_visible_name(left_name, scope);
                let right_fresh = self.bind_visible_name(right_name, scope);
                let renamed_expr = self.rename_expr(expr, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::TupleAssignment {
                        left_type_ref: left_type_ref.clone(),
                        left_name: left_fresh,
                        right_type_ref: right_type_ref.clone(),
                        right_name: right_fresh,
                        expr: renamed_expr,
                        span: *span,
                        left_type_span: *left_type_span,
                        left_name_span: *left_name_span,
                        right_type_span: *right_type_span,
                        right_name_span: *right_name_span,
                    },
                );
            }
            Statement::ArrayPush { name, expr, span, name_span } => {
                let renamed_expr = self.rename_expr(expr, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::ArrayPush {
                        name: self.rename_name(name, scope),
                        expr: renamed_expr,
                        span: *span,
                        name_span: *name_span,
                    },
                );
            }
            Statement::Block { body, span } => {
                let mut block_scope = scope.clone();
                let lowered_body = self.lower_block(body, &mut block_scope, function_index)?;
                self.push_lowered_statement(&mut lowered, Statement::Block { body: lowered_body, span: *span });
            }
            Statement::FunctionCall { name, args, span, name_span } => {
                if let Some(function) = self.inline_target(name) {
                    lowered.extend(self.inline_call(&function, args, None, scope, function_index, *span)?);
                } else {
                    let renamed_args = args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?;
                    self.push_lowered_statement(
                        &mut lowered,
                        Statement::FunctionCall { name: name.clone(), args: renamed_args, span: *span, name_span: *name_span },
                    );
                }
            }
            Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
                if let Some(function) = self.inline_target(name) {
                    let renamed_bindings = bindings
                        .iter()
                        .map(|binding| {
                            let fresh = self.bind_visible_name(&binding.name, scope);
                            ParamAst { name: fresh, ..binding.clone() }
                        })
                        .collect::<Vec<_>>();
                    lowered.extend(self.inline_call(&function, args, Some(&renamed_bindings), scope, function_index, *span)?);
                } else {
                    let renamed_bindings = bindings
                        .iter()
                        .map(|binding| {
                            let fresh = self.bind_visible_name(&binding.name, scope);
                            ParamAst { name: fresh, ..binding.clone() }
                        })
                        .collect::<Vec<_>>();
                    let renamed_args = args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?;
                    self.push_lowered_statement(
                        &mut lowered,
                        Statement::FunctionCallAssign {
                            bindings: renamed_bindings,
                            name: name.clone(),
                            args: renamed_args,
                            span: *span,
                            name_span: *name_span,
                        },
                    );
                }
            }
            Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => {
                let renamed_bindings = bindings
                    .iter()
                    .map(|binding| {
                        let fresh = self.bind_visible_name(&binding.name, scope);
                        StateBindingAst { name: fresh, ..binding.clone() }
                    })
                    .collect();
                let renamed_args = args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::StateFunctionCallAssign {
                        bindings: renamed_bindings,
                        name: name.clone(),
                        args: renamed_args,
                        span: *span,
                        name_span: *name_span,
                    },
                );
            }
            Statement::StructDestructure { bindings, expr, span } => {
                let renamed_bindings = bindings
                    .iter()
                    .map(|binding| {
                        let fresh = self.bind_visible_name(&binding.name, scope);
                        StateBindingAst { name: fresh, ..binding.clone() }
                    })
                    .collect();
                let renamed_expr = self.rename_expr(expr, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::StructDestructure { bindings: renamed_bindings, expr: renamed_expr, span: *span },
                );
            }
            Statement::Assign { name, expr, span, name_span } => {
                let renamed_expr = self.rename_expr(expr, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::Assign { name: self.rename_name(name, scope), expr: renamed_expr, span: *span, name_span: *name_span },
                );
            }
            Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => {
                let renamed_expr = self.rename_expr(expr, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::TimeOp {
                        tx_var: *tx_var,
                        expr: renamed_expr,
                        message: message.clone(),
                        span: *span,
                        tx_var_span: *tx_var_span,
                        message_span: *message_span,
                    },
                );
            }
            Statement::Require { expr, message, span, message_span } => {
                let renamed_expr = self.rename_expr(expr, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::Require { expr: renamed_expr, message: message.clone(), span: *span, message_span: *message_span },
                );
            }
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
                let renamed_condition = self.rename_expr(condition, scope)?;
                let mut then_scope = scope.clone();
                self.predeclare_branch_bindings(then_branch, &mut then_scope);
                let lowered_then = self.lower_block(then_branch, &mut then_scope, function_index)?;

                let lowered_else = if let Some(else_branch) = else_branch {
                    let mut else_scope = scope.clone();
                    self.predeclare_branch_bindings(else_branch, &mut else_scope);
                    Some(self.lower_block(else_branch, &mut else_scope, function_index)?)
                } else {
                    None
                };
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::If {
                        condition: renamed_condition,
                        then_branch: lowered_then,
                        else_branch: lowered_else,
                        span: *span,
                        then_span: *then_span,
                        else_span: *else_span,
                    },
                );
            }
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                let mut body_scope = scope.clone();
                let lowered_ident = self.bind_visible_name(ident, &mut body_scope);
                let lowered_body = self.lower_block(body, &mut body_scope, function_index)?;
                let lowered_start = self.rename_expr(start, scope)?;
                let lowered_end = self.rename_expr(end, scope)?;
                let lowered_max_iterations = self.rename_expr(max_iterations, scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::For {
                        ident: lowered_ident,
                        start: lowered_start,
                        end: lowered_end,
                        max_iterations: lowered_max_iterations,
                        body: lowered_body,
                        span: *span,
                        ident_span: *ident_span,
                        body_span: *body_span,
                    },
                );
            }
            Statement::Return { exprs, span } => {
                let renamed_exprs = exprs.iter().map(|expr| self.rename_expr(expr, scope)).collect::<Result<Vec<_>, _>>()?;
                self.push_lowered_statement(&mut lowered, Statement::Return { exprs: renamed_exprs, span: *span });
            }
            Statement::Console { args, span } => {
                let renamed_args = args.iter().map(|arg| self.rename_expr(arg, scope)).collect::<Result<Vec<_>, _>>()?;
                self.push_lowered_statement(&mut lowered, Statement::Console { args: renamed_args, span: *span });
            }
        }
        Ok(lowered)
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
            return Err(CompilerError::Unsupported(format!(
                "function '{}' expects {} arguments",
                function.name,
                function.params.len()
            )));
        }

        let mut local_scope = HashMap::new();
        let mut lowered = Vec::new();
        self.debug_recorder.begin_inline_source_call(&function.name, SourceSpan::from(span));
        self.inline_depth = self.inline_depth.saturating_add(1);
        for (param, arg) in function.params.iter().zip(args.iter()) {
            let fresh = self.bind_visible_name(&param.name, &mut local_scope);
            let renamed_arg = self.rename_expr(arg, caller_scope)?;
            self.debug_recorder.record_inline_source_param(&param.name, &param.type_ref, renamed_arg.clone());
            self.push_lowered_statement(
                &mut lowered,
                Statement::VariableDefinition {
                    type_ref: param.type_ref.clone(),
                    modifiers: Vec::new(),
                    name: fresh,
                    expr: Some(renamed_arg),
                    span,
                    type_span: param.type_span,
                    modifier_spans: Vec::new(),
                    name_span: param.name_span,
                },
            );
        }

        let (callee_body, return_exprs) = match function.body.split_last() {
            Some((Statement::Return { exprs, .. }, body)) => (body, Some(exprs.as_slice())),
            Some((_last, _body)) => (function.body.as_slice(), None),
            None => (&[][..], None),
        };

        for statement in callee_body {
            lowered.extend(self.lower_statement(statement, &mut local_scope, callee_index)?);
        }
        let body_end_statement_index = self.debug_recorder.current_source_statement_index();

        if let (Some(bindings), Some(return_exprs)) = (bindings, return_exprs) {
            for (binding, expr) in bindings.iter().zip(return_exprs.iter()) {
                let renamed_expr = self.rename_expr(expr, &local_scope)?;
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::VariableDefinition {
                        type_ref: binding.type_ref.clone(),
                        modifiers: Vec::new(),
                        name: binding.name.clone(),
                        expr: Some(renamed_expr),
                        span,
                        type_span: binding.type_span,
                        modifier_spans: Vec::new(),
                        name_span: binding.name_span,
                    },
                );
            }
        }
        self.debug_recorder.finish_inline_source_call(body_end_statement_index);
        self.inline_depth = self.inline_depth.saturating_sub(1);
        Ok(lowered)
    }

    fn push_lowered_statement(&mut self, lowered: &mut Vec<Statement<'i>>, statement: Statement<'i>) {
        self.debug_recorder.record_lowered_source_statement(&statement);
        lowered.push(statement);
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
                ExprKind::Introspection { kind, index, field_span } => {
                    ExprKind::Introspection { kind: *kind, index: Box::new(self.rename_expr(index, scope)?), field_span: *field_span }
                }
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
                ExprKind::UnarySuffix { source, kind, span } => {
                    ExprKind::UnarySuffix { source: Box::new(self.rename_expr(source, scope)?), kind: *kind, span: *span }
                }
            },
            span,
        ))
    }
}
