use std::collections::{HashMap, HashSet};

use crate::debug_info::SourceSpan;

use super::*;

const INLINE_LOCAL_PREFIX: &str = "__inline";

pub(super) fn lower_inline_functions<'i>(
    contract: &ContractAst<'i>,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions = contract
        .functions
        .iter()
        .filter(|function| !function.entrypoint)
        .cloned()
        .map(|function| (function.name.clone(), function))
        .collect::<HashMap<_, _>>();
    let mut inliner = Inliner { functions, fresh_counter: 0, debug_recorder };

    let lowered_functions = contract
        .functions
        .iter()
        .filter(|function| function.entrypoint)
        .map(|function| inliner.lower_entrypoint_function(function))
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
    fresh_counter: usize,
    debug_recorder: &'d mut DebugRecorder<'i>,
}

impl<'i, 'd> Inliner<'i, 'd> {
    fn fresh_name(&mut self, base: &str) -> String {
        let name = format!("{}_{}_{}", INLINE_LOCAL_PREFIX, self.fresh_counter, base);
        self.fresh_counter += 1;
        name
    }

    fn lower_entrypoint_function(&mut self, function: &FunctionAst<'i>) -> Result<FunctionAst<'i>, CompilerError> {
        let mut scope = HashMap::new();
        for param in &function.params {
            scope.insert(param.name.clone(), param.name.clone());
        }
        self.debug_recorder.begin_source_function(&function.name);
        let mut visited_functions = HashSet::new();
        let body = self.lower_block(&function.body, &mut scope, &mut visited_functions)?;
        self.debug_recorder.finish_source_function();
        Ok(FunctionAst { body, ..function.clone() })
    }

    fn lower_block(
        &mut self,
        statements: &[Statement<'i>],
        scope: &mut HashMap<String, String>,
        visited_functions: &mut HashSet<String>,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let mut lowered = Vec::new();
        for statement in statements {
            lowered.extend(self.lower_statement(statement, scope, visited_functions)?);
        }
        Ok(lowered)
    }

    fn bind_visible_name(&mut self, source_name: &str, scope: &mut HashMap<String, String>) -> String {
        scope
            .entry(source_name.to_string())
            .or_insert_with(|| {
                let fresh = self.fresh_name(source_name);
                self.debug_recorder.record_visible_name(&fresh, source_name);
                fresh
            })
            .clone()
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
        visited_functions: &mut HashSet<String>,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let mut lowered = Vec::new();
        match statement {
            Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
                let fresh = self.bind_visible_name(name, scope);
                let renamed_expr = if let Some(expr) = expr {
                    let (prelude, renamed_expr) = self.lower_expr(expr, scope, visited_functions)?;
                    lowered.extend(prelude);
                    Some(renamed_expr)
                } else {
                    None
                };
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
                let (prelude, renamed_expr) = self.lower_expr(expr, scope, visited_functions)?;
                lowered.extend(prelude);
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
            Statement::Block { body, span } => {
                let mut block_scope = scope.clone();
                let lowered_body = self.lower_block(body, &mut block_scope, visited_functions)?;
                self.push_lowered_statement(&mut lowered, Statement::Block { body: lowered_body, span: *span });
            }
            Statement::FunctionCall { name, args, span, name_span } => {
                if let Some(function) = self.inline_target(name) {
                    lowered.extend(self.inline_call(&function, args, None, scope, visited_functions, *span)?);
                } else {
                    let (prelude, renamed_args) = self.lower_exprs(args, scope, visited_functions)?;
                    lowered.extend(prelude);
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
                    lowered.extend(self.inline_call(&function, args, Some(&renamed_bindings), scope, visited_functions, *span)?);
                } else {
                    let renamed_bindings = bindings
                        .iter()
                        .map(|binding| {
                            let fresh = self.bind_visible_name(&binding.name, scope);
                            ParamAst { name: fresh, ..binding.clone() }
                        })
                        .collect::<Vec<_>>();
                    let (prelude, renamed_args) = self.lower_exprs(args, scope, visited_functions)?;
                    lowered.extend(prelude);
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
                let (prelude, renamed_args) = self.lower_exprs(args, scope, visited_functions)?;
                lowered.extend(prelude);
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
                let (prelude, renamed_expr) = self.lower_expr(expr, scope, visited_functions)?;
                lowered.extend(prelude);
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::StructDestructure { bindings: renamed_bindings, expr: renamed_expr, span: *span },
                );
            }
            Statement::Assign { name, expr, span, name_span } => {
                let (prelude, renamed_expr) = self.lower_expr(expr, scope, visited_functions)?;
                lowered.extend(prelude);
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::Assign { name: self.rename_name(name, scope), expr: renamed_expr, span: *span, name_span: *name_span },
                );
            }
            Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => {
                let (prelude, renamed_expr) = self.lower_expr(expr, scope, visited_functions)?;
                lowered.extend(prelude);
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
                let (prelude, renamed_expr) = self.lower_expr(expr, scope, visited_functions)?;
                lowered.extend(prelude);
                self.push_lowered_statement(
                    &mut lowered,
                    Statement::Require { expr: renamed_expr, message: message.clone(), span: *span, message_span: *message_span },
                );
            }
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
                let (prelude, renamed_condition) = self.lower_expr(condition, scope, visited_functions)?;
                lowered.extend(prelude);
                let mut then_scope = scope.clone();
                self.predeclare_branch_bindings(then_branch, &mut then_scope);
                let lowered_then = self.lower_block(then_branch, &mut then_scope, visited_functions)?;

                let lowered_else = if let Some(else_branch) = else_branch {
                    let mut else_scope = scope.clone();
                    self.predeclare_branch_bindings(else_branch, &mut else_scope);
                    Some(self.lower_block(else_branch, &mut else_scope, visited_functions)?)
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
                let lowered_body = self.lower_block(body, &mut body_scope, visited_functions)?;
                let (mut prelude, lowered_start) = self.lower_expr(start, scope, visited_functions)?;
                let (more_prelude, lowered_end) = self.lower_expr(end, scope, visited_functions)?;
                prelude.extend(more_prelude);
                let (more_prelude, lowered_max_iterations) = self.lower_expr(max_iterations, scope, visited_functions)?;
                prelude.extend(more_prelude);
                lowered.extend(prelude);
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
                let (prelude, renamed_exprs) = self.lower_exprs(exprs, scope, visited_functions)?;
                lowered.extend(prelude);
                self.push_lowered_statement(&mut lowered, Statement::Return { exprs: renamed_exprs, span: *span });
            }
            Statement::Console { args, span } => {
                let (prelude, renamed_args) = self.lower_exprs(args, scope, visited_functions)?;
                lowered.extend(prelude);
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
        visited_functions: &mut HashSet<String>,
        span: span::Span<'i>,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        if visited_functions.contains(&function.name) {
            return Err(CompilerError::Unsupported(format!("recursive function call: {}", function.name)));
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
        visited_functions.insert(function.name.clone());
        for (param, arg) in function.params.iter().zip(args.iter()) {
            let fresh = self.bind_visible_name(&param.name, &mut local_scope);
            let (prelude, renamed_arg) = self.lower_expr(arg, caller_scope, visited_functions)?;
            lowered.extend(prelude);
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

        let lowered_result = (|| -> Result<(), CompilerError> {
            for statement in callee_body {
                lowered.extend(self.lower_statement(statement, &mut local_scope, visited_functions)?);
            }

            if let (Some(bindings), Some(return_exprs)) = (bindings, return_exprs) {
                for (binding, expr) in bindings.iter().zip(return_exprs.iter()) {
                    let (prelude, renamed_expr) = self.lower_expr(expr, &local_scope, visited_functions)?;
                    lowered.extend(prelude);
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

            Ok(())
        })();
        let body_end_statement_index = self.debug_recorder.current_source_statement_index();
        visited_functions.remove(&function.name);
        lowered_result?;
        self.debug_recorder.finish_inline_source_call(body_end_statement_index);
        Ok(lowered)
    }

    fn lower_exprs(
        &mut self,
        exprs: &[Expr<'i>],
        scope: &HashMap<String, String>,
        visited_functions: &mut HashSet<String>,
    ) -> Result<(Vec<Statement<'i>>, Vec<Expr<'i>>), CompilerError> {
        let mut lowered_statements = Vec::new();
        let mut lowered_exprs = Vec::with_capacity(exprs.len());
        for expr in exprs {
            let (prelude, lowered_expr) = self.lower_expr(expr, scope, visited_functions)?;
            lowered_statements.extend(prelude);
            lowered_exprs.push(lowered_expr);
        }
        Ok((lowered_statements, lowered_exprs))
    }

    fn lower_expr(
        &mut self,
        expr: &Expr<'i>,
        scope: &HashMap<String, String>,
        visited_functions: &mut HashSet<String>,
    ) -> Result<(Vec<Statement<'i>>, Expr<'i>), CompilerError> {
        let span = expr.span;
        match &expr.kind {
            ExprKind::Int(value) => Ok((Vec::new(), Expr::new(ExprKind::Int(*value), span))),
            ExprKind::Bool(value) => Ok((Vec::new(), Expr::new(ExprKind::Bool(*value), span))),
            ExprKind::Byte(value) => Ok((Vec::new(), Expr::new(ExprKind::Byte(*value), span))),
            ExprKind::String(value) => Ok((Vec::new(), Expr::new(ExprKind::String(value.clone()), span))),
            ExprKind::DateLiteral(value) => Ok((Vec::new(), Expr::new(ExprKind::DateLiteral(*value), span))),
            ExprKind::Identifier(name) => Ok((Vec::new(), Expr::new(ExprKind::Identifier(self.rename_name(name, scope)), span))),
            ExprKind::Array(values) => {
                let (prelude, values) = self.lower_exprs(values, scope, visited_functions)?;
                Ok((prelude, Expr::new(ExprKind::Array(values), span)))
            }
            ExprKind::Call { name, args, name_span } => {
                let (mut prelude, args) = self.lower_exprs(args, scope, visited_functions)?;
                if let Some(function) = self.inline_target(name) {
                    if function.return_types.len() != 1 {
                        return Err(CompilerError::Unsupported(format!(
                            "function '{}' with multiple return values cannot be used in expressions",
                            function.name
                        )));
                    }
                    let temp_name = self.fresh_name(name);
                    let binding = ParamAst {
                        type_ref: function.return_types[0].clone(),
                        name: temp_name.clone(),
                        span,
                        type_span: *name_span,
                        name_span: *name_span,
                    };
                    prelude.extend(self.inline_call(&function, &args, Some(&[binding]), scope, visited_functions, span)?);
                    Ok((prelude, Expr::identifier(temp_name)))
                } else {
                    Ok((prelude, Expr::new(ExprKind::Call { name: name.clone(), args, name_span: *name_span }, span)))
                }
            }
            ExprKind::New { name, args, name_span } => {
                let (prelude, args) = self.lower_exprs(args, scope, visited_functions)?;
                Ok((prelude, Expr::new(ExprKind::New { name: name.clone(), args, name_span: *name_span }, span)))
            }
            ExprKind::Split { source, index, part, span: split_span } => {
                let (mut prelude, source) = self.lower_expr(source, scope, visited_functions)?;
                let (more_prelude, index) = self.lower_expr(index, scope, visited_functions)?;
                prelude.extend(more_prelude);
                Ok((
                    prelude,
                    Expr::new(
                        ExprKind::Split { source: Box::new(source), index: Box::new(index), part: *part, span: *split_span },
                        span,
                    ),
                ))
            }
            ExprKind::Slice { source, start, end, span: slice_span } => {
                let (mut prelude, source) = self.lower_expr(source, scope, visited_functions)?;
                let (more_prelude, start) = self.lower_expr(start, scope, visited_functions)?;
                prelude.extend(more_prelude);
                let (more_prelude, end) = self.lower_expr(end, scope, visited_functions)?;
                prelude.extend(more_prelude);
                Ok((
                    prelude,
                    Expr::new(
                        ExprKind::Slice { source: Box::new(source), start: Box::new(start), end: Box::new(end), span: *slice_span },
                        span,
                    ),
                ))
            }
            ExprKind::ArrayIndex { source, index } => {
                let (mut prelude, source) = self.lower_expr(source, scope, visited_functions)?;
                let (more_prelude, index) = self.lower_expr(index, scope, visited_functions)?;
                prelude.extend(more_prelude);
                Ok((prelude, Expr::new(ExprKind::ArrayIndex { source: Box::new(source), index: Box::new(index) }, span)))
            }
            ExprKind::Unary { op, expr } => {
                let (prelude, expr) = self.lower_expr(expr, scope, visited_functions)?;
                Ok((prelude, Expr::new(ExprKind::Unary { op: *op, expr: Box::new(expr) }, span)))
            }
            ExprKind::Binary { op, left, right } => {
                let (mut prelude, left) = self.lower_expr(left, scope, visited_functions)?;
                let (more_prelude, right) = self.lower_expr(right, scope, visited_functions)?;
                prelude.extend(more_prelude);
                Ok((prelude, Expr::new(ExprKind::Binary { op: *op, left: Box::new(left), right: Box::new(right) }, span)))
            }
            ExprKind::Append { source, args, span: append_span } => {
                let (mut prelude, source) = self.lower_expr(source, scope, visited_functions)?;
                let (more_prelude, args) = self.lower_exprs(args, scope, visited_functions)?;
                prelude.extend(more_prelude);
                Ok((prelude, Expr::new(ExprKind::Append { source: Box::new(source), args, span: *append_span }, span)))
            }
            ExprKind::IfElse { condition, then_expr, else_expr } => {
                let (mut prelude, condition) = self.lower_expr(condition, scope, visited_functions)?;
                let (more_prelude, then_expr) = self.lower_expr(then_expr, scope, visited_functions)?;
                prelude.extend(more_prelude);
                let (more_prelude, else_expr) = self.lower_expr(else_expr, scope, visited_functions)?;
                prelude.extend(more_prelude);
                Ok((
                    prelude,
                    Expr::new(
                        ExprKind::IfElse {
                            condition: Box::new(condition),
                            then_expr: Box::new(then_expr),
                            else_expr: Box::new(else_expr),
                        },
                        span,
                    ),
                ))
            }
            ExprKind::Nullary(op) => Ok((Vec::new(), Expr::new(ExprKind::Nullary(*op), span))),
            ExprKind::Introspection { kind, index, field_span } => {
                let (prelude, index) = self.lower_expr(index, scope, visited_functions)?;
                Ok((
                    prelude,
                    Expr::new(ExprKind::Introspection { kind: *kind, index: Box::new(index), field_span: *field_span }, span),
                ))
            }
            ExprKind::StateObject(fields) => {
                let mut prelude = Vec::new();
                let mut lowered_fields = Vec::with_capacity(fields.len());
                for field in fields {
                    let (field_prelude, expr) = self.lower_expr(&field.expr, scope, visited_functions)?;
                    prelude.extend(field_prelude);
                    lowered_fields.push(StateFieldExpr {
                        name: field.name.clone(),
                        expr,
                        span: field.span,
                        name_span: field.name_span,
                    });
                }
                Ok((prelude, Expr::new(ExprKind::StateObject(lowered_fields), span)))
            }
            ExprKind::FieldAccess { source, field, field_span } => {
                let (prelude, source) = self.lower_expr(source, scope, visited_functions)?;
                Ok((
                    prelude,
                    Expr::new(ExprKind::FieldAccess { source: Box::new(source), field: field.clone(), field_span: *field_span }, span),
                ))
            }
            ExprKind::NumberWithUnit { value, unit } => {
                Ok((Vec::new(), Expr::new(ExprKind::NumberWithUnit { value: *value, unit: unit.clone() }, span)))
            }
            ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
                let (prelude, source) = self.lower_expr(source, scope, visited_functions)?;
                Ok((prelude, Expr::new(ExprKind::UnarySuffix { source: Box::new(source), kind: *kind, span: *suffix_span }, span)))
            }
        }
    }

    fn push_lowered_statement(&mut self, lowered: &mut Vec<Statement<'i>>, statement: Statement<'i>) {
        self.debug_recorder.record_lowered_source_statement(&statement);
        lowered.push(statement);
    }

    fn rename_name(&self, name: &str, scope: &HashMap<String, String>) -> String {
        scope.get(name).cloned().unwrap_or_else(|| name.to_string())
    }
}
