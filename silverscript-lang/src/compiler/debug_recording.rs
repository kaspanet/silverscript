use std::collections::HashMap;

use crate::ast::{ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, ParamAst, StateBindingAst, StateFieldExpr, Statement};
use crate::debug_info::{
    DebugFunctionRange, DebugInfo, DebugInfoRecorder, DebugLeafBinding, DebugNamedValue, DebugParamBinding, DebugParamMapping,
    DebugStackBinding, DebugStep, DebugVariableUpdate, SourceSpan, StepKind,
};

use super::stack_bindings::StackBindings;
use super::{
    CompilerError, StructRegistry, flatten_type_ref_leaves, struct_array_name_from_type_ref, struct_name_from_type_ref,
    type_name_from_ref,
};

/// High-level compiler/debug bridge.
///
/// This intentionally keeps the compiler-facing API small:
/// - record contract-scoped debug state once from the pre-lowering contract
/// - stage entrypoints once per compiled entrypoint script
/// - set final bytecode starts after the full contract script is assembled
/// - finalize into `DebugInfo`
///
/// The detailed source-step recorder will be built behind this facade in later
/// steps without forcing more compiler call sites.
#[derive(Debug, Default)]
pub(crate) struct DebugRecorder<'i> {
    active: Option<ActiveDebugRecorder<'i>>,
}

impl<'i> DebugRecorder<'i> {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { active: if enabled { Some(ActiveDebugRecorder::default()) } else { None } }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.active.is_some()
    }

    pub(crate) fn record_contract_scope(&mut self, contract: &ContractAst<'i>, constructor_args: &[Expr<'i>]) {
        let Some(active) = self.active.as_mut() else {
            return;
        };

        active.reset_iteration();

        for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
            active.recorder.record_constructor_arg(DebugNamedValue {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                value: value.clone(),
            });
        }

        for constant in &contract.constants {
            active.recorder.record_constant(DebugNamedValue {
                name: constant.name.clone(),
                type_name: constant.type_ref.type_name(),
                value: constant.expr.clone(),
            });
        }
    }

    pub(super) fn stage_source_functions(&mut self, contract: &ContractAst<'i>) -> Result<(), CompilerError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        active.source_params_by_function =
            contract.functions.iter().map(|function| (function.name.clone(), function.params.clone())).collect();
        Ok(())
    }

    pub(super) fn begin_source_function(&mut self, function_name: &str) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        active.active_source_function_name = Some(function_name.to_string());
        active.active_source_inline_frames.clear();
        active.next_source_frame_id = 1;
        active.inline_frame_plans_by_function.remove(function_name);
    }

    pub(super) fn finish_source_function(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        debug_assert!(active.active_source_inline_frames.is_empty(), "source function ended with unclosed inline frames");
        active.active_source_function_name = None;
        active.active_source_inline_frames.clear();
        active.next_source_frame_id = 1;
    }

    pub(super) fn record_visible_name(&mut self, lowered_name: &str, visible_name: &str) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let Some(function_name) = active.active_source_function_name.as_deref() else {
            return;
        };
        active
            .visible_names_by_function
            .entry(function_name.to_string())
            .or_default()
            .insert(lowered_name.to_string(), visible_name.to_string());
    }

    pub(super) fn begin_inline_source_call(&mut self, callee: &str, call_site_span: SourceSpan, start_statement_index: usize) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.active_source_function_name.is_none() {
            return;
        }
        let frame_depth = active.active_source_inline_frames.last().map(|frame| frame.frame_depth.saturating_add(1)).unwrap_or(1);
        let frame_id = active.next_source_frame_id;
        active.next_source_frame_id = active.next_source_frame_id.saturating_add(1);
        active.active_source_inline_frames.push(PendingInlineFrame {
            callee: callee.to_string(),
            call_site_span,
            frame_id,
            frame_depth,
            start_statement_index,
            param_updates: Vec::new(),
        });
    }

    pub(super) fn record_inline_source_param(&mut self, name: &str, type_name: &str, expr: Expr<'i>) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let rewritten_expr = active
            .active_source_function_name
            .as_deref()
            .map(|function_name| rewrite_debug_expr_with_function(expr.clone(), function_name, &active.visible_names_by_function))
            .unwrap_or(expr);
        let Some(frame) = active.active_source_inline_frames.last_mut() else {
            return;
        };
        frame.param_updates.push(DebugVariableUpdate {
            name: name.to_string(),
            type_name: type_name.to_string(),
            stack_binding: None,
            structured_leaf_bindings: None,
            expr: rewritten_expr,
        });
    }

    pub(super) fn finish_inline_source_call(&mut self, body_end_statement_index: usize, resume_statement_index: usize) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let Some(function_name) = active.active_source_function_name.as_deref() else {
            return;
        };
        let Some(frame) = active.active_source_inline_frames.pop() else {
            return;
        };
        if body_end_statement_index <= frame.start_statement_index {
            return;
        }
        active.inline_frame_plans_by_function.entry(function_name.to_string()).or_default().push(InlineFramePlan {
            callee: frame.callee,
            call_site_span: frame.call_site_span,
            frame_id: frame.frame_id,
            frame_depth: frame.frame_depth,
            start_statement_index: frame.start_statement_index,
            param_updates: frame.param_updates,
            body_end_statement_index,
            resume_statement_index,
        });
    }

    pub(crate) fn visible_name(&self, lowered_name: &str) -> String {
        let Some(active) = self.active.as_ref() else {
            return lowered_name.to_string();
        };
        let Some(function_name) = active.active_function_name.as_deref() else {
            return lowered_name.to_string();
        };
        if let Some(spec) = active.structured_leaf_specs_by_function.get(function_name).and_then(|specs| specs.get(lowered_name)) {
            return flattened_struct_field_name(&spec.visible_base_name, &spec.field_path);
        }
        active
            .visible_names_by_function
            .get(function_name)
            .and_then(|names| names.get(lowered_name))
            .cloned()
            .unwrap_or_else(|| lowered_name.to_string())
    }

    pub(crate) fn rewrite_debug_expr(&self, expr: Expr<'i>) -> Expr<'i> {
        let span = expr.span;
        let kind = match expr.kind {
            ExprKind::Identifier(name) => ExprKind::Identifier(self.visible_name(&name)),
            ExprKind::Array(values) => ExprKind::Array(values.into_iter().map(|value| self.rewrite_debug_expr(value)).collect()),
            ExprKind::Call { name, args, name_span } => {
                ExprKind::Call { name, args: args.into_iter().map(|arg| self.rewrite_debug_expr(arg)).collect(), name_span }
            }
            ExprKind::New { name, args, name_span } => {
                ExprKind::New { name, args: args.into_iter().map(|arg| self.rewrite_debug_expr(arg)).collect(), name_span }
            }
            ExprKind::Split { source, index, part, span } => ExprKind::Split {
                source: Box::new(self.rewrite_debug_expr(*source)),
                index: Box::new(self.rewrite_debug_expr(*index)),
                part,
                span,
            },
            ExprKind::Slice { source, start, end, span } => ExprKind::Slice {
                source: Box::new(self.rewrite_debug_expr(*source)),
                start: Box::new(self.rewrite_debug_expr(*start)),
                end: Box::new(self.rewrite_debug_expr(*end)),
                span,
            },
            ExprKind::ArrayIndex { source, index } => ExprKind::ArrayIndex {
                source: Box::new(self.rewrite_debug_expr(*source)),
                index: Box::new(self.rewrite_debug_expr(*index)),
            },
            ExprKind::Unary { op, expr } => ExprKind::Unary { op, expr: Box::new(self.rewrite_debug_expr(*expr)) },
            ExprKind::Binary { op, left, right } => ExprKind::Binary {
                op,
                left: Box::new(self.rewrite_debug_expr(*left)),
                right: Box::new(self.rewrite_debug_expr(*right)),
            },
            ExprKind::IfElse { condition, then_expr, else_expr } => ExprKind::IfElse {
                condition: Box::new(self.rewrite_debug_expr(*condition)),
                then_expr: Box::new(self.rewrite_debug_expr(*then_expr)),
                else_expr: Box::new(self.rewrite_debug_expr(*else_expr)),
            },
            ExprKind::Introspection { kind, index, field_span } => {
                ExprKind::Introspection { kind, index: Box::new(self.rewrite_debug_expr(*index)), field_span }
            }
            ExprKind::StateObject(fields) => ExprKind::StateObject(
                fields
                    .into_iter()
                    .map(|field| StateFieldExpr {
                        name: field.name,
                        expr: self.rewrite_debug_expr(field.expr),
                        span: field.span,
                        name_span: field.name_span,
                    })
                    .collect(),
            ),
            ExprKind::FieldAccess { source, field, field_span } => {
                ExprKind::FieldAccess { source: Box::new(self.rewrite_debug_expr(*source)), field, field_span }
            }
            ExprKind::UnarySuffix { source, kind, span } => {
                ExprKind::UnarySuffix { source: Box::new(self.rewrite_debug_expr(*source)), kind, span }
            }
            other => other,
        };
        Expr::new(kind, span)
    }

    pub(crate) fn begin_entrypoint(
        &mut self,
        function: &FunctionAst<'i>,
        contract_fields: &[ContractFieldAst<'i>],
        structs: &StructRegistry,
    ) -> Result<(), CompilerError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };

        debug_assert!(active.active_entrypoint.is_none(), "begin_entrypoint called while another entrypoint is active");
        let visible_names = active.visible_names_by_function.get(&function.name);
        let structured_leaf_specs = build_structured_leaf_specs_for_function(function, structs, visible_names)?;
        active.structured_leaf_specs_by_function.insert(function.name.clone(), structured_leaf_specs);
        active.entrypoints.push(StagedEntrypointDebug {
            name: function.name.clone(),
            script_len: 0,
            bytecode_start: None,
            params: build_param_mappings(
                function,
                active.source_params_by_function.get(&function.name).map(Vec::as_slice),
                contract_fields,
                structs,
            )?,
            steps: Vec::new(),
            next_step_sequence: 0,
            next_statement_index: 0,
            statement_index_by_path: HashMap::new(),
            frame_plans: active.inline_frame_plans_by_function.get(&function.name).cloned().unwrap_or_default(),
        });
        active.active_entrypoint = Some(active.entrypoints.len().saturating_sub(1));
        active.active_function_name = Some(function.name.clone());
        active.statement_debug_state_stack.clear();
        active.pending_statement_debug_states.clear();
        Ok(())
    }

    pub(crate) fn begin_statement_at(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_start: usize,
        _before_types: &HashMap<String, String>,
        _before_stack_bindings: &StackBindings,
    ) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let depth = active.statement_debug_state_stack.len();
        active.flush_pending_statement_slots_from_depth(depth.saturating_add(1));

        let span = SourceSpan::from(stmt.span());
        let (slot, is_new_slot) = if let Some(pending) = active.take_pending_statement_slot(depth) {
            if pending.span == span {
                let mut continued = pending;
                continued.continued_across_siblings = true;
                (continued, false)
            } else {
                active.flush_statement_slot(pending);
                (active.start_statement_slot(stmt, bytecode_start), true)
            }
        } else {
            (active.start_statement_slot(stmt, bytecode_start), true)
        };

        if is_new_slot {
            if let Some(entrypoint) = active.active_entrypoint_mut() {
                entrypoint.emit_inline_call_resumes(slot.statement_index, bytecode_start);
                entrypoint.emit_inline_call_enters(slot.statement_index, bytecode_start);
            }
        }
        active.statement_debug_state_stack.push(slot);
    }

    pub(crate) fn record_current_statement_source_step_at(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_end: usize,
        after_types: &HashMap<String, String>,
        after_stack_bindings: &StackBindings,
    ) {
        if !should_record_source_step(stmt) {
            return;
        }

        let current_updates =
            collect_variable_updates(self, stmt, &HashMap::new(), &StackBindings::default(), after_types, after_stack_bindings);
        let current_console_args = collect_console_args(self, stmt);

        let Some((bytecode_start, statement_index, already_recorded, accumulated_updates, accumulated_console_args)) =
            self.active.as_ref().and_then(|active| active.statement_debug_state_stack.last()).map(|state| {
                (
                    state.bytecode_start,
                    state.statement_index,
                    state.source_step_recorded,
                    state.variable_updates.clone(),
                    state.console_args.clone(),
                )
            })
        else {
            return;
        };
        if already_recorded {
            return;
        }

        let mut variable_updates = accumulated_updates;
        merge_debug_variable_updates(&mut variable_updates, current_updates);
        let mut console_args = accumulated_console_args;
        console_args.extend(current_console_args);

        let Some(active) = self.active.as_mut() else {
            return;
        };
        if let Some(state) = active.statement_debug_state_stack.last_mut() {
            state.source_step_recorded = true;
        }
        let Some(entrypoint) = active.active_entrypoint_mut() else {
            return;
        };
        let (call_depth, frame_id) = entrypoint.current_frame_context(statement_index);
        entrypoint.record_step(DebugStep {
            bytecode_start,
            bytecode_end,
            span: SourceSpan::from(stmt.span()),
            kind: StepKind::Source {},
            sequence: 0,
            call_depth,
            frame_id,
            variable_updates,
            console_args,
        });
    }

    pub(crate) fn finish_statement_at(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_end: usize,
        after_types: &HashMap<String, String>,
        after_stack_bindings: &StackBindings,
    ) {
        let current_updates =
            collect_variable_updates(self, stmt, &HashMap::new(), &StackBindings::default(), after_types, after_stack_bindings);
        let current_console_args = collect_console_args(self, stmt);

        if let Some(active) = self.active.as_mut()
            && let Some(state) = active.statement_debug_state_stack.last_mut()
        {
            merge_debug_variable_updates(&mut state.variable_updates, current_updates);
            state.console_args.extend(current_console_args);
            state.bytecode_end = bytecode_end;
            state.records_source_step |= should_record_source_step(stmt);
        }

        let Some(active) = self.active.as_mut() else {
            return;
        };
        let Some(state) = active.statement_debug_state_stack.pop() else {
            return;
        };
        let depth = active.statement_debug_state_stack.len();
        active.flush_pending_statement_slots_from_depth(depth.saturating_add(1));
        active.store_pending_statement_slot(depth, state);
    }

    pub(crate) fn finish_entrypoint(&mut self, script_len: usize) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        active.flush_pending_statement_slots_from_depth(0);
        let Some(index) = active.active_entrypoint.take() else {
            return;
        };
        if let Some(entrypoint) = active.entrypoints.get_mut(index) {
            entrypoint.emit_inline_call_resumes(entrypoint.next_statement_index, script_len);
            entrypoint.script_len = script_len;
        }
        active.active_function_name = None;
        active.statement_debug_state_stack.clear();
        active.pending_statement_debug_states.clear();
    }

    pub(crate) fn set_entrypoint_start(&mut self, name: &str, bytecode_start: usize) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let Some(entrypoint) = active.entrypoints.iter_mut().find(|entrypoint| entrypoint.name == name) else {
            return;
        };
        entrypoint.bytecode_start = Some(bytecode_start);
    }

    pub(crate) fn take_debug_info(&mut self, source: Option<&str>) -> Option<DebugInfo<'i>> {
        let active = self.active.as_mut()?;
        let mut recorder = std::mem::take(&mut active.recorder);

        for entrypoint in active.entrypoints.drain(..) {
            let bytecode_start = entrypoint.bytecode_start.unwrap_or(0);
            let sequence_base = recorder.reserve_sequence_block(entrypoint.next_step_sequence);

            recorder.record_function(DebugFunctionRange {
                name: entrypoint.name,
                bytecode_start,
                bytecode_end: bytecode_start + entrypoint.script_len,
            });

            for param in entrypoint.params {
                recorder.record_param(param);
            }

            for mut step in entrypoint.steps {
                step.bytecode_start += bytecode_start;
                step.bytecode_end += bytecode_start;
                step.sequence = sequence_base.saturating_add(step.sequence);
                recorder.record_step(step);
            }
        }

        Some(recorder.into_debug_info(source.unwrap_or_default().to_string()))
    }
}

fn should_record_source_step(stmt: &Statement<'_>) -> bool {
    !matches!(stmt, Statement::Block { .. })
}

fn rewrite_debug_expr_with_function<'i>(
    expr: Expr<'i>,
    function_name: &str,
    visible_names_by_function: &HashMap<String, HashMap<String, String>>,
) -> Expr<'i> {
    let span = expr.span;
    let visible_name = |name: &str| {
        visible_names_by_function.get(function_name).and_then(|names| names.get(name)).cloned().unwrap_or_else(|| name.to_string())
    };

    let kind = match expr.kind {
        ExprKind::Identifier(name) => ExprKind::Identifier(visible_name(&name)),
        ExprKind::Array(values) => ExprKind::Array(
            values
                .into_iter()
                .map(|value| rewrite_debug_expr_with_function(value, function_name, visible_names_by_function))
                .collect(),
        ),
        ExprKind::Call { name, args, name_span } => ExprKind::Call {
            name,
            args: args
                .into_iter()
                .map(|arg| rewrite_debug_expr_with_function(arg, function_name, visible_names_by_function))
                .collect(),
            name_span,
        },
        ExprKind::New { name, args, name_span } => ExprKind::New {
            name,
            args: args
                .into_iter()
                .map(|arg| rewrite_debug_expr_with_function(arg, function_name, visible_names_by_function))
                .collect(),
            name_span,
        },
        ExprKind::Split { source, index, part, span } => ExprKind::Split {
            source: Box::new(rewrite_debug_expr_with_function(*source, function_name, visible_names_by_function)),
            index: Box::new(rewrite_debug_expr_with_function(*index, function_name, visible_names_by_function)),
            part,
            span,
        },
        ExprKind::Slice { source, start, end, span } => ExprKind::Slice {
            source: Box::new(rewrite_debug_expr_with_function(*source, function_name, visible_names_by_function)),
            start: Box::new(rewrite_debug_expr_with_function(*start, function_name, visible_names_by_function)),
            end: Box::new(rewrite_debug_expr_with_function(*end, function_name, visible_names_by_function)),
            span,
        },
        ExprKind::ArrayIndex { source, index } => ExprKind::ArrayIndex {
            source: Box::new(rewrite_debug_expr_with_function(*source, function_name, visible_names_by_function)),
            index: Box::new(rewrite_debug_expr_with_function(*index, function_name, visible_names_by_function)),
        },
        ExprKind::Unary { op, expr } => {
            ExprKind::Unary { op, expr: Box::new(rewrite_debug_expr_with_function(*expr, function_name, visible_names_by_function)) }
        }
        ExprKind::Binary { op, left, right } => ExprKind::Binary {
            op,
            left: Box::new(rewrite_debug_expr_with_function(*left, function_name, visible_names_by_function)),
            right: Box::new(rewrite_debug_expr_with_function(*right, function_name, visible_names_by_function)),
        },
        ExprKind::IfElse { condition, then_expr, else_expr } => ExprKind::IfElse {
            condition: Box::new(rewrite_debug_expr_with_function(*condition, function_name, visible_names_by_function)),
            then_expr: Box::new(rewrite_debug_expr_with_function(*then_expr, function_name, visible_names_by_function)),
            else_expr: Box::new(rewrite_debug_expr_with_function(*else_expr, function_name, visible_names_by_function)),
        },
        ExprKind::Introspection { kind, index, field_span } => ExprKind::Introspection {
            kind,
            index: Box::new(rewrite_debug_expr_with_function(*index, function_name, visible_names_by_function)),
            field_span,
        },
        ExprKind::StateObject(fields) => ExprKind::StateObject(
            fields
                .into_iter()
                .map(|field| StateFieldExpr {
                    name: field.name,
                    expr: rewrite_debug_expr_with_function(field.expr, function_name, visible_names_by_function),
                    span: field.span,
                    name_span: field.name_span,
                })
                .collect(),
        ),
        ExprKind::FieldAccess { source, field, field_span } => ExprKind::FieldAccess {
            source: Box::new(rewrite_debug_expr_with_function(*source, function_name, visible_names_by_function)),
            field,
            field_span,
        },
        ExprKind::UnarySuffix { source, kind, span } => ExprKind::UnarySuffix {
            source: Box::new(rewrite_debug_expr_with_function(*source, function_name, visible_names_by_function)),
            kind,
            span,
        },
        other => other,
    };
    Expr::new(kind, span)
}

fn collect_console_args<'i>(recorder: &DebugRecorder<'i>, stmt: &Statement<'i>) -> Vec<Expr<'i>> {
    match stmt {
        Statement::Console { args, .. } => args.iter().cloned().map(|expr| recorder.rewrite_debug_expr(expr)).collect(),
        _ => Vec::new(),
    }
}

fn collect_variable_updates<'i>(
    recorder: &DebugRecorder<'i>,
    stmt: &Statement<'i>,
    _before_types: &HashMap<String, String>,
    _before_stack_bindings: &StackBindings,
    after_types: &HashMap<String, String>,
    after_stack_bindings: &StackBindings,
) -> Vec<DebugVariableUpdate<'i>> {
    match stmt {
        Statement::VariableDefinition { name, expr, .. } => vec![build_runtime_debug_update(
            recorder,
            name,
            expr.clone().unwrap_or_else(|| Expr::new(ExprKind::Identifier(name.clone()), crate::span::Span::default())),
            after_types,
            after_stack_bindings,
        )]
        .into_iter()
        .flatten()
        .collect(),
        Statement::Assign { name, expr, .. } => {
            vec![build_runtime_debug_update(recorder, name, expr.clone(), after_types, after_stack_bindings)]
                .into_iter()
                .flatten()
                .collect()
        }
        Statement::TupleAssignment { left_name, right_name, .. } => [left_name.as_str(), right_name.as_str()]
            .into_iter()
            .filter_map(|name| {
                build_runtime_debug_update(
                    recorder,
                    name,
                    Expr::new(ExprKind::Identifier(name.to_string()), crate::span::Span::default()),
                    after_types,
                    after_stack_bindings,
                )
            })
            .collect(),
        Statement::StateFunctionCallAssign { bindings, .. } | Statement::StructDestructure { bindings, .. } => bindings
            .iter()
            .filter_map(|binding| {
                build_runtime_debug_update(
                    recorder,
                    &binding.name,
                    Expr::new(ExprKind::Identifier(binding.name.clone()), crate::span::Span::default()),
                    after_types,
                    after_stack_bindings,
                )
            })
            .collect(),
        Statement::FunctionCallAssign { bindings, .. } => bindings
            .iter()
            .filter_map(|binding| {
                build_runtime_debug_update(
                    recorder,
                    &binding.name,
                    Expr::new(ExprKind::Identifier(binding.name.clone()), crate::span::Span::default()),
                    after_types,
                    after_stack_bindings,
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn merge_debug_variable_updates<'i>(target: &mut Vec<DebugVariableUpdate<'i>>, updates: Vec<DebugVariableUpdate<'i>>) {
    for update in updates {
        if let Some(existing) = target.iter_mut().find(|existing| existing.name == update.name) {
            existing.type_name = update.type_name.clone();
            existing.expr = update.expr.clone();
            existing.stack_binding = update.stack_binding.clone();
            match (&mut existing.structured_leaf_bindings, update.structured_leaf_bindings) {
                (Some(existing_leaves), Some(update_leaves)) => {
                    for leaf in update_leaves {
                        if let Some(existing_leaf) =
                            existing_leaves.iter_mut().find(|existing_leaf| existing_leaf.field_path == leaf.field_path)
                        {
                            *existing_leaf = leaf;
                        } else {
                            existing_leaves.push(leaf);
                        }
                    }
                }
                (None, Some(update_leaves)) => {
                    existing.structured_leaf_bindings = Some(update_leaves);
                }
                _ => {}
            }
        } else {
            target.push(update);
        }
    }
}

fn build_runtime_debug_update<'i>(
    recorder: &DebugRecorder<'i>,
    lowered_name: &str,
    expr: Expr<'i>,
    after_types: &HashMap<String, String>,
    after_stack_bindings: &StackBindings,
) -> Option<DebugVariableUpdate<'i>> {
    if let Some(update) = build_structured_root_debug_update(recorder, lowered_name, expr.clone(), after_stack_bindings) {
        return Some(update);
    }
    let type_name = after_types.get(lowered_name)?.clone();
    let stack_binding = after_stack_bindings
        .depth(lowered_name)
        .map(|from_top| crate::debug_info::DebugStackBinding { from_top, stack_height: Some(after_stack_bindings.len()) });
    if let Some(spec) = recorder
        .active
        .as_ref()
        .and_then(|active| active.active_function_name.as_deref())
        .and_then(|function_name| active_structured_leaf_spec(recorder, function_name, lowered_name))
    {
        return Some(DebugVariableUpdate {
            name: spec.visible_base_name.clone(),
            type_name: spec.base_type_name.clone(),
            stack_binding: None,
            structured_leaf_bindings: Some(vec![DebugLeafBinding {
                field_path: spec.field_path.clone(),
                type_name: spec.leaf_type_name.clone(),
                stack_binding: stack_binding.clone(),
            }]),
            expr: Expr::identifier(spec.visible_base_name.clone()),
        });
    }
    Some(DebugVariableUpdate {
        name: recorder.visible_name(lowered_name),
        type_name,
        stack_binding,
        structured_leaf_bindings: None,
        expr: recorder.rewrite_debug_expr(expr),
    })
}

fn build_structured_root_debug_update<'i>(
    recorder: &DebugRecorder<'i>,
    lowered_base_name: &str,
    expr: Expr<'i>,
    after_stack_bindings: &StackBindings,
) -> Option<DebugVariableUpdate<'i>> {
    let active = recorder.active.as_ref()?;
    let function_name = active.active_function_name.as_deref()?;
    let specs = active.structured_leaf_specs_by_function.get(function_name)?;
    let fallback_prefix = format!("__struct_{lowered_base_name}_");

    let mut leaf_bindings = specs
        .iter()
        .filter(|(leaf_name, _)| leaf_name.starts_with(&fallback_prefix))
        .map(|(leaf_name, spec)| DebugLeafBinding {
            field_path: spec.field_path.clone(),
            type_name: spec.leaf_type_name.clone(),
            stack_binding: after_stack_bindings
                .depth(leaf_name)
                .map(|from_top| DebugStackBinding { from_top, stack_height: Some(after_stack_bindings.len()) }),
        })
        .collect::<Vec<_>>();

    if leaf_bindings.is_empty() {
        return None;
    }

    leaf_bindings.sort_by(|left, right| left.field_path.cmp(&right.field_path));
    let first_spec = specs.iter().find(|(leaf_name, _)| leaf_name.starts_with(&fallback_prefix)).map(|(_, spec)| spec)?;

    Some(DebugVariableUpdate {
        name: first_spec.visible_base_name.clone(),
        type_name: first_spec.base_type_name.clone(),
        stack_binding: None,
        structured_leaf_bindings: Some(leaf_bindings),
        expr: recorder.rewrite_debug_expr(expr),
    })
}

fn active_structured_leaf_spec<'a, 'i>(
    recorder: &'a DebugRecorder<'i>,
    function_name: &str,
    lowered_name: &str,
) -> Option<&'a StructuredLeafSpec> {
    recorder.active.as_ref()?.structured_leaf_specs_by_function.get(function_name)?.get(lowered_name)
}

#[derive(Debug, Default)]
struct ActiveDebugRecorder<'i> {
    recorder: DebugInfoRecorder<'i>,
    source_params_by_function: HashMap<String, Vec<ParamAst<'i>>>,
    visible_names_by_function: HashMap<String, HashMap<String, String>>,
    structured_leaf_specs_by_function: HashMap<String, HashMap<String, StructuredLeafSpec>>,
    inline_frame_plans_by_function: HashMap<String, Vec<InlineFramePlan<'i>>>,
    entrypoints: Vec<StagedEntrypointDebug<'i>>,

    active_entrypoint: Option<usize>,
    active_function_name: Option<String>,
    active_source_function_name: Option<String>,
    active_source_inline_frames: Vec<PendingInlineFrame<'i>>,
    next_source_frame_id: u32,
    statement_debug_state_stack: Vec<StatementDebugState<'i>>,
    pending_statement_debug_states: Vec<Option<StatementDebugState<'i>>>,
}

impl<'i> ActiveDebugRecorder<'i> {
    fn active_entrypoint_mut(&mut self) -> Option<&mut StagedEntrypointDebug<'i>> {
        let index = self.active_entrypoint?;
        self.entrypoints.get_mut(index)
    }

    fn start_statement_slot(&mut self, stmt: &Statement<'i>, bytecode_start: usize) -> StatementDebugState<'i> {
        let span = SourceSpan::from(stmt.span());
        let mut source_path = self.statement_debug_state_stack.iter().map(|state| state.span).collect::<Vec<_>>();
        source_path.push(span);
        let reuses_ancestor_source_slot = self.statement_debug_state_stack.iter().any(|state| state.continued_across_siblings);
        let statement_index = self.active_entrypoint_mut().map_or(0, |entrypoint| {
            if reuses_ancestor_source_slot {
                entrypoint.reused_or_new_statement_index(source_path)
            } else {
                entrypoint.new_statement_index_for_path(source_path)
            }
        });
        StatementDebugState {
            statement_index,
            span,
            bytecode_start,
            bytecode_end: bytecode_start,
            continued_across_siblings: false,
            records_source_step: should_record_source_step(stmt),
            source_step_recorded: false,
            variable_updates: Vec::new(),
            console_args: Vec::new(),
        }
    }

    fn take_pending_statement_slot(&mut self, depth: usize) -> Option<StatementDebugState<'i>> {
        self.pending_statement_debug_states.get_mut(depth).and_then(Option::take)
    }

    fn store_pending_statement_slot(&mut self, depth: usize, state: StatementDebugState<'i>) {
        if self.pending_statement_debug_states.len() <= depth {
            self.pending_statement_debug_states.resize_with(depth + 1, || None);
        }
        debug_assert!(self.pending_statement_debug_states[depth].is_none(), "pending source slot already present at depth {depth}");
        self.pending_statement_debug_states[depth] = Some(state);
    }

    fn flush_pending_statement_slots_from_depth(&mut self, start_depth: usize) {
        let stop_depth = self.pending_statement_debug_states.len();
        if start_depth >= stop_depth {
            return;
        }

        for depth in (start_depth..stop_depth).rev() {
            if let Some(state) = self.pending_statement_debug_states[depth].take() {
                self.flush_statement_slot(state);
            }
        }
    }

    fn flush_statement_slot(&mut self, state: StatementDebugState<'i>) {
        let Some(entrypoint) = self.active_entrypoint_mut() else {
            return;
        };

        if !state.source_step_recorded && state.records_source_step {
            let (call_depth, frame_id) = entrypoint.current_frame_context(state.statement_index);
            entrypoint.record_step(DebugStep {
                bytecode_start: state.bytecode_start,
                bytecode_end: state.bytecode_end,
                span: state.span,
                kind: StepKind::Source {},
                sequence: 0,
                call_depth,
                frame_id,
                variable_updates: state.variable_updates.clone(),
                console_args: state.console_args.clone(),
            });
        }

        entrypoint.emit_inline_call_exits(entrypoint.next_statement_index, state.bytecode_end);
    }

    fn reset_iteration(&mut self) {
        self.recorder = DebugInfoRecorder::default();
        self.entrypoints.clear();
        self.active_entrypoint = None;
        self.active_function_name = None;
        self.active_source_function_name = None;
        self.active_source_inline_frames.clear();
        self.next_source_frame_id = 1;
        self.statement_debug_state_stack.clear();
        self.pending_statement_debug_states.clear();
    }
}

#[derive(Debug)]
struct StatementDebugState<'i> {
    statement_index: usize,
    span: SourceSpan,
    bytecode_start: usize,
    bytecode_end: usize,
    continued_across_siblings: bool,
    records_source_step: bool,
    source_step_recorded: bool,
    variable_updates: Vec<DebugVariableUpdate<'i>>,
    console_args: Vec<Expr<'i>>,
}

#[derive(Debug)]
struct PendingInlineFrame<'i> {
    callee: String,
    call_site_span: SourceSpan,
    frame_id: u32,
    frame_depth: u32,
    start_statement_index: usize,
    param_updates: Vec<DebugVariableUpdate<'i>>,
}

#[derive(Debug, Clone)]
struct InlineFramePlan<'i> {
    callee: String,
    call_site_span: SourceSpan,
    frame_id: u32,
    frame_depth: u32,
    start_statement_index: usize,
    param_updates: Vec<DebugVariableUpdate<'i>>,
    body_end_statement_index: usize,
    resume_statement_index: usize,
}

#[derive(Debug)]
struct StagedEntrypointDebug<'i> {
    name: String,
    script_len: usize,
    bytecode_start: Option<usize>,
    params: Vec<DebugParamMapping>,
    steps: Vec<DebugStep<'i>>,
    next_step_sequence: u32,
    next_statement_index: usize,
    statement_index_by_path: HashMap<Vec<SourceSpan>, usize>,
    frame_plans: Vec<InlineFramePlan<'i>>,
}

impl<'i> StagedEntrypointDebug<'i> {
    fn allocate_statement_index(&mut self) -> usize {
        let statement_index = self.next_statement_index;
        self.next_statement_index = self.next_statement_index.saturating_add(1);
        statement_index
    }

    fn new_statement_index_for_path(&mut self, source_path: Vec<SourceSpan>) -> usize {
        let statement_index = self.allocate_statement_index();
        self.statement_index_by_path.insert(source_path, statement_index);
        statement_index
    }

    fn reused_or_new_statement_index(&mut self, source_path: Vec<SourceSpan>) -> usize {
        if let Some(statement_index) = self.statement_index_by_path.get(&source_path) {
            return *statement_index;
        }

        let statement_index = self.allocate_statement_index();
        self.statement_index_by_path.insert(source_path, statement_index);
        statement_index
    }

    fn record_step(&mut self, mut step: DebugStep<'i>) {
        step.sequence = self.next_step_sequence;
        self.next_step_sequence = self.next_step_sequence.saturating_add(1);
        self.steps.push(step);
    }

    fn emit_inline_call_enters(&mut self, statement_index: usize, bytecode_start: usize) {
        let mut plans =
            self.frame_plans.iter().filter(|plan| plan.start_statement_index == statement_index).cloned().collect::<Vec<_>>();
        plans.sort_by_key(|plan| plan.frame_depth);

        for plan in plans {
            self.record_step(DebugStep {
                bytecode_start,
                bytecode_end: bytecode_start,
                span: plan.call_site_span,
                kind: StepKind::InlineCallEnter { callee: plan.callee },
                sequence: 0,
                call_depth: plan.frame_depth.saturating_sub(1),
                frame_id: plan.frame_id,
                variable_updates: plan.param_updates,
                console_args: Vec::new(),
            });
        }
    }

    fn emit_inline_call_exits(&mut self, statement_end_index: usize, bytecode_end: usize) {
        let mut plans =
            self.frame_plans.iter().filter(|plan| plan.body_end_statement_index == statement_end_index).cloned().collect::<Vec<_>>();
        plans.sort_by_key(|plan| std::cmp::Reverse(plan.frame_depth));
        let parent_lookup_index = statement_end_index.saturating_sub(1);

        for plan in plans {
            let parent_frame_id = self
                .frame_plans
                .iter()
                .filter(|candidate| {
                    candidate.frame_depth.saturating_add(1) == plan.frame_depth
                        && candidate.start_statement_index <= parent_lookup_index
                        && parent_lookup_index < candidate.body_end_statement_index
                })
                .max_by_key(|candidate| candidate.frame_depth)
                .map(|candidate| candidate.frame_id)
                .unwrap_or(0);
            let variable_updates = self
                .steps
                .iter()
                .rev()
                .find(|step| matches!(step.kind, StepKind::Source {}) && step.frame_id == plan.frame_id)
                .map(|step| step.variable_updates.clone())
                .unwrap_or_default();
            self.record_step(DebugStep {
                bytecode_start: bytecode_end,
                bytecode_end,
                span: plan.call_site_span,
                kind: StepKind::InlineCallExit { callee: plan.callee },
                sequence: 0,
                call_depth: plan.frame_depth.saturating_sub(1),
                frame_id: parent_frame_id,
                variable_updates,
                console_args: Vec::new(),
            });
        }
    }

    fn emit_inline_call_resumes(&mut self, statement_index: usize, bytecode_start: usize) {
        let mut plans =
            self.frame_plans.iter().filter(|plan| plan.resume_statement_index == statement_index).cloned().collect::<Vec<_>>();
        plans.sort_by_key(|plan| std::cmp::Reverse(plan.frame_depth));

        for plan in plans {
            let (call_depth, frame_id) = self.parent_frame_context(&plan);
            self.record_step(DebugStep {
                bytecode_start,
                bytecode_end: bytecode_start,
                span: plan.call_site_span,
                kind: StepKind::Source {},
                sequence: 0,
                call_depth,
                frame_id,
                variable_updates: Vec::new(),
                console_args: Vec::new(),
            });
        }
    }

    fn parent_frame_context(&self, plan: &InlineFramePlan<'i>) -> (u32, u32) {
        self.frame_plans
            .iter()
            .filter(|candidate| {
                candidate.frame_depth.saturating_add(1) == plan.frame_depth
                    && candidate.start_statement_index <= plan.resume_statement_index
                    && plan.resume_statement_index <= candidate.resume_statement_index
            })
            .max_by_key(|candidate| candidate.frame_depth)
            .map(|candidate| (candidate.frame_depth, candidate.frame_id))
            .unwrap_or((plan.frame_depth.saturating_sub(1), 0))
    }

    fn current_frame_context(&self, statement_index: usize) -> (u32, u32) {
        self.frame_plans
            .iter()
            .filter(|plan| plan.start_statement_index <= statement_index && statement_index < plan.body_end_statement_index)
            .max_by_key(|plan| plan.frame_depth)
            .map(|plan| (plan.frame_depth, plan.frame_id))
            .unwrap_or((0, 0))
    }
}

#[derive(Debug, Clone)]
struct StructuredLeafSpec {
    visible_base_name: String,
    base_type_name: String,
    field_path: Vec<String>,
    leaf_type_name: String,
}

fn build_structured_leaf_specs_for_function<'i>(
    function: &FunctionAst<'i>,
    structs: &StructRegistry,
    visible_names: Option<&HashMap<String, String>>,
) -> Result<HashMap<String, StructuredLeafSpec>, CompilerError> {
    let mut specs = HashMap::new();

    for param in &function.params {
        record_structured_binding_spec(&mut specs, &param.name, &param.type_ref, visible_names, structs)?;
    }
    collect_structured_binding_specs_from_statements(&mut specs, &function.body, visible_names, structs)?;

    Ok(specs)
}

fn collect_structured_binding_specs_from_statements<'i>(
    specs: &mut HashMap<String, StructuredLeafSpec>,
    statements: &[Statement<'i>],
    visible_names: Option<&HashMap<String, String>>,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    for statement in statements {
        match statement {
            Statement::VariableDefinition { name, type_ref, .. } => {
                record_structured_binding_spec(specs, name, type_ref, visible_names, structs)?;
            }
            Statement::FunctionCallAssign { bindings, .. } => {
                for binding in bindings {
                    record_structured_binding_spec(specs, &binding.name, &binding.type_ref, visible_names, structs)?;
                }
            }
            Statement::StateFunctionCallAssign { bindings, .. } | Statement::StructDestructure { bindings, .. } => {
                for binding in bindings {
                    record_structured_state_binding_spec(specs, binding, visible_names, structs)?;
                }
            }
            Statement::Block { body, .. } | Statement::For { body, .. } => {
                collect_structured_binding_specs_from_statements(specs, body, visible_names, structs)?;
            }
            Statement::If { then_branch, else_branch, .. } => {
                collect_structured_binding_specs_from_statements(specs, then_branch, visible_names, structs)?;
                if let Some(else_branch) = else_branch {
                    collect_structured_binding_specs_from_statements(specs, else_branch, visible_names, structs)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn record_structured_state_binding_spec(
    specs: &mut HashMap<String, StructuredLeafSpec>,
    binding: &StateBindingAst<'_>,
    visible_names: Option<&HashMap<String, String>>,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    record_structured_binding_spec(specs, &binding.name, &binding.type_ref, visible_names, structs)
}

fn record_structured_binding_spec(
    specs: &mut HashMap<String, StructuredLeafSpec>,
    lowered_base_name: &str,
    type_ref: &crate::ast::TypeRef,
    visible_names: Option<&HashMap<String, String>>,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    if struct_name_from_type_ref(type_ref, structs).is_none() && struct_array_name_from_type_ref(type_ref, structs).is_none() {
        return Ok(());
    }

    let visible_base_name =
        visible_names.and_then(|names| names.get(lowered_base_name)).cloned().unwrap_or_else(|| lowered_base_name.to_string());
    let base_type_name = type_ref.type_name();

    for (field_path, leaf_type) in flatten_type_ref_leaves(type_ref, structs)? {
        let lowered_leaf_name = flattened_struct_field_name(lowered_base_name, &field_path);
        specs.insert(
            lowered_leaf_name,
            StructuredLeafSpec {
                visible_base_name: visible_base_name.clone(),
                base_type_name: base_type_name.clone(),
                field_path,
                leaf_type_name: type_name_from_ref(&leaf_type),
            },
        );
    }

    Ok(())
}

fn build_param_mappings<'i>(
    function: &FunctionAst<'i>,
    source_params: Option<&[ParamAst<'i>]>,
    contract_fields: &[ContractFieldAst<'i>],
    structs: &StructRegistry,
) -> Result<Vec<DebugParamMapping>, CompilerError> {
    let field_count = contract_fields.len();
    let params_source = source_params.unwrap_or(&function.params);
    let mut param_specs = Vec::with_capacity(params_source.len());
    let mut flattened_param_names = Vec::new();

    for param in params_source {
        if struct_name_from_type_ref(&param.type_ref, structs).is_some()
            || struct_array_name_from_type_ref(&param.type_ref, structs).is_some()
        {
            let leaf_specs = flatten_type_ref_leaves(&param.type_ref, structs)?
                .into_iter()
                .map(|(field_path, leaf_type)| (field_path, type_name_from_ref(&leaf_type)))
                .collect::<Vec<_>>();
            for (field_path, _) in &leaf_specs {
                flattened_param_names.push(flattened_struct_field_name(&param.name, field_path));
            }
            param_specs.push(ParamBindingSpec::Structured(leaf_specs));
        } else {
            flattened_param_names.push(param.name.clone());
            param_specs.push(ParamBindingSpec::Scalar);
        }
    }

    let param_count = flattened_param_names.len();
    let mut flat_index = 0usize;
    let mut next_stack_index = || {
        let stack_index = (field_count + (param_count - 1 - flat_index)) as i64;
        flat_index = flat_index.saturating_add(1);
        stack_index
    };

    let mut params = Vec::with_capacity(params_source.len() + contract_fields.len());
    for (param, spec) in params_source.iter().zip(param_specs.into_iter()) {
        let binding = match spec {
            ParamBindingSpec::Scalar => DebugParamBinding::SingleValue { stack_index: next_stack_index() },
            ParamBindingSpec::Structured(leaf_specs) => DebugParamBinding::StructuredValue {
                leaf_bindings: leaf_specs
                    .into_iter()
                    .map(|(field_path, type_name)| DebugLeafBinding {
                        field_path,
                        type_name,
                        stack_binding: Some(DebugStackBinding { from_top: next_stack_index(), stack_height: None }),
                    })
                    .collect(),
            },
        };
        params.push(DebugParamMapping {
            name: param.name.clone(),
            type_name: param.type_ref.type_name(),
            binding,
            function: function.name.clone(),
        });
    }

    for (index, field) in contract_fields.iter().enumerate() {
        params.push(DebugParamMapping {
            name: field.name.clone(),
            type_name: field.type_ref.type_name(),
            binding: DebugParamBinding::SingleValue { stack_index: (field_count - 1 - index) as i64 },
            function: function.name.clone(),
        });
    }

    Ok(params)
}

#[derive(Debug)]
enum ParamBindingSpec {
    Scalar,
    Structured(Vec<(Vec<String>, String)>),
}

fn flattened_struct_field_name(base: &str, field_path: &[String]) -> String {
    let mut out = format!("__struct_{base}");
    for part in field_path {
        out.push('_');
        out.push_str(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::DebugRecorder;
    use crate::ast::{Expr, parse_contract_ast};
    use crate::compiler::build_struct_registry;

    #[test]
    fn disabled_recorder_returns_no_debug_info() {
        let contract = parse_contract_ast(
            r#"
            contract Demo() {
                entrypoint function spend(int x) {
                    require(x > 0);
                }
            }
            "#,
        )
        .expect("parse contract");

        let mut recorder = DebugRecorder::new(false);
        recorder.record_contract_scope(&contract, &[]);
        assert!(recorder.take_debug_info(Some("contract Demo() {}")).is_none());
    }

    #[test]
    fn enabled_recorder_records_contract_scope() {
        let contract = parse_contract_ast(
            r#"
            contract Demo(int seed) {
                int constant BONUS = 2;

                entrypoint function spend(int x) {
                    require(x + seed + BONUS > 0);
                }
            }
            "#,
        )
        .expect("parse contract");

        let mut recorder = DebugRecorder::new(true);
        recorder.record_contract_scope(&contract, &[Expr::int(7)]);
        let debug_info = recorder.take_debug_info(Some("contract Demo(int seed) {}")).expect("debug info");

        assert_eq!(debug_info.source, "contract Demo(int seed) {}");
        assert_eq!(debug_info.constructor_args.len(), 1);
        assert_eq!(debug_info.constructor_args[0].name, "seed");
        assert_eq!(debug_info.constants.len(), 1);
        assert_eq!(debug_info.constants[0].name, "BONUS");
    }

    #[test]
    fn begin_entrypoint_keeps_bytecode_metadata_separate_from_source_steps() {
        let contract = parse_contract_ast(
            r#"
            contract Demo() {
                entrypoint function spend(int x) {
                    require(x > 0);
                }
            }
            "#,
        )
        .expect("parse contract");
        let structs = build_struct_registry(&contract).expect("build struct registry");
        let function = contract.functions.first().expect("entrypoint function");

        let mut recorder = DebugRecorder::new(true);
        recorder.record_contract_scope(&contract, &[]);
        recorder.begin_entrypoint(function, &contract.fields, &structs).expect("begin entrypoint");

        let active = recorder.active.as_ref().expect("active recorder");
        let entrypoint = active.entrypoints.first().expect("staged entrypoint");

        assert_eq!(entrypoint.name, "spend");
        assert_eq!(entrypoint.script_len, 0);
        assert!(entrypoint.bytecode_start.is_none());
        assert_eq!(entrypoint.params.len(), 1);
    }

    #[test]
    fn record_contract_scope_resets_iteration_state() {
        let contract = parse_contract_ast(
            r#"
            contract Demo() {
                entrypoint function spend(int x) {
                    require(x > 0);
                }
            }
            "#,
        )
        .expect("parse contract");
        let structs = build_struct_registry(&contract).expect("build struct registry");
        let function = contract.functions.first().expect("entrypoint function");

        let mut recorder = DebugRecorder::new(true);
        recorder.record_contract_scope(&contract, &[]);
        recorder.begin_entrypoint(function, &contract.fields, &structs).expect("begin entrypoint");
        recorder.finish_entrypoint(12);

        recorder.record_contract_scope(&contract, &[]);

        let active = recorder.active.as_ref().expect("active recorder");
        assert!(active.entrypoints.is_empty());
        assert!(active.active_entrypoint.is_none());
    }
}
