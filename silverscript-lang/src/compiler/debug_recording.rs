use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::ast::{ConstantAst, ContractFieldAst, Expr, FunctionAst, ParamAst, Statement};
use crate::debug_info::{
    DebugFunctionRange, DebugInfo, DebugInfoRecorder, DebugNamedValue, DebugParamBinding, DebugParamLeafBinding, DebugParamMapping,
    DebugStep, DebugVariableUpdate, RuntimeBinding, SourceSpan, StepKind,
};

use super::{CompilerError, resolve_expr_for_debug};

/// Contract-level debug recorder used by the compiler.
///
/// This facade routes calls to either an active backend (records debug metadata)
/// or a no-op backend (recording disabled), keeping compiler call sites uniform.
pub struct DebugRecorder<'i> {
    inner: Box<dyn DebugRecorderImpl<'i> + 'i>,
}

impl fmt::Debug for DebugRecorder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugRecorder").finish_non_exhaustive()
    }
}

impl<'i> DebugRecorder<'i> {
    /// Creates a debug recorder. When `enabled` is false, all methods become no-ops.
    pub fn new(enabled: bool) -> Self {
        if enabled { Self { inner: Box::new(ActiveDebugRecorder::default()) } } else { Self { inner: Box::new(NoopDebugRecorder) } }
    }

    /// Records contract-scoped debugger bindings (constructor args and constant declarations).
    pub fn record_contract_scope(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>], constants: &[ConstantAst<'i>]) {
        self.inner.record_contract_scope(params, values, constants);
    }

    /// Starts staging debug metadata for one entrypoint compilation.
    pub fn begin_entrypoint(
        &mut self,
        name: &str,
        function: &FunctionAst<'i>,
        contract_fields: &[ContractFieldAst<'i>],
        structs: &super::StructRegistry,
    ) -> Result<(), CompilerError> {
        self.inner.begin_entrypoint(name, function, contract_fields, structs)
    }

    /// Finishes the active entrypoint stage and stores its local script length.
    pub fn finish_entrypoint(&mut self, script_len: usize) {
        self.inner.finish_entrypoint(script_len);
    }

    /// Sets the absolute script start of a staged entrypoint in final contract bytecode.
    pub fn set_entrypoint_start(&mut self, name: &str, bytecode_start: usize) {
        self.inner.set_entrypoint_start(name, bytecode_start);
    }

    /// Starts one statement frame at the provided bytecode offset.
    pub fn begin_statement_at(
        &mut self,
        bytecode_offset: usize,
        env: &HashMap<String, Expr<'i>>,
        stack_bindings: &HashMap<String, i64>,
    ) {
        self.inner.begin_statement_at(bytecode_offset, env, stack_bindings);
    }

    /// Finishes one statement frame and records variable diffs and bytecode range.
    pub fn finish_statement_at(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_end: usize,
        env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
        stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError> {
        self.inner.finish_statement_at(stmt, bytecode_end, env, types, stack_bindings)
    }

    /// Records an inline call entry step and opens a nested call frame.
    pub fn begin_inline_call(
        &mut self,
        span: SourceSpan,
        bytecode_offset: usize,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
        stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError> {
        self.inner.begin_inline_call(span, bytecode_offset, function, env, stack_bindings)
    }

    /// Records an inline call exit step and closes the active nested call frame.
    pub fn finish_inline_call(&mut self, span: SourceSpan, bytecode_offset: usize, callee: &str) {
        self.inner.finish_inline_call(span, bytecode_offset, callee);
    }

    /// Records an explicit variable binding as a zero-width source step.
    pub fn record_variable_binding(
        &mut self,
        name: String,
        type_name: String,
        expr: Expr<'i>,
        runtime_binding: Option<RuntimeBinding>,
        bytecode_offset: usize,
        span: SourceSpan,
    ) {
        self.inner.record_variable_binding(name, type_name, expr, runtime_binding, bytecode_offset, span);
    }

    /// Finalizes and returns debug info if recording is enabled.
    pub fn into_debug_info(self, source: String) -> Option<DebugInfo<'i>> {
        self.inner.into_debug_info(source)
    }
}

trait DebugRecorderImpl<'i>: fmt::Debug {
    fn record_contract_scope(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>], constants: &[ConstantAst<'i>]);
    fn begin_entrypoint(
        &mut self,
        name: &str,
        function: &FunctionAst<'i>,
        contract_fields: &[ContractFieldAst<'i>],
        structs: &super::StructRegistry,
    ) -> Result<(), CompilerError>;
    fn finish_entrypoint(&mut self, script_len: usize);
    fn set_entrypoint_start(&mut self, name: &str, bytecode_start: usize);
    fn begin_statement_at(&mut self, bytecode_offset: usize, env: &HashMap<String, Expr<'i>>, stack_bindings: &HashMap<String, i64>);
    fn finish_statement_at(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_end: usize,
        env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
        stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError>;
    fn begin_inline_call(
        &mut self,
        span: SourceSpan,
        bytecode_offset: usize,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
        stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError>;
    fn finish_inline_call(&mut self, span: SourceSpan, bytecode_offset: usize, callee: &str);
    fn record_variable_binding(
        &mut self,
        name: String,
        type_name: String,
        expr: Expr<'i>,
        runtime_binding: Option<RuntimeBinding>,
        bytecode_offset: usize,
        span: SourceSpan,
    );
    fn into_debug_info(self: Box<Self>, source: String) -> Option<DebugInfo<'i>>;
}

#[derive(Debug, Default)]
struct NoopDebugRecorder;

impl<'i> DebugRecorderImpl<'i> for NoopDebugRecorder {
    fn record_contract_scope(&mut self, _params: &[ParamAst<'i>], _values: &[Expr<'i>], _constants: &[ConstantAst<'i>]) {}
    fn begin_entrypoint(
        &mut self,
        _name: &str,
        _function: &FunctionAst<'i>,
        _contract_fields: &[ContractFieldAst<'i>],
        _structs: &super::StructRegistry,
    ) -> Result<(), CompilerError> {
        Ok(())
    }
    fn finish_entrypoint(&mut self, _script_len: usize) {}
    fn set_entrypoint_start(&mut self, _name: &str, _bytecode_start: usize) {}
    fn begin_statement_at(
        &mut self,
        _bytecode_offset: usize,
        _env: &HashMap<String, Expr<'i>>,
        _stack_bindings: &HashMap<String, i64>,
    ) {
    }

    fn finish_statement_at(
        &mut self,
        _stmt: &Statement<'i>,
        _bytecode_end: usize,
        _env: &HashMap<String, Expr<'i>>,
        _types: &HashMap<String, String>,
        _stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError> {
        Ok(())
    }

    fn begin_inline_call(
        &mut self,
        _span: SourceSpan,
        _bytecode_offset: usize,
        _function: &FunctionAst<'i>,
        _env: &HashMap<String, Expr<'i>>,
        _stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError> {
        Ok(())
    }

    fn finish_inline_call(&mut self, _span: SourceSpan, _bytecode_offset: usize, _callee: &str) {}
    fn record_variable_binding(
        &mut self,
        _name: String,
        _type_name: String,
        _expr: Expr<'i>,
        _runtime_binding: Option<RuntimeBinding>,
        _bytecode_offset: usize,
        _span: SourceSpan,
    ) {
    }

    fn into_debug_info(self: Box<Self>, _source: String) -> Option<DebugInfo<'i>> {
        None
    }
}

#[derive(Debug, Default)]
struct ActiveDebugRecorder<'i> {
    recorder: DebugInfoRecorder<'i>,
    entrypoints: Vec<StagedEntrypointDebug<'i>>,
    active_entrypoint: Option<usize>,
}

impl<'i> ActiveDebugRecorder<'i> {
    fn active_entrypoint_mut(&mut self) -> Option<&mut StagedEntrypointDebug<'i>> {
        let index = self.active_entrypoint?;
        self.entrypoints.get_mut(index)
    }
}

impl<'i> DebugRecorderImpl<'i> for ActiveDebugRecorder<'i> {
    fn record_contract_scope(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>], constants: &[ConstantAst<'i>]) {
        for (param, value) in params.iter().zip(values.iter()) {
            self.recorder.record_constructor_arg(DebugNamedValue {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                value: value.clone(),
            });
        }
        for constant in constants {
            self.recorder.record_constant(DebugNamedValue {
                name: constant.name.clone(),
                type_name: constant.type_ref.type_name(),
                value: constant.expr.clone(),
            });
        }
    }

    fn begin_entrypoint(
        &mut self,
        name: &str,
        function: &FunctionAst<'i>,
        contract_fields: &[ContractFieldAst<'i>],
        structs: &super::StructRegistry,
    ) -> Result<(), CompilerError> {
        debug_assert!(self.active_entrypoint.is_none(), "begin_entrypoint called while another entrypoint is active");
        self.entrypoints.push(StagedEntrypointDebug::new(name.to_string(), function, contract_fields, structs)?);
        self.active_entrypoint = Some(self.entrypoints.len().saturating_sub(1));
        Ok(())
    }

    fn finish_entrypoint(&mut self, script_len: usize) {
        let Some(index) = self.active_entrypoint.take() else {
            return;
        };
        let Some(entrypoint) = self.entrypoints.get_mut(index) else {
            return;
        };
        entrypoint.script_len = script_len;
        debug_assert!(entrypoint.statement_stack.is_empty(), "entrypoint ended with unclosed statement frames");
        debug_assert!(entrypoint.call_stack.len() == 1, "entrypoint ended with unclosed inline call frames");
    }

    fn set_entrypoint_start(&mut self, name: &str, bytecode_start: usize) {
        let Some(entrypoint) = self.entrypoints.iter_mut().find(|entrypoint| entrypoint.name == name) else {
            return;
        };
        entrypoint.bytecode_start = Some(bytecode_start);
    }

    fn begin_statement_at(&mut self, bytecode_offset: usize, env: &HashMap<String, Expr<'i>>, stack_bindings: &HashMap<String, i64>) {
        let Some(entrypoint) = self.active_entrypoint_mut() else {
            return;
        };
        entrypoint.statement_stack.push(StatementFrame {
            start: bytecode_offset,
            env_before: env.clone(),
            stack_bindings_before: stack_bindings.clone(),
        });
    }

    fn finish_statement_at(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_end: usize,
        env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
        stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError> {
        let Some(entrypoint) = self.active_entrypoint_mut() else {
            return Ok(());
        };
        let Some(frame) = entrypoint.statement_stack.pop() else {
            return Ok(());
        };

        let updates = collect_variable_updates(&frame.env_before, &frame.stack_bindings_before, env, types, stack_bindings)?;
        let console_args = collect_console_args(stmt, env)?;
        let span = SourceSpan::from(stmt.span());
        let bytecode_len = bytecode_end.saturating_sub(frame.start);
        let step_index = entrypoint.push_step(frame.start, frame.start + bytecode_len, span, StepKind::Source {});
        entrypoint.steps[step_index].variable_updates.extend(updates);
        entrypoint.steps[step_index].console_args.extend(console_args);
        Ok(())
    }

    fn begin_inline_call(
        &mut self,
        span: SourceSpan,
        bytecode_offset: usize,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
        stack_bindings: &HashMap<String, i64>,
    ) -> Result<(), CompilerError> {
        let Some(entrypoint) = self.active_entrypoint_mut() else {
            return Ok(());
        };

        let parent_depth = entrypoint.current_call_depth();
        let callee_frame_id = entrypoint.allocate_frame_id();
        let enter_step_index = entrypoint.push_step_with_context(
            bytecode_offset,
            bytecode_offset,
            span,
            StepKind::InlineCallEnter { callee: function.name.clone() },
            parent_depth,
            callee_frame_id,
        );

        let mut updates = Vec::new();
        let mut synthetic_names: Vec<String> = env.keys().filter(|name| name.starts_with("__arg_")).cloned().collect();
        synthetic_names.sort_unstable();
        for name in synthetic_names {
            if let Some(expr) = env.get(&name).cloned() {
                let runtime_binding = runtime_binding_for_inline_binding(&expr, stack_bindings);
                resolve_variable_update(env, &mut updates, &name, "internal", expr, runtime_binding)?;
            }
        }

        for param in &function.params {
            let expr = env.get(&param.name).cloned().unwrap_or_else(|| Expr::identifier(param.name.clone()));
            let runtime_binding = runtime_binding_for_inline_binding(&expr, stack_bindings)
                .or_else(|| runtime_binding_for_stack_name(&param.name, stack_bindings));
            resolve_variable_update(env, &mut updates, &param.name, &param.type_ref.type_name(), expr, runtime_binding)?;
        }

        entrypoint.steps[enter_step_index].variable_updates.extend(updates);
        entrypoint.push_call_frame(callee_frame_id, parent_depth.saturating_add(1));
        Ok(())
    }

    fn finish_inline_call(&mut self, span: SourceSpan, bytecode_offset: usize, callee: &str) {
        let Some(entrypoint) = self.active_entrypoint_mut() else {
            return;
        };
        entrypoint.pop_call_frame();
        entrypoint.push_step(bytecode_offset, bytecode_offset, span, StepKind::InlineCallExit { callee: callee.to_string() });
    }

    fn record_variable_binding(
        &mut self,
        name: String,
        type_name: String,
        expr: Expr<'i>,
        runtime_binding: Option<RuntimeBinding>,
        bytecode_offset: usize,
        span: SourceSpan,
    ) {
        let Some(entrypoint) = self.active_entrypoint_mut() else {
            return;
        };
        let step_index = entrypoint.push_step(bytecode_offset, bytecode_offset, span, StepKind::Source {});
        entrypoint.steps[step_index].variable_updates.push(DebugVariableUpdate { name, type_name, runtime_binding, expr });
    }

    fn into_debug_info(mut self: Box<Self>, source: String) -> Option<DebugInfo<'i>> {
        for entrypoint in self.entrypoints.drain(..) {
            debug_assert!(entrypoint.bytecode_start.is_some(), "missing bytecode start for staged entrypoint '{}'", entrypoint.name);
            let bytecode_start = entrypoint.bytecode_start.unwrap_or(0);
            let seq_base = self.recorder.reserve_sequence_block(entrypoint.next_step_sequence);

            for step in entrypoint.steps {
                self.recorder.record_step(DebugStep {
                    bytecode_start: step.bytecode_start + bytecode_start,
                    bytecode_end: step.bytecode_end + bytecode_start,
                    span: step.span,
                    kind: step.kind,
                    sequence: seq_base.saturating_add(step.sequence),
                    call_depth: step.call_depth,
                    frame_id: step.frame_id,
                    variable_updates: step.variable_updates,
                    console_args: step.console_args,
                });
            }

            for param in entrypoint.params {
                self.recorder.record_param(param);
            }

            self.recorder.record_function(DebugFunctionRange {
                name: entrypoint.name,
                bytecode_start,
                bytecode_end: bytecode_start + entrypoint.script_len,
            });
        }

        Some(self.recorder.into_debug_info(source))
    }
}

#[derive(Debug)]
struct StagedEntrypointDebug<'i> {
    name: String,
    script_len: usize,
    bytecode_start: Option<usize>,
    steps: Vec<DebugStep<'i>>,
    params: Vec<DebugParamMapping>,
    next_step_sequence: u32,
    call_stack: Vec<CallFrame>,
    next_frame_id: u32,
    statement_stack: Vec<StatementFrame<'i>>,
}

impl<'i> StagedEntrypointDebug<'i> {
    fn new(
        name: String,
        function: &FunctionAst<'i>,
        contract_fields: &[ContractFieldAst<'i>],
        structs: &super::StructRegistry,
    ) -> Result<Self, CompilerError> {
        let mut entrypoint = Self {
            name,
            script_len: 0,
            bytecode_start: None,
            steps: Vec::new(),
            params: Vec::new(),
            next_step_sequence: 0,
            call_stack: vec![CallFrame { frame_id: 0, call_depth: 0 }],
            next_frame_id: 1,
            statement_stack: Vec::new(),
        };
        entrypoint.record_param_bindings(function, contract_fields, structs)?;
        Ok(entrypoint)
    }

    fn allocate_frame_id(&mut self) -> u32 {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.saturating_add(1);
        frame_id
    }

    fn push_call_frame(&mut self, frame_id: u32, call_depth: u32) {
        self.call_stack.push(CallFrame { frame_id, call_depth });
    }

    fn pop_call_frame(&mut self) {
        if self.call_stack.len() > 1 {
            self.call_stack.pop();
        }
    }

    fn current_frame(&self) -> CallFrame {
        self.call_stack.last().copied().unwrap_or(CallFrame { frame_id: 0, call_depth: 0 })
    }

    fn current_call_depth(&self) -> u32 {
        self.current_frame().call_depth
    }

    fn next_sequence(&mut self) -> u32 {
        let sequence = self.next_step_sequence;
        self.next_step_sequence = self.next_step_sequence.saturating_add(1);
        sequence
    }

    fn push_step(&mut self, bytecode_start: usize, bytecode_end: usize, span: SourceSpan, kind: StepKind) -> usize {
        let frame = self.current_frame();
        self.push_step_with_context(bytecode_start, bytecode_end, span, kind, frame.call_depth, frame.frame_id)
    }

    fn push_step_with_context(
        &mut self,
        bytecode_start: usize,
        bytecode_end: usize,
        span: SourceSpan,
        kind: StepKind,
        call_depth: u32,
        frame_id: u32,
    ) -> usize {
        let sequence = self.next_sequence();
        self.steps.push(DebugStep {
            bytecode_start,
            bytecode_end,
            span,
            kind,
            sequence,
            call_depth,
            frame_id,
            variable_updates: Vec::new(),
            console_args: Vec::new(),
        });
        self.steps.len().saturating_sub(1)
    }

    fn record_param_bindings(
        &mut self,
        function: &FunctionAst<'i>,
        contract_fields: &[ContractFieldAst<'i>],
        structs: &super::StructRegistry,
    ) -> Result<(), CompilerError> {
        let field_count = contract_fields.len();
        let mut param_leaf_specs = Vec::with_capacity(function.params.len());
        let mut flattened_param_names = Vec::new();

        for param in &function.params {
            if super::struct_name_from_type_ref(&param.type_ref, structs).is_some()
                || super::struct_array_name_from_type_ref(&param.type_ref, structs).is_some()
            {
                let leaf_specs = super::flatten_type_ref_leaves(&param.type_ref, structs)?
                    .into_iter()
                    .map(|(path, leaf_type)| (path, super::type_name_from_ref(&leaf_type)))
                    .collect::<Vec<_>>();
                for (path, _) in &leaf_specs {
                    flattened_param_names.push(super::flattened_struct_name(&param.name, path));
                }
                param_leaf_specs.push(Some(leaf_specs));
            } else {
                flattened_param_names.push(param.name.clone());
                param_leaf_specs.push(None);
            }
        }

        let param_count = flattened_param_names.len();
        let mut flat_index = 0usize;
        let mut next_stack_index = || {
            let stack_index = (field_count + (param_count - 1 - flat_index)) as i64;
            flat_index = flat_index.saturating_add(1);
            stack_index
        };
        for (param, leaf_specs) in function.params.iter().zip(param_leaf_specs.into_iter()) {
            let binding = if let Some(leaf_specs) = leaf_specs {
                let mut leaf_bindings = Vec::with_capacity(leaf_specs.len());
                for (field_path, leaf_type_name) in leaf_specs {
                    leaf_bindings.push(DebugParamLeafBinding {
                        field_path,
                        type_name: leaf_type_name,
                        stack_index: next_stack_index(),
                    });
                }
                DebugParamBinding::StructuredValue { leaf_bindings }
            } else {
                DebugParamBinding::SingleValue { stack_index: next_stack_index() }
            };
            self.params.push(DebugParamMapping {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                binding,
                function: function.name.clone(),
            });
        }
        for (index, field) in contract_fields.iter().enumerate() {
            self.params.push(DebugParamMapping {
                name: field.name.clone(),
                type_name: field.type_ref.type_name(),
                binding: DebugParamBinding::SingleValue { stack_index: (field_count - 1 - index) as i64 },
                function: function.name.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StatementFrame<'i> {
    start: usize,
    env_before: HashMap<String, Expr<'i>>,
    stack_bindings_before: HashMap<String, i64>,
}

#[derive(Debug, Clone, Copy)]
struct CallFrame {
    frame_id: u32,
    call_depth: u32,
}

fn collect_variable_updates<'i>(
    before_env: &HashMap<String, Expr<'i>>,
    before_stack_bindings: &HashMap<String, i64>,
    after_env: &HashMap<String, Expr<'i>>,
    types: &HashMap<String, String>,
    after_stack_bindings: &HashMap<String, i64>,
) -> Result<Vec<DebugVariableUpdate<'i>>, CompilerError> {
    let mut names: Vec<String> =
        after_env.keys().chain(after_stack_bindings.keys()).cloned().collect::<HashSet<_>>().into_iter().collect();
    names.sort_unstable();

    let mut updates = Vec::new();
    for name in names {
        let Some(type_name) = types.get(&name) else {
            continue;
        };

        let after_expr = after_env.get(&name).cloned().unwrap_or_else(|| Expr::identifier(name.clone()));
        let expr_changed = before_env.get(&name) != Some(&after_expr);
        let before_runtime_binding = runtime_binding_for_stack_name(&name, before_stack_bindings);
        let after_runtime_binding = runtime_binding_for_stack_name(&name, after_stack_bindings);
        if !expr_changed && before_runtime_binding == after_runtime_binding {
            continue;
        }

        resolve_variable_update(after_env, &mut updates, &name, type_name, after_expr, after_runtime_binding)?;
    }
    Ok(updates)
}

fn resolve_variable_update<'i>(
    env: &HashMap<String, Expr<'i>>,
    updates: &mut Vec<DebugVariableUpdate<'i>>,
    name: &str,
    type_name: &str,
    expr: Expr<'i>,
    runtime_binding: Option<RuntimeBinding>,
) -> Result<(), CompilerError> {
    let resolved = resolve_expr_for_debug(expr, env, &mut HashSet::new())?;
    updates.push(DebugVariableUpdate { name: name.to_string(), type_name: type_name.to_string(), runtime_binding, expr: resolved });
    Ok(())
}

fn collect_console_args<'i>(stmt: &Statement<'i>, env: &HashMap<String, Expr<'i>>) -> Result<Vec<Expr<'i>>, CompilerError> {
    let Statement::Console { args, .. } = stmt else {
        return Ok(Vec::new());
    };

    args.iter().cloned().map(|expr| resolve_expr_for_debug(expr, env, &mut HashSet::new())).collect()
}

fn runtime_binding_for_stack_name(name: &str, stack_bindings: &HashMap<String, i64>) -> Option<RuntimeBinding> {
    stack_bindings.get(name).copied().map(|from_top| RuntimeBinding::DataStackSlot { from_top })
}

fn runtime_binding_for_inline_binding<'i>(expr: &Expr<'i>, stack_bindings: &HashMap<String, i64>) -> Option<RuntimeBinding> {
    match &expr.kind {
        crate::ast::ExprKind::Identifier(identifier) => runtime_binding_for_stack_name(identifier, stack_bindings),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::ast::{Expr, parse_contract_ast};
    use crate::debug_info::{RuntimeBinding, StepKind};

    use super::{DebugRecorder, SourceSpan, collect_variable_updates};

    #[test]
    fn noop_recorders_are_pure_noops() {
        let source = r#"
            contract Demo() {
                entrypoint function spend(int x) {
                    int y = x;
                    require(true);
                }
            }
        "#;
        let contract = parse_contract_ast(source).expect("parse contract");
        let function = contract.functions.first().expect("function");
        let stmt = function.body.first().expect("statement");
        let structs = super::super::build_struct_registry(&contract).expect("build struct registry");

        let mut recorder = DebugRecorder::new(false);
        recorder.record_contract_scope(&contract.params, &[], &contract.constants);
        recorder.begin_entrypoint("spend", function, &contract.fields, &structs).expect("noop begin entrypoint");

        let span = SourceSpan::from(stmt.span());

        recorder.begin_statement_at(0, &HashMap::new(), &HashMap::new());
        recorder.finish_statement_at(stmt, 0, &HashMap::new(), &HashMap::new(), &HashMap::new()).expect("noop statement recording");

        recorder.begin_inline_call(span, 1, function, &HashMap::new(), &HashMap::new()).expect("noop begin call recording");
        recorder.finish_inline_call(span, 2, "callee");
        recorder.record_variable_binding("tmp".to_string(), "int".to_string(), Expr::int(1), None, 2, span);
        recorder.finish_entrypoint(1);

        assert!(recorder.into_debug_info(String::new()).is_none());
    }

    #[test]
    fn active_recorders_preserve_sequences_and_inline_frame_ids() {
        let source = r#"
            contract Demo() {
                entrypoint function spend(int x) {
                    int y = x;
                    require(true);
                }
            }
        "#;
        let contract = parse_contract_ast(source).expect("parse contract");
        let function = contract.functions.first().expect("function");
        let stmt = function.body.first().expect("statement");
        let structs = super::super::build_struct_registry(&contract).expect("build struct registry");

        let mut recorder = DebugRecorder::new(true);
        recorder.begin_entrypoint("spend", function, &contract.fields, &structs).expect("begin entrypoint");

        let mut before = HashMap::new();
        before.insert("x".to_string(), Expr::identifier("x"));

        let mut after = before.clone();
        after.insert("y".to_string(), Expr::int(7));

        let mut types = HashMap::new();
        types.insert("x".to_string(), "int".to_string());
        types.insert("y".to_string(), "int".to_string());

        recorder.begin_statement_at(0, &before, &HashMap::new());
        recorder.finish_statement_at(stmt, 0, &after, &types, &HashMap::new()).expect("record_step first statement");

        let span = SourceSpan::from(stmt.span());
        let mut inline_env = HashMap::new();
        inline_env.insert("x".to_string(), Expr::int(3));
        recorder.begin_inline_call(span, 1, function, &inline_env, &HashMap::new()).expect("begin call recording");
        recorder.record_variable_binding("tmp".to_string(), "int".to_string(), Expr::int(9), None, 1, span);
        recorder.finish_inline_call(span, 2, "callee");

        recorder.finish_entrypoint(2);
        recorder.set_entrypoint_start("spend", 0);

        let info = recorder.into_debug_info(String::new()).expect("debug info available");

        let sequences = info.steps.iter().map(|step| step.sequence).collect::<Vec<_>>();
        assert_eq!(sequences, vec![0, 1, 2, 3]);

        let inline_enter_step = info
            .steps
            .iter()
            .find(|step| matches!(&step.kind, StepKind::InlineCallEnter { .. }) && step.frame_id == 1)
            .expect("inline enter step exists");
        assert!(inline_enter_step.variable_updates.iter().any(|update| update.name == "x"));

        let inline_zero_width_source_step = info
            .steps
            .iter()
            .find(|step| {
                step.is_zero_width()
                    && step.frame_id == 1
                    && matches!(&step.kind, StepKind::Source {})
                    && step.variable_updates.iter().any(|update| update.name == "tmp")
            })
            .expect("inline zero-width source step exists");
        assert_eq!(inline_zero_width_source_step.variable_updates.len(), 1);

        let tmp_update = inline_zero_width_source_step.variable_updates.first().expect("tmp update exists");
        assert_eq!(tmp_update.name, "tmp");

        assert!(info.params.iter().any(|param| param.name == "x"));
    }

    #[test]
    fn collect_variable_updates_records_runtime_slot_changes_without_env_expr() {
        let before_env = HashMap::new();
        let after_env = HashMap::new();
        let before_stack_bindings = HashMap::from([("amount".to_string(), 1)]);
        let after_stack_bindings = HashMap::from([("amount".to_string(), 2)]);
        let types = HashMap::from([("amount".to_string(), "int".to_string())]);

        let updates = collect_variable_updates(&before_env, &before_stack_bindings, &after_env, &types, &after_stack_bindings)
            .expect("collect updates");

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "amount");
        assert_eq!(updates[0].expr, Expr::identifier("amount"));
        assert_eq!(updates[0].runtime_binding, Some(RuntimeBinding::DataStackSlot { from_top: 2 }));
    }
}
