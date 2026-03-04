use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::ast::{ContractFieldAst, Expr, FunctionAst, ParamAst, Statement};
use crate::debug_info::{
    DebugConstantMapping, DebugFunctionRange, DebugInfo, DebugParamMapping, DebugRecorder, DebugStep, DebugVariableUpdate, SourceSpan,
    StepKind,
};

use super::{CompilerError, resolve_expr_for_debug};

/// Per-function debug recorder active during function compilation.
/// Records params, statements, and variable updates for a single function.
/// When disabled (`inner` is `None`), all methods are zero-cost no-ops.
pub struct FunctionRecorder<'i> {
    inner: Option<ActiveFunctionRecorder<'i>>,
}

impl fmt::Debug for FunctionRecorder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionRecorder").finish_non_exhaustive()
    }
}

impl<'i> FunctionRecorder<'i> {
    pub fn new(enabled: bool, function: &FunctionAst<'i>, contract_fields: &[ContractFieldAst<'i>]) -> Self {
        if enabled { Self { inner: Some(ActiveFunctionRecorder::new(function, contract_fields)) } } else { Self { inner: None } }
    }

    pub fn record_statement_with_env_diff(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_start: usize,
        bytecode_end: usize,
        before_env: Option<&HashMap<String, Expr<'i>>>,
        after_env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
    ) -> Result<(), CompilerError> {
        if let Some(rec) = &mut self.inner {
            let updates = rec.collect_variable_updates(before_env, after_env, types)?;
            rec.record_statement_step(stmt, bytecode_start, bytecode_end, updates);
        }
        Ok(())
    }

    pub fn record_binding(&mut self, name: String, type_name: String, expr: Expr<'i>, bytecode_offset: usize, span: SourceSpan) {
        if let Some(rec) = &mut self.inner {
            let step_index = rec.push_step(bytecode_offset, bytecode_offset, span, StepKind::Source {});
            rec.steps[step_index].variable_updates.push(DebugVariableUpdate { name, type_name, expr });
        }
    }

    pub fn begin_call(
        &mut self,
        span: SourceSpan,
        bytecode_offset: usize,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
    ) -> Result<(), CompilerError> {
        match &mut self.inner {
            Some(rec) => {
                let parent_depth = rec.current_call_depth();
                let callee_frame_id = rec.allocate_frame_id();
                let enter_step_index = rec.push_step_with_context(
                    bytecode_offset,
                    bytecode_offset,
                    span,
                    StepKind::InlineCallEnter { callee: function.name.clone() },
                    parent_depth,
                    callee_frame_id,
                );

                let mut updates = Vec::new();
                for param in &function.params {
                    rec.resolve_variable_update(
                        env,
                        &mut updates,
                        &param.name,
                        &param.type_ref.type_name(),
                        env.get(&param.name).cloned().unwrap_or_else(|| Expr::identifier(param.name.clone())),
                    )?;
                }
                rec.add_updates_to_step(enter_step_index, updates);
                rec.push_call_frame(callee_frame_id, parent_depth.saturating_add(1));
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn finish_call(&mut self, span: SourceSpan, bytecode_offset: usize, callee: &str) {
        if let Some(rec) = &mut self.inner {
            rec.pop_call_frame();
            rec.push_step(bytecode_offset, bytecode_offset, span, StepKind::InlineCallExit { callee: callee.to_string() });
        }
    }

    pub fn step_count(&self) -> u32 {
        self.inner.as_ref().map_or(0, |rec| rec.next_step_sequence)
    }

    pub fn emit_steps_with_offset(&self, offset: usize, seq_base: u32, recorder: &mut DebugRecorder<'i>) {
        if let Some(rec) = &self.inner {
            for step in &rec.steps {
                recorder.record_step(DebugStep {
                    bytecode_start: step.bytecode_start + offset,
                    bytecode_end: step.bytecode_end + offset,
                    span: step.span,
                    kind: step.kind.clone(),
                    sequence: seq_base.saturating_add(step.sequence),
                    call_depth: step.call_depth,
                    frame_id: step.frame_id,
                    variable_updates: step.variable_updates.clone(),
                });
            }
            for param in &rec.params {
                recorder.record_param(param.clone());
            }
        }
    }

    pub fn begin_statement(&mut self, builder: &super::ScriptBuilder, env: &HashMap<String, Expr<'i>>) -> StatementGuard<'i> {
        StatementGuard { start: builder.script().len(), env_before: self.inner.as_ref().map(|_| env.clone()) }
    }
}

pub struct StatementGuard<'i> {
    start: usize,
    env_before: Option<HashMap<String, Expr<'i>>>,
}

impl<'i> StatementGuard<'i> {
    /// Finishes recording: snapshots the current bytecode offset, diffs the env,
    /// and records the debug step on the given recorder.
    pub fn finish(
        self,
        recorder: &mut FunctionRecorder<'i>,
        stmt: &Statement<'i>,
        builder: &super::ScriptBuilder,
        env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
    ) -> Result<(), CompilerError> {
        let end = builder.script().len();
        recorder.record_statement_with_env_diff(stmt, self.start, end, self.env_before.as_ref(), env, types)
    }
}

#[derive(Debug, Default)]
struct ActiveFunctionRecorder<'i> {
    steps: Vec<DebugStep<'i>>,
    params: Vec<DebugParamMapping>,
    next_step_sequence: u32,
    call_stack: Vec<CallFrame>,
    next_frame_id: u32,
}

#[derive(Debug, Clone, Copy)]
struct CallFrame {
    frame_id: u32,
    call_depth: u32,
}

impl<'i> ActiveFunctionRecorder<'i> {
    fn new(function: &FunctionAst<'i>, contract_fields: &[ContractFieldAst<'i>]) -> Self {
        let mut recorder = Self { call_stack: vec![CallFrame { frame_id: 0, call_depth: 0 }], next_frame_id: 1, ..Default::default() };
        recorder.record_param_bindings(function, contract_fields);
        recorder
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
        let seq = self.next_step_sequence;
        self.next_step_sequence = self.next_step_sequence.saturating_add(1);
        seq
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
        });
        self.steps.len().saturating_sub(1)
    }

    fn record_param_bindings(&mut self, function: &FunctionAst<'i>, contract_fields: &[ContractFieldAst<'i>]) {
        let param_count = function.params.len();
        let field_count = contract_fields.len();
        for (index, param) in function.params.iter().enumerate() {
            self.params.push(DebugParamMapping {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                stack_index: (field_count + (param_count - 1 - index)) as i64,
                function: function.name.clone(),
            });
        }
        for (index, field) in contract_fields.iter().enumerate() {
            self.params.push(DebugParamMapping {
                name: field.name.clone(),
                type_name: field.type_ref.type_name(),
                stack_index: (field_count - 1 - index) as i64,
                function: function.name.clone(),
            });
        }
    }

    fn record_statement_step(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_start: usize,
        bytecode_end: usize,
        updates: Vec<DebugVariableUpdate<'i>>,
    ) {
        let span = SourceSpan::from(stmt.span());
        let bytecode_len = bytecode_end.saturating_sub(bytecode_start);
        let step_index = self.push_step(bytecode_start, bytecode_start + bytecode_len, span, StepKind::Source {});
        self.add_updates_to_step(step_index, updates);
    }

    fn add_updates_to_step(&mut self, step_index: usize, updates: Vec<DebugVariableUpdate<'i>>) {
        let Some(step) = self.steps.get_mut(step_index) else {
            return;
        };
        step.variable_updates.extend(updates);
    }

    fn collect_variable_updates(
        &self,
        before_env: Option<&HashMap<String, Expr<'i>>>,
        after_env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
    ) -> Result<Vec<DebugVariableUpdate<'i>>, CompilerError> {
        let Some(before_env) = before_env else {
            return Ok(Vec::new());
        };

        let mut names: Vec<String> = after_env.keys().cloned().collect();
        names.sort_unstable();

        let mut updates = Vec::new();
        for name in names {
            if name.starts_with("__arg_") {
                continue;
            }
            let Some(after_expr) = after_env.get(&name) else {
                continue;
            };
            if before_env.get(&name).is_some_and(|before_expr| before_expr == after_expr) {
                continue;
            }
            let Some(type_name) = types.get(&name) else {
                continue;
            };
            self.resolve_variable_update(after_env, &mut updates, &name, type_name, after_expr.clone())?;
        }
        Ok(updates)
    }

    fn resolve_variable_update(
        &self,
        env: &HashMap<String, Expr<'i>>,
        updates: &mut Vec<DebugVariableUpdate<'i>>,
        name: &str,
        type_name: &str,
        expr: Expr<'i>,
    ) -> Result<(), CompilerError> {
        let resolved = resolve_expr_for_debug(expr, env, &mut HashSet::new())?;
        updates.push(DebugVariableUpdate { name: name.to_string(), type_name: type_name.to_string(), expr: resolved });
        Ok(())
    }
}

/// Contract-level debug recorder that merges per-function recordings.
/// When disabled (`inner` is `None`), all methods are zero-cost no-ops.
pub struct ContractRecorder<'i> {
    inner: Option<ActiveContractRecorder<'i>>,
}

impl fmt::Debug for ContractRecorder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContractRecorder").finish_non_exhaustive()
    }
}

impl<'i> ContractRecorder<'i> {
    pub fn new(enabled: bool) -> Self {
        if enabled { Self { inner: Some(ActiveContractRecorder::default()) } } else { Self { inner: None } }
    }

    pub fn record_constructor_constants(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>]) {
        if let Some(rec) = &mut self.inner {
            for (param, value) in params.iter().zip(values.iter()) {
                rec.recorder.record_constant(DebugConstantMapping {
                    name: param.name.clone(),
                    type_name: param.type_ref.type_name(),
                    value: value.clone(),
                });
            }
        }
    }

    pub fn record_compiled_function(&mut self, name: &str, script_len: usize, debug: &FunctionRecorder<'i>, offset: usize) {
        if let Some(rec) = &mut self.inner {
            let seq_base = rec.recorder.reserve_sequence_block(debug.step_count());
            debug.emit_steps_with_offset(offset, seq_base, &mut rec.recorder);
            rec.recorder.record_function(DebugFunctionRange {
                name: name.to_string(),
                bytecode_start: offset,
                bytecode_end: offset + script_len,
            });
        }
    }

    pub fn into_debug_info(self, source: String) -> Option<DebugInfo<'i>> {
        self.inner.map(|rec| rec.recorder.into_debug_info(source))
    }
}

#[derive(Debug, Default)]
struct ActiveContractRecorder<'i> {
    recorder: DebugRecorder<'i>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::ast::{Expr, parse_contract_ast};
    use crate::debug_info::StepKind;

    use super::{ContractRecorder, FunctionRecorder, SourceSpan};

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

        let mut recorder = FunctionRecorder::new(false, function, &contract.fields);

        let span = SourceSpan::from(stmt.span());

        recorder.record_statement_with_env_diff(stmt, 0, 1, None, &HashMap::new(), &HashMap::new()).expect("noop statement recording");

        recorder.begin_call(span, 1, function, &HashMap::new()).expect("noop begin call recording");
        recorder.finish_call(span, 2, "callee");
        recorder.record_binding("tmp".to_string(), "int".to_string(), Expr::int(1), 2, span);
        assert_eq!(recorder.step_count(), 0);

        let mut sink = ContractRecorder::new(false);
        sink.record_constructor_constants(&contract.params, &[]);
        sink.record_compiled_function("spend", 1, &recorder, 0);
        assert!(sink.into_debug_info(String::new()).is_none());
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

        let mut recorder = FunctionRecorder::new(true, function, &contract.fields);

        let mut before = HashMap::new();
        before.insert("x".to_string(), Expr::identifier("x"));

        let mut after = before.clone();
        after.insert("y".to_string(), Expr::int(7));

        let mut types = HashMap::new();
        types.insert("x".to_string(), "int".to_string());
        types.insert("y".to_string(), "int".to_string());

        recorder.record_statement_with_env_diff(stmt, 0, 1, Some(&before), &after, &types).expect("record_step first statement");

        let span = SourceSpan::from(stmt.span());
        let mut inline_env = HashMap::new();
        inline_env.insert("x".to_string(), Expr::int(3));
        recorder.begin_call(span, 1, function, &inline_env).expect("begin call recording");
        recorder.record_binding("tmp".to_string(), "int".to_string(), Expr::int(9), 1, span);
        recorder.finish_call(span, 2, "callee");

        assert_eq!(recorder.step_count(), 4);

        let mut sink = ContractRecorder::new(true);
        sink.record_compiled_function("spend", 2, &recorder, 0);
        let info = sink.into_debug_info(String::new()).expect("debug info available");

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
}
