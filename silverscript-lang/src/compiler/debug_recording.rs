use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::ast::{ContractFieldAst, Expr, FunctionAst, ParamAst, Statement};
use crate::debug_info::{
    DebugConstantMapping, DebugFunctionRange, DebugInfo, DebugMapping, DebugParamMapping, DebugRecorder, DebugVariableUpdate,
    MappingKind, SourceSpan,
};

use super::{CompilerError, resolve_expr_for_debug};

type ResolvedVariableUpdate<'i> = (String, String, Expr<'i>);

#[derive(Clone)]
struct FunctionRecorderSnapshot<'i> {
    events: Vec<DebugMapping>,
    variable_updates: Vec<DebugVariableUpdate<'i>>,
    next_frame_id: u32,
}

trait FunctionRecorderImpl<'i> {
    fn capture_env_snapshot(&self, env: &HashMap<String, Expr<'i>>) -> Option<HashMap<String, Expr<'i>>>;

    fn record_statement_with_env_diff(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_start: usize,
        bytecode_end: usize,
        before_env: Option<&HashMap<String, Expr<'i>>>,
        after_env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
    ) -> Result<(), CompilerError>;

    fn record_inline_param_updates(
        &mut self,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
    ) -> Result<(), CompilerError>;

    fn record_virtual_binding(
        &mut self,
        name: String,
        type_name: String,
        expr: Expr<'i>,
        bytecode_offset: usize,
        span: Option<SourceSpan>,
    );

    fn start_inline_call_recording(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        callee: &str,
    ) -> Box<dyn FunctionRecorderImpl<'i> + 'i>;

    fn finish_inline_call_recording(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        callee: &str,
        inline: &dyn FunctionRecorderImpl<'i>,
    );

    fn sequence_count(&self) -> u32;

    fn emit_with_offset(&self, offset: usize, seq_base: u32, recorder: &mut DebugRecorder<'i>);

    fn snapshot(&self) -> Option<FunctionRecorderSnapshot<'i>>;
}

/// Per-function debug recorder active during function compilation.
/// Records params, statements, and variable updates for a single function.
pub struct FunctionRecorder<'i> {
    imp: Box<dyn FunctionRecorderImpl<'i> + 'i>,
}

impl fmt::Debug for FunctionRecorder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionRecorder").finish_non_exhaustive()
    }
}

impl<'i> FunctionRecorder<'i> {
    pub fn new(enabled: bool, function: &FunctionAst<'i>, contract_fields: &[ContractFieldAst<'i>]) -> Self {
        if enabled {
            Self { imp: Box::new(ActiveFunctionRecorder::new(function, contract_fields)) }
        } else {
            Self { imp: Box::new(NoopFunctionRecorder) }
        }
    }

    fn from_impl(imp: Box<dyn FunctionRecorderImpl<'i> + 'i>) -> Self {
        Self { imp }
    }

    pub fn capture_env_snapshot(&self, env: &HashMap<String, Expr<'i>>) -> Option<HashMap<String, Expr<'i>>> {
        self.imp.capture_env_snapshot(env)
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
        self.imp.record_statement_with_env_diff(stmt, bytecode_start, bytecode_end, before_env, after_env, types)
    }

    pub fn record_inline_param_updates(
        &mut self,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
    ) -> Result<(), CompilerError> {
        self.imp.record_inline_param_updates(function, env, span, bytecode_offset)
    }

    pub fn record_virtual_binding(
        &mut self,
        name: String,
        type_name: String,
        expr: Expr<'i>,
        bytecode_offset: usize,
        span: Option<SourceSpan>,
    ) {
        self.imp.record_virtual_binding(name, type_name, expr, bytecode_offset, span)
    }

    pub fn start_inline_call_recording(&mut self, span: Option<SourceSpan>, bytecode_offset: usize, callee: &str) -> Self {
        Self::from_impl(self.imp.start_inline_call_recording(span, bytecode_offset, callee))
    }

    pub fn finish_inline_call_recording(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        callee: &str,
        inline: &FunctionRecorder<'i>,
    ) {
        self.imp.finish_inline_call_recording(span, bytecode_offset, callee, inline.imp.as_ref());
    }

    pub fn sequence_count(&self) -> u32 {
        self.imp.sequence_count()
    }

    pub fn emit_with_offset(&self, offset: usize, seq_base: u32, recorder: &mut DebugRecorder<'i>) {
        self.imp.emit_with_offset(offset, seq_base, recorder);
    }
}

#[derive(Debug, Default)]
struct NoopFunctionRecorder;

impl<'i> FunctionRecorderImpl<'i> for NoopFunctionRecorder {
    fn capture_env_snapshot(&self, _env: &HashMap<String, Expr<'i>>) -> Option<HashMap<String, Expr<'i>>> {
        None
    }

    fn record_statement_with_env_diff(
        &mut self,
        _stmt: &Statement<'i>,
        _bytecode_start: usize,
        _bytecode_end: usize,
        _before_env: Option<&HashMap<String, Expr<'i>>>,
        _after_env: &HashMap<String, Expr<'i>>,
        _types: &HashMap<String, String>,
    ) -> Result<(), CompilerError> {
        Ok(())
    }

    fn record_inline_param_updates(
        &mut self,
        _function: &FunctionAst<'i>,
        _env: &HashMap<String, Expr<'i>>,
        _span: Option<SourceSpan>,
        _bytecode_offset: usize,
    ) -> Result<(), CompilerError> {
        Ok(())
    }

    fn record_virtual_binding(
        &mut self,
        _name: String,
        _type_name: String,
        _expr: Expr<'i>,
        _bytecode_offset: usize,
        _span: Option<SourceSpan>,
    ) {
    }

    fn start_inline_call_recording(
        &mut self,
        _span: Option<SourceSpan>,
        _bytecode_offset: usize,
        _callee: &str,
    ) -> Box<dyn FunctionRecorderImpl<'i> + 'i> {
        Box::new(Self)
    }

    fn finish_inline_call_recording(
        &mut self,
        _span: Option<SourceSpan>,
        _bytecode_offset: usize,
        _callee: &str,
        _inline: &dyn FunctionRecorderImpl<'i>,
    ) {
    }

    fn sequence_count(&self) -> u32 {
        0
    }

    fn emit_with_offset(&self, _offset: usize, _seq_base: u32, _recorder: &mut DebugRecorder<'i>) {}

    fn snapshot(&self) -> Option<FunctionRecorderSnapshot<'i>> {
        None
    }
}

#[derive(Debug, Default)]
struct ActiveFunctionRecorder<'i> {
    function_name: String,
    events: Vec<DebugMapping>,
    variable_updates: Vec<DebugVariableUpdate<'i>>,
    param_mappings: Vec<DebugParamMapping>,
    next_seq: u32,
    call_depth: u32,
    frame_id: u32,
    next_frame_id: u32,
}

impl<'i> ActiveFunctionRecorder<'i> {
    fn new(function: &FunctionAst<'i>, contract_fields: &[ContractFieldAst<'i>]) -> Self {
        let mut recorder =
            Self { function_name: function.name.clone(), call_depth: 0, frame_id: 0, next_frame_id: 1, ..Default::default() };
        recorder.record_stack_bindings(function, contract_fields);
        recorder
    }

    fn new_inline_child(&mut self) -> Self {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.saturating_add(1);
        // Child starts allocating from the parent's current frontier.
        // Parent frontier is reconciled back in `merge_inline_events` after the
        // child returns, so sibling inline calls never reuse frame ids.
        Self {
            function_name: self.function_name.clone(),
            call_depth: self.call_depth.saturating_add(1),
            frame_id,
            next_frame_id: self.next_frame_id,
            ..Default::default()
        }
    }

    fn next_sequence(&mut self) -> u32 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    fn push_event(&mut self, bytecode_start: usize, bytecode_end: usize, span: Option<SourceSpan>, kind: MappingKind) -> u32 {
        let sequence = self.next_sequence();
        self.events.push(DebugMapping {
            bytecode_start,
            bytecode_end,
            span,
            kind,
            sequence,
            call_depth: self.call_depth,
            frame_id: self.frame_id,
        });
        sequence
    }

    fn record_stack_bindings(&mut self, function: &FunctionAst<'i>, contract_fields: &[ContractFieldAst<'i>]) {
        let param_count = function.params.len();
        let field_count = contract_fields.len();
        // Runtime stack layout at function entry is:
        //   top -> contract fields (reverse declaration order), then function args.
        // Keep debug stack indexes aligned with that layout so shadow evaluation
        // reads the same values as normal execution.
        for (index, param) in function.params.iter().enumerate() {
            self.param_mappings.push(DebugParamMapping {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                stack_index: (field_count + (param_count - 1 - index)) as i64,
                function: function.name.clone(),
            });
        }
        for (index, field) in contract_fields.iter().enumerate() {
            self.param_mappings.push(DebugParamMapping {
                name: field.name.clone(),
                type_name: field.type_ref.type_name(),
                stack_index: (field_count - 1 - index) as i64,
                function: function.name.clone(),
            });
        }
    }

    fn record_statement_span(&mut self, span: SourceSpan, bytecode_start: usize, bytecode_len: usize) -> u32 {
        let kind = if bytecode_len == 0 { MappingKind::Virtual {} } else { MappingKind::Statement {} };
        self.push_event(bytecode_start, bytecode_start + bytecode_len, Some(span), kind)
    }

    fn record_statement_updates(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_start: usize,
        bytecode_end: usize,
        variables: Vec<ResolvedVariableUpdate<'i>>,
    ) {
        let span = SourceSpan::from(stmt.span());
        let sequence = self.record_statement_span(span, bytecode_start, bytecode_end.saturating_sub(bytecode_start));
        self.record_variable_updates(variables, bytecode_end, Some(span), sequence);
    }

    fn merge_inline_events(&mut self, inline: FunctionRecorderSnapshot<'i>) {
        if inline.events.is_empty() {
            // Keep frame-id frontier monotonic even if the inline call recorded
            // no events; this preserves uniqueness for later sibling calls.
            self.next_frame_id = self.next_frame_id.max(inline.next_frame_id);
            return;
        }

        let mut seq_map: HashMap<u32, u32> = HashMap::new();
        let mut events = inline.events;
        events.sort_by_key(|event| event.sequence);

        for mut event in events {
            let local_seq = event.sequence;
            let merged_seq = self.next_sequence();
            event.sequence = merged_seq;
            self.events.push(event);
            seq_map.insert(local_seq, merged_seq);
        }

        let mut updates = inline.variable_updates;
        updates.sort_by_key(|update| update.sequence);
        for mut update in updates {
            if let Some(merged_seq) = seq_map.get(&update.sequence) {
                update.sequence = *merged_seq;
                self.variable_updates.push(update);
            }
        }

        // Child may allocate nested frame ids; advance parent frontier so later
        // sibling inline calls start after the whole child subtree.
        self.next_frame_id = self.next_frame_id.max(inline.next_frame_id);
    }

    fn record_variable_updates(
        &mut self,
        variables: Vec<ResolvedVariableUpdate<'i>>,
        bytecode_offset: usize,
        span: Option<SourceSpan>,
        sequence: u32,
    ) {
        for (name, type_name, expr) in variables {
            self.variable_updates.push(DebugVariableUpdate {
                name,
                type_name,
                expr,
                bytecode_offset,
                span,
                function: self.function_name.clone(),
                sequence,
                frame_id: self.frame_id,
            });
        }
    }

    fn collect_variable_updates(
        &self,
        before_env: Option<&HashMap<String, Expr<'i>>>,
        after_env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
    ) -> Result<Vec<ResolvedVariableUpdate<'i>>, CompilerError> {
        let Some(before_env) = before_env else {
            return Ok(Vec::new());
        };

        // Stable ordering keeps debug metadata deterministic across runs.
        let mut names: Vec<String> = after_env.keys().cloned().collect();
        names.sort_unstable();

        let mut updates = Vec::new();
        for name in names {
            // Inline synthetic args are plumbing, not user-facing variables.
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
            self.variable_update(after_env, &mut updates, &name, type_name, after_expr.clone())?;
        }
        Ok(updates)
    }

    /// Records a variable update by resolving its expression against the current environment.
    /// This expands locals and synthetic inline placeholders (`__arg_*`) into
    /// caller-visible expressions, leaving only real param identifiers.
    fn variable_update(
        &self,
        env: &HashMap<String, Expr<'i>>,
        variables: &mut Vec<ResolvedVariableUpdate<'i>>,
        name: &str,
        type_name: &str,
        expr: Expr<'i>,
    ) -> Result<(), CompilerError> {
        let resolved = resolve_expr_for_debug(expr, env, &mut HashSet::new())?;
        variables.push((name.to_string(), type_name.to_string(), resolved));
        Ok(())
    }
}

impl<'i> FunctionRecorderImpl<'i> for ActiveFunctionRecorder<'i> {
    fn capture_env_snapshot(&self, env: &HashMap<String, Expr<'i>>) -> Option<HashMap<String, Expr<'i>>> {
        Some(env.clone())
    }

    fn record_statement_with_env_diff(
        &mut self,
        stmt: &Statement<'i>,
        bytecode_start: usize,
        bytecode_end: usize,
        before_env: Option<&HashMap<String, Expr<'i>>>,
        after_env: &HashMap<String, Expr<'i>>,
        types: &HashMap<String, String>,
    ) -> Result<(), CompilerError> {
        let updates = self.collect_variable_updates(before_env, after_env, types)?;
        self.record_statement_updates(stmt, bytecode_start, bytecode_end, updates);
        Ok(())
    }

    fn record_inline_param_updates(
        &mut self,
        function: &FunctionAst<'i>,
        env: &HashMap<String, Expr<'i>>,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
    ) -> Result<(), CompilerError> {
        // Anchor inline param updates to the next callee statement sequence.
        // We intentionally "peek" (do not consume) so these updates align with
        // the first real callee statement event sequence.
        let sequence = self.next_seq;
        let mut variables = Vec::new();
        for param in &function.params {
            self.variable_update(
                env,
                &mut variables,
                &param.name,
                &param.type_ref.type_name(),
                env.get(&param.name).cloned().unwrap_or_else(|| Expr::identifier(param.name.clone())),
            )?;
        }
        self.record_variable_updates(variables, bytecode_offset, span, sequence);
        Ok(())
    }

    fn record_virtual_binding(
        &mut self,
        name: String,
        type_name: String,
        expr: Expr<'i>,
        bytecode_offset: usize,
        span: Option<SourceSpan>,
    ) {
        let sequence = self.push_event(bytecode_offset, bytecode_offset, span, MappingKind::Virtual {});
        self.variable_updates.push(DebugVariableUpdate {
            name,
            type_name,
            expr,
            bytecode_offset,
            span,
            function: self.function_name.clone(),
            sequence,
            frame_id: self.frame_id,
        });
    }

    fn start_inline_call_recording(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        callee: &str,
    ) -> Box<dyn FunctionRecorderImpl<'i> + 'i> {
        self.push_event(bytecode_offset, bytecode_offset, span, MappingKind::InlineCallEnter { callee: callee.to_string() });
        Box::new(self.new_inline_child())
    }

    fn finish_inline_call_recording(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        callee: &str,
        inline: &dyn FunctionRecorderImpl<'i>,
    ) {
        if let Some(snapshot) = inline.snapshot() {
            self.merge_inline_events(snapshot);
        }
        self.push_event(bytecode_offset, bytecode_offset, span, MappingKind::InlineCallExit { callee: callee.to_string() });
    }

    fn sequence_count(&self) -> u32 {
        self.next_seq
    }

    fn emit_with_offset(&self, offset: usize, seq_base: u32, recorder: &mut DebugRecorder<'i>) {
        emit_events_with_offset(&self.events, offset, seq_base, recorder);
        emit_variable_updates_with_offset(&self.variable_updates, offset, seq_base, recorder);
        record_param_mappings(&self.param_mappings, recorder);
    }

    fn snapshot(&self) -> Option<FunctionRecorderSnapshot<'i>> {
        Some(FunctionRecorderSnapshot {
            events: self.events.clone(),
            variable_updates: self.variable_updates.clone(),
            next_frame_id: self.next_frame_id,
        })
    }
}

trait ContractRecorderImpl<'i> {
    fn record_constructor_constants(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>]);

    fn record_compiled_function(&mut self, name: &str, script_len: usize, debug: &FunctionRecorder<'i>, offset: usize);

    fn into_debug_info(self: Box<Self>, source: String) -> Option<DebugInfo<'i>>;
}

/// Global debug recording sink that can be enabled or disabled.
/// When Off, all recording calls become no-ops with zero overhead.
pub struct ContractRecorder<'i> {
    imp: Box<dyn ContractRecorderImpl<'i> + 'i>,
}

impl fmt::Debug for ContractRecorder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContractRecorder").finish_non_exhaustive()
    }
}

impl<'i> ContractRecorder<'i> {
    pub fn new(enabled: bool) -> Self {
        if enabled { Self { imp: Box::new(ActiveContractRecorder::default()) } } else { Self { imp: Box::new(NoopContractRecorder) } }
    }

    pub fn record_constructor_constants(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>]) {
        self.imp.record_constructor_constants(params, values);
    }

    pub fn record_compiled_function(&mut self, name: &str, script_len: usize, debug: &FunctionRecorder<'i>, offset: usize) {
        self.imp.record_compiled_function(name, script_len, debug, offset);
    }

    pub fn into_debug_info(self, source: String) -> Option<DebugInfo<'i>> {
        self.imp.into_debug_info(source)
    }
}

#[derive(Debug, Default)]
struct NoopContractRecorder;

impl<'i> ContractRecorderImpl<'i> for NoopContractRecorder {
    fn record_constructor_constants(&mut self, _params: &[ParamAst<'i>], _values: &[Expr<'i>]) {}

    fn record_compiled_function(&mut self, _name: &str, _script_len: usize, _debug: &FunctionRecorder<'i>, _offset: usize) {}

    fn into_debug_info(self: Box<Self>, _source: String) -> Option<DebugInfo<'i>> {
        None
    }
}

#[derive(Debug, Default)]
struct ActiveContractRecorder<'i> {
    recorder: DebugRecorder<'i>,
}

impl<'i> ContractRecorderImpl<'i> for ActiveContractRecorder<'i> {
    fn record_constructor_constants(&mut self, params: &[ParamAst<'i>], values: &[Expr<'i>]) {
        for (param, value) in params.iter().zip(values.iter()) {
            self.recorder.record_constant(DebugConstantMapping {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                value: value.clone(),
            });
        }
    }

    fn record_compiled_function(&mut self, name: &str, script_len: usize, debug: &FunctionRecorder<'i>, offset: usize) {
        let seq_base = self.recorder.reserve_sequence_block(debug.sequence_count());
        debug.emit_with_offset(offset, seq_base, &mut self.recorder);
        self.recorder.record_function(DebugFunctionRange {
            name: name.to_string(),
            bytecode_start: offset,
            bytecode_end: offset + script_len,
        });
    }

    fn into_debug_info(self: Box<Self>, source: String) -> Option<DebugInfo<'i>> {
        Some(self.recorder.into_debug_info(source))
    }
}

fn emit_events_with_offset(events: &[DebugMapping], offset: usize, seq_base: u32, recorder: &mut DebugRecorder<'_>) {
    for event in events {
        recorder.record(DebugMapping {
            bytecode_start: event.bytecode_start + offset,
            bytecode_end: event.bytecode_end + offset,
            span: event.span,
            kind: event.kind.clone(),
            sequence: seq_base.saturating_add(event.sequence),
            call_depth: event.call_depth,
            frame_id: event.frame_id,
        });
    }
}

fn emit_variable_updates_with_offset<'i>(
    updates: &[DebugVariableUpdate<'i>],
    offset: usize,
    seq_base: u32,
    recorder: &mut DebugRecorder<'i>,
) {
    for update in updates {
        recorder.record_variable_update(DebugVariableUpdate {
            name: update.name.clone(),
            type_name: update.type_name.clone(),
            expr: update.expr.clone(),
            bytecode_offset: update.bytecode_offset + offset,
            span: update.span,
            function: update.function.clone(),
            sequence: seq_base.saturating_add(update.sequence),
            frame_id: update.frame_id,
        });
    }
}

fn record_param_mappings(params: &[DebugParamMapping], recorder: &mut DebugRecorder<'_>) {
    for param in params {
        recorder.record_param(param.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::ast::{Expr, parse_contract_ast};
    use crate::debug_info::MappingKind;

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
        assert!(recorder.capture_env_snapshot(&HashMap::new()).is_none());

        recorder.record_statement_with_env_diff(stmt, 0, 1, None, &HashMap::new(), &HashMap::new()).expect("noop statement recording");

        let inline = recorder.start_inline_call_recording(None, 1, "callee");
        recorder.finish_inline_call_recording(None, 2, "callee", &inline);
        recorder.record_virtual_binding("tmp".to_string(), "int".to_string(), Expr::int(1), 2, None);
        assert_eq!(recorder.sequence_count(), 0);

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

        recorder.record_statement_with_env_diff(stmt, 0, 1, Some(&before), &after, &types).expect("record first statement");

        let span = SourceSpan::from(stmt.span());
        let mut inline = recorder.start_inline_call_recording(Some(span), 1, "callee");
        inline.record_virtual_binding("tmp".to_string(), "int".to_string(), Expr::int(9), 1, Some(span));
        recorder.finish_inline_call_recording(Some(span), 2, "callee", &inline);

        assert_eq!(recorder.sequence_count(), 4);

        let mut sink = ContractRecorder::new(true);
        sink.record_compiled_function("spend", 2, &recorder, 0);
        let info = sink.into_debug_info(String::new()).expect("debug info available");

        let sequences = info.mappings.iter().map(|mapping| mapping.sequence).collect::<Vec<_>>();
        assert_eq!(sequences, vec![0, 1, 2, 3]);

        let virtual_mapping =
            info.mappings.iter().find(|mapping| matches!(&mapping.kind, MappingKind::Virtual {})).expect("virtual mapping exists");
        assert_eq!(virtual_mapping.frame_id, 1);

        let tmp_update = info.variable_updates.iter().find(|update| update.name == "tmp").expect("tmp update exists");
        assert_eq!(tmp_update.frame_id, 1);
        assert_eq!(tmp_update.sequence, virtual_mapping.sequence);

        assert!(info.params.iter().any(|param| param.name == "x"));
    }
}
