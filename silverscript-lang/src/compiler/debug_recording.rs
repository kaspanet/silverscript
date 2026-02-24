use std::collections::{HashMap, HashSet};

use kaspa_txscript::script_builder::ScriptBuilder;

use crate::ast::{ContractFieldAst, Expr, FunctionAst, ParamAst, SpannedStatement};
use crate::debug::{
    DebugConstantMapping, DebugEvent, DebugEventKind, DebugFunctionRange, DebugInfo, DebugParamMapping, DebugRecorder,
    DebugVariableUpdate, SourceSpan,
};

use super::{CompilerError, expand_inline_args, resolve_expr};

type ResolvedVariableUpdate = (String, String, Expr);

pub(super) fn record_synthetic_range(
    builder: &mut ScriptBuilder,
    recorder: &mut DebugSink,
    label: &'static str,
    f: impl FnOnce(&mut ScriptBuilder) -> Result<(), CompilerError>,
) -> Result<(), CompilerError> {
    let start = builder.script().len();
    f(builder)?;
    let end = builder.script().len();
    recorder.record_synthetic_range(start, end, label);
    Ok(())
}

/// Per-function debug recorder active during function compilation.
/// Records params, statements, and variable updates for a single function.
#[derive(Debug, Default)]
pub struct FunctionDebugRecorder {
    function_name: String,
    enabled: bool,
    events: Vec<DebugEvent>,
    variable_updates: Vec<DebugVariableUpdate>,
    param_mappings: Vec<DebugParamMapping>,
    next_seq: u32,
    call_depth: u32,
    frame_id: u32,
    next_frame_id: u32,
}

impl FunctionDebugRecorder {
    pub fn new(enabled: bool, function: &FunctionAst, contract_fields: &[ContractFieldAst]) -> Self {
        let mut recorder =
            Self { function_name: function.name.clone(), enabled, call_depth: 0, frame_id: 0, next_frame_id: 1, ..Default::default() };
        recorder.record_stack_bindings(function, contract_fields);
        recorder
    }

    fn sequence_count(&self) -> u32 {
        self.next_seq
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn new_inline_child(&mut self) -> Self {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.saturating_add(1);
        Self {
            function_name: self.function_name.clone(),
            enabled: self.enabled,
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

    fn push_event(
        &mut self,
        bytecode_start: usize,
        bytecode_end: usize,
        span: Option<SourceSpan>,
        kind: DebugEventKind,
    ) -> Option<u32> {
        if !self.enabled {
            return None;
        }
        let sequence = self.next_sequence();
        self.events.push(DebugEvent {
            bytecode_start,
            bytecode_end,
            span,
            kind,
            sequence,
            call_depth: self.call_depth,
            frame_id: self.frame_id,
        });
        Some(sequence)
    }

    fn record_stack_bindings(&mut self, function: &FunctionAst, contract_fields: &[ContractFieldAst]) {
        if !self.enabled {
            return;
        }
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

    fn record_statement_span(&mut self, span: Option<SourceSpan>, bytecode_start: usize, bytecode_len: usize) -> Option<u32> {
        let kind = if bytecode_len == 0 { DebugEventKind::Virtual {} } else { DebugEventKind::Statement {} };
        self.push_event(bytecode_start, bytecode_start + bytecode_len, span, kind)
    }

    fn record_statement_updates(
        &mut self,
        stmt: &SpannedStatement,
        bytecode_start: usize,
        bytecode_end: usize,
        variables: Vec<ResolvedVariableUpdate>,
    ) {
        if let Some(sequence) = self.record_statement_span(stmt.span, bytecode_start, bytecode_end.saturating_sub(bytecode_start)) {
            self.record_variable_updates(variables, bytecode_end, stmt.span, sequence);
        }
    }

    /// Records one source step for `stmt` and emits variable updates for names
    /// whose expressions changed between `before_env` and `after_env`.
    /// Stored expressions are resolved against `after_env` so debugger shadow
    /// evaluation can compute values from the current state.
    pub fn record_statement_with_env_diff(
        &mut self,
        stmt: &SpannedStatement,
        bytecode_start: usize,
        bytecode_end: usize,
        before_env: Option<&HashMap<String, Expr>>,
        after_env: &HashMap<String, Expr>,
        types: &HashMap<String, String>,
    ) -> Result<(), CompilerError> {
        let updates = self.collect_variable_updates(before_env, after_env, types)?;
        self.record_statement_updates(stmt, bytecode_start, bytecode_end, updates);
        Ok(())
    }

    /// Starts an inline call recording session and returns a child recorder for
    /// callee body statements.
    pub fn start_inline_call_recording(&mut self, span: Option<SourceSpan>, bytecode_offset: usize, callee: &str) -> Self {
        self.push_event(bytecode_offset, bytecode_offset, span, DebugEventKind::InlineCallEnter { callee: callee.to_string() });
        self.new_inline_child()
    }

    /// Merges recorded callee events and emits the inline exit marker.
    pub fn finish_inline_call_recording(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        callee: &str,
        inline: &FunctionDebugRecorder,
    ) {
        self.merge_inline_events(inline);
        self.push_event(bytecode_offset, bytecode_offset, span, DebugEventKind::InlineCallExit { callee: callee.to_string() });
    }

    fn merge_inline_events(&mut self, inline: &FunctionDebugRecorder) {
        if !self.enabled || inline.events.is_empty() {
            self.next_frame_id = self.next_frame_id.max(inline.next_frame_id);
            return;
        }
        let mut seq_map: HashMap<u32, u32> = HashMap::new();
        let mut events = inline.events.clone();
        events.sort_by_key(|event| event.sequence);

        for mut event in events {
            let local_seq = event.sequence;
            let merged_seq = self.next_sequence();
            event.sequence = merged_seq;
            self.events.push(event);
            seq_map.insert(local_seq, merged_seq);
        }

        let mut updates = inline.variable_updates.clone();
        updates.sort_by_key(|update| update.sequence);
        for mut update in updates {
            if let Some(merged_seq) = seq_map.get(&update.sequence) {
                update.sequence = *merged_seq;
                self.variable_updates.push(update);
            }
        }
        self.next_frame_id = self.next_frame_id.max(inline.next_frame_id);
    }

    fn record_variable_updates(
        &mut self,
        variables: Vec<ResolvedVariableUpdate>,
        bytecode_offset: usize,
        span: Option<SourceSpan>,
        sequence: u32,
    ) {
        if !self.enabled {
            return;
        }
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
        before_env: Option<&HashMap<String, Expr>>,
        after_env: &HashMap<String, Expr>,
        types: &HashMap<String, String>,
    ) -> Result<Vec<ResolvedVariableUpdate>, CompilerError> {
        if !self.enabled {
            return Ok(Vec::new());
        }
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
    /// The resolved expression is what enables shadow VM evaluation at debug time.
    fn variable_update(
        &self,
        env: &HashMap<String, Expr>,
        variables: &mut Vec<ResolvedVariableUpdate>,
        name: &str,
        type_name: &str,
        expr: Expr,
    ) -> Result<(), CompilerError> {
        if !self.enabled {
            return Ok(());
        }
        let resolved = resolve_expr(expr, env, &mut HashSet::new())?;
        let resolved = expand_inline_args(resolved, env, &mut HashSet::new())?;
        variables.push((name.to_string(), type_name.to_string(), resolved));
        Ok(())
    }
}

/// Global debug recording sink that can be enabled or disabled.
/// When Off, all recording calls become no-ops with zero overhead.
pub enum DebugSink {
    Off,
    On(DebugRecorder),
}

impl DebugSink {
    pub fn new(enabled: bool) -> Self {
        if enabled { Self::On(DebugRecorder::default()) } else { Self::Off }
    }

    fn recorder_mut(&mut self) -> Option<&mut DebugRecorder> {
        match self {
            Self::Off => None,
            Self::On(rec) => Some(rec),
        }
    }

    pub fn record_constructor_constants(&mut self, params: &[ParamAst], values: &[Expr]) {
        let Some(rec) = self.recorder_mut() else {
            return;
        };
        for (param, value) in params.iter().zip(values.iter()) {
            rec.record_constant(DebugConstantMapping {
                name: param.name.clone(),
                type_name: param.type_ref.type_name(),
                value: value.clone(),
            });
        }
    }

    pub fn record_synthetic_range(&mut self, start: usize, end: usize, label: &'static str) {
        if end <= start {
            return;
        }
        let Some(rec) = self.recorder_mut() else {
            return;
        };
        let sequence = rec.next_sequence();
        rec.record(DebugEvent {
            bytecode_start: start,
            bytecode_end: end,
            span: None,
            kind: DebugEventKind::Synthetic { label: label.to_string() },
            sequence,
            call_depth: 0,
            frame_id: 0,
        });
    }

    pub fn record_compiled_function(&mut self, name: &str, script_len: usize, debug: &FunctionDebugRecorder, offset: usize) {
        let Some(rec) = self.recorder_mut() else {
            return;
        };
        let seq_base = rec.reserve_sequence_block(debug.sequence_count());
        emit_events_with_offset(&debug.events, offset, seq_base, rec);
        emit_variable_updates_with_offset(&debug.variable_updates, offset, seq_base, rec);
        rec.record_function(DebugFunctionRange { name: name.to_string(), bytecode_start: offset, bytecode_end: offset + script_len });
        record_param_mappings(&debug.param_mappings, rec);
    }

    pub fn into_debug_info(self, source: String) -> Option<DebugInfo> {
        match self {
            Self::Off => None,
            Self::On(rec) => Some(rec.into_debug_info(source)),
        }
    }
}

fn emit_events_with_offset(events: &[DebugEvent], offset: usize, seq_base: u32, recorder: &mut DebugRecorder) {
    for event in events {
        recorder.record(DebugEvent {
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

fn emit_variable_updates_with_offset(updates: &[DebugVariableUpdate], offset: usize, seq_base: u32, recorder: &mut DebugRecorder) {
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

fn record_param_mappings(params: &[DebugParamMapping], recorder: &mut DebugRecorder) {
    for param in params {
        recorder.record_param(param.clone());
    }
}
