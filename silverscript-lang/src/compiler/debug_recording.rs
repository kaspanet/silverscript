use std::collections::{HashMap, HashSet};

use kaspa_txscript::script_builder::ScriptBuilder;

use crate::ast::{Expr, FunctionAst, ParamAst, SourceSpan, Statement};
use crate::debug::{
    DebugConstantMapping, DebugEvent, DebugEventKind, DebugFunctionRange, DebugInfo, DebugParamMapping, DebugRecorder,
    DebugVariableUpdate,
};

use super::{CompilerError, resolve_expr_for_debug};

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
}

impl FunctionDebugRecorder {
    pub fn new(enabled: bool, function: &FunctionAst) -> Self {
        let mut recorder = Self { function_name: function.name.clone(), enabled, call_depth: 0, frame_id: 0, ..Default::default() };
        recorder.record_params(function);
        recorder
    }

    pub fn inline(enabled: bool, function_name: String, call_depth: u32, frame_id: u32) -> Self {
        Self { function_name, enabled, call_depth, frame_id, ..Default::default() }
    }

    pub fn sequence_count(&self) -> u32 {
        self.next_seq
    }

    pub fn call_depth(&self) -> u32 {
        self.call_depth
    }

    pub fn new_inline_child(&self, frame_id: u32) -> Self {
        Self::inline(self.enabled, self.function_name.clone(), self.call_depth().saturating_add(1), frame_id)
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

    fn record_params(&mut self, function: &FunctionAst) {
        if !self.enabled {
            return;
        }
        let param_count = function.params.len();
        for (index, param) in function.params.iter().enumerate() {
            self.param_mappings.push(DebugParamMapping {
                name: param.name.clone(),
                type_name: param.type_name.clone(),
                stack_index: (param_count - 1 - index) as i64,
                function: function.name.clone(),
            });
        }
    }

    pub fn record_statement(&mut self, stmt: &Statement, bytecode_start: usize, bytecode_len: usize) -> Option<u32> {
        let kind = if bytecode_len == 0 { DebugEventKind::Virtual {} } else { DebugEventKind::Statement {} };
        self.push_event(bytecode_start, bytecode_start + bytecode_len, stmt.span, kind)
    }

    pub fn record_virtual_step(&mut self, span: Option<SourceSpan>, bytecode_offset: usize) -> Option<u32> {
        self.push_event(bytecode_offset, bytecode_offset, span, DebugEventKind::Virtual {})
    }

    pub fn record_statement_updates(
        &mut self,
        stmt: &Statement,
        bytecode_start: usize,
        bytecode_end: usize,
        variables: Vec<(String, String, Expr)>,
    ) {
        if let Some(sequence) = self.record_statement(stmt, bytecode_start, bytecode_end.saturating_sub(bytecode_start)) {
            self.record_variable_updates(variables, bytecode_end, stmt.span, sequence);
        }
    }

    pub fn record_virtual_updates(
        &mut self,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
        variables: Vec<(String, String, Expr)>,
    ) {
        if let Some(sequence) = self.record_virtual_step(span, bytecode_offset) {
            self.record_variable_updates(variables, bytecode_offset, span, sequence);
        }
    }

    pub fn record_inline_param_updates(
        &mut self,
        function: &FunctionAst,
        env: &HashMap<String, Expr>,
        span: Option<SourceSpan>,
        bytecode_offset: usize,
    ) -> Result<(), CompilerError> {
        if !self.enabled {
            return Ok(());
        }
        let mut variables = Vec::with_capacity(function.params.len());
        for param in &function.params {
            self.variable_update(
                env,
                &mut variables,
                &param.name,
                &param.type_name,
                env.get(&param.name).cloned().unwrap_or(Expr::Identifier(param.name.clone())),
            )?;
        }
        self.record_virtual_updates(span, bytecode_offset, variables);
        Ok(())
    }

    pub fn record_inline_call_enter(&mut self, span: Option<SourceSpan>, bytecode_offset: usize, callee: &str) -> Option<u32> {
        self.push_event(bytecode_offset, bytecode_offset, span, DebugEventKind::InlineCallEnter { callee: callee.to_string() })
    }

    pub fn record_inline_call_exit(&mut self, span: Option<SourceSpan>, bytecode_offset: usize, callee: &str) -> Option<u32> {
        self.push_event(bytecode_offset, bytecode_offset, span, DebugEventKind::InlineCallExit { callee: callee.to_string() })
    }

    pub fn merge_inline_events(&mut self, inline: &FunctionDebugRecorder) {
        if !self.enabled || inline.events.is_empty() {
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
    }

    pub(super) fn record_variable_updates(
        &mut self,
        variables: Vec<(String, String, Expr)>,
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

    /// Records a variable update by resolving its expression against the current environment.
    /// This expands all local variable references inline, leaving only param identifiers.
    /// The resolved expression is what enables shadow VM evaluation at debug time.
    pub(super) fn variable_update(
        &self,
        env: &HashMap<String, Expr>,
        variables: &mut Vec<(String, String, Expr)>,
        name: &str,
        type_name: &str,
        expr: Expr,
    ) -> Result<(), CompilerError> {
        if !self.enabled {
            return Ok(());
        }
        let resolved = resolve_expr_for_debug(expr, env, &mut HashSet::new())?;
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
                type_name: param.type_name.clone(),
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
