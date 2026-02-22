use std::collections::{HashMap, HashSet};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{DynOpcodeImplementation, EngineCtx, EngineFlags, TxScriptEngine, parse_script};
use serde::{Deserialize, Serialize};

use crate::ast::{Expr, SourceSpan};
use crate::compiler::compile_debug_expr;
use crate::debug::{DebugFunctionRange, DebugInfo, DebugMapping, DebugParamMapping, DebugVariableUpdate, MappingKind};

fn encode_hex(bytes: &[u8]) -> String {
    faster_hex::hex_string(bytes)
}

pub type DebugTx<'a> = PopulatedTransaction<'a>;
pub type DebugReused = SigHashReusedValuesUnsync;
pub type DebugOpcode<'a> = DynOpcodeImplementation<DebugTx<'a>, DebugReused>;
pub type DebugEngine<'a> = TxScriptEngine<'a, DebugTx<'a>, DebugReused>;

#[derive(Debug, Clone)]
pub enum DebugValue {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<DebugValue>),
    /// Value could not be evaluated (e.g., from inline function return)
    Unknown(std::string::String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableOrigin {
    Local,
    Param,
    Constant,
}

impl VariableOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Param => "arg",
            Self::Constant => "const",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    pub value: DebugValue,
    pub is_constant: bool,
    pub origin: VariableOrigin,
}

#[derive(Debug, Clone)]
pub struct SourceContextLine {
    pub line: u32,
    pub text: String,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct SourceContext {
    pub lines: Vec<SourceContextLine>,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub pc: usize,
    pub opcode: Option<String>,
    pub mapping: Option<DebugMapping>,
    pub stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSnapshot {
    pub dstack: Vec<String>,
    pub astack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeMeta {
    pub index: usize,
    pub byte_offset: usize,
    pub display: String,
    pub mapping: Option<DebugMapping>,
}

pub struct DebugSession<'a> {
    engine: DebugEngine<'a>,
    opcodes: Vec<Option<DebugOpcode<'a>>>,
    op_displays: Vec<String>,
    opcode_offsets: Vec<usize>,
    script_len: usize,
    pc: usize,
    debug_info: DebugInfo,
    source_mappings: Vec<DebugMapping>,
    current_step_index: Option<usize>,
    uses_sequence_order: bool,
    source_lines: Vec<String>,
    breakpoints: HashSet<u32>,
}

struct ShadowParamValue {
    name: String,
    type_name: String,
    stack_index: i64,
    value: Vec<u8>,
}

impl<'a> DebugSession<'a> {
    // --- Session construction + stepping ---

    /// Creates a debug session for lockscript-only execution.
    /// Use this when debugging pure contract logic without sigscript setup.
    pub fn lockscript_only(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        Self::from_scripts(script, source, debug_info, engine)
    }

    /// Creates a debug session simulating a full transaction spend.
    /// Executes sigscript first to seed the stack, then debugs lockscript execution.
    pub fn full(
        sigscript: &[u8],
        lockscript: &[u8],
        source: &str,
        debug_info: Option<DebugInfo>,
        mut engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        seed_engine_with_sigscript(&mut engine, sigscript)?;
        Self::from_scripts(lockscript, source, debug_info, engine)
    }

    /// Internal constructor: parses script, prepares opcodes, extracts statement mappings.
    pub fn from_scripts(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        let debug_info = debug_info.unwrap_or_else(DebugInfo::empty);
        let opcodes = parse_script::<DebugTx<'a>, DebugReused>(script).collect::<Result<Vec<_>, _>>()?;
        let op_displays = opcodes.iter().map(|op| format!("{op:?}")).collect();
        let opcodes: Vec<Option<DebugOpcode<'a>>> = opcodes.into_iter().map(Some).collect();
        let source_lines: Vec<String> = source.lines().map(String::from).collect();
        let (opcode_offsets, script_len) = build_opcode_offsets(&opcodes);

        let uses_sequence_order = debug_info.mappings.iter().any(|mapping| mapping.sequence != 0)
            || debug_info.variable_updates.iter().any(|update| update.sequence != 0);
        let mut source_mappings: Vec<DebugMapping> = debug_info
            .mappings
            .iter()
            .filter(|mapping| {
                matches!(
                    &mapping.kind,
                    MappingKind::Statement {}
                        | MappingKind::Virtual {}
                        | MappingKind::InlineCallEnter { .. }
                        | MappingKind::InlineCallExit { .. }
                )
            })
            .cloned()
            .collect();
        if uses_sequence_order {
            source_mappings.sort_by_key(|mapping| (mapping.sequence, mapping.bytecode_start, mapping.bytecode_end));
        } else {
            source_mappings.sort_by_key(|mapping| (mapping.bytecode_start, mapping.bytecode_end));
        }

        Ok(Self {
            engine,
            opcodes,
            op_displays,
            opcode_offsets,
            script_len,
            pc: 0,
            debug_info,
            source_mappings,
            current_step_index: None,
            uses_sequence_order,
            source_lines,
            breakpoints: HashSet::new(),
        })
    }

    /// Executes a single opcode and advances the program counter.
    pub fn step_opcode(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.pc >= self.opcodes.len() {
            return Ok(None);
        }

        let opcode = self.opcodes[self.pc].take().expect("opcode already executed");
        self.engine.execute_opcode(opcode)?;
        self.pc += 1;
        Ok(Some(self.state()))
    }

    /// Step into: advance to next source step regardless of call depth.
    pub fn step_into(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|_, _| true)
    }

    /// Step over: advance to next source step at the same or shallower call depth.
    pub fn step_over(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|candidate, current| candidate <= current)
    }

    /// Step out: advance to next source step at a shallower call depth.
    pub fn step_out(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|candidate, current| candidate < current)
    }

    /// Backward-compatible statement stepping alias.
    pub fn step_statement(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_over()
    }

    fn step_with_depth_predicate(
        &mut self,
        predicate: impl Fn(u32, u32) -> bool,
    ) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if !self.uses_source_stepping() {
            return self.step_opcode();
        }

        let current_depth = self.current_step_mapping().map(|mapping| mapping.call_depth).unwrap_or(0);
        let mut search_from = self.current_step_index;

        loop {
            let Some(target_index) =
                self.next_steppable_mapping_index(search_from, |mapping| predicate(mapping.call_depth, current_depth))
            else {
                while self.step_opcode()?.is_some() {}
                return Ok(None);
            };

            if self.advance_to_mapping(target_index)? {
                self.current_step_index = Some(target_index);
                return Ok(Some(self.state()));
            }

            search_from = Some(target_index);
        }
    }

    fn advance_to_mapping(&mut self, target_index: usize) -> Result<bool, kaspa_txscript_errors::TxScriptError> {
        let Some(target) = self.source_mappings.get(target_index).cloned() else {
            return Ok(false);
        };
        loop {
            let offset = self.current_byte_offset();

            if offset > target.bytecode_start {
                return Ok(false);
            }

            if mapping_matches_offset(&target, offset) && self.engine.is_executing() {
                return Ok(true);
            }

            if self.step_opcode()?.is_none() {
                return Ok(false);
            }
        }
    }

    /// Advances execution to the first user statement, skipping dispatcher/synthetic bytecode.
    /// Call this after session creation to skip over contract setup code.
    /// Skips opcodes until the first source-mapped statement is encountered.
    pub fn run_to_first_executed_statement(&mut self) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        if !self.uses_source_stepping() {
            return Ok(());
        }
        loop {
            if self.pc >= self.opcodes.len() {
                return Ok(());
            }
            let offset = self.current_byte_offset();
            if self.engine.is_executing() {
                let found = self
                    .source_mappings
                    .iter()
                    .enumerate()
                    .find(|(_, mapping)| self.is_steppable_mapping(mapping) && mapping_matches_offset(mapping, offset));
                if let Some((index, _)) = found {
                    self.current_step_index = Some(index);
                    return Ok(());
                }
            }
            if self.step_opcode()?.is_none() {
                return Ok(());
            }
        }
    }

    /// Continues execution until a breakpoint is hit or script completes.
    pub fn continue_to_breakpoint(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.breakpoints.is_empty() {
            while self.step_opcode()?.is_some() {}
            return Ok(None);
        }
        loop {
            if self.step_into()?.is_none() {
                return Ok(None);
            }
            if let Some(mapping) = self.current_step_mapping() {
                if self.mapping_hits_breakpoint(mapping) {
                    return Ok(Some(self.state()));
                }
            }
        }
    }

    /// Returns the current execution state snapshot.
    pub fn state(&self) -> SessionState {
        let opcode = self.pc.checked_sub(1).and_then(|index| self.op_displays.get(index)).cloned();
        SessionState { pc: self.pc, opcode, mapping: self.current_location(), stack: self.stack() }
    }

    /// Returns true if the script engine is still running.
    pub fn is_executing(&self) -> bool {
        self.engine.is_executing()
    }

    /// Returns the current data and alt stack contents.
    pub fn stacks_snapshot(&self) -> StackSnapshot {
        let stacks = self.engine.stacks();
        StackSnapshot {
            dstack: stacks.dstack.iter().map(|bytes| encode_hex(bytes)).collect(),
            astack: stacks.astack.iter().map(|bytes| encode_hex(bytes)).collect(),
        }
    }

    /// Returns metadata for all opcodes (executed/pending status, byte offset).
    pub fn opcode_metas(&self) -> Vec<OpcodeMeta> {
        (0..self.op_displays.len())
            .map(|index| {
                let byte_offset = self.opcode_offsets.get(index).copied().unwrap_or(self.script_len);
                OpcodeMeta {
                    index,
                    byte_offset,
                    display: self.op_displays.get(index).cloned().unwrap_or_default(),
                    mapping: self.mapping_for_offset(byte_offset).cloned(),
                }
            })
            .collect()
    }

    /// Returns the total number of opcodes in the script.
    pub fn opcode_count(&self) -> usize {
        self.op_displays.len()
    }

    pub fn debug_info(&self) -> &DebugInfo {
        &self.debug_info
    }

    // --- Mapping + source context ---

    /// Returns source lines around the current statement (radius = 6 lines).
    /// Active line is marked via `is_active` field. Returns None if no source mapping exists.
    /// Returns surrounding source lines with the current line highlighted.
    pub fn source_context(&self) -> Option<SourceContext> {
        let span = self.current_span()?;
        let line = span.line.saturating_sub(1) as usize;
        let radius = 6;
        let start = line.saturating_sub(radius);
        let end = (line + radius).min(self.source_lines.len().saturating_sub(1));

        let mut lines = Vec::new();
        for idx in start..=end {
            let display_line = idx + 1;
            let content = self.source_lines.get(idx).map(String::as_str).unwrap_or("");
            lines.push(SourceContextLine { line: display_line as u32, text: content.to_string(), is_active: idx == line });
        }

        Some(SourceContext { lines })
    }

    /// Adds a breakpoint at the given line number. Returns true if added.
    pub fn add_breakpoint(&mut self, line: u32) -> bool {
        let valid = self
            .source_mappings
            .iter()
            .filter(|mapping| self.is_steppable_mapping(mapping))
            .any(|mapping| mapping.span.is_some_and(|span| line >= span.line && line <= span.end_line));
        if valid {
            self.breakpoints.insert(line);
        }
        valid
    }

    /// Returns all currently set breakpoint line numbers.
    pub fn breakpoints(&self) -> Vec<u32> {
        let mut lines = self.breakpoints.iter().copied().collect::<Vec<_>>();
        lines.sort_unstable();
        lines
    }

    /// Removes the breakpoint at the given line number.
    pub fn clear_breakpoint(&mut self, line: u32) {
        self.breakpoints.remove(&line);
    }

    // --- Variable inspection ---

    /// Returns all variables in scope at current execution point.
    /// Includes params, local variables (up to current offset), and constructor constants.
    /// Values are computed via shadow VM evaluation.
    pub fn list_variables(&self) -> Result<Vec<Variable>, String> {
        let (sequence, frame_id) = self.current_step_sequence_and_frame();
        self.collect_variables(sequence, frame_id)
    }

    pub fn list_variables_at_sequence(&self, sequence: u32, frame_id: u32) -> Result<Vec<Variable>, String> {
        self.collect_variables(sequence, frame_id)
    }

    fn collect_variables(&self, sequence: u32, frame_id: u32) -> Result<Vec<Variable>, String> {
        let function_name = self.current_function_name().ok_or_else(|| "No function context available".to_string())?;
        let offset = self.current_byte_offset();
        let include_current_sequence = self.include_current_sequence_updates(sequence, frame_id);
        let var_updates = self.current_variable_updates(function_name, offset, sequence, frame_id, include_current_sequence);

        let mut variables: Vec<Variable> = Vec::new();
        let mut seen_names: HashSet<String> = HashSet::new();

        for (name, update) in &var_updates {
            let value = self.evaluate_update_with_shadow_vm(function_name, update).unwrap_or_else(DebugValue::Unknown);
            variables.push(Variable {
                name: name.clone(),
                type_name: update.type_name.clone(),
                value,
                is_constant: false,
                origin: VariableOrigin::Local,
            });
            seen_names.insert(name.clone());
        }

        for param in self.debug_info.params.iter().filter(|param| param.function == function_name) {
            if seen_names.contains(&param.name) {
                continue;
            }
            let value = self.read_param_value(param)?;
            variables.push(Variable {
                name: param.name.clone(),
                type_name: param.type_name.clone(),
                value,
                is_constant: false,
                origin: VariableOrigin::Param,
            });
            seen_names.insert(param.name.clone());
        }

        for constant in &self.debug_info.constants {
            if seen_names.contains(&constant.name) {
                continue;
            }
            let value = self.evaluate_constant(&constant.value);
            variables.push(Variable {
                name: constant.name.clone(),
                type_name: constant.type_name.clone(),
                value,
                is_constant: true,
                origin: VariableOrigin::Constant,
            });
            seen_names.insert(constant.name.clone());
        }

        variables.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(variables)
    }

    /// Returns a specific variable by name, or error if not in scope.
    /// Retrieves a specific variable by name with its current value.
    pub fn variable_by_name(&self, name: &str) -> Result<Variable, String> {
        let function_name = self.current_function_name().ok_or_else(|| "No function context available".to_string())?;
        let offset = self.current_byte_offset();
        let (sequence, frame_id) = self.current_step_sequence_and_frame();
        let include_current_sequence = self.include_current_sequence_updates(sequence, frame_id);
        let var_updates = self.current_variable_updates(function_name, offset, sequence, frame_id, include_current_sequence);

        if let Some(update) = var_updates.get(name) {
            let value = self.evaluate_update_with_shadow_vm(function_name, update).unwrap_or_else(DebugValue::Unknown);
            return Ok(Variable {
                name: name.to_string(),
                type_name: update.type_name.clone(),
                value,
                is_constant: false,
                origin: VariableOrigin::Local,
            });
        }

        if let Some(param) = self.debug_info.params.iter().find(|param| param.function == function_name && param.name == name) {
            let value = self.read_param_value(param)?;
            return Ok(Variable {
                name: name.to_string(),
                type_name: param.type_name.clone(),
                value,
                is_constant: false,
                origin: VariableOrigin::Param,
            });
        }

        // Check constructor constants
        if let Some(constant) = self.debug_info.constants.iter().find(|c| c.name == name) {
            let value = self.evaluate_constant(&constant.value);
            return Ok(Variable {
                name: name.to_string(),
                type_name: constant.type_name.clone(),
                value,
                is_constant: true,
                origin: VariableOrigin::Constant,
            });
        }

        Err(format!("unknown variable '{name}'"))
    }

    // --- DebugValue formatting ---
    /// Formats a debug value for display based on its type.
    pub fn format_value(&self, type_name: &str, value: &DebugValue) -> String {
        let element_type = type_name.strip_suffix("[]");
        match (type_name, value) {
            ("int", DebugValue::Int(number)) => number.to_string(),
            ("bool", DebugValue::Bool(value)) => value.to_string(),
            ("string", DebugValue::String(value)) => value.clone(),
            (_, DebugValue::Unknown(reason)) => {
                if reason.trim().is_empty() {
                    "<unavailable>".to_string()
                } else if reason.contains("failed to compile debug expression")
                    || reason.contains("undefined identifier")
                    || reason.contains("__arg_")
                {
                    "<unavailable: depends on inlined function call internals>".to_string()
                } else if reason.contains("failed to execute shadow script") {
                    "<unavailable: runtime evaluation failed>".to_string()
                } else {
                    format!("<unavailable: {}>", concise_reason(reason))
                }
            }
            (_, DebugValue::Bytes(bytes)) if element_type.is_some() => {
                let element_type = element_type.expect("checked");
                let Some(element_size) = array_element_size(element_type) else {
                    return format!("0x{}", encode_hex(bytes));
                };
                if element_size == 0 || bytes.len() % element_size != 0 {
                    return format!("0x{}", encode_hex(bytes));
                }

                let mut values: Vec<String> = Vec::new();
                for chunk in bytes.chunks(element_size) {
                    let decoded = match element_type {
                        "int" => DebugValue::Int(decode_i64(chunk).unwrap_or(0)),
                        "bool" => DebugValue::Bool(decode_i64(chunk).unwrap_or(0) != 0),
                        _ => DebugValue::Bytes(chunk.to_vec()),
                    };
                    values.push(self.format_value(element_type, &decoded));
                }
                format!("[{}]", values.join(", "))
            }
            (_, DebugValue::Bytes(bytes)) => format!("0x{}", encode_hex(bytes)),
            (_, DebugValue::Int(number)) => number.to_string(),
            (_, DebugValue::Bool(value)) => value.to_string(),
            (_, DebugValue::String(value)) => value.clone(),
            (_, DebugValue::Array(values)) => {
                let value_type = element_type.unwrap_or(type_name);
                format!("[{}]", values.iter().map(|v| self.format_value(value_type, v)).collect::<Vec<_>>().join(", "))
            }
        }
    }

    /// Returns the debug mapping for the current bytecode position.
    pub fn current_location(&self) -> Option<DebugMapping> {
        self.current_step_mapping().cloned().or_else(|| self.mapping_for_offset(self.current_byte_offset()).cloned())
    }

    /// Returns the current bytecode offset in the script.
    pub fn current_byte_offset(&self) -> usize {
        self.opcode_offsets.get(self.pc).copied().unwrap_or(self.script_len)
    }

    /// Returns the source span (line/col range) at the current position.
    pub fn current_span(&self) -> Option<SourceSpan> {
        self.current_location().and_then(|mapping| mapping.span)
    }

    pub fn call_stack(&self) -> Vec<String> {
        let mut stack = Vec::new();
        let Some(current) = self.current_step_index else {
            return stack;
        };
        for mapping in self.source_mappings.iter().take(current + 1) {
            match &mapping.kind {
                MappingKind::InlineCallEnter { callee } => stack.push(callee.clone()),
                MappingKind::InlineCallExit { .. } => {
                    stack.pop();
                }
                _ => {}
            }
        }
        stack
    }

    /// Returns the name of the function currently being executed.
    pub fn current_function_name(&self) -> Option<&str> {
        self.current_function_range().map(|range| range.name.as_str())
    }

    fn current_function_range(&self) -> Option<&DebugFunctionRange> {
        let offset = self.current_byte_offset();
        self.debug_info.functions.iter().find(|function| offset >= function.bytecode_start && offset < function.bytecode_end)
    }

    fn current_variable_updates(
        &self,
        function_name: &str,
        offset: usize,
        sequence: u32,
        frame_id: u32,
        include_current_sequence: bool,
    ) -> HashMap<String, &DebugVariableUpdate> {
        let mut latest: HashMap<String, &DebugVariableUpdate> = HashMap::new();
        for update in self.debug_info.variable_updates.iter().filter(|update| {
            if update.function != function_name {
                return false;
            }
            if self.uses_sequence_order {
                // For statement stops expose pre-state (< sequence). For virtual steps (no bytecode),
                // same-sequence updates are treated as already materialized debugger state.
                update.frame_id == frame_id
                    && (update.sequence < sequence || (include_current_sequence && update.sequence == sequence))
            } else {
                // Older debug info without sequence metadata falls back to opcode-offset snapshots.
                update.bytecode_offset <= offset
            }
        }) {
            if self.uses_sequence_order {
                match latest.get(&update.name) {
                    Some(existing) if existing.sequence > update.sequence => {}
                    _ => {
                        latest.insert(update.name.clone(), update);
                    }
                }
            } else {
                match latest.get(&update.name) {
                    Some(existing) if existing.bytecode_offset > update.bytecode_offset => {}
                    _ => {
                        latest.insert(update.name.clone(), update);
                    }
                }
            }
        }
        latest
    }

    /// Best mapping = smallest bytecode span containing `offset`.
    fn mapping_for_offset(&self, offset: usize) -> Option<&DebugMapping> {
        let mut best: Option<&DebugMapping> = None;
        let mut best_len = usize::MAX;
        for mapping in &self.debug_info.mappings {
            if mapping_matches_offset(mapping, offset) {
                let len = mapping.bytecode_end.saturating_sub(mapping.bytecode_start);
                if len < best_len {
                    best = Some(mapping);
                    best_len = len;
                }
            }
        }
        best
    }

    fn current_step_mapping(&self) -> Option<&DebugMapping> {
        self.current_step_index.and_then(|index| self.source_mappings.get(index))
    }

    fn current_step_sequence_and_frame(&self) -> (u32, u32) {
        self.current_step_mapping().map(|mapping| (mapping.sequence, mapping.frame_id)).unwrap_or((0, 0))
    }

    fn uses_source_stepping(&self) -> bool {
        !self.source_mappings.is_empty()
    }

    fn is_statement_step_mapping(&self, mapping: &DebugMapping) -> bool {
        matches!(&mapping.kind, MappingKind::Statement {})
    }

    fn is_virtual_step_mapping(&self, mapping: &DebugMapping) -> bool {
        matches!(&mapping.kind, MappingKind::Virtual {})
    }

    fn include_current_sequence_updates(&self, sequence: u32, frame_id: u32) -> bool {
        self.current_step_mapping().is_some_and(|mapping| {
            mapping.sequence == sequence && mapping.frame_id == frame_id && self.is_virtual_step_mapping(mapping)
        })
    }

    fn is_steppable_mapping(&self, mapping: &DebugMapping) -> bool {
        self.is_statement_step_mapping(mapping) || self.is_virtual_step_mapping(mapping)
    }

    fn next_steppable_mapping_index(&self, from: Option<usize>, predicate: impl Fn(&DebugMapping) -> bool) -> Option<usize> {
        let start = from.map(|index| index.saturating_add(1)).unwrap_or(0);
        for index in start..self.source_mappings.len() {
            let mapping = self.source_mappings.get(index)?;
            if !self.is_steppable_mapping(mapping) {
                continue;
            }
            if predicate(mapping) {
                return Some(index);
            }
        }
        None
    }

    fn mapping_hits_breakpoint(&self, mapping: &DebugMapping) -> bool {
        mapping.span.map(|span| (span.line..=span.end_line).any(|line| self.breakpoints.contains(&line))).unwrap_or(false)
    }

    /// Returns the current main stack as hex-encoded strings.
    pub fn stack(&self) -> Vec<String> {
        let stacks = self.engine.stacks();
        stacks.dstack.iter().map(|bytes| encode_hex(bytes)).collect()
    }

    fn evaluate_update_with_shadow_vm(&self, function_name: &str, update: &DebugVariableUpdate) -> Result<DebugValue, String> {
        self.evaluate_expr_with_shadow_vm(function_name, &update.type_name, &update.expr)
    }

    /// Evaluates an expression using shadow VM execution.
    ///
    /// Strategy: compile the pre-resolved expression to bytecode, build a mini-script
    /// that pushes current param values then executes the bytecode, run on fresh VM,
    /// read result from top of stack. This guarantees debugger sees same semantics as
    /// real execution without duplicating evaluation logic.
    fn evaluate_expr_with_shadow_vm(&self, function_name: &str, type_name: &str, expr: &Expr) -> Result<DebugValue, String> {
        let params = self.shadow_param_values(function_name)?;
        let mut param_indexes = HashMap::new();
        let mut param_types = HashMap::new();
        for param in &params {
            param_indexes.insert(param.name.clone(), param.stack_index);
            param_types.insert(param.name.clone(), param.type_name.clone());
        }
        let bytecode = compile_debug_expr(expr, &param_indexes, &param_types)
            .map_err(|err| format!("failed to compile debug expression: {err}"))?;
        let script = self.build_shadow_script(&params, &bytecode)?;
        let bytes = self.execute_shadow_script(&script)?;
        decode_value_by_type(type_name, bytes)
    }

    fn shadow_param_values(&self, function_name: &str) -> Result<Vec<ShadowParamValue>, String> {
        let mut params = Vec::new();
        for param in self.debug_info.params.iter().filter(|param| param.function == function_name) {
            params.push(ShadowParamValue {
                name: param.name.clone(),
                type_name: param.type_name.clone(),
                stack_index: param.stack_index,
                value: self.read_stack_at_index(param.stack_index)?,
            });
        }
        // Push higher stack indexes first so index 0 remains the top parameter.
        params.sort_by(|left, right| right.stack_index.cmp(&left.stack_index));
        Ok(params)
    }

    fn build_shadow_script(&self, params: &[ShadowParamValue], expr_bytecode: &[u8]) -> Result<Vec<u8>, String> {
        let mut builder = ScriptBuilder::new();
        for param in params {
            builder.add_data(&param.value).map_err(|err| err.to_string())?;
        }
        builder.add_ops(expr_bytecode).map_err(|err| err.to_string())?;
        Ok(builder.drain())
    }

    fn execute_shadow_script(&self, script: &[u8]) -> Result<Vec<u8>, String> {
        let sig_cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        let mut engine: DebugEngine<'_> =
            TxScriptEngine::new(EngineCtx::new(&sig_cache).with_reused(&reused_values), EngineFlags { covenants_enabled: true });
        for opcode in parse_script::<DebugTx<'_>, DebugReused>(script) {
            let opcode = opcode.map_err(|err| format!("failed to parse shadow script: {err}"))?;
            engine.execute_opcode(opcode).map_err(|err| format!("failed to execute shadow script: {err}"))?;
        }
        engine.stacks().dstack.last().cloned().ok_or_else(|| "shadow VM produced an empty stack".to_string())
    }

    fn read_param_value(&self, param: &DebugParamMapping) -> Result<DebugValue, String> {
        let bytes = self.read_stack_at_index(param.stack_index)?;
        decode_value_by_type(&param.type_name, bytes)
    }

    fn evaluate_constant(&self, expr: &Expr) -> DebugValue {
        match expr {
            Expr::Int(v) => DebugValue::Int(*v),
            Expr::Bool(v) => DebugValue::Bool(*v),
            Expr::Bytes(v) => DebugValue::Bytes(v.clone()),
            Expr::String(v) => DebugValue::String(v.clone()),
            _ => DebugValue::Unknown("complex expression".to_string()),
        }
    }

    fn read_stack_at_index(&self, index: i64) -> Result<Vec<u8>, String> {
        if index < 0 {
            return Err("negative stack index".to_string());
        }
        let stacks = self.engine.stacks();
        let stack = stacks.dstack;
        let idx = index as usize;
        if idx >= stack.len() {
            return Err("stack index out of range".to_string());
        }
        let stack_index = stack.len() - 1 - idx;
        Ok(stack.get(stack_index).cloned().unwrap_or_default())
    }
}

/// Returns byte size for fixed-size array elements (e.g., bytes32 → 32), or None for variable-size.
fn array_element_size(element_type: &str) -> Option<usize> {
    match element_type {
        "int" => Some(8),
        "bool" => Some(1),
        "byte" => Some(1),
        other => other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()),
    }
}

/// Decodes raw bytes into a typed debug value based on the type name.
fn decode_value_by_type(type_name: &str, bytes: Vec<u8>) -> Result<DebugValue, String> {
    match type_name {
        "int" => Ok(DebugValue::Int(decode_i64(&bytes)?)),
        "bool" => Ok(DebugValue::Bool(decode_i64(&bytes)? != 0)),
        "string" => match String::from_utf8(bytes.clone()) {
            Ok(value) => Ok(DebugValue::String(value)),
            Err(_) => Ok(DebugValue::Bytes(bytes)),
        },
        _ => Ok(DebugValue::Bytes(bytes)),
    }
}

/// Truncates error messages to 96 chars for display in debugger UI.
fn concise_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let first_line = trimmed.lines().next().unwrap_or(trimmed);
    const MAX_CHARS: usize = 96;
    if first_line.chars().count() <= MAX_CHARS {
        first_line.to_string()
    } else {
        let mut out = String::new();
        for ch in first_line.chars().take(MAX_CHARS) {
            out.push(ch);
        }
        out.push_str("...");
        out
    }
}

/// Decode a sign-magnitude little-endian integer
fn decode_i64(bytes: &[u8]) -> Result<i64, String> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        return Err("numeric value is longer than 8 bytes".to_string());
    }
    let msb = bytes[bytes.len() - 1];
    let sign = 1 - 2 * ((msb >> 7) as i64);
    let first_byte = (msb & 0x7f) as i64;
    let mut value = first_byte;
    for byte in bytes[..bytes.len() - 1].iter().rev() {
        value = (value << 8) + (*byte as i64);
    }
    Ok(value * sign)
}

/// Executes sigscript to seed the stack before debugging lockscript.
fn seed_engine_with_sigscript(engine: &mut DebugEngine<'_>, sigscript: &[u8]) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    for opcode in parse_script::<DebugTx<'_>, DebugReused>(sigscript) {
        engine.execute_opcode(opcode?)?;
    }
    Ok(())
}

fn build_opcode_offsets(opcodes: &[Option<DebugOpcode<'_>>]) -> (Vec<usize>, usize) {
    let mut offsets = Vec::with_capacity(opcodes.len() + 1);
    let mut offset = 0usize;
    for opcode in opcodes {
        offsets.push(offset);
        if let Some(op) = opcode {
            offset = offset.saturating_add(op.serialize().len());
        }
    }
    (offsets, offset)
}

fn mapping_matches_offset(mapping: &DebugMapping, offset: usize) -> bool {
    if mapping.bytecode_start == mapping.bytecode_end {
        offset == mapping.bytecode_start
    } else {
        offset >= mapping.bytecode_start && offset < mapping.bytecode_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ast::{BinaryOp, Expr};
    use crate::debug::{DebugConstantMapping, DebugFunctionRange, DebugInfo, DebugParamMapping, DebugVariableUpdate};

    fn make_session(
        params: Vec<DebugParamMapping>,
        updates: Vec<DebugVariableUpdate>,
        sigscript: &[u8],
    ) -> Result<DebugSession<'static>, kaspa_txscript_errors::TxScriptError> {
        let sig_cache = Box::leak(Box::new(Cache::new(10_000)));
        let reused_values: &'static SigHashReusedValuesUnsync = Box::leak(Box::new(SigHashReusedValuesUnsync::new()));
        let engine: DebugEngine<'static> =
            TxScriptEngine::new(EngineCtx::new(sig_cache).with_reused(reused_values), EngineFlags { covenants_enabled: true });
        let debug_info = DebugInfo {
            source: String::new(),
            mappings: vec![],
            variable_updates: updates,
            params,
            functions: vec![DebugFunctionRange { name: "f".to_string(), bytecode_start: 0, bytecode_end: 1 }],
            constants: vec![DebugConstantMapping { name: "K".to_string(), type_name: "int".to_string(), value: Expr::Int(7) }],
        };
        DebugSession::full(sigscript, &[], "", Some(debug_info), engine)
    }

    #[test]
    fn decode_i64_handles_basic_values() {
        assert_eq!(decode_i64(&[]).unwrap(), 0);
        assert_eq!(decode_i64(&[1]).unwrap(), 1);
        assert_eq!(decode_i64(&[0x81]).unwrap(), -1);
        assert_eq!(decode_i64(&[0, 0x80]).unwrap(), 0);
    }

    #[test]
    fn shadow_vm_evaluates_param_expression() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(3).unwrap();
        sig_builder.add_i64(9).unwrap();
        let sigscript = sig_builder.drain();

        let session = make_session(
            vec![
                DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 1, function: "f".to_string() },
                DebugParamMapping { name: "b".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() },
            ],
            vec![],
            &sigscript,
        )
        .unwrap();

        let value = session
            .evaluate_expr_with_shadow_vm(
                "f",
                "int",
                &Expr::Binary {
                    op: BinaryOp::Add,
                    left: Box::new(Expr::Identifier("a".to_string())),
                    right: Box::new(Expr::Identifier("b".to_string())),
                },
            )
            .unwrap();
        assert!(matches!(value, DebugValue::Int(12)));
    }

    #[test]
    fn list_variables_returns_unknown_for_uncompilable_expr() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let session = make_session(
            vec![DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() }],
            vec![DebugVariableUpdate {
                name: "x".to_string(),
                type_name: "int".to_string(),
                expr: Expr::Identifier("missing".to_string()),
                bytecode_offset: 0,
                span: None,
                function: "f".to_string(),
                sequence: 0,
                frame_id: 0,
            }],
            &sigscript,
        )
        .unwrap();

        let vars = session.list_variables().unwrap();
        let x = vars.into_iter().find(|var| var.name == "x").expect("x variable");
        assert!(matches!(x.value, DebugValue::Unknown(_)));
    }
}
