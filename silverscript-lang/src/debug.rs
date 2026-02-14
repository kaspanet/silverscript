use crate::ast::{Expr, SourceSpan};
use serde::{Deserialize, Serialize};

pub mod session;

pub mod labels {
    pub mod synthetic {
        /// Checks which function was selected (DUP, PUSH index, NUMEQUAL, IF, DROP).
        pub const DISPATCHER_GUARD: &str = "dispatcher.guard";
        /// Function didn't match — try next, or fail if last.
        pub const DISPATCHER_ELSE: &str = "dispatcher.else";
        /// Closes all dispatcher if/else branches.
        pub const DISPATCHER_ENDIFS: &str = "dispatcher.endifs";
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugEventKind {
    Statement {},
    Virtual {},
    InlineCallEnter { callee: String },
    InlineCallExit { callee: String },
    Synthetic { label: String },
}

/// Single debug mapping recorded during compilation.
/// Maps a bytecode range to source location and event type (statement or synthetic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEvent {
    pub bytecode_start: usize,
    pub bytecode_end: usize,
    pub span: Option<SourceSpan>,
    pub kind: DebugEventKind,
    #[serde(default)]
    pub sequence: u32,
    #[serde(default)]
    pub call_depth: u32,
    #[serde(default)]
    pub frame_id: u32,
}

/// Accumulates debug metadata during compilation.
/// Collects events, variable updates, param mappings, function ranges, and constants.
/// Converted to `DebugInfo` after compilation completes.
#[derive(Debug, Default)]
pub struct DebugRecorder {
    events: Vec<DebugEvent>,
    variable_updates: Vec<DebugVariableUpdate>,
    params: Vec<DebugParamMapping>,
    functions: Vec<DebugFunctionRange>,
    constants: Vec<DebugConstantMapping>,
    next_sequence: u32,
}

impl DebugRecorder {
    pub fn record(&mut self, event: DebugEvent) {
        self.events.push(event);
    }

    pub fn record_variable_update(&mut self, update: DebugVariableUpdate) {
        self.variable_updates.push(update);
    }

    pub fn record_param(&mut self, param: DebugParamMapping) {
        self.params.push(param);
    }

    pub fn record_function(&mut self, function: DebugFunctionRange) {
        self.functions.push(function);
    }

    pub fn record_constant(&mut self, constant: DebugConstantMapping) {
        self.constants.push(constant);
    }

    pub fn next_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }

    pub fn reserve_sequence_block(&mut self, count: u32) -> u32 {
        let base = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(count);
        base
    }

    pub fn into_events(self) -> Vec<DebugEvent> {
        self.events
    }

    pub fn into_debug_info(self, source: String) -> DebugInfo {
        DebugInfo {
            source,
            mappings: self.events.into_iter().map(DebugMapping::from).collect(),
            variable_updates: self.variable_updates,
            params: self.params,
            functions: self.functions,
            constants: self.constants,
        }
    }
}

/// Complete debug metadata attached to compiled contract.
/// Contains everything needed to map bytecode execution back to source and evaluate variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugInfo {
    pub source: String,
    pub mappings: Vec<DebugMapping>,
    pub variable_updates: Vec<DebugVariableUpdate>,
    pub params: Vec<DebugParamMapping>,
    pub functions: Vec<DebugFunctionRange>,
    pub constants: Vec<DebugConstantMapping>,
}

impl DebugInfo {
    pub fn empty() -> Self {
        Self {
            source: String::new(),
            mappings: Vec::new(),
            variable_updates: Vec::new(),
            params: Vec::new(),
            functions: Vec::new(),
            constants: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugVariableUpdate {
    pub name: String,
    pub type_name: String,
    /// Pre-resolved expression with all local variable references expanded inline.
    /// Only function parameter Identifiers remain. Enables shadow VM evaluation.
    pub expr: Expr,
    pub bytecode_offset: usize,
    pub span: Option<SourceSpan>,
    pub function: String,
    #[serde(default)]
    pub sequence: u32,
    #[serde(default)]
    pub frame_id: u32,
}

/// Maps function parameter to its stack position.
/// Stack index is measured from stack top (0 = topmost param).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugParamMapping {
    pub name: String,
    pub type_name: String,
    pub stack_index: i64,
    pub function: String,
}

/// Bytecode range for a compiled function.
/// Used to determine which function is executing at a given bytecode offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugFunctionRange {
    pub name: String,
    pub bytecode_start: usize,
    pub bytecode_end: usize,
}

/// Constructor constant (contract instantiation parameter).
/// Recorded for display in debugger variable list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugConstantMapping {
    pub name: String,
    pub type_name: String,
    pub value: Expr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugMapping {
    pub bytecode_start: usize,
    pub bytecode_end: usize,
    pub span: Option<SourceSpan>,
    pub kind: MappingKind,
    #[serde(default)]
    pub sequence: u32,
    #[serde(default)]
    pub call_depth: u32,
    #[serde(default)]
    pub frame_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingKind {
    Statement {},
    Virtual {},
    InlineCallEnter { callee: String },
    InlineCallExit { callee: String },
    Synthetic { label: String },
}

impl From<DebugEventKind> for MappingKind {
    fn from(kind: DebugEventKind) -> Self {
        match kind {
            DebugEventKind::Statement {} => MappingKind::Statement {},
            DebugEventKind::Virtual {} => MappingKind::Virtual {},
            DebugEventKind::InlineCallEnter { callee } => MappingKind::InlineCallEnter { callee },
            DebugEventKind::InlineCallExit { callee } => MappingKind::InlineCallExit { callee },
            DebugEventKind::Synthetic { label } => MappingKind::Synthetic { label },
        }
    }
}

impl From<DebugEvent> for DebugMapping {
    fn from(event: DebugEvent) -> Self {
        DebugMapping {
            bytecode_start: event.bytecode_start,
            bytecode_end: event.bytecode_end,
            span: event.span,
            kind: event.kind.into(),
            sequence: event.sequence,
            call_depth: event.call_depth,
            frame_id: event.frame_id,
        }
    }
}
