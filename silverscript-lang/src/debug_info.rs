use crate::ast::Expr;
use crate::span;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSpan {
    pub line: u32,
    pub col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl<'a> From<span::Span<'a>> for SourceSpan {
    fn from(span: span::Span<'a>) -> Self {
        let (line, col, end_line, end_col) = span.line_col_range();
        Self { line: line as u32, col: col as u32, end_line: end_line as u32, end_col: end_col as u32 }
    }
}

/// Accumulates debug metadata during compilation.
/// Collects events, variable updates, param mappings, function ranges, and constants.
/// Converted to `DebugInfo` after compilation completes.
#[derive(Debug, Default)]
pub struct DebugRecorder<'i> {
    events: Vec<DebugMapping>,
    variable_updates: Vec<DebugVariableUpdate<'i>>,
    params: Vec<DebugParamMapping>,
    functions: Vec<DebugFunctionRange>,
    constants: Vec<DebugConstantMapping<'i>>,
    next_sequence: u32,
}

impl<'i> DebugRecorder<'i> {
    pub fn record(&mut self, mapping: DebugMapping) {
        self.events.push(mapping);
    }

    pub fn record_variable_update(&mut self, update: DebugVariableUpdate<'i>) {
        self.variable_updates.push(update);
    }

    pub fn record_param(&mut self, param: DebugParamMapping) {
        self.params.push(param);
    }

    pub fn record_function(&mut self, function: DebugFunctionRange) {
        self.functions.push(function);
    }

    pub fn record_constant(&mut self, constant: DebugConstantMapping<'i>) {
        self.constants.push(constant);
    }

    /// Returns the next global sequence id for one emitted debug event.
    pub fn next_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }

    /// Reserves a contiguous sequence block and returns its base id.
    /// Callers use this when merging per-function debug data into contract-level
    /// metadata so each function keeps local order while remaining globally ordered.
    pub fn reserve_sequence_block(&mut self, count: u32) -> u32 {
        let base = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(count);
        base
    }

    pub fn into_debug_info(self, source: String) -> DebugInfo<'i> {
        DebugInfo {
            source,
            mappings: self.events,
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
pub struct DebugInfo<'i> {
    pub source: String,
    pub mappings: Vec<DebugMapping>,
    pub variable_updates: Vec<DebugVariableUpdate<'i>>,
    pub params: Vec<DebugParamMapping>,
    pub functions: Vec<DebugFunctionRange>,
    pub constants: Vec<DebugConstantMapping<'i>>,
}

impl<'i> DebugInfo<'i> {
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
pub struct DebugVariableUpdate<'i> {
    pub name: String,
    pub type_name: String,
    /// Pre-resolved expression with all local variable references expanded inline.
    /// Only function parameter Identifiers remain. Enables shadow VM evaluation.
    pub expr: Expr<'i>,
    pub bytecode_offset: usize,
    pub span: Option<SourceSpan>,
    pub function: String,
    /// Sequence of the statement/virtual mapping that produced this update.
    /// The debugger uses this to show locals only after that step executes.
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
pub struct DebugConstantMapping<'i> {
    pub name: String,
    pub type_name: String,
    pub value: Expr<'i>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugMapping {
    pub bytecode_start: usize,
    pub bytecode_end: usize,
    pub span: Option<SourceSpan>,
    pub kind: MappingKind,
    /// Global event order used as a stable tiebreak for overlapping mappings.
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
}

#[cfg(test)]
mod tests {
    use super::SourceSpan;
    use crate::span::Span;

    #[test]
    fn source_span_from_span_uses_line_col_range() {
        let source = "alpha\nbeta\ngamma";
        let span = Span::new(source, 6, 10).expect("span");
        let source_span = SourceSpan::from(span);
        assert_eq!(source_span.line, 2);
        assert_eq!(source_span.col, 1);
        assert_eq!(source_span.end_line, 2);
        assert_eq!(source_span.end_col, 5);
    }
}
