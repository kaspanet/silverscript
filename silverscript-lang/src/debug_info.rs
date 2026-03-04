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
/// Collects steps, variable updates, param mappings, function ranges, and constants.
/// Converted to `DebugInfo` after compilation completes.
#[derive(Debug, Default)]
pub struct DebugRecorder<'i> {
    steps: Vec<DebugStep<'i>>,
    params: Vec<DebugParamMapping>,
    functions: Vec<DebugFunctionRange>,
    constants: Vec<DebugConstantMapping<'i>>,
    next_sequence: u32,
}

impl<'i> DebugRecorder<'i> {
    pub fn record_step(&mut self, step: DebugStep<'i>) {
        self.steps.push(step);
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
        DebugInfo { source, steps: self.steps, params: self.params, functions: self.functions, constants: self.constants }
    }
}

/// Complete debug metadata attached to compiled contract.
/// Contains everything needed to map bytecode execution back to source and evaluate variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugInfo<'i> {
    pub source: String,
    pub steps: Vec<DebugStep<'i>>,
    pub params: Vec<DebugParamMapping>,
    pub functions: Vec<DebugFunctionRange>,
    pub constants: Vec<DebugConstantMapping<'i>>,
}

impl<'i> DebugInfo<'i> {
    pub fn empty() -> Self {
        Self { source: String::new(), steps: Vec::new(), params: Vec::new(), functions: Vec::new(), constants: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugVariableUpdate<'i> {
    pub name: String,
    pub type_name: String,
    /// Pre-resolved expression with all local variable references expanded inline.
    /// Only function parameter Identifiers remain. Enables shadow VM evaluation.
    pub expr: Expr<'i>,
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
pub struct DebugStep<'i> {
    pub bytecode_start: usize,
    pub bytecode_end: usize,
    pub span: SourceSpan,
    pub kind: StepKind,
    /// Global step order used as a stable tiebreak for overlapping steps.
    #[serde(default)]
    pub sequence: u32,
    #[serde(default)]
    pub call_depth: u32,
    #[serde(default)]
    pub frame_id: u32,
    #[serde(default)]
    pub variable_updates: Vec<DebugVariableUpdate<'i>>,
}

impl<'i> DebugStep<'i> {
    pub fn id(&self) -> StepId {
        StepId { sequence: self.sequence, frame_id: self.frame_id }
    }

    pub fn is_zero_width(&self) -> bool {
        self.bytecode_start == self.bytecode_end
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StepId {
    pub sequence: u32,
    pub frame_id: u32,
}

impl StepId {
    pub const ROOT: Self = Self { sequence: 0, frame_id: 0 };

    pub fn new(sequence: u32, frame_id: u32) -> Self {
        Self { sequence, frame_id }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepKind {
    #[serde(alias = "Statement", alias = "Virtual")]
    Source {},
    InlineCallEnter {
        callee: String,
    },
    InlineCallExit {
        callee: String,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DebugInfo, SourceSpan, StepKind};
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

    #[test]
    fn debug_info_schema_requires_step_span() {
        let value = json!({
            "source": "",
            "steps": [{
                "bytecode_start": 0,
                "bytecode_end": 1,
                "kind": { "Source": {} },
                "sequence": 0,
                "call_depth": 0,
                "frame_id": 0,
                "variable_updates": []
            }],
            "variable_updates": [],
            "params": [],
            "functions": [],
            "constants": []
        });

        let parsed: Result<DebugInfo<'static>, _> = serde_json::from_value(value);
        assert!(parsed.is_err(), "step span should be required");
    }

    #[test]
    fn debug_info_schema_nests_variable_updates_in_steps() {
        let value = json!({
            "source": "",
            "steps": [{
                "bytecode_start": 0,
                "bytecode_end": 1,
                "span": { "line": 1, "col": 1, "end_line": 1, "end_col": 1 },
                "kind": { "Source": {} },
                "sequence": 0,
                "call_depth": 0,
                "frame_id": 0,
                "variable_updates": []
            }],
            "variable_updates": [],
            "params": [],
            "functions": [],
            "constants": []
        });

        let parsed: DebugInfo<'static> = serde_json::from_value(value).expect("parse debug info");
        let serialized = serde_json::to_value(parsed).expect("serialize debug info");

        assert!(serialized.get("variable_updates").is_none(), "top-level variable_updates should not exist");
        assert!(serialized["steps"][0].get("variable_updates").is_some(), "step should carry variable_updates");
    }

    #[test]
    fn debug_info_schema_accepts_legacy_statement_and_virtual_kind_names() {
        let statement_value = json!({
            "source": "",
            "steps": [{
                "bytecode_start": 0,
                "bytecode_end": 1,
                "span": { "line": 1, "col": 1, "end_line": 1, "end_col": 1 },
                "kind": { "Statement": {} },
                "sequence": 0,
                "call_depth": 0,
                "frame_id": 0,
                "variable_updates": []
            }],
            "params": [],
            "functions": [],
            "constants": []
        });

        let virtual_value = json!({
            "source": "",
            "steps": [{
                "bytecode_start": 0,
                "bytecode_end": 0,
                "span": { "line": 1, "col": 1, "end_line": 1, "end_col": 1 },
                "kind": { "Virtual": {} },
                "sequence": 0,
                "call_depth": 0,
                "frame_id": 0,
                "variable_updates": []
            }],
            "params": [],
            "functions": [],
            "constants": []
        });

        let statement: DebugInfo<'static> = serde_json::from_value(statement_value).expect("legacy statement parses");
        let virtual_step: DebugInfo<'static> = serde_json::from_value(virtual_value).expect("legacy virtual parses");

        assert!(matches!(statement.steps[0].kind, StepKind::Source {}));
        assert!(matches!(virtual_step.steps[0].kind, StepKind::Source {}));
    }
}
