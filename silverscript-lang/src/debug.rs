use crate::ast::{Expr, SourceSpan};

pub mod session;

#[derive(Debug, Clone)]
pub enum DebugEventKind {
    Statement { stmt_type: String },
    Synthetic { label: String },
}

#[derive(Debug, Clone)]
pub struct DebugEvent {
    pub bytecode_start: usize,
    pub bytecode_end: usize,
    pub span: Option<SourceSpan>,
    pub kind: DebugEventKind,
}

#[derive(Debug, Default)]
pub struct DebugRecorder {
    events: Vec<DebugEvent>,
    variable_updates: Vec<DebugVariableUpdate>,
    params: Vec<DebugParamMapping>,
    functions: Vec<DebugFunctionRange>,
    constants: Vec<DebugConstantMapping>,
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

#[derive(Debug, Clone)]
pub struct DebugInfo {
    pub source: String,
    pub mappings: Vec<DebugMapping>,
    pub variable_updates: Vec<DebugVariableUpdate>,
    pub params: Vec<DebugParamMapping>,
    pub functions: Vec<DebugFunctionRange>,
    pub constants: Vec<DebugConstantMapping>,
}

#[derive(Debug, Clone)]
pub struct DebugVariableUpdate {
    pub name: String,
    pub type_name: String,
    pub expr: Expr,
    pub bytecode_offset: usize,
    pub span: Option<SourceSpan>,
    pub function: String,
}

#[derive(Debug, Clone)]
pub struct DebugParamMapping {
    pub name: String,
    pub type_name: String,
    pub stack_index: i64,
    pub function: String,
}

#[derive(Debug, Clone)]
pub struct DebugFunctionRange {
    pub name: String,
    pub bytecode_start: usize,
    pub bytecode_end: usize,
}

#[derive(Debug, Clone)]
pub struct DebugConstantMapping {
    pub name: String,
    pub type_name: String,
    pub value: Expr,
}

#[derive(Debug, Clone)]
pub struct DebugMapping {
    pub bytecode_start: usize,
    pub bytecode_end: usize,
    pub span: Option<SourceSpan>,
    pub kind: MappingKind,
}

#[derive(Debug, Clone)]
pub enum MappingKind {
    Statement { stmt_type: String },
    Synthetic { label: String },
}

impl From<DebugEventKind> for MappingKind {
    fn from(kind: DebugEventKind) -> Self {
        match kind {
            DebugEventKind::Statement { stmt_type } => MappingKind::Statement { stmt_type },
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
        }
    }
}
