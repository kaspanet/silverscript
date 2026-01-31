use std::collections::{HashMap, HashSet};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::{DynOpcodeImplementation, TxScriptEngine, parse_script};

use crate::ast::{BinaryOp, Expr, SourceSpan, SplitPart, UnaryOp};
use crate::debug::{DebugFunctionRange, DebugInfo, DebugMapping, DebugParamMapping, DebugVariableUpdate, MappingKind};

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

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    pub value: DebugValue,
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

pub struct DebugSession<'a> {
    engine: DebugEngine<'a>,
    opcodes: Vec<Option<DebugOpcode<'a>>>,
    op_displays: Vec<String>,
    opcode_offsets: Vec<usize>,
    script_len: usize,
    pc: usize,
    debug_info: Option<DebugInfo>,
    statement_mappings: Vec<DebugMapping>,
    source_lines: Vec<String>,
    breakpoints: HashSet<u32>,
}

impl<'a> DebugSession<'a> {
    pub fn lockscript_only(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        Self::from_scripts(script, source, debug_info, engine)
    }

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

    pub fn from_scripts(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        let opcodes = parse_script::<DebugTx<'a>, DebugReused>(script).collect::<Result<Vec<_>, _>>()?;
        let op_displays = opcodes.iter().map(|op| format!("{op:?}")).collect();
        let opcodes: Vec<Option<DebugOpcode<'a>>> = opcodes.into_iter().map(Some).collect();
        let source_lines: Vec<String> = source.lines().map(String::from).collect();
        let (opcode_offsets, script_len) = build_opcode_offsets(&opcodes);

        let statement_mappings = debug_info
            .as_ref()
            .map(|info| {
                let mut mappings = info
                    .mappings
                    .iter()
                    .filter(|mapping| matches!(&mapping.kind, MappingKind::Statement { .. }))
                    .cloned()
                    .collect::<Vec<_>>();
                mappings.sort_by_key(|mapping| (mapping.bytecode_start, mapping.bytecode_end));
                mappings
            })
            .unwrap_or_default();

        Ok(Self {
            engine,
            opcodes,
            op_displays,
            opcode_offsets,
            script_len,
            pc: 0,
            debug_info,
            statement_mappings,
            source_lines,
            breakpoints: HashSet::new(),
        })
    }

    pub fn step_opcode(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.pc >= self.opcodes.len() {
            return Ok(None);
        }

        let opcode = self.opcodes[self.pc].take().expect("opcode already executed");
        self.engine.execute_opcode(opcode)?;
        self.pc += 1;
        Ok(Some(self.state()))
    }

    pub fn step_statement(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.statement_mappings.is_empty() {
            return self.step_opcode();
        }

        let start_offset = self.current_byte_offset();
        let start_stmt =
            self.statement_for_offset(start_offset).filter(|_| self.engine.is_executing()).map(|stmt| stmt.bytecode_start);

        let mut progressed = false;
        loop {
            if self.pc >= self.opcodes.len() {
                return Ok(if progressed { Some(self.state()) } else { None });
            }

            if self.step_opcode()?.is_none() {
                return Ok(if progressed { Some(self.state()) } else { None });
            }
            progressed = true;

            let offset = self.current_byte_offset();
            if let Some(stmt) = self.statement_for_offset(offset) {
                if self.engine.is_executing() {
                    let stmt_start = stmt.bytecode_start;
                    if start_stmt.map(|s| s != stmt_start).unwrap_or(true) {
                        return Ok(Some(self.state()));
                    }
                }
            }
        }
    }

    pub fn run_to_first_executed_statement(&mut self) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        if self.statement_mappings.is_empty() {
            return Ok(());
        }
        loop {
            if self.pc >= self.opcodes.len() {
                return Ok(());
            }
            let offset = self.current_byte_offset();
            if self.statement_for_offset(offset).is_some() {
                if self.engine.is_executing() {
                    return Ok(());
                }
            }
            if self.step_opcode()?.is_none() {
                return Ok(());
            }
        }
    }

    pub fn continue_to_breakpoint(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.breakpoints.is_empty() {
            while self.step_opcode()?.is_some() {}
            return Ok(None);
        }
        loop {
            if self.step_statement()?.is_none() {
                return Ok(None);
            }
            let offset = self.current_byte_offset();
            if let Some(mapping) = self.statement_for_offset(offset) {
                if self.engine.is_executing() {
                    if let Some(span) = mapping.span {
                        if self.breakpoints.contains(&span.line) {
                            return Ok(Some(self.state()));
                        }
                    }
                }
            }
        }
    }

    pub fn state(&self) -> SessionState {
        let executed = self.pc.saturating_sub(1);
        let opcode = self.op_displays.get(executed).cloned();
        SessionState {
            pc: self.pc,
            opcode,
            mapping: self.mapping_for_offset(self.current_byte_offset()).cloned(),
            stack: self.format_stack(),
        }
    }

    pub fn opcode_count(&self) -> usize {
        self.op_displays.len()
    }

    pub fn source_context(&self) -> Option<SourceContext> {
        let span = self.statement_for_offset(self.current_byte_offset()).and_then(|mapping| mapping.span)?;
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

    pub fn add_breakpoint(&mut self, line: u32) {
        self.breakpoints.insert(line);
    }

    pub fn breakpoints(&self) -> Vec<u32> {
        let mut lines = self.breakpoints.iter().copied().collect::<Vec<_>>();
        lines.sort_unstable();
        lines
    }

    pub fn clear_breakpoint(&mut self, line: u32) {
        self.breakpoints.remove(&line);
    }

    pub fn list_variables(&self) -> Result<Vec<Variable>, String> {
        let info = self.debug_info.as_ref().ok_or_else(|| "No debug info available".to_string())?;
        let function_name = self.current_function_name().ok_or_else(|| "No function context available".to_string())?;
        let offset = self.current_byte_offset();
        let var_updates = self.current_variable_updates(function_name, offset);

        let mut variables: Vec<Variable> = Vec::new();

        for (name, update) in &var_updates {
            // Try to evaluate; if it fails (e.g., inline function return), show Unknown
            let value = self
                .evaluate_expr(&update.expr, function_name, &var_updates, &mut HashSet::new())
                .unwrap_or_else(|err| DebugValue::Unknown(err));
            variables.push(Variable { name: name.clone(), type_name: update.type_name.clone(), value });
        }

        for param in info.params.iter().filter(|param| param.function == function_name) {
            if var_updates.contains_key(&param.name) {
                continue;
            }
            let value = self.read_param_value(param)?;
            variables.push(Variable { name: param.name.clone(), type_name: param.type_name.clone(), value });
        }

        // Add constructor constants
        for constant in &info.constants {
            if var_updates.contains_key(&constant.name) {
                continue;
            }
            let value = self.evaluate_constant(&constant.value);
            variables.push(Variable { name: constant.name.clone(), type_name: constant.type_name.clone(), value });
        }

        variables.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(variables)
    }

    pub fn variable_by_name(&self, name: &str) -> Result<Variable, String> {
        let info = self.debug_info.as_ref().ok_or_else(|| "No debug info available".to_string())?;
        let function_name = self.current_function_name().ok_or_else(|| "No function context available".to_string())?;
        let offset = self.current_byte_offset();
        let var_updates = self.current_variable_updates(function_name, offset);

        if let Some(update) = var_updates.get(name) {
            let value = self.evaluate_expr(&update.expr, function_name, &var_updates, &mut HashSet::new())?;
            return Ok(Variable { name: name.to_string(), type_name: update.type_name.clone(), value });
        }

        if let Some(param) = info.params.iter().find(|param| param.function == function_name && param.name == name) {
            let value = self.read_param_value(param)?;
            return Ok(Variable { name: name.to_string(), type_name: param.type_name.clone(), value });
        }

        // Check constructor constants
        if let Some(constant) = info.constants.iter().find(|c| c.name == name) {
            let value = self.evaluate_constant(&constant.value);
            return Ok(Variable { name: name.to_string(), type_name: constant.type_name.clone(), value });
        }

        Err(format!("unknown variable '{name}'"))
    }

    pub fn format_value(&self, type_name: &str, value: &DebugValue) -> String {
        let element_type = type_name.strip_suffix("[]");
        match (type_name, value) {
            ("int", DebugValue::Int(number)) => number.to_string(),
            ("bool", DebugValue::Bool(value)) => value.to_string(),
            ("string", DebugValue::String(value)) => value.clone(),
            (_, DebugValue::Unknown(_)) => "<from function call>".to_string(),
            (_, DebugValue::Bytes(bytes)) if element_type.is_some() => {
                let element_type = element_type.expect("checked");
                let Some(element_size) = self.array_element_size(element_type) else {
                    return format!("0x{}", hex::encode(bytes));
                };
                if element_size == 0 || bytes.len() % element_size != 0 {
                    return format!("0x{}", hex::encode(bytes));
                }

                let mut values: Vec<String> = Vec::new();
                for chunk in bytes.chunks(element_size) {
                    let decoded = match element_type {
                        "int" => DebugValue::Int(self.decode_i64(chunk).unwrap_or(0)),
                        "bool" => DebugValue::Bool(self.decode_i64(chunk).unwrap_or(0) != 0),
                        _ => DebugValue::Bytes(chunk.to_vec()),
                    };
                    values.push(self.format_value(element_type, &decoded));
                }
                format!("[{}]", values.join(", "))
            }
            (_, DebugValue::Bytes(bytes)) => format!("0x{}", hex::encode(bytes)),
            (_, DebugValue::Int(number)) => number.to_string(),
            (_, DebugValue::Bool(value)) => value.to_string(),
            (_, DebugValue::String(value)) => value.clone(),
            (_, DebugValue::Array(values)) => {
                let value_type = element_type.unwrap_or(type_name);
                format!("[{}]", values.iter().map(|v| self.format_value(value_type, v)).collect::<Vec<_>>().join(", "))
            }
        }
    }

    pub fn stack(&self) -> Vec<String> {
        self.format_stack()
    }

    pub fn current_location(&self) -> Option<DebugMapping> {
        self.mapping_for_offset(self.current_byte_offset()).cloned()
    }

    pub fn current_byte_offset(&self) -> usize {
        self.opcode_offsets.get(self.pc).copied().unwrap_or(self.script_len)
    }

    pub fn current_span(&self) -> Option<SourceSpan> {
        self.current_location().and_then(|mapping| mapping.span)
    }

    pub fn current_function_name(&self) -> Option<&str> {
        self.current_function_range().map(|range| range.name.as_str())
    }

    fn current_function_range(&self) -> Option<&DebugFunctionRange> {
        let info = self.debug_info.as_ref()?;
        let offset = self.current_byte_offset();
        info.functions.iter().find(|function| offset >= function.bytecode_start && offset < function.bytecode_end)
    }

    fn current_variable_updates(&self, function_name: &str, offset: usize) -> HashMap<String, &DebugVariableUpdate> {
        let mut latest: HashMap<String, &DebugVariableUpdate> = HashMap::new();
        let Some(info) = self.debug_info.as_ref() else {
            return latest;
        };
        for update in
            info.variable_updates.iter().filter(|update| update.function == function_name && update.bytecode_offset <= offset)
        {
            match latest.get(&update.name) {
                Some(existing) if existing.bytecode_offset > update.bytecode_offset => {}
                _ => {
                    latest.insert(update.name.clone(), update);
                }
            }
        }
        latest
    }

    fn mapping_for_offset(&self, offset: usize) -> Option<&DebugMapping> {
        let mappings = self.debug_info.as_ref()?.mappings.as_slice();
        let mut best: Option<&DebugMapping> = None;
        let mut best_len = usize::MAX;
        for mapping in mappings {
            if offset >= mapping.bytecode_start && offset < mapping.bytecode_end {
                let len = mapping.bytecode_end.saturating_sub(mapping.bytecode_start);
                if len < best_len {
                    best = Some(mapping);
                    best_len = len;
                }
            }
        }
        best
    }

    fn statement_for_offset(&self, offset: usize) -> Option<&DebugMapping> {
        let mut best: Option<&DebugMapping> = None;
        let mut best_len = usize::MAX;
        for mapping in &self.statement_mappings {
            if offset >= mapping.bytecode_start && offset < mapping.bytecode_end {
                let len = mapping.bytecode_end.saturating_sub(mapping.bytecode_start);
                if len < best_len {
                    best = Some(mapping);
                    best_len = len;
                }
            }
        }
        best
    }

    fn format_stack(&self) -> Vec<String> {
        let stacks = self.engine.stacks();
        stacks.dstack.iter().map(|item| hex::encode(item)).collect()
    }

    fn evaluate_expr(
        &self,
        expr: &Expr,
        function_name: &str,
        var_updates: &HashMap<String, &DebugVariableUpdate>,
        visiting: &mut HashSet<String>,
    ) -> Result<DebugValue, String> {
        match expr {
            Expr::Int(value) => Ok(DebugValue::Int(*value)),
            Expr::Bool(value) => Ok(DebugValue::Bool(*value)),
            Expr::Bytes(value) => Ok(DebugValue::Bytes(value.clone())),
            Expr::String(value) => Ok(DebugValue::String(value.clone())),
            Expr::Array(values) => {
                let mut out = Vec::with_capacity(values.len());
                for value in values {
                    out.push(self.evaluate_expr(value, function_name, var_updates, visiting)?);
                }
                Ok(DebugValue::Array(out))
            }
            Expr::Identifier(name) => {
                if let Some(update) = var_updates.get(name) {
                    if !visiting.insert(name.clone()) {
                        return Err(format!("cyclic reference to '{name}'"));
                    }
                    let value = self.evaluate_expr(&update.expr, function_name, var_updates, visiting)?;
                    visiting.remove(name);
                    return Ok(value);
                }
                if let Some(param) = self.param_for_name(function_name, name) {
                    return self.read_param_value(param);
                }
                Err(format!("unknown identifier '{name}'"))
            }
            Expr::Unary { op: UnaryOp::Not, expr } => {
                let value = self.evaluate_expr(expr, function_name, var_updates, visiting)?;
                Ok(DebugValue::Bool(!self.value_to_bool(&value)))
            }
            Expr::Unary { op: UnaryOp::Neg, expr } => {
                let value = self.evaluate_expr(expr, function_name, var_updates, visiting)?;
                let number = self.value_to_int(&value)?;
                Ok(DebugValue::Int(-number))
            }
            Expr::Binary { op, left, right } => {
                let left_value = self.evaluate_expr(left, function_name, var_updates, visiting)?;
                let right_value = self.evaluate_expr(right, function_name, var_updates, visiting)?;
                self.evaluate_binary(*op, left_value, right_value)
            }
            Expr::IfElse { condition, then_expr, else_expr } => {
                let cond = self.evaluate_expr(condition, function_name, var_updates, visiting)?;
                if self.value_to_bool(&cond) {
                    self.evaluate_expr(then_expr, function_name, var_updates, visiting)
                } else {
                    self.evaluate_expr(else_expr, function_name, var_updates, visiting)
                }
            }
            Expr::Split { source, index, part } => {
                let source_val = self.evaluate_expr(source, function_name, var_updates, visiting)?;
                let index_val = self.evaluate_expr(index, function_name, var_updates, visiting)?;
                let idx = self.value_to_int(&index_val)? as usize;
                match source_val {
                    DebugValue::Bytes(bytes) => {
                        let mid = idx.min(bytes.len());
                        let out = match part {
                            SplitPart::Left => bytes[..mid].to_vec(),
                            SplitPart::Right => bytes[mid..].to_vec(),
                        };
                        Ok(DebugValue::Bytes(out))
                    }
                    DebugValue::Array(values) => {
                        let mid = idx.min(values.len());
                        let out = match part {
                            SplitPart::Left => values[..mid].to_vec(),
                            SplitPart::Right => values[mid..].to_vec(),
                        };
                        Ok(DebugValue::Array(out))
                    }
                    _ => Err("split() expects bytes or array".to_string()),
                }
            }
            Expr::Slice { source, start, end } => {
                let source_val = self.evaluate_expr(source, function_name, var_updates, visiting)?;
                let start_val = self.evaluate_expr(start, function_name, var_updates, visiting)?;
                let end_val = self.evaluate_expr(end, function_name, var_updates, visiting)?;
                let start_idx = self.value_to_int(&start_val)? as usize;
                let end_idx = self.value_to_int(&end_val)? as usize;
                match source_val {
                    DebugValue::Bytes(bytes) => {
                        let s = start_idx.min(bytes.len());
                        let e = end_idx.min(bytes.len());
                        Ok(DebugValue::Bytes(bytes[s..e].to_vec()))
                    }
                    DebugValue::Array(values) => {
                        let s = start_idx.min(values.len());
                        let e = end_idx.min(values.len());
                        Ok(DebugValue::Array(values[s..e].to_vec()))
                    }
                    _ => Err("slice() expects bytes or array".to_string()),
                }
            }
            Expr::ArrayIndex { source, index } => {
                let source_val = self.evaluate_expr(source, function_name, var_updates, visiting)?;
                let index_val = self.evaluate_expr(index, function_name, var_updates, visiting)?;
                let idx = self.value_to_int(&index_val)? as usize;
                match source_val {
                    DebugValue::Array(values) => values.get(idx).cloned().ok_or_else(|| "index out of range".to_string()),
                    DebugValue::Bytes(bytes) => {
                        bytes.get(idx).map(|b| DebugValue::Bytes(vec![*b])).ok_or_else(|| "index out of range".to_string())
                    }
                    _ => Err("indexing expects array or bytes".to_string()),
                }
            }
            Expr::Call { name, args } => self.evaluate_call(name, args, function_name, var_updates, visiting),
            Expr::Introspection { kind, .. } => {
                Err(format!("cannot evaluate introspection ({kind:?}) - requires transaction context"))
            }
            Expr::Nullary(op) => Err(format!("cannot evaluate {op:?} - requires transaction context")),
            Expr::New { name, .. } => Err(format!("cannot evaluate {name}(...) constructor in debugger")),
        }
    }

    fn evaluate_call(
        &self,
        name: &str,
        args: &[Expr],
        function_name: &str,
        var_updates: &HashMap<String, &DebugVariableUpdate>,
        visiting: &mut HashSet<String>,
    ) -> Result<DebugValue, String> {
        match name {
            "bytes" => {
                if args.is_empty() || args.len() > 2 {
                    return Err("bytes() expects one or two arguments".to_string());
                }
                let value = self.evaluate_expr(&args[0], function_name, var_updates, visiting)?;
                if args.len() == 2 {
                    let size_val = self.evaluate_expr(&args[1], function_name, var_updates, visiting)?;
                    let size = self.value_to_int(&size_val)? as usize;
                    let number = self.value_to_int(&value)?;
                    return Ok(DebugValue::Bytes(self.encode_i64_le(number, size)));
                }
                match value {
                    DebugValue::String(s) => Ok(DebugValue::Bytes(s.as_bytes().to_vec())),
                    DebugValue::Bytes(bytes) => Ok(DebugValue::Bytes(bytes)),
                    DebugValue::Int(number) => Ok(DebugValue::Bytes(self.encode_i64_le(number, 8))),
                    DebugValue::Bool(value) => Ok(DebugValue::Bytes(vec![if value { 1 } else { 0 }])),
                    _ => Err("bytes() expects int, bool, bytes, or string".to_string()),
                }
            }
            "int" => {
                if args.len() != 1 {
                    return Err("int() expects one argument".to_string());
                }
                let value = self.evaluate_expr(&args[0], function_name, var_updates, visiting)?;
                let number = self.value_to_int(&value)?;
                Ok(DebugValue::Int(number))
            }
            "length" => {
                if args.len() != 1 {
                    return Err("length() expects one argument".to_string());
                }
                let value = self.evaluate_expr(&args[0], function_name, var_updates, visiting)?;
                let length = match value {
                    DebugValue::Bytes(bytes) => bytes.len(),
                    DebugValue::String(s) => s.as_bytes().len(),
                    DebugValue::Array(values) => values.len(),
                    _ => return Err("length() expects bytes, string, or array".to_string()),
                };
                Ok(DebugValue::Int(length as i64))
            }
            name if name.starts_with("bytes") => {
                let size = name
                    .strip_prefix("bytes")
                    .and_then(|v| v.parse::<usize>().ok())
                    .ok_or_else(|| format!("{name}() is not supported"))?;
                if args.len() != 1 {
                    return Err(format!("{name}() expects one argument"));
                }
                let value = self.evaluate_expr(&args[0], function_name, var_updates, visiting)?;
                let number = self.value_to_int(&value)?;
                Ok(DebugValue::Bytes(self.encode_i64_le(number, size)))
            }
            _ => Err(format!("unsupported call '{name}' in debugger")),
        }
    }

    fn evaluate_binary(&self, op: BinaryOp, left: DebugValue, right: DebugValue) -> Result<DebugValue, String> {
        match op {
            BinaryOp::Add => match (left, right) {
                (DebugValue::Bytes(mut left), DebugValue::Bytes(right)) => {
                    left.extend_from_slice(&right);
                    Ok(DebugValue::Bytes(left))
                }
                (left, right) => Ok(DebugValue::Int(self.value_to_int(&left)? + self.value_to_int(&right)?)),
            },
            BinaryOp::Sub => Ok(DebugValue::Int(self.value_to_int(&left)? - self.value_to_int(&right)?)),
            BinaryOp::Mul => Ok(DebugValue::Int(self.value_to_int(&left)? * self.value_to_int(&right)?)),
            BinaryOp::Div => Ok(DebugValue::Int(self.value_to_int(&left)? / self.value_to_int(&right)?)),
            BinaryOp::Mod => Ok(DebugValue::Int(self.value_to_int(&left)? % self.value_to_int(&right)?)),
            BinaryOp::BitAnd => Ok(DebugValue::Int(self.value_to_int(&left)? & self.value_to_int(&right)?)),
            BinaryOp::BitOr => Ok(DebugValue::Int(self.value_to_int(&left)? | self.value_to_int(&right)?)),
            BinaryOp::BitXor => Ok(DebugValue::Int(self.value_to_int(&left)? ^ self.value_to_int(&right)?)),
            BinaryOp::Eq => Ok(DebugValue::Bool(self.value_equals(&left, &right))),
            BinaryOp::Ne => Ok(DebugValue::Bool(!self.value_equals(&left, &right))),
            BinaryOp::Lt => Ok(DebugValue::Bool(self.value_to_int(&left)? < self.value_to_int(&right)?)),
            BinaryOp::Le => Ok(DebugValue::Bool(self.value_to_int(&left)? <= self.value_to_int(&right)?)),
            BinaryOp::Gt => Ok(DebugValue::Bool(self.value_to_int(&left)? > self.value_to_int(&right)?)),
            BinaryOp::Ge => Ok(DebugValue::Bool(self.value_to_int(&left)? >= self.value_to_int(&right)?)),
            BinaryOp::And => Ok(DebugValue::Bool(self.value_to_bool(&left) && self.value_to_bool(&right))),
            BinaryOp::Or => Ok(DebugValue::Bool(self.value_to_bool(&left) || self.value_to_bool(&right))),
        }
    }

    fn array_element_size(&self, element_type: &str) -> Option<usize> {
        match element_type {
            "int" => Some(8),
            "bool" => Some(1),
            "byte" => Some(1),
            other => other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()),
        }
    }

    fn value_equals(&self, left: &DebugValue, right: &DebugValue) -> bool {
        match (left, right) {
            (DebugValue::Int(a), DebugValue::Int(b)) => a == b,
            (DebugValue::Bool(a), DebugValue::Bool(b)) => a == b,
            (DebugValue::Bytes(a), DebugValue::Bytes(b)) => a == b,
            (DebugValue::String(a), DebugValue::String(b)) => a == b,
            _ => false,
        }
    }

    fn value_to_bool(&self, value: &DebugValue) -> bool {
        match value {
            DebugValue::Bool(value) => *value,
            DebugValue::Int(value) => *value != 0,
            DebugValue::Bytes(bytes) => bytes.iter().any(|b| *b != 0),
            DebugValue::String(s) => !s.is_empty(),
            DebugValue::Array(values) => !values.is_empty(),
            DebugValue::Unknown(_) => false,
        }
    }

    fn value_to_int(&self, value: &DebugValue) -> Result<i64, String> {
        match value {
            DebugValue::Int(value) => Ok(*value),
            DebugValue::Bool(value) => Ok(if *value { 1 } else { 0 }),
            DebugValue::Bytes(bytes) => self.decode_i64(bytes),
            DebugValue::String(s) => s.parse::<i64>().map_err(|_| "string is not an int".to_string()),
            DebugValue::Array(_) => Err("array is not an int".to_string()),
            DebugValue::Unknown(reason) => Err(format!("unknown value: {reason}")),
        }
    }

    fn param_for_name(&self, function_name: &str, name: &str) -> Option<&DebugParamMapping> {
        let info = self.debug_info.as_ref()?;
        info.params.iter().find(|param| param.function == function_name && param.name == name)
    }

    fn read_param_value(&self, param: &DebugParamMapping) -> Result<DebugValue, String> {
        let bytes = self.read_stack_at_index(param.stack_index)?;
        self.decode_value_by_type(&param.type_name, bytes)
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

    fn decode_value_by_type(&self, type_name: &str, bytes: Vec<u8>) -> Result<DebugValue, String> {
        match type_name {
            "int" => Ok(DebugValue::Int(self.decode_i64(&bytes)?)),
            "bool" => Ok(DebugValue::Bool(self.decode_i64(&bytes)? != 0)),
            "string" => match String::from_utf8(bytes.clone()) {
                Ok(value) => Ok(DebugValue::String(value)),
                Err(_) => Ok(DebugValue::Bytes(bytes)),
            },
            _ => Ok(DebugValue::Bytes(bytes)),
        }
    }

    fn decode_i64(&self, bytes: &[u8]) -> Result<i64, String> {
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

    fn encode_i64_le(&self, value: i64, size: usize) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut out = vec![0u8; size];
        for (idx, byte) in bytes.iter().take(size).enumerate() {
            out[idx] = *byte;
        }
        out
    }
}

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
