use std::collections::{HashMap, HashSet};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{PopulatedTransaction, TransactionInput, UtxoEntry};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{DynOpcodeImplementation, EngineCtx, EngineFlags, TxScriptEngine, parse_script};

use silverscript_lang::ast::{Expr, ExprKind};
use silverscript_lang::compiler::compile_debug_expr;
use silverscript_lang::debug_info::{
    DebugFunctionRange, DebugInfo, DebugParamMapping, DebugStep, DebugVariableUpdate, SourceSpan, StepId, StepKind,
};

pub use crate::presentation::{SourceContext, SourceContextLine};
use crate::presentation::{build_source_context, format_value as format_debug_value};
use crate::util::{decode_i64, encode_hex};

pub type DebugTx<'a> = PopulatedTransaction<'a>;
pub type DebugReused = SigHashReusedValuesUnsync;
pub type DebugOpcode<'a> = DynOpcodeImplementation<DebugTx<'a>, DebugReused>;
pub type DebugEngine<'a> = TxScriptEngine<'a, DebugTx<'a>, DebugReused>;

#[derive(Clone, Copy)]
pub struct ShadowTxContext<'a> {
    pub tx: &'a DebugTx<'a>,
    pub input: &'a TransactionInput,
    pub input_index: usize,
    pub utxo_entry: &'a UtxoEntry,
    pub covenants_ctx: &'a CovenantsContext,
}

#[derive(Debug, Clone)]
pub enum DebugValue {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<DebugValue>),
    /// Value could not be evaluated (for example unresolved identifiers or shadow VM failures).
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
pub struct SessionState<'i> {
    pub pc: usize,
    pub opcode: Option<String>,
    pub step: Option<DebugStep<'i>>,
    pub stack: Vec<String>,
}

pub struct DebugSession<'a, 'i> {
    engine: DebugEngine<'a>,
    shadow_tx_context: Option<ShadowTxContext<'a>>,
    opcodes: Vec<Option<DebugOpcode<'a>>>,
    op_displays: Vec<String>,
    opcode_offsets: Vec<usize>,
    script_len: usize,
    pc: usize,
    debug_info: DebugInfo<'i>,
    step_order: Vec<usize>,
    current_step_index: Option<usize>,
    source_lines: Vec<String>,
    breakpoints: HashSet<u32>,
    // Source-level step ids that were already visited in this session.
    executed_steps: HashSet<StepId>,
}

struct ShadowParamValue {
    name: String,
    type_name: String,
    stack_index: i64,
    value: Vec<u8>,
}

struct VariableContext<'a> {
    function_name: &'a str,
    function_start: usize,
    function_end: usize,
    offset: usize,
    step_id: StepId,
}

impl<'a, 'i> DebugSession<'a, 'i> {
    // --- Session construction + stepping ---

    /// Creates a debug session simulating a full transaction spend.
    /// Executes sigscript first to seed the stack, then debugs lockscript execution.
    pub fn full(
        sigscript: &[u8],
        lockscript: &[u8],
        source: &str,
        debug_info: Option<DebugInfo<'i>>,
        mut engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        seed_engine_with_sigscript(&mut engine, sigscript)?;
        Self::from_scripts(lockscript, source, debug_info, engine)
    }

    /// Internal constructor: parses script, prepares opcodes, extracts statement steps.
    pub fn from_scripts(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo<'i>>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        let debug_info = debug_info.unwrap_or_else(DebugInfo::empty);
        let opcodes = parse_script::<DebugTx<'a>, DebugReused>(script).collect::<Result<Vec<_>, _>>()?;
        let op_displays = opcodes.iter().map(|op| format!("{op:?}")).collect();
        let opcodes: Vec<Option<DebugOpcode<'a>>> = opcodes.into_iter().map(Some).collect();
        let source_lines: Vec<String> = source.lines().map(String::from).collect();
        let (opcode_offsets, script_len) = build_opcode_offsets(&opcodes);

        let mut step_order: Vec<usize> = (0..debug_info.steps.len()).collect();
        // Overlapping inline ranges can share the same bytecode offsets; keep
        // compiler emission order via sequence before comparing range width.
        step_order.sort_by_key(|&index| {
            let step = &debug_info.steps[index];
            (step.bytecode_start, step.sequence, step_kind_order(&step.kind), step.call_depth, step.bytecode_end, step.frame_id)
        });

        Ok(Self {
            engine,
            shadow_tx_context: None,
            opcodes,
            op_displays,
            opcode_offsets,
            script_len,
            pc: 0,
            debug_info,
            step_order,
            current_step_index: None,
            source_lines,
            breakpoints: HashSet::new(),
            executed_steps: HashSet::new(),
        })
    }

    /// Executes a single opcode and advances the program counter.
    pub fn step_opcode(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        if self.pc >= self.opcodes.len() {
            return Ok(None);
        }

        let opcode = self.opcodes[self.pc].take().expect("opcode already executed");
        self.engine.execute_opcode(opcode)?;
        self.pc += 1;
        self.sync_step_cursor_to_current_offset();
        Ok(Some(self.state()))
    }

    pub fn with_shadow_tx_context(mut self, shadow_tx_context: ShadowTxContext<'a>) -> Self {
        self.shadow_tx_context = Some(shadow_tx_context);
        self
    }

    /// Step into: advance to next source step regardless of call depth.
    pub fn step_into(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|_, _| true)
    }

    /// Step over: advance to next source step at the same or shallower call depth.
    pub fn step_over(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|candidate, current| candidate <= current)
    }

    /// Step out: advance to next source step at a shallower call depth.
    pub fn step_out(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|candidate, current| candidate < current)
    }

    /// Shared stepping loop for `step_into`, `step_over`, and `step_out`.
    /// Picks the next steppable step whose call depth satisfies `predicate`,
    /// executes opcodes until that step becomes active, and skips candidates
    /// that are already behind the current byte offset (for example, non-taken
    /// branch steps).
    fn step_with_depth_predicate(
        &mut self,
        predicate: impl Fn(u32, u32) -> bool,
    ) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        if self.step_order.is_empty() {
            return self.step_opcode();
        }

        let current_depth = self.current_timeline_step().map(|step| step.call_depth).unwrap_or(0);
        let mut search_from = self.current_step_index;

        loop {
            let Some(target_index) = self.next_steppable_step_index(search_from, |step| predicate(step.call_depth, current_depth))
            else {
                while self.step_opcode()?.is_some() {}
                return Ok(None);
            };

            if self.advance_to_step(target_index)? {
                self.current_step_index = Some(target_index);
                self.mark_step_executed(target_index);
                return Ok(Some(self.state()));
            }

            search_from = Some(target_index);
        }
    }

    fn advance_to_step(&mut self, target_index: usize) -> Result<bool, kaspa_txscript_errors::TxScriptError> {
        let Some(target) = self.step_at_order(target_index) else {
            return Ok(false);
        };
        let (target_start, target_end) = (target.bytecode_start, target.bytecode_end);
        loop {
            let offset = self.current_byte_offset();

            if offset > target_start {
                return Ok(false);
            }

            if range_matches_offset(target_start, target_end, offset) && self.engine.is_executing() {
                return Ok(true);
            }

            if self.step_opcode()?.is_none() {
                return Ok(false);
            }
        }
    }

    /// Advances execution to the first user statement, skipping dispatcher/synthetic bytecode.
    /// Call this after session creation to skip over contract setup code.
    /// Skips opcodes until the first source step is encountered.
    pub fn run_to_first_executed_statement(&mut self) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        if self.step_order.is_empty() {
            return Ok(());
        }
        loop {
            if self.pc >= self.opcodes.len() {
                return Ok(());
            }
            let offset = self.current_byte_offset();
            if self.engine.is_executing() {
                if let Some(index) = self.steppable_step_index_for_offset(offset) {
                    self.current_step_index = Some(index);
                    self.mark_step_executed(index);
                    return Ok(());
                }
            }
            if self.step_opcode()?.is_none() {
                return Ok(());
            }
        }
    }

    /// Continues execution until a breakpoint is hit or script completes.
    pub fn continue_to_breakpoint(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        if self.breakpoints.is_empty() {
            while self.step_opcode()?.is_some() {}
            return Ok(None);
        }
        loop {
            if self.step_into()?.is_none() {
                return Ok(None);
            }
            if let Some(step) = self.current_timeline_step() {
                if self.step_hits_breakpoint(step) {
                    return Ok(Some(self.state()));
                }
            }
        }
    }

    /// Returns the current execution state snapshot.
    pub fn state(&self) -> SessionState<'i> {
        let executed = self.pc.saturating_sub(1);
        let opcode = self.op_displays.get(executed).cloned();
        SessionState { pc: self.pc, opcode, step: self.current_step(), stack: self.stack() }
    }

    /// Returns true if the script engine is still running.
    pub fn is_executing(&self) -> bool {
        self.engine.is_executing()
    }

    pub fn debug_info(&self) -> &DebugInfo<'i> {
        &self.debug_info
    }

    // --- Step + source context ---

    /// Returns source lines around the current statement (radius = 6 lines).
    /// Returns surrounding source lines with the current line highlighted.
    pub fn source_context(&self) -> Option<SourceContext> {
        let span = self.current_span()?;
        Some(build_source_context(&self.source_lines, span, 6))
    }

    /// Adds a breakpoint at the given line number. Returns true if added.
    pub fn add_breakpoint(&mut self, line: u32) -> bool {
        let valid = self
            .step_order
            .iter()
            .filter_map(|&index| self.debug_info.steps.get(index))
            .any(|step| self.is_steppable_step(step) && line >= step.span.line && line <= step.span.end_line);
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
        self.collect_variables(self.current_step_id())
    }

    pub fn list_variables_at_sequence(&self, sequence: u32, frame_id: u32) -> Result<Vec<Variable>, String> {
        self.collect_variables(StepId::new(sequence, frame_id))
    }

    fn collect_variables(&self, step_id: StepId) -> Result<Vec<Variable>, String> {
        let context = self.current_variable_context(step_id)?;
        let mut variables = self.collect_variables_map(&context)?.into_values().collect::<Vec<_>>();
        variables.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(variables)
    }

    /// Returns a specific variable by name, or error if not in scope.
    pub fn variable_by_name(&self, name: &str) -> Result<Variable, String> {
        let context = self.current_variable_context(self.current_step_id())?;
        let variables = self.collect_variables_map(&context)?;
        variables.get(name).cloned().ok_or_else(|| format!("unknown variable '{name}'"))
    }

    // --- DebugValue formatting ---
    /// Formats a debug value for display based on its type.
    pub fn format_value(&self, type_name: &str, value: &DebugValue) -> String {
        format_debug_value(type_name, value)
    }

    /// Returns the debug step for the current bytecode position.
    pub fn current_step(&self) -> Option<DebugStep<'i>> {
        self.current_timeline_step().cloned().or_else(|| self.step_for_offset(self.current_byte_offset()).cloned())
    }

    /// Returns the current bytecode offset in the script.
    pub fn current_byte_offset(&self) -> usize {
        self.opcode_offsets.get(self.pc).copied().unwrap_or(self.script_len)
    }

    /// Returns the source span (line/col range) at the current position.
    pub fn current_span(&self) -> Option<SourceSpan> {
        self.current_step().map(|step| step.span)
    }

    pub fn call_stack(&self) -> Vec<String> {
        let mut stack = Vec::new();
        let Some(current) = self.current_step_index else {
            return stack;
        };
        for order_index in 0..=current {
            let Some(step) = self.step_at_order(order_index) else {
                continue;
            };
            match &step.kind {
                StepKind::InlineCallEnter { callee } => stack.push(callee.clone()),
                StepKind::InlineCallExit { .. } => {
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

    fn current_variable_updates(&self, context: &VariableContext<'_>) -> HashMap<String, &DebugVariableUpdate<'i>> {
        let mut latest_by_name: HashMap<String, (u32, &DebugVariableUpdate<'i>)> = HashMap::new();
        for step in self.debug_info.steps.iter().filter(|step| self.step_updates_are_visible(step, context)) {
            for update in &step.variable_updates {
                match latest_by_name.get(&update.name) {
                    Some((existing_sequence, _)) if *existing_sequence > step.sequence => {}
                    _ => {
                        latest_by_name.insert(update.name.clone(), (step.sequence, update));
                    }
                }
            }
        }
        latest_by_name.into_iter().map(|(name, (_, update))| (name, update)).collect()
    }

    fn current_variable_context(&self, step_id: StepId) -> Result<VariableContext<'_>, String> {
        let function = self.current_function_range().ok_or_else(|| "No function context available".to_string())?;
        Ok(VariableContext {
            function_name: function.name.as_str(),
            function_start: function.bytecode_start,
            function_end: function.bytecode_end,
            offset: self.current_byte_offset(),
            step_id,
        })
    }

    fn collect_variables_map(&self, context: &VariableContext<'_>) -> Result<HashMap<String, Variable>, String> {
        let mut variables: HashMap<String, Variable> = HashMap::new();
        let var_updates = self.current_variable_updates(context);

        for (name, update) in &var_updates {
            if is_inline_synthetic_name(name) {
                continue;
            }
            let value =
                self.evaluate_update_with_shadow_vm(context.function_name, update, &var_updates).unwrap_or_else(DebugValue::Unknown);
            variables.insert(
                name.clone(),
                Variable {
                    name: name.clone(),
                    type_name: update.type_name.clone(),
                    value,
                    is_constant: false,
                    origin: VariableOrigin::Local,
                },
            );
        }

        for param in self.debug_info.params.iter().filter(|param| param.function == context.function_name) {
            if variables.contains_key(&param.name) {
                continue;
            }
            let value = self.read_param_value(param)?;
            variables.insert(
                param.name.clone(),
                Variable {
                    name: param.name.clone(),
                    type_name: param.type_name.clone(),
                    value,
                    is_constant: false,
                    origin: VariableOrigin::Param,
                },
            );
        }

        // Contract constants are contract-scoped, not frame-scoped, so they
        // remain visible while stepping through inline callee frames.
        for constant in &self.debug_info.constants {
            if variables.contains_key(&constant.name) {
                continue;
            }
            variables.insert(
                constant.name.clone(),
                Variable {
                    name: constant.name.clone(),
                    type_name: constant.type_name.clone(),
                    value: self.evaluate_constant(&constant.value),
                    is_constant: true,
                    origin: VariableOrigin::Constant,
                },
            );
        }

        Ok(variables)
    }

    fn step_updates_are_visible(&self, step: &DebugStep<'i>, context: &VariableContext<'_>) -> bool {
        if step.bytecode_start < context.function_start || step.bytecode_start >= context.function_end {
            return false;
        }
        // Stay in the active inline frame and only consider updates from
        // steps already executed in this session.
        let step_id = step.id();
        step_id.frame_id == context.step_id.frame_id
            && self.executed_steps.contains(&step_id)
            && step_id.sequence < context.step_id.sequence
            && step.bytecode_end <= context.offset
    }

    /// Returns the most specific step for `offset`.
    /// Multiple steps may overlap; choosing the narrowest bytecode span makes
    /// location lookups prefer inner statement/inline ranges over broader ranges.
    fn step_for_offset(&self, offset: usize) -> Option<&DebugStep<'i>> {
        let mut best: Option<&DebugStep<'i>> = None;
        let mut best_len = usize::MAX;
        for step in &self.debug_info.steps {
            if step_matches_offset(step, offset) {
                let len = step.bytecode_end.saturating_sub(step.bytecode_start);
                if len < best_len {
                    best = Some(step);
                    best_len = len;
                }
            }
        }
        best
    }

    fn step_at_order(&self, order_index: usize) -> Option<&DebugStep<'i>> {
        let step_index = *self.step_order.get(order_index)?;
        self.debug_info.steps.get(step_index)
    }

    fn current_timeline_step(&self) -> Option<&DebugStep<'i>> {
        self.current_step_index.and_then(|index| self.step_at_order(index))
    }

    fn current_step_id(&self) -> StepId {
        self.current_timeline_step().map(DebugStep::id).unwrap_or(StepId::ROOT)
    }

    fn mark_step_executed(&mut self, step_index: usize) {
        if let Some(step) = self.step_at_order(step_index) {
            self.executed_steps.insert(step.id());
        }
    }

    fn sync_step_cursor_to_current_offset(&mut self) {
        let offset = self.current_byte_offset();
        if let Some(index) = self.steppable_step_index_for_offset(offset) {
            if self.current_step_index.is_some_and(|current| index < current) {
                // In sequence mode multiple steps may resolve to the same byte offset.
                // Keep cursor monotonic and avoid snapping backward to an earlier
                // step for that offset.
                return;
            }
            // `si` executes raw opcodes; keep statement cursor in sync so later
            // source-level steps (`next`/`step`/`finish`) start from the real
            // current step instead of an old one.
            self.current_step_index = Some(index);
            self.mark_step_executed(index);
        }
    }

    fn is_steppable_step(&self, step: &DebugStep<'i>) -> bool {
        // InlineCallEnter is steppable so `step_into` can land on a call
        // boundary and build call-stack transitions. InlineCallExit is not
        // steppable to avoid synthetic extra stops while unwinding.
        matches!(&step.kind, StepKind::Source {} | StepKind::InlineCallEnter { .. })
    }

    fn steppable_step_index_for_offset(&self, offset: usize) -> Option<usize> {
        self.step_order.iter().enumerate().find_map(|(order_index, &step_index)| {
            let step = self.debug_info.steps.get(step_index)?;
            (self.is_steppable_step(step) && step_matches_offset(step, offset)).then_some(order_index)
        })
    }

    fn next_steppable_step_index(&self, from: Option<usize>, predicate: impl Fn(&DebugStep<'i>) -> bool) -> Option<usize> {
        let start = from.map(|index| index.saturating_add(1)).unwrap_or(0);
        for index in start..self.step_order.len() {
            let step = self.step_at_order(index)?;
            if !self.is_steppable_step(step) {
                continue;
            }
            if predicate(step) {
                return Some(index);
            }
        }
        None
    }

    fn step_hits_breakpoint(&self, step: &DebugStep<'i>) -> bool {
        (step.span.line..=step.span.end_line).any(|line| self.breakpoints.contains(&line))
    }

    /// Returns the current main stack as hex-encoded strings.
    pub fn stack(&self) -> Vec<String> {
        let stacks = self.engine.stacks();
        stacks.dstack.iter().map(|item| encode_hex(item)).collect()
    }

    /// Evaluates an expression using shadow VM execution.
    ///
    /// Strategy: compile the pre-resolved expression to bytecode, build a mini-script
    /// that pushes current param values then executes the bytecode, run on fresh VM,
    /// read result from top of stack. This guarantees debugger sees same semantics as
    /// real execution without duplicating evaluation logic.
    fn evaluate_update_with_shadow_vm(
        &self,
        function_name: &str,
        update: &DebugVariableUpdate<'i>,
        updates: &HashMap<String, &DebugVariableUpdate<'i>>,
    ) -> Result<DebugValue, String> {
        let params = self.shadow_param_values(function_name)?;
        let type_name = &update.type_name;
        let expr = &update.expr;
        let mut param_indexes = HashMap::new();
        let mut param_types = HashMap::new();
        for param in &params {
            param_indexes.insert(param.name.clone(), param.stack_index);
            param_types.insert(param.name.clone(), param.type_name.clone());
        }
        let mut env: HashMap<String, Expr<'i>> = HashMap::new();
        let mut eval_types = param_types;
        for (name, update) in updates {
            env.insert((*name).clone(), update.expr.clone());
            eval_types.insert((*name).clone(), update.type_name.clone());
        }
        let bytecode = compile_debug_expr(expr, &env, &param_indexes, &eval_types)
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
        let mut engine: DebugEngine<'_> = if let Some(shadow) = self.shadow_tx_context {
            let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(shadow.covenants_ctx);
            TxScriptEngine::from_transaction_input(
                shadow.tx,
                shadow.input,
                shadow.input_index,
                shadow.utxo_entry,
                ctx,
                EngineFlags { covenants_enabled: true },
            )
        } else {
            TxScriptEngine::new(EngineCtx::new(&sig_cache).with_reused(&reused_values), EngineFlags { covenants_enabled: true })
        };
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

    fn evaluate_constant(&self, expr: &Expr<'i>) -> DebugValue {
        match &expr.kind {
            ExprKind::Int(v) => DebugValue::Int(*v),
            ExprKind::Bool(v) => DebugValue::Bool(*v),
            ExprKind::Byte(v) => DebugValue::Bytes(vec![*v]),
            ExprKind::String(v) => DebugValue::String(v.clone()),
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

fn step_kind_order(kind: &StepKind) -> u8 {
    match kind {
        StepKind::InlineCallEnter { .. } => 0,
        StepKind::Source {} => 1,
        StepKind::InlineCallExit { .. } => 2,
    }
}

fn range_matches_offset(bytecode_start: usize, bytecode_end: usize, offset: usize) -> bool {
    if bytecode_start == bytecode_end { offset == bytecode_start } else { offset >= bytecode_start && offset < bytecode_end }
}

fn step_matches_offset(step: &DebugStep<'_>, offset: usize) -> bool {
    range_matches_offset(step.bytecode_start, step.bytecode_end, offset)
}

fn is_inline_synthetic_name(name: &str) -> bool {
    name.starts_with("__arg_")
}

#[cfg(test)]
mod tests {
    use super::*;

    use silverscript_lang::ast::{BinaryOp, Expr, ExprKind};
    use silverscript_lang::debug_info::{
        DebugConstantMapping, DebugFunctionRange, DebugInfo, DebugParamMapping, DebugStep, DebugVariableUpdate, SourceSpan, StepKind,
    };
    use silverscript_lang::span;

    fn make_session(
        params: Vec<DebugParamMapping>,
        steps: Vec<DebugStep<'static>>,
        sigscript: &[u8],
    ) -> Result<DebugSession<'static, 'static>, kaspa_txscript_errors::TxScriptError> {
        let sig_cache = Box::leak(Box::new(Cache::new(10_000)));
        let reused_values: &'static SigHashReusedValuesUnsync = Box::leak(Box::new(SigHashReusedValuesUnsync::new()));
        let engine: DebugEngine<'static> =
            TxScriptEngine::new(EngineCtx::new(sig_cache).with_reused(reused_values), EngineFlags { covenants_enabled: true });
        let debug_info = DebugInfo {
            source: String::new(),
            steps,
            params,
            functions: vec![DebugFunctionRange { name: "f".to_string(), bytecode_start: 0, bytecode_end: 1 }],
            constants: vec![DebugConstantMapping { name: "K".to_string(), type_name: "int".to_string(), value: Expr::int(7) }],
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

        let update = DebugVariableUpdate {
            name: "x".to_string(),
            type_name: "int".to_string(),
            expr: Expr::new(
                ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier("a")), right: Box::new(Expr::identifier("b")) },
                span::Span::default(),
            ),
        };
        let value = session.evaluate_update_with_shadow_vm("f", &update, &HashMap::new()).unwrap();
        assert!(matches!(value, DebugValue::Int(12)));
    }

    #[test]
    fn list_variables_returns_unknown_for_uncompilable_expr() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() }],
            vec![DebugStep {
                bytecode_start: 0,
                bytecode_end: 0,
                span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                kind: StepKind::Source {},
                sequence: 0,
                call_depth: 0,
                frame_id: 0,
                variable_updates: vec![DebugVariableUpdate {
                    name: "x".to_string(),
                    type_name: "int".to_string(),
                    expr: Expr::identifier("missing"),
                }],
            }],
            &sigscript,
        )
        .unwrap();

        session.executed_steps.insert(StepId { sequence: 0, frame_id: 0 });
        // In sequence-only mode, query visibility at an explicit sequence that
        // is after the update's sequence.
        let vars = session.list_variables_at_sequence(1, 0).unwrap();
        let x = vars.into_iter().find(|var| var.name == "x").expect("x variable");
        assert!(matches!(x.value, DebugValue::Unknown(_)));
    }

    #[test]
    fn list_variables_hides_inline_synthetics_but_uses_them_for_shadow_eval() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() }],
            vec![DebugStep {
                bytecode_start: 0,
                bytecode_end: 0,
                span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                kind: StepKind::Source {},
                sequence: 0,
                call_depth: 0,
                frame_id: 0,
                variable_updates: vec![
                    DebugVariableUpdate { name: "__arg_f_0".to_string(), type_name: "int".to_string(), expr: Expr::identifier("a") },
                    DebugVariableUpdate {
                        name: "x".to_string(),
                        type_name: "int".to_string(),
                        expr: Expr::new(
                            ExprKind::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(Expr::identifier("__arg_f_0")),
                                right: Box::new(Expr::int(1)),
                            },
                            span::Span::default(),
                        ),
                    },
                ],
            }],
            &sigscript,
        )
        .unwrap();

        session.executed_steps.insert(StepId { sequence: 0, frame_id: 0 });
        let vars = session.list_variables_at_sequence(1, 0).unwrap();

        assert!(!vars.iter().any(|var| var.name.starts_with("__arg_")));
        let x = vars.into_iter().find(|var| var.name == "x").expect("x variable");
        assert!(matches!(x.value, DebugValue::Int(6)));
    }

    #[test]
    fn shadow_eval_resolves_nested_inline_synthetic_chain() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() }],
            vec![DebugStep {
                bytecode_start: 0,
                bytecode_end: 0,
                span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                kind: StepKind::Source {},
                sequence: 0,
                call_depth: 0,
                frame_id: 0,
                variable_updates: vec![
                    DebugVariableUpdate {
                        name: "__arg_outer_0".to_string(),
                        type_name: "int".to_string(),
                        expr: Expr::identifier("a"),
                    },
                    DebugVariableUpdate {
                        name: "__arg_inner_0".to_string(),
                        type_name: "int".to_string(),
                        expr: Expr::identifier("__arg_outer_0"),
                    },
                    DebugVariableUpdate {
                        name: "x".to_string(),
                        type_name: "int".to_string(),
                        expr: Expr::new(
                            ExprKind::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(Expr::identifier("__arg_inner_0")),
                                right: Box::new(Expr::int(1)),
                            },
                            span::Span::default(),
                        ),
                    },
                ],
            }],
            &sigscript,
        )
        .unwrap();

        session.executed_steps.insert(StepId { sequence: 0, frame_id: 0 });
        let vars = session.list_variables_at_sequence(1, 0).unwrap();

        assert!(!vars.iter().any(|var| var.name.starts_with("__arg_")));
        let x = vars.into_iter().find(|var| var.name == "x").expect("x variable");
        assert!(matches!(x.value, DebugValue::Int(6)));
    }
}
