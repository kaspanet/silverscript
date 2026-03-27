use std::collections::{HashMap, HashSet};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{PopulatedTransaction, TransactionInput, UtxoEntry};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{DynOpcodeImplementation, EngineCtx, EngineFlags, TxScriptEngine, parse_script};
use serde::{Deserialize, Serialize};

use silverscript_lang::ast::{
    ContractAst, Expr, ExprKind, StateFieldExpr, TypeBase, TypeRef, UnarySuffixKind, parse_contract_ast, parse_expression_ast,
    parse_type_ref,
};
use silverscript_lang::compiler::{
    CovenantDeclBinding, CovenantDeclInfo, ResolvedCovenantCallTarget, compile_debug_expr, flattened_struct_name,
};
use silverscript_lang::debug_info::{
    DebugFunctionRange, DebugInfo, DebugLeafBinding, DebugNamedValue, DebugParamBinding, DebugStep, DebugVariableUpdate,
    RuntimeBinding, SourceSpan, StepId, StepKind,
};
use silverscript_lang::span;

pub use crate::presentation::{SourceContext, SourceContextLine};
use crate::presentation::{build_source_context, format_value as format_debug_value};
use crate::util::{decode_i64, encode_hex, fixed_array_element_size};

pub type DebugTx<'a> = PopulatedTransaction<'a>;
pub type DebugReused = SigHashReusedValuesUnsync;
pub type DebugOpcode<'a> = DynOpcodeImplementation<DebugTx<'a>, DebugReused>;
pub type DebugEngine<'a> = TxScriptEngine<'a, DebugTx<'a>, DebugReused>;

#[derive(Clone)]
pub struct ShadowTxContext<'a> {
    pub tx: &'a DebugTx<'a>,
    pub input: &'a TransactionInput,
    pub input_index: usize,
    pub utxo_entry: &'a UtxoEntry,
}

#[derive(Debug, Clone)]
pub enum DebugValue {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<DebugValue>),
    Object(Vec<(String, DebugValue)>),
    /// Value could not be evaluated (for example unresolved identifiers or shadow VM failures).
    Unknown(std::string::String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableOrigin {
    Local,
    Param,
    ContractField,
    ConstructorArg,
    Constant,
}

impl VariableOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Param => "arg",
            Self::ContractField => "state",
            Self::ConstructorArg => "ctor",
            Self::Constant => "const",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    pub value: DebugValue,
    pub origin: VariableOrigin,
}

#[derive(Debug, Clone)]
pub struct SessionState<'i> {
    pub pc: usize,
    pub opcode: Option<String>,
    pub step: Option<DebugStep<'i>>,
    pub stack: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CallStackEntry {
    pub callee_name: String,
    pub call_site_span: Option<SourceSpan>,
    /// Sequence of the InlineCallEnter step (caller's context).
    pub sequence: u32,
    /// Frame ID of the InlineCallEnter step (caller's frame).
    pub frame_id: u32,
}

#[derive(Debug, Clone)]
pub struct FailureFrame {
    pub function_name: String,
    /// Source location: failure site for innermost frame, call-site for callers.
    pub span: Option<SourceSpan>,
    pub variables: Vec<Variable>,
}

#[derive(Debug, Clone)]
pub struct FailureReport {
    /// Human-readable description, e.g. "require() failed".
    pub message: String,
    /// Innermost frame first.
    pub frames: Vec<FailureFrame>,
    /// Full source text for rendering context lines.
    pub source_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSnapshot {
    pub dstack: Vec<String>,
    pub astack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeMeta<'i> {
    pub index: usize,
    pub byte_offset: usize,
    pub display: String,
    pub step: Option<DebugStep<'i>>,
}

#[derive(Clone)]
struct CovenantSessionContext {
    bindings: Vec<CovenantDeclInfo>,
}

impl CovenantSessionContext {
    fn binding_for_function(&self, function_name: &str) -> Option<&CovenantDeclInfo> {
        self.bindings.iter().find(|binding| binding.matches_generated_name(function_name))
    }

    fn display_name_for_function(&self, function_name: &str) -> Option<String> {
        self.binding_for_function(function_name).and_then(|binding| binding.display_name_for_function(function_name))
    }

    fn hides_name(&self, name: &str) -> bool {
        name.starts_with("__cov_") || name.starts_with("__covenant_policy_")
    }
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
    contract_ast: Option<ContractAst<'i>>,
    covenant_ctx: Option<CovenantSessionContext>,
    covenant_param_value: Option<DebugValue>,
    active_covenant_policy_name: Option<String>,
    active_covenant_display_name: Option<String>,
    step_order: Vec<usize>,
    current_step_index: Option<usize>,
    source_lines: Vec<String>,
    breakpoints: HashSet<u32>,
    // Source-level step ids that were already visited in this session.
    executed_steps: HashSet<StepId>,
    inline_scope_snapshots: HashMap<u32, HashMap<String, Variable>>,
    console_output: Vec<String>,
}

struct ShadowBindingValue {
    name: String,
    stack_index: i64,
    value: Vec<u8>,
}

struct VariableContext {
    function_name: String,
    function_start: usize,
    function_end: usize,
    step_id: StepId,
}

struct VisibleScope<'a, 'i> {
    context: VariableContext,
    updates: HashMap<String, &'a DebugVariableUpdate<'i>>,
}

#[derive(Clone)]
enum ScopeValueSource<'i> {
    RuntimeSlot { from_top: i64 },
    StructuredBinding { base_name: String, leaf_bindings: Vec<DebugLeafBinding> },
    Expr(Expr<'i>),
    Unavailable { message: String },
}

struct ScopeBinding<'i> {
    type_name: String,
    source: ScopeValueSource<'i>,
    origin: VariableOrigin,
    hidden: bool,
}

type ScopeState<'i> = HashMap<String, ScopeBinding<'i>>;
type ShadowBindings = Vec<ShadowBindingValue>;
type EvalEnv<'i> = HashMap<String, Expr<'i>>;
type StackBindings = HashMap<String, i64>;
type EvalTypes = HashMap<String, String>;
type ShadowResolution<'i> = (ShadowBindings, EvalEnv<'i>, StackBindings, EvalTypes);

impl<'a, 'i> DebugSession<'a, 'i> {
    // --- Session construction + stepping ---

    /// Creates a debug session simulating a full transaction spend.
    /// Executes sigscript first to seed the stack, then debugs lockscript execution.
    pub fn full(
        sigscript: &[u8],
        lockscript: &[u8],
        source: &'i str,
        debug_info: Option<DebugInfo<'i>>,
        mut engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        seed_engine_with_sigscript(&mut engine, sigscript)?;
        Self::from_scripts(lockscript, source, debug_info, engine)
    }

    /// Internal constructor: parses script, prepares opcodes, extracts statement steps.
    pub fn from_scripts(
        script: &[u8],
        source: &'i str,
        debug_info: Option<DebugInfo<'i>>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        let debug_info = debug_info.unwrap_or_else(DebugInfo::empty);
        let contract_ast = parse_contract_ast(source).ok();
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
            contract_ast,
            covenant_ctx: None,
            covenant_param_value: None,
            active_covenant_policy_name: None,
            active_covenant_display_name: None,
            step_order,
            current_step_index: None,
            source_lines,
            breakpoints: HashSet::new(),
            executed_steps: HashSet::new(),
            inline_scope_snapshots: HashMap::new(),
            console_output: Vec::new(),
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

    pub fn with_covenant_mode(
        mut self,
        infos: Vec<CovenantDeclInfo>,
        param_value: Option<DebugValue>,
        active_call: Option<ResolvedCovenantCallTarget>,
    ) -> Self {
        self.covenant_ctx = (!infos.is_empty()).then_some(CovenantSessionContext { bindings: infos });
        self.covenant_param_value = param_value;
        self.active_covenant_policy_name = active_call.as_ref().map(|call| call.info.lowered.policy_function.clone());
        self.active_covenant_display_name = active_call.as_ref().map(display_name_for_active_covenant_call);
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

    pub fn run_to_completion(&mut self) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        while self.step_into()?.is_some() {}
        Ok(())
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
                self.run_until_end()?;
                return Ok(None);
            };

            if self.advance_to_step(target_index)? {
                self.mark_step_executed(target_index);
                return Ok(Some(self.state()));
            }

            search_from = Some(target_index);
        }
    }

    fn run_until_end(&mut self) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        while self.step_opcode()?.is_some() {}
        Ok(())
    }

    fn advance_to_step(&mut self, target_index: usize) -> Result<bool, kaspa_txscript_errors::TxScriptError> {
        let Some(target) = self.step_at_order(target_index) else {
            return Ok(false);
        };
        let (target_start, target_end) = (target.bytecode_start, target.bytecode_end);
        loop {
            let offset = self.current_byte_offset();

            if range_matches_offset(target_start, target_end, offset) && self.engine.is_executing() {
                return Ok(true);
            }

            if offset > target_start {
                return Ok(false);
            }

            if self.step_opcode()?.is_none() {
                return Ok(false);
            }
        }
    }

    /// Advances execution to the first user statement, skipping dispatcher/synthetic bytecode.
    /// Call this after session creation to skip over contract setup code.
    /// Skips opcodes until the first real source step is encountered.
    pub fn run_to_first_executed_statement(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        if self.step_order.is_empty() {
            return Ok(None);
        }
        loop {
            if self.pc >= self.opcodes.len() {
                return Ok(None);
            }
            let offset = self.current_byte_offset();
            if self.engine.is_executing() {
                if let Some(index) = self.initial_step_index_for_offset(offset, None) {
                    self.mark_step_executed(index);
                    return Ok(Some(self.state()));
                }
            }
            if self.step_opcode()?.is_none() {
                return Ok(None);
            }
        }
    }

    /// Continues execution until a breakpoint is hit or script completes.
    pub fn continue_to_breakpoint(&mut self) -> Result<Option<SessionState<'i>>, kaspa_txscript_errors::TxScriptError> {
        if self.breakpoints.is_empty() {
            self.run_to_completion()?;
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

    pub fn take_console_output(&mut self) -> Vec<String> {
        std::mem::take(&mut self.console_output)
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

    /// Resolves a requested source line to a steppable line, preferring exact
    /// hits then the next steppable line.
    pub fn resolve_breakpoint_line(&self, line: u32) -> Option<u32> {
        let mut next: Option<u32> = None;
        for step in self.step_order.iter().filter_map(|&index| self.debug_info.steps.get(index)) {
            if !self.is_steppable_step(step) {
                continue;
            }
            if line >= step.span.line && line <= step.span.end_line {
                return Some(line);
            }
            if step.span.line > line {
                match next {
                    Some(current) if current <= step.span.line => {}
                    _ => next = Some(step.span.line),
                }
            }
        }
        next
    }

    /// Resolves and adds a breakpoint. Returns the actual line if set.
    pub fn add_breakpoint_resolved(&mut self, line: u32) -> Option<u32> {
        let resolved = self.resolve_breakpoint_line(line)?;
        self.breakpoints.insert(resolved);
        Some(resolved)
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
    /// Includes locals, params, constructor args, and contract constants.
    pub fn list_variables(&self) -> Result<Vec<Variable>, String> {
        self.collect_variables(self.current_scope_step_id())
    }

    pub fn list_variables_at_sequence(&self, sequence: u32, frame_id: u32) -> Result<Vec<Variable>, String> {
        self.collect_variables(StepId::new(sequence, frame_id))
    }

    fn collect_variables(&self, step_id: StepId) -> Result<Vec<Variable>, String> {
        let scope_state = self.scope_state(step_id)?;
        let mut variables = self.collect_variables_map(&scope_state).into_values().collect::<Vec<_>>();
        variables.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(variables)
    }

    /// Returns a specific variable by name, or error if not in scope.
    pub fn variable_by_name(&self, name: &str) -> Result<Variable, String> {
        let scope_state = self.current_scope_state()?;
        let binding = scope_state.get(name).ok_or_else(|| format!("unknown variable '{name}'"))?;
        let value = self.resolve_scope_binding(&scope_state, binding).unwrap_or_else(DebugValue::Unknown);
        Ok(Variable { name: name.to_string(), type_name: binding.type_name.clone(), value, origin: binding.origin })
    }

    pub fn evaluate_expression(&self, expr_src: &str) -> Result<(String, DebugValue), String> {
        let expr = parse_expression_ast(expr_src).map_err(|err| format!("parse error: {err}"))?;
        self.evaluate_parsed_expression(&expr)
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
        for step in self.active_steps() {
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

    /// Returns the active inline call stack with source spans and frame identity.
    pub fn call_stack_with_spans(&self) -> Vec<CallStackEntry> {
        let mut stack = Vec::new();
        for step in self.active_steps() {
            match &step.kind {
                StepKind::InlineCallEnter { callee } => stack.push(CallStackEntry {
                    callee_name: self.display_function_name(callee),
                    call_site_span: Some(step.span),
                    sequence: step.sequence,
                    frame_id: step.frame_id,
                }),
                StepKind::InlineCallExit { .. } => {
                    stack.pop();
                }
                _ => {}
            }
        }
        stack
    }

    /// Returns the name of the function currently being executed.
    pub fn current_function_name(&self) -> Option<String> {
        self.current_compiled_function_name().map(|function_name| self.display_function_name(&function_name))
    }

    fn current_compiled_function_name(&self) -> Option<String> {
        self.compiled_function_name_for_step(self.current_scope_step_id())
    }

    fn function_range_for_step(&self, step_id: StepId) -> Option<&DebugFunctionRange> {
        let offset = self
            .debug_info
            .steps
            .iter()
            .find(|step| step.id() == step_id)
            .map(|step| step.bytecode_start)
            .unwrap_or_else(|| self.current_byte_offset());
        self.debug_info.functions.iter().find(|function| range_matches_offset(function.bytecode_start, function.bytecode_end, offset))
    }

    fn compiled_function_name_for_step(&self, step_id: StepId) -> Option<String> {
        let entrypoint = self.function_range_for_step(step_id)?;
        if step_id.frame_id == 0 {
            return Some(entrypoint.name.clone());
        }

        let mut active_calls = Vec::new();
        let mut steps = self
            .debug_info
            .steps
            .iter()
            .filter(|step| {
                step.sequence <= step_id.sequence
                    && range_matches_offset(entrypoint.bytecode_start, entrypoint.bytecode_end, step.bytecode_start)
            })
            .collect::<Vec<_>>();
        steps.sort_by_key(|step| step.sequence);

        for step in steps {
            match &step.kind {
                StepKind::InlineCallEnter { callee } => active_calls.push((step.frame_id, callee.clone())),
                StepKind::InlineCallExit { .. } => {
                    active_calls.pop();
                }
                StepKind::Source {} => {}
            }
        }

        active_calls
            .into_iter()
            .rev()
            .find_map(|(frame_id, callee)| (frame_id == step_id.frame_id).then_some(callee))
            .or_else(|| Some(entrypoint.name.clone()))
    }

    fn covenant_ctx(&self) -> Option<&CovenantSessionContext> {
        self.covenant_ctx.as_ref()
    }

    fn param_origin(&self, name: &str) -> VariableOrigin {
        if self.contract_ast.as_ref().is_some_and(|contract| contract.fields.iter().any(|field| field.name == name)) {
            VariableOrigin::ContractField
        } else {
            VariableOrigin::Param
        }
    }

    fn display_function_name(&self, function_name: &str) -> String {
        if self.active_covenant_policy_name.as_deref() == Some(function_name) {
            if let Some(name) = &self.active_covenant_display_name {
                return name.clone();
            }
        }
        self.covenant_ctx().and_then(|ctx| ctx.display_name_for_function(function_name)).unwrap_or_else(|| function_name.to_string())
    }

    fn is_hidden_debug_name(&self, name: &str) -> bool {
        is_inline_synthetic_name(name) || self.covenant_ctx().is_some_and(|ctx| ctx.hides_name(name))
    }

    fn current_variable_updates(&self, context: &VariableContext) -> HashMap<String, &DebugVariableUpdate<'i>> {
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

    fn current_variable_context(&self, step_id: StepId) -> Result<VariableContext, String> {
        let function = self.function_range_for_step(step_id).ok_or_else(|| "No function context available".to_string())?;
        let function_name =
            self.compiled_function_name_for_step(step_id).ok_or_else(|| "No function context available".to_string())?;
        Ok(VariableContext { function_name, function_start: function.bytecode_start, function_end: function.bytecode_end, step_id })
    }

    fn scope_state(&self, step_id: StepId) -> Result<ScopeState<'i>, String> {
        let context = self.current_variable_context(step_id)?;
        let scope = VisibleScope { updates: self.current_variable_updates(&context), context };
        Ok(self.scope_state_from_visible(&scope))
    }

    fn scope_state_from_visible(&self, scope: &VisibleScope<'_, 'i>) -> ScopeState<'i> {
        let mut bindings = HashMap::new();
        let function_params: Vec<_> =
            self.debug_info.params.iter().filter(|param| param.function == scope.context.function_name).collect();

        for param in function_params {
            let origin = self.param_origin(&param.name);
            match &param.binding {
                DebugParamBinding::SingleValue { stack_index } => {
                    bindings.entry(param.name.clone()).or_insert_with(|| ScopeBinding {
                        type_name: param.type_name.clone(),
                        source: ScopeValueSource::RuntimeSlot { from_top: *stack_index },
                        origin,
                        hidden: false,
                    });
                }
                DebugParamBinding::StructuredValue { leaf_bindings } => {
                    let leaf_bindings = leaf_bindings.clone();
                    bindings.entry(param.name.clone()).or_insert_with(|| ScopeBinding {
                        type_name: param.type_name.clone(),
                        source: ScopeValueSource::StructuredBinding {
                            base_name: param.name.clone(),
                            leaf_bindings: leaf_bindings
                                .iter()
                                .map(|leaf| DebugLeafBinding {
                                    field_path: leaf.field_path.clone(),
                                    type_name: leaf.type_name.clone(),
                                    stack_index: None,
                                })
                                .collect(),
                        },
                        origin,
                        hidden: false,
                    });
                    for leaf in &leaf_bindings {
                        let leaf_name = flattened_struct_name(&param.name, &leaf.field_path);
                        if let Some(stack_index) = leaf.stack_index {
                            bindings.entry(leaf_name).or_insert_with(|| ScopeBinding {
                                type_name: leaf.type_name.clone(),
                                source: ScopeValueSource::RuntimeSlot { from_top: stack_index },
                                origin,
                                hidden: true,
                            });
                        }
                    }
                }
            }
        }

        record_debug_named_values(&mut bindings, &self.debug_info.constructor_args, VariableOrigin::ConstructorArg);
        record_debug_named_values(&mut bindings, &self.debug_info.constants, VariableOrigin::Constant);

        let frozen_inline_names = if scope.context.step_id.frame_id == 0 {
            HashSet::new()
        } else {
            self.freeze_inline_snapshot_bindings(&mut bindings, scope.context.step_id.frame_id)
        };

        for (name, update) in &scope.updates {
            if frozen_inline_names.contains(name) {
                continue;
            }
            let source = match (&update.structured_leaf_bindings, update.runtime_binding.as_ref()) {
                (Some(leaf_bindings), _) => {
                    ScopeValueSource::StructuredBinding { base_name: name.clone(), leaf_bindings: leaf_bindings.clone() }
                }
                (None, Some(_))
                    if is_inline_synthetic_name(name)
                        && matches!(&update.expr.kind, ExprKind::Identifier(identifier) if frozen_inline_names.contains(identifier)) =>
                {
                    ScopeValueSource::Expr(update.expr.clone())
                }
                (None, Some(RuntimeBinding::DataStackSlot { from_top })) => ScopeValueSource::RuntimeSlot { from_top: *from_top },
                (None, None) => ScopeValueSource::Expr(update.expr.clone()),
            };
            bindings
                .entry(name.clone())
                .and_modify(|binding| {
                    binding.type_name = update.type_name.clone();
                    binding.source = source.clone();
                    binding.hidden = self.is_hidden_debug_name(name);
                })
                .or_insert_with(|| ScopeBinding {
                    type_name: update.type_name.clone(),
                    source,
                    origin: VariableOrigin::Local,
                    hidden: self.is_hidden_debug_name(name),
                });
        }

        self.inject_covenant_overlay_bindings(scope, &mut bindings);
        bindings
    }

    fn inject_covenant_overlay_bindings(&self, scope: &VisibleScope<'_, 'i>, bindings: &mut ScopeState<'i>) {
        let Some(binding_spec) = self.covenant_ctx().and_then(|ctx| ctx.binding_for_function(&scope.context.function_name)) else {
            return;
        };
        let state_param_type = match parse_type_ref(&binding_spec.source_binding.param_type_name) {
            Ok(type_ref) => type_ref,
            Err(_) => {
                bindings.insert(
                    binding_spec.source_binding.param_name.clone(),
                    ScopeBinding {
                        type_name: binding_spec.source_binding.param_type_name.clone(),
                        source: ScopeValueSource::Unavailable {
                            message: format!(
                                "failed to parse covenant state parameter type '{}'",
                                binding_spec.source_binding.param_type_name
                            ),
                        },
                        origin: VariableOrigin::Param,
                        hidden: false,
                    },
                );
                return;
            }
        };

        let injected = self.covenant_param_value.as_ref().and_then(|value| {
            self.inject_debug_value_binding(
                bindings,
                &binding_spec.source_binding.param_name,
                &state_param_type,
                value,
                VariableOrigin::Param,
            )
        });
        if injected.is_some() {
            return;
        }

        let message = match binding_spec.binding {
            CovenantDeclBinding::Auth => "prev_state is unavailable".to_string(),
            CovenantDeclBinding::Cov => "prev_states is unavailable".to_string(),
        };
        bindings.insert(
            binding_spec.source_binding.param_name.clone(),
            ScopeBinding {
                type_name: binding_spec.source_binding.param_type_name.clone(),
                source: ScopeValueSource::Unavailable { message },
                origin: VariableOrigin::Param,
                hidden: false,
            },
        );
    }

    fn inject_debug_value_binding(
        &self,
        bindings: &mut ScopeState<'i>,
        name: &str,
        type_ref: &TypeRef,
        value: &DebugValue,
        origin: VariableOrigin,
    ) -> Option<()> {
        let type_name = type_ref.type_name();
        let leaf_specs = flatten_contract_type_leaves(self.contract_ast.as_ref()?, type_ref).ok()?;
        if leaf_specs.is_empty() {
            let expr = debug_value_to_expr(value)?;
            bindings.insert(name.to_string(), ScopeBinding { type_name, source: ScopeValueSource::Expr(expr), origin, hidden: false });
            return Some(());
        }
        let leaf_bindings = leaf_specs
            .iter()
            .map(|(field_path, leaf_type)| DebugLeafBinding {
                field_path: field_path.clone(),
                type_name: leaf_type.type_name(),
                stack_index: None,
            })
            .collect::<Vec<_>>();

        bindings.insert(
            name.to_string(),
            ScopeBinding {
                type_name,
                source: ScopeValueSource::StructuredBinding { base_name: name.to_string(), leaf_bindings: leaf_bindings.clone() },
                origin,
                hidden: false,
            },
        );

        for (field_path, leaf_type) in leaf_specs {
            let leaf_value = structured_leaf_value(value, &field_path)?;
            let leaf_expr = debug_value_to_expr(&leaf_value)?;
            let leaf_name = flattened_struct_name(name, &field_path);
            bindings.insert(
                leaf_name,
                ScopeBinding { type_name: leaf_type.type_name(), source: ScopeValueSource::Expr(leaf_expr), origin, hidden: true },
            );
        }
        Some(())
    }

    fn freeze_inline_snapshot_bindings(&self, bindings: &mut ScopeState<'i>, frame_id: u32) -> HashSet<String> {
        let Some(parent_vars) = self.inline_scope_snapshots.get(&frame_id) else {
            return HashSet::new();
        };
        let mut frozen_names = HashSet::new();

        for (name, variable) in parent_vars {
            let Some(expr) = debug_value_to_expr(&variable.value) else {
                continue;
            };

            let structured_leaf_bindings = bindings.get(name.as_str()).and_then(|existing| match &existing.source {
                ScopeValueSource::StructuredBinding { leaf_bindings, .. } => Some(leaf_bindings.clone()),
                _ => None,
            });
            if let Some(leaf_bindings) = structured_leaf_bindings {
                frozen_names.insert(name.clone());
                for leaf in &leaf_bindings {
                    let Some(leaf_value) = structured_leaf_value(&variable.value, &leaf.field_path) else {
                        continue;
                    };
                    let Some(leaf_expr) = debug_value_to_expr(&leaf_value) else {
                        continue;
                    };
                    let leaf_name = flattened_struct_name(name, &leaf.field_path);
                    bindings.insert(
                        leaf_name.clone(),
                        ScopeBinding {
                            type_name: leaf.type_name.clone(),
                            source: ScopeValueSource::Expr(leaf_expr),
                            origin: variable.origin,
                            hidden: true,
                        },
                    );
                    frozen_names.insert(leaf_name);
                }
                continue;
            }

            if is_structured_type_name(&variable.type_name)
                && let Ok(type_ref) = parse_type_ref(&variable.type_name)
                && self.inject_debug_value_binding(bindings, name, &type_ref, &variable.value, variable.origin).is_some()
            {
                frozen_names.insert(name.clone());
                if let Some(contract) = self.contract_ast.as_ref()
                    && let Ok(leaf_specs) = flatten_contract_type_leaves(contract, &type_ref)
                {
                    for (field_path, _) in leaf_specs {
                        frozen_names.insert(flattened_struct_name(name, &field_path));
                    }
                }
                continue;
            }

            bindings.insert(
                name.clone(),
                ScopeBinding {
                    type_name: variable.type_name.clone(),
                    source: ScopeValueSource::Expr(expr),
                    origin: variable.origin,
                    hidden: false,
                },
            );
            frozen_names.insert(name.clone());
        }

        frozen_names
    }

    fn collect_variables_map(&self, scope_state: &ScopeState<'i>) -> HashMap<String, Variable> {
        let mut variables: HashMap<String, Variable> = HashMap::new();

        for (name, binding) in scope_state {
            if binding.hidden {
                continue;
            }
            let value = self.resolve_scope_binding(scope_state, binding).unwrap_or_else(DebugValue::Unknown);
            variables.insert(
                name.clone(),
                Variable { name: name.clone(), type_name: binding.type_name.clone(), value, origin: binding.origin },
            );
        }

        variables
    }

    fn step_updates_are_visible(&self, step: &DebugStep<'i>, context: &VariableContext) -> bool {
        if step.bytecode_start < context.function_start || step.bytecode_start >= context.function_end {
            return false;
        }
        // Stay in the active inline frame and only consider updates from
        // source steps that completed before the currently highlighted step.
        let step_id = step.id();
        step_id.frame_id == context.step_id.frame_id
            && self.executed_steps.contains(&step_id)
            && step_id.sequence < context.step_id.sequence
    }

    /// Returns the most specific step for `offset`.
    /// Multiple steps may overlap; choosing the narrowest bytecode span makes
    /// location lookups prefer inner statement/inline ranges over broader ranges.
    fn step_for_offset(&self, offset: usize) -> Option<&DebugStep<'i>> {
        let mut best: Option<&DebugStep<'i>> = None;
        let mut best_len = usize::MAX;
        for step in &self.debug_info.steps {
            if range_matches_offset(step.bytecode_start, step.bytecode_end, offset) {
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

    fn current_scope_step_id(&self) -> StepId {
        let Some(current_index) = self.current_step_index else {
            return self.current_timeline_step().map(DebugStep::id).unwrap_or(StepId::ROOT);
        };
        let Some(current_step) = self.current_timeline_step() else {
            return StepId::ROOT;
        };
        if !matches!(current_step.kind, StepKind::InlineCallEnter { .. }) {
            return current_step.id();
        }
        for index in (0..current_index).rev() {
            if let Some(step) = self.step_at_order(index) {
                return StepId::new(current_step.sequence, step.frame_id);
            }
        }
        current_step.id()
    }

    fn current_scope_state(&self) -> Result<ScopeState<'i>, String> {
        self.scope_state(self.current_scope_step_id())
    }

    fn active_steps(&self) -> impl Iterator<Item = &DebugStep<'i>> + '_ {
        let end = self.current_step_index.map(|index| index + 1).unwrap_or(0);
        self.step_order[..end].iter().filter_map(|&step_index| self.debug_info.steps.get(step_index))
    }

    fn mark_step_executed(&mut self, step_index: usize) {
        self.current_step_index = Some(step_index);
        if let Some(step) = self.step_at_order(step_index).cloned() {
            if !self.executed_steps.insert(step.id()) {
                return;
            }
            self.capture_inline_scope_snapshot(&step);
            self.render_console_messages(&step);
        }
    }

    fn capture_inline_scope_snapshot(&mut self, step: &DebugStep<'i>) {
        if !matches!(step.kind, StepKind::InlineCallEnter { .. }) || self.inline_scope_snapshots.contains_key(&step.frame_id) {
            return;
        }

        let step_id = self
            .current_step_index
            .map(|index| {
                let parent_frame_id = if index == 0 {
                    0
                } else {
                    self.step_at_order(index.saturating_sub(1)).map(|previous| previous.frame_id).unwrap_or(0)
                };
                StepId::new(step.sequence, parent_frame_id)
            })
            .unwrap_or_else(|| self.current_scope_step_id());
        let Ok(scope_state) = self.scope_state(step_id) else {
            return;
        };
        let snapshot = self
            .collect_variables_map(&scope_state)
            .into_iter()
            .filter(|(_, variable)| matches!(variable.origin, VariableOrigin::Param | VariableOrigin::ContractField))
            .collect();
        self.inline_scope_snapshots.insert(step.frame_id, snapshot);
    }

    fn render_console_messages(&mut self, step: &DebugStep<'i>) {
        if step.console_args.is_empty() {
            return;
        }

        self.console_output.push(
            step.console_args
                .iter()
                .map(|expr| match self.evaluate_parsed_expression(expr) {
                    Ok((type_name, value)) => format_debug_value(&type_name, &value),
                    Err(err) => format_debug_value("", &DebugValue::Unknown(err)),
                })
                .collect::<Vec<_>>()
                .join(" "),
        );
    }

    fn sync_step_cursor_to_current_offset(&mut self) {
        let offset = self.current_byte_offset();
        let min_sequence = self.current_timeline_step().map(|step| step.sequence);
        if let Some(index) = self.steppable_step_index_for_offset(offset, min_sequence) {
            if self.current_step_index.is_some_and(|current| index < current) {
                // In sequence mode multiple steps may resolve to the same byte offset.
                // Keep cursor monotonic and avoid snapping backward to an earlier
                // step for that offset.
                return;
            }
            if self
                .current_timeline_step()
                .is_some_and(|current| self.step_at_order(index).is_some_and(|candidate| candidate.sequence < current.sequence))
            {
                return;
            }
            // `si` executes raw opcodes; keep statement cursor in sync so later
            // source-level steps (`next`/`step`/`finish`) start from the real
            // current step instead of an old one.
            self.mark_step_executed(index);
        }
    }

    fn is_steppable_step(&self, step: &DebugStep<'i>) -> bool {
        // InlineCallEnter is steppable so `step_into` can land on a call
        // boundary and build call-stack transitions. InlineCallExit is not
        // steppable to avoid synthetic extra stops while unwinding.
        match &step.kind {
            StepKind::Source {} => !is_synthetic_default_span(step.span),
            StepKind::InlineCallEnter { .. } => true,
            StepKind::InlineCallExit { .. } => false,
        }
    }

    fn steppable_step_index_for_offset(&self, offset: usize, min_sequence: Option<u32>) -> Option<usize> {
        if let Some(index) = self.current_step_index {
            if let Some(step) = self.step_at_order(index) {
                if !self.is_post_inline_call_source(step) {
                    if let Some(boundary_index) = self.find_steppable_step_index(|candidate| {
                        candidate.bytecode_start == offset
                            && step.bytecode_end == offset
                            && min_sequence.is_none_or(|min_sequence| candidate.sequence >= min_sequence)
                    }) {
                        return Some(boundary_index);
                    }
                }
            }
        }

        self.find_steppable_step_index(|step| {
            range_matches_offset(step.bytecode_start, step.bytecode_end, offset)
                && min_sequence.is_none_or(|min_sequence| step.sequence >= min_sequence)
        })
    }

    fn initial_step_index_for_offset(&self, offset: usize, min_sequence: Option<u32>) -> Option<usize> {
        let mut best: Option<(usize, u32, u32)> = None;
        for (order_index, &step_index) in self.step_order.iter().enumerate() {
            let Some(step) = self.debug_info.steps.get(step_index) else {
                continue;
            };
            if !self.is_steppable_step(step)
                || is_synthetic_default_span(step.span)
                || !range_matches_offset(step.bytecode_start, step.bytecode_end, offset)
                || min_sequence.is_some_and(|min_sequence| step.sequence < min_sequence)
            {
                continue;
            }

            match best {
                Some((_, best_depth, best_sequence)) if (best_depth, best_sequence) <= (step.call_depth, step.sequence) => {}
                _ => best = Some((order_index, step.call_depth, step.sequence)),
            }
        }
        best.map(|(order_index, _, _)| order_index)
    }

    fn find_steppable_step_index(&self, predicate: impl Fn(&DebugStep<'i>) -> bool) -> Option<usize> {
        self.step_order.iter().enumerate().find_map(|(order_index, &step_index)| {
            let step = self.debug_info.steps.get(step_index)?;
            (self.is_steppable_step(step) && predicate(step)).then_some(order_index)
        })
    }

    fn next_steppable_step_index(&self, from: Option<usize>, predicate: impl Fn(&DebugStep<'i>) -> bool) -> Option<usize> {
        let start = from.map(|index| index.saturating_add(1)).unwrap_or(0);
        let min_sequence = from.and_then(|index| self.step_at_order(index).map(|step| step.sequence));
        if let Some(index) = from {
            if let Some(step) = self.step_at_order(index) {
                if step.call_depth > 0 {
                    if let Some(index) = self.find_post_inline_source_after(step, min_sequence, true, &predicate) {
                        return Some(index);
                    }
                }

                if !self.is_post_inline_call_source(step) {
                    for index in start..self.step_order.len() {
                        let step = self.step_at_order(index)?;
                        if !self.is_steppable_step(step) {
                            continue;
                        }
                        if min_sequence.is_some_and(|min_sequence| step.sequence < min_sequence) {
                            continue;
                        }
                        if step.bytecode_start == self.step_at_order(from?)?.bytecode_end && predicate(step) {
                            return Some(index);
                        }
                    }
                }

                if let Some(index) = self.find_post_inline_source_after(step, min_sequence, false, &predicate) {
                    return Some(index);
                }
            }
        }
        for index in start..self.step_order.len() {
            let step = self.step_at_order(index)?;
            if !self.is_steppable_step(step) {
                continue;
            }
            if min_sequence.is_some_and(|min_sequence| step.sequence < min_sequence) {
                continue;
            }
            if predicate(step) {
                return Some(index);
            }
        }
        None
    }

    fn is_post_inline_call_source(&self, step: &DebugStep<'i>) -> bool {
        matches!(step.kind, StepKind::Source {})
            && self.debug_info.steps.iter().any(|previous| {
                previous.sequence.saturating_add(1) == step.sequence && matches!(previous.kind, StepKind::InlineCallExit { .. })
            })
    }

    fn find_post_inline_source_after(
        &self,
        current: &DebugStep<'i>,
        min_sequence: Option<u32>,
        require_same_end: bool,
        predicate: &impl Fn(&DebugStep<'i>) -> bool,
    ) -> Option<usize> {
        let mut best_post_inline: Option<(usize, usize)> = None;
        for index in 0..self.step_order.len() {
            let candidate = self.step_at_order(index)?;
            if !self.is_steppable_step(candidate) || !self.is_post_inline_call_source(candidate) {
                continue;
            }
            if candidate.sequence <= current.sequence {
                continue;
            }
            if min_sequence.is_some_and(|min_sequence| candidate.sequence < min_sequence) {
                continue;
            }
            if !predicate(candidate) {
                continue;
            }
            if candidate.bytecode_start > current.bytecode_start || candidate.bytecode_end < current.bytecode_end {
                continue;
            }
            if require_same_end && candidate.bytecode_end != current.bytecode_end {
                continue;
            }

            let candidate_len = candidate.bytecode_end.saturating_sub(candidate.bytecode_start);
            match best_post_inline {
                Some((_, best_len)) if best_len <= candidate_len => {}
                _ => best_post_inline = Some((index, candidate_len)),
            }
        }
        best_post_inline.map(|(index, _)| index)
    }

    fn step_hits_breakpoint(&self, step: &DebugStep<'i>) -> bool {
        matches!(step.kind, StepKind::Source {})
            && !is_synthetic_default_span(step.span)
            && (step.span.line..=step.span.end_line).any(|line| self.breakpoints.contains(&line))
    }

    /// Returns the current main stack as hex-encoded strings.
    pub fn stack(&self) -> Vec<String> {
        let stacks = self.engine.stacks();
        stacks.dstack.iter().map(|item| encode_hex(item)).collect()
    }

    /// Returns both main and alt stacks as hex strings.
    pub fn stack_snapshot(&self) -> StackSnapshot {
        let stacks = self.engine.stacks();
        StackSnapshot {
            dstack: stacks.dstack.iter().map(|item| encode_hex(item)).collect(),
            astack: stacks.astack.iter().map(|item| encode_hex(item)).collect(),
        }
    }

    /// Returns bytecode/opcode metadata aligned with source steps.
    pub fn opcode_metas(&self) -> Vec<OpcodeMeta<'i>> {
        self.op_displays
            .iter()
            .enumerate()
            .map(|(index, display)| OpcodeMeta {
                index,
                byte_offset: self.opcode_offsets.get(index).copied().unwrap_or(self.script_len),
                display: display.clone(),
                step: self.step_for_offset(self.opcode_offsets.get(index).copied().unwrap_or(self.script_len)).cloned(),
            })
            .collect()
    }

    /// Builds a structured failure report suitable for CLI/DAP rendering.
    pub fn build_failure_report(&self, error: &kaspa_txscript_errors::TxScriptError) -> FailureReport {
        let failure_span = self.current_span();
        let call_stack = self.call_stack_with_spans();
        let innermost_function = self.current_function_name().unwrap_or_else(|| "<unknown>".to_string());
        let innermost_vars: Vec<Variable> =
            self.list_variables().unwrap_or_default().into_iter().filter(|v| v.origin != VariableOrigin::Constant).collect();

        let mut frames =
            vec![FailureFrame { function_name: innermost_function.clone(), span: failure_span, variables: innermost_vars }];

        let entry_name = self.current_function_name().unwrap_or_else(|| "<entry>".to_string());
        for idx in (0..call_stack.len()).rev() {
            let entry = &call_stack[idx];
            let caller_vars: Vec<Variable> = self
                .list_variables_at_sequence(entry.sequence, entry.frame_id)
                .unwrap_or_default()
                .into_iter()
                .filter(|v| v.origin != VariableOrigin::Constant)
                .collect();
            let caller_name = if idx == 0 { entry_name.clone() } else { call_stack[idx - 1].callee_name.clone() };
            frames.push(FailureFrame { function_name: caller_name, span: entry.call_site_span, variables: caller_vars });
        }

        FailureReport { message: format!("{error}"), frames, source_text: self.source_lines.join("\n") }
    }

    fn resolve_scope_binding(&self, scope_state: &ScopeState<'i>, binding: &ScopeBinding<'i>) -> Result<DebugValue, String> {
        let mut visiting = HashSet::new();
        if let Some(value) = self.try_resolve_binding_value(scope_state, binding, &mut visiting) {
            return Ok(value);
        }
        match &binding.source {
            ScopeValueSource::RuntimeSlot { from_top } => self.read_stack_value(*from_top, &binding.type_name),
            ScopeValueSource::StructuredBinding { base_name, leaf_bindings } => {
                self.read_structured_binding_value(scope_state, base_name, &binding.type_name, leaf_bindings)
            }
            ScopeValueSource::Expr(expr) => self.evaluate_scope_expr_as(scope_state, expr, &binding.type_name),
            ScopeValueSource::Unavailable { message } => Err(message.clone()),
        }
    }

    fn evaluate_scope_expr_as(&self, scope_state: &ScopeState<'i>, expr: &Expr<'i>, type_name: &str) -> Result<DebugValue, String> {
        let (shadow_bindings, env, stack_bindings, eval_types) = self.scope_state_eval_context(scope_state)?;
        if is_structured_type_name(type_name) {
            return self
                .try_resolve_expr_value(scope_state, expr, &mut HashSet::new())
                .ok_or_else(|| format!("failed to resolve structured expression of type '{type_name}'"));
        }
        let prepared_expr = lower_expr_for_eval(expr, scope_state)?;
        let (bytecode, _) = compile_debug_expr(&prepared_expr, &env, &stack_bindings, &eval_types)
            .map_err(|err| format!("failed to compile debug expression: {err}"))?;
        let script = self.build_shadow_script(&shadow_bindings, &bytecode)?;
        let bytes = self.execute_shadow_script(&script)?;
        decode_value_by_type(type_name, bytes)
    }

    fn evaluate_parsed_expression(&self, expr: &Expr<'i>) -> Result<(String, DebugValue), String> {
        let scope_state = self.current_scope_state()?;
        self.evaluate_expr_in_scope(&scope_state, expr)
    }

    fn evaluate_expr_in_scope(&self, scope_state: &ScopeState<'i>, expr: &Expr<'i>) -> Result<(String, DebugValue), String> {
        let (shadow_bindings, env, stack_bindings, eval_types) = self.scope_state_eval_context(scope_state)?;
        if let Some(type_name) = direct_expr_type_name(scope_state, expr).filter(|type_name| is_structured_type_name(type_name)) {
            let value = self
                .try_resolve_expr_value(scope_state, expr, &mut HashSet::new())
                .ok_or_else(|| format!("failed to resolve structured expression of type '{type_name}'"))?;
            return Ok((type_name, value));
        }
        let prepared_expr = lower_expr_for_eval(expr, scope_state)?;
        let (bytecode, type_name) = compile_debug_expr(&prepared_expr, &env, &stack_bindings, &eval_types)
            .map_err(|err| format!("failed to compile debug expression: {err}"))?;
        let script = self.build_shadow_script(&shadow_bindings, &bytecode)?;
        let bytes = self.execute_shadow_script(&script)?;
        let value = decode_value_by_type(&type_name, bytes)?;
        Ok((type_name, value))
    }

    fn scope_state_eval_context(&self, scope_state: &ScopeState<'i>) -> Result<ShadowResolution<'i>, String> {
        let mut shadow_by_name = HashMap::new();
        let mut env = HashMap::new();
        let mut eval_types = HashMap::new();

        for (name, binding) in scope_state {
            eval_types.insert(name.clone(), binding.type_name.clone());
            match &binding.source {
                ScopeValueSource::RuntimeSlot { from_top } => {
                    shadow_by_name.insert(
                        name.clone(),
                        ShadowBindingValue { name: name.clone(), stack_index: *from_top, value: self.read_stack_at_index(*from_top)? },
                    );
                }
                ScopeValueSource::StructuredBinding { .. } | ScopeValueSource::Unavailable { .. } => {}
                ScopeValueSource::Expr(expr) => {
                    env.insert(name.clone(), expr.clone());
                }
            }
        }

        let mut shadow_bindings = shadow_by_name.into_values().collect::<Vec<_>>();
        shadow_bindings.sort_by(|left, right| right.stack_index.cmp(&left.stack_index));
        let binding_count = shadow_bindings.len();
        let stack_bindings = shadow_bindings
            .iter()
            .enumerate()
            .map(|(index, binding)| (binding.name.clone(), (binding_count - index - 1) as i64))
            .collect();
        Ok((shadow_bindings, env, stack_bindings, eval_types))
    }

    fn build_shadow_script(&self, bindings: &[ShadowBindingValue], expr_bytecode: &[u8]) -> Result<Vec<u8>, String> {
        let mut builder = ScriptBuilder::new();
        for binding in bindings {
            builder.add_data(&binding.value).map_err(|err| err.to_string())?;
        }
        builder.add_ops(expr_bytecode).map_err(|err| err.to_string())?;
        Ok(builder.drain())
    }

    fn execute_shadow_script(&self, script: &[u8]) -> Result<Vec<u8>, String> {
        let sig_cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        if let Some(shadow) = self.shadow_tx_context.as_ref() {
            let covenants_ctx = CovenantsContext::from_tx(shadow.tx)
                .map_err(|err| format!("failed to build covenants context for shadow evaluation: {err}"))?;
            let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&covenants_ctx);
            let mut engine = TxScriptEngine::from_transaction_input(
                shadow.tx,
                shadow.input,
                shadow.input_index,
                shadow.utxo_entry,
                ctx,
                EngineFlags { covenants_enabled: true },
            );
            for opcode in parse_script::<DebugTx<'_>, DebugReused>(script) {
                let opcode = opcode.map_err(|err| format!("failed to parse shadow script: {err}"))?;
                engine.execute_opcode(opcode).map_err(|err| format!("failed to execute shadow script: {err}"))?;
            }
            engine.stacks().dstack.last().cloned().ok_or_else(|| "shadow VM produced an empty stack".to_string())
        } else {
            let mut engine =
                TxScriptEngine::new(EngineCtx::new(&sig_cache).with_reused(&reused_values), EngineFlags { covenants_enabled: true });
            for opcode in parse_script::<DebugTx<'_>, DebugReused>(script) {
                let opcode = opcode.map_err(|err| format!("failed to parse shadow script: {err}"))?;
                engine.execute_opcode(opcode).map_err(|err| format!("failed to execute shadow script: {err}"))?;
            }
            engine.stacks().dstack.last().cloned().ok_or_else(|| "shadow VM produced an empty stack".to_string())
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

    fn read_stack_value(&self, index: i64, type_name: &str) -> Result<DebugValue, String> {
        let bytes = self.read_stack_at_index(index)?;
        decode_value_by_type(type_name, bytes)
    }

    fn read_structured_binding_value(
        &self,
        scope_state: &ScopeState<'i>,
        base_name: &str,
        type_name: &str,
        leaf_bindings: &[DebugLeafBinding],
    ) -> Result<DebugValue, String> {
        if type_name.ends_with("[]") {
            let mut leaf_arrays = Vec::with_capacity(leaf_bindings.len());
            let mut expected_len = None;
            for leaf in leaf_bindings {
                let leaf_name = flattened_struct_name(base_name, &leaf.field_path);
                let binding = scope_state.get(&leaf_name).ok_or_else(|| format!("missing structured leaf binding '{leaf_name}'"))?;
                let value = self.resolve_scope_binding(scope_state, binding)?;
                let DebugValue::Array(values) = value else {
                    return Err(format!("structured array leaf '{}' did not decode to an array", format_field_path(&leaf.field_path)));
                };
                if let Some(length) = expected_len {
                    if values.len() != length {
                        return Err("structured array leaves have mismatched lengths".to_string());
                    }
                } else {
                    expected_len = Some(values.len());
                }
                leaf_arrays.push((leaf.field_path.clone(), values));
            }

            let mut items = Vec::with_capacity(expected_len.unwrap_or(0));
            for index in 0..expected_len.unwrap_or(0) {
                let mut fields = Vec::new();
                for (field_path, values) in &leaf_arrays {
                    let value = values.get(index).cloned().ok_or_else(|| "structured array leaf index out of range".to_string())?;
                    insert_object_path(&mut fields, field_path, value)?;
                }
                items.push(DebugValue::Object(fields));
            }
            return Ok(DebugValue::Array(items));
        }

        let mut fields = Vec::with_capacity(leaf_bindings.len());
        for leaf in leaf_bindings {
            let leaf_name = flattened_struct_name(base_name, &leaf.field_path);
            let binding = scope_state.get(&leaf_name).ok_or_else(|| format!("missing structured leaf binding '{leaf_name}'"))?;
            let value = self.resolve_scope_binding(scope_state, binding)?;
            insert_object_path(&mut fields, &leaf.field_path, value)?;
        }
        Ok(DebugValue::Object(fields))
    }

    fn try_resolve_binding_value(
        &self,
        scope_state: &ScopeState<'i>,
        binding: &ScopeBinding<'i>,
        visiting: &mut HashSet<String>,
    ) -> Option<DebugValue> {
        match &binding.source {
            ScopeValueSource::RuntimeSlot { from_top } => self.read_stack_value(*from_top, &binding.type_name).ok(),
            ScopeValueSource::StructuredBinding { base_name, leaf_bindings } => {
                self.read_structured_binding_value(scope_state, base_name, &binding.type_name, leaf_bindings).ok()
            }
            ScopeValueSource::Expr(expr) => self.try_resolve_expr_value(scope_state, expr, visiting),
            ScopeValueSource::Unavailable { .. } => None,
        }
    }

    fn try_resolve_expr_value(
        &self,
        scope_state: &ScopeState<'i>,
        expr: &Expr<'i>,
        visiting: &mut HashSet<String>,
    ) -> Option<DebugValue> {
        match &expr.kind {
            ExprKind::Int(value) => Some(DebugValue::Int(*value)),
            ExprKind::Bool(value) => Some(DebugValue::Bool(*value)),
            ExprKind::Byte(value) => Some(DebugValue::Bytes(vec![*value])),
            ExprKind::String(value) => Some(DebugValue::String(value.clone())),
            ExprKind::Array(values) => {
                if values.iter().all(|value| matches!(value.kind, ExprKind::Byte(_))) {
                    let bytes = values
                        .iter()
                        .map(|value| match value.kind {
                            ExprKind::Byte(byte) => byte,
                            _ => unreachable!("checked"),
                        })
                        .collect();
                    Some(DebugValue::Bytes(bytes))
                } else {
                    let mut items = Vec::with_capacity(values.len());
                    for value in values {
                        let item = self.try_resolve_expr_value(scope_state, value, visiting)?;
                        items.push(item);
                    }
                    Some(DebugValue::Array(items))
                }
            }
            ExprKind::StateObject(fields) => {
                let mut values = Vec::with_capacity(fields.len());
                for field in fields {
                    let value = self.try_resolve_expr_value(scope_state, &field.expr, visiting)?;
                    values.push((field.name.clone(), value));
                }
                Some(DebugValue::Object(values))
            }
            ExprKind::Identifier(name) => {
                if !visiting.insert(name.clone()) {
                    return None;
                }
                let resolved =
                    scope_state.get(name).and_then(|binding| self.try_resolve_binding_value(scope_state, binding, visiting));
                visiting.remove(name);
                resolved
            }
            ExprKind::FieldAccess { source, field, .. } => {
                let Some(DebugValue::Object(fields)) = self.try_resolve_expr_value(scope_state, source, visiting) else {
                    return None;
                };
                fields.into_iter().find_map(|(name, value)| (name == *field).then_some(value))
            }
            ExprKind::ArrayIndex { source, index } => {
                let Some(DebugValue::Array(values)) = self.try_resolve_expr_value(scope_state, source, visiting) else {
                    return None;
                };
                let Some(DebugValue::Int(index)) = self.try_resolve_expr_value(scope_state, index, visiting) else {
                    return None;
                };
                let index = usize::try_from(index).ok()?;
                values.get(index).cloned()
            }
            ExprKind::UnarySuffix { source, kind, .. } => match kind {
                UnarySuffixKind::Length => match self.try_resolve_expr_value(scope_state, source, visiting)? {
                    DebugValue::Array(values) => Some(DebugValue::Int(values.len() as i64)),
                    DebugValue::Bytes(bytes) => Some(DebugValue::Int(bytes.len() as i64)),
                    DebugValue::String(value) => Some(DebugValue::Int(value.len() as i64)),
                    _ => None,
                },
                UnarySuffixKind::Reverse => None,
            },
            _ => None,
        }
    }
}

/// Decodes raw bytes into a typed debug value based on the type name.
fn decode_value_by_type(type_name: &str, bytes: Vec<u8>) -> Result<DebugValue, String> {
    if let Some(element_type) = type_name.strip_suffix("[]") {
        if let Some(element_size) = fixed_array_element_size(element_type) {
            return decode_known_width_array(type_name, bytes, element_type, element_size);
        }
    }

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

fn decode_known_width_array(type_name: &str, bytes: Vec<u8>, element_type: &str, element_size: usize) -> Result<DebugValue, String> {
    if element_size == 0 {
        return Err(format!("array element type '{type_name}' has zero width"));
    }
    if bytes.len() % element_size != 0 {
        return Err(format!("encoded value for '{type_name}' has invalid length {}", bytes.len()));
    }

    let mut values = Vec::with_capacity(bytes.len() / element_size);
    for chunk in bytes.chunks(element_size) {
        values.push(decode_value_by_type(element_type, chunk.to_vec())?);
    }
    Ok(DebugValue::Array(values))
}

fn insert_object_path(fields: &mut Vec<(String, DebugValue)>, path: &[String], value: DebugValue) -> Result<(), String> {
    let Some((field_name, rest)) = path.split_first() else {
        return Err("structured field path cannot be empty".to_string());
    };

    if rest.is_empty() {
        if fields.iter().any(|(name, _)| name == field_name) {
            return Err(format!("duplicate structured field '{field_name}'"));
        }
        fields.push((field_name.clone(), value));
        return Ok(());
    }

    if let Some((_, existing)) = fields.iter_mut().find(|(name, _)| name == field_name) {
        let DebugValue::Object(children) = existing else {
            return Err(format!("structured field '{field_name}' is not an object"));
        };
        return insert_object_path(children, rest, value);
    }

    let mut children = Vec::new();
    insert_object_path(&mut children, rest, value)?;
    fields.push((field_name.clone(), DebugValue::Object(children)));
    Ok(())
}

fn format_field_path(path: &[String]) -> String {
    if path.is_empty() { "<root>".to_string() } else { path.join(".") }
}

fn structured_leaf_value(value: &DebugValue, field_path: &[String]) -> Option<DebugValue> {
    if field_path.is_empty() {
        return Some(value.clone());
    }

    match value {
        DebugValue::Array(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                values.push(structured_leaf_value(item, field_path)?);
            }
            Some(DebugValue::Array(values))
        }
        DebugValue::Object(fields) => {
            let (field_name, rest) = field_path.split_first()?;
            let value = fields.iter().find_map(|(name, value)| (name == field_name).then_some(value))?;
            structured_leaf_value(value, rest)
        }
        _ => None,
    }
}

fn debug_value_to_expr<'i>(value: &DebugValue) -> Option<Expr<'i>> {
    match value {
        DebugValue::Int(value) => Some(Expr::int(*value)),
        DebugValue::Bool(value) => Some(Expr::bool(*value)),
        DebugValue::Bytes(bytes) => Some(Expr::bytes(bytes.clone())),
        DebugValue::String(value) => Some(Expr::new(ExprKind::String(value.clone()), span::Span::default())),
        DebugValue::Array(items) => {
            Some(Expr::new(ExprKind::Array(items.iter().map(debug_value_to_expr).collect::<Option<Vec<_>>>()?), span::Span::default()))
        }
        DebugValue::Object(fields) => Some(Expr::new(
            ExprKind::StateObject(
                fields
                    .iter()
                    .map(|(name, value)| {
                        Some(StateFieldExpr {
                            name: name.clone(),
                            expr: debug_value_to_expr(value)?,
                            span: span::Span::default(),
                            name_span: span::Span::default(),
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
            span::Span::default(),
        )),
        DebugValue::Unknown(_) => None,
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

fn is_synthetic_default_span(span: SourceSpan) -> bool {
    span.line == 1 && span.col == 1 && span.end_line == 1 && span.end_col == 1
}

fn display_name_for_active_covenant_call(target: &ResolvedCovenantCallTarget) -> String {
    match target.info.binding {
        CovenantDeclBinding::Auth => target.info.source_name.clone(),
        CovenantDeclBinding::Cov => {
            if target.is_leader {
                format!("{} [leader]", target.info.source_name)
            } else {
                format!("{} [delegate]", target.info.source_name)
            }
        }
    }
}

fn map_expr_children_for_eval<'i, F>(expr: &'i Expr<'i>, map_child: &mut F) -> Result<Expr<'i>, String>
where
    F: FnMut(&'i Expr<'i>) -> Result<Expr<'i>, String>,
{
    let span = expr.span;
    match &expr.kind {
        ExprKind::Unary { op, expr } => Ok(Expr::new(ExprKind::Unary { op: *op, expr: Box::new(map_child(expr)?) }, span)),
        ExprKind::Binary { op, left, right } => {
            Ok(Expr::new(ExprKind::Binary { op: *op, left: Box::new(map_child(left)?), right: Box::new(map_child(right)?) }, span))
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(map_child(condition)?),
                then_expr: Box::new(map_child(then_expr)?),
                else_expr: Box::new(map_child(else_expr)?),
            },
            span,
        )),
        ExprKind::Array(values) => {
            Ok(Expr::new(ExprKind::Array(values.iter().map(&mut *map_child).collect::<Result<Vec<_>, _>>()?), span))
        }
        ExprKind::StateObject(fields) => Ok(Expr::new(
            ExprKind::StateObject(
                fields
                    .iter()
                    .map(|field| {
                        Ok(StateFieldExpr {
                            name: field.name.clone(),
                            expr: map_child(&field.expr)?,
                            span: field.span,
                            name_span: field.name_span,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            ),
            span,
        )),
        ExprKind::FieldAccess { source, field, field_span } => Ok(Expr::new(
            ExprKind::FieldAccess { source: Box::new(map_child(source)?), field: field.clone(), field_span: *field_span },
            span,
        )),
        ExprKind::Call { name, args, name_span } => Ok(Expr::new(
            ExprKind::Call {
                name: name.clone(),
                args: args.iter().map(&mut *map_child).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(&mut *map_child).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(map_child(source)?),
                index: Box::new(map_child(index)?),
                part: *part,
                span: *split_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(map_child(source)?),
                start: Box::new(map_child(start)?),
                end: Box::new(map_child(end)?),
                span: *slice_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => {
            Ok(Expr::new(ExprKind::ArrayIndex { source: Box::new(map_child(source)?), index: Box::new(map_child(index)?) }, span))
        }
        ExprKind::Introspection { kind, index, field_span } => {
            Ok(Expr::new(ExprKind::Introspection { kind: *kind, index: Box::new(map_child(index)?), field_span: *field_span }, span))
        }
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
            Ok(Expr::new(ExprKind::UnarySuffix { source: Box::new(map_child(source)?), kind: *kind, span: *suffix_span }, span))
        }
        _ => Ok(expr.clone()),
    }
}

enum StructuredFieldAccessBase<'i> {
    Binding(String),
    IndexedBinding(String, &'i Expr<'i>),
}

fn collect_structured_field_access<'i>(expr: &'i Expr<'i>) -> Option<(StructuredFieldAccessBase<'i>, Vec<String>)> {
    match &expr.kind {
        ExprKind::FieldAccess { source, field, .. } => {
            let (base, mut path) = collect_structured_field_access(source)?;
            path.push(field.clone());
            Some((base, path))
        }
        ExprKind::Identifier(name) => Some((StructuredFieldAccessBase::Binding(name.clone()), Vec::new())),
        ExprKind::ArrayIndex { source, index } => match &source.kind {
            ExprKind::Identifier(name) => Some((StructuredFieldAccessBase::IndexedBinding(name.clone(), index), Vec::new())),
            _ => None,
        },
        _ => None,
    }
}

fn lower_structured_field_access_for_eval<'i>(expr: &'i Expr<'i>, scope_state: &ScopeState<'i>) -> Result<Option<Expr<'i>>, String> {
    let Some((base, field_path)) = collect_structured_field_access(expr) else {
        return Ok(None);
    };
    let base_name = match &base {
        StructuredFieldAccessBase::Binding(name) | StructuredFieldAccessBase::IndexedBinding(name, _) => name,
    };
    let Some(binding) = scope_state.get(base_name.as_str()) else {
        return Ok(None);
    };
    let ScopeValueSource::StructuredBinding { leaf_bindings, .. } = &binding.source else {
        return Ok(None);
    };
    if !leaf_bindings.iter().any(|leaf| leaf.field_path == field_path) {
        return Ok(None);
    }

    let lowered_leaf = Expr::identifier(flattened_struct_name(base_name, &field_path));
    Ok(Some(match base {
        StructuredFieldAccessBase::Binding(_) => Expr::new(lowered_leaf.kind, expr.span),
        StructuredFieldAccessBase::IndexedBinding(_, index) => Expr::new(
            ExprKind::ArrayIndex { source: Box::new(lowered_leaf), index: Box::new(lower_expr_for_eval(index, scope_state)?) },
            expr.span,
        ),
    }))
}

fn lower_structured_length_for_eval<'i>(expr: &Expr<'i>, scope_state: &ScopeState<'i>) -> Result<Option<Expr<'i>>, String> {
    let span = expr.span;
    let ExprKind::UnarySuffix { source, kind, span: suffix_span } = &expr.kind else {
        return Ok(None);
    };
    if !matches!(kind, UnarySuffixKind::Length) {
        return Ok(None);
    }
    let ExprKind::Identifier(name) = &source.kind else {
        return Ok(None);
    };
    let Some(binding) = scope_state.get(name.as_str()) else {
        return Ok(None);
    };
    let ScopeValueSource::StructuredBinding { leaf_bindings, .. } = &binding.source else {
        return Ok(None);
    };
    if !binding.type_name.ends_with("[]") {
        return Ok(None);
    }
    let Some(first_leaf) = leaf_bindings.first() else {
        return Err("structured array must contain fields".to_string());
    };
    Ok(Some(Expr::new(
        ExprKind::UnarySuffix {
            source: Box::new(Expr::identifier(flattened_struct_name(name, &first_leaf.field_path))),
            kind: *kind,
            span: *suffix_span,
        },
        span,
    )))
}

fn lower_expr_for_eval<'i>(expr: &'i Expr<'i>, scope_state: &ScopeState<'i>) -> Result<Expr<'i>, String> {
    match &expr.kind {
        ExprKind::FieldAccess { .. } => {
            if let Some(lowered) = lower_structured_field_access_for_eval(expr, scope_state)? {
                return Ok(lowered);
            }
            map_expr_children_for_eval(expr, &mut |child| lower_expr_for_eval(child, scope_state))
        }
        ExprKind::UnarySuffix { .. } => {
            if let Some(lowered) = lower_structured_length_for_eval(expr, scope_state)? {
                return Ok(lowered);
            }
            map_expr_children_for_eval(expr, &mut |child| lower_expr_for_eval(child, scope_state))
        }
        _ => map_expr_children_for_eval(expr, &mut |child| lower_expr_for_eval(child, scope_state)),
    }
}

fn is_inline_synthetic_name(name: &str) -> bool {
    name.starts_with("__arg_") || name.starts_with("__struct_")
}

fn contract_struct_fields<'i>(contract: &ContractAst<'i>, name: &str) -> Option<Vec<(String, TypeRef)>> {
    if name == "State" {
        return Some(contract.fields.iter().map(|field| (field.name.clone(), field.type_ref.clone())).collect());
    }
    contract
        .structs
        .iter()
        .find(|item| item.name == name)
        .map(|item| item.fields.iter().map(|field| (field.name.clone(), field.type_ref.clone())).collect())
}

fn flatten_contract_type_leaves<'i>(contract: &ContractAst<'i>, type_ref: &TypeRef) -> Result<Vec<(Vec<String>, TypeRef)>, String> {
    let TypeBase::Custom(name) = &type_ref.base else {
        return Ok(vec![(Vec::new(), type_ref.clone())]);
    };
    let Some(fields) = contract_struct_fields(contract, name) else {
        return Ok(vec![(Vec::new(), type_ref.clone())]);
    };

    let mut leaves = Vec::new();
    for (field_name, field_type_ref) in fields {
        let mut nested_type = field_type_ref;
        nested_type.array_dims.extend(type_ref.array_dims.iter().cloned());
        for (mut path, leaf_type) in flatten_contract_type_leaves(contract, &nested_type)? {
            path.insert(0, field_name.clone());
            leaves.push((path, leaf_type));
        }
    }
    Ok(leaves)
}

fn is_structured_type_name(type_name: &str) -> bool {
    parse_type_ref(type_name).ok().is_some_and(|type_ref| is_structured_type_ref(&type_ref))
}

fn direct_expr_type_name<'i>(scope_state: &ScopeState<'i>, expr: &Expr<'i>) -> Option<String> {
    match &expr.kind {
        ExprKind::Identifier(name) => scope_state.get(name).map(|binding| binding.type_name.clone()),
        ExprKind::ArrayIndex { source, .. } => {
            let source_type = direct_expr_type_name(scope_state, source)?;
            let type_ref = parse_type_ref(&source_type).ok()?;
            Some(type_ref.element_type()?.type_name())
        }
        _ => None,
    }
}

fn is_structured_type_ref(type_ref: &silverscript_lang::ast::TypeRef) -> bool {
    matches!(&type_ref.base, TypeBase::Custom(_)) || type_ref.element_type().is_some_and(|element| is_structured_type_ref(&element))
}

fn record_debug_named_values<'i>(bindings: &mut ScopeState<'i>, values: &[DebugNamedValue<'i>], origin: VariableOrigin) {
    for value in values {
        bindings.entry(value.name.clone()).or_insert_with(|| ScopeBinding {
            type_name: value.type_name.clone(),
            source: ScopeValueSource::Expr(value.value.clone()),
            origin,
            hidden: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use silverscript_lang::ast::{BinaryOp, Expr, ExprKind, StateFieldExpr};
    use silverscript_lang::debug_info::{
        DebugFunctionRange, DebugInfo, DebugLeafBinding, DebugNamedValue, DebugParamBinding, DebugParamMapping, DebugStep,
        DebugVariableUpdate, SourceSpan, StepKind,
    };
    use silverscript_lang::span;

    fn scalar_param(name: &str, type_name: &str, stack_index: i64) -> DebugParamMapping {
        DebugParamMapping {
            name: name.to_string(),
            type_name: type_name.to_string(),
            binding: DebugParamBinding::SingleValue { stack_index },
            function: "f".to_string(),
        }
    }

    fn structured_param(name: &str, type_name: &str, leaf_bindings: Vec<DebugLeafBinding>) -> DebugParamMapping {
        DebugParamMapping {
            name: name.to_string(),
            type_name: type_name.to_string(),
            binding: DebugParamBinding::StructuredValue { leaf_bindings },
            function: "f".to_string(),
        }
    }

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
            constructor_args: vec![],
            constants: vec![DebugNamedValue { name: "K".to_string(), type_name: "int".to_string(), value: Expr::int(7) }],
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

        let session = make_session(vec![scalar_param("a", "int", 1), scalar_param("b", "int", 0)], vec![], &sigscript).unwrap();

        let update = DebugVariableUpdate {
            name: "x".to_string(),
            type_name: "int".to_string(),
            runtime_binding: None,
            expr: Expr::new(
                ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier("a")), right: Box::new(Expr::identifier("b")) },
                span::Span::default(),
            ),
            structured_leaf_bindings: None,
        };
        let scope_state = session.scope_state(StepId::ROOT).unwrap();
        let value = session.evaluate_scope_expr_as(&scope_state, &update.expr, &update.type_name).unwrap();
        assert!(matches!(value, DebugValue::Int(12)));
    }

    #[test]
    fn console_logs_resolve_inline_frame_bindings() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![scalar_param("a", "int", 0)],
            vec![
                DebugStep {
                    bytecode_start: 0,
                    bytecode_end: 0,
                    span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                    kind: StepKind::InlineCallEnter { callee: "inner".to_string() },
                    sequence: 0,
                    call_depth: 0,
                    frame_id: 1,
                    variable_updates: vec![DebugVariableUpdate {
                        name: "x".to_string(),
                        type_name: "int".to_string(),
                        runtime_binding: None,
                        expr: Expr::identifier("a"),
                        structured_leaf_bindings: None,
                    }],
                    console_args: vec![],
                },
                DebugStep {
                    bytecode_start: 0,
                    bytecode_end: 0,
                    span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                    kind: StepKind::Source {},
                    sequence: 1,
                    call_depth: 1,
                    frame_id: 1,
                    variable_updates: vec![],
                    console_args: vec![
                        Expr::new(ExprKind::String("inner".to_string()), span::Span::default()),
                        Expr::new(
                            ExprKind::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(Expr::identifier("x")),
                                right: Box::new(Expr::int(1)),
                            },
                            span::Span::default(),
                        ),
                    ],
                },
            ],
            &sigscript,
        )
        .unwrap();

        session.mark_step_executed(0);
        session.mark_step_executed(1);

        assert_eq!(session.take_console_output(), vec!["inner 6"]);
    }

    #[test]
    fn list_variables_returns_unknown_for_uncompilable_expr() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![scalar_param("a", "int", 0)],
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
                    runtime_binding: None,
                    expr: Expr::identifier("missing"),
                    structured_leaf_bindings: None,
                }],
                console_args: vec![],
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
            vec![scalar_param("a", "int", 0)],
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
                        name: "__arg_f_0".to_string(),
                        type_name: "int".to_string(),
                        runtime_binding: None,
                        expr: Expr::identifier("a"),
                        structured_leaf_bindings: None,
                    },
                    DebugVariableUpdate {
                        name: "x".to_string(),
                        type_name: "int".to_string(),
                        runtime_binding: None,
                        expr: Expr::new(
                            ExprKind::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(Expr::identifier("__arg_f_0")),
                                right: Box::new(Expr::int(1)),
                            },
                            span::Span::default(),
                        ),
                        structured_leaf_bindings: None,
                    },
                ],
                console_args: vec![],
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
    fn list_variables_renders_struct_constant_from_recorded_value() {
        let sig_cache = Box::leak(Box::new(Cache::new(10_000)));
        let reused_values: &'static SigHashReusedValuesUnsync = Box::leak(Box::new(SigHashReusedValuesUnsync::new()));
        let engine: DebugEngine<'static> =
            TxScriptEngine::new(EngineCtx::new(sig_cache).with_reused(reused_values), EngineFlags { covenants_enabled: true });
        let debug_info = DebugInfo {
            source: String::new(),
            steps: vec![],
            params: vec![],
            functions: vec![DebugFunctionRange { name: "f".to_string(), bytecode_start: 0, bytecode_end: 1 }],
            constructor_args: vec![],
            constants: vec![DebugNamedValue {
                name: "DEFAULT_PAIR".to_string(),
                type_name: "Pair".to_string(),
                value: Expr::new(
                    ExprKind::StateObject(vec![
                        StateFieldExpr {
                            name: "amount".to_string(),
                            expr: Expr::int(7),
                            span: span::Span::default(),
                            name_span: span::Span::default(),
                        },
                        StateFieldExpr {
                            name: "code".to_string(),
                            expr: Expr::new(ExprKind::Array(vec![Expr::byte(0x12), Expr::byte(0x34)]), span::Span::default()),
                            span: span::Span::default(),
                            name_span: span::Span::default(),
                        },
                    ]),
                    span::Span::default(),
                ),
            }],
        };
        let session = DebugSession::full(&[], &[], "", Some(debug_info), engine).unwrap();
        let scope_state = session.scope_state(StepId::ROOT).unwrap();
        let vars = session.collect_variables_map(&scope_state);
        let pair = vars.get("DEFAULT_PAIR").expect("DEFAULT_PAIR variable");
        match &pair.value {
            DebugValue::Object(fields) => {
                assert_eq!(fields.len(), 2);
                assert!(matches!(fields[0], (ref name, DebugValue::Int(7)) if name == "amount"));
                assert!(matches!(fields[1], (ref name, DebugValue::Bytes(ref bytes)) if name == "code" && bytes == &vec![0x12, 0x34]));
            }
            other => panic!("expected object debug value, got {other:?}"),
        }
    }

    #[test]
    fn shadow_eval_resolves_nested_inline_synthetic_chain() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![scalar_param("a", "int", 0)],
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
                        runtime_binding: None,
                        expr: Expr::identifier("a"),
                        structured_leaf_bindings: None,
                    },
                    DebugVariableUpdate {
                        name: "__arg_inner_0".to_string(),
                        type_name: "int".to_string(),
                        runtime_binding: None,
                        expr: Expr::identifier("__arg_outer_0"),
                        structured_leaf_bindings: None,
                    },
                    DebugVariableUpdate {
                        name: "x".to_string(),
                        type_name: "int".to_string(),
                        runtime_binding: None,
                        expr: Expr::new(
                            ExprKind::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(Expr::identifier("__arg_inner_0")),
                                right: Box::new(Expr::int(1)),
                            },
                            span::Span::default(),
                        ),
                        structured_leaf_bindings: None,
                    },
                ],
                console_args: vec![],
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
    fn runtime_binding_reads_live_stack_slot_before_shadow_fallback() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![],
            vec![
                DebugStep {
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
                        runtime_binding: Some(RuntimeBinding::DataStackSlot { from_top: 0 }),
                        expr: Expr::identifier("missing"),
                        structured_leaf_bindings: None,
                    }],
                    console_args: vec![],
                },
                DebugStep {
                    bytecode_start: 0,
                    bytecode_end: 0,
                    span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                    kind: StepKind::Source {},
                    sequence: 1,
                    call_depth: 0,
                    frame_id: 0,
                    variable_updates: vec![],
                    console_args: vec![],
                },
            ],
            &sigscript,
        )
        .unwrap();

        session.executed_steps.insert(StepId { sequence: 0, frame_id: 0 });
        session.executed_steps.insert(StepId { sequence: 1, frame_id: 0 });
        session.current_step_index = Some(1);

        let x = session.variable_by_name("x").unwrap();
        assert_eq!(crate::presentation::format_value(&x.type_name, &x.value), "5");
    }

    #[test]
    fn evaluate_expression_supports_literals_bindings_and_errors() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![],
            vec![
                DebugStep {
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
                        runtime_binding: Some(RuntimeBinding::DataStackSlot { from_top: 0 }),
                        expr: Expr::identifier("missing"),
                        structured_leaf_bindings: None,
                    }],
                    console_args: vec![],
                },
                DebugStep {
                    bytecode_start: 0,
                    bytecode_end: 0,
                    span: SourceSpan { line: 1, col: 1, end_line: 1, end_col: 1 },
                    kind: StepKind::Source {},
                    sequence: 1,
                    call_depth: 0,
                    frame_id: 0,
                    variable_updates: vec![],
                    console_args: vec![],
                },
            ],
            &sigscript,
        )
        .unwrap();

        session.executed_steps.insert(StepId { sequence: 0, frame_id: 0 });
        session.executed_steps.insert(StepId { sequence: 1, frame_id: 0 });
        session.current_step_index = Some(1);

        let literal = session.evaluate_expression("1 + 2").unwrap();
        assert_eq!(literal.0, "int");
        assert!(matches!(literal.1, DebugValue::Int(3)));

        let scoped = session.evaluate_expression("x + 1").unwrap();
        assert_eq!(scoped.0, "int");
        assert!(matches!(scoped.1, DebugValue::Int(6)));

        let constant = session.evaluate_expression("K + 1").unwrap();
        assert_eq!(constant.0, "int");
        assert!(matches!(constant.1, DebugValue::Int(8)));

        let parse_err = session.evaluate_expression("1 +").unwrap_err();
        assert!(parse_err.contains("parse error"));

        let unknown_err = session.evaluate_expression("missing + 1").unwrap_err();
        assert!(unknown_err.contains("undefined identifier: missing"));
    }

    #[test]
    fn structured_param_reconstructs_object_and_exposes_hidden_leaf_bindings() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(7).unwrap();
        sig_builder.add_data(&[0x12, 0x34]).unwrap();
        let sigscript = sig_builder.drain();

        let session = make_session(
            vec![structured_param(
                "next",
                "State",
                vec![
                    DebugLeafBinding { field_path: vec!["amount".to_string()], type_name: "int".to_string(), stack_index: Some(1) },
                    DebugLeafBinding { field_path: vec!["code".to_string()], type_name: "byte[2]".to_string(), stack_index: Some(0) },
                ],
            )],
            vec![],
            &sigscript,
        )
        .unwrap();

        let next = session.variable_by_name("next").expect("structured param should be visible");
        assert_eq!(crate::presentation::format_value(&next.type_name, &next.value), "{amount: 7, code: 0x1234}");

        let scope_state = session.scope_state(StepId::ROOT).expect("scope state");
        assert!(scope_state.contains_key("__struct_next_amount"));
        assert!(scope_state.get("__struct_next_amount").is_some_and(|binding| binding.hidden));
    }

    #[test]
    fn lower_expr_for_eval_rewrites_structured_bindings_to_hidden_leaves() {
        let session = make_session(
            vec![
                structured_param(
                    "next",
                    "State",
                    vec![DebugLeafBinding {
                        field_path: vec!["amount".to_string()],
                        type_name: "int".to_string(),
                        stack_index: Some(0),
                    }],
                ),
                structured_param(
                    "next_states",
                    "State[]",
                    vec![DebugLeafBinding {
                        field_path: vec!["amount".to_string()],
                        type_name: "int[]".to_string(),
                        stack_index: Some(1),
                    }],
                ),
            ],
            vec![],
            &[],
        )
        .unwrap();

        let scope_state = session.scope_state(StepId::ROOT).expect("scope state");

        let field_expr = parse_expression_ast("next.amount").expect("parse field");
        let lowered_field = lower_expr_for_eval(&field_expr, &scope_state).expect("lower field access");
        assert!(matches!(lowered_field.kind, ExprKind::Identifier(ref name) if name == "__struct_next_amount"));

        let indexed_expr = parse_expression_ast("next_states[0].amount").expect("parse indexed field");
        let lowered_indexed = lower_expr_for_eval(&indexed_expr, &scope_state).expect("lower indexed field access");
        match lowered_indexed.kind {
            ExprKind::ArrayIndex { source, index } => {
                assert!(matches!(source.kind, ExprKind::Identifier(ref name) if name == "__struct_next_states_amount"));
                assert!(matches!(index.kind, ExprKind::Int(0)));
            }
            other => panic!("expected lowered array index, got {other:?}"),
        }

        let length_expr = parse_expression_ast("next_states.length").expect("parse structured length");
        let lowered_length = lower_expr_for_eval(&length_expr, &scope_state).expect("lower structured length");
        match lowered_length.kind {
            ExprKind::UnarySuffix { source, kind, .. } => {
                assert!(matches!(source.kind, ExprKind::Identifier(ref name) if name == "__struct_next_states_amount"));
                assert!(matches!(kind, UnarySuffixKind::Length));
            }
            other => panic!("expected lowered length suffix, got {other:?}"),
        }
    }
}
