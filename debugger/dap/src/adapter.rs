use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use dap::events::{Event, OutputEventBody, StoppedEventBody};
use dap::prelude::{Command, Request, Response, ResponseBody};
use dap::responses::{
    ContinueResponse, ScopesResponse, SetBreakpointsResponse, StackTraceResponse, ThreadsResponse, VariablesResponse,
};
use dap::types::{
    Breakpoint, Capabilities, OutputEventCategory, Scope, ScopePresentationhint, Source, StackFrame, StoppedEventReason, Thread,
    Variable,
};
use debugger_session::session::{DebugSession, VariableOrigin};
use debugger_session::{format_failure_report, format_value};

use crate::launch_config::LaunchConfig;
use crate::refs::{RefAllocator, RefTarget, ScopeKind};
use crate::runtime_builder::{OwnedRuntime, build_launch};

const MAIN_THREAD_ID: i64 = 1;

pub struct AdapterResult {
    pub response: Response,
    pub events: Vec<Event>,
    pub should_exit: bool,
}

pub struct DapAdapter {
    runtime: Option<Runtime>,
    refs: RefAllocator,
    frame_sequence: i64,
    configured: bool,
}

struct Runtime {
    runtime: OwnedRuntime,
    source_path: PathBuf,
    source_name: String,
    stop_on_entry: bool,
    no_debug: bool,
    breakpoints_by_source: HashMap<String, HashSet<u32>>,
    frame_map: Vec<FrameMeta>,
}

#[derive(Clone)]
struct FrameMeta {
    frame_id: i64,
    sequence: u32,
    frame_token: u32,
}

impl DapAdapter {
    pub fn new() -> Self {
        Self { runtime: None, refs: RefAllocator::new(), frame_sequence: 1, configured: false }
    }

    pub fn handle_request(&mut self, req: Request) -> AdapterResult {
        match self.handle_request_inner(req.clone()) {
            Ok(result) => result,
            Err(err) => {
                AdapterResult { response: req.error(&format!("internal adapter error: {err}")), events: vec![], should_exit: false }
            }
        }
    }

    fn handle_request_inner(&mut self, req: Request) -> Result<AdapterResult, String> {
        match req.command.clone() {
            Command::Initialize(_) => {
                let capabilities = Capabilities {
                    supports_configuration_done_request: Some(true),
                    supports_step_in_targets_request: Some(false),
                    supports_function_breakpoints: Some(false),
                    supports_conditional_breakpoints: Some(false),
                    support_terminate_debuggee: Some(true),
                    supports_loaded_sources_request: Some(false),
                    supports_evaluate_for_hovers: Some(false),
                    ..Default::default()
                };
                Ok(AdapterResult {
                    response: req.success(ResponseBody::Initialize(capabilities)),
                    events: vec![Event::Initialized],
                    should_exit: false,
                })
            }
            Command::Launch(args) => {
                let launch = match LaunchConfig::from_launch_args(&args) {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        return Ok(AdapterResult {
                            response: req.error(&err),
                            events: vec![self.output_stderr(err)],
                            should_exit: false,
                        });
                    }
                };

                match build_runtime(launch) {
                    Ok(runtime) => {
                        self.runtime = Some(runtime);
                        self.configured = false;
                        Ok(AdapterResult { response: req.success(ResponseBody::Launch), events: vec![], should_exit: false })
                    }
                    Err(err) => {
                        Ok(AdapterResult { response: req.error(&err), events: vec![self.output_stderr(err)], should_exit: false })
                    }
                }
            }
            Command::SetBreakpoints(args) => {
                let runtime = self.runtime.as_mut().ok_or_else(|| "setBreakpoints before launch".to_string())?;
                let requested_source_path =
                    args.source.path.as_deref().map(PathBuf::from).unwrap_or_else(|| runtime.source_path.clone());
                let source_key = canonical_source_key(&requested_source_path);

                if let Some(existing) = runtime.breakpoints_by_source.remove(&source_key) {
                    for line in existing {
                        runtime.runtime.session_mut().clear_breakpoint(line);
                    }
                }
                let requested_lines: Vec<i64> = if let Some(requested) = args.breakpoints {
                    Some(requested.into_iter().map(|source_bp| source_bp.line).collect::<Vec<_>>())
                } else {
                    #[allow(deprecated)]
                    args.lines
                }
                .unwrap_or_default();

                let runtime_source_key = canonical_source_key(&runtime.source_path);
                if source_key != runtime_source_key {
                    // This adapter session executes one script file. Keep breakpoints
                    // from other files isolated and report them as unverified.
                    runtime.breakpoints_by_source.insert(source_key, HashSet::new());
                    let breakpoints = requested_lines
                        .into_iter()
                        .map(|line| Breakpoint { verified: false, line: Some(line), ..Default::default() })
                        .collect();
                    return Ok(AdapterResult {
                        response: req.success(ResponseBody::SetBreakpoints(SetBreakpointsResponse { breakpoints })),
                        events: vec![],
                        should_exit: false,
                    });
                }

                let mut breakpoints = Vec::new();
                let mut resolved_for_source = HashSet::new();
                for line_value in requested_lines {
                    if line_value <= 0 {
                        breakpoints.push(Breakpoint { verified: false, line: Some(line_value), ..Default::default() });
                        continue;
                    }
                    let line = line_value as u32;
                    let resolved = runtime.runtime.session_mut().add_breakpoint_resolved(line);
                    let verified = resolved.is_some();
                    if let Some(actual_line) = resolved {
                        resolved_for_source.insert(actual_line);
                    }
                    breakpoints.push(Breakpoint { verified, line: Some(resolved.unwrap_or(line) as i64), ..Default::default() });
                }

                runtime.breakpoints_by_source.insert(source_key, resolved_for_source);

                Ok(AdapterResult {
                    response: req.success(ResponseBody::SetBreakpoints(SetBreakpointsResponse { breakpoints })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::SetExceptionBreakpoints(_) => Ok(AdapterResult {
                response: req.success(ResponseBody::SetExceptionBreakpoints(Default::default())),
                events: vec![],
                should_exit: false,
            }),
            Command::ConfigurationDone => {
                let runtime = self.runtime.as_mut().ok_or_else(|| "configurationDone before launch".to_string())?;
                self.configured = true;

                runtime
                    .runtime
                    .session_mut()
                    .run_to_first_executed_statement()
                    .map_err(|err| format!("failed to start session: {err}"))?;

                let events = if runtime.no_debug {
                    match runtime.runtime.session_mut().run_to_completion() {
                        Ok(()) => vec![self.output_stdout("Execution completed successfully."), Event::Terminated(None)],
                        Err(err) => {
                            let report = runtime.runtime.session().build_failure_report(&err);
                            let formatted = format_failure_report(&report, &format_value);
                            vec![self.output_stderr(formatted), Event::Terminated(None)]
                        }
                    }
                } else if runtime.stop_on_entry {
                    vec![self.make_stopped_event(StoppedEventReason::Entry, None)]
                } else {
                    match runtime.runtime.session_mut().continue_to_breakpoint() {
                        Ok(Some(_)) => vec![self.make_stopped_event(StoppedEventReason::Breakpoint, None)],
                        Ok(None) => vec![self.output_stdout("Execution completed successfully."), Event::Terminated(None)],
                        Err(err) => {
                            let report = runtime.runtime.session().build_failure_report(&err);
                            let formatted = format_failure_report(&report, &format_value);
                            if runtime.no_debug {
                                vec![self.output_stderr(formatted), Event::Terminated(None)]
                            } else {
                                vec![
                                    self.output_stderr(formatted.clone()),
                                    self.make_stopped_event(StoppedEventReason::Exception, Some(formatted)),
                                ]
                            }
                        }
                    }
                };

                Ok(AdapterResult { response: req.success(ResponseBody::ConfigurationDone), events, should_exit: false })
            }
            Command::Threads => Ok(AdapterResult {
                response: req.success(ResponseBody::Threads(ThreadsResponse {
                    threads: vec![Thread { id: MAIN_THREAD_ID, name: "main".to_string() }],
                })),
                events: vec![],
                should_exit: false,
            }),
            Command::StackTrace(_) => {
                let (span, current_step, source, current_function_name, call_stack) = {
                    let runtime = self.runtime.as_ref().ok_or_else(|| "stackTrace before launch".to_string())?;
                    let span = runtime.runtime.session().current_span();
                    let current_step = runtime.runtime.session().current_step();
                    let source = Source {
                        name: Some(runtime.source_name.clone()),
                        path: Some(runtime.source_path.to_string_lossy().to_string()),
                        ..Default::default()
                    };
                    let current_function_name =
                        runtime.runtime.session().current_function_name().unwrap_or_else(|| "<entry>".to_string());
                    let call_stack = runtime.runtime.session().call_stack_with_spans();
                    (span, current_step, source, current_function_name, call_stack)
                };

                let mut frames = Vec::new();
                let mut frame_map = Vec::new();

                let current_line = span.map(|s| s.line as i64).unwrap_or(1);
                let current_col = span.map(|s| s.col as i64).unwrap_or(1);

                let frame_id = self.next_frame_id();
                frames.push(StackFrame {
                    id: frame_id,
                    name: current_function_name,
                    source: Some(source.clone()),
                    line: current_line,
                    column: current_col,
                    ..Default::default()
                });
                frame_map.push(FrameMeta {
                    frame_id,
                    sequence: current_step.as_ref().map(|step| step.sequence).unwrap_or(0),
                    frame_token: current_step.as_ref().map(|step| step.frame_id).unwrap_or(0),
                });

                for entry in call_stack.into_iter().rev() {
                    let id = self.next_frame_id();
                    let frame_line = entry.call_site_span.map(|s| s.line as i64).unwrap_or(current_line);
                    let frame_col = entry.call_site_span.map(|s| s.col as i64).unwrap_or(current_col);
                    frames.push(StackFrame {
                        id,
                        name: entry.callee_name,
                        source: Some(source.clone()),
                        line: frame_line,
                        column: frame_col,
                        ..Default::default()
                    });
                    frame_map.push(FrameMeta { frame_id: id, sequence: entry.sequence, frame_token: entry.frame_id });
                }

                if let Some(runtime_mut) = self.runtime.as_mut() {
                    runtime_mut.frame_map = frame_map;
                }

                Ok(AdapterResult {
                    response: req.success(ResponseBody::StackTrace(StackTraceResponse {
                        total_frames: Some(frames.len() as i64),
                        stack_frames: frames,
                    })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::Scopes(args) => {
                let runtime = self.runtime.as_ref().ok_or_else(|| "scopes before launch".to_string())?;
                let frame_meta = runtime
                    .frame_map
                    .iter()
                    .find(|frame| frame.frame_id == args.frame_id)
                    .cloned()
                    .unwrap_or(FrameMeta { frame_id: args.frame_id, sequence: 0, frame_token: 0 });

                let variables_ref = self.refs.alloc(scope_target(ScopeKind::Variables, &frame_meta));
                let dstack_ref = self.refs.alloc(scope_target(ScopeKind::DataStack, &frame_meta));
                let astack_ref = self.refs.alloc(scope_target(ScopeKind::AltStack, &frame_meta));
                let scoped_vars = runtime
                    .runtime
                    .session()
                    .list_variables_at_sequence(frame_meta.sequence, frame_meta.frame_token)
                    .unwrap_or_default();
                let stack_snapshot = runtime.runtime.session().stack_snapshot();

                let scopes = vec![
                    Scope {
                        name: "Variables".to_string(),
                        presentation_hint: Some(ScopePresentationhint::Locals),
                        variables_reference: variables_ref,
                        named_variables: Some(scoped_vars.len() as i64),
                        expensive: false,
                        ..Default::default()
                    },
                    Scope {
                        name: "Data Stack".to_string(),
                        presentation_hint: Some(ScopePresentationhint::Registers),
                        variables_reference: dstack_ref,
                        indexed_variables: Some(stack_snapshot.dstack.len() as i64),
                        expensive: false,
                        ..Default::default()
                    },
                    Scope {
                        name: "Alt Stack".to_string(),
                        presentation_hint: Some(ScopePresentationhint::Registers),
                        variables_reference: astack_ref,
                        indexed_variables: Some(stack_snapshot.astack.len() as i64),
                        expensive: false,
                        ..Default::default()
                    },
                ];

                Ok(AdapterResult {
                    response: req.success(ResponseBody::Scopes(ScopesResponse { scopes })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::Variables(args) => {
                let runtime = self.runtime.as_ref().ok_or_else(|| "variables before launch".to_string())?;
                let target = self
                    .refs
                    .get(args.variables_reference)
                    .cloned()
                    .ok_or_else(|| format!("unknown variablesReference {}", args.variables_reference))?;

                let variables = match target {
                    RefTarget::Scope { kind: ScopeKind::Variables, sequence, frame_token } => {
                        let vars = runtime
                            .runtime
                            .session()
                            .list_variables_at_sequence(sequence, frame_token)
                            .map_err(|err| format!("variables unavailable: {err}"))?;
                        let mut bindings = vars;
                        bindings.sort_by_key(|item| {
                            let rank = match item.origin {
                                VariableOrigin::Param => 0,
                                VariableOrigin::Local => 1,
                                VariableOrigin::ContractField | VariableOrigin::ConstructorArg => 2,
                                VariableOrigin::Constant => 3,
                            };
                            (rank, item.name.clone())
                        });
                        bindings
                            .into_iter()
                            .map(|item| Variable {
                                name: binding_name(&item),
                                value: format_value(&item.type_name, &item.value),
                                type_field: Some(item.type_name),
                                evaluate_name: Some(item.name),
                                variables_reference: 0,
                                ..Default::default()
                            })
                            .collect::<Vec<_>>()
                    }
                    RefTarget::Scope { kind: ScopeKind::DataStack, .. } => {
                        let snapshot = runtime.runtime.session().stack_snapshot();
                        stack_scope_variables("dstack", &snapshot.dstack)
                    }
                    RefTarget::Scope { kind: ScopeKind::AltStack, .. } => {
                        let snapshot = runtime.runtime.session().stack_snapshot();
                        stack_scope_variables("astack", &snapshot.astack)
                    }
                };

                Ok(AdapterResult {
                    response: req.success(ResponseBody::Variables(VariablesResponse { variables })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::Next(_) => self.handle_step(req, StepKind::Next, |session| session.step_over()),
            Command::StepIn(_) => self.handle_step(req, StepKind::StepIn, |session| session.step_into()),
            Command::StepOut(_) => self.handle_step(req, StepKind::StepOut, |session| session.step_out()),
            Command::Continue(_) => {
                let runtime = self.runtime.as_mut().ok_or_else(|| "continue before launch".to_string())?;
                let no_debug = runtime.no_debug;
                let mut events = Vec::new();
                match runtime.runtime.session_mut().continue_to_breakpoint() {
                    Ok(Some(_)) => events.push(self.make_stopped_event(StoppedEventReason::Breakpoint, None)),
                    Ok(None) => {
                        events.push(self.output_stdout("Execution completed successfully."));
                        events.push(Event::Terminated(None));
                    }
                    Err(err) => {
                        let report = runtime.runtime.session().build_failure_report(&err);
                        let formatted = format_failure_report(&report, &format_value);
                        events.push(self.output_stderr(formatted.clone()));
                        if no_debug {
                            events.push(Event::Terminated(None));
                        } else {
                            events.push(self.make_stopped_event(StoppedEventReason::Exception, Some(formatted)));
                        }
                    }
                }
                Ok(AdapterResult {
                    response: req.success(ResponseBody::Continue(ContinueResponse { all_threads_continued: Some(true) })),
                    events,
                    should_exit: false,
                })
            }
            Command::Disconnect(_) => {
                self.runtime = None;
                Ok(AdapterResult { response: req.success(ResponseBody::Disconnect), events: vec![], should_exit: true })
            }
            _ => Ok(AdapterResult { response: req.error("unsupported request"), events: vec![], should_exit: false }),
        }
    }

    fn handle_step(
        &mut self,
        req: Request,
        step_kind: StepKind,
        mut step_fn: impl FnMut(
            &mut DebugSession<'static, 'static>,
        )
            -> Result<Option<debugger_session::session::SessionState<'static>>, kaspa_txscript_errors::TxScriptError>,
    ) -> Result<AdapterResult, String> {
        if !self.configured {
            return Ok(AdapterResult {
                response: req.error("cannot step before configurationDone"),
                events: vec![],
                should_exit: false,
            });
        }

        let runtime = self.runtime.as_mut().ok_or_else(|| "step request before launch".to_string())?;
        let mut events = Vec::new();
        let before_location = current_location_key(runtime.runtime.session());
        let mut step_result = step_fn(runtime.runtime.session_mut());

        let mut guard = 0usize;
        while matches!(step_result, Ok(Some(_))) && guard < 32 {
            let after_location = current_location_key(runtime.runtime.session());
            if after_location != before_location {
                break;
            }
            step_result = step_fn(runtime.runtime.session_mut());
            guard += 1;
        }

        match step_result {
            Ok(Some(_)) => events.push(self.make_stopped_event(StoppedEventReason::Step, None)),
            Ok(None) => {
                events.push(self.output_stdout("Execution completed successfully."));
                events.push(Event::Terminated(None));
            }
            Err(err) => {
                let report = runtime.runtime.session().build_failure_report(&err);
                let formatted = format_failure_report(&report, &format_value);
                events.push(self.output_stderr(formatted.clone()));
                events.push(self.make_stopped_event(StoppedEventReason::Exception, Some(formatted)));
            }
        }

        let body = match step_kind {
            StepKind::Next => ResponseBody::Next,
            StepKind::StepIn => ResponseBody::StepIn,
            StepKind::StepOut => ResponseBody::StepOut,
        };

        Ok(AdapterResult { response: req.success(body), events, should_exit: false })
    }

    fn make_stopped_event(&mut self, reason: StoppedEventReason, text: Option<String>) -> Event {
        self.refs.reset();
        Event::Stopped(StoppedEventBody {
            reason,
            description: None,
            thread_id: Some(MAIN_THREAD_ID),
            preserve_focus_hint: None,
            text,
            all_threads_stopped: Some(true),
            hit_breakpoint_ids: None,
        })
    }

    fn next_frame_id(&mut self) -> i64 {
        let id = self.frame_sequence;
        self.frame_sequence += 1;
        id
    }

    fn output_stderr(&self, msg: impl Into<String>) -> Event {
        Event::Output(OutputEventBody {
            category: Some(OutputEventCategory::Stderr),
            output: format!("{}\n", msg.into()),
            ..Default::default()
        })
    }

    fn output_stdout(&self, msg: impl Into<String>) -> Event {
        Event::Output(OutputEventBody {
            category: Some(OutputEventCategory::Stdout),
            output: format!("{}\n", msg.into()),
            ..Default::default()
        })
    }
}

enum StepKind {
    Next,
    StepIn,
    StepOut,
}

fn current_location_key(session: &DebugSession<'static, 'static>) -> Option<u32> {
    session.current_span().map(|span| span.line)
}

fn canonical_source_key(path: &Path) -> String {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy().to_string()
}

fn scope_target(kind: ScopeKind, frame_meta: &FrameMeta) -> RefTarget {
    RefTarget::Scope { kind, sequence: frame_meta.sequence, frame_token: frame_meta.frame_token }
}

fn binding_name(variable: &debugger_session::session::Variable) -> String {
    match variable.origin {
        VariableOrigin::Param | VariableOrigin::Local | VariableOrigin::ContractField => variable.name.clone(),
        VariableOrigin::ConstructorArg => format!("{} (ctor)", variable.name),
        VariableOrigin::Constant => format!("{} (const)", variable.name),
    }
}

fn stack_scope_variables(scope_name: &str, items: &[String]) -> Vec<Variable> {
    if items.is_empty() {
        return vec![Variable {
            name: "(empty)".to_string(),
            value: "<empty>".to_string(),
            variables_reference: 0,
            ..Default::default()
        }];
    }

    items
        .iter()
        .enumerate()
        .map(|(index, item)| Variable {
            name: format!("{scope_name}[{index}]"),
            value: stack_item_value(item),
            variables_reference: 0,
            ..Default::default()
        })
        .collect()
}

fn stack_item_value(item: &str) -> String {
    if item.is_empty() { "<empty bytes> (script 0 / false)".to_string() } else { format!("0x{item}") }
}

fn build_runtime(config: LaunchConfig) -> Result<Runtime, String> {
    let built = build_launch(config.resolve(None)?)?;
    Ok(Runtime {
        runtime: built.runtime,
        source_path: built.source_path,
        source_name: built.source_name,
        stop_on_entry: built.stop_on_entry,
        no_debug: built.no_debug,
        breakpoints_by_source: HashMap::new(),
        frame_map: Vec::new(),
    })
}
