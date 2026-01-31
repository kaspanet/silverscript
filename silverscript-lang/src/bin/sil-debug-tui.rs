//! # SilverScript Debugger (sil-debug-tui)
//!
//! A TUI front-end for the SilverScript debug session engine.

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use crossterm::{cursor, execute};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags};
use ratatui::prelude::*;
use ratatui::widgets::*;

use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::debug::session::{DebugEngine, DebugSession};

// ─────────────────────────────────────────────────────────────────────────────
// Theme colors - elegant dark theme with accent colors
// ─────────────────────────────────────────────────────────────────────────────

const ACCENT_PRIMARY: Color = Color::Rgb(138, 180, 248); // Soft blue
const ACCENT_SECONDARY: Color = Color::Rgb(129, 199, 132); // Soft green
const ACCENT_WARNING: Color = Color::Rgb(255, 183, 77); // Amber
const ACCENT_ERROR: Color = Color::Rgb(239, 83, 80); // Red
const ACCENT_MUTED: Color = Color::Rgb(144, 144, 144); // Gray
const BORDER_COLOR: Color = Color::Rgb(68, 68, 68); // Dark gray border
const BORDER_FOCUSED: Color = Color::Rgb(100, 100, 100); // Lighter border for focus
const BG_HIGHLIGHT: Color = Color::Rgb(38, 38, 38); // Subtle highlight
const TEXT_DIM: Color = Color::Rgb(120, 120, 120); // Dimmed text

struct App<'a> {
    session: DebugSession<'a>,
    status: String,
    status_type: StatusType,
    done: bool,
    contract_name: String,
    function_name: String,
    opcode_count: usize,
    result: Option<RunResult>,
    source_lines: Vec<String>,
    selected_line: u32,
    scroll_offset: usize,
}

#[derive(Clone, Copy)]
enum StatusType {
    Info,
    Success,
    Warning,
}

#[derive(Clone)]
enum RunResult {
    Success,
    Error(String),
}

impl<'a> App<'a> {
    fn new(session: DebugSession<'a>, contract_name: String, function_name: String, source: &str) -> Self {
        let source_lines: Vec<String> = source.lines().map(|s| s.to_string()).collect();
        let initial_line = session.current_span().map(|s| s.line).unwrap_or(1);
        Self {
            session,
            status: "Ready — ↑/↓ select line, 'n' step, 'b' breakpoint, '?' help".to_string(),
            status_type: StatusType::Info,
            done: false,
            contract_name,
            function_name,
            opcode_count: 0,
            result: None,
            source_lines,
            selected_line: initial_line,
            scroll_offset: 0,
        }
    }

    fn set_status(&mut self, msg: impl Into<String>, status_type: StatusType) {
        self.status = msg.into();
        self.status_type = status_type;
    }

    fn set_result(&mut self, result: RunResult) {
        self.result = Some(result);
    }

    fn select_up(&mut self) {
        if self.selected_line > 1 {
            self.selected_line -= 1;
        }
    }

    fn select_down(&mut self) {
        if (self.selected_line as usize) < self.source_lines.len() {
            self.selected_line += 1;
        }
    }

    fn sync_selection_to_active(&mut self) {
        if let Some(span) = self.session.current_span() {
            self.selected_line = span.line;
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: sil-debug-tui <contract.sil> [--no-selector] [--function <name>] [--ctor-arg <value> ...] [--arg <value> ...]\n\n  --ctor-arg is typed by the contract constructor params.\n  --arg is typed by the selected function ABI.\n\nExamples:\n  # constructor (int x, int y), function hello(int a, int b)\n  sil-debug-tui if_statement.sil --function hello --ctor-arg 3 --ctor-arg 10 --arg 1 --arg 2\n\nValue formats:\n  int:        123 (or 0x7b)\n  bool:       true|false\n  string:     hello (shell quoting handles spaces)\n  bytes*:     0xdeadbeef\n"
    );
}

fn parse_int_arg(raw: &str) -> Result<i64, Box<dyn Error>> {
    let cleaned = raw.replace('_', "");
    if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        return Ok(i64::from_str_radix(hex, 16)?);
    }
    Ok(cleaned.parse::<i64>()?)
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let trimmed = raw.trim();
    let hex_str = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if hex_str.is_empty() {
        return Ok(vec![]);
    }
    let normalized = if hex_str.len() % 2 != 0 { format!("0{hex_str}") } else { hex_str.to_string() };
    Ok(hex::decode(normalized)?)
}

fn parse_typed_arg(type_name: &str, raw: &str) -> Result<Expr, Box<dyn Error>> {
    match type_name {
        "int" => Ok(Expr::Int(parse_int_arg(raw)?)),
        "bool" => match raw {
            "true" => Ok(Expr::Bool(true)),
            "false" => Ok(Expr::Bool(false)),
            _ => Err(format!("invalid bool '{raw}' (expected true/false)").into()),
        },
        "string" => Ok(Expr::String(raw.to_string())),
        "bytes" | "byte" | "pubkey" | "sig" | "datasig" => Ok(Expr::Bytes(parse_hex_bytes(raw)?)),
        other => {
            if let Some(size) = other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
                let bytes = parse_hex_bytes(raw)?;
                if bytes.len() != size {
                    return Err(format!("{other} expects {size} bytes, got {}", bytes.len()).into());
                }
                Ok(Expr::Bytes(bytes))
            } else {
                Err(format!("unsupported arg type '{other}'").into())
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut script_path: Option<String> = None;
    let mut without_selector = false;
    let mut function_name: Option<String> = None;
    let mut raw_ctor_args: Vec<String> = Vec::new();
    let mut raw_args: Vec<String> = Vec::new();

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-selector" => without_selector = true,
            "--function" | "-f" => {
                function_name = args.next();
                if function_name.is_none() {
                    print_usage();
                    return Err("missing function name".into());
                }
            }
            "--ctor-arg" => {
                let value = args.next();
                if value.is_none() {
                    print_usage();
                    return Err("missing --ctor-arg value".into());
                }
                raw_ctor_args.push(value.expect("checked"));
            }
            "--arg" | "-a" => {
                let value = args.next();
                if value.is_none() {
                    print_usage();
                    return Err("missing --arg value".into());
                }
                raw_args.push(value.expect("checked"));
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            _ => {
                if script_path.is_some() {
                    print_usage();
                    return Err("unexpected extra argument".into());
                }
                script_path = Some(arg);
            }
        }
    }

    let script_path = match script_path {
        Some(path) => path,
        None => {
            print_usage();
            return Err("missing contract path".into());
        }
    };

    let source = fs::read_to_string(&script_path)?;
    let parsed_contract = parse_contract_ast(&source)?;

    if parsed_contract.params.len() != raw_ctor_args.len() {
        return Err(format!("constructor expects {} arguments, got {}", parsed_contract.params.len(), raw_ctor_args.len()).into());
    }

    let mut ctor_args = Vec::with_capacity(raw_ctor_args.len());
    for (param, raw) in parsed_contract.params.iter().zip(raw_ctor_args.iter()) {
        ctor_args.push(parse_typed_arg(&param.type_name, raw)?);
    }

    let compile_opts = CompileOptions { covenants_enabled: true, without_selector, record_debug_spans: true };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let flags = EngineFlags { covenants_enabled: compile_opts.covenants_enabled };
    let engine = DebugEngine::new(ctx, flags);

    let default_name = compiled.abi.first().map(|entry| entry.name.clone()).ok_or("contract has no functions")?;
    let selected_name = function_name.unwrap_or(default_name);
    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| format!("function '{selected_name}' not found"))?;

    if entry.inputs.len() != raw_args.len() {
        return Err(format!("function '{selected_name}' expects {} arguments, got {}", entry.inputs.len(), raw_args.len()).into());
    }

    let mut typed_args = Vec::with_capacity(raw_args.len());
    for (input, raw) in entry.inputs.iter().zip(raw_args.iter()) {
        typed_args.push(parse_typed_arg(&input.type_name, raw)?);
    }

    let sigscript = compiled.build_sig_script(&selected_name, typed_args)?;
    let mut session = DebugSession::full(&sigscript, &compiled.script, &source, debug_info, engine)?;
    session.run_to_first_executed_statement()?;

    // Extract contract name from filename
    let contract_name = std::path::Path::new(&script_path).file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string();

    run_tui(App::new(session, contract_name, selected_name, &source))
}

fn run_tui(mut app: App<'_>) -> Result<(), Box<dyn Error>> {
    // Clean up terminal and enter TUI mode
    let mut stdout = io::stdout();
    execute!(stdout, cursor::Hide, Clear(ClearType::All), cursor::MoveTo(0, 0), EnterAlternateScreen)?;
    enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    loop {
        terminal.draw(|frame| draw_ui(frame, &mut app))?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => {
                    if handle_key(&mut app, key)? {
                        break;
                    }
                }
                Event::Resize(_, _) => {
                    terminal.clear()?;
                }
                _ => {}
            }
        }
    }

    // Restore terminal state cleanly
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, cursor::Show, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    terminal.show_cursor()?;

    // Print exit message
    println!("\n  {} Debugger session ended.\n", "✓");

    Ok(())
}

fn handle_key(app: &mut App<'_>, key: KeyEvent) -> Result<bool, Box<dyn Error>> {
    // Handle Ctrl+C for clean exit
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Ok(true);
    }

    match key.code {
        KeyCode::Char('q') => {
            return Ok(true);
        }
        KeyCode::Esc => {
            return Ok(true);
        }
        KeyCode::Up => {
            app.select_up();
            app.set_status(format!("Line {} selected", app.selected_line), StatusType::Info);
        }
        KeyCode::Down => {
            app.select_down();
            app.set_status(format!("Line {} selected", app.selected_line), StatusType::Info);
        }
        KeyCode::Char('n') => {
            if app.done {
                app.set_status("Execution complete — press 'q' to quit", StatusType::Warning);
            } else {
                match app.session.step_statement() {
                    Ok(Some(_)) => {
                        app.opcode_count += 1;
                        app.sync_selection_to_active();
                        if let Some(span) = app.session.current_span() {
                            app.set_status(format!("Stepped to line {} (statement)", span.line), StatusType::Success);
                        } else {
                            app.set_status("Stepped (statement)", StatusType::Success);
                        }
                    }
                    Ok(None) => {
                        app.set_status("✓ Execution complete", StatusType::Success);
                        app.done = true;
                        app.set_result(RunResult::Success);
                    }
                    Err(err) => {
                        app.set_status("Execution failed", StatusType::Warning);
                        app.done = true;
                        app.set_result(RunResult::Error(err.to_string()));
                    }
                }
            }
        }
        KeyCode::Char('s') => {
            if app.done {
                app.set_status("Execution complete — press 'q' to quit", StatusType::Warning);
            } else {
                match app.session.step_opcode() {
                    Ok(Some(_)) => {
                        app.opcode_count += 1;
                        app.sync_selection_to_active();
                        app.set_status("Stepped (opcode)", StatusType::Info);
                    }
                    Ok(None) => {
                        app.set_status("✓ Execution complete", StatusType::Success);
                        app.done = true;
                        app.set_result(RunResult::Success);
                    }
                    Err(err) => {
                        app.set_status("Execution failed", StatusType::Warning);
                        app.done = true;
                        app.set_result(RunResult::Error(err.to_string()));
                    }
                }
            }
        }
        KeyCode::Char('c') => {
            if app.done {
                app.set_status("Execution complete — press 'q' to quit", StatusType::Warning);
            } else {
                match app.session.continue_to_breakpoint() {
                    Ok(Some(_)) => {
                        app.sync_selection_to_active();
                        if let Some(span) = app.session.current_span() {
                            app.set_status(format!("⏸ Paused at breakpoint (line {})", span.line), StatusType::Warning);
                        } else {
                            app.set_status("⏸ Paused at breakpoint", StatusType::Warning);
                        }
                    }
                    Ok(None) => {
                        app.set_status("✓ Execution complete", StatusType::Success);
                        app.done = true;
                        app.set_result(RunResult::Success);
                    }
                    Err(err) => {
                        app.set_status("Execution failed", StatusType::Warning);
                        app.done = true;
                        app.set_result(RunResult::Error(err.to_string()));
                    }
                }
            }
        }
        KeyCode::Char('b') => {
            toggle_breakpoint(app, app.selected_line);
        }
        KeyCode::Char('?') | KeyCode::F(1) => {
            app.set_status("↑/↓=select │ n=step │ s=opcode │ c=continue │ b=breakpoint │ q/Esc=quit", StatusType::Info);
        }
        _ => {}
    }

    Ok(false)
}

fn draw_ui(frame: &mut Frame<'_>, app: &mut App<'_>) {
    let area = frame.size();

    // Main layout: header, content, footer
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    // ─────────────────────────────────────────────────────────────────────────
    // Header
    // ─────────────────────────────────────────────────────────────────────────
    let header_text = vec![Line::from(vec![
        Span::styled("  SilverScript Debugger", Style::default().fg(ACCENT_PRIMARY).bold()),
        Span::styled("  │  ", Style::default().fg(BORDER_COLOR)),
        Span::styled(&app.contract_name, Style::default().fg(ACCENT_SECONDARY)),
        Span::styled("::", Style::default().fg(TEXT_DIM)),
        Span::styled(&app.function_name, Style::default().fg(ACCENT_SECONDARY)),
        Span::styled("()", Style::default().fg(TEXT_DIM)),
    ])];

    let header = Paragraph::new(header_text)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(BORDER_COLOR))
                .border_set(symbols::border::PLAIN),
        )
        .alignment(Alignment::Left);
    frame.render_widget(header, main_layout[0]);

    // ─────────────────────────────────────────────────────────────────────────
    // Content area: Source (left) | Variables + Stack (right)
    // ─────────────────────────────────────────────────────────────────────────
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_layout[1]);

    // Source panel
    draw_source_panel(frame, app, content_layout[0]);

    // Right panel: Variables + Stack
    let right_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content_layout[1]);

    draw_variables_panel(frame, app, right_layout[0]);
    draw_stack_panel(frame, app, right_layout[1]);

    // ─────────────────────────────────────────────────────────────────────────
    // Status bar
    // ─────────────────────────────────────────────────────────────────────────
    draw_status_bar(frame, app, main_layout[2]);
}

fn styled_block(title: &str, focused: bool) -> Block<'_> {
    let border_color = if focused { BORDER_FOCUSED } else { BORDER_COLOR };
    Block::default()
        .title(Span::styled(format!(" {title} "), Style::default().fg(ACCENT_PRIMARY).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .border_set(symbols::border::ROUNDED)
}

const BG_SELECTION: Color = Color::Rgb(50, 50, 70); // Selection highlight (blue-ish)

fn draw_source_panel(frame: &mut Frame<'_>, app: &mut App<'_>, area: Rect) {
    let block = styled_block("Source", true);
    let inner_area = block.inner(area);
    let visible_lines = inner_area.height as usize;

    // Get active line from session
    let active_line = app.session.current_span().map(|s| s.line);
    let breakpoints = app.session.breakpoints();

    // Calculate scroll offset to keep selected line visible
    let selected_idx = app.selected_line.saturating_sub(1) as usize;
    if selected_idx < app.scroll_offset {
        app.scroll_offset = selected_idx;
    } else if selected_idx >= app.scroll_offset + visible_lines {
        app.scroll_offset = selected_idx.saturating_sub(visible_lines - 1);
    }

    // Build all source lines
    let source_lines: Vec<Line<'_>> = app
        .source_lines
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(visible_lines)
        .map(|(idx, line_text)| {
            let line_num = (idx + 1) as u32;
            let is_breakpoint = breakpoints.contains(&line_num);
            let is_active = active_line == Some(line_num);
            let is_selected = app.selected_line == line_num;

            // Line number
            let line_num_span = Span::styled(format!("{:>4} ", line_num), Style::default().fg(TEXT_DIM));

            // Breakpoint indicator
            let bp_indicator = if is_breakpoint {
                Span::styled("● ", Style::default().fg(ACCENT_ERROR))
            } else {
                Span::styled("  ", Style::default())
            };

            // Active line marker (execution pointer)
            let marker = if is_active {
                Span::styled("→ ", Style::default().fg(ACCENT_SECONDARY).bold())
            } else {
                Span::styled("  ", Style::default())
            };

            // Source text styling
            let text_style = if is_active {
                Style::default().fg(Color::White).bold()
            } else if is_selected {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(ACCENT_MUTED)
            };
            let text = Span::styled(line_text.clone(), text_style);

            // Background: active takes precedence, then selected
            let bg = if is_active {
                BG_HIGHLIGHT
            } else if is_selected {
                BG_SELECTION
            } else {
                Color::Reset
            };

            Line::from(vec![line_num_span, bp_indicator, marker, text]).style(Style::default().bg(bg))
        })
        .collect();

    let source = Paragraph::new(source_lines).block(block);
    frame.render_widget(source, area);
}

fn draw_variables_panel(frame: &mut Frame<'_>, app: &mut App<'_>, area: Rect) {
    let block = styled_block("Variables", false);

    let vars = match app.session.list_variables() {
        Ok(items) if items.is_empty() => {
            vec![ListItem::new(Line::from(Span::styled("  No variables in scope", Style::default().fg(TEXT_DIM).italic())))]
        }
        Ok(items) => items
            .into_iter()
            .map(|var| {
                let value = app.session.format_value(&var.type_name, &var.value);
                let name = var.name.clone();
                let type_name = var.type_name.clone();
                ListItem::new(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(name, Style::default().fg(ACCENT_SECONDARY)),
                    Span::styled(": ", Style::default().fg(TEXT_DIM)),
                    Span::styled(type_name, Style::default().fg(ACCENT_PRIMARY)),
                    Span::styled(" = ", Style::default().fg(TEXT_DIM)),
                    Span::styled(value, Style::default().fg(Color::White)),
                ]))
            })
            .collect::<Vec<_>>(),
        Err(err) if err.contains("No function context") => {
            vec![
                ListItem::new(Line::from(Span::styled("  ⚠ No function selected", Style::default().fg(ACCENT_WARNING)))),
                ListItem::new(Line::from(Span::styled("  Use --function <name>", Style::default().fg(TEXT_DIM).italic()))),
            ]
        }
        Err(err) => vec![ListItem::new(Line::from(Span::styled(format!("  Error: {err}"), Style::default().fg(ACCENT_ERROR))))],
    };

    let vars_list = List::new(vars).block(block);
    frame.render_widget(vars_list, area);
}

fn draw_stack_panel(frame: &mut Frame<'_>, app: &mut App<'_>, area: Rect) {
    let stack = app.session.stack();
    let title = format!("Stack ({})", stack.len());
    let block = styled_block(&title, false);

    let stack_items: Vec<ListItem<'_>> = if stack.is_empty() {
        vec![ListItem::new(Line::from(Span::styled("  <empty>", Style::default().fg(TEXT_DIM).italic())))]
    } else {
        stack
            .iter()
            .enumerate()
            .rev()
            .map(|(i, item)| {
                let index_style = if i == stack.len() - 1 {
                    Style::default().fg(ACCENT_WARNING) // Top of stack
                } else {
                    Style::default().fg(TEXT_DIM)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("  [{i}] "), index_style),
                    Span::styled(item.to_string(), Style::default().fg(ACCENT_MUTED)),
                ]))
            })
            .collect()
    };

    let stack_list = List::new(stack_items).block(block);
    frame.render_widget(stack_list, area);
}

fn draw_status_bar(frame: &mut Frame<'_>, app: &mut App<'_>, area: Rect) {
    let status_color = match app.status_type {
        StatusType::Info => ACCENT_PRIMARY,
        StatusType::Success => ACCENT_SECONDARY,
        StatusType::Warning => ACCENT_WARNING,
    };

    let status_indicator = match app.status_type {
        StatusType::Info => "ℹ",
        StatusType::Success => "✓",
        StatusType::Warning => "⚠",
    };

    let state_indicator = if app.done {
        Span::styled(" DONE ", Style::default().fg(Color::Black).bg(ACCENT_SECONDARY).bold())
    } else {
        Span::styled(" RUNNING ", Style::default().fg(Color::Black).bg(ACCENT_PRIMARY).bold())
    };

    let result_span = render_result_span(app);

    let status_line = Line::from(vec![
        Span::styled("  ", Style::default()),
        state_indicator,
        Span::styled("  ", Style::default()),
        Span::styled(status_indicator, Style::default().fg(status_color)),
        Span::styled(" ", Style::default()),
        Span::styled(&app.status, Style::default().fg(status_color)),
        result_span,
    ]);

    let help_line = Line::from(vec![Span::styled(
        "  ↑/↓ select  │  n step  │  s opcode  │  c continue  │  b breakpoint  │  ? help  │  q quit",
        Style::default().fg(TEXT_DIM),
    )]);

    let status = Paragraph::new(vec![status_line, help_line]).block(
        Block::default().borders(Borders::TOP).border_style(Style::default().fg(BORDER_COLOR)).border_set(symbols::border::PLAIN),
    );
    frame.render_widget(status, area);
}

fn toggle_breakpoint(app: &mut App<'_>, line: u32) {
    let breakpoints = app.session.breakpoints();
    if breakpoints.contains(&line) {
        app.session.clear_breakpoint(line);
        app.set_status(format!("○ Cleared breakpoint at line {line}"), StatusType::Info);
    } else {
        app.session.add_breakpoint(line);
        app.set_status(format!("● Set breakpoint at line {line}"), StatusType::Warning);
    }
}

fn render_result_span(app: &App<'_>) -> Span<'static> {
    let Some(result) = &app.result else {
        return Span::styled("", Style::default());
    };

    match result {
        RunResult::Success => Span::styled("  RESULT: OK", Style::default().fg(ACCENT_SECONDARY).bold()),
        RunResult::Error(message) => {
            let mut truncated: String = message.chars().take(60).collect();
            if message.chars().count() > 60 {
                truncated.push('…');
            }
            Span::styled(format!("  RESULT: {truncated}"), Style::default().fg(ACCENT_ERROR).bold())
        }
    }
}
