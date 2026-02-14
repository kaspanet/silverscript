use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags};

use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::debug::MappingKind;
use silverscript_lang::debug::session::DebugSession;

fn example_contract_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("tests/examples/if_statement.sil")
}

// Convenience harness for the canonical example contract used by baseline session tests.
fn with_session<F>(mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&mut DebugSession<'_>) -> Result<(), Box<dyn Error>>,
{
    let contract_path = example_contract_path();
    assert!(contract_path.exists(), "example contract not found: {}", contract_path.display());

    let source = fs::read_to_string(&contract_path)?;
    with_session_for_source(&source, vec![Expr::Int(3), Expr::Int(10)], "hello", vec![Expr::Int(5), Expr::Int(5)], &mut f)
}

// Generic harness that compiles a contract and boots a debugger session for a selected function call.
fn with_session_for_source<F>(
    source: &str,
    ctor_args: Vec<Expr>,
    function_name: &str,
    function_args: Vec<Expr>,
    mut f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&mut DebugSession<'_>) -> Result<(), Box<dyn Error>>,
{
    let parsed_contract = parse_contract_ast(source)?;
    assert_eq!(parsed_contract.params.len(), ctor_args.len());

    // Compile with debug metadata enabled so line mappings and variable updates are available.
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let flags = EngineFlags { covenants_enabled: true };
    let engine = silverscript_lang::debug::session::DebugEngine::new(ctx, flags);

    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == function_name)
        .ok_or_else(|| format!("function '{function_name}' not found"))?;

    assert_eq!(entry.inputs.len(), function_args.len());

    // Seed stack with sigscript args and then execute the lockscript in debug mode.
    let sigscript = compiled.build_sig_script(function_name, function_args)?;
    let mut session = DebugSession::full(&sigscript, &compiled.script, source, debug_info, engine)?;

    f(&mut session)
}

#[test]
fn debug_session_provides_source_context_and_vars() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        // Skip dispatcher setup and land on first user statement.
        session.run_to_first_executed_statement()?;
        let context = session.source_context();
        assert!(context.is_some(), "expected source context");

        let vars = session.list_variables().expect("variables available");
        let names = vars.iter().map(|var| var.name.as_str()).collect::<HashSet<_>>();
        assert!(names.contains("a"), "expected param 'a' in variables");
        assert!(names.contains("b"), "expected param 'b' in variables");

        Ok(())
    })
}

#[test]
fn debug_session_steps_forward() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        let before = session.state().pc;
        let before_span = session.current_span();
        session.step_statement()?;
        let after = session.state().pc;
        let after_span = session.current_span();
        assert!(after > before || after_span != before_span, "expected statement step to make source progress");
        Ok(())
    })
}

#[test]
fn debug_session_breakpoint_management() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        let span = session.current_span().ok_or("no current span")?;
        let line = span.line;

        session.add_breakpoint(line);
        assert!(session.breakpoints().contains(&line));

        session.clear_breakpoint(line);
        assert!(!session.breakpoints().contains(&line));
        Ok(())
    })
}

#[test]
fn debug_session_tracks_array_assignment_updates() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract Arr() {
    entrypoint function main() {
        int[] a;
        int[] b;
        b.push(1);
        a = b;
        require(length(a) == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;
        assert!(session.add_breakpoint(9), "require line should accept breakpoints");
        session.continue_to_breakpoint()?;

        let a = session.variable_by_name("a")?;
        assert_eq!(session.format_value(&a.type_name, &a.value), "[1]");
        Ok(())
    })
}

#[test]
fn debug_session_hits_multiline_breakpoints() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract BP() {
    entrypoint function main(int a) {
        require(a == 1);
        require(a == 1);
        require(
            a == 1
        );
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(1)], |session| {
        session.run_to_first_executed_statement()?;
        // Line 8 is inside a multiline `require(...)` span and should still be hit.
        assert!(session.add_breakpoint(8), "expected breakpoint line to be valid");

        let hit = session.continue_to_breakpoint()?;
        assert!(hit.is_some(), "expected to stop at multiline statement breakpoint");

        let span = session.current_span().ok_or("expected source span at breakpoint")?;
        assert!((span.line..=span.end_line).contains(&8));
        Ok(())
    })
}

#[test]
fn debug_session_dedupes_shadowed_constructor_constants() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract Shadow(int x) {
    entrypoint function main(int x) {
        require(x == x);
    }
}
"#;

    with_session_for_source(source, vec![Expr::Int(7)], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;

        // Function param `x` should shadow constructor constant `x` in visible debugger variables.
        let vars = session.list_variables()?;
        let x_count = vars.iter().filter(|var| var.name == "x").count();
        assert_eq!(x_count, 1, "expected a single visible x variable");

        let x = session.variable_by_name("x")?;
        assert!(!x.is_constant, "function parameter should shadow constructor constant");
        assert_eq!(session.format_value(&x.type_name, &x.value), "3");
        Ok(())
    })
}

#[test]
fn debug_session_exposes_virtual_steps() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract Virtuals() {
    entrypoint function main(int a) {
        int x = a + 1;
        x = x + 2;
        require(x > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let first = session.current_location().ok_or("missing first location")?;
        assert!(matches!(first.kind, MappingKind::Virtual {}));
        let first_pc = session.state().pc;

        let second = session.step_over()?.ok_or("missing second step")?.mapping.ok_or("missing second mapping")?;
        assert!(matches!(second.kind, MappingKind::Virtual {}));
        assert_eq!(session.state().pc, first_pc, "virtual step should not execute opcodes");

        let third = session.step_over()?.ok_or("missing third step")?.mapping.ok_or("missing third mapping")?;
        assert!(matches!(third.kind, MappingKind::Statement {}));
        assert_eq!(session.state().pc, first_pc, "first real statement should still be at same pc boundary");
        Ok(())
    })
}

#[test]
fn debug_session_breakpoint_hits_virtual_line() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract VirtualBp() {
    entrypoint function main(int a) {
        int x = a + 1;
        x = x + 2;
        require(x > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;
        assert!(session.add_breakpoint(6), "line with virtual assignment should be a valid breakpoint");
        let hit = session.continue_to_breakpoint()?;
        assert!(hit.is_some(), "expected breakpoint on virtual line");
        let span = session.current_span().ok_or("missing span at virtual breakpoint")?;
        assert_eq!(span.line, 6);
        Ok(())
    })
}

#[test]
fn debug_session_inline_stepping_supports_into_over_out() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineStep() {
    function add1(int x) : (int) {
        int y = x + 1;
        require(y > 0);
        return(y);
    }

    entrypoint function main(int a) {
        int seed = a;
        (int r) = add1(seed);
        require(r > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(4)], |session| {
        session.run_to_first_executed_statement()?;
        let root = session.current_location().ok_or("missing root mapping")?;
        assert_eq!(root.call_depth, 0);

        let into = session.step_into()?.ok_or("step into failed")?.mapping.ok_or("missing mapping after step into")?;
        assert_eq!(into.call_depth, 1, "step into should enter inline callee");
        assert!(session.call_stack().iter().any(|name| name == "add1"), "inline call stack should include callee name");

        let out = session.step_out()?.ok_or("step out failed")?.mapping.ok_or("missing mapping after step out")?;
        assert_eq!(out.call_depth, 0, "step out should return to caller depth");
        Ok(())
    })?;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(4)], |session| {
        session.run_to_first_executed_statement()?;
        let over = session.step_over()?.ok_or("step over failed")?.mapping.ok_or("missing mapping after step over")?;
        assert_eq!(over.call_depth, 0, "step over should stay in caller depth");
        Ok(())
    })
}

#[test]
fn debug_session_inline_params_visible_inside_callee() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineParams() {
    function add1(int x) : (int) {
        int y = x + 1;
        require(y > 0);
        return(y);
    }

    entrypoint function main(int a) {
        int seed = a;
        (int r) = add1(seed);
        require(r > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(4)], |session| {
        session.run_to_first_executed_statement()?;
        session.step_into()?;

        let x = session.variable_by_name("x")?;
        let rendered = session.format_value(&x.type_name, &x.value);
        assert_eq!(rendered, "4", "inline param x should be visible inside callee");
        Ok(())
    })
}

#[test]
fn debug_session_function_call_assign_resolves_inline_args() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineAssign() {
    function inc(int x) : (int) {
        return(x + 1);
    }

    entrypoint function main(int a) {
        int seed = a;
        (int r) = inc(seed);
        require(r == a + 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(5)], |session| {
        session.run_to_first_executed_statement()?;
        session.step_over()?;
        let r = session.variable_by_name("r")?;
        let rendered = session.format_value(&r.type_name, &r.value);
        assert_eq!(rendered, "6");
        Ok(())
    })
}
