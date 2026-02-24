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
fn debug_session_prefers_function_param_value_over_shadowed_constructor_constant() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract ShadowMath(int fee) {
    entrypoint function main(int fee) {
        int local = fee + 1;
        local = local + fee;
        require(local > 0);
    }
}
"#;

    with_session_for_source(source, vec![Expr::Int(2)], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;

        session.step_over()?;
        let local_after_init = session.variable_by_name("local")?;
        assert_eq!(session.format_value(&local_after_init.type_name, &local_after_init.value), "4");

        session.step_over()?;
        let local_after_update = session.variable_by_name("local")?;
        assert_eq!(session.format_value(&local_after_update.type_name, &local_after_update.value), "7");

        let fee = session.variable_by_name("fee")?;
        assert!(!fee.is_constant);
        assert_eq!(session.format_value(&fee.type_name, &fee.value), "3");
        Ok(())
    })
}

#[test]
fn debug_session_offsets_param_indexes_when_contract_has_fields() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract FieldOffset(int c) {
    int x = 7;

    entrypoint function main(int a) {
        require(a > 0);
    }
}
"#;

    with_session_for_source(source, vec![Expr::Int(2)], "main", vec![Expr::Int(5)], |session| {
        session.run_to_first_executed_statement()?;

        let a = session.variable_by_name("a")?;
        assert_eq!(session.format_value(&a.type_name, &a.value), "5");

        let x = session.variable_by_name("x")?;
        assert_eq!(session.format_value(&x.type_name, &x.value), "7");
        Ok(())
    })
}

#[test]
fn debug_session_resolves_updates_that_reference_contract_fields() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract FieldMath(int c) {
    int x = 7;

    entrypoint function main(int a) {
        int z = a + x + c;
        require(z > 0);
    }
}
"#;

    with_session_for_source(source, vec![Expr::Int(2)], "main", vec![Expr::Int(5)], |session| {
        session.run_to_first_executed_statement()?;

        for _ in 0..4 {
            if let Ok(z) = session.variable_by_name("z") {
                assert_eq!(session.format_value(&z.type_name, &z.value), "14");
                return Ok(());
            }
            if session.step_over()?.is_none() {
                break;
            }
        }

        Err("expected z to become visible after assignment".into())
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
fn debug_session_step_opcode_advances_statement_cursor() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract OpcodeCursor() {
    entrypoint function main(int a) {
        int x = a + 1;
        x = x + 2;
        require(x > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_span().ok_or("missing start span")?;
        assert_eq!(start.line, 5);

        session.step_opcode()?.ok_or("expected si to execute one opcode")?;
        let after_si = session.current_span().ok_or("missing span after si")?;
        assert_ne!(after_si.line, start.line, "si should refresh statement cursor");

        let x = session.variable_by_name("x")?;
        assert_eq!(session.format_value(&x.type_name, &x.value), "1");
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
fn debug_session_tracks_local_variable_updates() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract LocalVars() {
    entrypoint function main(int a) {
        int x = a + 1;
        x = x + 2;
        require(x > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;
        assert!(session.variable_by_name("x").is_err(), "x should not exist before its statement executes");

        session.step_over()?;
        let x_after_init = session.variable_by_name("x")?;
        assert_eq!(session.format_value(&x_after_init.type_name, &x_after_init.value), "4");

        session.step_over()?;
        let x_after_assign = session.variable_by_name("x")?;
        assert_eq!(session.format_value(&x_after_assign.type_name, &x_after_assign.value), "6");
        Ok(())
    })
}

#[test]
fn debug_session_hits_if_header_breakpoint() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        assert!(session.add_breakpoint(7), "expected if-header line to accept breakpoints");

        let hit = session.continue_to_breakpoint()?;
        assert!(hit.is_some(), "expected to stop at if-header breakpoint");

        let span = session.current_span().ok_or("missing span at breakpoint")?;
        assert!((span.line..=span.end_line).contains(&7), "breakpoint should resolve to line 7 span");
        Ok(())
    })
}

#[test]
fn debug_session_step_over_and_out_handle_inline_calls() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineCalls() {
    function addOne(int x) : (int) {
        int y = x + 1;
        return(y);
    }

    entrypoint function main(int a) {
        (int b) = addOne(a);
        require(b == a + 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_span().ok_or("missing start span")?;
        assert_eq!(start.line, 10);

        session.step_over()?;
        let after_over = session.current_span().ok_or("missing span after step_over")?;
        assert_eq!(after_over.line, 11, "step_over should stay in caller and move past inline call");
        let b = session.variable_by_name("b")?;
        assert_eq!(session.format_value(&b.type_name, &b.value), "4", "inline return should resolve against caller params");
        Ok(())
    })?;

    with_session_for_source(source, vec![], "main", vec![Expr::Int(3)], |session| {
        session.run_to_first_executed_statement()?;
        session.step_into()?;
        let in_callee = session.current_span().ok_or("missing span in callee")?;
        assert_eq!(in_callee.line, 5, "step_into should enter callee body");
        assert_eq!(session.call_stack(), vec!["addOne".to_string()]);

        session.step_out()?;
        let after_out = session.current_span().ok_or("missing span after step_out")?;
        assert_eq!(after_out.line, 11, "step_out should return to caller after inline call");
        assert!(session.call_stack().is_empty(), "call stack should unwind after step_out");
        Ok(())
    })?;

    Ok(())
}
