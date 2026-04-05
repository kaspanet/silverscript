use std::collections::HashSet;
use std::error::Error;

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::opcodes::codes::OpTrue;
use kaspa_txscript::{EngineCtx, EngineFlags};

use debugger_session::{
    format_value,
    session::{DebugSession, DebugValue, ShadowTxContext},
};
use silverscript_lang::ast::{Expr, ExprKind, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract, struct_object};
use silverscript_lang::debug_info::StepKind;

const IF_STATEMENT_CONTRACT: &str = r#"pragma silverscript ^0.1.0;

contract IfStatement(int x, int y) {
    entrypoint function hello(int a, int b) {
        int d = a + b;
        d = d - a;
        if (d == x - 2) {
            int c = d + b;
            d = a + c;
            require(c > d);
        } else {
            require(d == a);
        }
        d = d + a;
        require(d == y);
    }
}
"#;

// Convenience harness for the canonical example contract used by baseline session tests.
fn with_session<F>(mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&mut DebugSession<'_, '_>) -> Result<(), Box<dyn Error>>,
{
    with_session_for_source(
        IF_STATEMENT_CONTRACT,
        vec![Expr::int(3), Expr::int(10)],
        "hello",
        vec![Expr::int(5), Expr::int(5)],
        &mut f,
    )
}

// Generic harness that compiles a contract and boots a debugger session for a selected function call.
fn with_session_for_source<F>(
    source: &str,
    ctor_args: Vec<Expr<'static>>,
    function_name: &str,
    function_args: Vec<Expr<'static>>,
    mut f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&mut DebugSession<'_, '_>) -> Result<(), Box<dyn Error>>,
{
    let parsed_contract = parse_contract_ast(source)?;
    assert_eq!(parsed_contract.params.len(), ctor_args.len());

    // Compile with debug metadata enabled so line steps and variable updates are available.
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let flags = EngineFlags { covenants_enabled: true };
    let engine = debugger_session::session::DebugEngine::new(ctx, flags);

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
fn debug_session_emits_console_logs_when_landing_on_step() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract ConsoleStep() {
    entrypoint function inspect(int a, int b) {
        console.log("sum", a + b);
        require(a + b > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "inspect", vec![Expr::int(2), Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        assert_eq!(session.take_console_output(), vec!["sum 5"]);

        session.step_opcode()?;
        assert!(session.take_console_output().is_empty(), "single-opcode stepping should move past the zero-width console step");
        Ok(())
    })
}

#[test]
fn debug_session_steps_forward() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        let before = session.state().pc;
        let before_span = session.current_span();
        session.step_over()?;
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(1)], |session| {
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

    with_session_for_source(source, vec![Expr::int(7)], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;

        // Function param `x` should shadow constructor constant `x` in visible debugger variables.
        let vars = session.list_variables()?;
        let x_count = vars.iter().filter(|var| var.name == "x").count();
        assert_eq!(x_count, 1, "expected a single visible x variable");

        let x = session.variable_by_name("x")?;
        assert_eq!(x.origin.label(), "arg", "function parameter should shadow constructor constant");
        assert_eq!(format_value(&x.type_name, &x.value), "3");
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

    with_session_for_source(source, vec![Expr::int(2)], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;

        session.step_over()?;
        let local_after_init = session.variable_by_name("local")?;
        assert_eq!(format_value(&local_after_init.type_name, &local_after_init.value), "4");

        session.step_over()?;
        let local_after_update = session.variable_by_name("local")?;
        assert_eq!(format_value(&local_after_update.type_name, &local_after_update.value), "7");

        let fee = session.variable_by_name("fee")?;
        assert_eq!(fee.origin.label(), "arg");
        assert_eq!(format_value(&fee.type_name, &fee.value), "3");
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

    with_session_for_source(source, vec![Expr::int(2)], "main", vec![Expr::int(5)], |session| {
        session.run_to_first_executed_statement()?;

        let a = session.variable_by_name("a")?;
        assert_eq!(format_value(&a.type_name, &a.value), "5");

        let x = session.variable_by_name("x")?;
        assert_eq!(format_value(&x.type_name, &x.value), "7");
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

    with_session_for_source(source, vec![Expr::int(2)], "main", vec![Expr::int(5)], |session| {
        session.run_to_first_executed_statement()?;

        for _ in 0..4 {
            if let Ok(z) = session.variable_by_name("z") {
                assert_eq!(format_value(&z.type_name, &z.value), "14");
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
fn debug_session_exposes_concrete_source_steps() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract Virtuals() {
    entrypoint function main(int a) {
        int x = a + 1;
        x = x + 2;
        require(x > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let first = session.current_step().ok_or("missing first location")?;
        assert!(matches!(first.kind, StepKind::Source {}));
        assert!(first.bytecode_end > first.bytecode_start, "first step should execute bytecode");

        let second = session.step_over()?.ok_or("missing second step")?.step.ok_or("missing second step payload")?;
        assert!(matches!(second.kind, StepKind::Source {}));
        assert!(second.bytecode_end > second.bytecode_start, "second step should execute bytecode");

        let third = session.step_over()?.ok_or("missing third step")?.step.ok_or("missing third step payload")?;
        assert!(matches!(third.kind, StepKind::Source {}));
        assert!(third.bytecode_end > third.bytecode_start, "third step should execute bytecode");
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_span().ok_or("missing start span")?;
        assert_eq!(start.line, 5);

        // `si` should eventually refresh the statement cursor once execution crosses a statement boundary.
        // The exact opcode count is not stable when compiler lowering changes.
        for _ in 0..50 {
            session.step_opcode()?.ok_or("expected si to execute one opcode")?;
            let after_si = session.current_span().ok_or("missing span after si")?;
            if after_si.line != start.line {
                break;
            }
        }
        let after_si = session.current_span().ok_or("missing span after si")?;
        assert_ne!(after_si.line, start.line, "si should refresh statement cursor");

        let x = session.variable_by_name("x")?;
        // After crossing the first statement boundary, `x = a + 1` should have executed.
        assert_eq!(format_value(&x.type_name, &x.value), "4");
        Ok(())
    })
}

#[test]
fn debug_session_breakpoint_hits_source_line() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract VirtualBp() {
    entrypoint function main(int a) {
        int x = a + 1;
        x = x + 2;
        require(x > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        assert!(session.add_breakpoint(6), "line with assignment should be a valid breakpoint");
        let hit = session.continue_to_breakpoint()?;
        assert!(hit.is_some(), "expected breakpoint on assignment line");
        let span = session.current_span().ok_or("missing span at assignment breakpoint")?;
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        assert!(session.variable_by_name("x").is_err(), "x should not exist before its statement executes");

        session.step_over()?;
        let x_after_init = session.variable_by_name("x")?;
        assert_eq!(format_value(&x_after_init.type_name, &x_after_init.value), "4");

        session.step_over()?;
        let x_after_assign = session.variable_by_name("x")?;
        assert_eq!(format_value(&x_after_assign.type_name, &x_after_assign.value), "6");
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_step().ok_or("missing start step")?;
        assert_eq!(start.span.line, 10);

        session.step_over()?;
        let after_over = session.current_step().ok_or("missing step after step_over")?;
        assert_eq!(after_over.span.line, 11, "step_over should move past inline call");
        let b = session.variable_by_name("b")?;
        assert_eq!(format_value(&b.type_name, &b.value), "4", "inline return should resolve against caller params");
        Ok(())
    })?;

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        session.step_into()?;
        let mut in_callee = session.current_span().ok_or("missing span in callee")?;
        if in_callee.line == 10 {
            // First stop can be the inline enter boundary on the caller line.
            session.step_into()?;
            in_callee = session.current_span().ok_or("missing span in callee after second step_into")?;
        }
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

#[test]
fn debug_session_run_to_first_statement_starts_in_caller_for_inline_entry() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract Repeat() {
    function inc(int x) {
        int y = x + 1;
        require(y > 0);
    }

    entrypoint function main(int a) {
        inc(a);
        inc(a);
        require(a >= 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::int(0)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_span().ok_or("missing start span")?;
        assert_eq!(start.line, 10, "first source step should be caller line, not callee internals");
        Ok(())
    })
}

#[test]
fn debug_session_step_into_repeated_inline_calls_preserves_order_and_stack() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract Repeat() {
    function inc(int x) {
        int y = x + 1;
        require(y > 0);
    }

    entrypoint function main(int a) {
        inc(a);
        inc(a);
        require(a >= 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::int(0)], |session| {
        session.run_to_first_executed_statement()?;

        let mut lines = vec![session.current_span().ok_or("missing initial span")?.line];
        let mut max_depth = session.call_stack().len();
        while (session.step_into()?).is_some() {
            lines.push(session.current_span().ok_or("missing span while stepping")?.line);
            max_depth = max_depth.max(session.call_stack().len());
        }

        assert_eq!(max_depth, 1, "repeated inline calls should not nest call frames");
        let count_10 = lines.iter().filter(|&&line| line == 10).count();
        assert!(count_10 >= 2, "expected duplicate call-site stops for first call");
        assert!(lines.windows(2).any(|window| window == [5, 6]), "expected callee body stepping");
        assert_eq!(lines.last().copied(), Some(12), "final step should reach caller require");
        assert!(session.call_stack().is_empty(), "call stack should be empty after execution");
        Ok(())
    })
}

#[test]
fn debug_session_step_into_nested_inline_calls_preserves_execution_order() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract NestedNoArgs() {
    function inner() {
        int y = 1;
        require(y > 0);
    }

    function outer() {
        inner();
        require(1 == 1);
    }

    entrypoint function main() {
        outer();
        require(1 == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;
        let mut lines = vec![session.current_span().ok_or("missing initial span")?.line];

        for _ in 0..5 {
            session.step_into()?.ok_or("expected additional source step")?;
            lines.push(session.current_span().ok_or("missing span while stepping")?.line);
        }

        assert_eq!(lines, vec![15, 10, 5, 6, 10, 11], "nested inline stepping order regressed");
        Ok(())
    })
}

#[test]
fn debug_session_inline_source_sequences_are_monotonic() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract DebugPoC(int const) {
    function bump(int x) {
        int y = x + 1;
        require(y > 0);
    }

    function check_pair(int leftInput, int rightInput) {
        int left = leftInput + rightInput;
        int right = left * 2;
        require(right >= left);
    }

    entrypoint function main(int a, int b) {
        int seed = a + const;
        check_pair(a, b);
        bump(seed);
        require(seed >= const);
        require(b >= 0);
    }
}
"#;

    with_session_for_source(source, vec![Expr::int(0)], "main", vec![Expr::int(0), Expr::int(0)], |session| {
        session.run_to_first_executed_statement()?;

        let initial = session.current_step().ok_or("missing initial location")?;
        let mut prev_sequence = initial.sequence;
        let mut lines = vec![session.current_span().ok_or("missing initial span")?.line];

        while session.step_into()?.is_some() {
            let loc = session.current_step().ok_or("missing location after step_into")?;
            assert!(
                loc.sequence >= prev_sequence,
                "source sequence rewound from {} to {} (lines {:?})",
                prev_sequence,
                loc.sequence,
                lines
            );
            prev_sequence = loc.sequence;
            lines.push(session.current_span().ok_or("missing span after step_into")?.line);
        }

        assert!(lines.starts_with(&[16, 17, 10, 11, 12]), "unexpected inline stepping prefix: {:?}", lines);
        assert!(lines.windows(2).any(|window| window == [5, 6]), "expected to step through bump body: {:?}", lines);
        assert_eq!(lines.last().copied(), Some(20), "expected final step to reach caller tail: {:?}", lines);
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(4)], |session| {
        session.run_to_first_executed_statement()?;

        let mut saw_inline_param = false;
        for _ in 0..8 {
            let in_callee = session.call_stack().iter().any(|name| name == "add1");
            if in_callee {
                if let Ok(x) = session.variable_by_name("x") {
                    let rendered = format_value(&x.type_name, &x.value);
                    assert_eq!(rendered, "4", "inline param x should reflect caller-provided value");
                    saw_inline_param = true;
                    break;
                }
            }
            if session.step_into()?.is_none() {
                break;
            }
        }

        assert!(saw_inline_param, "expected inline param x to be visible while inside add1");
        Ok(())
    })
}

#[test]
fn debug_session_eval_inside_inline_callee_uses_visible_bindings() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineEval() {
    function add1(int x) : (int) {
        int y = x + 1;
        require(y > 0);
        return(y);
    }

    entrypoint function main(int a) {
        (int r) = add1(a);
        require(r > 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::int(4)], |session| {
        session.run_to_first_executed_statement()?;
        assert!(session.add_breakpoint(6), "expected inline callee line to accept a breakpoint");

        let hit = session.continue_to_breakpoint()?;
        assert!(hit.is_some(), "expected to stop inside inline callee");
        assert!(session.call_stack().iter().any(|name| name == "add1"), "expected add1 to be active at breakpoint");

        let span = session.current_span().ok_or("expected source span at inline callee breakpoint")?;
        assert!((span.line..=span.end_line).contains(&6), "expected breakpoint span to cover callee require line");

        let x = session.variable_by_name("x")?;
        let y = session.variable_by_name("y")?;
        let (x_value, y_value) = match (&x.value, &y.value) {
            (DebugValue::Int(x_value), DebugValue::Int(y_value)) => (*x_value, *y_value),
            _ => return Err("expected inline callee bindings x and y to be ints".into()),
        };

        let (type_name, value) = session.evaluate_expression("((y * 2) + (x - 1)) - (y - x)")?;
        assert_eq!(type_name, "int");
        assert_eq!(format_value(&type_name, &value), ((y_value * 2) + (x_value - 1) - (y_value - x_value)).to_string());
        Ok(())
    })
}

#[test]
fn debug_session_exposes_ctor_args_and_contract_constants_distinctly() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract ScopeKinds(int init_amount) {
    int constant BONUS = 2;

    entrypoint function main(int delta) {
        int total = init_amount + delta + BONUS;
        require(total > 0);
    }
}
"#;

    with_session_for_source(source, vec![Expr::int(7)], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;

        let vars = session.list_variables()?;
        let init_amount = vars.iter().find(|var| var.name == "init_amount").ok_or("missing ctor arg")?;
        assert_eq!(init_amount.origin.label(), "ctor");

        let bonus = vars.iter().find(|var| var.name == "BONUS").ok_or("missing contract constant")?;
        assert_eq!(bonus.origin.label(), "const");

        let (type_name, value) = session.evaluate_expression("init_amount + BONUS + delta")?;
        assert_eq!(type_name, "int");
        assert_eq!(format_value(&type_name, &value), "12");
        Ok(())
    })
}

#[test]
fn debug_session_exposes_previous_statement_local_immediately_after_step() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract StepVisibility(int init_amount) {
    int constant BONUS = 2;

    function add_bonus(int x) : (int) {
        int y = x + BONUS;
        require(y > x);
        return(y);
    }

    entrypoint function inspect(int delta, int[] values) {
        int base = init_amount + values[0];
        (int after) = add_bonus(base + delta);
        require(after > base);
    }
}
"#;

    with_session_for_source(
        source,
        vec![Expr::int(7)],
        "inspect",
        vec![Expr::int(3), Expr::new(ExprKind::Array(vec![Expr::int(4)]), Default::default())],
        |session| {
            session.run_to_first_executed_statement()?;
            session.current_span().ok_or("missing starting span")?;

            session.step_over()?;
            session.current_span().ok_or("missing span after step")?;

            let base = session.variable_by_name("base")?;
            assert_eq!(format_value(&base.type_name, &base.value), "11");
            Ok(())
        },
    )
}

#[test]
fn debug_session_keeps_shifted_runtime_bindings_correct_after_inline_call() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract ShiftedBindings() {
    int amount = 11;
    byte[32] owner = 0x1111111111111111111111111111111111111111111111111111111111111111;

    function add_bonus(int x) : (int) {
        int y = x + 2;
        require(y > x);
        return(y);
    }

    entrypoint function inspect(int delta, int[] values) {
        int base = amount + values[0];
        (int after) = add_bonus(base + delta);
        require(after >= amount);
        require(owner == owner);
    }
}
"#;

    with_session_for_source(
        source,
        vec![],
        "inspect",
        vec![Expr::int(3), Expr::new(ExprKind::Array(vec![Expr::int(4), Expr::int(5)]), Default::default())],
        |session| {
            session.run_to_first_executed_statement()?;

            session.step_over()?;
            let call_line = session.current_span().ok_or("missing inline-call span")?.line;

            for _ in 0..6 {
                if session.current_span().is_some_and(|span| span.line > call_line) {
                    break;
                }
                if session.step_over()?.is_none() {
                    break;
                }
            }

            let current_line = session.current_span().ok_or("missing post-call span")?.line;
            assert!(current_line > call_line, "expected to step past inline call");

            let amount = session.variable_by_name("amount")?;
            assert_eq!(format_value(&amount.type_name, &amount.value), "11");

            let delta = session.variable_by_name("delta")?;
            assert_eq!(format_value(&delta.type_name, &delta.value), "3");

            let values = session.variable_by_name("values")?;
            assert_eq!(format_value(&values.type_name, &values.value), "[4, 5]");

            let base = session.variable_by_name("base")?;
            assert_eq!(format_value(&base.type_name, &base.value), "15");

            let after = session.variable_by_name("after")?;
            assert_eq!(format_value(&after.type_name, &after.value), "20");

            Ok(())
        },
    )
}

#[test]
fn debug_session_evaluates_structured_state_expressions() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract StructuredEvalState() {
    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;

    entrypoint function inspect(State next_state) {
        int bumped = next_state.amount + amount;
        require(bumped > 0);
    }
}
"#;

    with_session_for_source(
        source,
        vec![],
        "inspect",
        vec![struct_object(vec![("amount", Expr::int(5)), ("active", Expr::bool(true)), ("tag", Expr::bytes(vec![0xaa]))])],
        |session| {
            session.run_to_first_executed_statement()?;

            let (type_name, value) = session.evaluate_expression("next_state")?;
            assert_eq!(type_name, "State");
            assert_eq!(format_value(&type_name, &value), "{amount: 5, active: true, tag: 0xaa}");

            let (type_name, value) = session.evaluate_expression("next_state.amount")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "5");

            let (type_name, value) = session.evaluate_expression("next_state.amount + amount")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "6");
            Ok(())
        },
    )
}

#[test]
fn debug_session_evaluates_structured_state_array_expressions() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract StructuredEvalStateArray() {
    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;

    entrypoint function inspect(State[] next_states) {
        require(next_states.length == 2);
    }
}
"#;

    with_session_for_source(
        source,
        vec![],
        "inspect",
        vec![Expr::new(
            ExprKind::Array(vec![
                struct_object(vec![("amount", Expr::int(5)), ("active", Expr::bool(true)), ("tag", Expr::bytes(vec![0xaa]))]),
                struct_object(vec![("amount", Expr::int(7)), ("active", Expr::bool(true)), ("tag", Expr::bytes(vec![0xaa]))]),
            ]),
            Default::default(),
        )],
        |session| {
            session.run_to_first_executed_statement()?;

            let (type_name, value) = session.evaluate_expression("next_states")?;
            assert_eq!(type_name, "State[]");
            assert_eq!(
                format_value(&type_name, &value),
                "[{amount: 5, active: true, tag: 0xaa}, {amount: 7, active: true, tag: 0xaa}]"
            );

            let (type_name, value) = session.evaluate_expression("next_states.length")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "2");

            let (type_name, value) = session.evaluate_expression("next_states[0]")?;
            assert_eq!(type_name, "State");
            assert_eq!(format_value(&type_name, &value), "{amount: 5, active: true, tag: 0xaa}");

            let (type_name, value) = session.evaluate_expression("next_states[1].amount - next_states[0].amount")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "2");
            Ok(())
        },
    )
}

#[test]
fn debug_session_evaluates_custom_struct_expressions() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract StructuredEvalPair() {
    struct Pair {
        int amount;
        byte[2] code;
    }

    entrypoint function inspect(Pair next_pair) {
        require(next_pair.amount > 0);
    }
}
"#;

    with_session_for_source(
        source,
        vec![],
        "inspect",
        vec![struct_object(vec![("amount", Expr::int(9)), ("code", Expr::bytes(vec![0x12, 0x34]))])],
        |session| {
            session.run_to_first_executed_statement()?;

            let (type_name, value) = session.evaluate_expression("next_pair")?;
            assert_eq!(type_name, "Pair");
            assert_eq!(format_value(&type_name, &value), "{amount: 9, code: 0x1234}");

            let (type_name, value) = session.evaluate_expression("next_pair.amount")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "9");

            let (type_name, value) = session.evaluate_expression("next_pair.code")?;
            assert_eq!(type_name, "byte[2]");
            assert_eq!(format_value(&type_name, &value), "0x1234");
            Ok(())
        },
    )
}

#[test]
fn debug_session_preserves_structured_scope_inside_inline_calls() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineStructuredEval() {
    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;

    function inspect_inner(State inner_state) {
        int bumped = inner_state.amount + amount;
        require(bumped > 0);
    }

    entrypoint function inspect(State next_state) {
        inspect_inner(next_state);
        require(next_state.active == active);
    }
}
"#;

    with_session_for_source(
        source,
        vec![],
        "inspect",
        vec![struct_object(vec![("amount", Expr::int(5)), ("active", Expr::bool(true)), ("tag", Expr::bytes(vec![0xaa]))])],
        |session| {
            session.run_to_first_executed_statement()?;

            for _ in 0..3 {
                if !session.call_stack().is_empty() && session.variable_by_name("inner_state").is_ok() {
                    break;
                }
                session.step_into()?.ok_or("expected inline step")?;
            }

            assert_eq!(session.call_stack(), vec!["inspect_inner".to_string()]);
            let vars = session.list_variables()?;
            assert!(!vars.iter().any(|var| var.name.starts_with("__struct_")));

            let inner_state = session.variable_by_name("inner_state")?;
            assert_eq!(format_value(&inner_state.type_name, &inner_state.value), "{amount: 5, active: true, tag: 0xaa}");

            let next_state = session.variable_by_name("next_state")?;
            assert_eq!(format_value(&next_state.type_name, &next_state.value), "{amount: 5, active: true, tag: 0xaa}");

            let (type_name, value) = session.evaluate_expression("inner_state")?;
            assert_eq!(type_name, "State");
            assert_eq!(format_value(&type_name, &value), "{amount: 5, active: true, tag: 0xaa}");

            let (type_name, value) = session.evaluate_expression("inner_state.amount")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "5");

            let (type_name, value) = session.evaluate_expression("next_state.amount + amount")?;
            assert_eq!(type_name, "int");
            assert_eq!(format_value(&type_name, &value), "6");
            Ok(())
        },
    )
}

#[test]
fn debug_session_evaluates_structured_expressions_without_source_text() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract MissingStructuredSource() {
    int amount = 1;

    entrypoint function inspect(State next) {
        require(next.amount > amount);
    }
}
"#;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], compile_opts)?;
    let mut debug_info = compiled.debug_info.clone().ok_or("missing debug info")?;
    debug_info.source.clear();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let engine = debugger_session::session::DebugEngine::new(ctx, EngineFlags { covenants_enabled: true });
    let sigscript = compiled.build_sig_script("inspect", vec![struct_object(vec![("amount", Expr::int(7))])])?;
    let mut session = DebugSession::full(&sigscript, &compiled.script, "", Some(debug_info), engine)?;

    session.run_to_first_executed_statement()?;
    let (type_name, value) = session.evaluate_expression("next.amount")?;
    assert_eq!(type_name, "int");
    assert_eq!(format_value(&type_name, &value), "7");
    Ok(())
}

#[test]
fn debug_session_nested_inline_calls_with_args_compile_and_step() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract NestedArgs() {
    function inner(int x) {
        int y = x + 1;
        require(y > 0);
    }

    function outer(int v) {
        inner(v);
        require(v >= 0);
    }

    entrypoint function main(int a) {
        outer(a);
        require(a >= 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![Expr::int(0)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_step().ok_or("missing start step")?;
        assert_eq!(start.span.line, 15);

        session.step_over()?;
        let after_over = session.current_step().ok_or("missing step after step_over")?;
        assert_eq!(after_over.span.line, 16, "step_over should move past nested inline call in caller");
        Ok(())
    })
}

#[test]
fn debug_session_exposes_loop_index_variable_i() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract LoopIndex() {
    entrypoint function main() {
        int sum = 0;
        for(i,0,2,2){
            sum = sum + i;
        }
        require(sum >= 0);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;
        let mut saw_loop_index = false;

        for _ in 0..12 {
            if let Ok(i) = session.variable_by_name("i") {
                assert_eq!(format_value(&i.type_name, &i.value), "0");
                saw_loop_index = true;
                break;
            }
            if session.step_over()?.is_none() {
                break;
            }
        }

        assert!(saw_loop_index, "expected loop index 'i' to be visible while stepping loop body");
        Ok(())
    })
}

#[test]
fn debug_session_step_over_preserves_loop_iterations_on_same_source_line() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract LoopStepOver() {
    entrypoint function main() {
        int sum = 0;
        for(i,0,2,2){
            sum = sum + i;
        }
        require(sum == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;

        let mut saw_first_iteration = false;
        for _ in 0..8 {
            if let Ok(i) = session.variable_by_name("i") {
                if format_value(&i.type_name, &i.value) == "0" {
                    saw_first_iteration = true;
                    break;
                }
            }
            session.step_over()?.ok_or("expected to reach first loop iteration")?;
        }

        assert!(saw_first_iteration, "expected to stop within the first loop iteration");

        session.step_over()?.ok_or("expected to step within the loop")?;
        let line_after_next = session.current_span().ok_or("missing span after step_over in loop")?.line;
        assert_ne!(line_after_next, 9, "step_over should not skip the remaining loop iteration");

        let mut saw_second_iteration = false;
        for _ in 0..8 {
            if let Ok(i) = session.variable_by_name("i") {
                if format_value(&i.type_name, &i.value) == "1" {
                    saw_second_iteration = true;
                    break;
                }
            }
            if session.step_over()?.is_none() {
                break;
            }
        }

        assert!(saw_second_iteration, "expected to stop within the second loop iteration before leaving the loop");
        Ok(())
    })
}

#[test]
fn debug_session_loop_header_keeps_outer_locals_across_iterations() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract LoopHeaderLocals() {
    entrypoint function main() {
        int sum = 0;
        for(i,0,2,2){
            sum = sum + i;
        }
        require(sum == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;
        session.step_over()?.ok_or("expected for-header stop")?;
        assert_eq!(session.current_span().ok_or("missing for-header span")?.line, 6);

        session.step_over()?.ok_or("expected first loop-body stop")?;
        assert_eq!(session.current_span().ok_or("missing first loop-body span")?.line, 7);

        session.step_over()?.ok_or("expected second for-header stop")?;
        assert_eq!(session.current_span().ok_or("missing second for-header span")?.line, 6);

        let sum = session.variable_by_name("sum")?;
        assert_eq!(format_value(&sum.type_name, &sum.value), "0");
        Ok(())
    })
}

#[test]
fn debug_session_inline_loop_steps_stay_inside_callee() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineLoop() {
    function walk(int base) {
        int total = base;
        for(i, 0, 2, 2) {
            total = total + i;
        }
        require(total >= base);
    }

    entrypoint function main() {
        int alias = 1;
        walk(alias);
        require(alias == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        let caller_line = 14;

        session.run_to_first_executed_statement()?;
        let mut line = session.current_span().ok_or("missing initial span")?.line;
        for _ in 0..3 {
            if line == caller_line || line == 5 {
                break;
            }
            session.step_over()?.ok_or("expected to reach walk call or callee entry")?;
            line = session.current_span().ok_or("missing span while seeking walk")?.line;
        }

        if line == caller_line {
            session.step_into()?.ok_or("expected to enter walk")?;
            line = session.current_span().ok_or("missing walk entry span")?.line;
        }

        assert_eq!(line, 5, "expected to be at the first walk statement before loop stepping");

        assert_eq!(session.current_span().ok_or("missing walk entry span")?.line, 5);

        session.step_over()?.ok_or("expected loop header")?;
        assert_eq!(session.current_span().ok_or("missing loop header span")?.line, 6);

        session.step_over()?.ok_or("expected first loop body")?;
        assert_eq!(session.current_span().ok_or("missing first loop body span")?.line, 7);

        session.step_over()?.ok_or("expected second loop header")?;
        assert_eq!(session.current_span().ok_or("missing second loop header span")?.line, 6);

        session.step_over()?.ok_or("expected second loop body")?;
        let second_body_line = session.current_span().ok_or("missing second loop body span")?.line;
        assert_ne!(second_body_line, caller_line, "loop stepping regressed back to the caller while still inside walk");
        assert_eq!(second_body_line, 7);
        Ok(())
    })
}

#[test]
fn debug_session_inline_loop_preface_does_not_jump_to_caller() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineLoopPreface() {
    function walk(int threshold) {
        int total = 7;
        int even_acc = 0;
        int odd_acc = 0;
        bool touched_high = false;

        for(i, 0, 2, 2) {
            int current = i;

            if (current % 2 == 0) {
                even_acc = even_acc + current;
            } else if (current > threshold) {
                odd_acc = odd_acc + current;
                touched_high = true;
            } else {
                odd_acc = odd_acc + 1;
            }

            total = total + current;
        }

        require(total >= threshold);
    }

    entrypoint function main() {
        int branch_limit = 1;
        walk(branch_limit);
        require(branch_limit == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;
        session.step_over()?.ok_or("expected walk call site")?;
        let caller_line = session.current_span().ok_or("missing walk call span")?.line;
        assert_eq!(session.current_span().ok_or("missing walk call span")?.line, caller_line);

        session.step_into()?.ok_or("expected to enter walk")?;
        let mut line = session.current_span().ok_or("missing walk entry span")?.line;
        assert_ne!(line, caller_line, "step_into should enter walk rather than stay on the caller line");
        assert!((5..=8).contains(&line), "expected to enter walk preface, got line {line}");

        while line < 8 {
            session.step_over()?.ok_or("expected to continue through walk preface")?;
            line = session.current_span().ok_or("missing walk preface span")?.line;
            assert_ne!(line, caller_line, "preface stepping regressed back to caller before the loop");
        }

        assert_eq!(line, 8, "expected to reach touched_high initialization before the loop");

        session.step_over()?.ok_or("expected loop header")?;
        let next_line = session.current_span().ok_or("missing loop header span")?.line;
        assert_ne!(next_line, caller_line, "step_over jumped back to caller instead of entering the loop");
        assert_eq!(next_line, 10);
        Ok(())
    })
}

#[test]
fn debug_session_step_into_inline_call_with_args_enters_callee_immediately() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract InlineIntoArgs() {
    function walk(int threshold) {
        int total = threshold + 1;
        require(total > threshold);
    }

    entrypoint function main() {
        walk(1);
        require(1 == 1);
    }
}
"#;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;
        let call_line = session.current_span().ok_or("missing walk call span")?.line;
        assert!(call_line > 0, "expected to stop on a real walk call line");

        session.step_into()?.ok_or("expected to step into walk")?;
        assert_ne!(session.current_span().ok_or("missing walk entry span")?.line, call_line);
        assert_eq!(session.current_span().ok_or("missing walk entry span")?.line, 5);
        Ok(())
    })
}

const DEBUG_STRESS_SOURCE: &str = r#"pragma silverscript ^0.1.0;

contract DebugStress() {
    int constant START = 0;
    int constant MAX_ITERS = 6;
    int seed = 2;
    int baseline = 4;

    struct Pair {
        int left;
        int right;
    }

    struct Stats {
        int total;
        int evens;
        int odds;
        bool touched_high;
    }

    function inspect(Stats snapshot, Pair pair, int threshold) {
        int spread = pair.right - pair.left;

        if (snapshot.touched_high) {
            require(spread >= 0);
        } else if (snapshot.odds > snapshot.evens) {
            require(threshold >= pair.left);
        } else {
            require(snapshot.evens >= 0);
        }

        require(snapshot.total > threshold);
    }

    function walk(Pair pair, int threshold) {
        int total = pair.left + pair.right;
        int even_acc = 0;
        int odd_acc = 0;
        bool touched_high = false;

        for(i, START, MAX_ITERS, MAX_ITERS) {
            int current = pair.left + i;

            if (current % 2 == 0) {
                even_acc = even_acc + current;
            } else if (current > threshold) {
                odd_acc = odd_acc + current;
                touched_high = true;
            } else {
                odd_acc = odd_acc + 1;
            }

            total = total + current;
        }

        Stats snapshot = {
            total: total,
            evens: even_acc,
            odds: odd_acc,
            touched_high: touched_high
        };

        inspect(snapshot, pair, threshold);
        require(snapshot.total >= pair.left + pair.right);
    }

    entrypoint function main() {
        Pair start = {left: seed, right: seed + 3};
        Pair alias = start;
        int branch_limit = baseline + 2;

        if (alias.right > 0) {
            branch_limit = alias.right;
        } else if (alias.right == branch_limit) {
            branch_limit = branch_limit + 1;
        } else {
            branch_limit = branch_limit + 2;
        }

        walk(alias, branch_limit);

        require(alias.left == seed);
        require(alias.right == seed + 3);
    }
}
"#;

#[test]
fn debug_session_t_sil_step_over_from_line_39_stays_in_walk() -> Result<(), Box<dyn Error>> {
    let source = DEBUG_STRESS_SOURCE;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;

        let mut steps = 0usize;
        while session.current_span().ok_or("missing current span while seeking line 39")?.line != 39 {
            session.step_over()?.ok_or("expected to reach line 39 in target/t.sil")?;
            steps = steps.saturating_add(1);
            if steps > 32 {
                return Err("failed to reach line 39 in target/t.sil within 32 step_over calls".into());
            }
        }

        let rendered = session
            .debug_info()
            .steps
            .iter()
            .filter(|step| matches!(step.span.line, 36 | 37 | 38 | 39 | 41 | 42 | 80))
            .map(|step| {
                format!(
                    "seq={} kind={:?} line={} depth={} frame={} bc={}..{}",
                    step.sequence, step.kind, step.span.line, step.call_depth, step.frame_id, step.bytecode_start, step.bytecode_end
                )
            })
            .collect::<Vec<_>>();

        session.step_over()?.ok_or("expected a step after line 39")?;
        let next_line = session.current_span().ok_or("missing post-line-39 span")?.line;
        assert_eq!(
            next_line, 41,
            "step_over from target/t.sil line 39 should continue into the loop header, got line {next_line}; relevant steps: {rendered:#?}"
        );
        Ok(())
    })
}

#[test]
fn debug_session_t_sil_step_into_from_line_39_stays_in_walk() -> Result<(), Box<dyn Error>> {
    let source = DEBUG_STRESS_SOURCE;

    with_session_for_source(source, vec![], "main", vec![], |session| {
        session.run_to_first_executed_statement()?;

        let mut steps = 0usize;
        while session.current_span().ok_or("missing current span while seeking line 39")?.line != 39 {
            session.step_over()?.ok_or("expected to reach line 39 in target/t.sil")?;
            steps = steps.saturating_add(1);
            if steps > 32 {
                return Err("failed to reach line 39 in target/t.sil within 32 step_over calls".into());
            }
        }

        let rendered = session
            .debug_info()
            .steps
            .iter()
            .filter(|step| matches!(step.span.line, 36 | 37 | 38 | 39 | 41 | 42 | 80))
            .map(|step| {
                format!(
                    "seq={} kind={:?} line={} depth={} frame={} bc={}..{}",
                    step.sequence, step.kind, step.span.line, step.call_depth, step.frame_id, step.bytecode_start, step.bytecode_end
                )
            })
            .collect::<Vec<_>>();

        session.step_into()?.ok_or("expected a step after line 39")?;
        let next_line = session.current_span().ok_or("missing post-line-39 span")?.line;
        assert_eq!(
            next_line, 41,
            "step_into from target/t.sil line 39 should continue to the loop header, got line {next_line}; relevant steps: {rendered:#?}"
        );
        Ok(())
    })
}

#[test]
fn debug_session_shadow_eval_uses_tx_context_for_covenant_opcode_locals() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract CovLocal() {
    entrypoint function main() {
        byte[32] covid = OpInputCovenantId(this.activeInputIndex);
        require(covid == covid);
    }
}
"#;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], compile_opts)?;
    let debug_info = compiled.debug_info.clone();
    let sigscript = compiled.build_sig_script("main", vec![])?;

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x44u8; 32]), index: 0 },
        signature_script: sigscript.clone(),
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, vec![OpTrue].into()), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);

    let covenant_id = Hash::from_bytes([0x11u8; 32]);
    let utxo_entry =
        UtxoEntry::new(1000, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), Some(covenant_id));
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry]);
    let cov_ctx = CovenantsContext::from_tx(&populated_tx)?;

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx);
    let input_ref = &tx.inputs[0];
    let utxo_ref = populated_tx.utxo(0).ok_or("missing utxo for input 0")?;
    let engine = debugger_session::session::DebugEngine::from_transaction_input(
        &populated_tx,
        input_ref,
        0,
        utxo_ref,
        ctx,
        EngineFlags { covenants_enabled: true },
    );
    let shadow_ctx =
        ShadowTxContext { tx: &populated_tx, input: input_ref, input_index: 0, utxo_entry: utxo_ref, covenants_ctx: &cov_ctx };

    let mut session = DebugSession::full(&sigscript, &compiled.script, source, debug_info, engine)?.with_shadow_tx_context(shadow_ctx);
    session.run_to_first_executed_statement()?;

    for _ in 0..4 {
        if let Ok(covid) = session.variable_by_name("covid") {
            let rendered = format_value(&covid.type_name, &covid.value);
            assert_eq!(rendered, format!("0x{}", "11".repeat(32)));
            return Ok(());
        }
        if session.step_over()?.is_none() {
            break;
        }
    }

    Err("expected covid local to be evaluated using tx context".into())
}

#[test]
fn debug_session_eval_uses_tx_context_for_covenant_expression() -> Result<(), Box<dyn Error>> {
    let source = r#"pragma silverscript ^0.1.0;

contract CovEval() {
    entrypoint function main() {
        require(true);
    }
}
"#;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], compile_opts)?;
    let debug_info = compiled.debug_info.clone();
    let sigscript = compiled.build_sig_script("main", vec![])?;

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x44u8; 32]), index: 0 },
        signature_script: sigscript.clone(),
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, vec![OpTrue].into()), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);

    let covenant_id = Hash::from_bytes([0x22u8; 32]);
    let utxo_entry =
        UtxoEntry::new(1000, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), Some(covenant_id));
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry]);
    let cov_ctx = CovenantsContext::from_tx(&populated_tx)?;

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx);
    let input_ref = &tx.inputs[0];
    let utxo_ref = populated_tx.utxo(0).ok_or("missing utxo for input 0")?;
    let engine = debugger_session::session::DebugEngine::from_transaction_input(
        &populated_tx,
        input_ref,
        0,
        utxo_ref,
        ctx,
        EngineFlags { covenants_enabled: true },
    );

    let shadow_ctx =
        ShadowTxContext { tx: &populated_tx, input: input_ref, input_index: 0, utxo_entry: utxo_ref, covenants_ctx: &cov_ctx };

    let mut session = DebugSession::full(&sigscript, &compiled.script, source, debug_info, engine)?.with_shadow_tx_context(shadow_ctx);
    session.run_to_first_executed_statement()?;

    let (type_name, value) = session.evaluate_expression("OpInputCovenantId(this.activeInputIndex)")?;
    assert_eq!(type_name, "byte[32]");
    assert_eq!(format_value(&type_name, &value), format!("0x{}", "22".repeat(32)));
    Ok(())
}
