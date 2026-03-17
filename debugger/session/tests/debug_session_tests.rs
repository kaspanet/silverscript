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

use debugger_session::session::{DebugSession, DebugValue, ShadowTxContext};
use silverscript_lang::ast::{Expr, ExprKind, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
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

    with_session_for_source(source, vec![Expr::int(2)], "main", vec![Expr::int(3)], |session| {
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

    with_session_for_source(source, vec![Expr::int(2)], "main", vec![Expr::int(5)], |session| {
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

    with_session_for_source(source, vec![Expr::int(2)], "main", vec![Expr::int(5)], |session| {
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
        assert_eq!(session.format_value(&x.type_name, &x.value), "4");
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
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

    with_session_for_source(source, vec![], "main", vec![Expr::int(3)], |session| {
        session.run_to_first_executed_statement()?;
        let start = session.current_span().ok_or("missing start span")?;
        assert_eq!(start.line, 10);

        session.step_over()?;
        let mut after_over = session.current_span().ok_or("missing span after step_over")?;
        if after_over.line == 10 {
            // In simplified inline stepping mode we may stop once on the call-site
            // boundary before advancing past the call.
            session.step_over()?;
            after_over = session.current_span().ok_or("missing span after second step_over")?;
        }
        assert_eq!(after_over.line, 11, "step_over should eventually move past inline call");
        let b = session.variable_by_name("b")?;
        assert_eq!(session.format_value(&b.type_name, &b.value), "4", "inline return should resolve against caller params");
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
        let mut after_out = session.current_span().ok_or("missing span after step_out")?;
        if after_out.line == 10 {
            session.step_over()?;
            after_out = session.current_span().ok_or("missing span after post-step_out step_over")?;
        }
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

        assert_eq!(lines, vec![15, 10, 5, 6, 10, 15], "nested inline stepping order regressed");
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

        assert!(lines.starts_with(&[16, 17, 10, 11, 12, 17, 18, 5]), "unexpected inline stepping prefix: {:?}", lines);
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
                    let rendered = session.format_value(&x.type_name, &x.value);
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

        let evaluated = session.evaluate_expression("((y * 2) + (x - 1)) - (y - x)")?;
        assert_eq!(evaluated.type_name, "int");
        assert_eq!(
            session.format_value(&evaluated.type_name, &evaluated.value),
            ((y_value * 2) + (x_value - 1) - (y_value - x_value)).to_string()
        );
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
        assert!(!init_amount.is_constant);

        let bonus = vars.iter().find(|var| var.name == "BONUS").ok_or("missing contract constant")?;
        assert_eq!(bonus.origin.label(), "const");
        assert!(bonus.is_constant);

        let evaluated = session.evaluate_expression("init_amount + BONUS + delta")?;
        assert_eq!(evaluated.type_name, "int");
        assert_eq!(session.format_value(&evaluated.type_name, &evaluated.value), "12");
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
            assert_eq!(session.format_value(&base.type_name, &base.value), "11");
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
            assert_eq!(session.format_value(&amount.type_name, &amount.value), "11");

            let delta = session.variable_by_name("delta")?;
            assert_eq!(session.format_value(&delta.type_name, &delta.value), "3");

            let values = session.variable_by_name("values")?;
            assert_eq!(session.format_value(&values.type_name, &values.value), "[4, 5]");

            let base = session.variable_by_name("base")?;
            assert_eq!(session.format_value(&base.type_name, &base.value), "15");

            let after = session.variable_by_name("after")?;
            assert_eq!(session.format_value(&after.type_name, &after.value), "20");

            Ok(())
        },
    )
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
        let start = session.current_span().ok_or("missing start span")?;
        assert_eq!(start.line, 15);

        session.step_over()?;
        let mut after_over = session.current_span().ok_or("missing span after step_over")?;
        if after_over.line == 15 {
            session.step_over()?;
            after_over = session.current_span().ok_or("missing span after second step_over")?;
        }
        assert_eq!(after_over.line, 16, "step_over should move past nested inline call in caller");
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
                assert_eq!(session.format_value(&i.type_name, &i.value), "0");
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
            let rendered = session.format_value(&covid.type_name, &covid.value);
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

    let evaluated = session.evaluate_expression("OpInputCovenantId(this.activeInputIndex)")?;
    assert_eq!(evaluated.type_name, "byte[32]");
    assert_eq!(session.format_value(&evaluated.type_name, &evaluated.value), format!("0x{}", "22".repeat(32)));
    Ok(())
}
