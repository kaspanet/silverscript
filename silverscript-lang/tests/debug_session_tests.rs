use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags};

use silverscript_lang::ast::parse_contract_ast;
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::debug::session::DebugSession;

fn example_contract_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("tests/examples/if_statement.sil")
}

fn with_session<F>(mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&mut DebugSession<'_>) -> Result<(), Box<dyn Error>>,
{
    let contract_path = example_contract_path();
    assert!(contract_path.exists(), "example contract not found: {}", contract_path.display());

    let source = fs::read_to_string(&contract_path)?;
    let parsed_contract = parse_contract_ast(&source)?;

    let ctor_args = vec![silverscript_lang::ast::Expr::Int(3), silverscript_lang::ast::Expr::Int(10)];

    assert_eq!(parsed_contract.params.len(), ctor_args.len());

    let compile_opts = CompileOptions { covenants_enabled: true, without_selector: false, record_debug_spans: true };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);

    let flags = EngineFlags { covenants_enabled: compile_opts.covenants_enabled };
    let engine = silverscript_lang::debug::session::DebugEngine::new(ctx, flags);

    let selected_name = "hello".to_string();
    let entry = compiled.abi.iter().find(|entry| entry.name == selected_name).ok_or("function 'hello' not found")?;

    let typed_args = vec![silverscript_lang::ast::Expr::Int(1), silverscript_lang::ast::Expr::Int(2)];

    assert_eq!(entry.inputs.len(), typed_args.len());

    let sigscript = compiled.build_sig_script(&selected_name, typed_args)?;
    let mut session = DebugSession::full(&sigscript, &compiled.script, &source, debug_info, engine)?;

    f(&mut session)
}

#[test]
fn debug_session_provides_source_context_and_vars() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
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
        session.step_statement()?;
        let after = session.state().pc;
        assert!(after > before, "expected pc to advance");
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
