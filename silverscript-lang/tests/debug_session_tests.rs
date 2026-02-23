use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags};

use silverscript_lang::ast::Expr;
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
    let source = fs::read_to_string(&contract_path)?;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(&source, &[Expr::Int(3), Expr::Int(10)], compile_opts)?;

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let flags = EngineFlags { covenants_enabled: true };
    let engine = silverscript_lang::debug::session::DebugEngine::new(ctx, flags);

    let sigscript = compiled.build_sig_script("hello", vec![Expr::Int(5), Expr::Int(5)])?;
    let mut session = DebugSession::full(&sigscript, &compiled.script, &source, compiled.debug_info.clone(), engine)?;

    f(&mut session)
}

#[test]
fn debug_session_lists_entrypoint_params() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        let vars = session.list_variables().expect("variables available");
        let names = vars.iter().map(|var| var.name.as_str()).collect::<HashSet<_>>();
        assert!(names.contains("a"));
        assert!(names.contains("b"));
        Ok(())
    })
}

#[test]
fn debug_session_can_step_mappings() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        let stepped = session.step_statement()?;
        assert!(stepped.is_some(), "expected at least one statement step");
        Ok(())
    })
}

#[test]
fn debug_session_breakpoint_requires_source_spans() -> Result<(), Box<dyn Error>> {
    with_session(|session| {
        session.run_to_first_executed_statement()?;
        assert!(!session.add_breakpoint(7), "line breakpoints should be rejected without span mappings");
        assert!(session.breakpoints().is_empty());
        Ok(())
    })
}
