use std::fs;
use std::path::PathBuf;

use clap::Parser;
use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

#[derive(Debug, Parser)]
#[command(name = "silverc", about = "Compile SilverScript contracts into JSON artifacts")]
struct Cli {
    /// Source SilverScript file (e.g. contract.sil)
    src: String,
    /// Path to JSON constructor arguments
    #[arg(long = "constructor-args", value_name = "ctor.json")]
    constructor_args: Option<String>,
    /// Output file path for compiled artifact
    #[arg(short = 'o', value_name = "dst.json")]
    out: Option<String>,
    /// Parse source and print the contract AST
    #[arg(long = "ast-only")]
    ast_only: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) if err.use_stderr() => return Err(err.to_string()),
        Err(err) => {
            err.print().map_err(|print_err| format!("failed to print clap output: {print_err}"))?;
            return Ok(());
        }
    };

    let src = cli.src;
    let source = fs::read_to_string(&src).map_err(|err| format!("failed to read {src}: {err}"))?;
    let ast_only = cli.ast_only;

    if ast_only {
        let ast = parse_contract_ast(&source).map_err(|err| format!("parse error: {err}"))?;
        let rendered = ast.to_string();

        println!("{ast}");

        if let Some(path) = cli.out {
            fs::write(&path, rendered).map_err(|err| format!("failed to write {path}: {err}"))?;
        }
        return Ok(());
    }

    let constructor_args = if let Some(path) = cli.constructor_args {
        let json = fs::read_to_string(&path).map_err(|err| format!("failed to read {path}: {err}"))?;
        serde_json::from_str::<Vec<Expr>>(&json).map_err(|err| format!("failed to parse constructor args {path}: {err}"))?
    } else {
        Vec::new()
    };

    let compiled =
        compile_contract(&source, &constructor_args, CompileOptions::default()).map_err(|err| format!("compile error: {err}"))?;

    let output_path = match cli.out {
        Some(path) => PathBuf::from(path),
        None => default_output_path(&src),
    };

    let json = serde_json::to_string_pretty(&compiled).map_err(|err| format!("failed to serialize output: {err}"))?;
    fs::write(&output_path, json).map_err(|err| format!("failed to write {}: {err}", output_path.display()))?;

    Ok(())
}

fn default_output_path(src: &str) -> PathBuf {
    if let Some(stripped) = src.strip_suffix(".sil") {
        PathBuf::from(format!("{stripped}.json"))
    } else {
        PathBuf::from(format!("{src}.json"))
    }
}
