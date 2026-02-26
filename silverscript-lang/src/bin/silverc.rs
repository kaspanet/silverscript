use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

#[derive(Debug, Parser)]
#[command(
    name = "silverc",
    about = "Compile SilverScript contracts into JSON artifacts",
    long_about = "Compile a SilverScript source file into a compiled JSON artifact, or parse only and emit AST JSON.\n\
\n\
Default Destination: <source>.json (or <source>_ast.json with --ast-only)\n",
    after_help = "Examples:\n\
  silverc contract.sil\n\
  silverc contract.sil -o artifact.json\n\
  silverc contract.sil -c",
    next_line_help = true
)]
struct Cli {
    /// Source SilverScript file (e.g. contract.sil)
    #[arg(value_name = "SOURCE.sil")]
    src: PathBuf,
    /// Path to JSON constructor arguments
    #[arg(visible_alias = "ctor", long = "constructor-args", value_name = "CTOR.json")]
    constructor_args: Option<PathBuf>,
    /// Output file path for JSON output
    #[arg(short = 'o', long = "output", value_name = "FILE.json")]
    out: Option<PathBuf>,
    /// Write JSON output to stdout
    #[arg(short = 'c', long = "stdout")]
    stdout: bool,
    /// Parse source and emit AST JSON without compiling
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

    // both stdout and file output were requested, invalid usage
    if cli.stdout && cli.out.is_some() {
        return Err("invalid usage: both stdout and file output arguments were provided; pick only one".to_string());
    }

    let source = fs::read_to_string(&cli.src).map_err(|err| format!("failed to read {}: {err}", cli.src.display()))?;

    if cli.ast_only {
        let ast = parse_contract_ast(&source).map_err(|err| format!("parse error: {err}"))?;
        let rendered = ast.to_string();
        let target = resolve_output_target(&cli, &cli.src, true);
        emit_output(&rendered, target)?;
        return Ok(());
    }

    let constructor_args = if let Some(path) = &cli.constructor_args {
        let json = fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        serde_json::from_str::<Vec<Expr>>(&json)
            .map_err(|err| format!("failed to parse constructor args {}: {err}", path.display()))?
    } else {
        Vec::new()
    };

    let compiled =
        compile_contract(&source, &constructor_args, CompileOptions::default()).map_err(|err| format!("compile error: {err}"))?;

    let json = serde_json::to_string_pretty(&compiled).map_err(|err| format!("failed to serialize output: {err}"))?;
    let target = resolve_output_target(&cli, &cli.src, false);
    emit_output(&json, target)?;

    Ok(())
}

enum OutputTarget {
    Stdout,
    File(PathBuf),
}

fn resolve_output_target(cli: &Cli, src: &Path, ast_only: bool) -> OutputTarget {
    if cli.stdout {
        return OutputTarget::Stdout;
    }
    if let Some(path) = &cli.out {
        return OutputTarget::File(path.clone());
    }
    OutputTarget::File(default_output_path(src, ast_only))
}

fn emit_output(content: &str, target: OutputTarget) -> Result<(), String> {
    match target {
        OutputTarget::Stdout => {
            println!("{content}");
            Ok(())
        }
        OutputTarget::File(path) => {
            fs::write(&path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
            Ok(())
        }
    }
}

fn default_output_path(src: &Path, ast_only: bool) -> PathBuf {
    if !ast_only {
        return src.with_extension("json");
    }

    let stem = src.file_stem().or_else(|| src.file_name()).unwrap_or(OsStr::new("output"));
    let mut file_name = stem.to_os_string();
    file_name.push("_ast.json");
    src.with_file_name(file_name)
}
