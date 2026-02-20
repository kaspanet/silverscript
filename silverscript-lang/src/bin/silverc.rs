use std::env;
use std::fs;
use std::path::PathBuf;

use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Err(
            "usage: silverc <src.sil> [--constructor-args ctor.json] [-o dst.json] [--dump-ast] [--dump-ast-out ast.json]".to_string()
        );
    }

    let mut src: Option<String> = None;
    let mut ctor_args_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut dump_ast = false;
    let mut dump_ast_out_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dump-ast" => {
                dump_ast = true;
                i += 1;
            }
            "--dump-ast-out" => {
                let value = args.get(i + 1).ok_or_else(|| "--dump-ast-out requires a path".to_string())?;
                dump_ast_out_path = Some(value.clone());
                dump_ast = true;
                i += 2;
            }
            "--constructor-args" => {
                let value = args.get(i + 1).ok_or_else(|| "--constructor-args requires a path".to_string())?;
                ctor_args_path = Some(value.clone());
                i += 2;
            }
            "-o" => {
                let value = args.get(i + 1).ok_or_else(|| "-o requires a path".to_string())?;
                out_path = Some(value.clone());
                i += 2;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option: {value}"));
            }
            value => {
                if src.is_some() {
                    return Err("only one source file is supported".to_string());
                }
                src = Some(value.to_string());
                i += 1;
            }
        }
    }

    let src = src.ok_or_else(|| "missing source file".to_string())?;
    let source = fs::read_to_string(&src).map_err(|err| format!("failed to read {src}: {err}"))?;

    if dump_ast {
        let ast = parse_contract_ast(&source).map_err(|err| format!("parse error: {err}"))?;
        let rendered = ast.to_string();
        if let Some(path) = dump_ast_out_path {
            fs::write(&path, rendered).map_err(|err| format!("failed to write {path}: {err}"))?;
        } else {
            println!("{ast}");
        }
        return Ok(());
    }

    let constructor_args = if let Some(path) = ctor_args_path {
        let json = fs::read_to_string(&path).map_err(|err| format!("failed to read {path}: {err}"))?;
        serde_json::from_str::<Vec<Expr>>(&json).map_err(|err| format!("failed to parse constructor args {path}: {err}"))?
    } else {
        Vec::new()
    };

    let compiled =
        compile_contract(&source, &constructor_args, CompileOptions::default()).map_err(|err| format!("compile error: {err}"))?;

    let output_path = match out_path {
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
