use std::fs;

use silverscript_lang::ast::ContractAst;
use silverscript_lang::compiler::{CompileOptions, compile_contract, compile_contract_ast};

fn load_ast(name: &str) -> ContractAst {
    let path = format!("{}/tests/ast_json/{name}", env!("CARGO_MANIFEST_DIR"));
    let json = fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    serde_json::from_str(&json).unwrap_or_else(|err| panic!("failed to parse {path}: {err}"))
}

#[test]
fn compiles_from_ast_json_require() {
    let ast = load_ast("require_test.ast.json");
    let compiled_from_ast = compile_contract_ast(&ast, &[], CompileOptions::default()).expect("compile from AST succeeds");

    let source = r#"
        contract Test() {
            entrypoint function main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;
    let compiled_from_source = compile_contract(source, &[], CompileOptions::default()).expect("compile from source succeeds");

    assert_eq!(compiled_from_ast.script, compiled_from_source.script);
}

#[test]
fn compiles_from_ast_json_yield() {
    let ast = load_ast("yield_test.ast.json");
    let options = CompileOptions { allow_yield: true, ..CompileOptions::default() };
    let compiled_from_ast = compile_contract_ast(&ast, &[], options).expect("compile from AST succeeds");

    let source = r#"
        contract YieldTest() {
            entrypoint function main() {
                int x = 5;
                yield(x + 2);
            }
        }
    "#;
    let compiled_from_source = compile_contract(source, &[], options).expect("compile from source succeeds");

    assert_eq!(compiled_from_ast.script, compiled_from_source.script);
}
