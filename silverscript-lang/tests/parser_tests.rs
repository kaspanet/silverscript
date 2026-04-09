use silverscript_lang::ast::parse_contract_ast;
use silverscript_lang::parser::parse_source_file;

#[test]
fn parses_minimal_contract() {
    let input = r#"
        pragma silverscript ^0.10.0;
        contract Foo(int a) {
            function bar(int b) {
                int x = a + b;
                require(x > 0);
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
}

#[test]
fn parses_timeops_and_console() {
    let input = r#"
        contract TimeLock(pubkey owner) {
            function unlock(sig s) {
                require(this.age >= 10 days, "too early");
                console.log("ok", 1 + 2, checkSig(s, owner));
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
}

#[test]
fn rejects_number_unit_overflow() {
    let input = r#"
        contract TimeLock() {
            entrypoint function main() {
                require(this.age >= 9223372036854775807 weeks);
            }
        }
    "#;

    let err = parse_contract_ast(input).expect_err("unit multiplication overflow should be rejected");
    assert!(err.to_string().contains("overflow"), "unexpected error: {err}");
}

#[test]
fn parses_arrays_and_introspection() {
    let input = r#"
        contract Complex(byte[20] hash) {
            function verify(int idx) {
                int a = [1, 2, 3][0];
                int b = (a * 2).split(1).length;
                int c = tx.outputs[idx].value;
                int d = tx.inputs[idx].outpointIndex;
                require(c >= d);
            }
        }
    "#;

    let result = parse_source_file(input);
    if let Err(err) = result {
        panic!("{}", err);
    }
}

#[test]
fn parses_input_sigscript_and_rejects_output_sigscript() {
    let input_ok = r#"
        contract SigScriptCheck() {
            function verify(int idx) {
                require(tx.inputs[idx].sigScript.length >= 0);
            }
        }
    "#;
    assert!(parse_source_file(input_ok).is_ok());

    let input_bad = r#"
        contract SigScriptCheck() {
            function verify(int idx) {
                // outputs don't have a sigScript field, so parsing is expected to fail
                require(tx.outputs[idx].sigScript.length >= 0);
            }
        }
    "#;
    assert!(parse_contract_ast(input_bad).is_err());
}

#[test]
fn parses_structs_and_field_access() {
    let input = r#"
        contract Structs() {
            struct S {
                int a;
                string b;
            }

            function f(S x) {
                require(x.a == 0);
                require(x.b.length == 5);
            }

            entrypoint function main() {
                S y = {a: 0, b: "hello"};
                f(y);
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
}

#[test]
fn parses_struct_destructuring() {
    let input = r#"
        contract Structs() {
            struct S {
                int a;
                byte[5] b;
            }

            entrypoint function main() {
                S s = {a: 1, b: 0x0102030405};
                {a: int x, b: byte[5] y} = s;
                require(x == 1);
            }
        }
    "#;

    assert!(parse_source_file(input).is_ok());
}

#[test]
fn parses_runtime_bounded_for_syntax() {
    let input = r#"
        contract Decls(int max_outs) {
            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification)]
            function split() {
                int dyn = tx.outputs.length;
                for(i, 0, dyn, max_outs) {
                    require(i >= 0);
                }
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
}

#[test]
fn rejects_malformed_function_attributes() {
    let bad_path_start = r#"
        contract Decls() {
            #[.covenant(binding = auth, from = 1, to = 1, mode = transition)]
            function main() {
                require(true);
            }
        }
    "#;
    assert!(parse_source_file(bad_path_start).is_err());

    let bad_path_double_dot = r#"
        contract Decls() {
            #[covenant..transition(binding = auth, from = 1, to = 1, mode = transition)]
            function main() {
                require(true);
            }
        }
    "#;
    assert!(parse_source_file(bad_path_double_dot).is_err());

    let bad_arg_missing_equals = r#"
        contract Decls(int max_outs) {
            #[covenant(binding, from = 1, to = max_outs, mode = verification)]
            function main() {
                require(max_outs >= 0);
            }
        }
    "#;
    assert!(parse_source_file(bad_arg_missing_equals).is_err());
}

#[test]
fn rejects_invalid_for_arities() {
    let trailing_comma = r#"
        contract Loops() {
            function main() {
                for(i, 0, 1, 2,) {
                    require(i >= 0);
                }
            }
        }
    "#;
    assert!(parse_source_file(trailing_comma).is_err());

    let old_three_arg_syntax = r#"
        contract Loops() {
            function main() {
                for(i, 0, 1) {
                    require(i >= 0);
                }
            }
        }
    "#;
    assert!(parse_source_file(old_three_arg_syntax).is_err());

    let too_few_args = r#"
        contract Loops() {
            function main() {
                for(i, 0) {
                    require(i >= 0);
                }
            }
        }
    "#;
    assert!(parse_source_file(too_few_args).is_err());
}

#[test]
fn rejects_omitting_parentheses_in_tuple_return_signature() {
    let input = r#"
        contract Returns() {
            function pair() : int, int {
                return(1, 2);
            }
        }
    "#;

    assert!(parse_contract_ast(input).is_err());
}

#[test]
fn rejects_omitting_parentheses_in_tuple_return_statement() {
    let input = r#"
        contract Returns() {
            function pair() : (int, int) {
                return 1, 2;
            }
        }
    "#;

    assert!(parse_contract_ast(input).is_err());
}

#[test]
fn parses_tuple_variable_declaration_without_parentheses_as_tuple_assignment_syntax() {
    let input = r#"
        contract Returns() {
            function pair() : (int, int) {
                return(1, 2);
            }

            entrypoint function main() {
                int a, int b = pair();
            }
        }
    "#;

    assert!(parse_contract_ast(input).is_ok());
}
