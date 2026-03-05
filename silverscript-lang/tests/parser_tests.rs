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
                console.log("ok", 1, true);
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
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
    assert!(parse_source_file(input_bad).is_err());
}

#[test]
fn rejects_bounded_for_syntax() {
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
    assert!(result.is_err());
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
                for(i, 0, 1,) {
                    require(i >= 0);
                }
            }
        }
    "#;
    assert!(parse_source_file(trailing_comma).is_err());

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
