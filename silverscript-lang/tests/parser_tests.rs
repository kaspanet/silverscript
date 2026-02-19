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
                require(tx.outputs[idx].sigScript.length >= 0);
            }
        }
    "#;
    assert!(parse_source_file(input_bad).is_err());
}
