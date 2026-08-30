use silverscript_lang::ast::{Expr, ExprKind, Span, format_contract_ast, parse_contract_ast, parse_expression_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract, compile_contract_ast, sil_abi_artifact_from_compiled};

fn assert_compiled_formatted_contract_preserves_ast(source: &str, options: CompileOptions) {
    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    let compiled = compile_contract(&formatted, &[], options).expect("formatted contract compiles");

    assert_eq!(
        serde_json::to_value(&compiled.ast).expect("serialize compiled ast"),
        serde_json::to_value(&ast).expect("serialize original ast")
    );
}

fn parsed_string(source: &str) -> String {
    match parse_expression_ast(source).expect("string expression parses").kind {
        ExprKind::String(value) => value,
        kind => panic!("expected string expression, got {kind:?}"),
    }
}

#[test]
fn rejects_single_quoted_string_literals() {
    for source in ["'text'", r#"'It\'s working'"#] {
        assert!(parse_expression_ast(source).is_err(), "single-quoted string should fail: {source}");
    }
}

#[test]
fn documented_newline_escape_decodes_to_one_byte() {
    let value = parsed_string(r#""\n""#);
    assert_eq!(value.as_bytes(), &[0x0a]);
}

#[test]
fn string_parser_decodes_complete_json_escape_matrix() {
    let value = parsed_string(r#""\b\f\n\r\t\\\/\"\u0041\u00df\u6771\uD834\uDD1E""#);
    assert_eq!(value, "\u{8}\u{c}\n\r\t\\/\"Aß東𝄞");
    assert_eq!(parsed_string(r#""ends\\""#), "ends\\");
}

#[test]
fn string_parser_rejects_malformed_json_escapes() {
    for source in [r#""\x41""#, r#""\u12""#, r#""\uD800""#] {
        assert!(parse_expression_ast(source).is_err(), "malformed escape should fail: {source}");
    }
}

#[test]
fn string_formatter_round_trips_decoded_escapes() {
    let source = r#"
        contract Escapes() {
            entry main() {
                string value = "line\n\t\"quoted\"\\end\\";
                require(value.length > 0, "message\r\n");
            }
        }
    "#;
    let ast = parse_contract_ast(source).expect("escaped contract parses");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted escaped contract reparses");

    assert!(formatted.contains(r#"\n\t\"quoted\"\\end\\"#));
    assert_eq!(format_contract_ast(&reparsed), formatted);
}

#[test]
fn formatted_string_preserves_a_literal_backslash_before_quote() {
    let source = r#"
        contract Escapes() {
            string constant VALUE = "\\\"";

            entry main() {
                require(VALUE.length == 2);
            }
        }
    "#;
    let ast = parse_contract_ast(source).expect("source parses");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted source parses");

    let ExprKind::String(original) = &ast.constants[0].expr.kind else { panic!("original constant must be a string") };
    let ExprKind::String(round_tripped) = &reparsed.constants[0].expr.kind else { panic!("reparsed constant must be a string") };
    assert_eq!(
        round_tripped, original,
        "formatting must not consume a literal backslash before a quote; formatted source:\n{formatted}"
    );
}

#[test]
fn formats_contract_ast_into_canonical_silverscript() {
    let source = r#"
contract Pretty(sig s, pubkey pk){
int constant LIMIT=3;
byte[2] seed=byte[_](0x1234);
entry main(int x):(int, int){
int total=(x+LIMIT)*2;
int[] values=int[]{1,2,3};
values = values.append(total);
if(x>0&&x<LIMIT){
require(checkSig(s,pk), "ok");
}else{
require(tx.outputs[0].value>=total);
}
return(total, values[0]);
}
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);

    let expected = r#"contract Pretty(sig s, pubkey pk) {
    int constant LIMIT = 3;

    byte[2] seed = byte[2](0x1234);

    entry main(int x): (int, int) {
        int total = (x + LIMIT) * 2;
        int[] values = int[]{1, 2, 3};
        values = values.append(total);
        if (x > 0 && x < LIMIT) {
            require(checkSig(s, pk), "ok");
        } else {
            require(tx.outputs[0].value >= total);
        }
        return(total, values[0]);
    }
}
"#;

    assert_eq!(formatted, expected);
}

#[test]
fn formats_as_byte_conversion() {
    let source = r#"contract Convert() {
    entry main(int x) {
        byte[_] encoded = (x + 1) as byte[4];
        require(encoded.length == 4);
    }
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    assert!(formatted.contains("byte[_] encoded = (x + 1) as byte[4];"));
    parse_contract_ast(&formatted).expect("formatted conversion parses");
}

#[test]
fn formatted_contracts_parse_back_to_same_canonical_source() {
    let source = r#"
contract Advanced(int limit, pubkey owner) {
    int balance = 10;

    function compute(int x): (int, int) {
        int left = x + balance;
        int right = left * 2;
        return(left, right);
    }

    entry main() {
        (int left, int right) = compute(1 + 2 * 3);
        State {balance: int current} = readState();
        int[] values = int[]{1, 2};
        values = values.append(current);
        byte[] tail = this.activeScriptPubKey.slice(1, this.activeScriptPubKey.length);
        validateOutputState(0, State {balance: current});
        for (i, 0, limit, limit) {
            console.log("loop", i + current);
        }
        balance = current;
        require(this.ageDaa >= 10, "age");
        return(tail.split(1).1);
    }
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted output parses");
    let reformatted = format_contract_ast(&reparsed);

    assert_eq!(reformatted, formatted);
    assert!(formatted.contains("State {balance: int current} = readState();"));
    assert!(formatted.contains("byte[] tail = this.activeScriptPubKey.slice(1, this.activeScriptPubKey.length);"));
    assert!(formatted.contains("return(tail.split(1).1);"));
}

#[test]
fn formats_g16_verify_call() {
    let source = r#"contract Groth16(byte[] verifying_key, byte[] proof, byte[32] public_input) {
    entry verify() {
        g16.verify(verifying_key, proof, public_input);
    }
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);

    assert!(formatted.contains("g16.verify(verifying_key, proof, public_input);"));
}

#[test]
fn compiled_formatted_contract_preserves_exact_ast_for_basic_contract() {
    let source = r#"contract ExactBasic() {
    int constant LIMIT = 3;

    int balance = 10;

    function compute(int x): (int, int) {
        int left = x + balance;
        int right = left * LIMIT;
        return(left, right);
    }

    entry main() {
        int input = 1 + 2;
        (int left, int right) = compute(input);
        require(left < right, "ordered");
        console.log("pair", LIMIT + input);
    }
}
"#;

    assert_compiled_formatted_contract_preserves_ast(source, CompileOptions::default());
}

#[test]
fn compiled_formatted_contract_preserves_exact_ast_with_state_and_return() {
    let source = r#"contract ExactState() {
    int amount = 7;

    entry main(): (byte[]) {
        State {amount: int current} = readInputState(this.activeInputIndex);
        byte[] tail = this.activeScriptPubKey.slice(1, this.activeScriptPubKey.length);
        validateOutputState(0, State {amount: current});
        require(this.ageDaa >= 10, "age");
        return(tail.split(1).1);
    }
}
"#;

    assert_compiled_formatted_contract_preserves_ast(
        source,
        CompileOptions { allow_entrypoint_return: true, ..CompileOptions::default() },
    );
}

#[test]
fn formats_function_attributes_and_preserves_compilation() {
    let source = r#"contract Decls(int max_outs) {
    #[covenant(binding = auth, from = 1, to = max_outs, mode = verification)]
    function spend(int amount) {
        require(amount >= 0);
    }
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted attributes parse");

    assert!(formatted.contains("#[covenant(binding = auth, from = 1, to = max_outs, mode = verification)]"));
    assert_eq!(
        serde_json::to_value(&reparsed).expect("serialize reparsed ast"),
        serde_json::to_value(&ast).expect("serialize original ast")
    );

    let args = [Expr::int(3)];
    let from_source = compile_contract(source, &args, CompileOptions::default()).expect("source compiles");
    let direct = compile_contract_ast(&ast, &args, CompileOptions::default()).expect("direct AST compiles");
    let round_tripped =
        compile_contract_ast(&reparsed, &args, CompileOptions::default()).expect("formatted and reparsed AST compiles");
    let from_source_artifact = sil_abi_artifact_from_compiled(&from_source, &args).expect("source artifact builds");
    let direct_artifact = sil_abi_artifact_from_compiled(&direct, &args).expect("direct AST artifact builds");
    let round_tripped_artifact =
        sil_abi_artifact_from_compiled(&round_tripped, &args).expect("formatted and reparsed AST artifact builds");
    assert_eq!(from_source_artifact, direct_artifact);
    assert_eq!(direct_artifact, round_tripped_artifact);
}

#[test]
fn formats_no_arg_and_qualified_function_attributes() {
    let source = r#"contract Attributes() {
    #[covenant.delegate]
    function delegate() {
        require(true);
    }

    #[covenant.allow(rule = manual_entrypoint_in_leader_contract)]
    entry recover() {
        require(true);
    }
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted attributes parse");

    assert!(formatted.contains("#[covenant.delegate]\n"));
    assert!(formatted.contains("#[covenant.allow(rule = manual_entrypoint_in_leader_contract)]\n"));
    assert_eq!(
        serde_json::to_value(&reparsed).expect("serialize reparsed ast"),
        serde_json::to_value(&ast).expect("serialize original ast")
    );
}

#[test]
fn synthetic_items_preserve_ast_vector_order_after_formatting() {
    let source = r#"contract Generated() {
    int first = 1;

    entry spend() {
        require(first == 1);
    }
}
"#;

    let mut ast = parse_contract_ast(source).expect("parse succeeds");
    let mut synthetic_field = ast.fields[0].clone();
    synthetic_field.name = "second".to_string();
    synthetic_field.expr = Expr::int(2);
    synthetic_field.span = Span::default();
    synthetic_field.type_span = Span::default();
    synthetic_field.name_span = Span::default();
    ast.fields.push(synthetic_field);

    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted mixed-source AST parses");
    assert_eq!(reparsed.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), vec!["first", "second"]);

    let direct = compile_contract_ast(&ast, &[], CompileOptions::default()).expect("direct mixed-source AST compiles");
    let round_tripped =
        compile_contract_ast(&reparsed, &[], CompileOptions::default()).expect("formatted and reparsed mixed-source AST compiles");
    let direct_artifact = sil_abi_artifact_from_compiled(&direct, &[]).expect("direct mixed-source AST artifact builds");
    let round_tripped_artifact =
        sil_abi_artifact_from_compiled(&round_tripped, &[]).expect("formatted and reparsed mixed-source AST artifact builds");
    assert_eq!(direct_artifact, round_tripped_artifact);
}
