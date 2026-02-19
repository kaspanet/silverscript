use silverscript_lang::ast::{ExprKind, Statement, parse_contract_ast};

fn assert_span_text(source: &str, actual: &str, expected: &str) {
    let start = source.find(expected).expect("expected text must exist in source");
    let end = start + expected.len();
    assert_eq!(actual, expected);
    assert_eq!(&source[start..end], expected);
}

#[test]
fn populates_contract_function_and_statement_spans() {
    let source = r#"
        contract Foo(int a) {
            function bar(int b):(int) {
                int x = a + b;
                return(x);
            }
        }
    "#;
    let contract = parse_contract_ast(source).expect("contract should parse");

    assert_span_text(source, contract.name_span.as_str(), "Foo");
    assert_span_text(source, contract.functions[0].name_span.as_str(), "bar");
    assert_span_text(source, contract.functions[0].body_span.as_str(), "int x = a + b;\n                return(x);");

    let first_stmt = &contract.functions[0].body[0];
    let Statement::VariableDefinition { span, .. } = first_stmt else {
        panic!("expected first statement to be a variable definition");
    };
    assert_span_text(source, span.as_str(), "int x = a + b;");
}

#[test]
fn populates_slice_expression_spans() {
    let source = r#"
        contract SliceTest() {
            function main(byte[] data) {
                byte[] part = data.slice(1, 3);
            }
        }
    "#;
    let contract = parse_contract_ast(source).expect("contract should parse");
    let stmt = &contract.functions[0].body[0];

    let Statement::VariableDefinition { expr: Some(expr), .. } = stmt else {
        panic!("expected a variable definition with expression");
    };
    let ExprKind::Slice { source: base, start, end, span } = &expr.kind else {
        panic!("expected slice expression");
    };
    let ExprKind::Identifier(_) = &base.kind else {
        panic!("slice source should be an identifier");
    };

    assert_span_text(source, expr.span.as_str(), "data.slice(1, 3)");
    assert_span_text(source, span.as_str(), ".slice(1, 3)");
    assert_span_text(source, base.span.as_str(), "data");
    assert_span_text(source, start.span.as_str(), "1");
    assert_span_text(source, end.span.as_str(), "3");
}

#[test]
fn normalizes_byte_cast_to_byte1_call_in_ast() {
    let source = r#"
        contract CastTest() {
            function main(int a) {
                byte c = byte(a);
            }
        }
    "#;
    let contract = parse_contract_ast(source).expect("contract should parse");
    let stmt = &contract.functions[0].body[0];

    let Statement::VariableDefinition { expr: Some(expr), .. } = stmt else {
        panic!("expected a variable definition with expression");
    };
    let ExprKind::Call { name, args, name_span } = &expr.kind else {
        panic!("expected cast to normalize into a call");
    };

    assert_eq!(name, "byte[1]");
    assert_eq!(args.len(), 1);
    assert_span_text(source, expr.span.as_str(), "byte(a)");
    assert_span_text(source, name_span.as_str(), "byte");
    assert_span_text(source, args[0].span.as_str(), "a");
}
