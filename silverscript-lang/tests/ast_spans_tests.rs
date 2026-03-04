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
fn parses_function_attributes_and_bounded_for_ast() {
    let source = r#"
        contract Decls(int max_outs) {
            #[covenant(binding = cov, from = 2, to = max_outs, mode = predicate)]
            function policy() {
                int dyn = tx.outputs.length;
                for(i, 0, dyn, max_outs) {
                    require(i >= 0);
                }
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract should parse");
    let function = &contract.functions[0];
    assert_eq!(function.attributes.len(), 1);

    let attribute = &function.attributes[0];
    assert_eq!(attribute.path, vec!["covenant"]);
    assert_eq!(attribute.args.len(), 4);
    assert_eq!(attribute.args[0].name, "binding");
    assert_eq!(attribute.args[1].name, "from");
    assert_eq!(attribute.args[2].name, "to");
    assert_eq!(attribute.args[3].name, "mode");
    assert_span_text(source, attribute.path_spans[0].as_str(), "covenant");

    let Statement::For { max, .. } = &function.body[1] else {
        panic!("expected second statement to be a for loop");
    };
    let Some(max_expr) = max else {
        panic!("expected bounded for max expression");
    };
    let ExprKind::Identifier(name) = &max_expr.kind else {
        panic!("expected max bound to be an identifier");
    };
    assert_eq!(name, "max_outs");
}

#[test]
fn parses_multiple_and_noarg_function_attributes() {
    let source = r#"
        contract Attrs(int max_outs) {
            #[covenant(binding = auth, from = 1, to = max_outs + 1, mode = predicate)]
            #[experimental]
            function policy() {
                require(true);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract should parse");
    let function = &contract.functions[0];
    assert_eq!(function.attributes.len(), 2);

    let first = &function.attributes[0];
    assert_eq!(first.path, vec!["covenant"]);
    assert_eq!(first.args.len(), 4);
    assert_eq!(first.args[2].name, "to");
    assert_span_text(source, first.args[2].expr.span.as_str(), "max_outs + 1");

    let second = &function.attributes[1];
    assert_eq!(second.path, vec!["experimental"]);
    assert!(second.args.is_empty());
}
