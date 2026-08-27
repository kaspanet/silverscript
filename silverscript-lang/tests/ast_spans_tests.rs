use silverscript_lang::ast::visit::{AstVisitorMut, NameKind, visit_function_mut};
use silverscript_lang::ast::{ExprKind, Statement, parse_contract_ast, parse_expression_ast, parse_function_ast};
use silverscript_lang::span::Span;

fn assert_span_text(source: &str, actual: &str, expected: &str) {
    let start = source.find(expected).expect("expected text must exist in source");
    let end = start + expected.len();
    assert_eq!(actual, expected);
    assert_eq!(&source[start..end], expected);
}

#[derive(Debug, PartialEq, Eq)]
struct NameOccurrence {
    name: String,
    kind: NameKind,
    source: String,
}

#[derive(Default)]
struct NameOccurrenceCollector {
    occurrences: Vec<NameOccurrence>,
}

impl<'i> AstVisitorMut<'i> for NameOccurrenceCollector {
    fn visit_name(&mut self, name: &mut String, kind: NameKind, span: Span<'i>) {
        self.occurrences.push(NameOccurrence { name: name.clone(), kind, source: span.as_str().to_string() });
    }
}

#[test]
fn parses_standalone_functions_and_visits_name_spans() {
    let source = r#"function inspect(Turn turn) : int {
        int value = helper(turn.cycles);
        int left, int right = pair();
        (int total) = sum(left, right);
        value = value + 1;
        return(total);
    }"#;
    let mut function = parse_function_ast(source).expect("standalone function should parse");
    let mut collector = NameOccurrenceCollector::default();
    visit_function_mut(&mut collector, &mut function);

    assert_eq!(
        collector.occurrences,
        vec![
            NameOccurrence { name: "inspect".to_string(), kind: NameKind::Function, source: "inspect".to_string() },
            NameOccurrence { name: "turn".to_string(), kind: NameKind::Parameter, source: "turn".to_string() },
            NameOccurrence { name: "value".to_string(), kind: NameKind::LocalBinding, source: "value".to_string() },
            NameOccurrence { name: "helper".to_string(), kind: NameKind::CallTarget, source: "helper".to_string() },
            NameOccurrence { name: "turn".to_string(), kind: NameKind::IdentifierExpr, source: "turn".to_string() },
            NameOccurrence { name: "cycles".to_string(), kind: NameKind::StateField, source: "cycles".to_string() },
            NameOccurrence { name: "left".to_string(), kind: NameKind::LocalBinding, source: "left".to_string() },
            NameOccurrence { name: "right".to_string(), kind: NameKind::LocalBinding, source: "right".to_string() },
            NameOccurrence { name: "pair".to_string(), kind: NameKind::CallTarget, source: "pair".to_string() },
            NameOccurrence { name: "sum".to_string(), kind: NameKind::CallTarget, source: "sum".to_string() },
            NameOccurrence { name: "total".to_string(), kind: NameKind::LocalBinding, source: "total".to_string() },
            NameOccurrence { name: "left".to_string(), kind: NameKind::IdentifierExpr, source: "left".to_string() },
            NameOccurrence { name: "right".to_string(), kind: NameKind::IdentifierExpr, source: "right".to_string() },
            NameOccurrence { name: "value".to_string(), kind: NameKind::AssignmentTarget, source: "value".to_string() },
            NameOccurrence { name: "value".to_string(), kind: NameKind::IdentifierExpr, source: "value".to_string() },
            NameOccurrence { name: "total".to_string(), kind: NameKind::IdentifierExpr, source: "total".to_string() },
        ]
    );
}

#[test]
fn composed_expression_spans_remain_syntactically_complete() {
    let sources = [
        "(signed(next_status) + signed(increment)) as byte",
        "(value).field",
        "(values)[index]",
        "(values)[index].length",
        "(value).length",
        "(left + right) * factor",
        "left + (right * factor)",
    ];

    for source in sources {
        let expr = parse_expression_ast(source).unwrap_or_else(|err| panic!("`{source}` should parse: {err}"));
        assert_eq!(expr.span.as_str(), source, "composite expression span should be valid and complete");
    }
}

#[test]
fn redundant_parentheses_do_not_widen_identifier_name_spans() {
    let mut expr = parse_expression_ast("((value))").expect("parenthesized identifier should parse");
    let mut collector = NameOccurrenceCollector::default();
    collector.visit_expr(&mut expr);

    assert_eq!(expr.span.as_str(), "value");
    assert_eq!(
        collector.occurrences,
        vec![NameOccurrence { name: "value".to_string(), kind: NameKind::IdentifierExpr, source: "value".to_string() }]
    );
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
fn parses_function_attributes_and_for_ast() {
    let source = r#"
        contract Decls(int max_outs) {
            #[covenant(binding = cov, from = 2, to = max_outs, mode = verification)]
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
}

#[test]
fn parses_multiple_and_noarg_function_attributes() {
    let source = r#"
        contract Attrs(int max_outs) {
            #[covenant(binding = auth, from = 1, to = max_outs + 1, mode = verification)]
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
