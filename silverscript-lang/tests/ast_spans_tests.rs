use silverscript_lang::ast::visit::{AstVisitorMut, NameKind, visit_contract_mut, visit_function_mut};
use silverscript_lang::ast::{
    ExprKind, FunctionAst, Statement, TypeBase, parse_contract_ast, parse_expression_ast, parse_function_ast, parse_statement_ast,
};
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

struct SpanResetter;

#[derive(Debug, PartialEq, Eq)]
struct TypeOccurrence {
    type_name: String,
    base_name: String,
    span_prefix: String,
}

#[derive(Default)]
struct TypeOccurrenceCollector {
    occurrences: Vec<TypeOccurrence>,
}

#[derive(Default)]
struct TypeSourceCollector {
    occurrences: Vec<(String, String)>,
    call_targets: Vec<String>,
}

#[derive(Default)]
struct SyntheticMetadataCollector {
    type_names: Vec<(String, bool)>,
    attribute_path_segments: Vec<(String, bool)>,
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
fn parses_standalone_statements_with_original_source_spans() {
    let source = "  /* before */ value = (signed(value) + signed(step)) as byte; // after\n";
    let statement = parse_statement_ast(source).expect("standalone statement should parse");

    let Statement::Assign { name, expr, span, name_span } = statement else {
        panic!("expected an assignment");
    };
    assert_eq!(name, "value");
    assert_eq!(span.as_str(), "value = (signed(value) + signed(step)) as byte;");
    assert_eq!(name_span.as_str(), "value");
    assert_eq!(expr.span.as_str(), "(signed(value) + signed(step)) as byte");
    assert_eq!(span.get_input(), source);
    assert_eq!(name_span.get_input(), source);
    assert_eq!(expr.span.get_input(), source);
}

#[test]
fn parses_supported_standalone_statement_shapes() {
    let sources = [
        "int value = 1;",
        "CounterState { value: int current } = readInputState(0);",
        "{ int value = 1; value = 2; }",
        "if (ready) { value = 1; } else value = 2;",
    ];

    for source in sources {
        parse_statement_ast(source).unwrap_or_else(|err| panic!("`{source}` should parse as one statement: {err}"));
    }
}

#[test]
fn rejects_incomplete_or_multiple_standalone_statements() {
    for source in ["", "value = 1", "value = 1; other = 2;", "value + 1"] {
        assert!(parse_statement_ast(source).is_err(), "`{source}` must not parse as exactly one statement");
    }
}

impl<'i> AstVisitorMut<'i> for SpanResetter {
    fn visit_span(&mut self, span: &mut Span<'i>) {
        *span = Span::default();
    }
}

impl<'i> AstVisitorMut<'i> for TypeOccurrenceCollector {
    fn visit_type(&mut self, type_ref: &silverscript_lang::ast::TypeRef, span: Span<'i>) {
        let TypeBase::Custom(base_name) = &type_ref.base else {
            panic!("fixture only contains custom type sites");
        };
        let span_prefix = span
            .get_input()
            .get(span.start()..span.start() + base_name.len())
            .expect("custom type name should fit within the source")
            .to_string();
        self.occurrences.push(TypeOccurrence { type_name: type_ref.type_name(), base_name: base_name.to_string(), span_prefix });
    }

    fn visit_span(&mut self, span: &mut Span<'i>) {
        *span = Span::default();
    }
}

impl<'i> AstVisitorMut<'i> for TypeSourceCollector {
    fn visit_name(&mut self, name: &mut String, kind: NameKind, _span: Span<'i>) {
        if kind == NameKind::CallTarget {
            self.call_targets.push(name.clone());
        }
    }

    fn visit_type(&mut self, type_ref: &silverscript_lang::ast::TypeRef, span: Span<'i>) {
        self.occurrences.push((type_ref.type_name(), span.as_str().to_string()));
    }

    fn visit_span(&mut self, span: &mut Span<'i>) {
        *span = Span::default();
    }
}

impl<'i> AstVisitorMut<'i> for SyntheticMetadataCollector {
    fn visit_name(&mut self, name: &mut String, kind: NameKind, span: Span<'i>) {
        if kind == NameKind::AttributePathSegment {
            self.attribute_path_segments.push((name.clone(), span == Span::default()));
        }
    }

    fn visit_type(&mut self, type_ref: &silverscript_lang::ast::TypeRef, span: Span<'i>) {
        self.type_names.push((type_ref.type_name(), span == Span::default()));
    }
}

#[test]
fn visits_deserialized_function_metadata_without_source_spans() {
    let source = "#[covenant.singleton] function inspect() : (LeftResult, RightResult) {}";
    let function = parse_function_ast(source).expect("function metadata fixture should parse");
    let serialized = serde_json::to_string(&function).expect("function AST should serialize");
    let mut function: FunctionAst<'_> = serde_json::from_str(&serialized).expect("function AST should deserialize");
    let mut collector = SyntheticMetadataCollector::default();

    visit_function_mut(&mut collector, &mut function);

    assert_eq!(
        collector.type_names,
        [("LeftResult", true), ("RightResult", true)].map(|(name, synthetic)| (name.to_string(), synthetic))
    );
    assert_eq!(
        collector.attribute_path_segments,
        [("covenant", true), ("singleton", true)].map(|(name, synthetic)| (name.to_string(), synthetic))
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
fn visits_as_cast_targets_as_types_before_mutating_their_spans() {
    let source = "value as CounterState[]";
    let mut expr = parse_expression_ast(source).expect("as-cast expression should parse");
    let mut collector = TypeSourceCollector::default();

    collector.visit_expr(&mut expr);

    assert_eq!(collector.occurrences, vec![("CounterState[]".to_string(), "CounterState[]".to_string())]);
    assert!(collector.call_targets.is_empty(), "the internal cast name must not be exposed as a call target");
    let ExprKind::Call { name_span, .. } = expr.kind else {
        panic!("as cast should use the internal call representation");
    };
    assert!(name_span.as_str().is_empty(), "the stored cast type span must still be visited independently");
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
fn exposes_exact_spans_for_struct_types_and_typed_arrays() {
    let source = r#"function inspect() {
        CounterState   {value: int current} = readInputState(0);
        CounterState   {value: int copy} = current_state;
        CounterState[] values = CounterState[]   {CounterState {value: 1}};
    }"#;
    let mut function = parse_function_ast(source).expect("standalone function should parse");

    let Statement::StateFunctionCallAssign { target_struct, target_struct_span, .. } = &function.body[0] else {
        panic!("expected a state function call assignment");
    };
    assert_eq!(target_struct, "CounterState");
    assert_eq!(target_struct_span.as_str(), "CounterState");

    let Statement::StructDestructure { struct_name, struct_name_span, .. } = &function.body[1] else {
        panic!("expected a struct destructure assignment");
    };
    assert_eq!(struct_name, "CounterState");
    assert_eq!(struct_name_span.as_str(), "CounterState");

    let Statement::VariableDefinition { expr: Some(expr), .. } = &function.body[2] else {
        panic!("expected a variable definition with an initializer");
    };
    let ExprKind::Array { type_span, .. } = &expr.kind else {
        panic!("expected a typed array expression");
    };
    assert_eq!(type_span.as_str(), "CounterState[]");

    visit_function_mut(&mut SpanResetter, &mut function);
    let Statement::StateFunctionCallAssign { target_struct_span, .. } = &function.body[0] else {
        unreachable!("statement shape was already checked");
    };
    let Statement::StructDestructure { struct_name_span, .. } = &function.body[1] else {
        unreachable!("statement shape was already checked");
    };
    let Statement::VariableDefinition { expr: Some(expr), .. } = &function.body[2] else {
        unreachable!("statement shape was already checked");
    };
    let ExprKind::Array { type_span, .. } = &expr.kind else {
        unreachable!("expression shape was already checked");
    };
    assert!(target_struct_span.as_str().is_empty());
    assert!(struct_name_span.as_str().is_empty());
    assert!(type_span.as_str().is_empty());
}

#[test]
fn type_spans_start_at_the_base_type_after_leading_trivia() {
    let source = r#"function inspect(
        /* before scalar */ ScalarType /* before name */ scalar,
        /* before array */ ArrayType /* before suffix */ [] /* before name */ values
    ) {}"#;
    let function = parse_function_ast(source).expect("type-span fixture should parse");

    for param in &function.params {
        let TypeBase::Custom(name) = &param.type_ref.base else {
            panic!("fixture should use custom types");
        };
        let start = param.type_span.start();
        let authored_name = source.get(start..start + name.len()).expect("type name should fit within its source");

        assert_eq!(authored_name, name);
    }
}

#[test]
fn contract_traversal_classifies_struct_names() {
    let source = "contract Container() { struct Item { int value; } }";
    let mut contract = parse_contract_ast(source).expect("struct-name fixture should parse");
    let mut collector = NameOccurrenceCollector::default();

    visit_contract_mut(&mut collector, &mut contract);

    assert_eq!(
        collector.occurrences,
        [("Container", NameKind::Contract), ("Item", NameKind::Struct), ("value", NameKind::StructField),]
            .into_iter()
            .map(|(name, kind)| NameOccurrence { name: name.to_string(), kind, source: name.to_string() })
            .collect::<Vec<_>>()
    );
}

#[test]
fn visits_every_classified_type_site_before_mutating_its_span() {
    let source = r#"contract Inspect(/* leading */ ContractParam /* separator */ ctor) {
        struct Wrapper {
            StructFieldType field;
        }

        ContractFieldType stored = ContractFieldCtor { count: 0 };
        ConstantType constant initial = ConstantCtor { count: 0 };

        function inspect(FunctionParam param) : ReturnType {
            NestedResult nested = wrap(
                flag
                    ? OuterCtor { items: NestedArray[]{ InnerCtor { count: 1 } } }
                    : FallbackCtor { count: 0 }
            );
            VariableType local = VariableCtor { count: 1 };
            TupleLeft left, TupleRight right = pair();
            (CallBinding output) = identity(local);
            StateOwner { count: StateBinding from_call } = readInputState(0);
            DestructureOwner { count: DestructureBinding copy } = local;
            DeclaredArray[] values = LiteralArray[]{ ArrayElementCtor { count: 1 } };
            return(local);
        }
    }"#;
    let mut contract = parse_contract_ast(source).expect("type-site fixture should parse");
    let mut collector = TypeOccurrenceCollector::default();

    visit_contract_mut(&mut collector, &mut contract);

    let expected = [
        ("ContractParam", "ContractParam", "ContractParam"),
        ("StructFieldType", "StructFieldType", "StructFieldType"),
        ("ContractFieldType", "ContractFieldType", "ContractFieldType"),
        ("ContractFieldCtor", "ContractFieldCtor", "ContractFieldCtor"),
        ("ConstantType", "ConstantType", "ConstantType"),
        ("ConstantCtor", "ConstantCtor", "ConstantCtor"),
        ("ReturnType", "ReturnType", "ReturnType"),
        ("FunctionParam", "FunctionParam", "FunctionParam"),
        ("NestedResult", "NestedResult", "NestedResult"),
        ("OuterCtor", "OuterCtor", "OuterCtor"),
        ("NestedArray[]", "NestedArray", "NestedArray"),
        ("InnerCtor", "InnerCtor", "InnerCtor"),
        ("FallbackCtor", "FallbackCtor", "FallbackCtor"),
        ("VariableType", "VariableType", "VariableType"),
        ("VariableCtor", "VariableCtor", "VariableCtor"),
        ("TupleLeft", "TupleLeft", "TupleLeft"),
        ("TupleRight", "TupleRight", "TupleRight"),
        ("CallBinding", "CallBinding", "CallBinding"),
        ("StateOwner", "StateOwner", "StateOwner"),
        ("StateBinding", "StateBinding", "StateBinding"),
        ("DestructureOwner", "DestructureOwner", "DestructureOwner"),
        ("DestructureBinding", "DestructureBinding", "DestructureBinding"),
        ("DeclaredArray[]", "DeclaredArray", "DeclaredArray"),
        ("LiteralArray[]", "LiteralArray", "LiteralArray"),
        ("ArrayElementCtor", "ArrayElementCtor", "ArrayElementCtor"),
    ];
    assert_eq!(
        collector.occurrences,
        expected
            .into_iter()
            .map(|(type_name, base_name, span_prefix)| TypeOccurrence {
                type_name: type_name.to_string(),
                base_name: base_name.to_string(),
                span_prefix: span_prefix.to_string(),
            })
            .collect::<Vec<_>>()
    );
    assert!(contract.structs[0].fields[0].type_span.as_str().is_empty(), "contract traversal must visit struct-field spans");
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
