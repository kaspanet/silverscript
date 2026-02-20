use silverscript_lang::ast::parse_contract_ast;
use silverscript_lang::errors::{CompilerError, ParseErrorInterpretation};

#[test]
fn full_diagnostic_from_missing_semicolon() {
    let source = r#"
        contract Foo() {
            function bar(byte[] data) {
                int x = a + b
                int t = x + a;
            }
        }
    "#;
    let err = parse_contract_ast(source).expect_err("source without semicolon must fail parsing");
    let CompilerError::Parse(diagnostic) = err else {
        panic!("expected parse error");
    };
    assert_eq!(diagnostic.interpretation(), ParseErrorInterpretation::MissingSemicolon);
    assert_eq!(diagnostic.code(), "missing_semicolon");
    assert_eq!(diagnostic.expected_tokens(), ["WHITESPACE", "/*", "//", ";"]);
    assert_eq!(diagnostic.primary_message(), "parsing error occurred.");
    assert_eq!(diagnostic.help(), Some("statements must end with ';'"));
    assert_eq!(diagnostic.labels().len(), 1);

    let span = diagnostic.span();
    assert_eq!(span.start, span.end);
    assert_eq!(&source[span.start..span.start + 1], "b");

    let location = diagnostic.display_location();
    assert!(location.line() > 0);
    assert!(location.column() > 0);
    assert!(location.line_text().contains("int x = a + b"));
}

#[test]
fn unclassified_diagnostic_preserves_pest_message() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract Foo() {
            ???
        }
    "#;

    let err = parse_contract_ast(source).expect_err("invalid token must fail parsing");
    let CompilerError::Parse(diagnostic) = err else {
        panic!("expected parse error");
    };

    assert_eq!(diagnostic.interpretation(), ParseErrorInterpretation::Unclassified);
    assert_ne!(diagnostic.primary_message(), "parsing error occurred.");
    assert!(diagnostic.primary_message().contains("expected"));
}
