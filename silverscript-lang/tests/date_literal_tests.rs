use chrono::NaiveDateTime;
use silverscript_lang::ast::{Expr, StatementKind, parse_contract_ast};

fn extract_first_expr(source: &str) -> Expr {
    let ast = parse_contract_ast(source).expect("parse succeeds");
    let function = &ast.functions[0];
    let statement = &function.body[0];
    match &statement.kind {
        StatementKind::VariableDefinition { expr, .. } => expr.clone().expect("missing initializer"),
        StatementKind::Require { expr, .. } => expr.clone(),
        _ => panic!("unexpected statement"),
    }
}

#[test]
fn parses_date_literal_basic_iso() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract Test() {
            function test() {
                int d = date("2021-02-17T01:30:00");
            }
        }
    "#;
    let expr = extract_first_expr(source);
    let Expr::Int(parsed) = expr else {
        panic!("expected int literal");
    };
    let expected = NaiveDateTime::parse_from_str("2021-02-17T01:30:00", "%Y-%m-%dT%H:%M:%S").unwrap().and_utc().timestamp();
    assert_eq!(parsed, expected);
}

#[test]
fn rejects_non_existent_date() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract Test() {
            function test() {
                require(tx.time >= date("2021-50-03T05:30:00"));
            }
        }
    "#;
    let result = parse_contract_ast(source);
    assert!(result.is_err(), "expected parse error for non-existent date");
}

#[test]
fn rejects_invalid_iso_date_format() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract Test() {
            function test() {
                int d = date("02-16-2021 05:30:00 PM");
            }
        }
    "#;
    let result = parse_contract_ast(source);
    assert!(result.is_err(), "expected parse error for invalid iso date");
}

#[test]
fn rejects_full_iso_date_with_timezone() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract Test() {
            function test() {
                require(tx.time >= date("2021-03-03T05:30:00.000Z"));
            }
        }
    "#;
    let result = parse_contract_ast(source);
    assert!(result.is_err(), "expected parse error for full iso date with timezone");
}
