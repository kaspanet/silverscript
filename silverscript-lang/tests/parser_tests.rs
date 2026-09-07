use silverscript_lang::ast::visit::AstVisitorMut;
use silverscript_lang::ast::{BinaryOp, Expr, ExprKind, Statement, parse_contract_ast, parse_expression_ast, parse_type_ref};
use silverscript_lang::parser::parse_source_file;
use silverscript_lang::span::Span;

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
fn parses_entry_declaration() {
    let entry = r#"
        contract Foo() {
            entry main() {
                require(true);
            }
        }
    "#;
    assert!(parse_source_file(entry).is_ok());
}

#[test]
fn parses_int_as_fixed_byte_array() {
    let source = r#"
        contract Convert() {
            entry main(int x) {
                byte[8] y = x as byte[8];
                byte[_] z = x as byte[4];
                require(y.length == 8 && z.length == 4);
            }
        }
    "#;

    parse_contract_ast(source).expect("'as byte[N]' parses");
}

#[test]
fn type_predicates_only_match_scalars() {
    assert!(parse_type_ref("int").unwrap().is_int());
    assert!(parse_type_ref("temporal").unwrap().is_temporal());
    assert!(parse_type_ref("int").unwrap().is_int_like());
    assert!(parse_type_ref("temporal").unwrap().is_int_like());
    assert!(parse_type_ref("bool").unwrap().is_bool());
    assert!(parse_type_ref("string").unwrap().is_string());
    assert!(parse_type_ref("pubkey").unwrap().is_pubkey());
    assert!(parse_type_ref("sig").unwrap().is_sig());
    assert!(parse_type_ref("datasig").unwrap().is_datasig());
    assert!(parse_type_ref("byte").unwrap().is_byte());
    assert!(parse_type_ref("(int, bool)").unwrap().is_tuple());
    assert!(parse_type_ref("Record").unwrap().is_custom());

    assert!(!parse_type_ref("int[]").unwrap().is_int());
    assert!(!parse_type_ref("temporal[]").unwrap().is_temporal());
    assert!(!parse_type_ref("int[]").unwrap().is_int_like());
    assert!(!parse_type_ref("bool").unwrap().is_int_like());
    assert!(!parse_type_ref("byte[1]").unwrap().is_byte());
    assert!(!parse_type_ref("Record[]").unwrap().is_custom());
}

#[test]
fn dynamic_array_predicate_checks_the_outermost_dimension() {
    assert!(!parse_type_ref("int").unwrap().is_dynamic_array());
    assert!(parse_type_ref("int[]").unwrap().is_dynamic_array());
    assert!(!parse_type_ref("int[2]").unwrap().is_dynamic_array());
    assert!(parse_type_ref("int[2][]").unwrap().is_dynamic_array());
    assert!(!parse_type_ref("int[][2]").unwrap().is_dynamic_array());
}

#[test]
fn scalar_byte_cast_remains_scalar_in_the_ast() {
    let input = r#"
        contract Convert() {
            entry main(int value) {
                byte result = byte(value);
            }
        }
    "#;
    let contract = parse_contract_ast(input).expect("scalar byte cast should parse");
    let Statement::VariableDefinition { expr: Some(expr), .. } = &contract.functions[0].body[0] else {
        panic!("expected a variable definition with an initializer");
    };
    let ExprKind::Call { name, .. } = &expr.kind else {
        panic!("expected a scalar cast call");
    };

    assert_eq!(name, "byte");
}

#[test]
fn try_from_expr_vec_infers_a_fixed_array_type() {
    let expr = Expr::try_from(vec![Expr::int(1), Expr::int(2)]).expect("homogeneous array type should be inferred");
    let ExprKind::Array { type_ref, values, .. } = expr.kind else {
        panic!("expected an array expression");
    };

    assert_eq!(type_ref, parse_type_ref("int[2]").unwrap());
    assert_eq!(values.len(), 2);
    assert!(Expr::try_from(Vec::<Expr<'static>>::new()).is_err());
    assert!(Expr::try_from(vec![Expr::int(1), Expr::bool(true)]).is_err());
}

#[test]
fn byte_vector_constructors_distinguish_fixed_and_dynamic_arrays() {
    let ExprKind::Array { type_ref: fixed_type, .. } = Expr::bytes(vec![1, 2]).kind else {
        panic!("expected a fixed byte array expression");
    };
    let ExprKind::Array { type_ref: dynamic_type, .. } = Expr::dynamic_bytes(vec![1, 2]).kind else {
        panic!("expected a dynamic byte array expression");
    };

    assert_eq!(fixed_type, parse_type_ref("byte[2]").unwrap());
    assert_eq!(dynamic_type, parse_type_ref("byte[]").unwrap());
}

#[test]
fn array_constructor_resolves_inferred_dimension_to_fixed() {
    let ExprKind::Array { type_ref, .. } = Expr::array(parse_type_ref("int[_]").unwrap(), vec![Expr::int(1), Expr::int(2)]).kind
    else {
        panic!("expected an array expression");
    };

    assert_eq!(type_ref, parse_type_ref("int[2]").unwrap());
}

#[test]
fn try_from_nested_byte_vec_requires_equal_nonempty_elements() {
    let expr = Expr::try_from(vec![vec![1u8, 2], vec![3, 4]]).expect("uniform nested byte array should be inferred");
    let ExprKind::Array { type_ref, values, .. } = expr.kind else {
        panic!("expected an array expression");
    };

    assert_eq!(type_ref, parse_type_ref("byte[2][2]").unwrap());
    assert_eq!(values.len(), 2);

    let unequal = Expr::try_from(vec![vec![1u8], vec![2, 3]]).expect_err("unequal inner lengths should be rejected");
    assert!(unequal.to_string().contains("nested array elements must have equal lengths"), "unexpected error: {unequal}");

    let empty = Expr::try_from(Vec::<Vec<u8>>::new()).expect_err("empty nested array type cannot be inferred");
    assert!(empty.to_string().contains("nested array element type cannot be inferred"), "unexpected error: {empty}");
}

#[test]
fn parses_lock_requirement_and_console() {
    let input = r#"
        contract TimeLock(pubkey owner) {
            function unlock(sig s) {
                require(this.ageDaa >= 10, "too early");
                console.log("ok", 1 + 2, checkSig(s, owner));
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
}

#[test]
fn parses_lock_requirements_as_distinct_statement_variants() {
    let source = r#"
        contract Locks() {
            entry main(int daa, temporal timestamp) {
                require(this.ageDaa >= daa);
                require(tx.daa >= daa);
                require(tx.time >= timestamp);
            }
        }
    "#;

    let ast = parse_contract_ast(source).expect("lock requirements parse");
    let body = &ast.functions[0].body;
    assert!(matches!(body[0], Statement::RequireAgeDaa { .. }));
    assert!(matches!(body[1], Statement::RequireTxDaa { .. }));
    assert!(matches!(body[2], Statement::RequireTxTime { .. }));

    let kinds = body
        .iter()
        .map(|statement| serde_json::to_value(statement).expect("statement serializes")["kind"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(kinds, ["require_age_daa", "require_tx_daa", "require_tx_time"]);
}

#[test]
fn legacy_age_daa_spelling_is_not_a_lock_requirement() {
    let source = "contract Locks() { entry main() { require(this.age_daa >= 1); } }";
    let ast = parse_contract_ast(source).expect("legacy spelling remains syntactically an ordinary field access");
    assert!(matches!(ast.functions[0].body[0], Statement::Require { .. }));
}

#[test]
fn rejects_number_unit_overflow() {
    let input = r#"
        contract TimeLock() {
            entry main() {
                require(tx.time >= 9223372036854775807 weeks);
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
                int a = int[]{1, 2, 3}[0];
                int b = (a * 2).split(1).length;
                int c = tx.outputs[idx].value;
                int d = tx.inputs[idx].outpointIndex;
                byte[32] txId = tx.inputs[idx].outpointTxId;
                int inputCount = tx.inputs.length;
                require(c >= d);
            }
        }
    "#;

    parse_source_file(input).unwrap_or_else(|err| panic!("{err}"));

    let contract = parse_contract_ast(input).expect("contract should parse");
    let Statement::VariableDefinition { expr: Some(indexed), .. } = &contract.functions[0].body[2] else {
        panic!("expected indexed introspection variable");
    };
    assert!(matches!(&indexed.kind, ExprKind::IndexedIntrospection { .. }));

    let Statement::VariableDefinition { expr: Some(unindexed), .. } = &contract.functions[0].body[5] else {
        panic!("expected introspection variable");
    };
    assert!(matches!(&unindexed.kind, ExprKind::Introspection(_)));
}

#[test]
fn typed_array_literal_stores_its_declared_type_on_the_array_expr() {
    let input = r#"
        contract Arrays() {
            entry main() {
                byte[2][_] values = byte[2][]{byte[2](0x0102), byte[2](0x0304)};
            }
        }
    "#;
    let contract = parse_contract_ast(input).expect("typed array literal should parse");
    let Statement::VariableDefinition { expr: Some(expr), .. } = &contract.functions[0].body[0] else {
        panic!("expected a variable definition with an initializer");
    };
    let ExprKind::Array { type_ref, values, .. } = &expr.kind else {
        panic!("expected a typed array expression");
    };

    assert_eq!(type_ref, &parse_type_ref("byte[2][]").unwrap());
    assert_eq!(values.len(), 2);
}

#[test]
fn typed_array_literal_outer_dimension_controls_its_ast_type() {
    let input = r#"
        contract Arrays() {
            entry main() {
                int[] dynamic = int[]{1, 2, 3};
                int[3] inferred = int[_]{1, 2, 3};
                int[3] fixed = int[3]{1, 2, 3};
            }
        }
    "#;
    let contract = parse_contract_ast(input).expect("typed array literals should parse");
    let expected = ["int[]", "int[3]", "int[3]"];
    for (statement, expected_type) in contract.functions[0].body.iter().zip(expected) {
        let Statement::VariableDefinition { expr: Some(expr), .. } = statement else {
            panic!("expected a variable definition with an initializer");
        };
        let ExprKind::Array { type_ref, .. } = &expr.kind else {
            panic!("expected an array expression");
        };
        assert_eq!(type_ref, &parse_type_ref(expected_type).unwrap());
    }
}

#[test]
fn rejects_fixed_typed_array_literal_with_wrong_length() {
    let input = r#"
        contract Arrays() {
            entry main() {
                int[4] values = int[4]{1, 2, 3};
            }
        }
    "#;
    let err = parse_contract_ast(input).expect_err("fixed literal length mismatch should fail");
    assert!(err.to_string().contains("array literal size mismatch: expected 4, got 3"), "unexpected error: {err}");
}

#[test]
fn byte_array_hex_cast_becomes_a_typed_array_expr() {
    let input = r#"
        contract Arrays() {
            entry main() {
                byte[_] value = byte[_](0x010203);
            }
        }
    "#;
    let contract = parse_contract_ast(input).expect("byte-array hex literal should parse");
    let Statement::VariableDefinition { expr: Some(expr), .. } = &contract.functions[0].body[0] else {
        panic!("expected a variable definition with an initializer");
    };
    let ExprKind::Array { type_ref, values, .. } = &expr.kind else {
        panic!("expected the hex cast to lower directly to a typed array expression");
    };

    assert_eq!(type_ref, &parse_type_ref("byte[3]").unwrap());
    assert_eq!(values.len(), 3);
}

#[test]
fn fixed_byte_sequence_hex_casts_contain_fixed_byte_array_exprs() {
    let cases = [("pubkey", 32), ("sig", 65), ("datasig", 64)];

    for (type_name, size) in cases {
        let input = format!("contract C() {{ entry main() {{ {type_name} value = {type_name}(0x{}); }} }}", "02".repeat(size));
        let contract = parse_contract_ast(&input).expect("fixed byte-sequence hex literal should parse");
        let Statement::VariableDefinition { expr: Some(expr), .. } = &contract.functions[0].body[0] else {
            panic!("expected a variable definition with an initializer");
        };
        let ExprKind::Call { name, args, .. } = &expr.kind else {
            panic!("expected a scalar cast call");
        };
        assert_eq!(name, type_name);
        let [Expr { kind: ExprKind::Array { type_ref, values, .. }, .. }] = args.as_slice() else {
            panic!("expected a single typed byte-array argument");
        };
        assert_eq!(type_ref, &parse_type_ref(&format!("byte[{size}]")).unwrap());
        assert_eq!(values.len(), size);
        assert!(values.iter().all(|value| matches!(value.kind, ExprKind::Byte(2))));
    }
}

#[test]
fn rejects_untyped_array_literals() {
    let input = r#"
        contract Arrays() {
            entry main() {
                int[_] values = [1, 2, 3];
            }
        }
    "#;

    assert!(parse_source_file(input).is_err());
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

            entry main() {
                S y = S {a: 0, b: "hello"};
                f(y);
            }
        }
    "#;

    let result = parse_source_file(input);
    assert!(result.is_ok());
}

#[test]
fn parses_qualified_r0_verifier_calls() {
    let input = r#"
        contract R0(byte[32] image_id, byte[32] control_id) {
            entry main() {
                require(r0.g16.verify(image_id, bytes("proof"), image_id));
                require(r0.succinct.sha256.verify(bytes("claim"), bytes("control_index"), bytes("control_digests"), bytes("seal"), bytes("journal"), image_id, control_id));
                require(r0.succinct.verify(bytes("claim"), bytes("control_index"), bytes("control_digests"), bytes("seal"), bytes("journal"), image_id, control_id));
            }
        }
    "#;
    assert!(parse_source_file(input).is_ok());
}

#[test]
fn parses_g16_verify_call() {
    let input = r#"
        contract Groth16(byte[] verifying_key, byte[] proof, byte[32] public_input) {
            entry verify() {
                g16.verify(verifying_key, proof, public_input);
            }
        }
    "#;
    assert!(parse_source_file(input).is_ok());
}

#[test]
fn rejects_misspelled_r0_succinct_verifier_call() {
    let input = r#"
        contract R0(byte[32] image_id, byte[32] control_id) {
            entry main() {
                require(r0.succint.verify(image_id, control_id));
            }
        }
    "#;
    assert!(parse_source_file(input).is_err());
}

#[test]
fn parses_struct_destructuring() {
    let input = r#"
        contract Structs() {
            struct S {
                int a;
                byte[5] b;
            }

            entry main() {
                S s = S {a: 1, b: 0x0102030405};
                S {a: int x, b: byte[5] y} = s;
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

            entry main() {
                int a, int b = pair();
            }
        }
    "#;

    assert!(parse_contract_ast(input).is_ok());
}

// Regression for https://github.com/kaspanet/silverscript/issues/239.
// Run in a subprocess because a Rust stack overflow aborts the process instead of
// unwinding; a thread alone would also abort the parent test runner.
#[test]
fn ast_construction_fits_in_one_mib_stack() {
    const CHILD_ENV: &str = "SILVERSCRIPT_PARSER_STACK_REGRESSION_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        std::thread::Builder::new()
            .name("parser-with-one-mib-stack".into())
            .stack_size(1024 * 1024)
            .spawn(|| {
                let source = r#"
                    pragma silverscript ^0.1.0;
                    contract ParserStackRepro(byte[32] init_pairs) {
                        byte[32] pairs = init_pairs;

                        entry reproduce(byte[384] records, int count) {
                            State next_state = State {
                                pairs: blake3(byte[](byte[](records) + ((count) as byte[8]))),
                            };
                        }
                    }
                "#;
                parse_contract_ast(source).expect("the issue 239 expression should parse on a 1 MiB stack");
            })
            .expect("spawn parser thread")
            .join()
            .expect("parser thread should complete without panicking");
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("locate test executable"))
        .args(["--exact", "ast_construction_fits_in_one_mib_stack", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run parser stack regression in a subprocess");
    assert!(
        output.status.success(),
        "AST construction on a 1 MiB stack failed with {}.\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

// Parentheses change source spans, so compare expression structure after clearing them.
fn parse_expression_without_spans(source: &str) -> Expr<'_> {
    struct ClearSpans;
    impl<'i> AstVisitorMut<'i> for ClearSpans {
        fn visit_span(&mut self, span: &mut Span<'i>) {
            *span = Span::default();
        }
    }
    let mut expr = parse_expression_ast(source).expect("expression should parse");
    ClearSpans.visit_expr(&mut expr);
    expr
}

#[test]
fn redundant_parentheses_preserve_complex_expression_asts() {
    let cases = [
        (
            "a || b && c | d ^ e & f == g < h + i * j",
            "((a)) || (((b)) && (((c)) | (((d)) ^ (((e)) & (((f)) == (((g)) < (((h)) + (((i)) * ((j))))))))))",
        ),
        ("a - b - c", "((((a)) - ((b))) - ((c)))"),
        ("a / b % c", "((((a)) / ((b))) % ((c)))"),
        ("!ready || -amount < limit", "((!((ready))) || (((-((amount)))) < ((limit))))"),
        ("a ? b : c ? d : e", "(((a)) ? ((b)) : (((c)) ? ((d)) : ((e))))"),
        (
            "blake3(byte[](byte[](records) + (count as byte[8])))",
            "blake3(((byte[](((byte[](((records)))) + ((((count)) as byte[8])))))))",
        ),
        (
            "State { pairs: blake3(byte[](records)), count: count + 1 }",
            "((State { pairs: ((blake3(((byte[](((records)))))))), count: (((count)) + ((1))) }))",
        ),
        ("records[start + 1].slice(0, limit).length", "((((records))[(((start)) + ((1)))]).slice(((0)), ((limit)))).length"),
        ("int[3]{a + b, f(c), ready ? d : e}", "((int[3]{(((a)) + ((b))), ((f(((c))))), (((ready)) ? ((d)) : ((e)))}))"),
    ];
    for (plain, parenthesized) in cases {
        let expected = parse_expression_without_spans(plain);
        for depth in [0, 1, 4, 8] {
            let source = format!("{}{parenthesized}{}", "(".repeat(depth), ")".repeat(depth));
            let actual = parse_expression_without_spans(&source);
            assert_eq!(actual, expected, "parentheses must preserve the AST: {source}");
        }
    }
}

fn binary_expr<'i>(op: BinaryOp, left: Expr<'i>, right: Expr<'i>) -> Expr<'i> {
    Expr::new(ExprKind::Binary { op, left: Box::new(left), right: Box::new(right) }, Span::default())
}

#[test]
fn parentheses_preserve_explicit_operator_grouping() {
    let a = Expr::identifier("a");
    let b = Expr::identifier("b");
    let c = Expr::identifier("c");
    let cases = [
        ("((((a)) + ((b)))) * (((c)))", binary_expr(BinaryOp::Mul, binary_expr(BinaryOp::Add, a.clone(), b.clone()), c.clone())),
        ("(((a))) + ((((b)) * ((c))))", binary_expr(BinaryOp::Add, a.clone(), binary_expr(BinaryOp::Mul, b.clone(), c.clone()))),
        ("(((a))) - ((((b)) - ((c))))", binary_expr(BinaryOp::Sub, a.clone(), binary_expr(BinaryOp::Sub, b.clone(), c.clone()))),
        ("((((a)) - ((b)))) - (((c)))", binary_expr(BinaryOp::Sub, binary_expr(BinaryOp::Sub, a, b), c)),
    ];
    for (source, expected) in cases {
        assert_eq!(parse_expression_without_spans(source), expected, "incorrect grouping: {source}");
    }
}

#[test]
fn parenthesized_calls_and_casts_retain_their_ast_nodes() {
    let source = "(((blake3(((byte[](((byte[](((records)))) + ((((count)) as byte[8]))))))))))";
    let expected = Expr::call(
        "blake3",
        vec![Expr::call(
            "byte[]",
            vec![binary_expr(
                BinaryOp::Add,
                Expr::call("byte[]", vec![Expr::identifier("records")]),
                Expr::call("__as_cast_byte[8]", vec![Expr::identifier("count")]),
            )],
        )],
    );
    assert_eq!(parse_expression_without_spans(source), expected);
}
