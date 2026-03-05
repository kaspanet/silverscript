use silverscript_lang::ast::{BinaryOp, Expr, ExprKind, FunctionAst, NullaryOp, Statement};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionShape {
    name: String,
    entrypoint: bool,
    params: Vec<(String, String)>,
    attributes: Vec<String>,
    body: Vec<StmtShape>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StmtShape {
    Var { type_name: String, name: String, expr: ExprShape },
    Require(ExprShape),
    Call { name: String, args: Vec<ExprShape> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExprShape {
    Int(i64),
    Bool(bool),
    Identifier(String),
    Nullary(NullaryOp),
    Call { name: String, args: Vec<ExprShape> },
    Binary { op: BinaryOp, left: Box<ExprShape>, right: Box<ExprShape> },
}

fn normalize_expr(expr: &Expr<'_>) -> ExprShape {
    match &expr.kind {
        ExprKind::Int(v) => ExprShape::Int(*v),
        ExprKind::Bool(v) => ExprShape::Bool(*v),
        ExprKind::Identifier(name) => ExprShape::Identifier(name.clone()),
        ExprKind::Nullary(op) => ExprShape::Nullary(*op),
        ExprKind::Call { name, args, .. } => ExprShape::Call { name: name.clone(), args: args.iter().map(normalize_expr).collect() },
        ExprKind::Binary { op, left, right } => {
            ExprShape::Binary { op: *op, left: Box::new(normalize_expr(left)), right: Box::new(normalize_expr(right)) }
        }
        other => panic!("unsupported expr in covenant AST test: {other:?}"),
    }
}

fn normalize_stmt(stmt: &Statement<'_>) -> StmtShape {
    match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            let init = expr.as_ref().expect("generated wrapper variable definitions should be initialized");
            StmtShape::Var { type_name: type_ref.type_name(), name: name.clone(), expr: normalize_expr(init) }
        }
        Statement::Require { expr, .. } => StmtShape::Require(normalize_expr(expr)),
        Statement::FunctionCall { name, args, .. } => {
            StmtShape::Call { name: name.clone(), args: args.iter().map(normalize_expr).collect() }
        }
        other => panic!("unsupported statement in covenant AST test: {other:?}"),
    }
}

fn normalize_function(function: &FunctionAst<'_>) -> FunctionShape {
    FunctionShape {
        name: function.name.clone(),
        entrypoint: function.entrypoint,
        params: function.params.iter().map(|p| (p.name.clone(), p.type_ref.type_name())).collect(),
        attributes: function.attributes.iter().map(|a| a.path.join(".")).collect(),
        body: function.body.iter().map(normalize_stmt).collect(),
    }
}

fn normalize_contract_functions(source: &str, constructor_args: &[Expr<'_>]) -> Vec<FunctionShape> {
    let compiled = compile_contract(source, constructor_args, CompileOptions::default()).expect("compile succeeds");
    compiled.ast.functions.iter().map(normalize_function).collect()
}

fn id(name: &str) -> ExprShape {
    ExprShape::Identifier(name.to_string())
}

fn int(value: i64) -> ExprShape {
    ExprShape::Int(value)
}

fn call(name: &str, args: Vec<ExprShape>) -> ExprShape {
    ExprShape::Call { name: name.to_string(), args }
}

fn bin(op: BinaryOp, left: ExprShape, right: ExprShape) -> ExprShape {
    ExprShape::Binary { op, left: Box::new(left), right: Box::new(right) }
}

#[test]
fn lowers_auth_groups_single_to_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_outs) {
            #[covenant(binding = auth, from = 1, to = max_outs, groups = single)]
            function split(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let actual = normalize_contract_functions(source, &[Expr::int(4)]);

    let expected = vec![
        FunctionShape {
            // Original user policy is kept as an internal function.
            name: "__covenant_policy_split".to_string(),
            entrypoint: false,
            params: vec![("amount".to_string(), "int".to_string())],
            attributes: vec![],
            body: vec![StmtShape::Require(bin(BinaryOp::Ge, id("amount"), int(0)))],
        },
        FunctionShape {
            // Generated auth entrypoint wrapper.
            name: "split".to_string(),
            entrypoint: true,
            params: vec![("amount".to_string(), "int".to_string())],
            attributes: vec![],
            body: vec![
                // __cov_out_count = OpAuthOutputCount(this.activeInputIndex)
                StmtShape::Var {
                    type_name: "int".to_string(),
                    name: "__cov_out_count".to_string(),
                    expr: call("OpAuthOutputCount", vec![ExprShape::Nullary(NullaryOp::ActiveInputIndex)]),
                },
                // require(__cov_out_count <= max_outs)
                StmtShape::Require(bin(BinaryOp::Le, id("__cov_out_count"), id("max_outs"))),
                // __cov_id = OpInputCovenantId(this.activeInputIndex)
                StmtShape::Var {
                    type_name: "byte[32]".to_string(),
                    name: "__cov_id".to_string(),
                    expr: call("OpInputCovenantId", vec![ExprShape::Nullary(NullaryOp::ActiveInputIndex)]),
                },
                // __cov_shared_out_count = OpCovOutCount(__cov_id)
                StmtShape::Var {
                    type_name: "int".to_string(),
                    name: "__cov_shared_out_count".to_string(),
                    expr: call("OpCovOutCount", vec![id("__cov_id")]),
                },
                // require(__cov_shared_out_count == __cov_out_count)
                StmtShape::Require(bin(BinaryOp::Eq, id("__cov_shared_out_count"), id("__cov_out_count"))),
                // __covenant_policy_split(amount)
                StmtShape::Call { name: "__covenant_policy_split".to_string(), args: vec![id("amount")] },
            ],
        },
    ];

    assert_eq!(actual, expected);
}

#[test]
fn lowers_cov_to_leader_and_delegate_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            #[covenant(from = max_ins, to = max_outs, mode = predicate)]
            function transition_ok(int delta) {
                require(delta >= 0);
            }
        }
    "#;

    let actual = normalize_contract_functions(source, &[Expr::int(2), Expr::int(3)]);

    let common_prefix = vec![
        // __cov_id = OpInputCovenantId(this.activeInputIndex)
        StmtShape::Var {
            type_name: "byte[32]".to_string(),
            name: "__cov_id".to_string(),
            expr: call("OpInputCovenantId", vec![ExprShape::Nullary(NullaryOp::ActiveInputIndex)]),
        },
        // __cov_in_count = OpCovInputCount(__cov_id)
        StmtShape::Var {
            type_name: "int".to_string(),
            name: "__cov_in_count".to_string(),
            expr: call("OpCovInputCount", vec![id("__cov_id")]),
        },
        // require(__cov_in_count <= max_ins)
        StmtShape::Require(bin(BinaryOp::Le, id("__cov_in_count"), id("max_ins"))),
        // __cov_out_count = OpCovOutCount(__cov_id)
        StmtShape::Var {
            type_name: "int".to_string(),
            name: "__cov_out_count".to_string(),
            expr: call("OpCovOutCount", vec![id("__cov_id")]),
        },
        // require(__cov_out_count <= max_outs)
        StmtShape::Require(bin(BinaryOp::Le, id("__cov_out_count"), id("max_outs"))),
    ];

    let expected = vec![
        FunctionShape {
            // Original user policy is kept as an internal function.
            name: "__covenant_policy_transition_ok".to_string(),
            entrypoint: false,
            params: vec![("delta".to_string(), "int".to_string())],
            attributes: vec![],
            body: vec![StmtShape::Require(bin(BinaryOp::Ge, id("delta"), int(0)))],
        },
        FunctionShape {
            // Generated leader entrypoint.
            name: "transition_ok_leader".to_string(),
            entrypoint: true,
            params: vec![("delta".to_string(), "int".to_string())],
            attributes: vec![],
            body: {
                let mut body = common_prefix.clone();
                // require(OpCovInputIdx(__cov_id, 0) == this.activeInputIndex)
                body.push(StmtShape::Require(bin(
                    BinaryOp::Eq,
                    call("OpCovInputIdx", vec![id("__cov_id"), int(0)]),
                    ExprShape::Nullary(NullaryOp::ActiveInputIndex),
                )));
                // __covenant_policy_transition_ok(delta)
                body.push(StmtShape::Call { name: "__covenant_policy_transition_ok".to_string(), args: vec![id("delta")] });
                body
            },
        },
        FunctionShape {
            // Generated delegate entrypoint.
            name: "transition_ok_delegate".to_string(),
            entrypoint: true,
            params: vec![],
            attributes: vec![],
            body: {
                let mut body = common_prefix;
                // require(OpCovInputIdx(__cov_id, 0) != this.activeInputIndex)
                body.push(StmtShape::Require(bin(
                    BinaryOp::Ne,
                    call("OpCovInputIdx", vec![id("__cov_id"), int(0)]),
                    ExprShape::Nullary(NullaryOp::ActiveInputIndex),
                )));
                body
            },
        },
    ];

    assert_eq!(actual, expected);
}
