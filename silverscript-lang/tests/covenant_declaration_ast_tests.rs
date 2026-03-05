use silverscript_lang::ast::{BinaryOp, Expr, ExprKind, FunctionAst, NullaryOp, Statement, UnarySuffixKind};
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
    Var { type_name: String, name: String, expr: Option<ExprShape> },
    ArrayPush { name: String, expr: ExprShape },
    Require(ExprShape),
    Call { name: String, args: Vec<ExprShape> },
    CallAssign { bindings: Vec<(String, String)>, name: String, args: Vec<ExprShape> },
    Return(Vec<ExprShape>),
    StateCallAssign { bindings: Vec<(String, String, String)>, name: String, args: Vec<ExprShape> },
    If { condition: ExprShape, then_branch: Vec<StmtShape> },
    For { ident: String, start: ExprShape, end: ExprShape, body: Vec<StmtShape> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExprShape {
    Int(i64),
    Bool(bool),
    Identifier(String),
    Nullary(NullaryOp),
    Call { name: String, args: Vec<ExprShape> },
    ArrayIndex { source: Box<ExprShape>, index: Box<ExprShape> },
    UnarySuffix { source: Box<ExprShape>, kind: UnarySuffixKind },
    StateObject(Vec<(String, ExprShape)>),
    Binary { op: BinaryOp, left: Box<ExprShape>, right: Box<ExprShape> },
}

fn canonicalize_generated_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("__covenant_policy_") {
        return format!("covenant_policy_{rest}");
    }
    if let Some(rest) = name.strip_prefix("__cov_") {
        return format!("cov_{rest}");
    }
    name.to_string()
}

fn normalize_expr(expr: &Expr<'_>) -> ExprShape {
    match &expr.kind {
        ExprKind::Int(v) => ExprShape::Int(*v),
        ExprKind::Bool(v) => ExprShape::Bool(*v),
        ExprKind::Identifier(name) => ExprShape::Identifier(canonicalize_generated_name(name)),
        ExprKind::Nullary(op) => ExprShape::Nullary(*op),
        ExprKind::Call { name, args, .. } => {
            ExprShape::Call { name: canonicalize_generated_name(name), args: args.iter().map(normalize_expr).collect() }
        }
        ExprKind::ArrayIndex { source, index } => {
            ExprShape::ArrayIndex { source: Box::new(normalize_expr(source)), index: Box::new(normalize_expr(index)) }
        }
        ExprKind::UnarySuffix { source, kind, .. } => ExprShape::UnarySuffix { source: Box::new(normalize_expr(source)), kind: *kind },
        ExprKind::StateObject(fields) => {
            ExprShape::StateObject(fields.iter().map(|field| (field.name.clone(), normalize_expr(&field.expr))).collect())
        }
        ExprKind::Binary { op, left, right } => {
            ExprShape::Binary { op: *op, left: Box::new(normalize_expr(left)), right: Box::new(normalize_expr(right)) }
        }
        other => panic!("unsupported expr in covenant AST test: {other:?}"),
    }
}

fn normalize_stmt(stmt: &Statement<'_>) -> StmtShape {
    match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => StmtShape::Var {
            type_name: type_ref.type_name(),
            name: canonicalize_generated_name(name),
            expr: expr.as_ref().map(normalize_expr),
        },
        Statement::ArrayPush { name, expr, .. } => {
            StmtShape::ArrayPush { name: canonicalize_generated_name(name), expr: normalize_expr(expr) }
        }
        Statement::Require { expr, .. } => StmtShape::Require(normalize_expr(expr)),
        Statement::FunctionCall { name, args, .. } => {
            StmtShape::Call { name: canonicalize_generated_name(name), args: args.iter().map(normalize_expr).collect() }
        }
        Statement::FunctionCallAssign { bindings, name, args, .. } => StmtShape::CallAssign {
            bindings: bindings
                .iter()
                .map(|binding| (binding.type_ref.type_name(), canonicalize_generated_name(&binding.name)))
                .collect(),
            name: canonicalize_generated_name(name),
            args: args.iter().map(normalize_expr).collect(),
        },
        Statement::Return { exprs, .. } => StmtShape::Return(exprs.iter().map(normalize_expr).collect()),
        Statement::StateFunctionCallAssign { bindings, name, args, .. } => StmtShape::StateCallAssign {
            bindings: bindings
                .iter()
                .map(|binding| (binding.field_name.clone(), binding.type_ref.type_name(), canonicalize_generated_name(&binding.name)))
                .collect(),
            name: canonicalize_generated_name(name),
            args: args.iter().map(normalize_expr).collect(),
        },
        Statement::If { condition, then_branch, else_branch, .. } => {
            assert!(else_branch.is_none(), "generated covenant wrappers should not emit else branches");
            StmtShape::If { condition: normalize_expr(condition), then_branch: then_branch.iter().map(normalize_stmt).collect() }
        }
        Statement::For { ident, start, end, max, body, .. } => {
            assert!(max.is_none(), "generated covenant wrappers should emit 3-arg for loops only");
            StmtShape::For {
                ident: canonicalize_generated_name(ident),
                start: normalize_expr(start),
                end: normalize_expr(end),
                body: body.iter().map(normalize_stmt).collect(),
            }
        }
        other => panic!("unsupported statement in covenant AST test: {other:?}"),
    }
}

fn normalize_function(function: &FunctionAst<'_>) -> FunctionShape {
    FunctionShape {
        name: canonicalize_generated_name(&function.name),
        entrypoint: function.entrypoint,
        params: function.params.iter().map(|p| (canonicalize_generated_name(&p.name), p.type_ref.type_name())).collect(),
        attributes: function.attributes.iter().map(|a| a.path.join(".")).collect(),
        body: function.body.iter().map(normalize_stmt).collect(),
    }
}

fn normalize_contract_functions(source: &str, constructor_args: &[Expr<'_>]) -> Vec<FunctionShape> {
    let compiled = compile_contract(source, constructor_args, CompileOptions::default()).expect("compile succeeds");
    compiled.ast.functions.iter().map(normalize_function).collect()
}

fn assert_lowers_to_expected_ast(source: &str, expected_lowered_source: &str, constructor_args: &[Expr<'_>]) {
    let actual = normalize_contract_functions(source, constructor_args);
    let expected = normalize_contract_functions(expected_lowered_source, constructor_args);
    assert_eq!(actual, expected);
}

#[test]
fn lowers_auth_groups_single_to_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_outs) {
            int value = 0;

            #[covenant(binding = auth, from = 1, to = max_outs, groups = single)]
            function split(int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_outs) {
            int value = 0;

            function covenant_policy_split(int amount) {
                require(amount >= 0);
            }

            entrypoint function split(int amount) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                int cov_shared_out_count = OpCovOutCount(cov_id);
                require(cov_shared_out_count == cov_out_count);

                covenant_policy_split(amount);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: value });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4)]);
}

#[test]
fn lowers_cov_to_leader_and_delegate_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_ins, int max_outs) {
            int value = 0;

            #[covenant(from = max_ins, to = max_outs, mode = verification)]
            function transition_ok(int[] prev_values, int[] new_values, int delta) {
                require(delta >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_ins, int max_outs) {
            int value = 0;

            function covenant_policy_transition_ok(int[] prev_values, int[] new_values, int delta) {
                require(delta >= 0);
            }

            entrypoint function transition_ok_leader(int[] new_values, int delta) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_values;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        { value: int cov_prev_value } = readInputState(cov_in_idx);
                        prev_values.push(cov_prev_value);
                    }
                }

                covenant_policy_transition_ok(prev_values, new_values, delta);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, { value: new_values[cov_k] });
                    }
                }
            }

            entrypoint function transition_ok_delegate() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(3)]);
}

#[test]
fn lowers_singleton_transition_uses_returned_state_in_validation() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = transition)]
            function bump(int delta) : (int) {
                return(value + delta);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int init_value) {
            int value = init_value;

            function covenant_policy_bump(int delta) : (int) {
                return(value + delta);
            }

            entrypoint function bump(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_value) = covenant_policy_bump(delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, { value: cov_new_value });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(7)]);
}

#[test]
fn lowers_transition_array_return_to_exact_output_count_match() {
    let source = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            #[covenant(from = 1, to = max_outs, mode = transition)]
            function fanout(int[] next_values) : (int[]) {
                return(next_values);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            function covenant_policy_fanout(int[] next_values) : (int[]) {
                return(next_values);
            }

            entrypoint function fanout(int[] next_values) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_value) = covenant_policy_fanout(next_values);
                require(cov_out_count <= max_outs);
                require(cov_out_count == cov_new_value.length);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: cov_new_value[cov_k] });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10)]);
}

#[test]
fn lowers_singleton_transition_with_termination_allowed_to_array_cardinality_checks() {
    let source = r#"
        contract Decls(int init_value) {
            int value = init_value;

            #[covenant.singleton(mode = transition, termination = allowed)]
            function bump_or_terminate(int[] next_values) : (int[]) {
                return(next_values);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int init_value) {
            int value = init_value;

            function covenant_policy_bump_or_terminate(int[] next_values) : (int[]) {
                return(next_values);
            }

            entrypoint function bump_or_terminate(int[] next_values) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_value) = covenant_policy_bump_or_terminate(next_values);
                require(cov_out_count <= 1);
                require(cov_out_count == cov_new_value.length);

                for(cov_k, 0, 1) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: cov_new_value[cov_k] });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10)]);
}
