use silverscript_lang::ast::{BinaryOp, Expr, ExprKind, FunctionAst, NullaryOp, Statement, UnarySuffixKind};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use std::collections::HashSet;

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
        Statement::For { ident, start, end, body, .. } => StmtShape::For {
            ident: canonicalize_generated_name(ident),
            start: normalize_expr(start),
            end: normalize_expr(end),
            body: body.iter().map(normalize_stmt).collect(),
        },
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

fn function_by_name<'a>(functions: &'a [FunctionShape], name: &str) -> &'a FunctionShape {
    functions.iter().find(|function| function.name == name).unwrap_or_else(|| panic!("missing function '{}'", name))
}

fn assert_param_names(function: &FunctionShape, expected: &[&str]) {
    let actual: Vec<&str> = function.params.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(actual, expected, "unexpected params for '{}'", function.name);
}

#[test]
fn lowers_auth_groups_single_to_expected_wrapper_ast() {
    let source = r#"
        contract Decls(int max_outs) {
            int value = 0;

            #[covenant(binding = auth, from = 1, to = max_outs, groups = single)]
            function split(int prev_value, int[] new_values, int amount) {
                require(amount >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_outs) {
            int value = 0;

            function covenant_policy_split(int prev_value, int[] new_values, int amount) {
                require(amount >= 0);
            }

            entrypoint function split(int[] new_values, int amount) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                int cov_shared_out_count = OpCovOutCount(cov_id);
                require(cov_shared_out_count == cov_out_count);

                covenant_policy_split(value, new_values, amount);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, { value: new_values[cov_k] });
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
            function bump(int prev_value, int delta) : (int) {
                return(prev_value + delta);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int init_value) {
            int value = init_value;

            function covenant_policy_bump(int prev_value, int delta) : (int) {
                return(prev_value + delta);
            }

            entrypoint function bump(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_value) = covenant_policy_bump(value, delta);
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
            function fanout(int prev_value, int[] next_values) : (int[]) {
                return(next_values);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int max_outs, int init_value) {
            int value = init_value;

            function covenant_policy_fanout(int prev_value, int[] next_values) : (int[]) {
                return(next_values);
            }

            entrypoint function fanout(int[] next_values) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_value) = covenant_policy_fanout(value, next_values);
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
            function bump_or_terminate(int prev_value, int[] next_values) : (int[]) {
                return(next_values);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Decls(int init_value) {
            int value = init_value;

            function covenant_policy_bump_or_terminate(int prev_value, int[] next_values) : (int[]) {
                return(next_values);
            }

            entrypoint function bump_or_terminate(int[] next_values) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_value) = covenant_policy_bump_or_terminate(value, next_values);
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

#[test]
fn lowers_auth_verification_groups_multiple_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function step(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner, int nonce) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                covenant_policy_step(amount, owner, new_amount, new_owner, nonce);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_auth_verification_groups_single_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function step(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner
            ) {
                require(new_amount.length == new_owner.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner
            ) {
                require(new_amount.length == new_owner.length);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
                int cov_shared_out_count = OpCovOutCount(cov_id);
                require(cov_shared_out_count == cov_out_count);

                covenant_policy_step(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_auth_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function step(int prev_amount, byte[32] prev_owner, int fee) : (int, byte[32]) {
                return(prev_amount - fee, prev_owner);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int fee) : (int, byte[32]) {
                return(prev_amount - fee, prev_owner);
            }

            entrypoint function step(int fee) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_step(amount, owner, fee);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_cov_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function step(
                int[] prev_amount,
                byte[32][] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(
                int[] prev_amount,
                byte[32][] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }

            entrypoint function step_leader(int[] new_amount, byte[32][] new_owner, int nonce) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_amount;
                byte[32][] prev_owner;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                        prev_amount.push(cov_prev_amount);
                        prev_owner.push(cov_prev_owner);
                    }
                }

                covenant_policy_step(prev_amount, prev_owner, new_amount, new_owner, nonce);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function step_delegate() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_cov_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function step(int[] prev_amount, byte[32][] prev_owner, int fee) : (int[], byte[32][]) {
                require(fee >= 0);
                return(prev_amount, prev_owner);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int[] prev_amount, byte[32][] prev_owner, int fee) : (int[], byte[32][]) {
                require(fee >= 0);
                return(prev_amount, prev_owner);
            }

            entrypoint function step_leader(int[] prev_amount, byte[32][] prev_owner, int fee) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                    }
                }

                (int[] cov_new_amount, byte[32][] cov_new_owner) = covenant_policy_step(prev_amount, prev_owner, fee);
                require(cov_new_owner.length == cov_new_amount.length);
                require(cov_out_count <= max_outs);
                require(cov_out_count == cov_new_amount.length);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: cov_new_amount[cov_k],
                            owner: cov_new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function step_delegate() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_inferred_auth_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(from = 1, to = max_outs)]
            function step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                covenant_policy_step(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_inferred_cov_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(from = max_ins, to = max_outs)]
            function step(int[] prev_amount, byte[32][] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int[] prev_amount, byte[32][] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }

            entrypoint function step_leader(int[] new_amount, byte[32][] new_owner) {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

                int cov_in_count = OpCovInputCount(cov_id);
                require(cov_in_count <= max_ins);

                int cov_out_count = OpCovOutCount(cov_id);
                int[] prev_amount;
                byte[32][] prev_owner;

                for(cov_in_k, 0, max_ins) {
                    if (cov_in_k < cov_in_count) {
                        int cov_in_idx = OpCovInputIdx(cov_id, cov_in_k);
                        {
                            amount: int cov_prev_amount,
                            owner: byte[32] cov_prev_owner
                        } = readInputState(cov_in_idx);
                        prev_amount.push(cov_prev_amount);
                        prev_owner.push(cov_prev_owner);
                    }
                }

                covenant_policy_step(prev_amount, prev_owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpCovOutputIdx(cov_id, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }

            entrypoint function step_delegate() {
                byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

                require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_inferred_singleton_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(from = 1, to = 1)]
            function step(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            entrypoint function step(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_step(amount, owner, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_singleton_sugar_transition_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.singleton(mode = transition)]
            function step(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            entrypoint function step(int delta) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int cov_new_amount, byte[32] cov_new_owner) = covenant_policy_step(amount, owner, delta);
                require(cov_out_count == 1);

                int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
                validateOutputState(cov_out_idx, {
                    amount: cov_new_amount,
                    owner: cov_new_owner
                });
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_singleton_sugar_transition_termination_allowed_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.singleton(mode = transition, termination = allowed)]
            function step(
                int prev_amount,
                byte[32] prev_owner,
                int[] next_amount,
                byte[32][] next_owner
            ) : (int[], byte[32][]) {
                return(next_amount, next_owner);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(
                int prev_amount,
                byte[32] prev_owner,
                int[] next_amount,
                byte[32][] next_owner
            ) : (int[], byte[32][]) {
                return(next_amount, next_owner);
            }

            entrypoint function step(int[] next_amount, byte[32][] next_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                (int[] cov_new_amount, byte[32][] cov_new_owner) = covenant_policy_step(amount, owner, next_amount, next_owner);
                require(cov_new_owner.length == cov_new_amount.length);
                require(cov_out_count <= 1);
                require(cov_out_count == cov_new_amount.length);

                for(cov_k, 0, 1) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: cov_new_amount[cov_k],
                            owner: cov_new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn lowers_fanout_sugar_verification_two_field_state_to_expected_wrapper_ast() {
    let source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.fanout(to = max_outs, mode = verification)]
            function step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }
        }
    "#;

    let expected_lowered = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            function covenant_policy_step(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }

            entrypoint function step(int[] new_amount, byte[32][] new_owner) {
                int cov_out_count = OpAuthOutputCount(this.activeInputIndex);

                covenant_policy_step(amount, owner, new_amount, new_owner);
                require(cov_out_count <= max_outs);

                for(cov_k, 0, max_outs) {
                    if (cov_k < cov_out_count) {
                        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, cov_k);
                        validateOutputState(cov_out_idx, {
                            amount: new_amount[cov_k],
                            owner: new_owner[cov_k]
                        });
                    }
                }
            }
        }
    "#;

    assert_lowers_to_expected_ast(source, expected_lowered, &[Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
}

#[test]
fn covers_attribute_config_combinations_with_two_field_state() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function auth_verification_multi(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function auth_verification_single(
                int prev_amount,
                byte[32] prev_owner,
                int[] new_amount,
                byte[32][] new_owner
            ) {
                require(new_amount.length == new_owner.length);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function auth_transition(int prev_amount, byte[32] prev_owner, int fee) : (int, byte[32]) {
                return(prev_amount - fee, prev_owner);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function cov_verification(
                int[] prev_amount,
                byte[32][] prev_owner,
                int[] new_amount,
                byte[32][] new_owner,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function cov_transition(int[] prev_amount, byte[32][] prev_owner, int fee) : (int[], byte[32][]) {
                require(fee >= 0);
                return(prev_amount, prev_owner);
            }

            #[covenant(from = 1, to = max_outs)]
            function inferred_auth(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }

            #[covenant(from = max_ins, to = max_outs)]
            function inferred_cov(
                int[] prev_amount,
                byte[32][] prev_owner,
                int[] new_amount,
                byte[32][] new_owner
            ) {
                require(new_amount.length == new_owner.length);
            }

            #[covenant(from = 1, to = 1)]
            function inferred_transition(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            #[covenant.singleton(mode = transition)]
            function singleton_transition(int prev_amount, byte[32] prev_owner, int delta) : (int, byte[32]) {
                return(prev_amount + delta, prev_owner);
            }

            #[covenant.singleton(mode = transition, termination = allowed)]
            function singleton_terminate(
                int prev_amount,
                byte[32] prev_owner,
                int[] next_amount,
                byte[32][] next_owner
            ) : (int[], byte[32][]) {
                require(prev_amount >= 0);
                return(next_amount, next_owner);
            }

            #[covenant.fanout(to = max_outs, mode = verification)]
            function fanout_verification(int prev_amount, byte[32] prev_owner, int[] new_amount, byte[32][] new_owner) {
                require(new_amount.length == new_owner.length);
            }
        }
    "#;

    let functions = normalize_contract_functions(source, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);

    let expected_entrypoints: HashSet<&str> = vec![
        "auth_verification_multi",
        "auth_verification_single",
        "auth_transition",
        "cov_verification_leader",
        "cov_verification_delegate",
        "cov_transition_leader",
        "cov_transition_delegate",
        "inferred_auth",
        "inferred_cov_leader",
        "inferred_cov_delegate",
        "inferred_transition",
        "singleton_transition",
        "singleton_terminate",
        "fanout_verification",
    ]
    .into_iter()
    .collect();
    let actual_entrypoints: HashSet<&str> =
        functions.iter().filter(|function| function.entrypoint).map(|function| function.name.as_str()).collect();
    assert_eq!(actual_entrypoints, expected_entrypoints);

    for policy_name in [
        "covenant_policy_auth_verification_multi",
        "covenant_policy_auth_verification_single",
        "covenant_policy_auth_transition",
        "covenant_policy_cov_verification",
        "covenant_policy_cov_transition",
        "covenant_policy_inferred_auth",
        "covenant_policy_inferred_cov",
        "covenant_policy_inferred_transition",
        "covenant_policy_singleton_transition",
        "covenant_policy_singleton_terminate",
        "covenant_policy_fanout_verification",
    ] {
        let policy = function_by_name(&functions, policy_name);
        assert!(!policy.entrypoint, "policy '{}' must not be an entrypoint", policy_name);
    }

    assert_param_names(function_by_name(&functions, "auth_verification_multi"), &["new_amount", "new_owner", "nonce"]);
    assert_param_names(function_by_name(&functions, "auth_verification_single"), &["new_amount", "new_owner"]);
    assert_param_names(function_by_name(&functions, "auth_transition"), &["fee"]);
    assert_param_names(function_by_name(&functions, "cov_verification_leader"), &["new_amount", "new_owner", "nonce"]);
    assert_param_names(function_by_name(&functions, "cov_verification_delegate"), &[]);
    assert_param_names(function_by_name(&functions, "cov_transition_leader"), &["prev_amount", "prev_owner", "fee"]);
    assert_param_names(function_by_name(&functions, "cov_transition_delegate"), &[]);
    assert_param_names(function_by_name(&functions, "inferred_auth"), &["new_amount", "new_owner"]);
    assert_param_names(function_by_name(&functions, "inferred_cov_leader"), &["new_amount", "new_owner"]);
    assert_param_names(function_by_name(&functions, "inferred_cov_delegate"), &[]);
    assert_param_names(function_by_name(&functions, "inferred_transition"), &["delta"]);
    assert_param_names(function_by_name(&functions, "singleton_transition"), &["delta"]);
    assert_param_names(function_by_name(&functions, "singleton_terminate"), &["next_amount", "next_owner"]);
    assert_param_names(function_by_name(&functions, "fanout_verification"), &["new_amount", "new_owner"]);
}
