use silverscript_lang::ast::visit::{AstVisitorMut, NameKind, visit_contract_mut};
use silverscript_lang::ast::{ContractAst, Expr, FunctionAst, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::span::Span;
use std::collections::HashSet;

fn canonicalize_generated_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("__covenant_policy_") {
        return format!("covenant_policy_{rest}");
    }
    if let Some(rest) = name.strip_prefix("__cov_") {
        return format!("cov_{rest}");
    }
    if let Some(rest) = name.strip_prefix("__") {
        return rest.to_string();
    }
    name.to_string()
}

struct GeneratedNameCanonicalizer;

impl<'i> AstVisitorMut<'i> for GeneratedNameCanonicalizer {
    fn visit_name(&mut self, name: &mut String, _kind: NameKind) {
        *name = canonicalize_generated_name(name);
    }

    fn visit_span(&mut self, span: &mut Span<'i>) {
        *span = Span::default();
    }
}

fn normalize_contract(contract: &mut ContractAst<'_>) {
    visit_contract_mut(&mut GeneratedNameCanonicalizer, contract);
}

fn compile_and_normalize_contract<'i>(source: &'i str, constructor_args: &[Expr<'i>]) -> ContractAst<'i> {
    let compiled = compile_contract(source, constructor_args, CompileOptions::default()).expect("compile succeeds");
    let mut contract = compiled.ast;
    normalize_contract(&mut contract);
    contract
}

fn parse_and_normalize_contract<'i>(source: &'i str) -> ContractAst<'i> {
    let mut contract = parse_contract_ast(source).expect("expected contract parses");
    normalize_contract(&mut contract);
    contract
}

fn split_fixture_contracts(fixture: &str) -> (&str, &str) {
    let (source, expected) = fixture.split_once("// --- lowered ---").expect("fixture must contain lowered marker");
    (source.trim(), expected.trim())
}

fn assert_fixture_lowers_to_expected_ast<'i>(fixture: &'i str, constructor_args: &[Expr<'i>]) {
    let (source, expected_lowered_source) = split_fixture_contracts(fixture);
    let actual = compile_and_normalize_contract(source, constructor_args);
    let expected = parse_and_normalize_contract(expected_lowered_source);
    assert_eq!(actual, expected);
}

fn function_by_name<'a, 'i>(functions: &'a [FunctionAst<'i>], name: &str) -> &'a FunctionAst<'i> {
    functions.iter().find(|function| function.name == name).unwrap_or_else(|| panic!("missing function '{}'", name))
}

fn assert_param_names(function: &FunctionAst<'_>, expected: &[&str]) {
    let actual: Vec<&str> = function.params.iter().map(|param| param.name.as_str()).collect();
    assert_eq!(actual, expected, "unexpected params for '{}'", function.name);
}

macro_rules! fixture_ast_test {
    ($name:ident, [$($args:expr),* $(,)?]) => {
        #[test]
        fn $name() {
            assert_fixture_lowers_to_expected_ast(
                include_str!(concat!("covenant_declaration_ast_fixtures/", stringify!($name), ".sil")),
                &[$($args),*],
            );
        }
    };
}

fixture_ast_test!(lowers_auth_groups_single, [Expr::int(4)]);
fixture_ast_test!(lowers_cov_to_leader_and_delegate_expected_wrapper_ast, [Expr::int(2), Expr::int(3)]);
fixture_ast_test!(lowers_singleton_sugar_verification_to_single_state_validation, [Expr::int(7)]);
fixture_ast_test!(lowers_singleton_transition_uses_returned_state_in_validation, [Expr::int(7)]);
fixture_ast_test!(lowers_transition_array_return_to_exact_output_count_match, [Expr::int(4), Expr::int(10)]);
fixture_ast_test!(lowers_singleton_transition_with_termination_allowed_to_array_cardinality_checks, [Expr::int(10)]);
fixture_ast_test!(lowers_auth_verification_groups_multiple_two_field_state, [Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_auth_verification_groups_single_two_field_state, [Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_auth_transition_two_field_state, [Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_cov_verification_two_field_state, [Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_cov_transition_two_field_state, [Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_cov_transition_single_field_state, [Expr::int(2), Expr::int(2), Expr::int(10)]);
fixture_ast_test!(lowers_inferred_auth_verification_two_field_state, [Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(
    lowers_inferred_cov_verification_two_field_state,
    [Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]
);
fixture_ast_test!(lowers_inferred_singleton_transition_two_field_state, [Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_singleton_sugar_transition_two_field_state, [Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_singleton_sugar_transition_termination_allowed_two_field_state, [Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(lowers_fanout_sugar_verification_two_field_state, [Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
fixture_ast_test!(
    lowers_many_covenant_declarations_in_one_contract,
    [Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]
);

#[test]
fn covers_attribute_config_combinations_with_two_field_state() {
    let source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function auth_verification_multi(
                State prev_state,
                State[] new_states,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function auth_verification_single(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function auth_transition(State prev_state, int fee) : (State) {
                return({ amount: prev_state.amount - fee, owner: prev_state.owner });
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function cov_verification(
                State[] prev_states,
                State[] new_states,
                int nonce
            ) {
                require(nonce >= 0);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function cov_transition(State[] prev_states, int fee) : (State[]) {
                require(fee >= 0);
                return(prev_states);
            }

            #[covenant(from = 1, to = max_outs)]
            function inferred_auth(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = max_ins, to = max_outs)]
            function inferred_cov(State[] prev_states, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = 1, to = 1)]
            function inferred_transition(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition)]
            function singleton_transition(State prev_state, int delta) : (State) {
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition, termination = allowed)]
            function singleton_terminate(State prev_state, State[] next_states) : (State[]) {
                require(prev_state.amount >= 0);
                return(next_states);
            }

            #[covenant.fanout(to = max_outs, mode = verification)]
            function fanout_verification(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let contract = compile_and_normalize_contract(source, &[Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(vec![7u8; 32])]);
    let functions = &contract.functions;

    let expected_entrypoints: HashSet<&str> = vec![
        "auth_verification_multi",
        "auth_verification_single",
        "auth_transition",
        "leader_cov_verification",
        "delegate_cov_verification",
        "leader_cov_transition",
        "delegate_cov_transition",
        "inferred_auth",
        "leader_inferred_cov",
        "delegate_inferred_cov",
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
        let policy = function_by_name(functions, policy_name);
        assert!(!policy.entrypoint, "policy '{}' must not be an entrypoint", policy_name);
    }

    assert_param_names(function_by_name(functions, "auth_verification_multi"), &["new_states", "nonce"]);
    assert_param_names(function_by_name(functions, "auth_verification_single"), &["new_states"]);
    assert_param_names(function_by_name(functions, "auth_transition"), &["fee"]);
    assert_param_names(function_by_name(functions, "leader_cov_verification"), &["new_states", "nonce"]);
    assert_param_names(function_by_name(functions, "delegate_cov_verification"), &[]);
    assert_param_names(function_by_name(functions, "leader_cov_transition"), &["fee"]);
    assert_param_names(function_by_name(functions, "delegate_cov_transition"), &[]);
    assert_param_names(function_by_name(functions, "inferred_auth"), &["new_states"]);
    assert_param_names(function_by_name(functions, "leader_inferred_cov"), &["new_states"]);
    assert_param_names(function_by_name(functions, "delegate_inferred_cov"), &[]);
    assert_param_names(function_by_name(functions, "inferred_transition"), &["delta"]);
    assert_param_names(function_by_name(functions, "singleton_transition"), &["delta"]);
    assert_param_names(function_by_name(functions, "singleton_terminate"), &["next_states"]);
    assert_param_names(function_by_name(functions, "fanout_verification"), &["new_states"]);
}
