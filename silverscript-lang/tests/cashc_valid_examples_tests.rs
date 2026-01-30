use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use std::fs;

fn load_example_source(name: &str) -> String {
    let path = format!("{}/tests/examples/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn parse_contract_param_types(source: &str) -> Vec<String> {
    let contract_pos = source.find("contract").expect("contract keyword");
    let after_contract = &source[contract_pos..];
    let open_paren = after_contract.find('(').expect("contract params");
    let after_open = &after_contract[open_paren + 1..];
    let close_paren = after_open.find(')').expect("closing paren");
    let params = &after_open[..close_paren];
    let mut result = Vec::new();
    for param in params.split(',') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let mut parts = param.split_whitespace();
        if let Some(type_name) = parts.next() {
            result.push(type_name.to_string());
        }
    }
    result
}

fn dummy_expr_for_type(type_name: &str) -> Expr {
    if type_name == "int" {
        return 0i64.into();
    }
    if type_name == "bool" {
        return false.into();
    }
    if type_name == "string" {
        return String::from("aa").into();
    }
    if type_name == "bytes" {
        return Vec::<u8>::new().into();
    }
    if type_name == "pubkey" {
        return vec![0u8; 32].into();
    }
    if type_name == "sig" {
        return vec![0u8; 64].into();
    }
    if type_name == "datasig" {
        return vec![0u8; 64].into();
    }
    if let Some(size) = type_name.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
        return vec![0u8; size].into();
    }
    0i64.into()
}

#[test]
fn compiles_cashc_valid_examples() {
    // Skipped examples (from cashc valid-contract-files) and reasons:
    // - 2_of_3_multisig.sil: uses checkMultiSig.
    // - multiline_array_multisig.cash: uses checkMultiSig.
    // - simple_multisig.cash: uses checkMultiSig.
    // - trailing_comma.cash: uses checkMultiSig.
    // - covenant_all_fields.cash: cashtoken-related logic.
    // - token_category_comparison.cash: cashtoken-related logic.
    let examples = [
        "bitwise.sil",
        "bytes1_equals_byte.sil",
        "cast_hash_checksig.sil",
        "comments.sil",
        "correct_pragma.sil",
        "covenant.sil",
        "date_literal.sil",
        "debug_messages.sil",
        "deep_replace.sil",
        "deeply_nested-logs.sil",
        "deeply_nested.sil",
        "double_split.sil",
        "force_cast_smaller_bytes.sil",
        "if_statement.sil",
        "if_statement_number_units-logs.sil",
        "if_statement_number_units.sil",
        "int_to_byte.sil",
        "integer_formatting.sil",
        "log_intermediate_results.sil",
        "multifunction.sil",
        "multifunction_if_statements.sil",
        "multiline_statements.sil",
        "multiplication.sil",
        "num2bin.sil",
        "num2bin_variable.sil",
        "p2pkh-logs.sil",
        "p2pkh_with_assignment.sil",
        "p2pkh_with_cast.sil",
        "reassignment.sil",
        "simple_cast.sil",
        "simple_checkdatasig.sil",
        "simple_constant.sil",
        "simple_covenant.sil",
        "simple_functions.sil",
        "simple_if_statement.sil",
        "simple_splice.sil",
        "simple_variables.sil",
        "simulating_state.sil",
        "slice.sil",
        "slice_optimised.sil",
        "slice_variable_parameter.sil",
        "split_or_slice_signature.sil",
        "split_size.sil",
        "split_typed.sil",
        "string_concatenation.sil",
        "string_with_escaped_characters.sil",
        "tuple_unpacking.sil",
        "tuple_unpacking_parameter.sil",
        "tuple_unpacking_single_side_type.sil",
    ];

    for example in examples {
        let source = load_example_source(example);
        let param_types = parse_contract_param_types(&source);
        let constructor_args = param_types.into_iter().map(|t| dummy_expr_for_type(&t)).collect::<Vec<_>>();
        let compiled = compile_contract(&source, &constructor_args, CompileOptions::default());
        assert!(compiled.is_ok(), "{example} failed to compile: {}", compiled.unwrap_err());
    }
}
