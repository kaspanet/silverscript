mod common;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_ecdsa_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    EngineCtx, EngineFlags, SeqCommitAccessor, TxScriptEngine, parse_script, pay_to_address_script, pay_to_script_hash_script,
    pay_to_script_hash_signature_script_with_flags, script_to_str, serialize_i64,
};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, TypeArtifact};
use silverscript_lang::ast::{
    ContractAst, DATASIG_BYTE_LEN, Expr, ExprKind, SIG_BYTE_LEN, Statement, format_contract_ast, parse_contract_ast, parse_type_ref,
};
use silverscript_lang::compiler::{
    COMPILER_VERSION, CompileOptions, CompiledContract, CompilerError, CovenantDeclCallOptions, DispatchTag,
    compile_contract as compile_internal_contract, compile_contract_ast, compile_debug_expr, compile_to_sil_abi_artifact,
    generated_covenant_auth_entrypoint_name, sil_abi_artifact_from_compiled, struct_object,
};
use silverscript_lang::debug_info::StepKind;
use silverscript_lang::template::template_hash;

use common::{
    build_sig_script_for_covenant_decl, bytecode, compile_contract, compiled_template_parts_and_hash, encode_entry_sig_script,
    encode_single_entry_sig_script, entry_by_name, single_contract, state_layout,
};

fn script_builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

fn artifact_object(fields: impl IntoIterator<Item = (&'static str, ArtifactValue)>) -> ArtifactValue {
    fields.into_iter().map(|(name, value)| (name.to_string(), value)).collect::<BTreeMap<_, _>>().into()
}

#[test]
fn constructors_validate_argument_types() {
    let cases = [
        ("ScriptPubKeyP2PK", "1", "publicKey", "pubkey", "byte[36]"),
        ("ScriptPubKeyP2SH", "byte[31](byte[]{0x00})", "scriptHash", "byte[32]", "byte[37]"),
        ("ScriptPubKeyP2SHFromRedeemScript", "1", "redeemScript", "byte[]", "byte[37]"),
    ];

    for (constructor, argument, parameter, expected, result_type) in cases {
        let source = format!(
            r#"
            contract Test() {{
                entry spend() {{
                    {result_type} script = new {constructor}({argument});
                    require(true);
                }}
            }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("constructor argument should be rejected");
        assert!(
            err.to_string().contains(&format!("argument '{parameter}' expects {expected}")),
            "unexpected error for {constructor}: {err}"
        );
    }
}

#[test]
fn artifact_with_options_preserves_compiled_output_and_state_layout() {
    let source = r#"
        contract Metadata(int initial) {
            int value = initial;

            entry main(int expected) {
                require(value == expected);
            }
        }
    "#;

    let default_artifact = compile_to_sil_abi_artifact(source, &[7.into()]).expect("default artifact compiles");
    let default_contract = single_contract(&default_artifact);
    assert!(default_contract.compiled.state_span.len > 0, "stateful contracts should expose a non-empty state layout");

    let artifact = compile_contract(source, &[7.into()], CompileOptions { record_debug_infos: true, ..CompileOptions::default() })
        .expect("artifact with debug recording compiles");
    assert_eq!(artifact, default_artifact, "debug recording should not change the portable artifact");
}

fn pay_to_script_hash_signature_script(
    redeem_script: Vec<u8>,
    signature_script: Vec<u8>,
) -> Result<Vec<u8>, kaspa_txscript::script_builder::ScriptBuilderError> {
    pay_to_script_hash_signature_script_with_flags(
        redeem_script,
        signature_script,
        EngineFlags { covenants_enabled: true, ..Default::default() },
    )
}

fn run_bytecode_with_dispatch_tag(bytecode: Vec<u8>, dispatch_tag: DispatchTag) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let sigscript = dispatch_tag_sigscript(dispatch_tag);
    run_bytecode_with_sigscript(bytecode, sigscript)
}

fn run_bytecode_with_tx(
    bytecode: Vec<u8>,
    dispatch_tag: DispatchTag,
    lock_time: u64,
    sequence: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let sigscript = dispatch_tag_sigscript(dispatch_tag);

    let input = TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([0u8; 32]), index: 0 },
        sigscript,
        sequence,
        0,
    );
    let output =
        TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, bytecode.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute()
}

fn dispatch_tag_sigscript(dispatch_tag: DispatchTag) -> Vec<u8> {
    let mut builder = script_builder();
    builder.add_data(&dispatch_tag).unwrap();
    builder.drain()
}

fn run_bytecode_with_sigscript(bytecode: Vec<u8>, sigscript: Vec<u8>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    run_bytecode_with_sigscript_and_time(bytecode, sigscript, 0, 0)
}

fn run_bytecode_with_sigscript_and_time(
    bytecode: Vec<u8>,
    sigscript: Vec<u8>,
    lock_time: u64,
    sequence: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 },
        sigscript,
        sequence,
        0,
    );
    let output =
        TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, bytecode.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute()
}

fn bytecode_op_counts(bytecode: &[u8]) -> (usize, usize) {
    let mut instruction_count = 0;
    let mut charged_op_count = 0;

    for opcode in parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(bytecode) {
        let opcode = opcode.expect("compiled bytecode should parse");
        instruction_count += 1;
        if !opcode.is_push_opcode() {
            charged_op_count += 1;
        }
    }

    (instruction_count, charged_op_count)
}

fn sigscript_push_bytecode(bytecode: &[u8]) -> Vec<u8> {
    script_builder().add_data_with_push_opcode(bytecode).unwrap().drain()
}

fn test_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8; 32]), index },
        signature_script,
        0,
        0,
    )
}

fn execute_input(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated_tx = PopulatedTransaction::new(&tx, entries);
    let utxo_entry = populated_tx.utxo(input_idx).expect("utxo entry for selected input");

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        input_idx,
        utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute()
}

fn pragma_source(pragma: Option<&str>) -> String {
    let pragma = pragma.map(|pragma| format!("{pragma}\n")).unwrap_or_default();
    format!(
        r#"
            {pragma}
            contract Versioned() {{
                entry main() {{
                    require(true);
                }}
            }}
        "#
    )
}

#[test]
fn accepts_compatible_pragma_versions() {
    let pragmas = [
        "pragma silverscript ^0.1.0;",
        "pragma silverscript ~0.1.0;",
        "pragma silverscript <0.2.0;",
        "pragma silverscript <=0.1.5;",
        "pragma silverscript =0.1.0;",
        "pragma silverscript 0.1.0;",
        "pragma silverscript >=0.1.0, <0.2.0;",
        "pragma silverscript >=0.1.0, <1.0.0;",
        "pragma silverscript 0.1.*;",
    ];

    for pragma in pragmas {
        let source = pragma_source(Some(pragma));
        compile_contract(&source, &[], CompileOptions::default()).unwrap_or_else(|err| panic!("{pragma} should compile: {err}"));
    }
}

#[test]
fn rejects_pragmas_that_cover_future_major_versions() {
    let pragmas = [
        "pragma silverscript >=0.1.0;",
        "pragma silverscript >0.0.9;",
        "pragma silverscript *;",
        "pragma silverscript <=1.0.0;",
        "pragma silverscript >=0.1.0, <2.0.0;",
    ];

    for pragma in pragmas {
        let source = pragma_source(Some(pragma));
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("future-major pragma should fail");
        assert!(
            err.to_string().contains("cannot support pragmas that cover future major versions because they may have breaking changes"),
            "{pragma} produced unexpected error: {err}"
        );
    }
}

#[test]
fn accepts_missing_pragma_without_version_check() {
    let source = pragma_source(None);
    compile_contract(&source, &[], CompileOptions::default()).expect("contract without pragma should still compile");
}

#[test]
fn compiled_contract_includes_compiler_version() {
    let source = pragma_source(None);
    let artifact = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(artifact.compiler_version, COMPILER_VERSION);
}

#[test]
fn rejects_incompatible_pragma_versions() {
    let pragmas = [
        "pragma silverscript ^0.2.0;",
        "pragma silverscript ~0.1.1;",
        "pragma silverscript <0.1.0;",
        "pragma silverscript <=0.0.9;",
        "pragma silverscript =0.1.1;",
        "pragma silverscript >=0.1.0, <0.1.0;",
    ];

    for pragma in pragmas {
        let source = pragma_source(Some(pragma));
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("incompatible pragma should fail");
        assert!(err.to_string().contains("does not satisfy pragma"), "{pragma} produced unexpected error: {err}");
    }
}

#[test]
fn rejects_invalid_semver_pragma_requirements() {
    let source = pragma_source(Some("pragma silverscript >=0.1.0 <0.2.0;"));
    let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("invalid semver requirement should fail");
    assert!(err.to_string().contains("invalid SilverScript version requirement"), "unexpected error: {err}");
}

#[test]
fn rejects_multiple_pragma_directives() {
    let source = r#"
        pragma silverscript ^0.1.0;
        pragma silverscript >=0.1.0, <0.2.0;

        contract Versioned() {
            entry main() {
                require(true);
            }
        }
    "#;
    let err = parse_contract_ast(source).expect_err("second pragma should fail");
    assert!(err.to_string().contains("parse error"), "unexpected error: {err}");
}

#[test]
fn accepts_constructor_args_with_matching_types() {
    let source = r#"
        contract Types(int a, bool b, string c, byte[] d, byte e, byte[4] f, pubkey pk, sig s, datasig ds) {
            entry main() {
                require(true);
            }
        }
    "#;
    let args = vec![
        7.into(),
        true.into(),
        "hello".into(),
        vec![1u8; 10].into(),
        2u8.into(),
        vec![3u8; 4].into(),
        vec![4u8; 32].into(),
        vec![5u8; 65].into(),
        vec![6u8; 64].into(),
    ];
    compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn supports_struct_contract_params_fields_and_constants() {
    let source = r#"
        contract TopLevelStructs(Pair init_pair) {
            struct Pair {
                int amount;
                byte[2] code;
            }

            Pair constant DEFAULT_PAIR = Pair {amount: 7, code: byte[_](0x1234)};
            Pair from_param = init_pair;
            Pair from_constant = DEFAULT_PAIR;

            entry main() {
                require(true);
            }
        }
    "#;

    let args = vec![artifact_object([("amount", 11.into()), ("code", vec![0xabu8, 0xcd].into())])];
    let compiled = compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "top-level struct param/field/constant contract should run: {result:?}");
}

#[test]
fn portable_abi_verifies_struct_contract_field_state_layout() {
    let source = r#"
        contract StructState(Pair init_pair) {
            struct Pair {
                int amount;
                byte[2] code;
            }

            Pair from_param = init_pair;

            entry main() {
                require(true);
            }
        }
    "#;
    let args = vec![artifact_object([("amount", 11.into()), ("code", vec![0xabu8, 0xcd].into())])];

    let abi = compile_to_sil_abi_artifact(source, &args).expect("struct state contract compiles to a portable ABI");

    abi.verify().expect("portable ABI runtime-state metadata matches the flattened state span");
}

#[test]
fn constructor_arguments_are_concrete_values_not_runtime_introspection() {
    let source = r#"
        contract RuntimeConstructor(int expected_lock_time) {
            entry main() {
                require(OpTxLockTime() == expected_lock_time);
            }
        }
    "#;

    let err = compile_internal_contract(source, &[Expr::call("OpTxLockTime", vec![])], CompileOptions::default())
        .expect_err("constructor arguments must not evaluate runtime expressions");
    assert!(err.to_string().contains("constructor argument 'expected_lock_time' must be a concrete value"), "unexpected error: {err}");
    let contract = parse_contract_ast(source).expect("contract parses");
    contract
        .resolve_contract_state_values(&[Expr::call("OpTxLockTime", vec![])])
        .expect_err("state resolution must enforce the same concrete constructor boundary");

    let struct_source = r#"
        contract StructConstructor(Pair pair) {
            struct Pair { int value; }

            entry main() {
                require(pair.value == 1);
            }
        }
    "#;
    let pair = artifact_object([("value", 1.into())]);
    compile_contract(struct_source, &[pair], CompileOptions::default())
        .expect("structs containing only concrete values remain valid constructor arguments");

    let runtime_pair = struct_object("Pair", vec![("value", Expr::call("OpTxLockTime", vec![]))]);
    compile_internal_contract(struct_source, &[runtime_pair], CompileOptions::default())
        .expect_err("runtime expressions nested in constructor structs must be rejected");

    let array_source = r#"
        contract ArrayConstructor(int[] values) {
            entry main() {
                require(values.length == 1);
            }
        }
    "#;
    let literal_values = ArtifactValue::Array(vec![1.into()]);
    compile_contract(array_source, &[literal_values], CompileOptions::default())
        .expect("arrays containing only concrete values remain valid constructor arguments");

    let runtime_values = Expr::array(parse_type_ref("int[]").expect("array type parses"), vec![Expr::call("OpTxLockTime", vec![])]);
    compile_internal_contract(array_source, &[runtime_values], CompileOptions::default())
        .expect_err("runtime expressions nested in constructor arrays must be rejected");
}

#[test]
fn nested_struct_field_path_does_not_alias_underscored_field_name() {
    let source = r#"
        contract C() {
            struct Inner { int b; }
            struct Outer {
                Inner a;
                int a_b;
            }

            entry main(Outer o) {
                require(o.a.b == o.a_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let outer = artifact_object([("a", artifact_object([("b", 1.into())])), ("a_b", 2.into())]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[outer]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err(), "different nested and underscored fields must make the require fail");
}

#[test]
fn resolve_contract_state_values_resolves_constructor_args_constants_and_prior_fields() {
    let source = r#"
        contract ResolveState(int initAmount, byte[2] initTag) {
            int constant DEFAULT_COUNT = 9;

            int amount = initAmount;
            byte[2] tag = initTag;
            int count = DEFAULT_COUNT;
            int mirrored = amount;

            entry spend() {
                require(true);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract parses");
    let state_fields =
        contract.resolve_contract_state_values(&[Expr::int(42), Expr::bytes(vec![0xab, 0xcd])]).expect("state values resolve");

    assert_eq!(state_fields.len(), 4);
    assert_eq!(state_fields[0].name, "amount");
    assert_eq!(state_fields[0].type_name, "int");
    assert_int_expr(&state_fields[0].value, 42);

    assert_eq!(state_fields[1].name, "tag");
    assert_eq!(state_fields[1].type_name, "byte[2]");
    assert_byte_array_expr(&state_fields[1].value, &[0xab, 0xcd]);

    assert_eq!(state_fields[2].name, "count");
    assert_eq!(state_fields[2].type_name, "int");
    assert_int_expr(&state_fields[2].value, 9);

    assert_eq!(state_fields[3].name, "mirrored");
    assert_eq!(state_fields[3].type_name, "int");
    assert_int_expr(&state_fields[3].value, 42);
}

#[test]
fn resolve_contract_state_values_rejects_constructor_arg_count_mismatch() {
    let source = r#"
        contract ResolveState(int initAmount) {
            int amount = initAmount;

            entry spend() {
                require(true);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract parses");
    let err = contract.resolve_contract_state_values(&[]).expect_err("missing constructor arg should fail");

    assert!(err.to_string().contains("constructor argument count mismatch"), "unexpected error: {err}");
}

#[test]
fn resolve_contract_state_values_rejects_constructor_arg_type_mismatch() {
    let source = r#"
        contract ResolveState(int initAmount) {
            int amount = initAmount;

            entry spend() {
                require(true);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract parses");
    let err = contract.resolve_contract_state_values(&[Expr::bool(true)]).expect_err("wrong constructor arg type should fail");

    assert!(err.to_string().contains("constructor argument 'initAmount' expects int"), "unexpected error: {err}");
}

#[test]
fn resolve_contract_state_values_checks_constructor_dependent_array_dimensions() {
    let source = r#"
        contract ResolveState(int N, byte[N] initial) {
            byte[N] stored = initial;

            entry spend() {
                require(true);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract parses");
    let err = contract
        .resolve_contract_state_values(&[Expr::int(2), Expr::bytes(vec![0xab])])
        .expect_err("a constructor-sized array must use the resolved preceding constructor parameter");

    assert!(err.to_string().contains("constructor argument 'initial' expects byte[N]"), "unexpected error: {err}");
}

#[test]
fn resolve_contract_state_values_rejects_resolved_field_type_mismatch() {
    let source = r#"
        contract ResolveState(byte[2] initTag) {
            int amount = initTag;

            entry spend() {
                require(true);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract parses");
    let err = contract
        .resolve_contract_state_values(&[Expr::bytes(vec![0xab, 0xcd])])
        .expect_err("field resolving to wrong type should fail");

    assert!(err.to_string().contains("contract field 'amount' expects int"), "unexpected error: {err}");
}

fn assert_int_expr(expr: &Expr<'_>, expected: i64) {
    assert!(matches!(&expr.kind, ExprKind::Int(value) if *value == expected), "expected int {expected}, got {expr:?}");
}

fn assert_byte_array_expr(expr: &Expr<'_>, expected: &[u8]) {
    let ExprKind::Array { values, .. } = &expr.kind else {
        panic!("expected byte array {expected:?}, got {expr:?}");
    };

    let actual = values
        .iter()
        .map(|value| match &value.kind {
            ExprKind::Byte(byte) => *byte,
            _ => panic!("expected byte array {expected:?}, got {expr:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn compile_contract_omits_debug_info_when_recording_disabled() {
    let source = r#"
        contract DebugToggle() {
            entry spend(int x) {
                require(x == x);
            }
        }
    "#;

    let compiled = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.debug_info.is_none());
}

#[test]
fn compile_contract_emits_debug_info_scaffold_when_recording_enabled() {
    let source = r#"
        contract DebugToggle(int seed) {
            int amount = 7;
            int constant BONUS = 2;

            entry spend(int x) {
                require(x + amount + seed + BONUS > 0);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_internal_contract(source, &[Expr::int(11)], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    assert!(!debug_info.steps.is_empty(), "debug recording should emit statement steps again");
    assert!(debug_info.steps.iter().all(|step| step.bytecode_end >= step.bytecode_start));
    assert!(debug_info.steps.iter().all(|step| step.span.line > 0));
    assert_eq!(debug_info.constructor_args.len(), 1);
    assert_eq!(debug_info.constructor_args[0].name, "seed");
    assert_eq!(debug_info.constants.len(), 1);
    assert_eq!(debug_info.constants[0].name, "BONUS");
    assert!(debug_info.params.iter().any(|param| param.name == "x"));
    assert!(debug_info.params.iter().any(|param| param.name == "amount"));

    let function = debug_info.functions.iter().find(|function| function.name == "spend").expect("function range for spend");
    assert!(function.bytecode_end > function.bytecode_start);
    assert!(debug_info.source.contains("contract DebugToggle"));
}

#[test]
fn compile_contract_debug_info_scaffold_records_dispatch_tag_entrypoint_ranges() {
    let source = r#"
        contract DebugDispatchTag() {
            entry a(int x) {
                require(x >= 0);
            }

            entry b(int x) {
                require(x > 0);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_internal_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let function_a = debug_info.functions.iter().find(|function| function.name == "a").expect("function range for a");
    let function_b = debug_info.functions.iter().find(|function| function.name == "b").expect("function range for b");

    assert!(function_a.bytecode_start > 0, "dispatch tag should prepend dispatcher ops");
    assert!(function_a.bytecode_start < function_b.bytecode_start, "entrypoint ranges should follow compile order");
    assert!(function_a.bytecode_end <= function_b.bytecode_start, "entrypoint ranges should not overlap");
}

#[test]
fn compile_contract_debug_info_records_inline_boundaries_and_return_bindings() {
    let source = r#"
        contract InlineCalls() {
            function addOne(int x) : (int) {
                int y = x + 1;
                return(y);
            }

            entry main(int a) {
                (int b) = addOne(a);
                require(b == a + 1);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_internal_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");
    let rendered_steps = debug_info
        .steps
        .iter()
        .map(|step| {
            format!(
                "seq={} kind={:?} line={} depth={} frame={} updates={:?}",
                step.sequence,
                step.kind,
                step.span.line,
                step.call_depth,
                step.frame_id,
                step.variable_updates.iter().map(|update| update.name.clone()).collect::<Vec<_>>()
            )
        })
        .collect::<Vec<_>>();

    assert!(
        debug_info.steps.iter().any(|step| matches!(step.kind, StepKind::InlineCallEnter { .. })),
        "expected inline enter step, got {rendered_steps:#?}"
    );
    assert!(
        debug_info.steps.iter().any(|step| matches!(step.kind, StepKind::InlineCallExit { .. })),
        "expected inline exit step, got {rendered_steps:#?}"
    );
    assert!(
        debug_info.steps.iter().any(|step| {
            matches!(step.kind, StepKind::InlineCallEnter { .. }) && step.variable_updates.iter().any(|update| update.name == "x")
        }),
        "expected inline enter to carry x, got {rendered_steps:#?}"
    );
    assert!(
        debug_info.steps.iter().any(|step| step.call_depth > 0 && step.variable_updates.iter().any(|update| update.name == "y")),
        "expected inline frame step to update y, got {rendered_steps:#?}"
    );
    assert!(
        debug_info.steps.iter().any(|step| {
            matches!(step.kind, StepKind::Source {})
                && step.call_depth == 0
                && step.span.line == 9
                && step.variable_updates.iter().any(|update| update.name == "b")
        }),
        "expected caller-side line 9 source step to update b, got {rendered_steps:#?}"
    );
}

#[test]
fn compile_contract_debug_info_preserves_structured_scope_inside_inline_calls() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract InlineStructuredEval() {
            int amount = 1;
            bool active = true;
            byte[1] tag = byte[1](0xaa);

            function inspect_inner(State inner_state) {
                int bumped = inner_state.amount + amount;
                require(bumped > 0);
            }

            entry inspect(State next_state) {
                inspect_inner(next_state);
                require(next_state.active == active);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_internal_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let inline_steps = debug_info
        .steps
        .iter()
        .filter(|step| step.frame_id != 0 && matches!(step.kind, StepKind::Source {}))
        .map(|step| (step.span.line, step.call_depth))
        .collect::<Vec<_>>();
    assert!(
        inline_steps.iter().any(|(line, depth)| *line == 10 && *depth > 0),
        "expected callee assignment line to stay in inline frame, got {inline_steps:?}"
    );
    assert!(
        inline_steps.iter().any(|(line, depth)| *line == 11 && *depth > 0),
        "expected callee require line to stay in inline frame, got {inline_steps:?}"
    );

    let inner_state_update = debug_info
        .steps
        .iter()
        .filter(|step| step.frame_id != 0)
        .flat_map(|step| step.variable_updates.iter())
        .find(|update| update.name == "inner_state" && update.structured_leaf_bindings.is_some())
        .expect("expected structured inline param update");
    let mut field_paths = inner_state_update
        .structured_leaf_bindings
        .as_ref()
        .expect("structured inline param should carry leaf bindings")
        .iter()
        .map(|leaf| leaf.field_path.join("."))
        .collect::<Vec<_>>();
    field_paths.sort();
    assert_eq!(field_paths, vec!["active".to_string(), "amount".to_string(), "tag".to_string()]);
}

#[test]
fn branch_heavy_if_else_logic_matches_rust_model_across_cases() {
    fn branch_maze_expected(a: i64, b: i64, c: i64, d: i64) -> (i64, i64, i64, i64) {
        let mut x = a + b;
        let mut y = c - d;
        let mut z = 1i64;
        let mut score = 0i64;

        if a > b {
            x += c;
            if c > 0 {
                y += a;
                score += 3;
            } else {
                z *= 2;
                score -= 2;
            }
        } else {
            x -= d;
            if d % 2 == 0 {
                y -= b;
                score += 5;
            } else {
                z += 3;
                score -= 1;
            }
        }

        if x > y {
            z += x - y;
            if (a + d) > (b + c) {
                score += z;
            } else {
                score -= z;
            }
        } else {
            x += z;
            y += z;
            if (c - a) > d {
                score += x;
            } else {
                score += y;
            }
        }

        if (x + y + z) % 2 == 0 {
            score += 7;
        } else {
            score -= 4;
        }

        if score > 10 {
            x -= 1;
        } else if score < -5 {
            y += 2;
        } else {
            z += 1;
        }

        (x, y, z, score)
    }

    let source = r#"
        contract BranchMaze() {
            entry main(
                int a,
                int b,
                int c,
                int d,
                int expected_x,
                int expected_y,
                int expected_z,
                int expected_score
            ) {
                int x = a + b;
                int y = c - d;
                int z = 1;
                int score = 0;

                if (a > b) {
                    x = x + c;
                    if (c > 0) {
                        y = y + a;
                        score = score + 3;
                    } else {
                        z = z * 2;
                        score = score - 2;
                    }
                } else {
                    x = x - d;
                    if ((d % 2) == 0) {
                        y = y - b;
                        score = score + 5;
                    } else {
                        z = z + 3;
                        score = score - 1;
                    }
                }

                if (x > y) {
                    z = z + x - y;
                    if ((a + d) > (b + c)) {
                        score = score + z;
                    } else {
                        score = score - z;
                    }
                } else {
                    x = x + z;
                    y = y + z;
                    if ((c - a) > d) {
                        score = score + x;
                    } else {
                        score = score + y;
                    }
                }

                if (((x + y) + z) % 2 == 0) {
                    score = score + 7;
                } else {
                    score = score - 4;
                }

                if (score > 10) {
                    x = x - 1;
                } else if (score < -5) {
                    y = y + 2;
                } else {
                    z = z + 1;
                }

                require(x == expected_x);
                require(y == expected_y);
                require(z == expected_z);
                require(score == expected_score);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("branch-heavy contract should compile");
    let bytecode_len = bytecode(&compiled).len();
    let (instruction_count, charged_op_count) = bytecode_op_counts(&bytecode(&compiled));
    println!("branch_maze {bytecode_len} / {instruction_count} / {charged_op_count}");
    // Snapshot these metrics exactly so compiler codegen changes must consciously
    // acknowledge their size impact on a branch-heavy stress case.
    assert_eq!(
        bytecode_len, 384,
        "branch_maze metrics: bytecode_len={bytecode_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        instruction_count, 380,
        "branch_maze metrics: bytecode_len={bytecode_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        charged_op_count, 274,
        "branch_maze metrics: bytecode_len={bytecode_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    let cases = [(7, 2, 5, 4), (7, 2, -3, 4), (2, 7, 5, 4), (2, 7, 5, 3), (4, 4, 9, 2), (-3, 1, 6, -2), (10, -1, -4, 7), (0, 0, 0, 0)];

    for (a, b, c, d) in cases {
        let (expected_x, expected_y, expected_z, expected_score) = branch_maze_expected(a, b, c, d);
        let sigscript = encode_entry_sig_script(
            &compiled,
            "main",
            &[
                ArtifactValue::Int(a),
                ArtifactValue::Int(b),
                ArtifactValue::Int(c),
                ArtifactValue::Int(d),
                ArtifactValue::Int(expected_x),
                ArtifactValue::Int(expected_y),
                ArtifactValue::Int(expected_z),
                ArtifactValue::Int(expected_score),
            ],
        )
        .expect("sigscript builds");
        let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
        assert!(
            result.is_ok(),
            "branch-heavy case ({a}, {b}, {c}, {d}) should match Rust model ({expected_x}, {expected_y}, {expected_z}, {expected_score}): {result:?}"
        );
    }

    let (a, b, c, d) = cases[0];
    let (expected_x, expected_y, expected_z, expected_score) = branch_maze_expected(a, b, c, d);
    let wrong_sigscript = encode_entry_sig_script(
        &compiled,
        "main",
        &[
            ArtifactValue::Int(a),
            ArtifactValue::Int(b),
            ArtifactValue::Int(c),
            ArtifactValue::Int(d),
            ArtifactValue::Int(expected_x),
            ArtifactValue::Int(expected_y),
            ArtifactValue::Int(expected_z),
            ArtifactValue::Int(expected_score + 1),
        ],
    )
    .expect("sigscript builds");
    let err = run_bytecode_with_sigscript(bytecode(&compiled).clone(), wrong_sigscript)
        .expect_err("branch-heavy case with wrong expected output should fail");
    assert!(format!("{err:?}").contains("Verify"), "wrong expected output should fail with verify error, got: {err:?}");
}

#[test]
fn sorting_network_over_fixed_array_matches_rust_model_across_cases() {
    fn sorted_expected(values: [i64; 8]) -> [i64; 8] {
        let mut values = values;
        values.sort_unstable();
        values
    }

    let source = r#"
        contract SortingNetworkCheck() {
            entry main(
                int[8] values,
                int expected_a,
                int expected_b,
                int expected_c,
                int expected_d,
                int expected_e,
                int expected_f,
                int expected_g,
                int expected_h
            ) {
                int a = values[0];
                int b = values[1];
                int c = values[2];
                int d = values[3];
                int e = values[4];
                int f = values[5];
                int g = values[6];
                int h = values[7];

                if (a > b) { int tmp = a; a = b; b = tmp; }
                if (c > d) { int tmp = c; c = d; d = tmp; }
                if (e > f) { int tmp = e; e = f; f = tmp; }
                if (g > h) { int tmp = g; g = h; h = tmp; }

                if (a > c) { int tmp = a; a = c; c = tmp; }
                if (b > d) { int tmp = b; b = d; d = tmp; }
                if (e > g) { int tmp = e; e = g; g = tmp; }
                if (f > h) { int tmp = f; f = h; h = tmp; }

                if (b > c) { int tmp = b; b = c; c = tmp; }
                if (f > g) { int tmp = f; f = g; g = tmp; }
                if (a > e) { int tmp = a; a = e; e = tmp; }
                if (d > h) { int tmp = d; d = h; h = tmp; }

                if (b > f) { int tmp = b; b = f; f = tmp; }
                if (c > g) { int tmp = c; c = g; g = tmp; }

                if (b > e) { int tmp = b; b = e; e = tmp; }
                if (d > g) { int tmp = d; d = g; g = tmp; }

                if (c > e) { int tmp = c; c = e; e = tmp; }
                if (d > f) { int tmp = d; d = f; f = tmp; }

                if (d > e) { int tmp = d; d = e; e = tmp; }

                require(a <= b);
                require(b <= c);
                require(c <= d);
                require(d <= e);
                require(e <= f);
                require(f <= g);
                require(g <= h);

                require(a == expected_a);
                require(b == expected_b);
                require(c == expected_c);
                require(d == expected_d);
                require(e == expected_e);
                require(f == expected_f);
                require(g == expected_g);
                require(h == expected_h);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("sorting-network contract should compile");
    let bytecode_len = bytecode(&compiled).len();
    let (instruction_count, charged_op_count) = bytecode_op_counts(&bytecode(&compiled));
    println!("sorting_network {bytecode_len} / {instruction_count} / {charged_op_count}");
    assert_eq!(
        bytecode_len, 829,
        "sorting_network metrics: bytecode_len={bytecode_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        instruction_count, 824,
        "sorting_network metrics: bytecode_len={bytecode_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        charged_op_count, 642,
        "sorting_network metrics: bytecode_len={bytecode_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );

    let cases = [
        [8, 7, 6, 5, 4, 3, 2, 1],
        [3, 1, 4, 1, 5, 9, 2, 6],
        [0, -3, 7, 7, -1, 4, 2, 2],
        [10, 0, -10, 5, -5, 3, 1, 8],
        [1, 2, 3, 4, 5, 6, 7, 8],
        [9, 9, 9, 1, 1, 1, 5, 5],
    ];

    for values in cases {
        let [expected_a, expected_b, expected_c, expected_d, expected_e, expected_f, expected_g, expected_h] = sorted_expected(values);
        let sigscript = encode_entry_sig_script(
            &compiled,
            "main",
            &[
                ArtifactValue::Array(values.into_iter().map(ArtifactValue::Int).collect()),
                ArtifactValue::Int(expected_a),
                ArtifactValue::Int(expected_b),
                ArtifactValue::Int(expected_c),
                ArtifactValue::Int(expected_d),
                ArtifactValue::Int(expected_e),
                ArtifactValue::Int(expected_f),
                ArtifactValue::Int(expected_g),
                ArtifactValue::Int(expected_h),
            ],
        )
        .expect("sigscript builds");
        let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
        assert!(result.is_ok(), "sorting-network case {values:?} should match Rust model: {result:?}");
    }
}

#[test]
fn rejects_constructor_args_with_wrong_scalar_types() {
    let source = r#"
        contract Types(int a, bool b, string c) {
            entry main() {
                require(true);
            }
        }
    "#;
    let args = vec![true.into(), 1.into(), vec![1u8].into()];
    assert!(compile_contract(source, &args, CompileOptions::default()).is_err());
}

#[test]
fn rejects_constructor_args_with_wrong_byte_lengths() {
    let source = r#"
        contract Types(byte b, byte[4] c, pubkey pk, sig s, datasig ds) {
            entry main() {
                require(true);
            }
        }
    "#;
    let args = vec![vec![1u8; 2].into(), vec![2u8; 3].into(), vec![3u8; 31].into(), vec![4u8; 63].into(), vec![5u8; 66].into()];
    assert!(compile_contract(source, &args, CompileOptions::default()).is_err());
}

#[test]
fn enforces_exact_sig_and_datasig_lengths_in_constructor_args() {
    let source = r#"
        contract Types(sig s, datasig ds) {
            entry main() {
                require(true);
            }
        }
    "#;

    let valid_args = vec![vec![7u8; 65].into(), vec![8u8; 64].into()];
    compile_contract(source, &valid_args, CompileOptions::default()).expect("compile succeeds");

    let invalid_sig = vec![vec![7u8; 64].into(), vec![8u8; 64].into()];
    assert!(compile_contract(source, &invalid_sig, CompileOptions::default()).is_err());

    let invalid_datasig = vec![vec![7u8; 65].into(), vec![8u8; 65].into()];
    assert!(compile_contract(source, &invalid_datasig, CompileOptions::default()).is_err());
}

#[test]
fn accepts_constructor_args_with_any_bytes_length() {
    let source = r#"
        contract Types(byte[] blob) {
            entry main() {
                require(true);
            }
        }
    "#;
    let args = vec![vec![9u8; 128].into()];
    compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn build_sig_script_builds_expected_script() {
    let source = r#"
        contract BoundedBytes() {
            entry spend(byte[4] b, int i) {
                require(b == i as byte[4]);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let args = vec![vec![1u8, 2, 3, 4].into(), 7.into()];
    let sigscript = encode_entry_sig_script(&compiled, "spend", &args).expect("sigscript builds");

    let dispatch_tag = dispatch_tag_for(&compiled, "spend");
    let mut builder = script_builder();
    builder.add_data_with_push_opcode(&[1u8, 2, 3, 4]).unwrap();
    builder.add_i64(7).unwrap();
    builder.add_data(&dispatch_tag).unwrap();
    let expected = builder.drain();

    assert_eq!(sigscript, expected);
}

#[test]
fn byte_variable_from_int_literal_uses_raw_byte_push() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte x = 5;
                require(OpBin2Num(byte[](x)) == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte int literal should compile");
    let body = script_builder()
        .add_data_with_push_opcode(&[5u8])
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpBin2Num)
        .unwrap()
        .add_i64(5)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let dispatch_tag = entry_by_name(&compiled, "main").expect("entrypoint resolved").dispatch_tag.into_bytes();
    let expected = wrap_with_single_dispatch_tag(dispatch_tag, &[], &body);
    assert_eq!(bytecode(&compiled), expected);
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok(), "byte int literal script should execute");
}

#[test]
fn byte_variable_from_out_of_range_int_literal_is_rejected() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte x = 256;
                require(true);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err(), "byte x = 256 should be rejected");
}

#[test]
fn byte_equality_uses_op_equal_not_op_numequal() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte x = 5;
                byte y = 7;
                require(x == y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte equality should compile");
    assert!(bytecode(&compiled).iter().copied().any(|op| op == OpEqual), "byte equality should use OP_EQUAL");
    assert!(!bytecode(&compiled).iter().copied().any(|op| op == OpNumEqual), "byte equality should not use OP_NUMEQUAL");
}

#[test]
fn byte_equality_with_rhs_int_literal_uses_raw_byte_push() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte x = 1;
                require(x == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte equality with rhs literal should compile");
    let body = script_builder()
        .add_data_with_push_opcode(&[1u8])
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_data_with_push_opcode(&[1u8])
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let dispatch_tag = entry_by_name(&compiled, "main").expect("entrypoint resolved").dispatch_tag.into_bytes();
    let expected = wrap_with_single_dispatch_tag(dispatch_tag, &[], &body);
    assert_eq!(bytecode(&compiled), expected);
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(
        run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok(),
        "byte equality with rhs literal should execute"
    );
}

#[test]
fn byte_equality_with_lhs_int_literal_is_rejected() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte x = 200;
                require(200 == x);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("200 == x should compare int against byte");
    assert!(err.to_string().contains("type mismatch: cannot compare int and byte"), "unexpected error: {err}");
}

#[test]
fn byte_equality_with_out_of_range_rhs_int_literal_is_rejected() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte x = 5;
                require(x == 256);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err(), "x == 256 should be rejected when x is a byte");
}

#[test]
fn rejects_arithmetic_operations_on_byte_expressions() {
    for operator in ["+", "-", "*", "/", "%"] {
        let literal_source = format!(
            r#"
                contract ByteLiterals() {{
                    entry main() {{
                        int result = byte(6) {operator} byte(2);
                        require(result == 0);
                    }}
                }}
            "#
        );
        compile_contract(&literal_source, &[], CompileOptions::default())
            .expect_err(&format!("byte literals should not support {operator} arithmetic"));

        let variable_source = format!(
            r#"
                contract ByteVariables() {{
                    entry main() {{
                        byte b1 = 6;
                        byte b2 = 2;
                        int result = b1 {operator} b2;
                        require(result == 0);
                    }}
                }}
            "#
        );
        compile_contract(&variable_source, &[], CompileOptions::default())
            .expect_err(&format!("byte variables should not support {operator} arithmetic"));
    }
}

#[test]
fn rejects_negating_a_byte_expression() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte value = 5;
                int result = -value;
                require(result == 0);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect_err("negating a byte should be rejected");
}

#[test]
fn allows_arithmetic_after_signed_or_unsigned_byte_conversion() {
    let source = r#"
        contract Bytes() {
            entry main() {
                byte b1 = 5;
                byte b2 = 7;
                int signedResult = signed(b1) + signed(b2);
                int unsignedResult = unsigned(b1) + unsigned(b2);
                require(signedResult == 12);
                require(unsignedResult == 12);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[], CompileOptions::default()).expect("explicit byte conversions should allow arithmetic");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert_eq!(opcodes.matches("OpAdd").count(), 2, "converted byte arithmetic must emit OpAdd: {opcodes}");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok(), "converted byte arithmetic should execute");
}

#[test]
fn rejects_bitwise_operations_on_integers() {
    for operator in ["&", "|", "^"] {
        let source = format!(
            r#"
                contract Bitwise() {{
                    entry main() {{
                        require((128 {operator} 1) == 0);
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err(&format!("integer operands for {operator} should be rejected"));
        assert!(
            err.to_string().contains("bitwise operations require bytes or byte arrays, got int and int"),
            "unexpected error for {operator}: {err}"
        );
    }
}

#[test]
fn allows_bitwise_operations_on_bytes() {
    for (operator, expected) in [("&", 0x04), ("|", 0x3f), ("^", 0x3b)] {
        let source = format!(
            r#"
                contract Bitwise() {{
                    entry main() {{
                        byte x = 0x34;
                        byte y = 0x0f;
                        byte result = x {operator} y;
                        require(result == {expected});
                    }}
                }}
            "#
        );

        let compiled = compile_contract(&source, &[], CompileOptions::default())
            .unwrap_or_else(|err| panic!("byte operands for {operator} should compile: {err}"));
        let dispatch_tag = dispatch_tag_for(&compiled, "main");
        let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
        assert!(result.is_ok(), "byte operands for {operator} should execute: {result:?}");
    }
}

#[test]
fn rejects_bitwise_operations_mixing_bytes_and_byte_arrays() {
    for operator in ["&", "|", "^"] {
        let source = format!(
            r#"
                contract Bitwise() {{
                    entry main() {{
                        byte x = 0x12;
                        byte[1] y = byte[_](0x34);
                        byte result = x {operator} y;
                        require(result == 0);
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err(&format!("mixed byte and byte-array operands for {operator} should be rejected"));
        assert!(
            err.to_string().contains("bitwise operations require bytes or byte arrays, got byte and byte[1]"),
            "unexpected error for {operator}: {err}"
        );
    }
}

#[test]
fn rejects_bitwise_operations_on_different_sized_byte_arrays() {
    for operator in ["&", "|", "^"] {
        let source = format!(
            r#"
                contract Bitwise() {{
                    entry main() {{
                        byte[2] x = byte[_](0x1234);
                        byte[3] y = byte[_](0x56789a);
                        byte[] result = x {operator} y;
                        require(result.length > 0);
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err(&format!("different-sized byte arrays for {operator} should be rejected"));
        assert!(
            err.to_string().contains("bitwise operations require byte arrays of equal size, got byte[2] and byte[3]"),
            "unexpected error for {operator}: {err}"
        );
    }
}

#[test]
fn allows_bitwise_operations_on_dynamic_byte_arrays_and_checks_size_at_runtime() {
    for (operator, expected) in [("&", vec![0x00, 0x04]), ("|", vec![0x5f, 0x3f]), ("^", vec![0x5f, 0x3b])] {
        let source = format!(
            r#"
                contract Bitwise() {{
                    entry main(byte[] x, byte[] y, byte[] expected) {{
                        require((x {operator} y) == expected);
                    }}
                }}
            "#
        );
        let compiled = compile_contract(&source, &[], CompileOptions::default())
            .unwrap_or_else(|err| panic!("dynamic byte arrays for {operator} should compile: {err}"));

        let sigscript = encode_entry_sig_script(
            &compiled,
            "main",
            &[ArtifactValue::Bytes(vec![0x12, 0x34]), ArtifactValue::Bytes(vec![0x4d, 0x0f]), ArtifactValue::Bytes(expected)],
        )
        .expect("matching dynamic byte-array arguments should build");
        let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
        assert!(result.is_ok(), "matching dynamic byte arrays for {operator} should execute: {result:?}");

        let sigscript = encode_entry_sig_script(
            &compiled,
            "main",
            &[ArtifactValue::Bytes(vec![0x12, 0x34]), ArtifactValue::Bytes(vec![0x4d]), ArtifactValue::Bytes(vec![0x00, 0x00])],
        )
        .expect("different-sized dynamic byte-array arguments should build");
        let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
        assert!(result.is_err(), "different-sized dynamic byte arrays for {operator} should fail at runtime");
    }
}

#[test]
fn build_sig_script_rejects_unknown_function() {
    let source = r#"
        contract C() {
            entry spend(int a) {
                require(a == 1);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = encode_entry_sig_script(&compiled, "missing", &[ArtifactValue::Int(1)]);
    assert!(result.is_err());
}

#[test]
fn disallow_comparing_byte_array_to_byte_constant() {
    let source = r#"
        contract Test(byte[32] genesisPk, byte genesisIdentifierType) {
            byte[32] ownerIdentifier = genesisPk;
            byte identifierType = genesisIdentifierType;
            byte constant ZERO = 0x00;

            entry main() {
                if (ownerIdentifier == ZERO) {
                    require(true);
                }
            }
        }
    "#;

    assert!(
        compile_contract(source, &[ArtifactValue::Bytes(vec![1u8; 32]), ArtifactValue::Byte(0)], CompileOptions::default()).is_err(),
        "comparing byte[32] to byte should be rejected without cast"
    );
}

#[test]
fn disallow_comparing_dynamic_and_fixed_byte_arrays_without_cast_in_contract_scope() {
    let source = r#"
        contract Test(byte[] x) {
            byte[2] y = byte[_](0x1234);

            entry main() {
                require(x == y);
            }
        }
    "#;

    assert!(
        compile_contract(source, &[ArtifactValue::Bytes(vec![0x12])], CompileOptions::default()).is_err(),
        "comparing byte[] to byte[2] should be rejected without cast"
    );
}

#[test]
fn allow_comparing_dynamic_and_fixed_byte_arrays_with_cast_in_contract_scope() {
    let source = r#"
        contract Test(byte[] x) {
            byte[2] y = byte[_](0x1234);

            entry main() {
                require(x == byte[](y));
            }
        }
    "#;

    compile_contract(source, &[ArtifactValue::Bytes(vec![0x12])], CompileOptions::default())
        .expect("comparing byte[] to byte[2] should be allowed with cast");
}

#[test]
fn opcode_builtins_return_their_declared_types() {
    let source = r#"
        contract Builtins() {
            entry main(pubkey pk, byte[] redeem_script) {
                byte[20] subnet_id = OpTxSubnetId();
                byte[32] outpoint_tx_id = OpOutpointTxId(0);
                byte[8] input_sequence = OpTxInputSeq(0);
                int lock_time = OpTxLockTime();
                byte[32] sequence_commitment = OpChainblockSeqCommit(
                    byte[_](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)
                );
                byte[36] p2pk = new ScriptPubKeyP2PK(pk);
                byte[37] p2sh = new ScriptPubKeyP2SH(outpoint_tx_id);
                byte[37] p2sh_from_redeem_script = new ScriptPubKeyP2SHFromRedeemScript(redeem_script);
                require(true);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("fixed-size builtin results should assign to their exact types");
}

#[test]
fn script_pubkey_constructors_return_correct_fixed_dimension_types() {
    let source = r#"
        contract ScriptPubKeyDimensions() {
            entry main() {
                byte[36] p2pk = new ScriptPubKeyP2PK(
                    pubkey(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)
                );
                byte[37] p2sh = new ScriptPubKeyP2SH(
                    byte[32](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)
                );
                byte[37] p2sh_from_redeem_script =
                    new ScriptPubKeyP2SHFromRedeemScript(byte[]("redeem"));

                require(byte[](p2pk).length == 36);
                require(byte[](p2sh).length == 37);
                require(byte[](p2sh_from_redeem_script).length == 37);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("script-pubkey constructors should compile");
    let sigscript = encode_single_entry_sig_script(&compiled, &[]).expect("signature script should build");
    run_bytecode_with_sigscript(bytecode(&compiled), sigscript)
        .expect("script-pubkey constructor results should have their declared lengths after conversion to byte[]");
}

#[test]
fn fixed_size_hash_builtins_return_their_declared_lengths() {
    let source = r#"
        contract FixedSizeHashes() {
            entry main() {
                byte[32] sha256_hash = sha256(byte[]("message"));
                byte[32] blake2b_hash = blake2b(byte[]("message"));
                byte[32] blake2b_keyed_hash = blake2bWithKey(
                    byte[]("message"),
                    byte[]("0123456789abcdef0123456789abcdef")
                );
                byte[32] blake3_hash = blake3(byte[]("message"));
                byte[32] blake3_keyed_hash = blake3WithKey(
                    byte[]("message"),
                    byte[32]("0123456789abcdef0123456789abcdef")
                );
                byte[32] template_hash = templateHash(byte[]("prefix"), byte[]("suffix"));

                require(byte[](sha256_hash).length == 32);
                require(byte[](blake2b_hash).length == 32);
                require(byte[](blake2b_keyed_hash).length == 32);
                require(byte[](blake3_hash).length == 32);
                require(byte[](blake3_keyed_hash).length == 32);
                require(byte[](template_hash).length == 32);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("fixed-size hash builtins should compile");
    let sigscript = encode_single_entry_sig_script(&compiled, &[]).expect("signature script should build");
    run_bytecode_with_sigscript(bytecode(&compiled), sigscript)
        .expect("fixed-size hash builtin results should have their declared lengths after conversion to byte[]");
}

#[test]
fn introspection_fields_and_direct_lock_opcodes_emit_and_execute() {
    let source = r#"
        contract Introspection() {
            entry main() {
                require(tx.inputs[0].value == 5000);
                require(tx.inputs[0].scriptPubKey.length >= 0);
                require(tx.inputs[0].sigScript.length == 5);
                byte[32] outpoint_tx_id = tx.inputs[0].outpointTxId;
                require(byte[](outpoint_tx_id).length == 32);
                require(outpoint_tx_id == byte[32]("0123456789abcdef0123456789abcdef"));
                require(tx.inputs[0].outpointIndex == 7);
                require(tx.outputs[0].value == 1000);
                require(tx.outputs[0].scriptPubKey.length >= 0);
                require(OpTxLockTime() == 0);
                require(OpTxInputSeq(0) == byte[8]("sequence"));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("all indexed introspection fields should compile");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode should stringify");
    for opcode in [
        "OpTxInputAmount",
        "OpTxInputSpk",
        "OpTxInputScriptSigLen",
        "OpTxInputScriptSigSubstr",
        "OpOutpointTxId",
        "OpOutpointIndex",
        "OpTxLockTime",
        "OpTxInputSeq",
        "OpTxOutputAmount",
        "OpTxOutputSpk",
    ] {
        assert!(opcodes.contains(opcode), "missing {opcode} in {opcodes}");
    }

    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let (tx, mut entries) = build_basic_opcode_tx(sigscript);
    entries[0].script_public_key = ScriptPublicKey::new(0, bytecode(&compiled).clone().into());
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let populated = PopulatedTransaction::new(&tx, entries);
    let covenants = CovenantsContext::from_tx(&populated).expect("covenants context should build");
    let context = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&covenants);
    let mut trace = Vec::new();
    let result = {
        let mut vm = TxScriptEngine::from_transaction_input(
            &populated,
            &tx.inputs[0],
            0,
            populated.utxo(0).expect("utxo entry for input 0"),
            context,
            EngineFlags { covenants_enabled: true, ..Default::default() },
        )
        .with_opcode_execution_log_buffer(&mut trace);
        vm.execute()
    };
    let trace = String::from_utf8_lossy(&trace);
    assert!(result.is_ok(), "indexed introspection execution failed:\n{trace}");
}

#[test]
fn rejects_assigning_fixed_size_builtin_results_to_wrong_byte_array_sizes() {
    let cases = [
        ("OpTxSubnetId", "byte[19] value = OpTxSubnetId();"),
        ("OpOutpointTxId", "byte[31] value = OpOutpointTxId(0);"),
        ("OpTxInputSeq", "byte[7] value = OpTxInputSeq(0);"),
        ("outpointTxId introspection", "byte[31] value = tx.inputs[0].outpointTxId;"),
        (
            "OpChainblockSeqCommit",
            "byte[31] value = OpChainblockSeqCommit(byte[32](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f));",
        ),
        (
            "ScriptPubKeyP2PK",
            "byte[35] value = new ScriptPubKeyP2PK(pubkey(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f));",
        ),
        (
            "ScriptPubKeyP2SH",
            "byte[36] value = new ScriptPubKeyP2SH(byte[32](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f));",
        ),
        ("ScriptPubKeyP2SHFromRedeemScript", "byte[36] value = new ScriptPubKeyP2SHFromRedeemScript(byte[](\"redeem\"));"),
    ];

    for (name, statement) in cases {
        let source = format!(
            r#"
                contract Builtins() {{
                    entry main() {{
                        {statement}
                        require(true);
                    }}
                }}
            "#
        );
        let err =
            compile_contract(&source, &[], CompileOptions::default()).expect_err(&format!("{name} should reject the wrong size"));
        assert!(err.to_string().contains("variable 'value' expects byte["), "{name}: unexpected error: {err}");
    }
}

#[test]
fn op_tx_lock_time_returns_int() {
    let source = "contract C() { entry main() { temporal value = OpTxLockTime(); } }";
    let error = compile_contract(source, &[], CompileOptions::default()).expect_err("OpTxLockTime must not return temporal");
    assert!(error.to_string().contains("variable 'value' expects temporal"), "unexpected error: {error}");

    let source = "contract C() { entry main() { require(OpTxLockTime(0) >= 0); } }";
    let error = compile_contract(source, &[], CompileOptions::default()).expect_err("OpTxLockTime must not accept arguments");
    assert!(error.to_string().contains("expects 0 arguments"), "unexpected error: {error}");
}

#[test]
fn rejects_removed_locktime_and_sequence_fields() {
    for statement in ["int value = tx.locktime;", "byte[8] value = tx.inputs[0].sequence;"] {
        let source = format!("contract C() {{ entry main() {{ {statement} }} }}");
        assert!(
            compile_contract(&source, &[], CompileOptions::default()).is_err(),
            "removed introspection field must be rejected: {statement}"
        );
    }
}

#[test]
fn rejects_comparing_different_scalar_types_without_cast() {
    let source = r#"
        contract Reproduce() {
            entry main() {
                if (1 == true) {
                    require(false);
                }
            }
        }
    "#;

    let result = compile_contract(source, &[], CompileOptions::default());
    assert!(result.is_err(), "int == bool should be rejected");
}

#[test]
fn disallow_comparing_dynamic_and_fixed_int_arrays_without_cast() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x = int[]{1};
                int[1] y = int[_]{1};
                require(x == y);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err(), "int[] == int[1] should be rejected");
}

#[test]
fn rejects_comparing_int_arrays_even_with_matching_casts() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x = int[]{1};
                int[1] y = int[_]{1};
                require(x == int[](y));
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("int[] comparison should be rejected");
    assert!(err.to_string().contains("array comparison is only supported"), "unexpected error: {err}");
}

#[test]
fn allows_comparing_inferred_and_fixed_byte_arrays_when_sizes_match() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[_] x = byte[_](0x1256);
                byte[2] y = byte[_](0x1234);
                require(x == y);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_ok(), "byte[_] should infer to byte[2]");
}

#[test]
fn rejects_comparing_inferred_and_fixed_byte_arrays_when_sizes_differ() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[_] x = byte[_](0x12);
                byte[2] y = byte[_](0x1234);
                require(x == y);
            }
        }
    "#;

    assert!(
        compile_contract(source, &[], CompileOptions::default()).is_err(),
        "byte[_] inferred as byte[1] should not compare to byte[2]"
    );
}

#[test]
fn rejects_inferred_array_size_when_initializer_cannot_provide_matching_fixed_array_type() {
    let cases = [
        (
            "literal values do not match declared element type",
            r#"
                int[_] x = int[]{1, true};
            "#,
            "array element type mismatch",
        ),
        (
            "identifier is unknown",
            r#"
                int[_] x = y;
            "#,
            "cannot infer fixed array size from variable 'x'",
        ),
        (
            "identifier is not an array",
            r#"
                int y = 1;
                int[_] x = y;
            "#,
            "cannot infer fixed array size from variable 'x'",
        ),
        (
            "identifier has a different array element type",
            r#"
                bool[2] y = bool[]{true, false};
                int[_] x = y;
            "#,
            "cannot infer fixed array size from variable 'x'",
        ),
        (
            "identifier has a dynamic array size",
            r#"
                int[] y = int[]{1, 2};
                int[_] x = y;
            "#,
            "cannot infer fixed array size from variable 'x'",
        ),
    ];

    for (name, body, expected_error) in cases {
        let source = format!(
            r#"
                contract Arrays() {{
                    entry main() {{
                        {body}
                        require(true);
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err(&format!("{name} should fail"));
        assert!(err.to_string().contains(expected_error), "{name}: expected error containing '{expected_error}', got: {err}");
    }
}

#[test]
fn infers_fixed_sizes_for_multiple_array_element_types() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[_] ints = int[_]{1, 2, 3, 4};
                int[4] ints_expected = int[_]{1, 2, 3, 4};
                bool[_] flags = bool[_]{true, false};
                bool[2] flags_expected = bool[_]{true, false};
                pubkey[_] keys = pubkey[_]{
                    pubkey(0x0101010101010101010101010101010101010101010101010101010101010101),
                    pubkey(0x0202020202020202020202020202020202020202020202020202020202020202)
                };
                pubkey[2] keys_expected = pubkey[_]{
                    pubkey(0x0303030303030303030303030303030303030303030303030303030303030303),
                    pubkey(0x0404040404040404040404040404040404040404040404040404040404040404)
                };
                require(ints.length == 4);
                require(ints_expected.length == 4);
                require(ints[0] == ints_expected[0]);
                require(ints[1] == ints_expected[1]);
                require(ints[2] == ints_expected[2]);
                require(ints[3] == ints_expected[3]);
                require(flags.length == 2);
                require(flags_expected.length == 2);
                require(flags[0] == flags_expected[0]);
                require(flags[1] == flags_expected[1]);
                require(keys.length == 2);
                require(keys_expected.length == 2);
                require(keys[0] == keys_expected[0]);
                require(keys[1] == keys_expected[1]);
            }
        }
    "#;

    assert!(
        compile_contract(source, &[], CompileOptions::default()).is_ok(),
        "type[_] should infer fixed sizes across supported element types"
    );
}

#[test]
fn infers_fixed_array_size_from_function_call_initializer_expression() {
    let source = r#"
        contract Arrays() {
            function makeArray(): int[3] {
                return int[_]{1, 2, 3};
            }

            entry main() {
                int[_] x = makeArray();
                require(x.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("int[_] x should infer from function call returning int[3]");
}

#[test]
fn infers_fixed_array_size_from_array_concat_initializer_expression() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[2] left = int[_]{1, 2};
                int[1] right = int[_]{3};
                int[_] x = left + right;
                require(x.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("int[_] x should infer from int[2] + int[1]");
}

#[test]
fn infers_nested_fixed_array_size_from_array_concat_initializer_expression() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[2][_] x = byte[2][_]{byte[2](0x0102), byte[2](0x0304)};
                byte[2][_] y = byte[2][_]{byte[2](0x0506)};
                byte[2][_] z = x + y;
                require(z.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("byte[2][_] z should infer from byte[2][2] + byte[2][1]");
}

#[test]
fn typed_array_literal_dimensions_compile_with_declared_semantics() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] dynamic = int[]{1, 2, 3};
                int[3] inferred = int[_]{1, 2, 3};
                int[3] fixed = int[3]{1, 2, 3};
                require(dynamic.length == 3);
                require(inferred.length == 3);
                require(fixed.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("valid typed array dimensions should compile");
}

#[test]
fn rejects_dynamic_array_literal_for_fixed_array_variable() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[1] values = int[]{1};
                require(values[0] == 1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("dynamic array literal should not initialize a fixed array variable");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
fn accepts_inferred_and_fixed_literals_for_fixed_array_variables() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[1] inferred = int[_]{1};
                int[1] fixed = int[1]{1};
                require(inferred[0] == 1);
                require(fixed[0] == 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("inferred and matching fixed array literals should initialize fixed arrays");
}

#[test]
fn rejects_fixed_typed_array_literal_size_mismatch() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[4] values = int[4]{1, 2, 3};
                require(values.length == 4);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("fixed literal length mismatch should fail");
    assert!(err.to_string().contains("array literal size mismatch: expected 4, got 3"), "unexpected error: {err}");
}

#[test]
fn rejects_nested_array_literal_with_unequal_element_lengths() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[][] values = byte[][]{byte[](0x01), byte[](0x0203)};
                require(values.length == 2);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("nested arrays with unequal element lengths should be rejected");
    assert!(err.to_string().contains("array element type must have known size: byte[][]"), "unexpected error: {err}");
}

#[test]
fn infers_fixed_array_size_from_ternary_initializer_expression() {
    let source = r#"
        contract Arrays() {
            entry main(bool flag) {
                int[3] left = int[_]{1, 2, 3};
                int[3] right = int[_]{4, 5, 6};
                int[_] x = flag ? left : right;
                require(x.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("int[_] x should infer from ternary branches typed int[3]");
}

#[test]
fn recursively_infers_fixed_array_size_from_inferred_array_identifier() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[_] x = int[_]{1, 2, 3};
                int[_] y = x;
                require(y.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("int[_] y should infer from previously inferred int[_] x");
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn inferred_array_in_branch_does_not_shadow_outer_inference_scope() {
    let source = r#"
        contract Arrays() {
            entry main(bool condition) {
                int[_] values = int[_]{1, 2};
                if (condition) {
                    bool[_] values = bool[_]{true};
                    require(values.length == 1);
                }

                int[_] copy = values;
                require(copy.length == 2);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("branch-local inferred arrays should not affect the outer inference scope");
}

#[test]
fn rejects_comparing_dynamic_and_fixed_arrays_without_cast_in_function_scope() {
    let source = r#"
        contract Arrays() {
            entry main(byte[] x) {
                byte[2] y = byte[_](0x1234);
                require(x == y);
            }
        }
    "#;

    assert!(
        compile_contract(source, &[], CompileOptions::default()).is_err(),
        "byte[] param should not compare to byte[2] without cast"
    );
}

#[test]
fn allows_comparing_dynamic_and_fixed_arrays_with_cast_in_function_scope() {
    let source = r#"
        contract Arrays() {
            entry main(byte[] x) {
                byte[2] y = byte[_](0x1234);
                require(x == byte[](y));
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_ok(), "byte[] param should compare to byte[](byte[2])");
}

#[test]
fn byte_array_to_fixed_byte_array_cast_compiles_without_num2bin() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[] route_templates = byte[](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f);
                byte[32] target_template = byte[32](route_templates.slice(16, 48));
                require(byte[](target_template) == route_templates.slice(16, 48));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte[] to byte[32] cast should compile");
    assert!(!bytecode(&compiled).iter().copied().any(|op| op == OpNum2Bin), "byte[] to byte[32] cast should not emit OpNum2Bin");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok(), "byte[] to byte[32] cast should execute");
}

#[test]
fn rejects_cast_between_different_fixed_byte_array_sizes() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[32] hash = byte[_](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f);
                byte[31] truncated = byte[31](hash);
                require(truncated.length == 31);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte[32] to byte[31] cast should be rejected");
    assert!(err.to_string().contains("cannot cast byte[32] to byte[31]"), "unexpected error: {err}");
}

#[test]
fn fixed_byte_scalars_accept_dynamic_and_compatible_fixed_byte_array_casts() {
    let source = r#"
        contract T() {
            entry f(byte[] dynamicBytes, byte[32] pubkeyBytes, byte[65] sigBytes, byte[64] datasigBytes) {
                pubkey dynamicPubkey = pubkey(dynamicBytes);
                sig dynamicSig = sig(dynamicBytes);
                datasig dynamicDatasig = datasig(dynamicBytes);

                pubkey fixedPubkey = pubkey(pubkeyBytes);
                sig fixedSig = sig(sigBytes);
                datasig fixedDatasig = datasig(datasigBytes);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("dynamic and correctly sized fixed byte arrays should cast to fixed-byte scalar types");
}

#[test]
fn rejects_cast_from_wrong_sized_fixed_bytes_to_signature() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract T() {
            entry f(byte[10] x, pubkey pk) {
                sig s = sig(x);
                require(checkSig(s, pk));
            }
        }
    "#;

    let err =
        compile_contract(source, &[], CompileOptions::default()).expect_err("a ten-byte value cannot be cast to a 65-byte signature");
    assert!(err.to_string().contains("cannot cast byte[10] to sig"), "unexpected error: {err}");
}

#[test]
fn rejects_cast_from_wrong_sized_fixed_bytes_to_fixed_byte_scalars() {
    for (source_type, target_type) in [("byte[31]", "pubkey"), ("byte[64]", "sig"), ("byte[63]", "datasig")] {
        let source = format!("contract T() {{ entry f({source_type} bytes) {{ {target_type} value = {target_type}(bytes); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("a fixed byte array with the wrong size must not cast to a fixed-byte scalar");
        assert!(err.to_string().contains(&format!("cannot cast {source_type} to {target_type}")), "unexpected error: {err}");
    }
}

#[test]
fn rejects_compile_time_incompatible_scalar_casts() {
    let cases = [
        ("pubkey pk = pubkey(5);", "cannot cast int to pubkey"),
        ("sig s = sig(5);", "cannot cast int to sig"),
        ("datasig d = datasig(\"not a sig\");", "cannot cast string to datasig"),
        ("int x = int(\"abc\");", "cannot cast string to int"),
        ("string s = string(5);", "cannot cast int to string"),
    ];

    for (statement, expected_error) in cases {
        let source = format!("pragma silverscript ^0.1.0; contract T() {{ entry f() {{ {statement} require(true); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("a compile-time incompatible scalar cast must be rejected");
        assert!(err.to_string().contains(expected_error), "unexpected error for `{statement}`: {err}");
    }
}

#[test]
fn int_cast_rejects_non_byte_arrays() {
    let cases = [
        "int[] values = int[]{1}; int result = int(values);",
        "bool[] values = bool[]{true}; int result = int(values);",
        "byte[1][1] values = byte[1][1]{byte[1](0x01)}; int result = int(values);",
    ];

    for statements in cases {
        let source = format!("contract T() {{ entry f() {{ {statements} require(result == result); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("int casts must only accept one-dimensional byte arrays");
        assert!(err.to_string().contains("cannot cast") && err.to_string().contains("to int"), "unexpected error: {err}");
    }
}

#[test]
fn bool_cast_accepts_only_a_singular_byte_as_its_source() {
    let source = r#"
        contract ByteBoolCast() {
            entry main() {
                bool set = bool(byte(1));
                bool unset = bool(byte(0));
                require(set);
                require(!unset);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte-to-bool casts should compile");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert_eq!(opcodes.matches("OpIf").count(), 1, "byte-to-bool casts should not add branching beyond dispatch: {opcodes}");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "byte-to-bool casts should preserve VM truthiness: {result:?}");
}

#[test]
fn bool_cast_rejects_every_non_byte_source_type() {
    for type_name in ["bool", "int", "byte[]", "byte[1]", "byte[1][1]", "int[]", "bool[]", "string", "pubkey", "sig", "datasig"] {
        let source =
            format!("contract T() {{ entry f({type_name} values) {{ bool result = bool(values); require(result == result); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("bool casts must only accept singular bytes");
        assert!(err.to_string().contains(&format!("cannot cast {type_name} to bool")), "unexpected error: {err}");
    }
}

#[test]
fn rejects_cast_between_different_fixed_non_byte_array_sizes() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[2] source = int[2]{1, 2};
                int[3] value = int[3](source);
                require(value.length == 3);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("fixed array cast size mismatch should fail");
    assert!(err.to_string().contains("cannot cast int[2] to int[3]"), "unexpected error: {err}");
}

#[test]
fn encodes_non_byte_array_literal_cast_in_contract_field() {
    let source = r#"
        contract Arrays() {
            int[2] values = int[2](int[]{1, 2});

            entry main() {
                require(values[0] == 1);
                require(values[1] == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("non-byte array literal cast should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(
        run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok(),
        "encoded non-byte array literal cast should execute"
    );
}

#[test]
fn allows_same_rank_multidimensional_array_cast_refinement() {
    let source = r#"
        contract Arrays() {
            entry main(int[2][] rows) {
                int[2][1] fixedRows = int[2][1](rows);
                require(fixedRows.length == 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("a multidimensional array cast may fix a dynamic dimension without changing rank");
}

#[test]
fn allows_array_cast_to_less_specific_dimensions() {
    let source = r#"
        contract Arrays() {
            entry main(int[2][1] rows) {
                int[2][] dynamicRows = int[2][](rows);
                require(dynamicRows.length == 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("a multidimensional array cast may make a fixed dimension dynamic without changing rank");
}

#[test]
fn allows_array_cast_without_dimension_changes() {
    let source = r#"
        contract Arrays() {
            entry main(int[2][1] rows) {
                int[2][1] sameRows = int[2][1](rows);
                require(sameRows.length == 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("an array cast may preserve every dimension");
}

#[test]
fn rejects_array_cast_that_changes_rank() {
    let source = r#"
        contract Arrays() {
            entry main(int[2][] rows) {
                int[2] row = int[2](rows);
                require(row.length == 2);
            }
        }
    "#;

    let err =
        compile_contract(source, &[], CompileOptions::default()).expect_err("an array cast must preserve the number of dimensions");
    assert!(err.to_string().contains("cannot cast int[2][] to int[2]"), "unexpected error: {err}");
}

#[test]
fn rejects_array_cast_with_incompatible_fixed_dimensions() {
    let source = r#"
        contract Arrays() {
            entry main(int[2][3] rows) {
                int[3][2] reshapedRows = int[3][2](rows);
                require(reshapedRows.length == 2);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("equal total size must not permit incompatible fixed dimensions");
    assert!(err.to_string().contains("cannot cast int[2][3] to int[3][2]"), "unexpected error: {err}");
}

#[test]
fn rejects_cast_from_smaller_fixed_byte_array_to_larger_fixed_byte_array() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[31] hash = byte[_](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e);
                byte[32] padded = byte[32](hash);
                require(padded.length == 32);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte[31] to byte[32] cast should be rejected");
    assert!(err.to_string().contains("cannot cast byte[31] to byte[32]"), "unexpected error: {err}");
}

#[test]
fn allows_array_concat_to_matching_size() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[2] left = byte[_](0x0102);
                byte[2] right = byte[_](0x0304);
                byte[4] combined = left + right;
                require(combined == byte[_](0x01020304));
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("byte[2] + byte[2] should cast to byte[4]");
}

#[test]
fn rejects_cast_from_fixed_byte_array_concat_to_wrong_size() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[2] left = byte[_](0x0102);
                byte[2] right = byte[_](0x0304);
                byte[5] combined = byte[5](left + right);
                require(combined.length == 5);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte[2] + byte[2] should not cast to byte[5]");
    assert!(err.to_string().contains("cannot cast byte[4] to byte[5]"), "unexpected error: {err}");
}

#[test]
fn rejects_fixed_byte_array_size_mismatch_inside_struct_literal() {
    let source = r#"
        contract Arrays() {
            struct Wrapped {
                byte[32] hash;
            }

            entry main() {
                byte[31] hash = byte[_](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e);
                Wrapped wrapped = Wrapped {hash: byte[32](hash)};
                require(wrapped.hash.length == 32);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("byte[31] to byte[32] cast inside struct literal should be rejected");
    assert!(
        err.to_string().contains("cannot cast byte[31] to byte[32]")
            || err.to_string().contains("struct field 'hash' expects byte[32]"),
        "unexpected error: {err}"
    );
}

#[test]
fn build_sig_script_rejects_wrong_argument_count() {
    let source = r#"
        contract C() {
            entry spend(int a, int b) {
                require(a == b);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = encode_entry_sig_script(&compiled, "spend", &[ArtifactValue::Int(1)]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_rejects_wrong_argument_type() {
    let source = r#"
        contract C() {
            entry spend(byte[4] b) {
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = encode_entry_sig_script(&compiled, "spend", &[ArtifactValue::Bytes(vec![1u8; 3])]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_for_covenant_decl_routes_to_hidden_auth_entrypoint() {
    let source = r#"
        contract Counter(int init_value) {
            int value = init_value;

            #[covenant.singleton]
            function step(State prev_state, State new_state) {
                require(new_state.value >= prev_state.value);
            }
        }
    "#;

    let compiled = compile_contract(source, &[ArtifactValue::Int(7)], CompileOptions::default()).expect("compile succeeds");
    let args = vec![artifact_object([("value", 8.into())])];

    let actual = build_sig_script_for_covenant_decl(&compiled, "step", args.clone(), CovenantDeclCallOptions { is_leader: false })
        .expect("covenant sigscript builds");
    let expected = encode_entry_sig_script(&compiled, &generated_covenant_auth_entrypoint_name("step"), &args)
        .expect("hidden entrypoint sigscript builds");

    assert_eq!(actual, expected);
}

#[test]
fn build_sig_script_for_covenant_decl_routes_to_hidden_cov_entrypoints() {
    let source = r#"
        contract Pair(int init_value) {
            int value = init_value;

            #[covenant(from = 2, to = 2)]
            function rebalance(State[] prev_states, State[] new_states) {
                require(new_states.length == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[ArtifactValue::Int(7)], CompileOptions::default()).expect("compile succeeds");
    let leader_args = vec![ArtifactValue::Array(vec![artifact_object([("value", 8.into())])])];

    let leader =
        build_sig_script_for_covenant_decl(&compiled, "rebalance", leader_args.clone(), CovenantDeclCallOptions { is_leader: true })
            .expect("leader sigscript builds");
    let expected_leader =
        encode_entry_sig_script(&compiled, "__leader_rebalance", &leader_args).expect("hidden leader sigscript builds");
    assert_eq!(leader, expected_leader);

    let delegate = build_sig_script_for_covenant_decl(&compiled, "rebalance", vec![], CovenantDeclCallOptions { is_leader: false })
        .expect("delegate sigscript builds");
    let expected_delegate = encode_entry_sig_script(&compiled, "__delegate", &[]).expect("hidden delegate sigscript builds");
    assert_eq!(delegate, expected_delegate);
}

#[test]
fn build_sig_script_for_covenant_decl_rejects_unknown_declaration() {
    let source = r#"
        contract C() {
            entry spend() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = build_sig_script_for_covenant_decl(&compiled, "missing", vec![], CovenantDeclCallOptions { is_leader: false });
    assert!(result.is_err());
}

#[test]
fn rejects_double_underscore_variable_names() {
    let source = r#"
        contract Bad() {
            entry main() {
                int __tmp = 1;
                require(__tmp == 1);
            }
        }
    "#;
    assert!(parse_contract_ast(source).is_err());

    let source = r#"
        contract Bad(int __arg) {
            entry main() {
                require(__arg == 1);
            }
        }
    "#;
    assert!(parse_contract_ast(source).is_err());
}

#[test]
fn rejects_double_underscore_function_names() {
    let source = r#"
        contract Bad() {
            function __hidden() {
                require(true);
            }

            entry main() {
                require(true);
            }
        }
    "#;

    assert!(parse_contract_ast(source).is_err());
}

#[test]
fn rejects_double_underscore_struct_names() {
    let source = r#"
        contract Bad() {
            struct __Hidden {
                int value;
            }

            entry main() {
                require(true);
            }
        }
    "#;

    assert!(parse_contract_ast(source).is_err());
}

#[test]
fn rejects_struct_named_state() {
    let source = r#"
        contract Bad() {
            struct State {
                int value;
            }

            entry main() {
                require(true);
            }
        }
    "#;

    assert!(parse_contract_ast(source).is_err());
}

#[test]
fn rejects_external_call_without_entrypoint() {
    let source = r#"
        contract Entry() {
            function helper() {
                require(true);
            }

            entry main() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = encode_entry_sig_script(&compiled, "helper", &[ArtifactValue::Int(1)]);
    assert!(result.is_err());
}

#[test]
fn rejects_entrypoint_return_by_default() {
    let source = r#"
        contract EntryReturn() {
            entry main() : (int) {
                return(1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("entrypoint return should be disallowed by default");
    assert!(err.to_string().contains("entrypoint return requires allow_entrypoint_return=true"));
}

#[test]
fn allowed_entrypoint_return_requires_a_return_statement() {
    let source = r#"
        contract EntryReturn() {
            entry main() : int {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions { allow_entrypoint_return: true, ..CompileOptions::default() })
        .expect_err("a return-typed entrypoint must return a value");
    assert!(err.to_string().contains("function 'main' declares return types but has no return statement"), "unexpected error: {err}");
}

#[test]
fn allowed_entrypoint_return_checks_the_return_value_type() {
    let source = r#"
        contract EntryReturn() {
            entry main() : int {
                return false;
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions { allow_entrypoint_return: true, ..CompileOptions::default() })
        .expect_err("an entrypoint return value must match its declared type");
    assert!(err.to_string().contains("return value expects int"), "unexpected error: {err}");
}

#[test]
fn helper_with_declared_return_type_requires_a_return_statement() {
    let source = r#"
        contract HelperReturn() {
            function value() : int {
                require(true);
            }

            entry main() {
                value();
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("a return-typed helper must return a value");
    assert!(err.to_string().contains("function 'value' declares return types but has no return statement"), "unexpected error: {err}");
}

#[test]
fn build_sig_script_rejects_mismatched_bytes_length() {
    let source = r#"
        contract C() {
            entry spend(byte[4] b) {
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = encode_entry_sig_script(&compiled, "spend", &[ArtifactValue::Bytes(vec![1u8; 5])]);
    assert!(result.is_err());

    let source = r#"
        contract C() {
            entry spend(byte[5] b) {
                require(b.length == 5);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = encode_entry_sig_script(&compiled, "spend", &[ArtifactValue::Bytes(vec![1u8; 4])]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_appends_dispatch_tag_for_single_entrypoint() {
    let source = r#"
        contract Single() {
            entry spend(int a, byte[4] b) {
                require(a == 1);
                require(b.length == 4);
            }
        }
    "#;
    let artifact = compile_to_sil_abi_artifact(source, &[]).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&artifact, &[1.into(), vec![2u8; 4].into()]).expect("sigscript builds");
    let dispatch_tag =
        artifact.contract("Single").and_then(|contract| contract.entry("spend")).expect("entrypoint resolved").dispatch_tag;

    let expected = script_builder()
        .add_i64(1)
        .unwrap()
        .add_data_with_push_opcode(&[2u8; 4])
        .unwrap()
        .add_data(dispatch_tag.as_bytes())
        .unwrap()
        .drain();
    assert_eq!(sigscript, expected);
}

#[test]
fn compiles_struct_sugar_for_locals_calls_and_field_access() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            function f(S x) {
                require(x.a == 0);
                require(x.b.length == 5);
            }

            entry main() {
                f(S {a: 0, b: "12345"});
                S y = S {a: 0, b: "22345"};
                f(y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "script should execute successfully: {result:?}");
}

#[test]
fn compiles_struct_return_types_in_inline_calls() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            function make(int a) : (S) {
                return(S {a: a, b: "12345"});
            }

            function check(S x) {
                require(x.a == 0);
                require(x.b.length == 5);
            }

            entry main() {
                (S out) = make(0);
                check(out);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "struct-return inline call should execute successfully: {result:?}");
}

#[test]
fn build_sig_script_supports_struct_entrypoint_arguments() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            entry main(S x) {
                require(x.a == 0);
                require(x.b.length == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let arg = artifact_object([("a", 0.into()), ("b", "12345".into())]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[arg]).expect("sigscript builds");

    let expected = script_builder()
        .add_i64(0)
        .unwrap()
        .add_data_with_push_opcode(b"12345")
        .unwrap()
        .add_data(&dispatch_tag_for(&compiled, "main"))
        .unwrap()
        .drain();
    assert_eq!(sigscript, expected);
}

#[test]
fn build_sig_script_supports_state_entrypoint_arguments() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main(State s) {
                require(s.x == 9);
                require(s.y == byte[_](0x3412));
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let arg = artifact_object([("x", 9.into()), ("y", vec![0x34u8, 0x12].into())]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[arg]).expect("sigscript builds");

    let expected = script_builder()
        .add_i64(9)
        .unwrap()
        .add_data_with_push_opcode(&[0x34, 0x12])
        .unwrap()
        .add_data(&dispatch_tag_for(&compiled, "main"))
        .unwrap()
        .drain();
    assert_eq!(sigscript, expected);
}

#[test]
fn build_sig_script_supports_sig_array_arguments() {
    let source = r#"
        contract C() {
            entry main(sig[] sigs) {
                require(sigs.length == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sig_a = vec![0x11u8; 65];
    let sig_b = vec![0x22u8; 65];
    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Array(vec![sig_a.clone().into(), sig_b.clone().into()])])
            .expect("sigscript builds");

    let mut encoded = sig_a;
    encoded.extend(sig_b);
    let expected =
        script_builder().add_data_with_push_opcode(&encoded).unwrap().add_data(&dispatch_tag_for(&compiled, "main")).unwrap().drain();
    assert_eq!(sigscript, expected);
}

fn struct_array_arg(values: Vec<(i64, Vec<u8>)>) -> ArtifactValue {
    ArtifactValue::Array(values.into_iter().map(|(a, b)| artifact_object([("a", a.into()), ("b", b.into())])).collect())
}

fn fixed_struct_array_arg(values: Vec<(i64, Vec<u8>)>) -> ArtifactValue {
    struct_array_arg(values)
}

fn state_array_arg(values: Vec<i64>) -> ArtifactValue {
    ArtifactValue::Array(values.into_iter().map(|value| artifact_object([("value", value.into())])).collect())
}

fn state_array_arg_x(values: Vec<i64>) -> ArtifactValue {
    ArtifactValue::Array(values.into_iter().map(|value| artifact_object([("x", value.into())])).collect())
}

fn matrix_state_array_arg(values: Vec<(i64, Vec<u8>)>) -> ArtifactValue {
    ArtifactValue::Array(
        values.into_iter().map(|(amount, owner)| artifact_object([("amount", amount.into()), ("owner", owner.into())])).collect(),
    )
}

fn replace_compiled_interface<'i>(
    compiled: &mut CompiledContract<'i>,
    source: &'i str,
    old_dispatch_tag: DispatchTag,
    new_dispatch_tag: DispatchTag,
) {
    compiled.ast = parse_contract_ast(source).expect("interface parses");
    let tag_offset = compiled
        .bytecode
        .windows(old_dispatch_tag.len())
        .position(|window| window == old_dispatch_tag)
        .expect("original dispatch tag exists");
    compiled.bytecode[tag_offset..tag_offset + new_dispatch_tag.len()].copy_from_slice(&new_dispatch_tag);
}

#[test]
fn build_sig_script_for_covenant_decl_supports_all_covenant_ast_examples() {
    struct Case {
        source: &'static str,
        constructor_args: Vec<ArtifactValue>,
        function_name: &'static str,
        args: Vec<ArtifactValue>,
        options: CovenantDeclCallOptions,
        generated_covenant_entrypoint_name: &'static str,
    }

    let owner = vec![7u8; 32];
    let next_owner = vec![9u8; 32];
    let matrix_singleton_transition_source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.singleton(mode = transition)]
            function step(State prev_state, int delta) : (State) {
                return(State { amount: prev_state.amount + delta, owner: prev_state.owner });
            }
        }
    "#;
    let matrix_singleton_terminate_source = r#"
        contract Matrix(int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.singleton(mode = transition, termination = allowed)]
            function step(State prev_state, State[] next_states) : (State[]) {
                return(next_states);
            }
        }
    "#;
    let matrix_fanout_verification_source = r#"
        contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant.fanout(to = max_outs, mode = verification)]
            function step(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;
    let matrix_auth_source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
            function auth_verification_multi(State prev_state, State[] new_states, int nonce) {
                require(nonce >= 0);
            }

            #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
            function auth_verification_single(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(binding = auth, from = 1, to = 1, mode = transition)]
            function auth_transition(State prev_state, int fee) : (State) {
                return(State { amount: prev_state.amount - fee, owner: prev_state.owner });
            }

            #[covenant(from = 1, to = max_outs)]
            function inferred_auth(State prev_state, State[] new_states) {
                require(new_states.length == new_states.length);
            }

            #[covenant(from = 1, to = 1)]
            function inferred_transition(State prev_state, int delta) : (State) {
                return(State { amount: prev_state.amount + delta, owner: prev_state.owner });
            }

            #[covenant.singleton(mode = transition)]
            function singleton_transition(State prev_state, int delta) : (State) {
                return(State { amount: prev_state.amount + delta, owner: prev_state.owner });
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
    let matrix_cov_source = r#"
        contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
            int amount = init_amount;
            byte[32] owner = init_owner;

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function cov_verification(State[] prev_states, State[] new_states, int nonce) {
                require(nonce >= 0);
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
            function cov_transition(State[] prev_states, int fee) : (State[]) {
                require(fee >= 0);
                return(prev_states);
            }

            #[covenant(from = max_ins, to = max_outs)]
            function inferred_cov(State[] prev_states, State[] new_states) {
                require(new_states.length == new_states.length);
            }
        }
    "#;

    let cases = vec![
        Case {
            source: r#"
                contract Decls(int max_outs) {
                    int value = 0;

                    #[covenant(binding = auth, from = 1, to = max_outs, groups = single)]
                    function split(State prev_state, State[] new_states, int amount) {
                        require(amount >= 0);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(4)],
            function_name: "split",
            args: vec![state_array_arg(vec![11]), ArtifactValue::Int(3)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__split",
        },
        Case {
            source: r#"
                contract Decls(int max_ins, int max_outs) {
                    int value = 0;

                    #[covenant(from = max_ins, to = max_outs, mode = verification)]
                    function transition_ok(State[] prev_states, State[] new_states, int delta) {
                        require(delta >= 0);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(2), ArtifactValue::Int(3)],
            function_name: "transition_ok",
            args: vec![state_array_arg(vec![10, 11]), ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_transition_ok",
        },
        Case {
            source: r#"
                contract Decls(int max_ins, int max_outs) {
                    int value = 0;

                    #[covenant(from = max_ins, to = max_outs, mode = verification)]
                    function transition_ok(State[] prev_states, State[] new_states, int delta) {
                        require(delta >= 0);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(2), ArtifactValue::Int(3)],
            function_name: "transition_ok",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: r#"
                contract Decls(int init_value) {
                    int value = init_value;

                    #[covenant.singleton(mode = transition)]
                    function bump(State prev_state, int delta) : (State) {
                        return(State { value: prev_state.value + delta });
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(7)],
            function_name: "bump",
            args: vec![ArtifactValue::Int(2)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__bump",
        },
        Case {
            source: r#"
                contract Decls(int max_outs, int init_value) {
                    int value = init_value;

                    #[covenant(from = 1, to = max_outs, mode = transition)]
                    function fanout(State prev_state, State[] next_states) : (State[]) {
                        return(next_states);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(4), ArtifactValue::Int(10)],
            function_name: "fanout",
            args: vec![state_array_arg(vec![11, 12])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__fanout",
        },
        Case {
            source: r#"
                contract Decls(int init_value) {
                    int value = init_value;

                    #[covenant.singleton(mode = transition, termination = allowed)]
                    function bump_or_terminate(State prev_state, State[] next_states) : (State[]) {
                        return(next_states);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(10)],
            function_name: "bump_or_terminate",
            args: vec![state_array_arg(vec![13])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__bump_or_terminate",
        },
        Case {
            source: r#"
                contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
                    function step(State prev_state, State[] new_states, int nonce) {
                        require(nonce >= 0);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(4), ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), ArtifactValue::Int(0)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: r#"
                contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
                    function step(State prev_state, State[] new_states) {
                        require(new_states.length == new_states.length);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(4), ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: r#"
                contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = auth, from = 1, to = 1, mode = transition)]
                    function step(State prev_state, int fee) : (State) {
                        return(State { amount: prev_state.amount - fee, owner: prev_state.owner });
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(4), ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: r#"
                contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
                    function step(State[] prev_states, State[] new_states, int nonce) {
                        require(nonce >= 0);
                    }
                }
            "#,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), ArtifactValue::Int(0)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_step",
        },
        Case {
            source: r#"
                contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
                    function step(State[] prev_states, State[] new_states, int nonce) {
                        require(nonce >= 0);
                    }
                }
            "#,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "step",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: r#"
                contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
                    function step(State[] prev_states, int fee) : (State[]) {
                        require(fee >= 0);
                        return(prev_states);
                    }
                }
            "#,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "step",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_step",
        },
        Case {
            source: r#"
                contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
                    function step(State[] prev_states, int fee) : (State[]) {
                        require(fee >= 0);
                        return(prev_states);
                    }
                }
            "#,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "step",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: r#"
                contract Matrix(int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(from = 1, to = max_outs)]
                    function step(State prev_state, State[] new_states) {
                        require(new_states.length == new_states.length);
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(4), ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: r#"
                contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(from = max_ins, to = max_outs)]
                    function step(State[] prev_states, State[] new_states) {
                        require(new_states.length == new_states.length);
                    }
                }
            "#,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_step",
        },
        Case {
            source: r#"
                contract Matrix(int max_ins, int max_outs, int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(from = max_ins, to = max_outs)]
                    function step(State[] prev_states, State[] new_states) {
                        require(new_states.length == new_states.length);
                    }
                }
            "#,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "step",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: r#"
                contract Matrix(int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(from = 1, to = 1)]
                    function step(State prev_state, int delta) : (State) {
                        return(State { amount: prev_state.amount + delta, owner: prev_state.owner });
                    }
                }
            "#,
            constructor_args: vec![ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_singleton_transition_source,
            constructor_args: vec![ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_singleton_terminate_source,
            constructor_args: vec![ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_fanout_verification_source,
            constructor_args: vec![ArtifactValue::Int(4), ArtifactValue::Int(10), ArtifactValue::Bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "auth_verification_multi",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), ArtifactValue::Int(0)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__auth_verification_multi",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "auth_verification_single",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__auth_verification_single",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "auth_transition",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__auth_transition",
        },
        Case {
            source: matrix_cov_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "cov_verification",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), ArtifactValue::Int(0)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_cov_verification",
        },
        Case {
            source: matrix_cov_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "cov_verification",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: matrix_cov_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "cov_transition",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_cov_transition",
        },
        Case {
            source: matrix_cov_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "cov_transition",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "inferred_auth",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__inferred_auth",
        },
        Case {
            source: matrix_cov_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "inferred_cov",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_inferred_cov",
        },
        Case {
            source: matrix_cov_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "inferred_cov",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "inferred_transition",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__inferred_transition",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "singleton_transition",
            args: vec![ArtifactValue::Int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__singleton_transition",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "singleton_terminate",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__singleton_terminate",
        },
        Case {
            source: matrix_auth_source,
            constructor_args: vec![
                ArtifactValue::Int(2),
                ArtifactValue::Int(4),
                ArtifactValue::Int(10),
                ArtifactValue::Bytes(owner.clone()),
            ],
            function_name: "fanout_verification",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__fanout_verification",
        },
    ];

    for case in cases {
        let compiled = compile_contract(case.source, &case.constructor_args, CompileOptions::default()).expect("compile succeeds");
        let sigscript = build_sig_script_for_covenant_decl(&compiled, case.function_name, case.args.clone(), case.options)
            .expect("covenant declaration sigscript builds");
        let generated_entrypoint_name = if case.generated_covenant_entrypoint_name.starts_with("__leader_")
            || case.generated_covenant_entrypoint_name == "__delegate"
        {
            case.generated_covenant_entrypoint_name.to_string()
        } else {
            generated_covenant_auth_entrypoint_name(case.function_name)
        };
        let expected =
            encode_entry_sig_script(&compiled, &generated_entrypoint_name, &case.args).expect("generated entrypoint sigscript builds");
        assert_eq!(sigscript, expected, "covenant declaration sigscript should match generated entrypoint for {}", case.function_name);
    }
}

#[test]
fn runtime_rejects_regular_struct_array_entrypoint_arguments_without_struct_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(int[] items_a, byte[2][] items_b) {
                require(items_a.length == 2);
                require(items_b.length == 2);
                require(items_a[0] == 7);
                require(items_a[1] == 9);
                require(items_b[0] == byte[_](0x0102));
                require(items_b[1] == byte[_](0x0304));
            }
        }
    "#;

    let lowered = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("portable artifact compiles");
    let main_param_types: Vec<String> = lowered
        .ast
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(main_param_types, vec!["int[]".to_string(), "byte[2][]".to_string()]);

    let err = encode_entry_sig_script(&compiled, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect_err("struct[] arguments should be rejected when the entrypoint signature is not struct-typed");
    assert!(err.to_string().contains("expects 2 arguments"), "unexpected error: {err}");
}

#[test]
fn runtime_supports_regular_struct_array_entrypoint_arguments_with_struct_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(int[] items_a, byte[2][] items_b) {
                require(items_a.length == 2);
                require(items_b.length == 2);
                require(items_a[0] == 7);
                require(items_a[1] == 9);
                require(items_b[0] == byte[_](0x0102));
                require(items_b[1] == byte[_](0x0304));
            }
        }
    "#;

    let struct_signature_source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == byte[_](0x0102));
                require(x[1].b == byte[_](0x0304));
            }
        }
    "#;

    let mut compiled = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let original_artifact = compile_to_sil_abi_artifact(source, &[]).expect("original interface compiles");
    let old_dispatch_tag = single_contract(&original_artifact).entry("main").expect("main entry exists").dispatch_tag.into_bytes();
    let interface_artifact = compile_to_sil_abi_artifact(struct_signature_source, &[]).expect("struct interface compiles");
    let dispatch_tag = single_contract(&interface_artifact).entry("main").expect("main entry exists").dispatch_tag.into_bytes();
    replace_compiled_interface(&mut compiled, struct_signature_source, old_dispatch_tag, dispatch_tag);

    let main_param_types: Vec<String> = compiled
        .ast
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(main_param_types, vec!["S[]".to_string()]);

    let sigscript =
        encode_entry_sig_script(&interface_artifact, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
            .expect("sigscript builds");
    let result = run_bytecode_with_sigscript(compiled.bytecode, sigscript);

    assert!(result.is_ok(), "regular struct[] entrypoint arg should execute successfully: {result:?}");
}

#[test]
fn runtime_supports_direct_struct_array_entrypoint_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry f(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == byte[_](0x0102));
                require(x[1].b == byte[_](0x0304));
            }
        }
    "#;

    let lowered = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("portable artifact compiles");
    let f_param_types: Vec<String> = lowered
        .ast
        .functions
        .iter()
        .find(|function| function.name == "f")
        .expect("f exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(f_param_types, vec!["S[]".to_string()]);

    let sigscript = encode_entry_sig_script(&compiled, "f", &[struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);

    assert!(result.is_ok(), "direct struct[] entrypoint signature should execute successfully: {result:?}");
}

#[test]
fn runtime_rejects_mismatched_dynamic_struct_array_leaf_counts_before_append() {
    let source = r#"
        contract C() {
            struct Item {
                int number;
                byte[2] tag;
            }

            entry main(Item[] items, byte[2] appendedTag, byte[2] expectedTag) {
                require(appendedTag != expectedTag);
                int len = items.length;
                Item[] result = items.append(Item {number: 8, tag: appendedTag});
                require(result[len].number == 8);
                require(result[len].tag == expectedTag);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    // This cannot encode an Item[]: the number leaf contains one element,
    // while the tag leaf contains two. Without a cardinality guard, append
    // makes result[1] combine the appended number with the attacker's second
    // tag and all source-level requirements succeed.
    let number_leaf = [7, 0, 0, 0, 0, 0, 0, 0];
    let tag_leaf = [0x01, 0x02, 0x05, 0x06];
    let sigscript = script_builder()
        .add_data(&number_leaf)
        .unwrap()
        .add_data(&tag_leaf)
        .unwrap()
        .add_data(&[0x03, 0x04])
        .unwrap()
        .add_data(&[0x05, 0x06])
        .unwrap()
        .add_data(&dispatch_tag_for(&compiled, "main"))
        .unwrap()
        .drain();

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err(), "mismatched struct-array leaf counts must fail before the entrypoint body");
}

#[test]
fn codegen_reuses_dynamic_struct_array_leaf_sizes_for_cardinality_validation() {
    let source = r#"
        contract C() {
            struct Item {
                int number;
                byte[2] tag;
            }

            entry main(Item[] items) {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");

    assert_eq!(opcodes.matches("OpSize").count(), 2, "each flattened struct-array leaf should be sized once: {opcodes}");
}

#[test]
fn runtime_validates_cardinality_for_deeply_nested_struct_array_leaves() {
    let source = r#"
        contract C() {
            struct Leaf {
                int[2][3] matrix;
                byte[4] code;
            }
            struct Middle {
                Leaf leaf;
                bool[4][2] flags;
            }
            struct Item {
                Middle middle;
                int[2] totals;
            }

            entry main(Item[] items) {
                require(items.length == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let build_sigscript = |code_leaf_len: usize| {
        script_builder()
            // One outer Item for each leaf. Their respective strides are
            // 48 (int[2][3]), 4 (byte[4]), 8 (bool[4][2]), and 16 (int[2]).
            .add_data(&[0; 48])
            .unwrap()
            .add_data(&vec![0; code_leaf_len])
            .unwrap()
            .add_data(&[0; 8])
            .unwrap()
            .add_data(&[0; 16])
            .unwrap()
            .add_data(&dispatch_tag)
            .unwrap()
            .drain()
    };

    let valid = run_bytecode_with_sigscript(bytecode(&compiled).clone(), build_sigscript(4));
    assert!(valid.is_ok(), "equal leaf cardinalities across nested fixed-width layouts should execute: {valid:?}");

    let malformed = run_bytecode_with_sigscript(bytecode(&compiled), build_sigscript(8));
    assert!(malformed.is_err(), "a surplus element in a deeply nested leaf must be rejected");
}

#[test]
fn runtime_keeps_cardinality_groups_separate_for_multiple_struct_array_params() {
    let source = r#"
        contract C() {
            struct Item {
                int number;
                byte[2] tag;
            }

            entry main(Item[] first, Item[] second) {
                require(first.length == 1);
                require(second.length == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let first = ArtifactValue::Array(vec![artifact_object([("number", 1.into()), ("tag", vec![1u8, 2].into())])]);
    let second = ArtifactValue::Array(vec![
        artifact_object([("number", 2.into()), ("tag", vec![3u8, 4].into())]),
        artifact_object([("number", 3.into()), ("tag", vec![5u8, 6].into())]),
    ]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[first, second]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);

    assert!(result.is_ok(), "separate struct-array parameters may have different lengths: {result:?}");
}

#[test]
fn build_sig_script_enforces_fixed_struct_array_length() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(S[2] values) {
                require(values.length == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    encode_entry_sig_script(&compiled, "main", &[fixed_struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect("correctly sized struct array should encode");

    let err = encode_entry_sig_script(&compiled, "main", &[fixed_struct_array_arg(vec![(7, vec![0x01, 0x02])])])
        .expect_err("wrongly sized struct array should be rejected");
    assert!(err.to_string().contains("expects 2 bytes"), "unexpected error: {err}");
}

#[test]
fn artifact_sigscript_accepts_structurally_identical_object_values() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            struct T {
                int a;
                byte[2] b;
            }

            entry main(S[] values) {
                require(values.length == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let arg = ArtifactValue::Array(vec![artifact_object([("a", 7.into()), ("b", vec![0x01u8, 0x02].into())])]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[arg])
        .expect("portable object values are structural and do not carry a source struct name");
    run_bytecode_with_sigscript(bytecode(&compiled), sigscript).expect("the structurally compatible object value executes");
}

#[test]
fn runtime_supports_struct_array_append_value_length_without_assignment() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(S[] source) {
                require(source.append(S {a: 9, b: byte[_](0x0304)}).length == 2);
                require(source.length == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02])])]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);

    assert!(result.is_ok(), "struct[] append result length should be usable without assignment: {result:?}");
}

#[test]
fn runtime_supports_struct_array_append_assignment_from_different_source() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(S[] source) {
                S[] destination = S[]{S {a: 100, b: byte[_](0xaabb)}};
                destination = source.append(S {a: 9, b: byte[_](0x0304)});

                require(source.length == 1);
                require(source[0].a == 7);
                require(source[0].b == byte[_](0x0102));
                require(destination.length == 2);
                require(destination[0].a == 7);
                require(destination[0].b == byte[_](0x0102));
                require(destination[1].a == 9);
                require(destination[1].b == byte[_](0x0304));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02])])]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);

    assert!(result.is_ok(), "struct[] append assignment from a different source should execute successfully: {result:?}");
}

#[test]
fn runtime_supports_struct_array_append_value_expression() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entry main(S[] source) {
                S[] result = source.append(S {a: 9, b: byte[_](0x0304)}, S {a: 11, b: byte[_](0x0506)});

                require(source.length == 1);
                require(result.length == 3);
                require(result[0].a == 7);
                require(result[1].a == 9);
                require(result[2].a == 11);
                require(result[0].b == byte[_](0x0102));
                require(result[1].b == byte[_](0x0304));
                require(result[2].b == byte[_](0x0506));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02])])]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);

    assert!(result.is_ok(), "struct[] append value expression should execute successfully: {result:?}");
}

#[test]
fn runtime_rejects_regular_struct_array_non_entrypoint_arguments_without_struct_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            function verify(int[] items_a, byte[2][] items_b) {
                require(items_a.length == 2);
                require(items_b.length == 2);
                require(items_a[0] == 7);
                require(items_a[1] == 9);
                require(items_b[0] == byte[_](0x0102));
                require(items_b[1] == byte[_](0x0304));
            }

            entry main(int[] items_a, byte[2][] items_b) {
                verify(items_a, items_b);
            }
        }
    "#;

    let lowered = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("portable artifact compiles");
    let main_param_types: Vec<String> = lowered
        .ast
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(main_param_types, vec!["int[]".to_string(), "byte[2][]".to_string()]);

    let verify_param_types: Vec<String> = lowered
        .ast
        .functions
        .iter()
        .find(|function| function.name == "verify")
        .expect("verify exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(verify_param_types, vec!["int[]".to_string(), "byte[2][]".to_string()]);

    let err = encode_entry_sig_script(&compiled, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect_err("struct[] arguments should be rejected when entrypoint and internal function signatures are not struct-typed");
    assert!(err.to_string().contains("expects 2 arguments"), "unexpected error: {err}");
}

#[test]
fn runtime_supports_regular_struct_array_non_entrypoint_arguments_with_struct_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            function verify(int[] items_a, byte[2][] items_b) {
                require(items_a.length == 2);
                require(items_b.length == 2);
                require(items_a[0] == 7);
                require(items_a[1] == 9);
                require(items_b[0] == byte[_](0x0102));
                require(items_b[1] == byte[_](0x0304));
            }

            entry main(int[] items_a, byte[2][] items_b) {
                verify(items_a, items_b);
            }
        }
    "#;

    let struct_signature_source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            function verify(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == byte[_](0x0102));
                require(x[1].b == byte[_](0x0304));
            }

            entry main(S[] x) {
                verify(x);
            }
        }
    "#;

    let mut compiled = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let original_artifact = compile_to_sil_abi_artifact(source, &[]).expect("original interface compiles");
    let old_dispatch_tag = single_contract(&original_artifact).entry("main").expect("main entry exists").dispatch_tag.into_bytes();
    let interface_artifact = compile_to_sil_abi_artifact(struct_signature_source, &[]).expect("struct interface compiles");
    let dispatch_tag = single_contract(&interface_artifact).entry("main").expect("main entry exists").dispatch_tag.into_bytes();
    replace_compiled_interface(&mut compiled, struct_signature_source, old_dispatch_tag, dispatch_tag);

    let main_param_types: Vec<String> = compiled
        .ast
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(main_param_types, vec!["S[]".to_string()]);

    let verify_param_types: Vec<String> = compiled
        .ast
        .functions
        .iter()
        .find(|function| function.name == "verify")
        .expect("verify exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(verify_param_types, vec!["S[]".to_string()]);

    let sigscript =
        encode_entry_sig_script(&interface_artifact, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
            .expect("sigscript builds");
    let result = run_bytecode_with_sigscript(compiled.bytecode, sigscript);

    assert!(result.is_ok(), "regular struct[] arg should flow through non-entrypoint calls at runtime: {result:?}");
}

#[test]
fn rejects_wrong_argument_type_for_direct_struct_array_non_entrypoint_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            function verify(S[] x) {
                require(x.length == 2);
            }

            entry main() {
                int[] xs = int[]{7, 9};
                verify(xs);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("wrong non-entrypoint struct[] argument type should be rejected");
    assert!(err.to_string().contains("expects S[]") || err.to_string().contains("expects struct S"), "unexpected error: {err}");
}

#[test]
fn runtime_supports_direct_struct_array_non_entrypoint_signature() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            function verify(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == byte[_](0x0102));
                require(x[1].b == byte[_](0x0304));
            }

            entry main(S[] x) {
                verify(x);
            }
        }
    "#;

    let lowered = compile_internal_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("portable artifact compiles");
    let verify_param_types: Vec<String> = lowered
        .ast
        .functions
        .iter()
        .find(|function| function.name == "verify")
        .expect("verify exists")
        .params
        .iter()
        .map(|param| param.type_ref.type_name())
        .collect();
    assert_eq!(verify_param_types, vec!["S[]".to_string()]);

    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
            .expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);

    assert!(result.is_ok(), "direct struct[] non-entrypoint signature should execute successfully: {result:?}");
}

#[test]
fn debug_info_inline_call_with_plain_array_param_compiles() {
    let source = r#"
        contract C() {
            function verify(int[] x) {
                require(x.length == 2);
                require(x[0] == 7);
                require(x[1] == 9);
            }

            entry main(int[] x) {
                verify(x);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let result = compile_contract(source, &[], options);
    assert!(result.is_ok(), "plain array inline call should compile with debug info: {result:?}");
}

#[test]
fn debug_info_inline_call_with_struct_array_param_should_compile() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            function verify(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == byte[_](0x0102));
                require(x[1].b == byte[_](0x0304));
            }

            entry main(S[] x) {
                verify(x);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let result = compile_contract(source, &[], options);
    assert!(result.is_ok(), "struct[] inline call should compile with debug info: {result:?}");
}

#[test]
fn rejects_struct_literal_with_wrong_field_type_in_function_call() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            function f(S x) {
                require(x.a == 0);
            }

            entry main() {
                f(S {a: "hello", b: "world"});
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(
        err.to_string().contains("function argument '__struct__1_x_1_a' expects int")
            || err.to_string().contains("expects int")
            || err.to_string().contains("expects S")
    );
}

#[test]
fn rejects_non_struct_argument_for_struct_parameter() {
    let source = r#"
        contract C() {
            struct S {
                int x;
            }

            function f(S s) {
                require(s.x > 0);
            }

            entry main() {
                int x = 5;
                f(x);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("non-struct argument for struct parameter should be rejected");
    assert!(err.to_string().contains("expects S") || err.to_string().contains("expects struct S"), "unexpected error: {err}");
}

#[test]
fn rejects_struct_literal_with_wrong_field_type_in_variable_definition() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            entry main() {
                S y = S {a: "hello", b: "world"};
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("expects int"));
}

#[test]
fn rejects_struct_literal_with_missing_fields() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            entry main() {
                S y = S {a: 0};
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("struct field 'b' must be initialized"));
}

#[test]
fn rejects_struct_literal_with_mismatched_explicit_type() {
    let source = r#"
        contract C() {
            struct Left {
                int value;
            }

            struct Right {
                int value;
            }

            entry main() {
                Left value = Right {value: 1};
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("mismatched struct literal type should fail");
    assert!(err.to_string().contains("expected struct 'Left', got 'Right'"), "unexpected error: {err}");
}

#[test]
fn rejects_struct_destructuring_with_mismatched_explicit_type() {
    let source = r#"
        contract C() {
            struct Left {
                int value;
            }

            struct Right {
                int value;
            }

            entry main() {
                Left value = Left {value: 1};
                Right {value: int inner} = value;
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("mismatched destructuring type should fail");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
fn build_sig_script_rejects_struct_argument_with_wrong_field_type() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            entry main(S x) {
                require(x.a == 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let arg = artifact_object([("a", "hello".into()), ("b", "world".into())]);
    let result = encode_single_entry_sig_script(&compiled, &[arg]);
    assert!(result.is_err());
}

#[test]
fn compiles_struct_destructuring_and_runs() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[5] b;
            }

            entry main() {
                S s = S {a: 7, b: byte[_](0x0102030405)};
                S {a: int x, b: byte[5] y} = s;
                require(x == 7);
                require(y == byte[_](0x0102030405));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "struct destructuring runtime failed: {}", result.unwrap_err());
}

#[test]
fn rejects_struct_destructuring_with_missing_field() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[5] b;
            }

            entry main() {
                S s = S {a: 7, b: byte[_](0x0102030405)};
                S {a: int x} = s;
                require(x == 7);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("struct destructuring must bind all fields exactly once"));
}

#[test]
fn rejects_struct_destructuring_with_wrong_field_type() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                byte[5] b;
            }

            entry main() {
                S s = S {a: 7, b: byte[_](0x0102030405)};
                S {a: string x, b: byte[5] y} = s;
                require(y == byte[_](0x0102030405));
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("struct field 'a' expects int"));
}

#[test]
fn compiles_function_call_assignment_and_verifies() {
    let source = r#"
        contract Calls() {
            function f(int a, int b) : (int, int) {
                return(a + b, a * b);
            }

            entry main() {
                (int sum, int prod) = f(2, 3);
                require(sum == 5);
                require(prod == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn function_call_statement_evaluates_and_drops_unused_return_expression() {
    let source = r#"
        contract Calls() {
            function f(int a) : (int) {
                require(a >= 0);
                return(a + 1);
            }

            entry main() {
                f(2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let asm = script_to_str(&bytecode(&compiled)).expect("script should stringify");
    assert!(asm.contains("OpAdd OpDrop"), "unused inline return expression should be evaluated and dropped: {asm}");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn rejects_function_call_assignment_with_mismatched_signature() {
    let source = r#"
        contract Calls() {
            function f(int a, int b) : (int, int) {
                return(a + b, a * b);
            }

            entry main() {
                (int sum, byte[] prod) = f(2, 3);
                require(sum == 5);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn rejects_function_call_assignment_with_wrong_return_count() {
    let source = r#"
        contract Calls() {
            function f(int a, int b) : (int, int) {
                return(a + b, a * b);
            }

            entry main() {
                (int sum) = f(2, 3);
                require(sum == 5);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn rejects_internal_function_call_with_wrong_fixed_array_arg_size() {
    let source = r#"
        contract Calls() {
            function f(byte[4] b) {
                require(b.length == 4);
            }

            entry main() {
                f(byte[_](0x010203));
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn accepts_internal_function_call_with_matching_fixed_array_arg_size() {
    let source = r#"
        contract Calls() {
            function f(byte[4] b) {
                require(b.length == 4);
            }

            entry main() {
                f(byte[_](0x01020304));
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn rejects_internal_function_call_with_wrong_fixed_int_array_arg_size() {
    let source = r#"
        contract Calls() {
            function f(int[4] a) {
                require(a.length == 4);
            }

            entry main() {
                f(int[_]{1, 2, 3});
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn accepts_internal_function_call_with_matching_fixed_int_array_arg_size() {
    let source = r#"
        contract Calls() {
            function f(int[4] a) {
                require(a.length == 4);
            }

            entry main() {
                f(int[_]{1, 2, 3, 4});
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn allows_calling_void_function() {
    let source = r#"
        contract Calls() {
            function ping(int a) {
                require(a == 1);
            }

            entry main() {
                ping(1);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn recursive_fibonacci_inlining_behavior() {
    let source = r#"
        contract Fib() {
            function fib(int n) : (int) {
                int result = 0;
                if (n <= 1) {
                    result = n;
                } else {
                    (int a) = fib(n - 1);
                    (int b) = fib(n - 2);
                    result = a + b;
                }
                return(result);
            }

            entry main(int n) {
                (int out) = fib(n);
                require(out > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("recursive call should fail");
    let err_msg = err.to_string();
    assert!(err_msg.contains("recursive function call: fib"), "unexpected error: {err_msg}");
}

#[test]
fn function_call_in_require_statement() {
    let source = r#"
        contract Calls() {
            function plus_one(int n) : int {
                return n + 1;
            }

            entry main(int n) {
                require(plus_one(n) > 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("expression-position helper call should compile");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(4)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "expression-position helper call should execute successfully: {}", result.unwrap_err());
}

#[test]
fn single_return_helper_call_can_participate_in_expression() {
    let source = r#"
        contract Calls() {
            function plus_one(int n) : int {
                return n + 1;
            }

            entry main(int n) {
                require(plus_one(n) == n + 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("single-return helper call should compile");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(4)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "single-return helper call should execute successfully: {}", result.unwrap_err());
}

#[test]
fn single_return_helper_call_in_expression_respects_type_checking() {
    let source = r#"
        contract Calls() {
            function f() : int {
                return(5);
            }

            entry main() {
                byte[_] x = byte[_](0x1234);
                require(f() == x);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("type mismatch should be rejected");
    let err_msg = err.to_string();
    assert!(err_msg.contains("type mismatch: cannot compare int and byte[2]"), "unexpected error: {err_msg}");
}

#[test]
fn rejects_calling_later_defined_function() {
    let source = r#"
        contract Calls() {
            entry first() {
                second();
            }

            function second() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("forward call should now compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "first");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "forward call should execute successfully: {}", result.unwrap_err());
}

#[test]
fn rejects_mutually_recursive_helper_calls() {
    let source = r#"
        contract Recursion() {
            function even(int n) : (int) {
                int result = 0;
                if (n == 0) {
                    result = 1;
                } else {
                    (int out) = odd(n - 1);
                    result = out;
                }
                return(result);
            }

            function odd(int n) : (int) {
                int result = 0;
                if (n == 0) {
                    result = 0;
                } else {
                    (int out) = even(n - 1);
                    result = out;
                }
                return(result);
            }

            entry main() {
                (int out) = even(2);
                require(out == 1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("mutual recursion should fail");
    let err_msg = err.to_string();
    assert!(err_msg.contains("recursive function call"), "expected recursion error, got: {err_msg}");
}

#[test]
fn rejects_multi_return_helper_call_in_expression() {
    let source = r#"
        contract Calls() {
            function pair() : (int, int) {
                return(6, 7);
            }

            entry main() {
                require(pair() > 5);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("multi-return helper call should be rejected in expressions");
    let err_msg = err.to_string();
    assert!(err_msg.contains("returns a tuple and cannot be used directly in expressions"), "unexpected error: {err_msg}");
}

#[test]
fn multi_return_helper_call_assignment_remains_valid() {
    let source = r#"
        contract Calls() {
            function pair() : (int, int) {
                return(6, 7);
            }

            entry main() {
                (int a, int b) = pair();
                require(a == 6);
                require(b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("tuple call assignment should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "tuple call assignment should execute successfully: {}", result.unwrap_err());
}

#[test]
fn tuple_return_field_access_can_initialize_variable_and_run() {
    let source = r#"
        contract Calls() {
            function f() : (int, int, int, int) {
                return(2, 3, 4, 5);
            }

            entry main() {
                int x = f().2;
                require(x == 4);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("tuple field access should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "tuple field access variable initializer should execute successfully: {}", result.unwrap_err());
}

#[test]
fn tuple_return_field_access_can_be_used_in_require_and_run() {
    let source = r#"
        contract Calls() {
            function f() : (int, int, int, int) {
                return(2, 3, 4, 5);
            }

            entry main() {
                require(f().3 == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("tuple field access in require should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "tuple field access in require should execute successfully: {}", result.unwrap_err());
}

#[test]
fn tuple_return_field_access_allows_parenthesized_single_return_type() {
    let source = r#"
        contract Calls() {
            function f() : (int) {
                return(5);
            }

            entry main() {
                require(f().0 == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("f() : (int) should allow f().0");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "single-element tuple field access should execute successfully: {}", result.unwrap_err());
}

#[test]
fn tuple_return_field_access_rejects_direct_single_tuple_value_use_as_scalar() {
    let source = r#"
        contract Calls() {
            function f() : (int) {
                return(7);
            }

            entry main() {
                require(f() == 7);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect_err("f() : (int) should require f().0 for scalar use");
}

#[test]
fn tuple_return_field_access_rejects_scalar_single_return_type() {
    let source = r#"
        contract Calls() {
            function f() : int {
                return 5;
            }

            entry main() {
                require(f().0 == 5);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("f() : int should reject f().0");
    assert!(err.to_string().contains("does not return a tuple"), "unexpected error: {err}");
}

#[test]
fn tuple_return_field_access_rejects_out_of_bounds_index() {
    let source = r#"
        contract Calls() {
            function f() : (int, int, int) {
                return(1, 2, 3);
            }

            entry main() {
                require(f().3 == 3);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("f().10 should be out of bounds");
    assert!(err.to_string().contains("tuple index 3 out of bounds"), "unexpected error: {err}");
}

#[test]
fn allows_call_chain_with_earlier_defined_functions() {
    let source = r#"
        contract Calls() {
            function h(int x) : (int) {
                require(x > 0);
                return(x + 1);
            }

            function g(int y) : (int) {
                require(y > 1);
                (int z) = h(2);
                return(z + y);
            }

            function f(int w) : (int) {
                require(w > 2);
                (int v) = g(3);
                return(v + w);
            }

            entry main() {
                (int out) = f(4);
                require(out == 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn allows_call_chain_with_later_defined_functions() {
    let source = r#"
        contract Calls() {
            function f(int w) : (int) {
                require(w > 2);
                (int v) = g(3);
                return(v + w);
            }

            entry main() {
                (int out) = f(4);
                require(out == 10);
            }

            function g(int y) : (int) {
                require(y > 1);
                (int z) = h(2);
                return(z + y);
            }

            function h(int x) : (int) {
                require(x > 0);
                return(x + 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn rejects_calling_entrypoint_from_helper() {
    let source = r#"
        contract Calls() {
            entry main() {
                helper();
            }

            entry other() {
                require(true);
            }

            function helper() {
                other();
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("helper should not be able to call entrypoint");
    let err_msg = err.to_string();
    assert!(err_msg.contains("entry 'other' cannot be called"), "unexpected error: {err_msg}");
}

#[test]
fn rejects_calling_entrypoint_from_entrypoint() {
    let source = r#"
        contract Calls() {
            entry main() {
                other();
            }

            entry other() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("entrypoint should not be able to call entrypoint");
    let err_msg = err.to_string();
    assert!(err_msg.contains("entry 'other' cannot be called"), "unexpected error: {err_msg}");
}

#[test]
fn allows_calling_void_function_fails() {
    let source = r#"
        contract Calls() {
            function ping(int a) {
                require(a == 2);
            }

            entry main() {
                ping(1);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_err());
}

#[test]
fn rejects_return_without_signature() {
    let source = r#"
        contract C() {
            entry main() {
                return(1);
            }
        }
    "#;
    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn rejects_return_not_last_statement() {
    let source = r#"
        contract C() {
            entry main() : (int) {
                return(1);
                require(true);
            }
        }
    "#;
    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn rejects_return_value_count_mismatch() {
    let source = r#"
        contract C() {
            entry main() : (int, int) {
                return(1);
            }
        }
    "#;
    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn rejects_return_type_mismatch() {
    let source = r#"
        contract C() {
            entry main(bool b) : (int) {
                return(b);
            }
        }
    "#;
    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn single_return_signature_without_parentheses_compiles_and_runs() {
    let source = r#"
        contract C() {
            function calcInAmount() : int {
                return(41);
            }

            entry main() {
                (int amount) = calcInAmount();
                require(amount == 41);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "single bare return type should execute successfully: {}", result.unwrap_err());
}

#[test]
fn single_return_signature_without_parentheses_supports_direct_variable_definition_assignment() {
    let source = r#"
        contract C() {
            function calcInAmount() : int {
                return(41);
            }

            entry main() {
                int amount = calcInAmount();
                require(amount == 41);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "direct variable definition assignment should execute successfully: {}", result.unwrap_err());
}

#[test]
fn single_return_statement_without_parentheses_compiles_and_runs() {
    let source = r#"
        contract C() {
            function calcInAmount() : int {
                return 41;
            }

            entry main() {
                int amount = calcInAmount();
                require(amount == 41);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "single bare return statement should execute successfully: {}", result.unwrap_err());
}

#[test]
fn rejects_omitting_parentheses_in_tuple_function_call_assignment() {
    let source = r#"
        contract Returns() {
            function pair() : (int, int) {
                return(1, 2);
            }

            entry main() {
                int a, int b = pair();
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("tuple-returning function should require parenthesized call assignment");
    let err_msg = err.to_string();
    assert!(err_msg.contains("returns a tuple and cannot be used directly in expressions"), "unexpected error: {err_msg}");
}

#[test]
fn array_literal_codegen_uses_declared_element_type() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[] bytes = byte[]{1, 17, 128, 255};
                int[] ints = int[]{1, 17, 128, 255};
                byte[] selected = true ? byte[]{1, 17, 128, 255} : byte[]{255, 128, 17, 1};
                require(bytes.length == 4);
                require(ints.length == 4);
                require(selected == bytes);
                bytes = byte[]{255, 128, 17, 1};
                require(bytes == byte[]{255, 128, 17, 1});
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions { record_debug_infos: true, ..CompileOptions::default() })
        .expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array literals should use their declared element type: {}", result.unwrap_err());
}

#[test]
fn bool_array_literal_normalizes_runtime_elements_to_one_byte() {
    for (witness, expected) in [(2, "0100"), (0x80, "0000")] {
        let source = format!(
            r#"
                contract Arrays() {{
                    entry main(bool x) {{
                        bool[] values = bool[]{{x, false}};
                        require(byte[2](values) == byte[_](0x{expected}));
                    }}
                }}
            "#
        );

        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
        let sigscript = script_builder()
            .add_data_with_push_opcode(&[witness])
            .unwrap()
            .add_data(&dispatch_tag_for(&compiled, "main"))
            .unwrap()
            .drain();
        let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
        assert!(result.is_ok(), "bool[] literal witness {witness:#04x} should normalize to 0x{expected}: {result:?}");
    }
}

#[test]
fn runtime_and_compile_time_false_have_identical_bool_array_encoding() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract BoolArrayRuntime() {
            entry check(bool x) {
                bool[] runtimeArr = bool[]{x, false};
                bool[] constArr = bool[]{true, false};
                require(runtimeArr.length == 2);
                require(constArr.length == 2);
                require(byte[2](runtimeArr) == byte[2](constArr));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&compiled, "check", &[ArtifactValue::Bool(true)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "runtime and compile-time false should have identical bool[] encoding: {result:?}");
}

#[test]
fn bool_array_append_normalizes_runtime_elements_to_one_byte() {
    let source = r#"
        contract Arrays() {
            entry main(bool x) {
                bool[] values = bool[]{};
                bool[] result = values.append(x, false);
                require(byte[2](result) == byte[_](0x0100));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript =
        script_builder().add_data_with_push_opcode(&[2]).unwrap().add_data(&dispatch_tag_for(&compiled, "main")).unwrap().drain();
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "truthy bool[] append elements should be normalized to 0x01: {result:?}");
}

#[test]
fn int_array_literal_normalizes_runtime_elements_to_eight_bytes() {
    let source = r#"
        contract Arrays() {
            entry main(int x) {
                int[] values = int[]{x, 0};
                require(byte[16](values) == byte[_](0x01000000000000000000000000000000));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(1)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "int[] literal elements should each occupy eight bytes: {result:?}");
}

#[test]
fn int_array_append_normalizes_runtime_elements_to_eight_bytes() {
    let source = r#"
        contract Arrays() {
            entry main(int x) {
                int[] values = int[]{};
                int[] result = values.append(x, 0);
                require(byte[16](result) == byte[_](0x01000000000000000000000000000000));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(1)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "int[] append elements should each occupy eight bytes: {result:?}");
}

#[test]
fn struct_array_bool_and_int_leaves_use_fixed_width_encoding() {
    let source = r#"
        contract Arrays() {
            struct S { bool flag; int number; }

            entry main(bool flag, int number) {
                S[] values = S[]{S {flag: flag, number: number}};
                values = values.append(S {flag: false, number: 0});

                require(values.length == 2);
                require(values[0].flag);
                require(!values[1].flag);
                require(values[0].number == 1);
                require(values[1].number == 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(true), ArtifactValue::Int(1)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "flattened struct array leaves should retain bool/int element widths: {result:?}");
}

#[test]
fn nested_bool_and_int_array_literals_use_fixed_width_encoding() {
    let source = r#"
        contract Arrays() {
            entry main(bool flag, int number) {
                bool[2][] flags = bool[2][]{bool[2]{flag, false}};
                int[2][] numbers = int[2][]{int[2]{number, 0}};

                require(byte[2](flags) == byte[_](0x0100));
                require(byte[16](numbers) == byte[_](0x01000000000000000000000000000000));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(true), ArtifactValue::Int(1)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "nested array literals should normalize their scalar elements: {result:?}");
}

#[test]
fn constant_and_contract_field_arrays_use_fixed_width_encoding() {
    let source = r#"
        contract Arrays() {
            bool[2] constant FLAGS = bool[2]{true, false};
            int[2] constant NUMBERS = int[2]{1, 0};
            bool[2] fieldFlags = bool[2]{true, false};
            int[2] fieldNumbers = int[2]{1, 0};

            entry main() {
                require(byte[2](FLAGS) == byte[_](0x0100));
                require(byte[16](NUMBERS) == byte[_](0x01000000000000000000000000000000));
                require(byte[2](fieldFlags) == byte[_](0x0100));
                require(byte[16](fieldNumbers) == byte[_](0x01000000000000000000000000000000));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "compile-time array encoders should use the canonical scalar widths: {result:?}");
}

#[test]
fn bool_and_int_array_sigscript_arguments_use_fixed_width_encoding() {
    let source = r#"
        contract Arrays() {
            entry main(bool[2] flags, int[2] numbers) {
                require(byte[2](flags) == byte[_](0x0100));
                require(byte[16](numbers) == byte[_](0x01000000000000000000000000000000));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let flags = ArtifactValue::Array(vec![true.into(), false.into()]);
    let numbers = ArtifactValue::Array(vec![1.into(), 0.into()]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[flags, numbers]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "signature-script array encoding should use the canonical scalar widths: {result:?}");
}

#[test]
fn compiles_int_array_length_to_expected_script() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                require(x.length == 0);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let expected = script_builder()
        .add_data_with_push_opcode(&[])
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpSize)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpDiv)
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn compiles_int_array_append_to_expected_script() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                x = x.append(7);
                require(x.length == 1);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let expected = script_builder()
        .add_data_with_push_opcode(&[])
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_data_with_push_opcode(&serialize_i64(7, Some(8)).unwrap())
        .unwrap()
        .add_op(OpCat)
        .unwrap()
        .add_op(OpNip)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpSize)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpDiv)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn debug_expression_compilation_lowers_array_append() {
    let expr = Expr::new(
        ExprKind::Append {
            source: Box::new(Expr::array(parse_type_ref("int[1]").unwrap(), vec![Expr::int(1)])),
            args: vec![Expr::int(2)],
            span: Default::default(),
        },
        Default::default(),
    );

    let (bytecode, type_name) = compile_debug_expr(
        &expr,
        &std::collections::HashMap::new(),
        &std::collections::HashMap::new(),
        &std::collections::HashMap::new(),
    )
    .expect("debug append expression should compile after lowering");

    assert_eq!(type_name, "int[2]");
    assert!(bytecode.contains(&OpCat));
}

#[test]
fn branchy_three_slot_splice_repro_matches_current_codegen_shape() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract Repro(
            byte[32] init_mux_template,
            byte[288] init_route_templates,
            byte[32] init_white_player,
            byte[32] init_black_player,
            byte[64] init_board,
            int init_turn,
            int init_status,
            int init_move_timeout,
            byte[4] init_castle_rights,
            int init_en_passant_idx,
            int init_pending_src_idx,
            int init_pending_dst_idx,
            int init_pending_promo,
            int init_recent_castle,
            int init_draw_state
        ) {
            byte[64] board = init_board;
            int pending_src_idx = init_pending_src_idx;
            int pending_dst_idx = init_pending_dst_idx;

            entry apply() {
                int from_idx = pending_src_idx;
                int to_idx = pending_dst_idx;
                byte[64] prev_board = board;
                byte moving_piece = prev_board[from_idx];
                byte arrived_piece = moving_piece;

                int a = from_idx;
                byte va = byte(0x00);
                int b = to_idx;
                byte vb = arrived_piece;
                if (a > b) {
                    a = to_idx;
                    va = arrived_piece;
                    b = from_idx;
                    vb = byte(0x00);
                }

                int k_idx = 0;
                byte vk = prev_board[0];
                if (a == 0) {
                    k_idx = 1;
                    vk = prev_board[1];
                    if (b == 1) {
                        k_idx = 2;
                        vk = prev_board[2];
                    }
                }

                int x = a;
                byte vx = va;
                int y = b;
                byte vy = vb;
                int z = k_idx;
                byte vz = vk;
                if (k_idx < a) {
                    x = k_idx;
                    vx = vk;
                    y = a;
                    vy = va;
                    z = b;
                    vz = vb;
                } else if (k_idx < b) {
                    y = k_idx;
                    vy = vk;
                    z = b;
                    vz = vb;
                }

                byte[] prev_dyn = byte[](prev_board);
                byte[] prefix = prev_dyn.slice(0, x);
                byte[] middle_xy = prev_dyn.slice(x + 1, y);
                byte[] middle_yz = prev_dyn.slice(y + 1, z);
                byte[] suffix = prev_dyn.slice(z + 1, 64);
                byte[64] next_board = byte[64](
                    prefix + byte[1](vx) + middle_xy + byte[1](vy) + middle_yz + byte[1](vz) + suffix
                );

                require(next_board[10] == 1);
                require(next_board[20] == 2);
                require(next_board[30] == 3);
                require(next_board[40] == 0);
            }
        }
    "#;
    let args = vec![
        ArtifactValue::Bytes(vec![0x11u8; 32]),
        ArtifactValue::Bytes({
            let mut route_templates = Vec::with_capacity(32 * 9);
            for byte in 0x12u8..=0x1au8 {
                route_templates.extend_from_slice(&[byte; 32]);
            }
            route_templates
        }),
        ArtifactValue::Bytes(vec![0x21u8; 32]),
        ArtifactValue::Bytes(vec![0x22u8; 32]),
        ArtifactValue::Bytes(vec![0u8; 64]),
        ArtifactValue::Int(0),
        ArtifactValue::Int(0),
        ArtifactValue::Int(600),
        ArtifactValue::Bytes(vec![1u8; 4]),
        ArtifactValue::Int(-1),
        ArtifactValue::Int(12),
        ArtifactValue::Int(28),
        ArtifactValue::Int(0),
        ArtifactValue::Int(0),
        ArtifactValue::Int(3),
    ];
    let compiled = compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
    let asm = script_to_str(&bytecode(&compiled)).expect("compiled bytecode should stringify");

    // This is a reduced repro for the chess pawn blowup on the current branch.
    // This used to explode because branch-mutated splice
    // indices and replacement bytes fed a dynamic-byte splice that got rebuilt
    // into a very large opcode shape. With array locals kept on the stack, the
    // same source should stay close to the old master-size range instead of
    // ballooning into thousands of bytes and OpPick instructions.
    assert!(bytecode(&compiled).len() < 1000, "script should stay compact, got {}", bytecode(&compiled).len());
    assert!(asm.matches("OpPick").count() < 120, "OpPick count should stay bounded, got {}", asm.matches("OpPick").count());
    assert!(asm.matches("OpSubstr").count() <= 24, "OpSubstr count should stay near master, got {}", asm.matches("OpSubstr").count());
    assert!(
        asm.matches("OpDup").count() <= 16,
        "OpDup count including dispatch should stay near master, got {}",
        asm.matches("OpDup").count()
    );
}

#[test]
fn compiles_int_array_index_to_expected_script() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                x = x.append(7);
                require(x[0] == 7);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let expected = script_builder()
        .add_data_with_push_opcode(&[])
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_data_with_push_opcode(&serialize_i64(7, Some(8)).unwrap())
        .unwrap()
        .add_op(OpCat)
        .unwrap()
        .add_op(OpNip)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpSubstr)
        .unwrap()
        .add_i64(7)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn runs_array_append_runtime_examples() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                int[] y = x.append(7, 9, 11);
                require(x.append(1).length > 0);
                require(x.length == 0);
                require(y.length == 3);
                require(y[0] == 7);
                require(y[1] == 9);
                require(y[2] == 11);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array append runtime example failed: {}", result.unwrap_err());
}

#[test]
fn runs_array_append_value_length_without_assignment() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] values = int[]{1};
                require(values.append(2).length == 2);
                require(values.length == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "array append result length should be usable without assignment: {result:?}");
}

#[test]
fn runs_int_array_append_length_runtime_example() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x = int[]{1, 2, 3};
                x = x.append(4);
                require(x.length == 4);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "int[] append length runtime example failed: {}", result.unwrap_err());
}

#[test]
fn runs_slice_with_explicit_end_bounds() {
    let source = r#"
        contract SliceLowering() {
            entry main() {
                byte[] data = byte[](0x0102030405060708090a);
                byte[] segment = data.slice(3, 8);
                require(segment.length == 5);
                require(segment == byte[](byte[_](0x0405060708)));
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "slice runtime should succeed: {}", result.unwrap_err());
}

#[test]
fn runs_slice_reconstruction_and_compare_runtime_example() {
    let source = r#"
        contract SliceReconstruct() {
            entry main() {
                byte[] data = byte[](0x0102030405060708090a);
                byte[] left = data.slice(0, 4);
                byte[] right = data.slice(4, 10);
                byte[] rebuilt = left + right;

                require(left == byte[](byte[_](0x01020304)));
                require(right == byte[](byte[_](0x05060708090a)));
                require(rebuilt.length == data.length);
                require(rebuilt == data);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "slice reconstruction runtime should succeed: {}", result.unwrap_err());
}

#[test]
fn rejects_invalid_constant_slice_bounds() {
    let cases = [
        (
            "dynamic array negative start",
            "contract C() { entry main(int[] value) { int[] part = value.slice(-1, 0); } }",
            "out of bounds",
        ),
        (
            "dynamic array negative end",
            "contract C() { entry main(int[] value) { int[] part = value.slice(0, -1); } }",
            "out of bounds",
        ),
        ("slice start after end", "contract C() { entry main(int[] value) { int[] part = value.slice(2, 1); } }", "greater than end"),
        (
            "fixed array end beyond length",
            "contract C() { entry main(int[4] value) { int[] part = value.slice(0, 5); } }",
            "out of bounds",
        ),
        (
            "fixed array start beyond length",
            "contract C() { entry main(int[4] value, int end) { int[] part = value.slice(5, end); } }",
            "out of bounds",
        ),
        (
            "pubkey end beyond length",
            "contract C() { entry main(pubkey value) { byte[] part = value.slice(0, 33); } }",
            "out of bounds",
        ),
        ("sig end beyond length", "contract C() { entry main(sig value) { byte[] part = value.slice(0, 66); } }", "out of bounds"),
        (
            "datasig end beyond length",
            "contract C() { entry main(datasig value) { byte[] part = value.slice(0, 65); } }",
            "out of bounds",
        ),
        (
            "constant slice bound division by zero",
            "contract C() { entry main(byte[] value) { byte[] part = value.slice(0, 1 / 0); } }",
            "division by zero in constant expression",
        ),
        (
            "constant slice bound overflow",
            "contract C() { entry main(byte[] value) { byte[] part = value.slice(0, 9223372036854775807 + 1); } }",
            "arithmetic overflow",
        ),
    ];

    for (case, source, expected) in cases {
        let error = compile_contract(source, &[], CompileOptions::default()).expect_err(case);
        assert!(error.to_string().contains(expected), "unexpected error for {case}: {error}");
    }
}

#[test]
fn allows_constant_slice_bounds_at_sequence_end() {
    let source = r#"
        contract SliceBoundary() {
            entry main(int[4] values, pubkey publicKey, sig signature, datasig dataSignature) {
                int[] arrayTail = values.slice(4, 4);
                byte[] pubkeyTail = publicKey.slice(32, 32);
                byte[] sigTail = signature.slice(65, 65);
                byte[] datasigTail = dataSignature.slice(64, 64);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("empty slices at a sequence's end should compile");
}

#[test]
fn allows_concat_of_int_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] a = int[]{1, 2};
                int[] b = int[]{3, 4};
                int[4] c = int[4](a + b);

                require(c.length == 4);
                require(c[0] == 1);
                require(c[1] == 2);
                require(c[2] == 3);
                require(c[3] == 4);
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "int[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_byte_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[] a = byte[](0x0102);
                byte[] b = byte[](0x0304);
                byte[4] c = byte[4](a + b);

                require(c.length == 4);
                require(c == byte[_](0x01020304));
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "byte[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn concatenated_byte_array_literal_has_element_length() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[] x = byte[]{1};
                require((x + byte[]{2}).length == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "byte[] literal concatenation should have two elements: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_fixed_size_byte_array_elements_with_plus() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[2][] a = byte[2][]{byte[_](0x0102), byte[_](0x0304)};
                byte[2][] b = byte[2][]{byte[_](0x0506)};
                byte[2][3] c = byte[2][3](a + b);

                require(c.length == 3);
                require(c[0] == byte[_](0x0102));
                require(c[1] == byte[_](0x0304));
                require(c[2] == byte[_](0x0506));
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "byte[N][] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn composite_array_index_uses_its_result_type_for_bytewise_operations() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[2][] a = byte[2][]{byte[_](0x0102)};
                byte[2][] b = byte[2][]{byte[_](0x0304)};

                require((a + b)[0] == byte[_](0x0102));
                require(byte[]((a + b)[0]) == byte[](byte[_](0x0102)));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(!bytecode(&compiled).contains(&OpNum2Bin), "an indexed byte array element is already byte-encoded");

    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "composite array indexing should use bytewise operations: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_bool_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entry main() {
                bool[] a = bool[]{true, false};
                bool[] b = bool[]{true, false};
                bool[4] c = bool[4](a + b);

                require(c.length == 4);
                require(c[0]);
                require(!c[1]);
                require(c[2]);
                require(!c[3]);
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "bool[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_pubkey_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entry main() {
                pubkey p1 = pubkey(0x0202020202020202020202020202020202020202020202020202020202020202);
                pubkey p2 = pubkey(0x0303030303030303030303030303030303030303030303030303030303030303);

                pubkey[] a = pubkey[]{p1};
                pubkey[] b = pubkey[]{p2};
                pubkey[2] c = pubkey[2](a + b);

                require(c.length == 2);
                require(c[0] == p1);
                require(c[1] == p2);
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "pubkey[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn compiles_bytes20_array_append_without_num2bin() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[20][] x;
                x = x.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                require(x.length == 1);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let value =
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14];
    let expected = script_builder()
        .add_data_with_push_opcode(&[])
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_data_with_push_opcode(&value)
        .unwrap()
        .add_op(OpCat)
        .unwrap()
        .add_op(OpNip)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpSize)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_i64(20)
        .unwrap()
        .add_op(OpDiv)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn runs_bytes20_array_runtime_example() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[20][] x;
                x = x.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                x = x.append(byte[_](0x1111111111111111111111111111111111111111));
                require(x.length == 2);
                require(x[0] == byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                require(x[1] == byte[_](0x1111111111111111111111111111111111111111));
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "byte[20] array runtime example failed: {}", result.unwrap_err());
}

#[test]
fn allows_array_equality_comparison() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[20][] x;
                byte[20][] y;
                x = x.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                y = y.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                require(x == y);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array equality runtime failed: {}", result.unwrap_err());
}

#[test]
fn fails_array_equality_comparison() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[20][] x;
                byte[20][] y;
                x = x.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                y = y.append(byte[_](0x2222222222222222222222222222222222222222));
                require(x == y);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err());
}

#[test]
fn allows_comparison_of_byte_and_fixed_byte_sequence_arrays() {
    let source = r#"
        contract Arrays() {
            entry main(
                byte[] bytes,
                byte[2][] byteRows,
                pubkey[] publicKeys,
                pubkey[2][] publicKeyRows,
                sig[] signatures,
                datasig[] dataSignatures
            ) {
                require(bytes == bytes);
                require(byteRows == byteRows);
                require(publicKeys == publicKeys);
                require(publicKeyRows == publicKeyRows);
                require(signatures == signatures);
                require(dataSignatures == dataSignatures);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("byte arrays and arrays of fixed-byte sequence types should support comparison");
}

#[test]
fn rejects_comparison_of_non_byte_arrays() {
    let cases = [
        ("int array equality", "contract C() { entry main(int[] values) { require(values == values); } }", "int[]"),
        ("bool array inequality", "contract C() { entry main(bool[] values) { require(values != values); } }", "bool[]"),
        ("multidimensional int array", "contract C() { entry main(int[2][] values) { require(values == values); } }", "int[2][]"),
        (
            "struct array equality",
            "contract C() { struct S { int value; } entry main(S[] values) { require(values == values); } }",
            "S[]",
        ),
    ];

    for (name, source, type_name) in cases {
        let err = compile_contract(source, &[], CompileOptions::default()).expect_err(name);
        let message = err.to_string();
        assert!(message.contains("array comparison is only supported"), "{name}: unexpected error: {err}");
        assert!(message.contains(type_name), "{name}: missing rejected type in error: {err}");
    }
}

#[test]
fn allows_array_inequality_with_different_sizes() {
    let source = r#"
        contract Arrays() {
            entry main() {
                byte[20][] x;
                byte[20][] y;
                x = x.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                y = y.append(byte[_](0x0102030405060708090a0b0c0d0e0f1011121314));
                y = y.append(byte[_](0x2222222222222222222222222222222222222222));
                require(x != y);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array inequality runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_array_for_loop_example() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                x = x.append(1);
                x = x.append(2);
                x = x.append(3);
                for (i, 0, 3, 3) {
                    require(x[i] == i + 1);
                }
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array for-loop runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_array_for_loop_with_length_guard() {
    let source = r#"
        contract Arrays() {
            int constant MAX_ARRAY_SIZE = 7;

            entry main(int[] x) {
                require(x.length <= MAX_ARRAY_SIZE);
                for (i, 1, x.length, MAX_ARRAY_SIZE - 1) {
                    require(x[i] == x[i-1]+1);
                }
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let sigscript = encode_entry_sig_script(&compiled, "main", &[vec![1i64, 2i64, 3i64, 4i64].into()]).expect("sigscript builds");

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array for-loop length-guard runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_array_loop_and_function_calls_example() {
    let source = r#"
        contract Sum() {
            int constant MAX_ARRAY_SIZE = 5;
            function sumArray(int[] arr) : (int) {
                require(arr.length <= MAX_ARRAY_SIZE);
                int sum = 0;
                for (i, 0, arr.length, MAX_ARRAY_SIZE) {
                    sum = sum + arr[i];
                }
                return(sum);
            }

            entry main() {
                int[] x;
                x = x.append(1);
                x = x.append(2);
                x = x.append(3);
                (int total) = sumArray(x);
                require(total == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn rejects_array_append_elements_with_wrong_type() {
    let cases = [
        "require(x.append(true, 2, 3).length > 0);",
        "require(x.append(1, true, 3).length > 0);",
        "require(x.append(1, 2, true).length > 0);",
    ];

    for append_statement in cases {
        let source = format!(
            r#"
                contract Arrays() {{
                    entry main() {{
                        int[] x;
                        {append_statement}
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("compile should fail");
        assert!(err.to_string().contains("array append element type mismatch"), "unexpected error: {err}");
    }
}

#[test]
fn rejects_non_constant_for_loop_max_iterations() {
    let source = r#"
        contract Loops() {
            entry main(int start, int end, int max_iterations) {
                for (i, start, end, max_iterations) {
                    require(i >= 0);
                }
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("for loop max iterations must be a compile-time integer"));
}

#[test]
fn limits_for_loop_max_iterations_to_ten_thousand() {
    let cases = [("0", "1", "constant bounds"), ("start", "end", "runtime bounds")];

    for (start, end, description) in cases {
        let source = format!(
            r#"
                contract Loops() {{
                    entry main(int start, int end) {{
                        for (i, {start}, {end}, 10001) {{
                            require(i >= 0);
                        }}
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("compile should fail");
        assert!(
            err.to_string().contains("for loop max iterations must not exceed 10000"),
            "unexpected error for {description}: {err}"
        );
    }

    let source = r#"
        contract Loops() {
            entry main() {
                for (i, 0, 1, 10000) {
                    require(i == 0);
                }
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("the maximum permitted loop bound should compile");
}

#[test]
fn rejects_constant_for_loop_range_above_max_iterations() {
    let source = r#"
        contract Loops() {
            entry main() {
                for (i, 0, 4, 3) {
                    require(i >= 0);
                }
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("for loop range must not exceed max iterations"), "unexpected error: {err}");
}

#[test]
fn rejects_assignment_to_loop_variable_for_constant_and_runtime_bounds() {
    let cases = [
        r#"
            contract ConstantLoop() {
                entry main() {
                    int s = 0;
                    for (i, 0, 3, 3) {
                        i = i + 100;
                        s = s + i;
                    }
                }
            }
        "#,
        r#"
            contract RuntimeLoop() {
                entry main(int start, int end) {
                    int s = 0;
                    for (i, start, end, 3) {
                        i = i + 100;
                        s = s + i;
                    }
                }
            }
        "#,
    ];

    for source in cases {
        let err = compile_contract(source, &[], CompileOptions::default())
            .expect_err("assigning to a loop variable must be rejected before loop lowering");
        assert!(err.to_string().contains("cannot assign to loop variable 'i'"), "unexpected error: {err}");
        let span = err.span().expect("the assignment target should be identified");
        assert_eq!(&source[span.start..span.end], "i");
    }
}

#[test]
fn rejects_overflow_in_constant_for_loop_bounds() {
    let cases = [
        ("9223372036854775807 + 1", "arithmetic overflow: 9223372036854775807 + 1"),
        ("(-9223372036854775807) - 2", "arithmetic overflow: -9223372036854775807 - 2"),
        ("3037000500 * 3037000500", "arithmetic overflow: 3037000500 * 3037000500"),
        ("-(-9223372036854775807 - 1)", "arithmetic overflow: -(-9223372036854775808)"),
        ("(-9223372036854775807 - 1) / -1", "arithmetic overflow: -9223372036854775808 / -1"),
        ("(-9223372036854775807 - 1) % -1", "arithmetic overflow: -9223372036854775808 % -1"),
    ];

    for (expr, expected) in cases {
        let source = format!(
            r#"
                contract Loops() {{
                    entry main() {{
                        for (i, 0, 1, {expr}) {{
                            require(i >= 0);
                        }}
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("compile should fail");
        assert!(err.to_string().contains(expected), "unexpected error: {err}");
    }
}

#[test]
fn rejects_invalid_constant_for_loop_start_and_end_expressions() {
    let cases = [("1 / 0", "division by zero in constant expression"), ("9223372036854775807 + 1", "arithmetic overflow")];

    for (expr, expected) in cases {
        for (start, end) in [(expr, "1"), ("0", expr)] {
            let source = format!(
                r#"
                    contract Loops() {{
                        entry main() {{
                            for (i, {start}, {end}, 1) {{
                                require(i >= 0);
                            }}
                        }}
                    }}
                "#
            );

            let err = compile_contract(&source, &[], CompileOptions::default())
                .expect_err("an invalid constant loop bound must be rejected instead of lowered as a runtime expression");
            assert!(err.to_string().contains(expected), "unexpected error: {err}");
        }
    }
}

#[test]
fn runs_runtime_bounded_for_loop_example() {
    let source = r#"
        contract RuntimeLoop() {
            entry main(int start, int end, int expected_count, int expected_last) {
                int count = 0;
                int last = -1;

                for (i, start, end, 3) {
                    require(i < 10);
                    count = count + 1;
                    last = i;
                }

                require(count == expected_count);
                require(last == expected_last);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let sigscript = encode_entry_sig_script(&compiled, "main", &[2.into(), 4.into(), 2.into(), 3.into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
    assert!(result.is_ok(), "runtime-bounded for-loop should honor end-exclusive bounds: {}", result.unwrap_err());

    let sigscript = encode_entry_sig_script(&compiled, "main", &[5.into(), 8.into(), 3.into(), 7.into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
    assert!(result.is_ok(), "runtime-bounded for-loop should allow ranges up to max iterations: {}", result.unwrap_err());

    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[4.into(), 2.into(), 0.into(), (-1).into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "runtime-bounded for-loop should skip iterations when start >= end: {}", result.unwrap_err());
}

#[test]
fn runtime_for_loop_snapshots_compound_bound_expressions_before_the_body() {
    let source = r#"
        contract RuntimeLoopBounds() {
            entry main(int start, int end) {
                int count = 0;
                int total = 0;

                for (i, start + 1, end + 1, 3) {
                    count = count + 1;
                    total = total + i;
                    start = 100;
                    end = -100;
                }

                require(count == 3);
                require(total == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[0.into(), 3.into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "mutating variables used by bound expressions must not change the snapshotted range: {result:?}");
}

#[test]
fn runtime_for_loop_evaluates_each_bound_expression_once() {
    let source = r#"
        contract RuntimeLoopBoundEvaluation() {
            entry main() {
                for (i, tx.inputs.length - 1, tx.outputs.length + 1, 3) {
                    require(i >= 0);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode should stringify");
    assert_eq!(opcodes.matches("OpTxInputCount").count(), 1, "the start expression must be evaluated once: {opcodes}");
    assert_eq!(opcodes.matches("OpTxOutputCount").count(), 1, "the end expression must be evaluated once: {opcodes}");
}

#[test]
fn rejects_runtime_for_loop_range_above_max_iterations() {
    let source = r#"
        contract RuntimeLoop() {
            entry main(int start, int end) {
                for (i, start, end, 3) {
                    require(i >= start);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[2.into(), 6.into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err(), "runtime-bounded for-loop should fail when end - start exceeds max iterations");
}

#[test]
fn allows_array_assignment_with_compatible_types() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                int[] y;
                x = y;
                require(x.length == 0);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "array assignment runtime failed: {}", result.unwrap_err());
}

#[test]
fn inline_pubkey_param_reassignment_compiles_and_runs() {
    let source = r#"
        contract ReassignNonScalar() {
            function verify(pubkey selected, pubkey other, pubkey expected, bool take_other) {
                if (take_other) {
                    selected = other;
                }
                require(selected == expected);
            }

            entry main(pubkey a, pubkey b, pubkey expected, bool take_other) {
                verify(a, b, expected, take_other);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let a = vec![0x11u8; 32];
    let b = vec![0x22u8; 32];

    let sigscript_take_b = encode_entry_sig_script(
        &compiled,
        "main",
        &[
            ArtifactValue::Bytes(a.clone()),
            ArtifactValue::Bytes(b.clone()),
            ArtifactValue::Bytes(b.clone()),
            ArtifactValue::Bool(true),
        ],
    )
    .expect("sigscript builds");
    let result_take_b = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_take_b);
    assert!(result_take_b.is_ok(), "inline pubkey reassignment should allow taking the second value: {}", result_take_b.unwrap_err());

    let sigscript_keep_a = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bytes(a.clone()), ArtifactValue::Bytes(b), ArtifactValue::Bytes(a), ArtifactValue::Bool(false)],
    )
    .expect("sigscript builds");
    let result_keep_a = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_keep_a);
    assert!(
        result_keep_a.is_ok(),
        "inline pubkey reassignment should preserve the first value when branch is skipped: {}",
        result_keep_a.unwrap_err()
    );
}

#[test]
fn rejects_unsized_array_type() {
    let source = r#"
        contract Arrays() {
            entry main() {
                bytes[] x;
            }
        }
    "#;
    let options = CompileOptions::default();
    assert!(compile_contract(source, &[], options).is_err());
}

#[test]
fn rejects_array_element_assignment() {
    let source = r#"
        contract Arrays() {
            entry main() {
                int[] x;
                x[3] = 9;
            }
        }
    "#;
    let options = CompileOptions::default();
    assert!(compile_contract(source, &[], options).is_err());
}

#[test]
fn locking_bytecode_p2pk_matches_pay_to_address_script() {
    let source = r#"
        contract Test() {
            entry main(pubkey pk, byte[] expected) {
                byte[] spk = byte[](new ScriptPubKeyP2PK(pk));
                require(spk == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let pubkey = vec![0x11u8; 32];
    let address = Address::new(Prefix::Mainnet, Version::PubKey, &pubkey);
    let spk = pay_to_address_script(&address);
    let mut expected = Vec::new();
    expected.extend_from_slice(&spk.version().to_be_bytes());
    expected.extend_from_slice(spk.script());

    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[pubkey.into(), ArtifactValue::Bytes(expected)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "p2pk locking bytecode mismatch: {}", result.unwrap_err());
}

#[test]
fn locking_bytecode_p2sh_matches_pay_to_address_script() {
    let source = r#"
        contract Test() {
            entry main(byte[32] hash, byte[] expected) {
                byte[] spk = byte[](new ScriptPubKeyP2SH(hash));
                require(spk == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let hash = vec![0x22u8; 32];
    let address = Address::new(Prefix::Mainnet, Version::ScriptHash, &hash);
    let spk = pay_to_address_script(&address);
    let mut expected = Vec::new();
    expected.extend_from_slice(&spk.version().to_be_bytes());
    expected.extend_from_slice(spk.script());

    let sigscript =
        encode_entry_sig_script(&compiled, "main", &[hash.into(), ArtifactValue::Bytes(expected)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "p2sh locking bytecode mismatch: {}", result.unwrap_err());
}

#[test]
fn locking_bytecode_p2sh_from_redeem_script_matches_pay_to_script_hash_script() {
    let source = r#"
        contract Test() {
            entry main(byte[] redeem_script, byte[] expected) {
                byte[] spk = byte[](new ScriptPubKeyP2SHFromRedeemScript(redeem_script));
                require(spk == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let redeem_script = vec![OpTrue];
    let spk = pay_to_script_hash_script(&redeem_script);
    let mut expected = Vec::new();
    expected.extend_from_slice(&spk.version().to_be_bytes());
    expected.extend_from_slice(spk.script());

    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bytes(redeem_script), ArtifactValue::Bytes(expected)])
        .expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "p2sh-from-redeem-script locking bytecode mismatch: {}", result.unwrap_err());
}

fn run_bytecode_with_tx_and_covenants(
    script: Vec<u8>,
    tx: Transaction,
    mut entries: Vec<UtxoEntry>,
    seq_commit_accessor: Option<&dyn SeqCommitAccessor>,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    if let Some(entry) = entries.get_mut(0) {
        entry.script_public_key = ScriptPublicKey::new(0, script.clone().into());
    }
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).unwrap();
    let mut ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx);
    if let Some(accessor) = seq_commit_accessor {
        ctx = ctx.with_seq_commit_accessor(accessor);
    }

    let utxo_entry = populated.utxo(0).expect("utxo entry for input 0");
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &tx.inputs[0],
        0,
        utxo_entry,
        ctx,
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute()
}

fn build_basic_opcode_tx(sigscript: Vec<u8>) -> (Transaction, Vec<UtxoEntry>) {
    let outpoint_txid = TransactionId::from_bytes(*b"0123456789abcdef0123456789abcdef");
    let input = TransactionInput::new(
        TransactionOutpoint { transaction_id: outpoint_txid, index: 7 },
        sigscript,
        u64::from_le_bytes(*b"sequence"),
        0,
    );

    let output0_spk = ScriptPublicKey::new(0, b"outspk".to_vec().into());
    let output1_spk = ScriptPublicKey::new(0, b"extra".to_vec().into());
    let outputs = vec![
        TransactionOutput { value: 1000, script_public_key: output0_spk, covenant: None },
        TransactionOutput { value: 2000, script_public_key: output1_spk, covenant: None },
    ];

    let subnetwork_id = SubnetworkId::from_bytes(*b"abcdefghijklmnopqrst");
    let payload = b"payload-data".to_vec();
    let tx = Transaction::new(1, vec![input.clone()], outputs, 0, subnetwork_id, 123, payload);

    let utxo_spk = ScriptPublicKey::new(0, b"inputspk".to_vec().into());
    let utxo_entry = UtxoEntry::new(5_000, utxo_spk, 0, false, None);
    (tx, vec![utxo_entry])
}

fn build_covenant_opcode_tx(sigscript: Vec<u8>, covenant_id_a: Hash, covenant_id_b: Hash) -> (Transaction, Vec<UtxoEntry>) {
    let inputs = vec![
        TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(10), 0), sigscript, 0, 0),
        TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(11), 1), vec![], 0, 0),
        TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(12), 2), vec![], 0, 0),
    ];

    let spk = ScriptPublicKey::new(0, b"covenant".to_vec().into());
    let outputs = vec![
        TransactionOutput {
            value: 10,
            script_public_key: spk.clone(),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: covenant_id_a }),
        },
        TransactionOutput {
            value: 20,
            script_public_key: spk.clone(),
            covenant: Some(CovenantBinding { authorizing_input: 1, covenant_id: covenant_id_b }),
        },
        TransactionOutput {
            value: 30,
            script_public_key: spk.clone(),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: covenant_id_a }),
        },
    ];

    let tx = Transaction::new(1, inputs, outputs, 0, SubnetworkId::from_bytes([0u8; 20]), 0, vec![]);

    let utxo_spk = ScriptPublicKey::new(0, b"utxo".to_vec().into());
    let entries = vec![
        UtxoEntry::new(1_000, utxo_spk.clone(), 0, false, Some(covenant_id_a)),
        UtxoEntry::new(1_000, utxo_spk.clone(), 0, false, Some(covenant_id_b)),
        UtxoEntry::new(1_000, utxo_spk, 0, false, Some(covenant_id_a)),
    ];

    (tx, entries)
}

fn dispatch_tag_for(compiled: &silverscript_abi::SilAbiArtifact, function_name: &str) -> DispatchTag {
    entry_by_name(compiled, function_name).expect("entrypoint resolved").dispatch_tag.into_bytes()
}

fn dispatch_tag_for_preimage(preimage: &str) -> DispatchTag {
    let hash = blake3::hash(preimage.as_bytes());
    hash.as_bytes()[..4].try_into().expect("a BLAKE3 hash contains a four-byte dispatch tag")
}

fn wrap_with_single_dispatch(compiled: &silverscript_abi::SilAbiArtifact, body: Vec<u8>) -> Vec<u8> {
    wrap_with_single_dispatch_and_state(compiled, &[], &body)
}

fn wrap_with_single_dispatch_and_state(compiled: &silverscript_abi::SilAbiArtifact, state: &[u8], body: &[u8]) -> Vec<u8> {
    let entries = &single_contract(compiled).entries;
    let Some(entrypoint) = entries.values().next().filter(|_| entries.len() == 1) else {
        panic!("single-dispatch wrapper requires exactly one ABI entrypoint");
    };
    wrap_with_single_dispatch_tag(entrypoint.dispatch_tag.into_bytes(), state, body)
}

fn wrap_with_single_dispatch_tag(dispatch_tag: DispatchTag, state: &[u8], body: &[u8]) -> Vec<u8> {
    let mut builder = script_builder();
    if !state.is_empty() {
        builder.add_op(OpToAltStack).unwrap();
        builder.add_ops(state).unwrap();
        builder.add_op(OpFromAltStack).unwrap();
    }
    builder.add_op(OpDup).unwrap();
    builder.add_data(&dispatch_tag).unwrap();
    builder.add_op(OpEqual).unwrap();
    builder.add_op(OpIf).unwrap();
    builder.add_op(OpDrop).unwrap();
    builder.add_ops(body).unwrap();
    builder.add_op(OpElse).unwrap();
    builder.add_op(OpReturn).unwrap();
    builder.add_op(OpEndIf).unwrap();
    builder.drain()
}

fn stateless_single_dispatch_body_opcodes(compiled: &silverscript_abi::SilAbiArtifact, function_name: &str) -> Vec<u8> {
    let dispatch_tag = dispatch_tag_for(compiled, function_name);
    let prefix = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_data(&dispatch_tag)
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .drain();
    let bytecode = bytecode(compiled);
    let body = bytecode.strip_prefix(prefix.as_slice()).expect("single-dispatch prefix should be present");
    let body = body.strip_suffix(&[OpElse, OpReturn, OpEndIf]).expect("single-dispatch suffix should be present");

    parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(body)
        .map(|opcode| opcode.expect("entrypoint bytecode should parse").value())
        .collect()
}

#[test]
fn compiles_with_kcc1_dispatch_tag_for_single_entrypoint() {
    let source = r#"
        contract Test() {
            entry main() {
                require(1 + 2 == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let body = script_builder()
        .add_i64(1)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let dispatch_tag = entry_by_name(&compiled, "main").expect("entrypoint resolved").dispatch_tag.into_bytes();
    let expected = wrap_with_single_dispatch_tag(dispatch_tag, &[], &body);

    assert_eq!(bytecode(&compiled), expected);
    assert_eq!(state_layout(&compiled).start, 0);
    assert_eq!(state_layout(&compiled).len, 0);
    assert!(!bytecode(&compiled).contains(&OpToAltStack));
    assert!(!bytecode(&compiled).contains(&OpFromAltStack));
}

#[test]
fn compiles_stateless_multiple_entrypoints_with_kcc1_dispatch_tags() {
    let source = r#"
        contract Test() {
            entry a() { require(1 == 1); }
            entry b() { require(2 == 2); }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag_a = entry_by_name(&compiled, "a").expect("entrypoint resolved").dispatch_tag.into_bytes();
    let dispatch_tag_b = entry_by_name(&compiled, "b").expect("entrypoint resolved").dispatch_tag.into_bytes();

    let body_a = script_builder()
        .add_i64(1)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let body_b = script_builder()
        .add_i64(2)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected_bytecode = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_data(&dispatch_tag_a)
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_ops(&body_a)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_data(&dispatch_tag_b)
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_ops(&body_b)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_op(OpReturn)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .drain();

    assert_eq!(bytecode(&compiled), expected_bytecode);
    assert_eq!(state_layout(&compiled).start, 0);
    assert_eq!(state_layout(&compiled).len, 0);
    assert!(!bytecode(&compiled).contains(&OpToAltStack));
    assert!(!bytecode(&compiled).contains(&OpFromAltStack));

    let sigscript = encode_entry_sig_script(&compiled, "a", &[]).expect("sigscript builds");
    let expected = script_builder().add_data(&dispatch_tag_a).unwrap().drain();
    assert_eq!(sigscript, expected);
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript).is_ok());
}

#[test]
fn dispatch_tag_and_argument_encoding_match_kcc1_vector() {
    let source = r#"
        contract Test() {
            int constant N = 4;

            entry step(int value, byte[N] data, bool enabled, byte marker) {
                require(value == 17);
                require(data == byte[4](0x01020304));
                require(enabled);
                require(marker == byte(1));
            }
            entry other() { require(true); }
        }
    "#;

    let artifact = compile_to_sil_abi_artifact(source, &[]).expect("compile succeeds");
    let contract = artifact.contract("Test").expect("contract exists");
    let step = contract.entry("step").expect("step entrypoint exists");
    assert_eq!(step.params[1].ty, TypeArtifact::FixedBytes { len: 4 });
    assert_eq!(step.dispatch_tag.into_bytes(), [0x2c, 0x49, 0xed, 0x65]);

    let sigscript = encode_entry_sig_script(&artifact, "step", &[17.into(), vec![1u8, 2, 3, 4].into(), true.into(), 1u8.into()])
        .expect("KCC-01 vector sigscript builds");
    assert!(sigscript.ends_with(&[0x04, 0x2c, 0x49, 0xed, 0x65]));
    let bytecode = contract.compiled.bytecode.clone();
    assert!(run_bytecode_with_sigscript(bytecode, sigscript).is_ok());
}

#[test]
fn record_dispatch_tag_matches_kcc1_structural_type_vector() {
    let source = r#"
        contract CoffeeMachine() {
            int constant RECIPE_CODE_LEN = 4;

            struct CoffeeOrder {
                byte[RECIPE_CODE_LEN] recipe_code;
                byte sugar_level;
                bool with_milk;
            }

            entry dispense(CoffeeOrder[] orders) {
                require(orders.length >= 0);
            }
        }
    "#;

    let artifact = compile_to_sil_abi_artifact(source, &[]).expect("compile succeeds");
    let dispense =
        artifact.contract("CoffeeMachine").and_then(|contract| contract.entry("dispense")).expect("dispense entrypoint exists");
    assert_eq!(
        dispense.params[0].ty,
        TypeArtifact::DynamicArray { item: Box::new(TypeArtifact::Struct { name: "CoffeeOrder".to_string() }) }
    );
    assert_eq!(dispense.dispatch_tag.into_bytes(), [0x67, 0x6b, 0x1a, 0x86]);

    let json = serde_json::to_string(dispense).expect("ABI entry serializes");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&json).unwrap()["dispatch_tag"], "676b1a86");
}

#[test]
fn nested_record_dispatch_tags_hash_structural_type_preimages() {
    let source = r#"
        contract Test() {
            int constant N = 3;

            struct Inner {
                int value;
                byte[N] payload;
            }

            struct Outer {
                Inner child;
                bool[2] flags;
            }

            entry scalar(Outer value) { require(true); }
            entry dynamic(Outer[] values) { require(values.length >= 0); }
            entry fixed(Outer[2] values) { require(values.length == 2); }
        }
    "#;

    let artifact = compile_to_sil_abi_artifact(source, &[]).expect("compile succeeds");
    let contract = artifact.contract("Test").expect("contract exists");
    let vectors = [
        ("scalar", "scalar({{int,byte[3]},bool[2]})"),
        ("dynamic", "dynamic({{int,byte[3]},bool[2]}[])"),
        ("fixed", "fixed({{int,byte[3]},bool[2]}[2])"),
    ];

    for (entrypoint, preimage) in vectors {
        assert_eq!(
            contract.entry(entrypoint).expect("entrypoint exists").dispatch_tag.into_bytes(),
            dispatch_tag_for_preimage(preimage),
            "preimage: {preimage}"
        );
    }
}

#[test]
fn silverscript_abi_encodes_and_runs_nested_struct_entry_arguments() {
    let source = r#"
        contract AbiStructs(int expectedAmount) {
            struct Coordinates {
                int x;
                int y;
            }

            struct Item {
                int amount;
                Coordinates location;
                byte[4] code;
                bool active;
            }

            entry main(Item selected, Item[] items, Item[2] fixedItems) {
                Coordinates selectedLocation = selected.location;
                require(selected.amount == expectedAmount);
                require(selectedLocation.x == 1);
                require(selectedLocation.y == 2);
                require(selected.code == byte[4](0x01020304));
                require(selected.active);

                require(items.length == 2);
                require(items[0].amount == 10);
                require(items[0].code == byte[4](0x11121314));
                require(!items[0].active);
                require(items[1].amount == 20);
                require(items[1].code == byte[4](0x21222324));
                require(items[1].active);

                require(fixedItems[0].amount == 30);
                require(fixedItems[0].code == byte[4](0x31323334));
                require(fixedItems[0].active);
                require(fixedItems[1].amount == 40);
                require(fixedItems[1].code == byte[4](0x41424344));
                require(!fixedItems[1].active);
            }
        }
    "#;

    let artifact_constructor_args = [7.into()];
    let abi =
        compile_to_sil_abi_artifact(source, &artifact_constructor_args).expect("source compiles to a complete portable ABI artifact");
    abi.verify().expect("portable ABI matches the compiled contract");

    let coordinates = |x, y| {
        ArtifactValue::Object(BTreeMap::from([("x".to_string(), ArtifactValue::Int(x)), ("y".to_string(), ArtifactValue::Int(y))]))
    };
    let item = |amount, x, y, code: [u8; 4], active| {
        ArtifactValue::Object(BTreeMap::from([
            ("amount".to_string(), ArtifactValue::Int(amount)),
            ("location".to_string(), coordinates(x, y)),
            ("code".to_string(), ArtifactValue::Bytes(code.to_vec())),
            ("active".to_string(), ArtifactValue::Bool(active)),
        ]))
    };
    let args = vec![
        item(7, 1, 2, [1, 2, 3, 4], true),
        ArtifactValue::Array(vec![
            item(10, 11, 12, [0x11, 0x12, 0x13, 0x14], false),
            item(20, 21, 22, [0x21, 0x22, 0x23, 0x24], true),
        ]),
        ArtifactValue::Array(vec![
            item(30, 31, 32, [0x31, 0x32, 0x33, 0x34], true),
            item(40, 41, 42, [0x41, 0x42, 0x43, 0x44], false),
        ]),
    ];
    let sigscript = encode_single_entry_sig_script(&abi, &args).expect("ABI encodes sigscript");
    let bytecode = abi.contract("AbiStructs").expect("contract exists").compiled.bytecode.clone();

    run_bytecode_with_sigscript(bytecode, sigscript).expect("ABI-generated sigscript executes");
}

#[test]
fn artifact_values_compile_nested_constructor_arguments() {
    let source = r#"
        contract ArtifactConstructors(Config config, int[] values, byte[] payload, string label) {
            struct Flags {
                bool enabled;
            }

            struct Config {
                int count;
                Flags flags;
            }

            entry main() {
                require(config.count == 7);
                require(config.flags.enabled);
                require(values.length == 2);
                require(values[0] == 11);
                require(values[1] == 12);
                require(payload.length == 2);
                require(payload[0] == 0xaa);
                require(payload[1] == 0xbb);
                require(label == "ready");
            }
        }
    "#;
    let args = vec![
        ArtifactValue::Object(BTreeMap::from([
            ("count".to_string(), ArtifactValue::Int(7)),
            ("flags".to_string(), ArtifactValue::Object(BTreeMap::from([("enabled".to_string(), ArtifactValue::Bool(true))]))),
        ])),
        ArtifactValue::Array(vec![ArtifactValue::Int(11), ArtifactValue::Int(12)]),
        ArtifactValue::Bytes(vec![0xaa, 0xbb]),
        ArtifactValue::Text("ready".to_string()),
    ];

    let abi = compile_to_sil_abi_artifact(source, &args).expect("portable ABI constructor values compile");
    abi.verify().expect("portable ABI verifies");
    let contract = abi.contract("ArtifactConstructors").expect("contract exists");
    let bytecode = contract.compiled.bytecode.clone();
    let dispatch_tag = contract.entry("main").expect("entry exists").dispatch_tag.into_bytes();
    run_bytecode_with_dispatch_tag(bytecode, dispatch_tag).expect("compiled constructor values execute");
}

#[test]
fn dispatch_tag_hashes_exact_utf8_signature_bytes() {
    // KCC identifiers are currently ASCII-only. Mutating parsed ASTs still pins the
    // UTF-8 hashing semantics if that restriction is relaxed in the future.
    let cases = [
        ("café", true, b"caf\xc3\xa9(int)".as_slice(), [0x76, 0xbb, 0x38, 0x88]),
        ("轉帳", false, b"\xe8\xbd\x89\xe5\xb8\xb3()".as_slice(), [0x9a, 0x67, 0x99, 0xc5]),
        ("🚀", true, b"\xf0\x9f\x9a\x80(int)".as_slice(), [0xfa, 0x79, 0x41, 0x20]),
        ("café", false, b"caf\xc3\xa9()".as_slice(), [0xde, 0x33, 0x57, 0x99]),
        ("cafe\u{301}", false, b"cafe\xcc\x81()".as_slice(), [0x3f, 0x0c, 0x9d, 0xa1]),
    ];

    for (name, has_input, utf8_signature, expected_tag) in cases {
        let source = if has_input {
            "contract Test() { entry placeholder(int value) { require(true); } }"
        } else {
            "contract Test() { entry placeholder() { require(true); } }"
        };
        let mut contract = parse_contract_ast(source).expect("contract parses");
        contract.functions[0].name = name.to_string();

        let compiled = compile_contract_ast(&contract, &[], CompileOptions::default()).expect("contract compiles");
        assert_eq!(&blake3::hash(utf8_signature).as_bytes()[..4], expected_tag);
        assert_eq!(compiled.dispatch_tags.get(name).copied(), Some(expected_tag));
    }
}

#[test]
fn rejects_colliding_kcc1_dispatch_tags() {
    let source = r#"
        contract Test() {
            entry f75360() { require(true); }
            entry f79327() { require(true); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("colliding dispatch tags must be rejected");
    assert!(matches!(err, CompilerError::EntrypointDispatchTagCollision { .. }));
}

#[test]
fn rejects_noncanonical_inferred_array_type_in_entrypoint_abi() {
    let source = r#"
        contract Test() {
            entry step(byte[_] data) { require(true); }
            entry other() { require(true); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("entrypoint ABI types must be canonical");
    assert!(matches!(err, CompilerError::NonCanonicalEntrypointParameter { .. }));
}

#[test]
fn compiles_basic_arithmetic_and_verifies() {
    let source = r#"
        contract Test() {
            entry main() {
                require(1 + 2 == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");

    let body = script_builder()
        .add_i64(1)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn compiles_contract_constants_and_verifies() {
    let source = r#"
        contract Test() {
            int constant MAX_SUPPLY = 1_000_000;

            entry main() {
                require(MAX_SUPPLY == 1_000_000);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");

    let body = script_builder()
        .add_i64(1_000_000)
        .unwrap()
        .add_i64(1_000_000)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn compiles_contract_fields_as_script_prolog() {
    let source = r#"
        contract C() {
            int x = 5;
            byte[2] y = byte[_](0x1234);

            entry main() {
                require(x == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let state = script_builder()
        .add_data_with_push_opcode(&5i64.to_le_bytes())
        .unwrap()
        .add_data_with_push_opcode(&[0x12, 0x34])
        .unwrap()
        .drain();
    let body = script_builder()
        .add_op(OpOver)
        .unwrap()
        .add_i64(5)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch_and_state(&compiled, &state, &body);

    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn runs_contract_with_fields_prolog() {
    let source = r#"
        contract C() {
            int x = 5;
            byte[2] y = byte[_](0x1234);

            entry main() {
                require(x == 5);
                require(y == byte[_](0x1234));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn runs_dispatch_tag_dispatch_with_contract_fields() {
    let source = r#"
        contract C() {
            int x = 5;
            byte[2] y = byte[_](0x1234);

            entry a() {
                require(true);
            }

            entry b() {
                require(x == 5);
                require(y == byte[_](0x1234));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert_eq!(state_layout(&compiled).start, 1);
    assert!(state_layout(&compiled).len > 0);
    assert_eq!(bytecode(&compiled).first().copied(), Some(OpToAltStack));
    assert!(bytecode(&compiled).contains(&OpFromAltStack));

    let sigscript_a = encode_entry_sig_script(&compiled, "a", &[]).expect("sigscript a builds");
    let sigscript_b = encode_entry_sig_script(&compiled, "b", &[]).expect("sigscript b builds");

    let result_a = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_a);
    assert!(result_a.is_ok(), "entrypoint a runtime failed: {}", result_a.unwrap_err());

    let result_b = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_b);
    assert!(result_b.is_ok(), "entrypoint b runtime failed: {}", result_b.unwrap_err());
}

#[test]
fn compiles_validate_output_state_to_expected_script() {
    let source = r#"
        contract C(int init_x, byte[2] init_y) {
            int x = init_x;
            byte[2] y = init_y;

            entry main() {
                validateOutputState(0, State {x:x+1,y:byte[_](0x3412)});
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let expected = script_builder()
        // <x> as fixed-size int field encoding: <PUSHDATA8><8-byte little-endian>
        .add_data_with_push_opcode(&5i64.to_le_bytes())
        .unwrap()
        // <y>
        .add_data_with_push_opcode(&[1u8, 2u8])
        .unwrap()

        // ---- Preserve the non-identifier State literal in stack locals ----
        // Copy x past y, then evaluate x + 1.
        .add_op(OpOver)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        // Store the new y field alongside the new x field.
        .add_data_with_push_opcode(&[0x34, 0x12])
        .unwrap()

        // ---- Build fixed-size new_state.x chunk: <0x08><8-byte payload> ----
        // Push the PUSHDATA8 prefix, then copy the preserved x + 1 value.
        .add_data_with_push_opcode(&[0x08])
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpPick)
        .unwrap()

        // ---- Convert x+1 to fixed-size int field chunk: <0x08><8-byte payload> ----
        // convert numeric value to 8-byte payload
        .add_i64(8)
        .unwrap()
        .add_op(OpNum2Bin)
        .unwrap()
        // prefix || encoded x
        .add_op(OpCat)
        .unwrap()
        // ---- Build new_state.y pushdata chunk ----
        // pushdata prefix for 2-byte data is 0x02
        .add_data_with_push_opcode(&[0x02])
        .unwrap()
        // Copy the preserved new y field.
        .add_i64(2)
        .unwrap()
        .add_op(OpPick)
        .unwrap()
        // resulting chunk: <0x02><0x3412>
        .add_op(OpCat)
        .unwrap()
        // combine x_chunk || y_chunk
        .add_op(OpCat)
        .unwrap()

        // ---- Preserve the dispatch prefix before the state segment ----
        .add_op(OpTxInputIndex)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpTxInputScriptSigLen)
        .unwrap()
        .add_i64(bytecode(&compiled).len() as i64)
        .unwrap()
        .add_op(OpSub)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(state_layout(&compiled).start as i64)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpTxInputScriptSigSubstr)
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpCat)
        .unwrap()

        // ---- Extract the bytecode suffix after the state segment ----
        // current input index
        .add_op(OpTxInputIndex)
        .unwrap()
        // duplicate index for len + substr
        .add_op(OpDup)
        .unwrap()
        // sigscript length at current input
        .add_op(OpTxInputScriptSigLen)
        .unwrap()
        // duplicate sigscript length; one copy becomes substr length
        .add_op(OpDup)
        .unwrap()
        // Precompute state_end - bytecode_size, where
        // state_end = dispatch prefix + len(<x><y>) = 13.
        .add_i64(13 - bytecode(&compiled).len() as i64)
        .unwrap()
        // start offset of REST_OF_SCRIPT inside sigscript
        .add_op(OpAdd)
        .unwrap()
        // reorder for OpTxInputScriptSigSubstr(index, start, length)
        .add_op(OpSwap)
        .unwrap()
        // read REST_OF_SCRIPT from current input sigscript
        .add_op(OpTxInputScriptSigSubstr)
        .unwrap()

        // ---- new_redeem_script = <new x><new y><REST_OF_SCRIPT> ----
        // append REST_OF_SCRIPT to merged new-state chunks
        .add_op(OpCat)
        .unwrap()

        // ---- Build expected P2SH scriptPubKey bytes for new_redeem_script ----
        // hash160-equivalent in this system: blake2b(redeem)
        .add_op(OpBlake2b)
        .unwrap()
        // version bytes
        .add_data_with_push_opcode(&[0x00, 0x00])
        .unwrap()
        // locking opcode prefix OP_BLAKE2B
        .add_data_with_push_opcode(&[OpBlake2b])
        .unwrap()
        // version || OP_BLAKE2B
        .add_op(OpCat)
        .unwrap()
        // pushdata-length byte for 32-byte hash
        .add_data_with_push_opcode(&[0x20])
        .unwrap()
        // version || OP_BLAKE2B || push32
        .add_op(OpCat)
        .unwrap()
        // bring hash to top
        .add_op(OpSwap)
        .unwrap()
        // append hash bytes
        .add_op(OpCat)
        .unwrap()
        // trailing OP_EQUAL
        .add_data_with_push_opcode(&[OpEqual])
        .unwrap()
        // final expected output scriptPubKey bytes
        .add_op(OpCat)
        .unwrap()

        // ---- Compare against tx.outputs[0].scriptPubKey ----
        // output index argument
        .add_i64(0)
        .unwrap()
        // fetch tx.outputs[0].scriptPubKey
        .add_op(OpTxOutputSpk)
        .unwrap()
        // enforce expected == actual
        .add_op(OpEqualVerify)
        .unwrap()

        // ---- Entrypoint epilogue cleanup for original and new state fields ----
        // drop preserved new y and new x
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        // drop original y
        .add_op(OpDrop)
        .unwrap()
        // drop original x
        .add_op(OpDrop)
        .unwrap()
        // final success value
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let (state, body) = expected.split_at(state_layout(&compiled).len);
    let expected = wrap_with_single_dispatch_and_state(&compiled, state, body);

    let actual_ops = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert_eq!(bytecode(&compiled), expected, "actual opcodes: {actual_ops}");
}

#[test]
fn runs_validate_output_state() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {x:x+1,y:byte[_](0x3412)});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let output_compiled =
        compile_contract(source, &[6.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputState runtime failed: {}", result.unwrap_err());
}

#[test]
fn validate_output_state_normalizes_runtime_bool_fields() {
    let source = r#"
        contract C(bool initial) {
            bool flag = initial;

            entry main(bool next) {
                validateOutputState(0, State {flag: next});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[ArtifactValue::Bool(false)], CompileOptions::default()).expect("input contract compiles");
    let raw_truthy_arg = script_builder()
        .add_data_with_push_opcode(&[2])
        .unwrap()
        .add_data(&dispatch_tag_for(&input_compiled, "main"))
        .unwrap()
        .drain();
    let signature_script =
        pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), raw_truthy_arg).expect("P2SH signature script builds");
    let input = test_input(0, signature_script);

    let output_compiled =
        compile_contract(source, &[ArtifactValue::Bool(true)], CompileOptions::default()).expect("output contract compiles");
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output =
        TransactionOutput { value: 1000, script_public_key: pay_to_script_hash_script(&bytecode(&output_compiled)), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "truthy 0x02 must serialize as the same boolean state as canonical true: {result:?}");
}

#[test]
fn runs_validate_output_state_with_state_variable() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                State next = State {x: x + 1, y: byte[_](0x3412)};
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let output_compiled =
        compile_contract(source, &[6.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputState runtime failed: {}", result.unwrap_err());
}

fn run_read_input_state_with_template_case(
    reader_source: &str,
    reader_constructor_args: &[ArtifactValue],
    target_input_compiled: &silverscript_abi::SilAbiArtifact,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    run_read_input_state_with_template_case_with_input_spk(
        reader_source,
        reader_constructor_args,
        target_input_compiled,
        pay_to_script_hash_script(&bytecode(target_input_compiled)),
    )
}

fn run_read_input_state_with_template_case_with_input_spk(
    reader_source: &str,
    reader_constructor_args: &[ArtifactValue],
    target_input_compiled: &silverscript_abi::SilAbiArtifact,
    input1_spk: ScriptPublicKey,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reader_compiled =
        compile_contract(reader_source, reader_constructor_args, CompileOptions::default()).expect("compile reader succeeds");

    let input0 = test_input(0, dispatch_tag_sigscript(dispatch_tag_for(&reader_compiled, "main")));
    let input1 = test_input(1, sigscript_push_bytecode(&bytecode(target_input_compiled)));
    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, bytecode(&reader_compiled).clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input0.clone(), input1], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo0 = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let utxo1 = UtxoEntry::new(1000, input1_spk, 0, tx.is_coinbase(), None);

    execute_input(tx, vec![utxo0, utxo1], 0)
}

fn run_validate_output_state_with_template_case(
    template_prefix: Vec<u8>,
    template_suffix: Vec<u8>,
    expected_template_hash: Vec<u8>,
    output_compiled: &silverscript_abi::SilAbiArtifact,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let mux_source = format!(
        r#"
        contract M(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {{
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry routeToA() {{
                State s = State {{muxHash: muxHash, aHash: aHash, x: x + 1, y: byte[_](0x3412)}};
                validateOutputStateWithTemplate(
                    0,
                    s,
                    byte[](0x{}),
                    byte[](0x{}),
                    byte[32](0x{})
                );
            }}
        }}
    "#,
        template_prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        template_suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        expected_template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );

    let mux_input_compiled = compile_contract(
        &mux_source,
        &[vec![0x11u8; 32].into(), expected_template_hash.into(), 5.into(), vec![0x10u8, 0x20u8].into()],
        CompileOptions::default(),
    )
    .expect("compile mux succeeds");

    let sigscript = encode_entry_sig_script(&mux_input_compiled, "routeToA", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&mux_input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&bytecode(&mux_input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    execute_input(tx, vec![utxo_entry], 0)
}

#[test]
fn runs_validate_output_state_with_template() {
    let mux_hash = vec![0x11u8; 32];

    let target_source = r#"
        contract A(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry noop() {
                require(true);
            }
        }
    "#;

    let target_a0 = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), ArtifactValue::Int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (a_prefix, a_suffix, a_template_hash) = compiled_template_parts_and_hash(&target_a0);

    let target_output_compiled = compile_contract(
        target_source,
        &[mux_hash.into(), a_template_hash.clone().into(), 6.into(), vec![0x34u8, 0x12u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target output succeeds");
    let a_prefix_hex = a_prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let a_suffix_hex = a_suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let a_template_hash_hex = a_template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let mux_source = format!(
        r#"
        contract M(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {{
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry routeToA() {{
                State s = State {{muxHash: muxHash, aHash: aHash, x: x + 1, y: byte[_](0x3412)}};
                validateOutputStateWithTemplate(
                    0,
                    s,
                    byte[](0x{a_prefix_hex}),
                    byte[](0x{a_suffix_hex}),
                    byte[32](0x{a_template_hash_hex})
                );
            }}
        }}
    "#
    );

    let mux_input_compiled = compile_contract(
        &mux_source,
        &[vec![0x11u8; 32].into(), a_template_hash.clone().into(), 5.into(), vec![0x10u8, 0x20u8].into()],
        CompileOptions::default(),
    )
    .expect("compile mux succeeds");

    let sigscript = encode_entry_sig_script(&mux_input_compiled, "routeToA", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&mux_input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&bytecode(&mux_input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&target_output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputStateWithTemplate runtime failed: {}", result.unwrap_err());
}

#[test]
fn template_hash_matches_all_template_builtins() {
    let target_source = r#"
        contract Target(int initX) {
            int x = initX;

            entry noop() {
                require(true);
            }
        }
    "#;
    let target_input = compile_contract(target_source, &[7.into()], CompileOptions::default()).expect("compile target input succeeds");
    let target_output =
        compile_contract(target_source, &[8.into()], CompileOptions::default()).expect("compile target output succeeds");
    let layout = state_layout(&target_input);
    let prefix = &bytecode(&target_input)[..layout.start];
    let suffix = &bytecode(&target_input)[layout.start + layout.len..];
    let prefix_hex = prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let suffix_hex = suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let verifier_source = format!(
        r#"
        contract Verifier() {{
            struct RemoteState {{
                int x;
            }}

            entry main() {{
                byte[] templatePrefix = byte[](0x{prefix_hex});
                byte[] templateSuffix = byte[](0x{suffix_hex});
                byte[32] expectedTemplateHash = templateHash(templatePrefix, templateSuffix);

                RemoteState prev = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    expectedTemplateHash
                );
                require(prev.x == 7);

                validateOutputStateWithTemplate(
                    0,
                    RemoteState {{x: 8}},
                    templatePrefix,
                    templateSuffix,
                    expectedTemplateHash
                );
                validateOutputStateWithInputTemplate(
                    0,
                    RemoteState {{x: 8}},
                    1,
                    {},
                    {},
                    expectedTemplateHash
                );
            }}
        }}
    "#,
        prefix.len(),
        suffix.len(),
        prefix.len(),
        suffix.len(),
    );
    let verifier = compile_contract(&verifier_source, &[], CompileOptions::default()).expect("compile verifier succeeds");
    let verifier_sigscript = encode_single_entry_sig_script(&verifier, &[]).expect("verifier sigscript builds");
    let verifier_sigscript = pay_to_script_hash_signature_script(bytecode(&verifier).clone(), verifier_sigscript).unwrap();

    let verifier_input = test_input(0, verifier_sigscript);
    let target_input_tx = test_input(1, sigscript_push_bytecode(&bytecode(&target_input)));
    let output =
        TransactionOutput { value: 1000, script_public_key: pay_to_script_hash_script(&bytecode(&target_output)), covenant: None };
    let tx = Transaction::new(1, vec![verifier_input, target_input_tx], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let verifier_utxo = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&verifier)), 0, tx.is_coinbase(), None);
    let target_utxo = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&target_input)), 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![verifier_utxo, target_utxo], 0);
    assert!(result.is_ok(), "templateHash should match all state template builtins: {}", result.unwrap_err());

    let invalid_verifier_source = format!(
        r#"
        contract Verifier() {{
            struct RemoteState {{
                int x;
            }}

            entry main() {{
                RemoteState next = RemoteState {{x: 8}};
                validateOutputStateWithInputTemplate(
                    0,
                    next,
                    1,
                    {},
                    {},
                    templateHash(byte[](0x{prefix_hex}), byte[](0x{suffix_hex}))
                );
            }}
        }}
    "#,
        prefix.len() + 1,
        suffix.len(),
    );
    let invalid_verifier =
        compile_contract(&invalid_verifier_source, &[], CompileOptions::default()).expect("compile invalid verifier succeeds");
    let invalid_sigscript = encode_single_entry_sig_script(&invalid_verifier, &[]).expect("invalid verifier sigscript builds");
    let invalid_sigscript = pay_to_script_hash_signature_script(bytecode(&invalid_verifier).clone(), invalid_sigscript).unwrap();
    let invalid_input = test_input(0, invalid_sigscript);
    let target_input_tx = test_input(1, sigscript_push_bytecode(&bytecode(&target_input)));
    let output =
        TransactionOutput { value: 1000, script_public_key: pay_to_script_hash_script(&bytecode(&target_output)), covenant: None };
    let tx = Transaction::new(1, vec![invalid_input, target_input_tx], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let invalid_verifier_utxo =
        UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&invalid_verifier)), 0, tx.is_coinbase(), None);
    let target_utxo = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&target_input)), 0, tx.is_coinbase(), None);

    assert!(execute_input(tx, vec![invalid_verifier_utxo, target_utxo], 0).is_err(), "incorrect template lengths must fail");
}

#[test]
fn validate_output_state_with_input_template_requires_fixed_hash_type() {
    let source = r#"
        contract Verifier() {
            struct RemoteState {
                int x;
            }

            entry main() {
                RemoteState next = RemoteState {x: 8};
                validateOutputStateWithInputTemplate(0, next, 1, 2, 3, true);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect_err("validateOutputStateWithInputTemplate should require a byte[32] template hash");
}

#[test]
fn runs_validate_output_state_with_template_using_passed_struct_layout() {
    let target_hash_value = vec![0x44u8; 32];
    let target_hash_hex = target_hash_value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let target_source = format!(
        r#"
        contract A(byte[2] initY, int initX, byte[32] initTargetHash) {{
            byte[2] y = initY;
            int x = initX;
            byte[32] targetHash = initTargetHash;

            entry noop() {{
                require(y == byte[_](0x3412));
                require(x == 6);
                require(targetHash == byte[32](0x{target_hash_hex}));
            }}
        }}
    "#
    );

    let target_a0 = compile_contract(
        &target_source,
        &[vec![0x55u8, 0x66u8].into(), ArtifactValue::Int(0x1111_1111_1111_1111), vec![0x33u8; 32].into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (a_prefix, a_suffix, a_template_hash) = compiled_template_parts_and_hash(&target_a0);

    let target_output_compiled = compile_contract(
        &target_source,
        &[vec![0x34u8, 0x12u8].into(), 6.into(), target_hash_value.clone().into()],
        CompileOptions::default(),
    )
    .expect("compile target output succeeds");
    let a_prefix_hex = a_prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let a_suffix_hex = a_suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let a_template_hash_hex = a_template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let mux_source = format!(
        r#"
        contract M(int initX, byte[2] initY) {{
            struct C {{
                byte[2] y;
                int x;
                byte[32] targetHash;
            }}

            int x = initX;
            byte[2] y = initY;

            entry routeToA(byte[32] targetHash) {{
                C next = C {{
                    y: byte[_](0x3412),
                    x: x + 1,
                    targetHash: targetHash
                }};
                validateOutputStateWithTemplate(
                    0,
                    next,
                    byte[](0x{a_prefix_hex}),
                    byte[](0x{a_suffix_hex}),
                    byte[32](0x{a_template_hash_hex})
                );
            }}
        }}
    "#
    );

    let mux_input_compiled = compile_contract(&mux_source, &[5.into(), vec![0x10u8, 0x20u8].into()], CompileOptions::default())
        .expect("compile mux succeeds");

    let sigscript =
        encode_entry_sig_script(&mux_input_compiled, "routeToA", &[target_hash_value.clone().into()]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&mux_input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&bytecode(&mux_input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&target_output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(
        result.is_ok(),
        "validateOutputStateWithTemplate should route into a target contract whose State matches the passed struct layout: {}",
        result.unwrap_err()
    );

    let a_sigscript = encode_entry_sig_script(&target_output_compiled, "noop", &[]).expect("A sigscript builds");
    let a_sigscript = pay_to_script_hash_signature_script(bytecode(&target_output_compiled).clone(), a_sigscript).unwrap();
    let a_input = test_input(0, a_sigscript);
    let a_output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, vec![OpTrue].into()), covenant: None };
    let a_tx = Transaction::new(1, vec![a_input], vec![a_output], 0, Default::default(), 0, vec![]);
    let a_utxo = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&target_output_compiled)), 0, a_tx.is_coinbase(), None);
    let a_result = execute_input(a_tx, vec![a_utxo], 0);
    assert!(
        a_result.is_ok(),
        "target contract should observe the expected field values after routing with the passed struct layout: {}",
        a_result.unwrap_err()
    );
}

#[test]
fn validate_output_state_with_template_rejects_wrong_template_hash() {
    let target_source = r#"
        contract A(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), ArtifactValue::Int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (prefix, suffix, correct_template_hash) = compiled_template_parts_and_hash(&target);
    let mut wrong_template_hash = correct_template_hash.clone();
    wrong_template_hash[0] ^= 0x01;

    let target_output = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), correct_template_hash.into(), 6.into(), vec![0x34u8, 0x12u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target output succeeds");

    let result = run_validate_output_state_with_template_case(prefix, suffix, wrong_template_hash, &target_output);
    assert!(result.is_err(), "wrong template hash should fail at runtime");
}

#[test]
fn validate_output_state_with_template_rejects_wrong_template_parts() {
    let target_source = r#"
        contract A(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), ArtifactValue::Int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (mut prefix, suffix, template_hash) = compiled_template_parts_and_hash(&target);
    prefix.push(0x00);

    let target_output = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), template_hash.clone().into(), 6.into(), vec![0x34u8, 0x12u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target output succeeds");

    let result = run_validate_output_state_with_template_case(prefix, suffix, template_hash, &target_output);
    assert!(result.is_err(), "wrong template parts should fail at runtime");
}

#[test]
fn validate_output_state_with_template_rejects_wrong_output_script() {
    let target_source = r#"
        contract A(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), ArtifactValue::Int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (prefix, suffix, template_hash) = compiled_template_parts_and_hash(&target);

    let wrong_output = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), template_hash.clone().into(), 7.into(), vec![0x34u8, 0x12u8].into()],
        CompileOptions::default(),
    )
    .expect("compile wrong target output succeeds");

    let result = run_validate_output_state_with_template_case(prefix, suffix, template_hash, &wrong_output);
    assert!(result.is_err(), "wrong output script should fail at runtime");
}

#[test]
fn validate_output_state_with_template_rejects_different_target_state_layout() {
    let target_source = r#"
        contract D(byte[32] initMuxHash, byte[32] initAHash, int initX) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;

            entry noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), ArtifactValue::Int(0x1111_1111_1111_1111)],
        CompileOptions::default(),
    )
    .expect("compile different-layout target succeeds");
    let (prefix, suffix, template_hash) = compiled_template_parts_and_hash(&target);

    let wrong_layout_output =
        compile_contract(target_source, &[vec![0x11u8; 32].into(), template_hash.clone().into(), 6.into()], CompileOptions::default())
            .expect("compile different-layout output succeeds");

    let result = run_validate_output_state_with_template_case(prefix, suffix, template_hash, &wrong_layout_output);
    assert!(result.is_err(), "different target state layout should fail at runtime");
}

#[test]
fn conditional_counter_in_unrolled_loop_does_not_explode() {
    const SOURCE: &str = r#"
pragma silverscript ^0.1.0;

contract Sweep(int BOUND, byte[64] init_board) {
    byte[64] board = init_board;

    entry main() {
        int zero_count = 0;
        // Keep this loop small so regressions fail fast (the previous exponential blow-up
        // already manifested at single-digit iteration counts).
        for (i, 0, BOUND, BOUND) {
            if (OpBin2Num(byte[](board[i])) == 0) {
                zero_count = zero_count + 1;
            }
        }
        require(zero_count >= 0);
    }
}
"#;

    let bounds = [4i64, 8i64, 12i64];
    let mut lens = Vec::new();
    for b in bounds {
        let args = [b.into(), vec![0u8; 64].into()];
        let compiled = compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile succeeds");
        lens.push(bytecode(&compiled).len());
    }

    // Monotonic growth, and no doubling behavior in this range.
    assert!(lens[0] < lens[1] && lens[1] < lens[2], "expected monotonic growth, got {lens:?}");
    let d1 = lens[1] - lens[0];
    let d2 = lens[2] - lens[1];
    assert!(d2 <= d1 * 2, "unexpected superlinear growth: lens={lens:?} d1={d1} d2={d2}");

    // Absolute cap: the old exponential behavior already blew past this by bound=8..12.
    assert!(lens[2] < 5_000, "unexpected script size: lens={lens:?}");
}

#[test]
fn validate_output_state_accepts_state_value_from_array_index() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entry main(State[] xs) {
                State next = xs[0];
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[state_array_arg_x(vec![6])]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[6.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "state value sourced from array index should validate output state: {result:?}");
}

#[test]
fn validate_output_state_accepts_state_value_from_inline_returned_array() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            function id(State[] xs) : (State[]) {
                return(xs);
            }

            entry main(State[] xs) {
                (State[] ys) = id(xs);
                State next = ys[0];
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[state_array_arg_x(vec![6])]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[6.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "state value sourced from inline returned State[] should validate output state: {result:?}");
}

#[test]
fn read_input_state_accepts_self_state_under_dispatch_tag_dispatch() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entry noop() {
                require(true);
            }

            entry main() {
                State s = readInputState(this.activeInputIndex);
                require(s.x == 5);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState should read the current state under dispatch_tag dispatch: {result:?}");
}

#[test]
fn read_input_state_int_addition_uses_numeric_semantics() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entry main() {
                State s = readInputState(this.activeInputIndex);
                int y = s.x + 5;
                require(y == 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&compiled).clone(), sigscript).expect("p2sh sigscript wraps");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&compiled));
    let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState int arithmetic should use numeric semantics: {result:?}");
}

#[test]
fn read_input_state_accepts_three_field_state_under_dispatch_tag_dispatch() {
    let source = r#"
        contract C(int initAmount, byte[2] initCode, byte[32] initOwner) {
            int amount = initAmount;
            byte[2] code = initCode;
            byte[32] owner = initOwner;

            entry noop() {
                require(true);
            }

            entry main() {
                State s = readInputState(this.activeInputIndex);
                require(s.amount == 5);
                require(s.code == byte[_](0x3412));
                require(s.owner == byte[_](0x0101010101010101010101010101010101010101010101010101010101010101));
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![0x34u8, 0x12u8].into(), vec![1u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled =
        compile_contract(source, &[5.into(), vec![0x34u8, 0x12u8].into(), vec![1u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState should read mixed-width state under dispatch_tag dispatch: {result:?}");
}

#[test]
fn read_input_state_accepts_pubkey_and_bool_fields_under_dispatch_tag_dispatch() {
    let source = r#"
        contract C(bool initFlag, pubkey initOwner) {
            bool flag = initFlag;
            pubkey owner = initOwner;

            entry noop() {
                require(true);
            }

            entry main() {
                State s = readInputState(this.activeInputIndex);
                require(s.flag);
                require(s.owner == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[true.into(), vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled =
        compile_contract(source, &[true.into(), vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState should read pubkey and bool state under dispatch_tag dispatch: {result:?}");
}

#[test]
fn read_input_state_runtime_preserves_supported_field_types_across_contract_shapes() {
    let run_case = |source: &str, args: Vec<ArtifactValue>, label: &str| {
        let compiled = compile_contract(source, &args, CompileOptions::default()).unwrap_or_else(|err| panic!("{label}: {err:?}"));
        let sigscript = encode_entry_sig_script(&compiled, "main", &[]).expect("sigscript builds");
        let sigscript = pay_to_script_hash_signature_script(bytecode(&compiled).clone(), sigscript).expect("p2sh sigscript wraps");
        let input = test_input(0, sigscript);
        let input_spk = pay_to_script_hash_script(&bytecode(&compiled));
        let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
        let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
        let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

        let result = execute_input(tx, vec![utxo_entry], 0);
        assert!(result.is_ok(), "{label}: {result:?}");
    };

    run_case(
        r#"
            contract C(int initInt) {
                int someInt = initInt;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someInt + 5 == 15);
                }
            }
        "#,
        vec![10.into()],
        "int fields should preserve numeric semantics",
    );

    run_case(
        r#"
            contract C(int[2] initInts) {
                int[2] someInts = initInts;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someInts.length == 2);
                    require(x.someInts[0] == 1);
                    require(x.someInts[1] + 5 == 7);
                }
            }
        "#,
        vec![ArtifactValue::Array(vec![1.into(), 2.into()])],
        "int[2] fields should preserve array indexing semantics",
    );

    run_case(
        r#"
            contract C(bool initBool) {
                bool someBool = initBool;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBool);
                }
            }
        "#,
        vec![true.into()],
        "bool fields should preserve boolean semantics",
    );

    run_case(
        r#"
            contract C(bool[2] initBools) {
                bool[2] someBools = initBools;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBools.length == 2);
                    require(x.someBools[0]);
                    require(!x.someBools[1]);
                }
            }
        "#,
        vec![ArtifactValue::Array(vec![true.into(), false.into()])],
        "bool[2] fields should preserve array indexing semantics",
    );

    run_case(
        r#"
            contract C(byte[2] initBytes2) {
                byte[2] someBytes2 = initBytes2;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBytes2.length == 2);
                    require(x.someBytes2 == byte[_](0x3412));
                }
            }
        "#,
        vec![vec![0x34u8, 0x12u8].into()],
        "byte[2] fields should preserve fixed-byte-array semantics",
    );

    run_case(
        r#"
            contract C(pubkey initPubkey) {
                pubkey somePubkey = initPubkey;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.somePubkey == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));

                    byte[] owner = byte[](x.somePubkey);
                    owner = owner.append(byte(3));
                    require(owner.length == 33);
                }
            }
        "#,
        vec![vec![2u8; 32].into()],
        "pubkey fields should preserve fixed-size byte semantics",
    );

    run_case(
        r#"
            contract C(sig initSig) {
                sig someSig = initSig;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someSig == sig(0x1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111));

                    byte[] sigBytes = byte[](x.someSig);
                    sigBytes = sigBytes.append(byte(0x42));
                    require(sigBytes.length == 66);
                }
            }
        "#,
        vec![vec![0x11u8; 65].into()],
        "sig fields should preserve fixed-size byte semantics",
    );

    run_case(
        r#"
            contract C(datasig initDatasig) {
                datasig someDatasig = initDatasig;

                entry noop() {
                    require(true);
                }

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someDatasig == datasig(0x22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222));

                    byte[] datasigBytes = byte[](x.someDatasig);
                    datasigBytes = datasigBytes.append(byte(0x24));
                    require(datasigBytes.length == 65);
                }
            }
        "#,
        vec![vec![0x22u8; 64].into()],
        "datasig fields should preserve fixed-size byte semantics",
    );
}

#[test]
fn read_input_state_runtime_preserves_supported_field_types_with_single_entrypoint_dispatch() {
    let run_case = |source: &str, args: Vec<ArtifactValue>, label: &str| {
        let compiled = compile_contract(source, &args, CompileOptions::default()).unwrap_or_else(|err| panic!("{label}: {err:?}"));
        let sigscript = encode_single_entry_sig_script(&compiled, &[]).expect("sigscript builds");
        let sigscript = pay_to_script_hash_signature_script(bytecode(&compiled).clone(), sigscript).expect("p2sh sigscript wraps");
        let input = test_input(0, sigscript);
        let input_spk = pay_to_script_hash_script(&bytecode(&compiled));
        let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
        let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
        let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

        let result = execute_input(tx, vec![utxo_entry], 0);
        assert!(result.is_ok(), "{label}: {result:?}");
    };

    run_case(
        r#"
            contract C(int initInt) {
                int someInt = initInt;

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someInt + 5 == 15);
                }
            }
        "#,
        vec![10.into()],
        "single-entrypoint int fields should preserve numeric semantics",
    );

    run_case(
        r#"
            contract C(byte[2] initBytes2) {
                byte[2] someBytes2 = initBytes2;

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBytes2.length == 2);
                    require(x.someBytes2 == byte[_](0x3412));
                }
            }
        "#,
        vec![vec![0x34u8, 0x12u8].into()],
        "single-entrypoint byte[2] fields should preserve fixed-byte-array semantics",
    );

    run_case(
        r#"
            contract C(pubkey initPubkey) {
                pubkey somePubkey = initPubkey;

                entry main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.somePubkey == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));

                    byte[] owner = byte[](x.somePubkey);
                    owner = owner.append(byte(3));
                    require(owner.length == 33);
                }
            }
        "#,
        vec![vec![2u8; 32].into()],
        "single-entrypoint pubkey fields should preserve fixed-size byte semantics",
    );
}

#[test]
fn read_input_state_scalar_byte_round_trips_at_runtime() {
    let source = r#"
        contract C(byte initByte, pubkey initOwner) {
            byte someByte = initByte;
            pubkey someOwner = initOwner;

            entry noop() {
                require(true);
            }

            entry main() {
                State x = readInputState(this.activeInputIndex);

                // The companion pubkey field proves the state offsets are otherwise correct for this layout.
                require(x.someOwner == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));

                // Regression coverage: scalar byte fields should round-trip through readInputState
                // with the same semantics as ordinary byte values.
                require(x.someByte == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, &[ArtifactValue::Byte(7), vec![2u8; 32].into()], CompileOptions::default())
        .expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&compiled).clone(), sigscript).expect("p2sh sigscript wraps");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&compiled));
    let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "scalar byte readInputState should preserve runtime byte semantics: {result:?}");
}

#[test]
fn validate_output_state_accepts_state_under_dispatch_tag_dispatch() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entry noop() {
                require(true);
            }

            entry main(State next) {
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[artifact_object([("x", 6.into())])]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[6.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "state value should validate output state under dispatch_tag dispatch: {result:?}");
}

#[test]
fn validate_output_state_accepts_three_field_state_under_dispatch_tag_dispatch() {
    let source = r#"
        contract C(int initAmount, byte[2] initCode, byte[32] initOwner) {
            int amount = initAmount;
            byte[2] code = initCode;
            byte[32] owner = initOwner;

            entry noop() {
                require(true);
            }

            entry main(State next) {
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![0x34u8, 0x12u8].into(), vec![1u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let sigscript = encode_entry_sig_script(
        &input_compiled,
        "main",
        &[artifact_object([("amount", 6.into()), ("code", vec![0xabu8, 0xcdu8].into()), ("owner", vec![2u8; 32].into())])],
    )
    .expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled =
        compile_contract(source, &[6.into(), vec![0xabu8, 0xcdu8].into(), vec![2u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "mixed-width state should validate output state under dispatch_tag dispatch: {result:?}");
}

#[test]
fn debug_validate_output_state_accepts_current_byte32_fields() {
    let source = r#"
        contract C(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {muxHash: muxHash, aHash: aHash, x: x + 1, y: byte[_](0x3412)});
            }
        }
    "#;

    let input_compiled = compile_contract(
        source,
        &[vec![0x11u8; 32].into(), vec![0x22u8; 32].into(), 5.into(), vec![0x10u8, 0x20u8].into()],
        CompileOptions::default(),
    )
    .expect("compile succeeds");

    let output_compiled = compile_contract(
        source,
        &[vec![0x11u8; 32].into(), vec![0x22u8; 32].into(), 6.into(), vec![0x34u8, 0x12u8].into()],
        CompileOptions::default(),
    )
    .expect("compile succeeds");

    let sigscript = encode_single_entry_sig_script(&input_compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputState should accept current byte[32] fields: {result:?}");
}

#[test]
fn validate_output_state_accepts_pubkey_field_under_dispatch_tag_dispatch() {
    let source = r#"
        contract C(pubkey initOwner) {
            pubkey owner = initOwner;

            entry noop() {
                require(true);
            }

            entry main(State next) {
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[vec![1u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "main", &[artifact_object([("owner", vec![2u8; 32].into())])])
        .expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "pubkey state should validate output state under dispatch_tag dispatch: {result:?}");
}

#[test]
fn compiles_state_variable_and_internal_function_argument() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            function check(State s) {
                require(s.x == 6);
                require(s.y == byte[_](0x3412));
            }

            entry main() {
                State next = State {x: x + 1, y: byte[_](0x3412)};
                check(next);
            }
        }
    "#;

    compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn runs_state_variable_and_internal_function_argument() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            function check(State s) {
                require(s.x == 6);
                require(s.y == byte[_](0x3412));
            }

            entry main() {
                State next = State {x: x + 1, y: byte[_](0x3412)};
                check(next);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "script should execute successfully: {result:?}");
}

#[test]
fn plain_state_return_accepts_local_fixed_byte_field_from_local_identifier() {
    let source = r#"
        contract C(byte[2] initData) {
            byte[2] data = initData;

            function step(State prev_state) : (State) {
                byte[2] next_data = prev_state.data;
                return(State {
                    data: next_data
                });
            }

            entry main() {
                State prev = State {data: data};
                (State next) = step(prev);
                require(next.data == data);
            }
        }
    "#;

    compile_contract(source, &[vec![0u8, 0u8].into()], CompileOptions::default())
        .expect("plain State return with local fixed-byte identifier should compile");
}

#[test]
fn byte_hex_literal_is_a_scalar_numeral() {
    let source = r#"
        contract C() {
            entry main() {
                byte local = 0x07;
                require(local == local);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("scalar byte hex literal should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn hex_literals_are_numerals_for_int_and_byte() {
    let source = r#"
        contract HexNumerals() {
            entry main() {
                int a = 0x1234;
                byte b = 0x12;
                int eight_bytes = 0x0102030405060708;
                require(a == 4660);
                require(b == 18);
                require(eight_bytes == 72623859790382856);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("hex numerals should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn rejects_hex_numerals_that_do_not_fit_the_scalar_type() {
    let cases = [
        ("int", "0x010203040506070809", "nine-byte hex literal should not initialize int"),
        ("byte", "0x0102", "two-byte hex literal should not initialize byte"),
    ];

    for (type_name, literal, message) in cases {
        let source = format!("contract C() {{ entry main() {{ {type_name} value = {literal}; require(true); }} }}");
        compile_contract(&source, &[], CompileOptions::default()).expect_err(message);
    }
}

#[test]
fn hex_literal_over_eight_bytes_requires_an_immediate_byte_array_cast() {
    let raw = "0x010203040506070809";
    let uncast = format!("contract C() {{ entry main() {{ byte[_] value = {raw}; require(true); }} }}");
    let err = compile_contract(&uncast, &[], CompileOptions::default()).expect_err("uncast nine-byte hex literal should fail");
    assert!(
        err.to_string().contains("exceeds 8 bytes; cast it directly to a byte array or fixed byte-sequence type"),
        "unexpected error: {err}"
    );

    let source = format!("contract C() {{ entry main() {{ byte[_] value = byte[_]({raw}); require(value == byte[9]({raw})); }} }}");
    let compiled =
        compile_contract(&source, &[], CompileOptions::default()).expect("immediately cast nine-byte literal should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn fixed_byte_sequence_types_accept_immediate_hex_literals() {
    let pubkey = "02".repeat(32);
    let sig = "11".repeat(65);
    let datasig = "22".repeat(64);
    let source = format!(
        r#"
        contract C() {{
            entry main() {{
                pubkey public_key = pubkey(0x{pubkey});
                sig signature = sig(0x{sig});
                datasig data_signature = datasig(0x{datasig});
                require(public_key == public_key);
                require(signature == signature);
                require(data_signature == data_signature);
            }}
        }}
        "#
    );

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("direct fixed byte-sequence casts should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn fixed_byte_sequence_hex_literals_require_exact_sizes() {
    let cases = [("pubkey", 31, 32), ("pubkey", 33, 32), ("sig", 64, 65), ("sig", 66, 65), ("datasig", 63, 64), ("datasig", 65, 64)];

    for (type_name, actual, expected) in cases {
        let source = format!(
            "contract C() {{ entry main() {{ {type_name} value = {type_name}(0x{}); require(true); }} }}",
            "02".repeat(actual)
        );
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("wrong-sized fixed byte-sequence literal should fail");
        assert!(
            err.to_string().contains(&format!("{type_name} hex literal size mismatch: expected {expected} bytes, got {actual}")),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn empty_hex_literal_requires_a_byte_array_cast() {
    let source = r#"
        contract C() {
            entry main() {
                byte[] value = byte[](0x);
                require(value.length == 0);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("explicit empty byte literal should compile");

    let err = compile_contract("contract C() { entry main() { int value = 0x; require(true); } }", &[], CompileOptions::default())
        .expect_err("an empty numeral should fail");
    assert!(err.to_string().contains("invalid hex literal '0x'"), "unexpected error: {err}");
}

#[test]
fn compiles_read_input_state_to_expected_script() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                State {x: int in1_x, y: byte[2] in1_y} = readInputState(1);
                require(in1_x > 7);
                require(in1_y == byte[_](0x3412));
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let _expected = script_builder()
        // ---- Prolog state on active input: x=5, y=0x0102 ----
        // push x payload (8-byte LE)
        .add_data_with_push_opcode(&5i64.to_le_bytes())
        .unwrap()
        // push y payload bytes
        .add_data_with_push_opcode(&[1u8, 2u8])
        .unwrap()

        // ---- in1_x = readInputState(1).x ----
        // input index for start computation
        .add_i64(1)
        .unwrap()
        // same input index for scriptSig length
        .add_i64(1)
        .unwrap()
        // len(sigScript of input 1)
        .add_op(OpTxInputScriptSigLen)
        .unwrap()
        // this.bytecodeSize
        .add_i64(bytecode(&compiled).len() as i64)
        .unwrap()
        // base = sig_len - bytecode_size
        .add_op(OpSub)
        .unwrap()
        // skip int pushdata prefix byte (0x08)
        .add_i64(1)
        .unwrap()
        // start_x = base + 1
        .add_op(OpAdd)
        .unwrap()

        // input index for end computation
        .add_i64(1)
        .unwrap()
        // len(sigScript of input 1)
        .add_op(OpTxInputScriptSigLen)
        .unwrap()
        // this.bytecodeSize
        .add_i64(bytecode(&compiled).len() as i64)
        .unwrap()
        // base = sig_len - bytecode_size
        .add_op(OpSub)
        .unwrap()
        // skip int prefix
        .add_i64(1)
        .unwrap()
        // start_x = base + 1
        .add_op(OpAdd)
        .unwrap()
        // int payload length
        .add_i64(8)
        .unwrap()
        // end_x = start_x + 8
        .add_op(OpAdd)
        .unwrap()
        // bytes = sigScriptSubstr(input=1, start_x, end_x)
        .add_op(OpTxInputScriptSigSubstr)
        .unwrap()
        // literal threshold
        .add_i64(7)
        .unwrap()
        // in1_x > 7
        .add_op(OpGreaterThan)
        .unwrap()
        // enforce require(in1_x > 7)
        .add_op(OpVerify)
        .unwrap()

        // ---- in1_y = readInputState(1).y ----
        // input index for y start computation
        .add_i64(1)
        .unwrap()
        // same input index for scriptSig length
        .add_i64(1)
        .unwrap()
        // len(sigScript of input 1)
        .add_op(OpTxInputScriptSigLen)
        .unwrap()
        // this.bytecodeSize
        .add_i64(bytecode(&compiled).len() as i64)
        .unwrap()
        // base = sig_len - bytecode_size
        .add_op(OpSub)
        .unwrap()
        // skip x encoded chunk (9 bytes) + y pushdata prefix (1 byte)
        .add_i64(10)
        .unwrap()
        // start_y = base + 10
        .add_op(OpAdd)
        .unwrap()

        // input index for y end computation
        .add_i64(1)
        .unwrap()
        // len(sigScript of input 1)
        .add_op(OpTxInputScriptSigLen)
        .unwrap()
        // this.bytecodeSize
        .add_i64(bytecode(&compiled).len() as i64)
        .unwrap()
        // base = sig_len - bytecode_size
        .add_op(OpSub)
        .unwrap()
        // skip x chunk + y prefix
        .add_i64(10)
        .unwrap()
        // start_y = base + 10
        .add_op(OpAdd)
        .unwrap()
        // y payload length
        .add_i64(2)
        .unwrap()
        // end_y = start_y + 2
        .add_op(OpAdd)
        .unwrap()
        // bytes = sigScriptSubstr(input=1, start_y, end_y)
        .add_op(OpTxInputScriptSigSubstr)
        .unwrap()
        // expected y bytes
        .add_data_with_push_opcode(&[0x34, 0x12])
        .unwrap()
        // in1_y == 0x3412
        .add_op(OpEqual)
        .unwrap()
        // enforce require(in1_y == 0x3412)
        .add_op(OpVerify)
        .unwrap()

        // drop original y field from active-input state prolog
        .add_op(OpDrop)
        .unwrap()
        // drop original x field from active-input state prolog
        .add_op(OpDrop)
        .unwrap()
        // success
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let asm = script_to_str(&bytecode(&compiled)).expect("stringifies");
    // Two field reads, the single state-region read the framing guard uses to pin each field's
    // push header, and the window read whose P2SH is compared against the input's scriptPubKey.
    assert_eq!(
        asm.matches("OpTxInputScriptSigSubstr").count(),
        4,
        "should read two state fields behind a region read and a window read"
    );
    assert_eq!(asm.matches("OpGreaterThan").count(), 1, "should compare x numerically");
    let equal_verify_count = asm.matches("OpEqualVerify").count();
    assert_eq!(equal_verify_count, 3, "one push header pinned per state field, plus the scriptPubKey binding");
    assert_eq!(asm.matches("OpEqual").count() - equal_verify_count, 2, "should compare y bytewise in addition to dispatch");
    assert!(
        bytecode(&compiled).ends_with(&[OpDrop, OpDrop, OpTrue, OpElse, OpReturn, OpEndIf]),
        "expected stack cleanup for active state before the dispatch epilogue"
    );
}

#[test]
fn runs_read_input_state() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                State {x: int in1_x, y: byte[2] in1_y} = readInputState(1);
                require(in1_x > 7);
                require(in1_y == byte[_](0x3412));
            }
        }
    "#;

    let active_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input1_compiled =
        compile_contract(source, &[8.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input0 = test_input(0, dispatch_tag_sigscript(dispatch_tag_for(&active_compiled, "main")));
    let input1 = test_input(1, sigscript_push_bytecode(&bytecode(&input1_compiled)));

    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, bytecode(&active_compiled).clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input0.clone(), input1], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo0 = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    // The read input's own UTXO must commit to the script it presents — the plain decoder now
    // requires it, as the templated one always has.
    let utxo1 = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&input1_compiled)), 0, tx.is_coinbase(), None);
    let result = execute_input(tx, vec![utxo0, utxo1], 0);
    assert!(result.is_ok(), "readInputState runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_read_input_state_into_state_variable() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                State in1 = readInputState(1);
                require(in1.x > 7);
                require(in1.y == byte[_](0x3412));
            }
        }
    "#;

    let active_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input1_compiled =
        compile_contract(source, &[8.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input0 = test_input(0, dispatch_tag_sigscript(dispatch_tag_for(&active_compiled, "main")));
    let input1 = test_input(1, sigscript_push_bytecode(&bytecode(&input1_compiled)));

    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, bytecode(&active_compiled).clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input0.clone(), input1], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo0 = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    // The read input's own UTXO must commit to the script it presents — the plain decoder now
    // requires it, as the templated one always has.
    let utxo1 = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&input1_compiled)), 0, tx.is_coinbase(), None);
    let result = execute_input(tx, vec![utxo0, utxo1], 0);
    assert!(result.is_ok(), "readInputState runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_read_input_state_as_internal_function_argument() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            function check(State remote) {
                require(remote.x > 7);
                require(remote.y == byte[_](0x3412));
            }

            entry main() {
                check(readInputState(1));
            }
        }
    "#;

    let active_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input1_compiled =
        compile_contract(source, &[8.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input0 = test_input(0, dispatch_tag_sigscript(dispatch_tag_for(&active_compiled, "main")));
    let input1 = test_input(1, sigscript_push_bytecode(&bytecode(&input1_compiled)));
    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, bytecode(&active_compiled).clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input0, input1], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo0 = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    // The read input's own UTXO must commit to the script it presents — the plain decoder now
    // requires it, as the templated one always has.
    let utxo1 = UtxoEntry::new(1000, pay_to_script_hash_script(&bytecode(&input1_compiled)), 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo0, utxo1], 0);
    assert!(result.is_ok(), "readInputState call argument failed at runtime: {}", result.unwrap_err());
}

#[test]
fn runs_read_input_state_with_template_into_typed_struct_variable() {
    let target_hash_value = vec![0x44u8; 32];
    let target_hash_hex = target_hash_value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let target_source = r#"
        contract A(byte[2] initY, int initX, byte[32] initTargetHash) {
            byte[2] y = initY;
            int x = initX;
            byte[32] targetHash = initTargetHash;

            entry noop() {
                require(true);
            }
        }
    "#;
    let target_input_compiled = compile_contract(
        target_source,
        &[vec![0x34u8, 0x12u8].into(), 8.into(), target_hash_value.clone().into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (template_prefix, template_suffix, template_hash) = compiled_template_parts_and_hash(&target_input_compiled);

    let reader_source = format!(
        r#"
        contract Reader(int initRound) {{
            struct RemoteState {{
                byte[2] y;
                int x;
                byte[32] targetHash;
            }}

            int round = initRound;

            entry main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    byte[32](0x{})
                );
                require(round == 5);
                require(remote.y == byte[_](0x3412));
                require(remote.x == 8);
                require(remote.targetHash == byte[32](0x{target_hash_hex}));
            }}
        }}
    "#,
        template_prefix.len(),
        template_suffix.len(),
        template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );

    let result = run_read_input_state_with_template_case(&reader_source, &[5.into()], &target_input_compiled);
    assert!(
        result.is_ok(),
        "readInputStateWithTemplate should decode a foreign input using the passed struct layout: {}",
        result.unwrap_err()
    );
}

#[test]
fn typed_state_reader_disambiguates_the_implicit_state_layout() {
    let source = r#"
        contract Reader() {
            struct RemoteState {
                int n;
            }

            int n = 0;

            entry main() {
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    0,
                    0,
                    byte[_](0x0000000000000000000000000000000000000000000000000000000000000000)
                );
                require(remote.n >= 0);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("the explicit RemoteState type should disambiguate the identical implicit State layout");
}

#[test]
fn typed_state_reader_disambiguates_identical_custom_struct_layouts() {
    let source = r#"
        contract Reader() {
            struct AState {
                int n;
            }

            struct BState {
                int n;
            }

            int tag = 0;

            entry main() {
                AState remote = readInputStateWithTemplate(
                    1,
                    0,
                    0,
                    byte[_](0x0000000000000000000000000000000000000000000000000000000000000000)
                );
                require(remote.n >= 0);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("the explicit AState type should disambiguate identical custom layouts");
}

#[test]
fn typed_state_reader_destructuring_disambiguates_identical_custom_struct_layouts() {
    let source = r#"
        contract Reader() {
            struct AState {
                int n;
            }

            struct BState {
                int n;
            }

            int tag = 0;

            entry main() {
                AState {n: int remoteN} = readInputStateWithTemplate(
                    1,
                    0,
                    0,
                    byte[_](0x0000000000000000000000000000000000000000000000000000000000000000)
                );
                require(remoteN >= 0);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("the explicit pattern type should disambiguate identical layouts");
}

#[test]
fn runs_read_input_state_with_template_destructuring() {
    let target_hash_value = vec![0x55u8; 32];
    let target_hash_hex = target_hash_value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let target_source = r#"
        contract A(byte[2] initY, int initX, byte[32] initTargetHash) {
            byte[2] y = initY;
            int x = initX;
            byte[32] targetHash = initTargetHash;

            entry noop() {
                require(true);
            }
        }
    "#;
    let target_input_compiled = compile_contract(
        target_source,
        &[vec![0x78u8, 0x56u8].into(), 11.into(), target_hash_value.clone().into()],
        CompileOptions::default(),
    )
    .expect("compile target succeeds");
    let (template_prefix, template_suffix, template_hash) = compiled_template_parts_and_hash(&target_input_compiled);

    let reader_source = format!(
        r#"
        contract Reader() {{
            struct RemoteState {{
                byte[2] y;
                int x;
                byte[32] targetHash;
            }}

            entry main() {{
                RemoteState {{y: byte[2] inY, x: int inX, targetHash: byte[32] inHash}} = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    byte[32](0x{})
                );
                require(inY == byte[_](0x7856));
                require(inX == 11);
                require(inHash == byte[32](0x{target_hash_hex}));
            }}
        }}
    "#,
        template_prefix.len(),
        template_suffix.len(),
        template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );

    let result = run_read_input_state_with_template_case(&reader_source, &[], &target_input_compiled);
    assert!(result.is_ok(), "readInputStateWithTemplate destructuring should succeed: {}", result.unwrap_err());
}

#[test]
fn read_input_state_with_template_rejects_wrong_template_hash() {
    let target_source = r#"
        contract A(byte[2] initY, int initX) {
            byte[2] y = initY;
            int x = initX;

            entry noop() {
                require(true);
            }
        }
    "#;
    let target_input_compiled = compile_contract(target_source, &[vec![0x34u8, 0x12u8].into(), 8.into()], CompileOptions::default())
        .expect("compile target succeeds");
    let (template_prefix, template_suffix, mut template_hash) = compiled_template_parts_and_hash(&target_input_compiled);
    template_hash[0] ^= 0x01;

    let reader_source = format!(
        r#"
        contract Reader() {{
            struct RemoteState {{
                byte[2] y;
                int x;
            }}

            entry main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    byte[32](0x{})
                );
                require(remote.y == byte[_](0x3412));
                require(remote.x == 8);
            }}
        }}
    "#,
        template_prefix.len(),
        template_suffix.len(),
        template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );

    let result = run_read_input_state_with_template_case(&reader_source, &[], &target_input_compiled);
    assert!(result.is_err(), "wrong template hash should fail at runtime");
}

#[test]
fn read_input_state_with_template_rejects_wrong_template_sizes() {
    let target_source = r#"
        contract A(byte[2] initY, int initX) {
            byte[2] y = initY;
            int x = initX;

            entry noop() {
                require(true);
            }
        }
    "#;
    let target_input_compiled = compile_contract(target_source, &[vec![0x34u8, 0x12u8].into(), 8.into()], CompileOptions::default())
        .expect("compile target succeeds");
    let (template_prefix, template_suffix, template_hash) = compiled_template_parts_and_hash(&target_input_compiled);
    let wrong_prefix_len = template_prefix.len() + 1;

    let reader_source = format!(
        r#"
        contract Reader() {{
            struct RemoteState {{
                byte[2] y;
                int x;
            }}

            entry main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    byte[32](0x{})
                );
                require(remote.y == byte[_](0x3412));
                require(remote.x == 8);
            }}
        }}
    "#,
        wrong_prefix_len,
        template_suffix.len(),
        template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );

    let result = run_read_input_state_with_template_case(&reader_source, &[], &target_input_compiled);
    assert!(result.is_err(), "wrong template sizes should fail at runtime");
}

#[test]
fn read_input_state_with_template_rejects_input_with_wrong_p2sh_commitment() {
    let target_source = r#"
        contract A(byte[2] initY, int initX) {
            byte[2] y = initY;
            int x = initX;

            entry noop() {
                require(true);
            }
        }
    "#;
    let target_input_compiled = compile_contract(target_source, &[vec![0x34u8, 0x12u8].into(), 8.into()], CompileOptions::default())
        .expect("compile target succeeds");
    let (template_prefix, template_suffix, template_hash) = compiled_template_parts_and_hash(&target_input_compiled);

    let reader_source = format!(
        r#"
        contract Reader() {{
            struct RemoteState {{
                byte[2] y;
                int x;
            }}

            entry main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    byte[32](0x{})
                );
                require(remote.y == byte[_](0x3412));
                require(remote.x == 8);
            }}
        }}
    "#,
        template_prefix.len(),
        template_suffix.len(),
        template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );

    let wrong_input_spk = pay_to_script_hash_script(&[OpTrue]);
    let result = run_read_input_state_with_template_case_with_input_spk(&reader_source, &[], &target_input_compiled, wrong_input_spk);
    assert!(result.is_err(), "wrong foreign input P2SH commitment should fail at runtime");
}

#[test]
fn rejects_read_input_state_with_template_outside_direct_binding() {
    let source = r#"
        contract Reader() {
            struct RemoteState {
                int x;
            }

            function check(RemoteState remote) {
                require(remote.x > 0);
            }

            entry main(int prefixLen, int suffixLen, byte[32] expectedTemplateHash) {
                check(readInputStateWithTemplate(1, prefixLen, suffixLen, expectedTemplateHash));
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("readInputStateWithTemplate should be rejected outside direct struct bindings");
    assert!(err.to_string().contains("must be assigned to a struct variable or destructured directly"), "unexpected error: {err}");
}

#[test]
fn rejects_read_input_state_with_template_as_expression_call_argument() {
    let source = r#"
        contract Reader() {
            struct RemoteState {
                int x;
            }

            function identity(RemoteState remote) : RemoteState {
                return remote;
            }

            entry main(int prefixLen, int suffixLen, byte[32] expectedTemplateHash) {
                RemoteState remote = identity(
                    readInputStateWithTemplate(1, prefixLen, suffixLen, expectedTemplateHash)
                );
                require(remote.x > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("readInputStateWithTemplate should be rejected as an expression call argument");
    assert!(err.to_string().contains("must be assigned to a struct variable or destructured directly"), "unexpected error: {err}");
}

#[test]
fn read_input_state_with_template_checks_argument_types() {
    let cases = [
        ("true, prefixLen, suffixLen, expectedTemplateHash", "input_idx"),
        ("1, true, suffixLen, expectedTemplateHash", "template_prefix_len"),
        ("1, prefixLen, true, expectedTemplateHash", "template_suffix_len"),
        ("1, prefixLen, suffixLen, prefixLen", "expected_template_hash"),
    ];

    for (args, parameter) in cases {
        let source = format!(
            r#"
                contract Reader() {{
                    struct RemoteState {{
                        int x;
                    }}

                    entry main(int prefixLen, int suffixLen, byte[32] expectedTemplateHash) {{
                        RemoteState remote = readInputStateWithTemplate({args});
                        require(remote.x > 0);
                    }}
                }}
            "#
        );

        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("readInputStateWithTemplate should reject an argument with the wrong type");
        assert!(err.to_string().contains(parameter), "expected an error for '{parameter}', got: {err}");
    }
}

#[test]
fn rejects_validate_output_state_with_incorrect_state_variable_type() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            struct OtherState {
                int z;
            }

            int x = initX;
            byte[2] y = initY;

            entry main() {
                OtherState next = OtherState {z: 7};
                validateOutputState(0, next);
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("wrong struct type should be rejected");
    assert!(err.to_string().contains("State") || err.to_string().contains("struct"), "unexpected error: {err}");
}

#[test]
fn validate_output_state_lowers_nested_state_literal_in_state_field_order() {
    let source = r#"
        contract C(int initA, int initC, int initD) {
            struct S2 {
                int c;
                int d;
            }

            int a = initA;
            S2 b = S2 {c: initC, d: initD};

            entry main() {
                validateOutputState(0, State {b: S2 {d: 8, c: 7}, a: 6});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), 3.into(), 4.into()], CompileOptions::default()).expect("compile succeeds");
    let output_compiled =
        compile_contract(source, &[6.into(), 7.into(), 8.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&input_compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "nested state literal should validate in declared state field order: {result:?}");
}

#[test]
fn validate_output_state_with_state_identifier() {
    let source = r#"
        contract C(int initA, int initC, int initD) {
            struct S2 {
                int c;
                int d;
            }

            int a = initA;
            S2 b = S2 {c: initC, d: initD};

            entry main() {
                State next = State {b: S2 {d: 8, c: 7}, a: 6};
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), 3.into(), 4.into()], CompileOptions::default()).expect("compile succeeds");
    let output_compiled =
        compile_contract(source, &[6.into(), 7.into(), 8.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&input_compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "local State value should lower to validateOutputStateInner leaves: {result:?}");
}

#[test]
fn validate_output_state_with_template_uses_passed_struct_layout_not_local_state_layout() {
    let source = r#"
        contract M(int initX, byte[2] initY) {
            struct C {
                byte[2] y;
                int x;
                byte[32] targetHash;
            }

            int x = initX;
            byte[2] y = initY;

            entry route(byte[32] targetHash) {
                C next = C {
                    y: byte[_](0x3412),
                    x: x + 1,
                    targetHash: targetHash
                };
                validateOutputStateWithTemplate(
                    0,
                    next,
                    byte[](0x51),
                    byte[](0x52),
                    byte[32](0x0000000000000000000000000000000000000000000000000000000000000000)
                );
            }
        }
    "#;

    let result = compile_contract(source, &[5.into(), vec![0x10u8, 0x20u8].into()], CompileOptions::default());
    assert!(
        result.is_ok(),
        "validateOutputStateWithTemplate should encode the passed struct layout instead of the local State layout: {result:?}"
    );
}

#[test]
fn rejects_read_input_state_with_incorrect_target_type() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            struct OtherState {
                int z;
            }

            int x = initX;
            byte[2] y = initY;

            entry main() {
                OtherState in0 = readInputState(0);
                require(in0.z > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("readInputState assigned to wrong struct type should be rejected");
    assert!(err.to_string().contains("State") || err.to_string().contains("struct"), "unexpected error: {err}");
}

#[test]
fn rejects_read_input_state_destructuring_with_incorrect_target_type() {
    let source = r#"
        contract C(int initX) {
            struct OtherState {
                int x;
            }

            int x = initX;

            entry main() {
                OtherState {x: int inputX} = readInputState(0);
                require(inputX > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[5.into()], CompileOptions::default())
        .expect_err("readInputState destructured as the wrong struct type should be rejected");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
fn fails_validate_output_state_with_wrong_output_index() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {x:x+1,y:byte[_](0x3412)});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let expected_output_state =
        compile_contract(source, &[6.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let sigscript = encode_single_entry_sig_script(&input_compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let matching_spk = pay_to_script_hash_script(&bytecode(&expected_output_state));
    let wrong_spk = pay_to_script_hash_script(&bytecode(&input_compiled));

    let output0 = TransactionOutput { value: 1000, script_public_key: wrong_spk, covenant: None };
    let output1 = TransactionOutput { value: 1000, script_public_key: matching_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output0, output1], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(1000, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_err());
}

#[test]
fn fails_validate_output_state_with_mismatched_next_state_fields() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {x:x+1,y:byte[_](0x3412)});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let wrong_output_state =
        compile_contract(source, &[7.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let sigscript = encode_single_entry_sig_script(&input_compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let wrong_output_spk = pay_to_script_hash_script(&bytecode(&wrong_output_state));
    let output = TransactionOutput { value: 1000, script_public_key: wrong_output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(1000, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_err());
}

#[test]
fn rejects_validate_output_state_with_malformed_state_object() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {x:x+1});
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("state object missing fields should fail");
    assert!(err.to_string().contains("struct field 'y' must be initialized"), "unexpected error: {err}");
}

#[test]
fn rejects_validate_output_state_with_duplicate_state_field() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {x:x+1,y:byte[_](0x3412),x:x+2});
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("state object duplicate fields should fail");
    assert!(err.to_string().contains("duplicate struct field 'x'"), "unexpected error: {err}");
}

#[test]
fn rejects_validate_output_state_with_unknown_state_field() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entry main() {
                validateOutputState(0, State {x:x+1,y:byte[_](0x3412),z:1});
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("state object with unknown field should fail");
    assert!(err.to_string().contains("unknown struct field 'z'"), "unexpected error: {err}");
}

fn assert_compiled_body(source: &str, body: Vec<u8>) {
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected = wrap_with_single_dispatch(&compiled, body);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn checksig_result_can_be_used_in_bool_comparisons() {
    let source = r#"
        contract P2PK(sig signature, pubkey publicKey) {
            entry main() {
                require(checkSig(signature, publicKey) == true);
            }
        }
    "#;
    compile_contract(source, &[vec![0x11u8; 65].into(), vec![0x22u8; 32].into()], CompileOptions::default())
        .expect("checkSig bool comparison should compile");
}

#[test]
fn check_sig_ecdsa_lowers_to_matching_opcode() {
    let source = r#"
        contract ECDSA(sig signature, byte[33] publicKey) {
            entry main() {
                require(checkSigEcdsa(signature, publicKey));
            }
        }
    "#;
    let signature = vec![0x11; 65];
    let public_key = vec![0x22; 33];
    let compiled = compile_contract(source, &[signature.clone().into(), public_key.clone().into()], CompileOptions::default())
        .expect("compile succeeds");

    let expected = script_builder()
        .add_data_with_push_opcode(&signature)
        .unwrap()
        .add_data_with_push_opcode(&public_key)
        .unwrap()
        .add_op(OpCheckSigECDSA)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn check_sig_ecdsa_executes_ecdsa_signature_verification() {
    let source = r#"
        contract ECDSA() {
            entry main(sig signature, byte[33] publicKey) {
                require(checkSigEcdsa(signature, publicKey));
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[9u8; 32]).unwrap();
    let public_key = keypair.public_key().serialize().to_vec();

    let input =
        TransactionInput::new(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 }, vec![], 0, 1);
    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, bytecode(&compiled).clone().into()),
        covenant: None,
    };
    let mut tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key, 0, tx.is_coinbase(), None);
    let reused_values = SigHashReusedValuesUnsync::new();
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
    let signature_hash = calc_ecdsa_signature_hash(&populated_tx, 0, SIG_HASH_ALL, &reused_values);
    let message = secp256k1::Message::from_digest(signature_hash.into());
    let mut valid_signature = keypair.secret_key().sign_ecdsa(message).serialize_compact().to_vec();
    valid_signature.push(SIG_HASH_ALL.to_u8());
    assert_eq!(valid_signature.len(), SIG_BYTE_LEN);

    let mut run = |signature: Vec<u8>| {
        tx.inputs[0].signature_script =
            encode_entry_sig_script(&compiled, "main", &[signature.into(), public_key.clone().into()]).expect("sigscript builds");
        execute_input(tx.clone(), vec![utxo_entry.clone()], 0)
    };

    assert!(run(valid_signature.clone()).is_ok(), "valid ECDSA transaction signature should pass");
    valid_signature[0] ^= 0x01;
    assert!(run(valid_signature).is_err(), "forged ECDSA transaction signature should fail");
}

#[test]
fn checksigfromstack_lowers_to_matching_opcode() {
    let source = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            entry main() {
                require(checkMsgSig(signature, digest, publicKey));
            }
        }
    "#;
    let signature = vec![0x11; 64];
    let digest = vec![0x33; 32];
    let public_key = vec![0x22; 32];
    let compiled = compile_contract(
        source,
        &[signature.clone().into(), digest.clone().into(), public_key.clone().into()],
        CompileOptions::default(),
    )
    .expect("compile succeeds");

    let expected = script_builder()
        .add_data_with_push_opcode(&signature)
        .unwrap()
        .add_data_with_push_opcode(&digest)
        .unwrap()
        .add_data_with_push_opcode(&public_key)
        .unwrap()
        .add_op(OpCheckSigFromStack)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn check_msg_sig_ecdsa_lowers_to_matching_opcode() {
    let source = r#"
        contract DataSig(datasig signature, byte[32] digest, byte[33] publicKey) {
            entry main() {
                require(checkMsgSigEcdsa(signature, digest, publicKey));
            }
        }
    "#;
    let signature = vec![0x11; 64];
    let digest = vec![0x33; 32];
    let public_key = vec![0x22; 33];
    let compiled = compile_contract(
        source,
        &[signature.clone().into(), digest.clone().into(), public_key.clone().into()],
        CompileOptions::default(),
    )
    .expect("compile succeeds");

    let expected = script_builder()
        .add_data_with_push_opcode(&signature)
        .unwrap()
        .add_data_with_push_opcode(&digest)
        .unwrap()
        .add_data_with_push_opcode(&public_key)
        .unwrap()
        .add_op(OpCheckSigFromStackECDSA)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn checksigfromstack_requires_datasig_and_32_byte_digest_types() {
    let raw_message = r#"
        contract DataSig(datasig signature, byte[] message, pubkey publicKey) {
            entry main() {
                require(checkMsgSig(signature, message, publicKey));
            }
        }
    "#;
    let raw_message_err = compile_contract(
        raw_message,
        &[vec![0x11u8; 64].into(), b"authorize".to_vec().into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect_err("raw byte[] message should fail");
    assert!(raw_message_err.to_string().contains("argument 'digest' expects byte[32]"), "unexpected error: {raw_message_err}");

    let local_size_identifier = r#"
        contract DataSig(datasig signature, pubkey publicKey) {
            int constant N = 3;
            entry main() {
                byte[N] digest = byte[N](0x010203);
                require(checkMsgSig(signature, digest, publicKey));
            }
        }
    "#;
    let local_size_identifier_err =
        compile_contract(local_size_identifier, &[vec![0x11u8; 64].into(), vec![0x22u8; 32].into()], CompileOptions::default())
            .expect_err("local runtime size identifier should not satisfy byte[32]");
    assert!(
        local_size_identifier_err.to_string().contains("argument 'digest' expects byte[32]"),
        "unexpected error: {local_size_identifier_err}"
    );

    let contract_constant_size = r#"
        contract DataSig(datasig signature, pubkey publicKey) {
            int constant N = 32;

            entry main(byte[N] digest) {
                require(checkMsgSig(signature, digest, publicKey));
            }
        }
    "#;
    compile_contract(contract_constant_size, &[vec![0x11u8; 64].into(), vec![0x22u8; 32].into()], CompileOptions::default())
        .expect("contract constants should satisfy byte[32]");

    let signature_literal = format!("datasig(0x{})", "11".repeat(64));
    let digest_literal = format!("byte[32](0x{})", "33".repeat(32));
    let public_key_literal = format!("pubkey(0x{})", "22".repeat(32));
    let public_key_bytes_literal = format!("byte[32](0x{})", "22".repeat(32));
    let literal_args = format!(
        r#"
        contract DataSig() {{
            entry main() {{
                require(checkMsgSig({signature_literal}, {digest_literal}, {public_key_literal}));
            }}
        }}
    "#
    );
    compile_contract(&literal_args, &[], CompileOptions::default()).expect("literal datasig, digest, and pubkey args should compile");

    let byte_pubkey_variable = format!(
        r#"
        contract DataSig(datasig signature) {{
            entry main() {{
                byte[32] digest = {digest_literal};
                byte[32] publicKey = {public_key_bytes_literal};
                require(checkMsgSig(signature, digest, publicKey));
            }}
        }}
    "#
    );
    let byte_pubkey_variable_err = compile_contract(&byte_pubkey_variable, &[vec![0x11u8; 64].into()], CompileOptions::default())
        .expect_err("byte[32] variable should not be promoted to pubkey");
    assert!(
        byte_pubkey_variable_err.to_string().contains("argument 'publicKey' expects pubkey"),
        "unexpected error: {byte_pubkey_variable_err}"
    );

    let tx_signature = r#"
        contract DataSig(sig signature, byte[32] digest, pubkey publicKey) {
            entry main() {
                require(checkMsgSig(signature, digest, publicKey));
            }
        }
    "#;
    let tx_signature_err = compile_contract(
        tx_signature,
        &[vec![0x11u8; 65].into(), vec![0x33u8; 32].into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect_err("65-byte sig should fail");
    assert!(tx_signature_err.to_string().contains("argument 'signature' expects datasig"), "unexpected error: {tx_signature_err}");

    let schnorr_pubkey_for_ecdsa = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            entry main() {
                require(checkMsgSigEcdsa(signature, digest, publicKey));
            }
        }
    "#;
    let schnorr_pubkey_err = compile_contract(
        schnorr_pubkey_for_ecdsa,
        &[vec![0x11u8; 64].into(), vec![0x33u8; 32].into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect_err("32-byte Schnorr pubkey should fail for ECDSA");
    assert!(
        schnorr_pubkey_err.to_string().contains("argument 'publicKey' expects byte[33]"),
        "unexpected error: {schnorr_pubkey_err}"
    );
}

#[test]
fn g16_verify_lowers_to_groth16_precompile() {
    let source = r#"
        contract Groth16(byte[] verifying_key, byte[] proof, byte[32] public_input0, byte[32] public_input1) {
            entry verify() {
                g16.verify(verifying_key, proof, public_input0, public_input1);
            }
        }
    "#;
    let (verifying_key, proof, public_inputs) = kaspa_txscript::zk_precompiles::tests::helpers::load_groth_fields();
    let compiled = compile_contract(
        source,
        &[
            ArtifactValue::Bytes(verifying_key.clone()),
            ArtifactValue::Bytes(proof.clone()),
            public_inputs[0].clone().into(),
            public_inputs[1].clone().into(),
        ],
        CompileOptions::default(),
    )
    .expect("compile succeeds");

    let body = script_builder()
        .add_data_with_push_opcode(&public_inputs[1])
        .unwrap()
        .add_data_with_push_opcode(&public_inputs[0])
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_data_with_push_opcode(&proof)
        .unwrap()
        .add_data_with_push_opcode(&verifying_key)
        .unwrap()
        .add_data_with_push_opcode(&[kaspa_txscript::zk_precompiles::tags::ZkTag::Groth16 as u8])
        .unwrap()
        .add_op(OpZkPrecompile)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    assert_eq!(bytecode(&compiled), wrap_with_single_dispatch(&compiled, body));
}

#[test]
fn g16_verify_validates_arity_and_argument_types() {
    let missing_proof = r#"
        contract Groth16() {
            entry verify(byte[] verifying_key) {
                g16.verify(verifying_key);
            }
        }
    "#;
    let err = compile_contract(missing_proof, &[], CompileOptions::default()).expect_err("proof is required");
    assert!(err.to_string().contains("expects at least 2 arguments"), "unexpected error: {err}");

    let cases = [
        ("1, bytes_arg, public_input", "argument 'verifyingKey' expects byte[], got int"),
        ("bytes_arg, 1, public_input", "argument 'proof' expects byte[], got int"),
        ("bytes_arg, bytes_arg, bytes_arg", "argument 'publicInput0' expects byte[32], got byte[]"),
    ];
    for (args, expected) in cases {
        let source = format!(
            r#"
                contract Groth16() {{
                    entry verify(byte[] bytes_arg, byte[32] public_input) {{
                        g16.verify({args});
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("invalid argument should fail");
        assert!(err.to_string().contains(expected), "unexpected error for {args}: {err}");
    }

    let constant_sized_public_input = r#"
        contract Groth16() {
            int constant INPUT_SIZE = 32;

            entry verify(byte[] verifying_key, byte[] proof, byte[INPUT_SIZE] public_input) {
                g16.verify(verifying_key, proof, public_input);
            }
        }
    "#;
    compile_contract(constant_sized_public_input, &[], CompileOptions::default()).expect("contract constants should satisfy byte[32]");
}

#[test]
fn g16_verify_is_void_and_accepts_zero_public_inputs() {
    let direct_call = r#"
        contract Groth16() {
            entry verify(byte[] verifying_key, byte[] proof) {
                g16.verify(verifying_key, proof);
            }
        }
    "#;
    compile_contract(direct_call, &[], CompileOptions::default()).expect("zero-public-input call should compile");

    let expression_use = r#"
        contract Groth16() {
            entry verify(byte[] verifying_key, byte[] proof) {
                require(g16.verify(verifying_key, proof));
            }
        }
    "#;
    let err = compile_contract(expression_use, &[], CompileOptions::default()).expect_err("g16.verify should not return a value");
    assert!(err.to_string().contains("does not return a value"), "unexpected error: {err}");
}

#[test]
fn g16_verify_executes_with_fixture_and_rejects_tampered_input() {
    let source = r#"
        contract Groth16() {
            entry verify(
                byte[] verifying_key,
                byte[] proof,
                byte[32] public_input0,
                byte[32] public_input1,
                byte[32] public_input2,
                byte[32] public_input3,
                byte[32] public_input4,
            ) {
                g16.verify(
                    verifying_key,
                    proof,
                    public_input0,
                    public_input1,
                    public_input2,
                    public_input3,
                    public_input4,
                );
            }
        }
    "#;
    let (verifying_key, proof, public_inputs) = kaspa_txscript::zk_precompiles::tests::helpers::load_groth_fields();
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let build_args = |inputs: &[Vec<u8>]| -> Vec<ArtifactValue> {
        let mut args = vec![verifying_key.clone().into(), proof.clone().into()];
        args.extend(inputs.iter().cloned().map(Into::into));
        args
    };

    let sigscript = encode_entry_sig_script(&compiled, "verify", &build_args(&public_inputs)).expect("sigscript builds");
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript).is_ok(), "valid Groth16 proof should pass");

    let mut tampered_inputs = public_inputs;
    tampered_inputs[0][0] ^= 0x01;
    let sigscript = encode_entry_sig_script(&compiled, "verify", &build_args(&tampered_inputs)).expect("sigscript builds");
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript).is_err(), "tampered public input should fail");
}

#[test]
fn r0_succinct_verify_lowers_hash_aliases_to_zk_precompile() {
    let cases = ["r0.succinct.poseidon2.verify", "r0.succinct.verify"];

    for call_name in cases {
        let source = format!(
            r#"
                contract R0(
                    byte[32] image_id,
                    byte[32] control_id,
                    byte[32] claim,
                    byte[4] control_index,
                    byte[] control_digests,
                    byte[] seal,
                    byte[32] journal
                ) {{
                    entry main() {{
                        {call_name}(claim, control_index, control_digests, seal, journal, image_id, control_id);
                    }}
                }}
            "#
        );
        let image_id = vec![0x11u8; 32];
        let control_id = vec![0x22u8; 32];
        let claim = vec![0x33u8; 32];
        let control_index = vec![0x44u8; 4];
        let control_digests = vec![0x55u8];
        let seal = vec![0x66u8];
        let journal = vec![0x77u8; 32];
        let compiled = compile_contract(
            &source,
            &[
                image_id.clone().into(),
                control_id.clone().into(),
                claim.clone().into(),
                control_index.clone().into(),
                ArtifactValue::Bytes(control_digests.clone()),
                ArtifactValue::Bytes(seal.clone()),
                journal.clone().into(),
            ],
            CompileOptions::default(),
        )
        .expect("compile succeeds");

        let expected = ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
            .add_data_with_push_opcode(&claim)
            .unwrap()
            .add_data_with_push_opcode(&control_index)
            .unwrap()
            .add_data_with_push_opcode(&control_digests)
            .unwrap()
            .add_data_with_push_opcode(&seal)
            .unwrap()
            .add_data_with_push_opcode(&journal)
            .unwrap()
            .add_data_with_push_opcode(&image_id)
            .unwrap()
            .add_data_with_push_opcode(&control_id)
            .unwrap()
            .add_data_with_push_opcode(&[1u8])
            .unwrap()
            .add_data_with_push_opcode(&[kaspa_txscript::zk_precompiles::tags::ZkTag::R0Succinct as u8])
            .unwrap()
            .add_op(OpZkPrecompile)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap()
            .drain();
        let expected = wrap_with_single_dispatch(&compiled, expected);
        let asm = script_to_str(&bytecode(&compiled)).expect("R0 succinct script should stringify");
        assert!(asm.contains("OpZkPrecompile OpDrop"), "void verifier result should be dropped: {asm}");
        assert_eq!(bytecode(&compiled), expected, "{call_name} lowered unexpectedly");
    }
}

#[test]
fn r0_succinct_verify_rejects_reserved_non_poseidon_hashes() {
    let b32_a = format!("byte[32](0x{})", "11".repeat(32));
    let b32_b = format!("byte[32](0x{})", "22".repeat(32));

    for call_name in ["r0.succinct.blake2b.verify", "r0.succinct.sha256.verify"] {
        let source = format!(
            r#"
                contract R0() {{
                    entry main(byte[32] claim, byte[4] control_index, byte[] control_digests, byte[] seal, byte[32] journal) {{
                        {call_name}(claim, control_index, control_digests, seal, journal, {b32_a}, {b32_b});
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("reserved R0 hash should fail");
        assert!(
            err.to_string().contains("only Poseidon2 R0 Succinct verification is currently supported"),
            "unexpected error for {call_name}: {err}"
        );
    }
}

#[test]
fn r0_g16_verify_lowers_with_sdk_verifier_fragment() {
    let source = r#"
        contract R0(byte[32] journal_hash, byte[] proof, byte[32] image_id) {
            entry main() {
                r0.g16.verify(journal_hash, proof, image_id);
            }
        }
    "#;
    let journal_hash = vec![0x11u8; 32];
    let proof = vec![0x22u8; 128];
    let image_id = [0x33u8; 32];
    let compiled = compile_contract(
        source,
        &[journal_hash.clone().into(), ArtifactValue::Bytes(proof.clone()), image_id.to_vec().into()],
        CompileOptions::default(),
    )
    .expect("compile succeeds");

    let mut expected_builder = ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() });
    expected_builder.add_data_with_push_opcode(&journal_hash).unwrap();
    expected_builder.add_data_with_push_opcode(&proof).unwrap();
    expected_builder.add_data_with_push_opcode(&image_id).unwrap();
    kaspa_txscript_zk_sdk::append_r0_groth16_verifier_dynamic_image_id(&mut expected_builder).unwrap();
    expected_builder.add_op(OpDrop).unwrap();
    expected_builder.add_op(OpTrue).unwrap();
    let expected = wrap_with_single_dispatch(&compiled, expected_builder.drain());

    let asm = script_to_str(&bytecode(&compiled)).expect("R0 Groth16 script should stringify");
    assert!(asm.contains("OpZkPrecompile OpDrop"), "void verifier result should be dropped: {asm}");
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn r0_verify_builtins_do_not_return_values() {
    let b32_a = format!("byte[32](0x{})", "11".repeat(32));
    let b32_b = format!("byte[32](0x{})", "22".repeat(32));
    let cases = [
        format!(
            r#"
                contract R0() {{
                    entry main(byte[] proof) {{
                        require(r0.g16.verify({b32_a}, proof, {b32_b}));
                    }}
                }}
            "#
        ),
        format!(
            r#"
                contract R0() {{
                    entry main(byte[32] claim, byte[4] control_index, byte[] control_digests, byte[] seal, byte[32] journal) {{
                        bool valid = r0.succinct.verify(claim, control_index, control_digests, seal, journal, {b32_a}, {b32_b});
                        require(valid);
                    }}
                }}
            "#
        ),
    ];

    for source in cases {
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("void verifier should not be an expression");
        assert!(err.to_string().contains("does not return a value"), "unexpected error: {err}");
    }
}

#[test]
fn value_returning_builtin_statement_discards_result() {
    let source = r#"
        contract Hash() {
            entry main() {
                sha256(byte[]("ignored"));
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("value-returning builtin statement should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("builtin statement script should stringify");
    assert!(
        asm.ends_with("OpSHA256 OpDrop OpTrue OpElse OpReturn OpEndIf"),
        "builtin statement result should be discarded before the dispatch epilogue: {asm}"
    );
}

#[test]
fn discarded_helper_return_expressions_are_evaluated_and_dropped() {
    let source = r#"
        contract DiscardedHelperReturn() {
            function hashes() : (byte[32], byte[32]) {
                return(sha256(byte[]("first")), sha256(byte[]("second")));
            }

            entry main() {
                hashes();
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("discarded helper returns should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("script should stringify");
    assert_eq!(asm.matches("OpSHA256").count(), 2, "both return expressions must be evaluated: {asm}");
    assert_eq!(asm.matches("OpDrop").count(), 3, "both discarded return values plus the dispatch tag must be dropped: {asm}");
}

#[test]
fn discarded_nested_helper_return_expression_is_evaluated() {
    let source = r#"
        contract NestedDiscardedHelperReturn() {
            function fail() : int {
                return(1 / 0);
            }

            function outer() : int {
                return(fail());
            }

            entry main() {
                outer();
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested discarded return should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_err(), "the nested discarded division by zero must execute");
}

fn assert_r0_type_error(source: &str, expected: &str) {
    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("incorrect R0 builtin argument type should fail");
    assert!(err.to_string().contains(expected), "expected error containing '{expected}', got: {err}");
}

#[test]
fn r0_verify_builtins_reject_incorrect_argument_types() {
    let b32_a = format!("byte[32](0x{})", "11".repeat(32));
    let b32_b = format!("byte[32](0x{})", "22".repeat(32));
    let b4 = format!("byte[4](0x{})", "33".repeat(4));

    let g16_cases = [
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] proof) {{
                            require(r0.g16.verify(1, proof, {b32_a}));
                        }}
                    }}
                "#
            ),
            "argument 'journal_hash' expects byte[32]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main() {{
                            require(r0.g16.verify({b32_a}, 1, {b32_b}));
                        }}
                    }}
                "#
            ),
            "argument 'proof' expects byte[]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] proof) {{
                            require(r0.g16.verify({b32_a}, proof, 0x11));
                        }}
                    }}
                "#
            ),
            "argument 'image_id' expects byte[32]",
        ),
    ];
    for (source, expected) in g16_cases {
        assert_r0_type_error(&source, expected);
    }

    let succinct_calls = ["r0.succinct.poseidon2.verify", "r0.succinct.verify"];
    for call_name in succinct_calls {
        let source = format!(
            r#"
                contract R0() {{
                    entry main(byte[] control_digests, byte[] seal) {{
                        require({call_name}(1, {b4}, control_digests, seal, {b32_a}, {b32_a}, {b32_b}));
                    }}
                }}
            "#
        );
        assert_r0_type_error(&source, "argument 'claim' expects byte[32]");
    }

    let succinct_arg_cases = [
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] control_digests, byte[] seal) {{
                            require(r0.succinct.verify({b32_a}, 1, control_digests, seal, {b32_a}, {b32_a}, {b32_b}));
                        }}
                    }}
                "#
            ),
            "argument 'control_index' expects byte[4]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] seal) {{
                            require(r0.succinct.verify({b32_a}, {b4}, 1, seal, {b32_a}, {b32_a}, {b32_b}));
                        }}
                    }}
                "#
            ),
            "argument 'control_digests' expects byte[]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] control_digests) {{
                            require(r0.succinct.verify({b32_a}, {b4}, control_digests, 1, {b32_a}, {b32_a}, {b32_b}));
                        }}
                    }}
                "#
            ),
            "argument 'seal' expects byte[]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] control_digests, byte[] seal) {{
                            require(r0.succinct.verify({b32_a}, {b4}, control_digests, seal, 1, {b32_a}, {b32_b}));
                        }}
                    }}
                "#
            ),
            "argument 'journal' expects byte[32]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] control_digests, byte[] seal) {{
                            require(r0.succinct.verify({b32_a}, {b4}, control_digests, seal, {b32_a}, 0x11, {b32_b}));
                        }}
                    }}
                "#
            ),
            "argument 'image_id' expects byte[32]",
        ),
        (
            format!(
                r#"
                    contract R0() {{
                        entry main(byte[] control_digests, byte[] seal) {{
                            require(r0.succinct.verify({b32_a}, {b4}, control_digests, seal, {b32_a}, {b32_a}, 0x22));
                        }}
                    }}
                "#
            ),
            "argument 'control_id' expects byte[32]",
        ),
    ];
    for (source, expected) in succinct_arg_cases {
        assert_r0_type_error(&source, expected);
    }
}

#[test]
fn r0_succinct_verify_runtime_checks_each_hash_with_fixture() {
    let (control_id, seal, claim, hashfn, control_index, control_digests, journal, image_id) =
        kaspa_txscript::zk_precompiles::tests::helpers::load_stark_fields();
    assert_eq!(hashfn, vec![1u8], "fixture should use Poseidon2 hash function id");

    let cases = ["r0.succinct.poseidon2.verify", "r0.succinct.verify"];
    for call_name in cases {
        let source = format!(
            r#"
                contract R0(byte[32] image_id, byte[32] control_id) {{
                    entry main(byte[32] claim, byte[4] control_index, byte[] control_digests, byte[] seal, byte[32] journal) {{
                        {call_name}(claim, control_index, control_digests, seal, journal, image_id, control_id);
                    }}
                }}
            "#
        );
        let compiled = compile_contract(&source, &[image_id.clone().into(), control_id.clone().into()], CompileOptions::default())
            .expect("compile succeeds");

        let sigscript = encode_entry_sig_script(
            &compiled,
            "main",
            &[
                claim.clone().into(),
                control_index.clone().into(),
                ArtifactValue::Bytes(control_digests.clone()),
                ArtifactValue::Bytes(seal.clone()),
                journal.clone().into(),
            ],
        )
        .expect("sigscript builds");
        let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
        assert!(result.is_ok(), "{call_name} should execute successfully: {result:?}");
    }
}

#[test]
fn r0_g16_verify_executes_with_fixture() {
    // Fixture values are copied from rusty-kaspa's
    // crypto/txscript/zk-sdk/tests/r0_script_builder.rs::load_groth_fixture.
    // The receipt hex is vendored from
    // crypto/txscript/zk-sdk/tests/data/zk_builder_tests/groth.rcpt.hex.
    let journal_hash = kaspa_txscript::hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456").unwrap();
    let image_id = kaspa_txscript::hex::decode("75641a540ee2ad9ee5902bcdcdb8b55c0bef4a28287309b858f97b1356c6c2e0").unwrap();
    let receipt_bytes = kaspa_txscript::hex::decode(include_str!("fixtures/r0_groth16.rcpt.hex").trim()).unwrap();
    let receipt: risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> = borsh::from_slice(&receipt_bytes).unwrap();
    let proof = kaspa_txscript_zk_sdk::prepare_r0_groth16_proof(&receipt).unwrap();

    let source = r#"
        contract R0() {
            entry main(byte[32] journal_hash, byte[] proof, byte[32] image_id) {
                r0.g16.verify(journal_hash, proof, image_id);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[journal_hash.into(), ArtifactValue::Bytes(proof), image_id.into()])
        .expect("sigscript builds");

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "R0 Groth16 verifier should execute successfully: {result:?}");
}

#[test]
fn checksigfromstack_result_is_checked_as_bool() {
    let bool_assignment = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            entry main() {
                bool ok = checkMsgSig(signature, digest, publicKey);
                require(ok);
            }
        }
    "#;
    compile_contract(
        bool_assignment,
        &[vec![0x11u8; 64].into(), vec![0x33u8; 32].into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect("bool assignment should compile");

    let byte_assignment = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            entry main() {
                byte[32] ok = checkMsgSig(signature, digest, publicKey);
                require(true);
            }
        }
    "#;
    let byte_assignment_err = compile_contract(
        byte_assignment,
        &[vec![0x11u8; 64].into(), vec![0x33u8; 32].into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect_err("builtin bool result should not assign to byte[32]");
    assert!(byte_assignment_err.to_string().contains("variable 'ok' expects byte[32]"), "unexpected error: {byte_assignment_err}");

    let bool_return = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            function ok() : bool {
                return checkMsgSig(signature, digest, publicKey);
            }

            entry main() {
                require(ok());
            }
        }
    "#;
    compile_contract(
        bool_return,
        &[vec![0x11u8; 64].into(), vec![0x33u8; 32].into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect("bool return should compile");

    let byte_return = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            function bad() : byte[32] {
                return checkMsgSig(signature, digest, publicKey);
            }

            entry main() {
                require(true);
            }
        }
    "#;
    let byte_return_err = compile_contract(
        byte_return,
        &[vec![0x11u8; 64].into(), vec![0x33u8; 32].into(), vec![0x22u8; 32].into()],
        CompileOptions::default(),
    )
    .expect_err("builtin bool result should not return byte[32]");
    assert!(byte_return_err.to_string().contains("return value expects byte[32]"), "unexpected error: {byte_return_err}");
}

#[test]
fn checksigfromstack_executes_schnorr_signature_verification() {
    let source = r#"
        contract DataSig(datasig signature, byte[32] digest, pubkey publicKey) {
            entry main() {
                require(checkMsgSig(signature, digest, publicKey));
            }
        }
    "#;
    let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[7u8; 32]).unwrap();
    let public_key = keypair.x_only_public_key().0.serialize().to_vec();
    let digest = Hash::from_bytes([3u8; 32]);
    let message = secp256k1::Message::from_digest(digest.into());
    let valid_signature = keypair.sign_schnorr(message).as_ref().to_vec();

    let run = |signature: Vec<u8>| {
        let compiled = compile_contract(
            source,
            &[signature.into(), digest.as_bytes().to_vec().into(), public_key.clone().into()],
            CompileOptions::default(),
        )
        .expect("compile succeeds");
        let dispatch_tag = dispatch_tag_for(&compiled, "main");
        run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag)
    };

    assert!(run(valid_signature.clone()).is_ok(), "valid Schnorr data signature should pass");
    let mut forged_signature = valid_signature;
    forged_signature[0] ^= 0x01;
    assert!(run(forged_signature).is_err(), "forged Schnorr data signature should fail");
}

#[test]
fn checksigfromstack_false_result_can_be_asserted() {
    let source = r#"
        contract DataSig() {
            entry main(datasig signature, byte[32] digest, pubkey publicKey) {
                require(!checkMsgSig(signature, digest, publicKey));
            }
        }
    "#;
    let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[7u8; 32]).unwrap();
    let public_key = keypair.x_only_public_key().0.serialize().to_vec();
    let digest = Hash::from_bytes([3u8; 32]);
    let message = secp256k1::Message::from_digest(digest.into());
    let valid_signature = keypair.sign_schnorr(message).as_ref().to_vec();
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let run = |signature: Vec<u8>| {
        let sigscript = encode_entry_sig_script(
            &compiled,
            "main",
            &[signature.into(), digest.as_bytes().to_vec().into(), public_key.clone().into()],
        )
        .expect("sigscript builds");
        run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript)
    };

    let valid_result = run(valid_signature);
    assert!(valid_result.is_err(), "valid Schnorr data signature should fail the negated assertion");
    let zero_sig_result = run(vec![0u8; 64]);
    assert!(zero_sig_result.is_ok(), "zero Schnorr data signature should pass the negated assertion: {zero_sig_result:?}");
}

#[test]
fn check_msg_sig_ecdsa_executes_ecdsa_signature_verification() {
    let source = r#"
        contract DataSig(datasig signature, byte[32] digest, byte[33] publicKey) {
            entry main() {
                require(checkMsgSigEcdsa(signature, digest, publicKey));
            }
        }
    "#;
    let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[9u8; 32]).unwrap();
    let public_key = keypair.public_key().serialize().to_vec();
    let digest = Hash::from_bytes([5u8; 32]);
    let message = secp256k1::Message::from_digest(digest.into());
    let valid_signature = keypair.secret_key().sign_ecdsa(message).serialize_compact().to_vec();
    assert_eq!(valid_signature.len(), DATASIG_BYTE_LEN);

    let run = |signature: Vec<u8>| {
        let compiled = compile_contract(
            source,
            &[signature.into(), digest.as_bytes().to_vec().into(), public_key.clone().into()],
            CompileOptions::default(),
        )
        .expect("compile succeeds");
        let dispatch_tag = dispatch_tag_for(&compiled, "main");
        run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag)
    };

    assert!(run(valid_signature.clone()).is_ok(), "valid ECDSA data signature should pass");
    let mut forged_signature = valid_signature;
    forged_signature[0] ^= 0x01;
    assert!(run(forged_signature).is_err(), "forged ECDSA data signature should fail");
}

#[test]
fn canonicalizes_bool_comparison_operands_for_equality_and_inequality() {
    let cases = [(("=="), OpNumEqual), (("!="), OpNumNotEqual)];

    for (operator, compare_op) in cases {
        let source = format!(
            r#"
                contract BoolCompare() {{
                    entry main(bool x, bool y) {{
                        require(x {operator} y);
                    }}
                }}
            "#
        );
        let body = script_builder()
            .add_op(OpOver)
            .unwrap()
            .add_op(OpSize)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_op(OpLessThan)
            .unwrap()
            .add_op(OpVerify)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpSize)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_op(OpLessThan)
            .unwrap()
            .add_op(OpVerify)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpOver)
            .unwrap()
            .add_op(OpOver)
            .unwrap()
            .add_op(Op0NotEqual)
            .unwrap()
            .add_op(OpSwap)
            .unwrap()
            .add_op(Op0NotEqual)
            .unwrap()
            .add_op(compare_op)
            .unwrap()
            .add_op(OpVerify)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap()
            .drain();

        assert_compiled_body(&source, body);
    }
}

#[test]
fn compiles_opcode_builtins() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            r#"
                contract Test() {
                    entry main() {
                        require(byte[](OpTxSubnetId()) == byte[]("subnet"));
                    }
                }
            "#,
            script_builder()
                .add_op(OpTxSubnetId)
                .unwrap()
                .add_data_with_push_opcode(b"subnet")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxGas() == 0);
                    }
                }
            "#,
            script_builder()
                .add_op(OpTxGas)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxPayloadLen() >= 0);
                    }
                }
            "#,
            script_builder()
                .add_op(OpTxPayloadLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxPayloadSubstr(1, 3) == byte[]("ok"));
                    }
                }
            "#,
            script_builder()
                .add_i64(1)
                .unwrap()
                .add_i64(3)
                .unwrap()
                .add_op(OpTxPayloadSubstr)
                .unwrap()
                .add_data_with_push_opcode(b"ok")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(byte[](OpOutpointTxId(0)) == byte[]("txid"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpOutpointTxId)
                .unwrap()
                .add_data_with_push_opcode(b"txid")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpOutpointIndex(0) == 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpOutpointIndex)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputScriptSigLen(0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputScriptSigLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputScriptSigSubstr(0, 0, 1) == byte[]("sig"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxInputScriptSigSubstr)
                .unwrap()
                .add_data_with_push_opcode(b"sig")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(byte[](OpTxInputSeq(0)) == byte[]("seq"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputSeq)
                .unwrap()
                .add_data_with_push_opcode(b"seq")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputDaaScore(0) == 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputDaaScore)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputDaaScore(0) == 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputDaaScore)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputIsCoinbase(0) == false);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputIsCoinbase)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(Op0NotEqual)
                .unwrap()
                .add_op(OpSwap)
                .unwrap()
                .add_op(Op0NotEqual)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputSpkLen(0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputSpkLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputSpkSubstr(0, 0, 1) == byte[]("spk"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxInputSpkSubstr)
                .unwrap()
                .add_data_with_push_opcode(b"spk")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxOutputSpkLen(0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxOutputSpkLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxOutputSpkSubstr(0, 0, 1) == byte[]("out"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxOutputSpkSubstr)
                .unwrap()
                .add_data_with_push_opcode(b"out")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpAuthOutputCount(0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpAuthOutputCount)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpAuthOutputIdx(0, 0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpAuthOutputIdx)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(byte[](OpInputCovenantId(0)) == byte[]("cov"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpInputCovenantId)
                .unwrap()
                .add_data_with_push_opcode(b"cov")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(byte[](OpOutputCovenantId(0)) == byte[]("cov"));
                    }
                }
            "#,
            script_builder()
                .add_i64(0)
                .unwrap()
                .add_op(OpOutputCovenantId)
                .unwrap()
                .add_data_with_push_opcode(b"cov")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpCovInputCount(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_data_with_push_opcode(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap()
                .add_op(OpCovInputCount)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpCovInputIdx(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_data_with_push_opcode(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpCovInputIdx)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpCovOutputCount(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_data_with_push_opcode(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap()
                .add_op(OpCovOutputCount)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpCovOutputIdx(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0) >= 0);
                    }
                }
            "#,
            script_builder()
                .add_data_with_push_opcode(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpCovOutputIdx)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpNum2Bin(5, 2) == byte[]("bin"));
                    }
                }
            "#,
            script_builder()
                .add_i64(5)
                .unwrap()
                .add_i64(2)
                .unwrap()
                .add_op(OpNum2Bin)
                .unwrap()
                .add_data_with_push_opcode(b"bin")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(OpBin2Num(byte[]("a")) == 5);
                    }
                }
            "#,
            script_builder()
                .add_data_with_push_opcode(b"a")
                .unwrap()
                .add_op(OpBin2Num)
                .unwrap()
                .add_i64(5)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    entry main() {
                        require(byte[](OpChainblockSeqCommit(byte[32]("0123456789abcdef0123456789abcdef"))) == byte[]("commit"));
                    }
                }
            "#,
            script_builder()
                .add_data_with_push_opcode(b"0123456789abcdef0123456789abcdef")
                .unwrap()
                .add_op(OpChainblockSeqCommit)
                .unwrap()
                .add_data_with_push_opcode(b"commit")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
    ];

    for (source, body) in cases {
        assert_compiled_body(source, body);
    }
}

#[test]
fn executes_opcode_builtins_basic() {
    let cases = vec![
        (
            "sha256",
            r#"
                contract Test() {
                    entry main() {
                        require(sha256(byte[]("msg")) == sha256(byte[]("msg")));
                    }
                }
            "#,
        ),
        (
            "subnet_id",
            r#"
                contract Test() {
                    entry main() {
                        byte[20] subnet_id = OpTxSubnetId();
                        require(byte[](subnet_id).length == 20);
                        require(byte[](subnet_id) == byte[]("abcdefghijklmnopqrst"));
                    }
                }
            "#,
        ),
        (
            "gas",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxGas() == 123);
                    }
                }
            "#,
        ),
        (
            "payload_len",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxPayloadLen() == 12);
                    }
                }
            "#,
        ),
        (
            "payload_substr",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxPayloadSubstr(1, 4) == byte[]("ayl"));
                    }
                }
            "#,
        ),
        (
            "outpoint_txid",
            r#"
                contract Test() {
                    entry main() {
                        byte[32] outpoint_tx_id = OpOutpointTxId(0);
                        require(byte[](outpoint_tx_id).length == 32);
                        require(byte[](outpoint_tx_id) == byte[]("0123456789abcdef0123456789abcdef"));
                    }
                }
            "#,
        ),
        (
            "outpoint_index",
            r#"
                contract Test() {
                    entry main() {
                        require(OpOutpointIndex(0) == 7);
                    }
                }
            "#,
        ),
        (
            "sigscript_len",
            r#"
                contract Test() {
                    entry dummy() { require(true); }
                    entry main() {
                        require(OpTxInputScriptSigLen(0) == 5);
                    }
                }
            "#,
        ),
        (
            "sigscript_substr",
            r#"
                contract Test() {
                    entry dummy() { require(true); }
                    entry main() {
                        require(OpTxInputScriptSigSubstr(0, 0, 1) == byte[](0x04));
                    }
                }
            "#,
        ),
        (
            "input_seq",
            r#"
                contract Test() {
                    entry main() {
                        byte[8] input_sequence = OpTxInputSeq(0);
                        require(byte[](input_sequence).length == 8);
                        require(byte[](input_sequence) == byte[]("sequence"));
                    }
                }
            "#,
        ),
        (
            "input_daa_score",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputDaaScore(0) == 0);
                    }
                }
            "#,
        ),
        (
            "is_coinbase",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputIsCoinbase(0) == false);
                    }
                }
            "#,
        ),
        (
            "input_spk_len",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputSpkLen(0) == OpTxInputSpkLen(0));
                    }
                }
            "#,
        ),
        (
            "input_spk_substr",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxInputSpkSubstr(0, 0, 1) == OpTxInputSpkSubstr(0, 0, 1));
                    }
                }
            "#,
        ),
        (
            "output_spk_len",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxOutputSpkLen(0) == 8);
                    }
                }
            "#,
        ),
        (
            "output_spk_substr",
            r#"
                contract Test() {
                    entry main() {
                        require(OpTxOutputSpkSubstr(0, 2, 8) == byte[]("outspk"));
                    }
                }
            "#,
        ),
        (
            "num2bin_bin2num",
            r#"
                contract Test() {
                    entry main() {
                        require(OpBin2Num(OpNum2Bin(5, 2)) == 5);
                    }
                }
            "#,
        ),
    ];

    for (name, source) in cases {
        let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
        let dispatch_tag = dispatch_tag_for(&compiled, "main");
        let sigscript = dispatch_tag_sigscript(dispatch_tag);
        let (tx, entries) = build_basic_opcode_tx(sigscript);
        let result = run_bytecode_with_tx_and_covenants(bytecode(&compiled), tx, entries, None);
        assert!(result.is_ok(), "opcode builtin {name} failed: {}", result.unwrap_err());
    }
}

#[test]
fn template_hash_matches_canonical_rust_and_sil_vectors() {
    let cases: &[(&[u8], &[u8], &str)] = &[
        (b"", b"", "e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e"),
        (b"a", b"bc", "405e183e2494cdbe2df89349cc0ffa5b77fb885ad97a1d5660ecd0692ef8142a"),
        (b"ab", b"c", "a0968c014f3fc7bd1a7d9a8d1ad1177eb379bd2f05e56309eb4e20347c5e7eba"),
        (&[0x00, 0xff], &[0x10, 0x00, 0x80], "6616a66757315de0221cb2acba729113cebde31f8d3ca7fa93878a0584b96905"),
    ];

    let sil_bytes = |bytes: &[u8]| {
        if bytes.is_empty() {
            "byte[](\"\")".to_string()
        } else {
            format!("byte[](0x{})", bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
        }
    };

    for (prefix, suffix, expected_hex) in cases {
        let mut expected = [0u8; 32];
        faster_hex::hex_decode(expected_hex.as_bytes(), &mut expected).unwrap();
        assert_eq!(template_hash(prefix, suffix), expected);

        let prefix = sil_bytes(prefix);
        let suffix = sil_bytes(suffix);
        let source = format!(
            r#"
            contract Test() {{
                entry main() {{
                    require(templateHash({prefix}, {suffix}) == byte[32](0x{expected_hex}));
                }}
            }}
        "#
        );

        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("templateHash should compile");
        let dispatch_tag = dispatch_tag_for(&compiled, "main");
        let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
        assert!(result.is_ok(), "templateHash should match canonical vector {expected_hex}: {result:?}");
    }
}

#[test]
fn template_hash_binds_prefix_suffix_boundary() {
    let source = r#"
        contract Test() {
            entry main() {
                require(templateHash(byte[]("a"), byte[]("bc")) != templateHash(byte[]("ab"), byte[]("c")));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("templateHash should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "templateHash should commit to the prefix/suffix boundary: {result:?}");
}

#[test]
fn executes_opcode_builtins_covenants() {
    let source = r#"
        contract Test() {
            entry main() {
                byte[32] input_covenant_id = OpInputCovenantId(0);
                byte[32] output_covenant_id_a = OpOutputCovenantId(0);
                byte[32] output_covenant_id_b = OpOutputCovenantId(1);

                require(byte[](input_covenant_id).length == 32);
                require(byte[](output_covenant_id_a).length == 32);
                require(byte[](output_covenant_id_b).length == 32);
                require(OpAuthOutputCount(0) == 2);
                require(OpAuthOutputIdx(0, 1) == 2);
                require(byte[](input_covenant_id) == byte[]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
                require(byte[](output_covenant_id_a) == byte[]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
                require(byte[](output_covenant_id_b) == byte[]("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
                require(OpCovInputCount(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) == 2);
                require(OpCovInputIdx(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1) == 2);
                require(OpCovOutputCount(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) == 2);
                require(OpCovOutputIdx(byte[32]("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1) == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let sigscript = dispatch_tag_sigscript(dispatch_tag);
    let covenant_id_a = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let covenant_id_b = Hash::from_bytes(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    let (tx, entries) = build_covenant_opcode_tx(sigscript, covenant_id_a, covenant_id_b);

    let result = run_bytecode_with_tx_and_covenants(bytecode(&compiled), tx, entries, None);
    assert!(result.is_ok(), "opcode builtins covenants failed: {}", result.unwrap_err());
}

#[test]
fn executes_opcode_chainblock_seq_commit() {
    struct MockSeqCommitAccessor {
        block: Hash,
        commitment: Hash,
    }

    impl SeqCommitAccessor for MockSeqCommitAccessor {
        fn is_chain_ancestor_from_pov(&self, block_hash: Hash) -> Option<bool> {
            Some(block_hash == self.block)
        }

        fn seq_commitment_within_depth(&self, block_hash: Hash) -> Option<Hash> {
            (block_hash == self.block).then_some(self.commitment)
        }
    }

    let source = r#"
        contract Test() {
            entry main() {
                byte[32] sequence_commitment =
                    OpChainblockSeqCommit(byte[32]("0123456789abcdef0123456789abcdef"));
                require(byte[](sequence_commitment).length == 32);
                require(byte[](sequence_commitment) == byte[]("fedcba9876543210fedcba9876543210"));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let sigscript = dispatch_tag_sigscript(dispatch_tag);
    let (tx, entries) = build_basic_opcode_tx(sigscript);

    let block = Hash::from_bytes(*b"0123456789abcdef0123456789abcdef");
    let commitment = Hash::from_bytes(*b"fedcba9876543210fedcba9876543210");
    let accessor = MockSeqCommitAccessor { block, commitment };
    let result = run_bytecode_with_tx_and_covenants(bytecode(&compiled), tx, entries, Some(&accessor));
    assert!(result.is_ok(), "chainblock seq commit failed: {}", result.unwrap_err());
}

#[test]
fn compiles_if_else_and_verifies() {
    let source = r#"
        contract Test() {
            entry main() {
                if (1 < 2) {
                    require(true);
                } else {
                    require(false);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");

    let body = script_builder()
        .add_i64(1)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_op(OpFalse)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn compiles_require_age_daa_to_csv_and_verifies() {
    let source = r#"
        contract Test() {
            entry main() {
                require(this.ageDaa >= 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");

    let body = script_builder()
        .add_i64(10)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_i64(1_i64 << 32)
        .unwrap()
        .add_op(OpWithin)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpCheckSequenceVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_tx(bytecode(&compiled), dispatch_tag, 0, 20).is_ok());
}

#[test]
fn compiles_require_tx_daa_to_bounded_cltv_and_verifies() {
    let source = r#"
        contract Test() {
            entry main() {
                require(tx.daa >= 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let body = script_builder()
        .add_i64(10)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(0)
        .unwrap()
        .add_i64(kaspa_txscript::LOCK_TIME_THRESHOLD as i64)
        .unwrap()
        .add_op(OpWithin)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpCheckLockTimeVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_tx(bytecode(&compiled), dispatch_tag, 10, 0).is_ok());
}

#[test]
fn compiles_require_tx_time_to_lower_bounded_cltv_and_verifies() {
    let threshold = kaspa_txscript::LOCK_TIME_THRESHOLD as i64;
    let source = format!(
        r#"
        contract Test() {{
            entry main() {{
                require(tx.time >= temporal({threshold}));
            }}
        }}
    "#
    );

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let body = script_builder()
        .add_i64(threshold)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(threshold)
        .unwrap()
        .add_op(OpGreaterThanOrEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpCheckLockTimeVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_tx(bytecode(&compiled), dispatch_tag, threshold as u64, 0).is_ok());
}

#[test]
fn signed_arithmetic_and_comparisons_match_rust_for_small_values() {
    type SignedArithmeticCase = (&'static str, fn(i64, i64) -> i64);
    type SignedComparisonCase = (&'static str, fn(i64, i64) -> bool);

    let operators: [SignedArithmeticCase; 5] =
        [("+", |a, b| a + b), ("-", |a, b| a - b), ("*", |a, b| a * b), ("/", |a, b| a / b), ("%", |a, b| a % b)];
    for (operator, oracle) in operators {
        let source = format!("contract C() {{ entry main(int a, int b, int expected) {{ require(a {operator} b == expected); }} }}");
        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("arithmetic contract compiles");
        for a in -20..=20 {
            for b in -20..=20 {
                if matches!(operator, "/" | "%") && b == 0 {
                    continue;
                }
                let sigscript = encode_entry_sig_script(
                    &compiled,
                    "main",
                    &[ArtifactValue::Int(a), ArtifactValue::Int(b), ArtifactValue::Int(oracle(a, b))],
                )
                .expect("arithmetic signature script builds");
                run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript)
                    .unwrap_or_else(|error| panic!("operator={operator} a={a} b={b}: {error:?}"));
            }
        }
    }

    let comparisons: [SignedComparisonCase; 6] = [
        ("==", |a, b| a == b),
        ("!=", |a, b| a != b),
        ("<", |a, b| a < b),
        ("<=", |a, b| a <= b),
        (">", |a, b| a > b),
        (">=", |a, b| a >= b),
    ];
    for (operator, oracle) in comparisons {
        let expected = oracle(-7, 3);
        let source = format!("contract C() {{ entry main(int a, int b) {{ require((a {operator} b) == {expected}); }} }}");
        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("comparison contract compiles");
        let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(-7), ArtifactValue::Int(3)])
            .expect("comparison signature script builds");
        run_bytecode_with_sigscript(bytecode(&compiled), sigscript).expect("comparison agrees with Rust");
    }
}

#[test]
fn boolean_operators_use_vm_truthiness_for_noncanonical_values() {
    let witnesses: &[&[u8]] = &[&[], &[0], &[0x80], &[1], &[2], &[0xff]];
    for operator in ["&&", "||", "==", "!="] {
        for &left in witnesses {
            for &right in witnesses {
                let left_truthy = !left.is_empty() && left != [0] && left != [0x80];
                let right_truthy = !right.is_empty() && right != [0] && right != [0x80];
                let expected = match operator {
                    "&&" => left_truthy && right_truthy,
                    "||" => left_truthy || right_truthy,
                    "==" => left_truthy == right_truthy,
                    "!=" => left_truthy != right_truthy,
                    _ => unreachable!(),
                };
                let source = format!("contract C() {{ entry main(bool a, bool b) {{ require((a {operator} b) == {expected}); }} }}");
                let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("boolean contract compiles");
                let sigscript = script_builder()
                    .add_data_with_push_opcode(left)
                    .unwrap()
                    .add_data_with_push_opcode(right)
                    .unwrap()
                    .add_data(&dispatch_tag_for(&compiled, "main"))
                    .unwrap()
                    .drain();
                run_bytecode_with_sigscript(bytecode(&compiled), sigscript).unwrap_or_else(|error| {
                    panic!("operator={operator} left={left:?} right={right:?} expected={expected}: {error:?}")
                });
            }
        }
    }
}

#[test]
fn relative_age_rejects_out_of_range_static_and_dynamic_values() {
    for invalid in [-1_i64, 1_i64 << 32] {
        let source = format!("contract C() {{ entry main() {{ require(this.ageDaa >= {invalid}); }} }}");
        let error = compile_contract(&source, &[], CompileOptions::default()).expect_err("known out-of-range age must be rejected");
        assert!(error.to_string().contains("0 <= value < 2^32"), "unexpected error: {error}");
    }

    let largest_in_range = "contract C() { entry main() { require(this.ageDaa >= 4294967295); } }";
    let compiled = compile_contract(largest_in_range, &[], CompileOptions::default()).expect("2^32 - 1 remains valid");
    let sigscript = encode_single_entry_sig_script(&compiled, &[]).expect("signature script builds");
    run_bytecode_with_sigscript_and_time(bytecode(&compiled), sigscript, 0, 0)
        .expect_err("the largest 32-bit requirement must reject sequence zero");

    let dynamic_source = "contract C() { entry main(int age) { require(this.ageDaa >= age); } }";
    let compiled = compile_contract(dynamic_source, &[], CompileOptions::default()).expect("dynamic age contract compiles");
    for invalid in [-1, 1_i64 << 32] {
        let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(invalid)]).expect("signature script builds");
        run_bytecode_with_sigscript_and_time(bytecode(&compiled).clone(), sigscript, 0, 0)
            .expect_err("out-of-range runtime age must be rejected before CSV");
    }
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(0)]).expect("signature script builds");
    run_bytecode_with_sigscript_and_time(bytecode(&compiled), sigscript, 0, 0).expect("zero age must remain valid");
}

#[test]
fn absolute_daa_and_time_locks_enforce_consensus_domains() {
    let threshold = kaspa_txscript::LOCK_TIME_THRESHOLD as i64;

    for source in [
        "contract C() { entry main() { require(tx.daa >= -1); } }".to_string(),
        format!("contract C() {{ entry main() {{ require(tx.daa >= {threshold}); }} }}"),
    ] {
        let error = compile_contract(&source, &[], CompileOptions::default()).expect_err("known out-of-domain DAA value must fail");
        assert!(error.to_string().contains("0 <= value < LOCK_TIME_THRESHOLD"), "unexpected DAA error: {error}");
    }
    let largest_daa = format!("contract C() {{ entry main() {{ require(tx.daa >= {}); }} }}", threshold - 1);
    compile_contract(&largest_daa, &[], CompileOptions::default()).expect("largest DAA-domain value compiles");

    let early_time = format!("contract C() {{ entry main() {{ require(tx.time >= temporal({})); }} }}", threshold - 1);
    let error = compile_contract(&early_time, &[], CompileOptions::default()).expect_err("known DAA-domain timestamp must fail");
    assert!(error.to_string().contains("at least LOCK_TIME_THRESHOLD"), "unexpected time error: {error}");
    let first_time = format!("contract C() {{ entry main() {{ require(tx.time >= temporal({threshold})); }} }}");
    compile_contract(&first_time, &[], CompileOptions::default()).expect("first timestamp-domain value compiles");

    let dynamic_daa =
        compile_contract("contract C() { entry main(int value) { require(tx.daa >= value); } }", &[], CompileOptions::default())
            .expect("dynamic DAA contract compiles");
    for invalid in [-1, threshold] {
        let sigscript = encode_entry_sig_script(&dynamic_daa, "main", &[ArtifactValue::Int(invalid)]).expect("DAA sigscript builds");
        run_bytecode_with_sigscript_and_time(bytecode(&dynamic_daa).clone(), sigscript, threshold as u64 - 1, 0)
            .expect_err("runtime DAA domain guard must reject the value");
    }
    let sigscript = encode_entry_sig_script(&dynamic_daa, "main", &[ArtifactValue::Int(42)]).expect("DAA sigscript builds");
    run_bytecode_with_sigscript_and_time(bytecode(&dynamic_daa), sigscript, 42, 0).expect("valid DAA lock must satisfy CLTV");

    let dynamic_time =
        compile_contract("contract C() { entry main(temporal value) { require(tx.time >= value); } }", &[], CompileOptions::default())
            .expect("dynamic time contract compiles");
    let invalid_sigscript =
        encode_entry_sig_script(&dynamic_time, "main", &[ArtifactValue::Int(threshold - 1)]).expect("time sigscript builds");
    run_bytecode_with_sigscript_and_time(bytecode(&dynamic_time).clone(), invalid_sigscript, threshold as u64, 0)
        .expect_err("runtime timestamp domain guard must reject a DAA-domain value");
    let valid_sigscript =
        encode_entry_sig_script(&dynamic_time, "main", &[ArtifactValue::Int(threshold)]).expect("time sigscript builds");
    run_bytecode_with_sigscript_and_time(bytecode(&dynamic_time), valid_sigscript, threshold as u64, 0)
        .expect("valid timestamp lock must satisfy CLTV");
}

#[test]
fn lock_requirements_reject_invalid_constant_expressions() {
    let cases = [
        "contract C() { entry main() { require(this.ageDaa >= 9223372036854775807 + 1); } }",
        "contract C() { entry main() { require(tx.daa >= 9223372036854775807 + 1); } }",
        "contract C() { entry main() { require(tx.time >= temporal(9223372036854775807 / 0)); } }",
    ];

    for source in cases {
        let err = compile_contract(source, &[], CompileOptions::default())
            .expect_err("an invalid constant lock target must not be treated as a runtime expression");
        assert!(
            matches!(err.root(), CompilerError::ArithmeticOverflow(_) | CompilerError::InvalidLiteral(_)),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn temporal_literals_use_milliseconds_and_are_separate_from_daa_age() {
    let relative_source = "contract C() { entry main() { require(this.ageDaa >= 1 days); } }";
    compile_contract(relative_source, &[], CompileOptions::default()).expect_err("this.ageDaa must reject temporal expressions");

    let date_source = r#"contract C() { entry main() { require(tx.time >= date("2030-01-01T00:00:00")); } }"#;
    let unix_milliseconds = 1_893_456_000_000;
    assert!(unix_milliseconds >= 500_000_000_000, "the consensus threshold must classify this as a timestamp");
    let compiled = compile_contract(date_source, &[], CompileOptions::default()).expect("date contract compiles");
    let sigscript = encode_single_entry_sig_script(&compiled, &[]).expect("signature script builds");
    run_bytecode_with_sigscript_and_time(bytecode(&compiled), sigscript, unix_milliseconds, 0)
        .expect("the millisecond timestamp must satisfy CLTV");
}

#[test]
fn rejects_unsupported_lock_requirement_comparisons() {
    for condition in [
        "this.ageDaa > 10",
        "this.ageDaa < 10",
        "this.ageDaa <= 10",
        "tx.daa > 10",
        "tx.daa < 10",
        "tx.daa <= 10",
        "tx.time > temporal(10)",
        "tx.time < temporal(10)",
        "tx.time <= temporal(10)",
    ] {
        let source = format!(
            r#"
                contract Test() {{
                    entry main() {{
                        require({condition});
                    }}
                }}
            "#
        );

        assert!(
            compile_contract(&source, &[], CompileOptions::default()).is_err(),
            "unsupported time comparison should fail compilation: {condition}"
        );
    }
}

#[test]
fn rejects_lock_targets_outside_supported_requirements() {
    for statement in [
        "require(this.ageDaa == 10);",
        "require(tx.daa == 10);",
        "require(tx.time == temporal(10));",
        "require(10 <= this.ageDaa);",
        "require(10 <= tx.daa);",
        "require(temporal(10) <= tx.time);",
        "int value = this.ageDaa;",
        "int value = tx.daa;",
        "int value = tx.time;",
        "if (this.ageDaa >= 10) { require(true); }",
        "if (tx.daa >= 10) { require(true); }",
        "if (tx.time >= temporal(10)) { require(true); }",
        "require(this.age_daa >= 10);",
        "require(this.time >= 10);",
    ] {
        let source = format!(
            r#"
                contract Test() {{
                    entry main() {{
                        {statement}
                    }}
                }}
            "#
        );

        assert!(
            compile_contract(&source, &[], CompileOptions::default()).is_err(),
            "time variable outside require(time >= threshold) should fail compilation: {statement}"
        );
    }
}

#[test]
#[ignore = "TODO: Re-enable when fallible local-alias optimization is restored"]
fn compiles_reused_variables_and_verifies() {
    let source = r#"
        contract Test() {
            entry main() {
                int a = 2 + 3;
                int b = a * a + a;
                require(b == 30);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");

    let body = script_builder()
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(30)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn return_reused_local_is_stored_once_and_reused() {
    let source = r#"
        contract Test() {
            entry main() : (int) {
                int a = 2 + 3;
                return(a * a + a);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions { allow_entrypoint_return: true, ..CompileOptions::default() })
        .expect("compile succeeds");

    let expected = script_builder()
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpRoll)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, expected);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
fn compiles_sigscript_inputs_and_verifies() {
    let source = r#"
        contract Test() {
            entry main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let mut builder = script_builder();
    builder.add_i64(3).unwrap();
    builder.add_i64(4).unwrap();
    builder.add_data(&dispatch_tag).unwrap();
    let sigscript = builder.drain();

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "sigscript test failed: {}", result.unwrap_err());
}

#[test]
fn compiles_bytecode_size_and_runs_sum_array() {
    let source = r#"
        contract Sum() {
            int constant MAX_ARRAY_SIZE = 5;
            function sumArray(int[] arr) : (int) {
                require(arr.length <= MAX_ARRAY_SIZE);
                int sum = 0;
                for (i, 0, arr.length, MAX_ARRAY_SIZE) {
                    sum = sum + arr[i];
                }
                return(sum);
            }

            entry main(int expected_bytecode_size) {
                require(expected_bytecode_size == this.bytecodeSize);
                int[] x;
                x = x.append(1);
                x = x.append(2);
                x = x.append(3);
                (int total) = sumArray(x);
                require(total == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_size = bytecode(&compiled).len() as i64;
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(expected_size)]).expect("sigscript builds");

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "script size contract failed: {}", result.unwrap_err());
}

fn data_prefix_for_size(data_len: usize) -> Vec<u8> {
    let dummy_data = vec![0u8; data_len];
    let mut builder = script_builder();
    builder.add_data_with_push_opcode(&dummy_data).unwrap();
    let script = builder.drain();
    script[..script.len() - data_len].to_vec()
}

#[test]
fn compiles_bytecode_size_data_prefix_small_script() {
    let source = r#"
        contract PrefixSmall() {
            entry main(byte[] expected_data_prefix) {
                require(expected_data_prefix == this.bytecodeSizeDataPrefix);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(bytecode(&compiled).len());
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "bytecodeSizeDataPrefix small failed: {}", result.unwrap_err());
}

#[test]
fn compiles_bytecode_size_data_prefix_medium_script() {
    let source = r#"
        contract PrefixMedium() {
            entry main(byte[] expected_data_prefix) {
                require(expected_data_prefix == this.bytecodeSizeDataPrefix);
                for (i, 0, 100, 100) {
                    require(true);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(bytecode(&compiled).len());
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "bytecodeSizeDataPrefix medium failed: {}", result.unwrap_err());
}

#[test]
fn compiles_bytecode_size_data_prefix_large_script() {
    let source = r#"
        contract PrefixLarge() {
            entry main(byte[] expected_data_prefix) {
                require(expected_data_prefix == this.bytecodeSizeDataPrefix);
                for (i, 0, 300, 300) {
                    require(true);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(bytecode(&compiled).len());
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "bytecodeSizeDataPrefix large failed: {}", result.unwrap_err());
}

#[test]
fn compiles_sigscript_reused_inputs_and_verifies() {
    let source = r#"
        contract Test() {
            entry main(int a) {
                require(a * a + a == 12);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let mut builder = script_builder();
    builder.add_i64(3).unwrap();
    builder.add_data(&dispatch_tag).unwrap();
    let sigscript = builder.drain();

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "sigscript reuse test failed: {}", result.unwrap_err());
}

#[test]
fn compiles_sigscript_inputs_and_fails_on_wrong_sum() {
    let source = r#"
        contract Test() {
            entry main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let mut builder = script_builder();
    builder.add_i64(2).unwrap();
    builder.add_i64(4).unwrap();
    builder.add_data(&dispatch_tag).unwrap();
    let sigscript = builder.drain();

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err());
}

#[test]
fn compiles_sigscript_reused_inputs_and_fails_on_wrong_value() {
    let source = r#"
        contract Test() {
            entry main(int a) {
                require(a * a + a == 12);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let mut builder = script_builder();
    builder.add_i64(4).unwrap();
    builder.add_data(&dispatch_tag).unwrap();
    let sigscript = builder.drain();

    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err());
}

#[test]
fn entrypoints_validate_fixed_array_argument_sizes_at_runtime() {
    let source = r#"
        contract Test() {
            int constant COUNT = 2;
            bool enabled = true;

            entry bytes(byte[3] x) {
                require(enabled);
            }

            entry ints(int[COUNT] x) {
                require(enabled);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let sigscript = |entrypoint: &str, value: &[u8]| {
        let mut builder = script_builder();
        builder.add_data_with_push_opcode(value).unwrap();
        builder.add_data(&dispatch_tag_for(&compiled, entrypoint)).unwrap();
        builder.drain()
    };

    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript("bytes", &[1, 2, 3])).is_ok());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript("bytes", &[1, 2])).is_err());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript("bytes", &[1, 2, 3, 4])).is_err());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript("ints", &[0; 16])).is_ok());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript("ints", &[0; 8])).is_err());

    let asm = script_to_str(&bytecode(&compiled)).expect("stringifies");
    assert_eq!(asm.matches("OpSize").count(), 2, "each entrypoint should validate its fixed-array argument: {asm}");
}

#[test]
fn entrypoints_validate_fixed_width_scalar_argument_sizes_at_runtime() {
    let cases = [("byte", 1usize), ("pubkey", 32), ("sig", 65), ("datasig", 64)];

    for (type_name, expected_size) in cases {
        let source = format!(
            r#"
                contract ScalarSize() {{
                    entry main({type_name} value) {{
                        require(true);
                    }}
                }}
            "#
        );
        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("fixed-width scalar should compile");
        let body = script_builder()
            .add_op(OpDup)
            .unwrap()
            .add_op(OpSize)
            .unwrap()
            .add_i64(expected_size as i64)
            .unwrap()
            .add_op(OpNumEqualVerify)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap()
            .add_op(OpVerify)
            .unwrap()
            .add_op(OpDrop)
            .unwrap()
            .add_op(OpTrue)
            .unwrap()
            .drain();
        let dispatch_tag = dispatch_tag_for(&compiled, "main");
        let expected = wrap_with_single_dispatch(&compiled, body);
        assert_eq!(bytecode(&compiled), expected, "unexpected ABI validation bytecode for {type_name}");

        let sigscript =
            |size: usize| script_builder().add_data_with_push_opcode(&vec![1; size]).unwrap().add_data(&dispatch_tag).unwrap().drain();
        assert!(
            run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(expected_size)).is_ok(),
            "{type_name} should accept exactly {expected_size} bytes"
        );
        if type_name == "byte" {
            let zero_sigscript =
                encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Byte(0)]).expect("zero byte sigscript builds");
            assert!(
                run_bytecode_with_sigscript(bytecode(&compiled).clone(), zero_sigscript).is_ok(),
                "the typed builder must preserve byte(0) as a one-byte stack item"
            );
        }
        assert!(
            run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(expected_size - 1)).is_err(),
            "{type_name} should reject a short value"
        );
        assert!(
            run_bytecode_with_sigscript(bytecode(&compiled), sigscript(expected_size + 1)).is_err(),
            "{type_name} should reject a long value"
        );
    }
}

#[test]
fn entrypoint_int_argument_accepts_below_nine_bytes_and_rejects_nine() {
    let source = r#"
        contract IntSize() {
            entry main(int value) {
                require(true);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("int parameter should compile");
    let body = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpSize)
        .unwrap()
        .add_i64(9)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let expected = wrap_with_single_dispatch(&compiled, body);
    assert_eq!(bytecode(&compiled), expected);

    let sigscript =
        |size: usize| script_builder().add_data_with_push_opcode(&vec![1; size]).unwrap().add_data(&dispatch_tag).unwrap().drain();
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(0)).is_ok());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(8)).is_ok());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript(9)).is_err());
}

#[test]
fn entrypoint_bool_argument_accepts_at_most_one_byte() {
    let source = r#"
        contract BoolSize() {
            entry main(bool value) {
                require(true);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("bool parameter should compile");
    let body = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpSize)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let expected = wrap_with_single_dispatch(&compiled, body);
    assert_eq!(bytecode(&compiled), expected);

    let sigscript =
        |size: usize| script_builder().add_data_with_push_opcode(&vec![1; size]).unwrap().add_data(&dispatch_tag).unwrap().drain();
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(0)).is_ok());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(1)).is_ok());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript(2)).is_err());
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript(9)).is_err());
}

#[test]
fn compile_time_length_for_fixed_size_int_array() {
    let source = r#"
        contract Test() {
            entry test() {
                int[5] nums = int[_]{1, 2, 3, 4, 5};
                require(nums.length == 5);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let asm = script_to_str(&bytecode(&compiled)).expect("stringifies");
    assert!(!asm.contains("OpSize"), "fixed-size array length should be compile-time, got asm: {asm}");
    assert!(asm.contains("Op5 Op5 OpNumEqual OpVerify"), "expected compile-time length comparison, got asm: {asm}");
}

#[test]
fn compile_time_length_for_fixed_size_byte_array() {
    let source = r#"
        contract Test() {
            entry test() {
                byte[3] data = byte[_](0x010203);
                require(data.length == 3);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let asm = script_to_str(&bytecode(&compiled)).expect("stringifies");
    assert!(!asm.contains("OpSize"), "fixed-size byte-array length should be compile-time, got asm: {asm}");
    assert!(asm.contains("Op3 Op3 OpNumEqual OpVerify"), "expected compile-time length comparison, got asm: {asm}");
}

#[test]
fn compile_time_length_for_inferred_array_sizes() {
    let source = r#"
        contract Test() {
            entry test() {
                byte[_] data = byte[_](0x1234abcd);
                int[_] nums = int[_]{1, 2, 3};
                require(data.length == 4);
                require(nums.length == 3);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let asm = script_to_str(&bytecode(&compiled)).expect("stringifies");
    assert!(!asm.contains("OpSize"), "inferred fixed-array lengths should be compile-time, got asm: {asm}");
    assert!(asm.contains("Op4 Op4 OpNumEqual OpVerify"), "expected byte-array compile-time length, got asm: {asm}");
    assert!(asm.contains("Op3 Op3 OpNumEqual OpVerify"), "expected int-array compile-time length, got asm: {asm}");
}

#[test]
fn accepts_fixed_size_array_init_with_correct_size() {
    let source = r#"
        contract Test() {
            entry test() {
                int[4] nums = int[_]{1, 2, 3, 4};
                byte[3] data = byte[_](0x010203);
                require(nums.length == 4);
                require(data.length == 3);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn rejects_fixed_size_array_init_with_too_few_elements() {
    let source = r#"
        contract Test() {
            entry test() {
                int[4] nums = int[_]{1, 2, 3};  // Too few
            }
        }
    "#;
    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("should reject array with too few elements");
    assert!(matches!(err.root(), CompilerError::SizeMismatch), "unexpected error: {err:?}");
}

#[test]
fn rejects_fixed_size_array_init_with_too_many_elements() {
    let source = r#"
        contract Test() {
            entry test() {
                int[3] nums = int[_]{1, 2, 3, 4, 5};  // Too many
            }
        }
    "#;
    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("should reject array with too many elements");
    assert!(matches!(err.root(), CompilerError::SizeMismatch), "unexpected error: {err:?}");
}

#[test]
fn accepts_fixed_size_byte_array_init() {
    let source = r#"
        contract Test() {
            entry test() {
                byte[32] hash = byte[_](0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f);
                require(hash.length == 32);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn accepts_array_type_with_constant_size() {
    // Test that constants can be used in array type declarations like int[SIZE]
    let source = r#"
        contract Test() {
            int constant SIZE = 4;
            entry test() {
                int[SIZE] nums = int[_]{1, 2, 3, 4};
                require(nums.length == SIZE);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds with int[SIZE]");
}

#[test]
fn rejects_contract_constant_initializer_type_mismatches() {
    let cases = [
        ("int constant VALUE = true;", "scalar mismatch"),
        ("bool constant VALUE = 1;", "reverse scalar mismatch"),
        ("int[2] constant VALUE = bool[2]{true, false};", "array element mismatch"),
        ("int[2] constant VALUE = int[1]{1};", "fixed array size mismatch"),
        ("string[] constant VALUE = string[]{\"value\"};", "unknown-width array element"),
        (
            "struct Pair { int amount; bool enabled; } Pair constant VALUE = Pair {amount: true, enabled: false};",
            "struct field mismatch",
        ),
    ];

    for (declaration, description) in cases {
        let source = format!(
            r#"
                contract ConstantType() {{
                    {declaration}
                    entry main() {{ require(true); }}
                }}
            "#
        );
        compile_contract(&source, &[], CompileOptions::default()).expect_err(&format!("{description} should fail compilation"));
    }
}

#[test]
fn accepts_well_typed_constant_dependencies_on_constructor_params_and_constants() {
    let source = r#"
        contract ConstantDependencies(int base) {
            int constant NEXT = base + 1;
            int constant RESULT = NEXT + 1;

            entry main() {
                require(RESULT == base + 2);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[3.into()], CompileOptions::default()).expect("well-typed constant dependencies should compile");
    let sigscript = dispatch_tag_sigscript(dispatch_tag_for(&compiled, "main"));
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "constant dependencies should retain their runtime value: {result:?}");
}

#[test]
fn mismatched_contract_constant_reports_the_initializer_span() {
    let source = r#"
        contract ConstantType() {
            int constant VALUE = true;
            entry main() { require(true); }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("the mismatched constant must fail compilation");
    assert!(err.to_string().contains("constant 'VALUE' expects int"), "unexpected error: {err}");
    let span = err.span().expect("the constant initializer should be identified");
    assert_eq!(&source[span.start..span.end], "true");
}

#[test]
fn rejects_cyclic_constant_array_dimensions() {
    let cases = ["int constant A = A;".to_string(), "int constant A = B; int constant B = A;".to_string()];

    for constants in cases {
        let source = format!(
            r#"
                contract ConstantCycle() {{
                    {constants}

                    entry spend(int[A] values) {{
                        require(true);
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("constant cycle must be rejected");
        assert!(err.to_string().contains("cyclic identifier reference"), "unexpected error: {err}");
    }
}

#[test]
fn encodes_contract_field_with_constant_array_size() {
    let source = r#"
        contract Test() {
            int constant HALF_SIZE = 2;
            int constant SIZE = HALF_SIZE * 2;
            int[SIZE] values = int[_]{1, 2, 3, 4};

            entry test() {
                require(values.length == SIZE);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("constant-sized contract field should compile");
}

#[test]
fn compile_time_length_with_constant_size() {
    // Test that array.length is computed at compile-time for arrays with constant sizes
    let source = r#"
        contract Test() {
            int constant SIZE = 5;
            entry test() {
                int[SIZE] nums = int[_]{1, 2, 3, 4, 5};
                require(nums.length == SIZE);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let asm = script_to_str(&bytecode(&compiled)).expect("stringifies");
    assert!(!asm.contains("OpSize"), "constant-sized array length should be compile-time, got asm: {asm}");
    assert!(asm.contains("Op5 Op5 OpNumEqual OpVerify"), "expected compile-time length comparison, got asm: {asm}");
}

#[test]
fn accepts_byte_array_with_constant_size() {
    // Test that constants work with byte arrays too
    let source = r#"
        contract Test() {
            int constant HASH_SIZE = 32;
            entry test(byte[HASH_SIZE] hash) {
                require(hash.length == HASH_SIZE);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds with byte[HASH_SIZE]");
}

#[test]
fn constant_array_dimension_expressions_compare_by_value() {
    let source = r#"
        contract Test() {
            int constant HALF_SIZE = 16;
            int constant HASH_SIZE = HALF_SIZE * 2;

            function consume(byte[32] hash) {
                require(hash.length == 32);
            }

            entry test(byte[HASH_SIZE] hash) {
                consume(hash);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("equal compiled array dimensions should match");
}

#[test]
fn fixed_and_dynamic_array_types_are_not_identical() {
    let source = r#"
        contract Test() {
            function consume(byte[] hash) {
                require(hash.length == 32);
            }

            entry test(byte[32] hash) {
                consume(hash);
            }
        }
    "#;
    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("fixed and dynamic array types should differ");
    assert!(err.to_string().contains("function argument 'hash' expects byte[]"), "unexpected error: {err}");
}

#[test]
fn rejects_integer_to_byte_array_casts() {
    for cast in ["byte[](x)", "byte[8](x)"] {
        let source = format!(
            r#"
            contract Test() {{
                entry test(int x) {{
                    byte[] encoded = {cast};
                    require(encoded.length == 8);
                }}
            }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("int-to-bytes cast should be rejected");
        assert!(
            err.to_string().contains("cannot cast int to") && err.to_string().contains("use 'value as byte[N]' instead"),
            "unexpected error for {cast}: {err}"
        );
    }

    let source = r#"
        contract Test() {
            entry test(int x) {
                byte[] encoded = byte[](x, 4);
                require(encoded.length == 4);
            }
        }
    "#;
    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("sized byte[] cast should be rejected");
    assert!(err.to_string().contains("byte[]() expects 1 arguments"), "unexpected error: {err}");
}

#[test]
fn bool_as_int_normalizes_vm_truthiness() {
    let source = r#"
        contract Test() {
            entry main(bool value) {
                int normalized = value as int;
                require(normalized == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("bool as int compiles");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert_eq!(opcodes.matches("Op0NotEqual").count(), 1, "bool as int must normalize VM truthiness exactly once: {opcodes}");

    let raw_truthy_arg =
        script_builder().add_data_with_push_opcode(&[2]).unwrap().add_data(&dispatch_tag_for(&compiled, "main")).unwrap().drain();
    let result = run_bytecode_with_sigscript(bytecode(&compiled), raw_truthy_arg);
    assert!(result.is_ok(), "truthy 0x02 must normalize to integer 1: {result:?}");
}

#[test]
fn function_style_int_cast_rejects_bool_expressions() {
    let source = r#"
        contract Test() {
            entry main(bool value) {
                int converted = int(value);
                require(converted == 1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("int(bool) must be rejected");
    assert!(err.to_string().contains("cannot cast bool to int with int(); use 'value as int' instead"), "unexpected error: {err}");
}

#[test]
fn as_int_rejects_non_bool_expressions() {
    let source = "contract Test() { entry main(int value) { int converted = value as int; require(converted == value); } }";
    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("only bool expressions may use as int");
    assert!(err.to_string().contains("'as int' source must be bool"), "unexpected error: {err}");
}

#[test]
fn int_as_fixed_bytes_has_a_fixed_result_type_and_uses_num2bin() {
    let source = r#"
        contract Test() {
            entry test(int x) {
                byte[8] y = x as byte[8];
                byte[_] z = x as byte[4];
                require(y == byte[8](OpNum2Bin(x, 8)));
                require(z == byte[4](OpNum2Bin(x, 4)));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("fixed-size integer conversions compile");
    assert_eq!(bytecode(&compiled).iter().filter(|&&op| op == OpNum2Bin).count(), 4);
    let sigscript = script_builder().add_i64(42).unwrap().add_data(&dispatch_tag_for(&compiled, "test")).unwrap().drain();
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript).is_ok(), "fixed-size integer conversions should execute");
}

#[test]
fn int_as_byte_uses_num2bin_and_executes() {
    let source = r#"
        contract Test() {
            entry test(int x) {
                byte encoded = x as byte;
                require(encoded == byte(42));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("int as byte compiles");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert_eq!(opcodes.matches("OpNum2Bin").count(), 1, "int as byte must emit one OpNum2Bin: {opcodes}");

    let sigscript = encode_entry_sig_script(&compiled, "test", &[ArtifactValue::Int(42)]).expect("int argument encodes");
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript).is_ok(), "one-byte numeric conversion should execute");
}

#[test]
fn int_as_byte_fails_at_runtime_when_value_does_not_fit() {
    let source = r#"
        contract Test() {
            entry test(int x) {
                byte encoded = x as byte;
                require(encoded == encoded);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("int as byte compiles");
    let sigscript = encode_entry_sig_script(&compiled, "test", &[ArtifactValue::Int(128)]).expect("int argument encodes");
    let err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript).expect_err("128 needs two script-number bytes");
    assert_eq!(
        err,
        kaspa_txscript_errors::TxScriptError::Serialization(kaspa_txscript_errors::SerializationError::NumberTooLong(128, 1))
    );
}

#[test]
fn int_as_fixed_bytes_accepts_a_compile_time_size_constant() {
    let source = r#"
        contract Test() {
            int constant SIZE = 4;

            entry test(int x) {
                byte[_] encoded = x as byte[SIZE];
                require(encoded.length == SIZE);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("constant byte size compiles");
}

#[test]
fn int_as_fixed_bytes_rejects_invalid_source_target_and_size() {
    let cases = [
        ("byte[] data = byte[](0x01); byte[_] encoded = data as byte[4];", "source must be int"),
        ("int x = 1; byte[] encoded = x as byte[];", "requires byte or a fixed byte[N] target"),
        ("int x = 1; byte[_] encoded = x as byte[_];", "cannot infer fixed array size"),
        ("int x = 1; byte[_] encoded = x as byte[9];", "must be between 1 and 8"),
    ];

    for (statement, expected_error) in cases {
        let source = format!("contract Test() {{ entry test() {{ {statement} require(true); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("invalid 'as byte[N]' must fail");
        assert!(err.to_string().contains(expected_error), "unexpected error for {statement}: {err}");
    }
}

#[test]
fn blake2b_builtins_require_dynamic_byte_array_arguments() {
    let invalid_cases = [
        ("blake2b", "blake2b(5)", "argument 'data' expects byte[], got int"),
        ("blake2b fixed data", "blake2b(5 as byte[8])", "argument 'data' expects byte[], got byte[8]"),
        ("blake2bWithKey data", "blake2bWithKey(5, byte[](\"key\"))", "argument 'data' expects byte[], got int"),
        ("blake2bWithKey key", "blake2bWithKey(byte[](\"data\"), byte[2](0x0001))", "argument 'key' expects byte[], got byte[2]"),
    ];

    for (name, call, expected_error) in invalid_cases {
        let source = format!(
            r#"
            contract Test() {{
                entry test() {{
                    require({call}.length == 32);
                }}
            }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err(&format!("{name} should reject non-byte[]"));
        assert!(err.to_string().contains(expected_error), "unexpected error for {name}: {err}");
    }

    let valid_source = r#"
        contract Test() {
            entry test(byte[] data, byte[] key) {
                require(blake2b(data).length == 32);
                require(blake2bWithKey(data, key).length == 32);
            }
        }
    "#;
    let compiled = compile_contract(valid_source, &[], CompileOptions::default()).expect("byte[] arguments should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("Blake2b script should stringify");
    assert!(asm.contains("OpBlake2b"), "expected OpBlake2b in generated script: {asm}");
    assert!(asm.contains("OpBlake2bWithKey"), "expected OpBlake2bWithKey in generated script: {asm}");
}

#[test]
fn builtin_function_arguments_are_type_checked() {
    let invalid_calls = [
        ("length", "length(1) >= 0", "argument 'data' expects byte[], got int"),
        ("sha256", "sha256(1).length == 32", "argument 'data' expects byte[], got int"),
        ("blake3", "blake3(false).length == 32", "argument 'data' expects byte[], got bool"),
        ("signed conversion", "signed(false) == 0", "argument 'value' expects byte, got bool"),
        ("unsigned conversion", "unsigned(false) == 0", "argument 'value' expects byte, got bool"),
        ("checkSig", "checkSig(1, 2)", "argument 'signature' expects sig, got int"),
        ("transaction index", "OpOutpointTxId(false).length == 32", "argument 'idx' expects int, got bool"),
        ("input sequence index", "OpTxInputSeq(false).length == 8", "argument 'idx' expects int, got bool"),
        ("transaction substring", "OpTxPayloadSubstr(false, 1).length >= 0", "argument 'start' expects int, got bool"),
        ("transaction substring end", "OpTxPayloadSubstr(0, false).length >= 0", "argument 'end' expects int, got bool"),
        ("input signature substring end", "OpTxInputScriptSigSubstr(0, 0, false).length >= 0", "argument 'end' expects int, got bool"),
        (
            "input script public key substring end",
            "OpTxInputSpkSubstr(0, 0, false).length >= 0",
            "argument 'end' expects int, got bool",
        ),
        (
            "output script public key substring end",
            "OpTxOutputSpkSubstr(0, 0, false).length >= 0",
            "argument 'end' expects int, got bool",
        ),
        ("covenant id", "OpCovInputCount(byte[](\"id\")) >= 0", "argument 'covenant_id' expects byte[32], got byte[]"),
        ("number encoding", "OpNum2Bin(false, 1).length >= 0", "argument 'num' expects int, got bool"),
        ("number decoding", "OpBin2Num(1) >= 0", "argument 'num' expects byte[], got int"),
        (
            "sequence commitment",
            "OpChainblockSeqCommit(byte[](\"block\")).length == 32",
            "argument 'block' expects byte[32], got byte[]",
        ),
    ];

    for (name, expression, expected_error) in invalid_calls {
        let source = format!("contract Test() {{ entry test() {{ require({expression}); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err(&format!("{name} should type-check arguments"));
        assert!(err.to_string().contains(expected_error), "unexpected error for {name}: {err}");
    }
}

#[test]
fn fixed_byte_array_up_to_eight_bytes_casts_to_int_without_extra_opcodes() {
    let source = r#"
        contract Test() {
            entry test(byte[2] data) {
                int number = int(data);
                require(number == 42);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte[2] to int cast compiles");
    assert!(!bytecode(&compiled).contains(&OpBin2Num), "int(data) must not emit OpBin2Num");

    let sigscript = encode_entry_sig_script(&compiled, "test", &[vec![42u8, 0].into()]).expect("sigscript builds");
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript).is_ok(), "int(byte[2]) should produce a usable integer value");
}

#[test]
fn int_cast_rejects_dynamic_and_oversized_byte_arrays() {
    for type_name in ["byte[]", "byte[9]"] {
        let source =
            format!("contract Test() {{ entry test({type_name} data) {{ int number = int(data); require(number == number); }} }}");
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("int casts require a fixed byte array no wider than eight bytes");
        assert!(err.to_string().contains(&format!("cannot cast {type_name} to int")), "unexpected error: {err}");
    }
}

#[test]
fn scalar_int_and_byte_cast_directionality() {
    for expression in ["value", "value + 1"] {
        let source = format!(
            r#"
            contract Test() {{
                entry test(int value) {{
                    byte narrowed = byte({expression});
                    require(narrowed == narrowed);
                }}
            }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("non-literal int expressions must not cast to scalar byte");
        assert!(err.to_string().contains("cannot cast non-literal int expression to byte"), "unexpected error: {err}");
    }

    let literal_source = r#"
        contract Test() {
            entry test() {
                byte zero = byte(0);
                byte value = byte(42);
                byte max = byte(255);
                require(zero == byte(0));
                require(value == byte(42));
                require(max == byte(255));
            }
        }
    "#;
    compile_contract(literal_source, &[], CompileOptions::default()).expect("in-range int literals may cast to byte");

    let out_of_range_source = r#"
        contract Test() {
            entry test() {
                byte invalid = byte(256);
                require(invalid == invalid);
            }
        }
    "#;
    let err = compile_contract(out_of_range_source, &[], CompileOptions::default())
        .expect_err("out-of-range int literal must not cast to byte");
    assert!(err.to_string().contains("integer literal 256 is out of range for byte"), "unexpected error: {err}");
}

#[test]
fn scalar_byte_cast_cannot_escape_validate_output_state_push() {
    let direct_cast_source = r#"
        contract ByteCast() {
            entry main(string value) {
                require(byte(value) == byte(1));
            }
        }
    "#;
    let err =
        compile_contract(direct_cast_source, &[], CompileOptions::default()).expect_err("a string must not cast to a scalar byte");
    assert!(err.to_string().contains("cannot cast string to byte"), "unexpected error: {err}");

    let source = r#"
        contract ByteCastState(byte initial) {
            byte marker = initial;

            entry roll(string next_marker) {
                validateOutputState(0, State {
                    marker: byte(next_marker)
                });
            }

            entry accept() {
                require(marker == byte(1));
            }
        }
    "#;

    compile_contract(source, &[ArtifactValue::Byte(0)], CompileOptions::default())
        .expect_err("a string must not cast to a scalar byte and escape the generated one-byte state push");
}

#[test]
fn int_cast_rejects_scalar_byte_expressions() {
    let variable_source = r#"
        contract Test() {
            entry test(byte value) {
                int widened = int(value);
                require(widened == widened);
            }
        }
    "#;
    let err = compile_contract(variable_source, &[], CompileOptions::default()).expect_err("int(byte variable) must be rejected");
    assert!(err.to_string().contains("use signed() or unsigned()"), "unexpected error: {err}");

    let literal_source = r#"
        contract Test() {
            entry test() {
                int widened = int(byte(42));
                require(widened == widened);
            }
        }
    "#;
    let err = compile_contract(literal_source, &[], CompileOptions::default()).expect_err("int(byte expression) must be rejected");
    assert!(err.to_string().contains("use signed() or unsigned()"), "unexpected error: {err}");
}

#[test]
fn signed_byte_cast_is_a_passthrough_with_signed_numeric_semantics() {
    let source = r#"
        contract Test() {
            entry test(byte value) {
                int converted = signed(value);
                require(converted == -127);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("signed(byte) compiles");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert!(!opcodes.contains("OpCat"), "signed(byte) must be a passthrough: {opcodes}");
    assert!(!opcodes.contains("OpBin2Num"), "signed(byte) must not normalize its operand: {opcodes}");

    let sigscript = encode_entry_sig_script(&compiled, "test", &[ArtifactValue::Byte(255)]).expect("byte argument encodes");
    assert!(run_bytecode_with_sigscript(bytecode(&compiled), sigscript).is_ok(), "0xff must have signed value -127");
}

#[test]
fn unsigned_byte_cast_appends_zero_and_preserves_255() {
    let source = r#"
        contract Test() {
            entry test() {
                int i = 255;
                byte b = 255;
                require(unsigned(b) == i);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("unsigned(byte) compiles");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode stringifies");
    assert_eq!(opcodes.matches("OpCat").count(), 1, "unsigned(byte) must append one zero byte: {opcodes}");
    assert!(!opcodes.contains("OpBin2Num"), "unsigned(byte) must use concatenation rather than normalization: {opcodes}");
    let dispatch_tag = dispatch_tag_for(&compiled, "test");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok(), "unsigned(0xff) must equal 255");
}

#[test]
fn empty_array_statement_expr_evaluation_compiles_to_empty_array_data() {
    let source = r#"
        contract Test() {
            entry main() {
                require(byte[]{} == byte[]{});
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let body = script_builder()
        .add_data_with_push_opcode(&[])
        .unwrap()
        .add_data_with_push_opcode(&[])
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);
    assert_eq!(bytecode(&compiled), expected);
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn function_param_shadows_constructor_constant_with_same_name() {
    // When a constructor constant and a function parameter share the same name,
    // the function parameter value must be used (not the constant).
    let source = r#"
        contract Shadow(int fee) {
            entry main(int fee) {
                int local = fee + 1;
                require(local == 4);
            }
        }
    "#;

    // Constructor fee=2, param fee=3 => local = 3+1 = 4 => pass
    let compiled = compile_contract(source, &[ArtifactValue::Int(2)], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(3)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
    assert!(result.is_ok(), "function param should shadow constructor constant: {}", result.unwrap_err());

    // Constructor fee=2, param fee=2 => local = 2+1 = 3 != 4 => fail (proves it's not always the constant)
    let sigscript_wrong = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(2)]).expect("sigscript builds");
    let result_wrong = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_wrong);
    assert!(result_wrong.is_err(), "require(3==4) should fail, proving the param value matters");
}

#[test]
fn allows_same_variable_name_in_different_functions() {
    let source = r#"
        contract SeparateFunctionScopes() {
            function check_positive(int value) {
                int result = value + 1;
                require(result > 0);
            }

            function check_negative(int value) {
                int result = value - 1;
                require(result < 0);
            }

            entry main() {
                check_positive(1);
                check_negative(-1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default())
        .expect("separate functions should have independent variable namespaces");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn allows_same_variable_name_in_non_overlapping_sibling_scopes() {
    let source = r#"
        contract SiblingScopes() {
            entry main() {
                if (true) {
                    int value = 1;
                    require(value == 1);
                } else {
                    int value = 2;
                    require(value == 2);
                }

                {
                    int temporary = 3;
                    require(temporary == 3);
                }
                {
                    int temporary = 4;
                    require(temporary == 4);
                }

                for (i, 0, 1, 1) {
                    require(i == 0);
                }
                for (i, 0, 1, 1) {
                    require(i == 0);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default())
        .expect("non-overlapping sibling scopes should have independent variable namespaces");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    assert!(run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).is_ok());
}

#[test]
fn rejects_function_param_that_shadows_contract_constant_with_same_name() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract C() {
            int constant N = 2;
            entry f(int N) {
                int s = 0;
                for (i, 0, N, 10) {
                    s = s + 1;
                }
                require(s == N);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("a function parameter must not shadow a contract constant");
    assert!(err.to_string().contains("variable 'N' is already defined"), "unexpected error: {err}");
    let span = err.span().expect("the conflicting parameter should be identified");
    assert_eq!(&source[span.start..span.end], "N");
}

#[test]
fn rejects_contract_constant_that_shadows_constructor_parameter_used_as_array_size() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract C(int A) {
            int constant A = 2;
            entry f() {
                byte[A] b = byte[A](0x11223344);
                require(b.length == 4);
            }
        }
    "#;

    let err = compile_contract(source, &[ArtifactValue::Int(4)], CompileOptions::default())
        .expect_err("a contract constant must not shadow a constructor parameter");
    assert!(err.to_string().contains("variable 'A' is already defined"), "unexpected error: {err}");
    let span = err.span().expect("the conflicting constant should be identified");
    assert_eq!(&source[span.start..span.end], "A");
}

#[test]
fn rejects_duplicate_variable_definition_in_same_scope() {
    let source = r#"
        contract DuplicateLocal() {
            entry main() {
                int value = 1;
                int value = 2;
                require(value > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("duplicate variable definitions in the same scope should be rejected");
    assert!(err.to_string().contains("variable 'value' is already defined"), "unexpected error: {err}");
    let span = err.span().expect("the duplicate declaration should be identified");
    assert_eq!(&source[span.start..span.end], "value");
}

#[test]
fn rejects_constant_declarations_inside_functions() {
    let cases = [
        "int constant value = 1;",
        "{ bool constant value = true; }",
        "if (true) { byte[1] constant value = byte[1](0x01); }",
        "for (i, 0, 1, 1) { int constant value = i; }",
    ];

    for declaration in cases {
        let source = format!(
            r#"
                contract LocalConstant() {{
                    entry main() {{
                        {declaration}
                        require(true);
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("constant declarations inside functions must fail compilation");
        assert!(err.to_string().contains("constant declarations are only allowed at contract level"), "unexpected error: {err}");
        let span = err.span().expect("the local constant modifier should be identified");
        assert_eq!(&source[span.start..span.end], "constant");
    }
}

#[test]
fn rejects_assignments_to_contract_constants() {
    let cases = [
        ("int constant VALUE = 1;", "VALUE = 2;", "VALUE"),
        ("int[2] constant VALUES = int[2]{1, 2};", "VALUES = int[2]{3, 4};", "VALUES"),
        (
            "struct Pair { int left; int right; } Pair constant PAIR = Pair {left: 1, right: 2};",
            "PAIR = Pair {left: 3, right: 4};",
            "PAIR",
        ),
    ];

    for (declaration, assignment, name) in cases {
        let source = format!(
            r#"
                contract ConstantAssignment() {{
                    {declaration}
                    entry main() {{
                        {{ {assignment} }}
                        require(true);
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default())
            .expect_err("assigning to a contract constant must fail compilation");
        assert!(err.to_string().contains(&format!("cannot assign to contract constant '{name}'")), "unexpected error: {err}");
        let span = err.span().expect("the constant assignment target should be identified");
        assert_eq!(&source[span.start..span.end], name);
    }
}

#[test]
fn rejects_assignments_to_state_fields() {
    let cases = [
        ("int value = 1;", "value = 2;", "value"),
        ("int[2] values = int[2]{1, 2};", "values = int[2]{3, 4};", "values"),
        ("struct Pair { int left; int right; } Pair pair = Pair {left: 1, right: 2};", "pair = Pair {left: 3, right: 4};", "pair"),
    ];

    for (declaration, assignment, name) in cases {
        let source = format!(
            r#"
                contract StateFieldAssignment() {{
                    {declaration}
                    entry main() {{
                        {{ {assignment} }}
                        require(true);
                    }}
                }}
            "#
        );
        let err =
            compile_contract(&source, &[], CompileOptions::default()).expect_err("assigning to a state field must fail compilation");
        assert!(err.to_string().contains(&format!("cannot assign to state field '{name}'")), "unexpected error: {err}");
        let span = err.span().expect("the state field assignment target should be identified");
        assert_eq!(&source[span.start..span.end], name);
    }
}

#[test]
fn rejects_shadowing_in_nested_function_scopes() {
    let cases = [
        r#"
            contract ParameterShadowing() {
                entry main(int value) {
                    int value = 1;
                }
            }
        "#,
        r#"
            contract BlockShadowing() {
                entry main() {
                    int value = 1;
                    { int value = 2; }
                }
            }
        "#,
        r#"
            contract BranchShadowing() {
                entry main(bool condition) {
                    int value = 1;
                    if (condition) { int value = 2; }
                }
            }
        "#,
        r#"
            contract LoopShadowing() {
                entry main(int i) {
                    for (i, 0, 1, 1) { require(i == 0); }
                }
            }
        "#,
        r#"
            contract TupleShadowing() {
                entry main() {
                    byte[] left = byte[](0xaa);
                    byte[] source = byte[](0x0102);
                    { (byte[] left, byte[] right) = source.split(1); }
                }
            }
        "#,
        r#"
            contract FunctionResultShadowing() {
                function pair() : (int, int) { return(1, 2); }
                entry main() {
                    int value = 3;
                    { (int value, int other) = pair(); }
                }
            }
        "#,
        r#"
            contract StructBindingShadowing() {
                struct S { int field; }
                entry main() {
                    int value = 3;
                    S source = S {field: 1};
                    { S {field: int value} = source; }
                }
            }
        "#,
    ];

    for source in cases {
        let err = compile_contract(source, &[], CompileOptions::default()).expect_err("shadowing should be rejected");
        assert!(err.to_string().contains("is already defined"), "unexpected error: {err}");
    }
}

#[test]
fn ternary_syntax_lowers_to_ternary_expr() {
    let source = r#"
        contract TernaryAst() {
            entry main(bool flag) {
                int value = flag ? 7 : 11;
                require(value > 0);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("contract parses");
    let Statement::VariableDefinition { expr: Some(expr), .. } = &contract.functions[0].body[0] else {
        panic!("expected variable definition");
    };
    assert!(matches!(&expr.kind, ExprKind::Ternary { .. }), "ternary should lower to ExprKind::Ternary: {expr:?}");
}

#[test]
fn ternary_expression_executes_selected_branch() {
    let source = r#"
        contract TernaryRuntime() {
            entry main(int dispatch_tag, int expected) {
                int value = dispatch_tag > 0 ? 7 : 11;
                require(value == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("ternary contract should compile");

    let sigscript_then =
        encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(1), ArtifactValue::Int(7)]).expect("sigscript builds");
    let result_then = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_then);
    assert!(result_then.is_ok(), "then branch should execute successfully: {}", result_then.unwrap_err());

    let sigscript_else =
        encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(0), ArtifactValue::Int(11)]).expect("sigscript builds");
    let result_else = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_else);
    assert!(result_else.is_ok(), "else branch should execute successfully: {}", result_else.unwrap_err());

    let sigscript_wrong =
        encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(0), ArtifactValue::Int(7)]).expect("sigscript builds");
    let result_wrong = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_wrong);
    assert!(result_wrong.is_err(), "else branch should not produce the then value");
}

#[test]
fn ternary_expression_does_not_execute_unselected_branch() {
    let source = r#"
        contract TernaryShortCircuit() {
            entry main(
                bool select_then,
                int then_numerator,
                int then_divisor,
                int else_numerator,
                int else_divisor,
                int expected
            ) {
                int value = select_then ? then_numerator / then_divisor : else_numerator / else_divisor;
                require(value == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("ternary contract should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("ternary script should stringify");
    let if_index = asm.find("OpIf").expect("ternary should emit OpIf");
    let else_index = asm.find("OpElse").expect("ternary should emit OpElse");
    let end_if_index = asm.find("OpEndIf").expect("ternary should emit OpEndIf");
    let div_indices = asm.match_indices("OpDiv").map(|(index, _)| index).collect::<Vec<_>>();
    assert_eq!(div_indices.len(), 2, "each ternary branch should contain one division: {asm}");
    assert!(
        if_index < div_indices[0] && div_indices[0] < else_index && else_index < div_indices[1] && div_indices[1] < end_if_index,
        "divisions should remain inside their respective conditional branches: {asm}"
    );

    let select_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[
            ArtifactValue::Bool(true),
            ArtifactValue::Int(10),
            ArtifactValue::Int(2),
            ArtifactValue::Int(20),
            ArtifactValue::Int(0),
            ArtifactValue::Int(5),
        ],
    )
    .expect("then-branch sigscript builds");
    let then_result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_then);
    assert!(then_result.is_ok(), "zero divisor in the unselected else branch must not execute: {}", then_result.unwrap_err());

    let select_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[
            ArtifactValue::Bool(false),
            ArtifactValue::Int(10),
            ArtifactValue::Int(0),
            ArtifactValue::Int(20),
            ArtifactValue::Int(4),
            ArtifactValue::Int(5),
        ],
    )
    .expect("else-branch sigscript builds");
    let else_result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_else);
    assert!(else_result.is_ok(), "zero divisor in the unselected then branch must not execute: {}", else_result.unwrap_err());

    let failing_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[
            ArtifactValue::Bool(true),
            ArtifactValue::Int(10),
            ArtifactValue::Int(0),
            ArtifactValue::Int(20),
            ArtifactValue::Int(4),
            ArtifactValue::Int(5),
        ],
    )
    .expect("failing then-branch sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled).clone(), failing_then).is_err(),
        "zero divisor in the selected then branch should execute and fail"
    );

    let failing_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[
            ArtifactValue::Bool(false),
            ArtifactValue::Int(10),
            ArtifactValue::Int(2),
            ArtifactValue::Int(20),
            ArtifactValue::Int(0),
            ArtifactValue::Int(5),
        ],
    )
    .expect("failing else-branch sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled), failing_else).is_err(),
        "zero divisor in the selected else branch should execute and fail"
    );
}

#[test]
fn ternary_does_not_read_input_state_in_unselected_then_branch() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract TernaryHoist(int initX) {
            int x = initX;

            function get(State st): int {
                return st.x;
            }

            entry main(bool useRemote) {
                int v = useRemote ? get(readInputState(9)) : 42;
                require(v == 42);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[ArtifactValue::Int(7)], CompileOptions::default()).expect("ternary contract should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("ternary script should stringify");
    let if_index = asm.find("OpIf").expect("ternary should emit OpIf");
    let read_index = asm.find("OpTxInputScriptSigLen").expect("selected branch should contain the input-state read");
    let else_index = asm.find("OpElse").expect("ternary should emit OpElse");
    assert!(
        if_index < read_index && read_index < else_index,
        "input-state access should remain inside the ternary's then branch: {asm}"
    );

    let select_local = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(false)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_local);
    assert!(result.is_ok(), "input 9 in the unselected branch must not be read: {}", result.unwrap_err());

    let select_remote = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(true)]).expect("sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled), select_remote).is_err(),
        "input 9 in the selected branch should be read and fail"
    );
}

#[test]
fn ternary_expression_does_not_execute_function_call_in_unselected_else_branch() {
    let source = r#"
        contract TernaryCallShortCircuit() {
            function fail(int value) : int {
                require(false);
                return value;
            }

            entry main(bool select_then, int then_value, int else_value, int expected) {
                int value = select_then ? then_value : fail(else_value);
                require(value == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("ternary contract should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("ternary script should stringify");
    let if_index = asm.find("OpIf").expect("ternary should emit OpIf");
    let else_index = asm.find("OpElse").expect("ternary should emit OpElse");
    let fail_index = asm.find("OpFalse OpVerify").expect("else-branch helper should emit require(false)");
    let end_if_index = asm.find("OpEndIf").expect("ternary should emit OpEndIf");
    assert!(
        if_index < else_index && else_index < fail_index && fail_index < end_if_index,
        "require(false) should remain inside the ternary's else branch: {asm}"
    );

    let select_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(true), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(7)],
    )
    .expect("then-branch sigscript builds");
    let then_result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_then);
    assert!(then_result.is_ok(), "require(false) in the unselected else-branch call must not execute: {}", then_result.unwrap_err());

    let select_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(false), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(11)],
    )
    .expect("else-branch sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled), select_else).is_err(),
        "require(false) in the selected else-branch call should execute and fail"
    );
}

#[test]
fn ternary_expression_does_not_execute_function_call_in_unselected_then_branch() {
    let source = r#"
        contract TernaryCallShortCircuit() {
            function fail(int value) : int {
                require(false);
                return value;
            }

            entry main(bool select_then, int then_value, int else_value, int expected) {
                int value = select_then ? fail(then_value) : else_value;
                require(value == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("ternary contract should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("ternary script should stringify");
    let if_index = asm.find("OpIf").expect("ternary should emit OpIf");
    let fail_index = asm.find("OpFalse OpVerify").expect("then-branch helper should emit require(false)");
    let else_index = asm.find("OpElse").expect("ternary should emit OpElse");
    let end_if_index = asm.find("OpEndIf").expect("ternary should emit OpEndIf");
    assert!(
        if_index < fail_index && fail_index < else_index && else_index < end_if_index,
        "require(false) should remain inside the ternary's then branch: {asm}"
    );

    let select_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(false), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(11)],
    )
    .expect("else-branch sigscript builds");
    let else_result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_else);
    assert!(else_result.is_ok(), "require(false) in the unselected then-branch call must not execute: {}", else_result.unwrap_err());

    let select_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(true), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(7)],
    )
    .expect("then-branch sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled), select_then).is_err(),
        "require(false) in the selected then-branch call should execute and fail"
    );
}

#[test]
fn nested_ternary_function_call_remains_in_selected_branch() {
    let source = r#"
        contract NestedTernaryCallShortCircuit() {
            function fail(int value) : int {
                require(false);
                return value;
            }

            entry main(bool select_then, int then_value, int else_value, int expected) {
                int value = 1 + (select_then ? then_value : fail(else_value));
                require(value == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested ternary contract should compile");

    let select_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(true), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(8)],
    )
    .expect("then-branch sigscript builds");
    let then_result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_then);
    assert!(
        then_result.is_ok(),
        "require(false) in a nested unselected else-branch call must not execute: {}",
        then_result.unwrap_err()
    );

    let select_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(false), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(12)],
    )
    .expect("else-branch sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled), select_else).is_err(),
        "require(false) in a nested selected else-branch call should execute and fail"
    );
}

#[test]
fn ternary_lowering_initializes_generated_results_for_supported_types() {
    let source = r#"
        contract TernaryDefaults(int N, byte[N] initial_bytes, pubkey initial_pubkey, sig initial_sig, datasig initial_datasig) {
            struct Pair {
                int number;
                bool flag;
            }

            entry main(bool select_then, int number, byte value) {
                int int_result = select_then ? number : 1;
                bool bool_result = select_then ? true : false;
                byte byte_result = select_then ? value : 1;
                string string_result = select_then ? "then" : "else";
                byte[N] fixed_array_result = select_then ? initial_bytes : initial_bytes;
                byte[] dynamic_array_result = select_then ? byte[](initial_bytes) : byte[](initial_bytes);
                pubkey pubkey_result = select_then ? initial_pubkey : initial_pubkey;
                sig sig_result = select_then ? initial_sig : initial_sig;
                datasig datasig_result = select_then ? initial_datasig : initial_datasig;
                Pair struct_result = select_then
                    ? Pair {number: number, flag: true}
                    : Pair {number: 1, flag: false};
                require(int_result >= 0);
                require(bool_result || !bool_result);
                require(byte_result == value || byte_result == 1);
                require(string_result.length > 0);
                require(fixed_array_result.length == 2);
                require(dynamic_array_result.length == 2);
                require(pubkey_result == initial_pubkey);
                require(sig_result == initial_sig);
                require(datasig_result == initial_datasig);
                require(struct_result.number >= 0);
            }
        }
    "#;

    compile_contract(
        source,
        &[
            ArtifactValue::Int(2),
            ArtifactValue::Bytes(vec![1, 2]),
            ArtifactValue::Bytes(vec![3; 32]),
            ArtifactValue::Bytes(vec![4; 65]),
            ArtifactValue::Bytes(vec![5; 64]),
        ],
        CompileOptions::default(),
    )
    .expect("ternary defaults should compile for every supported value type");
}

#[test]
fn if_else_does_not_execute_function_call_in_unselected_else_branch() {
    let source = r#"
        contract IfElseCallShortCircuit() {
            function fail(int value) : int {
                require(false);
                return value;
            }

            entry main(bool select_then, int then_value, int else_value, int expected) {
                int value = expected;
                if (select_then) {
                    value = then_value;
                } else {
                    value = fail(else_value);
                }
                require(value == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("if/else contract should compile");
    let asm = script_to_str(&bytecode(&compiled)).expect("if/else script should stringify");
    let if_index = asm.find("OpIf").expect("if/else should emit OpIf");
    let else_index = asm.find("OpElse").expect("if/else should emit OpElse");
    let fail_index = asm.find("OpFalse OpVerify").expect("else-branch helper should emit require(false)");
    let end_if_index = asm.find("OpEndIf").expect("if/else should emit OpEndIf");
    assert!(
        if_index < else_index && else_index < fail_index && fail_index < end_if_index,
        "require(false) should remain inside the else branch: {asm}"
    );

    let select_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(true), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(7)],
    )
    .expect("then-branch sigscript builds");
    let then_result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), select_then);
    assert!(then_result.is_ok(), "require(false) in the unselected else-branch call must not execute: {}", then_result.unwrap_err());

    let select_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Bool(false), ArtifactValue::Int(7), ArtifactValue::Int(11), ArtifactValue::Int(11)],
    )
    .expect("else-branch sigscript builds");
    assert!(
        run_bytecode_with_sigscript(bytecode(&compiled), select_else).is_err(),
        "require(false) in the selected else-branch call should execute and fail"
    );
}

#[test]
fn ternary_expression_rejects_mismatched_branch_types() {
    let source = r#"
        contract TernaryTypes() {
            entry main(bool flag) {
                int value = flag ? 7 : false;
                require(value > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("mismatched ternary branches should fail");
    assert!(err.to_string().contains("variable 'value' expects int"), "unexpected error: {err}");
}

#[test]
fn ternary_expression_rejects_branch_type_that_does_not_match_declared_variable_type() {
    let source = r#"
        contract TernaryDeclaredType() {
            entry main(bool cond, bool y, bool z) {
                int x = cond ? y : z;
                require(x > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("ternary result type should match declared type");
    assert!(err.to_string().contains("variable 'x' expects int"), "unexpected error: {err}");
}

#[test]
fn ternary_expression_rejects_branch_type_that_does_not_match_function_return_type() {
    let source = r#"
        contract TernaryReturnType() {
            function choose(bool cond, bool y, bool z): int {
                return cond ? y : z;
            }

            entry main(bool cond, bool y, bool z) {
                int value = choose(cond, y, z);
                require(value > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("ternary result type should match return type");
    assert!(err.to_string().contains("return value expects int"), "unexpected error: {err}");
}

#[test]
fn nested_inline_calls_with_args_compile_and_execute() {
    // Nested inline calls must propagate synthetic __arg_ bindings so that
    // deeply nested calls can resolve arguments that flow through outer calls.
    let source = r#"
        contract NestedArgs() {
            function inner(int x) {
                int y = x + 1;
                require(y > 0);
            }

            function outer(int v) {
                inner(v);
                require(v >= 0);
            }

            function top(int z) {
                outer(z);
                require(z >= 0);
            }

            entry main(int a) {
                top(a);
                require(a >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested inline calls should compile");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "nested inline calls should execute correctly: {}", result.unwrap_err());
}

#[test]
fn inline_local_binding_is_stored_once_and_reused() {
    let source = r#"
        contract InlineRepeat() {
            function helper(int x) {
                int y = x + 1;
                require(y > 1);
                require(y < 10);
            }

            entry main(int x) {
                helper(x);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline helper should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "x + 1 should be computed once and stored for both require statements"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored inline local should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(10)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored inline local should still enforce the second require");
}

#[test]
fn inline_function_argument_expression_is_stored_once_and_reused() {
    let source = r#"
        contract InlineArgRepeat() {
            function f(int y) {
                require(y > 1);
                require(y < 10);
            }

            entry main(int x) {
                f(x + 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline call should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "x + 1 should be computed once and reused for both require statements in the inline callee"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored inline argument should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(10)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored inline argument should still enforce the second require");
}

#[test]
#[ignore = "TODO: Re-enable when fallible local-alias optimization is restored"]
fn inline_argument_alias_reuses_existing_local_without_extra_snapshot() {
    let source = r#"
        contract InlineAliasReuse() {
            function f(int z) {
                require(z > 1);
            }

            function g(int z) {
                require(z < 10);
            }

            entry main(int x) {
                int y = x * x;
                f(y);
                g(y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline alias reuse should compile");

    let body = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(10)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpOver).count(), 1);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpPick).count(), 0);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(), 1);

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(2)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "reused local should satisfy both inline requires: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(4)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "reused local should still fail the second inline require");
}

#[test]
#[ignore = "TODO: Re-enable when fallible local-alias optimization is restored"]
fn inline_argument_alias_snapshots_entrypoint_param_once_per_inlined_call() {
    let source = r#"
        contract InlineParamAliasReuse() {
            function f(int z) {
                require(z > 1);
            }

            function g(int z) {
                require(z < 10);
            }

            entry main(int y) {
                f(y);
                g(y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline param alias reuse should compile");

    let body = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(10)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpDup).count(), 2);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpOver).count(), 0);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpPick).count(), 0);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpDrop).count(), 1);

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(2)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "entrypoint param alias should satisfy both inline requires: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(10)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "entrypoint param alias should still fail the second inline require");
}

#[test]
#[ignore = "TODO: Re-enable when fallible local-alias optimization is restored"]
fn local_alias_snapshots_existing_stack_value_once() {
    let source = r#"
        contract LocalAliasReuse() {
            entry main(int x) {
                int y = x * x;
                require(y > 1);
                int z = y;
                require(z > 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("local alias reuse should compile");

    let body = script_builder()
        .add_op(OpDup)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_single_dispatch(&compiled, body);

    assert_eq!(bytecode(&compiled), expected);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(), 1);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpOver).count(), 1);
    assert_eq!(bytecode(&compiled).iter().copied().filter(|op| *op == OpPick).count(), 0);

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(2)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "local alias should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(1)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "local alias should still enforce the requires");
}

#[test]
fn local_alias_reassignment_from_alias_passes_for_x_5() {
    let source = r#"
        contract LocalAliasReassign() {
            entry main(int x) {
                int y = x * x;
                require(y > 1);
                int z = y;
                z = z + 1;
                require(z > y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("local alias reassignment should compile");

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "x=5 should pass after z is incremented past y: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(1)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "x=1 should still fail the initial require(y > 1)");
}

#[test]
fn local_bool_expression_is_stored_once_and_reused() {
    let source = r#"
        contract BoolRepeat() {
            entry main(int x) {
                bool y = x + 1 > 1;
                require(y);
                require(y == true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("bool local should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "x + 1 should be computed once for the stored bool expression"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored bool local should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(0)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored bool local should still enforce the false branch");
}

#[test]
fn local_nested_expression_is_stored_once_and_reused() {
    let source = r#"
        contract NestedRepeat() {
            entry main(int x) {
                int y = (x + 1) * (x + 2);
                require(y > 10);
                require(y < 100);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested local should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        2,
        "the nested local expression should compute each addition once before storing the result"
    );
    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the nested local expression should multiply once before storing the result"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored nested local should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(10)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored nested local should still enforce the second require");
}

#[test]
fn rejects_using_branch_local_outside_its_scope() {
    let source = r#"
        contract BranchScope() {
            entry main(bool cond) {
                if (cond) {
                    int x = 1;
                    require(x == 1);
                } else {
                    int x = 2;
                    require(x == 2);
                }
                require(x > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("branch-local x should not be visible after the if");
    assert!(err.to_string().contains("undefined identifier"), "unexpected error: {err}");
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_branch_local_shadowing_and_preserves_outer_scope() {
    let source = r#"
        contract BranchShadowing() {
            entry main(bool cond) {
                int x = 3;
                if (cond) {
                    int x = 1;
                    require(x == 1);
                } else {
                    int x = 2;
                    require(x == 2);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("branch-local shadowing should compile");

    for cond in [true, false] {
        let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(cond)]).expect("sigscript builds");
        let result = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript);
        assert!(result.is_ok(), "branch-local shadowing should execute successfully for cond={cond}: {}", result.unwrap_err());
    }
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_for_loop_local_shadowing_and_preserves_outer_scope() {
    let source = r#"
        contract LoopShadowing() {
            entry main() {
                int x = 10;
                for (i, 0, 2, 2) {
                    int x = i + 1;
                    require(x == i + 1);
                }
                require(x == 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("loop-local shadowing should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "loop-local shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_standalone_block_local_shadowing_and_preserves_outer_scope() {
    let source = r#"
        contract BlockShadowing() {
            entry main() {
                int x = 3;
                {
                    int x = 1;
                    require(x == 1);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("block-local shadowing should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "block-local shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_function_parameter_shadowing() {
    let source = r#"
        contract ParameterShadowing() {
            entry main(int x) {
                int x = 1;
                require(x == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("parameter shadowing should compile");
    let sigscript = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(9)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "parameter shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_inlined_function_parameter_shadowing() {
    let source = r#"
        contract InlineParameterShadowing() {
            function check(int x) {
                int x = 1;
                require(x == 1);
            }

            entry main() {
                check(9);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[], CompileOptions::default()).expect("inlined function parameter shadowing should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "inlined function parameter shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_standalone_block_tuple_binding_shadowing() {
    let source = r#"
        contract TupleBlockShadowing() {
            entry main() {
                byte[] left = byte[](0xaa);
                byte[] source = byte[](0x0102);
                {
                    (byte[] left, byte[] right) = source.split(1);
                    require(left == byte[](0x01));
                    require(right == byte[](0x02));
                }
                require(left == byte[](0xaa));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("tuple binding shadowing should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "tuple binding shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
fn runs_split_on_non_byte_array() {
    let source = r#"
        contract SplitNonByteArray() {
            entry main() {
                int[] values = int[]{10, 20, 30, 40};
                (int[] left, int[] right) = values.split(1);
                require(left.length == 1);
                require(left[0] == 10);
                require(right.length == 3);
                require(right[0] == 20);
                require(right[1] == 30);
                require(right[2] == 40);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("split on int[] should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "split on int[] should execute successfully: {}", result.unwrap_err());
}

#[test]
fn runtime_split_index_produces_dynamic_array_parts() {
    let source = r#"
        contract SplitDynamicIndex() {
            entry main(int[] values, int n) {
                (int[] left, int[] right) = values.split(n);
                require(left.length == 2);
                require(left[0] == 10);
                require(left[1] == 20);
                require(right.length == 2);
                require(right[0] == 30);
                require(right[1] == 40);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("runtime split index should produce dynamic parts");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[vec![10i64, 20, 30, 40].into(), ArtifactValue::Int(2)])
        .expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "runtime-index split should execute successfully: {result:?}");
}

#[test]
fn constant_split_index_produces_dynamic_parts_for_dynamic_source() {
    let source = r#"
        contract SplitConstantIndex() {
            int constant N = 2;

            entry main(int[] values) {
                (int[] left, int[] right) = values.split(N);
                require(left.length == 2);
                require(left[0] == 10);
                require(left[1] == 20);
                require(right.length == 2);
                require(right[0] == 30);
                require(right[1] == 40);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[], CompileOptions::default()).expect("constant split index should preserve dynamic parts");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[vec![10i64, 20, 30, 40].into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "constant-index split of a dynamic source should execute successfully: {result:?}");
}

#[test]
fn constant_split_index_produces_dynamic_parts_for_fixed_source() {
    let source = r#"
        contract SplitFixedSource() {
            int constant N = 1;

            entry main() {
                int[4] values = int[4]{10, 20, 30, 40};
                int[] left = values.split(N).0;
                int[] right = values.split(N).1;
                require(left.length == 1);
                require(left[0] == 10);
                require(right.length == 3);
                require(right[0] == 20);
                require(right[1] == 30);
                require(right[2] == 40);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("fixed source split should return dynamic parts");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "constant-index split of a fixed source should execute successfully: {result:?}");
}

#[test]
fn rejects_constant_split_indices_outside_sequence_bounds() {
    let cases = [
        ("dynamic array negative index", "contract C() { entry main(int[] value) { int[] part = value.split(-1).0; } }"),
        ("fixed array index beyond end", "contract C() { entry main(int[4] value) { int[] part = value.split(5).1; } }"),
        ("pubkey index beyond end", "contract C() { entry main(pubkey value) { byte[] part = value.split(33).0; } }"),
        ("sig index beyond end", "contract C() { entry main(sig value) { byte[] part = value.split(66).1; } }"),
        ("datasig index beyond end", "contract C() { entry main(datasig value) { byte[] part = value.split(65).0; } }"),
    ];

    for (case, source) in cases {
        let error = compile_contract(source, &[], CompileOptions::default()).expect_err(case);
        assert!(error.to_string().contains("out of bounds"), "unexpected error for {case}: {error}");
    }
}

#[test]
fn allows_constant_split_indices_at_sequence_end() {
    let source = r#"
        contract SplitBoundary() {
            entry main(int[4] values, pubkey publicKey, sig signature, datasig dataSignature) {
                int[] arrayTail = values.split(4).1;
                byte[] pubkeyTail = publicKey.split(32).1;
                byte[] sigTail = signature.split(65).1;
                byte[] datasigTail = dataSignature.split(64).1;
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("splitting at a sequence's end should compile");
}

#[test]
fn rejects_split_bindings_that_do_not_match_inferred_part_types() {
    let runtime_index = r#"
        contract SplitRuntimeMismatch() {
            entry main(int[] values, int n) {
                (int[1] left, int[] right) = values.split(n);
            }
        }
    "#;
    let err = compile_contract(runtime_index, &[], CompileOptions::default())
        .expect_err("a runtime split index must not produce a fixed-size binding");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");

    let fixed_source = r#"
        contract SplitFixedMismatch() {
            entry main() {
                int[4] values = int[4]{10, 20, 30, 40};
                (int[2] left, int[1] right) = values.split(2);
            }
        }
    "#;
    let err = compile_contract(fixed_source, &[], CompileOptions::default())
        .expect_err("both fixed split bindings must match their inferred sizes");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
fn rejects_split_tuple_bindings_with_different_element_types() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract C() {
            entry f(byte[4] data) {
                (int a, int b) = data.split(2);
                require(a == 1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("byte array split parts must not be reinterpreted as integers");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
fn rejects_split_tuple_bindings_with_incorrect_fixed_sizes() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract C() {
            entry f(byte[4] data) {
                (byte[3] p, byte[1] q) = data.split(2);
                require(p.length == 3);
            }
        }
    "#;

    let err =
        compile_contract(source, &[], CompileOptions::default()).expect_err("split bindings must use the actual inferred part sizes");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
fn runs_slice_on_non_byte_array() {
    let source = r#"
        contract SliceNonByteArray() {
            entry main() {
                int[] values = int[]{10, 20, 30, 40};
                int[] part = values.slice(1, 3);
                require(part.length == 2);
                require(part[0] == 20);
                require(part[1] == 30);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("slice on int[] should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "slice on int[] should execute successfully: {}", result.unwrap_err());
}

#[test]
fn runs_split_and_slice_on_struct_array() {
    let source = r#"
        contract StructArraySequenceOperations() {
            struct S {
                int number;
                byte[2] tag;
            }

            entry main() {
                S[] values = S[]{
                    S {number: 10, tag: byte[_](0x0102)},
                    S {number: 20, tag: byte[_](0x0304)},
                    S {number: 30, tag: byte[_](0x0506)}
                };
                S[] left = values.split(1).0;
                S[] right = values.split(1).1;
                S[] part = values.slice(1, 3);

                require(left.length == 1);
                require(left[0].number == 10);
                require(left[0].tag == byte[_](0x0102));
                require(right.length == 2);
                require(right[0].number == 20);
                require(right[0].tag == byte[_](0x0304));
                require(right[1].number == 30);
                require(right[1].tag == byte[_](0x0506));
                require(part.length == 2);
                require(part[0].number == 20);
                require(part[0].tag == byte[_](0x0304));
                require(part[1].number == 30);
                require(part[1].tag == byte[_](0x0506));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("struct array sequence operations should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "struct array sequence operations should execute successfully: {}", result.unwrap_err());
}

#[test]
fn rejects_struct_array_equality_and_inequality_comparisons() {
    for operator in ["==", "!="] {
        let source = format!(
            r#"
                contract StructArrayComparisons() {{
                    struct Item {{ int id; byte[2] tag; }}
                    entry main(Item[] values) {{
                        require(values {operator} values);
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("struct-array comparison should fail");
        assert!(err.to_string().contains("array comparison is only supported"), "unexpected error: {err}");
    }
}

#[test]
fn rejects_struct_array_comparisons_with_structured_expressions_on_either_side() {
    for comparison in ["S[]{S {value: 7}} == values", "values == S[]{S {value: 7}}"] {
        let source = format!(
            r#"
                contract StructArrayComparisonSymmetry() {{
                    struct S {{ int value; }}
                    entry main(S[] values) {{
                        require({comparison});
                    }}
                }}
            "#
        );
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("struct-array comparison should fail");
        assert!(err.to_string().contains("array comparison is only supported"), "unexpected error: {err}");
    }
}

#[test]
fn scalar_struct_values_can_be_compared_directly() {
    let source = r#"
        contract StructEquality() {
            struct Item {
                int number;
                byte tag;
            }

            entry main() {
                Item left = Item {number: 7, tag: byte(1)};
                Item same = Item {number: 7, tag: byte(1)};
                Item different = Item {number: 8, tag: byte(2)};

                // Identifier to identifier.
                require(left == same);
                require(left != different);

                // Literal to literal.
                require(Item {number: 7, tag: byte(1)} == Item {number: 7, tag: byte(1)});
                require(Item {number: 7, tag: byte(1)} != Item {number: 8, tag: byte(2)});

                // Identifier to literal, in both directions.
                require(left == Item {number: 7, tag: byte(1)});
                require(Item {number: 7, tag: byte(1)} == left);
                require(left != Item {number: 8, tag: byte(2)});
                require(Item {number: 8, tag: byte(2)} != left);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("scalar struct comparisons should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "scalar struct comparisons should execute successfully: {result:?}");
}

#[test]
fn rejects_scalar_struct_comparison_with_non_comparable_fields() {
    let source = r#"
        contract StructEquality() {
            struct Item { int[] values; }

            entry main(Item left, Item right) {
                require(left == right);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("whole-struct comparison must preserve the comparison rules of each field");
    assert!(err.to_string().contains("struct comparison is not supported for field type int[]"), "unexpected error: {err}");
}

#[test]
fn allows_sequence_operations_on_string_and_fixed_byte_types() {
    let source = r#"
        contract ByteSequenceOperations() {
            entry main(string text, pubkey publicKey, sig signature, datasig dataSignature) {
                (string textLeft, string textRight) = text.split(1);
                (byte[] pubkeyLeft, byte[] pubkeyRight) = publicKey.split(1);
                (byte[] sigLeft, byte[] sigRight) = signature.split(1);
                (byte[] datasigLeft, byte[] datasigRight) = dataSignature.split(1);
                string textSlice = text.slice(0, 1);
                byte[] pubkeySlice = publicKey.slice(0, 1);
                byte[] sigSlice = signature.slice(0, 1);
                byte[] datasigSlice = dataSignature.slice(0, 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("sequence operations should accept strings and fixed-byte types");
}

#[test]
fn runtime_split_index_produces_dynamic_parts_for_fixed_byte_types() {
    let source = r#"
        contract RuntimeFixedByteSequenceSplit() {
            entry main(pubkey publicKey, sig signature, datasig dataSignature, int n) {
                (byte[] pubkeyLeft, byte[] pubkeyRight) = publicKey.split(n);
                (byte[] sigLeft, byte[] sigRight) = signature.split(n);
                (byte[] datasigLeft, byte[] datasigRight) = dataSignature.split(n);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("runtime split indices should produce dynamic parts for fixed-byte types");
}

#[test]
fn fixed_byte_split_parts_are_dynamic_arrays() {
    let source = r#"
        contract InferredFixedByteSequenceSplit() {
            entry main(pubkey publicKey) {
                byte[] left = publicKey.split(4).0;
                byte[] right = publicKey.split(4).1;
                require(left.length == 4);
                require(right.length == 28);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("fixed-byte split results should be dynamic byte arrays");
}

#[test]
fn inferred_tuple_split_binding_is_dynamic() {
    let source = r#"
        contract InferredTupleSplitBinding() {
            entry main(byte[] values) {
                (byte[] left, byte[] right) = values.split(4);
                require(left.length == 4);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default()).expect("tuple split bindings should use dynamic arrays");
}

#[test]
fn rejects_fixed_bindings_for_dynamic_split_parts() {
    let source = r#"
        contract FixedByteSequenceSplitMismatch() {
            entry main(pubkey publicKey) {
                (byte[1] left, byte[31] right) = publicKey.split(1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("split parts are dynamic even when their runtime sizes are known");
    assert!(err.to_string().contains("type mismatch"), "unexpected error: {err}");
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_standalone_block_function_result_binding_shadowing() {
    let source = r#"
        contract FunctionResultBlockShadowing() {
            function pair() : (int, int) {
                return(1, 2);
            }

            entry main() {
                int x = 3;
                {
                    (int x, int y) = pair();
                    require(x == 1);
                    require(y == 2);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("function result binding shadowing should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "function result binding shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_standalone_block_state_binding_shadowing() {
    let source = r#"
        contract StateBindingBlockShadowing(int initialValue) {
            int value = initialValue;

            entry main() {
                int x = 3;
                {
                    State {value: int x} = readInputState(this.activeInputIndex);
                    require(x == 7);
                }
                require(x == 3);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[ArtifactValue::Int(7)], CompileOptions::default()).expect("state binding shadowing should compile");
    let sigscript = encode_single_entry_sig_script(&input_compiled, &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "state binding shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn runs_standalone_block_struct_destructure_binding_shadowing() {
    let source = r#"
        contract StructBindingBlockShadowing() {
            struct S {
                int value;
            }

            entry main() {
                int x = 3;
                S s = S {value: 1};
                {
                    S {value: int x} = s;
                    require(x == 1);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[], CompileOptions::default()).expect("struct destructure binding shadowing should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "struct destructure binding shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn branch_shadowing_initializer_reads_outer_binding() {
    let source = r#"
        contract BranchInitializerShadowing() {
            entry main(bool cond) {
                int x = 3;
                if (cond) {
                    int x = x + 1;
                    require(x == 4);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[], CompileOptions::default()).expect("branch shadowing initializer should read the outer binding");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(true)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "branch shadowing initializer should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn branch_reference_before_shadowing_declaration_reads_outer_binding() {
    let source = r#"
        contract BranchReferenceBeforeShadowing() {
            entry main(bool cond) {
                int x = 3;
                if (cond) {
                    require(x == 3);
                    int x = 1;
                    require(x == 1);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default())
        .expect("a branch reference before a shadowing declaration should read the outer binding");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Bool(true)]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "branch reference before shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn for_loop_shadowing_initializer_reads_outer_binding() {
    let source = r#"
        contract LoopInitializerShadowing() {
            entry main() {
                int x = 3;
                for (i, 0, 2, 2) {
                    int x = x + i;
                    require(x == 3 + i);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[], CompileOptions::default()).expect("loop shadowing initializer should read the outer binding");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "loop shadowing initializer should execute successfully: {}", result.unwrap_err());
}

#[test]
#[ignore = "TODO: Re-enable once shadowing is enabled"]
fn for_loop_reference_before_shadowing_declaration_reads_outer_binding() {
    let source = r#"
        contract LoopReferenceBeforeShadowing() {
            entry main() {
                int x = 3;
                for (i, 0, 2, 2) {
                    require(x == 3);
                    int x = i + 1;
                    require(x == i + 1);
                }
                require(x == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default())
        .expect("a loop reference before a shadowing declaration should read the outer binding");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "loop reference before shadowing should execute successfully: {}", result.unwrap_err());
}

#[test]
fn rejects_using_block_local_outside_its_scope() {
    let source = r#"
        contract BlockScope() {
            entry main() {
                {
                    int x = 1;
                    require(x == 1);
                }
                require(x > 0);
            }
        }
    "#;

    let err =
        compile_contract(source, &[], CompileOptions::default()).expect_err("block-local x should not be visible after the block");
    assert!(err.to_string().contains("undefined identifier"), "unexpected error: {err}");
}

#[test]
fn runs_standalone_block_and_preserves_outer_scope() {
    let source = r#"
        contract BlockRuntime() {
            entry main(int x) {
                int y = x + 1;
                {
                    int z = y + 1;
                    require(z == x + 2);
                }
                require(y == x + 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "standalone block should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(8)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_ok(), "outer scope should remain valid after the block: {}", result_err.unwrap_err());
}

#[test]
fn inline_nested_argument_expression_is_stored_once_and_reused() {
    let source = r#"
        contract InlineCallRepeat() {
            function f(int y) {
                require(y > 10);
                require(y < 100);
            }

            entry main(int x) {
                f((x + 1) * (x + 2));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline nested arg should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        2,
        "the inline nested argument should compute each addition once and reuse the stored result"
    );
    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the inline nested argument should multiply once and reuse the stored result"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(5)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored inline nested argument should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(10)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored inline nested argument should still enforce the second require");
}

#[test]
fn function_call_assignment_result_is_stored_once_and_reused() {
    let source = r#"
        contract CallAssignRepeat() {
            function g(int x) : (int) {
                require(x > 0);
                return(x - 17);
            }

            function f(int x) : (int) {
                require(x > 17);
                (int base) = g(x);
                int shifted = base + 2;
                return(shifted * 2);
            }

            entry main(int x) {
                (int y) = f(x);
                require(y > 1);
                require(y < 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("function-call assignment should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpSub).count(),
        1,
        "the nested g(x) return calculation should be computed once and the assigned local reused"
    );
    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the extra arithmetic in f(x) should be computed once and the assigned local reused"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(19)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored function-call assignment result should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(29)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored function-call assignment result should still enforce the second require");
}

#[test]
fn struct_return_field_is_stored_once_and_reused() {
    let source = r#"
        contract StructFieldRepeat() {
            struct S {
                int a;
                int b;
            }

            function f(int x) : (S) {
                return(S {
                    a: x + 1,
                    b: x * x,
                });
            }

            entry main(int x) {
                (S s) = f(x);
                require(s.a < 10);
                require(s.b < 20);
                require(s.a > 1);
                require(s.b > 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("struct-return local should compile");

    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "s.a should be computed once and reused across both require statements"
    );
    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "s.b should be computed once and reused across both require statements"
    );

    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(3)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored struct fields should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(10)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "stored struct fields should still enforce the require conditions");
}

#[test]
fn compile_time_if_branch_stores_local_var_once_and_reuses_it() {
    let source = r#"
        contract IfRepeat() {

            entry main(int x) {
                if (1 < 2) {
                    int a = x + 1;
                    require(a < 10);
                    require(a > 1);
                } else {
                    require(false);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let opcodes = stateless_single_dispatch_body_opcodes(&compiled, "main");
    let if_pos = opcodes.iter().position(|op| *op == OpIf).expect("if present");
    let else_pos = opcodes.iter().position(|op| *op == OpElse).expect("else present");
    let endif_pos = opcodes.iter().position(|op| *op == OpEndIf).expect("endif present");
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpOver).count(), 0);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpPick).count(), 0);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpAdd).count(), 1);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDrop).count(), 1);
    assert_eq!(opcodes[endif_pos + 1..].iter().copied().filter(|op| *op == OpDrop).count(), 1);
    assert_eq!(opcodes[endif_pos + 1..].iter().copied().filter(|op| *op == OpRoll).count(), 0);
}

#[test]
fn compile_time_if_branch_stores_struct_fields_once_and_reuses_them() {
    let source = r#"
        contract IfStructRepeat() {
            struct S {
                int a;
                int b;
            }

            entry main(int x) {
                if (1 < 2) {
                    S s = S { a: x + 1, b: x * x };
                    require(s.a < 10);
                    require(s.b < 20);
                    require(s.a > 1);
                    require(s.b > 2);
                } else {
                    require(false);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let opcodes = stateless_single_dispatch_body_opcodes(&compiled, "main");

    assert_eq!(
        opcodes.iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "s.a should be computed once and reused across both require statements"
    );
    assert_eq!(
        opcodes.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "s.b should be computed once and reused across both require statements"
    );

    let if_pos = opcodes.iter().position(|op| *op == OpIf).expect("if present");
    let else_pos = opcodes.iter().position(|op| *op == OpElse).expect("else present");
    let endif_pos = opcodes.iter().position(|op| *op == OpEndIf).expect("endif present");
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpOver).count(), 3);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpPick).count(), 1);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpAdd).count(), 1);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpMul).count(), 1);
    assert_eq!(opcodes[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDrop).count(), 2);
    assert_eq!(opcodes[endif_pos + 1..].iter().copied().filter(|op| *op == OpDrop).count(), 1);
    assert_eq!(opcodes[endif_pos + 1..].iter().copied().filter(|op| *op == OpRoll).count(), 0);
}

#[test]
fn struct_reassignment_snapshots_all_fields_before_rebinding() {
    let source = r#"
        contract C() {
            struct S { int a; int b; }

            entry main() {
                S s = S {a: 10, b: 20};
                s = S {a: s.b, b: s.a};
                require(s.a == 20);
                require(s.b == 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("struct field swap should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "struct field swap should execute atomically: {result:?}");
}

#[test]
fn nested_struct_reassignment_snapshots_all_leaves_before_rebinding() {
    let source = r#"
        contract C() {
            struct Inner { int x; int y; }
            struct Outer { Inner inner; int z; }

            entry main() {
                Outer value = Outer {inner: Inner {x: 1, y: 2}, z: 3};
                value = Outer {inner: Inner {x: value.inner.y, y: value.z}, z: value.inner.x};
                require(value.inner.x == 2);
                require(value.inner.y == 3);
                require(value.z == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested struct rotation should compile");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "nested struct rotation should execute atomically: {result:?}");
}

#[test]
fn struct_array_self_append_snapshots_all_leaf_expressions_before_rebinding() {
    let source = r#"
        contract C() {
            struct S { int a; int b; }

            entry main(S[] values) {
                values = values.append(S {a: values.length, b: values.length});
                require(values.length == 2);
                require(values[1].a == 1);
                require(values[1].b == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("struct array append should compile");
    let argument = ArtifactValue::Array(vec![artifact_object([("a", 7.into()), ("b", 8.into())])]);
    let sigscript = encode_single_entry_sig_script(&compiled, &[argument]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "struct array leaf expressions should observe the pre-append value: {result:?}");
}

#[test]
fn partially_reassigned_struct_field_does_not_recompute_unchanged_fields() {
    let source = r#"
        contract ConsumePartialStructField() {
            struct S {
                int a;
                int b;
            }

            entry main(int x) {
                S s = S {a: x + 1, b: x * x};
                s = S {a: s.a + 1, b: s.b};
                require(s.a > 0);
                require(s.b > 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("partial struct reassignment should compile");
    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the unchanged field should keep using its original expression instead of being copied into a new stack slot"
    );
    assert_eq!(
        bytecode(&compiled).iter().copied().filter(|op| *op == OpAdd).count(),
        2,
        "only the initial `s.a = x + 1` and the reassigned `s.a = s.a + 1` should emit additions"
    );
    let sigscript_ok = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(2)]).expect("sigscript builds");
    let result_ok = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "partial struct reassignment should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = encode_single_entry_sig_script(&compiled, &[ArtifactValue::Int(0)]).expect("sigscript builds");
    let result_err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_err);
    assert!(result_err.is_err(), "partial struct reassignment should still enforce the updated field checks");
}

#[test]
fn if_branch_reassignment_drops_hidden_shadow_bindings() {
    let source = r#"
        contract BranchShadowCleanup() {
            entry main(int flag, int a, int b, int expected) {
                int d = a + b;
                d = d - a;
                if (flag > 0) {
                    int c = d + b;
                    d = a + c;
                } else {
                    d = d + a;
                }
                require(d == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("if branch reassignment should compile");

    let sigscript_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Int(1), ArtifactValue::Int(1), ArtifactValue::Int(1), ArtifactValue::Int(3)],
    )
    .expect("sigscript builds");
    let result_then = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_then);
    assert!(result_then.is_ok(), "then-branch reassignment should leave a clean stack: {}", result_then.unwrap_err());

    let sigscript_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Int(0), ArtifactValue::Int(1), ArtifactValue::Int(1), ArtifactValue::Int(2)],
    )
    .expect("sigscript builds");
    let result_else = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_else);
    assert!(result_else.is_ok(), "else-branch reassignment should leave a clean stack: {}", result_else.unwrap_err());
}

#[test]
fn struct_if_reassignment_preserves_types_after_merge() {
    let source = r#"
        contract StructMergeTypes() {
            struct S {
                int a;
                int b;
            }

            function verify_pair(S value, int expected_a, int expected_b) {
                require(value.a == expected_a);
                require(value.b == expected_b);
            }

            entry main(int flag, int expected_a, int expected_b) {
                S s = S {a: 2, b: 3};
                if (flag > 0) {
                    s = S {a: s.a + 1, b: s.b + 1};
                } else {
                    s = S {a: s.a + 2, b: s.b + 2};
                }
                S t = s;
                verify_pair(t, expected_a, expected_b);
            }
        }
    "#;

    let compiled =
        compile_internal_contract(source, &[], CompileOptions::default()).expect("post-if struct type merge should compile");
    let normalized = format_contract_ast(&compiled.ast);
    assert!(normalized.contains("S t = s;"), "merged struct type should still allow assignment after the if: {normalized}");
}

#[test]
fn partial_struct_if_reassignment_preserves_types_after_merge() {
    let source = r#"
        contract PartialStructMergeTypes() {
            struct S {
                int a;
                int b;
            }

            function verify_pair(S value, int expected_a, int expected_b) {
                require(value.a == expected_a);
                require(value.b == expected_b);
            }

            entry main(int flag, int expected_a, int expected_b) {
                S s = S {a: 2, b: 3};
                if (flag > 0) {
                    s = S {a: s.a + 1, b: s.b};
                } else {
                    s = S {a: s.a, b: s.b + 2};
                }
                S t = s;
                verify_pair(t, expected_a, expected_b);
            }
        }
    "#;

    let compiled =
        compile_internal_contract(source, &[], CompileOptions::default()).expect("post-if partial struct type merge should compile");
    let normalized = format_contract_ast(&compiled.ast);
    assert!(normalized.contains("S t = s;"), "merged struct type should still allow assignment after the if: {normalized}");
}

#[test]
fn struct_if_branch_reassignment_drops_hidden_shadow_bindings() {
    let source = r#"
        contract StructBranchCleanup() {
            struct S {
                int a;
                int b;
            }

            entry main(int flag, int x, int y, int expected_a, int expected_b) {
                S s = S {a: x, b: y};
                if (flag > 0) {
                    S t = S {a: s.a + 1, b: s.b + 2};
                    s = S {a: t.a + y, b: t.b + x};
                } else {
                    S t = S {a: s.a + x, b: s.b + y};
                    s = S {a: t.a + 1, b: t.b + 1};
                }
                require(s.a == expected_a);
                require(s.b == expected_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("struct branch cleanup should compile");

    let sigscript_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Int(1), ArtifactValue::Int(2), ArtifactValue::Int(3), ArtifactValue::Int(6), ArtifactValue::Int(7)],
    )
    .expect("sigscript builds");
    let result_then = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_then);
    assert!(result_then.is_ok(), "then-branch struct cleanup should leave a clean stack: {}", result_then.unwrap_err());

    let sigscript_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Int(0), ArtifactValue::Int(2), ArtifactValue::Int(3), ArtifactValue::Int(5), ArtifactValue::Int(7)],
    )
    .expect("sigscript builds");
    let result_else = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_else);
    assert!(result_else.is_ok(), "else-branch struct cleanup should leave a clean stack: {}", result_else.unwrap_err());
}

#[test]
fn partial_struct_if_branch_reassignment_drops_hidden_shadow_bindings() {
    let source = r#"
        contract PartialStructBranchCleanup() {
            struct S {
                int a;
                int b;
            }

            entry main(int flag, int x, int y, int expected_a, int expected_b) {
                S s = S {a: x, b: y};
                if (flag > 0) {
                    S t = S {a: s.a + 1, b: s.b};
                    s = S {a: t.a + y, b: s.b};
                } else {
                    S t = S {a: s.a, b: s.b + y};
                    s = S {a: s.a, b: t.b + x};
                }
                require(s.a == expected_a);
                require(s.b == expected_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("partial struct branch cleanup should compile");

    let sigscript_then = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Int(1), ArtifactValue::Int(2), ArtifactValue::Int(3), ArtifactValue::Int(6), ArtifactValue::Int(3)],
    )
    .expect("sigscript builds");
    let result_then = run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript_then);
    assert!(result_then.is_ok(), "then-branch partial struct cleanup should leave a clean stack: {}", result_then.unwrap_err());

    let sigscript_else = encode_entry_sig_script(
        &compiled,
        "main",
        &[ArtifactValue::Int(0), ArtifactValue::Int(2), ArtifactValue::Int(3), ArtifactValue::Int(2), ArtifactValue::Int(8)],
    )
    .expect("sigscript builds");
    let result_else = run_bytecode_with_sigscript(bytecode(&compiled), sigscript_else);
    assert!(result_else.is_ok(), "else-branch partial struct cleanup should leave a clean stack: {}", result_else.unwrap_err());
}

#[test]
fn conditional_counter_in_unrolled_loop_stays_linear() {
    const SOURCE: &str = r#"
pragma silverscript ^0.1.0;

contract CounterLoop(int BOUND) {
    entry main() {
        int count = 0;
        for (i, 0, BOUND, BOUND) {
            if (true) {
                count = count + 1;
            }
        }
        require(count >= 0);
    }
}
"#;

    let bounds = [4i64, 8i64, 12i64];
    let mut lens = Vec::new();
    for b in bounds {
        let args = [b.into()];
        let compiled = compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile succeeds");
        lens.push(bytecode(&compiled).len());
    }

    assert!(lens[0] < lens[1] && lens[1] < lens[2], "expected monotonic growth, got {lens:?}");
    let d1 = lens[1] - lens[0];
    let d2 = lens[2] - lens[1];

    assert!(d2 <= d1 * 2, "unexpected superlinear growth: lens={lens:?} d1={d1} d2={d2}");
    assert!(lens[2] < 5_000, "unexpected script size: lens={lens:?}");
}

#[test]
fn struct_conditional_counter_in_unrolled_loop_stays_linear() {
    const SOURCE: &str = r#"
pragma silverscript ^0.1.0;

contract StructCounterLoop(int BOUND) {
    struct S {
        int a;
        int b;
    }

    entry main() {
        S s = S {a: 0, b: 0};
        for (i, 0, BOUND, BOUND) {
            if (true) {
                s = S {a: s.a + 1, b: s.b + 1};
            }
        }
        require(s.a >= 0);
        require(s.b >= 0);
    }
}
"#;

    let bounds = [4i64, 8i64, 12i64];
    let mut lens = Vec::new();
    for b in bounds {
        let args = [b.into()];
        let compiled = compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile succeeds");
        lens.push(bytecode(&compiled).len());
    }

    assert!(lens[0] < lens[1] && lens[1] < lens[2], "expected monotonic growth, got {lens:?}");
    let d1 = lens[1] - lens[0];
    let d2 = lens[2] - lens[1];

    assert!(d2 <= d1 * 2, "unexpected superlinear growth: lens={lens:?} d1={d1} d2={d2}");
    assert!(lens[2] < 10_000, "unexpected script size: lens={lens:?}");
}

#[test]
fn validate_output_state_preserves_nested_struct_field_paths() {
    let source = r#"
        contract M(int initLeft, int initRight) {
            struct Left {
                int id;
            }

            struct Right {
                int id;
            }

            Left left = Left {id: initLeft};
            Right right = Right {id: initRight};

            entry route() {
                State next = State {
                    left: Left {id: 3},
                    right: Right {id: 4}
                };
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[1.into(), 2.into()], CompileOptions::default()).expect("compile succeeds");
    let output_compiled = compile_contract(source, &[3.into(), 4.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "route", &[]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "nested state fields with the same leaf name should remain distinct by path: {result:?}");
}

#[test]
fn validate_output_state_with_template_preserves_nested_struct_field_paths() {
    let target_hash = vec![0x44u8; 32];
    let target_hash_hex = target_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let target_source = format!(
        r#"
        contract Target(byte[32] initTargetHash, int initLeft, int initRight) {{
            struct Left {{
                int id;
            }}

            struct Right {{
                int id;
            }}

            Left left = Left {{id: initLeft}};
            Right right = Right {{id: initRight}};
            byte[32] targetHash = initTargetHash;

            entry noop() {{
                require(left.id == 1);
                require(right.id == 2);
                require(targetHash == byte[32](0x{target_hash_hex}));
            }}
        }}
    "#
    );

    let target_template_compiled =
        compile_contract(&target_source, &[vec![0x33u8; 32].into(), 0.into(), 0.into()], CompileOptions::default())
            .expect("compile target template succeeds");
    let (template_prefix, template_suffix, template_hash) = compiled_template_parts_and_hash(&target_template_compiled);
    let template_prefix_hex = template_prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let template_suffix_hex = template_suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let template_hash_hex = template_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let target_output_compiled =
        compile_contract(&target_source, &[target_hash.clone().into(), 1.into(), 2.into()], CompileOptions::default())
            .expect("compile target output succeeds");

    let source = format!(
        r#"
        contract M() {{
            struct Left {{
                int id;
            }}

            struct Right {{
                int id;
            }}

            struct Pair {{
                Left left;
                Right right;
                byte[32] targetHash;
            }}

            entry route(byte[32] targetHash) {{
                Pair next = Pair {{
                    left: Left {{id: 1}},
                    right: Right {{id: 2}},
                    targetHash: targetHash
                }};
                validateOutputStateWithTemplate(
                    0,
                    next,
                    byte[](0x{template_prefix_hex}),
                    byte[](0x{template_suffix_hex}),
                    byte[32](0x{template_hash_hex})
                );
                validateOutputStateWithInputTemplate(
                    0,
                    next,
                    1,
                    {},
                    {},
                    byte[32](0x{template_hash_hex})
                );
            }}
        }}
    "#,
        template_prefix.len(),
        template_suffix.len(),
    );

    let input_compiled = compile_contract(&source, &[], CompileOptions::default()).expect("compile router succeeds");
    let sigscript = encode_entry_sig_script(&input_compiled, "route", &[target_hash.into()]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(bytecode(&input_compiled).clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let template_input = test_input(1, sigscript_push_bytecode(&bytecode(&target_template_compiled)));
    let input_spk = pay_to_script_hash_script(&bytecode(&input_compiled));
    let output_spk = pay_to_script_hash_script(&bytecode(&target_output_compiled));
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input, template_input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);
    let template_utxo =
        UtxoEntry::new(output.value, pay_to_script_hash_script(&bytecode(&target_template_compiled)), 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry, template_utxo], 0);
    assert!(result.is_ok(), "nested struct fields with the same leaf name should remain distinct by path: {result:?}");
}

#[test]
fn blake2b_builtins_lower_and_execute_correctly() {
    let data = b"genesis covenant";
    let key = b"CovenantID";
    let expected = blake2b_simd::Params::new().hash_length(32).hash(data);
    let expected_keyed = blake2b_simd::Params::new().hash_length(32).key(key).hash(data);
    let expected_hex = expected.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let expected_keyed_hex = expected_keyed.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let source = format!(
        r#"
        contract Blake2bHashes() {{
            entry main() {{
                require(blake2b(byte[]("genesis covenant")) == byte[32](0x{expected_hex}));
                require(blake2bWithKey(byte[]("genesis covenant"), byte[]("CovenantID")) == byte[32](0x{expected_keyed_hex}));
            }}
        }}
        "#
    );

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("Blake2b builtins compile");
    assert!(bytecode(&compiled).contains(&OpBlake2b));
    assert!(bytecode(&compiled).contains(&OpBlake2bWithKey));
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "Blake2b builtins should execute correctly: {result:?}");
}

#[test]
fn blake3_builtins_lower_and_execute_correctly() {
    let data = b"genesis covenant";
    let key = std::array::from_fn(|i| i as u8);
    let expected = blake3::hash(data);
    let expected_keyed = blake3::keyed_hash(&key, data);
    let key_hex = key.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let expected_hex = expected.to_hex();
    let expected_keyed_hex = expected_keyed.to_hex();
    let source = format!(
        r#"
        contract Blake3Hashes() {{
            entry main() {{
                require(blake3(byte[]("genesis covenant")) == byte[32](0x{expected_hex}));
                require(blake3WithKey(byte[]("genesis covenant"), byte[32](0x{key_hex})) == byte[32](0x{expected_keyed_hex}));
            }}
        }}
        "#
    );

    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("Blake3 builtins compile");
    assert!(bytecode(&compiled).contains(&OpBlake3));
    assert!(bytecode(&compiled).contains(&OpBlake3WithKey));
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "Blake3 builtins should call the engine correctly: {result:?}");
}

#[test]
fn blake3_with_key_requires_a_fixed_32_byte_key() {
    let dynamic_key = r#"
        contract Blake3Hash() {
            entry main(byte[] key) {
                require(blake3WithKey(byte[]("data"), key).length == 32);
            }
        }
    "#;
    let err = compile_contract(dynamic_key, &[], CompileOptions::default()).expect_err("dynamic Blake3 key should be rejected");
    assert!(err.to_string().contains("argument 'key' expects byte[32]"), "unexpected error: {err}");

    let explicit_cast = r#"
        contract Blake3Hash() {
            entry main(byte[] key) {
                require(blake3WithKey(byte[]("data"), byte[32](key)).length == 32);
            }
        }
    "#;
    compile_contract(explicit_cast, &[], CompileOptions::default()).expect("explicit byte[32] key cast should compile");

    let numeric_data = r#"
        contract Blake3Hash() {
            entry main(byte[32] key) {
                require(blake3WithKey(5, key).length == 32);
            }
        }
    "#;
    let err = compile_contract(numeric_data, &[], CompileOptions::default()).expect_err("numeric Blake3 data should be rejected");
    assert!(err.to_string().contains("argument 'data' expects byte[], got int"), "unexpected error: {err}");
}

#[test]
fn rejects_misaligned_dynamic_array_entrypoint_payload() {
    let source = r#"
        contract DynamicArrayAlignment() {
            entry main(int[] values) {
                require(values.length == 0);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("dynamic int array should compile");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode should stringify");
    assert!(opcodes.contains("OpMod"), "dynamic array validation should check payload alignment: {opcodes}");

    // Bypass build_sig_script to model an untrusted spender pushing one byte for
    // an int[] whose elements require eight bytes each.
    let sigscript =
        script_builder().add_data_with_push_opcode(&[1]).unwrap().add_data(&dispatch_tag_for(&compiled, "main")).unwrap().drain();
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_err(), "a dynamic int array payload must contain a whole number of elements");
}

#[test]
fn derived_dynamic_array_length_counts_elements() {
    let source = r#"
        contract DerivedArrayLength() {
            entry main(int[] values) {
                require(values.slice(0, 1).length == 1);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("dynamic int array slice should compile");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[vec![10i64, 20i64].into()]).expect("sigscript builds");
    let result = run_bytecode_with_sigscript(bytecode(&compiled), sigscript);
    assert!(result.is_ok(), "slice length should be measured in int elements, not encoded bytes: {result:?}");
}

#[test]
fn rejects_fixed_array_cast_with_incompatible_encoded_sizes() {
    let source = r#"
        contract ArrayCastRepresentation() {
            entry main() {
                byte[2] values = byte[2](int[2]{1, 2});
                require(values.length == 2);
            }
        }
    "#;
    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("casting two encoded ints to two bytes should be rejected");
    assert!(err.to_string().contains("cannot cast int[2] to byte[2]"), "unexpected error: {err}");
}

#[test]
fn allows_fixed_array_cast_with_compatible_encoded_size() {
    let source = r#"
        contract ArrayCastRepresentation() {
            entry main() {
                byte[16] values = byte[16](int[2]{1, 2});
                require(values[0] == 1);
                require(values[8] == 2);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default())
        .expect("fixed arrays with equal encoded sizes should be cast-compatible");
    let opcodes = script_to_str(&bytecode(&compiled)).expect("compiled bytecode should stringify");
    assert!(!opcodes.contains("OpNum2Bin"), "an equal-size array cast should remain a passthrough: {opcodes}");
    let dispatch_tag = dispatch_tag_for(&compiled, "main");
    let result = run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag);
    assert!(result.is_ok(), "the reinterpreted byte array should preserve the int payload bytes: {result:?}");
}

#[test]
fn array_casts_require_the_same_base_type() {
    let incompatible_element_source = r#"
        contract ArrayCastRepresentation() {
            entry main() {
                int[1] values = int[1](bool[8]{true, false, false, false, false, false, false, false});
                require(values.length == 1);
            }
        }
    "#;
    let err = compile_contract(incompatible_element_source, &[], CompileOptions::default())
        .expect_err("equal encoded size must not permit a bool-array to int-array cast");
    assert!(err.to_string().contains("cannot cast bool[8] to int[1]"), "unexpected error: {err}");
}

#[test]
fn allows_signature_array_dimension_casts_in_both_directions() {
    let source = r#"
        contract ArrayCastRepresentation() {
            entry main(sig[] dynamicSignatures, sig[1] fixedSignatures) {
                sig[1] refined = sig[1](dynamicSignatures);
                sig[] derefined = sig[](fixedSignatures);
                require(refined.length == 1);
                require(derefined.length == 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("same-base signature arrays may cast between dynamic and fixed dimensions");
}

#[test]
fn rejects_ordered_comparisons_for_non_numeric_operands() {
    for (type_name, left, right) in [("string", "\"aaaaaaaaa\"", "\"bbbbbbbbb\""), ("byte", "byte(0xff)", "byte(0x01)")] {
        for operator in ["<", "<=", ">", ">="] {
            let source = format!(
                r#"
                    contract OrderedComparison() {{
                        entry main() {{
                            require({left} {operator} {right});
                        }}
                    }}
                "#
            );
            let err = compile_contract(&source, &[], CompileOptions::default())
                .err()
                .unwrap_or_else(|| panic!("{type_name} operands for {operator} should be rejected"));
            assert!(
                err.to_string().contains("ordered comparison requires matching int or temporal operands"),
                "unexpected error for {operator}: {err}"
            );
        }
    }
}

#[test]
fn rejects_entrypoint_parameter_that_shadows_contract_field() {
    let source = r#"
        contract FieldParameterCollision() {
            int field = 5;

            entry spend(int field) {
                require(field == 7);
            }
        }
    "#;
    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("an entrypoint parameter must not shadow a contract field");
    assert!(err.to_string().contains("variable 'field' is already defined"), "unexpected error: {err}");
}

#[test]
fn rejects_duplicate_function_names() {
    for duplicate in [
        r#"
            entry spend() {
                require(true);
            }

            entry spend(int value) {
                require(value > 0);
            }
        "#,
        r#"
            function helper(int value) {
                require(value > 0);
            }

            function helper(bool value) {
                require(value);
            }

            entry spend() {
                require(true);
            }
        "#,
    ] {
        let source = format!("contract DuplicateFunctions() {{{duplicate}}}");
        let err = compile_contract(&source, &[], CompileOptions::default()).expect_err("duplicate function names should be rejected");
        assert!(err.to_string().contains("duplicate function name"), "unexpected error: {err}");
    }
}

#[test]
fn rejects_user_function_with_builtin_name() {
    let source = r#"
        pragma silverscript ^0.1.0;
        contract Test(int init_amount) {
            int amount = init_amount;

            function validateOutputState(int idx, State s) {
                require(idx == 12345);
            }

            entry main(int out_idx, int out_amount) {
                validateOutputState(out_idx, State { amount: out_amount });
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[ArtifactValue::Int(0)], CompileOptions::default())
        .expect_err("user-defined functions must not use builtin names");
    assert!(err.to_string().contains("function name 'validateOutputState' is reserved for a builtin"), "unexpected error: {err}");
    let span = err.span().expect("the reserved function name should be identified");
    assert_eq!(&source[span.start..span.end], "validateOutputState");
}

#[test]
fn rejects_builtin_names_for_variables() {
    let cases = [
        "contract T(int sha256) { entry main() { require(true); } }",
        "contract T() { int constant readInputState = 1; entry main() { require(true); } }",
        "contract T() { int OpTxGas = 1; entry main() { require(true); } }",
        "contract T() { entry main(int validateOutputState) { require(true); } }",
        "contract T() { entry main() { int ScriptPubKeyP2PK = 1; require(true); } }",
        "contract T() { entry main() { for (blake2b, 0, 1, 1) { require(true); } } }",
    ];

    for source in cases {
        let constructor_args = if source.contains("int sha256") { vec![0.into()] } else { vec![] };
        let err =
            compile_contract(source, &constructor_args, CompileOptions::default()).expect_err("variables must not use builtin names");
        assert!(err.to_string().contains("is reserved for a builtin"), "unexpected error for `{source}`: {err}");
    }
}

#[test]
fn rejects_duplicate_declaration_names() {
    let cases = [
        (
            "contract DuplicateCtor(int value, int value) { entry spend() { require(true); } }",
            vec![1.into(), 2.into()],
            vec![Expr::int(1), Expr::int(2)],
            "value",
            "duplicate contract parameter name 'value'",
        ),
        (
            "contract DuplicateEntry() { entry spend(int value, int value) { require(value == value); } }",
            vec![],
            vec![],
            "value",
            "duplicate parameter name 'value' in function 'spend'",
        ),
        (
            "contract DuplicateHelper() { function helper(int value, int value) { require(true); } entry spend() { require(true); } }",
            vec![],
            vec![],
            "value",
            "duplicate parameter name 'value' in function 'helper'",
        ),
        (
            "contract DuplicateConstant() { int constant VALUE = 1; int constant VALUE = 2; entry spend() { require(true); } }",
            vec![],
            vec![],
            "VALUE",
            "duplicate constant name 'VALUE'",
        ),
    ];

    for (source, constructor_args, ast_constructor_args, duplicate_name, expected_error) in cases {
        let source_error = compile_contract(source, &constructor_args, CompileOptions::default())
            .expect_err("source compilation must reject duplicate declarations");
        assert_eq!(source_error.root().to_string(), format!("unsupported feature: {expected_error}"));
        let span = source_error.span().expect("source error identifies the second declaration");
        assert_eq!(&source[span.start..span.end], duplicate_name);

        let ast = parse_contract_ast(source).expect("duplicate declarations remain representable in the public AST");
        let ast_error = compile_contract_ast(&ast, &ast_constructor_args, CompileOptions::default())
            .expect_err("public AST compilation must reject duplicate declarations");
        assert_eq!(ast_error.root().to_string(), source_error.root().to_string());
    }
}

#[derive(Clone, Debug)]
enum ConformancePureExpr {
    Int(i64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Eq(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConformanceValue {
    Int(i64),
    Bool(bool),
}

impl ConformancePureExpr {
    fn eval(&self) -> ConformanceValue {
        match self {
            Self::Int(value) => ConformanceValue::Int(*value),
            Self::Add(left, right) => ConformanceValue::Int(conformance_int(left.eval()) + conformance_int(right.eval())),
            Self::Sub(left, right) => ConformanceValue::Int(conformance_int(left.eval()) - conformance_int(right.eval())),
            Self::Mul(left, right) => ConformanceValue::Int(conformance_int(left.eval()) * conformance_int(right.eval())),
            Self::Eq(left, right) => ConformanceValue::Bool(left.eval() == right.eval()),
            Self::Lt(left, right) => ConformanceValue::Bool(conformance_int(left.eval()) < conformance_int(right.eval())),
            Self::And(left, right) => ConformanceValue::Bool(conformance_bool(left.eval()) && conformance_bool(right.eval())),
            Self::Or(left, right) => ConformanceValue::Bool(conformance_bool(left.eval()) || conformance_bool(right.eval())),
            Self::Not(value) => ConformanceValue::Bool(!conformance_bool(value.eval())),
        }
    }

    fn source(&self) -> String {
        match self {
            Self::Int(value) => value.to_string(),
            Self::Add(left, right) => format!("({} + {})", left.source(), right.source()),
            Self::Sub(left, right) => format!("({} - {})", left.source(), right.source()),
            Self::Mul(left, right) => format!("({} * {})", left.source(), right.source()),
            Self::Eq(left, right) => format!("({} == {})", left.source(), right.source()),
            Self::Lt(left, right) => format!("({} < {})", left.source(), right.source()),
            Self::And(left, right) => format!("({} && {})", left.source(), right.source()),
            Self::Or(left, right) => format!("({} || {})", left.source(), right.source()),
            Self::Not(value) => format!("!({})", value.source()),
        }
    }
}

fn conformance_int(value: ConformanceValue) -> i64 {
    match value {
        ConformanceValue::Int(value) => value,
        ConformanceValue::Bool(_) => panic!("generator produced an ill-typed integer expression"),
    }
}

fn conformance_bool(value: ConformanceValue) -> bool {
    match value {
        ConformanceValue::Bool(value) => value,
        ConformanceValue::Int(_) => panic!("generator produced an ill-typed boolean expression"),
    }
}

fn next_conformance_seed(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    *seed
}

fn generate_conformance_int(seed: &mut u64, depth: usize) -> ConformancePureExpr {
    if depth == 0 {
        return ConformancePureExpr::Int((next_conformance_seed(seed) % 17) as i64 - 8);
    }
    let left = Box::new(generate_conformance_int(seed, depth - 1));
    let right = Box::new(generate_conformance_int(seed, depth - 1));
    match next_conformance_seed(seed) % 3 {
        0 => ConformancePureExpr::Add(left, right),
        1 => ConformancePureExpr::Sub(left, right),
        _ => ConformancePureExpr::Mul(left, right),
    }
}

fn generate_conformance_bool(seed: &mut u64, depth: usize) -> ConformancePureExpr {
    if depth == 0 {
        let left = Box::new(generate_conformance_int(seed, 1));
        let right = Box::new(generate_conformance_int(seed, 1));
        return if next_conformance_seed(seed) & 1 == 0 {
            ConformancePureExpr::Eq(left, right)
        } else {
            ConformancePureExpr::Lt(left, right)
        };
    }
    match next_conformance_seed(seed) % 3 {
        0 => ConformancePureExpr::Not(Box::new(generate_conformance_bool(seed, depth - 1))),
        1 => ConformancePureExpr::And(
            Box::new(generate_conformance_bool(seed, depth - 1)),
            Box::new(generate_conformance_bool(seed, depth - 1)),
        ),
        _ => ConformancePureExpr::Or(
            Box::new(generate_conformance_bool(seed, depth - 1)),
            Box::new(generate_conformance_bool(seed, depth - 1)),
        ),
    }
}

fn compile_and_execute_conformance_assertion(assertion: &str) {
    let source = format!("contract Generated() {{ entry spend() {{ require({assertion}); }} }}");
    let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("generated well-typed program compiles");
    let dispatch_tag = dispatch_tag_for(&compiled, "spend");
    run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).expect("reference result agrees with local VM");
}

#[test]
fn bounded_reference_evaluator_matches_local_vm() {
    let mut seed = 0x05ee_dc0d_ed15_ca11_u64;
    for _case in 0..64 {
        let expr = generate_conformance_bool(&mut seed, 2);
        let expected = conformance_bool(expr.eval());
        compile_and_execute_conformance_assertion(&format!("{} == {expected}", expr.source()));
    }
}

#[test]
fn bounded_metamorphic_variants_preserve_behavior() {
    let variants = [
        "int alpha = 2 + 3; require(alpha == 5);",
        "int renamed = 2 + 3; require(renamed == 5);",
        "int alpha = 5; require(alpha == 5);",
        "int alpha = helper(2, 3); require(alpha == 5);",
        "int alpha = false ? (1 / 0) : 5; require(alpha == 5);",
    ];
    for body in variants {
        let helper = if body.contains("helper") { "function helper(int a, int b): int { return a + b; }" } else { "" };
        let source = format!("contract Meta() {{ {helper} entry spend() {{ {body} }} }}");
        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("metamorphic variant compiles");
        let dispatch_tag = dispatch_tag_for(&compiled, "spend");
        run_bytecode_with_dispatch_tag(bytecode(&compiled), dispatch_tag).expect("metamorphic variant executes");
    }
}

#[test]
fn formatting_and_ast_round_trip_preserve_artifact() {
    let source = "contract RoundTrip(int seed) { int state = seed; entry spend() { require(state == 4); } }";
    let args = [Expr::int(4)];
    let original = compile_contract(source, &[4.into()], CompileOptions::default()).expect("source compiles");
    let ast = parse_contract_ast(source).expect("source parses");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted source parses");
    let from_ast = compile_contract_ast(&reparsed, &args, CompileOptions::default()).expect("public AST path compiles");
    let from_ast_artifact = sil_abi_artifact_from_compiled(&from_ast, &args).expect("AST portable artifact builds");
    assert_eq!(bytecode(&original), from_ast.bytecode);
    let original_entries = &single_contract(&original).entries;
    let ast_entries = &single_contract(&from_ast_artifact).entries;
    assert_eq!(original_entries, ast_entries);
    assert_eq!(state_layout(&original), from_ast.state_layout);
}

#[test]
fn debug_recording_does_not_change_executable_artifact() {
    let source = "contract DebugInvariant() { entry spend() { int x = 2 + 3; require(x == 5); } }";
    let plain = compile_contract(source, &[], CompileOptions::default()).expect("plain compile");
    let debug = compile_contract(source, &[], CompileOptions { record_debug_infos: true, ..CompileOptions::default() })
        .expect("debug compile");
    assert_eq!(single_contract(&plain).entries, single_contract(&debug).entries);
    assert_eq!(state_layout(&plain), state_layout(&debug));
    let plain_internal = compile_internal_contract(source, &[], CompileOptions::default()).expect("plain internal compile");
    let debug_internal =
        compile_internal_contract(source, &[], CompileOptions { record_debug_infos: true, ..CompileOptions::default() })
            .expect("debug internal compile");
    assert!(plain_internal.debug_info.is_none());
    assert!(debug_internal.debug_info.is_some());
    let dispatch_tag = dispatch_tag_for(&plain, "spend");
    run_bytecode_with_dispatch_tag(bytecode(&plain), dispatch_tag).expect("plain artifact executes");
    let dispatch_tag = dispatch_tag_for(&debug, "spend");
    run_bytecode_with_dispatch_tag(bytecode(&debug), dispatch_tag).expect("debug artifact executes with equivalent semantics");
}

#[test]
fn public_ast_robustness_seeds_return_without_panicking() {
    let seeds = [
        r#"{"name":"NoFunctions","params":[],"constants":[],"functions":[]}"#,
        r#"{"name":"UnknownType","params":[],"constants":[],"functions":[{"name":"spend","params":[{"type_ref":{"base":"Missing"},"name":"x"}],"entrypoint":true,"body":[]}] }"#,
        r#"{"name":"BadReturn","params":[],"constants":[],"functions":[{"name":"spend","params":[],"entrypoint":true,"return_types":[{"base":"int"}],"body":[]}] }"#,
    ];
    for seed in seeds {
        let ast: ContractAst<'_> = serde_json::from_str(seed).expect("seed is valid public AST JSON");
        let outcome = catch_unwind(AssertUnwindSafe(|| compile_contract_ast(&ast, &[], CompileOptions::default())));
        assert!(outcome.is_ok(), "public AST compilation panicked for seed: {seed}");
    }
}

#[test]
fn entrypoint_abi_rejects_undeclared_record_types_even_when_unused() {
    let source = r#"
        contract UnknownRecordAbi() {
            entry main(Missing value) {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("every custom type published in the entrypoint ABI must resolve to a declared struct");
    assert!(err.to_string().contains("unknown type 'Missing' in function parameter"), "unexpected error: {err}");
}

#[test]
fn variable_definition_rejects_undeclared_type_even_when_unused() {
    let source = r#"
        contract UnknownLocalType() {
            entry main() {
                Missing value;
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("an unused local variable must still have a declared type");
    assert!(err.to_string().contains("unknown type 'Missing' in variable"), "unexpected error: {err}");
}

#[test]
fn dynamic_array_abi_rejects_zero_width_elements() {
    let cases = [
        r#"
            contract ZeroWidthArray() {
                entry main(byte[0][] values) {
                    require(true);
                }
            }
        "#,
        r#"
            contract ConstantZeroWidthArray() {
                int constant N = 0;

                entry main(byte[N][] values) {
                    require(true);
                }
            }
        "#,
        r#"
            contract ZeroWidthStructField() {
                struct Item {
                    byte[0] data;
                }

                entry main() {
                    require(true);
                }
            }
        "#,
        r#"
            contract InferredZeroWidthArray() {
                entry main() {
                    byte[_] values = byte[]{};
                    require(true);
                }
            }
        "#,
    ];

    for source in cases {
        let err = compile_contract(source, &[], CompileOptions::default())
            .expect_err("every fixed array dimension must be greater than zero");
        assert!(err.to_string().contains("must be greater than zero"), "unexpected error: {err}");
    }

    let constructor_source = r#"
        contract ZeroWidthConstructor(byte[0] value) {
            entry main() {
                require(true);
            }
        }
    "#;
    let err = compile_contract(constructor_source, &[ArtifactValue::Bytes(Vec::new())], CompileOptions::default())
        .expect_err("constructor parameter dimensions must be greater than zero");
    assert!(err.to_string().contains("must be greater than zero"), "unexpected error: {err}");
}

#[test]
fn dynamic_record_array_abi_rejects_empty_recursive_layouts() {
    let source = r#"
        contract EmptyRecordArray() {
            struct Empty {}

            entry main(Empty[] values) {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("a struct must contain at least one field");
    assert!(err.to_string().contains("struct 'Empty' must contain at least one field"), "unexpected error: {err}");
}

#[test]
fn artifact_state_resolution_supports_constructor_sized_arrays() {
    let source = r#"
        contract C(int N, byte[N] initial) {
            byte[N] stored = initial;

            entry main() {
                require(stored.length == N);
            }
        }
    "#;
    let constructor_args = [Expr::int(2), Expr::bytes(vec![0xaa, 0xbb])];
    let compiled = compile_internal_contract(source, &constructor_args, CompileOptions::default()).expect("contract compiles");

    let state = compiled
        .ast
        .resolve_contract_state_values(&constructor_args)
        .expect("the compiled artifact should resolve with the same constructor arguments accepted by compilation");
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].value, constructor_args[1]);
}

#[test]
fn artifact_sigscript_builder_supports_constructor_sized_struct_array_fields() {
    let source = r#"
        contract C(int N) {
            struct Item {
                byte[N] data;
            }

            entry main(Item[] items) {
                require(items.length == 1);
            }
        }
    "#;
    let artifact = compile_to_sil_abi_artifact(source, &[3.into()]).expect("contract compiles");
    let input = &artifact.contract("C").and_then(|contract| contract.entry("main")).expect("entrypoint exists").params[0];
    assert_eq!(input.ty, TypeArtifact::DynamicArray { item: Box::new(TypeArtifact::Struct { name: "Item".to_string() }) });
    assert_eq!(artifact.structs["Item"].fields[0].ty, TypeArtifact::FixedBytes { len: 3 });

    let json = serde_json::to_string(&artifact).expect("portable artifact serializes");
    let artifact: SilAbiArtifact = serde_json::from_str(&json).expect("portable artifact deserializes");
    assert_eq!(artifact.structs["Item"].fields[0].ty, TypeArtifact::FixedBytes { len: 3 });
    let items =
        ArtifactValue::Array(vec![ArtifactValue::Object(BTreeMap::from([("data".to_string(), vec![0xaau8, 0xbb, 0xcc].into())]))]);
    let sigscript = encode_single_entry_sig_script(&artifact, &[items]).expect("resolved ABI encodes the valid argument");
    let bytecode = artifact.contract("C").expect("contract exists").compiled.bytecode.clone();

    run_bytecode_with_sigscript(bytecode, sigscript).expect("artifact-built invocation executes");
}

#[test]
fn artifact_sigscript_builder_rejects_wrong_constructor_sized_struct_fields() {
    let source = r#"
        contract C(int N) {
            struct Item {
                byte[N] data;
            }

            entry main(Item item) {
                require(item.data.length == N);
            }
        }
    "#;
    let artifact = compile_to_sil_abi_artifact(source, &[3.into()]).expect("contract compiles");
    let item = |data: Vec<u8>| ArtifactValue::Object(BTreeMap::from([("data".to_string(), ArtifactValue::from(data))]));
    encode_single_entry_sig_script(&artifact, &[item(vec![0xaa, 0xbb, 0xcc])])
        .expect("the valid constructor-sized struct argument encodes");

    for data in [vec![0xaa, 0xbb], vec![0xaa, 0xbb, 0xcc, 0xdd]] {
        encode_single_entry_sig_script(&artifact, &[item(data)])
            .expect_err("the resolved ABI must reject an incorrectly sized nested field");
    }
}

#[test]
fn overflowing_fixed_array_size_is_rejected_at_the_untrusted_abi_boundary() {
    let source = r#"
        contract C() {
            int constant N = 2305843009213693952;

            entry main(int[N] values) {
                require(values.length == N);
            }
        }
    "#;
    // N * sizeof(int) is 2^64 and overflows usize on the supported 64-bit host. A fixed parameter with that impossible encoded
    // width must be rejected rather than weakened into the dynamic-array rule that accepts any multiple of eight bytes.
    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("an impossible fixed-width entrypoint parameter must be rejected");
    assert!(matches!(err.root(), CompilerError::ArithmeticOverflow(_)), "unexpected error: {err}");
}

#[test]
fn append_accepts_a_slice_result_as_its_array_source() {
    let source = r#"
        contract SliceAppend() {
            entry main(byte[] values) {
                byte[] result = values.slice(0, values.length).append(byte(7));
                require(result.length == values.length + 1);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("a statically typed byte[] slice should remain a valid append source after lowering");
}

#[test]
fn append_accepts_a_nested_array_element_as_its_array_source() {
    let source = r#"
        contract NestedArrayAppend() {
            entry main(int[2][] rows) {
                int[3] result = rows[0].append(7);
                require(result.length == 3);
            }
        }
    "#;

    compile_contract(source, &[], CompileOptions::default())
        .expect("a statically typed nested-array element should remain a valid append source after lowering");
}

fn execute_handcrafted_p2sh(
    compiled: &silverscript_abi::SilAbiArtifact,
    unlocking_prefix: Vec<u8>,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let flags = EngineFlags { covenants_enabled: true, ..Default::default() };
    let signature_script = pay_to_script_hash_signature_script_with_flags(bytecode(compiled).clone(), unlocking_prefix, flags)
        .expect("redeem script push should build");
    let input = TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
        signature_script,
        0,
        0,
    );
    let spent_output =
        TransactionOutput { value: 1_000, script_public_key: pay_to_script_hash_script(&bytecode(compiled)), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![spent_output.clone()], 0, SubnetworkId::default(), 0, vec![]);
    let utxo = UtxoEntry::new(spent_output.value, spent_output.script_public_key, 0, tx.is_coinbase(), None);
    let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        flags,
    );
    vm.execute()
}

fn compile_sigscript_boundary_contract() -> silverscript_abi::SilAbiArtifact {
    let source = r#"
        contract Boundary(int committed) {
            int stored = committed;

            entry main(int left, int right) {
                require(stored == 9);
                require(left == 11);
                require(right == 22);
            }
        }
    "#;
    compile_contract(source, &[ArtifactValue::Int(9)], CompileOptions::default()).expect("boundary contract compiles")
}

fn valid_sigscript_boundary_prefix(compiled: &silverscript_abi::SilAbiArtifact) -> Vec<u8> {
    script_builder().add_i64(11).unwrap().add_i64(22).unwrap().add_data(&dispatch_tag_for(compiled, "main")).unwrap().drain()
}

#[test]
fn handcrafted_p2sh_sigscript_accepts_exact_argument_stack() {
    let compiled = compile_sigscript_boundary_contract();
    execute_handcrafted_p2sh(&compiled, valid_sigscript_boundary_prefix(&compiled)).expect("exact argument stack must execute");
}

#[test]
fn handcrafted_p2sh_sigscript_rejects_surplus_items_beneath_arguments() {
    let compiled = compile_sigscript_boundary_contract();
    let tag = dispatch_tag_for(&compiled, "main");
    let cases = [
        script_builder().add_i64(0).unwrap().add_i64(11).unwrap().add_i64(22).unwrap().add_data(&tag).unwrap().drain(),
        script_builder().add_i64(99).unwrap().add_i64(11).unwrap().add_i64(22).unwrap().add_data(&tag).unwrap().drain(),
        script_builder()
            .add_data_with_push_opcode(&[0x55; 32])
            .unwrap()
            .add_i64(11)
            .unwrap()
            .add_i64(22)
            .unwrap()
            .add_data(&tag)
            .unwrap()
            .drain(),
    ];

    for unlocking_prefix in cases {
        let err = execute_handcrafted_p2sh(&compiled, unlocking_prefix).expect_err("surplus stack item must not be accepted");
        assert!(
            matches!(err, kaspa_txscript_errors::TxScriptError::CleanStack(_)),
            "surplus item should survive only to clean-stack rejection: {err:?}"
        );
    }
}

#[test]
fn handcrafted_p2sh_sigscript_rejects_missing_reordered_and_trailing_items() {
    let compiled = compile_sigscript_boundary_contract();
    let tag = dispatch_tag_for(&compiled, "main");
    let missing_leading = script_builder().add_i64(22).unwrap().add_data(&tag).unwrap().drain();
    let reordered = script_builder().add_i64(22).unwrap().add_i64(11).unwrap().add_data(&tag).unwrap().drain();
    let item_after_tag =
        script_builder().add_i64(11).unwrap().add_i64(22).unwrap().add_data(&tag).unwrap().add_i64(1).unwrap().drain();

    for unlocking_prefix in [missing_leading, reordered, item_after_tag] {
        execute_handcrafted_p2sh(&compiled, unlocking_prefix).expect_err("malformed argument/dispatch position must fail");
    }
}

#[test]
fn handcrafted_p2sh_sigscript_rejects_unknown_tag_non_push_opcode_and_oversized_int() {
    let compiled = compile_sigscript_boundary_contract();
    let tag = dispatch_tag_for(&compiled, "main");
    let unknown_tag = script_builder().add_i64(11).unwrap().add_i64(22).unwrap().add_data(&[0xde, 0xad, 0xbe, 0xef]).unwrap().drain();
    execute_handcrafted_p2sh(&compiled, unknown_tag).expect_err("unknown dispatch tag must fail");

    let mut non_push = vec![OpDup];
    non_push.extend(valid_sigscript_boundary_prefix(&compiled));
    let err = execute_handcrafted_p2sh(&compiled, non_push).expect_err("signature script must be push-only");
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::SignatureScriptNotPushOnly), "unexpected non-push error: {err:?}");

    let oversized = script_builder()
        .add_data_with_push_opcode(&[11, 0, 0, 0, 0, 0, 0, 0, 0])
        .unwrap()
        .add_i64(22)
        .unwrap()
        .add_data(&tag)
        .unwrap()
        .drain();
    execute_handcrafted_p2sh(&compiled, oversized).expect_err("nine-byte int must fail the compiler-emitted size guard");
}

#[test]
fn handcrafted_p2sh_sigscript_preserves_nonminimal_but_valid_int_semantics() {
    let compiled = compile_sigscript_boundary_contract();
    let left = [11, 0, 0, 0, 0, 0, 0, 0];
    let right = [22, 0, 0, 0, 0, 0, 0, 0];
    let prefix = script_builder()
        .add_data_with_push_opcode(&left)
        .unwrap()
        .add_data_with_push_opcode(&right)
        .unwrap()
        .add_data(&dispatch_tag_for(&compiled, "main"))
        .unwrap()
        .drain();
    execute_handcrafted_p2sh(&compiled, prefix).expect("Rusty Kaspa permits nonminimal numeric encodings up to eight bytes");
}

#[test]
fn runtime_empty_loop_with_extreme_reversed_bounds_matches_constant_lowering() {
    let constant_source = r#"
        contract ConstantLoopBounds() {
            entry main() {
                for (i, 9223372036854775807, -9223372036854775807, 1) {
                    require(false);
                }
                require(true);
            }
        }
    "#;
    let err = compile_contract(constant_source, &[], CompileOptions::default())
        .expect_err("an overflowing constant loop range must fail compilation");
    assert!(matches!(err.root(), CompilerError::ArithmeticOverflow(_)), "unexpected error: {err}");
    assert!(err.to_string().contains("arithmetic overflow: -9223372036854775807 - 9223372036854775807"), "unexpected error: {err}");

    let runtime_source = r#"
        contract RuntimeLoopBounds() {
            entry main(int start, int end) {
                for (i, start, end, 1) {
                    require(false);
                }
                require(true);
            }
        }
    "#;
    let compiled = compile_contract(runtime_source, &[], CompileOptions::default()).expect("runtime-bound contract compiles");
    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(i64::MAX), ArtifactValue::Int(-i64::MAX)])
        .expect("runtime sigscript builds");
    let err = run_bytecode_with_sigscript(bytecode(&compiled), sigscript)
        .expect_err("the equivalent runtime range subtraction must overflow");
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::NumberTooBig(_)), "unexpected runtime error: {err:?}");
}

#[test]
fn compiler_rejects_redeem_scripts_above_the_signature_script_limit() {
    let source = r#"
        contract OversizedLoop() {
            entry main(int start, int end) {
                for (i, start, end, 10000) {
                    require(i >= start);
                    require(i <= end);
                    require(i != start - 1);
                }
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("a redeem script that cannot fit in a signature script must be rejected");
    match err.root() {
        CompilerError::RedeemScriptTooLarge { actual, maximum } => {
            assert!(*actual > *maximum);
            assert_eq!(*maximum, MAINNET_PARAMS.new_max_signature_script_len);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn compiler_rejects_entry_abis_that_cannot_fit_the_unlocking_stack() {
    fn source_with_params(count: usize) -> String {
        let params = (0..count).map(|index| format!("int p{index}")).collect::<Vec<_>>().join(", ");
        format!(
            r#"
                contract StackBoundary() {{
                    entry main({params}) {{
                        require(true);
                    }}
                }}
            "#
        )
    }

    compile_contract(&source_with_params(242), &[], CompileOptions::default())
        .expect("242 arguments, the dispatch tag, and the redeem script fit the 244-item stack limit");

    let err = compile_contract(&source_with_params(243), &[], CompileOptions::default())
        .expect_err("243 arguments plus the dispatch tag and redeem script must be rejected");
    match err.root() {
        CompilerError::EntrypointStackTooLarge { function, actual, maximum } => {
            assert_eq!(function, "main");
            assert_eq!(*actual, 245);
            assert_eq!(*maximum, 244);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn compiler_rejects_fixed_abi_payloads_that_cannot_fit_a_signature_script() {
    let source = r#"
        contract OversizedFixedArgument() {
            entry main(byte[250000] payload) {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("an ABI whose minimum signature script is too large must be rejected");
    match err.root() {
        CompilerError::EntrypointSignatureScriptTooLarge { function, estimated, maximum } => {
            assert_eq!(function, "main");
            assert!(*estimated > *maximum);
            assert_eq!(*maximum, MAINNET_PARAMS.new_max_signature_script_len);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn signature_script_builder_requires_explicit_byte_values() {
    let source = r#"
        contract ByteArgument() {
            entry main(byte value) {
                require(true);
            }

            entry array(byte[] values) {
                require(values.length == 1);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte contract compiles");

    for value in [0, 0x80, 0xff] {
        let err = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Int(value)])
            .expect_err("integer AST values must not be reinterpreted as ABI bytes");
        assert!(err.to_string().contains("expected byte"), "unexpected error for {value:#04x}: {err}");
    }

    let sigscript = encode_entry_sig_script(&compiled, "main", &[ArtifactValue::Byte(0xff)]).expect("an explicit byte value builds");
    run_bytecode_with_sigscript(bytecode(&compiled).clone(), sigscript).expect("the explicit byte invocation executes");

    let contextual_array = ArtifactValue::Array(vec![1.into()]);
    let err = encode_entry_sig_script(&compiled, "array", &[contextual_array])
        .expect_err("integer artifact values must not be reinterpreted as ABI bytes");
    assert!(err.to_string().contains("expected bytes"), "unexpected array error: {err}");

    let sigscript =
        encode_entry_sig_script(&compiled, "array", &[ArtifactValue::Bytes(vec![1])]).expect("explicit byte elements build");
    run_bytecode_with_sigscript(bytecode(&compiled), sigscript).expect("the explicit byte-array invocation executes");
}
