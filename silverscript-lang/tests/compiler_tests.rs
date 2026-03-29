use blake2b_simd::Params as Blake2bParams;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
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
    pay_to_script_hash_signature_script,
};
use silverscript_lang::ast::{Expr, ExprKind, format_contract_ast, parse_contract_ast};
use silverscript_lang::compiler::{
    CompileOptions, CompiledContract, CovenantDeclCallOptions, FunctionAbiEntry, FunctionInputAbi, compile_contract,
    compile_contract_ast, function_branch_index, struct_object,
};
use silverscript_lang::debug_info::{DebugParamBinding, RuntimeBinding, StepKind};

fn run_script_with_selector(script: Vec<u8>, selector: Option<i64>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let sigscript = selector_sigscript(selector);
    run_script_with_sigscript(script, sigscript)
}

fn run_script_with_tx(
    script: Vec<u8>,
    selector: Option<i64>,
    lock_time: u64,
    sequence: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let sigscript = selector_sigscript(selector);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn selector_sigscript(selector: Option<i64>) -> Vec<u8> {
    let mut builder = ScriptBuilder::new();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    builder.drain()
}

fn run_script_with_sigscript(script: Vec<u8>, sigscript: Vec<u8>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn script_op_counts(script: &[u8]) -> (usize, usize) {
    let mut instruction_count = 0;
    let mut charged_op_count = 0;

    for opcode in parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(script) {
        let opcode = opcode.expect("compiled script should parse");
        instruction_count += 1;
        if !opcode.is_push_opcode() {
            charged_op_count += 1;
        }
    }

    (instruction_count, charged_op_count)
}

fn sigscript_push_script(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_data(script).unwrap().drain()
}

fn test_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count: 0,
    }
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
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

#[test]
fn accepts_constructor_args_with_matching_types() {
    let source = r#"
        contract Types(int a, bool b, string c, byte[] d, byte e, byte[4] f, pubkey pk, sig s, datasig ds) {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![
        Expr::int(7),
        Expr::bool(true),
        Expr::string("hello".to_string()),
        Expr::bytes(vec![1u8; 10]),
        Expr::byte(2),
        Expr::bytes(vec![3u8; 4]),
        Expr::bytes(vec![4u8; 32]),
        Expr::bytes(vec![5u8; 65]),
        Expr::bytes(vec![6u8; 64]),
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

            Pair constant DEFAULT_PAIR = {amount: 7, code: 0x1234};
            Pair from_param = init_pair;
            Pair from_constant = DEFAULT_PAIR;

            entrypoint function main() {
                require(true);
            }
        }
    "#;

    let args = vec![struct_object(vec![("amount", Expr::int(11)), ("code", Expr::bytes(vec![0xab, 0xcd]))])];
    let compiled = compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
    assert!(result.is_ok(), "top-level struct param/field/constant contract should run: {result:?}");
}

#[test]
fn compile_contract_omits_debug_info_when_recording_disabled() {
    let source = r#"
        contract DebugToggle() {
            entrypoint function spend(int x) {
                require(x == x);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.debug_info.is_none());
}

#[test]
fn compile_contract_emits_debug_info_when_recording_enabled() {
    let source = r#"
        contract DebugToggle() {
            entrypoint function spend(int x) {
                require(x == x);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");
    assert!(!debug_info.steps.is_empty());
    assert!(!debug_info.functions.is_empty());
    assert!(debug_info.params.iter().any(|param| param.name == "x"));
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
            entrypoint function main(
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
    let script_len = compiled.script.len();
    let (instruction_count, charged_op_count) = script_op_counts(&compiled.script);
    println!("branch_maze {script_len} / {instruction_count} / {charged_op_count}");
    // Snapshot these metrics exactly so compiler codegen changes must consciously
    // acknowledge their size impact on a branch-heavy stress case.
    assert_eq!(
        script_len, 326,
        "branch_maze metrics: script_len={script_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        instruction_count, 326,
        "branch_maze metrics: script_len={script_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        charged_op_count, 231,
        "branch_maze metrics: script_len={script_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    let cases = [(7, 2, 5, 4), (7, 2, -3, 4), (2, 7, 5, 4), (2, 7, 5, 3), (4, 4, 9, 2), (-3, 1, 6, -2), (10, -1, -4, 7), (0, 0, 0, 0)];

    for (a, b, c, d) in cases {
        let (expected_x, expected_y, expected_z, expected_score) = branch_maze_expected(a, b, c, d);
        let sigscript = compiled
            .build_sig_script(
                "main",
                vec![
                    Expr::int(a),
                    Expr::int(b),
                    Expr::int(c),
                    Expr::int(d),
                    Expr::int(expected_x),
                    Expr::int(expected_y),
                    Expr::int(expected_z),
                    Expr::int(expected_score),
                ],
            )
            .expect("sigscript builds");
        let result = run_script_with_sigscript(compiled.script.clone(), sigscript);
        assert!(
            result.is_ok(),
            "branch-heavy case ({a}, {b}, {c}, {d}) should match Rust model ({expected_x}, {expected_y}, {expected_z}, {expected_score}): {result:?}"
        );
    }

    let (a, b, c, d) = cases[0];
    let (expected_x, expected_y, expected_z, expected_score) = branch_maze_expected(a, b, c, d);
    let wrong_sigscript = compiled
        .build_sig_script(
            "main",
            vec![
                Expr::int(a),
                Expr::int(b),
                Expr::int(c),
                Expr::int(d),
                Expr::int(expected_x),
                Expr::int(expected_y),
                Expr::int(expected_z),
                Expr::int(expected_score + 1),
            ],
        )
        .expect("sigscript builds");
    let err = run_script_with_sigscript(compiled.script.clone(), wrong_sigscript)
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
            entrypoint function main(
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
    let script_len = compiled.script.len();
    let (instruction_count, charged_op_count) = script_op_counts(&compiled.script);
    println!("sorting_network {script_len} / {instruction_count} / {charged_op_count}");
    assert_eq!(
        script_len, 772,
        "sorting_network metrics: script_len={script_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        instruction_count, 772,
        "sorting_network metrics: script_len={script_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
    );
    assert_eq!(
        charged_op_count, 599,
        "sorting_network metrics: script_len={script_len} instruction_count={instruction_count} charged_op_count={charged_op_count}"
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
        let sigscript = compiled
            .build_sig_script(
                "main",
                vec![
                    values.to_vec().into(),
                    Expr::int(expected_a),
                    Expr::int(expected_b),
                    Expr::int(expected_c),
                    Expr::int(expected_d),
                    Expr::int(expected_e),
                    Expr::int(expected_f),
                    Expr::int(expected_g),
                    Expr::int(expected_h),
                ],
            )
            .expect("sigscript builds");
        let result = run_script_with_sigscript(compiled.script.clone(), sigscript);
        assert!(result.is_ok(), "sorting-network case {values:?} should match Rust model: {result:?}");
    }
}

#[test]
fn debug_info_records_console_expression_args() {
    let source = r#"
        contract DebugConsole() {
            entrypoint function spend(int x, int y) {
                console.log("sum", x + y);
                require(x + y > 0);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let console_step = debug_info
        .steps
        .iter()
        .find(|step| matches!(step.kind, StepKind::Source {}) && !step.console_args.is_empty())
        .expect("console step should be recorded");

    assert_eq!(console_step.bytecode_start, console_step.bytecode_end, "console step should be zero-width");
    assert_eq!(console_step.console_args.len(), 2);
    assert!(matches!(console_step.console_args[0].kind, ExprKind::String(ref value) if value == "sum"));
    assert!(matches!(console_step.console_args[1].kind, ExprKind::Binary { .. }));
}

#[test]
fn debug_info_records_runtime_binding_for_stable_scalar_local() {
    let source = r#"
        contract DebugBinding() {
            entrypoint function spend(int x) {
                int y = x + 1;
                require(y > 0);
                require(y < 10);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let y_update = debug_info
        .steps
        .iter()
        .flat_map(|step| step.variable_updates.iter())
        .find(|update| update.name == "y")
        .expect("y update should be recorded");

    assert!(matches!(y_update.runtime_binding, Some(RuntimeBinding::DataStackSlot { .. })));
}

#[test]
fn debug_info_records_struct_param_leaf_bindings_in_runtime_order() {
    let source = r#"
        contract DebugStructParam() {
            struct Pair {
                int amount;
                byte[2] code;
            }

            entrypoint function spend(Pair next, int fee) {
                require(fee >= 0);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let next = debug_info.params.iter().find(|param| param.name == "next").expect("structured param should be recorded");
    assert_eq!(next.type_name, "Pair");
    let DebugParamBinding::StructuredValue { leaf_bindings } = &next.binding else {
        panic!("expected structured binding");
    };
    assert_eq!(leaf_bindings.len(), 2);
    assert_eq!(leaf_bindings[0].field_path, vec!["amount".to_string()]);
    assert_eq!(leaf_bindings[0].type_name, "int");
    assert_eq!(leaf_bindings[0].stack_index, Some(2));
    assert_eq!(leaf_bindings[1].field_path, vec!["code".to_string()]);
    assert_eq!(leaf_bindings[1].type_name, "byte[2]");
    assert_eq!(leaf_bindings[1].stack_index, Some(1));

    let fee = debug_info.params.iter().find(|param| param.name == "fee").expect("scalar param should be recorded");
    assert_eq!(fee.binding, DebugParamBinding::SingleValue { stack_index: 0 });
}

#[test]
fn debug_info_records_state_array_param_leaf_bindings_in_runtime_order() {
    let source = r#"
        contract DebugStateArrayParam() {
            int amount = 1;
            byte[32] owner = 0x1111111111111111111111111111111111111111111111111111111111111111;

            entrypoint function spend(State[] next_states, int fee) {
                require(fee >= 0);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let next_states =
        debug_info.params.iter().find(|param| param.name == "next_states").expect("state-array param should be recorded");
    assert_eq!(next_states.type_name, "State[]");
    let DebugParamBinding::StructuredValue { leaf_bindings } = &next_states.binding else {
        panic!("expected structured binding");
    };
    assert_eq!(leaf_bindings.len(), 2);
    assert_eq!(leaf_bindings[0].field_path, vec!["amount".to_string()]);
    assert_eq!(leaf_bindings[0].type_name, "int[]");
    assert_eq!(leaf_bindings[0].stack_index, Some(4));
    assert_eq!(leaf_bindings[1].field_path, vec!["owner".to_string()]);
    assert_eq!(leaf_bindings[1].type_name, "byte[32][]");
    assert_eq!(leaf_bindings[1].stack_index, Some(3));

    let fee = debug_info.params.iter().find(|param| param.name == "fee").expect("scalar param should be recorded");
    assert_eq!(fee.binding, DebugParamBinding::SingleValue { stack_index: 2 });
}

#[test]
fn debug_info_distinguishes_ctor_args_from_contract_constants() {
    let source = r#"
        contract DebugConstants(int seed) {
            int constant BONUS = 2;

            entrypoint function spend() {
                require(seed + BONUS >= 0);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[Expr::int(7)], options).expect("compile succeeds");
    let debug_info = compiled.debug_info.expect("debug info should be present");

    let _seed = debug_info.constructor_args.iter().find(|binding| binding.name == "seed").expect("seed binding should be recorded");

    let bonus = debug_info.constants.iter().find(|binding| binding.name == "BONUS").expect("BONUS binding should be recorded");
    assert_eq!(bonus.type_name, "int");
}

#[test]
fn debug_info_single_entrypoint_sequences_and_offsets_are_stable() {
    let source = r#"
        contract DebugSingle() {
            entrypoint function spend(int x) {
                int y = x;
                require(y == x);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    assert!(compiled.without_selector);

    let debug_info = compiled.debug_info.expect("debug info should be present");
    let function = debug_info.functions.iter().find(|function| function.name == "spend").expect("function range for spend");
    assert_eq!(function.bytecode_start, 0, "single-entrypoint contract should not use selector prefix");
    assert!(function.bytecode_end > function.bytecode_start);

    let mut sequences = debug_info.steps.iter().map(|step| step.sequence).collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (0..debug_info.steps.len() as u32).collect::<Vec<_>>(), "step sequences should be contiguous");

    let function_steps = debug_info
        .steps
        .iter()
        .filter(|step| step.bytecode_start >= function.bytecode_start && step.bytecode_end <= function.bytecode_end)
        .collect::<Vec<_>>();
    assert!(!function_steps.is_empty(), "function should contain at least one debug step");
    assert!(function_steps.iter().all(|step| step.bytecode_start <= step.bytecode_end), "step ranges should be valid");
}

#[test]
fn debug_info_selector_entrypoints_have_global_sequences_and_offset_ranges() {
    let source = r#"
        contract DebugSelector() {
            entrypoint function a(int x) {
                int y = x;
                require(y == x);
            }

            entrypoint function b(int x) {
                int z = x;
                require(z == x);
            }
        }
    "#;

    let options = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    assert!(!compiled.without_selector);

    let debug_info = compiled.debug_info.expect("debug info should be present");
    let function_a = debug_info.functions.iter().find(|function| function.name == "a").expect("function range for a");
    let function_b = debug_info.functions.iter().find(|function| function.name == "b").expect("function range for b");

    assert!(function_a.bytecode_start > 0, "selector mode should prepend dispatcher ops");
    assert!(function_a.bytecode_start < function_b.bytecode_start, "entrypoint ranges should follow compile order");
    assert!(function_a.bytecode_end <= function_b.bytecode_start, "entrypoint ranges should not overlap");

    let steps_for_a = debug_info
        .steps
        .iter()
        .filter(|step| step.bytecode_start >= function_a.bytecode_start && step.bytecode_end <= function_a.bytecode_end)
        .collect::<Vec<_>>();
    let steps_for_b = debug_info
        .steps
        .iter()
        .filter(|step| step.bytecode_start >= function_b.bytecode_start && step.bytecode_end <= function_b.bytecode_end)
        .collect::<Vec<_>>();
    assert!(!steps_for_a.is_empty(), "entrypoint a should contain debug steps");
    assert!(!steps_for_b.is_empty(), "entrypoint b should contain debug steps");

    let mut sequences = debug_info.steps.iter().map(|step| step.sequence).collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (0..debug_info.steps.len() as u32).collect::<Vec<_>>(), "global step sequences should be contiguous");

    let max_a_sequence = steps_for_a.iter().map(|step| step.sequence).max().expect("a sequence max");
    let min_b_sequence = steps_for_b.iter().map(|step| step.sequence).min().expect("b sequence min");
    assert!(max_a_sequence < min_b_sequence, "later entrypoint should reserve a later sequence block");
}

#[test]
fn rejects_constructor_args_with_wrong_scalar_types() {
    let source = r#"
        contract Types(int a, bool b, string c) {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![Expr::bool(true), Expr::int(1), Expr::bytes(vec![1u8])];
    assert!(compile_contract(source, &args, CompileOptions::default()).is_err());
}

#[test]
fn rejects_constructor_args_with_wrong_byte_lengths() {
    let source = r#"
        contract Types(byte b, byte[4] c, pubkey pk, sig s, datasig ds) {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![
        Expr::bytes(vec![1u8; 2]),
        Expr::bytes(vec![2u8; 3]),
        Expr::bytes(vec![3u8; 31]),
        Expr::bytes(vec![4u8; 63]),
        Expr::bytes(vec![5u8; 66]),
    ];
    assert!(compile_contract(source, &args, CompileOptions::default()).is_err());
}

#[test]
fn enforces_exact_sig_and_datasig_lengths_in_constructor_args() {
    let source = r#"
        contract Types(sig s, datasig ds) {
            entrypoint function main() {
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
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![Expr::bytes(vec![9u8; 128])];
    compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn build_sig_script_builds_expected_script() {
    let source = r#"
        contract BoundedBytes() {
            entrypoint function spend(byte[4] b, int i) {
                require(b == byte[4](i));
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let args = vec![Expr::bytes(vec![1u8, 2, 3, 4]), Expr::int(7)];
    let sigscript = compiled.build_sig_script("spend", args).expect("sigscript builds");

    let selector = selector_for(&compiled, "spend");
    let mut builder = ScriptBuilder::new();
    builder.add_data(&[1u8, 2, 3, 4]).unwrap();
    builder.add_i64(7).unwrap();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    let expected = builder.drain();

    assert_eq!(sigscript, expected);
}

#[test]
fn byte_variable_from_int_literal_uses_raw_byte_push() {
    let source = r#"
        contract Bytes() {
            entrypoint function main() {
                byte x = 5;
                require(OpBin2Num(x) == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte int literal should compile");
    let expected = ScriptBuilder::new()
        .add_data(&[5u8])
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
        .drain();
    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, None).is_ok(), "byte int literal script should execute");
}

#[test]
fn byte_variable_from_out_of_range_int_literal_is_rejected() {
    let source = r#"
        contract Bytes() {
            entrypoint function main() {
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
            entrypoint function main() {
                byte x = 5;
                byte y = 7;
                require(x == y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte equality should compile");
    assert!(compiled.script.iter().copied().any(|op| op == OpEqual), "byte equality should use OP_EQUAL");
    assert!(!compiled.script.iter().copied().any(|op| op == OpNumEqual), "byte equality should not use OP_NUMEQUAL");
}

#[test]
fn byte_equality_with_rhs_int_literal_uses_raw_byte_push() {
    let source = r#"
        contract Bytes() {
            entrypoint function main() {
                byte x = 1;
                require(x == 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte equality with rhs literal should compile");
    let expected = ScriptBuilder::new()
        .add_data(&[1u8])
        .unwrap()
        .add_data(&[1u8])
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();
    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, None).is_ok(), "byte equality with rhs literal should execute");
}

#[test]
fn byte_equality_with_out_of_range_rhs_int_literal_is_rejected() {
    let source = r#"
        contract Bytes() {
            entrypoint function main() {
                byte x = 5;
                require(x == 256);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err(), "x == 256 should be rejected when x is a byte");
}

#[test]
fn rejects_adding_byte_values() {
    let source = r#"
        contract Bytes() {
            entrypoint function main() {
                byte x = 5;
                byte y = 7;
                require(x + y > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte addition should be rejected");
    assert!(err.to_string().contains("byte values do not support '+'"), "unexpected error: {err}");
}

#[test]
fn rejects_assigning_sum_of_byte_values_to_byte() {
    let source = r#"
        contract Bytes() {
            entrypoint function main() {
                byte x = 5;
                byte y = 7;
                byte z = x + y;
                require(OpBin2Num(z) == 12);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte addition assignment should be rejected");
    assert!(err.to_string().contains("byte values do not support '+'"), "unexpected error: {err}");
}

#[test]
fn build_sig_script_rejects_unknown_function() {
    let source = r#"
        contract C() {
            entrypoint function spend(int a) {
                require(a == 1);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("missing", vec![Expr::int(1)]);
    assert!(result.is_err());
}

#[test]
fn disallow_comparing_byte_array_to_byte_constant() {
    let source = r#"
        contract Test(byte[32] genesisPk, byte genesisIdentifierType) {
            byte[32] ownerIdentifier = genesisPk;
            byte identifierType = genesisIdentifierType;
            byte constant ZERO = 0x00;

            entrypoint function main() {
                if (ownerIdentifier == ZERO) {
                    require(true);
                }
            }
        }
    "#;

    assert!(
        compile_contract(source, &[Expr::bytes(vec![1u8; 32]), Expr::byte(0)], CompileOptions::default()).is_err(),
        "comparing byte[32] to byte should be rejected without cast"
    );
}

#[test]
fn disallow_comparing_dynamic_and_fixed_byte_arrays_without_cast_in_contract_scope() {
    let source = r#"
        contract Test(byte[] x) {
            byte[2] y = 0x1234;

            entrypoint function main() {
                require(x == y);
            }
        }
    "#;

    assert!(
        compile_contract(source, &[Expr::bytes(vec![0x12])], CompileOptions::default()).is_err(),
        "comparing byte[] to byte[2] should be rejected without cast"
    );
}

#[test]
fn allow_comparing_dynamic_and_fixed_byte_arrays_with_cast_in_contract_scope() {
    let source = r#"
        contract Test(byte[] x) {
            byte[2] y = 0x1234;

            entrypoint function main() {
                require(x == byte[](y));
            }
        }
    "#;

    compile_contract(source, &[Expr::bytes(vec![0x12])], CompileOptions::default())
        .expect("comparing byte[] to byte[2] should be allowed with cast");
}

#[test]
fn rejects_comparing_different_scalar_types_without_cast() {
    let source = r#"
        contract Reproduce() {
            entrypoint function main() {
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
            entrypoint function main() {
                int[] x = [1];
                int[1] y = [1];
                require(x == y);
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_err(), "int[] == int[1] should be rejected");
}

#[test]
fn allows_comparing_dynamic_and_fixed_int_arrays_with_cast() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x = [1];
                int[1] y = [1];
                require(x == int[](y));
            }
        }
    "#;

    assert!(compile_contract(source, &[], CompileOptions::default()).is_ok(), "int[] == int[](int[1]) should compile");
}

#[test]
fn allows_comparing_inferred_and_fixed_byte_arrays_when_sizes_match() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[_] x = 0x1256;
                byte[2] y = 0x1234;
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
            entrypoint function main() {
                byte[_] x = 0x12;
                byte[2] y = 0x1234;
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
fn infers_fixed_sizes_for_multiple_array_element_types() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[_] ints = [1, 2, 3, 4];
                int[4] ints_expected = [1, 2, 3, 4];
                bool[_] flags = [true, false];
                bool[2] flags_expected = [true, false];
                pubkey[_] keys = [
                    0x0101010101010101010101010101010101010101010101010101010101010101,
                    0x0202020202020202020202020202020202020202020202020202020202020202
                ];
                pubkey[2] keys_expected = [
                    0x0303030303030303030303030303030303030303030303030303030303030303,
                    0x0404040404040404040404040404040404040404040404040404040404040404
                ];
                require(ints == ints_expected);
                require(flags == flags_expected);
                require(keys == keys_expected);
            }
        }
    "#;

    assert!(
        compile_contract(source, &[], CompileOptions::default()).is_ok(),
        "type[_] should infer fixed sizes across supported element types"
    );
}

#[test]
fn rejects_comparing_dynamic_and_fixed_arrays_without_cast_in_function_scope() {
    let source = r#"
        contract Arrays() {
            entrypoint function main(byte[] x) {
                byte[2] y = 0x1234;
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
            entrypoint function main(byte[] x) {
                byte[2] y = 0x1234;
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
            entrypoint function main() {
                byte[] route_templates = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f;
                byte[32] target_template = byte[32](route_templates.slice(16, 48));
                require(byte[](target_template) == route_templates.slice(16, 48));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("byte[] to byte[32] cast should compile");
    assert!(!compiled.script.iter().copied().any(|op| op == OpNum2Bin), "byte[] to byte[32] cast should not emit OpNum2Bin");
    assert!(run_script_with_selector(compiled.script, None).is_ok(), "byte[] to byte[32] cast should execute");
}

#[test]
fn rejects_cast_between_different_fixed_byte_array_sizes() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[32] hash = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
                byte[31] truncated = byte[31](hash);
                require(truncated.length == 31);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte[32] to byte[31] cast should be rejected");
    assert!(err.to_string().contains("cannot cast byte[32] to byte[31]"), "unexpected error: {err}");
}

#[test]
fn rejects_cast_from_smaller_fixed_byte_array_to_larger_fixed_byte_array() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[31] hash = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e;
                byte[32] padded = byte[32](hash);
                require(padded.length == 32);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("byte[31] to byte[32] cast should be rejected");
    assert!(err.to_string().contains("cannot cast byte[31] to byte[32]"), "unexpected error: {err}");
}

#[test]
fn build_sig_script_rejects_wrong_argument_count() {
    let source = r#"
        contract C() {
            entrypoint function spend(int a, int b) {
                require(a == b);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::int(1)]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_rejects_wrong_argument_type() {
    let source = r#"
        contract C() {
            entrypoint function spend(byte[4] b) {
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::bytes(vec![1u8; 3])]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_for_covenant_decl_routes_to_hidden_auth_entrypoint() {
    let source = r#"
        contract Counter(int init_value) {
            int value = init_value;

            #[covenant.singleton]
            function step(State prev_state, State[] new_states) {
                require(new_states.length <= 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[Expr::int(7)], CompileOptions::default()).expect("compile succeeds");
    let args = vec![vec![struct_object(vec![("value", Expr::int(8))])].into()];

    let actual = compiled
        .build_sig_script_for_covenant_decl("step", args.clone(), CovenantDeclCallOptions { is_leader: false })
        .expect("covenant sigscript builds");
    let expected = compiled.build_sig_script("__step", args).expect("hidden entrypoint sigscript builds");

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

    let compiled = compile_contract(source, &[Expr::int(7)], CompileOptions::default()).expect("compile succeeds");
    let leader_args = vec![vec![struct_object(vec![("value", Expr::int(8))])].into()];

    let leader = compiled
        .build_sig_script_for_covenant_decl("rebalance", leader_args.clone(), CovenantDeclCallOptions { is_leader: true })
        .expect("leader sigscript builds");
    let expected_leader = compiled.build_sig_script("__leader_rebalance", leader_args).expect("hidden leader sigscript builds");
    assert_eq!(leader, expected_leader);

    let delegate = compiled
        .build_sig_script_for_covenant_decl("rebalance", vec![], CovenantDeclCallOptions { is_leader: false })
        .expect("delegate sigscript builds");
    let expected_delegate = compiled.build_sig_script("__delegate_rebalance", vec![]).expect("hidden delegate sigscript builds");
    assert_eq!(delegate, expected_delegate);
}

#[test]
fn build_sig_script_for_covenant_decl_rejects_unknown_declaration() {
    let source = r#"
        contract C() {
            entrypoint function spend() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script_for_covenant_decl("missing", vec![], CovenantDeclCallOptions { is_leader: false });
    assert!(result.is_err());
}

#[test]
fn rejects_double_underscore_variable_names() {
    let source = r#"
        contract Bad() {
            entrypoint function main() {
                int __tmp = 1;
                require(__tmp == 1);
            }
        }
    "#;
    assert!(parse_contract_ast(source).is_err());

    let source = r#"
        contract Bad(int __arg) {
            entrypoint function main() {
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

            entrypoint function main() {
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

            entrypoint function main() {
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

            entrypoint function main() {
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

            entrypoint function main() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("helper", vec![Expr::int(1)]);
    assert!(result.is_err());
}

#[test]
fn rejects_entrypoint_return_by_default() {
    let source = r#"
        contract EntryReturn() {
            entrypoint function main() : (int) {
                return(1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("entrypoint return should be disallowed by default");
    assert!(err.to_string().contains("entrypoint return requires allow_entrypoint_return=true"));
}

#[test]
fn build_sig_script_rejects_mismatched_bytes_length() {
    let source = r#"
        contract C() {
            entrypoint function spend(byte[4] b) {
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::bytes(vec![1u8; 5])]);
    assert!(result.is_err());

    let source = r#"
        contract C() {
            entrypoint function spend(byte[5] b) {
                require(b.length == 5);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::bytes(vec![1u8; 4])]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_omits_selector_without_selector() {
    let source = r#"
        contract Single() {
            entrypoint function spend(int a, byte[4] b) {
                require(a == 1);
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.without_selector);
    let sigscript = compiled.build_sig_script("spend", vec![1.into(), vec![2u8; 4].into()]).expect("sigscript builds");

    let expected = ScriptBuilder::new().add_i64(1).unwrap().add_data(&[2u8; 4]).unwrap().drain();
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

            entrypoint function main() {
                f({a: 0, b: "12345"});
                S y = {a: 0, b: "22345"};
                f(y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
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
                return({a: a, b: "12345"});
            }

            function check(S x) {
                require(x.a == 0);
                require(x.b.length == 5);
            }

            entrypoint function main() {
                (S out) = make(0);
                check(out);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
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

            entrypoint function main(S x) {
                require(x.a == 0);
                require(x.b.length == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let arg = struct_object(vec![("a", Expr::int(0)), ("b", Expr::string("12345"))]);
    let sigscript = compiled.build_sig_script("main", vec![arg]).expect("sigscript builds");

    let expected = ScriptBuilder::new().add_i64(0).unwrap().add_data(b"12345").unwrap().drain();
    assert_eq!(sigscript, expected);
}

#[test]
fn build_sig_script_supports_state_entrypoint_arguments() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main(State s) {
                require(s.x == 9);
                require(s.y == 0x3412);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let arg = struct_object(vec![("x", Expr::int(9)), ("y", Expr::bytes(vec![0x34, 0x12]))]);
    let sigscript = compiled.build_sig_script("main", vec![arg]).expect("sigscript builds");

    let expected = ScriptBuilder::new().add_i64(9).unwrap().add_data(&[0x34, 0x12]).unwrap().drain();
    assert_eq!(sigscript, expected);
}

#[test]
fn build_sig_script_supports_sig_array_arguments() {
    let source = r#"
        contract C() {
            entrypoint function main(sig[] sigs) {
                require(sigs.length == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sig_a = vec![0x11u8; 65];
    let sig_b = vec![0x22u8; 65];
    let sigscript = compiled
        .build_sig_script("main", vec![vec![Expr::bytes(sig_a.clone()), Expr::bytes(sig_b.clone())].into()])
        .expect("sigscript builds");

    let mut encoded = sig_a;
    encoded.extend(sig_b);
    let expected = ScriptBuilder::new().add_data(&encoded).unwrap().drain();
    assert_eq!(sigscript, expected);
}

fn struct_array_arg<'i>(values: Vec<(i64, Vec<u8>)>) -> Expr<'i> {
    values.into_iter().map(|(a, b)| struct_object(vec![("a", Expr::int(a)), ("b", Expr::bytes(b))])).collect::<Vec<_>>().into()
}

fn state_array_arg<'i>(values: Vec<i64>) -> Expr<'i> {
    values.into_iter().map(|value| struct_object(vec![("value", Expr::int(value))])).collect::<Vec<_>>().into()
}

fn state_array_arg_x<'i>(values: Vec<i64>) -> Expr<'i> {
    values.into_iter().map(|value| struct_object(vec![("x", Expr::int(value))])).collect::<Vec<_>>().into()
}

fn matrix_state_array_arg<'i>(values: Vec<(i64, Vec<u8>)>) -> Expr<'i> {
    values
        .into_iter()
        .map(|(amount, owner)| struct_object(vec![("amount", Expr::int(amount)), ("owner", Expr::bytes(owner))]))
        .collect::<Vec<_>>()
        .into()
}

fn replace_compiled_interface<'i>(
    compiled: &mut CompiledContract<'i>,
    source: &'i str,
    entrypoint_name: &str,
    inputs: &[(&str, &str)],
) {
    compiled.ast = parse_contract_ast(source).expect("interface parses");
    compiled.abi = vec![FunctionAbiEntry {
        name: entrypoint_name.to_string(),
        inputs: inputs
            .iter()
            .map(|(name, type_name)| FunctionInputAbi { name: (*name).to_string(), type_name: (*type_name).to_string() })
            .collect(),
    }];
}

#[test]
fn build_sig_script_for_covenant_decl_supports_all_covenant_ast_examples() {
    struct Case {
        source: &'static str,
        constructor_args: Vec<Expr<'static>>,
        function_name: &'static str,
        args: Vec<Expr<'static>>,
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
                return({ amount: prev_state.amount + delta, owner: prev_state.owner });
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
    let matrix_all_source = r#"
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

            #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
            function auth_transition(State prev_state, int fee) : (State) {
                return({ amount: prev_state.amount - fee, owner: prev_state.owner });
            }

            #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
            function cov_verification(State[] prev_states, State[] new_states, int nonce) {
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
            constructor_args: vec![Expr::int(4)],
            function_name: "split",
            args: vec![state_array_arg(vec![11]), Expr::int(3)],
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
            constructor_args: vec![Expr::int(2), Expr::int(3)],
            function_name: "transition_ok",
            args: vec![state_array_arg(vec![10, 11]), Expr::int(1)],
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
            constructor_args: vec![Expr::int(2), Expr::int(3)],
            function_name: "transition_ok",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_transition_ok",
        },
        Case {
            source: r#"
                contract Decls(int init_value) {
                    int value = init_value;

                    #[covenant.singleton(mode = transition)]
                    function bump(State prev_state, int delta) : (State) {
                        return({ value: prev_state.value + delta });
                    }
                }
            "#,
            constructor_args: vec![Expr::int(7)],
            function_name: "bump",
            args: vec![Expr::int(2)],
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
            constructor_args: vec![Expr::int(4), Expr::int(10)],
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
            constructor_args: vec![Expr::int(10)],
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
            constructor_args: vec![Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), Expr::int(0)],
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
            constructor_args: vec![Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
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

                    #[covenant(binding = auth, from = 1, to = max_outs, mode = transition)]
                    function step(State prev_state, int fee) : (State) {
                        return({ amount: prev_state.amount - fee, owner: prev_state.owner });
                    }
                }
            "#,
            constructor_args: vec![Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![Expr::int(1)],
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
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), Expr::int(0)],
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
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_step",
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
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![Expr::int(1)],
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
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_step",
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
            constructor_args: vec![Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
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
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
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
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_step",
        },
        Case {
            source: r#"
                contract Matrix(int init_amount, byte[32] init_owner) {
                    int amount = init_amount;
                    byte[32] owner = init_owner;

                    #[covenant(from = 1, to = 1)]
                    function step(State prev_state, int delta) : (State) {
                        return({ amount: prev_state.amount + delta, owner: prev_state.owner });
                    }
                }
            "#,
            constructor_args: vec![Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![Expr::int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_singleton_transition_source,
            constructor_args: vec![Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![Expr::int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_singleton_terminate_source,
            constructor_args: vec![Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_fanout_verification_source,
            constructor_args: vec![Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "step",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__step",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "auth_verification_multi",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), Expr::int(0)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__auth_verification_multi",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "auth_verification_single",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__auth_verification_single",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "auth_transition",
            args: vec![Expr::int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__auth_transition",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "cov_verification",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())]), Expr::int(0)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_cov_verification",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "cov_verification",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_cov_verification",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "cov_transition",
            args: vec![Expr::int(1)],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_cov_transition",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "cov_transition",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_cov_transition",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "inferred_auth",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__inferred_auth",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "inferred_cov",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: true },
            generated_covenant_entrypoint_name: "__leader_inferred_cov",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "inferred_cov",
            args: vec![],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__delegate_inferred_cov",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "inferred_transition",
            args: vec![Expr::int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__inferred_transition",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "singleton_transition",
            args: vec![Expr::int(1)],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__singleton_transition",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "singleton_terminate",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__singleton_terminate",
        },
        Case {
            source: matrix_all_source,
            constructor_args: vec![Expr::int(2), Expr::int(4), Expr::int(10), Expr::bytes(owner.clone())],
            function_name: "fanout_verification",
            args: vec![matrix_state_array_arg(vec![(11, next_owner.clone())])],
            options: CovenantDeclCallOptions { is_leader: false },
            generated_covenant_entrypoint_name: "__fanout_verification",
        },
    ];

    for case in cases {
        let compiled = compile_contract(case.source, &case.constructor_args, CompileOptions::default()).expect("compile succeeds");
        let sigscript = compiled
            .build_sig_script_for_covenant_decl(case.function_name, case.args.clone(), case.options)
            .expect("covenant declaration sigscript builds");
        let expected = compiled
            .build_sig_script(case.generated_covenant_entrypoint_name, case.args)
            .expect("generated entrypoint sigscript builds");
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

            entrypoint function main(int[] items_a, byte[2][] items_b) {
                require(items_a.length == 2);
                require(items_b.length == 2);
                require(items_a[0] == 7);
                require(items_a[1] == 9);
                require(items_b[0] == 0x0102);
                require(items_b[1] == 0x0304);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
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
    assert_eq!(main_param_types, vec!["int[]".to_string(), "byte[2][]".to_string()]);

    let err = compiled
        .build_sig_script("main", vec![struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
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

            entrypoint function main(int[] items_a, byte[2][] items_b) {
                require(items_a.length == 2);
                require(items_b.length == 2);
                require(items_a[0] == 7);
                require(items_a[1] == 9);
                require(items_b[0] == 0x0102);
                require(items_b[1] == 0x0304);
            }
        }
    "#;

    let struct_signature_source = r#"
        contract C() {
            struct S {
                int a;
                byte[2] b;
            }

            entrypoint function main(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == 0x0102);
                require(x[1].b == 0x0304);
            }
        }
    "#;

    let mut compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    replace_compiled_interface(&mut compiled, struct_signature_source, "main", &[("x", "S[]")]);

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

    let sigscript = compiled
        .build_sig_script("main", vec![struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);

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

            entrypoint function f(S[] x) {
                require(x.length == 2);
                require(x[0].a == 7);
                require(x[1].a == 9);
                require(x[0].b == 0x0102);
                require(x[1].b == 0x0304);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let f_param_types: Vec<String> = compiled
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

    let sigscript = compiled
        .build_sig_script("f", vec![struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);

    assert!(result.is_ok(), "direct struct[] entrypoint signature should execute successfully: {result:?}");
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
                require(items_b[0] == 0x0102);
                require(items_b[1] == 0x0304);
            }

            entrypoint function main(int[] items_a, byte[2][] items_b) {
                verify(items_a, items_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
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
    assert_eq!(main_param_types, vec!["int[]".to_string(), "byte[2][]".to_string()]);

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
    assert_eq!(verify_param_types, vec!["int[]".to_string(), "byte[2][]".to_string()]);

    let err = compiled
        .build_sig_script("main", vec![struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
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
                require(items_b[0] == 0x0102);
                require(items_b[1] == 0x0304);
            }

            entrypoint function main(int[] items_a, byte[2][] items_b) {
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
                require(x[0].b == 0x0102);
                require(x[1].b == 0x0304);
            }

            entrypoint function main(S[] x) {
                verify(x);
            }
        }
    "#;

    let mut compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    replace_compiled_interface(&mut compiled, struct_signature_source, "main", &[("x", "S[]")]);

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

    let sigscript = compiled
        .build_sig_script("main", vec![struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);

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

            entrypoint function main() {
                int[] xs = [7, 9];
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
                require(x[0].b == 0x0102);
                require(x[1].b == 0x0304);
            }

            entrypoint function main(S[] x) {
                verify(x);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
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

    let sigscript = compiled
        .build_sig_script("main", vec![struct_array_arg(vec![(7, vec![0x01, 0x02]), (9, vec![0x03, 0x04])])])
        .expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);

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

            entrypoint function main(int[] x) {
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
                require(x[0].b == 0x0102);
                require(x[1].b == 0x0304);
            }

            entrypoint function main(S[] x) {
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

            entrypoint function main() {
                f({a: "hello", b: "world"});
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(
        err.to_string().contains("function argument '__struct_x_a' expects int")
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

            entrypoint function main() {
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

            entrypoint function main() {
                S y = {a: "hello", b: "world"};
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

            entrypoint function main() {
                S y = {a: 0};
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("compile should fail");
    assert!(err.to_string().contains("struct field 'b' must be initialized"));
}

#[test]
fn build_sig_script_rejects_struct_argument_with_wrong_field_type() {
    let source = r#"
        contract C() {
            struct S {
                int a;
                string b;
            }

            entrypoint function main(S x) {
                require(x.a == 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let arg = struct_object(vec![("a", Expr::string("hello")), ("b", Expr::string("world"))]);
    let result = compiled.build_sig_script("main", vec![arg]);
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

            entrypoint function main() {
                S s = {a: 7, b: 0x0102030405};
                {a: int x, b: byte[5] y} = s;
                require(x == 7);
                require(y == 0x0102030405);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
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

            entrypoint function main() {
                S s = {a: 7, b: 0x0102030405};
                {a: int x} = s;
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

            entrypoint function main() {
                S s = {a: 7, b: 0x0102030405};
                {a: string x, b: byte[5] y} = s;
                require(y == 0x0102030405);
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

            entrypoint function main() {
                (int sum, int prod) = f(2, 3);
                require(sum == 5);
                require(prod == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_function_call_statement_drops_returns() {
    let source = r#"
        contract Calls() {
            function f(int a) : (int) {
                require(a >= 0);
                return(a + 1);
            }

            entrypoint function main() {
                f(2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    assert!(compiled.script.windows(2).any(|window| window == [OpAdd, OpDrop]), "expected return value to be dropped");
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn rejects_function_call_assignment_with_mismatched_signature() {
    let source = r#"
        contract Calls() {
            function f(int a, int b) : (int, int) {
                return(a + b, a * b);
            }

            entrypoint function main() {
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

            entrypoint function main() {
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

            entrypoint function main() {
                f(0x010203);
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

            entrypoint function main() {
                f(0x01020304);
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

            entrypoint function main() {
                f([1, 2, 3]);
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

            entrypoint function main() {
                f([1, 2, 3, 4]);
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

            entrypoint function main() {
                ping(1);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
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

            entrypoint function main(int n) {
                require(fib(n) > 0);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("recursive call should fail");
    let err_msg = err.to_string();
    assert!(err_msg.contains("unknown function"), "expected 'unknown function' error, got: {err_msg}");
}

#[test]
fn rejects_calling_later_defined_function() {
    let source = r#"
        contract Calls() {
            entrypoint function first() {
                second();
            }

            function second() {
                require(true);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("forward call should fail");
    assert!(err.to_string().contains("earlier-defined"));
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

            entrypoint function main() {
                (int out) = f(4);
                require(out == 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}
#[test]
fn allows_calling_void_function_fails() {
    let source = r#"
        contract Calls() {
            function ping(int a) {
                require(a == 2);
            }

            entrypoint function main() {
                ping(1);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    assert!(run_script_with_selector(compiled.script, selector).is_err());
}

#[test]
fn rejects_return_without_signature() {
    let source = r#"
        contract C() {
            entrypoint function main() {
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
            entrypoint function main() : (int) {
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
            entrypoint function main() : (int, int) {
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
            entrypoint function main(bool b) : (int) {
                return(b);
            }
        }
    "#;
    assert!(compile_contract(source, &[], CompileOptions::default()).is_err());
}

#[test]
fn compiles_int_array_length_to_expected_script() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x;
                require(x.length == 0);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_data(&[])
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
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
}

#[test]
fn compiles_int_array_push_to_expected_script() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x;
                x.push(7);
                require(x.length == 1);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_data(&[])
        .unwrap()
        .add_i64(7)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpNum2Bin)
        .unwrap()
        .add_op(OpCat)
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
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
}

#[test]
fn compiles_int_array_index_to_expected_script() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x;
                x.push(7);
                require(x[0] == 7);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_data(&[])
        .unwrap()
        .add_i64(7)
        .unwrap()
        .add_i64(8)
        .unwrap()
        .add_op(OpNum2Bin)
        .unwrap()
        .add_op(OpCat)
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
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
}

#[test]
fn runs_array_runtime_examples() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x;
                x.push(7);
                x.push(9);
                require(x.length == 2);
                require(x[0] == 7);
                require(x[1] == 9);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array runtime example failed: {}", result.unwrap_err());
}

#[test]
fn runs_int_array_push_length_runtime_example() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x = [1, 2, 3];
                x.push(4);
                require(x.length == 4);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "int[] push length runtime example failed: {}", result.unwrap_err());
}

#[test]
fn runs_slice_with_explicit_end_bounds() {
    let source = r#"
        contract SliceLowering() {
            entrypoint function main() {
                byte[] data = 0x0102030405060708090a;
                byte[] segment = data.slice(3, 8);
                require(segment.length == 5);
                require(segment == byte[](0x0405060708));
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "slice runtime should succeed: {}", result.unwrap_err());
}

#[test]
fn runs_slice_reconstruction_and_compare_runtime_example() {
    let source = r#"
        contract SliceReconstruct() {
            entrypoint function main() {
                byte[] data = 0x0102030405060708090a;
                byte[] left = data.slice(0, 4);
                byte[] right = data.slice(4, 10);
                byte[] rebuilt = left + right;

                require(left == byte[](0x01020304));
                require(right == byte[](0x05060708090a));
                require(rebuilt.length == data.length);
                require(rebuilt == data);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "slice reconstruction runtime should succeed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_int_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] a = [1, 2];
                int[] b = [3, 4];
                int[4] c = a + b;

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
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "int[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_byte_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[] a = 0x0102;
                byte[] b = 0x0304;
                byte[4] c = a + b;

                require(c.length == 4);
                require(c == 0x01020304);
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "byte[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_fixed_size_byte_array_elements_with_plus() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[2][] a = [0x0102, 0x0304];
                byte[2][] b = [0x0506];
                byte[2][3] c = a + b;

                require(c.length == 3);
                require(c[0] == 0x0102);
                require(c[1] == 0x0304);
                require(c[2] == 0x0506);
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "byte[N][] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_bool_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                bool[] a = [true, false];
                bool[] b = [true, false];
                bool[4] c = a + b;

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
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "bool[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn allows_concat_of_pubkey_arrays_with_plus() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                pubkey p1 = 0x0202020202020202020202020202020202020202020202020202020202020202;
                pubkey p2 = 0x0303030303030303030303030303030303030303030303030303030303030303;

                pubkey[] a = [p1];
                pubkey[] b = [p2];
                pubkey[2] c = a + b;

                require(c.length == 2);
                require(c[0] == p1);
                require(c[1] == p2);
            }
        }
    "#;

    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "pubkey[] concatenation runtime failed: {}", result.unwrap_err());
}

#[test]
fn compiles_bytes20_array_push_without_num2bin() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[20][] x;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                require(x.length == 1);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let value =
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14];
    let expected = ScriptBuilder::new()
        .add_data(&[])
        .unwrap()
        .add_data(&value)
        .unwrap()
        .add_op(OpCat)
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
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
}

#[test]
fn runs_bytes20_array_runtime_example() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[20][] x;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                x.push(0x1111111111111111111111111111111111111111);
                require(x.length == 2);
                require(x[0] == 0x0102030405060708090a0b0c0d0e0f1011121314);
                require(x[1] == 0x1111111111111111111111111111111111111111);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "byte[20] array runtime example failed: {}", result.unwrap_err());
}

#[test]
fn allows_array_equality_comparison() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[20][] x;
                byte[20][] y;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                require(x == y);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array equality runtime failed: {}", result.unwrap_err());
}

#[test]
fn fails_array_equality_comparison() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[20][] x;
                byte[20][] y;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x2222222222222222222222222222222222222222);
                require(x == y);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}

#[test]
fn allows_array_inequality_with_different_sizes() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                byte[20][] x;
                byte[20][] y;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x2222222222222222222222222222222222222222);
                require(x != y);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array inequality runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_array_for_loop_example() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x;
                x.push(1);
                x.push(2);
                x.push(3);
                for (i, 0, 3, 3) {
                    require(x[i] == i + 1);
                }
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array for-loop runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_array_for_loop_with_length_guard() {
    let source = r#"
        contract Arrays() {
            int constant MAX_ARRAY_SIZE = 7;

            entrypoint function main(int[] x) {
                require(x.length <= MAX_ARRAY_SIZE);
                for (i, 1, x.length, MAX_ARRAY_SIZE - 1) {
                    require(x[i] == x[i-1]+1);
                }
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");

    let sigscript = compiled.build_sig_script("main", vec![vec![1i64, 2i64, 3i64, 4i64].into()]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
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

            entrypoint function main() {
                int[] x;
                x.push(1);
                x.push(2);
                x.push(3);
                (int total) = sumArray(x);
                require(total == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
    assert!(result.is_ok(), "array/loop/function-call example failed: {}", result.unwrap_err());
}

#[test]
fn rejects_non_constant_for_loop_max_iterations() {
    let source = r#"
        contract Loops() {
            entrypoint function main(int start, int end, int max_iterations) {
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
fn rejects_overflow_in_constant_for_loop_bounds() {
    let cases = [
        ("9223372036854775807 + 1", "constant integer overflow: 9223372036854775807 + 1"),
        ("(-9223372036854775807) - 2", "constant integer overflow: -9223372036854775807 - 2"),
        ("3037000500 * 3037000500", "constant integer overflow: 3037000500 * 3037000500"),
        ("-(-9223372036854775807 - 1)", "constant integer overflow: -(-9223372036854775808)"),
        ("(-9223372036854775807 - 1) / -1", "constant integer overflow: -9223372036854775808 / -1"),
        ("(-9223372036854775807 - 1) % -1", "constant integer overflow: -9223372036854775808 % -1"),
    ];

    for (expr, expected) in cases {
        let source = format!(
            r#"
                contract Loops() {{
                    entrypoint function main() {{
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
fn runs_runtime_bounded_for_loop_example() {
    let source = r#"
        contract RuntimeLoop() {
            entrypoint function main(int start, int end, int expected_count, int expected_last) {
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

    let sigscript = compiled.build_sig_script("main", vec![2.into(), 4.into(), 2.into(), 3.into()]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script.clone(), sigscript);
    assert!(result.is_ok(), "runtime-bounded for-loop should honor end-exclusive bounds: {}", result.unwrap_err());

    let sigscript = compiled.build_sig_script("main", vec![5.into(), 20.into(), 3.into(), 7.into()]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script.clone(), sigscript);
    assert!(result.is_ok(), "runtime-bounded for-loop should stop after max iterations: {}", result.unwrap_err());

    let sigscript = compiled.build_sig_script("main", vec![4.into(), 2.into(), 0.into(), (-1).into()]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "runtime-bounded for-loop should skip iterations when start >= end: {}", result.unwrap_err());
}

#[test]
fn allows_array_assignment_with_compatible_types() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                int[] x;
                int[] y;
                x = y;
                require(x.length == 0);
            }
        }
    "#;
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &[], options).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
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

            entrypoint function main(pubkey a, pubkey b, pubkey expected, bool take_other) {
                verify(a, b, expected, take_other);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let a = vec![0x11u8; 32];
    let b = vec![0x22u8; 32];

    let sigscript_take_b = compiled
        .build_sig_script("main", vec![Expr::bytes(a.clone()), Expr::bytes(b.clone()), Expr::bytes(b.clone()), Expr::bool(true)])
        .expect("sigscript builds");
    let result_take_b = run_script_with_sigscript(compiled.script.clone(), sigscript_take_b);
    assert!(result_take_b.is_ok(), "inline pubkey reassignment should allow taking the second value: {}", result_take_b.unwrap_err());

    let sigscript_keep_a = compiled
        .build_sig_script("main", vec![Expr::bytes(a.clone()), Expr::bytes(b), Expr::bytes(a), Expr::bool(false)])
        .expect("sigscript builds");
    let result_keep_a = run_script_with_sigscript(compiled.script, sigscript_keep_a);
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
            entrypoint function main() {
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
            entrypoint function main() {
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
            entrypoint function main(pubkey pk, byte[] expected) {
                byte[] spk = new ScriptPubKeyP2PK(pk);
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

    let sigscript = compiled.build_sig_script("main", vec![pubkey.into(), expected.into()]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "p2pk locking bytecode mismatch: {}", result.unwrap_err());
}

#[test]
fn locking_bytecode_p2sh_matches_pay_to_address_script() {
    let source = r#"
        contract Test() {
            entrypoint function main(byte[32] hash, byte[] expected) {
                byte[] spk = new ScriptPubKeyP2SH(hash);
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

    let sigscript = compiled.build_sig_script("main", vec![hash.into(), expected.into()]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "p2sh locking bytecode mismatch: {}", result.unwrap_err());
}

#[test]
fn locking_bytecode_p2sh_from_redeem_script_matches_pay_to_script_hash_script() {
    let source = r#"
        contract Test() {
            entrypoint function main(byte[] redeem_script, byte[] expected) {
                byte[] spk = new ScriptPubKeyP2SHFromRedeemScript(redeem_script);
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

    let sigscript = compiled.build_sig_script("main", vec![redeem_script.into(), expected.into()]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "p2sh-from-redeem-script locking bytecode mismatch: {}", result.unwrap_err());
}

fn run_script_with_tx_and_covenants(
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
    let mut vm =
        TxScriptEngine::from_transaction_input(&populated, &tx.inputs[0], 0, utxo_entry, ctx, EngineFlags { covenants_enabled: true });
    vm.execute()
}

fn build_basic_opcode_tx(sigscript: Vec<u8>) -> (Transaction, Vec<UtxoEntry>) {
    let outpoint_txid = TransactionId::from_bytes(*b"0123456789abcdef0123456789abcdef");
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: outpoint_txid, index: 7 },
        signature_script: sigscript,
        sequence: u64::from_le_bytes(*b"sequence"),
        sig_op_count: 0,
    };

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

fn selector_for(compiled: &CompiledContract<'_>, function_name: &str) -> Option<i64> {
    if compiled.without_selector {
        None
    } else {
        Some(function_branch_index(&compiled.ast, function_name).expect("selector resolved"))
    }
}

fn wrap_with_dispatch(body: Vec<u8>, selector: Option<i64>) -> Vec<u8> {
    if let Some(selector) = selector {
        let mut builder = ScriptBuilder::new();
        builder.add_op(OpDup).unwrap();
        builder.add_i64(selector).unwrap();
        builder.add_op(OpNumEqual).unwrap();
        builder.add_op(OpIf).unwrap();
        builder.add_op(OpDrop).unwrap();
        builder.add_ops(&body).unwrap();
        builder.add_op(OpElse).unwrap();
        builder.add_op(OpDrop).unwrap();
        builder.add_op(OpFalse).unwrap();
        builder.add_op(OpVerify).unwrap();
        builder.add_op(OpEndIf).unwrap();
        builder.drain()
    } else {
        body
    }
}

#[test]
fn compiles_without_selector_single_function() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                require(1 + 2 == 3);
            }
        }
    "#;

    let contract = parse_contract_ast(source).expect("ast parsed");
    let compiled = compile_contract_ast(&contract, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(compiled.without_selector);

    let expected = ScriptBuilder::new()
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

    assert_eq!(compiled.script, expected);
}

#[test]
fn compiles_with_selector_multiple_entrypoints() {
    let source = r#"
        contract Test() {
            entrypoint function a() { require(true); }
            entrypoint function b() { require(true); }
        }
    "#;

    let contract = parse_contract_ast(source).expect("ast parsed");
    let compiled = compile_contract_ast(&contract, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(!compiled.without_selector);
    let selector = function_branch_index(&compiled.ast, "a").expect("selector resolved");
    let sigscript = compiled.build_sig_script("a", vec![]).expect("sigscript builds");
    let expected = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    assert_eq!(sigscript, expected);
}

#[test]
fn compiles_basic_arithmetic_and_verifies() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                require(1 + 2 == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
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

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn compiles_contract_constants_and_verifies() {
    let source = r#"
        contract Test() {
            int constant MAX_SUPPLY = 1_000_000;

            entrypoint function main() {
                require(MAX_SUPPLY == 1_000_000);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
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

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn compiles_contract_fields_as_script_prolog() {
    let source = r#"
        contract C() {
            int x = 5;
            byte[2] y = 0x1234;

            entrypoint function main() {
                require(x == 5);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected = ScriptBuilder::new()
        .add_data(&5i64.to_le_bytes())
        .unwrap()
        .add_data(&[0x12, 0x34])
        .unwrap()
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

    assert_eq!(compiled.script, expected);
}

#[test]
fn runs_contract_with_fields_prolog() {
    let source = r#"
        contract C() {
            int x = 5;
            byte[2] y = 0x1234;

            entrypoint function main() {
                require(x == 5);
                require(y == 0x1234);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn runs_selector_dispatch_with_contract_fields() {
    let source = r#"
        contract C() {
            int x = 5;
            byte[2] y = 0x1234;

            entrypoint function a() {
                require(true);
            }

            entrypoint function b() {
                require(x == 5);
                require(y == 0x1234);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    assert!(!compiled.without_selector, "test requires selector dispatch");

    let sigscript_a = compiled.build_sig_script("a", vec![]).expect("sigscript a builds");
    let sigscript_b = compiled.build_sig_script("b", vec![]).expect("sigscript b builds");

    let result_a = run_script_with_sigscript(compiled.script.clone(), sigscript_a);
    assert!(result_a.is_ok(), "entrypoint a runtime failed: {}", result_a.unwrap_err());

    let result_b = run_script_with_sigscript(compiled.script, sigscript_b);
    assert!(result_b.is_ok(), "entrypoint b runtime failed: {}", result_b.unwrap_err());
}

#[test]
fn compiles_validate_output_state_to_expected_script() {
    let source = r#"
        contract C(int init_x, byte[2] init_y) {
            int x = init_x;
            byte[2] y = init_y;

            entrypoint function main() {
                validateOutputState(0,{x:x+1,y:0x3412});
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        // <x> as fixed-size int field encoding: <PUSHDATA8><8-byte little-endian>
        .add_data(&5i64.to_le_bytes())
        .unwrap()
        // <y>
        .add_data(&[1u8, 2u8])
        .unwrap()

        // ---- Build new_state.x = x + 1 ----
        // duplicate x from stack (x is second item from top: y=0, x=1)
        .add_op(OpOver)
        .unwrap()
        // push literal 1
        .add_i64(1)
        .unwrap()
        // x + 1
        .add_op(OpAdd)
        .unwrap()

        // ---- Convert x+1 to fixed-size int field chunk: <0x08><8-byte payload> ----
        // convert numeric value to 8-byte payload
        .add_i64(8)
        .unwrap()
        .add_op(OpNum2Bin)
        .unwrap()
        // prepend PUSHDATA8 prefix byte
        .add_data(&[0x08])
        .unwrap()
        .add_op(OpSwap)
        .unwrap()
        .add_op(OpCat)
        .unwrap()
        // ---- Build new_state.y pushdata chunk ----
        // raw y bytes
        .add_data(&[0x34, 0x12])
        .unwrap()
        // pushdata prefix for 2-byte data is 0x02
        .add_data(&[0x02])
        .unwrap()
        // reorder to prefix || data
        .add_op(OpSwap)
        .unwrap()
        // resulting chunk: <0x02><0x3412>
        .add_op(OpCat)
        .unwrap()
        // combine x_chunk || y_chunk
        .add_op(OpCat)
        .unwrap()

        // ---- Extract REST_OF_SCRIPT from current input signature script ----
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
        // script_size of currently compiled contract (new redeem target)
        .add_i64(compiled.script.len() as i64)
        .unwrap()
        // sigscript_len - script_size => bytes before current redeem
        .add_op(OpSub)
        .unwrap()
        // add fixed current-state field prefix length: len(<x><y>) = 12
        .add_i64(12)
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
        .add_data(&[0x00, 0x00])
        .unwrap()
        // locking opcode prefix OP_BLAKE2B
        .add_data(&[OpBlake2b])
        .unwrap()
        // version || OP_BLAKE2B
        .add_op(OpCat)
        .unwrap()
        // pushdata-length byte for 32-byte hash
        .add_data(&[0x20])
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
        .add_data(&[OpEqual])
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
        // expected == actual
        .add_op(OpEqual)
        .unwrap()
        // enforce match
        .add_op(OpVerify)
        .unwrap()

        // ---- Entrypoint epilogue cleanup for original state fields ----
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

    assert_eq!(compiled.script, expected);
}

#[test]
fn runs_validate_output_state() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                validateOutputState(0,{x:x+1,y:0x3412});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input = test_input(0, sigscript_push_script(&input_compiled.script));

    let output_compiled =
        compile_contract(source, &[6.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputState runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_validate_output_state_with_state_variable() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                State next = {x: x + 1, y: 0x3412};
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input = test_input(0, sigscript_push_script(&input_compiled.script));

    let output_compiled =
        compile_contract(source, &[6.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputState runtime failed: {}", result.unwrap_err());
}

fn compiled_template_parts_and_hash(compiled: &CompiledContract) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let template_hash = Blake2bParams::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize().as_bytes().to_vec();
    (prefix, suffix, template_hash)
}

#[test]
fn encode_state_matches_replaced_state_segment() {
    let source = r#"
        contract A(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let state = struct_object(vec![("x", Expr::int(6)), ("y", vec![0x34u8, 0x12u8].into())]);

    let materialized_script = compiled.encode_state(&state).expect("encode succeeds");

    let mut contract = parse_contract_ast(source).expect("parse succeeds");
    let ExprKind::StateObject(entries) = &state.kind else {
        panic!("expected state object");
    };
    for field in &mut contract.fields {
        field.expr =
            entries.iter().find(|entry| entry.name == field.name).map(|entry| entry.expr.clone()).expect("state field exists");
    }
    let fully_materialized =
        compile_contract_ast(&contract, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    assert_eq!(materialized_script, fully_materialized.script);
    let layout = compiled.state_layout;
    assert_eq!(compiled.script[..layout.start], materialized_script[..layout.start]);
    assert_eq!(compiled.script[layout.start + layout.len..], materialized_script[layout.start + layout.len..]);
}

fn run_read_input_state_with_template_case(
    reader_source: &str,
    reader_constructor_args: &[Expr<'static>],
    target_input_compiled: &CompiledContract<'_>,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    run_read_input_state_with_template_case_with_input_spk(
        reader_source,
        reader_constructor_args,
        target_input_compiled,
        pay_to_script_hash_script(&target_input_compiled.script),
    )
}

fn run_read_input_state_with_template_case_with_input_spk(
    reader_source: &str,
    reader_constructor_args: &[Expr<'static>],
    target_input_compiled: &CompiledContract<'_>,
    input1_spk: ScriptPublicKey,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reader_compiled =
        compile_contract(reader_source, reader_constructor_args, CompileOptions::default()).expect("compile reader succeeds");

    let input0 = test_input(0, vec![]);
    let input1 = test_input(1, sigscript_push_script(&target_input_compiled.script));
    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, reader_compiled.script.clone().into()),
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
    output_compiled: &CompiledContract,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let mux_source = format!(
        r#"
        contract M(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {{
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entrypoint function routeToA() {{
                validateOutputStateWithTemplate(
                    0,
                    {{muxHash: muxHash, aHash: aHash, x: x + 1, y: 0x3412}},
                    0x{},
                    0x{},
                    0x{}
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

    let sigscript = mux_input_compiled.build_sig_script("routeToA", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(mux_input_compiled.script.clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&mux_input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
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

            entrypoint function noop() {
                require(true);
            }
        }
    "#;

    let target_a0 = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), Expr::int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
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

            entrypoint function routeToA() {{
                validateOutputStateWithTemplate(
                    0,
                    {{muxHash: muxHash, aHash: aHash, x: x + 1, y: 0x3412}},
                    0x{a_prefix_hex},
                    0x{a_suffix_hex},
                    0x{a_template_hash_hex}
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

    let sigscript = mux_input_compiled.build_sig_script("routeToA", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(mux_input_compiled.script.clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&mux_input_compiled.script);
    let output_spk = pay_to_script_hash_script(&target_output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputStateWithTemplate runtime failed: {}", result.unwrap_err());
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

            entrypoint function noop() {{
                require(y == 0x3412);
                require(x == 6);
                require(targetHash == 0x{target_hash_hex});
            }}
        }}
    "#
    );

    let target_a0 = compile_contract(
        &target_source,
        &[vec![0x55u8, 0x66u8].into(), Expr::int(0x1111_1111_1111_1111), vec![0x33u8; 32].into()],
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

            entrypoint function routeToA(byte[32] targetHash) {{
                C next = {{
                    y: 0x3412,
                    x: x + 1,
                    targetHash: targetHash
                }};
                validateOutputStateWithTemplate(
                    0,
                    next,
                    0x{a_prefix_hex},
                    0x{a_suffix_hex},
                    0x{a_template_hash_hex}
                );
            }}
        }}
    "#
    );

    let mux_input_compiled = compile_contract(&mux_source, &[5.into(), vec![0x10u8, 0x20u8].into()], CompileOptions::default())
        .expect("compile mux succeeds");

    let sigscript = mux_input_compiled.build_sig_script("routeToA", vec![target_hash_value.clone().into()]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(mux_input_compiled.script.clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);

    let input_spk = pay_to_script_hash_script(&mux_input_compiled.script);
    let output_spk = pay_to_script_hash_script(&target_output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(
        result.is_ok(),
        "validateOutputStateWithTemplate should route into a target contract whose State matches the passed struct layout: {}",
        result.unwrap_err()
    );

    let a_sigscript = target_output_compiled.build_sig_script("noop", vec![]).expect("A sigscript builds");
    let a_sigscript = pay_to_script_hash_signature_script(target_output_compiled.script.clone(), a_sigscript).unwrap();
    let a_input = test_input(0, a_sigscript);
    let a_output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, vec![OpTrue].into()), covenant: None };
    let a_tx = Transaction::new(1, vec![a_input], vec![a_output], 0, Default::default(), 0, vec![]);
    let a_utxo = UtxoEntry::new(1000, pay_to_script_hash_script(&target_output_compiled.script), 0, a_tx.is_coinbase(), None);
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

            entrypoint function noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), Expr::int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
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

            entrypoint function noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), Expr::int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
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

            entrypoint function noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), Expr::int(0x1111_1111_1111_1111), vec![0x55u8, 0x66u8].into()],
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

            entrypoint function noop() {
                require(true);
            }
        }
    "#;

    let target = compile_contract(
        target_source,
        &[vec![0x11u8; 32].into(), vec![0x33u8; 32].into(), Expr::int(0x1111_1111_1111_1111)],
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

    entrypoint function main() {
        int zero_count = 0;
        // Keep this loop small so regressions fail fast (the previous exponential blow-up
        // already manifested at single-digit iteration counts).
        for (i, 0, BOUND, BOUND) {
            if (OpBin2Num(board[i]) == 0) {
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
        let args = [Expr::int(b), Expr::bytes(vec![0u8; 64])];
        let compiled = compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile succeeds");
        lens.push(compiled.script.len());
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

            entrypoint function main(State[] xs) {
                State next = xs[0];
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = input_compiled.build_sig_script("main", vec![state_array_arg_x(vec![6])]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[6.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
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

            entrypoint function main(State[] xs) {
                (State[] ys) = id(xs);
                State next = ys[0];
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = input_compiled.build_sig_script("main", vec![state_array_arg_x(vec![6])]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[6.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "state value sourced from inline returned State[] should validate output state: {result:?}");
}

#[test]
fn read_input_state_accepts_self_state_under_selector_dispatch() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main() {
                State s = readInputState(this.activeInputIndex);
                require(s.x == 5);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = input_compiled.build_sig_script("main", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState should read the current state under selector dispatch: {result:?}");
}

#[test]
fn read_input_state_int_addition_uses_numeric_semantics() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entrypoint function main() {
                State s = readInputState(this.activeInputIndex);
                int y = s.x + 5;
                require(y == 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = compiled.build_sig_script("main", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("p2sh sigscript wraps");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState int arithmetic should use numeric semantics: {result:?}");
}

#[test]
fn read_input_state_accepts_three_field_state_under_selector_dispatch() {
    let source = r#"
        contract C(int initAmount, byte[2] initCode, byte[32] initOwner) {
            int amount = initAmount;
            byte[2] code = initCode;
            byte[32] owner = initOwner;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main() {
                State s = readInputState(this.activeInputIndex);
                require(s.amount == 5);
                require(s.code == 0x3412);
                require(s.owner == 0x0101010101010101010101010101010101010101010101010101010101010101);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![0x34u8, 0x12u8].into(), vec![1u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let sigscript = input_compiled.build_sig_script("main", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled =
        compile_contract(source, &[5.into(), vec![0x34u8, 0x12u8].into(), vec![1u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState should read mixed-width state under selector dispatch: {result:?}");
}

#[test]
fn read_input_state_accepts_pubkey_and_bool_fields_under_selector_dispatch() {
    let source = r#"
        contract C(bool initFlag, pubkey initOwner) {
            bool flag = initFlag;
            pubkey owner = initOwner;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main() {
                State s = readInputState(this.activeInputIndex);
                require(s.flag);
                require(s.owner == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[true.into(), vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = input_compiled.build_sig_script("main", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled =
        compile_contract(source, &[true.into(), vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "readInputState should read pubkey and bool state under selector dispatch: {result:?}");
}

#[test]
fn read_input_state_runtime_preserves_supported_field_types_across_contract_shapes() {
    let run_case = |source: &str, args: Vec<Expr<'_>>, label: &str| {
        let compiled = compile_contract(source, &args, CompileOptions::default()).unwrap_or_else(|err| panic!("{label}: {err:?}"));
        let sigscript = compiled.build_sig_script("main", vec![]).expect("sigscript builds");
        let sigscript = pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("p2sh sigscript wraps");
        let input = test_input(0, sigscript);
        let input_spk = pay_to_script_hash_script(&compiled.script);
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

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
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

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someInts.length == 2);
                    require(x.someInts[0] == 1);
                    require(x.someInts[1] + 5 == 7);
                }
            }
        "#,
        vec![vec![Expr::int(1), Expr::int(2)].into()],
        "int[2] fields should preserve array indexing semantics",
    );

    run_case(
        r#"
            contract C(bool initBool) {
                bool someBool = initBool;

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
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

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBools.length == 2);
                    require(x.someBools[0]);
                    require(!x.someBools[1]);
                }
            }
        "#,
        vec![vec![Expr::bool(true), Expr::bool(false)].into()],
        "bool[2] fields should preserve array indexing semantics",
    );

    run_case(
        r#"
            contract C(byte[2] initBytes2) {
                byte[2] someBytes2 = initBytes2;

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBytes2.length == 2);
                    require(x.someBytes2 == 0x3412);
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

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.somePubkey == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));

                    byte[] owner = byte[](x.somePubkey);
                    owner.push(byte(3));
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

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someSig == sig(0x1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111));

                    byte[] sigBytes = byte[](x.someSig);
                    sigBytes.push(byte(0x42));
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

                entrypoint function noop() {
                    require(true);
                }

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someDatasig == datasig(0x22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222));

                    byte[] datasigBytes = byte[](x.someDatasig);
                    datasigBytes.push(byte(0x24));
                    require(datasigBytes.length == 65);
                }
            }
        "#,
        vec![vec![0x22u8; 64].into()],
        "datasig fields should preserve fixed-size byte semantics",
    );
}

#[test]
fn read_input_state_runtime_preserves_supported_field_types_without_selector_dispatch() {
    let run_case = |source: &str, args: Vec<Expr<'_>>, label: &str| {
        let compiled = compile_contract(source, &args, CompileOptions::default()).unwrap_or_else(|err| panic!("{label}: {err:?}"));
        let sigscript = compiled.build_sig_script("main", vec![]).expect("sigscript builds");
        let sigscript = pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("p2sh sigscript wraps");
        let input = test_input(0, sigscript);
        let input_spk = pay_to_script_hash_script(&compiled.script);
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

                entrypoint function main() {
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

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.someBytes2.length == 2);
                    require(x.someBytes2 == 0x3412);
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

                entrypoint function main() {
                    State x = readInputState(this.activeInputIndex);
                    require(x.somePubkey == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));

                    byte[] owner = byte[](x.somePubkey);
                    owner.push(byte(3));
                    require(owner.length == 33);
                }
            }
        "#,
        vec![vec![2u8; 32].into()],
        "single-entrypoint pubkey fields should preserve fixed-size byte semantics",
    );
}

// TODO: Fix this bug by using builder.add_data_with_push_opcode instead of builder.add_data after covpp-reset2 is finalized.
#[test]
fn read_input_state_scalar_byte_regression_repros_runtime_mismatch() {
    let source = r#"
        contract C(byte initByte, pubkey initOwner) {
            byte someByte = initByte;
            pubkey someOwner = initOwner;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main() {
                State x = readInputState(this.activeInputIndex);

                // The companion pubkey field proves the state offsets are otherwise correct for this layout.
                require(x.someOwner == pubkey(0x0202020202020202020202020202020202020202020202020202020202020202));

                // This should succeed once scalar byte fields round-trip through readInputState with
                // the same semantics as ordinary byte values. Today it still fails at runtime.
                require(x.someByte == 7);
            }
        }
    "#;

    let compiled =
        compile_contract(source, &[Expr::byte(7), vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = compiled.build_sig_script("main", vec![]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("p2sh sigscript wraps");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: input_spk.clone(), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_err(), "scalar byte readInputState regression should currently fail at runtime");
}

#[test]
fn validate_output_state_accepts_state_under_selector_dispatch() {
    let source = r#"
        contract C(int initX) {
            int x = initX;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main(State next) {
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[5.into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = input_compiled.build_sig_script("main", vec![struct_object(vec![("x", Expr::int(6))])]).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[6.into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "state value should validate output state under selector dispatch: {result:?}");
}

#[test]
fn validate_output_state_accepts_three_field_state_under_selector_dispatch() {
    let source = r#"
        contract C(int initAmount, byte[2] initCode, byte[32] initOwner) {
            int amount = initAmount;
            byte[2] code = initCode;
            byte[32] owner = initOwner;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main(State next) {
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![0x34u8, 0x12u8].into(), vec![1u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let sigscript = input_compiled
        .build_sig_script(
            "main",
            vec![struct_object(vec![
                ("amount", Expr::int(6)),
                ("code", Expr::bytes(vec![0xabu8, 0xcdu8])),
                ("owner", Expr::bytes(vec![2u8; 32])),
            ])],
        )
        .expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled =
        compile_contract(source, &[6.into(), vec![0xabu8, 0xcdu8].into(), vec![2u8; 32].into()], CompileOptions::default())
            .expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "mixed-width state should validate output state under selector dispatch: {result:?}");
}

#[test]
fn debug_validate_output_state_accepts_current_byte32_fields() {
    let source = r#"
        contract C(byte[32] initMuxHash, byte[32] initAHash, int initX, byte[2] initY) {
            byte[32] muxHash = initMuxHash;
            byte[32] aHash = initAHash;
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                validateOutputState(0, {muxHash: muxHash, aHash: aHash, x: x + 1, y: 0x3412});
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

    let input = test_input(0, sigscript_push_script(&input_compiled.script));
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "validateOutputState should accept current byte[32] fields: {result:?}");
}

#[test]
fn validate_output_state_accepts_pubkey_field_under_selector_dispatch() {
    let source = r#"
        contract C(pubkey initOwner) {
            pubkey owner = initOwner;

            entrypoint function noop() {
                require(true);
            }

            entrypoint function main(State next) {
                validateOutputState(0, next);
            }
        }
    "#;

    let input_compiled = compile_contract(source, &[vec![1u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let sigscript = input_compiled
        .build_sig_script("main", vec![struct_object(vec![("owner", Expr::bytes(vec![2u8; 32]))])])
        .expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_compiled.script.clone(), sigscript).unwrap();
    let output_compiled = compile_contract(source, &[vec![2u8; 32].into()], CompileOptions::default()).expect("compile succeeds");
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let output_spk = pay_to_script_hash_script(&output_compiled.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);

    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "pubkey state should validate output state under selector dispatch: {result:?}");
}

#[test]
fn compiles_state_variable_and_internal_function_argument() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            function check(State s) {
                require(s.x == 6);
                require(s.y == 0x3412);
            }

            entrypoint function main() {
                State next = {x: x + 1, y: 0x3412};
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
                require(s.y == 0x3412);
            }

            entrypoint function main() {
                State next = {x: x + 1, y: 0x3412};
                check(next);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let result = run_script_with_selector(compiled.script, selector);
    assert!(result.is_ok(), "script should execute successfully: {result:?}");
}

#[test]
fn plain_state_return_accepts_local_fixed_byte_field_from_local_identifier() {
    let source = r#"
        contract C(byte[2] initData) {
            byte[2] data = initData;

            function step(State prev_state) : (State) {
                byte[2] next_data = prev_state.data;
                return({
                    data: next_data
                });
            }

            entrypoint function main() {
                State prev = {data: data};
                (State next) = step(prev);
                require(next.data == data);
            }
        }
    "#;

    compile_contract(source, &[vec![0u8, 0u8].into()], CompileOptions::default())
        .expect("plain State return with local fixed-byte identifier should compile");
}

#[test]
fn byte_hex_literal_error_recommends_scalar_cast() {
    let source = r#"
        contract C() {
            entrypoint function main() {
                byte local = 0x07;
                require(local == local);
            }
        }
    "#;

    let err =
        compile_contract(source, &[], CompileOptions::default()).expect_err("scalar byte hex literal should require an explicit cast");

    assert_eq!(
        err.to_string(),
        "unsupported feature: variable 'local' expects byte; hex literals are byte arrays; use byte(0x07) to cast a one-byte hex literal to byte"
    );
}

#[test]
fn compiles_read_input_state_to_expected_script() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                {x: int in1_x, y: byte[2] in1_y} = readInputState(1);
                require(in1_x > 7);
                require(in1_y == 0x3412);
            }
        }
    "#;

    let compiled = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        // ---- Prolog state on active input: x=5, y=0x0102 ----
        // push x payload (8-byte LE)
        .add_data(&5i64.to_le_bytes())
        .unwrap()
        // push y payload bytes
        .add_data(&[1u8, 2u8])
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
        // this.scriptSize
        .add_i64(compiled.script.len() as i64)
        .unwrap()
        // base = sig_len - script_size
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
        // this.scriptSize
        .add_i64(compiled.script.len() as i64)
        .unwrap()
        // base = sig_len - script_size
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
        // this.scriptSize
        .add_i64(compiled.script.len() as i64)
        .unwrap()
        // base = sig_len - script_size
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
        // this.scriptSize
        .add_i64(compiled.script.len() as i64)
        .unwrap()
        // base = sig_len - script_size
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
        .add_data(&[0x34, 0x12])
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

    assert_eq!(compiled.script, expected);
}

#[test]
fn runs_read_input_state() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                {x: int in1_x, y: byte[2] in1_y} = readInputState(1);
                require(in1_x > 7);
                require(in1_y == 0x3412);
            }
        }
    "#;

    let active_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input1_compiled =
        compile_contract(source, &[8.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input0 = test_input(0, vec![]);
    let input1 = test_input(1, sigscript_push_script(&input1_compiled.script));

    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, active_compiled.script.clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input0.clone(), input1], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo0 = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let utxo1 = UtxoEntry::new(1000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, tx.is_coinbase(), None);
    let result = execute_input(tx, vec![utxo0, utxo1], 0);
    assert!(result.is_ok(), "readInputState runtime failed: {}", result.unwrap_err());
}

#[test]
fn runs_read_input_state_into_state_variable() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                State in1 = readInputState(1);
                require(in1.x > 7);
                require(in1.y == 0x3412);
            }
        }
    "#;

    let active_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let input1_compiled =
        compile_contract(source, &[8.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input0 = test_input(0, vec![]);
    let input1 = test_input(1, sigscript_push_script(&input1_compiled.script));

    let output = TransactionOutput {
        value: 1000,
        script_public_key: ScriptPublicKey::new(0, active_compiled.script.clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input0.clone(), input1], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo0 = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let utxo1 = UtxoEntry::new(1000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, tx.is_coinbase(), None);
    let result = execute_input(tx, vec![utxo0, utxo1], 0);
    assert!(result.is_ok(), "readInputState runtime failed: {}", result.unwrap_err());
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

            entrypoint function noop() {
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

            entrypoint function main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    0x{}
                );
                require(round == 5);
                require(remote.y == 0x3412);
                require(remote.x == 8);
                require(remote.targetHash == 0x{target_hash_hex});
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
fn runs_read_input_state_with_template_destructuring() {
    let target_hash_value = vec![0x55u8; 32];
    let target_hash_hex = target_hash_value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();

    let target_source = r#"
        contract A(byte[2] initY, int initX, byte[32] initTargetHash) {
            byte[2] y = initY;
            int x = initX;
            byte[32] targetHash = initTargetHash;

            entrypoint function noop() {
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

            entrypoint function main() {{
                {{y: byte[2] inY, x: int inX, targetHash: byte[32] inHash}} = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    0x{}
                );
                require(inY == 0x7856);
                require(inX == 11);
                require(inHash == 0x{target_hash_hex});
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

            entrypoint function noop() {
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

            entrypoint function main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    0x{}
                );
                require(remote.y == 0x3412);
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

            entrypoint function noop() {
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

            entrypoint function main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    0x{}
                );
                require(remote.y == 0x3412);
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

            entrypoint function noop() {
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

            entrypoint function main() {{
                RemoteState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    0x{}
                );
                require(remote.y == 0x3412);
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

            entrypoint function main(int prefixLen, int suffixLen, byte[32] templateHash) {
                check(readInputStateWithTemplate(1, prefixLen, suffixLen, templateHash));
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default())
        .expect_err("readInputStateWithTemplate should be rejected outside direct struct bindings");
    assert!(err.to_string().contains("must be assigned to a struct variable or destructured directly"), "unexpected error: {err}");
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

            entrypoint function main() {
                OtherState next = {z: 7};
                validateOutputState(0, next);
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("wrong struct type should be rejected");
    assert!(err.to_string().contains("State") || err.to_string().contains("struct"), "unexpected error: {err}");
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

            entrypoint function route(byte[32] targetHash) {
                C next = {
                    y: 0x3412,
                    x: x + 1,
                    targetHash: targetHash
                };
                validateOutputStateWithTemplate(
                    0,
                    next,
                    0x51,
                    0x52,
                    0x0000000000000000000000000000000000000000000000000000000000000000
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

            entrypoint function main() {
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
fn fails_validate_output_state_with_wrong_output_index() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                validateOutputState(0,{x:x+1,y:0x3412});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let expected_output_state =
        compile_contract(source, &[6.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input = test_input(0, sigscript_push_script(&input_compiled.script));

    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let matching_spk = pay_to_script_hash_script(&expected_output_state.script);
    let wrong_spk = pay_to_script_hash_script(&input_compiled.script);

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

            entrypoint function main() {
                validateOutputState(0,{x:x+1,y:0x3412});
            }
        }
    "#;

    let input_compiled =
        compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default()).expect("compile succeeds");
    let wrong_output_state =
        compile_contract(source, &[7.into(), vec![0x34u8, 0x12u8].into()], CompileOptions::default()).expect("compile succeeds");

    let input = test_input(0, sigscript_push_script(&input_compiled.script));

    let input_spk = pay_to_script_hash_script(&input_compiled.script);
    let wrong_output_spk = pay_to_script_hash_script(&wrong_output_state.script);
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

            entrypoint function main() {
                validateOutputState(0,{x:x+1});
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("state object missing fields should fail");
    assert!(err.to_string().contains("new_state must include all contract fields exactly once"), "unexpected error: {err}");
}

#[test]
fn rejects_validate_output_state_with_duplicate_state_field() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                validateOutputState(0,{x:x+1,y:0x3412,x:x+2});
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("state object duplicate fields should fail");
    assert!(err.to_string().contains("duplicate state field 'x'"), "unexpected error: {err}");
}

#[test]
fn rejects_validate_output_state_with_unknown_state_field() {
    let source = r#"
        contract C(int initX, byte[2] initY) {
            int x = initX;
            byte[2] y = initY;

            entrypoint function main() {
                validateOutputState(0,{x:x+1,y:0x3412,z:1});
            }
        }
    "#;

    let err = compile_contract(source, &[5.into(), vec![1u8, 2u8].into()], CompileOptions::default())
        .expect_err("state object with unknown field should fail");
    assert!(err.to_string().contains("new_state must include all contract fields exactly once"), "unexpected error: {err}");
}

fn assert_compiled_body(source: &str, body: Vec<u8>) {
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let expected = wrap_with_dispatch(body, selector);
    assert_eq!(compiled.script, expected);
}

#[test]
fn compiles_opcode_builtins() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(byte[](OpSha256(bytes("msg"))) == byte[]("hash"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"msg")
                .unwrap()
                .add_op(OpSHA256)
                .unwrap()
                .add_data(b"hash")
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
                    entrypoint function main() {
                        require(OpTxSubnetId() == bytes("subnet"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_op(OpTxSubnetId)
                .unwrap()
                .add_data(b"subnet")
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
                    entrypoint function main() {
                        require(OpTxGas() == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxPayloadLen() >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxPayloadSubstr(1, 3) == bytes("ok"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(1)
                .unwrap()
                .add_i64(3)
                .unwrap()
                .add_op(OpTxPayloadSubstr)
                .unwrap()
                .add_data(b"ok")
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
                    entrypoint function main() {
                        require(OpOutpointTxId(0) == bytes("txid"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpOutpointTxId)
                .unwrap()
                .add_data(b"txid")
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
                    entrypoint function main() {
                        require(OpOutpointIndex(0) == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxInputScriptSigLen(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxInputScriptSigSubstr(0, 0, 1) == bytes("sig"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxInputScriptSigSubstr)
                .unwrap()
                .add_data(b"sig")
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
                    entrypoint function main() {
                        require(OpTxInputSeq(0) == bytes("seq"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputSeq)
                .unwrap()
                .add_data(b"seq")
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
                    entrypoint function main() {
                        require(OpTxInputDaaScore(0) == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxInputDaaScore(0) == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxInputIsCoinbase(0) == false);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputIsCoinbase)
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
                    entrypoint function main() {
                        require(OpTxInputSpkLen(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxInputSpkSubstr(0, 0, 1) == bytes("spk"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxInputSpkSubstr)
                .unwrap()
                .add_data(b"spk")
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
                    entrypoint function main() {
                        require(OpTxOutputSpkLen(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpTxOutputSpkSubstr(0, 0, 1) == bytes("out"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxOutputSpkSubstr)
                .unwrap()
                .add_data(b"out")
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
                    entrypoint function main() {
                        require(OpAuthOutputCount(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(OpAuthOutputIdx(0, 0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
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
                    entrypoint function main() {
                        require(byte[](OpInputCovenantId(0)) == bytes("cov"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpInputCovenantId)
                .unwrap()
                .add_data(b"cov")
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
                    entrypoint function main() {
                        require(OpCovInputCount(bytes("c1")) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
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
                    entrypoint function main() {
                        require(OpCovInputIdx(bytes("c1"), 0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
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
                    entrypoint function main() {
                        require(OpCovOutputCount(bytes("c1")) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
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
                    entrypoint function main() {
                        require(OpCovOutputIdx(bytes("c1"), 0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
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
                    entrypoint function main() {
                        require(OpNum2Bin(5, 2) == bytes("bin"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(5)
                .unwrap()
                .add_i64(2)
                .unwrap()
                .add_op(OpNum2Bin)
                .unwrap()
                .add_data(b"bin")
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
                    entrypoint function main() {
                        require(OpBin2Num(bytes("a")) == 5);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"a")
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
                    entrypoint function main() {
                        require(OpChainblockSeqCommit(bytes("block")) == bytes("commit"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"block")
                .unwrap()
                .add_op(OpChainblockSeqCommit)
                .unwrap()
                .add_data(b"commit")
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
                    entrypoint function main() {
                        require(OpSha256(bytes("msg")) == OpSha256(bytes("msg")));
                    }
                }
            "#,
        ),
        (
            "subnet_id",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxSubnetId() == bytes("abcdefghijklmnopqrst"));
                    }
                }
            "#,
        ),
        (
            "gas",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxGas() == 123);
                    }
                }
            "#,
        ),
        (
            "payload_len",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxPayloadLen() == 12);
                    }
                }
            "#,
        ),
        (
            "payload_substr",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxPayloadSubstr(0, 7) == bytes("payload"));
                    }
                }
            "#,
        ),
        (
            "outpoint_txid",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpOutpointTxId(0) == bytes("0123456789abcdef0123456789abcdef"));
                    }
                }
            "#,
        ),
        (
            "outpoint_index",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpOutpointIndex(0) == 7);
                    }
                }
            "#,
        ),
        (
            "sigscript_len",
            r#"
                contract Test() {
                    entrypoint function dummy() { require(true); }
                    entrypoint function main() {
                        require(OpTxInputScriptSigLen(0) == 1);
                    }
                }
            "#,
        ),
        (
            "sigscript_substr",
            r#"
                contract Test() {
                    entrypoint function dummy() { require(true); }
                    entrypoint function main() {
                        require(OpTxInputScriptSigSubstr(0, 0, 1) == bytes("Q"));
                    }
                }
            "#,
        ),
        (
            "input_seq",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxInputSeq(0) == bytes("sequence"));
                    }
                }
            "#,
        ),
        (
            "input_daa_score",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxInputDaaScore(0) == 0);
                    }
                }
            "#,
        ),
        (
            "is_coinbase",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxInputIsCoinbase(0) == bool(0));
                    }
                }
            "#,
        ),
        (
            "input_spk_len",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxInputSpkLen(0) == OpTxInputSpkLen(0));
                    }
                }
            "#,
        ),
        (
            "input_spk_substr",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxInputSpkSubstr(0, 0, 1) == OpTxInputSpkSubstr(0, 0, 1));
                    }
                }
            "#,
        ),
        (
            "output_spk_len",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxOutputSpkLen(0) == 8);
                    }
                }
            "#,
        ),
        (
            "output_spk_substr",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxOutputSpkSubstr(0, 2, 8) == bytes("outspk"));
                    }
                }
            "#,
        ),
        (
            "num2bin_bin2num",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpBin2Num(OpNum2Bin(5, 2)) == 5);
                    }
                }
            "#,
        ),
    ];

    for (name, source) in cases {
        let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
        let selector = selector_for(&compiled, "main");
        let sigscript = selector_sigscript(selector);
        let (tx, entries) = build_basic_opcode_tx(sigscript);
        let result = run_script_with_tx_and_covenants(compiled.script, tx, entries, None);
        assert!(result.is_ok(), "opcode builtin {name} failed: {}", result.unwrap_err());
    }
}

#[test]
fn executes_opcode_builtins_covenants() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                require(OpAuthOutputCount(0) == 2);
                require(OpAuthOutputIdx(0, 1) == 2);
                require(byte[](OpInputCovenantId(0)) == bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
                require(OpCovInputCount(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) == 2);
                require(OpCovInputIdx(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1) == 2);
                require(OpCovOutputCount(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) == 2);
                require(OpCovOutputIdx(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1) == 2);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let sigscript = selector_sigscript(selector);
    let covenant_id_a = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let covenant_id_b = Hash::from_bytes(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    let (tx, entries) = build_covenant_opcode_tx(sigscript, covenant_id_a, covenant_id_b);

    let result = run_script_with_tx_and_covenants(compiled.script, tx, entries, None);
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
            entrypoint function main() {
                require(OpChainblockSeqCommit(bytes("0123456789abcdef0123456789abcdef")) == bytes("fedcba9876543210fedcba9876543210"));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let sigscript = selector_sigscript(selector);
    let (tx, entries) = build_basic_opcode_tx(sigscript);

    let block = Hash::from_bytes(*b"0123456789abcdef0123456789abcdef");
    let commitment = Hash::from_bytes(*b"fedcba9876543210fedcba9876543210");
    let accessor = MockSeqCommitAccessor { block, commitment };
    let result = run_script_with_tx_and_covenants(compiled.script, tx, entries, Some(&accessor));
    assert!(result.is_ok(), "chainblock seq commit failed: {}", result.unwrap_err());
}

#[test]
fn compiles_if_else_and_verifies() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                if (1 < 2) {
                    require(true);
                } else {
                    require(false);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
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

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn compiles_time_op_csv_and_verifies() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                require(this.age >= 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new().add_i64(10).unwrap().add_op(OpCheckSequenceVerify).unwrap().add_op(OpTrue).unwrap().drain();
    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_tx(compiled.script, selector, 0, 20).is_ok());
}

#[test]
fn compiles_reused_variables_and_verifies() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                int a = 2 + 3;
                int b = a * a + a;
                require(b == 30);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
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
        .add_i64(0)
        .unwrap()
        .add_op(OpRoll)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn return_reused_local_is_stored_once_and_reused() {
    let source = r#"
        contract Test() {
            entrypoint function main() : (int) {
                int a = 2 + 3;
                return(a * a + a);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions { allow_entrypoint_return: true, ..CompileOptions::default() })
        .expect("compile succeeds");

    let expected = ScriptBuilder::new()
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

    assert_eq!(compiled.script, expected);
}

#[test]
fn compiles_sigscript_inputs_and_verifies() {
    let source = r#"
        contract Test() {
            entrypoint function main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let mut builder = ScriptBuilder::new();
    builder.add_i64(3).unwrap();
    builder.add_i64(4).unwrap();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    let sigscript = builder.drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "sigscript test failed: {}", result.unwrap_err());
}

#[test]
fn compiles_script_size_and_runs_sum_array() {
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

            entrypoint function main(int expected_script_size) {
                require(expected_script_size == this.scriptSize);
                int[] x;
                x.push(1);
                x.push(2);
                x.push(3);
                (int total) = sumArray(x);
                require(total == 6);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_size = compiled.script.len() as i64;
    let sigscript = compiled.build_sig_script("main", vec![Expr::int(expected_size)]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "script size contract failed: {}", result.unwrap_err());
}

fn data_prefix_for_size(data_len: usize) -> Vec<u8> {
    let dummy_data = vec![0u8; data_len];
    let mut builder = ScriptBuilder::new();
    builder.add_data(&dummy_data).unwrap();
    let script = builder.drain();
    script[..script.len() - data_len].to_vec()
}

#[test]
fn compiles_script_size_data_prefix_small_script() {
    let source = r#"
        contract PrefixSmall() {
            entrypoint function main(byte[] expected_data_prefix) {
                require(expected_data_prefix == this.scriptSizeDataPrefix);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(compiled.script.len());
    let sigscript = compiled.build_sig_script("main", vec![Expr::bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "scriptSizeDataPrefix small failed: {}", result.unwrap_err());
}

#[test]
fn compiles_script_size_data_prefix_medium_script() {
    let source = r#"
        contract PrefixMedium() {
            entrypoint function main(byte[] expected_data_prefix) {
                require(expected_data_prefix == this.scriptSizeDataPrefix);
                for (i, 0, 100, 100) {
                    require(true);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(compiled.script.len());
    let sigscript = compiled.build_sig_script("main", vec![Expr::bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "scriptSizeDataPrefix medium failed: {}", result.unwrap_err());
}

#[test]
fn compiles_script_size_data_prefix_large_script() {
    let source = r#"
        contract PrefixLarge() {
            entrypoint function main(byte[] expected_data_prefix) {
                require(expected_data_prefix == this.scriptSizeDataPrefix);
                for (i, 0, 300, 300) {
                    require(true);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(compiled.script.len());
    let sigscript = compiled.build_sig_script("main", vec![Expr::bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "scriptSizeDataPrefix large failed: {}", result.unwrap_err());
}

#[test]
fn compiles_sigscript_reused_inputs_and_verifies() {
    let source = r#"
        contract Test() {
            entrypoint function main(int a) {
                require(a * a + a == 12);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let mut builder = ScriptBuilder::new();
    builder.add_i64(3).unwrap();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    let sigscript = builder.drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "sigscript reuse test failed: {}", result.unwrap_err());
}

#[test]
fn compiles_sigscript_inputs_and_fails_on_wrong_sum() {
    let source = r#"
        contract Test() {
            entrypoint function main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let mut builder = ScriptBuilder::new();
    builder.add_i64(2).unwrap();
    builder.add_i64(4).unwrap();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    let sigscript = builder.drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}

#[test]
fn compiles_sigscript_reused_inputs_and_fails_on_wrong_value() {
    let source = r#"
        contract Test() {
            entrypoint function main(int a) {
                require(a * a + a == 12);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(&compiled, "main");
    let mut builder = ScriptBuilder::new();
    builder.add_i64(4).unwrap();
    if let Some(selector) = selector {
        builder.add_i64(selector).unwrap();
    }
    let sigscript = builder.drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}

#[test]
fn compile_time_length_for_fixed_size_int_array() {
    let source = r#"
        contract Test() {
            entrypoint function test() {
                int[5] nums = [1, 2, 3, 4, 5];
                require(nums.length == 5);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    // Expected script for compile-time length:
    // The nums.length should be replaced with a compile-time constant 5
    // require(nums.length == 5) becomes: <5> <5> OP_NUMEQUALVERIFY, then OP_TRUE for entrypoint return
    let expected_script = vec![
        0x55, // OP_5 (push 5 for nums.length)
        0x55, // OP_5 (push 5 for comparison)
        0x9c, // OP_NUMEQUALVERIFY (combined OP_NUMEQUAL + OP_VERIFY)
        0x69, // OP_VERIFY
        0x51, // OP_TRUE (entrypoint return value)
    ];

    assert_eq!(
        compiled.script, expected_script,
        "Script should use compile-time length. Expected: {:?}, Got: {:?}",
        expected_script, compiled.script
    );
}

#[test]
fn compile_time_length_for_fixed_size_byte_array() {
    let source = r#"
        contract Test() {
            entrypoint function test() {
                byte[3] data = 0x010203;
                require(data.length == 3);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    // Expected script for compile-time length:
    // data.length should be replaced with a compile-time constant 3
    // require(data.length == 3) becomes: <3> <3> OP_NUMEQUALVERIFY, then OP_TRUE for entrypoint return
    let expected_script = vec![
        0x53, // OP_3 (push 3 for data.length)
        0x53, // OP_3 (push 3 for comparison)
        0x9c, // OP_NUMEQUALVERIFY (combined OP_NUMEQUAL + OP_VERIFY)
        0x69, // OP_VERIFY
        0x51, // OP_TRUE (entrypoint return value)
    ];

    assert_eq!(
        compiled.script, expected_script,
        "Script should use compile-time length. Expected: {:?}, Got: {:?}",
        expected_script, compiled.script
    );
}

#[test]
fn compile_time_length_for_inferred_array_sizes() {
    let source = r#"
        contract Test() {
            entrypoint function test() {
                byte[_] data = 0x1234abcd;
                int[_] nums = [1, 2, 3];
                require(data.length == 4);
                require(nums.length == 3);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    // Both lengths should be compile-time constants (no OP_SIZE path):
    // require(data.length == 4) -> OP_4 OP_4 OP_NUMEQUALVERIFY
    // require(nums.length == 3) -> OP_3 OP_3 OP_NUMEQUALVERIFY
    let expected_script = vec![
        0x54, // OP_4 (data.length)
        0x54, // OP_4
        0x9c, // OP_NUMEQUALVERIFY
        0x69, // OP_VERIFY
        0x53, // OP_3 (nums.length)
        0x53, // OP_3
        0x9c, // OP_NUMEQUALVERIFY
        0x69, // OP_VERIFY
        0x51, // OP_TRUE
    ];

    assert_eq!(
        compiled.script, expected_script,
        "Script should use compile-time inferred lengths. Expected: {:?}, Got: {:?}",
        expected_script, compiled.script
    );
}

#[test]
fn accepts_fixed_size_array_init_with_correct_size() {
    let source = r#"
        contract Test() {
            entrypoint function test() {
                int[4] nums = [1, 2, 3, 4];
                byte[3] data = 0x010203;
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
            entrypoint function test() {
                int[4] nums = [1, 2, 3];  // Too few
            }
        }
    "#;
    let result = compile_contract(source, &[], CompileOptions::default());
    assert!(result.is_err(), "Should reject array with too few elements");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("type mismatch") || err_msg.contains("size mismatch"), "Error should mention type or size mismatch");
}

#[test]
fn rejects_fixed_size_array_init_with_too_many_elements() {
    let source = r#"
        contract Test() {
            entrypoint function test() {
                int[3] nums = [1, 2, 3, 4, 5];  // Too many
            }
        }
    "#;
    let result = compile_contract(source, &[], CompileOptions::default());
    assert!(result.is_err(), "Should reject array with too many elements");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("type mismatch") || err_msg.contains("size mismatch"), "Error should mention type or size mismatch");
}

#[test]
fn accepts_fixed_size_byte_array_init() {
    let source = r#"
        contract Test() {
            entrypoint function test() {
                byte[32] hash = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
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
            entrypoint function test() {
                int[SIZE] nums = [1, 2, 3, 4];
                require(nums.length == SIZE);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds with int[SIZE]");
}

#[test]
fn compile_time_length_with_constant_size() {
    // Test that array.length is computed at compile-time for arrays with constant sizes
    let source = r#"
        contract Test() {
            int constant SIZE = 5;
            entrypoint function test() {
                int[SIZE] nums = [1, 2, 3, 4, 5];
                require(nums.length == SIZE);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    // Expected script for compile-time length with constant size:
    // nums.length should be replaced with compile-time constant 5 (from SIZE)
    // SIZE constant should also be replaced with 5
    // require(nums.length == SIZE) becomes: <5> <5> OP_NUMEQUALVERIFY
    let expected_script = vec![
        0x55, // OP_5 (push 5 for nums.length)
        0x55, // OP_5 (push 5 for SIZE constant)
        0x9c, // OP_NUMEQUALVERIFY
        0x69, // OP_VERIFY
        0x51, // OP_TRUE (entrypoint return value)
    ];

    assert_eq!(
        compiled.script, expected_script,
        "Script should use compile-time length with constant. Expected: {:?}, Got: {:?}",
        expected_script, compiled.script
    );
}

#[test]
fn accepts_byte_array_with_constant_size() {
    // Test that constants work with byte arrays too
    let source = r#"
        contract Test() {
            int constant HASH_SIZE = 32;
            entrypoint function test(byte[HASH_SIZE] hash) {
                require(hash.length == HASH_SIZE);
            }
        }
    "#;
    compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds with byte[HASH_SIZE]");
}

#[test]
fn blake2b_int_and_byte_cast_forms_compile_to_identical_script() {
    let source_plain = r#"
        contract Test() {
            entrypoint function test() {
                int x = 5;
                require(blake2b(x).length == 32);
            }
        }
    "#;

    let source_cast = r#"
        contract Test() {
            entrypoint function test() {
                int x = 5;
                require(blake2b(byte[](x)).length == 32);
            }
        }
    "#;

    let compiled_plain = compile_contract(source_plain, &[], CompileOptions::default()).expect("plain form compiles");
    let compiled_cast = compile_contract(source_cast, &[], CompileOptions::default()).expect("byte-cast form compiles");

    assert_eq!(
        compiled_plain.script, compiled_cast.script,
        "blake2b(x) and blake2b(byte[](x)) should currently compile to identical scripts"
    );
}

#[test]
fn empty_array_statement_expr_evaluation_compiles_to_empty_array_data() {
    let source = r#"
        contract Test() {
            entrypoint function main() {
                require([] == []);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_data(&[])
        .unwrap()
        .add_data(&[])
        .unwrap()
        .add_op(OpEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
    assert_eq!(compiled.script[0], OpFalse);
    assert_eq!(compiled.script[1], OpFalse);
}

#[test]
fn function_param_shadows_constructor_constant_with_same_name() {
    // When a constructor constant and a function parameter share the same name,
    // the function parameter value must be used (not the constant).
    let source = r#"
        contract Shadow(int fee) {
            entrypoint function main(int fee) {
                int local = fee + 1;
                require(local == 4);
            }
        }
    "#;

    // Constructor fee=2, param fee=3 => local = 3+1 = 4 => pass
    let compiled = compile_contract(source, &[Expr::int(2)], CompileOptions::default()).expect("compile succeeds");
    let sigscript = compiled.build_sig_script("main", vec![Expr::int(3)]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script.clone(), sigscript);
    assert!(result.is_ok(), "function param should shadow constructor constant: {}", result.unwrap_err());

    // Constructor fee=2, param fee=2 => local = 2+1 = 3 != 4 => fail (proves it's not always the constant)
    let sigscript_wrong = compiled.build_sig_script("main", vec![Expr::int(2)]).expect("sigscript builds");
    let result_wrong = run_script_with_sigscript(compiled.script, sigscript_wrong);
    assert!(result_wrong.is_err(), "require(3==4) should fail, proving the param value matters");
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

            entrypoint function main(int a) {
                top(a);
                require(a >= 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested inline calls should compile");
    let sigscript = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result = run_script_with_sigscript(compiled.script, sigscript);
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

            entrypoint function main(int x) {
                helper(x);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline helper should compile");

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "x + 1 should be computed once and stored for both require statements"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored inline local should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(10)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
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

            entrypoint function main(int x) {
                f(x + 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline call should compile");

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "x + 1 should be computed once and reused for both require statements in the inline callee"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored inline argument should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(10)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "stored inline argument should still enforce the second require");
}

#[test]
fn inline_argument_alias_does_not_store_param_in_addition_to_reused_local() {
    let source = r#"
        contract InlineAliasReuse() {
            function f(int z) {
                require(z > 1);
            }

            function g(int z) {
                require(z < 10);
            }

            entrypoint function main(int x) {
                int y = x * x;
                f(y);
                g(y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline alias reuse should compile");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
        // Copy `x` twice and compute `x * x`, leaving the new local `y` on stack.
        .add_op(OpDup)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        // Inline `f(y)`: there is no explicit store for callee param `z`.
        // We just read the already-stored `y` slot, proving `z` is only an alias.
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        // Inline `g(y)`: same again, read `y` directly instead of storing `z`.
        .add_op(OpDup)
        .unwrap()
        .add_i64(10)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        // Drop the reused local `y`, then drop the original entrypoint param `x`.
        .add_i64(0)
        .unwrap()
        .add_op(OpRoll)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpOver).count(), 1);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpPick).count(), 0);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpMul).count(), 1);

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(2)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "reused local should satisfy both inline requires: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(4)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "reused local should still fail the second inline require");
}

#[test]
fn inline_argument_alias_reuses_entrypoint_param_without_extra_stack_storage() {
    let source = r#"
        contract InlineParamAliasReuse() {
            function f(int z) {
                require(z > 1);
            }

            function g(int z) {
                require(z < 10);
            }

            entrypoint function main(int y) {
                f(y);
                g(y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline param alias reuse should compile");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
        // Inline `f(y)`: `y` is already the entrypoint param on stack, so `z`
        // is only an alias and we simply read that slot.
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        // Inline `g(y)`: same aliasing behavior, still no explicit store for `z`.
        .add_op(OpDup)
        .unwrap()
        .add_i64(10)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        // Only the original entrypoint param `y` remains to clean up.
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpDup).count(), 2);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpOver).count(), 0);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpPick).count(), 0);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpDrop).count(), 1);

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(2)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "entrypoint param alias should satisfy both inline requires: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(10)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "entrypoint param alias should still fail the second inline require");
}

#[test]
fn local_alias_reuses_existing_stack_slot_without_explicit_store() {
    let source = r#"
        contract LocalAliasReuse() {
            entrypoint function main(int x) {
                int y = x * x;
                require(y > 1);
                int z = y;
                require(z > 1);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("local alias reuse should compile");
    let selector = selector_for(&compiled, "main");

    let body = ScriptBuilder::new()
        // Copy `x` twice and compute `x * x`, leaving the reused local `y` on stack.
        .add_op(OpDup)
        .unwrap()
        .add_op(OpOver)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        // First `require(y > 1)` reads the stored `y` value.
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        // `int z = y` does not emit any explicit store. The next require still
        // reads the same stack slot directly, showing `z` aliases `y`.
        .add_op(OpDup)
        .unwrap()
        .add_i64(1)
        .unwrap()
        .add_op(OpGreaterThan)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        // Drop the reused local `y`, then the original entrypoint param `x`.
        .add_i64(0)
        .unwrap()
        .add_op(OpRoll)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpMul).count(), 1);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpOver).count(), 1);
    assert_eq!(compiled.script.iter().copied().filter(|op| *op == OpPick).count(), 0);

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(2)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "local alias should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(1)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "local alias should still enforce the requires");
}

#[test]
fn local_alias_reassignment_from_alias_passes_for_x_5() {
    let source = r#"
        contract LocalAliasReassign() {
            entrypoint function main(int x) {
                int y = x * x;
                require(y > 1);
                int z = y;
                z = z + 1;
                require(z > y);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("local alias reassignment should compile");

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "x=5 should pass after z is incremented past y: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(1)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "x=1 should still fail the initial require(y > 1)");
}

#[test]
fn local_bool_expression_is_stored_once_and_reused() {
    let source = r#"
        contract BoolRepeat() {
            entrypoint function main(int x) {
                bool y = x + 1 > 1;
                require(y);
                require(y == true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("bool local should compile");

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "x + 1 should be computed once for the stored bool expression"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored bool local should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(0)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "stored bool local should still enforce the false branch");
}

#[test]
fn local_nested_expression_is_stored_once_and_reused() {
    let source = r#"
        contract NestedRepeat() {
            entrypoint function main(int x) {
                int y = (x + 1) * (x + 2);
                require(y > 10);
                require(y < 100);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("nested local should compile");

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        2,
        "the nested local expression should compute each addition once before storing the result"
    );
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the nested local expression should multiply once before storing the result"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored nested local should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(10)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "stored nested local should still enforce the second require");
}

#[test]
fn inline_nested_argument_expression_is_stored_once_and_reused() {
    let source = r#"
        contract InlineCallRepeat() {
            function f(int y) {
                require(y > 10);
                require(y < 100);
            }

            entrypoint function main(int x) {
                f((x + 1) * (x + 2));
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("inline nested arg should compile");

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        2,
        "the inline nested argument should compute each addition once and reuse the stored result"
    );
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the inline nested argument should multiply once and reuse the stored result"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(5)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored inline nested argument should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(10)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
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

            entrypoint function main(int x) {
                (int y) = f(x);
                require(y > 1);
                require(y < 10);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("function-call assignment should compile");

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpSub).count(),
        1,
        "the nested g(x) return calculation should be computed once and the assigned local reused"
    );
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the extra arithmetic in f(x) should be computed once and the assigned local reused"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(19)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored function-call assignment result should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(29)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
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
                return({
                    a: x + 1,
                    b: x * x,
                });
            }

            entrypoint function main(int x) {
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
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "s.a should be computed once and reused across both require statements"
    );
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "s.b should be computed once and reused across both require statements"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(3)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "stored struct fields should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(10)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "stored struct fields should still enforce the require conditions");
}

#[test]
fn compile_time_if_branch_stores_local_var_once_and_reuses_it() {
    let source = r#"
        contract IfRepeat() {

            entrypoint function main(int x) {
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

    let script = &compiled.script;
    let if_pos = script.iter().position(|op| *op == OpIf).expect("if present");
    let else_pos = script.iter().position(|op| *op == OpElse).expect("else present");
    let endif_pos = script.iter().position(|op| *op == OpEndIf).expect("endif present");
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpOver).count(), 0);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpPick).count(), 0);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpAdd).count(), 1);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDrop).count(), 1);
    assert_eq!(script[endif_pos + 1..].iter().copied().filter(|op| *op == OpDrop).count(), 1);
    assert_eq!(script[endif_pos + 1..].iter().copied().filter(|op| *op == OpRoll).count(), 0);
}

#[test]
fn compile_time_if_branch_stores_struct_fields_once_and_reuses_them() {
    let source = r#"
        contract IfStructRepeat() {
            struct S {
                int a;
                int b;
            }

            entrypoint function main(int x) {
                if (1 < 2) {
                    S s = { a: x + 1, b: x * x };
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

    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        1,
        "s.a should be computed once and reused across both require statements"
    );
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "s.b should be computed once and reused across both require statements"
    );

    let script = &compiled.script;
    let if_pos = script.iter().position(|op| *op == OpIf).expect("if present");
    let else_pos = script.iter().position(|op| *op == OpElse).expect("else present");
    let endif_pos = script.iter().position(|op| *op == OpEndIf).expect("endif present");
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDup).count(), 3);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpOver).count(), 3);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpPick).count(), 1);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpAdd).count(), 1);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpMul).count(), 1);
    assert_eq!(script[if_pos + 1..else_pos].iter().copied().filter(|op| *op == OpDrop).count(), 2);
    assert_eq!(script[endif_pos + 1..].iter().copied().filter(|op| *op == OpDrop).count(), 1);
    assert_eq!(script[endif_pos + 1..].iter().copied().filter(|op| *op == OpRoll).count(), 0);
}

#[test]
fn partially_reassigned_struct_field_rolls_last_use_without_copying_unchanged_fields() {
    let source = r#"
        contract ConsumePartialStructField() {
            struct S {
                int a;
                int b;
            }

            entrypoint function main(int x) {
                S s = {a: x + 1, b: x * x};
                s = {a: s.a + 1, b: s.b};
                require(s.a > 0);
                require(s.b > 0);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("partial struct reassignment should compile");
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpMul).count(),
        1,
        "the unchanged field should keep using its original expression instead of being copied into a new stack slot"
    );
    assert_eq!(
        compiled.script.iter().copied().filter(|op| *op == OpAdd).count(),
        2,
        "only the initial `s.a = x + 1` and the reassigned `s.a = s.a + 1` should emit additions"
    );
    assert!(
        compiled.script.iter().copied().filter(|op| *op == OpRoll).count() >= 2,
        "the stack-backed struct leaves should be rebound with rolls instead of rebuilding the whole struct"
    );

    let sigscript_ok = compiled.build_sig_script("main", vec![Expr::int(2)]).expect("sigscript builds");
    let result_ok = run_script_with_sigscript(compiled.script.clone(), sigscript_ok);
    assert!(result_ok.is_ok(), "partial struct reassignment should execute successfully: {}", result_ok.unwrap_err());

    let sigscript_err = compiled.build_sig_script("main", vec![Expr::int(0)]).expect("sigscript builds");
    let result_err = run_script_with_sigscript(compiled.script, sigscript_err);
    assert!(result_err.is_err(), "partial struct reassignment should still enforce the updated field checks");
}

#[test]
fn if_branch_reassignment_drops_hidden_shadow_bindings() {
    let source = r#"
        contract BranchShadowCleanup() {
            entrypoint function main(int flag, int a, int b, int expected) {
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

    let sigscript_then =
        compiled.build_sig_script("main", vec![Expr::int(1), Expr::int(1), Expr::int(1), Expr::int(3)]).expect("sigscript builds");
    let result_then = run_script_with_sigscript(compiled.script.clone(), sigscript_then);
    assert!(result_then.is_ok(), "then-branch reassignment should leave a clean stack: {}", result_then.unwrap_err());

    let sigscript_else =
        compiled.build_sig_script("main", vec![Expr::int(0), Expr::int(1), Expr::int(1), Expr::int(2)]).expect("sigscript builds");
    let result_else = run_script_with_sigscript(compiled.script, sigscript_else);
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

            entrypoint function main(int flag, int expected_a, int expected_b) {
                S s = {a: 2, b: 3};
                if (flag > 0) {
                    s = {a: s.a + 1, b: s.b + 1};
                } else {
                    s = {a: s.a + 2, b: s.b + 2};
                }
                S t = s;
                verify_pair(t, expected_a, expected_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("post-if struct type merge should compile");
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

            entrypoint function main(int flag, int expected_a, int expected_b) {
                S s = {a: 2, b: 3};
                if (flag > 0) {
                    s = {a: s.a + 1, b: s.b};
                } else {
                    s = {a: s.a, b: s.b + 2};
                }
                S t = s;
                verify_pair(t, expected_a, expected_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("post-if partial struct type merge should compile");
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

            entrypoint function main(int flag, int x, int y, int expected_a, int expected_b) {
                S s = {a: x, b: y};
                if (flag > 0) {
                    S t = {a: s.a + 1, b: s.b + 2};
                    s = {a: t.a + y, b: t.b + x};
                } else {
                    S t = {a: s.a + x, b: s.b + y};
                    s = {a: t.a + 1, b: t.b + 1};
                }
                require(s.a == expected_a);
                require(s.b == expected_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("struct branch cleanup should compile");

    let sigscript_then = compiled
        .build_sig_script("main", vec![Expr::int(1), Expr::int(2), Expr::int(3), Expr::int(6), Expr::int(7)])
        .expect("sigscript builds");
    let result_then = run_script_with_sigscript(compiled.script.clone(), sigscript_then);
    assert!(result_then.is_ok(), "then-branch struct cleanup should leave a clean stack: {}", result_then.unwrap_err());

    let sigscript_else = compiled
        .build_sig_script("main", vec![Expr::int(0), Expr::int(2), Expr::int(3), Expr::int(5), Expr::int(7)])
        .expect("sigscript builds");
    let result_else = run_script_with_sigscript(compiled.script, sigscript_else);
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

            entrypoint function main(int flag, int x, int y, int expected_a, int expected_b) {
                S s = {a: x, b: y};
                if (flag > 0) {
                    S t = {a: s.a + 1, b: s.b};
                    s = {a: t.a + y, b: s.b};
                } else {
                    S t = {a: s.a, b: s.b + y};
                    s = {a: s.a, b: t.b + x};
                }
                require(s.a == expected_a);
                require(s.b == expected_b);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("partial struct branch cleanup should compile");

    let sigscript_then = compiled
        .build_sig_script("main", vec![Expr::int(1), Expr::int(2), Expr::int(3), Expr::int(6), Expr::int(3)])
        .expect("sigscript builds");
    let result_then = run_script_with_sigscript(compiled.script.clone(), sigscript_then);
    assert!(result_then.is_ok(), "then-branch partial struct cleanup should leave a clean stack: {}", result_then.unwrap_err());

    let sigscript_else = compiled
        .build_sig_script("main", vec![Expr::int(0), Expr::int(2), Expr::int(3), Expr::int(2), Expr::int(8)])
        .expect("sigscript builds");
    let result_else = run_script_with_sigscript(compiled.script, sigscript_else);
    assert!(result_else.is_ok(), "else-branch partial struct cleanup should leave a clean stack: {}", result_else.unwrap_err());
}

#[test]
fn conditional_counter_in_unrolled_loop_stays_linear() {
    const SOURCE: &str = r#"
pragma silverscript ^0.1.0;

contract CounterLoop(int BOUND) {
    entrypoint function main() {
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
        let args = [Expr::int(b)];
        let compiled = compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile succeeds");
        lens.push(compiled.script.len());
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

    entrypoint function main() {
        S s = {a: 0, b: 0};
        for (i, 0, BOUND, BOUND) {
            if (true) {
                s = {a: s.a + 1, b: s.b + 1};
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
        let args = [Expr::int(b)];
        let compiled = compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile succeeds");
        lens.push(compiled.script.len());
    }

    assert!(lens[0] < lens[1] && lens[1] < lens[2], "expected monotonic growth, got {lens:?}");
    let d1 = lens[1] - lens[0];
    let d2 = lens[2] - lens[1];

    assert!(d2 <= d1 * 2, "unexpected superlinear growth: lens={lens:?} d1={d1} d2={d2}");
    assert!(lens[2] < 10_000, "unexpected script size: lens={lens:?}");
}
