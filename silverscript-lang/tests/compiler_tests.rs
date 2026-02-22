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
use kaspa_txscript::{EngineCtx, EngineFlags, SeqCommitAccessor, TxScriptEngine, pay_to_address_script, pay_to_script_hash_script};
use silverscript_lang::ast::{Expr, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract, compile_contract_ast, function_branch_index};

const OPTIONS: CompileOptions = CompileOptions { allow_yield: false, allow_entrypoint_return: false, record_debug_infos: false };

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

#[test]
fn accepts_constructor_args_with_matching_types() {
    let source = r#"
        contract Types(int a, bool b, string c, bytes d, byte e, bytes4 f, pubkey pk, sig s, datasig ds) {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![
        Expr::Int(7),
        Expr::Bool(true),
        Expr::String("hello".to_string()),
        Expr::Bytes(vec![1u8; 10]),
        Expr::Bytes(vec![2u8; 1]),
        Expr::Bytes(vec![3u8; 4]),
        Expr::Bytes(vec![4u8; 32]),
        Expr::Bytes(vec![5u8; 64]),
        Expr::Bytes(vec![6u8; 64]),
    ];
    compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
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
    let args = vec![Expr::Bool(true), Expr::Int(1), Expr::Bytes(vec![1u8])];
    assert!(compile_contract(source, &args, CompileOptions::default()).is_err());
}

#[test]
fn rejects_constructor_args_with_wrong_byte_lengths() {
    let source = r#"
        contract Types(byte b, bytes4 c, pubkey pk, sig s, datasig ds) {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![
        Expr::Bytes(vec![1u8; 2]),
        Expr::Bytes(vec![2u8; 3]),
        Expr::Bytes(vec![3u8; 31]),
        Expr::Bytes(vec![4u8; 63]),
        Expr::Bytes(vec![5u8; 66]),
    ];
    assert!(compile_contract(source, &args, CompileOptions::default()).is_err());
}

#[test]
fn accepts_constructor_args_with_any_bytes_length() {
    let source = r#"
        contract Types(bytes blob) {
            entrypoint function main() {
                require(true);
            }
        }
    "#;
    let args = vec![Expr::Bytes(vec![9u8; 128])];
    compile_contract(source, &args, CompileOptions::default()).expect("compile succeeds");
}

#[test]
fn build_sig_script_builds_expected_script() {
    let source = r#"
        contract BoundedBytes() {
            entrypoint function spend(bytes4 b, int i) {
                require(b == bytes4(i));
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let args = vec![Expr::Bytes(vec![1u8, 2, 3, 4]), Expr::Int(7)];
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
fn build_sig_script_rejects_unknown_function() {
    let source = r#"
        contract C() {
            entrypoint function spend(int a) {
                require(a == 1);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("missing", vec![Expr::Int(1)]);
    assert!(result.is_err());
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
    let result = compiled.build_sig_script("spend", vec![Expr::Int(1)]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_rejects_wrong_argument_type() {
    let source = r#"
        contract C() {
            entrypoint function spend(bytes4 b) {
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::Bytes(vec![1u8; 3])]);
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
fn rejects_yield_without_allow_option() {
    let source = r#"
        contract YieldDefaultDisallowed() {
            entrypoint function main() {
                int x = 1;
                yield(x + 1);
            }
        }
    "#;

    let err = compile_contract(source, &[], CompileOptions::default()).expect_err("yield should be disallowed by default");
    assert!(err.to_string().contains("yield requires allow_yield=true"));
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
    let result = compiled.build_sig_script("helper", vec![Expr::Int(1)]);
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
            entrypoint function spend(bytes4 b) {
                require(b.length == 4);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::Bytes(vec![1u8; 5])]);
    assert!(result.is_err());

    let source = r#"
        contract C() {
            entrypoint function spend(bytes5 b) {
                require(b.length == 5);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let result = compiled.build_sig_script("spend", vec![Expr::Bytes(vec![1u8; 4])]);
    assert!(result.is_err());
}

#[test]
fn build_sig_script_omits_selector_without_selector() {
    let source = r#"
        contract Single() {
            entrypoint function spend(int a, bytes4 b) {
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
                (int sum, bytes prod) = f(2, 3);
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
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");

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
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");

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
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");

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
        .add_op(OpBin2Num)
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
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array runtime example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_bytes20_array_push_without_num2bin() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                bytes20[] x;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                require(x.length == 1);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");

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
                bytes20[] x;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                x.push(0x1111111111111111111111111111111111111111);
                require(x.length == 2);
                require(x[0] == 0x0102030405060708090a0b0c0d0e0f1011121314);
                require(x[1] == 0x1111111111111111111111111111111111111111);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "bytes20 array runtime example failed: {}", result.unwrap_err());
}

#[test]
fn allows_array_equality_comparison() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                bytes20[] x;
                bytes20[] y;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                require(x == y);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array equality runtime failed: {}", result.unwrap_err());
}

#[test]
fn fails_array_equality_comparison() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                bytes20[] x;
                bytes20[] y;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x2222222222222222222222222222222222222222);
                require(x == y);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}

#[test]
fn allows_array_inequality_with_different_sizes() {
    let source = r#"
        contract Arrays() {
            entrypoint function main() {
                bytes20[] x;
                bytes20[] y;
                x.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x0102030405060708090a0b0c0d0e0f1011121314);
                y.push(0x2222222222222222222222222222222222222222);
                require(x != y);
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
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
                for (i, 0, 3) {
                    require(x[i] == i + 1);
                }
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
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
                for (i, 1, MAX_ARRAY_SIZE) {
                    if (i < x.length) {
                        require(x[i] == x[i-1]+1);
                    }
                }
            }
        }
    "#;
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");

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
                for (i, 0, MAX_ARRAY_SIZE) {
                    if (i < arr.length) {
                       sum = sum + arr[i];
                    }
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
    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().drain();
    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "array assignment runtime failed: {}", result.unwrap_err());
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
    assert!(compile_contract(source, &[], OPTIONS).is_err());
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
    assert!(compile_contract(source, &[], OPTIONS).is_err());
}

#[test]
fn locking_bytecode_p2pk_matches_pay_to_address_script() {
    let source = r#"
        contract Test() {
            entrypoint function main(pubkey pk, bytes expected) {
                bytes spk = new LockingBytecodeP2PK(pk);
                require(spk == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
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
            entrypoint function main(bytes32 hash, bytes expected) {
                bytes spk = new LockingBytecodeP2SH(hash);
                require(spk == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
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
            entrypoint function main(bytes redeem_script, bytes expected) {
                bytes spk = new LockingBytecodeP2SHFromRedeemScript(redeem_script);
                require(spk == expected);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], OPTIONS).expect("compile succeeds");
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

fn selector_for(compiled: &CompiledContract, function_name: &str) -> Option<i64> {
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
                        require(OpSha256(bytes("msg")) == bytes("hash"));
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
                        require(OpTxInputIsCoinbase(0) == 0);
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
                        require(OpInputCovenantId(0) == bytes("cov"));
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
                        require(OpCovOutCount(bytes("c1")) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
                .unwrap()
                .add_op(OpCovOutCount)
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
            "is_coinbase",
            r#"
                contract Test() {
                    entrypoint function main() {
                        require(OpTxInputIsCoinbase(0) == 0);
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
                require(OpInputCovenantId(0) == bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
                require(OpCovInputCount(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) == 2);
                require(OpCovInputIdx(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1) == 2);
                require(OpCovOutCount(bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) == 2);
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
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(30)
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
                for (i, 0, MAX_ARRAY_SIZE) {
                    if (i < arr.length) {
                       sum = sum + arr[i];
                    }
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
    let sigscript = compiled.build_sig_script("main", vec![Expr::Int(expected_size)]).expect("sigscript builds");

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
            entrypoint function main(bytes expected_data_prefix) {
                require(expected_data_prefix == this.scriptSizeDataPrefix);
                require(true);
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(compiled.script.len());
    let sigscript = compiled.build_sig_script("main", vec![Expr::Bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "scriptSizeDataPrefix small failed: {}", result.unwrap_err());
}

#[test]
fn compiles_script_size_data_prefix_medium_script() {
    let source = r#"
        contract PrefixMedium() {
            entrypoint function main(bytes expected_data_prefix) {
                require(expected_data_prefix == this.scriptSizeDataPrefix);
                for (i, 0, 100) {
                    require(true);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(compiled.script.len());
    let sigscript = compiled.build_sig_script("main", vec![Expr::Bytes(expected_prefix)]).expect("sigscript builds");

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "scriptSizeDataPrefix medium failed: {}", result.unwrap_err());
}

#[test]
fn compiles_script_size_data_prefix_large_script() {
    let source = r#"
        contract PrefixLarge() {
            entrypoint function main(bytes expected_data_prefix) {
                require(expected_data_prefix == this.scriptSizeDataPrefix);
                for (i, 0, 300) {
                    require(true);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let expected_prefix = data_prefix_for_size(compiled.script.len());
    let sigscript = compiled.build_sig_script("main", vec![Expr::Bytes(expected_prefix)]).expect("sigscript builds");

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
