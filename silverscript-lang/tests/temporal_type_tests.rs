mod common;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use silverscript_abi::ArtifactValue;
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use common::{bytecode, encode_single_entry_sig_script};

fn execute(compiled: silverscript_abi::SilAbiArtifact, args: &[ArtifactValue]) {
    let signature_script = encode_single_entry_sig_script(&compiled, args).expect("signature script builds");
    let input = TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([9; 32]), index: 0 },
        signature_script,
        0,
        0,
    );
    let output =
        TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, bytecode(&compiled).into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo = UtxoEntry::new(output.value, output.script_public_key, 0, false, None);
    let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
    let cache = Cache::new(10_000);
    let reused = SigHashReusedValuesUnsync::new();
    TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        0,
        &utxo,
        EngineCtx::new(&cache).with_reused(&reused),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    )
    .execute()
    .expect("compiled temporal expression executes");
}

#[test]
fn temporal_supports_int_operations_with_temporal_operands() {
    let source = r#"
        contract LockRequirements() {
            entry main(temporal a, temporal b) {
                require(a + b == temporal(23));
                require(a - b == temporal(17));
                require(a * b == temporal(60));
                require(a / b == temporal(6));
                require(a % b == temporal(2));
                require(a >= b);
                require(b < a);
                require(-b == temporal(-3));
            }
        }
    "#;
    let compiled =
        compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default()).expect("temporal operations compile");
    execute(compiled, &[20.into(), 3.into()]);
}

#[test]
fn int_and_temporal_conversions_are_runtime_no_ops() {
    let source = r#"
        contract TimeCasts() {
            entry main(temporal timestamp, int raw) {
                int converted_int = int(timestamp);
                temporal converted_time = temporal(raw);
                require(converted_int == 1234);
                require(converted_time == temporal(5678));
            }
        }
    "#;
    let compiled =
        compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default()).expect("explicit conversions compile");
    execute(compiled, &[1234.into(), 5678.into()]);
}

#[test]
fn temporal_fields_arrays_and_millisecond_units_round_trip() {
    let source = r#"
        contract TimeStorage(temporal start) {
            temporal stored = start;

            entry main(temporal now, temporal deadline) {
                temporal[2] points = temporal[2]{stored, deadline};
                require(points[1] - points[0] == 2 seconds);
                require(now >= deadline);
            }
        }
    "#;
    let compiled = compile_to_sil_abi_artifact_with_options(source, &[ArtifactValue::Int(1_000)], CompileOptions::default())
        .expect("temporal storage compiles");
    execute(compiled, &[3_000.into(), 3_000.into()]);
}

#[test]
fn temporal_array_entrypoint_arguments_round_trip() {
    let source = r#"
        contract TimeSeries() {
            entry main(temporal[3] points) {
                require(points.length == 3);
                require(points[0] == temporal(1_000));
                require(points[1] - points[0] == 1 seconds);
                require(points[2] - points[1] == 1 minutes);
            }
        }
    "#;
    let compiled =
        compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default()).expect("temporal array argument compiles");
    let points = ArtifactValue::Array(vec![1_000.into(), 2_000.into(), 62_000.into()]);
    execute(compiled, &[points]);
}

#[test]
fn temporal_array_size_inference_and_append_execute() {
    let source = r#"
        contract TimeSeries() {
            entry main(temporal runtimeValue) {
                temporal[_] inferred = temporal[_]{1 seconds, runtimeValue};
                temporal[] values = temporal[]{};
                temporal[] appended = values.append(inferred[0], inferred[1], 3 seconds);

                require(inferred.length == 2);
                require(appended.length == 3);
                require(appended[0] == temporal(1_000));
                require(appended[1] == temporal(2_000));
                require(appended[2] == temporal(3_000));
            }
        }
    "#;
    let compiled =
        compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default()).expect("temporal array operations compile");
    execute(compiled, &[2_000.into()]);
}

#[test]
fn temporal_arrays_reject_int_elements_without_conversion() {
    for source in [
        "contract C() { entry main() { temporal[] values = int[]{1, 2}; } }",
        "contract C() { entry main() { temporal[] values = temporal[]{}; values = values.append(1); } }",
        "contract C() { entry main() { int[] values = temporal[]{temporal(1)}; } }",
    ] {
        assert!(
            compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default()).is_err(),
            "mixed int/temporal array must be rejected: {source}"
        );
    }
}

#[test]
fn int_and_temporal_require_explicit_conversion() {
    for source in [
        "contract C() { entry main() { int value = 1 seconds; } }",
        "contract C() { entry main() { temporal value = 1; } }",
        "contract C() { entry main(temporal t, int x) { require(t + x == t); } }",
        "contract C() { entry main(temporal t, int x) { require(t >= x); } }",
        "contract C() { entry main() { require(tx.time >= 1); } }",
        "contract C() { entry main() { require(tx.daa >= temporal(500000000000)); } }",
        "contract C() { entry main() { require(this.ageDaa >= 1 seconds); } }",
        "contract C() { entry main() { require(this.age >= 1); } }",
    ] {
        assert!(
            compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default()).is_err(),
            "mixed or obsolete temporal expression must be rejected: {source}"
        );
    }
}

#[test]
fn known_relative_age_must_fit_u32() {
    let source = r#"
        contract C() {
            int constant TOO_OLD = 2147483648 * 2;
            entry main() { require(this.ageDaa >= TOO_OLD); }
        }
    "#;
    let error = compile_to_sil_abi_artifact_with_options(source, &[], CompileOptions::default())
        .expect_err("known 2^32 value must be rejected");
    assert!(error.to_string().contains("0 <= value < 2^32"), "unexpected error: {error}");

    let negative = "contract C() { entry main() { require(this.ageDaa >= -1); } }";
    let error = compile_to_sil_abi_artifact_with_options(negative, &[], CompileOptions::default())
        .expect_err("known negative age must be rejected");
    assert!(error.to_string().contains("0 <= value < 2^32"), "unexpected error: {error}");

    let zero = "contract C() { entry main() { require(this.ageDaa >= 0); } }";
    compile_to_sil_abi_artifact_with_options(zero, &[], CompileOptions::default()).expect("zero remains valid");

    let max = "contract C() { entry main() { require(this.ageDaa >= 4294967295); } }";
    compile_to_sil_abi_artifact_with_options(max, &[], CompileOptions::default()).expect("2^32 - 1 remains valid");

    let constructor_known = "contract C(int age) { entry main() { require(this.ageDaa >= age); } }";
    let error =
        compile_to_sil_abi_artifact_with_options(constructor_known, &[ArtifactValue::Int(1_i64 << 32)], CompileOptions::default())
            .expect_err("known constructor age must be rejected");
    assert!(error.to_string().contains("0 <= value < 2^32"), "unexpected error: {error}");
}
