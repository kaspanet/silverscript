//! The compute estimate the compiler records for every entry bounds the script
//! units the Kaspa script engine meters for that entry. These tests execute the
//! compiled contracts in the engine and compare the metered units with the
//! bound evaluated at the actual argument lengths.

mod common;

use std::collections::BTreeMap;
use std::fs;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::units::SigopCount;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::opcodes::codes::OpTrue;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script};
use sha2::{Digest, Sha256};
use silverscript_abi::{
    ArtifactValue, ComputeEstimateArtifact, SilAbiArtifact, compute_budget_for_script_units, entry_argument_byte_lengths,
};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use common::{bytecode, compile_contract, encode_entry_sig_script, push_redeem_script, single_contract};

fn load_example_source(name: &str) -> String {
    let path = format!("{}/tests/examples/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn estimate<'a>(artifact: &'a SilAbiArtifact, entry: &str) -> &'a ComputeEstimateArtifact {
    single_contract(artifact).entry(entry).expect("entry exists").compute.as_ref().expect("entry has a compute estimate")
}

/// Spend a pay-to-script-hash output of the contract with `entry(args)` in a
/// transaction paying one anyone-can-spend output, and return the script units
/// the engine metered.
fn metered_units(artifact: &SilAbiArtifact, entry: &str, args: &[ArtifactValue]) -> u64 {
    let mut sigscript = encode_entry_sig_script(artifact, entry, args).expect("sigscript builds");
    sigscript.extend_from_slice(&push_redeem_script(&bytecode(artifact)));
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        compute_commit: SigopCount(0).into(),
    };
    let output = TransactionOutput { value: 1_500, script_public_key: ScriptPublicKey::new(0, vec![OpTrue].into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(2_000, pay_to_script_hash_script(&bytecode(artifact)), 0, false, None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute().unwrap_or_else(|err| panic!("{entry} executes: {err}"));
    vm.used_script_units().0
}

/// Evaluate an entry's bound at the actual argument lengths and the artifact's
/// redeem script. Other lengths are looked up in `extra`.
fn bound(artifact: &SilAbiArtifact, entry: &str, args: &[ArtifactValue], extra: &BTreeMap<&str, u64>) -> u64 {
    let contract = single_contract(artifact);
    let entry_artifact = contract.entry(entry).expect("entry exists");
    let arg_lengths = entry_argument_byte_lengths(artifact, contract, entry_artifact, args).expect("argument lengths");
    let redeem_script = contract.compiled.bytecode.len() as u64;
    estimate(artifact, entry)
        .script_units_with(|key| match key {
            "redeem_script" => Some(redeem_script),
            _ => arg_lengths.get(key).copied().or_else(|| extra.get(key).copied()),
        })
        .unwrap_or_else(|err| panic!("{entry} bound evaluates: {err}"))
}

#[test]
fn wrapper_and_dispatch_cost_are_exact_for_every_entry_position() {
    let source = r#"
        contract Dispatch() {
            entry first() { require(true); }
            entry second() { require(true); }
            entry third() { require(true); }
        }
    "#;
    let artifact = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    for (index, entry) in ["first", "second", "third"].iter().enumerate() {
        let estimate = estimate(&artifact, entry);
        // The pay-to-script-hash output script hashes the redeem script at two units per byte,
        // then pushes the digest and the comparison result.
        assert_eq!(estimate.script_units_per_byte, BTreeMap::from([("redeem_script".to_string(), 2)]));
        assert_eq!(estimate.sig_ops, 0);
        // Each preceding entry duplicates the four-byte tag; the match pushes one byte.
        assert_eq!(estimate.script_units, 33 + 4 * (index as u64 + 1) + 1);
        assert_eq!(bound(&artifact, entry, &[], &BTreeMap::new()), metered_units(&artifact, entry, &[]));
    }
}

#[test]
fn variable_length_arguments_are_priced_per_byte() {
    let source = r#"
        contract Digest() {
            entry check(byte[] preimage, byte[32] digest, int nonce) {
                require(sha256(preimage) == digest);
                require(nonce >= 0);
            }
        }
    "#;
    let artifact = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let estimate = estimate(&artifact, "check");
    assert!(estimate.script_units_per_byte["preimage"] >= 1, "hashing charges at least one unit per byte");

    for preimage_len in [0usize, 1, 100, 5_000] {
        let preimage = vec![0xabu8; preimage_len];
        let digest = Sha256::digest(&preimage).to_vec();
        let args = [ArtifactValue::Bytes(preimage), ArtifactValue::Bytes(digest), ArtifactValue::Int(7)];
        let metered = metered_units(&artifact, "check", &args);
        let bound = bound(&artifact, "check", &args, &BTreeMap::new());
        assert!(bound >= metered, "bound {bound} must cover {metered} metered units for {preimage_len} bytes");
        // Only comparison results and encoded sizes are rounded up; nothing grows with the preimage.
        assert!(bound - metered <= 32, "bound {bound} is far above {metered} metered units for {preimage_len} bytes");
    }
}

#[test]
fn r0_succinct_example_estimate_is_tight() {
    let source = load_example_source("r0_succinct.sil");
    let (control_id, seal, claim, hashfn, control_index, control_digests, journal, image_id) =
        kaspa_txscript::zk_precompiles::tests::helpers::load_stark_fields();
    assert_eq!(hashfn, vec![1u8]);
    let artifact = compile_to_sil_abi_artifact_with_options(&source, &[image_id.into(), control_id.into()], CompileOptions::default())
        .expect("compile succeeds");
    let estimate = estimate(&artifact, "verify");
    assert_eq!(estimate.script_units_per_byte.keys().collect::<Vec<_>>(), ["control_digests", "redeem_script", "seal"]);
    assert_eq!(estimate.sig_ops, 0);
    assert!(estimate.script_units >= 25_000_000, "the succinct verifier alone costs 25M units");

    let args = [claim.into(), control_index.into(), ArtifactValue::Bytes(control_digests), ArtifactValue::Bytes(seal), journal.into()];
    let metered = metered_units(&artifact, "verify", &args);
    let bound = bound(&artifact, "verify", &args, &BTreeMap::new());
    assert!(bound >= metered, "bound {bound} covers {metered}");
    // Only the encoded sizes of the two variable-length arguments are rounded up.
    assert!(bound - metered <= 32, "bound {bound} is close to {metered}");
    assert_eq!(estimate.compute_budget_with(|_| None).unwrap_err().to_string(), "no byte length was supplied for `control_digests`");
}

#[test]
fn g16_verify_example_estimate_is_tight() {
    let source = load_example_source("g16_verify.sil");
    let (verifying_key, proof, public_inputs) = kaspa_txscript::zk_precompiles::tests::helpers::load_groth_fields();
    let artifact = compile_to_sil_abi_artifact_with_options(&source, &[], CompileOptions::default()).expect("compile succeeds");
    let mut args = vec![ArtifactValue::Bytes(verifying_key), ArtifactValue::Bytes(proof)];
    args.extend(public_inputs.into_iter().map(Into::into));
    let metered = metered_units(&artifact, "verify", &args);
    // Five public inputs: the verifier charges six gamma_abc elements on top of its base cost.
    assert!(metered >= 14_000_000 + 6 * 250_000);
    let bound = bound(&artifact, "verify", &args, &BTreeMap::new());
    assert!(bound >= metered, "bound {bound} covers {metered}");
    assert!(bound - metered <= 32, "bound {bound} is close to {metered}");
}

#[test]
fn signature_checks_are_counted_and_priced() {
    let source = r#"
        contract Owned(pubkey owner) {
            entry spend(sig ownerSig) {
                require(checkSig(ownerSig, owner));
            }
        }
    "#;
    let artifact =
        compile_contract(source, &[ArtifactValue::Bytes(vec![2u8; 32])], CompileOptions::default()).expect("compile succeeds");
    let estimate = estimate(&artifact, "spend");
    assert_eq!(estimate.sig_ops, 1);
    // One sigop at 1000 grams, plus the wrapper, the dispatch, and the pushed key and result.
    assert!(estimate.script_units >= 100_000 && estimate.script_units < 100_500, "{}", estimate.script_units);
    assert_eq!(estimate.script_units_per_byte.keys().collect::<Vec<_>>(), ["redeem_script"]);
}

#[test]
fn branches_take_the_most_expensive_path_and_state_fields_have_symbols() {
    let source = r#"
        contract Branchy(int limit) {
            string note = "hello";
            int counter = 0;
            entry pick(bool heavy, byte[] payload) {
                if (heavy) {
                    require(blake2b(payload + payload) != blake2b(payload));
                    require(note.length >= 0);
                } else {
                    require(counter <= limit);
                }
            }
        }
    "#;
    let artifact = compile_contract(source, &[ArtifactValue::Int(5)], CompileOptions::default()).expect("compile succeeds");
    let estimate = estimate(&artifact, "pick");
    // The heavy branch hashes the payload three times over at two units per byte, plus the copies it makes.
    assert!(estimate.script_units_per_byte["payload"] >= 6, "{:?}", estimate.script_units_per_byte);
    assert!(estimate.script_units_per_byte.contains_key("state.note"), "{:?}", estimate.script_units_per_byte);

    let extra = BTreeMap::from([("state.note", 5)]);
    for heavy in [true, false] {
        let args = [ArtifactValue::Bool(heavy), ArtifactValue::Bytes(vec![1u8; 700])];
        let metered = metered_units(&artifact, "pick", &args);
        let bound = bound(&artifact, "pick", &args, &extra);
        assert!(bound >= metered, "heavy={heavy}: bound {bound} covers {metered}");
        if heavy {
            assert!(bound - metered <= 64, "heavy={heavy}: bound {bound} is close to {metered}");
        }
    }
}

#[test]
fn struct_leaves_and_introspection_are_keyed_by_source_names() {
    let source = r#"
        contract Keys() {
            struct Note { int id; byte[] body; }
            entry post(Note note, int outputIndex) {
                byte[] spk = tx.outputs[outputIndex].scriptPubKey;
                require(spk != note.body);
                byte[] sigScript = tx.inputs[this.activeInputIndex].sigScript;
                require(sigScript.length > 0);
            }
        }
    "#;
    let artifact = compile_contract(source, &[], CompileOptions::default()).expect("compile succeeds");
    let estimate = estimate(&artifact, "post");
    let mut keys = estimate.script_units_per_byte.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["note.body", "redeem_script", "tx.inputs[this.activeInputIndex].signature_script", "tx.outputs[*].script_public_key"]
    );

    let contract = single_contract(&artifact);
    let args = [
        ArtifactValue::Object(BTreeMap::from([
            ("id".to_string(), ArtifactValue::Int(3)),
            ("body".to_string(), ArtifactValue::Bytes(vec![7; 40])),
        ])),
        ArtifactValue::Int(0),
    ];
    let lengths = entry_argument_byte_lengths(&artifact, contract, contract.entry("post").unwrap(), &args).unwrap();
    assert_eq!(lengths, BTreeMap::from([("note.id".to_string(), 1), ("note.body".to_string(), 40), ("outputIndex".to_string(), 0)]));
}

#[test]
fn every_example_entry_gets_an_estimate_and_the_artifact_round_trips() {
    let dir = format!("{}/tests/examples", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "sil") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        // Only contracts without constructor arguments compile here; the rest are covered by their own tests.
        let Ok(artifact) = compile_to_sil_abi_artifact_with_options(&source, &[], CompileOptions::default()) else { continue };
        for (name, entry) in &single_contract(&artifact).entries {
            let estimate = entry.compute.as_ref().unwrap_or_else(|| panic!("{}::{name} has an estimate", path.display()));
            assert!(estimate.script_units >= 38, "{}::{name} at least pays for the wrapper and dispatch", path.display());
            assert_eq!(estimate.script_units_per_byte.get("redeem_script"), Some(&2), "{}::{name}", path.display());
            checked += 1;
        }
        let json = silverscript_abi::to_pretty_json(&artifact).unwrap();
        assert!(json.contains("\"compute\": {"), "{} serializes estimates", path.display());
        let parsed: SilAbiArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, artifact);
    }
    assert!(checked > 10, "examples exercised {checked} entries");

    // Artifacts written before estimates existed still load.
    let source = "contract Plain() { entry go() { require(true); } }";
    let artifact = compile_contract(source, &[], CompileOptions::default()).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&silverscript_abi::to_pretty_json(&artifact).unwrap()).unwrap();
    json["contracts"]["Plain"]["entries"]["go"].as_object_mut().unwrap().remove("compute");
    let parsed: SilAbiArtifact = serde_json::from_value(json).unwrap();
    assert_eq!(single_contract(&parsed).entry("go").unwrap().compute, None);
}

#[test]
fn compute_budget_covers_the_bound_with_the_free_allowance() {
    assert_eq!(compute_budget_for_script_units(0), Some(0));
    assert_eq!(compute_budget_for_script_units(9_999), Some(0));
    assert_eq!(compute_budget_for_script_units(10_000), Some(1));
    // The measurement from the issue that motivated the estimate.
    assert_eq!(compute_budget_for_script_units(25_446_424), Some(2_544));
    assert_eq!(compute_budget_for_script_units(u64::MAX), None);

    let estimate = ComputeEstimateArtifact {
        script_units: 25_000_000,
        script_units_per_byte: BTreeMap::from([("seal".to_string(), 2), ("redeem_script".to_string(), 2)]),
        sig_ops: 0,
    };
    let lengths = |key: &str| Some(if key == "seal" { 222_668 } else { 544 });
    assert_eq!(estimate.script_units_with(lengths).unwrap(), 25_446_424);
    assert_eq!(estimate.compute_budget_with(lengths).unwrap(), 2_544);
}
