use blake2b_simd::Params as Blake2bParams;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::standard::multisig_redeem_script;
use rand::{RngCore, thread_rng};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract, struct_object};
use std::fs;

mod common;

use common::{COV_A, assert_verify_like_error, compiled_template_parts_and_hash, covenant_decl_sigscript, covenant_utxo, execute_input_with_covenants};

fn load_example_source(name: &str) -> String {
    let path = format!("{}/tests/examples/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn random_keypair() -> Keypair {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let mut sk_bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut sk_bytes);
        if let Ok(secret_key) = SecretKey::from_slice(&sk_bytes) {
            return Keypair::from_secret_key(&secp, &secret_key);
        }
    }
}

fn dog20_state_array_arg<'i>(values: Vec<(Vec<u8>, i64)>) -> Expr<'i> {
    dog20_state_array_arg_with_minter(values.into_iter().map(|(owner_identifier, amount)| (owner_identifier, amount, false)).collect())
}

fn dog20_state_array_arg_full<'i>(values: Vec<(Vec<u8>, u8, i64, bool)>) -> Expr<'i> {
    values
        .into_iter()
        .map(|(owner_identifier, identifier_type, amount, is_minter)| {
            struct_object(vec![
                ("ownerIdentifier", Expr::bytes(owner_identifier)),
                ("identifierType", Expr::byte(identifier_type)),
                ("amount", Expr::int(amount)),
                ("isMinter", Expr::bool(is_minter)),
            ])
        })
        .collect::<Vec<_>>()
        .into()
}

fn dog20_state_array_arg_with_minter<'i>(values: Vec<(Vec<u8>, i64, bool)>) -> Expr<'i> {
    dog20_state_array_arg_full(
        values.into_iter().map(|(owner_identifier, amount, is_minter)| (owner_identifier, 0, amount, is_minter)).collect(),
    )
}

fn sig_array_arg<'i>(values: Vec<Vec<u8>>) -> Expr<'i> {
    values.into_iter().map(Expr::bytes).collect::<Vec<_>>().into()
}

fn witness_array_arg<'i>(values: Vec<u8>) -> Expr<'i> {
    Expr::bytes(values)
}

fn compile_dog20_state<'a>(source: &'a str, owner: Vec<u8>, amount: i64, max_cov_ins: i64, max_cov_outs: i64) -> CompiledContract<'a> {
    compile_dog20_state_with_minter(source, owner, amount, false, max_cov_ins, max_cov_outs)
}

fn compile_dog20_state_full<'a>(
    source: &'a str,
    owner: Vec<u8>,
    amount: i64,
    identifier_type: u8,
    is_minter: bool,
    max_cov_ins: i64,
    max_cov_outs: i64,
) -> CompiledContract<'a> {
    compile_contract(
        source,
        &[
            Expr::bytes(owner),
            Expr::int(amount),
            Expr::byte(identifier_type),
            Expr::bool(is_minter),
            Expr::int(max_cov_ins),
            Expr::int(max_cov_outs),
        ],
        CompileOptions::default(),
    )
    .expect("compile succeeds")
}

fn compile_dog20_state_with_minter<'a>(
    source: &'a str,
    owner: Vec<u8>,
    amount: i64,
    is_minter: bool,
    max_cov_ins: i64,
    max_cov_outs: i64,
) -> CompiledContract<'a> {
    compile_dog20_state_full(source, owner, amount, 0, is_minter, max_cov_ins, max_cov_outs)
}

fn sign_tx_input(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize, keypair: &Keypair) -> Vec<u8> {
    let tx = MutableTransaction::with_entries(tx, entries);
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("valid sighash message");
    let sig = keypair.sign_schnorr(msg);
    let mut signature = sig.as_ref().to_vec();
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

fn tx_input_from_outpoint_v1(previous_outpoint: TransactionOutpoint, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput::new_with_compute_budget(previous_outpoint, signature_script, 0, 0)
}

fn blake2b32(data: &[u8]) -> Vec<u8> {
    Blake2bParams::new().hash_length(32).to_state().update(data).finalize().as_bytes().to_vec()
}

#[test]
fn dog20_can_split_then_merge_tokens_with_two_way_fanout() {
    let source = load_example_source("dog20.sil");

    let genesis_owner = random_keypair();
    let handoff_owner = random_keypair();
    let split_owner_a = random_keypair();
    let split_owner_b = random_keypair();
    let merged_owner = random_keypair();

    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();
    let handoff_owner_bytes = handoff_owner.x_only_public_key().0.serialize().to_vec();
    let split_owner_a_bytes = split_owner_a.x_only_public_key().0.serialize().to_vec();
    let split_owner_b_bytes = split_owner_b.x_only_public_key().0.serialize().to_vec();
    let merged_owner_bytes = merged_owner.x_only_public_key().0.serialize().to_vec();

    let genesis = compile_dog20_state(&source, genesis_owner_bytes.clone(), 1_000, 2, 2);
    let handoff = compile_dog20_state(&source, handoff_owner_bytes.clone(), 1_000, 2, 2);
    let split_a = compile_dog20_state(&source, split_owner_a_bytes.clone(), 400, 2, 2);
    let split_b = compile_dog20_state(&source, split_owner_b_bytes.clone(), 600, 2, 2);

    let handoff_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&handoff.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let handoff_entries = vec![covenant_utxo(&genesis, COV_A)];
    let handoff_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 }, vec![])],
        handoff_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let handoff_sig = sign_tx_input(handoff_unsigned_tx, handoff_entries.clone(), 0, &genesis_owner);
    let handoff_sigscript = covenant_decl_sigscript(
        &genesis,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(handoff_owner_bytes.clone(), 1_000)]),
            sig_array_arg(vec![handoff_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let handoff_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
            handoff_sigscript,
        )],
        handoff_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(handoff_tx.clone(), handoff_entries, 0).expect("Dog20 handoff should succeed");

    let split_outputs = vec![
        TransactionOutput {
            value: 700,
            script_public_key: pay_to_script_hash_script(&split_a.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
        TransactionOutput {
            value: 700,
            script_public_key: pay_to_script_hash_script(&split_b.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
    ];
    let split_entries = vec![UtxoEntry::new(
        handoff_outputs[0].value,
        handoff_outputs[0].script_public_key.clone(),
        0,
        handoff_tx.is_coinbase(),
        Some(COV_A),
    )];
    let split_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: handoff_tx.id(), index: 0 }, vec![])],
        split_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let split_sig = sign_tx_input(split_unsigned_tx, split_entries.clone(), 0, &handoff_owner);
    let split_sigscript = covenant_decl_sigscript(
        &handoff,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(split_owner_a_bytes.clone(), 400), (split_owner_b_bytes.clone(), 600)]),
            sig_array_arg(vec![split_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let split_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: handoff_tx.id(), index: 0 }, split_sigscript)],
        split_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(split_tx.clone(), split_entries, 0).expect("Dog20 split should succeed");

    let merged = compile_dog20_state(&source, merged_owner_bytes.clone(), 1_000, 2, 2);
    let merge_outputs = vec![TransactionOutput {
        value: 2_000,
        script_public_key: pay_to_script_hash_script(&merged.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let merge_entries = vec![
        UtxoEntry::new(700, pay_to_script_hash_script(&split_a.script), 0, split_tx.is_coinbase(), Some(COV_A)),
        UtxoEntry::new(700, pay_to_script_hash_script(&split_b.script), 0, split_tx.is_coinbase(), Some(COV_A)),
    ];
    let merge_unsigned_tx = Transaction::new(
        1,
        vec![
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, vec![]),
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, vec![]),
        ],
        merge_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let merge_sig_a = sign_tx_input(merge_unsigned_tx.clone(), merge_entries.clone(), 0, &split_owner_a);
    let merge_sig_b = sign_tx_input(merge_unsigned_tx, merge_entries.clone(), 0, &split_owner_b);
    let merge_leader_sigscript = covenant_decl_sigscript(
        &split_a,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(merged_owner_bytes, 1_000)]),
            sig_array_arg(vec![merge_sig_a, merge_sig_b]),
            witness_array_arg(vec![0, 1]),
        ],
        true,
    );
    let merge_delegate_sigscript = covenant_decl_sigscript(&split_b, "transfer", vec![], false);
    let merge_tx = Transaction::new(
        1,
        vec![
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, merge_leader_sigscript),
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, merge_delegate_sigscript),
        ],
        merge_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(merge_tx.clone(), merge_entries.clone(), 0).expect("Dog20 merge leader should succeed");
    execute_input_with_covenants(merge_tx, merge_entries, 1).expect("Dog20 merge delegate should succeed");
}

#[test]
fn dog20_rejects_merge_when_one_signature_is_wrong() {
    let source = load_example_source("dog20.sil");

    let genesis_owner = random_keypair();
    let handoff_owner = random_keypair();
    let split_owner_a = random_keypair();
    let split_owner_b = random_keypair();
    let wrong_signer = random_keypair();
    let merged_owner = random_keypair();

    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();
    let handoff_owner_bytes = handoff_owner.x_only_public_key().0.serialize().to_vec();
    let split_owner_a_bytes = split_owner_a.x_only_public_key().0.serialize().to_vec();
    let split_owner_b_bytes = split_owner_b.x_only_public_key().0.serialize().to_vec();
    let merged_owner_bytes = merged_owner.x_only_public_key().0.serialize().to_vec();

    let genesis = compile_dog20_state(&source, genesis_owner_bytes.clone(), 1_000, 2, 2);
    let handoff = compile_dog20_state(&source, handoff_owner_bytes.clone(), 1_000, 2, 2);
    let split_a = compile_dog20_state(&source, split_owner_a_bytes.clone(), 400, 2, 2);
    let split_b = compile_dog20_state(&source, split_owner_b_bytes.clone(), 600, 2, 2);
    let merged = compile_dog20_state(&source, merged_owner_bytes.clone(), 1_000, 2, 2);

    let handoff_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&handoff.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let handoff_entries = vec![covenant_utxo(&genesis, COV_A)];
    let handoff_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 }, vec![])],
        handoff_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let handoff_sig = sign_tx_input(handoff_unsigned_tx, handoff_entries.clone(), 0, &genesis_owner);
    let handoff_sigscript = covenant_decl_sigscript(
        &genesis,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(handoff_owner_bytes.clone(), 1_000)]),
            sig_array_arg(vec![handoff_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let handoff_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
            handoff_sigscript,
        )],
        handoff_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(handoff_tx.clone(), handoff_entries, 0).expect("Dog20 handoff should succeed");

    let split_outputs = vec![
        TransactionOutput {
            value: 700,
            script_public_key: pay_to_script_hash_script(&split_a.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
        TransactionOutput {
            value: 700,
            script_public_key: pay_to_script_hash_script(&split_b.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
    ];
    let split_entries = vec![UtxoEntry::new(
        handoff_outputs[0].value,
        handoff_outputs[0].script_public_key.clone(),
        0,
        handoff_tx.is_coinbase(),
        Some(COV_A),
    )];
    let split_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: handoff_tx.id(), index: 0 }, vec![])],
        split_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let split_sig = sign_tx_input(split_unsigned_tx, split_entries.clone(), 0, &handoff_owner);
    let split_sigscript = covenant_decl_sigscript(
        &handoff,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(split_owner_a_bytes.clone(), 400), (split_owner_b_bytes.clone(), 600)]),
            sig_array_arg(vec![split_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let split_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: handoff_tx.id(), index: 0 }, split_sigscript)],
        split_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(split_tx.clone(), split_entries, 0).expect("Dog20 split should succeed");

    let merge_outputs = vec![TransactionOutput {
        value: 2_000,
        script_public_key: pay_to_script_hash_script(&merged.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let merge_entries = vec![
        UtxoEntry::new(700, pay_to_script_hash_script(&split_a.script), 0, split_tx.is_coinbase(), Some(COV_A)),
        UtxoEntry::new(700, pay_to_script_hash_script(&split_b.script), 0, split_tx.is_coinbase(), Some(COV_A)),
    ];
    let merge_unsigned_tx = Transaction::new(
        1,
        vec![
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, vec![]),
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, vec![]),
        ],
        merge_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let merge_sig_a = sign_tx_input(merge_unsigned_tx.clone(), merge_entries.clone(), 0, &split_owner_a);
    let wrong_sig_b = sign_tx_input(merge_unsigned_tx, merge_entries.clone(), 0, &wrong_signer);
    let merge_leader_sigscript = covenant_decl_sigscript(
        &split_a,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(merged_owner_bytes, 1_000)]),
            sig_array_arg(vec![merge_sig_a, wrong_sig_b]),
            witness_array_arg(vec![0, 1]),
        ],
        true,
    );
    let merge_delegate_sigscript = covenant_decl_sigscript(&split_b, "transfer", vec![], false);
    let merge_tx = Transaction::new(
        1,
        vec![
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, merge_leader_sigscript),
            tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, merge_delegate_sigscript),
        ],
        merge_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    let err = execute_input_with_covenants(merge_tx, merge_entries, 0)
        .expect_err("Dog20 merge should reject when one signature does not match the previous owner");
    assert_verify_like_error(err);
}

#[test]
fn dog20_rejects_split_when_amounts_do_not_match() {
    let source = load_example_source("dog20.sil");

    let genesis_owner = random_keypair();
    let handoff_owner = random_keypair();
    let split_owner_a = random_keypair();
    let split_owner_b = random_keypair();

    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();
    let handoff_owner_bytes = handoff_owner.x_only_public_key().0.serialize().to_vec();
    let split_owner_a_bytes = split_owner_a.x_only_public_key().0.serialize().to_vec();
    let split_owner_b_bytes = split_owner_b.x_only_public_key().0.serialize().to_vec();

    let genesis = compile_dog20_state(&source, genesis_owner_bytes.clone(), 1_000, 2, 2);
    let handoff = compile_dog20_state(&source, handoff_owner_bytes.clone(), 1_000, 2, 2);
    let split_a = compile_dog20_state(&source, split_owner_a_bytes.clone(), 400, 2, 2);
    let split_b = compile_dog20_state(&source, split_owner_b_bytes.clone(), 500, 2, 2);

    let handoff_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&handoff.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let handoff_entries = vec![covenant_utxo(&genesis, COV_A)];
    let handoff_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 }, vec![])],
        handoff_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let handoff_sig = sign_tx_input(handoff_unsigned_tx, handoff_entries.clone(), 0, &genesis_owner);
    let handoff_sigscript = covenant_decl_sigscript(
        &genesis,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(handoff_owner_bytes.clone(), 1_000)]),
            sig_array_arg(vec![handoff_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let handoff_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
            handoff_sigscript,
        )],
        handoff_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(handoff_tx.clone(), handoff_entries, 0).expect("Dog20 handoff should succeed");

    let split_outputs = vec![
        TransactionOutput {
            value: 700,
            script_public_key: pay_to_script_hash_script(&split_a.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
        TransactionOutput {
            value: 700,
            script_public_key: pay_to_script_hash_script(&split_b.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
    ];
    let split_entries = vec![UtxoEntry::new(
        handoff_outputs[0].value,
        handoff_outputs[0].script_public_key.clone(),
        0,
        handoff_tx.is_coinbase(),
        Some(COV_A),
    )];
    let split_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: handoff_tx.id(), index: 0 }, vec![])],
        split_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let split_sig = sign_tx_input(split_unsigned_tx, split_entries.clone(), 0, &handoff_owner);
    let split_sigscript = covenant_decl_sigscript(
        &handoff,
        "transfer",
        vec![
            dog20_state_array_arg(vec![(split_owner_a_bytes, 400), (split_owner_b_bytes, 500)]),
            sig_array_arg(vec![split_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let split_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: handoff_tx.id(), index: 0 }, split_sigscript)],
        split_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    let err = execute_input_with_covenants(split_tx, split_entries, 0)
        .expect_err("Dog20 split should reject when output amounts do not add up to the input amount");
    assert_verify_like_error(err);
}

#[test]
fn dog20_minter_can_split_then_mint_then_burn() {
    let source = load_example_source("dog20.sil");

    let genesis_owner = random_keypair();
    let other_owner = random_keypair();
    let minter_owner = random_keypair();

    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();
    let other_owner_bytes = other_owner.x_only_public_key().0.serialize().to_vec();
    let minter_owner_bytes = minter_owner.x_only_public_key().0.serialize().to_vec();

    let genesis = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 1_000, true, 2, 2);
    let split_minter = compile_dog20_state_with_minter(&source, minter_owner_bytes.clone(), 400, true, 2, 2);
    let split_other = compile_dog20_state(&source, other_owner_bytes.clone(), 600, 2, 2);
    let minted_minter = compile_dog20_state_with_minter(&source, minter_owner_bytes.clone(), 900, true, 2, 2);
    let burned_minter = compile_dog20_state_with_minter(&source, minter_owner_bytes.clone(), 500, true, 2, 2);

    let split_outputs = vec![
        TransactionOutput {
            value: 1_000,
            script_public_key: pay_to_script_hash_script(&split_minter.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
        TransactionOutput {
            value: 1_000,
            script_public_key: pay_to_script_hash_script(&split_other.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
    ];
    let split_entries = vec![covenant_utxo(&genesis, COV_A)];
    let split_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 }, vec![])],
        split_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let split_sig = sign_tx_input(split_unsigned_tx, split_entries.clone(), 0, &genesis_owner);
    let split_sigscript = covenant_decl_sigscript(
        &genesis,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(minter_owner_bytes.clone(), 400, true), (other_owner_bytes.clone(), 600, false)]),
            sig_array_arg(vec![split_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let split_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
            split_sigscript,
        )],
        split_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(split_tx.clone(), split_entries, 0).expect("Dog20 minter split should succeed");

    let forged_other = compile_dog20_state(&source, other_owner_bytes.clone(), 700, 2, 2);
    let forged_other_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&forged_other.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let forged_other_entries =
        vec![UtxoEntry::new(1_000, pay_to_script_hash_script(&split_other.script), 0, split_tx.is_coinbase(), Some(COV_A))];
    let forged_other_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, vec![])],
        forged_other_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let forged_other_sig = sign_tx_input(forged_other_unsigned_tx, forged_other_entries.clone(), 0, &other_owner);
    let forged_other_sigscript = covenant_decl_sigscript(
        &split_other,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(other_owner_bytes.clone(), 700, false)]),
            sig_array_arg(vec![forged_other_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let forged_other_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, forged_other_sigscript)],
        forged_other_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    let err = execute_input_with_covenants(forged_other_tx, forged_other_entries, 0)
        .expect_err("Dog20 non-minter branch should reject minting more tokens");
    assert_verify_like_error(err);

    let forged_other_minter = compile_dog20_state_with_minter(&source, other_owner_bytes.clone(), 600, true, 2, 2);
    let forged_other_minter_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&forged_other_minter.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let forged_other_minter_entries =
        vec![UtxoEntry::new(1_000, pay_to_script_hash_script(&split_other.script), 0, split_tx.is_coinbase(), Some(COV_A))];
    let forged_other_minter_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 1 }, vec![])],
        forged_other_minter_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let forged_other_minter_sig =
        sign_tx_input(forged_other_minter_unsigned_tx, forged_other_minter_entries.clone(), 0, &other_owner);
    let forged_other_minter_sigscript = covenant_decl_sigscript(
        &split_other,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(other_owner_bytes.clone(), 600, true)]),
            sig_array_arg(vec![forged_other_minter_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let forged_other_minter_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: split_tx.id(), index: 1 },
            forged_other_minter_sigscript,
        )],
        forged_other_minter_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    let err = execute_input_with_covenants(forged_other_minter_tx, forged_other_minter_entries, 0)
        .expect_err("Dog20 non-minter branch should reject setting isMinter=true");
    assert_verify_like_error(err);

    let mint_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&minted_minter.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let mint_entries =
        vec![UtxoEntry::new(1_000, pay_to_script_hash_script(&split_minter.script), 0, split_tx.is_coinbase(), Some(COV_A))];
    let mint_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, vec![])],
        mint_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let mint_sig = sign_tx_input(mint_unsigned_tx, mint_entries.clone(), 0, &minter_owner);
    let mint_sigscript = covenant_decl_sigscript(
        &split_minter,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(minter_owner_bytes.clone(), 900, true)]),
            sig_array_arg(vec![mint_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let mint_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, mint_sigscript)],
        mint_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(mint_tx.clone(), mint_entries, 0).expect("Dog20 minter should be able to create tokens");

    let burn_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&burned_minter.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let burn_entries =
        vec![UtxoEntry::new(1_000, pay_to_script_hash_script(&minted_minter.script), 0, mint_tx.is_coinbase(), Some(COV_A))];
    let burn_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: mint_tx.id(), index: 0 }, vec![])],
        burn_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let burn_sig = sign_tx_input(burn_unsigned_tx, burn_entries.clone(), 0, &minter_owner);
    let burn_sigscript = covenant_decl_sigscript(
        &minted_minter,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(minter_owner_bytes, 500, true)]),
            sig_array_arg(vec![burn_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let burn_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: mint_tx.id(), index: 0 }, burn_sigscript)],
        burn_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(burn_tx, burn_entries, 0).expect("Dog20 minter should be able to burn tokens");
}

#[test]
fn dog20_minter_can_mint_in_single_transaction() {
    let source = load_example_source("dog20.sil");

    let genesis_owner = random_keypair();
    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();

    let genesis = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 1_000, true, 2, 2);
    let minted = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 1_500, true, 2, 2);

    let mint_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&minted.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let mint_entries = vec![covenant_utxo(&genesis, COV_A)];
    let mint_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 }, vec![])],
        mint_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let mint_sig = sign_tx_input(mint_unsigned_tx, mint_entries.clone(), 0, &genesis_owner);
    let mint_sigscript = covenant_decl_sigscript(
        &genesis,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(genesis_owner_bytes, 1_500, true)]),
            sig_array_arg(vec![mint_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let mint_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
            mint_sigscript,
        )],
        mint_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(mint_tx, mint_entries, 0).expect("Dog20 minter should be able to mint in a single transaction");
}

#[test]
fn dog20_minter_example_regresses_on_helper_call_with_template_parts_from_dog20() {
    let dog20_source = load_example_source("dog20.sil");
    let dog20_minter_source = load_example_source("dog20-minter.sil");

    let owner = random_keypair();
    let owner_bytes = owner.x_only_public_key().0.serialize().to_vec();
    let dog20_covenant_id = Hash::from_bytes(*b"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

    let dog20 = compile_dog20_state(&dog20_source, owner_bytes.clone(), 1_000, 2, 2);
    let (template_prefix, template_suffix, expected_template_hash) = compiled_template_parts_and_hash(&dog20);

    let result = compile_contract(
        &dog20_minter_source,
        &[
            Expr::bytes(owner_bytes),
            Expr::bytes(dog20_covenant_id.as_bytes().to_vec()),
            Expr::int(1_000),
            Expr::bool(false),
            Expr::int(template_prefix.len() as i64),
            Expr::int(template_suffix.len() as i64),
            Expr::bytes(expected_template_hash),
            Expr::bytes(template_prefix),
            Expr::bytes(template_suffix),
        ],
        CompileOptions::default(),
    );

    let err = result.expect_err("regression: dog20-minter.sil currently rejects the calcInAmount() helper when parameterized from dog20.sil");
    assert!(
        err.to_string().contains("unknown function call: calcInAmount"),
        "expected calcInAmount helper regression, got: {err:?}"
    );
}

#[test]
fn dog20_non_minter_can_spend_script_hash_and_covenant_id_owned_outputs() {
    let source = load_example_source("dog20.sil");
    const IDENTIFIER_SCRIPT_HASH: u8 = 0x01;
    const IDENTIFIER_COVENANT_ID: u8 = 0x02;

    // Setup: create the special owners and split the genesis allocation into one
    // script-hash-owned branch and one covenant-id-owned branch.
    let genesis_owner = random_keypair();
    let multisig_spend_destination_owner = random_keypair();
    let covenant_spend_destination_owner = random_keypair();
    let multisig_key_0 = random_keypair();
    let multisig_key_1 = random_keypair();
    let multisig_key_2 = random_keypair();

    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();
    let multisig_spend_destination_owner_bytes = multisig_spend_destination_owner.x_only_public_key().0.serialize().to_vec();
    let covenant_spend_destination_owner_bytes = covenant_spend_destination_owner.x_only_public_key().0.serialize().to_vec();

    let multisig_redeem_script = multisig_redeem_script(
        vec![
            multisig_key_0.x_only_public_key().0.serialize(),
            multisig_key_1.x_only_public_key().0.serialize(),
            multisig_key_2.x_only_public_key().0.serialize(),
        ]
        .into_iter(),
        2,
    )
    .expect("multisig redeem script builds");
    let multisig_script_hash = blake2b32(&multisig_redeem_script);
    let covenant_owner = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    let covenant_owner_bytes = covenant_owner.as_bytes().to_vec();

    let genesis = compile_dog20_state(&source, genesis_owner_bytes.clone(), 1_000, 2, 2);
    let split_states = vec![
        compile_dog20_state_full(&source, multisig_script_hash.clone(), 400, IDENTIFIER_SCRIPT_HASH, false, 2, 2),
        compile_dog20_state_full(&source, covenant_owner_bytes.clone(), 600, IDENTIFIER_COVENANT_ID, false, 2, 2),
    ];

    let split_outputs: Vec<_> = split_states
        .iter()
        .map(|state| TransactionOutput {
            value: 150,
            script_public_key: pay_to_script_hash_script(&state.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        })
        .collect();
    let split_entries = vec![covenant_utxo(&genesis, COV_A)];
    let split_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 }, vec![])],
        split_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let split_sig = sign_tx_input(split_unsigned_tx, split_entries.clone(), 0, &genesis_owner);
    let split_sigscript = covenant_decl_sigscript(
        &genesis,
        "transfer",
        vec![
            dog20_state_array_arg_full(vec![
                (multisig_script_hash.clone(), IDENTIFIER_SCRIPT_HASH, 400, false),
                (covenant_owner_bytes.clone(), IDENTIFIER_COVENANT_ID, 600, false),
            ]),
            sig_array_arg(vec![split_sig]),
            witness_array_arg(vec![0]),
        ],
        true,
    );
    let split_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([1; 32]), index: 0 },
            split_sigscript,
        )],
        split_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    execute_input_with_covenants(split_tx.clone(), split_entries, 0).expect("Dog20 non-minter split should succeed");

    let build_single_output = |state: &CompiledContract<'_>| {
        vec![TransactionOutput {
            value: 150,
            script_public_key: pay_to_script_hash_script(&state.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        }]
    };
    let build_spend_tx = |dog20_index: u32,
                          auxiliary_outpoint: Option<TransactionOutpoint>,
                          sigscript: Vec<u8>,
                          outputs: Vec<TransactionOutput>| {
        let mut inputs = vec![tx_input_from_outpoint_v1(
            TransactionOutpoint { transaction_id: split_tx.id(), index: dog20_index },
            sigscript,
        )];
        if let Some(outpoint) = auxiliary_outpoint {
            inputs.push(tx_input_from_outpoint_v1(outpoint, vec![]));
        }
        Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![])
    };
    let build_dog20_sigscript = |state: &CompiledContract<'_>, destination_owner: Vec<u8>, amount: i64, witness: u8| {
        covenant_decl_sigscript(
            state,
            "transfer",
            vec![
                dog20_state_array_arg(vec![(destination_owner, amount)]),
                sig_array_arg(vec![]),
                witness_array_arg(vec![witness]),
            ],
            true,
        )
    };

    let script_hash_spent = compile_dog20_state(&source, multisig_spend_destination_owner_bytes.clone(), 400, 2, 2);
    let script_hash_spend_outputs = build_single_output(&script_hash_spent);
    let script_hash_spend_entries = vec![
        UtxoEntry::new(150, pay_to_script_hash_script(&split_states[0].script), 0, split_tx.is_coinbase(), Some(COV_A)),
        UtxoEntry::new(500, pay_to_script_hash_script(&multisig_redeem_script), 0, false, None),
    ];
    let script_hash_auxiliary_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([2; 32]), index: 0 };

    // Wrong witness: the Dog20 input points at itself instead of the attached multisig input.
    {
        let script_hash_wrong_witness_tx = build_spend_tx(
            0,
            Some(script_hash_auxiliary_outpoint),
            build_dog20_sigscript(&split_states[0], multisig_spend_destination_owner_bytes.clone(), 400, 0),
            script_hash_spend_outputs.clone(),
        );
        let err = execute_input_with_covenants(script_hash_wrong_witness_tx, script_hash_spend_entries.clone(), 0)
            .expect_err("Dog20 script-hash-owned tokens should reject the wrong witness index");
        assert_verify_like_error(err);
    }

    // Missing input: no multisig-controlled auxiliary input is attached at all.
    {
        let script_hash_missing_extra_tx = build_spend_tx(
            0,
            None,
            build_dog20_sigscript(&split_states[0], multisig_spend_destination_owner_bytes.clone(), 400, 0),
            script_hash_spend_outputs.clone(),
        );
        let err = execute_input_with_covenants(script_hash_missing_extra_tx, vec![script_hash_spend_entries[0].clone()], 0)
            .expect_err("Dog20 script-hash-owned tokens should reject a spend without the matching p2sh input");
        assert_verify_like_error(err);
    }

    // Wrong owner type: a covenant-owned auxiliary input cannot authorize the multisig-owned branch.
    {
        let script_hash_wrong_owner_entries = vec![
            script_hash_spend_entries[0].clone(),
            UtxoEntry::new(500, pay_to_script_hash_script(&[0x51]), 0, false, Some(covenant_owner)),
        ];
        let script_hash_wrong_owner_tx = build_spend_tx(
            0,
            Some(TransactionOutpoint { transaction_id: TransactionId::from_bytes([4; 32]), index: 0 }),
            build_dog20_sigscript(&split_states[0], multisig_spend_destination_owner_bytes.clone(), 400, 1),
            script_hash_spend_outputs.clone(),
        );
        let err = execute_input_with_covenants(script_hash_wrong_owner_tx, script_hash_wrong_owner_entries, 0)
            .expect_err("Dog20 script-hash-owned tokens should reject a covenant-id witness input");
        assert_verify_like_error(err);
    }

    // Happy path: the witness points at the attached multisig-controlled input.
    {
        let script_hash_spend_tx = build_spend_tx(
            0,
            Some(script_hash_auxiliary_outpoint),
            build_dog20_sigscript(&split_states[0], multisig_spend_destination_owner_bytes.clone(), 400, 1),
            script_hash_spend_outputs,
        );
        execute_input_with_covenants(script_hash_spend_tx, script_hash_spend_entries, 0)
            .expect("Dog20 script-hash-owned tokens should spend when the matching p2sh input is present");
    }

    let covenant_id_spent = compile_dog20_state(&source, covenant_spend_destination_owner_bytes.clone(), 600, 2, 2);
    let covenant_id_spend_outputs = build_single_output(&covenant_id_spent);
    let covenant_id_spend_entries = vec![
        UtxoEntry::new(150, pay_to_script_hash_script(&split_states[1].script), 0, split_tx.is_coinbase(), Some(COV_A)),
        UtxoEntry::new(500, pay_to_script_hash_script(&[0x51]), 0, false, Some(covenant_owner)),
    ];
    let covenant_id_auxiliary_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([3; 32]), index: 0 };

    // Wrong witness: the Dog20 input points at itself instead of the attached covenant-owned input.
    {
        let covenant_id_wrong_witness_tx = build_spend_tx(
            1,
            Some(covenant_id_auxiliary_outpoint),
            build_dog20_sigscript(&split_states[1], covenant_spend_destination_owner_bytes.clone(), 600, 0),
            covenant_id_spend_outputs.clone(),
        );
        let err = execute_input_with_covenants(covenant_id_wrong_witness_tx, covenant_id_spend_entries.clone(), 0)
            .expect_err("Dog20 covenant-id-owned tokens should reject the wrong witness index");
        assert_verify_like_error(err);
    }

    // Missing input: no covenant-owned auxiliary input is attached at all.
    {
        let covenant_id_missing_extra_tx = build_spend_tx(
            1,
            None,
            build_dog20_sigscript(&split_states[1], covenant_spend_destination_owner_bytes.clone(), 600, 0),
            covenant_id_spend_outputs.clone(),
        );
        let err = execute_input_with_covenants(covenant_id_missing_extra_tx, vec![covenant_id_spend_entries[0].clone()], 0)
            .expect_err("Dog20 covenant-id-owned tokens should reject a spend without the matching covenant input");
        assert_verify_like_error(err);
    }

    // Wrong owner type: a multisig-controlled auxiliary input cannot authorize the covenant-id-owned branch.
    {
        let covenant_id_wrong_owner_entries = vec![
            covenant_id_spend_entries[0].clone(),
            UtxoEntry::new(500, pay_to_script_hash_script(&multisig_redeem_script), 0, false, None),
        ];
        let covenant_id_wrong_owner_tx = build_spend_tx(
            1,
            Some(TransactionOutpoint { transaction_id: TransactionId::from_bytes([5; 32]), index: 0 }),
            build_dog20_sigscript(&split_states[1], covenant_spend_destination_owner_bytes.clone(), 600, 1),
            covenant_id_spend_outputs.clone(),
        );
        let err = execute_input_with_covenants(covenant_id_wrong_owner_tx, covenant_id_wrong_owner_entries, 0)
            .expect_err("Dog20 covenant-id-owned tokens should reject a multisig witness input");
        assert_verify_like_error(err);
    }

    // Happy path: the witness points at the attached covenant-owned input.
    {
        let covenant_id_spend_tx = build_spend_tx(
            1,
            Some(covenant_id_auxiliary_outpoint),
            build_dog20_sigscript(&split_states[1], covenant_spend_destination_owner_bytes, 600, 1),
            covenant_id_spend_outputs,
        );
        execute_input_with_covenants(covenant_id_spend_tx, covenant_id_spend_entries, 0)
            .expect("Dog20 covenant-id-owned tokens should spend when the matching covenant input is present");
    }
}
