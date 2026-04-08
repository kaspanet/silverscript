use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;
use rand::{RngCore, thread_rng};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract, struct_object};
use std::fs;

mod common;

use common::{COV_A, assert_verify_like_error, covenant_decl_sigscript, covenant_utxo, execute_input_with_covenants};

use crate::common::covenant_output;
use crate::common::tx_input;

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

fn dog20_state_array_arg_with_minter<'i>(values: Vec<(Vec<u8>, i64, bool)>) -> Expr<'i> {
    values
        .into_iter()
        .map(|(owner_identifier, amount, is_minter)| {
            struct_object(vec![
                ("ownerIdentifier", Expr::bytes(owner_identifier)),
                ("identifierType", Expr::byte(0)),
                ("amount", Expr::int(amount)),
                ("isMinter", Expr::bool(is_minter)),
            ])
        })
        .collect::<Vec<_>>()
        .into()
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

fn compile_dog20_state_with_minter<'a>(
    source: &'a str,
    owner: Vec<u8>,
    amount: i64,
    is_minter: bool,
    max_cov_ins: i64,
    max_cov_outs: i64,
) -> CompiledContract<'a> {
    compile_contract(
        source,
        &[
            Expr::bytes(owner),
            Expr::int(amount),
            Expr::byte(0),
            Expr::bool(is_minter),
            Expr::int(max_cov_ins),
            Expr::int(max_cov_outs),
        ],
        CompileOptions::default(),
    )
    .expect("compile succeeds")
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

    let genesis_owner_bytes = genesis_owner.x_only_public_key().0.serialize().to_vec();
    let other_owner_bytes = other_owner.x_only_public_key().0.serialize().to_vec();

    let genesis = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 1_000, true, 2, 2);
    let split_genesis = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 400, true, 2, 2);
    let split_other = compile_dog20_state(&source, other_owner_bytes.clone(), 600, 2, 2);
    let minted_genesis = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 900, true, 2, 2);
    let burned_genesis = compile_dog20_state_with_minter(&source, genesis_owner_bytes.clone(), 500, true, 2, 2);

    let split_outputs = vec![
        TransactionOutput {
            value: 1_000,
            script_public_key: pay_to_script_hash_script(&split_genesis.script),
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
            dog20_state_array_arg_with_minter(vec![(genesis_owner_bytes.clone(), 400, true), (other_owner_bytes.clone(), 600, false)]),
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

    let mint_outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&minted_genesis.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let mint_entries =
        vec![UtxoEntry::new(1_000, pay_to_script_hash_script(&split_genesis.script), 0, split_tx.is_coinbase(), Some(COV_A))];
    let mint_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: split_tx.id(), index: 0 }, vec![])],
        mint_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let mint_sig = sign_tx_input(mint_unsigned_tx, mint_entries.clone(), 0, &genesis_owner);
    let mint_sigscript = covenant_decl_sigscript(
        &split_genesis,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(genesis_owner_bytes.clone(), 900, true)]),
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
        script_public_key: pay_to_script_hash_script(&burned_genesis.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let burn_entries =
        vec![UtxoEntry::new(1_000, pay_to_script_hash_script(&minted_genesis.script), 0, mint_tx.is_coinbase(), Some(COV_A))];
    let burn_unsigned_tx = Transaction::new(
        1,
        vec![tx_input_from_outpoint_v1(TransactionOutpoint { transaction_id: mint_tx.id(), index: 0 }, vec![])],
        burn_outputs.clone(),
        0,
        Default::default(),
        0,
        vec![],
    );
    let burn_sig = sign_tx_input(burn_unsigned_tx, burn_entries.clone(), 0, &genesis_owner);
    let burn_sigscript = covenant_decl_sigscript(
        &minted_genesis,
        "transfer",
        vec![
            dog20_state_array_arg_with_minter(vec![(genesis_owner_bytes, 500, true)]),
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
