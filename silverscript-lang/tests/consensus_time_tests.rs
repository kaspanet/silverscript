use kaspa_consensus::config::ConfigBuilder;
use kaspa_consensus::consensus::test_consensus::TestConsensus;
use kaspa_consensus::params::{DEVNET_PARAMS, ForkActivation};
use kaspa_consensus_core::api::ConsensusApi;
use kaspa_consensus_core::api::args::TransactionValidationArgs;
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::merkle::calc_hash_merkle_root;
use kaspa_consensus_core::muhash::MuHashExtensions;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_muhash::MuHash;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};

const FUNDING_AMOUNT: u64 = 10_000_000_000;
const AGE_OUTPUT_AMOUNT: u64 = 1_900_000_000;

fn spending_transaction(outpoint: TransactionOutpoint, signature_script: Vec<u8>, sequence: u64, lock_time: u64) -> Transaction {
    spending_transaction_with_output(
        outpoint,
        signature_script,
        sequence,
        lock_time,
        FUNDING_AMOUNT,
        ScriptPublicKey::from_vec(0, vec![0x51]),
    )
}

fn spending_transaction_with_output(
    outpoint: TransactionOutpoint,
    signature_script: Vec<u8>,
    sequence: u64,
    lock_time: u64,
    input_amount: u64,
    output_script_public_key: ScriptPublicKey,
) -> Transaction {
    let mut tx = Transaction::new(
        0,
        vec![TransactionInput::new(outpoint, signature_script, sequence, 0)],
        vec![TransactionOutput::new(input_amount - 1_000, output_script_public_key)],
        lock_time,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    tx.finalize();
    tx
}

#[tokio::test]
async fn compiled_lock_domains_are_enforced_in_actual_consensus_blocks() {
    // Compile one contract for each lock domain. The tests below spend their
    // outputs in real consensus blocks rather than inspecting emitted opcodes.
    let age_source = "contract Age() { entry main(int age) { require(this.ageDaa >= age); } }";
    let age = compile_contract(age_source, &[], CompileOptions::default()).expect("age contract compiles");
    let time_source = "contract TimeLock() { entry main(temporal timestamp) { require(tx.time >= timestamp); } }";
    let time = compile_contract(time_source, &[], CompileOptions::default()).expect("time contract compiles");
    let daa_source = "contract DaaLock() { entry main(int daa) { require(tx.daa >= daa); } }";
    let daa = compile_contract(daa_source, &[], CompileOptions::default()).expect("DAA contract compiles");

    let funding_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), 0);
    let age_overflow_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([2; 32]), 0);
    let daa_outpoints = (10_u8..15).map(|id| TransactionOutpoint::new(TransactionId::from_bytes([id; 32]), 0)).collect::<Vec<_>>();
    let time_outpoints = (20_u8..22).map(|id| TransactionOutpoint::new(TransactionId::from_bytes([id; 32]), 0)).collect::<Vec<_>>();

    // Give every rejected attempt its own UTXO. Reusing an outpoint from an
    // invalid candidate could make a later assertion depend on that candidate.
    let mut initial_utxos = vec![
        (funding_outpoint, UtxoEntry::new(FUNDING_AMOUNT, ScriptPublicKey::from_vec(0, vec![0x51]), 0, false, None)),
        (age_overflow_outpoint, UtxoEntry::new(FUNDING_AMOUNT, ScriptPublicKey::new(0, age.bytecode.clone().into()), 0, false, None)),
    ];
    initial_utxos.extend(daa_outpoints.iter().copied().map(|outpoint| {
        (outpoint, UtxoEntry::new(FUNDING_AMOUNT, ScriptPublicKey::new(0, daa.bytecode.clone().into()), 0, false, None))
    }));
    initial_utxos.extend(time_outpoints.iter().copied().map(|outpoint| {
        (outpoint, UtxoEntry::new(FUNDING_AMOUNT, ScriptPublicKey::new(0, time.bytecode.clone().into()), 0, false, None))
    }));

    let config = ConfigBuilder::new(DEVNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|params| {
            let mut genesis_multiset = MuHash::new();
            initial_utxos.iter().for_each(|(outpoint, utxo)| genesis_multiset.add_utxo(outpoint, utxo));
            params.genesis.utxo_commitment = genesis_multiset.finalize();
            params.genesis.hash = Header::from(&params.genesis).hash;
            params.coinbase_maturity = 0;
            params.crescendo_activation = ForkActivation::always();
        })
        .build();
    let consensus = TestConsensus::new(&config);
    let mut genesis_multiset = MuHash::new();
    consensus.append_imported_pruning_point_utxos(&initial_utxos, &mut genesis_multiset);
    consensus.import_pruning_point_utxo_set(config.genesis.hash, genesis_multiset).unwrap();
    let wait_handles = consensus.init();

    // Start with four blocks, then put the five age-locked outputs in block 5.
    // This gives all five outputs the same creation DAA score and lets each
    // attempted age spend use a fresh output.
    let mut tip = config.genesis.hash;
    for block_id in 1_u64..=4 {
        let block_hash = block_id.into();
        let status = consensus.add_empty_utxo_valid_block_with_parents(block_hash, vec![tip]).await;
        assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "bootstrap block {block_id} status: {status:?}");
        tip = block_hash;
    }

    let mut funding_tx = Transaction::new(
        0,
        vec![TransactionInput::new(funding_outpoint, vec![], 0, 0)],
        (0..5).map(|_| TransactionOutput::new(AGE_OUTPUT_AMOUNT, ScriptPublicKey::new(0, age.bytecode.clone().into()))).collect(),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    funding_tx.finalize();
    let funding_tx_id = funding_tx.id();
    let mut funding_tx = MutableTransaction::from_tx(funding_tx);
    consensus.validate_mempool_transaction(&mut funding_tx, &TransactionValidationArgs::default()).unwrap();
    let funding_block_hash = 5.into();
    let status = consensus.add_utxo_valid_block_with_parents(funding_block_hash, vec![tip], vec![(*funding_tx.tx).clone()]).await;
    assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "funding block status: {status:?}");
    tip = funding_block_hash;
    let funding_daa_score = consensus.get_header(funding_block_hash).unwrap().daa_score;
    assert_eq!(funding_daa_score, config.genesis.daa_score + 4, "the funding transaction must be in the fifth post-genesis block");

    let age_sigscript = age.build_sig_script("main", vec![Expr::int(4)]).expect("age sigscript builds");
    let miner_data = MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]);

    // At ages 0, 1, 2, and 3, append the spend to an otherwise valid candidate
    // block and verify that consensus disqualifies it. After each rejection,
    // add one valid empty block so the output age advances by exactly one.
    for additional_blocks in 0_u64..4 {
        assert_eq!(
            consensus.get_header(tip).unwrap().daa_score,
            funding_daa_score + additional_blocks,
            "each wait block must advance the DAA score by exactly one"
        );
        let age_tx = spending_transaction_with_output(
            TransactionOutpoint::new(funding_tx_id, additional_blocks as u32),
            age_sigscript.clone(),
            4,
            0,
            AGE_OUTPUT_AMOUNT,
            ScriptPublicKey::from_vec(0, vec![0x51]),
        );
        let mut premature_block =
            consensus.build_utxo_valid_block_with_parents((100 + additional_blocks).into(), vec![tip], miner_data.clone(), vec![]);
        premature_block.transactions.push(age_tx.clone());
        premature_block.header.hash_merkle_root = calc_hash_merkle_root(premature_block.transactions.iter());
        let status = consensus.validate_and_insert_block(premature_block.to_immutable()).virtual_state_task.await;
        assert!(
            matches!(status, Ok(BlockStatus::StatusDisqualifiedFromChain)),
            "age-four spend block must be disqualified after only {additional_blocks} additional blocks: {status:?}"
        );

        let block_hash = (6 + additional_blocks).into();
        let status = consensus.add_empty_utxo_valid_block_with_parents(block_hash, vec![tip]).await;
        assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "age wait block status: {status:?}");
        tip = block_hash;
    }
    assert_eq!(consensus.get_header(tip).unwrap().daa_score, funding_daa_score + 4);

    // Four additional blocks have now elapsed, so an identical age-four spend
    // from the fifth output must be accepted in an actual block.
    let age_tx = spending_transaction_with_output(
        TransactionOutpoint::new(funding_tx_id, 4),
        age_sigscript,
        4,
        0,
        AGE_OUTPUT_AMOUNT,
        ScriptPublicKey::from_vec(0, vec![0x51]),
    );
    let mut age_tx = MutableTransaction::from_tx(age_tx);
    consensus.validate_mempool_transaction(&mut age_tx, &TransactionValidationArgs::default()).unwrap();
    let age_block_hash = 10.into();
    let status = consensus.add_utxo_valid_block_with_parents(age_block_hash, vec![tip], vec![(*age_tx.tx).clone()]).await;
    assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "age block status: {status:?}");
    tip = age_block_hash;

    // tx.daa is an absolute DAA lock. Choose a target four DAA increments in
    // the future and keep the value below LOCK_TIME_THRESHOLD so consensus
    // interprets the transaction lock time in the DAA domain.
    let daa_start = consensus.get_header(tip).unwrap().daa_score;
    let daa_target = daa_start + 4;
    assert!(daa_target < kaspa_txscript::LOCK_TIME_THRESHOLD);
    let daa_sigscript = daa.build_sig_script("main", vec![Expr::int(daa_target as i64)]).expect("DAA sigscript builds");

    // Candidate blocks at target - 4 through target - 1 must all fail. Add one
    // valid empty block after each attempt to advance the chain one DAA step.
    for additional_blocks in 0_u64..4 {
        assert_eq!(consensus.get_header(tip).unwrap().daa_score, daa_start + additional_blocks);
        let daa_tx = spending_transaction(daa_outpoints[additional_blocks as usize], daa_sigscript.clone(), 0, daa_target);
        let mut premature_block =
            consensus.build_utxo_valid_block_with_parents((200 + additional_blocks).into(), vec![tip], miner_data.clone(), vec![]);
        premature_block.transactions.push(daa_tx);
        premature_block.header.hash_merkle_root = calc_hash_merkle_root(premature_block.transactions.iter());
        let status = consensus.validate_and_insert_block(premature_block.to_immutable()).virtual_state_task.await;
        assert!(status.is_err(), "tx.daa spend block must be rejected after only {additional_blocks} DAA increments: {status:?}");

        let block_hash = (20 + additional_blocks).into();
        let status = consensus.add_empty_utxo_valid_block_with_parents(block_hash, vec![tip]).await;
        assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "DAA wait block status: {status:?}");
        tip = block_hash;
    }
    assert_eq!(consensus.get_header(tip).unwrap().daa_score, daa_target);

    // At the exact target DAA score, the same absolute lock is finalized and
    // consensus accepts it into the next real block.
    let daa_tx = spending_transaction(daa_outpoints[4], daa_sigscript, 0, daa_target);
    let mut daa_tx = MutableTransaction::from_tx(daa_tx);
    consensus.validate_mempool_transaction(&mut daa_tx, &TransactionValidationArgs::default()).unwrap();
    let daa_block_hash = 24.into();
    let status = consensus.add_utxo_valid_block_with_parents(daa_block_hash, vec![tip], vec![(*daa_tx.tx).clone()]).await;
    assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "DAA block status: {status:?}");
    tip = daa_block_hash;

    // Transaction time locks are compared with the virtual past median time.
    // Equality remains locked because finality requires lock_time < median time.
    let locked_time_millis = consensus.get_virtual_past_median_time();
    assert!(locked_time_millis >= kaspa_txscript::LOCK_TIME_THRESHOLD);
    let locked_time_sigscript =
        time.build_sig_script("main", vec![Expr::temporal(locked_time_millis as i64)]).expect("locked time sigscript builds");
    let premature_time_tx = spending_transaction(time_outpoints[0], locked_time_sigscript, 0, locked_time_millis);
    let mut premature_time_block = consensus.build_utxo_valid_block_with_parents(300.into(), vec![tip], miner_data.clone(), vec![]);
    premature_time_block.transactions.push(premature_time_tx);
    premature_time_block.header.hash_merkle_root = calc_hash_merkle_root(premature_time_block.transactions.iter());
    let status = consensus.validate_and_insert_block(premature_time_block.to_immutable()).virtual_state_task.await;
    assert!(status.is_err(), "tx.time must remain locked when past median time equals its millisecond target: {status:?}");

    // Move only the requested lock back by one raw unit, without advancing the
    // chain. Acceptance at T - 1 after rejection at T proves that tx.time uses
    // millisecond—not second—granularity end to end.
    let unlocked_time_millis = locked_time_millis - 1;
    assert_eq!(locked_time_millis - unlocked_time_millis, 1, "the acceptance boundary must be one millisecond wide");
    let unlocked_time_sigscript =
        time.build_sig_script("main", vec![Expr::temporal(unlocked_time_millis as i64)]).expect("unlocked time sigscript builds");
    let time_tx = spending_transaction(time_outpoints[1], unlocked_time_sigscript, 0, unlocked_time_millis);
    let mut time_tx = MutableTransaction::from_tx(time_tx);
    consensus.validate_mempool_transaction(&mut time_tx, &TransactionValidationArgs::default()).unwrap();
    let time_block_hash = 25.into();
    let status = consensus.add_utxo_valid_block_with_parents(time_block_hash, vec![tip], vec![(*time_tx.tx).clone()]).await;
    assert!(matches!(status, Ok(BlockStatus::StatusUTXOValid)), "time block status: {status:?}");
    tip = time_block_hash;

    // Finally, prove the compiled this.ageDaa runtime guard also survives the
    // full consensus path: 2^32 is rejected even when supplied dynamically.
    let overflow_sigscript = age.build_sig_script("main", vec![Expr::int(1_i64 << 32)]).expect("age sigscript builds");
    let mut overflow_tx = MutableTransaction::from_tx(spending_transaction(age_overflow_outpoint, overflow_sigscript, 0, 0));
    let _ = consensus.validate_mempool_transaction(&mut overflow_tx, &TransactionValidationArgs::default());
    let overflow_tx = (*overflow_tx.tx).clone();
    let mut invalid_block = consensus.build_utxo_valid_block_with_parents(26.into(), vec![tip], miner_data, vec![]);
    invalid_block.transactions.push(overflow_tx);
    invalid_block.header.hash_merkle_root = calc_hash_merkle_root(invalid_block.transactions.iter());
    let status = consensus.validate_and_insert_block(invalid_block.to_immutable()).virtual_state_task.await;
    assert!(matches!(status, Ok(BlockStatus::StatusDisqualifiedFromChain)), "overflow block must be disqualified: {status:?}");

    consensus.shutdown(wait_handles);
}
