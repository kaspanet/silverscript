use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use blake2b_simd::Params as Blake2bParams;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::parse_script;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script, pay_to_script_hash_signature_script};
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract};

const DEFAULT_MOVE_TIMEOUT: i64 = 600;

struct SizeSnapshot {
    name: &'static str,
    ctor: fn() -> Vec<Expr<'static>>,
    expected_script_len: usize,
    expected_instruction_count: usize,
    expected_charged_op_count: usize,
}

struct Player {
    keypair: Keypair,
    pubkey_bytes: Vec<u8>,
    owner_hash: Hash,
    player_id: Hash,
    player_ref: Hash,
}

struct TemplateFixture {
    source: &'static str,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: Hash,
}

struct MuxChessFixture {
    mux: TemplateFixture,
    settle: TemplateFixture,
    pawn: TemplateFixture,
    knight: TemplateFixture,
    vert: TemplateFixture,
    horiz: TemplateFixture,
    diag: TemplateFixture,
    king: TemplateFixture,
    castle: TemplateFixture,
    castle_challenge: TemplateFixture,
}

struct GameStateArgs<'a> {
    board: &'a [u8],
    turn: i64,
    status: i64,
    castle_rights: [u8; 4],
    en_passant_idx: i64,
    pending_src_idx: i64,
    pending_dst_idx: i64,
    pending_promo: i64,
    recent_castle: i64,
    draw_state: i64,
}

struct PlayerStateArgs<'a> {
    league_template: &'a Hash,
    player_template: &'a Hash,
    mux_template: &'a Hash,
    routes_commitment: &'a Hash,
    owner_hash: &'a Hash,
    player_id: &'a Hash,
    open_games: i64,
    rating: i64,
    games: i64,
    wins: i64,
    draws: i64,
    losses: i64,
}

struct MoveArgs {
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
    promo_piece: i64,
}

fn apps_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/apps/chess")
}

fn source_cache() -> &'static Mutex<HashMap<String, &'static str>> {
    static CACHE: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn compiled_contract_cache() -> &'static Mutex<HashMap<String, Arc<CompiledContract<'static>>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<CompiledContract<'static>>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn compile_cache_key(source: &'static str, ctor: &[Expr<'static>]) -> String {
    format!("{:p}:{}:{}", source.as_ptr(), source.len(), serde_json::to_string(ctor).expect("serialize chess ctor args"))
}

fn compile_cached(source: &'static str, ctor: &[Expr<'static>]) -> Arc<CompiledContract<'static>> {
    let key = compile_cache_key(source, ctor);
    {
        let cache = compiled_contract_cache().lock().expect("compile cache mutex poisoned");
        if let Some(compiled) = cache.get(&key) {
            return Arc::clone(compiled);
        }
    }

    let compiled = Arc::new(compile_contract(source, ctor, CompileOptions::default()).expect("compile chess contract succeeds"));
    let mut cache = compiled_contract_cache().lock().expect("compile cache mutex poisoned");
    cache.insert(key, Arc::clone(&compiled));
    compiled
}

fn contract_path(name: &str) -> PathBuf {
    apps_root().join(name)
}

fn load_contract_source(path: &Path) -> &'static str {
    let key = path.display().to_string();
    {
        let cache = source_cache().lock().expect("source cache mutex poisoned");
        if let Some(source) = cache.get(&key) {
            return source;
        }
    }

    let source = fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let leaked: &'static str = Box::leak(source.into_boxed_str());

    let mut cache = source_cache().lock().expect("source cache mutex poisoned");
    cache.insert(key, leaked);
    leaked
}

fn local_contract_source(name: &str) -> &'static str {
    load_contract_source(&contract_path(name))
}

fn mux_source() -> &'static str {
    local_contract_source("chess_mux.sil")
}

fn settle_source() -> &'static str {
    local_contract_source("chess_settle.sil")
}

fn league_source() -> &'static str {
    local_contract_source("league.sil")
}

fn player_source() -> &'static str {
    local_contract_source("player.sil")
}

fn pawn_source() -> &'static str {
    local_contract_source("chess_pawn.sil")
}

fn knight_source() -> &'static str {
    local_contract_source("chess_knight.sil")
}

fn vert_source() -> &'static str {
    local_contract_source("chess_vert.sil")
}

fn horiz_source() -> &'static str {
    local_contract_source("chess_horiz.sil")
}

fn diag_source() -> &'static str {
    local_contract_source("chess_diag.sil")
}

fn king_source() -> &'static str {
    local_contract_source("chess_king.sil")
}

fn castle_source() -> &'static str {
    local_contract_source("chess_castle.sil")
}

fn castle_challenge_source() -> &'static str {
    local_contract_source("chess_castle_challenge.sil")
}

fn blake2b_bytes(data: &[u8]) -> Hash {
    Hash::from_slice(Blake2bParams::new().hash_length(32).to_state().update(data).finalize().as_bytes())
}

fn hash_bytes(value: Hash) -> Vec<u8> {
    value.as_bytes().to_vec()
}

fn hash_pair(left: Hash, right: Hash) -> Hash {
    let left = left.as_bytes();
    let right = right.as_bytes();
    blake2b_bytes(&[left.as_slice(), right.as_slice()].concat())
}

fn hash_expr(value: Hash) -> Expr<'static> {
    Expr::bytes(hash_bytes(value))
}

fn repeated_hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn player_ref(owner_hash: Hash, player_id: Hash) -> Hash {
    hash_pair(owner_hash, player_id)
}

fn player_from_seed(seed: u8) -> Player {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (x_only, _) = keypair.x_only_public_key();
    let pubkey_bytes = x_only.serialize().to_vec();
    let owner_hash = blake2b_bytes(&pubkey_bytes);
    let player_id = blake2b_bytes(&[b"test-player-id".as_slice(), pubkey_bytes.as_slice()].concat());
    let player_ref = player_ref(owner_hash, player_id);
    Player { keypair, pubkey_bytes, owner_hash, player_id, player_ref }
}

fn standard_board() -> Vec<u8> {
    vec![
        0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d, 0x0e, 0x0b, 0x0a,
        0x0c,
    ]
}

fn sample_route_templates() -> Vec<u8> {
    let mut route_templates = Vec::with_capacity(32 * 9);
    for byte in 0x12u8..=0x1au8 {
        route_templates.extend_from_slice(&[byte; 32]);
    }
    route_templates
}

fn sample_routes_commitment() -> Hash {
    blake2b_bytes(&sample_route_templates())
}

fn square_idx(x: i64, y: i64) -> i64 {
    y * 8 + x
}

fn full_castle_rights() -> [u8; 4] {
    [1, 1, 1, 1]
}

fn castle_rights_expr(rights: [u8; 4]) -> Expr<'static> {
    Expr::bytes(rights.to_vec())
}

fn move_piece(board: &mut [u8], from_x: usize, from_y: usize, to_x: usize, to_y: usize) {
    let from_idx = from_y * 8 + from_x;
    let to_idx = to_y * 8 + to_x;
    let piece = board[from_idx];
    board[from_idx] = 0x00;
    board[to_idx] = piece;
}

fn mv(from_x: i64, from_y: i64, to_x: i64, to_y: i64) -> MoveArgs {
    MoveArgs { from_x, from_y, to_x, to_y, promo_piece: 0 }
}

fn packed_route_templates(fix: &MuxChessFixture) -> Vec<u8> {
    let player_template = player_template_hash(fix);
    let mut out = Vec::with_capacity(32 * 9);
    out.extend_from_slice(&fix.pawn.hash.as_bytes());
    out.extend_from_slice(&fix.knight.hash.as_bytes());
    out.extend_from_slice(&fix.vert.hash.as_bytes());
    out.extend_from_slice(&fix.horiz.hash.as_bytes());
    out.extend_from_slice(&fix.diag.hash.as_bytes());
    out.extend_from_slice(&fix.king.hash.as_bytes());
    out.extend_from_slice(&fix.castle.hash.as_bytes());
    out.extend_from_slice(&fix.castle_challenge.hash.as_bytes());
    let settle_commitment = Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(&fix.settle.hash.as_bytes())
        .update(&player_template.as_bytes())
        .finalize()
        .as_bytes()
        .to_vec();
    out.extend_from_slice(&settle_commitment);
    out
}

fn routes_commitment(route_templates: &[u8]) -> Hash {
    blake2b_bytes(route_templates)
}

fn template_fixture(source: &'static str, ctor: &[Expr<'static>]) -> TemplateFixture {
    let compiled = compile_cached(source, ctor);
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let hash = blake2b_bytes(&[prefix.as_slice(), suffix.as_slice()].concat());
    TemplateFixture { source, prefix, suffix, hash }
}

fn fixture() -> &'static MuxChessFixture {
    static FIXTURE: OnceLock<MuxChessFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let dummy_board = standard_board();
        let game_ctor = vec![
            Expr::bytes(vec![0x11u8; 32]),
            Expr::bytes(vec![0x33u8; 32 * 9]),
            Expr::bytes(vec![0x21u8; 32]),
            Expr::bytes(vec![0x22u8; 32]),
            Expr::bytes(dummy_board),
            Expr::int(0),
            Expr::int(0),
            Expr::int(DEFAULT_MOVE_TIMEOUT),
            castle_rights_expr(full_castle_rights()),
            Expr::int(-1),
            Expr::int(-1),
            Expr::int(-1),
            Expr::int(0),
            Expr::int(0),
            Expr::int(3),
        ];
        let settle_ctor =
            vec![Expr::bytes(vec![0x44u8; 32]), Expr::bytes(vec![0x21u8; 32]), Expr::bytes(vec![0x22u8; 32]), Expr::int(0)];

        MuxChessFixture {
            mux: template_fixture(mux_source(), &game_ctor),
            settle: template_fixture(settle_source(), &settle_ctor),
            pawn: template_fixture(pawn_source(), &game_ctor),
            knight: template_fixture(knight_source(), &game_ctor),
            vert: template_fixture(vert_source(), &game_ctor),
            horiz: template_fixture(horiz_source(), &game_ctor),
            diag: template_fixture(diag_source(), &game_ctor),
            king: template_fixture(king_source(), &game_ctor),
            castle: template_fixture(castle_source(), &game_ctor),
            castle_challenge: template_fixture(castle_challenge_source(), &game_ctor),
        }
    })
}

fn compile_state(
    source: &'static str,
    fix: &MuxChessFixture,
    white_hash: &Hash,
    black_hash: &Hash,
    state: GameStateArgs<'_>,
) -> Arc<CompiledContract<'static>> {
    let ctor = vec![
        hash_expr(fix.mux.hash),
        Expr::bytes(packed_route_templates(fix)),
        hash_expr(*white_hash),
        hash_expr(*black_hash),
        Expr::bytes(state.board.to_vec()),
        Expr::int(state.turn),
        Expr::int(state.status),
        Expr::int(DEFAULT_MOVE_TIMEOUT),
        castle_rights_expr(state.castle_rights),
        Expr::int(state.en_passant_idx),
        Expr::int(state.pending_src_idx),
        Expr::int(state.pending_dst_idx),
        Expr::int(state.pending_promo),
        Expr::int(state.recent_castle),
        Expr::int(state.draw_state),
    ];
    compile_cached(source, &ctor)
}

fn compile_settle_state(
    source: &'static str,
    player_template: &Hash,
    white_hash: &Hash,
    black_hash: &Hash,
    status: i64,
) -> Arc<CompiledContract<'static>> {
    let ctor = vec![hash_expr(*player_template), hash_expr(*white_hash), hash_expr(*black_hash), Expr::int(status)];
    compile_cached(source, &ctor)
}

fn compile_player_state(source: &'static str, state: PlayerStateArgs<'_>) -> Arc<CompiledContract<'static>> {
    let ctor = vec![
        hash_expr(*state.league_template),
        hash_expr(*state.player_template),
        hash_expr(*state.mux_template),
        hash_expr(*state.routes_commitment),
        hash_expr(*state.owner_hash),
        hash_expr(*state.player_id),
        Expr::int(state.open_games),
        Expr::int(state.rating),
        Expr::int(state.games),
        Expr::int(state.wins),
        Expr::int(state.draws),
        Expr::int(state.losses),
    ];
    compile_cached(source, &ctor)
}

fn player_template_hash(fix: &MuxChessFixture) -> Hash {
    let compiled = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &repeated_hash(0x11),
            player_template: &repeated_hash(0x22),
            mux_template: &fix.mux.hash,
            routes_commitment: &repeated_hash(0x33),
            owner_hash: &repeated_hash(0x44),
            player_id: &repeated_hash(0x55),
            open_games: 0,
            rating: 1200,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let layout = compiled.state_layout;
    blake2b_bytes(&[compiled.script[..layout.start].as_ref(), compiled.script[layout.start + layout.len..].as_ref()].concat())
}

fn entry_sigscript(compiled: &CompiledContract<'_>, function: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let sigscript = compiled.build_sig_script(function, args).expect("sigscript builds");
    pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("wrap p2sh sigscript")
}

fn tx_input(index: u32, signature_script: Vec<u8>, sig_op_count: u8) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count,
    }
}

fn covenant_output_with_value(
    compiled: &CompiledContract<'_>,
    authorizing_input: u16,
    covenant_id: Hash,
    value: u64,
) -> TransactionOutput {
    TransactionOutput {
        value,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn covenant_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    covenant_output_with_value(compiled, authorizing_input, covenant_id, 1_000)
}

fn covenant_utxo_with_value(compiled: &CompiledContract<'_>, covenant_id: Hash, value: u64) -> UtxoEntry {
    UtxoEntry::new(value, pay_to_script_hash_script(&compiled.script), 0, false, Some(covenant_id))
}

fn covenant_utxo(compiled: &CompiledContract<'_>, covenant_id: Hash) -> UtxoEntry {
    covenant_utxo_with_value(compiled, covenant_id, 1_000)
}

fn execute_input_with_covenants(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let utxo = populated.utxo(input_idx).expect("selected input utxo");
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn sign_tx_input_schnorr(tx: &Transaction, entries: &[UtxoEntry], input_idx: usize, player: &Player) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let sig_hash = calc_schnorr_signature_hash(&populated, input_idx, SIG_HASH_ALL, &reused_values);
    let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("valid sighash message");
    let sig = player.keypair.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref());
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

fn run_route(
    active: &CompiledContract<'_>,
    selector: i64,
    mv: MoveArgs,
    player: &Player,
    target: &TemplateFixture,
    out: &CompiledContract<'_>,
    covenant_id: Hash,
) {
    let placeholder_sig = vec![0u8; 65];
    let placeholder_sigscript = entry_sigscript(
        active,
        "route",
        vec![
            selector.into(),
            mv.from_x.into(),
            mv.from_y.into(),
            mv.to_x.into(),
            mv.to_y.into(),
            mv.promo_piece.into(),
            0.into(),
            Expr::bytes(placeholder_sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            hash_expr(player.player_id),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    let outputs = vec![covenant_output(out, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let mut tx = Transaction::new(1, vec![tx_input(0, placeholder_sigscript, 1)], outputs, 0, Default::default(), 0, vec![]);
    let sig = sign_tx_input_schnorr(&tx, &entries, 0, player);
    tx.inputs[0].signature_script = entry_sigscript(
        active,
        "route",
        vec![
            selector.into(),
            mv.from_x.into(),
            mv.from_y.into(),
            mv.to_x.into(),
            mv.to_y.into(),
            mv.promo_piece.into(),
            0.into(),
            Expr::bytes(sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            hash_expr(player.player_id),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "route should succeed: {:?}", result.unwrap_err());
}

fn run_worker_apply(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    mux: &TemplateFixture,
) {
    let sigscript = entry_sigscript(active, "apply", vec![Expr::bytes(mux.prefix.clone()), Expr::bytes(mux.suffix.clone())]);
    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let tx = Transaction::new(1, vec![tx_input(0, sigscript, 0)], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "{label} worker apply should succeed: {:?}", result.unwrap_err());
}

fn run_prep_apply(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    target: &TemplateFixture,
) {
    let sigscript = entry_sigscript(active, "apply", vec![Expr::bytes(target.prefix.clone()), Expr::bytes(target.suffix.clone())]);
    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let tx = Transaction::new(1, vec![tx_input(0, sigscript, 0)], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "{label} prep apply should succeed: {:?}", result.unwrap_err());
}

fn approx_expected_score(diff: i64) -> i64 {
    if diff < -800 {
        990
    } else if diff < -600 {
        970
    } else if diff < -400 {
        910
    } else if diff < -250 {
        820
    } else if diff < -150 {
        700
    } else if diff < -75 {
        600
    } else if diff < 75 {
        500
    } else if diff < 150 {
        400
    } else if diff < 250 {
        300
    } else if diff < 400 {
        180
    } else if diff < 600 {
        90
    } else if diff < 800 {
        30
    } else {
        10
    }
}

fn approx_updated_rating(self_rating: i64, opp_rating: i64, actual_score: i64) -> i64 {
    let expected = approx_expected_score(opp_rating - self_rating);
    let delta = (32 * (actual_score - expected)) / 1000;
    self_rating + delta
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

fn assert_size_within_noise(name: &str, actual: usize, expected: usize) {
    let diff = actual.abs_diff(expected);
    assert!(diff <= 10, "{name} expected {expected} (+/-10), got {actual} (diff={diff})");
}

fn size_snapshots() -> Vec<SizeSnapshot> {
    vec![
        SizeSnapshot {
            name: "league.sil",
            ctor: league_constructor_args,
            expected_script_len: 468,
            expected_instruction_count: 269,
            expected_charged_op_count: 199,
        },
        SizeSnapshot {
            name: "player.sil",
            ctor: player_constructor_args,
            expected_script_len: 3382,
            expected_instruction_count: 2482,
            expected_charged_op_count: 1618,
        },
        SizeSnapshot {
            name: "chess_mux.sil",
            ctor: mux_constructor_args,
            expected_script_len: 1644,
            expected_instruction_count: 986,
            expected_charged_op_count: 666,
        },
        SizeSnapshot {
            name: "chess_settle.sil",
            ctor: settle_constructor_args,
            expected_script_len: 2591,
            expected_instruction_count: 2007,
            expected_charged_op_count: 1307,
        },
        SizeSnapshot {
            name: "chess_pawn.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 1906,
            expected_instruction_count: 1272,
            expected_charged_op_count: 830,
        },
        SizeSnapshot {
            name: "chess_knight.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 1430,
            expected_instruction_count: 831,
            expected_charged_op_count: 552,
        },
        SizeSnapshot {
            name: "chess_vert.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 2038,
            expected_instruction_count: 1409,
            expected_charged_op_count: 969,
        },
        SizeSnapshot {
            name: "chess_horiz.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 2038,
            expected_instruction_count: 1409,
            expected_charged_op_count: 969,
        },
        SizeSnapshot {
            name: "chess_diag.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 2005,
            expected_instruction_count: 1383,
            expected_charged_op_count: 951,
        },
        SizeSnapshot {
            name: "chess_king.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 1516,
            expected_instruction_count: 898,
            expected_charged_op_count: 595,
        },
        SizeSnapshot {
            name: "chess_castle.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 1564,
            expected_instruction_count: 959,
            expected_charged_op_count: 628,
        },
        SizeSnapshot {
            name: "chess_castle_challenge.sil",
            ctor: pawn_constructor_args,
            expected_script_len: 1663,
            expected_instruction_count: 1060,
            expected_charged_op_count: 691,
        },
    ]
}

fn pawn_constructor_args() -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(sample_route_templates()),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(standard_board()),
        Expr::int(0),
        Expr::int(0),
        Expr::int(DEFAULT_MOVE_TIMEOUT),
        Expr::bytes(vec![1u8; 4]),
        Expr::int(-1),
        Expr::int(12),
        Expr::int(28),
        Expr::int(0),
        Expr::int(0),
        Expr::int(3),
    ]
}

fn mux_constructor_args() -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(sample_route_templates()),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(vec![0u8; 64]),
        Expr::int(0),
        Expr::int(0),
        Expr::int(DEFAULT_MOVE_TIMEOUT),
        Expr::bytes(vec![1u8; 4]),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(0),
        Expr::int(0),
        Expr::int(3),
    ]
}

fn settle_constructor_args() -> Vec<Expr<'static>> {
    vec![Expr::bytes(vec![0x31u8; 32]), Expr::bytes(vec![0x21u8; 32]), Expr::bytes(vec![0x22u8; 32]), Expr::int(1)]
}

fn player_constructor_args() -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(vec![0x33u8; 32]),
        Expr::bytes(sample_routes_commitment().as_bytes().to_vec()),
        Expr::bytes(vec![0x44u8; 32]),
        Expr::bytes(vec![0x55u8; 32]),
        Expr::int(0),
        Expr::int(1200),
        Expr::int(7),
        Expr::int(4),
        Expr::int(2),
        Expr::int(1),
    ]
}

fn league_constructor_args() -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(vec![0x33u8; 32]),
        Expr::bytes(sample_routes_commitment().as_bytes().to_vec()),
        Expr::int(1200),
        Expr::bytes(vec![0x44u8; 32]),
    ]
}

#[test]
fn chess_apps_compile_and_probe_sizes_within_noise() {
    let mut actual_sizes = Vec::new();

    for snapshot in size_snapshots() {
        let source = local_contract_source(snapshot.name);
        let ctor = (snapshot.ctor)();
        let compiled = compile_cached(source, &ctor);
        let (instruction_count, charged_op_count) = script_op_counts(&compiled.script);

        actual_sizes.push((snapshot.name, compiled.script.len(), instruction_count, charged_op_count));
    }

    for (name, script_len, instruction_count, charged_op_count) in &actual_sizes {
        println!("{name} {script_len} / {instruction_count} / {charged_op_count}");
    }

    for (snapshot, (_, script_len, instruction_count, charged_op_count)) in size_snapshots().into_iter().zip(actual_sizes) {
        assert_size_within_noise(&format!("{} script_len", snapshot.name), script_len, snapshot.expected_script_len);
        assert_size_within_noise(
            &format!("{} instruction_count", snapshot.name),
            instruction_count,
            snapshot.expected_instruction_count,
        );
        assert_size_within_noise(&format!("{} charged_op_count", snapshot.name), charged_op_count, snapshot.expected_charged_op_count);
    }
}

#[test]
fn league_register_player_runtime_matches_expected_output_state() {
    let owner = player_from_seed(7);
    let fix = fixture();
    let route_templates = packed_route_templates(fix);
    let routes_commitment = routes_commitment(&route_templates);

    let league_template = repeated_hash(0x11);
    let admin = repeated_hash(0x33);
    let base_rating = 1200i64;
    let covenant_id = Hash::from_bytes([0x66u8; 32]);
    let player_id_domain = b"LeaguePlayerId".to_vec();

    let player_template_ctor = vec![
        hash_expr(league_template),
        hash_expr(repeated_hash(0x44)),
        hash_expr(fix.mux.hash),
        hash_expr(routes_commitment),
        hash_expr(repeated_hash(0x55)),
        hash_expr(repeated_hash(0x77)),
        Expr::int(0),
        Expr::int(900),
        Expr::int(1),
        Expr::int(2),
        Expr::int(3),
        Expr::int(4),
    ];
    let player_template_contract = compile_cached(player_source(), &player_template_ctor);
    let layout = player_template_contract.state_layout;
    let player_prefix = player_template_contract.script[..layout.start].to_vec();
    let player_suffix = player_template_contract.script[layout.start + layout.len..].to_vec();
    let player_template = blake2b_bytes(&[player_prefix.as_slice(), player_suffix.as_slice()].concat());

    let league_ctor = vec![
        hash_expr(league_template),
        hash_expr(player_template),
        hash_expr(fix.mux.hash),
        hash_expr(routes_commitment),
        Expr::int(base_rating),
        hash_expr(admin),
    ];
    let league = compile_cached(league_source(), &league_ctor);

    let league_input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0xabu8; 32]), index: 7 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };

    let player_id = blake2b_bytes(&[player_id_domain.as_slice(), &[0xabu8; 32], &7u32.to_le_bytes()].concat());

    let registered_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &owner.owner_hash,
            player_id: &player_id,
            open_games: 0,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );

    let placeholder_sigscript = entry_sigscript(
        &league,
        "register_player",
        vec![
            Expr::bytes(vec![0u8; 65]),
            Expr::bytes(owner.pubkey_bytes.clone()),
            Expr::bytes(player_prefix.clone()),
            Expr::bytes(player_suffix.clone()),
        ],
    );
    let outputs = vec![covenant_output(&league, 0, covenant_id), covenant_output(&registered_player, 0, covenant_id)];
    let entries = vec![covenant_utxo(&league, covenant_id)];
    let mut tx = Transaction::new(1, vec![league_input], outputs, 0, Default::default(), 0, vec![]);
    tx.inputs[0].signature_script = placeholder_sigscript;

    let sig = sign_tx_input_schnorr(&tx, &entries, 0, &owner);
    tx.inputs[0].signature_script = entry_sigscript(
        &league,
        "register_player",
        vec![Expr::bytes(sig), Expr::bytes(owner.pubkey_bytes), Expr::bytes(player_prefix), Expr::bytes(player_suffix)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "league register_player runtime failed: {}", result.unwrap_err());
}

#[test]
fn player_start_game_runtime_matches_expected_output_states() {
    let fix = fixture();
    let route_templates = packed_route_templates(fix);
    let routes_commitment = routes_commitment(&route_templates);
    let white = player_from_seed(0x31);
    let black = player_from_seed(0x32);

    let league_template = repeated_hash(0x19);
    let base_rating = 1200i64;
    let covenant_id = Hash::from_bytes([0x71u8; 32]);

    let player_contract = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &repeated_hash(0x44),
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &repeated_hash(0x55),
            player_id: &repeated_hash(0x56),
            open_games: 0,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let player_layout = player_contract.state_layout;
    let player_template = blake2b_bytes(
        &[
            player_contract.script[..player_layout.start].as_ref(),
            player_contract.script[player_layout.start + player_layout.len..].as_ref(),
        ]
        .concat(),
    );
    let player_prefix_len = player_layout.start as i64;
    let player_suffix_len = (player_contract.script.len() - (player_layout.start + player_layout.len)) as i64;

    let white_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &white.owner_hash,
            player_id: &white.player_id,
            open_games: 0,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let black_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &black.owner_hash,
            player_id: &black.player_id,
            open_games: 0,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let next_white_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &white.owner_hash,
            player_id: &white.player_id,
            open_games: 1,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let next_black_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &black.owner_hash,
            player_id: &black.player_id,
            open_games: 1,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let opening_mux = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &standard_board(),
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    let white_placeholder = entry_sigscript(
        &white_player,
        "start_game",
        vec![
            Expr::bytes(vec![0u8; 65]),
            Expr::bytes(white.pubkey_bytes.clone()),
            Expr::int(0),
            Expr::int(player_prefix_len),
            Expr::int(player_suffix_len),
            Expr::bytes(route_templates.clone()),
            Expr::int(DEFAULT_MOVE_TIMEOUT),
            Expr::bytes(fix.mux.prefix.clone()),
            Expr::bytes(fix.mux.suffix.clone()),
        ],
    );
    let black_placeholder = entry_sigscript(
        &black_player,
        "delegate_start_game",
        vec![
            Expr::bytes(vec![0u8; 65]),
            Expr::bytes(black.pubkey_bytes.clone()),
            Expr::int(DEFAULT_MOVE_TIMEOUT),
            Expr::int(player_prefix_len),
            Expr::int(player_suffix_len),
        ],
    );

    let outputs = vec![
        covenant_output(&next_white_player, 0, covenant_id),
        covenant_output(&next_black_player, 0, covenant_id),
        covenant_output(&opening_mux, 0, covenant_id),
    ];
    let entries = vec![covenant_utxo(&white_player, covenant_id), covenant_utxo(&black_player, covenant_id)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input(0, white_placeholder, 1), tx_input(1, black_placeholder, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    let white_sig = sign_tx_input_schnorr(&tx, &entries, 0, &white);
    let black_sig = sign_tx_input_schnorr(&tx, &entries, 1, &black);

    tx.inputs[0].signature_script = entry_sigscript(
        &white_player,
        "start_game",
        vec![
            Expr::bytes(white_sig),
            Expr::bytes(white.pubkey_bytes),
            Expr::int(0),
            Expr::int(player_prefix_len),
            Expr::int(player_suffix_len),
            Expr::bytes(route_templates),
            Expr::int(DEFAULT_MOVE_TIMEOUT),
            Expr::bytes(fix.mux.prefix.clone()),
            Expr::bytes(fix.mux.suffix.clone()),
        ],
    );
    tx.inputs[1].signature_script = entry_sigscript(
        &black_player,
        "delegate_start_game",
        vec![
            Expr::bytes(black_sig),
            Expr::bytes(black.pubkey_bytes),
            Expr::int(DEFAULT_MOVE_TIMEOUT),
            Expr::int(player_prefix_len),
            Expr::int(player_suffix_len),
        ],
    );

    let leader_result = execute_input_with_covenants(tx.clone(), entries.clone(), 0);
    assert!(leader_result.is_ok(), "player start_game leader runtime failed: {}", leader_result.unwrap_err());

    let delegate_result = execute_input_with_covenants(tx, entries, 1);
    assert!(delegate_result.is_ok(), "player delegate_start_game runtime failed: {}", delegate_result.unwrap_err());
}

#[test]
fn mux_route_to_pawn_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let board0 = standard_board();
    let covenant_id = Hash::from_bytes([0x81u8; 32]);

    let mux0 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    let pawn0 = compile_state(
        fix.pawn.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 1),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_route(&mux0, 0, mv(4, 1, 4, 3), &white, &fix.pawn, &pawn0, covenant_id);
}

#[test]
fn pawn_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let board0 = standard_board();
    let covenant_id = Hash::from_bytes([0x82u8; 32]);

    let pawn0 = compile_state(
        fix.pawn.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 1),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3);
    let mux1 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_worker_apply("pawn", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn knight_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board1 = standard_board();
    move_piece(&mut board1, 4, 1, 4, 3);
    let covenant_id = Hash::from_bytes([0x83u8; 32]);

    let knight1 = compile_state(
        fix.knight.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: square_idx(6, 7),
            pending_dst_idx: square_idx(5, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board2 = board1.clone();
    move_piece(&mut board2, 6, 7, 5, 5);
    let mux2 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board2,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_worker_apply("knight", &knight1, &mux2, covenant_id, &fix.mux);
}

#[test]
fn vert_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board3 = vec![0u8; 64];
    board3[0] = 0x04;
    let covenant_id = Hash::from_bytes([0x84u8; 32]);

    let vert = compile_state(
        fix.vert.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board3,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(0, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board4 = board3.clone();
    move_piece(&mut board4, 0, 0, 0, 3);
    let mux4 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board4,
            turn: 1,
            status: 0,
            castle_rights: [1, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_worker_apply("vert", &vert, &mux4, covenant_id, &fix.mux);
}

#[test]
fn horiz_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board7 = vec![0u8; 64];
    board7[31] = 0x05;
    let covenant_id = Hash::from_bytes([0x85u8; 32]);

    let horiz_left = compile_state(
        fix.horiz.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board7,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(7, 3),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board8 = board7.clone();
    move_piece(&mut board8, 7, 3, 4, 3);
    let mux8 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board8,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_worker_apply("horiz", &horiz_left, &mux8, covenant_id, &fix.mux);
}

#[test]
fn diag_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board11 = vec![0u8; 64];
    board11[0] = 0x03;
    let covenant_id = Hash::from_bytes([0x86u8; 32]);

    let diag_up_right = compile_state(
        fix.diag.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board11,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(3, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board12 = board11.clone();
    move_piece(&mut board12, 0, 0, 3, 3);
    let mux12 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board12,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_worker_apply("diag", &diag_up_right, &mux12, covenant_id, &fix.mux);
}

#[test]
fn king_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board19 = vec![0u8; 64];
    board19[4] = 0x06;
    let covenant_id = Hash::from_bytes([0x87u8; 32]);

    let king = compile_state(
        fix.king.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board19,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(4, 1),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board20 = board19.clone();
    move_piece(&mut board20, 4, 0, 4, 1);
    let mux20 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board20,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );

    run_worker_apply("king", &king, &mux20, covenant_id, &fix.mux);
}

#[test]
fn castle_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board21 = vec![0u8; 64];
    board21[4] = 0x06;
    board21[7] = 0x04;
    let covenant_id = Hash::from_bytes([0x88u8; 32]);

    let castle = compile_state(
        fix.castle.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board21,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(6, 0),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
        },
    );
    let mut board22 = board21.clone();
    board22[4] = 0x00;
    board22[5] = 0x04;
    board22[6] = 0x06;
    board22[7] = 0x00;
    let mux22 = compile_state(
        fix.mux.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board22,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 3,
        },
    );

    run_worker_apply("castle", &castle, &mux22, covenant_id, &fix.mux);
}

#[test]
fn castle_challenge_apply_runtime_matches_expected_output_state() {
    let fix = fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);
    let mut board0 = vec![0u8; 64];
    board0[4] = 0x06;
    board0[7] = 0x04;
    board0[11] = 0x09;
    let covenant_id = Hash::from_bytes([0x89u8; 32]);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 1),
            pending_dst_idx: square_idx(4, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 3,
        },
    );

    let pawn0 = compile_state(
        fix.pawn.source,
        fix,
        &white.player_ref,
        &black.player_ref,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 1),
            pending_dst_idx: square_idx(4, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 3,
        },
    );

    run_prep_apply("castle_challenge", &prep0, &pawn0, covenant_id, &fix.pawn);
}

#[test]
fn settle_runtime_matches_expected_output_states() {
    let fix = fixture();
    let route_templates = packed_route_templates(fix);
    let routes_commitment = routes_commitment(&route_templates);
    let base_rating = 1200;
    let league_template = repeated_hash(0x33);
    let covenant_id = Hash::from_bytes([0x72u8; 32]);

    let white = player_from_seed(0x21);
    let black = player_from_seed(0x22);

    let player_contract = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &repeated_hash(0x44),
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &repeated_hash(0x55),
            player_id: &repeated_hash(0x56),
            open_games: 0,
            rating: base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        },
    );
    let player_layout = player_contract.state_layout;
    let player_template = blake2b_bytes(
        &[
            player_contract.script[..player_layout.start].as_ref(),
            player_contract.script[player_layout.start + player_layout.len..].as_ref(),
        ]
        .concat(),
    );
    let white_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &white.owner_hash,
            player_id: &white.player_id,
            open_games: 1,
            rating: base_rating,
            games: 10,
            wins: 6,
            draws: 2,
            losses: 2,
        },
    );
    let black_player = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &black.owner_hash,
            player_id: &black.player_id,
            open_games: 1,
            rating: base_rating,
            games: 10,
            wins: 2,
            draws: 2,
            losses: 6,
        },
    );

    let white_rating = approx_updated_rating(base_rating, base_rating, 1000);
    let black_rating = approx_updated_rating(base_rating, base_rating, 0);

    let routed_settle = compile_settle_state(fix.settle.source, &player_template, &white.player_ref, &black.player_ref, 1);
    let settled_white = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &white.owner_hash,
            player_id: &white.player_id,
            open_games: 0,
            rating: white_rating,
            games: 11,
            wins: 7,
            draws: 2,
            losses: 2,
        },
    );
    let settled_black = compile_player_state(
        player_source(),
        PlayerStateArgs {
            league_template: &league_template,
            player_template: &player_template,
            mux_template: &fix.mux.hash,
            routes_commitment: &routes_commitment,
            owner_hash: &black.owner_hash,
            player_id: &black.player_id,
            open_games: 0,
            rating: black_rating,
            games: 11,
            wins: 2,
            draws: 2,
            losses: 7,
        },
    );

    let settle_sigscript = entry_sigscript(
        &routed_settle,
        "settle",
        vec![
            Expr::bytes(player_contract.script[..player_layout.start].to_vec()),
            Expr::bytes(player_contract.script[player_layout.start + player_layout.len..].to_vec()),
        ],
    );
    let settle_prefix_len = fix.settle.prefix.len() as i64;
    let settle_suffix_len = fix.settle.suffix.len() as i64;
    let white_delegate_sigscript = entry_sigscript(
        &white_player,
        "delegate_settle",
        vec![
            Expr::int(settle_prefix_len),
            Expr::int(settle_suffix_len),
            hash_expr(fix.settle.hash),
            Expr::bytes(route_templates.clone()),
        ],
    );
    let black_delegate_sigscript = entry_sigscript(
        &black_player,
        "delegate_settle",
        vec![Expr::int(settle_prefix_len), Expr::int(settle_suffix_len), hash_expr(fix.settle.hash), Expr::bytes(route_templates)],
    );

    let outputs = vec![
        covenant_output_with_value(&settled_white, 0, covenant_id, 2_000),
        covenant_output_with_value(&settled_black, 0, covenant_id, 1_000),
    ];
    let entries = vec![
        covenant_utxo(&routed_settle, covenant_id),
        covenant_utxo(&white_player, covenant_id),
        covenant_utxo(&black_player, covenant_id),
    ];
    let tx = Transaction::new(
        1,
        vec![tx_input(0, settle_sigscript, 0), tx_input(1, white_delegate_sigscript, 0), tx_input(2, black_delegate_sigscript, 0)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );

    let leader_result = execute_input_with_covenants(tx.clone(), entries.clone(), 0);
    assert!(leader_result.is_ok(), "settle leader runtime failed: {}", leader_result.unwrap_err());

    let white_delegate_result = execute_input_with_covenants(tx.clone(), entries.clone(), 1);
    assert!(white_delegate_result.is_ok(), "white delegate_settle runtime failed: {}", white_delegate_result.unwrap_err());

    let black_delegate_result = execute_input_with_covenants(tx, entries, 2);
    assert!(black_delegate_result.is_ok(), "black delegate_settle runtime failed: {}", black_delegate_result.unwrap_err());
}
