//! Foreign input state must be framed the way the reader assumes.
//!
//! `readInputState` and `readInputStateWithTemplate` decode a foreign input's
//! state fields at offsets fixed at compile time. Those offsets are only
//! meaningful if every field in the foreign state region is encoded with the
//! canonical push header the state encoder emits. Kaspa's script engine also
//! accepts non-minimal push encodings, so without a guard a foreign input can
//! widen one field's header and narrow another's, keep the region's total
//! length identical, and slide every later field read onto bytes of its own
//! choosing.
//!
//! These tests execute on the real script engine.

mod common;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script, pay_to_script_hash_signature_script};
use silverscript_abi::ArtifactValue;
use silverscript_lang::compiler::CompileOptions;

use common::{bytecode, compile_contract, encode_single_entry_sig_script, state_layout};

/// A two-field state whose canonical encoding is `01 <flag> 20 <32 key bytes>`.
///
/// Reading `key` therefore assumes `flag`'s header occupies exactly one byte.
const TARGET_SOURCE: &str = r#"
    contract Target(byte initFlag, byte[32] initKey) {
        byte flag = initFlag;
        byte[32] key = initKey;

        entry noop() {
            require(true);
        }
    }
"#;

const HONEST_FLAG: u8 = 0x07;
const HONEST_KEY_BYTE: u8 = 0xaa;

/// The canonical state region: `01 07` followed by `20` and 32 key bytes.
fn honest_state_region() -> Vec<u8> {
    let mut region = vec![0x01, HONEST_FLAG, 0x20];
    region.extend_from_slice(&[HONEST_KEY_BYTE; 32]);
    region
}

/// The same 35 bytes, reframed: `flag`'s header widened to `OpPushData1 01`
/// and `key`'s push narrowed to 31 bytes to pay for it.
///
/// ```text
/// canonical: 01 07          20 aa*32
/// reframed:  4c 01 07    1f aa*31
/// ```
///
/// A reader using canonical offsets takes `flag` from index 1 and `key` from
/// indices 3..35, so it sees `flag = 0x01` and `key = 1f ‖ aa*31` — neither of
/// which is the state this script actually carries.
fn reframed_state_region() -> Vec<u8> {
    let mut region = vec![0x4c, 0x01, HONEST_FLAG, 0x1f];
    region.extend_from_slice(&[HONEST_KEY_BYTE; 31]);
    region
}

/// The reframe a length pin already refuses: `flag`'s header widened with
/// nothing narrowed to pay for it, so the region grows by one byte.
fn lengthened_state_region() -> Vec<u8> {
    let mut region = vec![0x4c, 0x01, HONEST_FLAG, 0x20];
    region.extend_from_slice(&[HONEST_KEY_BYTE; 32]);
    region
}

/// A region one byte longer, laid out so that the SHIFTED reads a longer script
/// produces still land on canonical-looking push headers.
///
/// The plain reader places its window at `sigscript_len(idx) - this.bytecodeSize`,
/// the READER's own constant. One extra byte in the foreign script therefore
/// moves every read one byte later, and the framing guard checks its headers at
/// the shifted offsets — where the bytes belong to the forger. Paying one byte
/// of padding buys both header positions:
///
/// ```text
/// byte:      0     1     2      3     4..36
/// value:     00    01    flag   20    key
///            pad   ^hdr  ^flag  ^hdr  ^key      (^ = where the shifted read looks)
/// ```
///
/// So the guard sees `OpData1` and `OpData32` exactly where it requires them,
/// and the reader takes `flag` and `key` from bytes the forger chose.
const SLID_FLAG: u8 = 0x5a;
const SLID_KEY_BYTE: u8 = 0xc3;

fn window_sliding_region() -> Vec<u8> {
    let mut region = vec![0x00, 0x01, SLID_FLAG, 0x20];
    region.extend_from_slice(&[SLID_KEY_BYTE; 32]);
    region
}

/// What a reader using canonical offsets takes out of `region`: the byte at
/// index 1, and the 32 bytes at indices 3..35.
fn read_at_canonical_offsets(region: &[u8]) -> (u8, [u8; 32]) {
    let mut key = [0u8; 32];
    key.copy_from_slice(&region[3..35]);
    (region[1], key)
}

fn byte_array_value(bytes: &[u8]) -> ArtifactValue {
    ArtifactValue::Bytes(bytes.to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn push_bytecode(bytecode: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
        .add_data_with_push_opcode(bytecode)
        .expect("push bytecode")
        .drain()
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

/// Splices `region` into the target's compiled bytecode in place of its state
/// region, leaving the prefix and suffix — and therefore the template hash —
/// untouched.
fn target_bytecode_with_state_region(region: &[u8]) -> Vec<u8> {
    let target = compile_contract(
        TARGET_SOURCE,
        &[ArtifactValue::Byte(HONEST_FLAG), byte_array_value(&[HONEST_KEY_BYTE; 32])],
        CompileOptions::default(),
    )
    .expect("compile target");
    let layout = state_layout(&target);
    let compiled = bytecode(&target);

    let mut forged = compiled[..layout.start].to_vec();
    forged.extend_from_slice(region);
    forged.extend_from_slice(&compiled[layout.start + layout.len..]);
    forged
}

fn target_template_parts() -> (Vec<u8>, Vec<u8>) {
    let target = compile_contract(
        TARGET_SOURCE,
        &[ArtifactValue::Byte(HONEST_FLAG), byte_array_value(&[HONEST_KEY_BYTE; 32])],
        CompileOptions::default(),
    )
    .expect("compile target");
    let layout = state_layout(&target);
    let compiled = bytecode(&target);
    (compiled[..layout.start].to_vec(), compiled[layout.start + layout.len..].to_vec())
}

/// Runs a reader over a foreign input at index 1 whose committed script carries
/// `region` as its state, asserting the reader observes `expected`.
fn run_templated_reader(region: &[u8], expected: (u8, [u8; 32])) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let (prefix, suffix) = target_template_parts();
    let (prefix_hex, suffix_hex) = (hex(&prefix), hex(&suffix));
    let reader_source = format!(
        r#"
        contract Reader() {{
            struct TargetState {{
                byte flag;
                byte[32] key;
            }}

            entry main(byte expectedFlag, byte[32] expectedKey) {{
                byte[] templatePrefix = byte[](0x{prefix_hex});
                byte[] templateSuffix = byte[](0x{suffix_hex});

                TargetState remote = readInputStateWithTemplate(
                    1,
                    {},
                    {},
                    templateHash(templatePrefix, templateSuffix)
                );
                require(remote.flag == expectedFlag);
                require(remote.key == expectedKey);
            }}
        }}
    "#,
        prefix.len(),
        suffix.len(),
    );

    let reader = compile_contract(&reader_source, &[], CompileOptions::default()).expect("compile reader");
    let (expected_flag, expected_key) = expected;
    let args = [ArtifactValue::Byte(expected_flag), byte_array_value(&expected_key)];
    let reader_sigscript = encode_single_entry_sig_script(&reader, &args).expect("reader sigscript");
    let reader_sigscript = pay_to_script_hash_signature_script(bytecode(&reader).clone(), reader_sigscript).expect("reader p2sh");

    let forged = target_bytecode_with_state_region(region);
    let tx = Transaction::new(
        1,
        vec![test_input(0, reader_sigscript), test_input(1, push_bytecode(&forged))],
        vec![TransactionOutput { value: 1_000, script_public_key: pay_to_script_hash_script(&bytecode(&reader)), covenant: None }],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![
        UtxoEntry::new(1_000, pay_to_script_hash_script(&bytecode(&reader)), 0, false, None),
        UtxoEntry::new(1_000, pay_to_script_hash_script(&forged), 0, false, None),
    ];
    execute_input(tx, entries, 0)
}

/// The same shape for the plain `readInputState`, which decodes a foreign input
/// assumed to share the reader's own template.
fn run_plain_reader(region: &[u8], expected: (u8, [u8; 32])) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reader_source = r#"
        contract Peer(byte initFlag, byte[32] initKey) {
            byte flag = initFlag;
            byte[32] key = initKey;

            entry main(byte expectedFlag, byte[32] expectedKey) {
                State remote = readInputState(1);
                require(remote.flag == expectedFlag);
                require(remote.key == expectedKey);
            }
        }
    "#;
    let reader = compile_contract(
        reader_source,
        &[ArtifactValue::Byte(HONEST_FLAG), byte_array_value(&[HONEST_KEY_BYTE; 32])],
        CompileOptions::default(),
    )
    .expect("compile peer reader");

    let (expected_flag, expected_key) = expected;
    let args = [ArtifactValue::Byte(expected_flag), byte_array_value(&expected_key)];
    let reader_sigscript = encode_single_entry_sig_script(&reader, &args).expect("peer sigscript");
    let reader_sigscript = pay_to_script_hash_signature_script(bytecode(&reader).clone(), reader_sigscript).expect("peer p2sh");

    // The foreign input carries the reader's own template with `region` spliced
    // in as its state.
    let layout = state_layout(&reader);
    let compiled = bytecode(&reader);
    let mut forged = compiled[..layout.start].to_vec();
    forged.extend_from_slice(region);
    forged.extend_from_slice(&compiled[layout.start + layout.len..]);

    let tx = Transaction::new(
        1,
        vec![test_input(0, reader_sigscript), test_input(1, push_bytecode(&forged))],
        vec![TransactionOutput { value: 1_000, script_public_key: pay_to_script_hash_script(&compiled), covenant: None }],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![
        UtxoEntry::new(1_000, pay_to_script_hash_script(&compiled), 0, false, None),
        UtxoEntry::new(1_000, pay_to_script_hash_script(&forged), 0, false, None),
    ];
    execute_input(tx, entries, 0)
}

// ---------------------------------------------------------------------------
// readInputStateWithTemplate
// ---------------------------------------------------------------------------

/// Positive control. Without it a later rejection could be any malformation
/// rather than the framing guard firing.
#[test]
fn templated_read_accepts_canonical_framing() {
    let region = honest_state_region();
    let result = run_templated_reader(&region, (HONEST_FLAG, [HONEST_KEY_BYTE; 32]));
    assert!(result.is_ok(), "canonical framing must still be readable: {}", result.unwrap_err());
}

/// The defect: the region's total length, its prefix and its suffix are all
/// unchanged, so the length pin, the template hash and the P2SH commitment all
/// still pass. Only the framing moved.
#[test]
fn templated_read_rejects_length_preserving_reframe() {
    let honest = honest_state_region();
    let reframed = reframed_state_region();
    assert_eq!(honest.len(), reframed.len(), "the reframe must preserve the region length");

    let observed = read_at_canonical_offsets(&reframed);
    assert_ne!(observed, (HONEST_FLAG, [HONEST_KEY_BYTE; 32]), "the reframe must move what a constant-offset read sees");

    let result = run_templated_reader(&reframed, observed);
    assert!(result.is_err(), "a length-preserving reframe must not be readable at canonical offsets");
}

/// The length pin already refuses this one. Asserting it separately keeps the
/// framing guard from being credited for a check that predates it.
#[test]
fn templated_read_rejects_length_changing_reframe() {
    let lengthened = lengthened_state_region();
    assert_ne!(lengthened.len(), honest_state_region().len(), "this case must change the region length");

    let result = run_templated_reader(&lengthened, read_at_canonical_offsets(&lengthened));
    assert!(result.is_err(), "a length-changing reframe must be refused");
}

// ---------------------------------------------------------------------------
// readInputState
// ---------------------------------------------------------------------------

#[test]
fn plain_read_accepts_canonical_framing() {
    let region = honest_state_region();
    let result = run_plain_reader(&region, (HONEST_FLAG, [HONEST_KEY_BYTE; 32]));
    assert!(result.is_ok(), "canonical framing must still be readable: {}", result.unwrap_err());
}

/// The plain builtin authenticates the foreign input neither by template hash
/// nor by P2SH commitment. The guard makes its constant offsets meaningful; it
/// does not tie the region to the right script, which stays the caller's duty.
#[test]
fn plain_read_rejects_length_preserving_reframe() {
    let reframed = reframed_state_region();
    let observed = read_at_canonical_offsets(&reframed);

    let result = run_plain_reader(&reframed, observed);
    assert!(result.is_err(), "a length-preserving reframe must not be readable at canonical offsets");
}

// ---------------------------------------------------------------------------
// readInputState in expression position
// ---------------------------------------------------------------------------

/// `readInputState` is also legal as a struct-valued expression, which is the
/// form the covenant declaration lowering generates. That path builds the same
/// constant-offset reads and needs the same guard.
/// A LONGER foreign script slides the plain reader's window, and the framing
/// guard follows it onto bytes the forger chose.
///
/// The guard pins each field's push header at the offset the read uses. It does
/// not pin where those offsets are MEASURED FROM: `readInputState` anchors its
/// window on `this.bytecodeSize`, which describes the reader, not the script it
/// is reading. A foreign script one byte longer shifts every read by one, and
/// the guard then validates framing against the shifted bytes — which the forger
/// supplies. One byte of padding is the whole cost.
///
/// The templated decoder is not exposed to this. It requires the window's P2SH to
/// equal the foreign input's own scriptPubKey, and a scriptPubKey commits to the
/// WHOLE redeem script — so a longer script cannot present a shorter window and
/// still match. The plain decoder makes no such check, and that is the difference
/// this test exists to close.
#[test]
fn plain_read_rejects_a_longer_foreign_script() {
    let region = window_sliding_region();
    assert_eq!(region.len(), honest_state_region().len() + 1, "one byte longer — which is what slides the window");

    // The shifted read is the canonical read one byte later, so applying the
    // canonical offsets to `region[1..]` is exactly what the reader will see.
    assert_eq!(
        read_at_canonical_offsets(&region[1..]),
        (SLID_FLAG, [SLID_KEY_BYTE; 32]),
        "the shifted window really does land on the forger's values"
    );

    let result = run_plain_reader(&region, (SLID_FLAG, [SLID_KEY_BYTE; 32]));
    assert!(
        result.is_err(),
        "a foreign script longer than the reader's own template must not be decoded, however its region is framed: {result:?}"
    );
}

fn run_expression_position_reader(region: &[u8], observed: (u8, [u8; 32])) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reader_source = r#"
        contract Peer(byte initFlag, byte[32] initKey) {
            byte flag = initFlag;
            byte[32] key = initKey;

            entry main() {
                validateOutputState(0, readInputState(1));
            }
        }
    "#;
    let reader = compile_contract(
        reader_source,
        &[ArtifactValue::Byte(HONEST_FLAG), byte_array_value(&[HONEST_KEY_BYTE; 32])],
        CompileOptions::default(),
    )
    .expect("compile expression-position reader");

    let reader_sigscript = encode_single_entry_sig_script(&reader, &[]).expect("reader sigscript");
    let reader_sigscript = pay_to_script_hash_signature_script(bytecode(&reader).clone(), reader_sigscript).expect("reader p2sh");

    let layout = state_layout(&reader);
    let compiled = bytecode(&reader);
    let splice = |region: &[u8]| {
        let mut spliced = compiled[..layout.start].to_vec();
        spliced.extend_from_slice(region);
        spliced.extend_from_slice(&compiled[layout.start + layout.len..]);
        spliced
    };

    // The output the reader is required to produce, built from what a
    // constant-offset read takes out of `region`.
    let (observed_flag, observed_key) = observed;
    let mut observed_region = vec![0x01, observed_flag, 0x20];
    observed_region.extend_from_slice(&observed_key);

    let forged = splice(region);
    let tx = Transaction::new(
        1,
        vec![test_input(0, reader_sigscript), test_input(1, push_bytecode(&forged))],
        vec![TransactionOutput {
            value: 1_000,
            script_public_key: pay_to_script_hash_script(&splice(&observed_region)),
            covenant: None,
        }],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![
        UtxoEntry::new(1_000, pay_to_script_hash_script(&compiled), 0, false, None),
        UtxoEntry::new(1_000, pay_to_script_hash_script(&forged), 0, false, None),
    ];
    execute_input(tx, entries, 0)
}

#[test]
fn expression_position_read_accepts_canonical_framing() {
    let region = honest_state_region();
    let result = run_expression_position_reader(&region, (HONEST_FLAG, [HONEST_KEY_BYTE; 32]));
    assert!(result.is_ok(), "canonical framing must still be readable: {}", result.unwrap_err());
}

/// The window binding reaches expression position too.
///
/// `validateOutputState(0, readInputState(1))` lowers through the same statement path as a
/// destructuring read, so it inherits the scriptPubKey binding rather than needing its own. Left
/// untested that would be an assumption about the lowering; here it is a fact about the emitted
/// script.
#[test]
fn expression_position_read_rejects_a_longer_foreign_script() {
    let result = run_expression_position_reader(&window_sliding_region(), (SLID_FLAG, [SLID_KEY_BYTE; 32]));
    assert!(result.is_err(), "expression position must refuse a longer foreign script as well: {result:?}");
}

#[test]
fn expression_position_read_rejects_length_preserving_reframe() {
    let reframed = reframed_state_region();
    let observed = read_at_canonical_offsets(&reframed);

    let result = run_expression_position_reader(&reframed, observed);
    assert!(result.is_err(), "a length-preserving reframe must not be readable at canonical offsets");
}

// ---------------------------------------------------------------------------
// Multi-byte push headers
// ---------------------------------------------------------------------------
//
// A payload of 76 bytes or more is pushed with `OpPushData1 <len>`, so its
// canonical header is TWO bytes rather than one, and a payload of 256 or more
// takes three. Pinning only a header's first byte would leave the length byte
// free, and a header can also be re-encoded at a different width entirely
// (`4c 50` and `4d 4f 00` both occupy an 82-byte chunk). The cases below place
// one 80-byte field first, in the middle and last, so each forgery violates
// exactly ONE field's header pin.

const WIDE_A: u8 = 0x11;
const WIDE_C: u8 = 0x22;
const WIDE_BLOB_BYTE: u8 = 0xbb;
const WIDE_BLOB_LEN: usize = 80;

/// `byte a; byte[80] blob; byte c` — the wide field in the middle.
const WIDE_MIDDLE_SOURCE: &str = r#"
    contract WideMiddle(byte initA, byte[80] initBlob, byte initC) {
        byte a = initA;
        byte[80] blob = initBlob;
        byte c = initC;

        entry main(byte[80] expectedBlob) {
            State remote = readInputState(1);
            require(remote.blob == expectedBlob);
        }
    }
"#;

/// `byte[80] blob; byte a; byte c` — the wide field first.
const WIDE_FIRST_SOURCE: &str = r#"
    contract WideFirst(byte[80] initBlob, byte initA, byte initC) {
        byte[80] blob = initBlob;
        byte a = initA;
        byte c = initC;

        entry main(byte[80] expectedBlob) {
            State remote = readInputState(1);
            require(remote.blob == expectedBlob);
        }
    }
"#;

/// `byte a; byte c; byte[80] blob` — the wide field last.
const WIDE_LAST_SOURCE: &str = r#"
    contract WideLast(byte initA, byte initC, byte[80] initBlob) {
        byte a = initA;
        byte c = initC;
        byte[80] blob = initBlob;

        entry main(byte[80] expectedBlob) {
            State remote = readInputState(1);
            require(remote.blob == expectedBlob);
        }
    }
"#;

fn wide_ctor(source: &str) -> Vec<ArtifactValue> {
    let a = ArtifactValue::Byte(WIDE_A);
    let c = ArtifactValue::Byte(WIDE_C);
    let blob = byte_array_value(&[WIDE_BLOB_BYTE; WIDE_BLOB_LEN]);
    match source {
        s if s == WIDE_FIRST_SOURCE => vec![blob, a, c],
        s if s == WIDE_LAST_SOURCE => vec![a, c, blob],
        _ => vec![a, blob, c],
    }
}

/// Runs the same-template reader over a foreign input at index 1 carrying
/// `region`, asserting it decodes `blob` as `expected_blob`.
fn run_wide_reader(source: &str, region: &[u8], expected_blob: &[u8]) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reader = compile_contract(source, &wide_ctor(source), CompileOptions::default()).expect("compile wide reader");

    let args = [byte_array_value(expected_blob)];
    let reader_sigscript = encode_single_entry_sig_script(&reader, &args).expect("wide sigscript");
    let reader_sigscript = pay_to_script_hash_signature_script(bytecode(&reader).clone(), reader_sigscript).expect("wide p2sh");

    let layout = state_layout(&reader);
    let compiled = bytecode(&reader);
    assert_eq!(layout.len, region.len(), "the forged region must keep the state region's length");
    let mut forged = compiled[..layout.start].to_vec();
    forged.extend_from_slice(region);
    forged.extend_from_slice(&compiled[layout.start + layout.len..]);

    let tx = Transaction::new(
        1,
        vec![test_input(0, reader_sigscript), test_input(1, push_bytecode(&forged))],
        vec![TransactionOutput { value: 1_000, script_public_key: pay_to_script_hash_script(&compiled), covenant: None }],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![
        UtxoEntry::new(1_000, pay_to_script_hash_script(&compiled), 0, false, None),
        UtxoEntry::new(1_000, pay_to_script_hash_script(&forged), 0, false, None),
    ];
    execute_input(tx, entries, 0)
}

/// `OpPushData1 80` followed by the payload — the canonical wide chunk.
fn wide_chunk_canonical() -> Vec<u8> {
    let mut chunk = vec![0x4c, WIDE_BLOB_LEN as u8];
    chunk.extend_from_slice(&[WIDE_BLOB_BYTE; WIDE_BLOB_LEN]);
    chunk
}

/// `OpPushData2 79 0` followed by 79 payload bytes. Same 82-byte chunk, so
/// every other field keeps its offset, but this field's header is re-encoded
/// at a different width — and a reader at canonical offsets takes the trailing
/// length byte as the payload's first byte.
fn wide_chunk_rewidened() -> Vec<u8> {
    let mut chunk = vec![0x4d, (WIDE_BLOB_LEN - 1) as u8, 0x00];
    chunk.extend_from_slice(&[WIDE_BLOB_BYTE; WIDE_BLOB_LEN - 1]);
    chunk
}

/// What a reader takes for `blob` out of [`wide_chunk_rewidened`]: it skips the
/// two bytes it believes are the header, so it reads the third header byte plus
/// all but one payload byte.
fn wide_rewidened_observed_blob() -> Vec<u8> {
    let mut observed = vec![0x00];
    observed.extend_from_slice(&[WIDE_BLOB_BYTE; WIDE_BLOB_LEN - 1]);
    observed
}

#[test]
fn wide_header_read_accepts_canonical_framing() {
    let mut region = vec![0x01, WIDE_A];
    region.extend_from_slice(&wide_chunk_canonical());
    region.extend_from_slice(&[0x01, WIDE_C]);

    let result = run_wide_reader(WIDE_MIDDLE_SOURCE, &region, &[WIDE_BLOB_BYTE; WIDE_BLOB_LEN]);
    assert!(result.is_ok(), "canonical framing must still be readable: {}", result.unwrap_err());
}

/// The case a first-byte-only header check would miss: `4c 50` becomes `4c 4f`,
/// so only the header's LENGTH byte moves, and the byte it gives up is paid for
/// by widening the following field's header.
#[test]
fn wide_header_read_rejects_length_byte_reframe() {
    let mut region = vec![0x01, WIDE_A, 0x4c, (WIDE_BLOB_LEN - 1) as u8];
    region.extend_from_slice(&[WIDE_BLOB_BYTE; WIDE_BLOB_LEN - 1]);
    region.extend_from_slice(&[0x4c, 0x01, WIDE_C]);

    let mut observed = vec![WIDE_BLOB_BYTE; WIDE_BLOB_LEN - 1];
    observed.push(0x4c);

    let result = run_wide_reader(WIDE_MIDDLE_SOURCE, &region, &observed);
    assert!(result.is_err(), "a header whose length byte alone was changed must be refused");
}

/// Violates only the FIRST field's header pin, so it survives a guard that
/// skips that field.
#[test]
fn wide_header_read_rejects_reframe_of_the_first_field() {
    let mut region = wide_chunk_rewidened();
    region.extend_from_slice(&[0x01, WIDE_A, 0x01, WIDE_C]);

    let result = run_wide_reader(WIDE_FIRST_SOURCE, &region, &wide_rewidened_observed_blob());
    assert!(result.is_err(), "a reframe of the first field must be refused");
}

/// Violates only the LAST field's header pin, so it survives a guard that
/// stops short of the final field.
#[test]
fn wide_header_read_rejects_reframe_of_the_last_field() {
    let mut region = vec![0x01, WIDE_A, 0x01, WIDE_C];
    region.extend_from_slice(&wide_chunk_rewidened());

    let result = run_wide_reader(WIDE_LAST_SOURCE, &region, &wide_rewidened_observed_blob());
    assert!(result.is_err(), "a reframe of the last field must be refused");
}
