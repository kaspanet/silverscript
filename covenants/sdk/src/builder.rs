//! Covenant builder for state-aware covenants.
//!
//! This module exposes a builder that assembles redeem scripts capable of:
//!
//! - Pulling action data from the scriptSig and feeding it into a transition closure.
//! - Placing the previous state directly on the stack for the
//!   transition to consume.
//! - Reconstructing the redeem script with transition outputs and re-hashing it
//!   for every requested output (absolute or authorized).
//!
//! # Automatic Placeholder Resolution
//!
//! The redeem script must know its own serialized length so that the caller can push
//! it in the scriptSig. Because that length depends on the final script, the builder
//! iteratively emits a placeholder, measures the length, recomputes the constants,
//! and repeats until the values stabilize.

use kaspa_txscript::{
    opcodes::codes::*,
    script_builder::{ScriptBuilder, ScriptBuilderError},
    script_class::ScriptClass,
};
use thiserror::Error;

const PLACEHOLDER_END: i64 = 17;
const MAX_PLACEHOLDER_ITERS: usize = 8;

/// Tiny helper trait extending `ScriptBuilder` with a handful of concatenation helpers.
trait ScriptBuilderExt {
    fn add_affixes(&mut self, prefix: &[u8], suffix: &[u8]) -> Result<&mut Self, ScriptBuilderError>;
    // fn add_prefix_with<F>(&mut self, build_prefix: F) -> Result<&mut Self, ScriptBuilderError>
    // where
    //     F: FnOnce(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError>;
    // fn add_suffix_with<F>(&mut self, build_suffix: F) -> Result<&mut Self, ScriptBuilderError>
    // where
    //     F: FnOnce(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError>;
    fn add_prefix(&mut self, prefix: &[u8]) -> Result<&mut Self, ScriptBuilderError> {
        self.add_affixes(prefix, &[])
    }
    // fn add_suffix(&mut self, suffix: &[u8]) -> Result<&mut Self, ScriptBuilderError> {
    //     self.add_affixes(&[], suffix)
    // }
}

impl ScriptBuilderExt for ScriptBuilder {
    fn add_affixes(&mut self, prefix: &[u8], suffix: &[u8]) -> Result<&mut Self, ScriptBuilderError> {
        match (prefix.is_empty(), suffix.is_empty()) {
            (true, true) => Ok(self),
            (false, true) => self.add_data(prefix)?.add_op(OpSwap)?.add_op(OpCat),
            (true, false) => self.add_data(suffix)?.add_op(OpCat),
            (false, false) => self.add_data(prefix)?.add_op(OpSwap)?.add_op(OpCat)?.add_data(suffix)?.add_op(OpCat),
        }
    }

    // fn add_prefix_with<F>(&mut self, build_prefix: F) -> Result<&mut Self, ScriptBuilderError>
    // where
    //     F: FnOnce(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError>,
    // {
    //     build_prefix(self)?;
    //     self.add_op(OpSwap)?.add_op(OpCat)
    // }

    // fn add_suffix_with<F>(&mut self, build_suffix: F) -> Result<&mut Self, ScriptBuilderError>
    // where
    //     F: FnOnce(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError>,
    // {
    //     build_suffix(self)?;
    //     self.add_op(OpCat)
    // }
}

#[derive(Clone, Copy)]
enum OutputTarget {
    Absolute(i64),
    AuthorizedSlot(i64),
}

#[derive(Debug, Error)]
pub enum CovenantBuilderError {
    #[error("state must be set")]
    MissingState,
    #[error("output verification target must be set")]
    MissingOutputTarget,
    #[error("placeholder resolution did not converge")]
    PlaceholderDidNotConverge,
    #[error("script builder error: {0}")]
    ScriptBuilder(#[from] ScriptBuilderError),
}

/// Encapsulates push-metadata for both the persisted state and the action blob.
///
/// The builder keeps the raw state bytes here so that every iteration can re-use
/// the same allocation without re-encoding. The action metadata is stored too so
/// we can reason about the scriptSig layout when performing placeholder math.
struct StateDescriptor {
    state_bytes: Vec<u8>,
    state_push_header: Vec<u8>,
    state_push_size: i64,
    _action_push_header: Vec<u8>,
    action_push_size: i64,
}

impl StateDescriptor {
    fn new(state_bytes: Vec<u8>, action_len: usize) -> Self {
        fn push_descriptor(len: usize) -> (Vec<u8>, i64) {
            let data = vec![0u8; len];
            let script = ScriptBuilder::new().add_data(&data).unwrap().drain();
            let push_header = script[0..script.len() - len].to_vec();
            let push_size = script.len() as i64;
            (push_header, push_size)
        }

        let (state_push_header, state_push_size) = push_descriptor(state_bytes.len());
        let (_action_push_header, action_push_size) = push_descriptor(action_len);

        Self { state_bytes, state_push_header, state_push_size, _action_push_header, action_push_size }
    }

    fn state_bytes(&self) -> &[u8] {
        &self.state_bytes
    }
}

/// Computes the serialized size of a data push (opcode + optional length bytes + data).
pub fn compute_push_size(data: &[u8]) -> i64 {
    ScriptBuilder::new().add_data(data).unwrap().drain().len() as i64
}

/// Builder for constructing stateful covenant scripts with SPK reconstruction.
///
/// This builder implements the pattern where:
/// 1. Old state is pushed to the stack for the transition to consume.
/// 2. Action data is provided in the scriptSig.
/// 3. Script computes new state and reconstructs the redeem script.
/// 4. Hashes and verifies the reconstructed script matches the output SPK.
pub struct CovenantBuilder {
    /// Descriptor for the current embedded state (includes push metadata).
    state: Option<StateDescriptor>,
    /// Every requested verification target (absolute index or authorized slot).
    targets: Vec<OutputTarget>,
    /// Optional assertion on the number of authorized outputs.
    required_auth_output_count: Option<i64>,
    /// Optional user-supplied transition closure.
    state_transition: Option<Box<dyn Fn(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError>>>,
}

impl CovenantBuilder {
    /// Creates a new covenant builder.
    pub fn new() -> Self {
        Self { state: None, targets: Vec::new(), required_auth_output_count: None, state_transition: None }
    }

    /// Sets the state that will be pushed into the redeem script and the expected action length.
    ///
    /// The state bytes are placed directly on the execution stack so the transition closure
    /// can consume and transform them. No non-executing branch is used.
    ///
    /// # Arguments
    /// * `state` - The state bytes to embed in the covenant
    /// * `action_len` - The size (in bytes) of action data that will be supplied per spend
    pub fn with_state(mut self, state: Vec<u8>, action_len: usize) -> Self {
        self.state = Some(StateDescriptor::new(state, action_len));
        self
    }

    /// Adds SPK verification logic for the output at the given index.
    ///
    /// This reconstructs the expected redeem script with new state,
    /// hashes it, builds the P2SH SPK, and verifies it matches the output.
    ///
    /// # Arguments
    /// * `output_index` - The output index to verify (typically 0)
    pub fn verify_output_spk_at(mut self, output_index: i64) -> Self {
        self.targets.push(OutputTarget::Absolute(output_index));
        self
    }

    /// Verifies the script public key of the k-th authorized output (k-based index).
    pub fn verify_authorized_output_spk_at(mut self, auth_slot: i64) -> Self {
        self.targets.push(OutputTarget::AuthorizedSlot(auth_slot));
        self
    }

    /// Requires that the number of authorized outputs for this input equals `count`.
    pub fn require_authorized_output_count(mut self, count: i64) -> Self {
        self.required_auth_output_count = Some(count);
        self
    }

    /// Injects a custom state-transition script fragment.
    ///
    /// The transition closure is responsible for leaving as many new-state byte blobs on the
    /// stack as there are verification targets (absolute + authorized). Each verification step
    /// consumes exactly one of those states.
    pub fn with_state_transition<F>(mut self, transition: F) -> Self
    where
        F: Fn(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError> + 'static,
    {
        self.state_transition = Some(Box::new(transition));
        self
    }

    /// Builds the final covenant script.
    ///
    /// This follows the reference implementation pattern exactly:
    /// 1. Push state bytes (transition consumes them).
    /// 2. Verify scriptSig length.
    /// 3. Build prefix (state push header) and concatenate with new state.
    /// 4. Extract suffix, concatenate to form new redeem script.
    /// 5. Hash and build SPK, verify against output.
    ///
    /// # Returns
    /// The complete covenant script bytes.
    pub fn build(self) -> Result<Vec<u8>, CovenantBuilderError> {
        let descriptor = self.state.ok_or(CovenantBuilderError::MissingState)?;
        let targets = self.targets;
        if targets.is_empty() {
            return Err(CovenantBuilderError::MissingOutputTarget);
        }
        let required_auth_output_count = self.required_auth_output_count;
        let state_transition = self.state_transition;

        let state_push_total = descriptor.state_push_size;
        let action_push_total = descriptor.action_push_size;
        // Assume OpPushData header for redeem script is a single byte for the first pass.
        let assumed_redeem_header = 1;
        let mut start_offset = Self::start_offset(action_push_total, assumed_redeem_header, state_push_total);
        let mut end = PLACEHOLDER_END.max(start_offset);

        for _ in 0..MAX_PLACEHOLDER_ITERS {
            let script = Self::build_with_params(
                &descriptor,
                &targets,
                required_auth_output_count,
                state_transition.as_deref(),
                end,
                start_offset,
            )?;
            let redeem_len = script.len() as i64;
            let redeem_push_size = compute_push_size(&script);
            let redeem_header = redeem_push_size - redeem_len;

            let next_end = action_push_total + redeem_push_size;
            let next_start = Self::start_offset(action_push_total, redeem_header, state_push_total);

            if next_end == end && next_start == start_offset {
                return Ok(script);
            }

            end = next_end;
            start_offset = next_start;
        }

        Err(CovenantBuilderError::PlaceholderDidNotConverge)
    }

    fn start_offset(action_push_total: i64, redeem_header: i64, state_push_total: i64) -> i64 {
        action_push_total + redeem_header + state_push_total
    }

    /*
         OUTPUT SPK VERIFICATION ALGORITHM (byte-accurate; no stack model)

         Definitions:
            - state_len = length of the state bytes
            - action_push_total = encoded size of pushing action bytes in scriptSig
                                  (1/2/3/5-byte header + action_len)
            - redeem_script = this covenant script (the one being built)
            - redeem_len = redeem_script length in bytes
            - redeem_push_total = encoded size of pushing redeem_script in scriptSig
                                  (1/2/3/5-byte header + redeem_len)
            - end = action_push_total + redeem_push_total (total scriptSig length)
            - start_offset = action_push_total + redeem_header + state_push_total
                  where redeem_header = redeem_push_total - redeem_len

         scriptSig layout (exact bytes):
            [action_push_header][action_bytes][redeem_push_header][redeem_script_bytes]

         redeem_script layout for state (exact bytes inside redeem_script):
            [state_push_header][state_bytes]            // pushed, executed, not hidden

         Deterministic byte procedure:

         1) Check scriptSig length:
             assert scriptSig.len == end

         2) Extract action bytes from scriptSig:
             action_data = scriptSig[ action_push_header .. action_push_header + action_len ]

         3) Extract redeem suffix from scriptSig:
             suffix = scriptSig[ start_offset .. end ]

         4) Build prefix bytes (state push header only):
             prefix = [state_push_header]

         5) Compute one or more new_state payloads via the transition closure and
            reconstruct redeem script bytes for each verification target:
             new_state_i = f(old_state, action_data)[i]
             new_redeem_script_i = prefix || new_state_i || suffix

         6) Compute expected P2SH SPK bytes:
             hash = Blake2b(new_redeem_script_i)
             spk_prefix = [version_be(2 bytes), OpBlake2b, OpData32]
             expected_spk = spk_prefix || hash || [OpEqual]

         7) Resolve output index:
             if absolute target: out_idx = output_index
             else: out_idx = auth_output_idx(input_index, slot)

         8) Verify output SPK bytes (per target):
             assert TxOutputSpk(out_idx) == expected_spk_i

         Result:
             Script succeeds iff the output SPK matches the reconstructed redeem script hash.
    */

    fn build_with_params(
        descriptor: &StateDescriptor,
        targets: &[OutputTarget],
        required_auth_output_count: Option<i64>,
        state_transition: Option<&dyn Fn(&mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError>>,
        end: i64,
        start_offset: i64,
    ) -> Result<Vec<u8>, CovenantBuilderError> {
        let mut builder = ScriptBuilder::new();

        builder.add_data(descriptor.state_bytes())?;

        if let Some(transition) = state_transition {
            // the transition function assumes the following stack:
            // [action_data (from sig), old_state (just pushed)]
            // and is expected to leave the new_state on top of the stack instead
            transition(&mut builder)?;
        } else {
            assert_eq!(descriptor.state_push_size, descriptor.action_push_size);
            builder.add_op(OpDrop)?;
        }

        if let Some(count) = required_auth_output_count {
            builder.add_op(OpTxInputIndex)?.add_op(OpAuthOutputCount)?.add_i64(count)?.add_op(OpNumEqualVerify)?;
        }

        // The redeem script has to know exactly how many bytes were pushed via the scriptSig.
        builder.add_op(OpTxInputIndex)?.add_op(OpTxInputScriptSigLen)?.add_i64(end)?.add_op(OpNumEqualVerify)?;

        for target in targets {
            // Each iteration consumes one new-state blob left by the transition closure.
            // We rebuild the redeem script bytes around that state so every verification
            // hashes exactly what the corresponding output should commit to.
            builder.add_prefix(descriptor.state_push_header.as_slice())?;

            builder.add_op(OpTxInputIndex)?.add_i64(start_offset)?.add_i64(end)?.add_op(OpTxInputScriptSigSubstr)?.add_op(OpCat)?;

            builder.add_op(OpDup)?.add_op(OpBlake2b)?;

            // Wrap the top-of-stack 32-byte hash with SPK prefix and suffix.
            builder.add_affixes(
                // P2SH SPK prefix: version_be(2 bytes) || OpBlake2b || OpData32
                &{
                    let [b0, b1] = ScriptClass::ScriptHash.version().to_be_bytes(); // version_be follows SpkEncoding
                    [b0, b1, OpBlake2b, OpData32]
                },
                // P2SH SPK suffix: [OpEqual]
                &[OpEqual],
            )?;

            match target {
                OutputTarget::Absolute(output_index) => {
                    builder.add_i64(*output_index)?;
                }
                OutputTarget::AuthorizedSlot(slot) => {
                    builder.add_op(OpTxInputIndex)?.add_i64(*slot)?.add_op(OpAuthOutputIdx)?;
                }
            }

            builder.add_op(OpTxOutputSpk)?.add_op(OpEqualVerify)?;

            // Remove the reconstructed script so the next iteration starts fresh.
            builder.add_op(OpDrop)?;
        }

        builder.add_op(OpTrue)?;

        Ok(builder.drain())
    }
}

impl Default for CovenantBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{
        constants::{SOMPI_PER_KASPA, TX_VERSION},
        hashing::sighash::SigHashReusedValuesUnsync,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{
            CovenantBinding, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
        },
    };
    use kaspa_txscript::{
        EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
        script_builder::ScriptBuilder as TxScriptBuilder,
    };

    #[test]
    fn test_builder_with_spk_verification() {
        let state = vec![0xaa; 32]; // 32-byte state
        let state_len = state.len();
        let covenant =
            CovenantBuilder::new().with_state(state, state_len).verify_output_spk_at(0).build().expect("builder should succeed");

        // Should contain OpBlake2b for hashing
        assert!(covenant.contains(&OpBlake2b));
        // Should contain OpEqualVerify for verification
        assert!(covenant.contains(&OpEqualVerify));
    }

    #[test]
    fn test_builder_auth_output_helpers_emit_opcodes() {
        let script = CovenantBuilder::new()
            .with_state(vec![0x44; 8], 8)
            .require_authorized_output_count(1)
            .verify_authorized_output_spk_at(0)
            .build()
            .expect("builder should succeed");

        assert!(script.contains(&OpAuthOutputCount));
        assert!(script.contains(&OpAuthOutputIdx));
    }

    /// Test the complete covenant execution flow end-to-end.
    #[test]
    fn test_state_transition_with_spk_verification() {
        const STATE_LEN_BYTES: usize = 8;
        const STATE_LEN_I64: i64 = STATE_LEN_BYTES as i64;
        // TODO(serialize-u32): this should be 4 once we can safely encode arbitrary u32 values
        // using the VM's numeric format.
        const ACTION_LEN_BYTES: usize = 1;
        const VERIFICATION_TARGETS: usize = 3; // 1 absolute + 2 authorized outputs

        // Define numeric state transition: new_state = old_state + action_data
        let old_state_value: i64 = 41;
        let action_delta: u8 = 5;
        let new_state_value = old_state_value + action_delta as i64;

        let old_state = old_state_value.to_le_bytes();
        let new_state = new_state_value.to_le_bytes();
        let action_data = [action_delta];
        assert_eq!(old_state.len(), new_state.len());
        assert_eq!(old_state.len(), STATE_LEN_BYTES);
        assert_eq!(action_data.len(), ACTION_LEN_BYTES);

        fn transition(b: &mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError> {
            // the transition function assumes the following stack:
            // [action_data (from sig), old_state (just pushed)]
            // and is expected to leave the new_state on top of the stack instead

            // The line below implements f(current_state, action_data) -> action_data
            // b.add_op(OpDrop)

            /*
                The line below implements:

                state: i64
                action_data: u8

                f(current_state, action_data):
                    new_state = current_state + action_data

            */

            b.add_op(OpBin2Num)?.add_op(OpSwap)?.add_op(OpBin2Num)?.add_op(OpAdd)?.add_i64(STATE_LEN_I64)?.add_op(OpNum2Bin)?;

            for _ in 1..VERIFICATION_TARGETS {
                b.add_op(OpDup)?;
            }

            Ok(b)
        }

        fn build_script(state: &[u8]) -> Result<Vec<u8>, CovenantBuilderError> {
            CovenantBuilder::new()
                .with_state(state.to_vec(), ACTION_LEN_BYTES)
                .with_state_transition(transition)
                .verify_output_spk_at(0)
                .require_authorized_output_count(2)
                .verify_authorized_output_spk_at(0)
                .verify_authorized_output_spk_at(1)
                .build()
        }

        let input_redeem_script = build_script(&old_state).expect("input builder should succeed");
        let output_redeem_script = build_script(&new_state).expect("output builder should succeed");

        println!("Input redeem script length: {}", input_redeem_script.len());
        println!("Output redeem script length: {}", output_redeem_script.len());

        // Verify scripts have same length
        assert_eq!(input_redeem_script.len(), output_redeem_script.len(), "Input and output redeem scripts must have same length");

        // Create P2SH script public keys
        let input_spk = pay_to_script_hash_script(&input_redeem_script);
        let output_spk = pay_to_script_hash_script(&output_redeem_script);

        println!("Input SPK: {:?}", input_spk.script());
        println!("Output SPK: {:?}", output_spk.script());

        // Create transaction
        let dummy_prev_out = TransactionOutpoint::new(kaspa_hashes::Hash::from_u64_word(1), 0);
        let covenant_id = kaspa_hashes::Hash::from_u64_word(42);
        let tx_input = TransactionInput::new(dummy_prev_out, vec![], 0, 0);
        let mut tx_output = TransactionOutput::new(SOMPI_PER_KASPA, output_spk);
        tx_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });

        let mut tx =
            Transaction::new(TX_VERSION, vec![tx_input], vec![tx_output.clone(), tx_output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);

        // Build scriptSig: <action_data> <input_redeem_script>
        // (action first so the transition hook consumes it before the embedded state)
        let sig_script = TxScriptBuilder::new().add_data(&action_data).unwrap().add_data(&input_redeem_script).unwrap().drain();

        println!("ScriptSig length: {}", sig_script.len());
        let expected_scriptsig_len = compute_push_size(&action_data) + compute_push_size(&input_redeem_script);
        assert_eq!(sig_script.len() as i64, expected_scriptsig_len, "ScriptSig length should match builder-computed expectations");

        tx.inputs[0].signature_script = sig_script;

        // Create UTXO entry
        let utxo_entry = UtxoEntry::new(SOMPI_PER_KASPA, input_spk, 0, false, Some(covenant_id));

        // Execute
        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();
        let flags = EngineFlags { covenants_enabled: true };

        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let covenants_ctx = CovenantsContext::from_tx(&populated_tx).expect("covenants context");
        let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&covenants_ctx);
        let mut engine = TxScriptEngine::from_transaction_input(&populated_tx, &tx.inputs[0], 0, &utxo_entry, ctx, flags);

        let result = engine.execute();

        match &result {
            Ok(_) => println!("✓ Covenant execution succeeded!"),
            Err(e) => println!("✗ Covenant execution failed: {:?}", e),
        }

        result.expect("Covenant should validate state transition and output SPK");
    }

    /// Demonstrates a 1->2 split where the action selects how much state should move to
    /// the first output and the remainder flows to the second output.
    #[test]
    fn test_state_split_transition_with_two_outputs() {
        const STATE_LEN_BYTES: usize = 8;
        const STATE_LEN_I64: i64 = STATE_LEN_BYTES as i64;
        const ACTION_LEN_BYTES: usize = 1;

        let current_state_value: i64 = 1_000;
        let action_value: u8 = 5;
        assert!((action_value as i64) <= current_state_value, "action value must not exceed state");

        let old_state = current_state_value.to_le_bytes();
        let new_state_1 = (action_value as i64).to_le_bytes();
        let new_state_2 = (current_state_value - action_value as i64).to_le_bytes();
        // TODO(serialize-u32): the engine expects minimally-encoded signed numbers; the
        // 4-byte action blob works for the current test value but needs a generalized
        // encoder that mirrors the VM's number format.
        let action_data = action_value.to_le_bytes();

        fn transition(b: &mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError> {
            // the transition function assumes the following stack:
            // [action_data (from sig), old_state (just pushed)]
            // and is expected to leave the new_state on top of the stack instead

            b
                // Convert stack to numeric form: [state, action]
                .add_op(OpBin2Num)?
                .add_op(OpSwap)?
                .add_op(OpBin2Num)?
                // Validate action <= state
                .add_op(Op2Dup)?
                .add_op(OpSwap)?
                .add_op(OpLessThanOrEqual)?
                .add_op(OpVerify)?
                // Compute (state - action) while keeping originals
                .add_op(Op2Dup)?
                .add_op(OpSub)?
                .add_op(OpRot)?
                .add_op(OpDrop)?
                // Stack now: [action, diff]
                .add_i64(STATE_LEN_I64)?
                .add_op(OpNum2Bin)? // diff -> bytes
                .add_op(OpSwap)?
                .add_i64(STATE_LEN_I64)?
                .add_op(OpNum2Bin)?; // action -> bytes

            // Provide exactly VERIFICATION_TARGETS new states (top-first order)
            Ok(b)
        }

        fn build_script(state: &[u8]) -> Result<Vec<u8>, CovenantBuilderError> {
            CovenantBuilder::new()
                .with_state(state.to_vec(), ACTION_LEN_BYTES)
                .with_state_transition(transition)
                .require_authorized_output_count(2)
                .verify_authorized_output_spk_at(0)
                .verify_authorized_output_spk_at(1)
                .build()
        }

        let input_redeem_script = build_script(&old_state).expect("input builder should succeed");
        let left_output_redeem_script = build_script(&new_state_1).expect("left output builder should succeed");
        let right_output_redeem_script = build_script(&new_state_2).expect("right output builder should succeed");

        println!("Input redeem script length: {}", input_redeem_script.len());
        println!("Left output redeem script length: {}", left_output_redeem_script.len());
        println!("Right output redeem script length: {}", right_output_redeem_script.len());

        let input_spk = pay_to_script_hash_script(&input_redeem_script);
        let left_output_spk = pay_to_script_hash_script(&left_output_redeem_script);
        let right_output_spk = pay_to_script_hash_script(&right_output_redeem_script);

        println!("Input SPK: {:?}", input_spk.script());
        println!("Left output SPK: {:?}", left_output_spk.script());
        println!("Right output SPK: {:?}", right_output_spk.script());

        let dummy_prev_out = TransactionOutpoint::new(kaspa_hashes::Hash::from_u64_word(7), 0);
        let covenant_id = kaspa_hashes::Hash::from_u64_word(77);
        let tx_input = TransactionInput::new(dummy_prev_out, vec![], 0, 0);

        // Both outputs commit to the covenant so the authorizing input can enforce the split.
        let mut left_output = TransactionOutput::new(SOMPI_PER_KASPA, left_output_spk);
        left_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });
        let mut right_output = TransactionOutput::new(SOMPI_PER_KASPA, right_output_spk);
        right_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });

        let mut tx = Transaction::new(TX_VERSION, vec![tx_input], vec![left_output, right_output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);

        // Build scriptSig: <action_data> <input_redeem_script>
        let sig_script = TxScriptBuilder::new().add_data(&action_data).unwrap().add_data(&input_redeem_script).unwrap().drain();
        let expected_scriptsig_len = compute_push_size(&action_data) + compute_push_size(&input_redeem_script);
        assert_eq!(sig_script.len() as i64, expected_scriptsig_len, "ScriptSig length should match expectations");
        tx.inputs[0].signature_script = sig_script;

        let utxo_entry = UtxoEntry::new(SOMPI_PER_KASPA, input_spk, 0, false, Some(covenant_id));
        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();
        let flags = EngineFlags { covenants_enabled: true };

        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let covenants_ctx = CovenantsContext::from_tx(&populated_tx).expect("covenants context");
        let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&covenants_ctx);
        let mut engine = TxScriptEngine::from_transaction_input(&populated_tx, &tx.inputs[0], 0, &utxo_entry, ctx, flags);

        engine.execute().expect("split covenant should validate");
    }

    #[test]
    fn test_state_split_transition_with_two_large_outputs() {
        const STATE_BYTES_LEN: usize = 756;
        const ACTION_BYTES_LEN: usize = 722;

        let current_state_value = [17u8; STATE_BYTES_LEN];
        let action_value = [234u8; ACTION_BYTES_LEN];

        fn xor_shared_prefix(a: &[u8], b: &[u8]) -> Vec<u8> {
            let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
            let prefix = a.iter().zip(b).map(|(x, y)| x ^ y);
            prefix.chain(long.iter().skip(short.len()).copied()).collect()
        }

        let old_state = current_state_value.as_ref();
        let new_state = xor_shared_prefix(current_state_value.as_ref(), action_value.as_ref());
        let new_state_1 = new_state.as_ref();
        let new_state_2 = new_state.as_ref();
        let action_data = action_value.as_ref();

        fn transition(b: &mut ScriptBuilder) -> Result<&mut ScriptBuilder, ScriptBuilderError> {
            let action_len = ACTION_BYTES_LEN as i64;
            let state_len = STATE_BYTES_LEN as i64;

            if ACTION_BYTES_LEN == STATE_BYTES_LEN {
                b.add_op(OpXor)?.add_op(OpDup)
            } else {
                b
                    // Stack: [action, state]
                    .add_op(OpDup)? // [action, state, state] (keep original state for suffix)
                    .add_i64(0)?
                    .add_i64(action_len)?
                    .add_op(OpSubstr)? // prefix = state[0..action_len]; stack [action, state, prefix]
                    .add_op(OpRot)? // [state, prefix, action]
                    .add_op(OpXor)? // xor_prefix = prefix ^ action; stack [state, xor_prefix]
                    .add_op(OpSwap)? // [xor_prefix, state]
                    .add_i64(action_len)?
                    .add_i64(state_len)?
                    .add_op(OpSubstr)? // suffix = state[action_len..state_len]; stack [xor_prefix, suffix]
                    .add_op(OpCat)? // new_state = xor_prefix || suffix
                    .add_op(OpDup)
            }
        }

        fn build_script(state: &[u8]) -> Result<Vec<u8>, CovenantBuilderError> {
            CovenantBuilder::new()
                .with_state(state.to_vec(), ACTION_BYTES_LEN)
                .with_state_transition(transition)
                .require_authorized_output_count(2)
                .verify_authorized_output_spk_at(0)
                .verify_authorized_output_spk_at(1)
                .build()
        }

        let input_redeem_script = build_script(&old_state).expect("input builder should succeed");
        let left_output_redeem_script = build_script(&new_state_1).expect("left output builder should succeed");
        let right_output_redeem_script = build_script(&new_state_2).expect("right output builder should succeed");

        println!("Input redeem script length: {}", input_redeem_script.len());
        println!("Left output redeem script length: {}", left_output_redeem_script.len());
        println!("Right output redeem script length: {}", right_output_redeem_script.len());

        let input_spk = pay_to_script_hash_script(&input_redeem_script);
        let left_output_spk = pay_to_script_hash_script(&left_output_redeem_script);
        let right_output_spk = pay_to_script_hash_script(&right_output_redeem_script);

        println!("Input SPK: {:?}", input_spk.script());
        println!("Left output SPK: {:?}", left_output_spk.script());
        println!("Right output SPK: {:?}", right_output_spk.script());

        let dummy_prev_out = TransactionOutpoint::new(kaspa_hashes::Hash::from_u64_word(7), 0);
        let covenant_id = kaspa_hashes::Hash::from_u64_word(77);
        let tx_input = TransactionInput::new(dummy_prev_out, vec![], 0, 0);

        // Both outputs commit to the covenant so the authorizing input can enforce the split.
        let mut left_output = TransactionOutput::new(SOMPI_PER_KASPA, left_output_spk);
        left_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });
        let mut right_output = TransactionOutput::new(SOMPI_PER_KASPA, right_output_spk);
        right_output.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id });

        let mut tx = Transaction::new(TX_VERSION, vec![tx_input], vec![left_output, right_output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);

        // Build scriptSig: <action_data> <input_redeem_script>
        let sig_script = TxScriptBuilder::new().add_data(&action_data).unwrap().add_data(&input_redeem_script).unwrap().drain();
        let expected_scriptsig_len = compute_push_size(&action_data) + compute_push_size(&input_redeem_script);
        assert_eq!(sig_script.len() as i64, expected_scriptsig_len, "ScriptSig length should match expectations");
        tx.inputs[0].signature_script = sig_script;

        let utxo_entry = UtxoEntry::new(SOMPI_PER_KASPA, input_spk, 0, false, Some(covenant_id));
        let sig_cache = Cache::new(10_000);
        let reused_values = SigHashReusedValuesUnsync::new();
        let flags = EngineFlags { covenants_enabled: true };

        let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);
        let covenants_ctx = CovenantsContext::from_tx(&populated_tx).expect("covenants context");
        let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&covenants_ctx);
        let mut engine = TxScriptEngine::from_transaction_input(&populated_tx, &tx.inputs[0], 0, &utxo_entry, ctx, flags);

        engine.execute().expect("xor covenant should validate");
    }
}
