#![allow(non_upper_case_globals)] // Match the VM's opcode constant names.

//! Validate compiled bytecode fragments, including raw builder calls and SDK fragments,
//! and bound the script units each entrypoint charges.
//!
//! Analyze each entrypoint body with its own arguments and state fields. Check
//! state initialization with the largest argument count and a saved dispatch tag.
//! The caller checks dispatch using its fixed argument + field + 3 stack bound.
//! Every IF/NOTIF explores both branches, joining equal-height stacks at ENDIF.
//! Small constants survive copies and joins to resolve stack indices and arity.
//!
//! Alongside the stack heights, the analysis meters every path the way the VM's
//! runtime resource meter does: bytes newly pushed by an opcode, bytes hashed,
//! signature operations, and proof verification. Each stack item carries an
//! upper bound of its byte length as a linear form over the lengths the
//! compiler cannot know (variable-length arguments, variable-length state
//! fields, and transaction fields read through introspection), so the charged
//! units come out as `constant + Σ coefficient × length`. Joins take the
//! term-by-term maximum, so the result bounds every path.
use super::{DispatchTag, FunctionAst};
use crate::checked_arithmetic::{checked_add, checked_mul};
use crate::errors::CompilerError;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::SCRIPT_UNITS_PER_GRAM;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::zk_precompiles::groth16::GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS;
use kaspa_txscript::zk_precompiles::tags::ZkTag;
use kaspa_txscript::{MAX_STACK_SIZE, deserialize_i64, parse_script, serialize_i64};
use silverscript_abi::ComputeEstimateArtifact;
use std::collections::BTreeMap;

mod linear;
mod stack;
use linear::{IndexKey, IntrospectionSource, Linear, Symbol};
use stack::Stack;

/// Script units the VM charges per signature operation on mainnet.
pub(super) const SIG_OP_SCRIPT_UNITS: u64 = MAINNET_PARAMS.mass_per_sig_op * SCRIPT_UNITS_PER_GRAM;
/// Script units the VM charges per hashed byte. These mirror the pinned VM's
/// private `HashOpcodePricing`; the compiler tests compare them against it.
const SHA256_SCRIPT_UNITS_PER_BYTE: u64 = 1;
const BLAKE2B_SCRIPT_UNITS_PER_BYTE: u64 = 2;
const BLAKE3_SCRIPT_UNITS_PER_BYTE: u64 = 1;
/// A script number occupies at most eight bytes.
const NUMBER_ENCODED_LEN: u64 = 8;
/// Lengths of script elements, scripts, and payloads stay below 2^23, so their
/// script-number encoding occupies at most three bytes.
const LENGTH_ENCODED_LEN: u64 = 3;
/// A boolean result is pushed as `[1]` or `[]`.
const BOOL_ENCODED_LEN: u64 = 1;
const HASH_LEN: u64 = 32;
const SUBNETWORK_ID_LEN: u64 = 20;

/// What is known about one stack item. Every variant still counts as one item.
/// `Bytes` keeps a small, exact byte value for operations that need a known index
/// or argument count. `Sized` bounds the byte length of an item whose contents
/// are unknown, and `Num` is a script number whose value is known as a linear
/// form even though its encoded length is not. Large literals become `Sized`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Value {
    /// Unknown contents and unbounded length. Charging its bytes makes the path's cost unbounded.
    Unknown,
    Bytes(Vec<u8>),
    Sized {
        bound: Linear,
        exact: bool,
    },
    Num {
        value: Linear,
        encoded_len: u64,
    },
}

impl Value {
    pub(super) fn literal(bytes: &[u8]) -> Self {
        // Argument counts and stack indices fit in eight bytes. Do not
        // retain potentially large proof/key/data literals in abstract states.
        if bytes.len() <= 8 { Self::Bytes(bytes.to_vec()) } else { Self::exact(Linear::constant(bytes.len() as i64)) }
    }

    pub(super) fn number(number: i64) -> Self {
        Self::Bytes(serialize_i64(number, None).expect("minimal i64 serialization fits").to_vec())
    }

    /// An item whose length is exactly `len`.
    pub(super) fn exact(len: Linear) -> Self {
        Self::Sized { bound: len, exact: true }
    }

    /// An item whose length is at most `bound`.
    pub(super) fn bounded(bound: Linear) -> Self {
        Self::Sized { bound, exact: false }
    }

    /// An argument or state field with a fixed encoded size, exact for byte
    /// sequences and an upper bound for minimally encoded numbers and booleans.
    pub(super) fn fixed(size: u64, exact: bool) -> Self {
        Self::Sized { bound: Linear::constant(size as i64), exact }
    }

    /// A variable-length argument or state field whose encoded length the
    /// estimate reports under `name`.
    pub(super) fn named_length(name: String) -> Self {
        Self::exact(Linear::symbol(Symbol::Named(name)))
    }

    /// A script number whose value is unknown.
    pub(super) fn unknown_number() -> Self {
        Self::bounded(Linear::constant(NUMBER_ENCODED_LEN as i64))
    }

    fn unknown_bool() -> Self {
        Self::bounded(Linear::constant(BOOL_ENCODED_LEN as i64))
    }

    /// A script number equal to `value`. Constant values keep their exact encoding.
    fn numeric(value: Linear, encoded_len: u64) -> Self {
        match value.as_constant() {
            Some(constant) => {
                serialize_i64(constant, None).ok().map_or_else(Self::unknown_number, |bytes| Self::Bytes(bytes.to_vec()))
            }
            None => Self::Num { value, encoded_len },
        }
    }

    /// A script number holding a byte length.
    fn length(value: Linear) -> Self {
        Self::numeric(value, LENGTH_ENCODED_LEN)
    }

    /// An upper bound of the item's byte length, or None if it is unbounded.
    pub(super) fn len_bound(&self) -> Option<Linear> {
        match self {
            Self::Unknown => None,
            Self::Bytes(bytes) => Some(Linear::constant(bytes.len() as i64)),
            Self::Sized { bound, .. } => Some(bound.clone()),
            Self::Num { encoded_len, .. } => Some(Linear::constant(*encoded_len as i64)),
        }
    }

    /// The item's byte length when it is known exactly.
    fn exact_len(&self) -> Option<Linear> {
        match self {
            Self::Bytes(bytes) => Some(Linear::constant(bytes.len() as i64)),
            Self::Sized { bound, exact: true } => Some(bound.clone()),
            Self::Unknown | Self::Sized { exact: false, .. } | Self::Num { .. } => None,
        }
    }

    /// The item's value as a nonnegative script number, when known.
    fn as_number(&self) -> Option<Linear> {
        match self {
            Self::Bytes(bytes) => deserialize_i64(bytes, false).ok().map(Linear::constant),
            Self::Num { value, .. } => Some(value.clone()),
            Self::Unknown | Self::Sized { .. } => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Bytes(bytes) => deserialize_i64(bytes, false).ok(),
            _ => None,
        }
    }

    /// The common knowledge of two differing values: a length bound both satisfy.
    fn join(left: &Self, right: &Self) -> Self {
        match (left.len_bound(), right.len_bound()) {
            (Some(a), Some(b)) => Self::bounded(a.max(&b)),
            _ => Self::Unknown,
        }
    }
}

/// One decoded instruction from a compiled bytecode fragment. `opcode` identifies
/// the VM operation, and `offset` is its starting byte position within that fragment,
/// used to report errors. For push operations, `literal` is the value to put on the
/// simulated stack (only its length for large data); other operations ignore that field.
struct Instruction {
    opcode: u8,
    offset: usize,
    literal: Value,
}

/// Saved states for one open IF/NOTIF while the analyzer walks its branches.
/// `else_entry` saves the stacks just after popping the condition, ready to start
/// the else branch; ELSE takes it out, leaving None. Without an ELSE, it is the
/// result of skipping the then branch. It is also None if that path is unreachable.
/// `then_exit` is filled at ELSE with the then branch's result, or None if that
/// path cannot continue. The else branch's result stays in `current`, outside this
/// struct. `seen_else` tells ENDIF whether to merge with `then_exit` or `else_entry`
/// and lets the analyzer reject a second ELSE for the same IF.
#[derive(Default)]
struct Branch {
    else_entry: Option<Stack>,
    then_exit: Option<Stack>,
    seen_else: bool,
}

/// Context attached to stack-analysis errors. `function` names the entrypoint
/// being checked, and `offset` identifies the current opcode's starting byte in
/// the analyzed bytecode fragment (an entrypoint body or state initializer).
/// Its helper methods use these fields when reporting failures.
struct Location<'a> {
    function: &'a str,
    offset: usize,
}

impl Location<'_> {
    fn error(&self, message: impl Into<String>) -> CompilerError {
        CompilerError::BytecodeStackAnalysis { function: self.function.into(), offset: self.offset, message: message.into() }
    }

    fn stack_too_large(&self, actual: usize) -> CompilerError {
        CompilerError::BytecodeStackTooLarge { function: self.function.into(), offset: self.offset, actual, maximum: MAX_STACK_SIZE }
    }
}

fn instructions(bytecode: &[u8]) -> Result<Vec<Instruction>, CompilerError> {
    let mut result = Vec::new();
    let mut offset = 0;
    for parsed in parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(bytecode) {
        let op = parsed.map_err(|error| CompilerError::BytecodeStackAnalysis {
            function: "<script>".into(),
            offset,
            message: error.to_string(),
        })?;
        let opcode = op.value();
        let literal = match opcode {
            Op0 => Value::number(0),
            Op1Negate => Value::number(-1),
            Op1..=Op16 => Value::number(i64::from(opcode - Op1 + 1)),
            _ => Value::literal(op.get_data()),
        };
        result.push(Instruction { opcode, offset, literal });
        let prefix = match opcode {
            OpPushData1 => 2,
            OpPushData2 => 3,
            OpPushData4 => 5,
            _ => 1,
        };
        offset = checked_add(offset, checked_add(prefix, op.len())?)?;
    }
    Ok(result)
}

/// The stack an entrypoint body starts from: its flattened arguments (deepest
/// first) followed by the contract's flattened state fields.
pub(super) struct EntrypointInputs {
    pub(super) params: Vec<Value>,
    pub(super) state: Vec<Value>,
}

/// Script units the dispatcher charges before the body of the entrypoint at
/// `index` runs. Each preceding entrypoint duplicates the caller's tag for a
/// failed comparison, and the matching comparison pushes one byte.
fn dispatch_script_units(index: usize) -> Result<u64, CompilerError> {
    let tag_len = std::mem::size_of::<DispatchTag>() as u64;
    checked_add(checked_mul(tag_len, checked_add(index as u64, 1)?)?, 1)
}

/// Script units the pay-to-script-hash output script charges before the
/// redeem script runs: it hashes the pushed redeem script with BLAKE2b, pushes
/// the digest, and compares it with the expected hash.
fn p2sh_wrapper_script_units() -> Result<Linear, CompilerError> {
    Linear::symbol(Symbol::RedeemScript)
        .mul_constant(BLAKE2B_SCRIPT_UNITS_PER_BYTE)?
        .add_constant((HASH_LEN + BOOL_ENCODED_LEN) as i64)
}

/// Check that every entrypoint body and the state initializer stay within the
/// consensus stack limit, and bound the script units each entrypoint charges.
///
/// The returned estimate for an entrypoint covers the pay-to-script-hash
/// wrapper, the state initializer, its dispatch, and its body along the most
/// expensive path. It is None for an entrypoint whose cost could not be bounded.
pub(super) fn analyze_entrypoints(
    compiled_entrypoints: &[(String, Vec<u8>)],
    entrypoints: &[&FunctionAst<'_>],
    inputs: &BTreeMap<String, EntrypointInputs>,
    state_push_bytecode: &[u8],
) -> Result<BTreeMap<String, Option<ComputeEstimateArtifact>>, CompilerError> {
    // Variable-size state initializers can emit expressions, not just one push
    // per field. Check their temporaries while the caller's tag is saved on alt.
    // The surrounding TOALTSTACK/FROMALTSTACK only move that item between stacks.
    let state_charges = if state_push_bytecode.is_empty() {
        Some(Charges::default())
    } else {
        let largest = entrypoints.iter().max_by_key(|function| function.params.len()).expect("contract has entrypoints");
        let initial = Stack::new(largest.params.len(), 1, &Location { function: &largest.name, offset: 0 })?;
        Charges::of(analyze(&instructions(state_push_bytecode)?, &largest.name, initial)?)
    };

    let mut estimates = BTreeMap::new();
    for (index, (name, bytecode)) in compiled_entrypoints.iter().enumerate() {
        let inputs = inputs.get(name).expect("body has entrypoint inputs");
        let mut main = inputs.params.clone();
        main.extend(inputs.state.iter().cloned());
        let initial = Stack::from_values(main, Vec::new(), &Location { function: name, offset: 0 })?;
        let body_charges = Charges::of(analyze(&instructions(bytecode)?, name, initial)?);
        let estimate = match (&state_charges, body_charges) {
            (Some(state), Some(body)) => {
                let units = p2sh_wrapper_script_units()?
                    .add(&state.units)?
                    .add(&body.units)?
                    .add_constant(dispatch_script_units(index)? as i64)?;
                let sig_ops = checked_add(state.sig_ops, body.sig_ops)?;
                Some(estimate_artifact(&units, sig_ops)?)
            }
            _ => None,
        };
        estimates.insert(name.clone(), estimate);
    }
    Ok(estimates)
}

/// The units and signature operations charged along the most expensive
/// continuing path of a fragment.
#[derive(Default)]
struct Charges {
    units: Linear,
    sig_ops: u64,
}

impl Charges {
    /// None when the charges could not be bounded. A fragment without a
    /// continuing path never succeeds, so it charges nothing that matters.
    fn of(state: Option<Stack>) -> Option<Self> {
        match state {
            Some(state) => state.units().map(|units| Self { units: units.clone(), sig_ops: state.sig_ops() }),
            None => Some(Self::default()),
        }
    }
}

fn estimate_artifact(units: &Linear, sig_ops: u64) -> Result<ComputeEstimateArtifact, CompilerError> {
    let mut script_units_per_byte: BTreeMap<String, u64> = BTreeMap::new();
    for (symbol, coefficient) in units.terms() {
        // Lengths of inputs and outputs selected by unknown indices share one
        // key; a consumer bounds them with the largest such length.
        let entry = script_units_per_byte.entry(symbol.to_string()).or_insert(0);
        *entry = checked_add(*entry, *coefficient)?;
    }
    // A negative constant only arises from exact `length - k` terms; rounding it
    // up to zero keeps the estimate an upper bound.
    let script_units = u64::try_from(units.constant_part().max(0)).expect("nonnegative");
    Ok(ComputeEstimateArtifact { script_units, script_units_per_byte, sig_ops })
}

/// Check that a bytecode fragment never needs more than MAX_STACK_SIZE items
/// across the main and alternate stacks, and meter its paths. Walk the bytecode
/// in order and simulate each opcode's pushes, pops, moves, and charges with
/// `step`. The checked `Stack` operations reject underflow and enforce the
/// combined size limit whenever items are added.
/// The caller supplies `initial`: arguments + state fields on main and empty alt
/// for a body, or arguments on main and the saved dispatch tag on alt for state
/// initialization.
/// An unknown value still occupies one stack slot.
/// We keep small literal values only to determine stack indices and ZK arg counts.
///
/// `current` holds the simulated stacks for the path being checked. For every
/// contract IF/NOTIF, check BOTH paths without evaluating the condition:
///
/// - IF: pop the condition, save a copy of the stacks in `else_entry`, and keep
///   walking through the then branch using `current`.
/// - ELSE: save the then branch's resulting stacks in `then_exit`. Restore
///   `else_entry` as `current`, so the else branch starts from the stacks at IF,
///   not from whatever the then branch left behind.
/// - ENDIF: merge the two results into `current` and continue after the conditional.
///   Both paths must leave the same number of items on each stack. Keep a known
///   value only if both paths agree; otherwise keep a common length bound. Without
///   an ELSE, the other result is the saved state at IF (the branch that does nothing).
///
/// For example, starting with main stack [x, condition], `IF PUSH 1 ELSE PUSH 2
/// ENDIF` checks [x, 1] and [x, 2] separately, then continues with [x, ≤1 byte].
/// Their stack sizes are never added together. `branches` holds one saved frame
/// per open IF, so nested conditionals follow the same process.
///
/// `current = None` means this path cannot continue, for example after RETURN.
/// Skip its ordinary opcodes, but still process IF/ELSE/ENDIF so another saved
/// path can resume. When merging, only paths that can continue contribute a state.
///
/// Returns the state of the continuing path, or None when no path continues.
fn analyze(instructions: &[Instruction], function: &str, initial: Stack) -> Result<Option<Stack>, CompilerError> {
    let mut current = Some(initial);
    let mut branches: Vec<Branch> = Vec::new();
    for instruction in instructions {
        let location = Location { function, offset: instruction.offset };
        match instruction.opcode {
            OpIf | OpNotIf => {
                let mut branch = Branch::default();
                if let Some(mut state) = current.take() {
                    state.pop(&location)?;
                    branch.else_entry = Some(state.clone());
                    current = Some(state);
                }
                branches.push(branch);
            }
            OpElse => {
                let branch = branches.last_mut().ok_or_else(|| location.error("ELSE without IF"))?;
                if branch.seen_else {
                    return Err(location.error("duplicate ELSE"));
                }
                branch.seen_else = true;
                branch.then_exit = current.take();
                current = branch.else_entry.take();
            }
            OpEndIf => {
                let branch = branches.pop().ok_or_else(|| location.error("ENDIF without IF"))?;
                current = Stack::join(current, if branch.seen_else { branch.then_exit } else { branch.else_entry }, &location)?;
            }
            OpReturn => current = None,
            _ => {
                if let Some(state) = &mut current {
                    step(state, instruction, &location)?;
                }
            }
        }
    }
    if !branches.is_empty() {
        return Err(Location { function, offset: instructions.last().map_or(0, |i| i.offset) }.error("unterminated IF"));
    }
    Ok(current)
}

/// Update the simulated main and alternate stacks for one opcode, assuming that
/// opcode executes successfully, and charge what the VM meters for it. This
/// tracks which items it consumes, produces, copies, or moves, and the byte
/// length of every result; it does not run hashes or proof verification, and it
/// folds arithmetic only where the operands are known linear forms.
/// For example, ADD changes [x, y] into [≤8 bytes], while DUP changes [x] into
/// [x, x] and charges the bytes of x.
///
/// Pushes and stack rearrangements preserve known values so later instructions
/// can use them as stack indices or argument counts. Instructions whose effect
/// depends on an operand, such as PICK/ROLL or a ZK precompile, require the
/// relevant index, tag, or count to be known.
///
/// Return an error if an operand is missing, an opcode is unmodeled, or its stack
/// effect cannot be determined. `at` supplies the entrypoint and byte offset for
/// diagnostics. On error, `state` may already be partly updated; analysis stops.
/// All stack access goes through `Stack`, which checks operands and combined
/// capacity and meters pushed bytes. The caller, `analyze`, handles IF/ELSE/ENDIF
/// and RETURN.
fn step(state: &mut Stack, instruction: &Instruction, at: &Location<'_>) -> Result<(), CompilerError> {
    let op = instruction.opcode;
    match op {
        // Literal bytes are paid for in the script size, so the VM does not meter them.
        Op0..=OpPushData4 | Op1Negate | Op1..=Op16 => state.push_unmetered(instruction.literal.clone(), at)?,
        OpNop => {}
        // Pure moves between the stacks are not metered.
        OpToAltStack => state.move_to_alt(at)?,
        OpFromAltStack => state.move_from_alt(at)?,
        OpDepth => state.push(Value::number(i64::try_from(state.main_len()).map_err(|_| at.error("stack depth exceeds i64"))?), at)?,
        OpSize => {
            let size = match state.peek(0, at)?.exact_len() {
                Some(len) => Value::length(len),
                None => Value::bounded(Linear::constant(LENGTH_ENCODED_LEN as i64)),
            };
            state.push(size, at)?;
        }
        OpDup | Op2Dup | Op3Dup | OpOver | Op2Over => {
            let (depth, count) = match op {
                OpDup => (1, 1),
                Op2Dup => (2, 2),
                Op3Dup => (3, 3),
                OpOver => (2, 1),
                _ => (4, 2),
            };
            state.extend_from_within(depth, count, at)?;
        }
        OpRot | Op2Rot | OpSwap | Op2Swap => {
            let (count, shift) = match op {
                OpRot => (3, 1),
                Op2Rot => (6, 2),
                OpSwap => (2, 1),
                _ => (4, 2),
            };
            state.rotate_left(count, shift, at)?;
        }
        OpTuck => {
            let value = state.peek(0, at)?.clone();
            state.insert(2, value, at)?;
        }
        OpNip => {
            state.remove(1, at)?;
        }
        OpPick => {
            let depth = state.pop_count(at)?;
            let value = state.peek(depth, at)?.clone();
            state.push(value, at)?;
        }
        OpRoll => {
            // The VM rotates the item into place without copying it.
            let depth = state.pop_count(at)?;
            let value = state.remove(depth, at)?;
            state.push_unmetered(value, at)?;
        }
        OpZkPrecompile => {
            let tag = match state.pop(at)? {
                Value::Bytes(bytes) if bytes.len() == 1 => ZkTag::try_from(bytes[0]).ok(),
                _ => None,
            }
            .ok_or_else(|| at.error("ZK precompile tag is unknown or unsupported"))?;
            let count = match tag {
                ZkTag::Groth16 => {
                    state.pop(at)?; // verification key
                    state.pop(at)?; // proof
                    let public_inputs = state.pop_count(at)?; // public input count
                    // The verifier charges for every gamma_abc_g1 element of the key: one per public input plus one.
                    let elements = checked_add(public_inputs as u64, 1)?;
                    state.charge_constant(checked_mul(elements, GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS)?)?;
                    public_inputs
                }
                ZkTag::R0Succinct => 8,
            };
            state.charge_constant(tag.cost().0)?;
            state.drop_items(count, at)?;
            state.push(Value::number(1), at)?;
        }
        OpCat => {
            let b = state.pop(at)?;
            let a = state.pop(at)?;
            let value = match (a.len_bound(), b.len_bound()) {
                (Some(la), Some(lb)) => {
                    Value::Sized { bound: la.add(&lb)?, exact: a.exact_len().is_some() && b.exact_len().is_some() }
                }
                _ => Value::Unknown,
            };
            state.push(value, at)?;
        }
        OpSubstr => {
            let end = state.pop(at)?;
            let start = state.pop(at)?;
            let data = state.pop(at)?;
            state.push(substring(&data, &start, &end), at)?;
        }
        OpNum2Bin => {
            let size = state.pop(at)?;
            state.pop(at)?; // number
            let value = match size.as_i64() {
                Some(size @ 0..=8) => Value::exact(Linear::constant(size)),
                _ => Value::unknown_number(),
            };
            state.push(value, at)?;
        }
        OpBin2Num => {
            let value = state.pop(at)?;
            state
                .push(value.as_number().map_or_else(Value::unknown_number, |number| Value::numeric(number, NUMBER_ENCODED_LEN)), at)?;
        }
        OpSHA256 | OpBlake2b | OpBlake3 => {
            let data = state.pop(at)?;
            state.charge_per_byte(&data, hash_script_units_per_byte(op))?;
            state.push(Value::exact(Linear::constant(HASH_LEN as i64)), at)?;
        }
        OpBlake2bWithKey | OpBlake3WithKey => {
            state.pop(at)?; // key
            let data = state.pop(at)?;
            state.charge_per_byte(&data, hash_script_units_per_byte(op))?;
            state.push(Value::exact(Linear::constant(HASH_LEN as i64)), at)?;
        }
        OpInvert => {
            let data = state.pop(at)?;
            let value = match (data.exact_len(), data.len_bound()) {
                (Some(len), _) => Value::exact(len),
                (None, Some(bound)) => Value::bounded(bound),
                (None, None) => Value::Unknown,
            };
            state.push(value, at)?;
        }
        OpAnd | OpOr | OpXor => {
            // The VM requires operands of equal length; the result has that length.
            let b = state.pop(at)?;
            let a = state.pop(at)?;
            let value = match (a.exact_len(), b.exact_len(), a.len_bound(), b.len_bound()) {
                (Some(len), Some(_), _, _) => Value::exact(len),
                (_, _, Some(la), Some(lb)) => Value::bounded(la.max(&lb)),
                _ => Value::Unknown,
            };
            state.push(value, at)?;
        }
        OpAdd | OpSub | OpMul | OpDiv | OpMod | OpMin | OpMax => {
            let b = state.pop(at)?;
            let a = state.pop(at)?;
            state.push(fold_binary(op, &a, &b)?, at)?;
        }
        Op1Add | Op1Sub | OpNegate | OpAbs => {
            let a = state.pop(at)?;
            state.push(fold_unary(op, &a)?, at)?;
        }
        OpNot | Op0NotEqual => state.apply_effect(1, vec![Value::unknown_bool()], at)?,
        OpEqual | OpNumEqual | OpNumNotEqual | OpLessThan | OpGreaterThan | OpLessThanOrEqual | OpGreaterThanOrEqual | OpBoolAnd
        | OpBoolOr => state.apply_effect(2, vec![Value::unknown_bool()], at)?,
        OpWithin => state.apply_effect(3, vec![Value::unknown_bool()], at)?,
        // Effects are those of the pinned Kaspa VM, on successful execution.
        // In particular its CLTV/CSV consume their operands.
        OpDrop | OpVerify | OpCheckLockTimeVerify | OpCheckSequenceVerify => state.drop_items(1, at)?,
        Op2Drop | OpEqualVerify | OpNumEqualVerify => state.drop_items(2, at)?,
        OpCheckSig | OpCheckSigECDSA => {
            state.charge_sig_ops(1, SIG_OP_SCRIPT_UNITS)?;
            state.apply_effect(2, vec![Value::unknown_bool()], at)?;
        }
        OpCheckSigVerify => {
            // The VM runs CHECKSIG, which pushes the (necessarily true) result, then pops it.
            state.charge_sig_ops(1, SIG_OP_SCRIPT_UNITS)?;
            state.charge_constant(BOOL_ENCODED_LEN)?;
            state.drop_items(2, at)?;
        }
        OpCheckSigFromStack | OpCheckSigFromStackECDSA => {
            state.charge_sig_ops(1, SIG_OP_SCRIPT_UNITS)?;
            state.apply_effect(3, vec![Value::unknown_bool()], at)?;
        }
        // Transaction introspection. Numbers other than lengths have unknown values.
        OpTxInputIndex => state.push(Value::numeric(Linear::symbol(Symbol::ActiveInputIndex), NUMBER_ENCODED_LEN), at)?,
        OpTxVersion | OpTxInputCount | OpTxOutputCount | OpTxLockTime | OpTxGas => state.push(Value::unknown_number(), at)?,
        OpTxSubnetId => state.push(Value::exact(Linear::constant(SUBNETWORK_ID_LEN as i64)), at)?,
        OpTxPayloadLen => state.push(Value::length(introspection(IntrospectionSource::Payload, IndexKey::None)), at)?,
        OpTxPayloadSubstr => {
            let end = state.pop(at)?;
            let start = state.pop(at)?;
            let source = Value::exact(introspection(IntrospectionSource::Payload, IndexKey::None));
            state.push(substring(&source, &start, &end), at)?;
        }
        OpOutpointIndex
        | OpTxInputSeq
        | OpTxInputAmount
        | OpTxInputDaaScore
        | OpTxOutputAmount
        | OpAuthOutputCount
        | OpCovInputCount
        | OpCovOutputCount
        | OpOutputAuthorizingInput => state.apply_effect(1, vec![Value::unknown_number()], at)?,
        OpTxInputIsCoinbase => state.apply_effect(1, vec![Value::unknown_bool()], at)?,
        OpOutpointTxId | OpInputCovenantId | OpOutputCovenantId | OpChainblockSeqCommit => {
            state.apply_effect(1, vec![Value::exact(Linear::constant(HASH_LEN as i64))], at)?
        }
        OpAuthOutputIdx | OpCovInputIdx | OpCovOutputIdx => state.apply_effect(2, vec![Value::unknown_number()], at)?,
        OpTxInputSpk | OpTxOutputSpk | OpTxInputSpkLen | OpTxOutputSpkLen | OpTxInputScriptSigLen => {
            let index = state.pop(at)?;
            let key = index_key(state, &index)?;
            let source = introspection(introspection_source(op), key);
            let value = match op {
                OpTxInputSpk | OpTxOutputSpk => Value::exact(source),
                _ => Value::length(source),
            };
            state.push(value, at)?;
        }
        OpTxInputScriptSigSubstr | OpTxInputSpkSubstr | OpTxOutputSpkSubstr => {
            let end = state.pop(at)?;
            let start = state.pop(at)?;
            let index = state.pop(at)?;
            let key = index_key(state, &index)?;
            let source = Value::exact(introspection(introspection_source(op), key));
            state.push(substring(&source, &start, &end), at)?;
        }
        // Reject new or variable-arity opcodes until explicitly modeled; never assume zero.
        _ => return Err(at.error(format!("unmodeled opcode 0x{op:02x}"))),
    }
    Ok(())
}

fn hash_script_units_per_byte(op: u8) -> u64 {
    match op {
        OpSHA256 => SHA256_SCRIPT_UNITS_PER_BYTE,
        OpBlake2b | OpBlake2bWithKey => BLAKE2B_SCRIPT_UNITS_PER_BYTE,
        OpBlake3 | OpBlake3WithKey => BLAKE3_SCRIPT_UNITS_PER_BYTE,
        _ => unreachable!("not a hash opcode"),
    }
}

fn introspection_source(op: u8) -> IntrospectionSource {
    match op {
        OpTxInputScriptSigLen | OpTxInputScriptSigSubstr => IntrospectionSource::SignatureScript,
        OpTxInputSpk | OpTxInputSpkLen | OpTxInputSpkSubstr => IntrospectionSource::InputScriptPublicKey,
        OpTxOutputSpk | OpTxOutputSpkLen | OpTxOutputSpkSubstr => IntrospectionSource::OutputScriptPublicKey,
        _ => unreachable!("not an indexed introspection opcode"),
    }
}

fn introspection(source: IntrospectionSource, index: IndexKey) -> Linear {
    Linear::symbol(Symbol::Introspection { source, index })
}

/// Identify the input or output an introspection opcode reads, so two reads of
/// the same field resolve to the same length symbol.
fn index_key(state: &mut Stack, index: &Value) -> Result<IndexKey, CompilerError> {
    if let Some(literal) = index.as_i64() {
        return Ok(IndexKey::Literal(literal));
    }
    if let Value::Num { value, .. } = index
        && value.as_symbol() == Some(&Symbol::ActiveInputIndex)
    {
        return Ok(IndexKey::ActiveInput);
    }
    state.opaque_index()
}

/// The result of `source[start..end]`. Its length is exactly `end - start` when
/// both bounds are known; otherwise it is bounded by the source, since the VM
/// rejects a range past the end of the source.
fn substring(source: &Value, start: &Value, end: &Value) -> Value {
    if let (Some(start), Some(end)) = (start.as_number(), end.as_number())
        && let Some(len) = end.checked_sub(&start)
    {
        return Value::exact(len);
    }
    match source.len_bound() {
        Some(bound) => Value::bounded(bound),
        None => Value::Unknown,
    }
}

/// Fold a binary arithmetic result when the operands are known, so the values
/// can serve as later substring bounds or stack indices.
fn fold_binary(op: u8, a: &Value, b: &Value) -> Result<Value, CompilerError> {
    if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
        let folded = match op {
            OpAdd => a.checked_add(b),
            OpSub => a.checked_sub(b),
            OpMul => a.checked_mul(b),
            OpDiv => a.checked_div(b),
            OpMod => a.checked_rem(b),
            OpMin => Some(a.min(b)),
            OpMax => Some(a.max(b)),
            _ => unreachable!("not a binary arithmetic opcode"),
        };
        return Ok(folded
            .and_then(|number| serialize_i64(number, None).ok())
            .map_or_else(Value::unknown_number, |bytes| Value::Bytes(bytes.to_vec())));
    }
    let (Some(a), Some(b)) = (a.as_number(), b.as_number()) else { return Ok(Value::unknown_number()) };
    let folded = match op {
        OpAdd => Some(a.add(&b)?),
        OpSub => a.checked_sub(&b),
        OpMul => match (
            a.as_constant().and_then(|factor| u64::try_from(factor).ok()),
            b.as_constant().and_then(|factor| u64::try_from(factor).ok()),
        ) {
            (Some(factor), _) => Some(b.mul_constant(factor)?),
            (_, Some(factor)) => Some(a.mul_constant(factor)?),
            _ => None,
        },
        _ => None,
    };
    Ok(folded.map_or_else(Value::unknown_number, |number| Value::numeric(number, NUMBER_ENCODED_LEN)))
}

fn fold_unary(op: u8, a: &Value) -> Result<Value, CompilerError> {
    if let Some(a) = a.as_i64() {
        let folded = match op {
            Op1Add => a.checked_add(1),
            Op1Sub => a.checked_sub(1),
            OpNegate => a.checked_neg(),
            OpAbs => a.checked_abs(),
            _ => unreachable!("not a unary arithmetic opcode"),
        };
        return Ok(folded
            .and_then(|number| serialize_i64(number, None).ok())
            .map_or_else(Value::unknown_number, |bytes| Value::Bytes(bytes.to_vec())));
    }
    let Some(a) = a.as_number() else { return Ok(Value::unknown_number()) };
    let folded = match op {
        Op1Add => Some(a.add_constant(1)?),
        Op1Sub => a.checked_sub(&Linear::constant(1)),
        _ => None,
    };
    Ok(folded.map_or_else(Value::unknown_number, |number| Value::numeric(number, NUMBER_ENCODED_LEN)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::{EngineFlags, TxScriptEngine, caches::Cache};

    fn check(script: &[u8], params: usize) -> Result<Option<Stack>, CompilerError> {
        let initial = Stack::new(checked_add(params, 1)?, 0, &Location { function: "test", offset: 0 })?;
        analyze(&instructions(script)?, "test", initial)
    }

    fn overflow(error: CompilerError) {
        assert!(matches!(error, CompilerError::BytecodeStackTooLarge { actual: 245, maximum: 244, .. }), "{error}");
    }

    fn check_with_vm(script: &[u8], fits: bool) {
        let analysis = check(script, 0);
        let mut builder = ScriptBuilder::new();
        builder.add_data(&[1, 2, 3, 4]).unwrap();
        builder.add_ops(script).unwrap();
        let script = builder.drain();
        let reused = SigHashReusedValuesUnsync::new();
        let cache = Cache::new(128);
        let execution = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
            &script,
            &reused,
            &cache,
            EngineFlags { covenants_enabled: true, ..Default::default() },
        )
        .execute_and_return_stacks();
        if fits {
            analysis.unwrap();
            execution.unwrap();
        } else {
            overflow(analysis.unwrap_err());
            assert!(matches!(execution, Err(kaspa_txscript_errors::TxScriptError::StackSizeExceeded(245, 244))));
        }
    }

    #[test]
    fn step_rejects_stack_growth_without_analyze() {
        let at = Location { function: "test", offset: 42 };
        for (opcode, main_items) in [
            (Op1, 243),
            (OpDup, 243),
            (OpOver, 243),
            (Op2Dup, 242),
            (Op2Over, 242),
            (Op3Dup, 241),
            (OpTuck, 243),
            (OpDepth, 243),
            (OpSize, 243),
            (OpTxVersion, 243),
        ] {
            let mut stack = Stack::new(main_items, 1, &at).unwrap();
            let instruction = Instruction { opcode, offset: 42, literal: Value::number(1) };
            let error = step(&mut stack, &instruction, &at).unwrap_err();
            assert!(
                matches!(error, CompilerError::BytecodeStackTooLarge { offset: 42, actual: 245, maximum: 244, .. }),
                "opcode 0x{opcode:02x}: {error}"
            );
        }
    }

    #[test]
    fn compiled_body_check_reports_body_relative_offsets() {
        let contract = crate::ast::parse_contract_ast("contract Test() { entry main() {} }").unwrap();
        let mut body = vec![Op1; 244];
        body.push(OpDup);
        let inputs = BTreeMap::from([("main".to_string(), EntrypointInputs { params: Vec::new(), state: Vec::new() })]);
        let error = analyze_entrypoints(&[("main".into(), body)], &[&contract.functions[0]], &inputs, &[]).unwrap_err();
        assert!(matches!(error, CompilerError::BytecodeStackTooLarge { offset: 244, actual: 245, maximum: 244, .. }), "{error}");
    }

    #[test]
    fn combined_stack_boundary_and_temporary_indices() {
        for op in [OpPick, OpRoll] {
            for count in [243, 244] {
                let mut script = vec![OpDrop]; // initial ABI tag
                script.extend(std::iter::repeat_n(Op1, count));
                script.extend([Op1, op]);
                check_with_vm(&script, count == 243);
            }
        }
        let mut script = vec![OpDrop];
        script.extend(std::iter::repeat_n(Op1, 244));
        script.extend(std::iter::repeat_n(OpToAltStack, 120));
        check_with_vm(&script, true);
        script.push(Op1);
        check_with_vm(&script, false);
        script.pop();
        script.extend(std::iter::repeat_n(OpFromAltStack, 120));
        check_with_vm(&script, true);
        script.push(OpDup);
        check_with_vm(&script, false);
    }

    #[test]
    fn branches_check_each_peak_without_adding_mutually_exclusive_paths() {
        for (then_count, else_count) in [(244, 244), (245, 0), (0, 245)] {
            let mut script = vec![OpDrop, OpIf]; // unknown ABI bool
            script.extend(std::iter::repeat_n(Op1, then_count));
            script.extend(std::iter::repeat_n(OpDrop, then_count));
            script.push(OpElse);
            script.extend(std::iter::repeat_n(Op1, else_count));
            script.extend(std::iter::repeat_n(OpDrop, else_count));
            script.push(OpEndIf);
            if then_count == 244 {
                check(&script, 1).unwrap();
            } else {
                overflow(check(&script, 1).unwrap_err());
            }
        }
    }

    #[test]
    fn branch_joins_preserve_heights_but_forget_differing_constants() {
        for script in [vec![OpDrop, OpIf, Op1, OpElse, OpEndIf], vec![OpDrop, OpIf, Op1, OpToAltStack, OpElse, Op1, OpEndIf]] {
            assert!(matches!(check(&script, 1), Err(CompilerError::BytecodeStackAnalysis { .. })));
        }
        let mut script = vec![OpDrop, OpIf, Op0, OpElse, Op1, OpEndIf, OpIf];
        script.extend(std::iter::repeat_n(Op1, 245));
        script.push(OpEndIf);
        overflow(check(&script, 1).unwrap_err());
    }

    #[test]
    fn literal_conditions_check_both_branches_and_return_terminates_paths() {
        for prefix in [vec![OpDrop, Op0, OpIf], vec![OpDrop, 1, 0x80, OpIf], vec![OpDrop, Op1, OpNotIf]] {
            let mut script = prefix;
            script.extend(std::iter::repeat_n(Op1, 245));
            script.extend([OpElse, Op1, OpEndIf]);
            overflow(check(&script, 0).unwrap_err());
        }
        let mut script = vec![OpDrop, Op1, OpIf, OpElse];
        script.extend(std::iter::repeat_n(Op1, 245));
        script.push(OpEndIf);
        overflow(check(&script, 0).unwrap_err());
        check(&[OpDrop, OpIf, OpReturn, OpElse, Op1, OpEndIf, OpDrop], 1).unwrap();
        let mut script = vec![OpDrop, OpReturn];
        script.extend(std::iter::repeat_n(Op1, 245));
        assert!(check(&script, 0).unwrap().is_none(), "a returning path does not continue");
    }

    #[test]
    fn malformed_or_unmodeled_stack_effects_are_errors() {
        for script in [
            vec![OpDrop, OpDrop, OpDrop],
            vec![OpDrop, OpFromAltStack],
            vec![OpDrop, OpElse],
            vec![OpDrop, OpEndIf],
            vec![OpDrop, Op1, OpIf],
            vec![OpDrop, Op1, OpIf, OpElse, OpElse, OpEndIf],
            vec![OpDrop, OpCheckMultiSig],
            vec![OpDrop, OpPick],
            vec![OpDrop, OpZkPrecompile],
            vec![OpPushData1],
        ] {
            assert!(matches!(check(&script, 1), Err(CompilerError::BytecodeStackAnalysis { .. })), "{script:?}");
        }
        // IFDUP is unmodeled regardless of whether its operand is known.
        for script in [vec![OpDrop, OpIfDup], vec![OpDrop, Op0, OpIfDup], vec![OpDrop, Op1, OpIfDup]] {
            let error = check(&script, 1).unwrap_err();
            assert!(matches!(error, CompilerError::BytecodeStackAnalysis { message, .. }
                if message == "unmodeled opcode 0x73"));
        }
    }

    #[test]
    fn zk_argument_counts_and_saved_values_are_tracked() {
        for tag in [ZkTag::Groth16, ZkTag::R0Succinct] {
            let mut script = vec![OpDrop];
            match tag {
                ZkTag::Groth16 => {
                    // Save/restore the proof as the SDK's generated verifier does.
                    script.extend([Op0, OpToAltStack, Op0, Op0, Op2, OpFromAltStack, Op0]);
                }
                ZkTag::R0Succinct => script.extend(std::iter::repeat_n(Op0, 8)),
            }
            script.extend([1, tag as u8, OpZkPrecompile]);
            script.extend(std::iter::repeat_n(Op1, 243));
            check(&script, 0).unwrap();
            script.push(Op1);
            overflow(check(&script, 0).unwrap_err());
        }
        // Unknown public-input count must not silently use a default effect.
        assert!(matches!(
            check(&[OpDrop, Op0, Op0, 1, ZkTag::Groth16 as u8, OpZkPrecompile], 1),
            Err(CompilerError::BytecodeStackAnalysis { .. })
        ));
    }

    #[test]
    fn stack_manipulation_values_match_the_vm() {
        // Distinct constants make incorrect shuffle order visible, including
        // errors that would later misidentify a dispatch tag or ZK count.
        for ops in [
            vec![OpDup],
            vec![Op2Dup],
            vec![Op3Dup],
            vec![OpOver],
            vec![Op2Over],
            vec![OpRot],
            vec![Op2Rot],
            vec![OpSwap],
            vec![Op2Swap],
            vec![OpTuck],
            vec![OpNip],
            vec![OpDrop],
            vec![Op2Drop],
            vec![Op2, OpPick],
            vec![Op2, OpRoll],
            vec![OpToAltStack, OpSwap, OpFromAltStack],
            vec![OpDepth],
            vec![OpSize],
            vec![OpAdd],
            vec![OpSub],
            vec![OpMul],
            vec![OpDiv],
            vec![OpMod],
            vec![OpMin],
            vec![OpMax],
            vec![Op1Add],
            vec![Op1Sub],
            vec![OpNegate],
            vec![OpNegate, OpAbs],
            vec![OpBin2Num],
        ] {
            let mut builder = ScriptBuilder::new();
            for number in 1..=6 {
                builder.add_i64(number).unwrap();
            }
            builder.add_ops(&ops).unwrap();
            let script = builder.drain();
            let mut state = Stack::new(0, 0, &Location { function: "test", offset: 0 }).unwrap();
            for instruction in instructions(&script).unwrap() {
                step(&mut state, &instruction, &Location { function: "test", offset: instruction.offset }).unwrap();
            }
            let reused = SigHashReusedValuesUnsync::new();
            let cache = Cache::new(128);
            let stacks = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
                &script,
                &reused,
                &cache,
                EngineFlags { covenants_enabled: true, ..Default::default() },
            )
            .execute_and_return_stacks()
            .unwrap();
            let expected: Vec<Value> = stacks.dstack.iter().map(|entry| Value::literal(entry)).collect();
            assert_eq!(state.main_values(), expected, "opcodes: {ops:?}");
            assert_eq!(state.alt_len(), 0);
        }
    }

    #[test]
    fn pushdata_offsets_include_length_prefixes() {
        let script = [OpPushData1, 1, 7, OpPushData2, 1, 0, 8, OpPushData4, 1, 0, 0, 0, 9, OpDup];
        let parsed = instructions(&script).unwrap();
        assert_eq!(parsed.iter().map(|op| op.offset).collect::<Vec<_>>(), [0, 3, 7, 13]);
    }

    /// Run `ops` after pushing `literals`, and return the VM's charged units next
    /// to the analyzer's bound for the same fragment.
    fn charged_units(literals: &[&[u8]], ops: &[u8]) -> (u64, Option<Linear>, Vec<Value>) {
        let mut builder = ScriptBuilder::new();
        for literal in literals {
            builder.add_data(literal).unwrap();
        }
        builder.add_ops(ops).unwrap();
        let script = builder.drain();
        let mut state = Stack::new(0, 0, &Location { function: "test", offset: 0 }).unwrap();
        for instruction in instructions(&script).unwrap() {
            step(&mut state, &instruction, &Location { function: "test", offset: instruction.offset }).unwrap();
        }
        let reused = SigHashReusedValuesUnsync::new();
        let cache = Cache::new(128);
        let mut vm = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
            &script,
            &reused,
            &cache,
            EngineFlags { covenants_enabled: true, ..Default::default() },
        );
        vm.execute().unwrap();
        (vm.used_script_units().0, state.units().cloned(), state.main_values().to_vec())
    }

    #[test]
    fn metered_bytes_match_the_vm_for_known_sizes() {
        let big = vec![7u8; 300];
        type Case<'a> = (Vec<&'a [u8]>, Vec<u8>, u64);
        let cases: Vec<Case<'_>> = vec![
            // Literal pushes, moves, rolls, and drops are free.
            (vec![&big, &[1], &[2]], vec![OpToAltStack, OpFromAltStack, OpSwap, OpRot, OpDrop, OpDrop, OpDrop, Op1], 0),
            (vec![&big, &[1]], vec![Op1, OpRoll, OpDrop], 0),
            // Copies charge the copied bytes.
            (vec![&big], vec![OpDup, OpDrop, OpDrop, Op1], 300),
            (vec![&big, &[1]], vec![Op1, OpPick, OpDrop, Op2Drop, Op1], 300),
            (vec![&big, &[1]], vec![Op2Dup, Op2Drop, Op2Drop, Op1], 301),
            (vec![&big, &[1]], vec![OpOver, OpDrop, Op2Drop, Op1], 300),
            (vec![&big, &[1]], vec![OpTuck, OpDrop, Op2Drop, Op1], 1),
            // Results charge their bytes: concatenation, sizes, hashes, numbers, and booleans.
            (vec![&big, &[1, 2]], vec![OpCat, OpDrop, Op1], 302),
            (vec![&big], vec![OpSize, OpDrop, OpDrop, Op1], 2),
            (vec![&big], vec![OpSHA256, OpDrop, Op1], 332),
            (vec![&big], vec![OpBlake2b, OpDrop, Op1], 632),
            (vec![&big], vec![OpBlake3, OpDrop, Op1], 332),
            (vec![&big, &[9; 32]], vec![OpBlake3WithKey, OpDrop, Op1], 332),
            (vec![&[100], &[100]], vec![OpAdd, OpDrop, Op1], 2),
            (vec![&[100], &[100]], vec![OpEqual], 1),
            (vec![&[7]], vec![Op4, OpNum2Bin, OpDrop, Op1], 4),
            (vec![&big, &[10], &[20]], vec![OpSubstr, OpDrop, Op1], 10),
        ];
        for (literals, ops, expected) in cases {
            let (vm_units, bound, _) = charged_units(&literals, &ops);
            assert_eq!(vm_units, expected, "VM units for {ops:?}");
            assert_eq!(bound, Some(Linear::constant(expected as i64)), "analyzer bound for {ops:?}");
        }
    }

    #[test]
    fn unknown_results_are_bounded_not_exact() {
        for (literals, ops, expected_vm, expected_bound) in [
            // A boolean result is one byte at most, and a script number eight.
            (vec![&[100][..], &[100][..]], vec![OpNumEqual], 1, BOOL_ENCODED_LEN),
            (vec![&[1][..], &[2][..]], vec![OpLessThan], 1, BOOL_ENCODED_LEN),
            // A false result is empty, but the bound still allows one byte.
            (vec![&[100][..], &[101][..]], vec![OpEqual, OpNot], 1, 2 * BOOL_ENCODED_LEN),
            (vec![&[7][..]], vec![OpBin2Num], 1, 1),
        ] {
            let (vm_units, bound, _) = charged_units(&literals, &ops);
            assert_eq!(vm_units, expected_vm);
            assert_eq!(bound, Some(Linear::constant(expected_bound as i64)), "{ops:?}");
        }
        // A substring with unknown bounds keeps the source's length as its bound.
        let at = Location { function: "test", offset: 0 };
        let mut state = Stack::from_values(
            vec![Value::exact(Linear::constant(50)), Value::unknown_number(), Value::unknown_number()],
            vec![],
            &at,
        )
        .unwrap();
        step(&mut state, &Instruction { opcode: OpSubstr, offset: 0, literal: Value::Unknown }, &at).unwrap();
        assert_eq!(state.main_values(), [Value::bounded(Linear::constant(50))]);
        assert_eq!(state.units(), Some(&Linear::constant(50)));
    }

    #[test]
    fn symbolic_lengths_flow_through_copies_splits_and_hashes() {
        let seal = Symbol::Named("seal".to_string());
        let at = Location { function: "test", offset: 0 };
        let run = |ops: &[u8], main: Vec<Value>| {
            let state = Stack::from_values(main, vec![], &at).unwrap();
            analyze(&instructions(ops).unwrap(), "test", state).unwrap().expect("the path continues")
        };
        let exact_seal = || Value::exact(Linear::symbol(seal.clone()));

        // Two copies of a variable-length argument cost twice its length.
        let state = run(&[OpDup, OpDrop, Op0, OpPick], vec![exact_seal()]);
        assert_eq!(state.units(), Some(&Linear::symbol(seal.clone()).mul_constant(2).unwrap()));

        // Hashing charges per byte, and the digest is 32 bytes.
        let state = run(&[OpBlake2b], vec![exact_seal()]);
        assert_eq!(state.units(), Some(&Linear::symbol(seal.clone()).mul_constant(2).unwrap().add_constant(32).unwrap()));
        assert_eq!(state.main_values(), [Value::exact(Linear::constant(32))]);

        // `x.split(4)`: SIZE yields the exact symbolic length, so the right part is `len - 4`.
        let state = run(&[OpSize, Op4, OpSwap, OpSubstr], vec![exact_seal()]);
        let right = Linear::symbol(seal.clone()).checked_sub(&Linear::constant(4)).unwrap();
        assert_eq!(state.main_values(), [Value::exact(right.clone())]);
        assert_eq!(state.units(), Some(&right.add_constant(LENGTH_ENCODED_LEN as i64).unwrap()));

        // Concatenating a symbolic and a literal value sums their lengths exactly.
        let state = run(&[OpCat, OpSize], vec![exact_seal(), Value::literal(&[1; 10])]);
        let total = Linear::symbol(seal.clone()).add_constant(10).unwrap();
        assert_eq!(state.main_values(), [Value::exact(total.clone()), Value::length(total.clone())]);
        assert_eq!(state.units(), Some(&total.add_constant(LENGTH_ENCODED_LEN as i64).unwrap()));

        // Joining branches keeps the larger bound of each item and the larger charge.
        let state = run(&[OpIf, OpDup, OpDrop, OpElse, Op1, OpDrop, OpEndIf], vec![exact_seal(), Value::number(1)]);
        assert_eq!(state.units(), Some(&Linear::symbol(seal.clone())));
        assert_eq!(state.main_values(), [exact_seal()]);
        let state = run(&[OpIf, OpDrop, Op0, OpElse, OpEndIf], vec![exact_seal(), Value::number(1)]);
        assert_eq!(state.main_values(), [Value::bounded(Linear::symbol(seal.clone()))]);
    }

    #[test]
    fn introspection_lengths_resolve_to_the_same_field() {
        let at = Location { function: "test", offset: 0 };
        let run = |ops: &[u8]| {
            let mut state = Stack::from_values(vec![], vec![], &at).unwrap();
            for instruction in instructions(ops).unwrap() {
                step(&mut state, &instruction, &Location { function: "test", offset: instruction.offset }).unwrap();
            }
            state
        };
        let sig_script = |index| Linear::symbol(Symbol::Introspection { source: IntrospectionSource::SignatureScript, index });

        // `tx.inputs[this.activeInputIndex].sigScript` as the compiler emits it:
        // the substring spans the whole script of the same input.
        let state = run(&[OpTxInputIndex, OpDup, OpTxInputScriptSigLen, Op0, OpSwap, OpTxInputScriptSigSubstr]);
        assert_eq!(state.main_values(), [Value::exact(sig_script(IndexKey::ActiveInput))]);
        assert_eq!(
            state.units(),
            Some(
                &sig_script(IndexKey::ActiveInput)
                    .add_constant((NUMBER_ENCODED_LEN + NUMBER_ENCODED_LEN + LENGTH_ENCODED_LEN) as i64)
                    .unwrap()
            )
        );

        // A literal index names that input.
        let state = run(&[Op2, OpTxInputScriptSigLen]);
        assert_eq!(state.main_values(), [Value::length(sig_script(IndexKey::Literal(2)))]);

        // Unknown indices never resolve to the same field: two lengths of inputs
        // selected by unknown indices do not cancel.
        let state = run(&[OpTxInputCount, OpTxInputScriptSigLen, OpTxInputCount, OpTxInputScriptSigLen, OpSub]);
        assert_eq!(state.main_values(), [Value::unknown_number()]);
        let state = run(&[OpTxInputCount, OpTxInputScriptSigLen]);
        let [value] = state.main_values() else { panic!("one result") };
        let Value::Num { value, .. } = value else { panic!("symbolic length, got {value:?}") };
        assert!(matches!(value.as_symbol(), Some(Symbol::Introspection { index: IndexKey::Opaque(_), .. })));
        // A substring with an unknown start keeps the source's length as its bound.
        let state = run(&[Op1, OpTxInputCount, Op0, OpTxInputScriptSigSubstr]);
        assert_eq!(state.main_values(), [Value::bounded(sig_script(IndexKey::Literal(1)))]);

        // Payload and script public keys have their own symbols.
        let state = run(&[OpTxPayloadLen, Op0, OpSwap, OpTxPayloadSubstr, Op1, OpTxOutputSpk, OpCat]);
        let payload = Linear::symbol(Symbol::Introspection { source: IntrospectionSource::Payload, index: IndexKey::None });
        let spk =
            Linear::symbol(Symbol::Introspection { source: IntrospectionSource::OutputScriptPublicKey, index: IndexKey::Literal(1) });
        assert_eq!(state.main_values(), [Value::exact(payload.add(&spk).unwrap())]);
    }

    #[test]
    fn signature_and_proof_charges_match_the_vm_pricing() {
        let at = Location { function: "test", offset: 0 };
        let mut state =
            Stack::from_values(vec![Value::exact(Linear::constant(65)), Value::exact(Linear::constant(32))], vec![], &at).unwrap();
        step(&mut state, &Instruction { opcode: OpCheckSig, offset: 0, literal: Value::Unknown }, &at).unwrap();
        assert_eq!(state.sig_ops(), 1);
        assert_eq!(state.units(), Some(&Linear::constant((SIG_OP_SCRIPT_UNITS + BOOL_ENCODED_LEN) as i64)));
        assert_eq!(
            SIG_OP_SCRIPT_UNITS,
            EngineFlags::default().sigop_script_units.0,
            "the estimate prices sigops like the default engine"
        );

        let mut script = vec![Op0, Op0, Op0, Op0, Op0, Op0, Op0, Op0, 1, ZkTag::R0Succinct as u8, OpZkPrecompile];
        let mut state = Stack::from_values(vec![], vec![], &at).unwrap();
        for instruction in instructions(&script).unwrap() {
            step(&mut state, &instruction, &at).unwrap();
        }
        assert_eq!(state.units(), Some(&Linear::constant(ZkTag::R0Succinct.cost().0 as i64 + 1)));

        // Three public inputs, their count, the proof, and the verifying key.
        script = vec![Op0, Op0, Op0, Op3, Op0, Op0, 1, ZkTag::Groth16 as u8, OpZkPrecompile];
        let mut state = Stack::from_values(vec![], vec![], &at).unwrap();
        for instruction in instructions(&script).unwrap() {
            step(&mut state, &instruction, &at).unwrap();
        }
        assert_eq!(
            state.units(),
            Some(&Linear::constant((ZkTag::Groth16.cost().0 + 4 * GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS + 1) as i64))
        );
    }

    #[test]
    fn unbounded_values_make_the_charge_unbounded() {
        let at = Location { function: "test", offset: 0 };
        let mut state = Stack::new(1, 0, &at).unwrap();
        step(&mut state, &Instruction { opcode: OpDup, offset: 0, literal: Value::Unknown }, &at).unwrap();
        assert_eq!(state.units(), None);
        assert!(Charges::of(Some(state)).is_none());
        assert!(Charges::of(None).is_some_and(|charges| charges.units == Linear::default() && charges.sig_ops == 0));
    }

    #[test]
    fn dispatch_units_count_tag_copies_and_the_matching_comparison() {
        assert_eq!(dispatch_script_units(0).unwrap(), 5);
        assert_eq!(dispatch_script_units(1).unwrap(), 9);
        assert_eq!(dispatch_script_units(2).unwrap(), 13);
        assert_eq!(
            p2sh_wrapper_script_units().unwrap(),
            Linear::symbol(Symbol::RedeemScript).mul_constant(2).unwrap().add_constant(33).unwrap()
        );
    }

    #[test]
    fn estimate_artifact_merges_terms_by_display_name() {
        let opaque = |index| Symbol::Introspection { source: IntrospectionSource::SignatureScript, index: IndexKey::Opaque(index) };
        let units = Linear::constant(10)
            .add(&Linear::symbol(opaque(1)))
            .unwrap()
            .add(&Linear::symbol(opaque(2)).mul_constant(2).unwrap())
            .unwrap()
            .add(&Linear::symbol(Symbol::Named("seal".to_string())))
            .unwrap();
        let estimate = estimate_artifact(&units, 3).unwrap();
        assert_eq!(estimate.script_units, 10);
        assert_eq!(estimate.sig_ops, 3);
        assert_eq!(
            estimate.script_units_per_byte,
            BTreeMap::from([("seal".to_string(), 1), ("tx.inputs[*].signature_script".to_string(), 3)])
        );
    }
}
