#![allow(non_upper_case_globals)] // Match the VM's opcode constant names.

//! Validate compiled bytecode fragments, including raw builder calls and SDK fragments.
//!
//! Analyze each entrypoint body with its own arguments and state fields. Check
//! state initialization with the largest argument count and a saved dispatch tag.
//! The caller checks dispatch using its fixed argument + field + 3 stack bound.
//! Every IF/NOTIF explores both branches, joining equal-height stacks at ENDIF.
//! Small constants survive copies and joins to resolve stack indices and arity.
use super::FunctionAst;
use crate::checked_arithmetic::checked_add;
use crate::errors::CompilerError;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::zk_precompiles::tags::ZkTag;
use kaspa_txscript::{MAX_STACK_SIZE, parse_script, serialize_i64};

mod stack;
use stack::Stack;

/// What is known about one stack item. `Unknown` still counts as one item;
/// `Bytes` keeps a small, exact byte value for operations that need a known index
/// or argument count. Large literals and most computed results become unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Bytes(Vec<u8>),
}

impl Value {
    fn literal(bytes: &[u8]) -> Self {
        // Argument counts and stack indices fit in eight bytes. Do not
        // retain potentially large proof/key/data literals in abstract states.
        if bytes.len() <= 8 { Self::Bytes(bytes.to_vec()) } else { Self::Unknown }
    }

    fn number(number: i64) -> Self {
        Self::Bytes(serialize_i64(number, None).expect("minimal i64 serialization fits").to_vec())
    }
}

/// One decoded instruction from a compiled bytecode fragment. `opcode` identifies
/// the VM operation, and `offset` is its starting byte position within that fragment,
/// used to report errors. For push operations, `literal` is the value to put on the
/// simulated stack (unknown for large data); other operations ignore that field.
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

pub(super) fn validate_bytecode_stack_limits(
    compiled_entrypoints: &[(String, Vec<u8>)],
    entrypoints: &[&FunctionAst<'_>],
    state_fields: usize,
    state_push_bytecode: &[u8],
) -> Result<(), CompilerError> {
    for (name, bytecode) in compiled_entrypoints {
        let function = entrypoints.iter().find(|function| function.name == *name).expect("body has an entrypoint");
        let initial = Stack::new(checked_add(function.params.len(), state_fields)?, 0, &Location { function: name, offset: 0 })?;
        analyze(&instructions(bytecode)?, name, initial)?;
    }

    // Variable-size state initializers can emit expressions, not just one push
    // per field. Check their temporaries while the caller's tag is saved on alt.
    // The surrounding TOALTSTACK/FROMALTSTACK only move that item between stacks.
    if !state_push_bytecode.is_empty() {
        let largest = entrypoints.iter().max_by_key(|function| function.params.len()).expect("contract has entrypoints");
        let initial = Stack::new(largest.params.len(), 1, &Location { function: &largest.name, offset: 0 })?;
        analyze(&instructions(state_push_bytecode)?, &largest.name, initial)?;
    }
    Ok(())
}

/// Check that a bytecode fragment never needs more than MAX_STACK_SIZE items
/// across the main and alternate stacks. Walk the bytecode in order and simulate each
/// opcode's pushes, pops, and moves with `step`. The checked `Stack` operations
/// reject underflow and enforce the combined size limit whenever items are added.
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
///   value only if both paths agree; otherwise mark that slot unknown. Without an
///   ELSE, the other result is the saved state at IF (the branch that does nothing).
///
/// For example, starting with main stack [x, condition], `IF PUSH 1 ELSE PUSH 2
/// ENDIF` checks [x, 1] and [x, 2] separately, then continues with [x, Unknown].
/// Their stack sizes are never added together. `branches` holds one saved frame
/// per open IF, so nested conditionals follow the same process.
///
/// `current = None` means this path cannot continue, for example after RETURN.
/// Skip its ordinary opcodes, but still process IF/ELSE/ENDIF so another saved
/// path can resume. When merging, only paths that can continue contribute a state.
fn analyze(instructions: &[Instruction], function: &str, initial: Stack) -> Result<(), CompilerError> {
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
    Ok(())
}

/// Update the simulated main and alternate stacks for one opcode, assuming that
/// opcode executes successfully. This tracks which items it consumes, produces,
/// copies, or moves; it does not run arithmetic, hashes, or proof verification.
/// For example, ADD changes [x, y] into [Unknown], while DUP changes [x] into [x, x].
///
/// Pushes and stack rearrangements preserve known values so later instructions
/// can use them as stack indices or argument counts. Most other instructions use
/// the fixed (pops, pushes) table below and produce unknown values. Instructions
/// whose effect depends on an operand, such as PICK/ROLL or a ZK precompile, have
/// dedicated handling and require the relevant index, tag, or count to be known.
///
/// Return an error if an operand is missing, an opcode is unmodeled, or its stack
/// effect cannot be determined. `at` supplies the entrypoint and byte offset for
/// diagnostics. On error, `state` may already be partly updated; analysis stops.
/// All stack access goes through `Stack`, which checks operands and combined
/// capacity. The caller, `analyze`, handles IF/ELSE/ENDIF and RETURN.
fn step(state: &mut Stack, instruction: &Instruction, at: &Location<'_>) -> Result<(), CompilerError> {
    let op = instruction.opcode;
    match op {
        Op0..=OpPushData4 | Op1Negate | Op1..=Op16 => state.push(instruction.literal.clone(), at)?,
        OpNop => {}
        OpToAltStack => state.move_to_alt(at)?,
        OpFromAltStack => state.move_from_alt(at)?,
        OpDepth => state.push(Value::number(i64::try_from(state.main_len()).map_err(|_| at.error("stack depth exceeds i64"))?), at)?,
        OpSize => {
            let size = match state.peek(0, at)? {
                Value::Bytes(bytes) => Value::number(bytes.len() as i64),
                Value::Unknown => Value::Unknown,
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
        OpPick | OpRoll => {
            let depth = state.pop_count(at)?;
            let value = if op == OpRoll { state.remove(depth, at)? } else { state.peek(depth, at)?.clone() };
            state.push(value, at)?;
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
                    state.pop_count(at)? // public input count
                }
                ZkTag::R0Succinct => 8,
            };
            state.drop_items(count, at)?;
            state.push(Value::number(1), at)?;
        }
        _ => {
            // Effects are those of the pinned Kaspa VM, on successful execution.
            // In particular its CLTV/CSV consume their operands. Reject new or
            // variable-arity opcodes until explicitly modeled; never assume zero.
            let (pops, pushes) = match op {
                OpDrop | OpVerify | OpCheckLockTimeVerify | OpCheckSequenceVerify => (1, 0),
                Op2Drop | OpEqualVerify | OpNumEqualVerify | OpCheckSigVerify => (2, 0),
                OpInvert
                | Op1Add
                | Op1Sub
                | OpNegate
                | OpAbs
                | OpNot
                | Op0NotEqual
                | OpSHA256
                | OpBlake2b
                | OpBlake3
                | OpBin2Num
                | OpOutpointTxId
                | OpOutpointIndex
                | OpTxInputSeq
                | OpTxInputAmount
                | OpTxInputSpk
                | OpTxInputDaaScore
                | OpTxInputIsCoinbase
                | OpTxOutputAmount
                | OpTxOutputSpk
                | OpTxInputSpkLen
                | OpTxOutputSpkLen
                | OpTxInputScriptSigLen
                | OpAuthOutputCount
                | OpInputCovenantId
                | OpCovInputCount
                | OpCovOutputCount
                | OpChainblockSeqCommit
                | OpOutputCovenantId
                | OpOutputAuthorizingInput => (1, 1),
                OpEqual | OpCat | OpAnd | OpOr | OpXor | OpAdd | OpSub | OpMul | OpDiv | OpMod | OpBoolAnd | OpBoolOr | OpNumEqual
                | OpNumNotEqual | OpLessThan | OpGreaterThan | OpLessThanOrEqual | OpGreaterThanOrEqual | OpMin | OpMax
                | OpBlake2bWithKey | OpBlake3WithKey | OpCheckSig | OpCheckSigECDSA | OpTxPayloadSubstr | OpAuthOutputIdx
                | OpNum2Bin | OpCovInputIdx | OpCovOutputIdx => (2, 1),
                OpSubstr
                | OpWithin
                | OpTxInputScriptSigSubstr
                | OpTxInputSpkSubstr
                | OpTxOutputSpkSubstr
                | OpCheckSigFromStack
                | OpCheckSigFromStackECDSA => (3, 1),
                OpTxVersion | OpTxInputCount | OpTxOutputCount | OpTxLockTime | OpTxSubnetId | OpTxGas | OpTxInputIndex
                | OpTxPayloadLen => (0, 1),
                _ => return Err(at.error(format!("unmodeled opcode 0x{op:02x}"))),
            };
            state.apply_effect(pops, pushes, at)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::{EngineFlags, TxScriptEngine, caches::Cache};

    fn check(script: &[u8], params: usize) -> Result<(), CompilerError> {
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
        let error = validate_bytecode_stack_limits(&[("main".into(), body)], &[&contract.functions[0]], 0, &[]).unwrap_err();
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
        check(&script, 0).unwrap();
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
}
