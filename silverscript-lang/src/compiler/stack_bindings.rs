use std::collections::{HashMap, HashSet};

use super::CompilerError;
use indexmap::IndexSet;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;

trait ScriptBuilderStackBindingExt {
    fn drop_from_depth(&mut self, depth: i64) -> Result<(), CompilerError>;
    fn pick_from_depth(&mut self, depth: i64) -> Result<(), CompilerError>;
    fn roll_from_depth(&mut self, depth: i64) -> Result<(), CompilerError>;
}

impl ScriptBuilderStackBindingExt for ScriptBuilder {
    fn drop_from_depth(&mut self, depth: i64) -> Result<(), CompilerError> {
        if depth == 0 {
            self.add_op(OpDrop)?;
        } else if depth == 1 {
            self.add_op(OpNip)?;
        } else if depth == 2 {
            self.add_op(OpRot)?;
            self.add_op(OpDrop)?;
        } else {
            self.add_i64(depth)?;
            self.add_op(OpRoll)?;
            self.add_op(OpDrop)?;
        }

        Ok(())
    }

    fn pick_from_depth(&mut self, depth: i64) -> Result<(), CompilerError> {
        if depth == 0 {
            self.add_op(OpDup)?;
        } else if depth == 1 {
            self.add_op(OpOver)?;
        } else {
            self.add_i64(depth)?;
            self.add_op(OpPick)?;
        }

        Ok(())
    }

    fn roll_from_depth(&mut self, depth: i64) -> Result<(), CompilerError> {
        if depth == 0 {
            return Ok(());
        } else if depth == 1 {
            self.add_op(OpSwap)?;
        } else if depth == 2 {
            self.add_op(OpRot)?;
        } else {
            self.add_i64(depth)?;
            self.add_op(OpRoll)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StackBindings {
    // Logical equivalent of the runtime stack, stored top-to-bottom so index
    // equals depth (from top).
    stack: IndexSet<String>,
}

impl StackBindings {
    #[cfg(test)]
    pub(crate) fn from_order_top_to_bottom(ordered_names: Vec<String>) -> Self {
        let input_len = ordered_names.len();
        let stack: IndexSet<_> = ordered_names.into_iter().collect();
        assert_eq!(input_len, stack.len(), "stack binding order should not contain duplicates");
        Self { stack }
    }

    pub(crate) fn from_depths(depths: HashMap<String, i64>) -> Self {
        let mut ordered = depths.into_iter().collect::<Vec<_>>();
        ordered.sort_by_key(|(_, depth)| *depth);
        assert!(
            ordered.iter().enumerate().all(|(expected_depth, (_, depth))| *depth == expected_depth as i64),
            "illegal stack binding depths"
        );
        Self { stack: ordered.into_iter().map(|(name, _)| name).collect() }
    }

    pub(crate) fn set_depth(&mut self, name: &str, depth: i64) {
        assert!((0..=self.stack.len() as i64).contains(&depth), "depth out of bounds: {depth}");
        let target_index = depth as usize;
        self.stack.insert_before(target_index, name.to_string());
    }

    pub(crate) fn len(&self) -> usize {
        self.stack.len()
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.stack.contains(name)
    }

    pub(crate) fn depth(&self, name: &str) -> Option<i64> {
        self.stack.get_index_of(name).map(|index| index as i64)
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &String> {
        self.stack.iter()
    }

    pub(crate) fn clone_depths(&self) -> HashMap<String, i64> {
        self.binding_order_top_to_bottom().into_iter().enumerate().map(|(depth, name)| (name, depth as i64)).collect()
    }

    pub(crate) fn binding_order_top_to_bottom(&self) -> Vec<String> {
        self.stack.iter().cloned().collect()
    }

    pub(crate) fn push_binding(&mut self, name: &str) {
        assert!(!self.contains(name), "binding already exists: {name}");
        self.set_depth(name, 0);
    }

    /// Removes the named bindings from the stack while preserving the relative
    /// order of all surviving bindings.
    ///
    /// The removal order is current top-to-bottom among the bindings being
    /// removed, which minimizes the total `ROLL` depth for this direct
    /// `ROLL+DROP` strategy.
    pub(crate) fn emit_drop_bindings(&mut self, names: &[String], builder: &mut ScriptBuilder) -> Result<(), CompilerError> {
        if names.is_empty() {
            return Ok(());
        }

        let names_to_remove = names.iter().cloned().collect::<HashSet<_>>();
        for name in self.binding_order_top_to_bottom() {
            if !names_to_remove.contains(&name) {
                continue;
            }

            let depth = self.depth(&name).expect("binding should exist before dropping");
            builder.drop_from_depth(depth)?;

            self.remove_name(&name);
        }

        Ok(())
    }

    /// Rewrites the physical stack after a scalar reassignment and updates the
    /// binding model to reflect the new stack shape.
    ///
    /// Assumptions:
    /// - `name` is already bound in this `StackBindings`
    /// - the newly computed RHS value is currently on top of the stack
    /// - the compiler wants the rebound name to move to depth `0`
    ///
    /// Operationally, this rolls the old bound value to the top, drops it, and
    /// leaves the newly computed RHS value at the top. The binding model is
    /// then updated so:
    /// - `name` becomes depth `0`
    /// - bindings that were above the old slot shift by `+1`
    /// - deeper bindings keep their previous depths
    pub(crate) fn emit_update_stack_for_rebinding(&mut self, name: &str, builder: &mut ScriptBuilder) -> Result<(), CompilerError> {
        let depth = self.depth(name).expect("binding should exist before stack rebinding");

        builder.drop_from_depth(depth + 1)?;

        self.move_name_to_top(name);

        Ok(())
    }

    pub(crate) fn emit_copy_binding_to_top(
        &self,
        name: &str,
        stack_depth: &mut i64,
        builder: &mut ScriptBuilder,
    ) -> Result<bool, CompilerError> {
        let Some(index) = self.depth(name) else {
            return Ok(false);
        };

        builder.pick_from_depth(index + *stack_depth)?;
        *stack_depth += 1;
        Ok(true)
    }

    pub(crate) fn emit_stack_reordering(&mut self, target_order: &[String], builder: &mut ScriptBuilder) -> Result<(), CompilerError> {
        let current_order = self.binding_order_top_to_bottom();
        if current_order == target_order {
            return Ok(());
        }

        let current_set = current_order.iter().cloned().collect::<HashSet<_>>();
        let target_set = target_order.iter().cloned().collect::<HashSet<_>>();
        assert_eq!(current_order.len(), current_set.len(), "current stack order should not contain duplicates");
        assert_eq!(target_order.len(), target_set.len(), "target stack order should not contain duplicates");
        assert_eq!(current_set, target_set, "stack reconciliation requires both layouts to contain the same bindings");
        // At this point both layouts are duplicate-free and contain exactly the
        // same bindings, so they are just two permutations of the same set.

        if let Some(opcodes) = local_stack_reordering_opcodes(&current_order, target_order) {
            builder.add_ops(&opcodes)?;
            self.reset_to_target_order(target_order);
            return Ok(());
        }

        let keep_start = longest_keepable_suffix_start(&current_order, target_order);
        let move_prefix = &target_order[..keep_start];
        let mut remaining_stack = self.stack.clone();

        for name in move_prefix {
            let index = remaining_stack.get_index_of(name).expect("binding existence was asserted above");
            let depth = index as i64;

            builder.roll_from_depth(depth)?;
            builder.add_op(OpToAltStack)?;

            remaining_stack.shift_remove_index(index);
        }

        debug_assert_eq!(remaining_stack.iter().cloned().collect::<Vec<_>>(), target_order[move_prefix.len()..]);

        for _ in 0..move_prefix.len() {
            builder.add_op(OpFromAltStack)?;
        }

        self.reset_to_target_order(target_order);
        Ok(())
    }

    fn reset_to_target_order(&mut self, target_order: &[String]) {
        self.stack = target_order.iter().cloned().collect();
    }

    fn remove_name(&mut self, name: &str) {
        self.stack.shift_remove(name);
    }

    fn move_name_to_top(&mut self, name: &str) {
        let from = self.stack.get_index_of(name).expect("binding should exist before moving to top");
        self.stack.move_index(from, 0);
    }
}

/// Returns the start index in `target_order` of the longest suffix that can be
/// left in place by the suffix-rebuild stack reordering strategy.
///
/// In that strategy:
/// - a prefix of `target_order` is extracted to altstack and restored later
/// - the bindings that are not moved stay on the main stack in their original
///   relative order
/// - after the restore, those untouched bindings therefore occupy a suffix of
///   the final target layout
///
/// So this helper looks for the longest suffix of `target_order` that appears
/// as a subsequence of `current_order`.
///
/// Example:
/// - `current = [a, b, c, d, e]`
/// - `target  = [c, a, b, d, e]`
/// - the keepable suffix is `[a, b, d, e]`
///   - it is a subsequence of `current`
///   - it starts at index `1` in `target`
/// - so the function returns `1`, meaning only `[c]` must move
///
/// Another example:
/// - `current = [a, b, c, d]`
/// - `target  = [d, c, b, a]`
/// - the longest keepable suffix is `[a]`
/// - so the function returns `3`
///
/// The returned value is therefore:
/// - `0` when the whole target can be kept in place
/// - `target.len()` when no non-empty target suffix is keepable
fn longest_keepable_suffix_start(current_order: &[String], target_order: &[String]) -> usize {
    let mut i = current_order.len();
    let mut j = target_order.len();

    while j > 0 {
        // Walk backward through `current_order` until we find the current
        // suffix item `target_order[j - 1]`, or prove that it is missing.
        while i > 0 && current_order[i - 1] != target_order[j - 1] {
            i -= 1;
        }
        if i == 0 {
            break;
        }
        // We matched one more suffix item, so extend the keepable suffix one
        // step to the left in `target_order` and continue the backward scan.
        i -= 1;
        j -= 1;
    }

    // `j` is now the start index of the longest keepable suffix in
    // `target_order`, so `target_order[j..]` is the untouched portion.
    j
}

/// Searches the bounded local opcode space used by the planner and returns the
/// first 1- or 2-op sequence that exactly rewrites `current_order` into
/// `target_order`.
fn local_stack_reordering_opcodes(current_order: &[String], target_order: &[String]) -> Option<Vec<u8>> {
    if current_order.len() != target_order.len() {
        return None;
    }

    let local_ops = [OpSwap, OpRot, Op2Swap, Op2Rot];

    for opcode in local_ops {
        if let Some(next_order) = apply_local_opcode(current_order, opcode)
            && next_order == target_order
        {
            return Some(vec![opcode]);
        }
    }

    for first in local_ops {
        let Some(mid_order) = apply_local_opcode(current_order, first) else {
            continue;
        };
        for second in local_ops {
            if let Some(next_order) = apply_local_opcode(&mid_order, second)
                && next_order == target_order
            {
                return Some(vec![first, second]);
            }
        }
    }

    None
}

/// Applies one local stack opcode to the compiler's top-to-bottom binding model.
///
/// This is the symbolic counterpart of the small bounded search in
/// `local_stack_reordering_opcodes`: given the current logical binding order, it
/// predicts what `SWAP`, `ROT`, `2SWAP`, or `2ROT` would do to the top portion
/// of the stack.
///
/// Returns `None` when:
/// - the opcode is not part of that local search space, or
/// - the current stack is too short for the opcode to apply.
#[allow(non_upper_case_globals)]
fn apply_local_opcode(order: &[String], opcode: u8) -> Option<Vec<String>> {
    let mut next = order.to_vec();
    match opcode {
        OpSwap if next.len() >= 2 => {
            next.swap(0, 1);
        }
        OpRot if next.len() >= 3 => {
            next[..3].rotate_right(1);
        }
        Op2Swap if next.len() >= 4 => {
            next[..4].rotate_left(2);
        }
        Op2Rot if next.len() >= 6 => {
            next[..6].rotate_right(2);
        }
        _ => return None,
    }
    Some(next)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::{StackBindings, apply_local_opcode, local_stack_reordering_opcodes, longest_keepable_suffix_start};
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::PopulatedTransaction;
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::opcodes::codes::*;
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::{EngineFlags, TxScriptEngine, deserialize_i64};

    fn bindings(depths: &[(&str, i64)]) -> StackBindings {
        StackBindings::from_depths(depths.iter().map(|(name, depth)| ((*name).to_string(), *depth)).collect::<HashMap<_, _>>())
    }

    fn names(order: &[&str]) -> Vec<String> {
        order.iter().map(|name| (*name).to_string()).collect()
    }

    /// Executes a raw script and decodes the resulting main stack as integers.
    ///
    /// The returned order matches txscript's raw stack iteration order, which
    /// is bottom-to-top in `Stack::inner`.
    fn execute_script_and_decode_stack(script: Vec<u8>) -> Vec<i64> {
        let reused_values = SigHashReusedValuesUnsync::new();
        let sig_cache = Cache::new(128);
        let stacks = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
            &script,
            &reused_values,
            &sig_cache,
            EngineFlags { covenants_enabled: true },
        )
        .execute_and_return_stacks()
        .expect("script executes");

        stacks.dstack.iter().map(|entry| deserialize_i64(entry, true).expect("stack entry decodes to int")).collect()
    }

    /// Executes local stack ops against a logical top-to-bottom test stack.
    ///
    /// This helper bridges between the test model and txscript's push/stack
    /// ordering so the rest of the test can stay in top-to-bottom terms.
    fn execute_local_opcode_sequence_top_to_bottom(values_top_to_bottom: &[i64], opcodes: &[u8]) -> Vec<i64> {
        let mut script = ScriptBuilder::new();
        for value in values_top_to_bottom.iter().rev() {
            script.add_i64(*value).expect("push test value");
        }
        script.add_ops(opcodes).expect("append local opcodes");
        let mut result = execute_script_and_decode_stack(script.drain());
        // Normalize the engine's raw bottom-to-top order back into the logical
        // top-to-bottom order used by `StackBindings` and `apply_local_opcode`.
        result.reverse();
        result
    }

    /// Enumerates the one- and two-op local sequences in planner search order.
    ///
    /// The sweep test uses this to compare the planner against the same
    /// canonical ordering it uses internally.
    fn local_opcode_sequences_in_search_order() -> Vec<Vec<u8>> {
        let local_ops = [OpSwap, OpRot, Op2Swap, Op2Rot];
        let mut sequences = Vec::new();
        sequences.extend(local_ops.iter().map(|opcode| vec![*opcode]));
        for first in local_ops {
            for second in local_ops {
                sequences.push(vec![first, second]);
            }
        }
        sequences
    }

    #[test]
    fn rebinding_moves_name_to_top_and_shifts_shallower_bindings() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2)]);
        let mut builder = ScriptBuilder::new();

        stack_bindings.emit_update_stack_for_rebinding("b", &mut builder).expect("rebind stack slot");

        assert_eq!(builder.drain(), vec![OpRot, OpDrop]);
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), names(&["b", "a", "c"]));
        assert_eq!(stack_bindings.depth("b"), Some(0));
        assert_eq!(stack_bindings.depth("a"), Some(1));
        assert_eq!(stack_bindings.depth("c"), Some(2));
    }

    #[test]
    fn drop_bindings_uses_drop_for_top_and_roll_for_deeper_entries() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2)]);
        let mut builder = ScriptBuilder::new();

        stack_bindings.emit_drop_bindings(&names(&["a", "c"]), &mut builder).expect("drop selected bindings");

        assert_eq!(builder.drain(), vec![OpDrop, OpNip]);
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), names(&["b"]));
    }

    #[test]
    fn stack_reordering_uses_local_swap_when_available() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1)]);
        let mut builder = ScriptBuilder::new();

        stack_bindings.emit_stack_reordering(&names(&["b", "a"]), &mut builder).expect("reorder with swap");

        assert_eq!(builder.drain(), vec![OpSwap]);
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), names(&["b", "a"]));
    }

    #[test]
    fn stack_reordering_uses_suffix_rebuild_for_non_local_permutation() {
        let current_order = names(&["a", "b", "c", "e", "d"]);
        let target_order = names(&["a", "b", "c", "d", "e"]);
        assert_eq!(local_stack_reordering_opcodes(&current_order, &target_order), None);

        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2), ("e", 3), ("d", 4)]);
        let mut builder = ScriptBuilder::new();

        stack_bindings.emit_stack_reordering(&target_order, &mut builder).expect("reorder with suffix rebuild");

        let script = builder.drain();
        assert!(script.contains(&OpToAltStack));
        assert!(script.contains(&OpFromAltStack));
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), target_order);
    }

    #[test]
    fn longest_keepable_suffix_start_finds_maximal_target_suffix() {
        let cases = [
            (vec!["a", "b", "c"], vec!["a", "b", "c"], 0),
            (vec!["a", "c", "b", "d"], vec!["a", "b", "c", "d"], 2),
            // move:        ↓
            // current: [a, b, c]
            // target:  [b, a, c]
            // keep:        ^^^^
            (vec!["a", "b", "c"], vec!["b", "a", "c"], 1),
            // move:           ↓
            // current: [a, b, c]
            // target:  [c, a, b]
            // keep:        ^^^^
            (vec!["a", "b", "c"], vec!["c", "a", "b"], 1),
            (vec!["a", "b", "c"], vec!["a", "c", "b"], 2),
            // move:        ↓  ↓  ↓
            // current: [a, b, c, d]
            // target:  [b, c, d, a]
            // keep:              ^
            (vec!["a", "b", "c", "d"], vec!["b", "c", "d", "a"], 3),
            (vec!["a", "b", "c", "d"], vec!["a", "d", "b", "c"], 2),
            (vec!["a", "b", "c", "d"], vec!["c", "d", "a", "b"], 2),
            (vec!["x"], vec!["x"], 0),
            (vec!["x", "y"], vec!["y", "x"], 1),
            (vec!["a", "b", "c", "d"], vec!["a", "b", "d", "c"], 3),
            // move:           ↓
            // current: [a, b, c, d, e]
            // target:  [c, a, b, d, e]
            // keep:        ^^^^^^^^^^
            (vec!["a", "b", "c", "d", "e"], vec!["c", "a", "b", "d", "e"], 1),
            // move:              ↓
            // current: [a, b, c, d]
            // target:  [d, a, b, c]
            // keep:        ^^^^^^^
            (vec!["a", "b", "c", "d"], vec!["d", "a", "b", "c"], 1),
            // move:        ↓  ↓  ↓
            // current: [a, b, c, d]
            // target:  [d, c, b, a]
            // keep:              ^
            (vec!["a", "b", "c", "d"], vec!["d", "c", "b", "a"], 3),
            // move:                 ↓
            // current: [a, b, c, d, e]
            // target:  [e, a, b, c, d]
            // keep:        ^^^^^^^^^^
            (vec!["a", "b", "c", "d", "e"], vec!["e", "a", "b", "c", "d"], 1),
            // move:        ↓     ↓
            // current: [a, b, c, d, e, f]
            // target:  [b, d, a, c, e, f]
            // keep:           ^^^^^^^^^^
            (vec!["a", "b", "c", "d", "e", "f"], vec!["b", "d", "a", "c", "e", "f"], 2),
        ];

        for (current, target, expected) in cases {
            let current = current.into_iter().map(str::to_string).collect::<Vec<_>>();
            let target = target.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert_eq!(longest_keepable_suffix_start(&current, &target), expected, "current={current:?} target={target:?}");
        }
    }

    #[test]
    fn local_stack_reordering_search_finds_two_op_sequence() {
        let current = names(&["a", "b", "c"]);
        let target = names(&["b", "c", "a"]);

        let opcodes = local_stack_reordering_opcodes(&current, &target).expect("two-op local sequence");
        assert_eq!(opcodes.len(), 2);

        let mut reordered = current;
        for opcode in opcodes {
            reordered = apply_local_opcode(&reordered, opcode).expect("planned local opcode should apply");
        }
        assert_eq!(reordered, target);
    }

    #[test]
    fn apply_local_opcode_matches_stack_machine_rotation_direction() {
        assert_eq!(apply_local_opcode(&names(&["a", "b", "c"]), OpRot), Some(names(&["c", "a", "b"])));
        assert_eq!(apply_local_opcode(&names(&["a", "b", "c", "d"]), Op2Swap), Some(names(&["c", "d", "a", "b"])));
        assert_eq!(apply_local_opcode(&names(&["a", "b", "c", "d", "e", "f"]), Op2Rot), Some(names(&["e", "f", "a", "b", "c", "d"])));
        assert_eq!(apply_local_opcode(&names(&["a"]), OpSwap), None);
    }

    #[test]
    fn apply_local_opcode_check_against_script_engine() {
        let executable_cases =
            [(2, OpSwap), (10, OpSwap), (3, OpRot), (10, OpRot), (4, Op2Swap), (10, Op2Swap), (6, Op2Rot), (10, Op2Rot)];

        for (stack_len, opcode) in executable_cases {
            let values = (0..stack_len).map(i64::from).collect::<Vec<_>>();
            let current_order = values.iter().map(ToString::to_string).collect::<Vec<_>>();
            let expected_order = apply_local_opcode(&current_order, opcode).expect("opcode should apply to labeled stack");
            let actual_order = execute_local_opcode_sequence_top_to_bottom(&values, &[opcode])
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();

            assert_eq!(actual_order, expected_order, "opcode {opcode} should match apply_local_opcode permutation");
        }

        assert_eq!(apply_local_opcode(&names(&["a"]), OpSwap), None);
    }

    /// This test validates the local stack-reordering fast path in four steps:
    ///
    /// 1. Start from a named stack longer than any local opcode touches.
    /// 2. Sweep every one- and two-op local sequence in planner search order.
    /// 3. Use the script engine as the ground truth for the target order each
    ///    sequence actually reaches, and only keep the first sequence that
    ///    reaches each distinct target.
    /// 4. For each non-identity target, assert that both
    ///    `local_stack_reordering_opcodes` and `emit_stack_reordering`
    ///    choose exactly that same sequence. For identity targets, only
    ///    check the outer `emit_stack_reordering` fast path.
    #[test]
    fn local_stack_reordering_and_emit_match_canonical_one_or_two_op_sequences() {
        let initial_values = vec![11, 22, 33, 44, 55, 66, 77, 88];
        let initial_order = (0..initial_values.len()).map(|index| format!("v{index}")).collect::<Vec<_>>();
        let value_to_label = initial_values.iter().copied().zip(initial_order.iter().cloned()).collect::<HashMap<_, _>>();
        let mut seen_targets = HashSet::new();

        for source_opcodes in local_opcode_sequences_in_search_order() {
            // Derive the target layout from the real engine.
            let target_values = execute_local_opcode_sequence_top_to_bottom(&initial_values, &source_opcodes);
            let target_order = target_values
                .iter()
                .map(|value| value_to_label.get(value).expect("target value should map to initial label").clone())
                .collect::<Vec<_>>();
            // Only test the first sequence that reaches each target, which is
            // the same sequence the planner should pick for that target.
            if !seen_targets.insert(target_order.clone()) {
                continue;
            }

            if target_order != initial_order {
                assert_eq!(
                    local_stack_reordering_opcodes(&initial_order, &target_order),
                    Some(source_opcodes.clone()),
                    "planner should choose the first matching local sequence for target {target_order:?}"
                );
            }

            let mut stack_bindings = StackBindings::from_order_top_to_bottom(initial_order.clone());
            let mut builder = ScriptBuilder::new();
            stack_bindings.emit_stack_reordering(&target_order, &mut builder).expect("emit stack reordering");

            assert_eq!(
                builder.drain(),
                if target_order == initial_order { vec![] } else { source_opcodes.clone() },
                "emit_stack_reordering should emit the first matching local sequence for target {target_order:?}"
            );
            assert_eq!(stack_bindings.binding_order_top_to_bottom(), target_order);
        }
    }

    #[test]
    fn emitted_stack_reordering_matches_engine_execution() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2), ("e", 3), ("d", 4)]);
        let target_order = names(&["a", "b", "c", "d", "e"]);

        let mut reorder_builder = ScriptBuilder::new();
        stack_bindings.emit_stack_reordering(&target_order, &mut reorder_builder).expect("emit stack reordering");

        let mut script = ScriptBuilder::new();
        for value in [5, 4, 3, 2, 1] {
            script.add_i64(value).expect("push test value");
        }
        script.add_ops(&reorder_builder.drain()).expect("append reordering ops");

        assert_eq!(execute_script_and_decode_stack(script.drain()), vec![4, 5, 3, 2, 1]);
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), target_order);
    }

    #[test]
    fn emitted_rebinding_matches_engine_execution() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2)]);
        let mut rebinding_builder = ScriptBuilder::new();
        stack_bindings.emit_update_stack_for_rebinding("b", &mut rebinding_builder).expect("emit rebinding update");

        let mut script = ScriptBuilder::new();
        for value in [3, 2, 1, 9] {
            script.add_i64(value).expect("push test value");
        }
        script.add_ops(&rebinding_builder.drain()).expect("append rebinding ops");

        assert_eq!(execute_script_and_decode_stack(script.drain()), vec![3, 1, 9]);
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), names(&["b", "a", "c"]));
    }
}
