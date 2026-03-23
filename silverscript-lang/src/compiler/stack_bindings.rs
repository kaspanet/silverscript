use std::collections::{HashMap, HashSet};

use super::CompilerError;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;

#[derive(Debug, Clone, Default)]
pub(crate) struct StackBindings {
    depths: HashMap<String, i64>,
}

impl StackBindings {
    pub(crate) fn from_depths(depths: HashMap<String, i64>) -> Self {
        Self { depths }
    }

    pub(crate) fn set_depth_from_top(&mut self, name: &str, depth: i64) {
        self.depths.insert(name.to_string(), depth);
    }

    pub(crate) fn len(&self) -> usize {
        self.depths.len()
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.depths.contains_key(name)
    }

    pub(crate) fn depth_from_top(&self, name: &str) -> Option<i64> {
        self.depths.get(name).copied()
    }

    pub(crate) fn keys(&self) -> std::collections::hash_map::Keys<'_, String, i64> {
        self.depths.keys()
    }

    pub(crate) fn clone_depths(&self) -> HashMap<String, i64> {
        self.depths.clone()
    }

    pub(crate) fn binding_order_top_to_bottom(&self) -> Vec<String> {
        let mut ordered = self.depths.iter().map(|(name, depth)| (name.clone(), *depth)).collect::<Vec<_>>();
        ordered.sort_by_key(|(_, depth)| *depth);
        ordered.into_iter().map(|(name, _)| name).collect()
    }

    pub(crate) fn push_binding(&mut self, name: &str) {
        for depth in self.depths.values_mut() {
            *depth += 1;
        }
        self.depths.insert(name.to_string(), 0);
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

            let depth_from_top = self.depth_from_top(&name).expect("binding should exist before dropping");
            if depth_from_top == 0 {
                builder.add_op(OpDrop)?;
            } else {
                builder.add_i64(depth_from_top)?;
                builder.add_op(OpRoll)?;
                builder.add_op(OpDrop)?;
            }

            self.depths.remove(&name);
            for depth in self.depths.values_mut() {
                if *depth > depth_from_top {
                    *depth -= 1;
                }
            }
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
        let depth_from_top = self.depth_from_top(name).expect("binding should exist before stack rebinding");

        builder.add_i64(depth_from_top + 1)?;
        builder.add_op(OpRoll)?;
        builder.add_op(OpDrop)?;

        for (n, d) in self.depths.iter_mut() {
            if n == name {
                *d = 0;
                continue;
            }
            if *d < depth_from_top {
                *d += 1;
            }
        }

        Ok(())
    }

    pub(crate) fn emit_copy_binding_to_top(
        &self,
        name: &str,
        stack_depth: &mut i64,
        builder: &mut ScriptBuilder,
    ) -> Result<bool, CompilerError> {
        let Some(index) = self.depth_from_top(name) else {
            return Ok(false);
        };

        builder.add_i64(index + *stack_depth)?;
        *stack_depth += 1;
        builder.add_op(OpPick)?;
        Ok(true)
    }

    pub(crate) fn emit_stack_reordering(&mut self, target_order: &[String], builder: &mut ScriptBuilder) -> Result<(), CompilerError> {
        let current_order = self.binding_order_top_to_bottom();
        if current_order == target_order {
            return Ok(());
        }

        let current_names = current_order.iter().cloned().collect::<HashSet<_>>();
        let target_names = target_order.iter().cloned().collect::<HashSet<_>>();
        if current_names != target_names {
            return Err(CompilerError::Unsupported(
                "stack reconciliation requires both layouts to contain the same bindings".to_string(),
            ));
        }

        if let Some(opcodes) = local_stack_reordering_opcodes(&current_order, target_order) {
            for opcode in opcodes {
                builder.add_op(opcode)?;
            }
            self.reset_to_target_order(target_order);
            return Ok(());
        }

        let keep_start = longest_keepable_suffix_start(&current_order, target_order);
        let move_prefix = &target_order[..keep_start];
        let mut remaining_order = current_order;

        for name in move_prefix {
            let depth_from_top = remaining_order
                .iter()
                .position(|current_name| current_name == name)
                .expect("target binding should exist during stack reordering") as i64;
            let moved_name =
                remaining_order.get(depth_from_top as usize).expect("planned stack reordering depth should remain valid").clone();

            builder.add_i64(depth_from_top)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpToAltStack)?;

            self.depths.remove(&moved_name);
            for depth in self.depths.values_mut() {
                if *depth > depth_from_top {
                    *depth -= 1;
                }
            }
            remaining_order.remove(depth_from_top as usize);
        }

        debug_assert_eq!(remaining_order, target_order[move_prefix.len()..]);

        for _ in 0..move_prefix.len() {
            builder.add_op(OpFromAltStack)?;
        }

        self.reset_to_target_order(target_order);
        Ok(())
    }

    fn reset_to_target_order(&mut self, target_order: &[String]) {
        self.depths.clear();
        for (depth, name) in target_order.iter().enumerate() {
            self.depths.insert(name.clone(), depth as i64);
        }
    }
}

fn longest_keepable_suffix_start(current_order: &[String], target_order: &[String]) -> usize {
    let mut i = current_order.len();
    let mut j = target_order.len();

    while j > 0 {
        while i > 0 && current_order[i - 1] != target_order[j - 1] {
            i -= 1;
        }
        if i == 0 {
            break;
        }
        i -= 1;
        j -= 1;
    }

    j
}

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

fn apply_local_opcode(order: &[String], opcode: u8) -> Option<Vec<String>> {
    let mut next = order.to_vec();
    if opcode == OpSwap {
        if next.len() < 2 {
            return None;
        }
        next.swap(0, 1);
    } else if opcode == OpRot {
        if next.len() < 3 {
            return None;
        }
        next[..3].rotate_right(1);
    } else if opcode == Op2Swap {
        if next.len() < 4 {
            return None;
        }
        next[..4].rotate_left(2);
    } else if opcode == Op2Rot {
        if next.len() < 6 {
            return None;
        }
        next[..6].rotate_right(2);
    } else {
        return None;
    }
    Some(next)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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

    fn execute_script_and_decode_stack(script: Vec<u8>) -> Vec<i64> {
        let reused_values = SigHashReusedValuesUnsync::new();
        let sig_cache = Cache::new(128);
        let stacks = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
            &script,
            &reused_values,
            &sig_cache,
            EngineFlags::default(),
        )
        .execute_and_return_stacks()
        .expect("script executes");

        stacks.dstack.iter().map(|entry| deserialize_i64(entry, true).expect("stack entry decodes to int")).collect()
    }

    #[test]
    fn rebinding_moves_name_to_top_and_shifts_shallower_bindings() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2)]);
        let mut builder = ScriptBuilder::new();

        stack_bindings.emit_update_stack_for_rebinding("b", &mut builder).expect("rebind stack slot");

        assert_eq!(builder.drain(), vec![Op2, OpRoll, OpDrop]);
        assert_eq!(stack_bindings.binding_order_top_to_bottom(), names(&["b", "a", "c"]));
        assert_eq!(stack_bindings.depth_from_top("b"), Some(0));
        assert_eq!(stack_bindings.depth_from_top("a"), Some(1));
        assert_eq!(stack_bindings.depth_from_top("c"), Some(2));
    }

    #[test]
    fn drop_bindings_uses_drop_for_top_and_roll_for_deeper_entries() {
        let mut stack_bindings = bindings(&[("a", 0), ("b", 1), ("c", 2)]);
        let mut builder = ScriptBuilder::new();

        stack_bindings.emit_drop_bindings(&names(&["a", "c"]), &mut builder).expect("drop selected bindings");

        assert_eq!(builder.drain(), vec![OpDrop, Op1, OpRoll, OpDrop]);
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
        let current = names(&["a", "c", "b", "d"]);
        let target = names(&["a", "b", "c", "d"]);

        assert_eq!(longest_keepable_suffix_start(&current, &target), 2);
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
        assert_eq!(apply_local_opcode(&names(&["a"]), OpSwap), None);
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
