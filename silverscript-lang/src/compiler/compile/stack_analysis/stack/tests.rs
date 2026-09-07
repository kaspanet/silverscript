use super::*;

#[test]
fn checked_stack_constructor_and_transfers_respect_combined_limit() {
    let at = Location { function: "test", offset: 37 };
    for main_items in [0, 120, 244] {
        let alt_items = 244 - main_items;
        let mut stack = Stack::new(main_items, alt_items, &at).unwrap();
        assert!(matches!(
            Stack::new(main_items, alt_items + 1, &at),
            Err(CompilerError::BytecodeStackTooLarge { actual: 245, maximum: 244, offset: 37, .. })
        ));
        let original = stack.clone();
        if main_items > 0 {
            stack.move_to_alt(&at).unwrap();
            stack.move_from_alt(&at).unwrap();
        } else {
            stack.move_from_alt(&at).unwrap();
            stack.move_to_alt(&at).unwrap();
        }
        assert_eq!(stack, original, "transfers must work even with both stacks at combined capacity");
        let error = stack.push(Value::Unknown, &at).unwrap_err();
        assert!(matches!(error, CompilerError::BytecodeStackTooLarge {
            function, offset: 37, actual: 245, maximum: 244,
        } if function == "test"));
    }
    // Replacing operands at the limit does not require extra room.
    let mut stack = Stack::new(243, 1, &at).unwrap();
    stack.apply_effect(2, 1, &at).unwrap();
    stack.push(Value::number(7), &at).unwrap();
    assert_eq!(stack.main.len() + stack.alt.len(), 244);
}

#[test]
fn checked_stack_operations_reject_missing_operands() {
    let at = Location { function: "test", offset: 19 };
    let mut stack = Stack::new(1, 0, &at).unwrap();
    // A full-capacity check alone cannot catch out-of-range reads or moves.
    assert!(stack.peek(1, &at).is_err());
    assert!(stack.remove(1, &at).is_err());
    assert!(stack.insert(2, Value::Unknown, &at).is_err());
    assert!(stack.extend_from_within(2, 1, &at).is_err());
    assert!(stack.extend_from_within(1, 2, &at).is_err());
    assert!(stack.rotate_left(2, 1, &at).is_err());
    assert!(stack.rotate_left(1, 2, &at).is_err());
    assert!(stack.drop_items(2, &at).is_err());
    assert!(stack.move_from_alt(&at).is_err());
    assert_eq!(stack.main_len(), 1);
    stack.pop(&at).unwrap();
    assert!(matches!(stack.pop(&at), Err(CompilerError::BytecodeStackAnalysis { offset: 19, .. })));
}

use std::collections::VecDeque;

const AT: Location<'static> = Location { function: "stack_tests", offset: 123 };

fn with_values(main: &[i64], alt: &[i64]) -> Stack {
    assert!(main.len() + alt.len() <= MAX_STACK_SIZE);
    Stack { main: main.iter().copied().map(Value::number).collect(), alt: alt.iter().copied().map(Value::number).collect() }
}

fn assert_analysis_error(error: CompilerError) {
    match error {
        CompilerError::BytecodeStackAnalysis { function, offset, message } => {
            assert_eq!(function, AT.function);
            assert_eq!(offset, AT.offset);
            assert!(!message.is_empty());
        }
        other => panic!("expected contextual stack-analysis error, got {other}"),
    }
}

fn assert_limit_error(error: CompilerError, expected_actual: usize) {
    match error {
        CompilerError::BytecodeStackTooLarge { function, offset, actual, maximum } => {
            assert_eq!(function, AT.function);
            assert_eq!(offset, AT.offset);
            assert_eq!(actual, expected_actual);
            assert_eq!(maximum, MAX_STACK_SIZE);
        }
        other => panic!("expected stack-size error, got {other}"),
    }
}

#[test]
fn new_and_capacity_cover_every_valid_main_alt_distribution() {
    for total in 0..=MAX_STACK_SIZE {
        for main in 0..=total {
            let alt = total - main;
            let stack = Stack::new(main, alt, &AT).unwrap();
            assert_eq!(stack.main_len(), main);
            assert_eq!(stack.alt_len(), alt);
            assert!(stack.main_values().iter().chain(&stack.alt).all(|value| *value == Value::Unknown));
            let before = stack.clone();
            stack.require_capacity(0, &AT).unwrap();
            stack.require_capacity(MAX_STACK_SIZE - total, &AT).unwrap();
            assert_limit_error(stack.require_capacity(MAX_STACK_SIZE - total + 1, &AT).unwrap_err(), MAX_STACK_SIZE + 1);
            assert_eq!(stack, before, "capacity queries must not change either stack");
        }
    }
    for main in 0..=MAX_STACK_SIZE + 1 {
        assert_limit_error(Stack::new(main, MAX_STACK_SIZE + 1 - main, &AT).unwrap_err(), MAX_STACK_SIZE + 1);
    }
}

#[test]
fn huge_counts_and_depths_return_errors_without_allocating_or_panicking() {
    assert!(matches!(Stack::new(usize::MAX, 1, &AT), Err(CompilerError::ArithmeticOverflow(_))));
    assert_limit_error(Stack::new(usize::MAX, 0, &AT).unwrap_err(), usize::MAX);
    let mut stack = with_values(&[10], &[20]);
    let before = stack.clone();
    assert!(matches!(stack.require_capacity(usize::MAX, &AT), Err(CompilerError::ArithmeticOverflow(_))));
    assert!(matches!(stack.peek(usize::MAX, &AT), Err(CompilerError::ArithmeticOverflow(_))));
    assert!(matches!(stack.remove(usize::MAX, &AT), Err(CompilerError::ArithmeticOverflow(_))));
    assert_analysis_error(stack.suffix_start(usize::MAX, &AT).unwrap_err());
    assert_analysis_error(stack.insert(usize::MAX, Value::Unknown, &AT).unwrap_err());
    assert_analysis_error(stack.extend_from_within(usize::MAX, 0, &AT).unwrap_err());
    assert_analysis_error(stack.extend_from_within(1, usize::MAX, &AT).unwrap_err());
    assert_analysis_error(stack.rotate_left(usize::MAX, 0, &AT).unwrap_err());
    assert_analysis_error(stack.rotate_left(1, usize::MAX, &AT).unwrap_err());
    assert_analysis_error(stack.drop_items(usize::MAX, &AT).unwrap_err());
    assert_analysis_error(stack.apply_effect(usize::MAX, 0, &AT).unwrap_err());
    assert_eq!(stack, before);
    assert!(matches!(stack.apply_effect(0, usize::MAX, &AT), Err(CompilerError::ArithmeticOverflow(_))));
    assert_eq!(stack, before);
}

#[test]
fn suffix_start_returns_the_documented_index_without_changing_values() {
    let stack = with_values(&[10, 20, 30, 40], &[50, 60]);
    let before = stack.clone();
    for (count, index) in [(0, 4), (1, 3), (2, 2), (3, 1), (4, 0)] {
        assert_eq!(stack.suffix_start(count, &AT).unwrap(), index);
    }
    // Alternate-stack items do not satisfy a main-stack operand requirement.
    assert_analysis_error(stack.suffix_start(5, &AT).unwrap_err());
    assert_eq!(stack, before);
    let empty_main = with_values(&[], &[50]);
    assert_eq!(empty_main.suffix_start(0, &AT).unwrap(), 0);
    assert_analysis_error(empty_main.suffix_start(1, &AT).unwrap_err());
}

#[test]
fn push_pop_and_peek_preserve_exact_values_and_lifo_order() {
    let values = [Value::number(7), Value::Unknown, Value::Bytes(vec![]), Value::Bytes(vec![0x80]), Value::Bytes(vec![1, 0])];
    let mut stack = with_values(&[], &[50, 60]);
    for (i, value) in values.iter().enumerate() {
        stack.push(value.clone(), &AT).unwrap();
        assert_eq!(stack.main_len(), i + 1);
        assert_eq!(stack.peek(0, &AT).unwrap(), value);
    }
    let before = stack.clone();
    for (depth, value) in values.iter().rev().enumerate() {
        assert_eq!(stack.peek(depth, &AT).unwrap(), value);
    }
    assert_analysis_error(stack.peek(values.len(), &AT).unwrap_err());
    assert_eq!(stack, before, "peek must not mutate either stack");
    for value in values.iter().rev() {
        assert_eq!(&stack.pop(&AT).unwrap(), value);
    }
    assert_analysis_error(stack.pop(&AT).unwrap_err());
    assert_eq!(stack, with_values(&[], &[50, 60]));
}

#[test]
fn push_rejects_combined_overflow_before_mutation() {
    let mut stack = Stack::new(1, MAX_STACK_SIZE - 2, &AT).unwrap();
    stack.push(Value::number(99), &AT).unwrap();
    let full = stack.clone();
    assert_limit_error(stack.push(Value::number(100), &AT).unwrap_err(), MAX_STACK_SIZE + 1);
    assert_eq!(stack, full);
    assert_eq!(stack.peek(0, &AT).unwrap(), &Value::number(99));
}

#[test]
fn pop_count_accepts_script_number_encodings() {
    for (bytes, expected) in [
        (vec![], 0),
        (vec![0], 0),
        (vec![0x80], 0), // empty, padded and negative zero
        (vec![1], 1),
        (vec![1, 0], 1), // nonminimal encodings are allowed here
        (vec![0x7f], 127),
        (vec![0x80, 0], 128),
        (vec![0xff, 0], 255),
        (vec![0, 1], 256),
    ] {
        let mut stack = with_values(&[42], &[50]);
        stack.push(Value::Bytes(bytes), &AT).unwrap();
        assert_eq!(stack.pop_count(&AT).unwrap(), expected);
        assert_eq!(stack, with_values(&[42], &[50]));
    }
    let mut stack = with_values(&[], &[]);
    stack.push(Value::Bytes(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]), &AT).unwrap();
    match usize::try_from(i64::MAX) {
        Ok(expected) => assert_eq!(stack.pop_count(&AT).unwrap(), expected),
        Err(_) => assert_analysis_error(stack.pop_count(&AT).unwrap_err()),
    }
}

#[test]
fn pop_count_rejects_unknown_negative_oversized_and_missing_values() {
    for value in [Value::Unknown, Value::Bytes(vec![0x81]), Value::Bytes(vec![0xff]), Value::Bytes(vec![0; 9])] {
        let mut stack = with_values(&[42], &[50]);
        stack.push(value, &AT).unwrap();
        assert_analysis_error(stack.pop_count(&AT).unwrap_err());
        assert_eq!(stack.alt, vec![Value::number(50)]);
    }
    assert_analysis_error(with_values(&[], &[50]).pop_count(&AT).unwrap_err());
}

#[test]
fn remove_uses_zero_based_depth_and_preserves_surrounding_order() {
    for (depth, removed, remaining) in
        [(0, 40, vec![10, 20, 30]), (1, 30, vec![10, 20, 40]), (2, 20, vec![10, 30, 40]), (3, 10, vec![20, 30, 40])]
    {
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        assert_eq!(stack.remove(depth, &AT).unwrap(), Value::number(removed));
        assert_eq!(stack, with_values(&remaining, &[50, 60]));
    }
    let mut stack = with_values(&[10, 20, 30, 40], &[50]);
    let before = stack.clone();
    assert_analysis_error(stack.remove(4, &AT).unwrap_err());
    assert_eq!(stack, before);
    assert_analysis_error(with_values(&[], &[50]).remove(0, &AT).unwrap_err());
}

#[test]
fn insert_places_values_above_below_and_between_existing_items() {
    for (depth, expected) in [
        (0, vec![10, 20, 30, 40, 99]),
        (1, vec![10, 20, 30, 99, 40]),
        (2, vec![10, 20, 99, 30, 40]),
        (3, vec![10, 99, 20, 30, 40]),
        (4, vec![99, 10, 20, 30, 40]),
    ] {
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        stack.insert(depth, Value::number(99), &AT).unwrap();
        assert_eq!(stack, with_values(&expected, &[50, 60]));
    }
    let mut empty = with_values(&[], &[50]);
    empty.insert(0, Value::number(99), &AT).unwrap();
    assert_eq!(empty, with_values(&[99], &[50]));
}

#[test]
fn insert_checks_depth_and_capacity_without_mutating_on_failure() {
    let mut stack = with_values(&[10, 20], &[50]);
    let before = stack.clone();
    assert_analysis_error(stack.insert(3, Value::number(99), &AT).unwrap_err());
    assert_eq!(stack, before);
    let mut full = Stack::new(2, MAX_STACK_SIZE - 2, &AT).unwrap();
    let before = full.clone();
    for depth in [0, 1, 2] {
        assert_limit_error(full.insert(depth, Value::number(99), &AT).unwrap_err(), MAX_STACK_SIZE + 1);
        assert_eq!(full, before);
    }
}

#[test]
fn extend_from_within_copies_the_selected_block_in_original_order() {
    for (depth, count, expected) in [
        (0, 0, vec![10, 20, 30, 40]),
        (4, 0, vec![10, 20, 30, 40]),
        (1, 1, vec![10, 20, 30, 40, 40]),
        (2, 1, vec![10, 20, 30, 40, 30]),
        (2, 2, vec![10, 20, 30, 40, 30, 40]),
        (3, 2, vec![10, 20, 30, 40, 20, 30]),
        (4, 2, vec![10, 20, 30, 40, 10, 20]),
        (4, 4, vec![10, 20, 30, 40, 10, 20, 30, 40]),
    ] {
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        stack.extend_from_within(depth, count, &AT).unwrap();
        assert_eq!(stack, with_values(&expected, &[50, 60]));
    }
    let mut stack = with_values(&[], &[50]);
    stack.extend_from_within(0, 0, &AT).unwrap();
    assert_eq!(stack, with_values(&[], &[50]));
}

#[test]
fn extend_from_within_validates_source_and_bulk_growth_before_mutation() {
    for (depth, count) in [(5, 0), (5, 1), (0, 1), (2, 3)] {
        let mut stack = with_values(&[10, 20, 30, 40], &[50]);
        let before = stack.clone();
        assert_analysis_error(stack.extend_from_within(depth, count, &AT).unwrap_err());
        assert_eq!(stack, before);
    }
    let mut stack = Stack::new(4, MAX_STACK_SIZE - 6, &AT).unwrap();
    stack.extend_from_within(4, 2, &AT).unwrap(); // exactly 244 combined
    let full = stack.clone();
    stack.extend_from_within(0, 0, &AT).unwrap();
    assert_eq!(stack, full);
    assert_limit_error(stack.extend_from_within(3, 3, &AT).unwrap_err(), MAX_STACK_SIZE + 3);
    assert_eq!(stack, full, "a bulk copy must not append even its first item when it cannot fit");
}

#[test]
fn rotate_left_rotates_only_the_requested_top_items() {
    for (count, shift, expected) in [
        (0, 0, vec![10, 20, 30, 40]),
        (1, 0, vec![10, 20, 30, 40]),
        (1, 1, vec![10, 20, 30, 40]),
        (4, 0, vec![10, 20, 30, 40]),
        (4, 4, vec![10, 20, 30, 40]),
        (2, 1, vec![10, 20, 40, 30]),
        (3, 1, vec![10, 30, 40, 20]),
        (3, 2, vec![10, 40, 20, 30]),
        (4, 1, vec![20, 30, 40, 10]),
        (4, 2, vec![30, 40, 10, 20]),
    ] {
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        stack.rotate_left(count, shift, &AT).unwrap();
        assert_eq!(stack, with_values(&expected, &[50, 60]));
    }
}

#[test]
fn rotate_left_checks_bounds_but_needs_no_spare_capacity() {
    let mut stack = with_values(&[10, 20, 30, 40], &[50]);
    let before = stack.clone();
    for (count, shift) in [(0, 1), (2, 3), (5, 0)] {
        assert_analysis_error(stack.rotate_left(count, shift, &AT).unwrap_err());
        assert_eq!(stack, before);
    }
    stack.alt = vec![Value::Unknown; MAX_STACK_SIZE - 4];
    stack.rotate_left(3, 1, &AT).unwrap();
    assert_eq!(stack.main_values(), with_values(&[10, 30, 40, 20], &[]).main_values());
    assert_eq!(stack.main_len() + stack.alt_len(), MAX_STACK_SIZE);
}

#[test]
fn drop_items_removes_only_the_requested_top_items() {
    for (count, expected) in [(0, vec![10, 20, 30, 40]), (1, vec![10, 20, 30]), (2, vec![10, 20]), (4, vec![])] {
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        stack.drop_items(count, &AT).unwrap();
        assert_eq!(stack, with_values(&expected, &[50, 60]));
    }
    let mut stack = with_values(&[], &[50]);
    stack.drop_items(0, &AT).unwrap();
    assert_analysis_error(stack.drop_items(1, &AT).unwrap_err());
    assert_eq!(stack, with_values(&[], &[50]));
    let mut stack = with_values(&[10, 20], &[50]);
    let before = stack.clone();
    assert_analysis_error(stack.drop_items(3, &AT).unwrap_err());
    assert_eq!(stack, before);
}

#[test]
fn apply_effect_preserves_lower_operands_and_pushes_unknown_results() {
    for (pops, pushes, expected) in [
        (0, 0, vec![Value::number(10), Value::number(20), Value::number(30), Value::number(40)]),
        (2, 3, vec![Value::number(10), Value::number(20), Value::Unknown, Value::Unknown, Value::Unknown]),
        (4, 0, vec![]),
        (4, 2, vec![Value::Unknown, Value::Unknown]),
    ] {
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        stack.apply_effect(pops, pushes, &AT).unwrap();
        assert_eq!(stack.main, expected);
        assert_eq!(stack.alt, with_values(&[], &[50, 60]).alt);
    }
    let mut stack = with_values(&[], &[50]);
    stack.apply_effect(0, 2, &AT).unwrap();
    assert_eq!(stack.main, vec![Value::Unknown, Value::Unknown]);
    assert_eq!(stack.alt, vec![Value::number(50)]);
}

#[test]
fn apply_effect_checks_net_capacity_and_rejects_missing_operands() {
    let mut full = Stack::new(4, MAX_STACK_SIZE - 4, &AT).unwrap();
    full.apply_effect(3, 3, &AT).unwrap();
    assert_eq!(full.main_len() + full.alt_len(), MAX_STACK_SIZE);
    full.apply_effect(3, 2, &AT).unwrap();
    full.apply_effect(0, 1, &AT).unwrap();
    assert_eq!(full.main_len() + full.alt_len(), MAX_STACK_SIZE);
    assert_limit_error(full.apply_effect(2, 3, &AT).unwrap_err(), MAX_STACK_SIZE + 1);
    // Failure may consume operands, but must never leave an oversized stack.
    assert!(full.main_len() + full.alt_len() <= MAX_STACK_SIZE);
    assert_eq!(full.alt_len(), MAX_STACK_SIZE - 4);
    let mut stack = with_values(&[10], &[50, 60]);
    let before = stack.clone();
    assert_analysis_error(stack.apply_effect(2, 0, &AT).unwrap_err());
    assert_eq!(stack, before);
}

#[test]
fn transfers_preserve_values_and_each_stacks_lifo_order() {
    let mut stack = with_values(&[10, 20, 30], &[50, 60]);
    stack.move_to_alt(&AT).unwrap();
    stack.move_to_alt(&AT).unwrap();
    assert_eq!(stack, with_values(&[10], &[50, 60, 30, 20]));
    stack.move_from_alt(&AT).unwrap();
    stack.move_from_alt(&AT).unwrap();
    stack.move_from_alt(&AT).unwrap();
    assert_eq!(stack, with_values(&[10, 20, 30, 60], &[50]));
    assert_eq!(stack.main_len() + stack.alt_len(), 5);
}

#[test]
fn transfers_reject_an_empty_source_without_changing_the_destination() {
    let mut main_empty = with_values(&[], &[50, 60]);
    let before = main_empty.clone();
    assert_analysis_error(main_empty.move_to_alt(&AT).unwrap_err());
    assert_eq!(main_empty, before);
    let mut alt_empty = with_values(&[10, 20], &[]);
    let before = alt_empty.clone();
    assert_analysis_error(alt_empty.move_from_alt(&AT).unwrap_err());
    assert_eq!(alt_empty, before);
}

#[test]
fn join_handles_all_combinations_of_terminated_paths() {
    let stack = with_values(&[10, 20], &[50]);
    assert_eq!(Stack::join(None, None, &AT).unwrap(), None);
    assert_eq!(Stack::join(Some(stack.clone()), None, &AT).unwrap(), Some(stack.clone()));
    assert_eq!(Stack::join(None, Some(stack.clone()), &AT).unwrap(), Some(stack));
}

#[test]
fn join_preserves_only_identical_values_on_both_stacks() {
    let left = Stack {
        main: vec![Value::number(1), Value::number(2), Value::Unknown, Value::Bytes(vec![])],
        alt: vec![Value::number(8), Value::Unknown],
    };
    let right = Stack {
        main: vec![Value::number(1), Value::number(3), Value::number(4), Value::Bytes(vec![0])],
        alt: vec![Value::number(8), Value::number(7)],
    };
    let expected = Stack {
        main: vec![Value::number(1), Value::Unknown, Value::Unknown, Value::Unknown],
        alt: vec![Value::number(8), Value::Unknown],
    };
    assert_eq!(Stack::join(Some(left), Some(right), &AT).unwrap(), Some(expected));
    // Zero encodings are numerically equivalent but distinct byte values.
}

#[test]
fn join_requires_each_stack_height_to_match_not_just_the_total() {
    for (left, right) in [
        (with_values(&[10], &[50]), with_values(&[10, 20], &[50])),
        (with_values(&[10], &[50]), with_values(&[10], &[50, 60])),
        (with_values(&[10, 20], &[50]), with_values(&[10], &[50, 60])),
        (with_values(&[], &[]), with_values(&[10], &[])),
    ] {
        assert_analysis_error(Stack::join(Some(left), Some(right), &AT).unwrap_err());
    }
    let full = Stack::new(120, 124, &AT).unwrap();
    assert_eq!(Stack::join(Some(full.clone()), Some(full.clone()), &AT).unwrap(), Some(full));
}

#[test]
fn join_is_idempotent_commutative_and_associative() {
    let values = [Value::Unknown, Value::number(0), Value::number(1)];
    let states: Vec<Stack> =
        values.iter().flat_map(|a| values.iter().map(move |b| Stack { main: vec![a.clone()], alt: vec![b.clone()] })).collect();
    let merge = |a: &Stack, b: &Stack| Stack::join(Some(a.clone()), Some(b.clone()), &AT).unwrap().unwrap();
    for a in &states {
        assert_eq!(merge(a, a), *a);
        for b in &states {
            assert_eq!(merge(a, b), merge(b, a));
            for c in &states {
                assert_eq!(merge(&merge(a, b), c), merge(a, &merge(b, c)));
            }
        }
    }
}

#[test]
fn failures_report_the_operation_location_not_the_constructor_location() {
    let origin = Location { function: "constructor", offset: 0 };
    let mut stack = Stack::new(0, MAX_STACK_SIZE, &origin).unwrap();
    assert_analysis_error(stack.pop(&AT).unwrap_err());
    assert_limit_error(stack.push(Value::Unknown, &AT).unwrap_err(), MAX_STACK_SIZE + 1);
}

#[test]
fn mixed_operations_match_an_independent_top_first_deque_model() {
    // The production stack stores its top at the end of a Vec. This model keeps
    // the top at the front of a deque, so ordering/index mistakes are independent.
    for seed in 0..32u64 {
        let mut random = seed + 1;
        let mut draw = |upper: usize| {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((random >> 32) as usize) % upper
        };
        let mut stack = with_values(&[10, 20, 30, 40], &[50, 60]);
        let mut main: VecDeque<Value> = stack.main.iter().rev().cloned().collect();
        let mut alt: VecDeque<Value> = stack.alt.iter().rev().cloned().collect();
        for turn in 0..256 {
            let operation = draw(12);
            match operation {
                0 if main.len() + alt.len() < 32 => {
                    let value = Value::number(draw(128) as i64);
                    stack.push(value.clone(), &AT).unwrap();
                    main.push_front(value);
                }
                1 if !main.is_empty() => assert_eq!(stack.pop(&AT).unwrap(), main.pop_front().unwrap()),
                2 if !main.is_empty() => {
                    let depth = draw(main.len());
                    assert_eq!(stack.peek(depth, &AT).unwrap(), &main[depth]);
                }
                3 if !main.is_empty() => {
                    let depth = draw(main.len());
                    assert_eq!(stack.remove(depth, &AT).unwrap(), main.remove(depth).unwrap());
                }
                4 if main.len() + alt.len() < 32 => {
                    let depth = draw(main.len() + 1);
                    let value = Value::number(draw(128) as i64);
                    stack.insert(depth, value.clone(), &AT).unwrap();
                    main.insert(depth, value);
                }
                5 => {
                    let depth = draw(main.len() + 1);
                    let count = draw(depth.min(32 - main.len() - alt.len()) + 1);
                    let copied: Vec<Value> = main.iter().skip(depth - count).take(count).cloned().collect();
                    stack.extend_from_within(depth, count, &AT).unwrap();
                    for value in copied.into_iter().rev() {
                        main.push_front(value);
                    }
                }
                6 => {
                    let count = draw(main.len() + 1);
                    let shift = draw(count + 1);
                    stack.rotate_left(count, shift, &AT).unwrap();
                    main.make_contiguous()[..count].rotate_right(shift);
                }
                7 => {
                    let count = draw(main.len() + 1);
                    stack.drop_items(count, &AT).unwrap();
                    for _ in 0..count {
                        main.pop_front();
                    }
                }
                8 => {
                    let pops = draw(main.len() + 1);
                    let pushes = draw((32 - main.len() - alt.len() + pops).min(3) + 1);
                    stack.apply_effect(pops, pushes, &AT).unwrap();
                    for _ in 0..pops {
                        main.pop_front();
                    }
                    for _ in 0..pushes {
                        main.push_front(Value::Unknown);
                    }
                }
                9 if !main.is_empty() => {
                    stack.move_to_alt(&AT).unwrap();
                    alt.push_front(main.pop_front().unwrap());
                }
                10 if !alt.is_empty() => {
                    stack.move_from_alt(&AT).unwrap();
                    main.push_front(alt.pop_front().unwrap());
                }
                11 => {
                    let count = draw(main.len() + 1);
                    let start = stack.suffix_start(count, &AT).unwrap();
                    let expected: Vec<Value> = main.iter().take(count).rev().cloned().collect();
                    assert_eq!(&stack.main_values()[start..], expected);
                }
                _ => {}
            }
            assert_eq!(
                stack.main_values(),
                main.iter().rev().cloned().collect::<Vec<_>>(),
                "main: seed {seed}, turn {turn}, operation {operation}"
            );
            assert_eq!(
                stack.alt,
                alt.iter().rev().cloned().collect::<Vec<_>>(),
                "alt: seed {seed}, turn {turn}, operation {operation}"
            );
            assert_eq!(stack.main_len(), main.len());
            assert_eq!(stack.alt_len(), alt.len());
        }
    }
}
