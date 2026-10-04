use super::{Location, Value};
use crate::checked_arithmetic::{checked_add, checked_sub};
use crate::errors::CompilerError;
use kaspa_txscript::{MAX_STACK_SIZE, deserialize_i64};

/// Checked stacks for one execution path. `main` holds ordinary operands and
/// `alt` holds values moved aside; both run bottom-to-top. The vectors are private
/// so callers must use operations that check operand availability and combined
/// capacity. Each operation receives the current `Location` for its errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Stack {
    main: Vec<Value>,
    alt: Vec<Value>,
}

impl Stack {
    pub(super) fn new(main_items: usize, alt_items: usize, at: &Location<'_>) -> Result<Self, CompilerError> {
        let mut stack = Self { main: Vec::new(), alt: Vec::new() };
        stack.require_capacity(checked_add(main_items, alt_items)?, at)?;
        stack.main = vec![Value::Unknown; main_items];
        stack.alt = vec![Value::Unknown; alt_items];
        Ok(stack)
    }

    /// Return the starting index of the top `count` main-stack items without
    /// modifying the stack. Fail with an underflow error if fewer items exist.
    /// For [a, b, c, d], count 2 returns index 2 (c); count 0 returns 4.
    pub(super) fn suffix_start(&self, count: usize, at: &Location<'_>) -> Result<usize, CompilerError> {
        if self.main.len() < count {
            return Err(at.error(format!("main stack underflow: need {count} items, have {}", self.main.len())));
        }
        checked_sub(self.main.len(), count)
    }

    /// Require room for additional items across BOTH stacks before adding any.
    pub(super) fn require_capacity(&self, additional: usize, at: &Location<'_>) -> Result<(), CompilerError> {
        let actual = checked_add(checked_add(self.main.len(), self.alt.len())?, additional)?;
        if actual > MAX_STACK_SIZE {
            return Err(at.stack_too_large(actual));
        }
        Ok(())
    }

    pub(super) fn main_len(&self) -> usize {
        self.main.len()
    }

    pub(super) fn push(&mut self, value: Value, at: &Location<'_>) -> Result<(), CompilerError> {
        self.require_capacity(1, at)?;
        self.main.push(value);
        Ok(())
    }

    pub(super) fn pop(&mut self, at: &Location<'_>) -> Result<Value, CompilerError> {
        self.suffix_start(1, at)?;
        Ok(self.main.pop().expect("one item checked"))
    }

    /// Pop a known nonnegative integer used as a stack index or argument count.
    pub(super) fn pop_count(&mut self, at: &Location<'_>) -> Result<usize, CompilerError> {
        if let Value::Bytes(bytes) = self.pop(at)?
            && let Ok(number) = deserialize_i64(&bytes)
            && let Ok(count) = usize::try_from(number)
        {
            return Ok(count);
        }
        Err(at.error("stack index or argument count is not a known nonnegative integer"))
    }

    pub(super) fn peek(&self, depth: usize, at: &Location<'_>) -> Result<&Value, CompilerError> {
        let index = self.suffix_start(checked_add(depth, 1)?, at)?;
        Ok(&self.main[index])
    }

    pub(super) fn remove(&mut self, depth: usize, at: &Location<'_>) -> Result<Value, CompilerError> {
        let index = self.suffix_start(checked_add(depth, 1)?, at)?;
        Ok(self.main.remove(index))
    }

    /// Insert below `depth` existing items; zero means push on top.
    pub(super) fn insert(&mut self, depth: usize, value: Value, at: &Location<'_>) -> Result<(), CompilerError> {
        let index = self.suffix_start(depth, at)?;
        self.require_capacity(1, at)?;
        self.main.insert(index, value);
        Ok(())
    }

    /// Append copies of the first `count` items in the top `depth` main-stack items.
    pub(super) fn extend_from_within(&mut self, depth: usize, count: usize, at: &Location<'_>) -> Result<(), CompilerError> {
        let start = self.suffix_start(depth, at)?;
        if count > depth {
            return Err(at.error("stack copy extends past the top item"));
        }
        self.require_capacity(count, at)?;
        self.main.extend_from_within(start..checked_add(start, count)?);
        Ok(())
    }

    pub(super) fn rotate_left(&mut self, count: usize, shift: usize, at: &Location<'_>) -> Result<(), CompilerError> {
        let start = self.suffix_start(count, at)?;
        if shift > count {
            return Err(at.error("stack rotation exceeds its operand count"));
        }
        self.main[start..].rotate_left(shift);
        Ok(())
    }

    pub(super) fn drop_items(&mut self, count: usize, at: &Location<'_>) -> Result<(), CompilerError> {
        let start = self.suffix_start(count, at)?;
        self.main.truncate(start);
        Ok(())
    }

    pub(super) fn apply_effect(&mut self, pops: usize, pushes: usize, at: &Location<'_>) -> Result<(), CompilerError> {
        self.drop_items(pops, at)?;
        // Operands are consumed before results are produced. Check the resulting
        // size, so replacing items at the limit doesn't appear to overflow.
        self.require_capacity(pushes, at)?;
        self.main.extend(std::iter::repeat_n(Value::Unknown, pushes));
        Ok(())
    }

    pub(super) fn move_to_alt(&mut self, at: &Location<'_>) -> Result<(), CompilerError> {
        let value = self.pop(at)?;
        // A transfer leaves combined usage unchanged, even at full capacity.
        self.alt.push(value);
        Ok(())
    }

    pub(super) fn move_from_alt(&mut self, at: &Location<'_>) -> Result<(), CompilerError> {
        let value = self.alt.pop().ok_or_else(|| at.error("alternate stack underflow"))?;
        // The item was already counted on alt; this does not require extra room.
        self.main.push(value);
        Ok(())
    }

    /// Merge continuing paths with equal heights. Differing values become unknown;
    /// no slots are added. None denotes a path that cannot continue after a branch.
    pub(super) fn join(left: Option<Self>, right: Option<Self>, at: &Location<'_>) -> Result<Option<Self>, CompilerError> {
        match (left, right) {
            (None, stack) | (stack, None) => Ok(stack),
            (Some(mut left), Some(right)) => {
                if left.main.len() != right.main.len() || left.alt.len() != right.alt.len() {
                    return Err(at.error("continuing branches have different main or alternate stack heights"));
                }
                for (a, b) in left.main.iter_mut().chain(&mut left.alt).zip(right.main.iter().chain(&right.alt)) {
                    if a != b {
                        *a = Value::Unknown;
                    }
                }
                Ok(Some(left))
            }
        }
    }

    #[cfg(test)]
    pub(super) fn main_values(&self) -> &[Value] {
        &self.main
    }

    #[cfg(test)]
    pub(super) fn alt_len(&self) -> usize {
        self.alt.len()
    }
}

#[cfg(test)]
mod tests;
