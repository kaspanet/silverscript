use super::linear::{IndexKey, Linear};
use super::{Location, Value};
use crate::checked_arithmetic::{checked_add, checked_mul, checked_sub};
use crate::errors::CompilerError;
use kaspa_txscript::{MAX_STACK_SIZE, deserialize_i64};

/// Checked stacks for one execution path. `main` holds ordinary operands and
/// `alt` holds values moved aside; both run bottom-to-top. The vectors are private
/// so callers must use operations that check operand availability and combined
/// capacity. Each operation receives the current `Location` for its errors.
///
/// The stack also meters the path the way the VM does: every byte an opcode
/// newly places on either stack costs one script unit, and hashing, signature
/// checks, and proof verification add their own charges. `push` and `insert`
/// meter the pushed value; `push_unmetered` and the alt-stack moves do not,
/// matching the VM's literal pushes and pure moves. `units` is an upper bound
/// of the charged units, or None once a charge could not be bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Stack {
    main: Vec<Value>,
    alt: Vec<Value>,
    units: Option<Linear>,
    sig_ops: u64,
    next_opaque_index: u64,
}

impl Stack {
    pub(super) fn new(main_items: usize, alt_items: usize, at: &Location<'_>) -> Result<Self, CompilerError> {
        let stack = Self::from_values(Vec::new(), Vec::new(), at)?;
        stack.require_capacity(checked_add(main_items, alt_items)?, at)?;
        Ok(Self { main: vec![Value::Unknown; main_items], alt: vec![Value::Unknown; alt_items], ..stack })
    }

    pub(super) fn from_values(main: Vec<Value>, alt: Vec<Value>, at: &Location<'_>) -> Result<Self, CompilerError> {
        let stack = Self { main: Vec::new(), alt: Vec::new(), units: Some(Linear::default()), sig_ops: 0, next_opaque_index: 0 };
        stack.require_capacity(checked_add(main.len(), alt.len())?, at)?;
        Ok(Self { main, alt, ..stack })
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

    /// The script units charged along this path so far, or None once a charge
    /// could not be bounded.
    pub(super) fn units(&self) -> Option<&Linear> {
        self.units.as_ref()
    }

    pub(super) fn sig_ops(&self) -> u64 {
        self.sig_ops
    }

    /// Charge script units.
    pub(super) fn charge(&mut self, units: &Linear) -> Result<(), CompilerError> {
        if let Some(total) = &self.units {
            self.units = Some(total.add(units)?);
        }
        Ok(())
    }

    pub(super) fn charge_constant(&mut self, units: u64) -> Result<(), CompilerError> {
        self.charge(&Linear::constant(units as i64))
    }

    /// Charge `units_per_byte` script units for every byte of `value`, or record
    /// that the path's cost is unbounded when the value's length is.
    pub(super) fn charge_per_byte(&mut self, value: &Value, units_per_byte: u64) -> Result<(), CompilerError> {
        match value.len_bound() {
            Some(len) => self.charge(&len.mul_constant(units_per_byte)?),
            None => {
                self.units = None;
                Ok(())
            }
        }
    }

    /// Count signature operations and charge their script units.
    pub(super) fn charge_sig_ops(&mut self, count: u64, units_per_sig_op: u64) -> Result<(), CompilerError> {
        self.sig_ops = checked_add(self.sig_ops, count)?;
        self.charge_constant(checked_mul(count, units_per_sig_op)?)
    }

    /// Mint a key for an input or output selected by an index the analyzer does
    /// not know. Each key is distinct, so two such lengths never cancel.
    pub(super) fn opaque_index(&mut self) -> Result<IndexKey, CompilerError> {
        let key = IndexKey::Opaque(self.next_opaque_index);
        self.next_opaque_index = checked_add(self.next_opaque_index, 1)?;
        Ok(key)
    }

    /// Push a value the VM meters, charging its bytes.
    pub(super) fn push(&mut self, value: Value, at: &Location<'_>) -> Result<(), CompilerError> {
        self.require_capacity(1, at)?;
        self.charge_per_byte(&value, 1)?;
        self.main.push(value);
        Ok(())
    }

    /// Push a value the VM does not meter: a literal, whose bytes are paid for
    /// in the script size.
    pub(super) fn push_unmetered(&mut self, value: Value, at: &Location<'_>) -> Result<(), CompilerError> {
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
            && let Ok(number) = deserialize_i64(&bytes, false)
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

    /// Insert below `depth` existing items; zero means push on top. The VM
    /// meters inserted values.
    pub(super) fn insert(&mut self, depth: usize, value: Value, at: &Location<'_>) -> Result<(), CompilerError> {
        let index = self.suffix_start(depth, at)?;
        self.require_capacity(1, at)?;
        self.charge_per_byte(&value, 1)?;
        self.main.insert(index, value);
        Ok(())
    }

    /// Append copies of the first `count` items in the top `depth` main-stack
    /// items. The VM meters the copied bytes.
    pub(super) fn extend_from_within(&mut self, depth: usize, count: usize, at: &Location<'_>) -> Result<(), CompilerError> {
        let start = self.suffix_start(depth, at)?;
        if count > depth {
            return Err(at.error("stack copy extends past the top item"));
        }
        self.require_capacity(count, at)?;
        let end = checked_add(start, count)?;
        for index in start..end {
            let value = self.main[index].clone();
            self.charge_per_byte(&value, 1)?;
        }
        self.main.extend_from_within(start..end);
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

    /// Replace `pops` operands with the given results, metering the results.
    pub(super) fn apply_effect(&mut self, pops: usize, results: Vec<Value>, at: &Location<'_>) -> Result<(), CompilerError> {
        self.drop_items(pops, at)?;
        // Operands are consumed before results are produced. Check the resulting
        // size, so replacing items at the limit doesn't appear to overflow.
        self.require_capacity(results.len(), at)?;
        for value in results {
            self.charge_per_byte(&value, 1)?;
            self.main.push(value);
        }
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

    /// Merge continuing paths with equal heights. Differing values keep only a
    /// common length bound; no slots are added. The merged charges are the
    /// term-by-term maximum of both paths, so they bound either path. None
    /// denotes a path that cannot continue after a branch.
    pub(super) fn join(left: Option<Self>, right: Option<Self>, at: &Location<'_>) -> Result<Option<Self>, CompilerError> {
        match (left, right) {
            (None, stack) | (stack, None) => Ok(stack),
            (Some(mut left), Some(right)) => {
                if left.main.len() != right.main.len() || left.alt.len() != right.alt.len() {
                    return Err(at.error("continuing branches have different main or alternate stack heights"));
                }
                for (a, b) in left.main.iter_mut().chain(&mut left.alt).zip(right.main.iter().chain(&right.alt)) {
                    if a != b {
                        *a = Value::join(a, b);
                    }
                }
                left.units = match (left.units, right.units) {
                    (Some(a), Some(b)) => Some(a.max(&b)),
                    _ => None,
                };
                left.sig_ops = left.sig_ops.max(right.sig_ops);
                left.next_opaque_index = left.next_opaque_index.max(right.next_opaque_index);
                Ok(Some(left))
            }
        }
    }

    #[cfg(test)]
    pub(super) fn main_values(&self) -> &[Value] {
        &self.main
    }

    /// Both stacks without the metered charges.
    #[cfg(test)]
    pub(super) fn values(&self) -> (&[Value], &[Value]) {
        (&self.main, &self.alt)
    }

    #[cfg(test)]
    pub(super) fn alt_len(&self) -> usize {
        self.alt.len()
    }
}

#[cfg(test)]
mod tests;
