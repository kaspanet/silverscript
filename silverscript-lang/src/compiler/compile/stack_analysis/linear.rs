//! Linear forms over byte-length symbols.
//!
//! The analyzer bounds every stack item's byte length, and every script-unit
//! charge, by `constant + Σ coefficient × symbol`, where each symbol stands for
//! a runtime byte length the compiler cannot know: a variable-length entrypoint
//! argument, a variable-length state field, or a transaction field read through
//! introspection. Coefficients are unsigned, so forms can be compared term by
//! term; the constant may be negative so that `length - 4`, the right part of
//! a split, stays representable and cancels exactly in a later subtraction.

use std::collections::BTreeMap;
use std::fmt;

use crate::checked_arithmetic::{checked_add, checked_mul};
use crate::errors::CompilerError;

/// A runtime byte length the compiler cannot know statically.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Symbol {
    /// The encoded length of a variable-length entrypoint argument or state
    /// field. The caller chooses the display name, for example `seal` or
    /// `state.note`.
    Named(String),
    /// The length of a transaction field read through introspection.
    Introspection { source: IntrospectionSource, index: IndexKey },
    /// The length of the redeem script the spender pushes: the contract's
    /// bytecode with its current state, which the pay-to-script-hash wrapper hashes.
    RedeemScript,
    /// The active input index. It only ever appears inside numeric values, never
    /// in a byte-length bound: the length of its script encoding is bounded
    /// separately.
    ActiveInputIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum IntrospectionSource {
    SignatureScript,
    InputScriptPublicKey,
    OutputScriptPublicKey,
    Payload,
}

/// Identifies which input or output an introspection symbol refers to.
///
/// Two symbols denote the same runtime length only when their keys are equal.
/// An `Opaque` key is minted per evaluation, so lengths of inputs selected by
/// unknown indices never cancel against each other in a subtraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum IndexKey {
    /// The source is not indexed (the transaction payload).
    None,
    Literal(i64),
    ActiveInput,
    Opaque(u64),
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Symbol::Named(name) => f.write_str(name),
            Symbol::ActiveInputIndex => f.write_str("this.activeInputIndex"),
            Symbol::RedeemScript => f.write_str("redeem_script"),
            Symbol::Introspection { source, index } => {
                let index = match index {
                    IndexKey::None => String::new(),
                    IndexKey::Literal(index) => format!("[{index}]"),
                    IndexKey::ActiveInput => "[this.activeInputIndex]".to_string(),
                    IndexKey::Opaque(_) => "[*]".to_string(),
                };
                match source {
                    IntrospectionSource::SignatureScript => write!(f, "tx.inputs{index}.signature_script"),
                    IntrospectionSource::InputScriptPublicKey => write!(f, "tx.inputs{index}.script_public_key"),
                    IntrospectionSource::OutputScriptPublicKey => write!(f, "tx.outputs{index}.script_public_key"),
                    IntrospectionSource::Payload => f.write_str("tx.payload"),
                }
            }
        }
    }
}

/// `constant + Σ coefficient × symbol` with unsigned coefficients. Zero
/// coefficients are never stored, so equal forms compare equal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Linear {
    constant: i64,
    terms: BTreeMap<Symbol, u64>,
}

impl Linear {
    pub(crate) fn constant(constant: i64) -> Self {
        Self { constant, terms: BTreeMap::new() }
    }

    pub(crate) fn symbol(symbol: Symbol) -> Self {
        Self { constant: 0, terms: BTreeMap::from([(symbol, 1)]) }
    }

    pub(crate) fn constant_part(&self) -> i64 {
        self.constant
    }

    pub(crate) fn terms(&self) -> &BTreeMap<Symbol, u64> {
        &self.terms
    }

    /// The constant value of a form without symbols.
    pub(crate) fn as_constant(&self) -> Option<i64> {
        self.terms.is_empty().then_some(self.constant)
    }

    /// The single symbol of a form equal to exactly that symbol.
    pub(crate) fn as_symbol(&self) -> Option<&Symbol> {
        match (self.constant, self.terms.iter().next()) {
            (0, Some((symbol, 1))) if self.terms.len() == 1 => Some(symbol),
            _ => None,
        }
    }

    pub(crate) fn add(&self, other: &Self) -> Result<Self, CompilerError> {
        let mut result = self.clone();
        result.constant = checked_add(result.constant, other.constant)?;
        for (symbol, coefficient) in &other.terms {
            let entry = result.terms.entry(symbol.clone()).or_insert(0);
            *entry = checked_add(*entry, *coefficient)?;
        }
        Ok(result)
    }

    pub(crate) fn add_constant(&self, constant: i64) -> Result<Self, CompilerError> {
        self.add(&Self::constant(constant))
    }

    pub(crate) fn mul_constant(&self, factor: u64) -> Result<Self, CompilerError> {
        if factor == 0 {
            return Ok(Self::default());
        }
        let mut result = self.clone();
        result.constant = checked_mul(result.constant, i64::try_from(factor).map_err(|_| overflow(factor))?)?;
        for coefficient in result.terms.values_mut() {
            *coefficient = checked_mul(*coefficient, factor)?;
        }
        Ok(result)
    }

    /// `self - other`, or None when a coefficient would go negative or the
    /// constant overflows.
    pub(crate) fn checked_sub(&self, other: &Self) -> Option<Self> {
        let mut result = self.clone();
        result.constant = result.constant.checked_sub(other.constant)?;
        for (symbol, coefficient) in &other.terms {
            let remaining = result.terms.get(symbol)?.checked_sub(*coefficient)?;
            if remaining == 0 {
                result.terms.remove(symbol);
            } else {
                result.terms.insert(symbol.clone(), remaining);
            }
        }
        Some(result)
    }

    /// The term-by-term maximum: an upper bound of both forms for every
    /// assignment of the symbols.
    pub(crate) fn max(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.constant = result.constant.max(other.constant);
        for (symbol, coefficient) in &other.terms {
            let entry = result.terms.entry(symbol.clone()).or_insert(0);
            *entry = (*entry).max(*coefficient);
        }
        result
    }
}

fn overflow(factor: u64) -> CompilerError {
    CompilerError::ArithmeticOverflow(format!("factor {factor} exceeds i64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> Symbol {
        Symbol::Named(name.to_string())
    }

    #[test]
    fn arithmetic_tracks_constants_and_coefficients() {
        let a = Linear::constant(3).add(&Linear::symbol(named("a"))).unwrap();
        let b = Linear::symbol(named("a")).add(&Linear::symbol(named("b"))).unwrap();
        let sum = a.add(&b).unwrap();
        assert_eq!(sum.constant_part(), 3);
        assert_eq!(sum.terms(), &BTreeMap::from([(named("a"), 2), (named("b"), 1)]));
        assert_eq!(sum.mul_constant(2).unwrap().terms(), &BTreeMap::from([(named("a"), 4), (named("b"), 2)]));
        assert_eq!(sum.mul_constant(0).unwrap(), Linear::default());
        assert_eq!(sum.checked_sub(&b).unwrap(), a);
        assert_eq!(sum.checked_sub(&b).unwrap().checked_sub(&Linear::symbol(named("a"))).unwrap(), Linear::constant(3));
        assert_eq!(a.checked_sub(&b), None, "a negative coefficient is not representable");
        assert_eq!(Linear::constant(1).checked_sub(&Linear::constant(2)), Some(Linear::constant(-1)), "constants may go negative");
        assert_eq!(
            Linear::symbol(named("a")).checked_sub(&Linear::constant(4)).unwrap().add_constant(4).unwrap(),
            Linear::symbol(named("a"))
        );
        assert_eq!(Linear::constant(i64::MIN).checked_sub(&Linear::constant(1)), None);
        assert!(matches!(Linear::constant(i64::MAX).add_constant(1), Err(CompilerError::ArithmeticOverflow(_))));
        assert!(matches!(Linear::constant(i64::MAX).mul_constant(2), Err(CompilerError::ArithmeticOverflow(_))));
        assert!(matches!(Linear::constant(1).mul_constant(u64::MAX), Err(CompilerError::ArithmeticOverflow(_))));
    }

    #[test]
    fn max_is_an_upper_bound_of_both_sides() {
        let a = Linear::constant(5).add(&Linear::symbol(named("a")).mul_constant(3).unwrap()).unwrap();
        let b = Linear::constant(2).add(&Linear::symbol(named("b"))).unwrap();
        let max = a.max(&b);
        assert_eq!(max.constant_part(), 5);
        assert_eq!(max.terms(), &BTreeMap::from([(named("a"), 3), (named("b"), 1)]));
        assert_eq!(max.checked_sub(&a).unwrap(), Linear::symbol(named("b")));
        assert_eq!(
            max.checked_sub(&b).unwrap(),
            Linear::constant(3).add(&Linear::symbol(named("a")).mul_constant(3).unwrap()).unwrap()
        );
    }

    #[test]
    fn constant_and_symbol_views() {
        assert_eq!(Linear::constant(7).as_constant(), Some(7));
        assert_eq!(Linear::symbol(named("a")).as_constant(), None);
        assert_eq!(Linear::symbol(named("a")).as_symbol(), Some(&named("a")));
        assert_eq!(Linear::symbol(named("a")).add_constant(1).unwrap().as_symbol(), None);
        assert_eq!(Linear::symbol(named("a")).mul_constant(2).unwrap().as_symbol(), None);
    }

    #[test]
    fn symbols_display_as_artifact_keys() {
        let introspection = |source, index| Symbol::Introspection { source, index };
        assert_eq!(named("seal").to_string(), "seal");
        assert_eq!(Symbol::ActiveInputIndex.to_string(), "this.activeInputIndex");
        assert_eq!(Symbol::RedeemScript.to_string(), "redeem_script");
        assert_eq!(introspection(IntrospectionSource::Payload, IndexKey::None).to_string(), "tx.payload");
        assert_eq!(
            introspection(IntrospectionSource::SignatureScript, IndexKey::Literal(2)).to_string(),
            "tx.inputs[2].signature_script"
        );
        assert_eq!(
            introspection(IntrospectionSource::InputScriptPublicKey, IndexKey::ActiveInput).to_string(),
            "tx.inputs[this.activeInputIndex].script_public_key"
        );
        assert_eq!(
            introspection(IntrospectionSource::OutputScriptPublicKey, IndexKey::Opaque(9)).to_string(),
            "tx.outputs[*].script_public_key"
        );
    }
}
