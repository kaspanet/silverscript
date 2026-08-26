use std::fmt::Display;

use crate::errors::CompilerError;

pub(crate) trait CheckedArithmetic: Copy + Display {
    fn checked_add_value(self, right: Self) -> Option<Self>;
    fn checked_sub_value(self, right: Self) -> Option<Self>;
    fn checked_mul_value(self, right: Self) -> Option<Self>;
    fn checked_div_value(self, right: Self) -> Option<Self>;
    fn checked_rem_value(self, right: Self) -> Option<Self>;
    fn checked_pow_value(self, exponent: u32) -> Option<Self>;
}

macro_rules! impl_checked_arithmetic {
    ($($type:ty),+ $(,)?) => {
        $(
            impl CheckedArithmetic for $type {
                fn checked_add_value(self, right: Self) -> Option<Self> { self.checked_add(right) }
                fn checked_sub_value(self, right: Self) -> Option<Self> { self.checked_sub(right) }
                fn checked_mul_value(self, right: Self) -> Option<Self> { self.checked_mul(right) }
                fn checked_div_value(self, right: Self) -> Option<Self> { self.checked_div(right) }
                fn checked_rem_value(self, right: Self) -> Option<Self> { self.checked_rem(right) }
                fn checked_pow_value(self, exponent: u32) -> Option<Self> { self.checked_pow(exponent) }
            }
        )+
    };
}

impl_checked_arithmetic!(i64, i128, usize);

pub(crate) trait CheckedNeg: Copy + Display {
    fn checked_neg_value(self) -> Option<Self>;
}

impl CheckedNeg for i64 {
    fn checked_neg_value(self) -> Option<Self> {
        self.checked_neg()
    }
}

pub(crate) fn checked_add<T: CheckedArithmetic>(left: T, right: T) -> Result<T, CompilerError> {
    left.checked_add_value(right).ok_or_else(|| CompilerError::ArithmeticOverflow(format!("{left} + {right}")))
}

pub(crate) fn checked_sub<T: CheckedArithmetic>(left: T, right: T) -> Result<T, CompilerError> {
    left.checked_sub_value(right).ok_or_else(|| CompilerError::ArithmeticOverflow(format!("{left} - {right}")))
}

pub(crate) fn checked_mul<T: CheckedArithmetic>(left: T, right: T) -> Result<T, CompilerError> {
    left.checked_mul_value(right).ok_or_else(|| CompilerError::ArithmeticOverflow(format!("{left} * {right}")))
}

pub(crate) fn checked_div<T: CheckedArithmetic>(left: T, right: T) -> Result<T, CompilerError> {
    left.checked_div_value(right).ok_or_else(|| CompilerError::ArithmeticOverflow(format!("{left} / {right}")))
}

pub(crate) fn checked_rem<T: CheckedArithmetic>(left: T, right: T) -> Result<T, CompilerError> {
    left.checked_rem_value(right).ok_or_else(|| CompilerError::ArithmeticOverflow(format!("{left} % {right}")))
}

pub(crate) fn checked_pow<T: CheckedArithmetic>(base: T, exponent: u32) -> Result<T, CompilerError> {
    base.checked_pow_value(exponent).ok_or_else(|| CompilerError::ArithmeticOverflow(format!("{base}^{exponent}")))
}

pub(crate) fn checked_neg<T: CheckedNeg>(value: T) -> Result<T, CompilerError> {
    value.checked_neg_value().ok_or_else(|| CompilerError::ArithmeticOverflow(format!("-({value})")))
}
