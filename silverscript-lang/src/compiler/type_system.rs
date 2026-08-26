use std::collections::HashMap;

use crate::ast::{ArrayDim, Expr, TypeBase, TypeRef};
use crate::checked_arithmetic::{checked_add, checked_mul};
use crate::errors::CompilerError;

use super::eval_const_int;

pub(crate) fn type_refs_equal<'i>(
    left: &TypeRef,
    right: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<bool, CompilerError> {
    if !bases_equal(&left.base, &right.base, constants)? || left.array_dims.len() != right.array_dims.len() {
        return Ok(false);
    }
    for (left, right) in left.array_dims.iter().zip(&right.array_dims) {
        if !dimensions_equal(left, right, constants)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn bases_equal<'i>(left: &TypeBase, right: &TypeBase, constants: &HashMap<String, Expr<'i>>) -> Result<bool, CompilerError> {
    match (left, right) {
        (TypeBase::Tuple(left), TypeBase::Tuple(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left, right) in left.iter().zip(right) {
                if !type_refs_equal(left, right, constants)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(left == right),
    }
}

pub(crate) fn array_size<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Result<Option<usize>, CompilerError> {
    let Some(dimension) = type_ref.array_size() else { return Ok(None) };
    dimension_value(dimension, constants)
}

pub(crate) fn fixed_type_size<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Result<Option<usize>, CompilerError> {
    if type_ref.is_array() {
        let Some(element_type) = type_ref.array_element_type() else { return Ok(None) };
        let Some(element_size) = fixed_type_size(&element_type, constants)? else { return Ok(None) };
        let Some(array_len) = array_size(type_ref, constants)? else { return Ok(None) };
        return checked_mul(element_size, array_len).map(Some);
    }

    Ok(match type_ref.base {
        TypeBase::Int | TypeBase::Temporal => Some(8),
        TypeBase::Bool | TypeBase::Byte => Some(1),
        TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig => type_ref.base.fixed_byte_sequence_len(),
        TypeBase::String | TypeBase::Tuple(_) | TypeBase::Custom(_) => None,
    })
}

pub(crate) fn concat_types<'i>(
    left: &TypeRef,
    right: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Option<TypeRef>, CompilerError> {
    let Some(element) = left.array_element_type() else { return Ok(None) };
    let Some(right_element) = right.array_element_type() else { return Ok(None) };
    if !type_refs_equal(&element, &right_element, constants)? {
        return Ok(None);
    }

    let Some(left_dimension) = left.array_size() else { return Ok(None) };
    let Some(right_dimension) = right.array_size() else { return Ok(None) };
    let dimension = match (left_dimension, right_dimension) {
        (ArrayDim::Dynamic, _) | (_, ArrayDim::Dynamic) => ArrayDim::Dynamic,
        (left, right) => {
            let Some(left) = dimension_value(left, constants)? else { return Ok(None) };
            let Some(right) = dimension_value(right, constants)? else { return Ok(None) };
            ArrayDim::Fixed(checked_add(left, right)?)
        }
    };
    let mut result = element;
    result.array_dims.push(dimension);
    Ok(Some(result))
}

pub(crate) fn append_type<'i>(
    source: &TypeRef,
    appended: usize,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Option<TypeRef>, CompilerError> {
    let mut result = source.clone();
    let Some(dimension) = result.array_dims.last_mut() else { return Ok(None) };
    *dimension = match &*dimension {
        ArrayDim::Dynamic => ArrayDim::Dynamic,
        dimension => {
            let Some(size) = dimension_value(dimension, constants)? else { return Ok(None) };
            ArrayDim::Fixed(checked_add(size, appended)?)
        }
    };
    Ok(Some(result))
}

fn dimensions_equal<'i>(left: &ArrayDim, right: &ArrayDim, constants: &HashMap<String, Expr<'i>>) -> Result<bool, CompilerError> {
    Ok(match (left, right) {
        (ArrayDim::Dynamic, ArrayDim::Dynamic) | (ArrayDim::Inferred, ArrayDim::Inferred) => true,
        (ArrayDim::Dynamic | ArrayDim::Inferred, _) | (_, ArrayDim::Dynamic | ArrayDim::Inferred) => false,
        _ => dimension_value(left, constants)? == dimension_value(right, constants)?,
    })
}

fn dimension_value<'i>(dimension: &ArrayDim, constants: &HashMap<String, Expr<'i>>) -> Result<Option<usize>, CompilerError> {
    Ok(match dimension {
        ArrayDim::Fixed(size) => Some(*size),
        ArrayDim::Constant(name) => {
            let expr =
                constants.get(name).ok_or_else(|| CompilerError::UndefinedIdentifier(format!("array dimension constant '{name}'")))?;
            let value = eval_const_int(expr, constants)?;
            Some(
                usize::try_from(value)
                    .map_err(|_| CompilerError::InvalidLiteral(format!("array dimension '{name}' must be a non-negative integer")))?,
            )
        }
        ArrayDim::Dynamic | ArrayDim::Inferred => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_type_size_reports_multiplication_overflow() {
        let type_ref = TypeRef { base: TypeBase::Int, array_dims: vec![ArrayDim::Fixed(usize::MAX / 8 + 1)] };
        let err = fixed_type_size(&type_ref, &HashMap::new()).expect_err("fixed byte-size overflow must be an error");

        assert!(matches!(err, CompilerError::ArithmeticOverflow(_)), "unexpected error: {err}");
    }

    #[test]
    fn array_dimension_arithmetic_reports_overflow_instead_of_inference_failure() {
        let max = TypeRef { base: TypeBase::Int, array_dims: vec![ArrayDim::Fixed(usize::MAX)] };
        let one = TypeRef { base: TypeBase::Int, array_dims: vec![ArrayDim::Fixed(1)] };

        let concat_err = concat_types(&max, &one, &HashMap::new()).expect_err("concatenated dimension must overflow");
        assert!(matches!(concat_err, CompilerError::ArithmeticOverflow(_)), "unexpected error: {concat_err}");

        let append_err = append_type(&max, 1, &HashMap::new()).expect_err("appended dimension must overflow");
        assert!(matches!(append_err, CompilerError::ArithmeticOverflow(_)), "unexpected error: {append_err}");
    }

    #[test]
    fn invalid_constant_dimensions_are_errors_instead_of_unknown_sizes() {
        let type_ref = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Constant("N".to_string())] };

        let err = array_size(&type_ref, &HashMap::new()).expect_err("a missing dimension constant must not become None");
        assert!(matches!(err, CompilerError::UndefinedIdentifier(_)), "unexpected error: {err}");

        let negative_constants = HashMap::from([("N".to_string(), Expr::int(-1))]);
        let err = array_size(&type_ref, &negative_constants).expect_err("a negative dimension must not become None");
        assert!(matches!(err, CompilerError::InvalidLiteral(_)), "unexpected error: {err}");

        let overflow = Expr::new(
            crate::ast::ExprKind::Binary {
                op: crate::ast::BinaryOp::Add,
                left: Box::new(Expr::int(i64::MAX)),
                right: Box::new(Expr::int(1)),
            },
            Default::default(),
        );
        let overflow_constants = HashMap::from([("N".to_string(), overflow)]);
        let err = fixed_type_size(&type_ref, &overflow_constants).expect_err("dimension overflow must not become an unknown size");
        assert!(matches!(err, CompilerError::ArithmeticOverflow(_)), "unexpected error: {err}");
    }
}
