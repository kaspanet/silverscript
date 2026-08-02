use std::collections::HashMap;

use crate::ast::{ArrayDim, Expr, TypeBase, TypeRef};

use super::eval_const_int;

pub(crate) fn type_refs_equal<'i>(left: &TypeRef, right: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> bool {
    bases_equal(&left.base, &right.base, constants)
        && left.array_dims.len() == right.array_dims.len()
        && left.array_dims.iter().zip(&right.array_dims).all(|(left, right)| dimensions_equal(left, right, constants))
}

fn bases_equal<'i>(left: &TypeBase, right: &TypeBase, constants: &HashMap<String, Expr<'i>>) -> bool {
    match (left, right) {
        (TypeBase::Tuple(left), TypeBase::Tuple(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(left, right)| type_refs_equal(left, right, constants))
        }
        _ => left == right,
    }
}

pub(crate) fn array_size<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    dimension_value(type_ref.array_size()?, constants)
}

pub(crate) fn concat_types<'i>(left: &TypeRef, right: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<TypeRef> {
    let element = left.array_element_type()?;
    if !type_refs_equal(&element, &right.array_element_type()?, constants) {
        return None;
    }

    let dimension = match (left.array_size()?, right.array_size()?) {
        (ArrayDim::Dynamic, _) | (_, ArrayDim::Dynamic) => ArrayDim::Dynamic,
        (left, right) => ArrayDim::Fixed(dimension_value(left, constants)?.checked_add(dimension_value(right, constants)?)?),
    };
    let mut result = element;
    result.array_dims.push(dimension);
    Some(result)
}

pub(crate) fn append_type<'i>(source: &TypeRef, appended: usize, constants: &HashMap<String, Expr<'i>>) -> Option<TypeRef> {
    let mut result = source.clone();
    let dimension = result.array_dims.last_mut()?;
    *dimension = match &*dimension {
        ArrayDim::Dynamic => ArrayDim::Dynamic,
        dimension => ArrayDim::Fixed(dimension_value(dimension, constants)?.checked_add(appended)?),
    };
    Some(result)
}

fn dimensions_equal<'i>(left: &ArrayDim, right: &ArrayDim, constants: &HashMap<String, Expr<'i>>) -> bool {
    match (left, right) {
        (ArrayDim::Dynamic, ArrayDim::Dynamic) | (ArrayDim::Inferred, ArrayDim::Inferred) => true,
        (ArrayDim::Dynamic | ArrayDim::Inferred, _) | (_, ArrayDim::Dynamic | ArrayDim::Inferred) => false,
        _ => match (dimension_value(left, constants), dimension_value(right, constants)) {
            (Some(left), Some(right)) => left == right,
            _ => left == right,
        },
    }
}

fn dimension_value<'i>(dimension: &ArrayDim, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    match dimension {
        ArrayDim::Fixed(size) => Some(*size),
        ArrayDim::Constant(name) => usize::try_from(eval_const_int(constants.get(name)?, constants).ok()?).ok(),
        ArrayDim::Dynamic | ArrayDim::Inferred => None,
    }
}
