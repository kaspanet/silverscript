use std::collections::HashMap;

use super::compile::{array_literal_matches_type_with_env_ref, type_name_from_ref};
use super::*;
use crate::ast::{ArrayDim, ConstantAst, ContractAst, ContractFieldAst, FunctionAst, ParamAst, Statement, TypeRef};

pub(super) fn lower_inferred_array_sizes<'i>(
    contract: &ContractAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let mut top_level_types = HashMap::new();
    for param in &contract.params {
        top_level_types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
    }

    let constants = contract
        .constants
        .iter()
        .map(|constant| lower_constant(constant, &mut top_level_types, contract_constants))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = contract
        .fields
        .iter()
        .map(|field| lower_field(field, &mut top_level_types, contract_constants))
        .collect::<Result<Vec<_>, _>>()?;
    let functions = contract
        .functions
        .iter()
        .map(|function| lower_function(function, &top_level_types, contract_constants))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst {
        name: contract.name.clone(),
        params: contract.params.clone(),
        structs: contract.structs.clone(),
        fields,
        constants,
        functions,
        span: contract.span,
        name_span: contract.name_span,
    })
}

pub(super) fn infer_fixed_array_type_from_initializer_ref<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<TypeRef> {
    if !matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        return None;
    }

    let element_type = declared_type.element_type()?;
    let init = initializer?;

    match &init.kind {
        ExprKind::Array(values) => {
            let mut inferred = element_type.clone();
            inferred.array_dims.push(ArrayDim::Fixed(values.len()));
            if array_literal_matches_type_with_env_ref(values, &inferred, types, constants) { Some(inferred) } else { None }
        }
        ExprKind::Identifier(name) => {
            let other_type = parse_type_ref(types.get(name)?).ok()?;
            if !other_type.is_array() || other_type.element_type() != Some(element_type.clone()) {
                return None;
            }
            let size = array_size_with_constants_ref(&other_type, constants)?;
            let mut inferred = element_type;
            inferred.array_dims.push(ArrayDim::Fixed(size));
            Some(inferred)
        }
        _ => None,
    }
}

fn lower_constant<'i>(
    constant: &ConstantAst<'i>,
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ConstantAst<'i>, CompilerError> {
    let type_ref = infer_type_ref(&constant.type_ref, Some(&constant.expr), types, constants)
        .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from constant '{}'", constant.name)))?;
    types.insert(constant.name.clone(), type_name_from_ref(&type_ref));
    Ok(ConstantAst { type_ref, ..constant.clone() })
}

fn lower_field<'i>(
    field: &ContractFieldAst<'i>,
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractFieldAst<'i>, CompilerError> {
    let type_ref = infer_type_ref(&field.type_ref, Some(&field.expr), types, constants)
        .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from contract field '{}'", field.name)))?;
    types.insert(field.name.clone(), type_name_from_ref(&type_ref));
    Ok(ContractFieldAst { type_ref, ..field.clone() })
}

fn lower_function<'i>(
    function: &FunctionAst<'i>,
    top_level_types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut types = top_level_types.clone();
    for param in &function.params {
        types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
    }
    let body = lower_block(&function.body, &mut types, constants)?;
    Ok(FunctionAst { body, ..function.clone() })
}

fn lower_block<'i>(
    statements: &[Statement<'i>],
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let mut lowered = Vec::with_capacity(statements.len());
    for statement in statements {
        lowered.push(lower_statement(statement, types, constants)?);
    }
    Ok(lowered)
}

fn lower_statement<'i>(
    statement: &Statement<'i>,
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Statement<'i>, CompilerError> {
    match statement {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            let lowered_type = infer_type_ref(type_ref, expr.as_ref(), types, constants)
                .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from variable '{}'", name)))?;
            types.insert(name.clone(), type_name_from_ref(&lowered_type));
            Ok(match statement {
                Statement::VariableDefinition { modifiers, span, type_span, modifier_spans, name_span, .. } => {
                    Statement::VariableDefinition {
                        type_ref: lowered_type,
                        modifiers: modifiers.clone(),
                        name: name.clone(),
                        expr: expr.clone(),
                        span: *span,
                        type_span: *type_span,
                        modifier_spans: modifier_spans.clone(),
                        name_span: *name_span,
                    }
                }
                _ => unreachable!(),
            })
        }
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
            let lowered_bindings = bindings
                .iter()
                .map(|binding| {
                    let lowered_type = infer_type_ref(&binding.type_ref, None, types, constants).ok_or_else(|| {
                        CompilerError::Unsupported(format!("cannot infer fixed array size from binding '{}'", binding.name))
                    })?;
                    types.insert(binding.name.clone(), type_name_from_ref(&lowered_type));
                    Ok(ParamAst { type_ref: lowered_type, ..binding.clone() })
                })
                .collect::<Result<Vec<_>, CompilerError>>()?;
            Ok(Statement::FunctionCallAssign {
                bindings: lowered_bindings,
                name: name.clone(),
                args: args.clone(),
                span: *span,
                name_span: *name_span,
            })
        }
        Statement::Block { body, span } => {
            let mut block_types = types.clone();
            let lowered_body = lower_block(body, &mut block_types, constants)?;
            Ok(Statement::Block { body: lowered_body, span: *span })
        }
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
            let mut then_types = types.clone();
            let lowered_then = lower_block(then_branch, &mut then_types, constants)?;
            let (lowered_else, merged_types) = if let Some(else_branch) = else_branch {
                let mut else_types = types.clone();
                let lowered_else = lower_block(else_branch, &mut else_types, constants)?;
                let mut merged = then_types;
                merged.extend(else_types);
                (Some(lowered_else), merged)
            } else {
                (None, then_types)
            };
            *types = merged_types;
            Ok(Statement::If {
                condition: condition.clone(),
                then_branch: lowered_then,
                else_branch: lowered_else,
                span: *span,
                then_span: *then_span,
                else_span: *else_span,
            })
        }
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
            let mut body_types = types.clone();
            body_types.insert(ident.clone(), "int".to_string());
            let lowered_body = lower_block(body, &mut body_types, constants)?;
            Ok(Statement::For {
                ident: ident.clone(),
                start: start.clone(),
                end: end.clone(),
                max_iterations: max_iterations.clone(),
                body: lowered_body,
                span: *span,
                ident_span: *ident_span,
                body_span: *body_span,
            })
        }
        _ => Ok(statement.clone()),
    }
}

fn infer_type_ref<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<TypeRef> {
    if matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        infer_fixed_array_type_from_initializer_ref(declared_type, initializer, types, constants)
    } else {
        Some(declared_type.clone())
    }
}

fn array_size_with_constants_ref<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    match type_ref.array_size()? {
        ArrayDim::Fixed(size) => Some(*size),
        ArrayDim::Constant(name) => match constants.get(name)?.kind {
            ExprKind::Int(value) if value >= 0 => Some(value as usize),
            _ => None,
        },
        ArrayDim::Dynamic | ArrayDim::Inferred => None,
    }
}
