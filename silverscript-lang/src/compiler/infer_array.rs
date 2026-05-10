use std::collections::HashMap;

use super::compile::type_name_from_ref;
use super::*;
use crate::ast::{ArrayDim, ConstantAst, ContractAst, ContractFieldAst, FunctionAst, ParamAst, Statement, TypeRef};

pub(super) fn lower_inferred_array_sizes<'i>(
    contract: &ContractAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions_by_name: HashMap<String, &FunctionAst<'i>> =
        contract.functions.iter().map(|function| (function.name.clone(), function)).collect();
    let mut top_level_types = HashMap::new();
    for param in &contract.params {
        top_level_types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
    }

    let constants = contract
        .constants
        .iter()
        .map(|constant| lower_constant(constant, &mut top_level_types, contract_constants, &functions_by_name))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = contract
        .fields
        .iter()
        .map(|field| lower_field(field, &mut top_level_types, contract_constants, &functions_by_name))
        .collect::<Result<Vec<_>, _>>()?;
    let functions = contract
        .functions
        .iter()
        .map(|function| lower_function(function, &top_level_types, contract_constants, &functions_by_name))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst {
        pragma: contract.pragma.clone(),
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

fn infer_fixed_array_type_from_initializer_ref<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Option<TypeRef> {
    if !matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        return None;
    }

    let element_type = declared_type.element_type()?;
    let init = initializer?;
    let init_type = infer_expr_type_ref(init, types, constants, functions, Some(&element_type))?;

    if !init_type.is_array() || init_type.element_type() != Some(element_type.clone()) {
        return None;
    }

    let size = array_size_with_constants_ref(&init_type, constants)?;
    let mut inferred = element_type;
    inferred.array_dims.push(ArrayDim::Fixed(size));
    Some(inferred)
}

fn lower_constant<'i>(
    constant: &ConstantAst<'i>,
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<ConstantAst<'i>, CompilerError> {
    let type_ref = infer_type_ref(&constant.type_ref, Some(&constant.expr), types, constants, functions)
        .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from constant '{}'", constant.name)))?;
    types.insert(constant.name.clone(), type_name_from_ref(&type_ref));
    Ok(ConstantAst { type_ref, ..constant.clone() })
}

fn lower_field<'i>(
    field: &ContractFieldAst<'i>,
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<ContractFieldAst<'i>, CompilerError> {
    let type_ref = infer_type_ref(&field.type_ref, Some(&field.expr), types, constants, functions)
        .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from contract field '{}'", field.name)))?;
    types.insert(field.name.clone(), type_name_from_ref(&type_ref));
    Ok(ContractFieldAst { type_ref, ..field.clone() })
}

fn lower_function<'i>(
    function: &FunctionAst<'i>,
    top_level_types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut types = top_level_types.clone();
    for param in &function.params {
        types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
    }
    let body = lower_block(&function.body, &mut types, constants, functions)?;
    Ok(FunctionAst { body, ..function.clone() })
}

fn lower_block<'i>(
    statements: &[Statement<'i>],
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let mut lowered = Vec::with_capacity(statements.len());
    for statement in statements {
        lowered.push(lower_statement(statement, types, constants, functions)?);
    }
    Ok(lowered)
}

fn lower_statement<'i>(
    statement: &Statement<'i>,
    types: &mut HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Statement<'i>, CompilerError> {
    match statement {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            let lowered_type = infer_type_ref(type_ref, expr.as_ref(), types, constants, functions)
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
                    let lowered_type = infer_type_ref(&binding.type_ref, None, types, constants, functions).ok_or_else(|| {
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
            let lowered_body = lower_block(body, &mut block_types, constants, functions)?;
            Ok(Statement::Block { body: lowered_body, span: *span })
        }
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
            let mut then_types = types.clone();
            let lowered_then = lower_block(then_branch, &mut then_types, constants, functions)?;
            let (lowered_else, merged_types) = if let Some(else_branch) = else_branch {
                let mut else_types = types.clone();
                let lowered_else = lower_block(else_branch, &mut else_types, constants, functions)?;
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
            let lowered_body = lower_block(body, &mut body_types, constants, functions)?;
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
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Option<TypeRef> {
    if matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        infer_fixed_array_type_from_initializer_ref(declared_type, initializer, types, constants, functions)
    } else {
        Some(declared_type.clone())
    }
}

fn infer_expr_type_ref<'i>(
    expr: &Expr<'i>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
    array_literal_element_type: Option<&TypeRef>,
) -> Option<TypeRef> {
    match &expr.kind {
        ExprKind::Identifier(name) => parse_type_ref(types.get(name)?).ok(),
        ExprKind::Array(values) => {
            let mut inferred = array_literal_element_type
                .cloned()
                .or_else(|| infer_array_literal_element_type(values, types, constants, functions))?;
            inferred.array_dims.push(ArrayDim::Fixed(values.len()));
            Some(inferred)
        }
        ExprKind::Call { name, .. } => {
            if let Some(function) = functions.get(name) {
                if function.entrypoint || function.return_types.len() != 1 {
                    return None;
                }
                return Some(function.return_types[0].clone());
            }
            parse_type_ref(name).ok()
        }
        ExprKind::Binary { op: BinaryOp::Add, left, right } => {
            let left_type = infer_expr_type_ref(left, types, constants, functions, None)?;
            let right_type = infer_expr_type_ref(right, types, constants, functions, None)?;
            let left_element = left_type.element_type()?;
            if right_type.element_type() != Some(left_element.clone()) {
                return None;
            }
            let left_size = array_size_with_constants_ref(&left_type, constants)?;
            let right_size = array_size_with_constants_ref(&right_type, constants)?;
            let mut inferred = left_element;
            inferred.array_dims.push(ArrayDim::Fixed(left_size.checked_add(right_size)?));
            Some(inferred)
        }
        ExprKind::IfElse { then_expr, else_expr, .. } => {
            let then_type = infer_expr_type_ref(then_expr, types, constants, functions, None)?;
            let else_type = infer_expr_type_ref(else_expr, types, constants, functions, None)?;
            (then_type == else_type).then_some(then_type)
        }
        ExprKind::Append { source, args, .. } => {
            let source_type = infer_expr_type_ref(source, types, constants, functions, None)?;
            let element_type = source_type.element_type()?;
            let source_size = array_size_with_constants_ref(&source_type, constants)?;
            let mut inferred = element_type;
            inferred.array_dims.push(ArrayDim::Fixed(source_size.checked_add(args.len())?));
            Some(inferred)
        }
        ExprKind::UnarySuffix { source, kind: UnarySuffixKind::Reverse, .. } => {
            infer_expr_type_ref(source, types, constants, functions, None)
        }
        _ => None,
    }
}

fn infer_array_literal_element_type<'i>(
    values: &[Expr<'i>],
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Option<TypeRef> {
    let first_type = infer_expr_type_ref(values.first()?, types, constants, functions, None)?;
    if values.iter().skip(1).all(|value| infer_expr_type_ref(value, types, constants, functions, None).as_ref() == Some(&first_type)) {
        Some(first_type)
    } else {
        None
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
