use std::collections::HashMap;

use super::builtin_types::{builtin_return_type, constructor_return_type, indexed_introspection_type, introspection_type};
use super::type_check::split_part_type;
use super::*;
use crate::ast::{ArrayDim, ConstantAst, ContractAst, ContractFieldAst, FunctionAst, ParamAst, Statement, TypeBase, TypeRef};

pub(super) fn lower_inferred_array_sizes<'i>(
    contract: &ContractAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions_by_name: HashMap<String, &FunctionAst<'i>> =
        contract.functions.iter().map(|function| (function.name.clone(), function)).collect();
    let mut top_level_types = HashMap::new();
    for param in &contract.params {
        top_level_types.insert(param.name.clone(), param.type_ref.clone());
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

fn infer_fixed_array_type_from_initializer<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Option<TypeRef>, CompilerError> {
    if !matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        return Ok(None);
    }

    let Some(element_type) = declared_type.array_element_type() else { return Ok(None) };
    let Some(init) = initializer else { return Ok(None) };
    let Some(init_type) = infer_expr_type(init, types, constants, functions)? else { return Ok(None) };

    let Some(init_element_type) = init_type.array_element_type() else { return Ok(None) };
    if !init_type.is_array() || !type_refs_equal(&init_element_type, &element_type, constants) {
        return Ok(None);
    }

    let size = if let ExprKind::Array { values, .. } = &init.kind {
        values.len()
    } else {
        let Some(size) = array_type_size(&init_type, constants) else { return Ok(None) };
        size
    };
    let mut inferred = element_type;
    inferred.array_dims.push(ArrayDim::Fixed(size));
    Ok(Some(inferred))
}

fn lower_constant<'i>(
    constant: &ConstantAst<'i>,
    types: &mut TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<ConstantAst<'i>, CompilerError> {
    let type_ref = infer_type(&constant.type_ref, Some(&constant.expr), types, constants, functions)?
        .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from constant '{}'", constant.name)))?;
    types.insert(constant.name.clone(), type_ref.clone());
    Ok(ConstantAst { type_ref, ..constant.clone() })
}

fn lower_field<'i>(
    field: &ContractFieldAst<'i>,
    types: &mut TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<ContractFieldAst<'i>, CompilerError> {
    let type_ref = infer_type(&field.type_ref, Some(&field.expr), types, constants, functions)?
        .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from contract field '{}'", field.name)))?;
    types.insert(field.name.clone(), type_ref.clone());
    Ok(ContractFieldAst { type_ref, ..field.clone() })
}

fn lower_function<'i>(
    function: &FunctionAst<'i>,
    top_level_types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut types = top_level_types.clone();
    for param in &function.params {
        types.insert(param.name.clone(), param.type_ref.clone());
    }
    let body = lower_block(&function.body, &mut types, constants, functions)?;
    Ok(FunctionAst { body, ..function.clone() })
}

fn lower_block<'i>(
    statements: &[Statement<'i>],
    types: &mut TypeMap,
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
    types: &mut TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Statement<'i>, CompilerError> {
    match statement {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            let lowered_type = infer_type(type_ref, expr.as_ref(), types, constants, functions)?
                .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from variable '{}'", name)))?;
            types.insert(name.clone(), lowered_type.clone());
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
        Statement::TupleAssignment {
            left_type_ref,
            left_name,
            right_type_ref,
            right_name,
            expr,
            span,
            left_type_span,
            left_name_span,
            right_type_span,
            right_name_span,
        } => {
            let (left_initializer, right_initializer) = match &expr.kind {
                ExprKind::Split { source, index, span, .. } => (
                    Some(Expr::new(
                        ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left, span: *span },
                        expr.span,
                    )),
                    Some(Expr::new(
                        ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Right, span: *span },
                        expr.span,
                    )),
                ),
                _ => (None, None),
            };
            let lowered_left = infer_type(left_type_ref, left_initializer.as_ref(), types, constants, functions)?
                .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from variable '{left_name}'")))?;
            let lowered_right = infer_type(right_type_ref, right_initializer.as_ref(), types, constants, functions)?
                .ok_or_else(|| CompilerError::Unsupported(format!("cannot infer fixed array size from variable '{right_name}'")))?;
            types.insert(left_name.clone(), lowered_left.clone());
            types.insert(right_name.clone(), lowered_right.clone());
            Ok(Statement::TupleAssignment {
                left_type_ref: lowered_left,
                left_name: left_name.clone(),
                right_type_ref: lowered_right,
                right_name: right_name.clone(),
                expr: expr.clone(),
                span: *span,
                left_type_span: *left_type_span,
                left_name_span: *left_name_span,
                right_type_span: *right_type_span,
                right_name_span: *right_name_span,
            })
        }
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
            let lowered_bindings = bindings
                .iter()
                .map(|binding| {
                    let lowered_type = infer_type(&binding.type_ref, None, types, constants, functions)?.ok_or_else(|| {
                        CompilerError::Unsupported(format!("cannot infer fixed array size from binding '{}'", binding.name))
                    })?;
                    types.insert(binding.name.clone(), lowered_type.clone());
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
            let lowered_else = if let Some(else_branch) = else_branch {
                let mut else_types = types.clone();
                let lowered_else = lower_block(else_branch, &mut else_types, constants, functions)?;
                Some(lowered_else)
            } else {
                None
            };
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
            body_types.insert(ident.clone(), TypeRef { base: TypeBase::Int, array_dims: Vec::new() });
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

fn infer_type<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Option<TypeRef>, CompilerError> {
    if matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        infer_fixed_array_type_from_initializer(declared_type, initializer, types, constants, functions)
    } else {
        Ok(Some(declared_type.clone()))
    }
}

pub(super) fn infer_expr_type<'i>(
    expr: &Expr<'i>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Option<TypeRef>, CompilerError> {
    Ok(match &expr.kind {
        ExprKind::Int(_) => Some(TypeRef { base: TypeBase::Int, array_dims: Vec::new() }),
        ExprKind::NumberWithUnit { unit, .. } if crate::ast::is_temporal_unit(unit) => {
            Some(TypeRef { base: TypeBase::Temporal, array_dims: Vec::new() })
        }
        ExprKind::NumberWithUnit { .. } => Some(TypeRef { base: TypeBase::Int, array_dims: Vec::new() }),
        ExprKind::Temporal(_) | ExprKind::DateLiteral(_) => Some(TypeRef { base: TypeBase::Temporal, array_dims: Vec::new() }),
        ExprKind::Bool(_) => Some(TypeRef { base: TypeBase::Bool, array_dims: Vec::new() }),
        ExprKind::String(_) => Some(TypeRef { base: TypeBase::String, array_dims: Vec::new() }),
        ExprKind::Byte(_) => Some(TypeRef { base: TypeBase::Byte, array_dims: Vec::new() }),
        ExprKind::Identifier(name) => types.get(name).cloned(),
        ExprKind::Array { type_ref, .. } => Some(type_ref.clone()),
        ExprKind::Call { name, .. } => {
            if let Some(type_ref) = as_cast_type(name) {
                return Ok(Some(type_ref));
            }
            if let Some(function) = functions.get(name) {
                return Ok((!function.entrypoint).then(|| function.return_type()).flatten());
            }
            parse_type_ref(name)
                .ok()
                .filter(|type_ref| !matches!(type_ref.base, TypeBase::Custom(_)))
                .or_else(|| builtin_return_type(name))
        }
        ExprKind::New { name, .. } => constructor_return_type(name),
        ExprKind::Binary { op: BinaryOp::Add, left, right } => {
            let Some(left_type) = infer_expr_type(left, types, constants, functions)? else { return Ok(None) };
            let Some(right_type) = infer_expr_type(right, types, constants, functions)? else { return Ok(None) };
            return concat_types(&left_type, &right_type, constants);
        }
        ExprKind::Ternary { then_expr, else_expr, .. } => {
            let Some(then_type) = infer_expr_type(then_expr, types, constants, functions)? else { return Ok(None) };
            let Some(else_type) = infer_expr_type(else_expr, types, constants, functions)? else { return Ok(None) };
            type_refs_equal(&then_type, &else_type, constants).then_some(then_type)
        }
        ExprKind::Append { source, args, .. } => {
            let Some(source_type) = infer_expr_type(source, types, constants, functions)? else { return Ok(None) };
            return append_type(&source_type, args.len(), constants);
        }
        ExprKind::Split { source, index, part, .. } => {
            let Some(source_type) = infer_expr_type(source, types, constants, functions)? else { return Ok(None) };
            split_part_type(&source_type, index, *part, constants).ok()
        }
        ExprKind::Introspection(kind) => Some(introspection_type(*kind)),
        ExprKind::IndexedIntrospection { kind, .. } => Some(indexed_introspection_type(*kind)),
        _ => None,
    })
}
