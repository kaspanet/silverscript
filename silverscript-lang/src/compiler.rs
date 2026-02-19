use std::collections::{HashMap, HashSet};

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use serde::{Deserialize, Serialize};

use crate::ast::{
    ArrayDim, BinaryOp, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, IntrospectionKind, NullaryOp, SplitPart,
    StateBindingAst, StateFieldExpr, Statement, TimeVar, TypeBase, TypeRef, UnaryOp, UnarySuffixKind, parse_contract_ast,
    parse_type_ref,
};
pub use crate::errors::{CompilerError, ErrorSpan};
use crate::span;

#[derive(Debug, Clone, Copy, Default)]
pub struct CompileOptions {
    pub allow_yield: bool,
    pub allow_entrypoint_return: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInputAbi {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionAbiEntry {
    pub name: String,
    pub inputs: Vec<FunctionInputAbi>,
}

pub type FunctionAbi = Vec<FunctionAbiEntry>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CompiledContract<'i> {
    pub contract_name: String,
    pub script: Vec<u8>,
    pub ast: ContractAst<'i>,
    pub abi: FunctionAbi,
    pub without_selector: bool,
}

pub fn compile_contract<'i>(
    source: &'i str,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    let contract = parse_contract_ast(source)?;
    compile_contract_ast(&contract, constructor_args, options)
}

pub fn compile_contract_ast<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    if contract.functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no functions".to_string()));
    }

    let entrypoint_functions: Vec<&FunctionAst<'i>> = contract.functions.iter().filter(|func| func.entrypoint).collect();
    if entrypoint_functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entrypoint functions".to_string()));
    }

    if contract.params.len() != constructor_args.len() {
        return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
    }

    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if !expr_matches_type(value, &param_type_name) {
            return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, param_type_name)));
        }
    }

    let without_selector = entrypoint_functions.len() == 1;

    let mut constants: HashMap<String, Expr<'i>> =
        contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        constants.insert(param.name.clone(), value.clone());
    }

    let functions_map = contract.functions.iter().cloned().map(|func| (func.name.clone(), func)).collect::<HashMap<_, _>>();
    let function_order =
        contract.functions.iter().enumerate().map(|(index, func)| (func.name.clone(), index)).collect::<HashMap<_, _>>();
    let abi = build_function_abi(contract);
    let uses_script_size = contract_uses_script_size(contract);

    let mut script_size = if uses_script_size { Some(100i64) } else { None };
    for _ in 0..32 {
        let (_contract_fields, field_prolog_script) = compile_contract_fields(&contract.fields, &constants, options, script_size)?;

        let mut compiled_entrypoints = Vec::new();
        for (index, func) in contract.functions.iter().enumerate() {
            if func.entrypoint {
                compiled_entrypoints.push(compile_function(
                    func,
                    index,
                    &contract.fields,
                    field_prolog_script.len(),
                    &constants,
                    options,
                    &functions_map,
                    &function_order,
                    script_size,
                )?);
            }
        }

        let entrypoint_script = if without_selector {
            compiled_entrypoints
                .first()
                .ok_or_else(|| CompilerError::Unsupported("contract has no entrypoint functions".to_string()))?
                .1
                .clone()
        } else {
            let mut builder = ScriptBuilder::new();
            let total = compiled_entrypoints.len();
            for (index, (_, script)) in compiled_entrypoints.iter().enumerate() {
                builder.add_op(OpDup)?;
                builder.add_i64(index as i64)?;
                builder.add_op(OpNumEqual)?;
                builder.add_op(OpIf)?;
                builder.add_op(OpDrop)?;
                builder.add_ops(script)?;
                if index == total - 1 {
                    builder.add_op(OpElse)?;
                    builder.add_op(OpDrop)?;
                    builder.add_op(OpFalse)?;
                    builder.add_op(OpVerify)?;
                } else {
                    builder.add_op(OpElse)?;
                }
            }

            for _ in 0..total {
                builder.add_op(OpEndIf)?;
            }

            builder.drain()
        };

        let mut script = field_prolog_script.clone();
        script.extend(entrypoint_script);

        if !uses_script_size {
            return Ok(CompiledContract {
                contract_name: contract.name.clone(),
                script,
                ast: contract.clone(),
                abi,
                without_selector,
            });
        }

        let actual_size = script.len() as i64;
        if Some(actual_size) == script_size {
            return Ok(CompiledContract {
                contract_name: contract.name.clone(),
                script,
                ast: contract.clone(),
                abi,
                without_selector,
            });
        }
        script_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("script size did not stabilize".to_string()))
}

fn contract_uses_script_size<'i>(contract: &ContractAst<'i>) -> bool {
    if contract.constants.iter().any(|constant| expr_uses_script_size(&constant.expr)) {
        return true;
    }
    if contract.fields.iter().any(|field| expr_uses_script_size(&field.expr)) {
        return true;
    }
    contract.functions.iter().any(|func| func.body.iter().any(statement_uses_script_size))
}

fn compile_contract_fields<'i>(
    fields: &[ContractFieldAst<'i>],
    base_constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    script_size: Option<i64>,
) -> Result<(HashMap<String, Expr<'i>>, Vec<u8>), CompilerError> {
    let mut env = base_constants.clone();
    let mut field_values = HashMap::new();
    let mut field_types = HashMap::new();
    let mut builder = ScriptBuilder::new();
    let params = HashMap::new();

    for field in fields {
        if env.contains_key(&field.name) {
            return Err(CompilerError::Unsupported(format!("duplicate contract field name: {}", field.name)));
        }

        let type_name = type_name_from_ref(&field.type_ref);
        if is_array_type(&type_name) && array_element_size(&type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {type_name}")));
        }

        let mut resolve_visiting = HashSet::new();
        let resolved = resolve_expr(field.expr.clone(), &env, &mut resolve_visiting)?;
        if !expr_matches_type_ref(&resolved, &field.type_ref) {
            return Err(CompilerError::Unsupported(format!("contract field '{}' expects {}", field.name, type_name)));
        }

        let mut compile_visiting = HashSet::new();
        let mut stack_depth = 0i64;
        if field.type_ref.array_dims.is_empty() && field.type_ref.base == TypeBase::Int {
            let ExprKind::Int(value) = &resolved.kind else {
                return Err(CompilerError::Unsupported(format!("contract field '{}' expects compile-time int value", field.name)));
            };
            builder.add_data(&value.to_le_bytes())?;
            builder.add_op(OpBin2Num)?;
        } else {
            compile_expr(
                &resolved,
                &env,
                &params,
                &field_types,
                &mut builder,
                options,
                &mut compile_visiting,
                &mut stack_depth,
                script_size,
                &env,
            )?;
        }

        env.insert(field.name.clone(), resolved.clone());
        field_values.insert(field.name.clone(), resolved);
        field_types.insert(field.name.clone(), type_name);
    }

    Ok((field_values, builder.drain()))
}

fn statement_uses_script_size(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::VariableDefinition { expr, .. } => expr.as_ref().is_some_and(expr_uses_script_size),
        Statement::TupleAssignment { expr, .. } => expr_uses_script_size(expr),
        Statement::ArrayPush { expr, .. } => expr_uses_script_size(expr),
        Statement::FunctionCall { name, args, .. } => name == "validateOutputState" || args.iter().any(expr_uses_script_size),
        Statement::FunctionCallAssign { args, .. } => args.iter().any(expr_uses_script_size),
        Statement::StateFunctionCallAssign { name, args, .. } => name == "readInputState" || args.iter().any(expr_uses_script_size),
        Statement::Assign { expr, .. } => expr_uses_script_size(expr),
        Statement::TimeOp { expr, .. } => expr_uses_script_size(expr),
        Statement::Require { expr, .. } => expr_uses_script_size(expr),
        Statement::If { condition, then_branch, else_branch, .. } => {
            expr_uses_script_size(condition)
                || then_branch.iter().any(statement_uses_script_size)
                || else_branch.as_ref().is_some_and(|branch| branch.iter().any(statement_uses_script_size))
        }
        Statement::For { start, end, body, .. } => {
            expr_uses_script_size(start) || expr_uses_script_size(end) || body.iter().any(statement_uses_script_size)
        }
        Statement::Yield { expr, .. } => expr_uses_script_size(expr),
        Statement::Return { exprs, .. } => exprs.iter().any(expr_uses_script_size),
        Statement::Console { args, .. } => args.iter().any(|arg| match arg {
            crate::ast::ConsoleArg::Identifier(_, _) => false,
            crate::ast::ConsoleArg::Literal(expr) => expr_uses_script_size(expr),
        }),
    }
}

fn expr_uses_script_size<'i>(expr: &Expr<'i>) -> bool {
    match &expr.kind {
        ExprKind::Nullary(NullaryOp::ThisScriptSize) => true,
        ExprKind::Nullary(NullaryOp::ThisScriptSizeDataPrefix) => true,
        ExprKind::Unary { expr, .. } => expr_uses_script_size(expr),
        ExprKind::Binary { left, right, .. } => expr_uses_script_size(left) || expr_uses_script_size(right),
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            expr_uses_script_size(condition) || expr_uses_script_size(then_expr) || expr_uses_script_size(else_expr)
        }
        ExprKind::Array(values) => values.iter().any(expr_uses_script_size),
        ExprKind::Call { args, .. } => args.iter().any(expr_uses_script_size),
        ExprKind::New { args, .. } => args.iter().any(expr_uses_script_size),
        ExprKind::Split { source, index, .. } => expr_uses_script_size(source) || expr_uses_script_size(index),
        ExprKind::Slice { source, start, end, .. } => {
            expr_uses_script_size(source) || expr_uses_script_size(start) || expr_uses_script_size(end)
        }
        ExprKind::UnarySuffix { source, .. } => expr_uses_script_size(source),
        ExprKind::ArrayIndex { source, index } => expr_uses_script_size(source) || expr_uses_script_size(index),
        ExprKind::Introspection { index, .. } => expr_uses_script_size(index),
        ExprKind::Int(_)
        | ExprKind::Bool(_)
        | ExprKind::Bytes(_)
        | ExprKind::String(_)
        | ExprKind::Identifier(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::NumberWithUnit { .. }
        | ExprKind::Nullary(_) => false,
        ExprKind::StateObject(fields) => fields.iter().any(|field| expr_uses_script_size(&field.expr)),
    }
}

fn byte_array_len<'i>(expr: &Expr<'i>) -> Option<usize> {
    match &expr.kind {
        ExprKind::Bytes(bytes) => Some(bytes.len()),
        ExprKind::Array(values) => values
            .iter()
            .map(|value| match &value.kind {
                ExprKind::Bytes(bytes) if bytes.len() == 1 => Some(()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(|_| values.len()),
        _ => None,
    }
}

fn is_byte_array<'i>(expr: &Expr<'i>) -> bool {
    byte_array_len(expr).is_some()
}

fn expr_matches_type_ref<'i>(expr: &Expr<'i>, type_ref: &TypeRef) -> bool {
    if is_array_type_ref(type_ref) {
        if !has_explicit_array_size_ref(type_ref) {
            return is_byte_array(expr)
                || matches!(&expr.kind, ExprKind::Array(values) if array_literal_matches_type_ref(values, type_ref));
        }

        return match &expr.kind {
            ExprKind::Bytes(bytes) => {
                let Some(element_type) = array_element_type_ref(type_ref) else {
                    return false;
                };
                if element_type.base != TypeBase::Byte || !element_type.array_dims.is_empty() {
                    return false;
                }
                array_size_ref(type_ref).is_none_or(|size| bytes.len() == size)
            }
            ExprKind::Array(values) => array_literal_matches_type_ref(values, type_ref),
            _ => false,
        };
    }

    match type_ref.base {
        TypeBase::Int => matches!(&expr.kind, ExprKind::Int(_) | ExprKind::DateLiteral(_)),
        TypeBase::Bool => matches!(&expr.kind, ExprKind::Bool(_)),
        TypeBase::String => matches!(&expr.kind, ExprKind::String(_)),
        TypeBase::Byte => matches!(&expr.kind, ExprKind::Bytes(bytes) if bytes.len() == 1),
        TypeBase::Pubkey => byte_array_len(expr) == Some(32),
        TypeBase::Sig => byte_array_len(expr) == Some(65),
        TypeBase::Datasig => byte_array_len(expr) == Some(64),
    }
}

fn array_literal_matches_type_ref<'i>(values: &[Expr<'i>], type_ref: &TypeRef) -> bool {
    let Some(element_type) = array_element_type_ref(type_ref) else {
        return false;
    };

    if let Some(expected_size) = array_size_ref(type_ref) {
        if values.len() != expected_size {
            return false;
        }
    }

    values.iter().all(|value| expr_matches_type_ref(value, &element_type))
}

fn array_literal_matches_type_with_env_ref<'i>(
    values: &[Expr<'i>],
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    let Some(element_type) = array_element_type_ref(type_ref) else {
        return false;
    };

    if let Some(expected_size) = array_size_with_constants_ref(type_ref, constants) {
        if values.len() != expected_size {
            return false;
        }
    }

    values.iter().all(|value| match &value.kind {
        ExprKind::Identifier(name) => types
            .get(name)
            .and_then(|value_type| parse_type_ref(value_type).ok())
            .is_some_and(|value_type| is_type_assignable_ref(&value_type, &element_type, constants)),
        _ => expr_matches_type_ref(value, &element_type),
    })
}

fn build_function_abi<'i>(contract: &ContractAst<'i>) -> FunctionAbi {
    contract
        .functions
        .iter()
        .filter(|func| func.entrypoint)
        .map(|func| FunctionAbiEntry {
            name: func.name.clone(),
            inputs: func
                .params
                .iter()
                .map(|param| FunctionInputAbi { name: param.name.clone(), type_name: type_name_from_ref(&param.type_ref) })
                .collect(),
        })
        .collect()
}

fn type_name_from_ref(type_ref: &TypeRef) -> String {
    type_ref.type_name()
}

fn is_array_type_ref(type_ref: &TypeRef) -> bool {
    type_ref.is_array()
}

fn array_element_type_ref(type_ref: &TypeRef) -> Option<TypeRef> {
    type_ref.element_type()
}

fn array_size_ref(type_ref: &TypeRef) -> Option<usize> {
    match type_ref.array_size()? {
        ArrayDim::Fixed(size) => Some(*size),
        _ => None,
    }
}

fn array_size_with_constants_ref<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    match type_ref.array_size()? {
        ArrayDim::Fixed(size) => Some(*size),
        ArrayDim::Constant(name) => {
            if let Some(Expr { kind: ExprKind::Int(value), .. }) = constants.get(name) {
                if *value >= 0 {
                    return Some(*value as usize);
                }
            }
            None
        }
        ArrayDim::Dynamic => None,
    }
}

fn fixed_type_size_ref(type_ref: &TypeRef) -> Option<i64> {
    if !type_ref.array_dims.is_empty() {
        if let (Some(elem_type), Some(size)) = (array_element_type_ref(type_ref), array_size_ref(type_ref)) {
            if elem_type.base == TypeBase::Byte && elem_type.array_dims.is_empty() {
                return Some(size as i64);
            }
            if elem_type.base == TypeBase::Int && elem_type.array_dims.is_empty() {
                return Some((size * 8) as i64);
            }
        }
        return None;
    }

    match type_ref.base {
        TypeBase::Int => Some(8),
        TypeBase::Bool => Some(1),
        TypeBase::Byte => Some(1),
        TypeBase::Pubkey => Some(32),
        TypeBase::Sig => Some(65),
        TypeBase::Datasig => Some(64),
        TypeBase::String => None,
    }
}

fn array_element_size_ref(type_ref: &TypeRef) -> Option<i64> {
    array_element_type_ref(type_ref).and_then(|element| fixed_type_size_ref(&element))
}

fn contains_return(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::Return { .. } => true,
        Statement::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(contains_return) || else_branch.as_ref().is_some_and(|branch| branch.iter().any(contains_return))
        }
        Statement::For { body, .. } => body.iter().any(contains_return),
        _ => false,
    }
}

fn contains_yield(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::Yield { .. } => true,
        Statement::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(contains_yield) || else_branch.as_ref().is_some_and(|branch| branch.iter().any(contains_yield))
        }
        Statement::For { body, .. } => body.iter().any(contains_yield),
        _ => false,
    }
}

fn validate_return_types<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if return_types.is_empty() {
        return Err(CompilerError::Unsupported("return requires function return types".to_string()));
    }
    if return_types.len() != exprs.len() {
        return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
    }
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        if !expr_matches_return_type_ref(expr, return_type, types, constants) {
            let type_name = type_name_from_ref(return_type);
            return Err(CompilerError::Unsupported(format!("return value expects {type_name}")));
        }
    }
    Ok(())
}

fn has_explicit_array_size_ref(type_ref: &TypeRef) -> bool {
    !matches!(type_ref.array_size(), Some(ArrayDim::Dynamic) | None)
}

fn is_array_type_assignable_ref<'i>(actual: &TypeRef, expected: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> bool {
    if actual == expected {
        return true;
    }

    if !is_array_type_ref(actual) || !is_array_type_ref(expected) {
        return false;
    }

    if array_element_type_ref(actual) != array_element_type_ref(expected) {
        return false;
    }

    if !has_explicit_array_size_ref(expected) {
        return true;
    }

    match (array_size_with_constants_ref(actual, constants), array_size_with_constants_ref(expected, constants)) {
        (Some(actual_size), Some(expected_size)) => actual_size == expected_size,
        _ => actual == expected,
    }
}

fn is_type_assignable_ref<'i>(actual: &TypeRef, expected: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> bool {
    actual == expected || is_array_type_assignable_ref(actual, expected, constants)
}

fn expr_matches_type_with_env_ref<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    match &expr.kind {
        ExprKind::Identifier(name) => {
            types.get(name).and_then(|t| parse_type_ref(t).ok()).is_some_and(|t| is_type_assignable_ref(&t, type_ref, constants))
        }
        ExprKind::Array(values) => is_array_type_ref(type_ref) && array_literal_matches_type_ref(values, type_ref),
        _ => expr_matches_type_ref(expr, type_ref),
    }
}

fn expr_matches_return_type_ref<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    match &expr.kind {
        ExprKind::Identifier(name) => {
            types.get(name).and_then(|t| parse_type_ref(t).ok()).is_some_and(|t| is_type_assignable_ref(&t, type_ref, constants))
        }
        ExprKind::Array(values) => is_array_type_ref(type_ref) && array_literal_matches_type_ref(values, type_ref),
        ExprKind::Int(_) | ExprKind::DateLiteral(_) | ExprKind::Bool(_) | ExprKind::Bytes(_) | ExprKind::String(_) => {
            expr_matches_type_ref(expr, type_ref)
        }
        _ => true,
    }
}

fn infer_fixed_array_type_from_initializer_ref<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<TypeRef> {
    if !declared_type.array_size().is_some_and(|dim| matches!(dim, ArrayDim::Dynamic)) {
        return None;
    }

    let element_type = array_element_type_ref(declared_type)?;
    let init = initializer?;

    match &init.kind {
        ExprKind::Array(values) => {
            let mut inferred = element_type.clone();
            inferred.array_dims.push(ArrayDim::Fixed(values.len()));
            if array_literal_matches_type_with_env_ref(values, &inferred, types, constants) { Some(inferred) } else { None }
        }
        ExprKind::Bytes(bytes) => {
            if element_type.base != TypeBase::Byte || !element_type.array_dims.is_empty() {
                return None;
            }
            let mut inferred = element_type.clone();
            inferred.array_dims.push(ArrayDim::Fixed(bytes.len()));
            Some(inferred)
        }
        ExprKind::Identifier(name) => {
            let other_type = parse_type_ref(types.get(name)?).ok()?;
            if !is_array_type_ref(&other_type) || array_element_type_ref(&other_type) != Some(element_type.clone()) {
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

fn expr_matches_type<'i>(expr: &Expr<'i>, type_name: &str) -> bool {
    parse_type_ref(type_name).is_ok_and(|type_ref| expr_matches_type_ref(expr, &type_ref))
}

fn array_literal_matches_type_with_env<'i>(
    values: &[Expr<'i>],
    type_name: &str,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    parse_type_ref(type_name).is_ok_and(|type_ref| array_literal_matches_type_with_env_ref(values, &type_ref, types, constants))
}

fn is_array_type(type_name: &str) -> bool {
    parse_type_ref(type_name).is_ok_and(|type_ref| is_array_type_ref(&type_ref))
}

fn array_element_type(type_name: &str) -> Option<String> {
    let type_ref = parse_type_ref(type_name).ok()?;
    let element = array_element_type_ref(&type_ref)?;
    Some(type_name_from_ref(&element))
}

fn array_size(type_name: &str) -> Option<usize> {
    let type_ref = parse_type_ref(type_name).ok()?;
    array_size_ref(&type_ref)
}

fn array_size_with_constants<'i>(type_name: &str, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    let type_ref = parse_type_ref(type_name).ok()?;
    array_size_with_constants_ref(&type_ref, constants)
}

fn fixed_type_size(type_name: &str) -> Option<i64> {
    let type_ref = parse_type_ref(type_name).ok()?;
    fixed_type_size_ref(&type_ref)
}

fn array_element_size(type_name: &str) -> Option<i64> {
    let type_ref = parse_type_ref(type_name).ok()?;
    array_element_size_ref(&type_ref)
}

fn is_type_assignable<'i>(actual: &str, expected: &str, constants: &HashMap<String, Expr<'i>>) -> bool {
    let Ok(actual_type) = parse_type_ref(actual) else {
        return false;
    };
    let Ok(expected_type) = parse_type_ref(expected) else {
        return false;
    };
    is_type_assignable_ref(&actual_type, &expected_type, constants)
}

fn expr_matches_type_with_env<'i>(
    expr: &Expr<'i>,
    type_name: &str,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    parse_type_ref(type_name).is_ok_and(|type_ref| expr_matches_type_with_env_ref(expr, &type_ref, types, constants))
}

fn infer_fixed_array_type_from_initializer<'i>(
    declared_type: &str,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<String> {
    let declared_type = parse_type_ref(declared_type).ok()?;
    infer_fixed_array_type_from_initializer_ref(&declared_type, initializer, types, constants).map(|t| type_name_from_ref(&t))
}

impl<'i> CompiledContract<'i> {
    pub fn build_sig_script(&self, function_name: &str, args: Vec<Expr<'i>>) -> Result<Vec<u8>, CompilerError> {
        let function = self
            .abi
            .iter()
            .find(|entry| entry.name == function_name)
            .ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", function_name)))?;

        if function.inputs.len() != args.len() {
            return Err(CompilerError::Unsupported(format!(
                "function '{}' expects {} arguments",
                function_name,
                function.inputs.len()
            )));
        }

        for (input, arg) in function.inputs.iter().zip(args.iter()) {
            if !expr_matches_type(arg, &input.type_name) {
                return Err(CompilerError::Unsupported(format!("function argument '{}' expects {}", input.name, input.type_name)));
            }
        }

        let mut builder = ScriptBuilder::new();
        for (input, arg) in function.inputs.iter().zip(args) {
            if is_array_type(&input.type_name) {
                match arg.kind {
                    ExprKind::Array(values) => {
                        let bytes = encode_array_literal(&values, &input.type_name)?;
                        builder.add_data(&bytes)?;
                    }
                    ExprKind::Bytes(value) => {
                        builder.add_data(&value)?;
                    }
                    _ => {
                        return Err(CompilerError::Unsupported(format!(
                            "function argument '{}' expects {}",
                            input.name, input.type_name
                        )));
                    }
                }
            } else {
                push_sigscript_arg(&mut builder, arg)?;
            }
        }
        if !self.without_selector {
            let selector = function_branch_index(&self.ast, function_name)?;
            builder.add_i64(selector)?;
        }
        Ok(builder.drain())
    }
}

fn push_sigscript_arg<'i>(builder: &mut ScriptBuilder, arg: Expr<'i>) -> Result<(), CompilerError> {
    match arg.kind {
        ExprKind::Int(value) => {
            builder.add_i64(value)?;
        }
        ExprKind::Bool(value) => {
            builder.add_i64(if value { 1 } else { 0 })?;
        }
        ExprKind::String(value) => {
            builder.add_data(value.as_bytes())?;
        }
        ExprKind::Bytes(value) => {
            builder.add_data(&value)?;
        }
        ExprKind::DateLiteral(value) => {
            builder.add_i64(value)?;
        }
        _ => {
            return Err(CompilerError::Unsupported("signature script arguments must be literals".to_string()));
        }
    }
    Ok(())
}

fn encode_fixed_size_value<'i>(value: &Expr<'i>, type_name: &str) -> Result<Vec<u8>, CompilerError> {
    match type_name {
        "int" => {
            let number = match &value.kind {
                ExprKind::Int(number) | ExprKind::DateLiteral(number) => *number,
                _ => return Err(CompilerError::Unsupported("array literal element type mismatch".to_string())),
            };
            Ok(number.to_le_bytes().to_vec())
        }
        "bool" => {
            let ExprKind::Bool(flag) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(vec![u8::from(*flag)])
        }
        "byte" => {
            let ExprKind::Bytes(bytes) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            if bytes.len() != 1 {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            }
            Ok(bytes.clone())
        }
        "pubkey" => {
            let ExprKind::Bytes(bytes) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            if bytes.len() != 32 {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            }
            Ok(bytes.clone())
        }
        _ => {
            // Handle fixed-size byte arrays like byte[N]
            if let (Some(inner_type), Some(size)) = (array_element_type(type_name), array_size(type_name)) {
                if inner_type == "byte" {
                    return match &value.kind {
                        ExprKind::Bytes(bytes) if bytes.len() == size => Ok(bytes.clone()),
                        ExprKind::Array(values) if values.len() == size => values
                            .iter()
                            .map(|value| match &value.kind {
                                ExprKind::Bytes(bytes) if bytes.len() == 1 => Some(bytes[0]),
                                _ => None,
                            })
                            .collect::<Option<Vec<_>>>()
                            .ok_or_else(|| CompilerError::Unsupported("array literal element type mismatch".to_string())),
                        _ => Err(CompilerError::Unsupported("array literal element type mismatch".to_string())),
                    };
                }
            }

            // Handle nested fixed-size arrays with known element sizes.
            if let ExprKind::Array(values) = &value.kind {
                let element_type = array_element_type(type_name)
                    .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
                let expected_len = array_size(type_name)
                    .ok_or_else(|| CompilerError::Unsupported("array literal element type mismatch".to_string()))?;
                if values.len() != expected_len {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                }

                let mut encoded = Vec::new();
                for value in values {
                    encoded.extend(encode_fixed_size_value(value, &element_type)?);
                }
                return Ok(encoded);
            }

            Err(CompilerError::Unsupported("array literal element type mismatch".to_string()))
        }
    }
}

fn encode_array_literal<'i>(values: &[Expr<'i>], type_name: &str) -> Result<Vec<u8>, CompilerError> {
    let element_type = array_element_type(type_name)
        .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
    let mut out = Vec::new();
    if fixed_type_size(&element_type).is_none() {
        return Err(CompilerError::Unsupported("array element type must have known size".to_string()));
    }
    for value in values {
        out.extend(encode_fixed_size_value(value, &element_type)?);
    }
    Ok(out)
}

fn infer_fixed_type_from_literal_expr<'i>(expr: &Expr<'i>) -> Option<String> {
    match &expr.kind {
        ExprKind::Int(_) | ExprKind::DateLiteral(_) => Some("int".to_string()),
        ExprKind::Bool(_) => Some("bool".to_string()),
        ExprKind::Bytes(bytes) if bytes.len() == 1 => Some("byte".to_string()),
        ExprKind::Bytes(bytes) => Some(format!("byte[{}]", bytes.len())),
        ExprKind::Array(values) if is_byte_array(expr) => Some(format!("byte[{}]", values.len())),
        ExprKind::Array(values) => {
            let nested_type = infer_fixed_array_literal_type(values)?;
            Some(nested_type.trim_end_matches("[]").to_string())
        }
        _ => None,
    }
}

fn infer_fixed_array_literal_type<'i>(values: &[Expr<'i>]) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    let first_type = infer_fixed_type_from_literal_expr(values.first()?)?;
    fixed_type_size(&first_type)?;
    if values.iter().skip(1).all(|value| infer_fixed_type_from_literal_expr(value).as_deref() == Some(first_type.as_str())) {
        Some(format!("{}[]", first_type))
    } else {
        None
    }
}

pub fn function_branch_index<'i>(contract: &ContractAst<'i>, function_name: &str) -> Result<i64, CompilerError> {
    contract
        .functions
        .iter()
        .filter(|func| func.entrypoint)
        .position(|func| func.name == function_name)
        .map(|index| index as i64)
        .ok_or_else(|| CompilerError::Unsupported(format!("function '{function_name}' not found")))
}

fn compile_function<'i>(
    function: &FunctionAst<'i>,
    function_index: usize,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    script_size: Option<i64>,
) -> Result<(String, Vec<u8>), CompilerError> {
    let contract_field_count = contract_fields.len();
    let param_count = function.params.len();
    let mut params = function
        .params
        .iter()
        .map(|param| param.name.clone())
        .enumerate()
        .map(|(index, name)| (name, (contract_field_count + (param_count - 1 - index)) as i64))
        .collect::<HashMap<_, _>>();

    for (index, field) in contract_fields.iter().enumerate() {
        params.insert(field.name.clone(), (contract_field_count - 1 - index) as i64);
    }

    let mut types =
        function.params.iter().map(|param| (param.name.clone(), type_name_from_ref(&param.type_ref))).collect::<HashMap<_, _>>();
    for field in contract_fields {
        types.insert(field.name.clone(), type_name_from_ref(&field.type_ref));
    }
    for param in &function.params {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if is_array_type(&param_type_name) && array_element_size(&param_type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param_type_name)));
        }
    }
    for return_type in &function.return_types {
        let return_type_name = type_name_from_ref(return_type);
        if is_array_type(&return_type_name) && array_element_size(&return_type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {return_type_name}")));
        }
    }
    let mut env: HashMap<String, Expr<'i>> = constants.clone();
    let mut builder = ScriptBuilder::new();
    let mut yields: Vec<Expr> = Vec::new();

    if !options.allow_yield && function.body.iter().any(contains_yield) {
        return Err(CompilerError::Unsupported("yield requires allow_yield=true".to_string()));
    }

    if function.entrypoint && !options.allow_entrypoint_return && function.body.iter().any(contains_return) {
        return Err(CompilerError::Unsupported("entrypoint return requires allow_entrypoint_return=true".to_string()));
    }

    let has_return = function.body.iter().any(contains_return);
    if has_return {
        if !matches!(function.body.last(), Some(Statement::Return { .. })) {
            return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
        }
        if function.body[..function.body.len() - 1].iter().any(contains_return) {
            return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
        }
        if function.body.iter().any(contains_yield) {
            return Err(CompilerError::Unsupported("return cannot be combined with yield".to_string()));
        }
        if function.return_types.is_empty() {
            return Err(CompilerError::Unsupported("return requires function return types".to_string()));
        }
    }

    let body_len = function.body.len();
    for (index, stmt) in function.body.iter().enumerate() {
        if matches!(stmt, Statement::Return { .. }) {
            if index != body_len - 1 {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            let Statement::Return { exprs, .. } = stmt else { unreachable!() };
            validate_return_types(exprs, &function.return_types, &types, constants)?;
            for expr in exprs {
                let resolved = resolve_expr(expr.clone(), &env, &mut HashSet::new()).map_err(|err| err.with_span(&expr.span))?;
                yields.push(resolved);
            }
            continue;
        }
        compile_statement(
            stmt,
            &mut env,
            &params,
            &mut types,
            &mut builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            constants,
            functions,
            function_order,
            function_index,
            &mut yields,
            script_size,
        )
        .map_err(|err| err.with_span(&stmt.span()))?;
    }

    let yield_count = yields.len();
    if yield_count == 0 {
        for _ in 0..param_count {
            builder.add_op(OpDrop)?;
        }
        for _ in 0..contract_field_count {
            builder.add_op(OpDrop)?;
        }
        builder.add_op(OpTrue)?;
    } else {
        let mut stack_depth = 0i64;
        for expr in &yields {
            compile_expr(
                expr,
                &env,
                &params,
                &types,
                &mut builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                constants,
            )?;
        }
        for _ in 0..param_count {
            builder.add_i64(yield_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
        for _ in 0..contract_field_count {
            builder.add_i64(yield_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
    }
    Ok((function.name.clone(), builder.drain()))
}

#[allow(clippy::too_many_arguments)]
fn compile_statement<'i>(
    stmt: &Statement<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr<'i>>,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            let type_name = type_name_from_ref(type_ref);
            let effective_type_name =
                if is_array_type(&type_name) && array_size_with_constants(&type_name, contract_constants).is_none() {
                    infer_fixed_array_type_from_initializer(&type_name, expr.as_ref(), types, contract_constants)
                        .unwrap_or_else(|| type_name.clone())
                } else {
                    type_name.clone()
                };

            // Check if this is a fixed-size array (e.g., byte[N]) or dynamic array (e.g., byte[])
            let is_fixed_size_array =
                is_array_type(&effective_type_name) && array_size_with_constants(&effective_type_name, contract_constants).is_some();
            let is_dynamic_array =
                is_array_type(&effective_type_name) && array_size_with_constants(&effective_type_name, contract_constants).is_none();

            if is_dynamic_array {
                if array_element_size(&effective_type_name).is_none() {
                    return Err(CompilerError::Unsupported(format!("array element type must have known size: {effective_type_name}")));
                }

                // For byte[] (dynamic byte arrays), allow initialization from any bytes expression
                let is_byte_array_type = effective_type_name.starts_with("byte[") && effective_type_name.ends_with("[]");

                let initial = match expr {
                    Some(e) if matches!(&e.kind, ExprKind::Identifier(_)) => {
                        let ExprKind::Identifier(other) = &e.kind else { unreachable!() };
                        match types.get(other) {
                            Some(other_type) if is_type_assignable(other_type, &effective_type_name, contract_constants) => {
                                Expr::new(ExprKind::Identifier(other.clone()), span::Span::default())
                            }
                            Some(_) => {
                                return Err(CompilerError::Unsupported(
                                    "array assignment requires compatible array types".to_string(),
                                ));
                            }
                            None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                        }
                    }
                    Some(e) if is_byte_array_type => {
                        // byte[] can be initialized from any bytes expression
                        e.clone()
                    }
                    Some(e) if matches!(&e.kind, ExprKind::Array(_)) => {
                        let ExprKind::Array(values) = &e.kind else { unreachable!() };
                        if !array_literal_matches_type_with_env(values, &effective_type_name, types, contract_constants) {
                            return Err(CompilerError::Unsupported("array initializer must be another array".to_string()));
                        }
                        resolve_expr(Expr::new(ExprKind::Array(values.clone()), e.span), env, &mut HashSet::new())?
                    }
                    Some(_) => return Err(CompilerError::Unsupported("array initializer must be another array".to_string())),
                    None => Expr::new(ExprKind::Array(Vec::new()), span::Span::default()),
                };
                env.insert(name.clone(), initial);
                types.insert(name.clone(), effective_type_name.clone());
                Ok(())
            } else if is_fixed_size_array {
                // Fixed-size arrays like byte[N] can be initialized from expressions
                let expr =
                    expr.clone().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;

                // For array literals, validate that the size matches the declared type
                if let ExprKind::Array(values) = &expr.kind {
                    if let Some(expected_size) = array_size_with_constants(&effective_type_name, contract_constants) {
                        if values.len() != expected_size {
                            return Err(CompilerError::Unsupported(format!(
                                "array size mismatch: expected {} elements for type {}, got {}",
                                expected_size,
                                effective_type_name,
                                values.len()
                            )));
                        }
                    }

                    // Validate element types match
                    if !array_literal_matches_type_with_env(values, &effective_type_name, types, contract_constants) {
                        return Err(CompilerError::Unsupported(format!(
                            "array element type mismatch for type {}",
                            effective_type_name
                        )));
                    }
                }

                let stored_expr =
                    if matches!(&expr.kind, ExprKind::Array(_)) { resolve_expr(expr, env, &mut HashSet::new())? } else { expr };
                env.insert(name.clone(), stored_expr);
                types.insert(name.clone(), effective_type_name.clone());
                Ok(())
            } else {
                let expr =
                    expr.clone().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
                env.insert(name.clone(), expr);
                types.insert(name.clone(), effective_type_name.clone());
                Ok(())
            }
        }
        Statement::ArrayPush { name, expr, .. } => {
            let array_type = types.get(name).ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?;
            if !is_array_type(array_type) {
                return Err(CompilerError::Unsupported("push() only supported on arrays".to_string()));
            }
            let element_type = array_element_type(array_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            let _element_size = array_element_size(array_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            let element_expr = if element_type == "int" {
                Expr::new(
                    ExprKind::Call { name: "byte[8]".to_string(), args: vec![expr.clone()], name_span: span::Span::default() },
                    span::Span::default(),
                )
            } else if element_type == "byte" {
                Expr::new(
                    ExprKind::Call { name: "byte[1]".to_string(), args: vec![expr.clone()], name_span: span::Span::default() },
                    span::Span::default(),
                )
            } else if element_type.contains('[') && element_type.starts_with("byte") {
                // Handle byte[N] type
                if expr_is_bytes(expr, env, types) {
                    expr.clone()
                } else {
                    // Try byte[N] syntax
                    if let Some(bracket_pos) = element_type.find('[') {
                        if element_type.ends_with(']') {
                            let base_type = &element_type[..bracket_pos];
                            let size_str = &element_type[bracket_pos + 1..element_type.len() - 1];
                            if base_type == "byte" {
                                if let Ok(_size) = size_str.parse::<usize>() {
                                    // Cast expression to byte[N]
                                    Expr::new(
                                        ExprKind::Call {
                                            name: element_type.to_string(),
                                            args: vec![expr.clone()],
                                            name_span: span::Span::default(),
                                        },
                                        span::Span::default(),
                                    )
                                } else {
                                    return Err(CompilerError::Unsupported("invalid array size".to_string()));
                                }
                            } else {
                                return Err(CompilerError::Unsupported("array element type not supported".to_string()));
                            }
                        } else {
                            return Err(CompilerError::Unsupported("array element type not supported".to_string()));
                        }
                    } else {
                        return Err(CompilerError::Unsupported("array element type not supported".to_string()));
                    }
                }
            } else {
                return Err(CompilerError::Unsupported("array element type not supported".to_string()));
            };

            let current = env.get(name).cloned().unwrap_or_else(|| Expr::new(ExprKind::Array(Vec::new()), span::Span::default()));
            let updated = Expr::new(
                ExprKind::Binary { op: BinaryOp::Add, left: Box::new(current), right: Box::new(element_expr) },
                span::Span::default(),
            );
            env.insert(name.clone(), updated);
            Ok(())
        }
        Statement::Require { expr, .. } => {
            let mut stack_depth = 0i64;
            compile_expr(
                expr,
                env,
                params,
                types,
                builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpVerify)?;
            Ok(())
        }
        Statement::TimeOp { tx_var, expr, .. } => {
            compile_time_op_statement(tx_var, expr, env, params, types, builder, options, script_size, contract_constants)
        }
        Statement::If { condition, then_branch, else_branch, .. } => compile_if_statement(
            condition,
            then_branch,
            else_branch.as_deref(),
            env,
            params,
            types,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        ),
        Statement::For { ident, start, end, body, .. } => compile_for_statement(
            ident,
            start,
            end,
            body,
            env,
            params,
            types,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        ),
        Statement::Yield { expr, .. } => {
            let mut visiting = HashSet::new();
            let resolved = resolve_expr(expr.clone(), env, &mut visiting)?;
            yields.push(resolved);
            Ok(())
        }
        Statement::Return { .. } => Err(CompilerError::Unsupported("return statement must be the last statement".to_string())),
        Statement::TupleAssignment { left_name, right_name, expr, .. } => match &expr.kind {
            ExprKind::Split { source, index, span: split_span, .. } => {
                let left_expr = Expr::new(
                    ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left, span: *split_span },
                    span::Span::default(),
                );
                let right_expr = Expr::new(
                    ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Right, span: *split_span },
                    span::Span::default(),
                );
                env.insert(left_name.clone(), left_expr);
                env.insert(right_name.clone(), right_expr);
                Ok(())
            }
            _ => Err(CompilerError::Unsupported("tuple assignment only supports split()".to_string())),
        },
        Statement::FunctionCall { name, args, .. } => {
            if name == "validateOutputState" {
                return compile_validate_output_state_statement(
                    args,
                    env,
                    params,
                    types,
                    builder,
                    options,
                    contract_fields,
                    contract_field_prefix_len,
                    script_size,
                    contract_constants,
                );
            }
            let returns = compile_inline_call(
                name,
                args,
                types,
                env,
                builder,
                options,
                contract_constants,
                functions,
                function_order,
                function_index,
                script_size,
            )?;
            if !returns.is_empty() {
                let mut stack_depth = 0i64;
                for expr in returns {
                    compile_expr(
                        &expr,
                        env,
                        params,
                        types,
                        builder,
                        options,
                        &mut HashSet::new(),
                        &mut stack_depth,
                        script_size,
                        contract_constants,
                    )?;
                    builder.add_op(OpDrop)?;
                    stack_depth -= 1;
                }
            }
            Ok(())
        }
        Statement::StateFunctionCallAssign { bindings, name, args, .. } => {
            if name == "readInputState" {
                return compile_read_input_state_statement(
                    bindings,
                    args,
                    env,
                    types,
                    contract_fields,
                    script_size,
                    contract_constants,
                );
            }
            Err(CompilerError::Unsupported(format!(
                "state destructuring assignment is only supported for readInputState(), got '{}()'",
                name
            )))
        }
        Statement::FunctionCallAssign { bindings, name, args, .. } => {
            let function = functions.get(name).ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
            if function.return_types.is_empty() {
                return Err(CompilerError::Unsupported("function has no return types".to_string()));
            }
            if function.return_types.len() != bindings.len() {
                return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
            }
            for (binding, return_type) in bindings.iter().zip(function.return_types.iter()) {
                if binding.type_ref != *return_type {
                    return Err(CompilerError::Unsupported("function return types must match binding types".to_string()));
                }
            }
            let returns = compile_inline_call(
                name,
                args,
                types,
                env,
                builder,
                options,
                contract_constants,
                functions,
                function_order,
                function_index,
                script_size,
            )?;
            if returns.len() != bindings.len() {
                return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
            }
            for (binding, expr) in bindings.iter().zip(returns.into_iter()) {
                env.insert(binding.name.clone(), expr);
                types.insert(binding.name.clone(), type_name_from_ref(&binding.type_ref));
            }
            Ok(())
        }
        Statement::Assign { name, expr, .. } => {
            let name_value = name.as_str();
            if let Some(type_name) = types.get(name_value) {
                if is_array_type(type_name) {
                    match &expr.kind {
                        ExprKind::Identifier(other) => match types.get(other) {
                            Some(other_type) if other_type == type_name => {
                                env.insert(name.clone(), Expr::new(ExprKind::Identifier(other.clone()), span::Span::default()));
                                return Ok(());
                            }
                            Some(_) => {
                                return Err(CompilerError::Unsupported(
                                    "array assignment requires compatible array types".to_string(),
                                ));
                            }
                            None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                        },
                        _ => {
                            return Err(CompilerError::Unsupported("array assignment only supports array identifiers".to_string()));
                        }
                    }
                }
            }
            let updated =
                if let Some(previous) = env.get(name_value) { replace_identifier(expr, name_value, previous) } else { expr.clone() };
            let resolved = resolve_expr(updated, env, &mut HashSet::new())?;
            env.insert(name.clone(), resolved);
            Ok(())
        }
        Statement::Console { .. } => Ok(()),
    }
}

fn encoded_field_chunk_size<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    if field.type_ref.array_dims.is_empty() && field.type_ref.base == TypeBase::Int {
        return Ok(10);
    }

    if field.type_ref.base != TypeBase::Byte {
        return Err(CompilerError::Unsupported(format!(
            "readInputState does not support field type {}",
            type_name_from_ref(&field.type_ref)
        )));
    }

    let payload_size = if field.type_ref.array_dims.is_empty() {
        1usize
    } else {
        array_size_with_constants_ref(&field.type_ref, contract_constants).ok_or_else(|| {
            CompilerError::Unsupported(format!("readInputState does not support field type {}", type_name_from_ref(&field.type_ref)))
        })?
    };

    Ok(data_prefix(payload_size).len() + payload_size)
}

fn read_input_state_binding_expr<'i>(
    input_idx: &Expr<'i>,
    field: &ContractFieldAst<'i>,
    field_chunk_offset: usize,
    script_size_value: i64,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let (field_payload_offset, field_payload_len, decode_int) =
        if field.type_ref.array_dims.is_empty() && field.type_ref.base == TypeBase::Int {
            (field_chunk_offset + 1, 8usize, true)
        } else if field.type_ref.base == TypeBase::Byte {
            let payload_len = if field.type_ref.array_dims.is_empty() {
                1usize
            } else {
                array_size_with_constants_ref(&field.type_ref, contract_constants).ok_or_else(|| {
                    CompilerError::Unsupported(format!(
                        "readInputState does not support field type {}",
                        type_name_from_ref(&field.type_ref)
                    ))
                })?
            };
            (field_chunk_offset + data_prefix(payload_len).len(), payload_len, false)
        } else {
            return Err(CompilerError::Unsupported(format!(
                "readInputState does not support field type {}",
                type_name_from_ref(&field.type_ref)
            )));
        };

    let sig_len = Expr::call("OpTxInputScriptSigLen", vec![input_idx.clone()]);
    let start = Expr::new(
        ExprKind::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::new(
                ExprKind::Binary { op: BinaryOp::Sub, left: Box::new(sig_len), right: Box::new(Expr::int(script_size_value)) },
                span::Span::default(),
            )),
            right: Box::new(Expr::int(field_payload_offset as i64)),
        },
        span::Span::default(),
    );
    let end = Expr::new(
        ExprKind::Binary { op: BinaryOp::Add, left: Box::new(start.clone()), right: Box::new(Expr::int(field_payload_len as i64)) },
        span::Span::default(),
    );
    let substr = Expr::call("OpTxInputScriptSigSubstr", vec![input_idx.clone(), start, end]);

    if decode_int { Ok(Expr::call("OpBin2Num", vec![substr])) } else { Ok(substr) }
}

fn compile_read_input_state_statement<'i>(
    bindings: &[StateBindingAst<'i>],
    args: &[Expr<'i>],
    env: &mut HashMap<String, Expr<'i>>,
    types: &mut HashMap<String, String>,
    contract_fields: &[ContractFieldAst<'i>],
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("readInputState(input_idx) expects 1 argument".to_string()));
    }
    if contract_fields.is_empty() {
        return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
    }
    let script_size_value =
        script_size.ok_or_else(|| CompilerError::Unsupported("readInputState requires this.scriptSize".to_string()))?;

    let mut bindings_by_field: HashMap<&str, &StateBindingAst<'i>> = HashMap::new();
    for binding in bindings {
        if bindings_by_field.insert(binding.field_name.as_str(), binding).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate state field '{}'", binding.field_name)));
        }
    }
    if bindings_by_field.len() != contract_fields.len() {
        return Err(CompilerError::Unsupported("readInputState bindings must include all contract fields exactly once".to_string()));
    }

    let input_idx = args[0].clone();
    let mut field_chunk_offset = 0usize;

    for field in contract_fields {
        let binding = bindings_by_field.get(field.name.as_str()).ok_or_else(|| {
            CompilerError::Unsupported("readInputState bindings must include all contract fields exactly once".to_string())
        })?;

        let binding_type = type_name_from_ref(&binding.type_ref);
        let field_type = type_name_from_ref(&field.type_ref);
        if binding_type != field_type {
            return Err(CompilerError::Unsupported(format!("readInputState binding '{}' expects {}", binding.name, field_type)));
        }

        let binding_expr =
            read_input_state_binding_expr(&input_idx, field, field_chunk_offset, script_size_value, contract_constants)?;
        env.insert(binding.name.clone(), binding_expr);
        types.insert(binding.name.clone(), binding_type);

        field_chunk_offset += encoded_field_chunk_size(field, contract_constants)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_validate_output_state_statement(
    args: &[Expr<'_>],
    env: &HashMap<String, Expr<'_>>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'_>],
    contract_field_prefix_len: usize,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    if args.len() != 2 {
        return Err(CompilerError::Unsupported("validateOutputState(output_idx, new_state) expects 2 arguments".to_string()));
    }
    if contract_fields.is_empty() {
        return Err(CompilerError::Unsupported("validateOutputState requires contract fields".to_string()));
    }

    let output_idx = &args[0];
    let ExprKind::StateObject(state_entries) = &args[1].kind else {
        return Err(CompilerError::Unsupported("validateOutputState second argument must be an object literal".to_string()));
    };

    let mut provided = HashMap::new();
    for entry in state_entries {
        if provided.insert(entry.name.as_str(), &entry.expr).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate state field '{}'", entry.name)));
        }
    }
    if provided.len() != contract_fields.len() {
        return Err(CompilerError::Unsupported("new_state must include all contract fields exactly once".to_string()));
    }

    let mut stack_depth = 0i64;
    for field in contract_fields {
        let Some(new_value) = provided.remove(field.name.as_str()) else {
            return Err(CompilerError::Unsupported(format!("missing state field '{}'", field.name)));
        };

        if field.type_ref.array_dims.is_empty() && field.type_ref.base == TypeBase::Int {
            compile_expr(
                new_value,
                env,
                params,
                types,
                builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_i64(8)?;
            stack_depth += 1;
            builder.add_op(OpNum2Bin)?;
            stack_depth -= 1;
            builder.add_data(&[0x08])?;
            stack_depth += 1;
            builder.add_op(OpSwap)?;
            builder.add_op(OpCat)?;
            stack_depth -= 1;
            builder.add_data(&[OpBin2Num])?;
            stack_depth += 1;
            builder.add_op(OpCat)?;
            stack_depth -= 1;
            continue;
        }

        let field_size = if field.type_ref.base == TypeBase::Byte {
            if field.type_ref.array_dims.is_empty() {
                Some(1usize)
            } else {
                array_size_with_constants_ref(&field.type_ref, contract_constants)
            }
        } else {
            None
        };

        let Some(field_size) = field_size else {
            return Err(CompilerError::Unsupported(format!(
                "validateOutputState does not support field type {}",
                type_name_from_ref(&field.type_ref)
            )));
        };

        compile_expr(
            new_value,
            env,
            params,
            types,
            builder,
            options,
            &mut HashSet::new(),
            &mut stack_depth,
            script_size,
            contract_constants,
        )?;
        let prefix = data_prefix(field_size);
        builder.add_data(&prefix)?;
        stack_depth += 1;
        builder.add_op(OpSwap)?;
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    let script_size_value =
        script_size.ok_or_else(|| CompilerError::Unsupported("validateOutputState requires this.scriptSize".to_string()))?;

    builder.add_op(OpTxInputIndex)?;
    stack_depth += 1;
    builder.add_op(OpDup)?;
    stack_depth += 1;
    builder.add_op(OpTxInputScriptSigLen)?;
    builder.add_op(OpDup)?;
    stack_depth += 1;
    builder.add_i64(script_size_value)?;
    stack_depth += 1;
    builder.add_op(OpSub)?;
    stack_depth -= 1;
    builder.add_i64(contract_field_prefix_len as i64)?;
    stack_depth += 1;
    builder.add_op(OpAdd)?;
    stack_depth -= 1;
    builder.add_op(OpSwap)?;
    builder.add_op(OpTxInputScriptSigSubstr)?;
    stack_depth -= 2;

    for _ in 0..contract_fields.len() {
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    builder.add_op(OpBlake2b)?;
    builder.add_data(&[0x00, 0x00])?;
    stack_depth += 1;
    builder.add_data(&[OpBlake2b])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_data(&[0x20])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_op(OpSwap)?;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_data(&[OpEqual])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;

    compile_expr(
        output_idx,
        env,
        params,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        Some(script_size_value),
        contract_constants,
    )?;
    builder.add_op(OpTxOutputSpk)?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_inline_call<'i>(
    name: &str,
    args: &[Expr<'i>],
    caller_types: &mut HashMap<String, String>,
    caller_env: &mut HashMap<String, Expr<'i>>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    caller_index: usize,
    script_size: Option<i64>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let function = functions.get(name).ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
    let callee_index =
        function_order.get(name).copied().ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
    if callee_index >= caller_index {
        return Err(CompilerError::Unsupported("functions may only call earlier-defined functions".to_string()));
    }

    if function.params.len() != args.len() {
        return Err(CompilerError::Unsupported(format!("function '{}' expects {} arguments", name, function.params.len())));
    }
    for (param, arg) in function.params.iter().zip(args.iter()) {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if !expr_matches_type_with_env(arg, &param_type_name, caller_types, contract_constants) {
            return Err(CompilerError::Unsupported(format!("function argument '{}' expects {}", param.name, param_type_name)));
        }
    }

    let mut types =
        function.params.iter().map(|param| (param.name.clone(), type_name_from_ref(&param.type_ref))).collect::<HashMap<_, _>>();
    for param in &function.params {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if is_array_type(&param_type_name) && array_element_size(&param_type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param_type_name)));
        }
    }

    let mut env: HashMap<String, Expr<'i>> = contract_constants.clone();
    for (index, (param, arg)) in function.params.iter().zip(args.iter()).enumerate() {
        let resolved = resolve_expr(arg.clone(), caller_env, &mut HashSet::new())?;
        let temp_name = format!("__arg_{name}_{index}");
        let param_type_name = type_name_from_ref(&param.type_ref);
        env.insert(temp_name.clone(), resolved.clone());
        types.insert(temp_name.clone(), param_type_name.clone());
        env.insert(param.name.clone(), Expr::new(ExprKind::Identifier(temp_name.clone()), span::Span::default()));
        caller_env.insert(temp_name.clone(), resolved);
        caller_types.insert(temp_name, param_type_name);
    }

    if !options.allow_yield && function.body.iter().any(contains_yield) {
        return Err(CompilerError::Unsupported("yield requires allow_yield=true".to_string()));
    }

    if function.entrypoint && !options.allow_entrypoint_return && function.body.iter().any(contains_return) {
        return Err(CompilerError::Unsupported("entrypoint return requires allow_entrypoint_return=true".to_string()));
    }

    let has_return = function.body.iter().any(contains_return);
    if has_return {
        if !matches!(function.body.last(), Some(Statement::Return { .. })) {
            return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
        }
        if function.body[..function.body.len() - 1].iter().any(contains_return) {
            return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
        }
        if function.body.iter().any(contains_yield) {
            return Err(CompilerError::Unsupported("return cannot be combined with yield".to_string()));
        }
    }

    let mut yields: Vec<Expr<'i>> = Vec::new();
    let params = HashMap::new();
    let body_len = function.body.len();
    for (index, stmt) in function.body.iter().enumerate() {
        if matches!(stmt, Statement::Return { .. }) {
            if index != body_len - 1 {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            let Statement::Return { exprs, .. } = stmt else { unreachable!() };
            validate_return_types(exprs, &function.return_types, &types, contract_constants)
                .map_err(|err| err.with_span(&stmt.span()))?;
            for expr in exprs {
                let resolved = resolve_expr(expr.clone(), &env, &mut HashSet::new()).map_err(|err| err.with_span(&expr.span))?;
                yields.push(resolved);
            }
            continue;
        }
        compile_statement(
            stmt,
            &mut env,
            &params,
            &mut types,
            builder,
            options,
            &[],
            0,
            contract_constants,
            functions,
            function_order,
            callee_index,
            &mut yields,
            script_size,
        )
        .map_err(|err| err.with_span(&stmt.span()))?;
    }

    for (name, value) in env.iter() {
        if name.starts_with("__arg_") {
            if let Some(type_name) = types.get(name) {
                caller_types.entry(name.clone()).or_insert_with(|| type_name.clone());
            }
            caller_env.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }

    Ok(yields)
}

#[allow(clippy::too_many_arguments)]
fn compile_if_statement<'i>(
    condition: &Expr<'i>,
    then_branch: &[Statement<'i>],
    else_branch: Option<&[Statement<'i>]>,
    env: &mut HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr<'i>>,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(
        condition,
        env,
        params,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpIf)?;

    let original_env = env.clone();
    let mut then_env = original_env.clone();
    let mut then_types = types.clone();
    compile_block(
        then_branch,
        &mut then_env,
        params,
        &mut then_types,
        builder,
        options,
        contract_fields,
        contract_field_prefix_len,
        contract_constants,
        functions,
        function_order,
        function_index,
        yields,
        script_size,
    )?;

    let mut else_env = original_env.clone();
    if let Some(else_branch) = else_branch {
        builder.add_op(OpElse)?;
        let mut else_types = types.clone();
        compile_block(
            else_branch,
            &mut else_env,
            params,
            &mut else_types,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        )?;
    }

    builder.add_op(OpEndIf)?;

    let resolved_condition = resolve_expr(condition.clone(), &original_env, &mut HashSet::new())?;
    merge_env_after_if(env, &original_env, &then_env, &else_env, &resolved_condition);
    Ok(())
}

fn merge_env_after_if<'i>(
    env: &mut HashMap<String, Expr<'i>>,
    original_env: &HashMap<String, Expr<'i>>,
    then_env: &HashMap<String, Expr<'i>>,
    else_env: &HashMap<String, Expr<'i>>,
    condition: &Expr<'i>,
) {
    for (name, original_expr) in original_env {
        let then_expr = then_env.get(name).unwrap_or(original_expr);
        let else_expr = else_env.get(name).unwrap_or(original_expr);

        if then_expr == else_expr {
            env.insert(name.clone(), then_expr.clone());
        } else {
            env.insert(
                name.clone(),
                Expr::new(
                    ExprKind::IfElse {
                        condition: Box::new(condition.clone()),
                        then_expr: Box::new(then_expr.clone()),
                        else_expr: Box::new(else_expr.clone()),
                    },
                    span::Span::default(),
                ),
            );
        }
    }
}

fn compile_time_op_statement<'i>(
    tx_var: &TimeVar,
    expr: &Expr<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(expr, env, params, types, builder, options, &mut HashSet::new(), &mut stack_depth, script_size, contract_constants)?;

    match tx_var {
        TimeVar::ThisAge => {
            builder.add_op(OpCheckSequenceVerify)?;
        }
        TimeVar::TxTime => {
            builder.add_op(OpCheckLockTimeVerify)?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_block<'i>(
    statements: &[Statement<'i>],
    env: &mut HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr<'i>>,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    for stmt in statements {
        compile_statement(
            stmt,
            env,
            params,
            types,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        )
        .map_err(|err| err.with_span(&stmt.span()))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_for_statement<'i>(
    ident: &str,
    start_expr: &Expr<'i>,
    end_expr: &Expr<'i>,
    body: &[Statement<'i>],
    env: &mut HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr<'i>>,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let start = eval_const_int(start_expr, contract_constants)?;
    let end = eval_const_int(end_expr, contract_constants)?;
    if end < start {
        return Err(CompilerError::Unsupported("for loop end must be >= start".to_string()));
    }

    let name = ident.to_string();
    let previous = env.get(&name).cloned();
    for value in start..end {
        env.insert(name.clone(), Expr::int(value));
        compile_block(
            body,
            env,
            params,
            types,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        )?;
    }

    match previous {
        Some(expr) => {
            env.insert(name, expr);
        }
        None => {
            env.remove(&name);
        }
    }

    Ok(())
}

fn eval_const_int<'i>(expr: &Expr<'i>, constants: &HashMap<String, Expr<'i>>) -> Result<i64, CompilerError> {
    match &expr.kind {
        ExprKind::Int(value) => Ok(*value),
        ExprKind::DateLiteral(value) => Ok(*value),
        ExprKind::Identifier(name) => match constants.get(name) {
            Some(value) => eval_const_int(value, constants),
            None => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
        },
        ExprKind::Unary { op: UnaryOp::Neg, expr } => Ok(-eval_const_int(expr, constants)?),
        ExprKind::Unary { .. } => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
        ExprKind::Binary { op, left, right } => {
            let lhs = eval_const_int(left, constants)?;
            let rhs = eval_const_int(right, constants)?;
            match op {
                BinaryOp::Add => Ok(lhs + rhs),
                BinaryOp::Sub => Ok(lhs - rhs),
                BinaryOp::Mul => Ok(lhs * rhs),
                BinaryOp::Div => {
                    if rhs == 0 {
                        return Err(CompilerError::InvalidLiteral("division by zero in for loop bounds".to_string()));
                    }
                    Ok(lhs / rhs)
                }
                BinaryOp::Mod => {
                    if rhs == 0 {
                        return Err(CompilerError::InvalidLiteral("modulo by zero in for loop bounds".to_string()));
                    }
                    Ok(lhs % rhs)
                }
                _ => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
            }
        }
        _ => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
    }
}

fn resolve_expr<'i>(
    expr: Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    let Expr { kind, span } = expr;
    match kind {
        ExprKind::Identifier(name) => {
            if name.starts_with("__arg_") {
                return Ok(Expr::new(ExprKind::Identifier(name), span));
            }
            if let Some(value) = env.get(&name) {
                if !visiting.insert(name.clone()) {
                    return Err(CompilerError::CyclicIdentifier(name));
                }
                let resolved = resolve_expr(value.clone(), env, visiting)?;
                visiting.remove(&name);
                Ok(resolved)
            } else {
                Ok(Expr::new(ExprKind::Identifier(name), span))
            }
        }
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op, expr: Box::new(resolve_expr(*expr, env, visiting)?) }, span))
        }
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op,
                left: Box::new(resolve_expr(*left, env, visiting)?),
                right: Box::new(resolve_expr(*right, env, visiting)?),
            },
            span,
        )),
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(resolve_expr(*condition, env, visiting)?),
                then_expr: Box::new(resolve_expr(*then_expr, env, visiting)?),
                else_expr: Box::new(resolve_expr(*else_expr, env, visiting)?),
            },
            span,
        )),
        ExprKind::Array(values) => {
            let mut resolved = Vec::with_capacity(values.len());
            for value in values {
                resolved.push(resolve_expr(value, env, visiting)?);
            }
            Ok(Expr::new(ExprKind::Array(resolved), span))
        }
        ExprKind::StateObject(fields) => {
            let mut resolved_fields = Vec::with_capacity(fields.len());
            for field in fields {
                resolved_fields.push(StateFieldExpr {
                    name: field.name,
                    expr: resolve_expr(field.expr, env, visiting)?,
                    span: field.span,
                    name_span: field.name_span,
                });
            }
            Ok(Expr::new(ExprKind::StateObject(resolved_fields), span))
        }
        ExprKind::Call { name, args, name_span } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr(arg, env, visiting)?);
            }
            Ok(Expr::new(ExprKind::Call { name, args: resolved, name_span }, span))
        }
        ExprKind::New { name, args, name_span } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr(arg, env, visiting)?);
            }
            Ok(Expr::new(ExprKind::New { name, args: resolved, name_span }, span))
        }
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(resolve_expr(*source, env, visiting)?),
                index: Box::new(resolve_expr(*index, env, visiting)?),
                part,
                span: split_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(resolve_expr(*source, env, visiting)?),
                index: Box::new(resolve_expr(*index, env, visiting)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => {
            Ok(Expr::new(ExprKind::Introspection { kind, index: Box::new(resolve_expr(*index, env, visiting)?), field_span }, span))
        }
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Ok(Expr::new(
            ExprKind::UnarySuffix { source: Box::new(resolve_expr(*source, env, visiting)?), kind, span: suffix_span },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(resolve_expr(*source, env, visiting)?),
                start: Box::new(resolve_expr(*start, env, visiting)?),
                end: Box::new(resolve_expr(*end, env, visiting)?),
                span: slice_span,
            },
            span,
        )),
        other => Ok(Expr::new(other, span)),
    }
}

fn replace_identifier<'i>(expr: &Expr<'i>, target: &str, replacement: &Expr<'i>) -> Expr<'i> {
    let span = expr.span;
    match &expr.kind {
        ExprKind::Identifier(name) if name == target => replacement.clone(),
        ExprKind::Identifier(_) => expr.clone(),
        ExprKind::Unary { op, expr: inner } => {
            Expr::new(ExprKind::Unary { op: *op, expr: Box::new(replace_identifier(inner, target, replacement)) }, span)
        }
        ExprKind::Binary { op, left, right } => Expr::new(
            ExprKind::Binary {
                op: *op,
                left: Box::new(replace_identifier(left, target, replacement)),
                right: Box::new(replace_identifier(right, target, replacement)),
            },
            span,
        ),
        ExprKind::Array(values) => {
            Expr::new(ExprKind::Array(values.iter().map(|value| replace_identifier(value, target, replacement)).collect()), span)
        }
        ExprKind::Call { name, args, name_span } => Expr::new(
            ExprKind::Call {
                name: name.clone(),
                args: args.iter().map(|arg| replace_identifier(arg, target, replacement)).collect(),
                name_span: *name_span,
            },
            span,
        ),
        ExprKind::New { name, args, name_span } => Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(|arg| replace_identifier(arg, target, replacement)).collect(),
                name_span: *name_span,
            },
            span,
        ),
        ExprKind::Split { source, index, part, span: split_span } => Expr::new(
            ExprKind::Split {
                source: Box::new(replace_identifier(source, target, replacement)),
                index: Box::new(replace_identifier(index, target, replacement)),
                part: *part,
                span: *split_span,
            },
            span,
        ),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Expr::new(
            ExprKind::UnarySuffix {
                source: Box::new(replace_identifier(source, target, replacement)),
                kind: *kind,
                span: *suffix_span,
            },
            span,
        ),
        ExprKind::Slice { source, start, end, span: slice_span } => Expr::new(
            ExprKind::Slice {
                source: Box::new(replace_identifier(source, target, replacement)),
                start: Box::new(replace_identifier(start, target, replacement)),
                end: Box::new(replace_identifier(end, target, replacement)),
                span: *slice_span,
            },
            span,
        ),
        ExprKind::ArrayIndex { source, index } => Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(replace_identifier(source, target, replacement)),
                index: Box::new(replace_identifier(index, target, replacement)),
            },
            span,
        ),
        ExprKind::IfElse { condition, then_expr, else_expr } => Expr::new(
            ExprKind::IfElse {
                condition: Box::new(replace_identifier(condition, target, replacement)),
                then_expr: Box::new(replace_identifier(then_expr, target, replacement)),
                else_expr: Box::new(replace_identifier(else_expr, target, replacement)),
            },
            span,
        ),
        ExprKind::Introspection { kind, index, field_span } => Expr::new(
            ExprKind::Introspection {
                kind: *kind,
                index: Box::new(replace_identifier(index, target, replacement)),
                field_span: *field_span,
            },
            span,
        ),
        ExprKind::Int(_)
        | ExprKind::Bool(_)
        | ExprKind::Bytes(_)
        | ExprKind::String(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::StateObject(_)
        | ExprKind::NumberWithUnit { .. }
        | ExprKind::Nullary(_) => expr.clone(),
    }
}

struct CompilationScope<'a, 'i> {
    env: &'a HashMap<String, Expr<'i>>,
    params: &'a HashMap<String, i64>,
    types: &'a HashMap<String, String>,
}

fn compile_expr<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let scope = CompilationScope { env, params, types };
    match &expr.kind {
        ExprKind::Int(value) => {
            builder.add_i64(*value)?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::Bool(value) => {
            builder.add_op(if *value { OpTrue } else { OpFalse })?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::Bytes(bytes) => {
            builder.add_data(bytes)?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::String(value) => {
            builder.add_data(value.as_bytes())?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return Err(CompilerError::CyclicIdentifier(name.clone()));
            }
            if let Some(expr) = env.get(name) {
                if let Some(type_name) = types.get(name) {
                    if let ExprKind::Array(values) = &expr.kind {
                        if is_array_type(type_name) {
                            let encoded = encode_array_literal(values, type_name)?;
                            builder.add_data(&encoded)?;
                            *stack_depth += 1;
                            visiting.remove(name);
                            return Ok(());
                        }
                    }
                }
                compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
                visiting.remove(name);
                return Ok(());
            }
            if let Some(index) = params.get(name) {
                builder.add_i64(*index + *stack_depth)?;
                *stack_depth += 1;
                builder.add_op(OpPick)?;
                visiting.remove(name);
                return Ok(());
            }
            visiting.remove(name);
            Err(CompilerError::UndefinedIdentifier(name.clone()))
        }
        ExprKind::DateLiteral(value) => {
            builder.add_i64(*value)?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::NumberWithUnit { .. } => {
            Err(CompilerError::Unsupported("number units must be normalized during parsing".to_string()))
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            compile_expr(condition, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_op(OpIf)?;
            *stack_depth -= 1;
            let depth_before = *stack_depth;
            compile_expr(then_expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_op(OpElse)?;
            *stack_depth = depth_before;
            compile_expr(else_expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_op(OpEndIf)?;
            *stack_depth = depth_before + 1;
            Ok(())
        }
        ExprKind::Array(values) => {
            if values.is_empty() {
                builder.add_data(&[])?;
                *stack_depth += 1;
                return Ok(());
            }
            let inferred_type = infer_fixed_array_literal_type(values)
                .ok_or_else(|| CompilerError::Unsupported("array literal type cannot be inferred".to_string()))?;
            let encoded = encode_array_literal(values, &inferred_type)?;
            builder.add_data(&encoded)?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::StateObject(_) => {
            Err(CompilerError::Unsupported("state object literals are only supported in validateOutputState".to_string()))
        }
        ExprKind::Call { name, args, .. } => {
            compile_call_expr(name.as_str(), args, &scope, builder, options, visiting, stack_depth, script_size, contract_constants)
        }
        ExprKind::New { name, args, .. } => match name.as_str() {
            "LockingBytecodeNullData" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("LockingBytecodeNullData expects a single array argument".to_string()));
                }
                let script = build_null_data_script(&args[0])?;
                builder.add_data(&script)?;
                *stack_depth += 1;
                Ok(())
            }
            "ScriptPubKeyP2PK" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("ScriptPubKeyP2PK expects a single pubkey argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
                builder.add_data(&[0x00, 0x00, OpData32])?;
                *stack_depth += 1;
                builder.add_op(OpSwap)?;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[OpCheckSig])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                Ok(())
            }
            "ScriptPubKeyP2SH" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("ScriptPubKeyP2SH expects a single bytes32 argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
                builder.add_data(&[0x00, 0x00])?;
                *stack_depth += 1;
                builder.add_data(&[OpBlake2b])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[0x20])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_op(OpSwap)?;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[OpEqual])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                Ok(())
            }
            "ScriptPubKeyP2SHFromRedeemScript" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(
                        "ScriptPubKeyP2SHFromRedeemScript expects a single redeem_script argument".to_string(),
                    ));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
                builder.add_op(OpBlake2b)?;
                builder.add_data(&[0x00, 0x00])?;
                *stack_depth += 1;
                builder.add_data(&[OpBlake2b])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[0x20])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_op(OpSwap)?;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[OpEqual])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                Ok(())
            }
            name => Err(CompilerError::Unsupported(format!("unknown constructor: {name}"))),
        },
        ExprKind::Unary { op, expr } => {
            compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            match op {
                UnaryOp::Not => builder.add_op(OpNot)?,
                UnaryOp::Neg => builder.add_op(OpNegate)?,
            };
            Ok(())
        }
        ExprKind::Binary { op, left, right } => {
            let bytes_eq =
                matches!(op, BinaryOp::Eq | BinaryOp::Ne) && (expr_is_bytes(left, env, types) || expr_is_bytes(right, env, types));
            let bytes_add = matches!(op, BinaryOp::Add) && (expr_is_bytes(left, env, types) || expr_is_bytes(right, env, types));
            if bytes_add {
                compile_concat_operand(
                    left,
                    env,
                    params,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                compile_concat_operand(
                    right,
                    env,
                    params,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
            } else {
                compile_expr(left, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
                compile_expr(right, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            }
            match op {
                BinaryOp::Or => {
                    builder.add_op(OpBoolOr)?;
                }
                BinaryOp::And => {
                    builder.add_op(OpBoolAnd)?;
                }
                BinaryOp::BitOr => {
                    builder.add_op(OpOr)?;
                }
                BinaryOp::BitXor => {
                    builder.add_op(OpXor)?;
                }
                BinaryOp::BitAnd => {
                    builder.add_op(OpAnd)?;
                }
                BinaryOp::Eq => {
                    builder.add_op(if bytes_eq { OpEqual } else { OpNumEqual })?;
                }
                BinaryOp::Ne => {
                    if bytes_eq {
                        builder.add_op(OpEqual)?;
                        builder.add_op(OpNot)?;
                    } else {
                        builder.add_op(OpNumNotEqual)?;
                    }
                }
                BinaryOp::Lt => {
                    builder.add_op(OpLessThan)?;
                }
                BinaryOp::Le => {
                    builder.add_op(OpLessThanOrEqual)?;
                }
                BinaryOp::Gt => {
                    builder.add_op(OpGreaterThan)?;
                }
                BinaryOp::Ge => {
                    builder.add_op(OpGreaterThanOrEqual)?;
                }
                BinaryOp::Add => {
                    if bytes_add {
                        builder.add_op(OpCat)?;
                    } else {
                        builder.add_op(OpAdd)?;
                    }
                }
                BinaryOp::Sub => {
                    builder.add_op(OpSub)?;
                }
                BinaryOp::Mul => {
                    builder.add_op(OpMul)?;
                }
                BinaryOp::Div => {
                    builder.add_op(OpDiv)?;
                }
                BinaryOp::Mod => {
                    builder.add_op(OpMod)?;
                }
            }
            *stack_depth -= 1;
            Ok(())
        }
        ExprKind::Split { source, index, part, .. } => compile_split_part(
            source,
            index,
            *part,
            env,
            params,
            types,
            builder,
            options,
            visiting,
            stack_depth,
            script_size,
            contract_constants,
        ),
        ExprKind::UnarySuffix { source, kind, .. } => match kind {
            UnarySuffixKind::Length => compile_length_expr(
                source,
                env,
                params,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            ),
            UnarySuffixKind::Reverse => Err(CompilerError::Unsupported("reverse() is not supported".to_string())),
        },
        ExprKind::Slice { source, start, end, .. } => {
            compile_expr(source, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            compile_expr(start, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            compile_expr(end, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;

            builder.add_op(Op2Dup)?;
            *stack_depth += 2;
            builder.add_op(OpSwap)?;
            builder.add_op(OpSub)?;
            *stack_depth -= 1;
            builder.add_op(OpSwap)?;
            builder.add_op(OpDrop)?;
            *stack_depth -= 1;
            builder.add_op(OpSubstr)?;
            *stack_depth -= 2;
            Ok(())
        }
        ExprKind::ArrayIndex { source, index } => {
            let resolved_source = match source.as_ref() {
                Expr { kind: ExprKind::Identifier(_), .. } => source.as_ref().clone(),
                _ => resolve_expr(*source.clone(), env, visiting)?,
            };
            let element_type = match &resolved_source.kind {
                ExprKind::Identifier(name) => {
                    let type_name = types.get(name).or_else(|| {
                        env.get(name).and_then(|value| match &value.kind {
                            ExprKind::Identifier(inner) => types.get(inner),
                            _ => None,
                        })
                    });
                    type_name
                        .and_then(|t| array_element_type(t))
                        .ok_or_else(|| CompilerError::Unsupported(format!("array index requires array identifier: {name}")))?
                }
                _ => return Err(CompilerError::Unsupported("array index requires array identifier".to_string())),
            };
            let element_size = fixed_type_size(&element_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            compile_expr(
                &resolved_source,
                env,
                params,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_i64(element_size)?;
            *stack_depth += 1;
            builder.add_op(OpMul)?;
            *stack_depth -= 1;
            builder.add_op(OpDup)?;
            *stack_depth += 1;
            builder.add_i64(element_size)?;
            *stack_depth += 1;
            builder.add_op(OpAdd)?;
            *stack_depth -= 1;
            builder.add_op(OpSubstr)?;
            *stack_depth -= 2;
            if element_type == "int" {
                builder.add_op(OpBin2Num)?;
            }
            Ok(())
        }
        ExprKind::Nullary(op) => {
            match op {
                NullaryOp::ActiveInputIndex => {
                    builder.add_op(OpTxInputIndex)?;
                }
                NullaryOp::ActiveScriptPubKey => {
                    builder.add_op(OpTxInputIndex)?;
                    builder.add_op(OpTxInputSpk)?;
                }
                NullaryOp::ThisScriptSize => {
                    let size = script_size
                        .ok_or_else(|| CompilerError::Unsupported("this.scriptSize is only available at compile time".to_string()))?;
                    builder.add_i64(size)?;
                }
                NullaryOp::ThisScriptSizeDataPrefix => {
                    let size = script_size.ok_or_else(|| {
                        CompilerError::Unsupported("this.scriptSizeDataPrefix is only available at compile time".to_string())
                    })?;
                    let size: usize = size.try_into().map_err(|_| {
                        CompilerError::Unsupported("this.scriptSizeDataPrefix requires a non-negative script size".to_string())
                    })?;
                    let prefix = data_prefix(size);
                    builder.add_data(&prefix)?;
                }
                NullaryOp::TxInputsLength => {
                    builder.add_op(OpTxInputCount)?;
                }
                NullaryOp::TxOutputsLength => {
                    builder.add_op(OpTxOutputCount)?;
                }
                NullaryOp::TxVersion => {
                    builder.add_op(OpTxVersion)?;
                }
                NullaryOp::TxLockTime => {
                    builder.add_op(OpTxLockTime)?;
                }
            }
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::Introspection { kind, index, .. } => {
            compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            match kind {
                IntrospectionKind::InputValue => {
                    builder.add_op(OpTxInputAmount)?;
                }
                IntrospectionKind::InputScriptPubKey => {
                    builder.add_op(OpTxInputSpk)?;
                }
                IntrospectionKind::InputSigScript => {
                    builder.add_op(OpDup)?;
                    builder.add_op(OpTxInputScriptSigLen)?;
                    builder.add_i64(0)?;
                    builder.add_op(OpSwap)?;
                    builder.add_op(OpTxInputScriptSigSubstr)?;
                }
                IntrospectionKind::InputOutpointTransactionHash => {
                    builder.add_op(OpOutpointTxId)?;
                }
                IntrospectionKind::InputOutpointIndex => {
                    builder.add_op(OpOutpointIndex)?;
                }
                IntrospectionKind::InputSequenceNumber => {
                    builder.add_op(OpTxInputSeq)?;
                }
                IntrospectionKind::OutputValue => {
                    builder.add_op(OpTxOutputAmount)?;
                }
                IntrospectionKind::OutputScriptPubKey => {
                    builder.add_op(OpTxOutputSpk)?;
                }
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_split_part<'i>(
    source: &Expr<'i>,
    index: &Expr<'i>,
    part: SplitPart,
    env: &HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    compile_expr(source, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    match part {
        SplitPart::Left => {
            compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_i64(0)?;
            *stack_depth += 1;
            builder.add_op(OpSwap)?;
            builder.add_op(OpSubstr)?;
            *stack_depth -= 2;
            Ok(())
        }
        SplitPart::Right => {
            builder.add_op(OpSize)?;
            *stack_depth += 1;
            compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_op(OpSwap)?;
            builder.add_op(OpSubstr)?;
            *stack_depth -= 2;
            Ok(())
        }
    }
}

fn expr_is_bytes<'i>(expr: &Expr<'i>, env: &HashMap<String, Expr<'i>>, types: &HashMap<String, String>) -> bool {
    let mut visiting = HashSet::new();
    expr_is_bytes_inner(expr, env, types, &mut visiting)
}

fn expr_is_bytes_inner<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    types: &HashMap<String, String>,
    visiting: &mut HashSet<String>,
) -> bool {
    match &expr.kind {
        ExprKind::Bytes(_) => true,
        ExprKind::String(_) => true,
        ExprKind::Array(_) => true,
        ExprKind::Slice { .. } => true,
        ExprKind::New { name, .. } => matches!(
            name.as_str(),
            "LockingBytecodeNullData" | "ScriptPubKeyP2PK" | "ScriptPubKeyP2SH" | "ScriptPubKeyP2SHFromRedeemScript"
        ),
        ExprKind::Call { name, .. } => {
            let name = name.as_str();
            matches!(
                name,
                "bytes"
                    | "blake2b"
                    | "sha256"
                    | "OpSha256"
                    | "OpTxSubnetId"
                    | "OpTxPayloadSubstr"
                    | "OpOutpointTxId"
                    | "OpTxInputScriptSigSubstr"
                    | "OpTxInputSeq"
                    | "OpTxInputSpkSubstr"
                    | "OpTxOutputSpkSubstr"
                    | "OpInputCovenantId"
                    | "OpNum2Bin"
                    | "OpChainblockSeqCommit"
            ) || name.starts_with("byte[")
        }
        ExprKind::Split { .. } => true,
        ExprKind::Binary { op: BinaryOp::Add, left, right } => {
            expr_is_bytes_inner(left, env, types, visiting) || expr_is_bytes_inner(right, env, types, visiting)
        }
        ExprKind::IfElse { condition: _, then_expr, else_expr } => {
            expr_is_bytes_inner(then_expr, env, types, visiting) && expr_is_bytes_inner(else_expr, env, types, visiting)
        }
        ExprKind::Introspection { kind, .. } => matches!(
            kind,
            IntrospectionKind::InputScriptPubKey
                | IntrospectionKind::InputSigScript
                | IntrospectionKind::InputOutpointTransactionHash
                | IntrospectionKind::OutputScriptPubKey
        ),
        ExprKind::Nullary(NullaryOp::ActiveScriptPubKey) => true,
        ExprKind::Nullary(NullaryOp::ThisScriptSizeDataPrefix) => true,
        ExprKind::ArrayIndex { source, .. } => match &source.kind {
            ExprKind::Identifier(name) => {
                types.get(name).and_then(|type_name| array_element_type(type_name)).map(|element| element != "int").unwrap_or(false)
            }
            _ => false,
        },
        ExprKind::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return false;
            }
            if let Some(expr) = env.get(name) {
                let result = expr_is_bytes_inner(expr, env, types, visiting)
                    || types.get(name).map(|type_name| is_bytes_type(type_name)).unwrap_or(false);
                visiting.remove(name);
                return result;
            }
            visiting.remove(name);
            types.get(name).map(|type_name| is_bytes_type(type_name)).unwrap_or(false)
        }
        ExprKind::UnarySuffix { kind, .. } => matches!(kind, UnarySuffixKind::Reverse),
        _ => false,
    }
}

fn compile_length_expr<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if let ExprKind::Identifier(name) = &expr.kind {
        if let Some(type_name) = types.get(name) {
            if let Some(size) = array_size_with_constants(type_name, contract_constants) {
                builder.add_i64(size as i64)?;
                *stack_depth += 1;
                return Ok(());
            }
            if let Some(element_size) = array_element_size(type_name) {
                compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
                builder.add_op(OpSize)?;
                builder.add_op(OpSwap)?;
                builder.add_op(OpDrop)?;
                builder.add_i64(element_size)?;
                *stack_depth += 1;
                builder.add_op(OpDiv)?;
                *stack_depth -= 1;
                return Ok(());
            }
        }
    }
    if let ExprKind::Array(values) = &expr.kind {
        builder.add_i64(values.len() as i64)?;
        *stack_depth += 1;
        return Ok(());
    }
    compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    builder.add_op(OpSize)?;
    Ok(())
}

fn compile_call_expr<'i>(
    name: &str,
    args: &[Expr<'i>],
    scope: &CompilationScope<'_, 'i>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    match name {
        "OpSha256" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpSHA256,
            script_size,
            contract_constants,
        ),
        "sha256" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("sha256() expects a single argument".to_string()));
            }
            compile_expr(
                &args[0],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpSHA256)?;
            Ok(())
        }
        "OpTxSubnetId" => compile_opcode_call(
            name,
            args,
            0,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxSubnetId,
            script_size,
            contract_constants,
        ),
        "OpTxGas" => compile_opcode_call(
            name,
            args,
            0,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxGas,
            script_size,
            contract_constants,
        ),
        "OpTxPayloadLen" => compile_opcode_call(
            name,
            args,
            0,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxPayloadLen,
            script_size,
            contract_constants,
        ),
        "OpTxPayloadSubstr" => compile_opcode_call(
            name,
            args,
            2,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxPayloadSubstr,
            script_size,
            contract_constants,
        ),
        "OpOutpointTxId" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpOutpointTxId,
            script_size,
            contract_constants,
        ),
        "OpOutpointIndex" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpOutpointIndex,
            script_size,
            contract_constants,
        ),
        "OpTxInputScriptSigLen" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputScriptSigLen,
            script_size,
            contract_constants,
        ),
        "OpTxInputScriptSigSubstr" => compile_opcode_call(
            name,
            args,
            3,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputScriptSigSubstr,
            script_size,
            contract_constants,
        ),
        "OpTxInputSeq" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputSeq,
            script_size,
            contract_constants,
        ),
        "OpTxInputIsCoinbase" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputIsCoinbase,
            script_size,
            contract_constants,
        ),
        "OpTxInputSpkLen" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputSpkLen,
            script_size,
            contract_constants,
        ),
        "OpTxInputSpkSubstr" => compile_opcode_call(
            name,
            args,
            3,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputSpkSubstr,
            script_size,
            contract_constants,
        ),
        "OpTxOutputSpkLen" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxOutputSpkLen,
            script_size,
            contract_constants,
        ),
        "OpTxOutputSpkSubstr" => compile_opcode_call(
            name,
            args,
            3,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxOutputSpkSubstr,
            script_size,
            contract_constants,
        ),
        "OpAuthOutputCount" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpAuthOutputCount,
            script_size,
            contract_constants,
        ),
        "OpAuthOutputIdx" => compile_opcode_call(
            name,
            args,
            2,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpAuthOutputIdx,
            script_size,
            contract_constants,
        ),
        "OpInputCovenantId" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpInputCovenantId,
            script_size,
            contract_constants,
        ),
        "OpCovInputCount" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpCovInputCount,
            script_size,
            contract_constants,
        ),
        "OpCovInputIdx" => compile_opcode_call(
            name,
            args,
            2,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpCovInputIdx,
            script_size,
            contract_constants,
        ),
        "OpCovOutCount" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpCovOutCount,
            script_size,
            contract_constants,
        ),
        "OpCovOutputIdx" => compile_opcode_call(
            name,
            args,
            2,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpCovOutputIdx,
            script_size,
            contract_constants,
        ),
        "OpNum2Bin" => compile_opcode_call(
            name,
            args,
            2,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpNum2Bin,
            script_size,
            contract_constants,
        ),
        "OpBin2Num" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpBin2Num,
            script_size,
            contract_constants,
        ),
        "OpChainblockSeqCommit" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpChainblockSeqCommit,
            script_size,
            contract_constants,
        ),
        "bytes" => {
            if args.is_empty() || args.len() > 2 {
                return Err(CompilerError::Unsupported("bytes() expects one or two arguments".to_string()));
            }
            if args.len() == 2 {
                compile_expr(
                    &args[0],
                    scope.env,
                    scope.params,
                    scope.types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                compile_expr(
                    &args[1],
                    scope.env,
                    scope.params,
                    scope.types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                builder.add_op(OpNum2Bin)?;
                *stack_depth -= 1;
                return Ok(());
            }
            match &args[0].kind {
                ExprKind::String(value) => {
                    builder.add_data(value.as_bytes())?;
                    *stack_depth += 1;
                    Ok(())
                }
                ExprKind::Identifier(name) => {
                    if let Some(expr) = scope.env.get(name) {
                        if let ExprKind::String(value) = &expr.kind {
                            builder.add_data(value.as_bytes())?;
                            *stack_depth += 1;
                            return Ok(());
                        }
                    }
                    if expr_is_bytes(&args[0], scope.env, scope.types) {
                        compile_expr(
                            &args[0],
                            scope.env,
                            scope.params,
                            scope.types,
                            builder,
                            options,
                            visiting,
                            stack_depth,
                            script_size,
                            contract_constants,
                        )?;
                        return Ok(());
                    }
                    compile_expr(
                        &args[0],
                        scope.env,
                        scope.params,
                        scope.types,
                        builder,
                        options,
                        visiting,
                        stack_depth,
                        script_size,
                        contract_constants,
                    )?;
                    builder.add_i64(8)?;
                    *stack_depth += 1;
                    builder.add_op(OpNum2Bin)?;
                    *stack_depth -= 1;
                    Ok(())
                }
                _ => {
                    if expr_is_bytes(&args[0], scope.env, scope.types) {
                        compile_expr(
                            &args[0],
                            scope.env,
                            scope.params,
                            scope.types,
                            builder,
                            options,
                            visiting,
                            stack_depth,
                            script_size,
                            contract_constants,
                        )?;
                        Ok(())
                    } else {
                        compile_expr(
                            &args[0],
                            scope.env,
                            scope.params,
                            scope.types,
                            builder,
                            options,
                            visiting,
                            stack_depth,
                            script_size,
                            contract_constants,
                        )?;
                        builder.add_i64(8)?;
                        *stack_depth += 1;
                        builder.add_op(OpNum2Bin)?;
                        *stack_depth -= 1;
                        Ok(())
                    }
                }
            }
        }
        "length" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("length() expects a single argument".to_string()));
            }
            compile_length_expr(
                &args[0],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )
        }
        "int" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("int() expects a single argument".to_string()));
            }
            compile_expr(
                &args[0],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            Ok(())
        }
        "sig" | "pubkey" | "datasig" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
            }
            compile_expr(
                &args[0],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            Ok(())
        }
        name if name.starts_with("byte[") && name.ends_with(']') => {
            let size_part = &name[5..name.len() - 1];
            if size_part.is_empty() {
                // Handle byte[] cast (dynamic array) - just compile the argument as-is
                if args.len() != 1 && args.len() != 2 {
                    return Err(CompilerError::Unsupported(format!("{name}() expects 1 or 2 arguments")));
                }
                compile_expr(
                    &args[0],
                    scope.env,
                    scope.params,
                    scope.types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                if args.len() == 2 {
                    // byte[](value, size) - OpNum2Bin with size parameter
                    compile_expr(
                        &args[1],
                        scope.env,
                        scope.params,
                        scope.types,
                        builder,
                        options,
                        visiting,
                        stack_depth,
                        script_size,
                        contract_constants,
                    )?;
                    *stack_depth += 1;
                    builder.add_op(OpNum2Bin)?;
                    *stack_depth -= 1;
                }
                Ok(())
            } else {
                // Handle byte[N] cast - extract size from byte[N]
                let size = size_part.parse::<i64>().map_err(|_| CompilerError::Unsupported(format!("{name}() is not supported")))?;
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
                }
                compile_expr(
                    &args[0],
                    scope.env,
                    scope.params,
                    scope.types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                builder.add_i64(size)?;
                *stack_depth += 1;
                builder.add_op(OpNum2Bin)?;
                *stack_depth -= 1;
                Ok(())
            }
        }
        "blake2b" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("blake2b() expects a single argument".to_string()));
            }
            compile_expr(
                &args[0],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpBlake2b)?;
            Ok(())
        }
        "checkSig" => {
            if args.len() != 2 {
                return Err(CompilerError::Unsupported("checkSig() expects 2 arguments".to_string()));
            }
            compile_expr(
                &args[0],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            compile_expr(
                &args[1],
                scope.env,
                scope.params,
                scope.types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpCheckSig)?;
            *stack_depth -= 1;
            Ok(())
        }
        "checkDataSig" => {
            // TODO: Remove this stub
            for arg in args {
                compile_expr(
                    arg,
                    scope.env,
                    scope.params,
                    scope.types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
            }
            for _ in 0..args.len() {
                builder.add_op(OpDrop)?;
                *stack_depth -= 1;
            }
            builder.add_op(OpTrue)?;
            *stack_depth += 1;
            Ok(())
        }
        _ => Err(CompilerError::Unsupported(format!("unknown function call: {name}"))),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_opcode_call<'i>(
    name: &str,
    args: &[Expr<'i>],
    expected_args: usize,
    scope: &CompilationScope<'_, 'i>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    opcode: u8,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if args.len() != expected_args {
        return Err(CompilerError::Unsupported(format!("{name}() expects {expected_args} argument(s)")));
    }
    for arg in args {
        compile_expr(
            arg,
            scope.env,
            scope.params,
            scope.types,
            builder,
            options,
            visiting,
            stack_depth,
            script_size,
            contract_constants,
        )?;
    }
    builder.add_op(opcode)?;
    *stack_depth += 1 - expected_args as i64;
    Ok(())
}

fn compile_concat_operand<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    if !expr_is_bytes(expr, env, types) {
        builder.add_i64(1)?;
        *stack_depth += 1;
        builder.add_op(OpNum2Bin)?;
        *stack_depth -= 1;
    }
    Ok(())
}

fn is_bytes_type(type_name: &str) -> bool {
    if type_name == "bytes" || type_name == "byte" || matches!(type_name, "pubkey" | "sig" | "string") {
        return true;
    }
    // Check for byte[N] arrays
    if let Some(elem_type) = array_element_type(type_name) {
        if elem_type == "byte" || elem_type == "bytes" {
            return true;
        }
    }
    is_array_type(type_name)
}

fn build_null_data_script<'i>(arg: &Expr<'i>) -> Result<Vec<u8>, CompilerError> {
    let elements = match &arg.kind {
        ExprKind::Array(items) => items,
        _ => return Err(CompilerError::Unsupported("LockingBytecodeNullData expects an array literal".to_string())),
    };

    let mut builder = ScriptBuilder::new();
    builder.add_op(OpReturn)?;
    for item in elements {
        match &item.kind {
            ExprKind::Int(value) => {
                builder.add_i64(*value)?;
            }
            ExprKind::DateLiteral(value) => {
                builder.add_i64(*value)?;
            }
            ExprKind::Bytes(bytes) => {
                builder.add_data(bytes)?;
            }
            ExprKind::String(value) => {
                builder.add_data(value.as_bytes())?;
            }
            ExprKind::Call { name, args, .. } if name == "bytes" || name == "byte[]" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(
                        "byte[]() in LockingBytecodeNullData expects a single argument".to_string(),
                    ));
                }
                match &args[0].kind {
                    ExprKind::String(value) => {
                        builder.add_data(value.as_bytes())?;
                    }
                    _ => {
                        return Err(CompilerError::Unsupported(
                            "byte[]() in LockingBytecodeNullData only supports string literals".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(CompilerError::Unsupported("LockingBytecodeNullData only supports int or bytes literals".to_string()));
            }
        }
    }

    let script = builder.drain();
    let mut spk_bytes = Vec::with_capacity(2 + script.len());
    spk_bytes.extend_from_slice(&0u16.to_be_bytes());
    spk_bytes.extend_from_slice(&script);
    Ok(spk_bytes)
}

fn data_prefix(data_len: usize) -> Vec<u8> {
    let dummy_data = vec![0u8; data_len];
    let mut builder = ScriptBuilder::new();
    builder.add_data(&dummy_data).unwrap();
    let script = builder.drain();
    script[..script.len() - data_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::{Op0, OpPushData1, OpPushData2, data_prefix};

    #[test]
    fn data_prefix_encodes_small_pushes() {
        assert_eq!(data_prefix(0), vec![Op0]);
        // For a single 0x00 byte, ScriptBuilder uses Op0, so the prefix is empty.
        assert_eq!(data_prefix(1), Vec::<u8>::new());
        assert_eq!(data_prefix(2), vec![2u8]);
        assert_eq!(data_prefix(75), vec![75u8]);
    }

    #[test]
    fn data_prefix_encodes_pushdata1() {
        assert_eq!(data_prefix(76), vec![OpPushData1, 76u8]);
        assert_eq!(data_prefix(255), vec![OpPushData1, 255u8]);
    }

    #[test]
    fn data_prefix_encodes_pushdata2() {
        assert_eq!(data_prefix(256), vec![OpPushData2, 0x00, 0x01]);
    }
}
