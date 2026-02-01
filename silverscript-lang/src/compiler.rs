use std::collections::{HashMap, HashSet};

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::{ScriptBuilder, ScriptBuilderError};
use thiserror::Error;

use crate::ast::{
    BinaryOp, ContractAst, Expr, FunctionAst, IntrospectionKind, NullaryOp, SplitPart, Statement, TimeVar, UnaryOp, parse_contract_ast,
};
use crate::parser::Rule;
use chrono::NaiveDateTime;

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("parse error: {0}")]
    Parse(#[from] pest::error::Error<Rule>),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
    #[error("invalid literal: {0}")]
    InvalidLiteral(String),
    #[error("undefined identifier: {0}")]
    UndefinedIdentifier(String),
    #[error("cyclic identifier reference: {0}")]
    CyclicIdentifier(String),
    #[error("script build error: {0}")]
    ScriptBuild(#[from] ScriptBuilderError),
}

#[derive(Debug, Clone, Copy)]
pub struct CompileOptions {
    pub covenants_enabled: bool,
    pub without_selector: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self { covenants_enabled: true, without_selector: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInputAbi {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionAbiEntry {
    pub name: String,
    pub inputs: Vec<FunctionInputAbi>,
}

pub type FunctionAbi = Vec<FunctionAbiEntry>;

#[derive(Debug)]
pub struct CompiledContract {
    pub contract_name: String,
    pub script: Vec<u8>,
    pub ast: ContractAst,
    pub abi: FunctionAbi,
    pub without_selector: bool,
}

pub fn compile_contract(source: &str, constructor_args: &[Expr], options: CompileOptions) -> Result<CompiledContract, CompilerError> {
    let contract = parse_contract_ast(source)?;
    compile_contract_ast(&contract, constructor_args, options)
}

pub fn compile_contract_ast(
    contract: &ContractAst,
    constructor_args: &[Expr],
    options: CompileOptions,
) -> Result<CompiledContract, CompilerError> {
    if contract.functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no functions".to_string()));
    }

    if contract.params.len() != constructor_args.len() {
        return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
    }

    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        if !expr_matches_type(value, &param.type_name) {
            return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, param.type_name)));
        }
    }

    if options.without_selector && contract.functions.len() != 1 {
        return Err(CompilerError::Unsupported("without_selector requires a single function".to_string()));
    }

    let mut constants = contract.constants.clone();
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
        let mut compiled_functions = Vec::new();
        for (index, func) in contract.functions.iter().enumerate() {
            compiled_functions.push(compile_function(func, index, &constants, options, &functions_map, &function_order, script_size)?);
        }

        let script = if options.without_selector {
            compiled_functions.first().ok_or_else(|| CompilerError::Unsupported("contract has no functions".to_string()))?.1.clone()
        } else {
            let mut builder = ScriptBuilder::new();
            let total = compiled_functions.len();
            for (index, (_, script)) in compiled_functions.iter().enumerate() {
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

        if !uses_script_size {
            return Ok(CompiledContract {
                contract_name: contract.name.clone(),
                script,
                ast: contract.clone(),
                abi,
                without_selector: options.without_selector,
            });
        }

        let actual_size = script.len() as i64;
        if Some(actual_size) == script_size {
            return Ok(CompiledContract {
                contract_name: contract.name.clone(),
                script,
                ast: contract.clone(),
                abi,
                without_selector: options.without_selector,
            });
        }
        script_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("script size did not stabilize".to_string()))
}

fn contract_uses_script_size(contract: &ContractAst) -> bool {
    if contract.constants.values().any(expr_uses_script_size) {
        return true;
    }
    contract.functions.iter().any(|func| func.body.iter().any(statement_uses_script_size))
}

fn statement_uses_script_size(stmt: &Statement) -> bool {
    match stmt {
        Statement::VariableDefinition { expr, .. } => expr.as_ref().is_some_and(expr_uses_script_size),
        Statement::TupleAssignment { expr, .. } => expr_uses_script_size(expr),
        Statement::ArrayPush { expr, .. } => expr_uses_script_size(expr),
        Statement::FunctionCall { args, .. } => args.iter().any(expr_uses_script_size),
        Statement::FunctionCallAssign { args, .. } => args.iter().any(expr_uses_script_size),
        Statement::Assign { expr, .. } => expr_uses_script_size(expr),
        Statement::TimeOp { expr, .. } => expr_uses_script_size(expr),
        Statement::Require { expr, .. } => expr_uses_script_size(expr),
        Statement::If { condition, then_branch, else_branch } => {
            expr_uses_script_size(condition)
                || then_branch.iter().any(statement_uses_script_size)
                || else_branch.as_ref().is_some_and(|branch| branch.iter().any(statement_uses_script_size))
        }
        Statement::For { start, end, body, .. } => {
            expr_uses_script_size(start) || expr_uses_script_size(end) || body.iter().any(statement_uses_script_size)
        }
        Statement::Yield { expr } => expr_uses_script_size(expr),
        Statement::Return { exprs } => exprs.iter().any(expr_uses_script_size),
        Statement::Console { args } => args.iter().any(|arg| match arg {
            crate::ast::ConsoleArg::Identifier(_) => false,
            crate::ast::ConsoleArg::Literal(expr) => expr_uses_script_size(expr),
        }),
    }
}

fn expr_uses_script_size(expr: &Expr) -> bool {
    match expr {
        Expr::Nullary(NullaryOp::ThisScriptSize) => true,
        Expr::Nullary(NullaryOp::ThisScriptSizeDataPrefix) => true,
        Expr::Unary { expr, .. } => expr_uses_script_size(expr),
        Expr::Binary { left, right, .. } => expr_uses_script_size(left) || expr_uses_script_size(right),
        Expr::IfElse { condition, then_expr, else_expr } => {
            expr_uses_script_size(condition) || expr_uses_script_size(then_expr) || expr_uses_script_size(else_expr)
        }
        Expr::Array(values) => values.iter().any(expr_uses_script_size),
        Expr::Call { args, .. } => args.iter().any(expr_uses_script_size),
        Expr::New { args, .. } => args.iter().any(expr_uses_script_size),
        Expr::Split { source, index, .. } => expr_uses_script_size(source) || expr_uses_script_size(index),
        Expr::Slice { source, start, end } => {
            expr_uses_script_size(source) || expr_uses_script_size(start) || expr_uses_script_size(end)
        }
        Expr::ArrayIndex { source, index } => expr_uses_script_size(source) || expr_uses_script_size(index),
        Expr::Introspection { index, .. } => expr_uses_script_size(index),
        Expr::Int(_) | Expr::Bool(_) | Expr::Bytes(_) | Expr::String(_) | Expr::Identifier(_) => false,
        Expr::Nullary(_) => false,
    }
}

fn expr_matches_type(expr: &Expr, type_name: &str) -> bool {
    if is_array_type(type_name) {
        return matches!(expr, Expr::Bytes(_)) || matches!(expr, Expr::Array(values) if array_literal_matches_type(values, type_name));
    }
    match type_name {
        "int" => matches!(expr, Expr::Int(_)),
        "bool" => matches!(expr, Expr::Bool(_)),
        "string" => matches!(expr, Expr::String(_)),
        "bytes" => matches!(expr, Expr::Bytes(_)),
        "byte" => matches!(expr, Expr::Bytes(bytes) if bytes.len() == 1),
        "pubkey" => matches!(expr, Expr::Bytes(bytes) if bytes.len() == 32),
        "sig" | "datasig" => matches!(expr, Expr::Bytes(bytes) if bytes.len() == 64 || bytes.len() == 65),
        _ => {
            if let Some(size) = type_name.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
                matches!(expr, Expr::Bytes(bytes) if bytes.len() == size)
            } else {
                false
            }
        }
    }
}

fn array_literal_matches_type(values: &[Expr], type_name: &str) -> bool {
    let Some(element_type) = array_element_type(type_name) else {
        return false;
    };
    match element_type {
        "int" => values.iter().all(|value| matches!(value, Expr::Int(_))),
        "byte" => values.iter().all(|value| matches!(value, Expr::Bytes(bytes) if bytes.len() == 1)),
        _ => {
            if let Some(size) = element_type.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
                values.iter().all(|value| matches!(value, Expr::Bytes(bytes) if bytes.len() == size))
            } else {
                false
            }
        }
    }
}

fn build_function_abi(contract: &ContractAst) -> FunctionAbi {
    contract
        .functions
        .iter()
        .map(|func| FunctionAbiEntry {
            name: func.name.clone(),
            inputs: func
                .params
                .iter()
                .map(|param| FunctionInputAbi { name: param.name.clone(), type_name: param.type_name.clone() })
                .collect(),
        })
        .collect()
}

fn is_array_type(type_name: &str) -> bool {
    type_name.ends_with("[]")
}

fn array_element_type(type_name: &str) -> Option<&str> {
    type_name.strip_suffix("[]")
}

fn fixed_type_size(type_name: &str) -> Option<i64> {
    match type_name {
        "int" => Some(8),
        "byte" => Some(1),
        _ => type_name.strip_prefix("bytes").and_then(|v| v.parse::<i64>().ok()),
    }
}

fn array_element_size(type_name: &str) -> Option<i64> {
    array_element_type(type_name).and_then(fixed_type_size)
}

fn contains_return(stmt: &Statement) -> bool {
    match stmt {
        Statement::Return { .. } => true,
        Statement::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(contains_return) || else_branch.as_ref().is_some_and(|branch| branch.iter().any(contains_return))
        }
        Statement::For { body, .. } => body.iter().any(contains_return),
        _ => false,
    }
}

fn contains_yield(stmt: &Statement) -> bool {
    match stmt {
        Statement::Yield { .. } => true,
        Statement::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(contains_yield) || else_branch.as_ref().is_some_and(|branch| branch.iter().any(contains_yield))
        }
        Statement::For { body, .. } => body.iter().any(contains_yield),
        _ => false,
    }
}

fn validate_return_types(exprs: &[Expr], return_types: &[String], types: &HashMap<String, String>) -> Result<(), CompilerError> {
    if return_types.is_empty() {
        return Err(CompilerError::Unsupported("return requires function return types".to_string()));
    }
    if return_types.len() != exprs.len() {
        return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
    }
    for (expr, type_name) in exprs.iter().zip(return_types.iter()) {
        if !expr_matches_return_type(expr, type_name, types) {
            return Err(CompilerError::Unsupported(format!("return value expects {type_name}")));
        }
    }
    Ok(())
}

fn expr_matches_type_with_env(expr: &Expr, type_name: &str, types: &HashMap<String, String>) -> bool {
    match expr {
        Expr::Identifier(name) => types.get(name).is_some_and(|t| t == type_name),
        Expr::Array(values) => is_array_type(type_name) && array_literal_matches_type(values, type_name),
        _ => expr_matches_type(expr, type_name),
    }
}

fn expr_matches_return_type(expr: &Expr, type_name: &str, types: &HashMap<String, String>) -> bool {
    match expr {
        Expr::Identifier(name) => types.get(name).is_some_and(|t| t == type_name),
        Expr::Array(values) => is_array_type(type_name) && array_literal_matches_type(values, type_name),
        Expr::Int(_) | Expr::Bool(_) | Expr::Bytes(_) | Expr::String(_) => expr_matches_type(expr, type_name),
        _ => true,
    }
}

impl CompiledContract {
    pub fn build_sig_script(&self, function_name: &str, args: Vec<Expr>) -> Result<Vec<u8>, CompilerError> {
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
                match arg {
                    Expr::Array(values) => {
                        let bytes = encode_array_literal(&values, &input.type_name)?;
                        builder.add_data(&bytes)?;
                    }
                    Expr::Bytes(value) => {
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

fn push_sigscript_arg(builder: &mut ScriptBuilder, arg: Expr) -> Result<(), CompilerError> {
    match arg {
        Expr::Int(value) => {
            builder.add_i64(value)?;
        }
        Expr::Bool(value) => {
            builder.add_i64(if value { 1 } else { 0 })?;
        }
        Expr::String(value) => {
            builder.add_data(value.as_bytes())?;
        }
        Expr::Bytes(value) => {
            builder.add_data(&value)?;
        }
        _ => {
            return Err(CompilerError::Unsupported("signature script arguments must be literals".to_string()));
        }
    }
    Ok(())
}

fn encode_array_literal(values: &[Expr], type_name: &str) -> Result<Vec<u8>, CompilerError> {
    let element_type = array_element_type(type_name)
        .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
    let mut out = Vec::new();
    match element_type {
        "int" => {
            for value in values {
                let Expr::Int(number) = value else {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                };
                out.extend(number.to_le_bytes());
            }
        }
        "byte" => {
            for value in values {
                let Expr::Bytes(bytes) = value else {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                };
                if bytes.len() != 1 {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                }
                out.extend(bytes);
            }
        }
        _ => {
            let size = element_type
                .strip_prefix("bytes")
                .and_then(|v| v.parse::<usize>().ok())
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            for value in values {
                let Expr::Bytes(bytes) = value else {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                };
                if bytes.len() != size {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                }
                out.extend(bytes);
            }
        }
    }
    Ok(out)
}

pub fn function_branch_index(contract: &ContractAst, function_name: &str) -> Result<i64, CompilerError> {
    contract
        .functions
        .iter()
        .position(|func| func.name == function_name)
        .map(|index| index as i64)
        .ok_or_else(|| CompilerError::Unsupported(format!("function '{function_name}' not found")))
}

fn compile_function(
    function: &FunctionAst,
    function_index: usize,
    constants: &HashMap<String, Expr>,
    options: CompileOptions,
    functions: &HashMap<String, FunctionAst>,
    function_order: &HashMap<String, usize>,
    script_size: Option<i64>,
) -> Result<(String, Vec<u8>), CompilerError> {
    let param_count = function.params.len();
    let params = function
        .params
        .iter()
        .map(|param| param.name.clone())
        .enumerate()
        .map(|(index, name)| (name, (param_count - 1 - index) as i64))
        .collect::<HashMap<_, _>>();
    let mut types = function.params.iter().map(|param| (param.name.clone(), param.type_name.clone())).collect::<HashMap<_, _>>();
    for param in &function.params {
        if is_array_type(&param.type_name) && array_element_size(&param.type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param.type_name)));
        }
    }
    for return_type in &function.return_types {
        if is_array_type(return_type) && array_element_size(return_type).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {return_type}")));
        }
    }
    let mut env: HashMap<String, Expr> = constants.clone();
    let mut builder = ScriptBuilder::new();
    let mut yields: Vec<Expr> = Vec::new();

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
            let Statement::Return { exprs } = stmt else { unreachable!() };
            validate_return_types(exprs, &function.return_types, &types)?;
            for expr in exprs {
                let resolved = resolve_expr(expr.clone(), &env, &mut HashSet::new())?;
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
            constants,
            functions,
            function_order,
            function_index,
            &mut yields,
            script_size,
        )?;
    }

    let yield_count = yields.len();
    if yield_count == 0 {
        for _ in 0..param_count {
            builder.add_op(OpDrop)?;
        }
        builder.add_op(OpTrue)?;
    } else {
        let mut stack_depth = 0i64;
        for expr in &yields {
            compile_expr(expr, &env, &params, &types, &mut builder, options, &mut HashSet::new(), &mut stack_depth, script_size)?;
        }
        for _ in 0..param_count {
            builder.add_i64(yield_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
    }
    Ok((function.name.clone(), builder.drain()))
}

#[allow(clippy::too_many_arguments)]
fn compile_statement(
    stmt: &Statement,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    functions: &HashMap<String, FunctionAst>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr>,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    match stmt {
        Statement::VariableDefinition { type_name, name, expr, .. } => {
            if is_array_type(type_name) {
                if array_element_size(type_name).is_none() {
                    return Err(CompilerError::Unsupported(format!("array element type must have known size: {type_name}")));
                }
                let initial = match expr {
                    Some(Expr::Identifier(other)) => match types.get(other) {
                        Some(other_type) if other_type == type_name => Expr::Identifier(other.clone()),
                        Some(_) => {
                            return Err(CompilerError::Unsupported("array assignment requires compatible array types".to_string()));
                        }
                        None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                    },
                    Some(_) => return Err(CompilerError::Unsupported("array initializer must be another array".to_string())),
                    None => Expr::Bytes(Vec::new()),
                };
                env.insert(name.clone(), initial);
                types.insert(name.clone(), type_name.clone());
                Ok(())
            } else {
                let expr =
                    expr.clone().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
                env.insert(name.clone(), expr);
                types.insert(name.clone(), type_name.clone());
                Ok(())
            }
        }
        Statement::ArrayPush { name, expr } => {
            let array_type = types.get(name).ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?;
            if !is_array_type(array_type) {
                return Err(CompilerError::Unsupported("push() only supported on arrays".to_string()));
            }
            let element_type = array_element_type(array_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            let element_size = array_element_size(array_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            let element_expr = if element_type == "int" {
                Expr::Call { name: "bytes8".to_string(), args: vec![expr.clone()] }
            } else if element_type == "byte" {
                Expr::Call { name: "bytes1".to_string(), args: vec![expr.clone()] }
            } else if element_type.starts_with("bytes") {
                if expr_is_bytes(expr, env, types) {
                    expr.clone()
                } else {
                    Expr::Call { name: format!("bytes{element_size}"), args: vec![expr.clone()] }
                }
            } else {
                return Err(CompilerError::Unsupported("array element type not supported".to_string()));
            };

            let current = env.get(name).cloned().unwrap_or_else(|| Expr::Bytes(Vec::new()));
            let updated = Expr::Binary { op: BinaryOp::Add, left: Box::new(current), right: Box::new(element_expr) };
            env.insert(name.clone(), updated);
            Ok(())
        }
        Statement::Require { expr, .. } => {
            let mut stack_depth = 0i64;
            compile_expr(expr, env, params, types, builder, options, &mut HashSet::new(), &mut stack_depth, script_size)?;
            builder.add_op(OpVerify)?;
            Ok(())
        }
        Statement::TimeOp { tx_var, expr, .. } => {
            compile_time_op_statement(tx_var, expr, env, params, types, builder, options, script_size)
        }
        Statement::If { condition, then_branch, else_branch } => compile_if_statement(
            condition,
            then_branch,
            else_branch.as_deref(),
            env,
            params,
            types,
            builder,
            options,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        ),
        Statement::For { ident, start, end, body } => compile_for_statement(
            ident,
            start,
            end,
            body,
            env,
            params,
            types,
            builder,
            options,
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        ),
        Statement::Yield { expr } => {
            let mut visiting = HashSet::new();
            let resolved = resolve_expr(expr.clone(), env, &mut visiting)?;
            yields.push(resolved);
            Ok(())
        }
        Statement::Return { .. } => Err(CompilerError::Unsupported("return statement must be the last statement".to_string())),
        Statement::TupleAssignment { left_name, right_name, expr, .. } => match expr.clone() {
            Expr::Split { source, index, .. } => {
                env.insert(left_name.clone(), Expr::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left });
                env.insert(right_name.clone(), Expr::Split { source, index, part: SplitPart::Right });
                Ok(())
            }
            _ => Err(CompilerError::Unsupported("tuple assignment only supports split()".to_string())),
        },
        Statement::FunctionCall { name, args } => {
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
                    compile_expr(&expr, env, params, types, builder, options, &mut HashSet::new(), &mut stack_depth, script_size)?;
                    builder.add_op(OpDrop)?;
                    stack_depth -= 1;
                }
            }
            Ok(())
        }
        Statement::FunctionCallAssign { bindings, name, args } => {
            let function = functions.get(name).ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
            if function.return_types.is_empty() {
                return Err(CompilerError::Unsupported("function has no return types".to_string()));
            }
            if function.return_types.len() != bindings.len() {
                return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
            }
            for (binding, return_type) in bindings.iter().zip(function.return_types.iter()) {
                if binding.type_name != *return_type {
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
                types.insert(binding.name.clone(), binding.type_name.clone());
            }
            Ok(())
        }
        Statement::Assign { name, expr } => {
            if let Some(type_name) = types.get(name) {
                if is_array_type(type_name) {
                    match expr {
                        Expr::Identifier(other) => match types.get(other) {
                            Some(other_type) if other_type == type_name => {
                                env.insert(name.clone(), Expr::Identifier(other.clone()));
                                return Ok(());
                            }
                            Some(_) => {
                                return Err(CompilerError::Unsupported(
                                    "array assignment requires compatible array types".to_string(),
                                ));
                            }
                            None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                        },
                        _ => return Err(CompilerError::Unsupported("array assignment only supports array identifiers".to_string())),
                    }
                }
            }
            let updated = if let Some(previous) = env.get(name) { replace_identifier(expr, name, previous) } else { expr.clone() };
            let resolved = resolve_expr(updated, env, &mut HashSet::new())?;
            env.insert(name.clone(), resolved);
            Ok(())
        }
        Statement::Console { .. } => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_inline_call(
    name: &str,
    args: &[Expr],
    caller_types: &mut HashMap<String, String>,
    caller_env: &mut HashMap<String, Expr>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    functions: &HashMap<String, FunctionAst>,
    function_order: &HashMap<String, usize>,
    caller_index: usize,
    script_size: Option<i64>,
) -> Result<Vec<Expr>, CompilerError> {
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
        if !expr_matches_type_with_env(arg, &param.type_name, caller_types) {
            return Err(CompilerError::Unsupported(format!("function argument '{}' expects {}", param.name, param.type_name)));
        }
    }

    let mut types = function.params.iter().map(|param| (param.name.clone(), param.type_name.clone())).collect::<HashMap<_, _>>();
    for param in &function.params {
        if is_array_type(&param.type_name) && array_element_size(&param.type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param.type_name)));
        }
    }

    let mut env: HashMap<String, Expr> = contract_constants.clone();
    for (index, (param, arg)) in function.params.iter().zip(args.iter()).enumerate() {
        let resolved = resolve_expr(arg.clone(), caller_env, &mut HashSet::new())?;
        let temp_name = format!("__arg_{name}_{index}");
        env.insert(temp_name.clone(), resolved.clone());
        types.insert(temp_name.clone(), param.type_name.clone());
        env.insert(param.name.clone(), Expr::Identifier(temp_name.clone()));
        caller_env.insert(temp_name.clone(), resolved);
        caller_types.insert(temp_name, param.type_name.clone());
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

    let mut yields: Vec<Expr> = Vec::new();
    let params = HashMap::new();
    let body_len = function.body.len();
    for (index, stmt) in function.body.iter().enumerate() {
        if matches!(stmt, Statement::Return { .. }) {
            if index != body_len - 1 {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            let Statement::Return { exprs } = stmt else { unreachable!() };
            validate_return_types(exprs, &function.return_types, &types)?;
            for expr in exprs {
                let resolved = resolve_expr(expr.clone(), &env, &mut HashSet::new())?;
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
            contract_constants,
            functions,
            function_order,
            callee_index,
            &mut yields,
            script_size,
        )?;
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
fn compile_if_statement(
    condition: &Expr,
    then_branch: &[Statement],
    else_branch: Option<&[Statement]>,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    functions: &HashMap<String, FunctionAst>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr>,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(condition, env, params, types, builder, options, &mut HashSet::new(), &mut stack_depth, script_size)?;
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

fn merge_env_after_if(
    env: &mut HashMap<String, Expr>,
    original_env: &HashMap<String, Expr>,
    then_env: &HashMap<String, Expr>,
    else_env: &HashMap<String, Expr>,
    condition: &Expr,
) {
    for (name, original_expr) in original_env {
        let then_expr = then_env.get(name).unwrap_or(original_expr);
        let else_expr = else_env.get(name).unwrap_or(original_expr);

        if then_expr == else_expr {
            env.insert(name.clone(), then_expr.clone());
        } else {
            env.insert(
                name.clone(),
                Expr::IfElse {
                    condition: Box::new(condition.clone()),
                    then_expr: Box::new(then_expr.clone()),
                    else_expr: Box::new(else_expr.clone()),
                },
            );
        }
    }
}

fn compile_time_op_statement(
    tx_var: &TimeVar,
    expr: &Expr,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(expr, env, params, types, builder, options, &mut HashSet::new(), &mut stack_depth, script_size)?;

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
fn compile_block(
    statements: &[Statement],
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    functions: &HashMap<String, FunctionAst>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr>,
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
            contract_constants,
            functions,
            function_order,
            function_index,
            yields,
            script_size,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_for_statement(
    ident: &str,
    start_expr: &Expr,
    end_expr: &Expr,
    body: &[Statement],
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    functions: &HashMap<String, FunctionAst>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    yields: &mut Vec<Expr>,
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
        env.insert(name.clone(), Expr::Int(value));
        compile_block(
            body,
            env,
            params,
            types,
            builder,
            options,
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

fn eval_const_int(expr: &Expr, constants: &HashMap<String, Expr>) -> Result<i64, CompilerError> {
    match expr {
        Expr::Int(value) => Ok(*value),
        Expr::Identifier(name) => match constants.get(name) {
            Some(value) => eval_const_int(value, constants),
            None => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
        },
        Expr::Unary { op: UnaryOp::Neg, expr } => Ok(-eval_const_int(expr, constants)?),
        Expr::Unary { .. } => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
        Expr::Binary { op, left, right } => {
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

fn resolve_expr(expr: Expr, env: &HashMap<String, Expr>, visiting: &mut HashSet<String>) -> Result<Expr, CompilerError> {
    match expr {
        Expr::Identifier(name) => {
            if name.starts_with("__arg_") {
                return Ok(Expr::Identifier(name));
            }
            if let Some(value) = env.get(&name) {
                if !visiting.insert(name.clone()) {
                    return Err(CompilerError::CyclicIdentifier(name));
                }
                let resolved = resolve_expr(value.clone(), env, visiting)?;
                visiting.remove(&name);
                Ok(resolved)
            } else {
                Ok(Expr::Identifier(name))
            }
        }
        Expr::Unary { op, expr } => Ok(Expr::Unary { op, expr: Box::new(resolve_expr(*expr, env, visiting)?) }),
        Expr::Binary { op, left, right } => Ok(Expr::Binary {
            op,
            left: Box::new(resolve_expr(*left, env, visiting)?),
            right: Box::new(resolve_expr(*right, env, visiting)?),
        }),
        Expr::IfElse { condition, then_expr, else_expr } => Ok(Expr::IfElse {
            condition: Box::new(resolve_expr(*condition, env, visiting)?),
            then_expr: Box::new(resolve_expr(*then_expr, env, visiting)?),
            else_expr: Box::new(resolve_expr(*else_expr, env, visiting)?),
        }),
        Expr::Array(values) => {
            let mut resolved = Vec::with_capacity(values.len());
            for value in values {
                resolved.push(resolve_expr(value, env, visiting)?);
            }
            Ok(Expr::Array(resolved))
        }
        Expr::Call { name, args } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr(arg, env, visiting)?);
            }
            Ok(Expr::Call { name, args: resolved })
        }
        Expr::New { name, args } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr(arg, env, visiting)?);
            }
            Ok(Expr::New { name, args: resolved })
        }
        Expr::Split { source, index, part } => Ok(Expr::Split {
            source: Box::new(resolve_expr(*source, env, visiting)?),
            index: Box::new(resolve_expr(*index, env, visiting)?),
            part,
        }),
        Expr::ArrayIndex { source, index } => Ok(Expr::ArrayIndex {
            source: Box::new(resolve_expr(*source, env, visiting)?),
            index: Box::new(resolve_expr(*index, env, visiting)?),
        }),
        Expr::Introspection { kind, index } => Ok(Expr::Introspection { kind, index: Box::new(resolve_expr(*index, env, visiting)?) }),
        other => Ok(other),
    }
}

fn replace_identifier(expr: &Expr, target: &str, replacement: &Expr) -> Expr {
    match expr {
        Expr::Identifier(name) if name == target => replacement.clone(),
        Expr::Identifier(_) => expr.clone(),
        Expr::Unary { op, expr: inner } => Expr::Unary { op: *op, expr: Box::new(replace_identifier(inner, target, replacement)) },
        Expr::Binary { op, left, right } => Expr::Binary {
            op: *op,
            left: Box::new(replace_identifier(left, target, replacement)),
            right: Box::new(replace_identifier(right, target, replacement)),
        },
        Expr::Array(values) => Expr::Array(values.iter().map(|value| replace_identifier(value, target, replacement)).collect()),
        Expr::Call { name, args } => {
            Expr::Call { name: name.clone(), args: args.iter().map(|arg| replace_identifier(arg, target, replacement)).collect() }
        }
        Expr::New { name, args } => {
            Expr::New { name: name.clone(), args: args.iter().map(|arg| replace_identifier(arg, target, replacement)).collect() }
        }
        Expr::Split { source, index, part } => Expr::Split {
            source: Box::new(replace_identifier(source, target, replacement)),
            index: Box::new(replace_identifier(index, target, replacement)),
            part: *part,
        },
        Expr::Slice { source, start, end } => Expr::Slice {
            source: Box::new(replace_identifier(source, target, replacement)),
            start: Box::new(replace_identifier(start, target, replacement)),
            end: Box::new(replace_identifier(end, target, replacement)),
        },
        Expr::ArrayIndex { source, index } => Expr::ArrayIndex {
            source: Box::new(replace_identifier(source, target, replacement)),
            index: Box::new(replace_identifier(index, target, replacement)),
        },
        Expr::IfElse { condition, then_expr, else_expr } => Expr::IfElse {
            condition: Box::new(replace_identifier(condition, target, replacement)),
            then_expr: Box::new(replace_identifier(then_expr, target, replacement)),
            else_expr: Box::new(replace_identifier(else_expr, target, replacement)),
        },
        Expr::Introspection { kind, index } => {
            Expr::Introspection { kind: *kind, index: Box::new(replace_identifier(index, target, replacement)) }
        }
        Expr::Int(_) | Expr::Bool(_) | Expr::Bytes(_) | Expr::String(_) | Expr::Nullary(_) => expr.clone(),
    }
}

struct CompilationScope<'a> {
    env: &'a HashMap<String, Expr>,
    params: &'a HashMap<String, i64>,
    types: &'a HashMap<String, String>,
}

fn compile_expr(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let scope = CompilationScope { env, params, types };
    match expr {
        Expr::Int(value) => {
            builder.add_i64(*value)?;
            *stack_depth += 1;
            Ok(())
        }
        Expr::Bool(value) => {
            builder.add_op(if *value { OpTrue } else { OpFalse })?;
            *stack_depth += 1;
            Ok(())
        }
        Expr::Bytes(bytes) => {
            builder.add_data(bytes)?;
            *stack_depth += 1;
            Ok(())
        }
        Expr::String(value) => {
            builder.add_data(value.as_bytes())?;
            *stack_depth += 1;
            Ok(())
        }
        Expr::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return Err(CompilerError::CyclicIdentifier(name.clone()));
            }
            if let Some(expr) = env.get(name) {
                compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
        Expr::IfElse { condition, then_expr, else_expr } => {
            compile_expr(condition, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            builder.add_op(OpIf)?;
            *stack_depth -= 1;
            let depth_before = *stack_depth;
            compile_expr(then_expr, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            builder.add_op(OpElse)?;
            *stack_depth = depth_before;
            compile_expr(else_expr, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            builder.add_op(OpEndIf)?;
            *stack_depth = depth_before + 1;
            Ok(())
        }
        Expr::Array(_) => Err(CompilerError::Unsupported("array literals are only supported in LockingBytecodeNullData".to_string())),
        Expr::Call { name, args } => match name.as_str() {
            "OpSha256" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpSHA256, false, script_size)
            }
            "sha256" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("sha256() expects a single argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                builder.add_op(OpSHA256)?;
                Ok(())
            }
            "date" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("date() expects a single argument".to_string()));
                }
                let value = match &args[0] {
                    Expr::String(value) => value.as_str(),
                    Expr::Identifier(name) => {
                        if let Some(Expr::String(value)) = env.get(name) {
                            value.as_str()
                        } else {
                            return Err(CompilerError::Unsupported("date() expects a string literal".to_string()));
                        }
                    }
                    _ => return Err(CompilerError::Unsupported("date() expects a string literal".to_string())),
                };
                let timestamp = parse_date_value(value)?;
                builder.add_i64(timestamp)?;
                *stack_depth += 1;
                Ok(())
            }
            "OpTxSubnetId" => {
                compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxSubnetId, true, script_size)
            }
            "OpTxGas" => {
                compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxGas, true, script_size)
            }
            "OpTxPayloadLen" => {
                compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxPayloadLen, true, script_size)
            }
            "OpTxPayloadSubstr" => compile_opcode_call(
                name,
                args,
                2,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxPayloadSubstr,
                true,
                script_size,
            ),
            "OpOutpointTxId" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpOutpointTxId, true, script_size)
            }
            "OpOutpointIndex" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpOutpointIndex, true, script_size)
            }
            "OpTxInputScriptSigLen" => compile_opcode_call(
                name,
                args,
                1,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxInputScriptSigLen,
                true,
                script_size,
            ),
            "OpTxInputScriptSigSubstr" => compile_opcode_call(
                name,
                args,
                3,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxInputScriptSigSubstr,
                true,
                script_size,
            ),
            "OpTxInputSeq" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputSeq, true, script_size)
            }
            "OpTxInputIsCoinbase" => compile_opcode_call(
                name,
                args,
                1,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxInputIsCoinbase,
                true,
                script_size,
            ),
            "OpTxInputSpkLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputSpkLen, true, script_size)
            }
            "OpTxInputSpkSubstr" => compile_opcode_call(
                name,
                args,
                3,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxInputSpkSubstr,
                true,
                script_size,
            ),
            "OpTxOutputSpkLen" => compile_opcode_call(
                name,
                args,
                1,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxOutputSpkLen,
                true,
                script_size,
            ),
            "OpTxOutputSpkSubstr" => compile_opcode_call(
                name,
                args,
                3,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpTxOutputSpkSubstr,
                true,
                script_size,
            ),
            "OpAuthOutputCount" => compile_opcode_call(
                name,
                args,
                1,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpAuthOutputCount,
                true,
                script_size,
            ),
            "OpAuthOutputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpAuthOutputIdx, true, script_size)
            }
            "OpInputCovenantId" => compile_opcode_call(
                name,
                args,
                1,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpInputCovenantId,
                true,
                script_size,
            ),
            "OpCovInputCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpCovInputCount, true, script_size)
            }
            "OpCovInputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpCovInputIdx, true, script_size)
            }
            "OpCovOutCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpCovOutCount, true, script_size)
            }
            "OpCovOutputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpCovOutputIdx, true, script_size)
            }
            "OpNum2Bin" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpNum2Bin, true, script_size)
            }
            "OpBin2Num" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpBin2Num, true, script_size)
            }
            "OpChainblockSeqCommit" => compile_opcode_call(
                name,
                args,
                1,
                &scope,
                builder,
                options,
                visiting,
                stack_depth,
                OpChainblockSeqCommit,
                false,
                script_size,
            ),
            "bytes" => {
                if args.is_empty() || args.len() > 2 {
                    return Err(CompilerError::Unsupported("bytes() expects one or two arguments".to_string()));
                }
                if args.len() == 2 {
                    compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                    compile_expr(&args[1], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                    builder.add_op(OpNum2Bin)?;
                    *stack_depth -= 1;
                    return Ok(());
                }
                match &args[0] {
                    Expr::String(value) => {
                        builder.add_data(value.as_bytes())?;
                        *stack_depth += 1;
                        Ok(())
                    }
                    Expr::Identifier(name) => {
                        if let Some(Expr::String(value)) = env.get(name) {
                            builder.add_data(value.as_bytes())?;
                            *stack_depth += 1;
                            return Ok(());
                        }
                        if expr_is_bytes(&args[0], env, types) {
                            compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                            return Ok(());
                        }
                        compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                        builder.add_i64(8)?;
                        *stack_depth += 1;
                        builder.add_op(OpNum2Bin)?;
                        *stack_depth -= 1;
                        Ok(())
                    }
                    _ => {
                        if expr_is_bytes(&args[0], env, types) {
                            compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                            Ok(())
                        } else {
                            compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
                if let Expr::Identifier(name) = &args[0] {
                    if let Some(type_name) = types.get(name) {
                        if let Some(element_size) = array_element_size(type_name) {
                            compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                builder.add_op(OpSize)?;
                Ok(())
            }
            "int" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("int() expects a single argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                Ok(())
            }
            "sig" | "pubkey" | "datasig" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                Ok(())
            }
            name if name.starts_with("bytes") => {
                let size = name
                    .strip_prefix("bytes")
                    .and_then(|v| v.parse::<i64>().ok())
                    .ok_or_else(|| CompilerError::Unsupported(format!("{name}() is not supported")))?;
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                builder.add_i64(size)?;
                *stack_depth += 1;
                builder.add_op(OpNum2Bin)?;
                *stack_depth -= 1;
                Ok(())
            }
            "blake2b" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("blake2b() expects a single argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                builder.add_op(OpBlake2b)?;
                Ok(())
            }
            "checkSig" => {
                if args.len() != 2 {
                    return Err(CompilerError::Unsupported("checkSig() expects 2 arguments".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                compile_expr(&args[1], env, params, types, builder, options, visiting, stack_depth, script_size)?;
                builder.add_op(OpCheckSig)?;
                *stack_depth -= 1;
                Ok(())
            }
            "checkDataSig" => {
                // TODO: Remove this stub
                for arg in args {
                    compile_expr(arg, env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
        },
        Expr::New { name, args } => match name.as_str() {
            "LockingBytecodeNullData" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("LockingBytecodeNullData expects a single array argument".to_string()));
                }
                let script = build_null_data_script(&args[0])?;
                builder.add_data(&script)?;
                *stack_depth += 1;
                Ok(())
            }
            "LockingBytecodeP2PK" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("LockingBytecodeP2PK expects a single pubkey argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
            "LockingBytecodeP2SH" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("LockingBytecodeP2SH expects a single bytes32 argument".to_string()));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
            "LockingBytecodeP2SHFromRedeemScript" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(
                        "LockingBytecodeP2SHFromRedeemScript expects a single redeem_script argument".to_string(),
                    ));
                }
                compile_expr(&args[0], env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
            _ => Err(CompilerError::Unsupported(format!("unknown constructor: {name}"))),
        },
        Expr::Unary { op, expr } => {
            compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            match op {
                UnaryOp::Not => builder.add_op(OpNot)?,
                UnaryOp::Neg => builder.add_op(OpNegate)?,
            };
            Ok(())
        }
        Expr::Binary { op, left, right } => {
            let bytes_eq =
                matches!(op, BinaryOp::Eq | BinaryOp::Ne) && (expr_is_bytes(left, env, types) || expr_is_bytes(right, env, types));
            let bytes_add = matches!(op, BinaryOp::Add) && (expr_is_bytes(left, env, types) || expr_is_bytes(right, env, types));
            if bytes_add {
                compile_concat_operand(left, env, params, types, builder, options, visiting, stack_depth, script_size)?;
                compile_concat_operand(right, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            } else {
                compile_expr(left, env, params, types, builder, options, visiting, stack_depth, script_size)?;
                compile_expr(right, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            }
            match op {
                BinaryOp::Or => {
                    builder.add_op(OpBoolOr)?;
                }
                BinaryOp::And => {
                    builder.add_op(OpBoolAnd)?;
                }
                BinaryOp::BitOr => {
                    require_covenants(options, "bitwise or")?;
                    builder.add_op(OpOr)?;
                }
                BinaryOp::BitXor => {
                    require_covenants(options, "bitwise xor")?;
                    builder.add_op(OpXor)?;
                }
                BinaryOp::BitAnd => {
                    require_covenants(options, "bitwise and")?;
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
                    require_covenants(options, "multiplication")?;
                    builder.add_op(OpMul)?;
                }
                BinaryOp::Div => {
                    require_covenants(options, "division")?;
                    builder.add_op(OpDiv)?;
                }
                BinaryOp::Mod => {
                    require_covenants(options, "modulo")?;
                    builder.add_op(OpMod)?;
                }
            }
            *stack_depth -= 1;
            Ok(())
        }
        Expr::Split { source, index, part } => {
            compile_expr(source, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            match part {
                SplitPart::Left => {
                    compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size)?;
                    builder.add_i64(0)?;
                    *stack_depth += 1;
                    builder.add_op(OpSwap)?;
                    builder.add_op(OpSubstr)?;
                    *stack_depth -= 2;
                }
                SplitPart::Right => {
                    builder.add_op(OpSize)?;
                    *stack_depth += 1;
                    compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size)?;
                    builder.add_op(OpSwap)?;
                    builder.add_op(OpSubstr)?;
                    *stack_depth -= 2;
                }
            }
            Ok(())
        }
        Expr::ArrayIndex { source, index } => {
            let resolved_source = match source.as_ref() {
                Expr::Identifier(_) => source.as_ref().clone(),
                _ => resolve_expr(*source.clone(), env, visiting)?,
            };
            let element_type = match &resolved_source {
                Expr::Identifier(name) => {
                    let type_name = types.get(name).or_else(|| {
                        env.get(name).and_then(|value| if let Expr::Identifier(inner) = value { types.get(inner) } else { None })
                    });
                    type_name
                        .and_then(|t| array_element_type(t))
                        .ok_or_else(|| CompilerError::Unsupported(format!("array index requires array identifier: {name}")))?
                }
                _ => return Err(CompilerError::Unsupported("array index requires array identifier".to_string())),
            };
            let element_size = fixed_type_size(element_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            compile_expr(&resolved_source, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size)?;
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
        Expr::Slice { source, start, end } => {
            compile_expr(source, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            compile_expr(start, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            compile_expr(end, env, params, types, builder, options, visiting, stack_depth, script_size)?;

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
        Expr::Nullary(op) => {
            match op {
                NullaryOp::ActiveInputIndex => {
                    builder.add_op(OpTxInputIndex)?;
                }
                NullaryOp::ActiveBytecode => {
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
        Expr::Introspection { kind, index } => {
            compile_expr(index, env, params, types, builder, options, visiting, stack_depth, script_size)?;
            match kind {
                IntrospectionKind::InputValue => {
                    builder.add_op(OpTxInputAmount)?;
                }
                IntrospectionKind::InputLockingBytecode => {
                    builder.add_op(OpTxInputSpk)?;
                }
                IntrospectionKind::OutputValue => {
                    builder.add_op(OpTxOutputAmount)?;
                }
                IntrospectionKind::OutputLockingBytecode => {
                    builder.add_op(OpTxOutputSpk)?;
                }
            }
            Ok(())
        }
    }
}

fn expr_is_bytes(expr: &Expr, env: &HashMap<String, Expr>, types: &HashMap<String, String>) -> bool {
    let mut visiting = HashSet::new();
    expr_is_bytes_inner(expr, env, types, &mut visiting)
}

fn expr_is_bytes_inner(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    types: &HashMap<String, String>,
    visiting: &mut HashSet<String>,
) -> bool {
    match expr {
        Expr::Bytes(_) => true,
        Expr::String(_) => true,
        Expr::Slice { .. } => true,
        Expr::New { name, .. } => matches!(
            name.as_str(),
            "LockingBytecodeNullData" | "LockingBytecodeP2PK" | "LockingBytecodeP2SH" | "LockingBytecodeP2SHFromRedeemScript"
        ),
        Expr::Call { name, .. } => {
            matches!(
                name.as_str(),
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
            ) || name.starts_with("bytes")
        }
        Expr::Split { .. } => true,
        Expr::Binary { op: BinaryOp::Add, left, right } => {
            expr_is_bytes_inner(left, env, types, visiting) || expr_is_bytes_inner(right, env, types, visiting)
        }
        Expr::IfElse { condition: _, then_expr, else_expr } => {
            expr_is_bytes_inner(then_expr, env, types, visiting) && expr_is_bytes_inner(else_expr, env, types, visiting)
        }
        Expr::Introspection { kind, .. } => {
            matches!(kind, IntrospectionKind::InputLockingBytecode | IntrospectionKind::OutputLockingBytecode)
        }
        Expr::Nullary(NullaryOp::ActiveBytecode) => true,
        Expr::Nullary(NullaryOp::ThisScriptSizeDataPrefix) => true,
        Expr::ArrayIndex { source, .. } => match source.as_ref() {
            Expr::Identifier(name) => {
                types.get(name).and_then(|type_name| array_element_type(type_name)).map(|element| element != "int").unwrap_or(false)
            }
            _ => false,
        },
        Expr::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return false;
            }
            if let Some(expr) = env.get(name) {
                let result = expr_is_bytes_inner(expr, env, types, visiting);
                visiting.remove(name);
                return result;
            }
            visiting.remove(name);
            types.get(name).map(|type_name| is_bytes_type(type_name)).unwrap_or(false)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_opcode_call(
    name: &str,
    args: &[Expr],
    expected_args: usize,
    scope: &CompilationScope,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    opcode: u8,
    requires_covenants: bool,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    if args.len() != expected_args {
        return Err(CompilerError::Unsupported(format!("{name}() expects {expected_args} argument(s)")));
    }
    if requires_covenants {
        require_covenants(options, name)?;
    }
    for arg in args {
        compile_expr(arg, scope.env, scope.params, scope.types, builder, options, visiting, stack_depth, script_size)?;
    }
    builder.add_op(opcode)?;
    *stack_depth += 1 - expected_args as i64;
    Ok(())
}

fn compile_concat_operand(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    compile_expr(expr, env, params, types, builder, options, visiting, stack_depth, script_size)?;
    if !expr_is_bytes(expr, env, types) {
        builder.add_i64(1)?;
        *stack_depth += 1;
        builder.add_op(OpNum2Bin)?;
        *stack_depth -= 1;
    }
    Ok(())
}

fn is_bytes_type(type_name: &str) -> bool {
    is_array_type(type_name)
        || type_name == "bytes"
        || type_name == "byte"
        || type_name.starts_with("bytes")
        || matches!(type_name, "pubkey" | "sig" | "string")
}

fn build_null_data_script(arg: &Expr) -> Result<Vec<u8>, CompilerError> {
    let elements = match arg {
        Expr::Array(items) => items,
        _ => return Err(CompilerError::Unsupported("LockingBytecodeNullData expects an array literal".to_string())),
    };

    let mut builder = ScriptBuilder::new();
    builder.add_op(OpReturn)?;
    for item in elements {
        match item {
            Expr::Int(value) => {
                builder.add_i64(*value)?;
            }
            Expr::Bytes(bytes) => {
                builder.add_data(bytes)?;
            }
            Expr::String(value) => {
                builder.add_data(value.as_bytes())?;
            }
            Expr::Call { name, args } if name == "bytes" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(
                        "bytes() in LockingBytecodeNullData expects a single argument".to_string(),
                    ));
                }
                match &args[0] {
                    Expr::String(value) => {
                        builder.add_data(value.as_bytes())?;
                    }
                    _ => {
                        return Err(CompilerError::Unsupported(
                            "bytes() in LockingBytecodeNullData only supports string literals".to_string(),
                        ));
                    }
                }
            }
            _ => return Err(CompilerError::Unsupported("LockingBytecodeNullData only supports int or bytes literals".to_string())),
        }
    }

    let script = builder.drain();
    let mut spk_bytes = Vec::with_capacity(2 + script.len());
    spk_bytes.extend_from_slice(&0u16.to_be_bytes());
    spk_bytes.extend_from_slice(&script);
    Ok(spk_bytes)
}
fn require_covenants(options: CompileOptions, feature: &str) -> Result<(), CompilerError> {
    if options.covenants_enabled {
        Ok(())
    } else {
        Err(CompilerError::Unsupported(format!("{feature} requires covenants-enabled opcodes; confirm covenants_enabled=true")))
    }
}

fn parse_date_value(value: &str) -> Result<i64, CompilerError> {
    let timestamp = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S")
        .map_err(|_| CompilerError::InvalidLiteral("invalid date literal".to_string()))?
        .and_utc()
        .timestamp();
    Ok(timestamp)
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
