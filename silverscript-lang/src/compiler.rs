use std::collections::{HashMap, HashSet};

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::{ScriptBuilder, ScriptBuilderError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ast::{
    BinaryOp, ConsoleArg, ContractAst, Expr, FunctionAst, IntrospectionKind, NullaryOp, SourceSpan, SplitPart, Statement,
    StatementKind, TimeVar, UnaryOp, parse_contract_ast,
};
use crate::debug::DebugInfo;
use crate::debug::labels::synthetic;
use crate::parser::Rule;
use chrono::NaiveDateTime;

mod debug_recording;

use debug_recording::{DebugSink, FunctionDebugRecorder, record_synthetic_range};

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

#[derive(Debug, Clone, Copy, Default)]
pub struct CompileOptions {
    pub allow_yield: bool,
    pub allow_entrypoint_return: bool,
    pub record_debug_infos: bool,
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
pub struct CompiledContract {
    pub contract_name: String,
    pub script: Vec<u8>,
    pub ast: ContractAst,
    pub abi: FunctionAbi,
    pub without_selector: bool,
    pub debug_info: Option<DebugInfo>,
}

pub fn compile_contract(source: &str, constructor_args: &[Expr], options: CompileOptions) -> Result<CompiledContract, CompilerError> {
    let contract = parse_contract_ast(source)?;
    compile_contract_impl(&contract, constructor_args, options, Some(source))
}

pub fn compile_contract_ast(
    contract: &ContractAst,
    constructor_args: &[Expr],
    options: CompileOptions,
) -> Result<CompiledContract, CompilerError> {
    compile_contract_impl(contract, constructor_args, options, None)
}

fn compile_contract_impl(
    contract: &ContractAst,
    constructor_args: &[Expr],
    options: CompileOptions,
    source: Option<&str>,
) -> Result<CompiledContract, CompilerError> {
    if contract.functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no functions".to_string()));
    }

    let entrypoint_functions: Vec<&FunctionAst> = contract.functions.iter().filter(|func| func.entrypoint).collect();
    if entrypoint_functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entrypoint functions".to_string()));
    }

    if contract.params.len() != constructor_args.len() {
        return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
    }

    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        if !expr_matches_type(value, &param.type_name) {
            return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, param.type_name)));
        }
    }

    let without_selector = entrypoint_functions.len() == 1;

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
        let mut compiled_entrypoints = Vec::new();
        // Create a recorder (active/non-active based on compilation options) to collect debug info
        let mut recorder = DebugSink::new(options.record_debug_infos);
        recorder.record_constructor_constants(&contract.params, constructor_args);

        for (index, func) in contract.functions.iter().enumerate() {
            if func.entrypoint {
                compiled_entrypoints.push(compile_function(
                    func,
                    index,
                    &constants,
                    options,
                    &functions_map,
                    &function_order,
                    script_size,
                )?);
            }
        }

        let script = if without_selector {
            let compiled = compiled_entrypoints
                .first()
                .ok_or_else(|| CompilerError::Unsupported("contract has no entrypoint functions".to_string()))?;
            recorder.record_compiled_function(&compiled.name, compiled.script.len(), &compiled.debug, 0);
            compiled.script.clone()
        } else {
            let mut builder = ScriptBuilder::new();
            let total = compiled_entrypoints.len();

            for (index, compiled) in compiled_entrypoints.iter().enumerate() {
                record_synthetic_range(&mut builder, &mut recorder, synthetic::DISPATCHER_GUARD, |builder| {
                    builder.add_op(OpDup)?;
                    builder.add_i64(index as i64)?;
                    builder.add_op(OpNumEqual)?;
                    builder.add_op(OpIf)?;
                    builder.add_op(OpDrop)?;
                    Ok(())
                })?;

                let func_start = builder.script().len();
                builder.add_ops(&compiled.script)?;
                recorder.record_compiled_function(&compiled.name, compiled.script.len(), &compiled.debug, func_start);

                record_synthetic_range(&mut builder, &mut recorder, synthetic::DISPATCHER_ELSE, |builder| {
                    builder.add_op(OpElse)?;
                    if index == total - 1 {
                        builder.add_op(OpDrop)?;
                        builder.add_op(OpFalse)?;
                        builder.add_op(OpVerify)?;
                    }
                    Ok(())
                })?;
            }

            record_synthetic_range(&mut builder, &mut recorder, synthetic::DISPATCHER_ENDIFS, |builder| {
                for _ in 0..total {
                    builder.add_op(OpEndIf)?;
                }
                Ok(())
            })?;

            builder.drain()
        };

        if !uses_script_size {
            let debug_info = recorder.into_debug_info(source.unwrap_or_default().to_string());
            return Ok(CompiledContract {
                contract_name: contract.name.clone(),
                script,
                ast: contract.clone(),
                abi,
                without_selector,
                debug_info,
            });
        }

        let actual_size = script.len() as i64;
        if Some(actual_size) == script_size {
            let debug_info = recorder.into_debug_info(source.unwrap_or_default().to_string());
            return Ok(CompiledContract {
                contract_name: contract.name.clone(),
                script,
                ast: contract.clone(),
                abi,
                without_selector,
                debug_info,
            });
        }
        script_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("script size did not stabilize".to_string()))
}

#[derive(Debug)]
struct CompiledFunction {
    name: String,
    script: Vec<u8>,
    debug: FunctionDebugRecorder,
}

fn contract_uses_script_size(contract: &ContractAst) -> bool {
    if contract.constants.values().any(expr_uses_script_size) {
        return true;
    }
    contract.functions.iter().any(|func| func.body.iter().any(statement_uses_script_size))
}

fn statement_uses_script_size(stmt: &Statement) -> bool {
    match &stmt.kind {
        StatementKind::VariableDefinition { expr, .. } => expr.as_ref().is_some_and(expr_uses_script_size),
        StatementKind::TupleAssignment { expr, .. } => expr_uses_script_size(expr),
        StatementKind::ArrayPush { expr, .. } => expr_uses_script_size(expr),
        StatementKind::FunctionCall { args, .. } => args.iter().any(expr_uses_script_size),
        StatementKind::FunctionCallAssign { args, .. } => args.iter().any(expr_uses_script_size),
        StatementKind::Assign { expr, .. } => expr_uses_script_size(expr),
        StatementKind::TimeOp { expr, .. } => expr_uses_script_size(expr),
        StatementKind::Require { expr, .. } => expr_uses_script_size(expr),
        StatementKind::If { condition, then_branch, else_branch, .. } => {
            expr_uses_script_size(condition)
                || then_branch.iter().any(statement_uses_script_size)
                || else_branch.as_ref().is_some_and(|branch| branch.iter().any(statement_uses_script_size))
        }
        StatementKind::For { start, end, body, .. } => {
            expr_uses_script_size(start) || expr_uses_script_size(end) || body.iter().any(statement_uses_script_size)
        }
        StatementKind::Yield { expr, .. } => expr_uses_script_size(expr),
        StatementKind::Return { exprs, .. } => exprs.iter().any(expr_uses_script_size),
        StatementKind::Console { args, .. } => {
            args.iter().any(|arg| matches!(arg, ConsoleArg::Literal(e) if expr_uses_script_size(e)))
        }
    }
}

fn expr_uses_script_size(expr: &Expr) -> bool {
    match expr {
        Expr::Int(_) | Expr::Bool(_) | Expr::Bytes(_) | Expr::String(_) | Expr::Identifier(_) => false,
        Expr::Array(items) => items.iter().any(expr_uses_script_size),
        Expr::Call { args, .. } | Expr::New { args, .. } => args.iter().any(expr_uses_script_size),
        Expr::Split { source, index, .. } => expr_uses_script_size(source) || expr_uses_script_size(index),
        Expr::Slice { source, start, end } => {
            expr_uses_script_size(source) || expr_uses_script_size(start) || expr_uses_script_size(end)
        }
        Expr::ArrayIndex { source, index } => expr_uses_script_size(source) || expr_uses_script_size(index),
        Expr::Unary { expr, .. } => expr_uses_script_size(expr),
        Expr::Binary { left, right, .. } => expr_uses_script_size(left) || expr_uses_script_size(right),
        Expr::IfElse { condition, then_expr, else_expr } => {
            expr_uses_script_size(condition) || expr_uses_script_size(then_expr) || expr_uses_script_size(else_expr)
        }
        Expr::Nullary(op) => matches!(op, NullaryOp::ThisScriptSize | NullaryOp::ThisScriptSizeDataPrefix),
        Expr::Introspection { index, .. } => expr_uses_script_size(index),
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
        .filter(|func| func.entrypoint)
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
    match &stmt.kind {
        StatementKind::Return { .. } => true,
        StatementKind::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(contains_return) || else_branch.as_ref().is_some_and(|branch| branch.iter().any(contains_return))
        }
        StatementKind::For { body, .. } => body.iter().any(contains_return),
        _ => false,
    }
}

fn contains_yield(stmt: &Statement) -> bool {
    match &stmt.kind {
        StatementKind::Yield { .. } => true,
        StatementKind::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(contains_yield) || else_branch.as_ref().is_some_and(|branch| branch.iter().any(contains_yield))
        }
        StatementKind::For { body, .. } => body.iter().any(contains_yield),
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
        .filter(|func| func.entrypoint)
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
) -> Result<CompiledFunction, CompilerError> {
    let mut builder = ScriptBuilder::new();
    let mut recorder = FunctionDebugRecorder::new(options.record_debug_infos, function);

    let mut env = constants.clone();
    let mut types = HashMap::new();
    let mut params = HashMap::new();

    let param_count = function.params.len();
    for (index, param) in function.params.iter().enumerate() {
        if is_array_type(&param.type_name) && array_element_size(&param.type_name).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param.type_name)));
        }
        params.insert(param.name.clone(), (param_count - 1 - index) as i64);
        types.insert(param.name.clone(), param.type_name.clone());
    }

    for return_type in &function.return_types {
        if is_array_type(return_type) && array_element_size(return_type).is_none() {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {return_type}")));
        }
    }

    if !options.allow_yield && function.body.iter().any(contains_yield) {
        return Err(CompilerError::Unsupported("yield requires allow_yield=true".to_string()));
    }

    if function.entrypoint && !options.allow_entrypoint_return && function.body.iter().any(contains_return) {
        return Err(CompilerError::Unsupported("entrypoint return requires allow_entrypoint_return=true".to_string()));
    }

    let has_return = function.body.iter().any(contains_return);
    if has_return {
        if !matches!(function.body.last(), Some(Statement { kind: StatementKind::Return { .. }, .. })) {
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
    {
        let mut body_compiler = FunctionBodyCompiler {
            builder: &mut builder,
            options,
            debug_recorder: &mut recorder,
            contract_constants: constants,
            functions,
            function_order,
            function_index,
            script_size,
            inline_frame_counter: 1,
        };
        for stmt in &function.body {
            if matches!(stmt.kind, StatementKind::Return { .. }) {
                let StatementKind::Return { exprs, .. } = &stmt.kind else { unreachable!() };
                validate_return_types(exprs, &function.return_types, &types)?;
                for expr in exprs {
                    let resolved = resolve_expr(expr.clone(), &env, &mut HashSet::new())?;
                    yields.push(resolved);
                }
                continue;
            }

            body_compiler.compile_statement(stmt, &mut env, &params, &mut types, &mut yields)?;
        }
    }

    if function.entrypoint {
        if !has_return && !function.return_types.is_empty() {
            return Err(CompilerError::Unsupported("entrypoint function must not have return types unless it returns".to_string()));
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
    }

    Ok(CompiledFunction { name: function.name.clone(), script: builder.drain(), debug: recorder })
}
struct FunctionBodyCompiler<'a> {
    builder: &'a mut ScriptBuilder,
    options: CompileOptions,
    debug_recorder: &'a mut FunctionDebugRecorder,
    contract_constants: &'a HashMap<String, Expr>,
    functions: &'a HashMap<String, FunctionAst>,
    function_order: &'a HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    inline_frame_counter: u32,
}

impl<'a> FunctionBodyCompiler<'a> {
    fn compile_statement(
        &mut self,
        stmt: &Statement,
        env: &mut HashMap<String, Expr>,
        params: &HashMap<String, i64>,
        types: &mut HashMap<String, String>,
        yields: &mut Vec<Expr>,
    ) -> Result<(), CompilerError> {
        let start = self.builder.script().len();
        let mut variables = Vec::new();

        match &stmt.kind {
            StatementKind::VariableDefinition { type_name, name, expr, .. } => {
                if is_array_type(type_name) {
                    if array_element_size(type_name).is_none() {
                        return Err(CompilerError::Unsupported(format!("array element type must have known size: {type_name}")));
                    }
                    let initial = match expr {
                        Some(Expr::Identifier(other)) => match types.get(other) {
                            Some(other_type) if other_type == type_name => Expr::Identifier(other.clone()),
                            Some(_) => {
                                return Err(CompilerError::Unsupported(
                                    "array assignment requires compatible array types".to_string(),
                                ));
                            }
                            None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                        },
                        Some(_) => return Err(CompilerError::Unsupported("array initializer must be another array".to_string())),
                        None => Expr::Bytes(Vec::new()),
                    };
                    self.debug_recorder.variable_update(env, &mut variables, name, type_name, initial.clone())?;
                    env.insert(name.clone(), initial);
                    types.insert(name.clone(), type_name.clone());
                } else {
                    let expr = expr
                        .clone()
                        .ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
                    self.debug_recorder.variable_update(env, &mut variables, name, type_name, expr.clone())?;
                    env.insert(name.clone(), expr);
                    types.insert(name.clone(), type_name.clone());
                }
            }
            StatementKind::ArrayPush { name, expr, .. } => {
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
                self.debug_recorder.variable_update(env, &mut variables, name, array_type, updated.clone())?;
                env.insert(name.clone(), updated);
            }
            StatementKind::Require { expr, .. } => {
                let mut stack_depth = 0i64;
                compile_expr(
                    expr,
                    env,
                    params,
                    types,
                    self.builder,
                    self.options,
                    &mut HashSet::new(),
                    &mut stack_depth,
                    self.script_size,
                )?;
                self.builder.add_op(OpVerify)?;
            }
            StatementKind::TimeOp { tx_var, expr, .. } => {
                compile_time_op_statement(tx_var, expr, env, params, types, self.builder, self.options, self.script_size)?;
            }
            StatementKind::If { condition, then_branch, else_branch, .. } => {
                self.compile_if_statement(condition, then_branch, else_branch.as_deref(), env, params, types, yields)?;
            }
            StatementKind::For { ident, start, end, body, .. } => {
                self.compile_for_statement(ident, start, end, body, env, params, types, yields, stmt.span)?;
            }
            StatementKind::Yield { expr, .. } => {
                let mut visiting = HashSet::new();
                let resolved = resolve_expr(expr.clone(), env, &mut visiting)?;
                yields.push(resolved);
            }
            StatementKind::Return { .. } => {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            StatementKind::TupleAssignment { left_type, left_name, right_type, right_name, expr, .. } => match expr.clone() {
                Expr::Split { source, index, .. } => {
                    let left_expr = Expr::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left };
                    let right_expr = Expr::Split { source, index, part: SplitPart::Right };
                    self.debug_recorder.variable_update(env, &mut variables, left_name, left_type, left_expr.clone())?;
                    self.debug_recorder.variable_update(env, &mut variables, right_name, right_type, right_expr.clone())?;
                    env.insert(left_name.clone(), left_expr);
                    env.insert(right_name.clone(), right_expr);
                }
                _ => return Err(CompilerError::Unsupported("tuple assignment only supports split()".to_string())),
            },
            StatementKind::FunctionCall { name, args, .. } => {
                let returns = self.compile_inline_call(name, args, params, types, env, stmt.span)?;
                if !returns.is_empty() {
                    let mut stack_depth = 0i64;
                    for expr in returns {
                        compile_expr(
                            &expr,
                            env,
                            params,
                            types,
                            self.builder,
                            self.options,
                            &mut HashSet::new(),
                            &mut stack_depth,
                            self.script_size,
                        )?;
                        self.builder.add_op(OpDrop)?;
                        stack_depth -= 1;
                    }
                }
            }
            StatementKind::FunctionCallAssign { bindings, name, args, .. } => {
                let return_types = {
                    let function = self
                        .functions
                        .get(name)
                        .ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
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
                    function.return_types.clone()
                };
                let returns = self.compile_inline_call(name, args, params, types, env, stmt.span)?;
                if returns.len() != return_types.len() {
                    return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
                }
                for (binding, expr) in bindings.iter().zip(returns.into_iter()) {
                    if self.options.record_debug_infos {
                        let resolved = resolve_expr_for_debug(expr.clone(), env, &mut HashSet::new())?;
                        variables.push((binding.name.clone(), binding.type_name.clone(), resolved));
                    }
                    env.insert(binding.name.clone(), expr);
                    types.insert(binding.name.clone(), binding.type_name.clone());
                }
            }
            StatementKind::Assign { name, expr, .. } => {
                if let Some(type_name) = types.get(name) {
                    if is_array_type(type_name) {
                        match expr {
                            Expr::Identifier(other) => match types.get(other) {
                                Some(other_type) if other_type == type_name => {
                                    self.debug_recorder.variable_update(
                                        env,
                                        &mut variables,
                                        name,
                                        type_name,
                                        Expr::Identifier(other.clone()),
                                    )?;
                                    env.insert(name.clone(), Expr::Identifier(other.clone()));
                                }
                                Some(_) => {
                                    return Err(CompilerError::Unsupported(
                                        "array assignment requires compatible array types".to_string(),
                                    ));
                                }
                                None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                            },
                            _ => {
                                return Err(CompilerError::Unsupported(
                                    "array assignment only supports array identifiers".to_string(),
                                ));
                            }
                        }
                    } else {
                        let updated =
                            if let Some(previous) = env.get(name) { replace_identifier(expr, name, previous) } else { expr.clone() };
                        let resolved = resolve_expr(updated, env, &mut HashSet::new())?;
                        self.debug_recorder.variable_update(env, &mut variables, name, type_name, resolved.clone())?;
                        env.insert(name.clone(), resolved);
                    }
                } else {
                    let updated =
                        if let Some(previous) = env.get(name) { replace_identifier(expr, name, previous) } else { expr.clone() };
                    let resolved = resolve_expr(updated, env, &mut HashSet::new())?;
                    let type_name = "unknown";
                    self.debug_recorder.variable_update(env, &mut variables, name, type_name, resolved.clone())?;
                    env.insert(name.clone(), resolved);
                }
            }
            StatementKind::Console { .. } => {}
        }

        let end = self.builder.script().len();
        let stmt_seq = self.debug_recorder.record_statement(stmt, start, end - start);
        // Record updates at the end of the statement so variables reflect post-statement state
        // when the debugger is paused at the next byte offset.
        if let Some(sequence) = stmt_seq {
            self.debug_recorder.record_variable_updates(variables, end, stmt.span, sequence);
        }
        Ok(())
    }

    fn compile_inline_call(
        &mut self,
        name: &str,
        args: &[Expr],
        caller_params: &HashMap<String, i64>,
        caller_types: &mut HashMap<String, String>,
        caller_env: &mut HashMap<String, Expr>,
        call_span: Option<SourceSpan>,
    ) -> Result<Vec<Expr>, CompilerError> {
        let function = self.functions.get(name).ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
        let callee_index = self
            .function_order
            .get(name)
            .copied()
            .ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
        if callee_index >= self.function_index {
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

        let mut env: HashMap<String, Expr> = self.contract_constants.clone();
        for (index, (param, arg)) in function.params.iter().zip(args.iter()).enumerate() {
            let resolved = resolve_expr(arg.clone(), caller_env, &mut HashSet::new())?;
            let temp_name = format!("__arg_{name}_{index}");
            env.insert(temp_name.clone(), resolved.clone());
            types.insert(temp_name.clone(), param.type_name.clone());
            env.insert(param.name.clone(), Expr::Identifier(temp_name.clone()));
            caller_env.insert(temp_name.clone(), resolved);
            caller_types.insert(temp_name, param.type_name.clone());
        }

        if !self.options.allow_yield && function.body.iter().any(contains_yield) {
            return Err(CompilerError::Unsupported("yield requires allow_yield=true".to_string()));
        }

        if function.entrypoint && !self.options.allow_entrypoint_return && function.body.iter().any(contains_return) {
            return Err(CompilerError::Unsupported("entrypoint return requires allow_entrypoint_return=true".to_string()));
        }

        let has_return = function.body.iter().any(contains_return);
        if has_return {
            if !matches!(function.body.last(), Some(Statement { kind: StatementKind::Return { .. }, .. })) {
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
        let params = caller_params.clone();
        let call_offset = self.builder.script().len();
        self.debug_recorder.record_inline_call_enter(call_span, call_offset, name);

        // Compile callee statements using an isolated inline debug recorder so emitted
        // events/variable updates carry the callee frame id and call depth.
        let frame_id = self.inline_frame_counter;
        self.inline_frame_counter = self.inline_frame_counter.saturating_add(1);
        let mut debug_recorder = FunctionDebugRecorder::inline(
            self.debug_recorder.enabled,
            self.debug_recorder.function_name.clone(),
            self.debug_recorder.call_depth().saturating_add(1),
            frame_id,
        );
        // Inline params are not stack-mapped like normal function params; materialize
        // them as variable updates at the inline entry virtual step.
        debug_recorder.record_inline_param_updates(function, &env, call_span, call_offset)?;
        let mut callee_compiler = FunctionBodyCompiler {
            builder: &mut *self.builder,
            options: self.options,
            debug_recorder: &mut debug_recorder,
            contract_constants: self.contract_constants,
            functions: self.functions,
            function_order: self.function_order,
            function_index: callee_index,
            script_size: self.script_size,
            inline_frame_counter: self.inline_frame_counter,
        };
        let body_len = function.body.len();
        for (index, stmt) in function.body.iter().enumerate() {
            if matches!(stmt.kind, StatementKind::Return { .. }) {
                if index != body_len - 1 {
                    return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
                }
                let StatementKind::Return { exprs, .. } = &stmt.kind else { unreachable!() };
                validate_return_types(exprs, &function.return_types, &types)?;
                for expr in exprs {
                    let resolved = resolve_expr(expr.clone(), &env, &mut HashSet::new())?;
                    yields.push(resolved);
                }
                continue;
            }
            callee_compiler.compile_statement(stmt, &mut env, &params, &mut types, &mut yields)?;
        }
        self.inline_frame_counter = callee_compiler.inline_frame_counter;
        drop(callee_compiler);
        // Remap inline-local sequence numbers and merge events/updates back into
        // the parent function recorder.
        self.debug_recorder.merge_inline_events(&debug_recorder);
        self.debug_recorder.record_inline_call_exit(call_span, self.builder.script().len(), name);

        for (name, value) in &env {
            if name.starts_with("__arg_") {
                if let Some(type_name) = types.get(name) {
                    caller_types.entry(name.clone()).or_insert_with(|| type_name.clone());
                }
                caller_env.entry(name.clone()).or_insert_with(|| value.clone());
            }
        }

        Ok(yields)
    }

    fn compile_if_statement(
        &mut self,
        condition: &Expr,
        then_branch: &[Statement],
        else_branch: Option<&[Statement]>,
        env: &mut HashMap<String, Expr>,
        params: &HashMap<String, i64>,
        types: &mut HashMap<String, String>,
        yields: &mut Vec<Expr>,
    ) -> Result<(), CompilerError> {
        let mut stack_depth = 0i64;
        compile_expr(
            condition,
            env,
            params,
            types,
            self.builder,
            self.options,
            &mut HashSet::new(),
            &mut stack_depth,
            self.script_size,
        )?;
        self.builder.add_op(OpIf)?;

        let original_env = env.clone();
        let mut then_env = original_env.clone();
        let mut then_types = types.clone();
        self.compile_block(then_branch, &mut then_env, params, &mut then_types, yields)?;

        let mut else_env = original_env.clone();
        if let Some(else_branch) = else_branch {
            self.builder.add_op(OpElse)?;
            let mut else_types = types.clone();
            self.compile_block(else_branch, &mut else_env, params, &mut else_types, yields)?;
        }

        self.builder.add_op(OpEndIf)?;

        let resolved_condition = resolve_expr(condition.clone(), &original_env, &mut HashSet::new())?;
        merge_env_after_if(env, &original_env, &then_env, &else_env, &resolved_condition);
        Ok(())
    }

    fn compile_block(
        &mut self,
        statements: &[Statement],
        env: &mut HashMap<String, Expr>,
        params: &HashMap<String, i64>,
        types: &mut HashMap<String, String>,
        yields: &mut Vec<Expr>,
    ) -> Result<(), CompilerError> {
        for stmt in statements {
            self.compile_statement(stmt, env, params, types, yields)?;
        }
        Ok(())
    }

    fn compile_for_statement(
        &mut self,
        ident: &str,
        start_expr: &Expr,
        end_expr: &Expr,
        body: &[Statement],
        env: &mut HashMap<String, Expr>,
        params: &HashMap<String, i64>,
        types: &mut HashMap<String, String>,
        yields: &mut Vec<Expr>,
        span: Option<SourceSpan>,
    ) -> Result<(), CompilerError> {
        let start = eval_const_int(start_expr, self.contract_constants)?;
        let end = eval_const_int(end_expr, self.contract_constants)?;
        if end < start {
            return Err(CompilerError::Unsupported("for loop end must be >= start".to_string()));
        }

        let name = ident.to_string();
        let previous = env.get(&name).cloned();
        let previous_type = types.get(&name).cloned();
        types.insert(name.clone(), "int".to_string());
        for value in start..end {
            let index_expr = Expr::Int(value);
            env.insert(name.clone(), index_expr.clone());
            if let Some(sequence) = self.debug_recorder.record_virtual_step(span, self.builder.script().len()) {
                self.debug_recorder.record_variable_updates(
                    vec![(name.clone(), "int".to_string(), index_expr)],
                    self.builder.script().len(),
                    span,
                    sequence,
                );
            }
            self.compile_block(body, env, params, types, yields)?;
        }

        match previous {
            Some(expr) => {
                env.insert(name, expr);
            }
            None => {
                env.remove(&name);
            }
        }
        match previous_type {
            Some(type_name) => {
                types.insert(ident.to_string(), type_name);
            }
            None => {
                types.remove(ident);
            }
        }

        Ok(())
    }
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

/// Compiles a pre-resolved expression for debugger evaluation.
///
/// The debugger uses this to evaluate variables by executing the compiled expression
/// on a shadow VM seeded with the current function parameters.
pub fn compile_debug_expr(
    expr: &Expr,
    params: &HashMap<String, i64>,
    types: &HashMap<String, String>,
) -> Result<Vec<u8>, CompilerError> {
    let env = HashMap::new();
    let mut builder = ScriptBuilder::new();
    let mut stack_depth = 0i64;
    compile_expr(expr, &env, params, types, &mut builder, CompileOptions::default(), &mut HashSet::new(), &mut stack_depth, None)?;
    Ok(builder.drain())
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
    resolve_expr_internal(expr, env, visiting, true)
}

pub(super) fn resolve_expr_for_debug(
    expr: Expr,
    env: &HashMap<String, Expr>,
    visiting: &mut HashSet<String>,
) -> Result<Expr, CompilerError> {
    resolve_expr_internal(expr, env, visiting, false)
}

fn resolve_expr_internal(
    expr: Expr,
    env: &HashMap<String, Expr>,
    visiting: &mut HashSet<String>,
    preserve_inline_args: bool,
) -> Result<Expr, CompilerError> {
    match expr {
        Expr::Identifier(name) => {
            if preserve_inline_args && name.starts_with("__arg_") {
                return Ok(Expr::Identifier(name));
            }
            if let Some(value) = env.get(&name) {
                if !visiting.insert(name.clone()) {
                    return Err(CompilerError::CyclicIdentifier(name));
                }
                let resolved = resolve_expr_internal(value.clone(), env, visiting, preserve_inline_args)?;
                visiting.remove(&name);
                Ok(resolved)
            } else {
                Ok(Expr::Identifier(name))
            }
        }
        Expr::Unary { op, expr } => {
            Ok(Expr::Unary { op, expr: Box::new(resolve_expr_internal(*expr, env, visiting, preserve_inline_args)?) })
        }
        Expr::Binary { op, left, right } => Ok(Expr::Binary {
            op,
            left: Box::new(resolve_expr_internal(*left, env, visiting, preserve_inline_args)?),
            right: Box::new(resolve_expr_internal(*right, env, visiting, preserve_inline_args)?),
        }),
        Expr::IfElse { condition, then_expr, else_expr } => Ok(Expr::IfElse {
            condition: Box::new(resolve_expr_internal(*condition, env, visiting, preserve_inline_args)?),
            then_expr: Box::new(resolve_expr_internal(*then_expr, env, visiting, preserve_inline_args)?),
            else_expr: Box::new(resolve_expr_internal(*else_expr, env, visiting, preserve_inline_args)?),
        }),
        Expr::Array(values) => {
            let mut resolved = Vec::with_capacity(values.len());
            for value in values {
                resolved.push(resolve_expr_internal(value, env, visiting, preserve_inline_args)?);
            }
            Ok(Expr::Array(resolved))
        }
        Expr::Call { name, args } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr_internal(arg, env, visiting, preserve_inline_args)?);
            }
            Ok(Expr::Call { name, args: resolved })
        }
        Expr::New { name, args } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr_internal(arg, env, visiting, preserve_inline_args)?);
            }
            Ok(Expr::New { name, args: resolved })
        }
        Expr::Split { source, index, part } => Ok(Expr::Split {
            source: Box::new(resolve_expr_internal(*source, env, visiting, preserve_inline_args)?),
            index: Box::new(resolve_expr_internal(*index, env, visiting, preserve_inline_args)?),
            part,
        }),
        Expr::ArrayIndex { source, index } => Ok(Expr::ArrayIndex {
            source: Box::new(resolve_expr_internal(*source, env, visiting, preserve_inline_args)?),
            index: Box::new(resolve_expr_internal(*index, env, visiting, preserve_inline_args)?),
        }),
        Expr::Slice { source, start, end } => Ok(Expr::Slice {
            source: Box::new(resolve_expr_internal(*source, env, visiting, preserve_inline_args)?),
            start: Box::new(resolve_expr_internal(*start, env, visiting, preserve_inline_args)?),
            end: Box::new(resolve_expr_internal(*end, env, visiting, preserve_inline_args)?),
        }),
        Expr::Introspection { kind, index } => {
            Ok(Expr::Introspection { kind, index: Box::new(resolve_expr_internal(*index, env, visiting, preserve_inline_args)?) })
        }
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
            "OpSha256" => compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpSHA256, script_size),
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
                compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxSubnetId, script_size)
            }
            "OpTxGas" => compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxGas, script_size),
            "OpTxPayloadLen" => {
                compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxPayloadLen, script_size)
            }
            "OpTxPayloadSubstr" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpTxPayloadSubstr, script_size)
            }
            "OpOutpointTxId" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpOutpointTxId, script_size)
            }
            "OpOutpointIndex" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpOutpointIndex, script_size)
            }
            "OpTxInputScriptSigLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputScriptSigLen, script_size)
            }
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
                script_size,
            ),
            "OpTxInputSeq" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputSeq, script_size)
            }
            "OpTxInputIsCoinbase" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputIsCoinbase, script_size)
            }
            "OpTxInputSpkLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputSpkLen, script_size)
            }
            "OpTxInputSpkSubstr" => {
                compile_opcode_call(name, args, 3, &scope, builder, options, visiting, stack_depth, OpTxInputSpkSubstr, script_size)
            }
            "OpTxOutputSpkLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxOutputSpkLen, script_size)
            }
            "OpTxOutputSpkSubstr" => {
                compile_opcode_call(name, args, 3, &scope, builder, options, visiting, stack_depth, OpTxOutputSpkSubstr, script_size)
            }
            "OpAuthOutputCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpAuthOutputCount, script_size)
            }
            "OpAuthOutputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpAuthOutputIdx, script_size)
            }
            "OpInputCovenantId" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpInputCovenantId, script_size)
            }
            "OpCovInputCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpCovInputCount, script_size)
            }
            "OpCovInputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpCovInputIdx, script_size)
            }
            "OpCovOutCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpCovOutCount, script_size)
            }
            "OpCovOutputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpCovOutputIdx, script_size)
            }
            "OpNum2Bin" => compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpNum2Bin, script_size),
            "OpBin2Num" => compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpBin2Num, script_size),
            "OpChainblockSeqCommit" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpChainblockSeqCommit, script_size)
            }
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
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    if args.len() != expected_args {
        return Err(CompilerError::Unsupported(format!("{name}() expects {expected_args} argument(s)")));
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
    use super::{CompileOptions, Expr, Op0, OpPushData1, OpPushData2, compile_contract, data_prefix};

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

    #[test]
    fn debug_info_keeps_all_constructor_args() {
        let source = r#"
            pragma silverscript ^0.1.0;
            contract C(int start, int stop, int bias, int minScore) {
                entrypoint function f() { require(start + bias >= minScore); }
            }
        "#;
        let constructor_args = vec![Expr::Int(0), Expr::Int(5), Expr::Int(1), Expr::Int(2)];
        let options = CompileOptions { record_debug_infos: true, ..Default::default() };
        let compiled = compile_contract(source, &constructor_args, options).expect("compile succeeds");
        let debug_info = compiled.debug_info.expect("debug info enabled");
        let constant_names = debug_info.constants.iter().map(|constant| constant.name.as_str()).collect::<Vec<_>>();
        assert_eq!(constant_names, vec!["start", "stop", "bias", "minScore"]);
    }

    #[test]
    fn debug_info_records_for_index_updates() {
        let source = r#"
            pragma silverscript ^0.1.0;
            contract C() {
                entrypoint function f() {
                    int sum = 0;
                    for (i, 0, 3) {
                        sum = sum + i;
                    }
                    require(sum >= 0);
                }
            }
        "#;
        let options = CompileOptions { record_debug_infos: true, ..Default::default() };
        let compiled = compile_contract(source, &[], options).expect("compile succeeds");
        let debug_info = compiled.debug_info.expect("debug info enabled");

        let index_values = debug_info
            .variable_updates
            .iter()
            .filter(|update| update.function == "f" && update.name == "i")
            .filter_map(|update| match update.expr {
                Expr::Int(value) => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(index_values, vec![0, 1, 2]);
    }
}
