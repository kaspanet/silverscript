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

    let mut compiled_functions = Vec::new();
    for func in &contract.functions {
        compiled_functions.push(compile_function(func, &constants, options)?);
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

    let abi = build_function_abi(contract);
    Ok(CompiledContract {
        contract_name: contract.name.clone(),
        script,
        ast: contract.clone(),
        abi,
        without_selector: options.without_selector,
    })
}

fn expr_matches_type(expr: &Expr, type_name: &str) -> bool {
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
        for arg in args {
            push_sigscript_arg(&mut builder, arg)?;
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
    constants: &HashMap<String, Expr>,
    options: CompileOptions,
) -> Result<(String, Vec<u8>), CompilerError> {
    let param_count = function.params.len();
    let params = function
        .params
        .iter()
        .map(|param| param.name.clone())
        .enumerate()
        .map(|(index, name)| (name, (param_count - 1 - index) as i64))
        .collect::<HashMap<_, _>>();
    let param_types = function.params.iter().map(|param| (param.name.clone(), param.type_name.clone())).collect::<HashMap<_, _>>();
    let mut env: HashMap<String, Expr> = constants.clone();
    let mut builder = ScriptBuilder::new();
    let mut yields: Vec<Expr> = Vec::new();

    for stmt in &function.body {
        compile_statement(stmt, &mut env, &params, &param_types, &mut builder, options, constants, &mut yields)?;
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
            compile_expr(expr, &env, &params, &param_types, &mut builder, options, &mut HashSet::new(), &mut stack_depth)?;
        }
        for _ in 0..param_count {
            builder.add_i64(yield_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
    }
    Ok((function.name.clone(), builder.drain()))
}

fn compile_statement(
    stmt: &Statement,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    yields: &mut Vec<Expr>,
) -> Result<(), CompilerError> {
    match stmt {
        Statement::VariableDefinition { name, expr, .. } => {
            env.insert(name.clone(), expr.clone());
            Ok(())
        }
        Statement::Require { expr, .. } => {
            let mut stack_depth = 0i64;
            compile_expr(expr, env, params, param_types, builder, options, &mut HashSet::new(), &mut stack_depth)?;
            builder.add_op(OpVerify)?;
            Ok(())
        }
        Statement::TimeOp { tx_var, expr, .. } => compile_time_op_statement(tx_var, expr, env, params, param_types, builder, options),
        Statement::If { condition, then_branch, else_branch } => compile_if_statement(
            condition,
            then_branch,
            else_branch.as_deref(),
            env,
            params,
            param_types,
            builder,
            options,
            contract_constants,
            yields,
        ),
        Statement::For { ident, start, end, body } => {
            compile_for_statement(ident, start, end, body, env, params, param_types, builder, options, contract_constants, yields)
        }
        Statement::Yield { expr } => {
            let mut visiting = HashSet::new();
            let resolved = resolve_expr(expr.clone(), env, &mut visiting)?;
            yields.push(resolved);
            Ok(())
        }
        Statement::TupleAssignment { left_name, right_name, expr, .. } => match expr.clone() {
            Expr::Split { source, index, .. } => {
                env.insert(left_name.clone(), Expr::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left });
                env.insert(right_name.clone(), Expr::Split { source, index, part: SplitPart::Right });
                Ok(())
            }
            _ => Err(CompilerError::Unsupported("tuple assignment only supports split()".to_string())),
        },
        Statement::Assign { name, expr } => {
            let updated = if let Some(previous) = env.get(name) { replace_identifier(expr, name, previous) } else { expr.clone() };
            let resolved = resolve_expr(updated, env, &mut HashSet::new())?;
            env.insert(name.clone(), resolved);
            Ok(())
        }
        Statement::Console { .. } => Ok(()),
    }
}

fn compile_if_statement(
    condition: &Expr,
    then_branch: &[Statement],
    else_branch: Option<&[Statement]>,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    yields: &mut Vec<Expr>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(condition, env, params, param_types, builder, options, &mut HashSet::new(), &mut stack_depth)?;
    builder.add_op(OpIf)?;

    let original_env = env.clone();
    let mut then_env = original_env.clone();
    compile_block(then_branch, &mut then_env, params, param_types, builder, options, contract_constants, yields)?;

    let mut else_env = original_env.clone();
    if let Some(else_branch) = else_branch {
        builder.add_op(OpElse)?;
        compile_block(else_branch, &mut else_env, params, param_types, builder, options, contract_constants, yields)?;
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
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(expr, env, params, param_types, builder, options, &mut HashSet::new(), &mut stack_depth)?;

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

fn compile_block(
    statements: &[Statement],
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    yields: &mut Vec<Expr>,
) -> Result<(), CompilerError> {
    for stmt in statements {
        compile_statement(stmt, env, params, param_types, builder, options, contract_constants, yields)?;
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
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    yields: &mut Vec<Expr>,
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
        compile_block(body, env, params, param_types, builder, options, contract_constants, yields)?;
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
    param_types: &'a HashMap<String, String>,
}

fn compile_expr(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
) -> Result<(), CompilerError> {
    let scope = CompilationScope { env, params, param_types };
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
                compile_expr(expr, env, params, param_types, builder, options, visiting, stack_depth)?;
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
            compile_expr(condition, env, params, param_types, builder, options, visiting, stack_depth)?;
            builder.add_op(OpIf)?;
            *stack_depth -= 1;
            let depth_before = *stack_depth;
            compile_expr(then_expr, env, params, param_types, builder, options, visiting, stack_depth)?;
            builder.add_op(OpElse)?;
            *stack_depth = depth_before;
            compile_expr(else_expr, env, params, param_types, builder, options, visiting, stack_depth)?;
            builder.add_op(OpEndIf)?;
            *stack_depth = depth_before + 1;
            Ok(())
        }
        Expr::Array(_) => Err(CompilerError::Unsupported("array literals are only supported in LockingBytecodeNullData".to_string())),
        Expr::Call { name, args } => match name.as_str() {
            "OpSha256" => compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpSHA256, false),
            "sha256" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("sha256() expects a single argument".to_string()));
                }
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
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
            "OpTxSubnetId" => compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxSubnetId, true),
            "OpTxGas" => compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxGas, true),
            "OpTxPayloadLen" => {
                compile_opcode_call(name, args, 0, &scope, builder, options, visiting, stack_depth, OpTxPayloadLen, true)
            }
            "OpTxPayloadSubstr" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpTxPayloadSubstr, true)
            }
            "OpOutpointTxId" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpOutpointTxId, true)
            }
            "OpOutpointIndex" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpOutpointIndex, true)
            }
            "OpTxInputScriptSigLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputScriptSigLen, true)
            }
            "OpTxInputScriptSigSubstr" => {
                compile_opcode_call(name, args, 3, &scope, builder, options, visiting, stack_depth, OpTxInputScriptSigSubstr, true)
            }
            "OpTxInputSeq" => compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputSeq, true),
            "OpTxInputIsCoinbase" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputIsCoinbase, true)
            }
            "OpTxInputSpkLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxInputSpkLen, true)
            }
            "OpTxInputSpkSubstr" => {
                compile_opcode_call(name, args, 3, &scope, builder, options, visiting, stack_depth, OpTxInputSpkSubstr, true)
            }
            "OpTxOutputSpkLen" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpTxOutputSpkLen, true)
            }
            "OpTxOutputSpkSubstr" => {
                compile_opcode_call(name, args, 3, &scope, builder, options, visiting, stack_depth, OpTxOutputSpkSubstr, true)
            }
            "OpAuthOutputCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpAuthOutputCount, true)
            }
            "OpAuthOutputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpAuthOutputIdx, true)
            }
            "OpInputCovenantId" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpInputCovenantId, true)
            }
            "OpCovInputCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpCovInputCount, true)
            }
            "OpCovInputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpCovInputIdx, true)
            }
            "OpCovOutCount" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpCovOutCount, true)
            }
            "OpCovOutputIdx" => {
                compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpCovOutputIdx, true)
            }
            "OpNum2Bin" => compile_opcode_call(name, args, 2, &scope, builder, options, visiting, stack_depth, OpNum2Bin, true),
            "OpBin2Num" => compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpBin2Num, true),
            "OpChainblockSeqCommit" => {
                compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpChainblockSeqCommit, false)
            }
            "bytes" => {
                if args.is_empty() || args.len() > 2 {
                    return Err(CompilerError::Unsupported("bytes() expects one or two arguments".to_string()));
                }
                if args.len() == 2 {
                    compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                    compile_expr(&args[1], env, params, param_types, builder, options, visiting, stack_depth)?;
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
                        if expr_is_bytes(&args[0], env, param_types) {
                            compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                            return Ok(());
                        }
                        compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                        builder.add_i64(8)?;
                        *stack_depth += 1;
                        builder.add_op(OpNum2Bin)?;
                        *stack_depth -= 1;
                        Ok(())
                    }
                    _ => {
                        if expr_is_bytes(&args[0], env, param_types) {
                            compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                            Ok(())
                        } else {
                            compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                builder.add_op(OpSize)?;
                Ok(())
            }
            "int" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("int() expects a single argument".to_string()));
                }
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                Ok(())
            }
            "sig" | "pubkey" | "datasig" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
                }
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                builder.add_op(OpBlake2b)?;
                builder.add_i64(0)?;
                *stack_depth += 1;
                builder.add_i64(20)?;
                *stack_depth += 1;
                builder.add_op(OpSubstr)?;
                *stack_depth -= 2;
                Ok(())
            }
            "checkSig" => {
                if args.len() != 2 {
                    return Err(CompilerError::Unsupported("checkSig() expects 2 arguments".to_string()));
                }
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                compile_expr(&args[1], env, params, param_types, builder, options, visiting, stack_depth)?;
                builder.add_op(OpCheckSig)?;
                *stack_depth -= 1;
                Ok(())
            }
            "checkDataSig" => {
                // TODO: Remove this stub
                for arg in args {
                    compile_expr(arg, env, params, param_types, builder, options, visiting, stack_depth)?;
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
            "LockingBytecodeP2PKH" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("LockingBytecodeP2PKH expects a single bytes20 argument".to_string()));
                }
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                builder.add_data(&[0x00, 0x00])?;
                *stack_depth += 1;
                builder.add_data(&[OpBlake2b])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[0x14])?;
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
            "LockingBytecodeP2SH20" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("LockingBytecodeP2SH20 expects a single bytes20 argument".to_string()));
                }
                compile_expr(&args[0], env, params, param_types, builder, options, visiting, stack_depth)?;
                builder.add_data(&[0x00, 0x00])?;
                *stack_depth += 1;
                builder.add_data(&[OpBlake2b])?;
                *stack_depth += 1;
                builder.add_op(OpCat)?;
                *stack_depth -= 1;
                builder.add_data(&[0x14])?;
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
            compile_expr(expr, env, params, param_types, builder, options, visiting, stack_depth)?;
            match op {
                UnaryOp::Not => builder.add_op(OpNot)?,
                UnaryOp::Neg => builder.add_op(OpNegate)?,
            };
            Ok(())
        }
        Expr::Binary { op, left, right } => {
            let bytes_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne)
                && (expr_is_bytes(left, env, param_types) || expr_is_bytes(right, env, param_types));
            let bytes_add =
                matches!(op, BinaryOp::Add) && (expr_is_bytes(left, env, param_types) || expr_is_bytes(right, env, param_types));
            if bytes_add {
                compile_concat_operand(left, env, params, param_types, builder, options, visiting, stack_depth)?;
                compile_concat_operand(right, env, params, param_types, builder, options, visiting, stack_depth)?;
            } else {
                compile_expr(left, env, params, param_types, builder, options, visiting, stack_depth)?;
                compile_expr(right, env, params, param_types, builder, options, visiting, stack_depth)?;
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
            compile_expr(source, env, params, param_types, builder, options, visiting, stack_depth)?;
            match part {
                SplitPart::Left => {
                    compile_expr(index, env, params, param_types, builder, options, visiting, stack_depth)?;
                    builder.add_i64(0)?;
                    *stack_depth += 1;
                    builder.add_op(OpSwap)?;
                    builder.add_op(OpSubstr)?;
                    *stack_depth -= 2;
                }
                SplitPart::Right => {
                    builder.add_op(OpSize)?;
                    *stack_depth += 1;
                    compile_expr(index, env, params, param_types, builder, options, visiting, stack_depth)?;
                    builder.add_op(OpSwap)?;
                    builder.add_op(OpSubstr)?;
                    *stack_depth -= 2;
                }
            }
            Ok(())
        }
        Expr::Slice { source, start, end } => {
            compile_expr(source, env, params, param_types, builder, options, visiting, stack_depth)?;
            compile_expr(start, env, params, param_types, builder, options, visiting, stack_depth)?;
            compile_expr(end, env, params, param_types, builder, options, visiting, stack_depth)?;

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
            compile_expr(index, env, params, param_types, builder, options, visiting, stack_depth)?;
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

fn expr_is_bytes(expr: &Expr, env: &HashMap<String, Expr>, param_types: &HashMap<String, String>) -> bool {
    let mut visiting = HashSet::new();
    expr_is_bytes_inner(expr, env, param_types, &mut visiting)
}

fn expr_is_bytes_inner(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    param_types: &HashMap<String, String>,
    visiting: &mut HashSet<String>,
) -> bool {
    match expr {
        Expr::Bytes(_) => true,
        Expr::String(_) => true,
        Expr::Slice { .. } => true,
        Expr::New { name, .. } => {
            matches!(name.as_str(), "LockingBytecodeNullData" | "LockingBytecodeP2PKH" | "LockingBytecodeP2SH20")
        }
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
            expr_is_bytes_inner(left, env, param_types, visiting) || expr_is_bytes_inner(right, env, param_types, visiting)
        }
        Expr::IfElse { condition: _, then_expr, else_expr } => {
            expr_is_bytes_inner(then_expr, env, param_types, visiting) && expr_is_bytes_inner(else_expr, env, param_types, visiting)
        }
        Expr::Introspection { kind, .. } => {
            matches!(kind, IntrospectionKind::InputLockingBytecode | IntrospectionKind::OutputLockingBytecode)
        }
        Expr::Nullary(NullaryOp::ActiveBytecode) => true,
        Expr::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return false;
            }
            if let Some(expr) = env.get(name) {
                let result = expr_is_bytes_inner(expr, env, param_types, visiting);
                visiting.remove(name);
                return result;
            }
            visiting.remove(name);
            param_types.get(name).map(|type_name| is_bytes_type(type_name)).unwrap_or(false)
        }
        _ => false,
    }
}

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
) -> Result<(), CompilerError> {
    if args.len() != expected_args {
        return Err(CompilerError::Unsupported(format!("{name}() expects {expected_args} argument(s)")));
    }
    if requires_covenants {
        require_covenants(options, name)?;
    }
    for arg in args {
        compile_expr(arg, scope.env, scope.params, scope.param_types, builder, options, visiting, stack_depth)?;
    }
    builder.add_op(opcode)?;
    *stack_depth += 1 - expected_args as i64;
    Ok(())
}

fn compile_concat_operand(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    param_types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
) -> Result<(), CompilerError> {
    compile_expr(expr, env, params, param_types, builder, options, visiting, stack_depth)?;
    if !expr_is_bytes(expr, env, param_types) {
        builder.add_i64(1)?;
        *stack_depth += 1;
        builder.add_op(OpNum2Bin)?;
        *stack_depth -= 1;
    }
    Ok(())
}

fn is_bytes_type(type_name: &str) -> bool {
    type_name == "bytes" || type_name == "byte" || type_name.starts_with("bytes") || matches!(type_name, "pubkey" | "sig" | "string")
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
