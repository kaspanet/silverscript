use std::collections::{HashMap, HashSet};

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::{ScriptBuilder, ScriptBuilderError};
use pest::Parser;
use pest::iterators::Pair;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::parser::{Rule, SilverScriptParser};

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

#[derive(Debug)]
pub struct CompiledContract {
    pub contract_name: String,
    pub function_name: String,
    pub script: Vec<u8>,
    pub ast: ContractAst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAst {
    pub name: String,
    pub params: Vec<String>,
    pub constants: HashMap<String, Expr>,
    pub functions: Vec<FunctionAst>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAst {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Statement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Statement {
    VariableDefinition { type_name: String, modifiers: Vec<String>, name: String, expr: Expr },
    TupleAssignment { left_type: String, left_name: String, right_type: String, right_name: String, expr: Expr },
    Assign { name: String, expr: Expr },
    TimeOp { tx_var: TimeVar, expr: Expr, message: Option<String> },
    Require { expr: Expr, message: Option<String> },
    If { condition: Expr, then_branch: Vec<Statement>, else_branch: Option<Vec<Statement>> },
    For { ident: String, start: Expr, end: Expr, body: Vec<Statement> },
    Yield { expr: Expr },
    Console { args: Vec<ConsoleArg> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ConsoleArg {
    Identifier(String),
    Literal(Expr),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeVar {
    ThisAge,
    TxTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Expr {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Identifier(String),
    Array(Vec<Expr>),
    Call { name: String, args: Vec<Expr> },
    New { name: String, args: Vec<Expr> },
    Split { source: Box<Expr>, index: Box<Expr>, part: SplitPart },
    Unary { op: UnaryOp, expr: Box<Expr> },
    Binary { op: BinaryOp, left: Box<Expr>, right: Box<Expr> },
    Nullary(NullaryOp),
    Introspection { kind: IntrospectionKind, index: Box<Expr> },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitPart {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryOp {
    Or,
    And,
    BitOr,
    BitXor,
    BitAnd,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullaryOp {
    ActiveInputIndex,
    ActiveBytecode,
    TxInputsLength,
    TxOutputsLength,
    TxVersion,
    TxLockTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntrospectionKind {
    InputValue,
    InputLockingBytecode,
    OutputValue,
    OutputLockingBytecode,
}

pub fn compile_contract(source: &str, options: CompileOptions) -> Result<CompiledContract, CompilerError> {
    let contract = parse_contract_ast(source)?;
    compile_contract_ast(&contract, options)
}

pub fn compile_contract_ast(contract: &ContractAst, options: CompileOptions) -> Result<CompiledContract, CompilerError> {
    if contract.functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no functions".to_string()));
    }

    if options.without_selector && contract.functions.len() != 1 {
        return Err(CompilerError::Unsupported("without_selector requires a single function".to_string()));
    }

    let mut compiled_functions = Vec::new();
    for func in &contract.functions {
        compiled_functions.push(compile_function(func, &contract.params, &contract.constants, options)?);
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

    Ok(CompiledContract { contract_name: contract.name.clone(), function_name: "dispatch".to_string(), script, ast: contract.clone() })
}

pub fn function_branch_index(contract: &ContractAst, function_name: &str) -> Result<i64, CompilerError> {
    contract
        .functions
        .iter()
        .position(|func| func.name == function_name)
        .map(|index| index as i64)
        .ok_or_else(|| CompilerError::Unsupported(format!("function '{function_name}' not found")))
}

pub fn parse_contract_ast(source: &str) -> Result<ContractAst, CompilerError> {
    let mut pairs = SilverScriptParser::parse(Rule::source_file, source)?;
    let source_pair = pairs.next().ok_or_else(|| CompilerError::Unsupported("empty source".to_string()))?;
    let mut contract = None;

    for pair in source_pair.into_inner() {
        if pair.as_rule() == Rule::contract_definition {
            contract = Some(parse_contract_definition(pair)?);
        }
    }

    contract.ok_or_else(|| CompilerError::Unsupported("no contract definition".to_string()))
}

fn compile_function(
    function: &FunctionAst,
    contract_params: &[String],
    contract_constants: &HashMap<String, Expr>,
    options: CompileOptions,
) -> Result<(String, Vec<u8>), CompilerError> {
    let mut param_names = contract_params.to_vec();
    param_names.extend(function.params.iter().cloned());
    let param_count = param_names.len();
    let params =
        param_names.into_iter().enumerate().map(|(index, name)| (name, (param_count - 1 - index) as i64)).collect::<HashMap<_, _>>();

    let mut env: HashMap<String, Expr> = contract_constants.clone();
    let mut builder = ScriptBuilder::new();
    let mut yields: Vec<Expr> = Vec::new();

    for stmt in &function.body {
        compile_statement(stmt, &mut env, &params, &mut builder, options, contract_constants, &mut yields)?;
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
            compile_expr(expr, &env, &params, &mut builder, options, &mut HashSet::new(), &mut stack_depth)?;
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
            compile_expr(expr, env, params, builder, options, &mut HashSet::new(), &mut stack_depth)?;
            builder.add_op(OpVerify)?;
            Ok(())
        }
        Statement::TimeOp { tx_var, expr, .. } => compile_time_op_statement(tx_var, expr, env, params, builder, options),
        Statement::If { condition, then_branch, else_branch } => compile_if_statement(
            condition,
            then_branch,
            else_branch.as_deref(),
            env,
            params,
            builder,
            options,
            contract_constants,
            yields,
        ),
        Statement::For { ident, start, end, body } => {
            compile_for_statement(ident, start, end, body, env, params, builder, options, contract_constants, yields)
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
        Statement::Assign { .. } | Statement::Console { .. } => {
            Err(CompilerError::Unsupported("statement type not supported in compiler yet".to_string()))
        }
    }
}

fn compile_if_statement(
    condition: &Expr,
    then_branch: &[Statement],
    else_branch: Option<&[Statement]>,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    yields: &mut Vec<Expr>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(condition, env, params, builder, options, &mut HashSet::new(), &mut stack_depth)?;
    builder.add_op(OpIf)?;

    compile_block(then_branch, env, params, builder, options, contract_constants, yields)?;

    if let Some(else_branch) = else_branch {
        builder.add_op(OpElse)?;
        compile_block(else_branch, env, params, builder, options, contract_constants, yields)?;
    }

    builder.add_op(OpEndIf)?;
    Ok(())
}

fn compile_time_op_statement(
    tx_var: &TimeVar,
    expr: &Expr,
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(expr, env, params, builder, options, &mut HashSet::new(), &mut stack_depth)?;

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
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr>,
    yields: &mut Vec<Expr>,
) -> Result<(), CompilerError> {
    for stmt in statements {
        compile_statement(stmt, env, params, builder, options, contract_constants, yields)?;
    }
    Ok(())
}

fn compile_for_statement(
    ident: &str,
    start_expr: &Expr,
    end_expr: &Expr,
    body: &[Statement],
    env: &mut HashMap<String, Expr>,
    params: &HashMap<String, i64>,
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
        compile_block(body, env, params, builder, options, contract_constants, yields)?;
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

fn parse_contract_definition(pair: Pair<'_, Rule>) -> Result<ContractAst, CompilerError> {
    let mut inner = pair.into_inner();
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing contract name".to_string()))?;
    let params_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing contract parameters".to_string()))?;
    let params = parse_parameter_list(params_pair)?;

    let mut functions = Vec::new();
    let mut constants: HashMap<String, Expr> = HashMap::new();

    for item_pair in inner {
        if item_pair.as_rule() != Rule::contract_item {
            continue;
        }
        let mut item_inner = item_pair.into_inner();
        if let Some(inner_item) = item_inner.next() {
            match inner_item.as_rule() {
                Rule::function_definition => {
                    functions.push(parse_function_definition(inner_item)?);
                }
                Rule::constant_definition => {
                    let mut const_inner = inner_item.into_inner();
                    let _type_name =
                        const_inner.next().ok_or_else(|| CompilerError::Unsupported("missing constant type".to_string()))?;
                    let name_pair =
                        const_inner.next().ok_or_else(|| CompilerError::Unsupported("missing constant name".to_string()))?;
                    let expr_pair =
                        const_inner.next().ok_or_else(|| CompilerError::Unsupported("missing constant initializer".to_string()))?;
                    let expr = parse_expression(expr_pair)?;
                    constants.insert(name_pair.as_str().to_string(), expr);
                }
                _ => {}
            }
        }
    }

    Ok(ContractAst { name: name_pair.as_str().to_string(), params, constants, functions })
}

fn parse_function_definition(pair: Pair<'_, Rule>) -> Result<FunctionAst, CompilerError> {
    let mut inner = pair.into_inner();
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function name".to_string()))?;
    let params_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function parameters".to_string()))?;
    let params = parse_parameter_list(params_pair)?;

    let mut body = Vec::new();
    for stmt in inner {
        body.push(parse_statement(stmt)?);
    }

    Ok(FunctionAst { name: name_pair.as_str().to_string(), params, body })
}

fn parse_statement(pair: Pair<'_, Rule>) -> Result<Statement, CompilerError> {
    match pair.as_rule() {
        Rule::statement => {
            if let Some(inner) = pair.into_inner().next() {
                parse_statement(inner)
            } else {
                Err(CompilerError::Unsupported("empty statement".to_string()))
            }
        }
        Rule::variable_definition => {
            let mut inner = pair.into_inner();
            let type_name =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing variable type".to_string()))?.as_str().to_string();

            let mut modifiers = Vec::new();
            while let Some(p) = inner.peek() {
                if p.as_rule() != Rule::modifier {
                    break;
                }
                modifiers.push(inner.next().expect("checked").as_str().to_string());
            }

            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing variable name".to_string()))?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing variable initializer".to_string()))?;
            let expr = parse_expression(expr_pair)?;
            Ok(Statement::VariableDefinition { type_name, modifiers, name: ident.as_str().to_string(), expr })
        }
        Rule::tuple_assignment => {
            let mut inner = pair.into_inner();
            let left_type =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing left tuple type".to_string()))?.as_str().to_string();
            let left_ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing left tuple name".to_string()))?;
            let right_type =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing right tuple type".to_string()))?.as_str().to_string();
            let right_ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing right tuple name".to_string()))?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing tuple expression".to_string()))?;

            let expr = parse_expression(expr_pair)?;
            Ok(Statement::TupleAssignment {
                left_type,
                left_name: left_ident.as_str().to_string(),
                right_type,
                right_name: right_ident.as_str().to_string(),
                expr,
            })
        }
        Rule::assign_statement => {
            let mut inner = pair.into_inner();
            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing assignment name".to_string()))?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing assignment expression".to_string()))?;
            let expr = parse_expression(expr_pair)?;
            Ok(Statement::Assign { name: ident.as_str().to_string(), expr })
        }
        Rule::time_op_statement => {
            let mut inner = pair.into_inner();
            let tx_var = inner.next().ok_or_else(|| CompilerError::Unsupported("missing time op variable".to_string()))?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing time op expression".to_string()))?;
            let message = inner.next().map(parse_require_message).transpose()?;

            let expr = parse_expression(expr_pair)?;
            let tx_var = match tx_var.as_str() {
                "this.age" => TimeVar::ThisAge,
                "tx.time" => TimeVar::TxTime,
                other => return Err(CompilerError::Unsupported(format!("unsupported time variable: {other}"))),
            };
            Ok(Statement::TimeOp { tx_var, expr, message })
        }
        Rule::require_statement => {
            let mut inner = pair.into_inner();
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing require expression".to_string()))?;
            let message = inner.next().map(parse_require_message).transpose()?;
            let expr = parse_expression(expr_pair)?;
            Ok(Statement::Require { expr, message })
        }
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let cond_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing if condition".to_string()))?;
            let cond_expr = parse_expression(cond_pair)?;
            let then_block = inner.next().ok_or_else(|| CompilerError::Unsupported("missing if block".to_string()))?;
            let then_branch = parse_block(then_block)?;
            let else_branch = inner.next().map(parse_block).transpose()?;
            Ok(Statement::If { condition: cond_expr, then_branch, else_branch })
        }
        Rule::for_statement => {
            let mut inner = pair.into_inner();
            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop identifier".to_string()))?;
            let start_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop start".to_string()))?;
            let end_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop end".to_string()))?;
            let block_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop body".to_string()))?;

            let start_expr = parse_expression(start_pair)?;
            let end_expr = parse_expression(end_pair)?;
            let body = parse_block(block_pair)?;

            Ok(Statement::For { ident: ident.as_str().to_string(), start: start_expr, end: end_expr, body })
        }
        Rule::yield_statement => {
            let mut inner = pair.into_inner();
            let list_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing yield arguments".to_string()))?;
            let args = parse_expression_list(list_pair)?;
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("yield() expects a single argument".to_string()));
            }
            Ok(Statement::Yield { expr: args[0].clone() })
        }
        Rule::console_statement => {
            let mut inner = pair.into_inner();
            let list_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing console arguments".to_string()))?;
            let args = parse_console_parameter_list(list_pair)?;
            Ok(Statement::Console { args })
        }
        _ => Err(CompilerError::Unsupported(format!("unexpected statement: {:?}", pair.as_rule()))),
    }
}

fn parse_block(pair: Pair<'_, Rule>) -> Result<Vec<Statement>, CompilerError> {
    match pair.as_rule() {
        Rule::block => {
            let mut statements = Vec::new();
            for stmt in pair.into_inner() {
                statements.push(parse_statement(stmt)?);
            }
            Ok(statements)
        }
        _ => Ok(vec![parse_statement(pair)?]),
    }
}

fn parse_console_parameter_list(pair: Pair<'_, Rule>) -> Result<Vec<ConsoleArg>, CompilerError> {
    let mut args = Vec::new();
    for param in pair.into_inner() {
        let value = if param.as_rule() == Rule::console_parameter { single_inner(param)? } else { param };
        match value.as_rule() {
            Rule::Identifier => args.push(ConsoleArg::Identifier(value.as_str().to_string())),
            Rule::literal => args.push(ConsoleArg::Literal(parse_literal(single_inner(value)?)?)),
            _ => return Err(CompilerError::Unsupported("console.log arguments not supported".to_string())),
        }
    }
    Ok(args)
}

fn parse_require_message(pair: Pair<'_, Rule>) -> Result<String, CompilerError> {
    let inner = single_inner(pair)?;
    match parse_string_literal(inner)? {
        Expr::String(value) => Ok(value),
        _ => Err(CompilerError::Unsupported("require message must be a string literal".to_string())),
    }
}

fn parse_expression(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    match pair.as_rule() {
        Rule::expression => parse_expression(single_inner(pair)?),
        Rule::logical_or => parse_infix(pair, parse_expression, map_logical_or),
        Rule::logical_and => parse_infix(pair, parse_expression, map_logical_and),
        Rule::bit_or => parse_infix(pair, parse_expression, map_bit_or),
        Rule::bit_xor => parse_infix(pair, parse_expression, map_bit_xor),
        Rule::bit_and => parse_infix(pair, parse_expression, map_bit_and),
        Rule::equality => parse_infix(pair, parse_expression, map_equality),
        Rule::comparison => parse_infix(pair, parse_expression, map_comparison),
        Rule::term => parse_infix(pair, parse_expression, map_term),
        Rule::factor => parse_infix(pair, parse_expression, map_factor),
        Rule::unary => parse_unary(pair),
        Rule::postfix => parse_postfix(pair),
        Rule::primary => parse_primary(single_inner(pair)?),
        Rule::parenthesized => parse_expression(single_inner(pair)?),
        Rule::literal => parse_literal(single_inner(pair)?),
        Rule::number_literal => parse_number_literal(pair),
        Rule::NumberLiteral => parse_number(pair.as_str()),
        Rule::BooleanLiteral => Ok(Expr::Bool(pair.as_str() == "true")),
        Rule::HexLiteral => parse_hex_literal(pair.as_str()),
        Rule::Identifier => Ok(Expr::Identifier(pair.as_str().to_string())),
        Rule::NullaryOp => parse_nullary(pair.as_str()),
        Rule::introspection => parse_introspection(pair),
        Rule::array => parse_array(pair),
        Rule::function_call => parse_function_call(pair),
        Rule::instantiation => parse_instantiation(pair),
        Rule::cast => parse_cast(pair),
        Rule::split_call
        | Rule::slice_call
        | Rule::tuple_index
        | Rule::unary_suffix
        | Rule::StringLiteral
        | Rule::DateLiteral
        | Rule::Bytes
        | Rule::type_name => Err(CompilerError::Unsupported(format!("expression not supported: {:?}", pair.as_rule()))),
        _ => Err(CompilerError::Unsupported(format!("unexpected expression: {:?}", pair.as_rule()))),
    }
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

fn parse_unary(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let mut ops = Vec::new();
    while let Some(op) = inner.peek() {
        if op.as_rule() != Rule::unary_op {
            break;
        }
        let op = inner.next().expect("checked").as_str();
        let op = match op {
            "!" => UnaryOp::Not,
            "-" => UnaryOp::Neg,
            _ => return Err(CompilerError::Unsupported(format!("unary operator '{op}'"))),
        };
        ops.push(op);
    }

    let mut expr = parse_expression(inner.next().ok_or_else(|| CompilerError::Unsupported("missing unary operand".to_string()))?)?;
    for op in ops.into_iter().rev() {
        expr = Expr::Unary { op, expr: Box::new(expr) };
    }
    Ok(expr)
}

fn parse_postfix(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let primary = inner.next().ok_or_else(|| CompilerError::Unsupported("missing primary in postfix".to_string()))?;
    let mut expr = parse_primary(primary)?;
    for postfix in inner {
        match postfix.as_rule() {
            Rule::split_call => {
                let mut split_inner = postfix.into_inner();
                let index_expr = split_inner.next().ok_or_else(|| CompilerError::Unsupported("missing split index".to_string()))?;
                let index = Box::new(parse_expression(index_expr)?);
                expr = Expr::Split { source: Box::new(expr), index, part: SplitPart::Left };
            }
            Rule::tuple_index => {
                let mut index_inner = postfix.into_inner();
                let index_expr = index_inner.next().ok_or_else(|| CompilerError::Unsupported("missing tuple index".to_string()))?;
                let index = match parse_expression(index_expr)? {
                    Expr::Int(value) => value,
                    _ => return Err(CompilerError::Unsupported("tuple index must be a literal integer".to_string())),
                };
                match (&expr, index) {
                    (Expr::Split { source, index: split_index, .. }, 0) => {
                        expr = Expr::Split { source: source.clone(), index: split_index.clone(), part: SplitPart::Left };
                    }
                    (Expr::Split { source, index: split_index, .. }, 1) => {
                        expr = Expr::Split { source: source.clone(), index: split_index.clone(), part: SplitPart::Right };
                    }
                    _ => return Err(CompilerError::Unsupported("tuple indexing only supports split() results".to_string())),
                }
            }
            _ => {
                return Err(CompilerError::Unsupported("postfix operators are not supported".to_string()));
            }
        }
    }
    Ok(expr)
}

fn parse_parameter_list(pair: Pair<'_, Rule>) -> Result<Vec<String>, CompilerError> {
    let mut names = Vec::new();
    for param in pair.into_inner() {
        if param.as_rule() != Rule::parameter {
            continue;
        }
        let mut inner = param.into_inner();
        let _type_name = inner.next().ok_or_else(|| CompilerError::Unsupported("missing parameter type".to_string()))?;
        let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing parameter name".to_string()))?;
        names.push(ident.as_str().to_string());
    }
    Ok(names)
}

fn parse_primary(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    match pair.as_rule() {
        Rule::parenthesized => parse_expression(single_inner(pair)?),
        Rule::literal => parse_literal(single_inner(pair)?),
        Rule::Identifier => Ok(Expr::Identifier(pair.as_str().to_string())),
        Rule::NullaryOp => parse_nullary(pair.as_str()),
        Rule::introspection => parse_introspection(pair),
        Rule::array => parse_array(pair),
        Rule::function_call => parse_function_call(pair),
        Rule::instantiation => parse_instantiation(pair),
        Rule::cast => parse_cast(pair),
        Rule::expression => parse_expression(pair),
        _ => Err(CompilerError::Unsupported(format!("primary not supported: {:?}", pair.as_rule()))),
    }
}

fn parse_literal(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    match pair.as_rule() {
        Rule::BooleanLiteral => Ok(Expr::Bool(pair.as_str() == "true")),
        Rule::number_literal => parse_number_literal(pair),
        Rule::NumberLiteral => parse_number(pair.as_str()),
        Rule::HexLiteral => parse_hex_literal(pair.as_str()),
        Rule::StringLiteral => parse_string_literal(pair),
        Rule::DateLiteral => Err(CompilerError::Unsupported("date literals are not supported".to_string())),
        _ => Err(CompilerError::Unsupported(format!("literal not supported: {:?}", pair.as_rule()))),
    }
}

fn parse_number(raw: &str) -> Result<Expr, CompilerError> {
    let cleaned = raw.replace('_', "");
    let value: i64 = cleaned.parse().map_err(|_| CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")))?;
    Ok(Expr::Int(value))
}

fn parse_array(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut values = Vec::new();
    for expr_pair in pair.into_inner() {
        values.push(parse_expression(expr_pair)?);
    }
    Ok(Expr::Array(values))
}

fn parse_function_call(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let name = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function name".to_string()))?.as_str().to_string();
    let args = match inner.next() {
        Some(list) => parse_expression_list(list)?,
        None => Vec::new(),
    };
    Ok(Expr::Call { name, args })
}

fn parse_instantiation(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let name = inner.next().ok_or_else(|| CompilerError::Unsupported("missing constructor name".to_string()))?.as_str().to_string();
    let args = match inner.next() {
        Some(list) => parse_expression_list(list)?,
        None => Vec::new(),
    };
    Ok(Expr::New { name, args })
}

fn parse_expression_list(pair: Pair<'_, Rule>) -> Result<Vec<Expr>, CompilerError> {
    let mut args = Vec::new();
    for expr_pair in pair.into_inner() {
        args.push(parse_expression(expr_pair)?);
    }
    Ok(args)
}

fn parse_cast(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let type_name = inner.next().ok_or_else(|| CompilerError::Unsupported("missing cast type".to_string()))?.as_str().to_string();
    let args = match inner.next() {
        Some(list) => parse_expression_list(list)?,
        None => Vec::new(),
    };
    if type_name == "bytes" {
        return Ok(Expr::Call { name: "bytes".to_string(), args });
    }
    if type_name == "int" {
        return Ok(Expr::Call { name: "int".to_string(), args });
    }
    if let Some(size) = type_name.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
        return Ok(Expr::Call { name: format!("bytes{size}"), args });
    }
    Err(CompilerError::Unsupported(format!("cast type not supported: {type_name}")))
}
fn parse_number_literal(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let number = inner.next().ok_or_else(|| CompilerError::InvalidLiteral("missing number literal".to_string()))?;
    if inner.next().is_some() {
        return Err(CompilerError::Unsupported("number units are not supported yet".to_string()));
    }
    parse_number(number.as_str())
}

fn parse_hex_literal(raw: &str) -> Result<Expr, CompilerError> {
    let trimmed = raw.trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() % 2 != 0 {
        return Err(CompilerError::InvalidLiteral(format!("hex literal has odd length: {raw}")));
    }
    let bytes = (0..trimmed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompilerError::InvalidLiteral(format!("invalid hex literal '{raw}'")))?;
    Ok(Expr::Bytes(bytes))
}

fn parse_string_literal(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let raw = pair.as_str();
    let unquoted = if raw.starts_with('"') && raw.ends_with('"') || raw.starts_with('\'') && raw.ends_with('\'') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    let unescaped = unquoted.replace("\\\"", "\"").replace("\\'", "'");
    Ok(Expr::String(unescaped))
}
fn parse_nullary(raw: &str) -> Result<Expr, CompilerError> {
    let op = match raw {
        "this.activeInputIndex" => NullaryOp::ActiveInputIndex,
        "this.activeBytecode" => NullaryOp::ActiveBytecode,
        "tx.inputs.length" => NullaryOp::TxInputsLength,
        "tx.outputs.length" => NullaryOp::TxOutputsLength,
        "tx.version" => NullaryOp::TxVersion,
        "tx.locktime" => NullaryOp::TxLockTime,
        _ => return Err(CompilerError::Unsupported(format!("unknown nullary op: {raw}"))),
    };
    Ok(Expr::Nullary(op))
}

fn parse_introspection(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let text = pair.as_str();
    let mut inner = pair.into_inner();
    let index_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing introspection index".to_string()))?;
    let field_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing introspection field".to_string()))?;

    let index = Box::new(parse_expression(index_pair)?);
    let field = field_pair.as_str();

    let kind = if text.starts_with("tx.inputs") {
        match field {
            ".value" => IntrospectionKind::InputValue,
            ".lockingBytecode" => IntrospectionKind::InputLockingBytecode,
            _ => return Err(CompilerError::Unsupported(format!("input field '{field}' not supported"))),
        }
    } else if text.starts_with("tx.outputs") {
        match field {
            ".value" => IntrospectionKind::OutputValue,
            ".lockingBytecode" => IntrospectionKind::OutputLockingBytecode,
            _ => return Err(CompilerError::Unsupported(format!("output field '{field}' not supported"))),
        }
    } else {
        return Err(CompilerError::Unsupported("unknown introspection root".to_string()));
    };

    Ok(Expr::Introspection { kind, index })
}

fn single_inner(pair: Pair<'_, Rule>) -> Result<Pair<'_, Rule>, CompilerError> {
    pair.into_inner().next().ok_or_else(|| CompilerError::Unsupported("expected inner pair".to_string()))
}

fn parse_infix<F, G>(pair: Pair<'_, Rule>, mut parse_operand: F, mut map_op: G) -> Result<Expr, CompilerError>
where
    F: FnMut(Pair<'_, Rule>) -> Result<Expr, CompilerError>,
    G: FnMut(Pair<'_, Rule>) -> Result<BinaryOp, CompilerError>,
{
    let mut inner = pair.into_inner();
    let first = inner.next().ok_or_else(|| CompilerError::Unsupported("missing infix operand".to_string()))?;
    let mut expr = parse_operand(first)?;

    while let Some(op_pair) = inner.next() {
        let rhs = inner.next().ok_or_else(|| CompilerError::Unsupported("missing infix rhs".to_string()))?;
        let op = map_op(op_pair)?;
        let rhs_expr = parse_operand(rhs)?;
        expr = Expr::Binary { op, left: Box::new(expr), right: Box::new(rhs_expr) };
    }

    Ok(expr)
}

fn map_logical_or(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::logical_or_op => Ok(BinaryOp::Or),
        _ => Err(CompilerError::Unsupported("unexpected logical_or operator".to_string())),
    }
}

fn map_logical_and(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::logical_and_op => Ok(BinaryOp::And),
        _ => Err(CompilerError::Unsupported("unexpected logical_and operator".to_string())),
    }
}

fn map_bit_or(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::bit_or_op => Ok(BinaryOp::BitOr),
        _ => Err(CompilerError::Unsupported("unexpected bit_or operator".to_string())),
    }
}

fn map_bit_xor(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::bit_xor_op => Ok(BinaryOp::BitXor),
        _ => Err(CompilerError::Unsupported("unexpected bit_xor operator".to_string())),
    }
}

fn map_bit_and(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::bit_and_op => Ok(BinaryOp::BitAnd),
        _ => Err(CompilerError::Unsupported("unexpected bit_and operator".to_string())),
    }
}

fn map_equality(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::equality_op => match pair.as_str() {
            "==" => Ok(BinaryOp::Eq),
            "!=" => Ok(BinaryOp::Ne),
            _ => Err(CompilerError::Unsupported("unexpected equality operator".to_string())),
        },
        _ => Err(CompilerError::Unsupported("unexpected equality operator".to_string())),
    }
}

fn map_comparison(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::comparison_op => match pair.as_str() {
            "<" => Ok(BinaryOp::Lt),
            "<=" => Ok(BinaryOp::Le),
            ">" => Ok(BinaryOp::Gt),
            ">=" => Ok(BinaryOp::Ge),
            _ => Err(CompilerError::Unsupported("unexpected comparison operator".to_string())),
        },
        _ => Err(CompilerError::Unsupported("unexpected comparison operator".to_string())),
    }
}

fn map_term(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::term_op => match pair.as_str() {
            "+" => Ok(BinaryOp::Add),
            "-" => Ok(BinaryOp::Sub),
            _ => Err(CompilerError::Unsupported("unexpected term operator".to_string())),
        },
        _ => Err(CompilerError::Unsupported("unexpected term operator".to_string())),
    }
}

fn map_factor(pair: Pair<'_, Rule>) -> Result<BinaryOp, CompilerError> {
    match pair.as_rule() {
        Rule::factor_op => match pair.as_str() {
            "*" => Ok(BinaryOp::Mul),
            "/" => Ok(BinaryOp::Div),
            "%" => Ok(BinaryOp::Mod),
            _ => Err(CompilerError::Unsupported("unexpected factor operator".to_string())),
        },
        _ => Err(CompilerError::Unsupported("unexpected factor operator".to_string())),
    }
}

struct CompilationScope<'a> {
    env: &'a HashMap<String, Expr>,
    params: &'a HashMap<String, i64>,
}

fn compile_expr(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
) -> Result<(), CompilerError> {
    let scope = CompilationScope { env, params };
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
        Expr::String(_) => Err(CompilerError::Unsupported("string literals are only supported via bytes(...)".to_string())),
        Expr::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return Err(CompilerError::CyclicIdentifier(name.clone()));
            }
            if let Some(expr) = env.get(name) {
                compile_expr(expr, env, params, builder, options, visiting, stack_depth)?;
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
        Expr::Array(_) => Err(CompilerError::Unsupported("array literals are only supported in LockingBytecodeNullData".to_string())),
        Expr::Call { name, args } => match name.as_str() {
            "OpSha256" => compile_opcode_call(name, args, 1, &scope, builder, options, visiting, stack_depth, OpSHA256, false),
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
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("bytes() expects a single argument".to_string()));
                }
                match &args[0] {
                    Expr::String(value) => {
                        builder.add_data(value.as_bytes())?;
                        *stack_depth += 1;
                        Ok(())
                    }
                    _ => Err(CompilerError::Unsupported("bytes() only supports string literals".to_string())),
                }
            }
            "int" => {
                if args.len() != 1 {
                    return Err(CompilerError::Unsupported("int() expects a single argument".to_string()));
                }
                compile_expr(&args[0], env, params, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, builder, options, visiting, stack_depth)?;
                compile_expr(&args[1], env, params, builder, options, visiting, stack_depth)?;
                builder.add_op(OpCheckSig)?;
                *stack_depth -= 1;
                Ok(())
            }
            "checkDataSig" => {
                for arg in args {
                    compile_expr(arg, env, params, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, builder, options, visiting, stack_depth)?;
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
                compile_expr(&args[0], env, params, builder, options, visiting, stack_depth)?;
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
            compile_expr(expr, env, params, builder, options, visiting, stack_depth)?;
            match op {
                UnaryOp::Not => builder.add_op(OpNot)?,
                UnaryOp::Neg => builder.add_op(OpNegate)?,
            };
            Ok(())
        }
        Expr::Binary { op, left, right } => {
            let bytes_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne) && (expr_is_bytes(left, env) || expr_is_bytes(right, env));
            let bytes_add = matches!(op, BinaryOp::Add) && (expr_is_bytes(left, env) || expr_is_bytes(right, env));
            if bytes_add {
                compile_concat_operand(left, env, params, builder, options, visiting, stack_depth)?;
                compile_concat_operand(right, env, params, builder, options, visiting, stack_depth)?;
            } else {
                compile_expr(left, env, params, builder, options, visiting, stack_depth)?;
                compile_expr(right, env, params, builder, options, visiting, stack_depth)?;
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
            let split_index = match &**index {
                Expr::Int(value) => *value,
                _ => return Err(CompilerError::Unsupported("split() index must be a literal integer".to_string())),
            };
            if split_index < 0 {
                return Err(CompilerError::Unsupported("split() index must be non-negative".to_string()));
            }
            compile_expr(source, env, params, builder, options, visiting, stack_depth)?;
            match part {
                SplitPart::Left => {
                    builder.add_i64(0)?;
                    *stack_depth += 1;
                    builder.add_i64(split_index)?;
                    *stack_depth += 1;
                    builder.add_op(OpSubstr)?;
                    *stack_depth -= 2;
                }
                SplitPart::Right => {
                    builder.add_op(OpSize)?;
                    *stack_depth += 1;
                    builder.add_i64(split_index)?;
                    *stack_depth += 1;
                    builder.add_op(OpSwap)?;
                    builder.add_op(OpSubstr)?;
                    *stack_depth -= 2;
                }
            }
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
            compile_expr(index, env, params, builder, options, visiting, stack_depth)?;
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

fn expr_is_bytes(expr: &Expr, env: &HashMap<String, Expr>) -> bool {
    match expr {
        Expr::Bytes(_) => true,
        Expr::String(_) => true,
        Expr::New { name, .. } => {
            matches!(name.as_str(), "LockingBytecodeNullData" | "LockingBytecodeP2PKH" | "LockingBytecodeP2SH20")
        }
        Expr::Call { name, .. } => {
            matches!(
                name.as_str(),
                "bytes"
                    | "blake2b"
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
        Expr::Binary { op: BinaryOp::Add, left, right } => expr_is_bytes(left, env) || expr_is_bytes(right, env),
        Expr::Introspection { kind, .. } => {
            matches!(kind, IntrospectionKind::InputLockingBytecode | IntrospectionKind::OutputLockingBytecode)
        }
        Expr::Nullary(NullaryOp::ActiveBytecode) => true,
        Expr::Identifier(name) => env.get(name).map(|e| expr_is_bytes(e, env)).unwrap_or(false),
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
        compile_expr(arg, scope.env, scope.params, builder, options, visiting, stack_depth)?;
    }
    builder.add_op(opcode)?;
    *stack_depth += 1 - expected_args as i64;
    Ok(())
}

fn compile_concat_operand(
    expr: &Expr,
    env: &HashMap<String, Expr>,
    params: &HashMap<String, i64>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
) -> Result<(), CompilerError> {
    compile_expr(expr, env, params, builder, options, visiting, stack_depth)?;
    if !expr_is_bytes(expr, env) {
        builder.add_i64(1)?;
        *stack_depth += 1;
        builder.add_op(OpNum2Bin)?;
        *stack_depth -= 1;
    }
    Ok(())
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
