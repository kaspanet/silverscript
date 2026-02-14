use std::collections::HashMap;

use pest::Parser;
use pest::iterators::Pair;
use serde::{Deserialize, Serialize};

use crate::compiler::CompilerError;
use crate::parser::{Rule, SilverScriptParser};
use chrono::NaiveDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAst {
    pub name: String,
    pub params: Vec<ParamAst>,
    pub constants: HashMap<String, Expr>,
    pub functions: Vec<FunctionAst>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSpan {
    pub line: u32,
    pub col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl SourceSpan {
    pub fn from_span(span: pest::Span<'_>) -> Self {
        let (line, col) = span.start_pos().line_col();
        let (end_line, end_col) = span.end_pos().line_col();
        Self { line: line as u32, col: col as u32, end_line: end_line as u32, end_col: end_col as u32 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAst {
    pub name: String,
    pub params: Vec<ParamAst>,
    #[serde(default)]
    pub entrypoint: bool,
    #[serde(default)]
    pub return_types: Vec<String>,
    pub body: Vec<Statement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamAst {
    pub type_name: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(skip)]
    pub span: Option<SourceSpan>,
    #[serde(flatten)]
    pub kind: StatementKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum StatementKind {
    VariableDefinition { type_name: String, modifiers: Vec<String>, name: String, expr: Option<Expr> },
    TupleAssignment { left_type: String, left_name: String, right_type: String, right_name: String, expr: Expr },
    ArrayPush { name: String, expr: Expr },
    FunctionCall { name: String, args: Vec<Expr> },
    FunctionCallAssign { bindings: Vec<ParamAst>, name: String, args: Vec<Expr> },
    Assign { name: String, expr: Expr },
    TimeOp { tx_var: TimeVar, expr: Expr, message: Option<String> },
    Require { expr: Expr, message: Option<String> },
    If { condition: Expr, then_branch: Vec<Statement>, else_branch: Option<Vec<Statement>> },
    For { ident: String, start: Expr, end: Expr, body: Vec<Statement> },
    Yield { expr: Expr },
    Return { exprs: Vec<Expr> },
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    Slice { source: Box<Expr>, start: Box<Expr>, end: Box<Expr> },
    ArrayIndex { source: Box<Expr>, index: Box<Expr> },
    Unary { op: UnaryOp, expr: Box<Expr> },
    Binary { op: BinaryOp, left: Box<Expr>, right: Box<Expr> },
    IfElse { condition: Box<Expr>, then_expr: Box<Expr>, else_expr: Box<Expr> },
    Nullary(NullaryOp),
    Introspection { kind: IntrospectionKind, index: Box<Expr> },
}

impl From<i64> for Expr {
    fn from(value: i64) -> Self {
        Expr::Int(value)
    }
}

impl From<bool> for Expr {
    fn from(value: bool) -> Self {
        Expr::Bool(value)
    }
}

impl From<Vec<u8>> for Expr {
    fn from(value: Vec<u8>) -> Self {
        Expr::Bytes(value)
    }
}

impl From<String> for Expr {
    fn from(value: String) -> Self {
        Expr::String(value)
    }
}

impl From<Vec<i64>> for Expr {
    fn from(value: Vec<i64>) -> Self {
        Expr::Array(value.into_iter().map(Expr::Int).collect())
    }
}

impl From<Vec<Vec<u8>>> for Expr {
    fn from(value: Vec<Vec<u8>>) -> Self {
        Expr::Array(value.into_iter().map(Expr::Bytes).collect())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SplitPart {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NullaryOp {
    ActiveInputIndex,
    ActiveBytecode,
    ThisScriptSize,
    ThisScriptSizeDataPrefix,
    TxInputsLength,
    TxOutputsLength,
    TxVersion,
    TxLockTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IntrospectionKind {
    InputValue,
    InputLockingBytecode,
    OutputValue,
    OutputLockingBytecode,
}

fn validate_user_identifier(name: &str) -> Result<(), CompilerError> {
    if name.starts_with("__") {
        return Err(CompilerError::Unsupported("identifier cannot start with '__'".to_string()));
    }
    Ok(())
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

fn parse_contract_definition(pair: Pair<'_, Rule>) -> Result<ContractAst, CompilerError> {
    let mut inner = pair.into_inner();
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing contract name".to_string()))?;
    let params_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing contract parameters".to_string()))?;
    let params = parse_typed_parameter_list(params_pair)?;

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
                    validate_user_identifier(name_pair.as_str())?;
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
    let mut entrypoint = false;
    let name_pair = match inner.next() {
        Some(pair) if pair.as_rule() == Rule::entrypoint => {
            entrypoint = true;
            inner.next().ok_or_else(|| CompilerError::Unsupported("missing function name".to_string()))?
        }
        Some(pair) => pair,
        None => return Err(CompilerError::Unsupported("missing function name".to_string())),
    };
    let params_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function parameters".to_string()))?;
    let params = parse_typed_parameter_list(params_pair)?;
    let mut return_types = Vec::new();
    if let Some(next) = inner.peek() {
        if next.as_rule() == Rule::return_type_list {
            let return_pair = inner.next().expect("checked");
            return_types = parse_return_type_list(return_pair)?;
        }
    }

    let mut body = Vec::new();
    for stmt in inner {
        body.push(parse_statement(stmt)?);
    }

    Ok(FunctionAst { name: name_pair.as_str().to_string(), params, entrypoint, return_types, body })
}

fn parse_statement(pair: Pair<'_, Rule>) -> Result<Statement, CompilerError> {
    if pair.as_rule() == Rule::statement {
        return if let Some(inner) = pair.into_inner().next() {
            parse_statement(inner)
        } else {
            Err(CompilerError::Unsupported("empty statement".to_string()))
        };
    }

    let span = Some(SourceSpan::from_span(pair.as_span()));

    let kind = match pair.as_rule() {
        Rule::variable_definition => {
            let mut inner = pair.into_inner();
            let type_name = inner
                .next()
                .ok_or_else(|| CompilerError::Unsupported("missing variable type".to_string()))?
                .as_str()
                .trim()
                .to_string();

            let mut modifiers = Vec::new();
            while let Some(p) = inner.peek() {
                if p.as_rule() != Rule::modifier {
                    break;
                }
                modifiers.push(inner.next().expect("checked").as_str().to_string());
            }

            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing variable name".to_string()))?;
            validate_user_identifier(ident.as_str())?;
            let expr = inner.next().map(parse_expression).transpose()?;
            StatementKind::VariableDefinition { type_name, modifiers, name: ident.as_str().to_string(), expr }
        }
        Rule::tuple_assignment => {
            let mut inner = pair.into_inner();
            let left_type =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing left tuple type".to_string()))?.as_str().to_string();
            let left_ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing left tuple name".to_string()))?;
            let right_type =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing right tuple type".to_string()))?.as_str().to_string();
            let right_ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing right tuple name".to_string()))?;
            validate_user_identifier(left_ident.as_str())?;
            validate_user_identifier(right_ident.as_str())?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing tuple expression".to_string()))?;

            let expr = parse_expression(expr_pair)?;
            StatementKind::TupleAssignment {
                left_type,
                left_name: left_ident.as_str().to_string(),
                right_type,
                right_name: right_ident.as_str().to_string(),
                expr,
            }
        }
        Rule::push_statement => {
            let mut inner = pair.into_inner();
            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing push target".to_string()))?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing push expression".to_string()))?;
            let expr = parse_expression(expr_pair)?;
            StatementKind::ArrayPush { name: ident.as_str().to_string(), expr }
        }
        Rule::assign_statement => {
            let mut inner = pair.into_inner();
            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing assignment name".to_string()))?;
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing assignment expression".to_string()))?;
            let expr = parse_expression(expr_pair)?;
            StatementKind::Assign { name: ident.as_str().to_string(), expr }
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
            StatementKind::TimeOp { tx_var, expr, message }
        }
        Rule::require_statement => {
            let mut inner = pair.into_inner();
            let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing require expression".to_string()))?;
            let message = inner.next().map(parse_require_message).transpose()?;
            let expr = parse_expression(expr_pair)?;
            StatementKind::Require { expr, message }
        }
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let cond_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing if condition".to_string()))?;
            let cond_expr = parse_expression(cond_pair)?;
            let then_block = inner.next().ok_or_else(|| CompilerError::Unsupported("missing if block".to_string()))?;
            let then_branch = parse_block(then_block)?;
            let else_branch = inner.next().map(parse_block).transpose()?;
            StatementKind::If { condition: cond_expr, then_branch, else_branch }
        }
        Rule::call_statement => {
            let mut inner = pair.into_inner();
            let call_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function call".to_string()))?;
            match parse_function_call(call_pair)? {
                Expr::Call { name, args } => StatementKind::FunctionCall { name, args },
                _ => return Err(CompilerError::Unsupported("function call expected".to_string())),
            }
        }
        Rule::function_call_assignment => {
            let mut bindings = Vec::new();
            let mut call_pair = None;
            for item in pair.into_inner() {
                if item.as_rule() == Rule::typed_binding {
                    let mut inner = item.into_inner();
                    let type_name = inner
                        .next()
                        .ok_or_else(|| CompilerError::Unsupported("missing binding type".to_string()))?
                        .as_str()
                        .trim()
                        .to_string();
                    let name = inner
                        .next()
                        .ok_or_else(|| CompilerError::Unsupported("missing binding name".to_string()))?
                        .as_str()
                        .to_string();
                    validate_user_identifier(&name)?;
                    bindings.push(ParamAst { type_name, name });
                } else if item.as_rule() == Rule::function_call {
                    call_pair = Some(item);
                }
            }
            let call_pair = call_pair.ok_or_else(|| CompilerError::Unsupported("missing function call".to_string()))?;
            match parse_function_call(call_pair)? {
                Expr::Call { name, args } => StatementKind::FunctionCallAssign { bindings, name, args },
                _ => return Err(CompilerError::Unsupported("function call expected".to_string())),
            }
        }
        Rule::for_statement => {
            let mut inner = pair.into_inner();
            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop identifier".to_string()))?;
            validate_user_identifier(ident.as_str())?;
            let start_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop start".to_string()))?;
            let end_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop end".to_string()))?;
            let block_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop body".to_string()))?;

            let start_expr = parse_expression(start_pair)?;
            let end_expr = parse_expression(end_pair)?;
            let body = parse_block(block_pair)?;

            StatementKind::For { ident: ident.as_str().to_string(), start: start_expr, end: end_expr, body }
        }
        Rule::yield_statement => {
            let mut inner = pair.into_inner();
            let list_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing yield arguments".to_string()))?;
            let args = parse_expression_list(list_pair)?;
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("yield() expects a single argument".to_string()));
            }
            StatementKind::Yield { expr: args[0].clone() }
        }
        Rule::return_statement => {
            let mut inner = pair.into_inner();
            let list_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing return arguments".to_string()))?;
            let args = parse_expression_list(list_pair)?;
            if args.is_empty() {
                return Err(CompilerError::Unsupported("return() expects at least one argument".to_string()));
            }
            StatementKind::Return { exprs: args }
        }
        Rule::console_statement => {
            let mut inner = pair.into_inner();
            let list_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing console arguments".to_string()))?;
            let args = parse_console_parameter_list(list_pair)?;
            StatementKind::Console { args }
        }
        _ => return Err(CompilerError::Unsupported(format!("unexpected statement: {:?}", pair.as_rule()))),
    };

    Ok(Statement { span, kind })
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
            Rule::slice_call => {
                let mut slice_inner = postfix.into_inner();
                let start_expr = slice_inner.next().ok_or_else(|| CompilerError::Unsupported("missing slice start".to_string()))?;
                let end_expr = slice_inner.next().ok_or_else(|| CompilerError::Unsupported("missing slice end".to_string()))?;
                let start = Box::new(parse_expression(start_expr)?);
                let end = Box::new(parse_expression(end_expr)?);
                expr = Expr::Slice { source: Box::new(expr), start, end };
            }
            Rule::tuple_index => {
                let mut index_inner = postfix.into_inner();
                let index_expr = index_inner.next().ok_or_else(|| CompilerError::Unsupported("missing tuple index".to_string()))?;
                let index = parse_expression(index_expr)?;
                match (&expr, &index) {
                    (Expr::Split { source, index: split_index, .. }, Expr::Int(0)) => {
                        expr = Expr::Split { source: source.clone(), index: split_index.clone(), part: SplitPart::Left };
                    }
                    (Expr::Split { source, index: split_index, .. }, Expr::Int(1)) => {
                        expr = Expr::Split { source: source.clone(), index: split_index.clone(), part: SplitPart::Right };
                    }
                    (Expr::Split { .. }, _) => {
                        return Err(CompilerError::Unsupported("tuple index must be 0 or 1".to_string()));
                    }
                    _ => {
                        expr = Expr::ArrayIndex { source: Box::new(expr), index: Box::new(index) };
                    }
                }
            }
            Rule::unary_suffix => {
                let text = postfix.as_str();
                if text.ends_with("length") {
                    expr = Expr::Call { name: "length".to_string(), args: vec![expr] };
                } else {
                    return Err(CompilerError::Unsupported("postfix operators are not supported".to_string()));
                }
            }
            _ => {
                return Err(CompilerError::Unsupported("postfix operators are not supported".to_string()));
            }
        }
    }
    Ok(expr)
}

fn parse_typed_parameter_list(pair: Pair<'_, Rule>) -> Result<Vec<ParamAst>, CompilerError> {
    let mut params = Vec::new();
    for param in pair.into_inner() {
        if param.as_rule() != Rule::parameter {
            continue;
        }
        let mut inner = param.into_inner();
        let type_name =
            inner.next().ok_or_else(|| CompilerError::Unsupported("missing parameter type".to_string()))?.as_str().trim().to_string();
        let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing parameter name".to_string()))?.as_str().to_string();
        validate_user_identifier(&ident)?;
        params.push(ParamAst { type_name, name: ident });
    }
    Ok(params)
}

fn parse_return_type_list(pair: Pair<'_, Rule>) -> Result<Vec<String>, CompilerError> {
    let mut types = Vec::new();
    for item in pair.into_inner() {
        if item.as_rule() == Rule::type_name {
            types.push(item.as_str().trim().to_string());
        }
    }
    Ok(types)
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
        Rule::DateLiteral => parse_date_literal(pair),
        _ => Err(CompilerError::Unsupported(format!("literal not supported: {:?}", pair.as_rule()))),
    }
}

fn parse_number(raw: &str) -> Result<Expr, CompilerError> {
    let cleaned = raw.replace('_', "");
    if let Some((base_str, exp_str)) = cleaned.split_once('e').or_else(|| cleaned.split_once('E')) {
        if exp_str.is_empty() {
            return Err(CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")));
        }
        let base: i64 = base_str.parse().map_err(|_| CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")))?;
        let exp: i64 = exp_str.parse().map_err(|_| CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")))?;
        if exp < 0 {
            return Err(CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")));
        }
        let pow = 10i128.pow(exp as u32);
        let value =
            (base as i128).checked_mul(pow).ok_or_else(|| CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")))?;
        if value > i64::MAX as i128 || value < i64::MIN as i128 {
            return Err(CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")));
        }
        return Ok(Expr::Int(value as i64));
    }
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
    if type_name == "byte" {
        return Ok(Expr::Call { name: "bytes1".to_string(), args });
    }
    if type_name == "int" {
        return Ok(Expr::Call { name: "int".to_string(), args });
    }
    if matches!(type_name.as_str(), "sig" | "pubkey" | "datasig") {
        return Ok(Expr::Call { name: type_name, args });
    }
    if let Some(size) = type_name.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
        return Ok(Expr::Call { name: format!("bytes{size}"), args });
    }
    Err(CompilerError::Unsupported(format!("cast type not supported: {type_name}")))
}

fn parse_number_literal(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let mut inner = pair.into_inner();
    let number = inner.next().ok_or_else(|| CompilerError::InvalidLiteral("missing number literal".to_string()))?;
    let value = parse_number(number.as_str())?;
    if let Some(unit_pair) = inner.next() {
        let unit = unit_pair.as_str();
        return apply_number_unit(value, unit);
    }
    Ok(value)
}

fn parse_hex_literal(raw: &str) -> Result<Expr, CompilerError> {
    let trimmed = raw.trim_start_matches("0x").trim_start_matches("0X");
    let normalized = if trimmed.len() % 2 != 0 { format!("0{trimmed}") } else { trimmed.to_string() };
    let bytes = (0..normalized.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&normalized[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompilerError::InvalidLiteral(format!("invalid hex literal '{raw}'")))?;
    Ok(Expr::Bytes(bytes))
}

fn apply_number_unit(expr: Expr, unit: &str) -> Result<Expr, CompilerError> {
    let value = match expr {
        Expr::Int(value) => value,
        _ => return Err(CompilerError::InvalidLiteral("number literal is not an int".to_string())),
    };
    let multiplier = match unit {
        "seconds" => 1,
        "minutes" => 60,
        "hours" => 60 * 60,
        "days" => 24 * 60 * 60,
        "weeks" => 7 * 24 * 60 * 60,
        "litras" => 1,
        "grains" => 100_000,
        "kas" => 100_000_000,
        _ => return Err(CompilerError::Unsupported(format!("number unit '{unit}' not supported"))),
    };
    Ok(Expr::Int(value.saturating_mul(multiplier)))
}

fn parse_date_literal(pair: Pair<'_, Rule>) -> Result<Expr, CompilerError> {
    let raw = pair.as_str();
    let start = raw
        .find('"')
        .or_else(|| raw.find('\''))
        .ok_or_else(|| CompilerError::InvalidLiteral("date literal missing quotes".to_string()))?;
    let quote = raw.as_bytes()[start] as char;
    let end = raw[start + 1..]
        .find(quote)
        .map(|idx| idx + start + 1)
        .ok_or_else(|| CompilerError::InvalidLiteral("date literal missing closing quote".to_string()))?;
    let value = &raw[start + 1..end];

    let timestamp = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S")
        .map_err(|_| CompilerError::InvalidLiteral("invalid date literal".to_string()))?
        .and_utc()
        .timestamp();
    Ok(Expr::Int(timestamp))
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
        "this.scriptSize" => NullaryOp::ThisScriptSize,
        "this.scriptSizeDataPrefix" => NullaryOp::ThisScriptSizeDataPrefix,
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
