use std::fmt;

use chrono::NaiveDateTime;
use pest::iterators::Pair;
use serde::{Deserialize, Serialize};

use crate::errors::CompilerError;
use crate::parser::{Rule, parse_source_file, parse_type_name as parse_type_name_rule};
pub use crate::span::{Span, SpanUtils};

#[derive(Debug, Clone)]
struct Identifier<'i> {
    name: String,
    span: Span<'i>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAst<'i> {
    pub name: String,
    pub params: Vec<ParamAst<'i>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<ContractFieldAst<'i>>,
    pub constants: Vec<ConstantAst<'i>>,
    pub functions: Vec<FunctionAst<'i>>,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
}

impl<'i> fmt::Display for ContractAst<'i> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pretty = serde_json::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&pretty)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractFieldAst<'i> {
    pub type_ref: TypeRef,
    pub name: String,
    pub expr: Expr<'i>,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub type_span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAst<'i> {
    pub name: String,
    pub params: Vec<ParamAst<'i>>,
    pub entrypoint: bool,
    #[serde(default)]
    pub return_types: Vec<TypeRef>,
    pub body: Vec<Statement<'i>>,
    #[serde(skip_deserializing)]
    pub return_type_spans: Vec<Span<'i>>,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
    #[serde(skip_deserializing)]
    pub body_span: Span<'i>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamAst<'i> {
    pub type_ref: TypeRef,
    pub name: String,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub type_span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateBindingAst<'i> {
    pub field_name: String,
    pub type_ref: TypeRef,
    pub name: String,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub field_span: Span<'i>,
    #[serde(skip_deserializing)]
    pub type_span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeRef {
    pub base: TypeBase,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub array_dims: Vec<ArrayDim>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TypeBase {
    Int,
    Bool,
    String,
    Pubkey,
    Sig,
    Datasig,
    Byte,
}

impl TypeBase {
    pub fn as_str(&self) -> &'static str {
        match self {
            TypeBase::Int => "int",
            TypeBase::Bool => "bool",
            TypeBase::String => "string",
            TypeBase::Pubkey => "pubkey",
            TypeBase::Sig => "sig",
            TypeBase::Datasig => "datasig",
            TypeBase::Byte => "byte",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ArrayDim {
    Dynamic,
    Fixed(usize),
    Constant(String),
}

impl TypeRef {
    pub fn type_name(&self) -> String {
        let mut out = self.base.as_str().to_string();
        for dim in &self.array_dims {
            match dim {
                ArrayDim::Dynamic => out.push_str("[]"),
                ArrayDim::Fixed(size) => out.push_str(&format!("[{size}]")),
                ArrayDim::Constant(name) => out.push_str(&format!("[{name}]")),
            }
        }
        out
    }

    pub fn is_array(&self) -> bool {
        !self.array_dims.is_empty()
    }

    pub fn element_type(&self) -> Option<Self> {
        if self.array_dims.is_empty() {
            return None;
        }
        let mut element = self.clone();
        element.array_dims.pop();
        Some(element)
    }

    pub fn array_size(&self) -> Option<&ArrayDim> {
        self.array_dims.last()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Statement<'i> {
    VariableDefinition {
        type_ref: TypeRef,
        #[serde(default)]
        modifiers: Vec<String>,
        name: String,
        expr: Option<Expr<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        type_span: Span<'i>,
        #[serde(skip_deserializing)]
        modifier_spans: Vec<Span<'i>>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    TupleAssignment {
        left_type_ref: TypeRef,
        left_name: String,
        right_type_ref: TypeRef,
        right_name: String,
        expr: Expr<'i>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        left_type_span: Span<'i>,
        #[serde(skip_deserializing)]
        left_name_span: Span<'i>,
        #[serde(skip_deserializing)]
        right_type_span: Span<'i>,
        #[serde(skip_deserializing)]
        right_name_span: Span<'i>,
    },
    ArrayPush {
        name: String,
        expr: Expr<'i>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    FunctionCall {
        name: String,
        args: Vec<Expr<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    FunctionCallAssign {
        bindings: Vec<ParamAst<'i>>,
        name: String,
        args: Vec<Expr<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    StateFunctionCallAssign {
        bindings: Vec<StateBindingAst<'i>>,
        name: String,
        args: Vec<Expr<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    Assign {
        name: String,
        expr: Expr<'i>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    TimeOp {
        tx_var: TimeVar,
        expr: Expr<'i>,
        message: Option<String>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        tx_var_span: Span<'i>,
        #[serde(skip_deserializing)]
        message_span: Option<Span<'i>>,
    },
    Require {
        expr: Expr<'i>,
        message: Option<String>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        message_span: Option<Span<'i>>,
    },
    If {
        condition: Expr<'i>,
        then_branch: Vec<Statement<'i>>,
        else_branch: Option<Vec<Statement<'i>>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        then_span: Span<'i>,
        #[serde(skip_deserializing)]
        else_span: Option<Span<'i>>,
    },
    For {
        ident: String,
        start: Expr<'i>,
        end: Expr<'i>,
        body: Vec<Statement<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
        #[serde(skip_deserializing)]
        ident_span: Span<'i>,
        #[serde(skip_deserializing)]
        body_span: Span<'i>,
    },
    Yield {
        expr: Expr<'i>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
    },
    Return {
        exprs: Vec<Expr<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
    },
    Console {
        args: Vec<ConsoleArg<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
    },
}

impl<'i> Statement<'i> {
    pub fn span(&self) -> Span<'i> {
        match self {
            Statement::VariableDefinition { span, .. }
            | Statement::TupleAssignment { span, .. }
            | Statement::ArrayPush { span, .. }
            | Statement::FunctionCall { span, .. }
            | Statement::FunctionCallAssign { span, .. }
            | Statement::StateFunctionCallAssign { span, .. }
            | Statement::Assign { span, .. }
            | Statement::Return { span, .. }
            | Statement::TimeOp { span, .. }
            | Statement::Require { span, .. }
            | Statement::If { span, .. }
            | Statement::For { span, .. }
            | Statement::Yield { span, .. }
            | Statement::Console { span, .. } => *span,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ConsoleArg<'i> {
    Identifier(String, #[serde(skip_deserializing)] Span<'i>),
    Literal(Expr<'i>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeVar {
    ThisAge,
    TxTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expr<'i> {
    // TODO: evaluate splitting kind in two:
    //   - actual Expressions
    //   - user defined primitive Values
    #[serde(flatten)]
    pub kind: ExprKind<'i>,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
}

impl<'i> Expr<'i> {
    pub fn new(kind: ExprKind<'i>, span: Span<'i>) -> Self {
        Self { kind, span }
    }

    pub fn int(value: i64) -> Self {
        Self::new(ExprKind::Int(value), Span::default())
    }

    pub fn bool(value: bool) -> Self {
        Self::new(ExprKind::Bool(value), Span::default())
    }

    pub fn byte(value: u8) -> Self {
        Self::new(ExprKind::Byte(value), Span::default())
    }

    pub fn bytes(value: Vec<u8>) -> Self {
        Self::new(ExprKind::Array(value.into_iter().map(Expr::byte).collect()), Span::default())
    }

    pub fn string(value: impl Into<String>) -> Self {
        Self::new(ExprKind::String(value.into()), Span::default())
    }

    pub fn identifier(value: impl Into<String>) -> Self {
        Self::new(ExprKind::Identifier(value.into()), Span::default())
    }

    pub fn call(name: impl Into<String>, args: Vec<Expr<'i>>) -> Self {
        Self::new(ExprKind::Call { name: name.into(), args, name_span: Span::default() }, Span::default())
    }
}

impl<'i> From<i64> for Expr<'i> {
    fn from(value: i64) -> Self {
        Expr::int(value)
    }
}

impl<'i> From<bool> for Expr<'i> {
    fn from(value: bool) -> Self {
        Expr::bool(value)
    }
}

impl<'i> From<Vec<u8>> for Expr<'i> {
    fn from(value: Vec<u8>) -> Self {
        Expr::bytes(value)
    }
}

impl<'i> From<String> for Expr<'i> {
    fn from(value: String) -> Self {
        Expr::string(value)
    }
}

impl<'i> From<&str> for Expr<'i> {
    fn from(value: &str) -> Self {
        Expr::string(value)
    }
}

impl<'i> From<Vec<i64>> for Expr<'i> {
    fn from(values: Vec<i64>) -> Self {
        let exprs = values.into_iter().map(Expr::int).collect();
        Expr::new(ExprKind::Array(exprs), Span::default())
    }
}

impl<'i> From<Vec<Expr<'i>>> for Expr<'i> {
    fn from(values: Vec<Expr<'i>>) -> Self {
        Expr::new(ExprKind::Array(values), Span::default())
    }
}

impl<'i> From<Vec<Vec<u8>>> for Expr<'i> {
    fn from(values: Vec<Vec<u8>>) -> Self {
        let exprs = values.into_iter().map(Expr::bytes).collect();
        Expr::new(ExprKind::Array(exprs), Span::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ExprKind<'i> {
    Int(i64),
    Bool(bool),
    Byte(u8),
    String(String),
    DateLiteral(i64),
    Identifier(String),
    Array(Vec<Expr<'i>>),
    Call {
        name: String,
        args: Vec<Expr<'i>>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    New {
        name: String,
        args: Vec<Expr<'i>>,
        #[serde(skip_deserializing)]
        name_span: Span<'i>,
    },
    Split {
        source: Box<Expr<'i>>,
        index: Box<Expr<'i>>,
        part: SplitPart,
        #[serde(skip_deserializing)]
        span: Span<'i>,
    },
    Slice {
        source: Box<Expr<'i>>,
        start: Box<Expr<'i>>,
        end: Box<Expr<'i>>,
        #[serde(skip_deserializing)]
        span: Span<'i>,
    },
    ArrayIndex {
        source: Box<Expr<'i>>,
        index: Box<Expr<'i>>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr<'i>>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr<'i>>,
        right: Box<Expr<'i>>,
    },
    IfElse {
        condition: Box<Expr<'i>>,
        then_expr: Box<Expr<'i>>,
        else_expr: Box<Expr<'i>>,
    },
    Nullary(NullaryOp),
    Introspection {
        kind: IntrospectionKind,
        index: Box<Expr<'i>>,
        #[serde(skip_deserializing)]
        field_span: Span<'i>,
    },
    StateObject(Vec<StateFieldExpr<'i>>),
    NumberWithUnit {
        value: i64,
        unit: String,
    },
    UnarySuffix {
        source: Box<Expr<'i>>,
        kind: UnarySuffixKind,
        #[serde(skip_deserializing)]
        span: Span<'i>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFieldExpr<'i> {
    pub name: String,
    pub expr: Expr<'i>,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitPart {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullaryOp {
    ActiveInputIndex,
    ActiveScriptPubKey,
    ThisScriptSize,
    ThisScriptSizeDataPrefix,
    TxInputsLength,
    TxOutputsLength,
    TxVersion,
    TxLockTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntrospectionKind {
    InputValue,
    InputScriptPubKey,
    InputSigScript,
    /// not supported yet
    InputOutpointTransactionHash,
    /// not supported yet
    InputOutpointIndex,
    /// not supported yet
    InputSequenceNumber,
    OutputValue,
    OutputScriptPubKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantAst<'i> {
    pub type_ref: TypeRef,
    pub name: String,
    pub expr: Expr<'i>,
    #[serde(skip_deserializing)]
    pub span: Span<'i>,
    #[serde(skip_deserializing)]
    pub type_span: Span<'i>,
    #[serde(skip_deserializing)]
    pub name_span: Span<'i>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnarySuffixKind {
    Reverse,
    Length,
}

pub fn parse_type_ref(type_name: &str) -> Result<TypeRef, CompilerError> {
    let mut pairs = parse_type_name_rule(type_name)?;
    let pair = pairs.next().ok_or_else(|| CompilerError::Unsupported("missing type name".to_string()))?;
    parse_type_name_pair(pair)
}

fn parse_type_name_pair(pair: Pair<'_, Rule>) -> Result<TypeRef, CompilerError> {
    if pair.as_rule() != Rule::type_name {
        return Err(CompilerError::Unsupported("expected type name".to_string()));
    }

    let mut inner = pair.into_inner();
    let base = match inner.next().ok_or_else(|| CompilerError::Unsupported("missing base type".to_string()))?.as_str() {
        "int" => TypeBase::Int,
        "bool" => TypeBase::Bool,
        "string" => TypeBase::String,
        "pubkey" => TypeBase::Pubkey,
        "sig" => TypeBase::Sig,
        "datasig" => TypeBase::Datasig,
        "byte" => TypeBase::Byte,
        other => return Err(CompilerError::Unsupported(format!("unknown base type: {other}"))),
    };

    let mut array_dims = Vec::new();
    for suffix in inner {
        if suffix.as_rule() != Rule::array_suffix {
            continue;
        }
        let mut suffix_inner = suffix.into_inner();
        let dim = match suffix_inner.next() {
            None => ArrayDim::Dynamic,
            Some(size_pair) => match size_pair.as_rule() {
                Rule::array_size => {
                    let raw = size_pair.as_str().trim();
                    if let Ok(size) = raw.parse::<usize>() { ArrayDim::Fixed(size) } else { ArrayDim::Constant(raw.to_string()) }
                }
                Rule::Identifier => ArrayDim::Constant(size_pair.as_str().to_string()),
                _ => return Err(CompilerError::Unsupported("invalid array dimension".to_string())),
            },
        };
        array_dims.push(dim);
    }

    Ok(TypeRef { base, array_dims })
}

pub fn parse_contract_ast<'i>(source: &'i str) -> Result<ContractAst<'i>, CompilerError> {
    let mut pairs = parse_source_file(source)?;
    let source_pair = pairs.next().ok_or_else(|| CompilerError::Unsupported("empty source".to_string()))?;
    let mut contract = None;

    for pair in source_pair.into_inner() {
        if pair.as_rule() == Rule::contract_definition {
            contract = Some(parse_contract_definition(pair)?);
        }
    }

    contract.ok_or_else(|| CompilerError::Unsupported("no contract definition".to_string()))
}

fn parse_contract_definition<'i>(pair: Pair<'i, Rule>) -> Result<ContractAst<'i>, CompilerError> {
    let span = Span::from(pair.as_span());

    let mut inner = pair.into_inner();
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing contract name".to_string()))?;
    let params_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing contract parameters".to_string()))?;

    let Identifier { name, span: name_span } = parse_identifier(name_pair)?;
    let params = parse_typed_parameter_list(params_pair)?;

    let mut functions = Vec::new();
    let mut fields = Vec::new();
    let mut constants = Vec::new();

    for item_pair in inner {
        if item_pair.as_rule() != Rule::contract_item {
            continue;
        }
        let mut item_inner = item_pair.into_inner();
        if let Some(inner_item) = item_inner.next() {
            match inner_item.as_rule() {
                Rule::function_definition => functions.push(parse_function_definition(inner_item)?),
                Rule::contract_field_definition => fields.push(parse_contract_field_definition(inner_item)?),
                Rule::constant_definition => constants.push(parse_constant_definition(inner_item)?),
                _ => {}
            }
        }
    }

    Ok(ContractAst { name, params, fields, constants, functions, span, name_span })
}

fn parse_function_definition<'i>(pair: Pair<'i, Rule>) -> Result<FunctionAst<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();

    let first = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function name".to_string()))?;
    let (entrypoint, name_pair) = if first.as_rule() == Rule::entrypoint {
        let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function name".to_string()))?;
        (true, name_pair)
    } else {
        (false, first)
    };

    let params_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function parameters".to_string()))?;
    let params = parse_typed_parameter_list(params_pair)?;

    let mut return_types = Vec::new();
    let mut return_type_spans = Vec::new();
    if let Some(next) = inner.peek() {
        if next.as_rule() == Rule::return_type_list {
            let return_pair = inner.next().expect("checked");
            let (types, spans) = parse_return_type_list(return_pair)?;
            return_types = types;
            return_type_spans = spans;
        }
    }

    let Identifier { name, span: name_span } = parse_identifier(name_pair)?;

    let mut body = Vec::new();
    let mut body_span: Option<Span<'i>> = None;
    for stmt_pair in inner {
        let stmt = parse_statement(stmt_pair)?;
        let stmt_span = stmt.span();
        body_span = Some(match body_span {
            None => stmt_span,
            Some(prev) => prev.join(&stmt_span),
        });
        body.push(stmt);
    }
    let body_span = body_span.unwrap_or(span);

    Ok(FunctionAst { name, entrypoint, params, return_types, return_type_spans, body, span, name_span, body_span })
}

fn parse_constant_definition<'i>(pair: Pair<'i, Rule>) -> Result<ConstantAst<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();

    let type_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing constant type".to_string()))?;
    let type_span = Span::from(type_pair.as_span());
    let type_ref = parse_type_name_pair(type_pair)?;

    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing constant name".to_string()))?;
    let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing constant initializer".to_string()))?;

    let expr = parse_expression(expr_pair)?;
    let Identifier { name, span: name_span } = parse_identifier(name_pair)?;

    Ok(ConstantAst { type_ref, name, expr, span, type_span, name_span })
}

fn parse_contract_field_definition<'i>(pair: Pair<'i, Rule>) -> Result<ContractFieldAst<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();

    let type_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing field type".to_string()))?;
    let type_span = Span::from(type_pair.as_span());
    let type_ref = parse_type_name_pair(type_pair)?;
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing field name".to_string()))?;
    let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing field initializer".to_string()))?;

    let expr = parse_expression(expr_pair)?;
    let Identifier { name, span: name_span } = parse_identifier(name_pair)?;

    Ok(ContractFieldAst { type_ref, name, expr, span, type_span, name_span })
}

fn parse_statement<'i>(pair: Pair<'i, Rule>) -> Result<Statement<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    match pair.as_rule() {
        Rule::statement => {
            if let Some(inner) = pair.into_inner().next() {
                parse_statement(inner)
            } else {
                Err(CompilerError::Unsupported("empty statement".to_string()).with_span(&span))
            }
        }
        Rule::variable_definition => {
            let mut inner = pair.into_inner();
            let type_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing variable type".to_string()).with_span(&span))?;
            let type_span = Span::from(type_pair.as_span());
            let type_ref = parse_type_name_pair(type_pair).map_err(|err| err.with_span(&span))?;

            let mut modifiers = Vec::new();
            let mut modifier_spans = Vec::new();
            while let Some(p) = inner.peek() {
                if p.as_rule() != Rule::modifier {
                    break;
                }
                let modifier = inner.next().expect("checked");
                modifiers.push(modifier.as_str().to_string());
                modifier_spans.push(Span::from(modifier.as_span()));
            }

            let ident =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing variable name".to_string()).with_span(&span))?;
            let Identifier { name, span: name_span } = parse_identifier(ident).map_err(|err| err.with_span(&span))?;
            let expr = match inner.next() {
                Some(expr_pair) => Some(parse_expression(expr_pair).map_err(|err| err.with_span(&span))?),
                None => None,
            };
            Ok(Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span })
        }
        Rule::tuple_assignment => {
            let mut inner = pair.into_inner();
            let left_type_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing left tuple type".to_string()).with_span(&span))?;
            let left_ident =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing left tuple name".to_string()).with_span(&span))?;
            let right_type_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing right tuple type".to_string()).with_span(&span))?;
            let right_ident =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing right tuple name".to_string()).with_span(&span))?;
            let expr_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing tuple expression".to_string()).with_span(&span))?;

            let Identifier { name: left_name, span: left_name_span } =
                parse_identifier(left_ident).map_err(|err| err.with_span(&span))?;
            let Identifier { name: right_name, span: right_name_span } =
                parse_identifier(right_ident).map_err(|err| err.with_span(&span))?;

            let right_type_span = Span::from(right_type_pair.as_span());
            let right_type_ref = parse_type_name_pair(right_type_pair).map_err(|err| err.with_span(&span))?;

            let left_type_span = Span::from(left_type_pair.as_span());
            let left_type_ref = parse_type_name_pair(left_type_pair).map_err(|err| err.with_span(&span))?;

            let expr = parse_expression(expr_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::TupleAssignment {
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
            })
        }
        Rule::push_statement => {
            let mut inner = pair.into_inner();
            let ident = inner.next().ok_or_else(|| CompilerError::Unsupported("missing push target".to_string()).with_span(&span))?;
            let expr_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing push expression".to_string()).with_span(&span))?;
            let Identifier { name, span: name_span } = parse_identifier(ident).map_err(|err| err.with_span(&span))?;
            let expr = parse_expression(expr_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::ArrayPush { name, expr, span, name_span })
        }
        Rule::function_call_assignment => {
            let mut inner = pair.into_inner();
            let mut bindings = Vec::new();
            while let Some(p) = inner.peek() {
                if p.as_rule() != Rule::typed_binding {
                    break;
                }
                let binding = inner.next().expect("checked");
                bindings.push(parse_typed_binding(binding).map_err(|err| err.with_span(&span))?);
            }
            let call_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing function call".to_string()).with_span(&span))?;
            let (Identifier { name, span: name_span }, args) =
                parse_function_call_parts(call_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::FunctionCallAssign { bindings, name, args, span, name_span })
        }
        Rule::state_function_call_assignment => {
            let mut inner = pair.into_inner();
            let mut bindings = Vec::new();
            while let Some(p) = inner.peek() {
                if p.as_rule() != Rule::state_typed_binding {
                    break;
                }
                let binding = inner.next().expect("checked");
                bindings.push(parse_state_typed_binding(binding).map_err(|err| err.with_span(&span))?);
            }
            let call_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing function call".to_string()).with_span(&span))?;
            let (Identifier { name, span: name_span }, args) =
                parse_function_call_parts(call_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::StateFunctionCallAssign { bindings, name, args, span, name_span })
        }
        Rule::call_statement => {
            let mut inner = pair.into_inner();
            let call_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing call statement".to_string()).with_span(&span))?;
            let (Identifier { name, span: name_span }, args) =
                parse_function_call_parts(call_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::FunctionCall { name, args, span, name_span })
        }
        Rule::assign_statement => {
            let mut inner = pair.into_inner();
            let ident =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing assignment name".to_string()).with_span(&span))?;
            let expr_pair = inner
                .next()
                .ok_or_else(|| CompilerError::Unsupported("missing assignment expression".to_string()).with_span(&span))?;
            let expr = parse_expression(expr_pair).map_err(|err| err.with_span(&span))?;
            let Identifier { name, span: name_span } = parse_identifier(ident).map_err(|err| err.with_span(&span))?;
            Ok(Statement::Assign { name, expr, span, name_span })
        }
        Rule::return_statement => {
            let mut inner = pair.into_inner();
            let list_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing return values".to_string()).with_span(&span))?;
            let exprs = parse_expression_list(list_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::Return { exprs, span })
        }
        Rule::time_op_statement => {
            let mut inner = pair.into_inner();
            let tx_var =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing time op variable".to_string()).with_span(&span))?;
            let expr_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing time op expression".to_string()).with_span(&span))?;
            let message = inner.next().map(parse_require_message).transpose().map_err(|err| err.with_span(&span))?;

            let expr = parse_expression(expr_pair).map_err(|err| err.with_span(&span))?;
            let tx_var_span = Span::from(tx_var.as_span());
            let tx_var_value = match tx_var.as_str() {
                "this.age" => TimeVar::ThisAge,
                "tx.time" => TimeVar::TxTime,
                other => {
                    return Err(CompilerError::Unsupported(format!("unsupported time variable: {other}")).with_span(&tx_var_span));
                }
            };
            let (message, message_span) = message.unzip();
            Ok(Statement::TimeOp { tx_var: tx_var_value, expr, message, span, tx_var_span, message_span })
        }
        Rule::require_statement => {
            let mut inner = pair.into_inner();
            let expr_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing require expression".to_string()).with_span(&span))?;
            let message = inner.next().map(parse_require_message).transpose().map_err(|err| err.with_span(&span))?;
            let expr = parse_expression(expr_pair).map_err(|err| err.with_span(&span))?;
            let (message, message_span) = message.unzip();
            Ok(Statement::Require { expr, message, span, message_span })
        }
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let cond_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing if condition".to_string()).with_span(&span))?;
            let cond_expr = parse_expression(cond_pair).map_err(|err| err.with_span(&span))?;
            let then_block =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing if block".to_string()).with_span(&span))?;
            let (then_branch, then_span) = parse_block(then_block).map_err(|err| err.with_span(&span))?;
            let else_data = inner.next().map(parse_block).transpose().map_err(|err| err.with_span(&span))?;
            let (else_branch, else_span) = match else_data {
                Some((branch, span)) => (Some(branch), Some(span)),
                None => (None, None),
            };
            Ok(Statement::If { condition: cond_expr, then_branch, else_branch, span, then_span, else_span })
        }
        Rule::for_statement => {
            let mut inner = pair.into_inner();
            let ident =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop identifier".to_string()).with_span(&span))?;
            let start_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop start".to_string()).with_span(&span))?;
            let end_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop end".to_string()).with_span(&span))?;
            let block_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing for loop body".to_string()).with_span(&span))?;

            let start_expr = parse_expression(start_pair).map_err(|err| err.with_span(&span))?;
            let end_expr = parse_expression(end_pair).map_err(|err| err.with_span(&span))?;
            let (body, body_span) = parse_block(block_pair).map_err(|err| err.with_span(&span))?;
            let Identifier { name: ident, span: ident_span } = parse_identifier(ident).map_err(|err| err.with_span(&span))?;

            Ok(Statement::For { ident, start: start_expr, end: end_expr, body, span, ident_span, body_span })
        }
        Rule::yield_statement => {
            let mut inner = pair.into_inner();
            let list_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing yield arguments".to_string()).with_span(&span))?;
            let args = parse_expression_list(list_pair).map_err(|err| err.with_span(&span))?;
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("yield() expects a single argument".to_string()).with_span(&span));
            }
            Ok(Statement::Yield { expr: args[0].clone(), span })
        }
        Rule::console_statement => {
            let mut inner = pair.into_inner();
            let list_pair =
                inner.next().ok_or_else(|| CompilerError::Unsupported("missing console arguments".to_string()).with_span(&span))?;
            let args = parse_console_parameter_list(list_pair).map_err(|err| err.with_span(&span))?;
            Ok(Statement::Console { args, span })
        }
        _ => Err(CompilerError::Unsupported(format!("unexpected statement: {:?}", pair.as_rule())).with_span(&span)),
    }
}

fn parse_block<'i>(pair: Pair<'i, Rule>) -> Result<(Vec<Statement<'i>>, Span<'i>), CompilerError> {
    let span = Span::from(pair.as_span());
    match pair.as_rule() {
        Rule::block => {
            let mut statements = Vec::new();
            let mut block_span: Option<Span<'i>> = None;
            for stmt_pair in pair.into_inner() {
                let stmt = parse_statement(stmt_pair)?;
                let stmt_span = stmt.span();
                block_span = Some(match block_span {
                    None => stmt_span,
                    Some(prev) => prev.join(&stmt_span),
                });
                statements.push(stmt);
            }
            Ok((statements, block_span.unwrap_or(span)))
        }
        _ => {
            let stmt = parse_statement(pair)?;
            let stmt_span = stmt.span();
            Ok((vec![stmt], stmt_span))
        }
    }
}

fn parse_console_parameter_list<'i>(pair: Pair<'i, Rule>) -> Result<Vec<ConsoleArg<'i>>, CompilerError> {
    let mut args = Vec::new();

    for param in pair.into_inner() {
        let value = if param.as_rule() == Rule::console_parameter { single_inner(param)? } else { param };
        match value.as_rule() {
            Rule::Identifier => {
                let Identifier { name, span } = parse_identifier(value)?;
                args.push(ConsoleArg::Identifier(name, span));
            }
            Rule::literal => args.push(ConsoleArg::Literal(parse_literal(single_inner(value)?)?)),
            _ => return Err(CompilerError::Unsupported("console.log arguments not supported".to_string())),
        }
    }
    Ok(args)
}

fn parse_typed_binding<'i>(pair: Pair<'i, Rule>) -> Result<ParamAst<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();

    let type_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing binding type".to_string()))?;
    let ident_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing binding name".to_string()))?;

    let type_span = Span::from(type_pair.as_span());
    let type_ref = parse_type_name_pair(type_pair)?;
    let Identifier { name, span: name_span } = parse_identifier(ident_pair)?;

    Ok(ParamAst { type_ref, name, span, type_span, name_span })
}

fn parse_require_message<'i>(pair: Pair<'i, Rule>) -> Result<(String, Span<'i>), CompilerError> {
    let inner = single_inner(pair)?;
    match parse_string_literal(inner)? {
        Expr { kind: ExprKind::String(value), span } => Ok((value, span)),
        _ => Err(CompilerError::Unsupported("require message must be a string literal".to_string())),
    }
}

fn parse_state_typed_binding<'i>(pair: Pair<'i, Rule>) -> Result<StateBindingAst<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();

    let field_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing state field name".to_string()))?;
    let type_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing binding type".to_string()))?;
    let ident_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing binding name".to_string()))?;

    let Identifier { name: field_name, span: field_span } = parse_identifier(field_pair)?;
    let type_span = Span::from(type_pair.as_span());
    let type_ref = parse_type_name_pair(type_pair)?;
    let Identifier { name, span: name_span } = parse_identifier(ident_pair)?;

    Ok(StateBindingAst { field_name, type_ref, name, span, field_span, type_span, name_span })
}

fn parse_expression<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
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
        Rule::NumberLiteral => parse_number_expr(pair),
        Rule::BooleanLiteral => Ok(Expr::new(ExprKind::Bool(pair.as_str() == "true"), Span::from(pair.as_span()))),
        Rule::HexLiteral => parse_hex_literal(pair),
        Rule::Identifier => {
            let Identifier { name, span } = parse_identifier(pair)?;
            Ok(Expr::new(ExprKind::Identifier(name), span))
        }
        Rule::NullaryOp => parse_nullary(pair.as_str(), Span::from(pair.as_span())),
        Rule::introspection => parse_introspection(pair),
        Rule::array => parse_array(pair),
        Rule::function_call => parse_function_call(pair),
        Rule::instantiation => parse_instantiation(pair),
        Rule::cast => parse_cast(pair),
        Rule::state_object => parse_state_object(pair),
        Rule::split_call
        | Rule::slice_call
        | Rule::tuple_index
        | Rule::unary_suffix
        | Rule::StringLiteral
        | Rule::DateLiteral
        | Rule::type_name
        | Rule::state_entry => Err(CompilerError::Unsupported(format!("expression not supported: {:?}", pair.as_rule()))),
        _ => Err(CompilerError::Unsupported(format!("unexpected expression: {:?}", pair.as_rule()))),
    }
}

fn parse_unary<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
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
        expr = Expr::new(ExprKind::Unary { op, expr: Box::new(expr) }, span);
    }
    Ok(expr)
}

fn parse_postfix<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let mut inner = pair.into_inner();
    let primary = inner.next().ok_or_else(|| CompilerError::Unsupported("missing primary in postfix".to_string()))?;
    let mut expr = parse_primary(primary)?;
    for postfix in inner {
        let postfix_span = Span::from(postfix.as_span());
        match postfix.as_rule() {
            Rule::split_call => {
                let mut split_inner = postfix.into_inner();
                let index_expr = split_inner.next().ok_or_else(|| CompilerError::Unsupported("missing split index".to_string()))?;
                let index = Box::new(parse_expression(index_expr)?);
                let span = expr.span.join(&postfix_span);
                expr = Expr::new(ExprKind::Split { source: Box::new(expr), index, part: SplitPart::Left, span: postfix_span }, span);
            }
            Rule::slice_call => {
                let mut slice_inner = postfix.into_inner();
                let start_expr = slice_inner.next().ok_or_else(|| CompilerError::Unsupported("missing slice start".to_string()))?;
                let end_expr = slice_inner.next().ok_or_else(|| CompilerError::Unsupported("missing slice end".to_string()))?;
                let start = Box::new(parse_expression(start_expr)?);
                let end = Box::new(parse_expression(end_expr)?);
                let span = expr.span.join(&postfix_span);
                expr = Expr::new(ExprKind::Slice { source: Box::new(expr), start, end, span: postfix_span }, span);
            }
            Rule::tuple_index => {
                let mut index_inner = postfix.into_inner();
                let index_pair = index_inner.next().ok_or_else(|| CompilerError::Unsupported("missing tuple index".to_string()))?;
                let index_expr = parse_expression(index_pair)?;
                let index_span = index_expr.span;
                let span = expr.span.join(&postfix_span);
                if let ExprKind::Split { source, index: split_index, span: split_span, .. } = &expr.kind {
                    let part = match index_expr.kind {
                        ExprKind::Int(0) => SplitPart::Left,
                        ExprKind::Int(1) => SplitPart::Right,
                        _ => {
                            return Err(CompilerError::Unsupported("split() index must be 0 or 1".to_string()).with_span(&index_span));
                        }
                    };
                    expr = Expr::new(
                        ExprKind::Split { source: source.clone(), index: split_index.clone(), part, span: *split_span },
                        span,
                    );
                } else {
                    expr = Expr::new(ExprKind::ArrayIndex { source: Box::new(expr), index: Box::new(index_expr) }, span);
                }
            }
            Rule::unary_suffix => {
                let kind = match postfix.as_str() {
                    ".reverse()" => UnarySuffixKind::Reverse,
                    ".length" => UnarySuffixKind::Length,
                    other => return Err(CompilerError::Unsupported(format!("unknown unary suffix '{other}'"))),
                };
                let span = expr.span.join(&postfix_span);
                expr = Expr::new(ExprKind::UnarySuffix { source: Box::new(expr), kind, span: postfix_span }, span);
            }
            _ => {
                return Err(CompilerError::Unsupported("postfix operators are not supported".to_string()));
            }
        }
    }
    Ok(expr)
}

fn parse_typed_parameter_list<'i>(pair: Pair<'i, Rule>) -> Result<Vec<ParamAst<'i>>, CompilerError> {
    let mut params = Vec::new();
    for param in pair.into_inner() {
        if param.as_rule() != Rule::parameter {
            continue;
        }

        let param_span = Span::from(param.as_span());
        let mut inner = param.into_inner();

        let type_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing parameter type".to_string()))?;
        let ident_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing parameter name".to_string()))?;

        let Identifier { name, span: name_span } = parse_identifier(ident_pair)?;
        let type_span = Span::from(type_pair.as_span());
        let type_ref = parse_type_name_pair(type_pair)?;

        params.push(ParamAst { type_ref, name, span: param_span, type_span, name_span });
    }
    Ok(params)
}

fn parse_return_type_list<'i>(pair: Pair<'i, Rule>) -> Result<(Vec<TypeRef>, Vec<Span<'i>>), CompilerError> {
    let mut return_types = Vec::new();
    let mut return_spans = Vec::new();
    for user_type in pair.into_inner() {
        if user_type.as_rule() != Rule::type_name {
            continue;
        }
        let type_span = Span::from(user_type.as_span());
        return_types.push(parse_type_name_pair(user_type)?);
        return_spans.push(type_span);
    }
    Ok((return_types, return_spans))
}

fn parse_primary<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    match pair.as_rule() {
        Rule::parenthesized => parse_expression(single_inner(pair)?),
        Rule::literal => parse_literal(single_inner(pair)?),
        Rule::Identifier => {
            let Identifier { name, span } = parse_identifier(pair)?;
            Ok(Expr::new(ExprKind::Identifier(name), span))
        }
        Rule::NullaryOp => parse_nullary(pair.as_str(), Span::from(pair.as_span())),
        Rule::introspection => parse_introspection(pair),
        Rule::array => parse_array(pair),
        Rule::function_call => parse_function_call(pair),
        Rule::instantiation => parse_instantiation(pair),
        Rule::cast => parse_cast(pair),
        Rule::state_object => parse_state_object(pair),
        Rule::expression => parse_expression(pair),
        _ => Err(CompilerError::Unsupported(format!("primary not supported: {:?}", pair.as_rule()))),
    }
}

fn parse_state_object<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut fields = Vec::new();
    for field_pair in pair.into_inner() {
        if field_pair.as_rule() != Rule::state_entry {
            continue;
        }
        let field_span = Span::from(field_pair.as_span());
        let mut inner = field_pair.into_inner();
        let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing state field name".to_string()))?;
        let expr_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing state field expression".to_string()))?;
        let Identifier { name, span: name_span } = parse_identifier(name_pair)?;
        let expr = parse_expression(expr_pair)?;
        fields.push(StateFieldExpr { name, expr, span: field_span, name_span });
    }
    Ok(Expr::new(ExprKind::StateObject(fields), span))
}

fn parse_literal<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    match pair.as_rule() {
        Rule::BooleanLiteral => Ok(Expr::new(ExprKind::Bool(pair.as_str() == "true"), Span::from(pair.as_span()))),
        Rule::number_literal => parse_number_literal(pair),
        Rule::NumberLiteral => parse_number_expr(pair),
        Rule::HexLiteral => parse_hex_literal(pair),
        Rule::StringLiteral => parse_string_literal(pair),
        Rule::DateLiteral => parse_date_literal(pair),
        _ => Err(CompilerError::Unsupported(format!("literal not supported: {:?}", pair.as_rule()))),
    }
}

fn parse_number_expr<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let value = parse_number(pair.as_str())?;
    Ok(Expr::new(ExprKind::Int(value), span))
}

fn parse_number(raw: &str) -> Result<i64, CompilerError> {
    let raw = raw.trim();
    let mut parts = raw.split(['e', 'E']);
    let base_raw = parts.next().unwrap_or("");
    let exp_raw = parts.next();

    // nothing allowed after having the exponent
    if parts.next().is_some() {
        return Err(CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")));
    }

    let base_clean = base_raw.replace('_', "");
    if base_clean.is_empty() || base_clean == "-" {
        return Err(CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")));
    }
    let mut value =
        base_clean.parse::<i128>().map_err(|_| CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")))?;

    if let Some(exp_raw) = exp_raw {
        let exp_clean = exp_raw.replace('_', "");

        // rejects negative exponent
        let exp = exp_clean.parse::<u32>().map_err(|_| CompilerError::InvalidLiteral(format!("invalid number literal '{raw}'")))?;
        let pow = 10i128.checked_pow(exp).ok_or_else(|| CompilerError::InvalidLiteral(format!("number literal overflow '{raw}'")))?;
        value = value.checked_mul(pow).ok_or_else(|| CompilerError::InvalidLiteral(format!("number literal overflow '{raw}'")))?;
    }

    if value < i64::MIN as i128 || value > i64::MAX as i128 {
        return Err(CompilerError::InvalidLiteral(format!("number literal overflow '{raw}'")));
    }

    Ok(value as i64)
}

fn parse_array<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut values = Vec::new();
    for expr_pair in pair.into_inner() {
        values.push(parse_expression(expr_pair)?);
    }
    Ok(Expr::new(ExprKind::Array(values), span))
}

fn parse_function_call_parts<'i>(pair: Pair<'i, Rule>) -> Result<(Identifier<'i>, Vec<Expr<'i>>), CompilerError> {
    let mut inner = pair.into_inner();
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing function name".to_string()))?;
    let args = match inner.next() {
        Some(list) => parse_expression_list(list)?,
        None => Vec::new(),
    };
    let name = parse_identifier(name_pair)?;
    Ok((name, args))
}

fn parse_function_call<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let (Identifier { name, span: name_span }, args) = parse_function_call_parts(pair)?;
    Ok(Expr::new(ExprKind::Call { name, args, name_span }, span))
}

fn parse_instantiation<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();
    let name_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing constructor name".to_string()))?;
    let args = match inner.next() {
        Some(list) => parse_expression_list(list)?,
        None => Vec::new(),
    };
    let Identifier { name, span: name_span } = parse_identifier(name_pair)?;
    Ok(Expr::new(ExprKind::New { name, args, name_span }, span))
}

fn parse_expression_list<'i>(pair: Pair<'i, Rule>) -> Result<Vec<Expr<'i>>, CompilerError> {
    let mut args = Vec::new();
    for expr_pair in pair.into_inner() {
        args.push(parse_expression(expr_pair)?);
    }
    Ok(args)
}

fn parse_cast<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();

    let type_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing cast type".to_string()))?;
    let type_name = type_pair.as_str().trim().to_string();
    let type_span = Span::from(type_pair.as_span());

    let mut args = Vec::new();
    for part in inner {
        args.push(parse_expression(part)?);
    }

    if type_name == "bytes" {
        return Ok(Expr::new(ExprKind::Call { name: "bytes".to_string(), args, name_span: type_span }, span));
    }

    if type_name == "byte" {
        return Ok(Expr::new(ExprKind::Call { name: "byte[1]".to_string(), args, name_span: type_span }, span));
    }

    if type_name == "int" {
        return Ok(Expr::new(ExprKind::Call { name: "int".to_string(), args, name_span: type_span }, span));
    }

    if matches!(type_name.as_str(), "sig" | "pubkey" | "datasig") {
        return Ok(Expr::new(ExprKind::Call { name: type_name, args, name_span: type_span }, span));
    }

    // Handle single byte cast (duplicate check removed above)
    // Support type[N] syntax
    if let Some(bracket_pos) = type_name.find('[') {
        if type_name.ends_with(']') {
            let size_str = &type_name[bracket_pos + 1..type_name.len() - 1];
            if size_str.is_empty() || size_str.parse::<usize>().is_ok() {
                return Ok(Expr::new(ExprKind::Call { name: type_name, args, name_span: type_span }, span));
            }
        }
    }

    Err(CompilerError::Unsupported(format!("cast type not supported: {type_name}")))
}

fn parse_number_literal<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();
    let number = inner.next().ok_or_else(|| CompilerError::InvalidLiteral("missing number literal".to_string()))?;
    let value = parse_number(number.as_str())?;
    let expr = Expr::new(ExprKind::Int(value), span);
    if let Some(unit) = inner.next() {
        return apply_number_unit(expr, unit.as_str());
    }
    Ok(expr)
}

fn parse_hex_literal<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let raw = pair.as_str();
    let trimmed = raw.trim_start_matches("0x").trim_start_matches("0X");
    let normalized = if trimmed.len() % 2 != 0 { format!("0{trimmed}") } else { trimmed.to_string() };
    let bytes = (0..normalized.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&normalized[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompilerError::InvalidLiteral(format!("invalid hex literal '{raw}'")))?;
    Ok(Expr::new(
        ExprKind::Array(bytes.into_iter().map(|byte| Expr::new(ExprKind::Byte(byte), span)).collect()),
        span,
    ))
}

fn apply_number_unit<'i>(expr: Expr<'i>, unit: &str) -> Result<Expr<'i>, CompilerError> {
    let span = expr.span;
    let value = match expr.kind {
        ExprKind::Int(value) => value,
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
    Ok(Expr::new(ExprKind::Int(value.saturating_mul(multiplier)), span))
}

fn parse_date_literal<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let mut inner = pair.into_inner();
    let string_pair = inner.next().ok_or_else(|| CompilerError::InvalidLiteral("missing date literal".to_string()))?;
    let value = match parse_string_literal(string_pair)? {
        Expr { kind: ExprKind::String(value), .. } => value,
        _ => return Err(CompilerError::InvalidLiteral("invalid date literal".to_string())),
    };
    let timestamp = NaiveDateTime::parse_from_str(&value, "%Y-%m-%dT%H:%M:%S")
        .map_err(|_| CompilerError::InvalidLiteral(format!("invalid date literal '{value}'")))?
        .and_utc()
        .timestamp();
    Ok(Expr::new(ExprKind::DateLiteral(timestamp), span))
}

fn parse_string_literal<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let raw = pair.as_str();
    let unquoted = if (raw.starts_with('"') && raw.ends_with('"')) || (raw.starts_with('\'') && raw.ends_with('\'')) {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    let unescaped = unquoted.replace("\\\"", "\"").replace("\\'", "'");
    Ok(Expr::new(ExprKind::String(unescaped), span))
}

fn parse_nullary<'i>(raw: &str, span: Span<'i>) -> Result<Expr<'i>, CompilerError> {
    let op = match raw {
        "this.activeInputIndex" => NullaryOp::ActiveInputIndex,
        "this.activeScriptPubKey" => NullaryOp::ActiveScriptPubKey,
        "this.scriptSize" => NullaryOp::ThisScriptSize,
        "this.scriptSizeDataPrefix" => NullaryOp::ThisScriptSizeDataPrefix,
        "tx.inputs.length" => NullaryOp::TxInputsLength,
        "tx.outputs.length" => NullaryOp::TxOutputsLength,
        "tx.version" => NullaryOp::TxVersion,
        "tx.locktime" => NullaryOp::TxLockTime,
        _ => return Err(CompilerError::Unsupported(format!("unknown nullary op: {raw}"))),
    };
    Ok(Expr::new(ExprKind::Nullary(op), span))
}

fn parse_introspection<'i>(pair: Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let text = pair.as_str();
    let mut inner = pair.into_inner();
    let index_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing introspection index".to_string()))?;
    let field_pair = inner.next().ok_or_else(|| CompilerError::Unsupported("missing introspection field".to_string()))?;

    let index = Box::new(parse_expression(index_pair)?);
    let field_raw = field_pair.as_str();
    let kind = if text.starts_with("tx.inputs") {
        match field_raw {
            ".value" => IntrospectionKind::InputValue,
            ".scriptPubKey" => IntrospectionKind::InputScriptPubKey,
            ".sigScript" => IntrospectionKind::InputSigScript,
            // TODO: support this
            ".outpointTransactionHash" => IntrospectionKind::InputOutpointTransactionHash,
            ".outpointIndex" => IntrospectionKind::InputOutpointIndex,
            ".sequenceNumber" => IntrospectionKind::InputSequenceNumber,
            _ => return Err(CompilerError::Unsupported(format!("input field '{field_raw}' not supported"))),
        }
    } else if text.starts_with("tx.outputs") {
        match field_raw {
            ".value" => IntrospectionKind::OutputValue,
            ".scriptPubKey" => IntrospectionKind::OutputScriptPubKey,
            _ => return Err(CompilerError::Unsupported(format!("output field '{field_raw}' not supported"))),
        }
    } else {
        return Err(CompilerError::Unsupported("unknown introspection root".to_string()));
    };

    Ok(Expr::new(ExprKind::Introspection { kind, index, field_span: Span::from(field_pair.as_span()) }, span))
}

fn single_inner(pair: Pair<'_, Rule>) -> Result<Pair<'_, Rule>, CompilerError> {
    pair.into_inner().next().ok_or_else(|| CompilerError::Unsupported("expected inner pair".to_string()))
}

fn parse_infix<'i, F, G>(pair: Pair<'i, Rule>, mut parse_operand: F, mut map_op: G) -> Result<Expr<'i>, CompilerError>
where
    F: FnMut(Pair<'i, Rule>) -> Result<Expr<'i>, CompilerError>,
    G: FnMut(Pair<'_, Rule>) -> Result<BinaryOp, CompilerError>,
{
    let mut inner = pair.into_inner();
    let first = inner.next().ok_or_else(|| CompilerError::Unsupported("missing infix operand".to_string()))?;
    let mut expr = parse_operand(first)?;

    while let Some(op_pair) = inner.next() {
        let rhs = inner.next().ok_or_else(|| CompilerError::Unsupported("missing infix rhs".to_string()))?;
        let op = map_op(op_pair)?;
        let rhs_expr = parse_operand(rhs)?;
        let span = expr.span.join(&rhs_expr.span);
        expr = Expr::new(ExprKind::Binary { op, left: Box::new(expr), right: Box::new(rhs_expr) }, span);
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

// validate user input
fn parse_identifier<'i>(pair: Pair<'i, Rule>) -> Result<Identifier<'i>, CompilerError> {
    let span = Span::from(pair.as_span());
    let value = pair.as_str().to_string();

    if value.starts_with("__") {
        return Err(CompilerError::Unsupported("identifiers starting with '__' are reserved".to_string()));
    }

    Ok(Identifier { name: value, span })
}
