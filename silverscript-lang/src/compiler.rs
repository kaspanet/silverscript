use std::collections::{HashMap, HashSet};

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::serialize_i64;
use serde::{Deserialize, Serialize};

use crate::ast::{
    ArrayDim, BinaryOp, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, IntrospectionKind, NullaryOp, SplitPart,
    StateBindingAst, StateFieldExpr, Statement, TimeVar, TypeBase, TypeRef, UnaryOp, UnarySuffixKind, parse_contract_ast,
    parse_type_ref,
};
use crate::debug_info::{DebugInfo, RuntimeBinding, SourceSpan};
pub use crate::errors::{CompilerError, ErrorSpan};
use crate::span;
mod covenant_declarations;
use covenant_declarations::lower_covenant_declarations;

mod debug_recording;
mod debug_value_types;
mod stack_bindings;

use debug_recording::DebugRecorder;
use debug_value_types::infer_debug_expr_value_type;
use stack_bindings::StackBindings;

/// Prefix used for synthetic argument bindings during inline function expansion.
pub const SYNTHETIC_ARG_PREFIX: &str = "__arg";
const COVENANT_POLICY_PREFIX: &str = "__covenant_policy";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CovenantDeclCallOptions {
    pub is_leader: bool,
}

fn generated_covenant_policy_name(function_name: &str) -> String {
    format!("{COVENANT_POLICY_PREFIX}_{function_name}")
}

fn generated_covenant_entrypoint_name(function_name: &str) -> String {
    format!("__{function_name}")
}

fn generated_covenant_leader_entrypoint_name(function_name: &str) -> String {
    format!("__leader_{function_name}")
}

fn generated_covenant_delegate_entrypoint_name(function_name: &str) -> String {
    format!("__delegate_{function_name}")
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CompileOptions {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledStateLayout {
    pub start: usize,
    pub len: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompiledContract<'i> {
    pub contract_name: String,
    pub script: Vec<u8>,
    pub ast: ContractAst<'i>,
    pub abi: Vec<FunctionAbiEntry>,
    pub without_selector: bool,
    pub state_layout: CompiledStateLayout,
    pub debug_info: Option<DebugInfo<'i>>,
}

#[derive(Clone, Default)]
struct LoweringScope {
    vars: HashMap<String, TypeRef>,
}

#[derive(Clone)]
struct StructFieldSpec {
    name: String,
    type_ref: TypeRef,
}

#[derive(Clone)]
struct StructSpec {
    fields: Vec<StructFieldSpec>,
}

type StructRegistry = HashMap<String, StructSpec>;

pub fn compile_contract<'i>(
    source: &'i str,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    let contract = parse_contract_ast(source)?;
    compile_contract_impl(&contract, constructor_args, options, Some(source))
}

pub fn compile_contract_ast<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    compile_contract_impl(contract, constructor_args, options, None)
}

pub fn struct_object<'i>(fields: Vec<(&str, Expr<'i>)>) -> Expr<'i> {
    Expr::new(
        ExprKind::StateObject(
            fields
                .into_iter()
                .map(|(name, expr)| StateFieldExpr {
                    name: name.to_string(),
                    expr,
                    span: Default::default(),
                    name_span: Default::default(),
                })
                .collect(),
        ),
        Default::default(),
    )
}

fn build_struct_registry<'i>(contract: &ContractAst<'i>) -> Result<StructRegistry, CompilerError> {
    let mut registry = HashMap::new();
    for item in &contract.structs {
        if item.name == "State" {
            return Err(CompilerError::Unsupported("'State' is a reserved struct name".to_string()));
        }
        let mut names = HashSet::new();
        let fields = item
            .fields
            .iter()
            .map(|field| {
                if !names.insert(field.name.clone()) {
                    return Err(CompilerError::Unsupported(format!("duplicate struct field '{}.{}'", item.name, field.name)));
                }
                Ok(StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
            })
            .collect::<Result<Vec<_>, CompilerError>>()?;
        if registry.insert(item.name.clone(), StructSpec { fields }).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate struct name: {}", item.name)));
        }
    }

    let mut state_field_names = HashSet::new();
    let state_fields = contract
        .fields
        .iter()
        .map(|field| {
            if !state_field_names.insert(field.name.clone()) {
                return Err(CompilerError::Unsupported(format!("duplicate contract field name: {}", field.name)));
            }
            Ok(StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
        })
        .collect::<Result<Vec<_>, CompilerError>>()?;
    registry.insert("State".to_string(), StructSpec { fields: state_fields });

    Ok(registry)
}

fn struct_name_from_type_ref<'a>(type_ref: &'a TypeRef, structs: &'a StructRegistry) -> Option<&'a str> {
    if !type_ref.array_dims.is_empty() {
        return None;
    }
    match &type_ref.base {
        TypeBase::Custom(name) if structs.contains_key(name) => Some(name.as_str()),
        _ => None,
    }
}

fn struct_array_name_from_type_ref(type_ref: &TypeRef, structs: &StructRegistry) -> Option<String> {
    let element_type = type_ref.element_type()?;
    struct_name_from_type_ref(&element_type, structs).map(ToOwned::to_owned)
}

fn ensure_known_or_builtin_type(type_ref: &TypeRef, structs: &StructRegistry, context: &str) -> Result<(), CompilerError> {
    if type_ref.array_dims.is_empty() {
        match &type_ref.base {
            TypeBase::Custom(name) if !structs.contains_key(name) => {
                return Err(CompilerError::Unsupported(format!("unknown type '{}' in {context}", name)));
            }
            _ => {}
        }
    } else if let TypeBase::Custom(name) = &type_ref.base {
        if structs.contains_key(name) {
            return Err(CompilerError::Unsupported(format!("arrays of struct type '{}' are not supported", name)));
        }
        return Err(CompilerError::Unsupported(format!("unknown type '{}' in {context}", name)));
    }
    Ok(())
}

fn validate_struct_graph(structs: &StructRegistry) -> Result<(), CompilerError> {
    fn visit(
        name: &str,
        structs: &StructRegistry,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> Result<(), CompilerError> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_string()) {
            return Err(CompilerError::Unsupported(format!("cyclic struct definition involving '{name}'")));
        }
        let item = structs.get(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
        for field in &item.fields {
            ensure_known_or_builtin_type(&field.type_ref, structs, "struct field")?;
            if let Some(child) = struct_name_from_type_ref(&field.type_ref, structs) {
                visit(child, structs, visiting, visited)?;
            }
        }
        visiting.remove(name);
        visited.insert(name.to_string());
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for name in structs.keys() {
        visit(name, structs, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn flattened_struct_name(base: &str, path: &[String]) -> String {
    let mut out = format!("__struct_{base}");
    for part in path {
        out.push('_');
        out.push_str(part);
    }
    out
}

fn flatten_struct_fields(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    prefix: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, TypeRef)>,
) -> Result<(), CompilerError> {
    if let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) {
        let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        for field in &item.fields {
            prefix.push(field.name.clone());
            flatten_struct_fields(&field.type_ref, structs, prefix, out)?;
            prefix.pop();
        }
    } else {
        out.push((prefix.clone(), type_ref.clone()));
    }
    Ok(())
}

fn resolve_struct_access<'i>(
    expr: &Expr<'i>,
    scope: &LoweringScope,
    structs: &StructRegistry,
) -> Result<(String, Vec<String>, TypeRef), CompilerError> {
    match &expr.kind {
        ExprKind::Identifier(name) => {
            let type_ref = scope.vars.get(name).cloned().ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?;
            Ok((name.clone(), Vec::new(), type_ref))
        }
        ExprKind::FieldAccess { source, field, .. } => {
            let (base, mut path, current_type) = resolve_struct_access(source, scope, structs)?;
            let struct_name = struct_name_from_type_ref(&current_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("field access requires a struct value".to_string()))?;
            let item =
                structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            let field_type = item
                .fields
                .iter()
                .find(|candidate| candidate.name == *field)
                .map(|candidate| candidate.type_ref.clone())
                .ok_or_else(|| CompilerError::Unsupported(format!("struct '{}' has no field '{}'", struct_name, field)))?;
            path.push(field.clone());
            Ok((base, path, field_type))
        }
        _ => Err(CompilerError::Unsupported("struct field access requires a struct variable".to_string())),
    }
}

fn flattened_struct_field_specs_for_type(type_ref: &TypeRef, structs: &StructRegistry) -> Result<Vec<StructFieldSpec>, CompilerError> {
    let mut leaves = Vec::new();
    flatten_struct_fields(type_ref, structs, &mut Vec::new(), &mut leaves)?;
    Ok(leaves
        .into_iter()
        .map(|(path, type_ref)| StructFieldSpec { name: path.last().cloned().unwrap_or_default(), type_ref })
        .collect())
}

fn binary_expr<'i>(op: BinaryOp, left: Expr<'i>, right: Expr<'i>) -> Expr<'i> {
    Expr::new(ExprKind::Binary { op, left: Box::new(left), right: Box::new(right) }, span::Span::default())
}

fn input_sigscript_base_expr<'i>(input_idx: &Expr<'i>, script_size_expr: Expr<'i>) -> Expr<'i> {
    binary_expr(BinaryOp::Sub, Expr::call("OpTxInputScriptSigLen", vec![input_idx.clone()]), script_size_expr)
}

fn input_sigscript_substr_expr<'i>(input_idx: &Expr<'i>, start: Expr<'i>, end: Expr<'i>) -> Expr<'i> {
    Expr::call("OpTxInputScriptSigSubstr", vec![input_idx.clone(), start, end])
}

fn input_script_pubkey_expr<'i>(input_idx: &Expr<'i>) -> Expr<'i> {
    Expr::new(
        ExprKind::Introspection {
            kind: IntrospectionKind::InputScriptPubKey,
            index: Box::new(input_idx.clone()),
            field_span: span::Span::default(),
        },
        span::Span::default(),
    )
}

fn lower_expr<'i>(expr: &Expr<'i>, scope: &LoweringScope, structs: &StructRegistry) -> Result<Expr<'i>, CompilerError> {
    let span = expr.span;
    match &expr.kind {
        ExprKind::FieldAccess { .. } => {
            if let ExprKind::FieldAccess { source, field, .. } = &expr.kind {
                if let ExprKind::ArrayIndex { source: array_source, index } = &source.as_ref().kind {
                    let (base, mut path, array_type) = resolve_struct_access(array_source, scope, structs)?;
                    let struct_name = struct_array_name_from_type_ref(&array_type, structs)
                        .ok_or_else(|| CompilerError::Unsupported("field access requires a struct value".to_string()))?;
                    let item = structs
                        .get(&struct_name)
                        .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
                    let field_type = item
                        .fields
                        .iter()
                        .find(|candidate| candidate.name == *field)
                        .map(|candidate| candidate.type_ref.clone())
                        .ok_or_else(|| CompilerError::Unsupported(format!("struct '{}' has no field '{}'", struct_name, field)))?;
                    if struct_name_from_type_ref(&field_type, structs).is_some()
                        || struct_array_name_from_type_ref(&field_type, structs).is_some()
                    {
                        return Err(CompilerError::Unsupported("nested struct array field access is not supported".to_string()));
                    }
                    path.push(field.clone());
                    return Ok(Expr::new(
                        ExprKind::ArrayIndex {
                            source: Box::new(Expr::identifier(flattened_struct_name(&base, &path))),
                            index: Box::new(lower_expr(index, scope, structs)?),
                        },
                        span,
                    ));
                }
            }
            let (base, path, type_ref) = resolve_struct_access(expr, scope, structs)?;
            if struct_name_from_type_ref(&type_ref, structs).is_some() {
                return Err(CompilerError::Unsupported("struct value must be used in a struct-typed position".to_string()));
            }
            Ok(Expr::new(ExprKind::Identifier(flattened_struct_name(&base, &path)), span))
        }
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op: *op, expr: Box::new(lower_expr(expr, scope, structs)?) }, span))
        }
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op: *op,
                left: Box::new(lower_expr(left, scope, structs)?),
                right: Box::new(lower_expr(right, scope, structs)?),
            },
            span,
        )),
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(lower_expr(condition, scope, structs)?),
                then_expr: Box::new(lower_expr(then_expr, scope, structs)?),
                else_expr: Box::new(lower_expr(else_expr, scope, structs)?),
            },
            span,
        )),
        ExprKind::Array(values) => Ok(Expr::new(
            ExprKind::Array(values.iter().map(|value| lower_expr(value, scope, structs)).collect::<Result<Vec<_>, _>>()?),
            span,
        )),
        ExprKind::StateObject(_) => {
            Err(CompilerError::Unsupported("struct literals are only supported in struct-typed positions".to_string()))
        }
        ExprKind::Call { name, args, name_span } => Ok(Expr::new(
            ExprKind::Call {
                name: name.clone(),
                args: args.iter().map(|arg| lower_expr(arg, scope, structs)).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(|arg| lower_expr(arg, scope, structs)).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(lower_expr(source, scope, structs)?),
                index: Box::new(lower_expr(index, scope, structs)?),
                part: *part,
                span: *split_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(lower_expr(source, scope, structs)?),
                start: Box::new(lower_expr(start, scope, structs)?),
                end: Box::new(lower_expr(end, scope, structs)?),
                span: *slice_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(lower_expr(source, scope, structs)?),
                index: Box::new(lower_expr(index, scope, structs)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::Introspection { kind: *kind, index: Box::new(lower_expr(index, scope, structs)?), field_span: *field_span },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
            if matches!(kind, UnarySuffixKind::Length)
                && let ExprKind::Identifier(name) = &source.kind
                && let Some(type_ref) = scope.vars.get(name)
                && struct_array_name_from_type_ref(type_ref, structs).is_some()
            {
                let first_leaf = flatten_type_ref_leaves(type_ref, structs)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| CompilerError::Unsupported("struct array must contain fields".to_string()))?;
                return Ok(Expr::new(
                    ExprKind::UnarySuffix {
                        source: Box::new(Expr::identifier(flattened_struct_name(name, &first_leaf.0))),
                        kind: *kind,
                        span: *suffix_span,
                    },
                    span,
                ));
            }
            Ok(Expr::new(
                ExprKind::UnarySuffix { source: Box::new(lower_expr(source, scope, structs)?), kind: *kind, span: *suffix_span },
                span,
            ))
        }
        _ => Ok(expr.clone()),
    }
}

fn read_input_state_field_expr_symbolic<'i>(
    input_idx: &Expr<'i>,
    field: &ContractFieldAst<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    field_chunk_offset: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let state_start_offset = state_start_offset(contract_field_prefix_len, contract_fields, contract_constants)?;
    let script_size_expr = Expr::new(ExprKind::Nullary(NullaryOp::ThisScriptSize), span::Span::default());
    let (field_payload_len, decode_numeric) = fixed_state_field_payload_len(field, contract_constants)?;
    let field_payload_offset = state_start_offset + field_chunk_offset + data_prefix(field_payload_len).len();

    let sig_len = Expr::call("OpTxInputScriptSigLen", vec![input_idx.clone()]);
    let start = Expr::new(
        ExprKind::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::new(
                ExprKind::Binary { op: BinaryOp::Sub, left: Box::new(sig_len), right: Box::new(script_size_expr) },
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

    if decode_numeric { Ok(Expr::call("OpBin2Num", vec![substr])) } else { Ok(substr) }
}

fn read_input_state_with_template_values<'i>(
    args: &[Expr<'i>],
    expected_type: &TypeRef,
    structs: &StructRegistry,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    if args.len() != 4 {
        return Err(CompilerError::Unsupported(
            "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                .to_string(),
        ));
    }

    let layout_fields = flattened_struct_field_specs_for_type(expected_type, structs)?;
    if layout_fields.is_empty() {
        return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
    }

    let script_size_expr = templated_input_script_size_expr(&args[1], &args[2], &layout_fields, contract_constants)?;
    let state_start_offset_expr = args[1].clone();
    let input_idx = &args[0];
    let mut field_chunk_offset = 0usize;
    let mut lowered = Vec::with_capacity(layout_fields.len());
    for field in &layout_fields {
        lowered.push(read_input_state_field_expr_with_type(
            input_idx,
            &field.type_ref,
            state_start_offset_expr.clone(),
            field_chunk_offset,
            script_size_expr.clone(),
            contract_constants,
            "readInputStateWithTemplate",
        )?);
        field_chunk_offset += encoded_field_chunk_size_for_type_ref(&field.type_ref, contract_constants)?;
    }
    Ok(lowered)
}

fn lower_struct_value_to_state_object_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Expr<'i>, CompilerError> {
    let lowered_values =
        lower_struct_value_expr(expr, expected_type, scope, structs, contract_fields, contract_constants, contract_field_prefix_len)?;
    let mut paths = Vec::new();
    flatten_struct_fields(expected_type, structs, &mut Vec::new(), &mut paths)?;
    let fields = paths
        .into_iter()
        .zip(lowered_values)
        .map(|((path, _), value)| StateFieldExpr {
            name: path.last().cloned().unwrap_or_default(),
            expr: value,
            span: expr.span,
            name_span: span::Span::default(),
        })
        .collect();
    Ok(Expr::new(ExprKind::StateObject(fields), expr.span))
}

fn lower_struct_value_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let expected_struct_name = struct_name_from_type_ref(expected_type, structs)
        .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;
    match &expr.kind {
        ExprKind::Call { name, args, .. } if name == "readInputState" => {
            if expected_struct_name != "State" {
                return Err(CompilerError::Unsupported("readInputState returns State".to_string()));
            }
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("readInputState(input_idx) expects 1 argument".to_string()));
            }
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            let mut field_chunk_offset = 0usize;
            let mut lowered = Vec::with_capacity(contract_fields.len());
            for field in contract_fields {
                lowered.push(read_input_state_field_expr_symbolic(
                    &args[0],
                    field,
                    contract_fields,
                    contract_field_prefix_len,
                    field_chunk_offset,
                    contract_constants,
                )?);
                field_chunk_offset += encoded_field_chunk_size(field, contract_constants)?;
            }
            Ok(lowered)
        }
        ExprKind::Call { name, .. } if name == "readInputStateWithTemplate" => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
        )),
        ExprKind::Identifier(_) | ExprKind::FieldAccess { .. } => {
            let (base, path, actual_type) = resolve_struct_access(expr, scope, structs)?;
            let actual_struct_name = struct_name_from_type_ref(&actual_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("expression is not a struct".to_string()))?;
            if actual_struct_name != expected_struct_name {
                return Err(CompilerError::Unsupported(format!(
                    "struct expression expects {}, got {}",
                    expected_type.type_name(),
                    actual_type.type_name()
                )));
            }
            let mut flattened = Vec::new();
            let mut leaves = Vec::new();
            let mut prefix = path.clone();
            flatten_struct_fields(&actual_type, structs, &mut prefix, &mut leaves)?;
            for (leaf_path, _) in leaves {
                flattened.push(Expr::identifier(flattened_struct_name(&base, &leaf_path)));
            }
            Ok(flattened)
        }
        ExprKind::ArrayIndex { source, index } => {
            let source_type = match &source.kind {
                ExprKind::Identifier(name) => scope
                    .vars
                    .get(name)
                    .cloned()
                    .ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?,
                _ => return Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
            };
            let actual_struct_name = struct_array_name_from_type_ref(&source_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("expression is not a struct".to_string()))?;
            if actual_struct_name != expected_struct_name {
                return Err(CompilerError::Unsupported(format!(
                    "struct expression expects {}, got {}",
                    expected_type.type_name(),
                    source_type.type_name()
                )));
            }
            let lowered_index = lower_expr(index, scope, structs)?;
            let source_leaves = lower_struct_array_value_expr(
                source,
                &source_type,
                scope,
                structs,
                contract_fields,
                contract_constants,
                contract_field_prefix_len,
            )?;
            Ok(source_leaves
                .into_iter()
                .map(|leaf| {
                    Expr::new(ExprKind::ArrayIndex { source: Box::new(leaf), index: Box::new(lowered_index.clone()) }, expr.span)
                })
                .collect())
        }
        ExprKind::StateObject(entries) => {
            let item = structs
                .get(expected_struct_name)
                .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{expected_struct_name}'")))?;
            let scope_types =
                scope.vars.iter().map(|(name, type_ref)| (name.clone(), type_name_from_ref(type_ref))).collect::<HashMap<_, _>>();
            let mut provided = HashMap::new();
            for entry in entries {
                if provided.insert(entry.name.clone(), &entry.expr).is_some() {
                    return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", entry.name)));
                }
            }
            let mut lowered = Vec::new();
            for field in &item.fields {
                let field_expr = provided
                    .remove(&field.name)
                    .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))?;
                if struct_name_from_type_ref(&field.type_ref, structs).is_some() {
                    lowered.extend(lower_struct_value_expr(
                        field_expr,
                        &field.type_ref,
                        scope,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?);
                } else {
                    let lowered_expr = lower_expr(field_expr, scope, structs)?;
                    if !expr_matches_return_type_ref(&lowered_expr, &field.type_ref, &scope_types, contract_constants) {
                        return Err(CompilerError::Unsupported(format!(
                            "struct field '{}' expects {}",
                            field.name,
                            field.type_ref.type_name()
                        )));
                    }
                    lowered.push(lowered_expr);
                }
            }
            if let Some(extra) = provided.keys().next() {
                return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
            }
            Ok(lowered)
        }
        _ => Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
    }
}

fn infer_struct_expr_type<'i>(
    expr: &Expr<'i>,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<TypeRef, CompilerError> {
    match &expr.kind {
        ExprKind::Identifier(_) | ExprKind::FieldAccess { .. } => {
            let (_, _, type_ref) = resolve_struct_access(expr, scope, structs)?;
            Ok(type_ref)
        }
        ExprKind::ArrayIndex { source, .. } => match &source.kind {
            ExprKind::Identifier(name) => scope
                .vars
                .get(name)
                .cloned()
                .ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?
                .element_type()
                .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
            _ => Err(CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
        },
        ExprKind::Call { name, .. } if name == "readInputState" => {
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            Ok(TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() })
        }
        ExprKind::Call { name, .. } if name == "readInputStateWithTemplate" => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
        )),
        _ => Err(CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
    }
}

fn lower_struct_destructure_statement<'i>(
    bindings: &[StateBindingAst<'i>],
    expr: &Expr<'i>,
    span: crate::span::Span<'i>,
    scope: &mut LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let expr_type = infer_struct_expr_type(expr, scope, structs, contract_fields)?;
    let struct_name = struct_name_from_type_ref(&expr_type, structs)
        .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string()))?;
    let struct_ast = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let direct_field_values = if matches!(&expr.kind, ExprKind::Call { name, .. } if name == "readInputState") {
        Some(
            struct_ast
                .fields
                .iter()
                .map(|field| field.name.clone())
                .zip(lower_struct_value_expr(
                    expr,
                    &expr_type,
                    scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?)
                .collect::<HashMap<_, _>>(),
        )
    } else {
        None
    };

    let mut binding_map = HashMap::new();
    let mut binding_names = HashSet::new();
    for binding in bindings {
        ensure_known_or_builtin_type(&binding.type_ref, structs, "struct destructuring")?;
        if binding_map.insert(binding.field_name.clone(), binding).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", binding.field_name)));
        }
        if !binding_names.insert(binding.name.clone()) {
            return Err(CompilerError::Unsupported(format!("duplicate binding name '{}'", binding.name)));
        }
    }

    if bindings.len() != struct_ast.fields.len() {
        return Err(CompilerError::Unsupported("struct destructuring must bind all fields exactly once".to_string()));
    }

    let mut lowered = Vec::new();
    for field in &struct_ast.fields {
        let binding = binding_map
            .remove(&field.name)
            .ok_or_else(|| CompilerError::Unsupported("struct destructuring must bind all fields exactly once".to_string()))?;
        if binding.type_ref != field.type_ref {
            return Err(CompilerError::Unsupported(format!(
                "struct field '{}' expects {}",
                field.name,
                type_name_from_ref(&field.type_ref)
            )));
        }

        if let Some(field_expr) = direct_field_values.as_ref().and_then(|fields| fields.get(&field.name)) {
            if struct_name_from_type_ref(&binding.type_ref, structs).is_some() {
                return Err(CompilerError::Unsupported("readInputState does not support nested struct fields".to_string()));
            }
            scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
            lowered.push(Statement::VariableDefinition {
                type_ref: binding.type_ref.clone(),
                modifiers: Vec::new(),
                name: binding.name.clone(),
                expr: Some(field_expr.clone()),
                span: binding.span,
                type_span: binding.type_span,
                modifier_spans: Vec::new(),
                name_span: binding.name_span,
            });
        } else {
            let projected_expr = Expr::new(
                ExprKind::FieldAccess { source: Box::new(expr.clone()), field: field.name.clone(), field_span: binding.field_span },
                span,
            );

            if struct_name_from_type_ref(&binding.type_ref, structs).is_some() {
                let lowered_values = lower_struct_value_expr(
                    &projected_expr,
                    &binding.type_ref,
                    scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                let mut paths = Vec::new();
                flatten_struct_fields(&binding.type_ref, structs, &mut Vec::new(), &mut paths)?;
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                lowered.extend(paths.into_iter().zip(lowered_values).map(|((path, field_type), field_expr)| {
                    Statement::VariableDefinition {
                        type_ref: field_type,
                        modifiers: Vec::new(),
                        name: flattened_struct_name(&binding.name, &path),
                        expr: Some(field_expr),
                        span: binding.span,
                        type_span: binding.type_span,
                        modifier_spans: Vec::new(),
                        name_span: binding.name_span,
                    }
                }));
            } else {
                let lowered_expr = lower_expr(&projected_expr, scope, structs)?;
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
                lowered.push(Statement::VariableDefinition {
                    type_ref: binding.type_ref.clone(),
                    modifiers: Vec::new(),
                    name: binding.name.clone(),
                    expr: Some(lowered_expr),
                    span: binding.span,
                    type_span: binding.type_span,
                    modifier_spans: Vec::new(),
                    name_span: binding.name_span,
                });
            }
        }
    }

    if !binding_map.is_empty() {
        return Err(CompilerError::Unsupported("struct destructuring must bind all fields exactly once".to_string()));
    }

    Ok(lowered)
}

fn validate_contract_struct_usage<'i>(contract: &ContractAst<'i>, structs: &StructRegistry) -> Result<(), CompilerError> {
    for param in &contract.params {
        ensure_known_or_builtin_type(&param.type_ref, structs, "contract parameter")?;
    }
    for field in &contract.fields {
        ensure_known_or_builtin_type(&field.type_ref, structs, "contract field")?;
    }
    for constant in &contract.constants {
        ensure_known_or_builtin_type(&constant.type_ref, structs, "constant")?;
    }

    Ok(())
}

fn compile_contract_impl<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
    source: Option<&'i str>,
) -> Result<CompiledContract<'i>, CompilerError> {
    if contract.functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no functions".to_string()));
    }
    if contract.params.len() != constructor_args.len() {
        return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
    }

    let structs = build_struct_registry(contract)?;
    validate_struct_graph(&structs)?;

    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if !expr_matches_declared_type_ref(value, &param.type_ref, &structs) {
            return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, param_type_name)));
        }
    }

    let mut constants: HashMap<String, Expr<'i>> =
        contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        constants.insert(param.name.clone(), value.clone());
    }

    let lowered_contract = lower_covenant_declarations(contract, &constants)?;
    let structs = build_struct_registry(&lowered_contract)?;
    validate_struct_graph(&structs)?;
    validate_contract_struct_usage(&lowered_contract, &structs)?;

    let entrypoint_functions: Vec<&FunctionAst<'i>> = lowered_contract.functions.iter().filter(|func| func.entrypoint).collect();
    if entrypoint_functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entrypoint functions".to_string()));
    }

    let without_selector = entrypoint_functions.len() == 1;

    let functions_map = lowered_contract.functions.iter().cloned().map(|func| (func.name.clone(), func)).collect::<HashMap<_, _>>();
    let function_order =
        lowered_contract.functions.iter().enumerate().map(|(index, func)| (func.name.clone(), index)).collect::<HashMap<_, _>>();
    let function_abi_entries = build_function_abi_entries(&lowered_contract);
    let uses_script_size = contract_uses_script_size(&lowered_contract, &structs, &constants);

    let mut script_size = if uses_script_size { Some(100i64) } else { None };

    for _ in 0..32 {
        let (_contract_fields, field_prolog_script) =
            compile_contract_fields(&lowered_contract.fields, &constants, options, script_size, &structs)?;

        let mut recorder = DebugRecorder::new(options.record_debug_infos);
        recorder.record_contract_scope(&contract.params, constructor_args, &contract.constants);
        let selector_prefix_len = if without_selector { 0 } else { 1 };
        let contract_field_prefix_len = selector_prefix_len + field_prolog_script.len();
        let state_layout = CompiledStateLayout { start: selector_prefix_len, len: field_prolog_script.len() };
        let mut compiled_entrypoints = Vec::new();
        for (index, func) in lowered_contract.functions.iter().enumerate() {
            if func.entrypoint {
                compiled_entrypoints.push(compile_entrypoint_function(
                    func,
                    index,
                    &lowered_contract.fields,
                    contract_field_prefix_len,
                    &constants,
                    options,
                    &structs,
                    &functions_map,
                    &function_order,
                    script_size,
                    &mut recorder,
                )?);
            }
        }

        let script = if without_selector {
            let (name, entrypoint_script) = compiled_entrypoints
                .first()
                .ok_or_else(|| CompilerError::Unsupported("contract has no entrypoint functions".to_string()))?;
            recorder.set_entrypoint_start(name, field_prolog_script.len());
            let mut script = field_prolog_script.clone();
            script.extend(entrypoint_script.clone());
            script
        } else {
            // Preserve the selector while encoding contract state once so
            // reflection helpers can rewrite a single contiguous state segment.
            let mut builder = ScriptBuilder::new();
            builder.add_op(OpToAltStack)?;
            builder.add_ops(&field_prolog_script)?;
            builder.add_op(OpFromAltStack)?;
            let total = compiled_entrypoints.len();
            for (entrypoint_index, (name, script)) in compiled_entrypoints.iter().enumerate() {
                builder.add_op(OpDup)?;
                builder.add_i64(entrypoint_index as i64)?;
                builder.add_op(OpNumEqual)?;
                builder.add_op(OpIf)?;
                builder.add_op(OpDrop)?;
                let start = builder.script().len();
                recorder.set_entrypoint_start(name, start);
                builder.add_ops(script)?;
                builder.add_op(OpElse)?;
                if entrypoint_index == total - 1 {
                    builder.add_op(OpDrop)?;
                    builder.add_op(OpFalse)?;
                    builder.add_op(OpVerify)?;
                }
            }

            for _ in 0..total {
                builder.add_op(OpEndIf)?;
            }

            builder.drain()
        };

        let debug_info = recorder.into_debug_info(source.unwrap_or_default().to_string());
        if !uses_script_size {
            return Ok(CompiledContract {
                contract_name: lowered_contract.name.clone(),
                script,
                ast: lowered_contract.clone(),
                abi: function_abi_entries,
                without_selector,
                state_layout,
                debug_info,
            });
        }

        let actual_size = script.len() as i64;
        if Some(actual_size) == script_size {
            return Ok(CompiledContract {
                contract_name: lowered_contract.name.clone(),
                script,
                ast: lowered_contract.clone(),
                abi: function_abi_entries,
                without_selector,
                state_layout,
                debug_info,
            });
        }
        script_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("script size did not stabilize".to_string()))
}

fn contract_uses_script_size<'i>(
    contract: &ContractAst<'i>,
    _structs: &StructRegistry,
    _contract_constants: &HashMap<String, Expr<'i>>,
) -> bool {
    if contract.constants.iter().any(|constant| expr_uses_script_size(&constant.expr)) {
        return true;
    }
    if contract.fields.iter().any(|field| expr_uses_script_size(&field.expr)) {
        return true;
    }
    contract.functions.iter().any(|func| func.body.iter().any(statement_uses_script_size))
}

fn expr_matches_declared_type_ref<'i>(expr: &Expr<'i>, type_ref: &TypeRef, structs: &StructRegistry) -> bool {
    if let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) {
        let Some(item) = structs.get(struct_name) else {
            return false;
        };
        let ExprKind::StateObject(fields) = &expr.kind else {
            return false;
        };
        if fields.len() != item.fields.len() {
            return false;
        }
        for field in &item.fields {
            let Some(value) = fields.iter().find(|entry| entry.name == field.name).map(|entry| &entry.expr) else {
                return false;
            };
            if !expr_matches_declared_type_ref(value, &field.type_ref, structs) {
                return false;
            }
        }
        return true;
    }

    if let Some(element_type) = array_element_type_ref(type_ref) {
        if struct_name_from_type_ref(&element_type, structs).is_some() {
            return matches!(&expr.kind, ExprKind::Array(values) if values.iter().all(|value| expr_matches_declared_type_ref(value, &element_type, structs)));
        }
    }

    expr_matches_type_ref(expr, type_ref)
}

fn encode_struct_value<'i>(expr: &Expr<'i>, type_ref: &TypeRef, structs: &StructRegistry) -> Result<Vec<u8>, CompilerError> {
    let struct_name = struct_name_from_type_ref(type_ref, structs)
        .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", type_ref.type_name())))?;
    let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let ExprKind::StateObject(fields) = &expr.kind else {
        return Err(CompilerError::Unsupported(format!("expression expects struct {}", type_ref.type_name())));
    };

    let mut out = Vec::new();
    for field in &item.fields {
        let value = fields
            .iter()
            .find(|entry| entry.name == field.name)
            .map(|entry| &entry.expr)
            .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))?;
        if struct_name_from_type_ref(&field.type_ref, structs).is_some() {
            out.extend(encode_struct_value(value, &field.type_ref, structs)?);
        } else {
            let field_type_name = type_name_from_ref(&field.type_ref);
            if field.type_ref.array_dims.is_empty() && field.type_ref.base == TypeBase::Int {
                let ExprKind::Int(number) = &value.kind else {
                    return Err(CompilerError::Unsupported(format!("struct field '{}' expects int", field.name)));
                };
                let serialized = serialize_i64(*number, Some(8usize))
                    .map_err(|err| CompilerError::Unsupported(format!("failed to serialize int literal {}: {err}", number)))?;
                out.extend_from_slice(&data_prefix(serialized.len()));
                out.extend(serialized);
            } else if is_array_type(&field_type_name)
                || matches!(value.kind, ExprKind::Array(_) | ExprKind::String(_) | ExprKind::Byte(_))
            {
                let encoded = match &value.kind {
                    ExprKind::Array(values) => {
                        if is_byte_array(value) {
                            values.iter().filter_map(|v| if let ExprKind::Byte(byte) = &v.kind { Some(*byte) } else { None }).collect()
                        } else {
                            encode_array_literal(values, &field_type_name)?
                        }
                    }
                    ExprKind::String(string) => string.as_bytes().to_vec(),
                    ExprKind::Byte(byte) => vec![*byte],
                    _ => return Err(CompilerError::Unsupported(format!("struct field '{}' expects {}", field.name, field_type_name))),
                };
                out.extend_from_slice(&data_prefix(encoded.len()));
                out.extend(encoded);
            } else {
                let encoded = encode_fixed_size_value(value, &field_type_name)?;
                out.extend_from_slice(&data_prefix(encoded.len()));
                out.extend(encoded);
            }
        }
    }
    Ok(out)
}

fn compile_contract_fields<'i>(
    fields: &[ContractFieldAst<'i>],
    base_constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    script_size: Option<i64>,
    structs: &StructRegistry,
) -> Result<(HashMap<String, Expr<'i>>, Vec<u8>), CompilerError> {
    let mut env = base_constants.clone();
    let mut field_values = HashMap::new();
    let mut field_types = HashMap::new();
    let mut builder = ScriptBuilder::new();
    let stack_bindings = StackBindings::default();

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
        if !expr_matches_declared_type_ref(&resolved, &field.type_ref, structs) {
            return Err(CompilerError::Unsupported(format!("contract field '{}' expects {}", field.name, type_name)));
        }

        let mut compile_visiting = HashSet::new();
        let mut stack_depth = 0i64;
        if struct_name_from_type_ref(&field.type_ref, structs).is_some() {
            let encoded = encode_struct_value(&resolved, &field.type_ref, structs)?;
            builder.add_data(&encoded)?;
        } else if fixed_type_size_with_constants_ref(&field.type_ref, &env).is_some() {
            let encoded = encode_fixed_size_value(&resolved, &type_name)?;
            builder.add_data(&encoded)?;
        } else {
            compile_expr(
                &resolved,
                &env,
                &stack_bindings,
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
        Statement::FunctionCall { name, args, .. } => {
            name == "validateOutputState" || name == "validateOutputStateWithTemplate" || args.iter().any(expr_uses_script_size)
        }
        Statement::FunctionCallAssign { args, .. } => args.iter().any(expr_uses_script_size),
        Statement::StateFunctionCallAssign { name, args, .. } => name == "readInputState" || args.iter().any(expr_uses_script_size),
        Statement::StructDestructure { expr, .. } => expr_uses_script_size(expr),
        Statement::Assign { expr, .. } => expr_uses_script_size(expr),
        Statement::TimeOp { expr, .. } => expr_uses_script_size(expr),
        Statement::Require { expr, .. } => expr_uses_script_size(expr),
        Statement::If { condition, then_branch, else_branch, .. } => {
            expr_uses_script_size(condition)
                || then_branch.iter().any(statement_uses_script_size)
                || else_branch.as_ref().is_some_and(|branch| branch.iter().any(statement_uses_script_size))
        }
        Statement::For { start, end, max_iterations, body, .. } => {
            expr_uses_script_size(start)
                || expr_uses_script_size(end)
                || expr_uses_script_size(max_iterations)
                || body.iter().any(statement_uses_script_size)
        }
        Statement::Return { exprs, .. } => exprs.iter().any(expr_uses_script_size),
        Statement::Console { args, .. } => args.iter().any(expr_uses_script_size),
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
        ExprKind::StateObject(fields) => fields.iter().any(|field| expr_uses_script_size(&field.expr)),
        ExprKind::Call { name, args, .. } => name == "readInputState" || args.iter().any(expr_uses_script_size),
        ExprKind::New { args, .. } => args.iter().any(expr_uses_script_size),
        ExprKind::Split { source, index, .. } => expr_uses_script_size(source) || expr_uses_script_size(index),
        ExprKind::Slice { source, start, end, .. } => {
            expr_uses_script_size(source) || expr_uses_script_size(start) || expr_uses_script_size(end)
        }
        ExprKind::FieldAccess { source, .. } => expr_uses_script_size(source),
        ExprKind::UnarySuffix { source, .. } => expr_uses_script_size(source),
        ExprKind::ArrayIndex { source, index } => expr_uses_script_size(source) || expr_uses_script_size(index),
        ExprKind::Introspection { index, .. } => expr_uses_script_size(index),
        ExprKind::Int(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::Identifier(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::NumberWithUnit { .. }
        | ExprKind::Nullary(_) => false,
    }
}

fn is_byte_array<'i>(expr: &Expr<'i>) -> bool {
    byte_array_len(expr).is_some()
}

fn byte_array_len<'i>(expr: &Expr<'i>) -> Option<usize> {
    match &expr.kind {
        ExprKind::Array(values) if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => Some(values.len()),
        _ => None,
    }
}

/// Does the expression match the expected type passed as a secondary argument.
///
/// If type is a fixed-size array (known at parsing time), it also verifies the array length.
fn expr_matches_type_ref<'i>(expr: &Expr<'i>, type_ref: &TypeRef) -> bool {
    if is_array_type_ref(type_ref) {
        if let Some(size) = array_size_ref(type_ref) {
            if let Some(element_type) = array_element_type_ref(type_ref) {
                if element_type.base == TypeBase::Byte {
                    return byte_array_len(expr) == Some(size);
                }
                return matches!(&expr.kind, ExprKind::Array(values) if values.len() == size && array_literal_matches_type_ref(values, type_ref));
            }
        }
        return is_byte_array(expr)
            || matches!(&expr.kind, ExprKind::Array(values) if array_literal_matches_type_ref(values, type_ref));
    }

    match type_ref.base {
        TypeBase::Int => matches!(&expr.kind, ExprKind::Int(_) | ExprKind::DateLiteral(_)),
        TypeBase::Bool => matches!(&expr.kind, ExprKind::Bool(_)),
        TypeBase::String => matches!(&expr.kind, ExprKind::String(_)),
        TypeBase::Byte => matches!(&expr.kind, ExprKind::Byte(_)),
        TypeBase::Pubkey => byte_array_len(expr) == Some(32),
        TypeBase::Sig => byte_array_len(expr) == Some(65),
        TypeBase::Datasig => byte_array_len(expr) == Some(64),
        TypeBase::Custom(_) => false,
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

fn build_function_abi_entries<'i>(contract: &ContractAst<'i>) -> Vec<FunctionAbiEntry> {
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

fn flatten_type_ref_leaves(type_ref: &TypeRef, structs: &StructRegistry) -> Result<Vec<(Vec<String>, TypeRef)>, CompilerError> {
    if let Some(struct_name) = struct_array_name_from_type_ref(type_ref, structs) {
        let outer_dims = type_ref.array_dims.clone();
        let item = structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        let mut leaves = Vec::new();
        for field in &item.fields {
            let mut field_type = field.type_ref.clone();
            field_type.array_dims.extend(outer_dims.iter().cloned());
            for (mut path, leaf_type) in flatten_type_ref_leaves(&field_type, structs)? {
                path.insert(0, field.name.clone());
                leaves.push((path, leaf_type));
            }
        }
        return Ok(leaves);
    }

    let mut leaves = Vec::new();
    flatten_struct_fields(type_ref, structs, &mut Vec::new(), &mut leaves)?;
    Ok(leaves)
}

fn lowering_scope_from_types(types: &HashMap<String, String>) -> Result<LoweringScope, CompilerError> {
    let mut scope = LoweringScope::default();
    for (name, type_name) in types {
        scope.vars.insert(name.clone(), parse_type_ref(type_name)?);
    }
    Ok(scope)
}

fn lower_runtime_expr<'i>(
    expr: &Expr<'i>,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
) -> Result<Expr<'i>, CompilerError> {
    let scope = lowering_scope_from_types(types)?;
    lower_expr(expr, &scope, structs)
}

fn lower_runtime_struct_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let scope = lowering_scope_from_types(types)?;
    if struct_name_from_type_ref(expected_type, structs).is_some() {
        return lower_struct_value_expr(
            expr,
            expected_type,
            &scope,
            structs,
            contract_fields,
            contract_constants,
            contract_field_prefix_len,
        );
    }
    if struct_array_name_from_type_ref(expected_type, structs).is_some() {
        return lower_struct_array_value_expr(
            expr,
            expected_type,
            &scope,
            structs,
            contract_fields,
            contract_constants,
            contract_field_prefix_len,
        );
    }
    Err(CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))
}

fn lower_struct_array_value_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &LoweringScope,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let Some(struct_name) = struct_array_name_from_type_ref(expected_type, structs) else {
        return Err(CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())));
    };

    match &expr.kind {
        ExprKind::Identifier(name) => {
            let actual_type =
                scope.vars.get(name).ok_or_else(|| CompilerError::Unsupported(format!("undefined identifier '{}'", name)))?;
            let actual_struct_name = struct_array_name_from_type_ref(actual_type, structs)
                .ok_or_else(|| CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name())))?;
            if actual_struct_name != struct_name || !is_type_assignable_ref(actual_type, expected_type, contract_constants) {
                return Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name())));
            }
            let leaves = flatten_type_ref_leaves(expected_type, structs)?;
            Ok(leaves
                .into_iter()
                .map(|(path, _)| Expr::new(ExprKind::Identifier(flattened_struct_name(name, &path)), span::Span::default()))
                .collect())
        }
        ExprKind::Array(values) => {
            let element_type = expected_type
                .element_type()
                .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;
            let leaf_specs = flatten_type_ref_leaves(&element_type, structs)?;
            let mut grouped: Vec<Vec<Expr<'i>>> = vec![Vec::with_capacity(values.len()); leaf_specs.len()];
            for value in values {
                let lowered = lower_struct_value_expr(
                    value,
                    &element_type,
                    scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                for (idx, expr) in lowered.into_iter().enumerate() {
                    grouped[idx].push(expr);
                }
            }
            Ok(grouped.into_iter().map(|entries| Expr::new(ExprKind::Array(entries), span::Span::default())).collect())
        }
        _ => Err(CompilerError::Unsupported(format!("expression expects struct {}", expected_type.type_name()))),
    }
}

fn flatten_runtime_return_exprs<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let mut flattened = Vec::new();
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        if struct_name_from_type_ref(return_type, structs).is_some() {
            flattened.extend(lower_runtime_struct_expr(
                expr,
                return_type,
                types,
                structs,
                contract_fields,
                contract_constants,
                contract_field_prefix_len,
            )?);
        } else {
            flattened.push(lower_runtime_expr(expr, types, structs)?);
        }
    }
    Ok(flattened)
}

fn store_struct_binding<'i>(
    name: &str,
    type_ref: &TypeRef,
    expr: &Expr<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    types: &mut HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_field_prefix_len: usize,
    is_assignment: bool,
) -> Result<(), CompilerError> {
    let lowered_values =
        lower_runtime_struct_expr(expr, type_ref, types, structs, contract_fields, contract_constants, contract_field_prefix_len)?;
    store_struct_binding_from_lowered_values(name, type_ref, lowered_values, env, types, structs, is_assignment)
}

fn store_struct_binding_from_lowered_values<'i>(
    name: &str,
    type_ref: &TypeRef,
    lowered_values: Vec<Expr<'i>>,
    env: &mut HashMap<String, Expr<'i>>,
    types: &mut HashMap<String, String>,
    structs: &StructRegistry,
    is_assignment: bool,
) -> Result<(), CompilerError> {
    let leaf_bindings = flatten_type_ref_leaves(type_ref, structs)?;
    let original_env = env.clone();
    let mut pending = Vec::with_capacity(leaf_bindings.len());

    for ((path, field_type), lowered_expr) in leaf_bindings.into_iter().zip(lowered_values.into_iter()) {
        let leaf_name = flattened_struct_name(name, &path);
        let stored_expr = if is_assignment {
            let updated = if let Some(previous) = original_env.get(&leaf_name) {
                replace_identifier(&lowered_expr, &leaf_name, previous)
            } else {
                lowered_expr
            };
            resolve_expr_for_runtime(updated, &original_env, types, &mut HashSet::new())?
        } else {
            lowered_expr
        };
        pending.push((leaf_name, type_name_from_ref(&field_type), stored_expr));
    }

    types.insert(name.to_string(), type_name_from_ref(type_ref));
    for (leaf_name, field_type_name, stored_expr) in pending {
        types.insert(leaf_name.clone(), field_type_name);
        env.insert(leaf_name, stored_expr);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn store_struct_binding_with_stack_rebindings<'i>(
    name: &str,
    type_ref: &TypeRef,
    lowered_values: Vec<Expr<'i>>,
    env: &mut HashMap<String, Expr<'i>>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    structs: &StructRegistry,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let leaf_bindings = flatten_type_ref_leaves(type_ref, structs)?;
    let original_env = env.clone();

    types.insert(name.to_string(), type_name_from_ref(type_ref));
    for ((path, field_type), lowered_expr) in leaf_bindings.into_iter().zip(lowered_values.into_iter()) {
        let leaf_name = flattened_struct_name(name, &path);
        let field_type_name = type_name_from_ref(&field_type);
        types.insert(leaf_name.clone(), field_type_name.clone());

        if matches!(field_type_name.as_str(), "int" | "bool" | "byte") && stack_bindings.contains(&leaf_name) {
            let mut stack_depth = 0i64;
            compile_expr(
                &lowered_expr,
                env,
                stack_bindings,
                types,
                builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                contract_constants,
            )?;
            stack_bindings.emit_update_stack_for_rebinding(&leaf_name, builder)?;
            continue;
        }

        let updated = if let Some(previous) = original_env.get(&leaf_name) {
            replace_identifier(&lowered_expr, &leaf_name, previous)
        } else {
            lowered_expr
        };
        let stored_expr = resolve_expr_for_runtime(updated, &original_env, types, &mut HashSet::new())?;
        env.insert(leaf_name, stored_expr);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_struct_leaf_stack_bindings<'i>(
    name: &str,
    type_ref: &TypeRef,
    env: &HashMap<String, Expr<'i>>,
    _assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    structs: &StructRegistry,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<String>, CompilerError> {
    if identifier_uses.get(name).copied().unwrap_or(0) < 2 {
        return Ok(Vec::new());
    }

    let mut added = Vec::new();
    for (path, leaf_type) in flatten_type_ref_leaves(type_ref, structs)? {
        let leaf_type_name = type_name_from_ref(&leaf_type);
        if !matches!(leaf_type_name.as_str(), "int" | "bool" | "byte") {
            continue;
        }

        let leaf_name = flattened_struct_name(name, &path);
        if stack_bindings.contains(&leaf_name) {
            continue;
        }

        let Some(bound_expr) = env.get(&leaf_name).cloned() else {
            continue;
        };

        let mut stack_depth = 0i64;
        compile_expr(
            &bound_expr,
            env,
            stack_bindings,
            types,
            builder,
            options,
            &mut HashSet::new(),
            &mut stack_depth,
            script_size,
            contract_constants,
        )?;
        stack_bindings.push_binding(&leaf_name);
        added.push(leaf_name);
    }

    Ok(added)
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
        TypeBase::Custom(_) => None,
    }
}

fn fixed_type_size_with_constants_ref<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    if type_ref.array_dims.is_empty() {
        return fixed_type_size_ref(type_ref).map(|size| size as usize);
    }

    let element_type = array_element_type_ref(type_ref)?;
    let array_len = array_size_with_constants_ref(type_ref, constants)?;
    let element_size = fixed_type_size_with_constants_ref(&element_type, constants)?;
    Some(array_len * element_size)
}

fn fixed_state_field_payload_len_for_type_ref<'i>(
    type_ref: &TypeRef,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(usize, bool), CompilerError> {
    let payload_len = fixed_type_size_with_constants_ref(type_ref, contract_constants).ok_or_else(|| {
        CompilerError::Unsupported(format!("readInputState does not support field type {}", type_name_from_ref(type_ref)))
    })?;
    let decode_numeric = type_ref.array_dims.is_empty() && matches!(type_ref.base, TypeBase::Int | TypeBase::Bool);
    Ok((payload_len, decode_numeric))
}

fn fixed_state_field_payload_len<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(usize, bool), CompilerError> {
    fixed_state_field_payload_len_for_type_ref(&field.type_ref, contract_constants)
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

fn collect_assigned_names<'i>(statements: &[Statement<'i>]) -> HashSet<String> {
    let mut assigned = HashSet::new();
    collect_assigned_names_into(statements, &mut assigned);
    assigned
}

fn collect_identifier_uses<'i>(statements: &[Statement<'i>]) -> HashMap<String, usize> {
    let mut uses = HashMap::new();
    for stmt in statements {
        collect_statement_identifier_uses(stmt, &mut uses);
    }
    uses
}

fn bump_identifier_use(uses: &mut HashMap<String, usize>, name: &str) {
    *uses.entry(name.to_string()).or_insert(0) += 1;
}

fn collect_statement_identifier_uses<'i>(stmt: &Statement<'i>, uses: &mut HashMap<String, usize>) {
    match stmt {
        Statement::VariableDefinition { expr, .. } => {
            if let Some(expr) = expr {
                collect_expr_identifier_uses(expr, uses);
            }
        }
        Statement::TupleAssignment { expr, .. }
        | Statement::Assign { expr, .. }
        | Statement::TimeOp { expr, .. }
        | Statement::Require { expr, .. }
        | Statement::StructDestructure { expr, .. } => collect_expr_identifier_uses(expr, uses),
        Statement::ArrayPush { expr, .. } => collect_expr_identifier_uses(expr, uses),
        Statement::FunctionCall { args, .. }
        | Statement::FunctionCallAssign { args, .. }
        | Statement::StateFunctionCallAssign { args, .. } => {
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
        }
        Statement::If { condition, then_branch, else_branch, .. } => {
            collect_expr_identifier_uses(condition, uses);
            for stmt in then_branch {
                collect_statement_identifier_uses(stmt, uses);
            }
            if let Some(else_branch) = else_branch {
                for stmt in else_branch {
                    collect_statement_identifier_uses(stmt, uses);
                }
            }
        }
        Statement::For { start, end, max_iterations, body, .. } => {
            collect_expr_identifier_uses(start, uses);
            collect_expr_identifier_uses(end, uses);
            collect_expr_identifier_uses(max_iterations, uses);
            for stmt in body {
                collect_statement_identifier_uses(stmt, uses);
            }
        }
        Statement::Return { exprs, .. } => {
            for expr in exprs {
                collect_expr_identifier_uses(expr, uses);
            }
        }
        Statement::Console { args, .. } => {
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
        }
    }
}

fn collect_expr_identifier_uses<'i>(expr: &Expr<'i>, uses: &mut HashMap<String, usize>) {
    match &expr.kind {
        ExprKind::Identifier(name) => bump_identifier_use(uses, name),
        ExprKind::Unary { expr, .. } => collect_expr_identifier_uses(expr, uses),
        ExprKind::Binary { left, right, .. } => {
            collect_expr_identifier_uses(left, uses);
            collect_expr_identifier_uses(right, uses);
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            collect_expr_identifier_uses(condition, uses);
            collect_expr_identifier_uses(then_expr, uses);
            collect_expr_identifier_uses(else_expr, uses);
        }
        ExprKind::Array(values) => {
            for value in values {
                collect_expr_identifier_uses(value, uses);
            }
        }
        ExprKind::StateObject(fields) => {
            for field in fields {
                collect_expr_identifier_uses(&field.expr, uses);
            }
        }
        ExprKind::Call { args, .. } | ExprKind::New { args, .. } => {
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
        }
        ExprKind::Split { source, index, .. } | ExprKind::ArrayIndex { source, index } => {
            collect_expr_identifier_uses(source, uses);
            collect_expr_identifier_uses(index, uses);
        }
        ExprKind::Slice { source, start, end, .. } => {
            collect_expr_identifier_uses(source, uses);
            collect_expr_identifier_uses(start, uses);
            collect_expr_identifier_uses(end, uses);
        }
        ExprKind::Introspection { index, .. } => collect_expr_identifier_uses(index, uses),
        ExprKind::UnarySuffix { source, .. } | ExprKind::FieldAccess { source, .. } => collect_expr_identifier_uses(source, uses),
        ExprKind::Int(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::Nullary(_)
        | ExprKind::NumberWithUnit { .. } => {}
    }
}

fn collect_assigned_names_into<'i>(statements: &[Statement<'i>], assigned: &mut HashSet<String>) {
    for stmt in statements {
        match stmt {
            Statement::Assign { name, .. } | Statement::ArrayPush { name, .. } => {
                assigned.insert(name.clone());
            }
            Statement::If { then_branch, else_branch, .. } => {
                collect_assigned_names_into(then_branch, assigned);
                if let Some(else_branch) = else_branch {
                    collect_assigned_names_into(else_branch, assigned);
                }
            }
            Statement::For { ident, body, .. } => {
                assigned.insert(ident.clone());
                collect_assigned_names_into(body, assigned);
            }
            _ => {}
        }
    }
}

fn validate_return_types<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if return_types.is_empty() {
        return Err(CompilerError::Unsupported("return requires function return types".to_string()));
    }
    if return_types.len() != exprs.len() {
        return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
    }
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        let matches = if struct_name_from_type_ref(return_type, structs).is_some() {
            lower_runtime_struct_expr(expr, return_type, types, structs, contract_fields, constants, contract_field_prefix_len).is_ok()
        } else {
            expr_matches_return_type_ref(expr, return_type, types, constants)
        };

        if !matches {
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
        ExprKind::Array(values) => {
            (is_array_type_ref(type_ref) && array_literal_matches_type_ref(values, type_ref)) || expr_matches_type_ref(expr, type_ref)
        }
        ExprKind::Int(_) | ExprKind::DateLiteral(_) | ExprKind::Bool(_) | ExprKind::Byte(_) | ExprKind::String(_) => {
            expr_matches_type_ref(expr, type_ref)
        }
        _ => true,
    }
}

fn expr_matches_return_type_ref_hint<'i>(expr: &Expr<'i>, type_ref: &TypeRef) -> Option<String> {
    match (&expr.kind, &type_ref.base, type_ref.array_dims.is_empty()) {
        (ExprKind::Array(values), TypeBase::Byte, true) if values.len() == 1 => match values[0].kind {
            ExprKind::Byte(byte) => {
                Some(format!("hex literals are byte arrays; use byte({byte:#04x}) to cast a one-byte hex literal to byte"))
            }
            _ => None,
        },
        _ => None,
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
        let structs = build_struct_registry(&self.ast)?;
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

        let mut builder = ScriptBuilder::new();
        for (input, arg) in function.inputs.iter().zip(args) {
            let type_ref = parse_type_ref(&input.type_name)?;
            push_typed_sigscript_arg(&mut builder, arg, &type_ref, &structs).map_err(|err| {
                CompilerError::Unsupported(format!("function argument '{}' expects {} ({err})", input.name, input.type_name))
            })?;
        }
        if !self.without_selector {
            let selector = function_branch_index(&self.ast, function_name)?;
            builder.add_i64(selector)?;
        }
        Ok(builder.drain())
    }

    pub fn build_sig_script_for_covenant_decl(
        &self,
        function_name: &str,
        args: Vec<Expr<'i>>,
        options: CovenantDeclCallOptions,
    ) -> Result<Vec<u8>, CompilerError> {
        let auth_entrypoint = generated_covenant_entrypoint_name(function_name);
        if self.abi.iter().any(|entry| entry.name == auth_entrypoint) {
            return self.build_sig_script(&auth_entrypoint, args);
        }

        let entrypoint = if options.is_leader {
            generated_covenant_leader_entrypoint_name(function_name)
        } else {
            generated_covenant_delegate_entrypoint_name(function_name)
        };

        if self.abi.iter().any(|entry| entry.name == entrypoint) {
            return self.build_sig_script(&entrypoint, args);
        }

        Err(CompilerError::Unsupported(format!("covenant declaration '{}' not found", function_name)))
    }
}

fn push_typed_sigscript_arg<'i>(
    builder: &mut ScriptBuilder,
    arg: Expr<'i>,
    type_ref: &TypeRef,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    if let Some(element_type) = type_ref.element_type() {
        if let Some(struct_name) = struct_name_from_type_ref(&element_type, structs) {
            let item =
                structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            let ExprKind::Array(values) = arg.kind else {
                return Err(CompilerError::Unsupported("signature script struct array arguments must be array literals".to_string()));
            };

            for field in &item.fields {
                let mut field_values = Vec::with_capacity(values.len());
                for value in &values {
                    let ExprKind::StateObject(entries) = &value.kind else {
                        return Err(CompilerError::Unsupported(
                            "signature script struct array arguments must contain object literals".to_string(),
                        ));
                    };

                    let mut matched = None;
                    for entry in entries {
                        if entry.name == field.name {
                            if matched.is_some() {
                                return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", field.name)));
                            }
                            matched = Some(entry.expr.clone());
                        }
                    }

                    field_values
                        .push(matched.ok_or_else(|| {
                            CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name))
                        })?);

                    if let Some(extra) = entries.iter().find(|entry| item.fields.iter().all(|field| field.name != entry.name)) {
                        return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra.name)));
                    }
                }

                let mut field_type = field.type_ref.clone();
                field_type.array_dims.push(ArrayDim::Dynamic);
                push_typed_sigscript_arg(
                    builder,
                    Expr::new(ExprKind::Array(field_values), span::Span::default()),
                    &field_type,
                    structs,
                )?;
            }
            return Ok(());
        }
    }

    if let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) {
        let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        let ExprKind::StateObject(fields) = arg.kind else {
            return Err(CompilerError::Unsupported("signature script struct arguments must be object literals".to_string()));
        };
        let mut provided = HashMap::new();
        for field in fields {
            if provided.insert(field.name.clone(), field.expr).is_some() {
                return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", field.name)));
            }
        }
        for field in &item.fields {
            let value = provided
                .remove(&field.name)
                .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))?;
            push_typed_sigscript_arg(builder, value, &field.type_ref, structs)?;
        }
        if let Some(extra) = provided.keys().next() {
            return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
        }
        return Ok(());
    }

    if !expr_matches_type_ref(&arg, type_ref) {
        return Err(CompilerError::Unsupported("signature script arguments must match the declared type".to_string()));
    }

    let type_name = type_name_from_ref(type_ref);
    if is_array_type(&type_name) {
        match &arg.kind {
            ExprKind::Array(values) => {
                if is_byte_array(&arg) {
                    let bytes: Vec<u8> = values
                        .iter()
                        .filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None })
                        .collect();
                    builder.add_data(&bytes)?;
                } else {
                    let bytes = encode_array_literal(values, &type_name)?;
                    builder.add_data(&bytes)?;
                }
                Ok(())
            }
            _ => Err(CompilerError::Unsupported("signature script arguments must be literals".to_string())),
        }
    } else {
        push_sigscript_arg(builder, arg)
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
        ExprKind::Byte(value) => {
            builder.add_data(&[value])?;
        }
        ExprKind::Array(values) if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => {
            let bytes: Vec<u8> =
                values.iter().filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None }).collect();
            builder.add_data(&bytes)?;
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
            serialize_i64(number, Some(8usize))
                .map_err(|err| CompilerError::Unsupported(format!("failed to serialize int literal {}: {err}", number)))
        }
        "bool" => {
            let ExprKind::Bool(flag) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(vec![u8::from(*flag)])
        }
        "byte" => {
            let ExprKind::Byte(byte) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(vec![*byte])
        }
        "pubkey" => {
            let Some(len) = byte_array_len(value) else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            if len != 32 {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            }
            let ExprKind::Array(bytes_exprs) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(bytes_exprs
                .iter()
                .filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None })
                .collect())
        }
        "sig" | "datasig" => {
            let expected_len = if type_name == "sig" { 65 } else { 64 };
            let Some(len) = byte_array_len(value) else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            if len != expected_len {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            }
            let ExprKind::Array(bytes_exprs) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(bytes_exprs
                .iter()
                .filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None })
                .collect())
        }
        _ => {
            // Handle fixed-size byte arrays like byte[N]
            if let (Some(inner_type), Some(size)) = (array_element_type(type_name), array_size(type_name)) {
                if inner_type == "byte" {
                    let Some(len) = byte_array_len(value) else {
                        return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                    };
                    if len != size {
                        return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                    }
                    let ExprKind::Array(bytes_exprs) = &value.kind else {
                        return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                    };
                    return Ok(bytes_exprs
                        .iter()
                        .filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None })
                        .collect());
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
        ExprKind::Byte(_) => Some("byte".to_string()),
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

#[allow(clippy::too_many_arguments)]
fn compile_entrypoint_function<'i>(
    function: &FunctionAst<'i>,
    function_index: usize,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
) -> Result<(String, Vec<u8>), CompilerError> {
    let contract_field_count = contract_fields.len();
    let mut flattened_param_names = Vec::new();
    let mut types = HashMap::new();
    for param in &function.params {
        let param_type_name = type_name_from_ref(&param.type_ref);
        types.insert(param.name.clone(), param_type_name.clone());
        if struct_name_from_type_ref(&param.type_ref, structs).is_some()
            || struct_array_name_from_type_ref(&param.type_ref, structs).is_some()
        {
            for (path, field_type) in flatten_type_ref_leaves(&param.type_ref, structs)? {
                let leaf_name = flattened_struct_name(&param.name, &path);
                types.insert(leaf_name.clone(), type_name_from_ref(&field_type));
                flattened_param_names.push(leaf_name);
            }
        } else {
            flattened_param_names.push(param.name.clone());
        }
    }

    let param_count = flattened_param_names.len();
    let mut stack_bindings = StackBindings::from_depths(
        flattened_param_names
            .iter()
            .enumerate()
            .map(|(index, name)| (name.clone(), (param_count - 1 - index) as i64))
            .collect::<HashMap<_, _>>(),
    );
    let initial_stack_binding_count = stack_bindings.len() + contract_field_count;

    for (index, field) in contract_fields.iter().enumerate().rev() {
        stack_bindings.set_depth_from_top(&field.name, (contract_field_count - 1 - index) as i64);
    }

    for field in contract_fields {
        types.insert(field.name.clone(), type_name_from_ref(&field.type_ref));
    }
    for param in &function.params {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if is_array_type(&param_type_name)
            && array_element_size(&param_type_name).is_none()
            && struct_array_name_from_type_ref(&param.type_ref, structs).is_none()
        {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param_type_name)));
        }
    }
    for return_type in &function.return_types {
        let return_type_name = type_name_from_ref(return_type);
        if is_array_type(&return_type_name)
            && array_element_size(&return_type_name).is_none()
            && struct_array_name_from_type_ref(return_type, structs).is_none()
        {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {return_type_name}")));
        }
    }
    let mut env: HashMap<String, Expr<'i>> = constants.clone();
    // Remove any constructor/constant names that collide with function param names (prioritizing function parameters on name collision).
    for param in &function.params {
        env.remove(&param.name);
        if struct_name_from_type_ref(&param.type_ref, structs).is_some()
            || struct_array_name_from_type_ref(&param.type_ref, structs).is_some()
        {
            for (path, _) in flatten_type_ref_leaves(&param.type_ref, structs)? {
                env.remove(&flattened_struct_name(&param.name, &path));
            }
        }
    }
    let mut builder = ScriptBuilder::new();
    let mut return_exprs: Vec<Expr> = Vec::new();
    let assigned_names = collect_assigned_names(&function.body);
    let identifier_uses = collect_identifier_uses(&function.body);

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
        if function.return_types.is_empty() {
            return Err(CompilerError::Unsupported("return requires function return types".to_string()));
        }
    }

    recorder.begin_entrypoint(&function.name, function, contract_fields);

    let body_len = function.body.len();
    for (index, stmt) in function.body.iter().enumerate() {
        recorder.begin_statement_at(builder.script().len(), &env, &stack_bindings);
        if let Statement::Return { exprs, .. } = stmt {
            if index != body_len - 1 {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            validate_return_types(
                exprs,
                &function.return_types,
                &types,
                structs,
                contract_fields,
                contract_field_prefix_len,
                constants,
            )?;
            for expr in exprs {
                let resolved = resolve_return_expr_for_runtime(expr.clone(), &env, &stack_bindings, &types, &mut HashSet::new())
                    .map_err(|err| err.with_span(&expr.span))?;
                return_exprs.push(resolved);
            }
        } else {
            compile_statement(
                stmt,
                &mut env,
                &assigned_names,
                &identifier_uses,
                &mut types,
                &mut stack_bindings,
                &mut builder,
                options,
                true,
                contract_fields,
                contract_field_prefix_len,
                constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
                recorder,
            )
            .map_err(|err| err.with_span(&stmt.span()))?;
        }
        recorder.finish_statement_at(stmt, builder.script().len(), &env, &types, &stack_bindings)?;
    }

    let flattened_returns = if has_return {
        flatten_runtime_return_exprs(
            &return_exprs,
            &function.return_types,
            &types,
            structs,
            contract_fields,
            constants,
            contract_field_prefix_len,
        )?
    } else {
        Vec::new()
    };

    let return_count = flattened_returns.len();
    if return_count == 0 {
        for _ in 0..stack_bindings.len().saturating_sub(initial_stack_binding_count) {
            builder.add_i64(return_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
        for _ in 0..param_count {
            builder.add_op(OpDrop)?;
        }
        for _ in 0..contract_field_count {
            builder.add_op(OpDrop)?;
        }
        builder.add_op(OpTrue)?;
    } else {
        let mut stack_depth = 0i64;
        for expr in &flattened_returns {
            compile_expr(
                expr,
                &env,
                &stack_bindings,
                &types,
                &mut builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                constants,
            )?;
        }
        for _ in 0..stack_bindings.len().saturating_sub(initial_stack_binding_count) {
            builder.add_i64(return_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
        for _ in 0..param_count {
            builder.add_i64(return_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
        for _ in 0..contract_field_count {
            builder.add_i64(return_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
    }
    let script = builder.drain();
    recorder.finish_entrypoint(script.len());
    Ok((function.name.clone(), script))
}

#[allow(clippy::too_many_arguments)]
fn compile_statement<'i>(
    stmt: &Statement<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    enable_mutable_scalar_stack_locals: bool,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
) -> Result<Vec<String>, CompilerError> {
    match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            if struct_name_from_type_ref(type_ref, structs).is_some() {
                let expr =
                    expr.as_ref().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
                if let ExprKind::Call { name: builtin_name, args, .. } = &expr.kind
                    && builtin_name == "readInputStateWithTemplate"
                {
                    let lowered_values = read_input_state_with_template_values(args, type_ref, structs, contract_constants)?;
                    let layout_fields = flattened_struct_field_specs_for_type(type_ref, structs)?;
                    compile_read_input_state_with_template_validation(
                        args,
                        env,
                        stack_bindings,
                        types,
                        builder,
                        options,
                        &layout_fields,
                        script_size,
                        contract_constants,
                    )?;
                    store_struct_binding_from_lowered_values(name, type_ref, lowered_values, env, types, structs, false)?;
                    return push_struct_leaf_stack_bindings(
                        name,
                        type_ref,
                        env,
                        assigned_names,
                        identifier_uses,
                        types,
                        stack_bindings,
                        builder,
                        options,
                        structs,
                        script_size,
                        contract_constants,
                    );
                }
                store_struct_binding(
                    name,
                    type_ref,
                    expr,
                    env,
                    types,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                    false,
                )?;
                return push_struct_leaf_stack_bindings(
                    name,
                    type_ref,
                    env,
                    assigned_names,
                    identifier_uses,
                    types,
                    stack_bindings,
                    builder,
                    options,
                    structs,
                    script_size,
                    contract_constants,
                );
            }
            if struct_array_name_from_type_ref(type_ref, structs).is_some() {
                if let Some(expr) = expr.as_ref() {
                    return store_struct_binding(
                        name,
                        type_ref,
                        expr,
                        env,
                        types,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                        false,
                    )
                    .map(|_| Vec::new());
                }

                types.insert(name.clone(), type_name_from_ref(type_ref));
                for (path, leaf_type) in flatten_type_ref_leaves(type_ref, structs)? {
                    let leaf_name = flattened_struct_name(name, &path);
                    types.insert(leaf_name.clone(), type_name_from_ref(&leaf_type));
                    env.insert(leaf_name, Expr::new(ExprKind::Array(Vec::new()), span::Span::default()));
                }
                return Ok(Vec::new());
            }

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
                    Some(Expr { kind: ExprKind::Identifier(other), .. }) => match types.get(other) {
                        Some(other_type) if is_type_assignable(other_type, &effective_type_name, contract_constants) => {
                            Expr::new(ExprKind::Identifier(other.clone()), span::Span::default())
                        }
                        Some(_) => {
                            return Err(CompilerError::Unsupported("array assignment requires compatible array types".to_string()));
                        }
                        None => return Err(CompilerError::UndefinedIdentifier(other.clone())),
                    },
                    Some(e) if is_byte_array_type => {
                        // byte[] can be initialized from any bytes expression
                        lower_runtime_expr(e, types, structs)?
                    }
                    Some(e @ Expr { kind: ExprKind::Array(values), .. }) => {
                        if !array_literal_matches_type_with_env(values, &effective_type_name, types, contract_constants) {
                            return Err(CompilerError::Unsupported("array initializer must be another array".to_string()));
                        }
                        resolve_expr(
                            lower_runtime_expr(&Expr::new(ExprKind::Array(values.clone()), e.span), types, structs)?,
                            env,
                            &mut HashSet::new(),
                        )?
                    }
                    Some(_) => return Err(CompilerError::Unsupported("array initializer must be another array".to_string())),
                    None => Expr::new(ExprKind::Array(Vec::new()), span::Span::default()),
                };
                env.insert(name.clone(), initial);
                types.insert(name.clone(), effective_type_name.clone());
                Ok(Vec::new())
            } else if is_fixed_size_array {
                // Fixed-size arrays like byte[N] can be initialized from expressions
                let expr =
                    expr.clone().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
                let expr = lower_runtime_expr(&expr, types, structs)?;

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
                Ok(Vec::new())
            } else {
                let expr =
                    expr.clone().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
                let expr = lower_runtime_expr(&expr, types, structs)?;
                let expected_type_ref = parse_type_ref(&effective_type_name)?;
                if !expr_matches_return_type_ref(&expr, &expected_type_ref, types, contract_constants) {
                    return Err(CompilerError::Unsupported(format!(
                        "variable '{}' expects {}{}",
                        name,
                        effective_type_name,
                        expr_matches_return_type_ref_hint(&expr, &expected_type_ref)
                            .map(|hint| format!("; {hint}"))
                            .unwrap_or_default()
                    )));
                }
                types.insert(name.clone(), effective_type_name.clone());
                let existing_is_predeclared_default = is_predeclared_scalar_default(name, &effective_type_name, env);

                // Scalars can be kept on the stack for reuse (>=2 uses with no mutation), or (optionally)
                // for mutation to avoid nested IfElse expression blowups under unrolled control flow.
                let used_at_least_twice = identifier_uses.get(name).copied().unwrap_or(0) >= 2;
                let stack_for_reuse = used_at_least_twice && !assigned_names.contains(name);
                let stack_for_mutation = enable_mutable_scalar_stack_locals && assigned_names.contains(name);
                if (stack_for_reuse || stack_for_mutation)
                    && (!env.contains_key(name) || existing_is_predeclared_default)
                    && !stack_bindings.contains(name)
                    && matches!(effective_type_name.as_str(), "int" | "bool" | "byte")
                {
                    let mut stack_depth = 0i64;
                    compile_expr(
                        &expr,
                        env,
                        stack_bindings,
                        types,
                        builder,
                        options,
                        &mut HashSet::new(),
                        &mut stack_depth,
                        script_size,
                        contract_constants,
                    )?;
                    env.insert(name.clone(), expr);
                    stack_bindings.push_binding(name);
                    Ok(vec![name.clone()])
                } else {
                    env.insert(name.clone(), expr);
                    Ok(Vec::new())
                }
            }
        }
        Statement::ArrayPush { name, expr, .. } => {
            let array_type = types.get(name).ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?;
            if !is_array_type(array_type) {
                return Err(CompilerError::Unsupported("push() only supported on arrays".to_string()));
            }
            let array_type_ref = parse_type_ref(array_type)?;
            if struct_array_name_from_type_ref(&array_type_ref, structs).is_some() {
                let element_type = array_type_ref
                    .element_type()
                    .ok_or_else(|| CompilerError::Unsupported("array element type not supported".to_string()))?;
                let leaf_values = lower_runtime_struct_expr(
                    expr,
                    &element_type,
                    types,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                for ((path, leaf_type), leaf_expr) in
                    flatten_type_ref_leaves(&element_type, structs)?.into_iter().zip(leaf_values.into_iter())
                {
                    let resolved_leaf_expr = resolve_expr(leaf_expr, env, &mut HashSet::new())?;
                    let leaf_name = flattened_struct_name(name, &path);
                    let leaf_type_name = type_name_from_ref(&leaf_type);
                    let element_expr = if leaf_type_name == "int" {
                        Expr::new(
                            ExprKind::Call {
                                name: "byte[8]".to_string(),
                                args: vec![resolved_leaf_expr],
                                name_span: span::Span::default(),
                            },
                            span::Span::default(),
                        )
                    } else if matches!(leaf_type_name.as_str(), "bool" | "byte") {
                        Expr::new(
                            ExprKind::Call {
                                name: "byte[1]".to_string(),
                                args: vec![resolved_leaf_expr],
                                name_span: span::Span::default(),
                            },
                            span::Span::default(),
                        )
                    } else if is_bytes_type(&leaf_type_name) {
                        if expr_is_bytes(&resolved_leaf_expr, env, types) {
                            resolved_leaf_expr
                        } else {
                            Expr::new(
                                ExprKind::Call {
                                    name: leaf_type_name.clone(),
                                    args: vec![resolved_leaf_expr],
                                    name_span: span::Span::default(),
                                },
                                span::Span::default(),
                            )
                        }
                    } else {
                        return Err(CompilerError::Unsupported("array element type not supported".to_string()));
                    };

                    let current =
                        env.get(&leaf_name).cloned().unwrap_or_else(|| Expr::new(ExprKind::Array(Vec::new()), span::Span::default()));
                    let updated = Expr::new(
                        ExprKind::Binary { op: BinaryOp::Add, left: Box::new(current), right: Box::new(element_expr) },
                        span::Span::default(),
                    );
                    env.insert(leaf_name, updated);
                }
                return Ok(Vec::new());
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
            } else if matches!(element_type.as_str(), "bool" | "byte") {
                Expr::new(
                    ExprKind::Call { name: "byte[1]".to_string(), args: vec![expr.clone()], name_span: span::Span::default() },
                    span::Span::default(),
                )
            } else if is_bytes_type(&element_type) {
                if expr_is_bytes(expr, env, types) {
                    expr.clone()
                } else {
                    Expr::new(
                        ExprKind::Call { name: element_type.to_string(), args: vec![expr.clone()], name_span: span::Span::default() },
                        span::Span::default(),
                    )
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
            Ok(Vec::new())
        }
        Statement::Require { expr, .. } => {
            let expr = lower_runtime_expr(expr, types, structs)?;
            let mut stack_depth = 0i64;
            compile_expr(
                &expr,
                env,
                stack_bindings,
                types,
                builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpVerify)?;
            Ok(Vec::new())
        }
        Statement::TimeOp { tx_var, expr, .. } => {
            let expr = lower_runtime_expr(expr, types, structs)?;
            compile_time_op_statement(tx_var, &expr, env, stack_bindings, types, builder, options, script_size, contract_constants)
                .map(|_| Vec::new())
        }
        Statement::If { condition, then_branch, else_branch, .. } => compile_if_statement(
            condition,
            then_branch,
            else_branch.as_deref(),
            env,
            assigned_names,
            identifier_uses,
            types,
            stack_bindings,
            builder,
            options,
            enable_mutable_scalar_stack_locals,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            recorder,
        )
        .map(|_| Vec::new()),
        Statement::For { ident, start, end, max_iterations, body, span, .. } => compile_for_statement(
            ident,
            start,
            end,
            max_iterations,
            body,
            *span,
            env,
            assigned_names,
            identifier_uses,
            types,
            stack_bindings,
            builder,
            options,
            enable_mutable_scalar_stack_locals,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            recorder,
        )
        .map(|_| Vec::new()),
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
                Ok(Vec::new())
            }
            _ => Err(CompilerError::Unsupported("tuple assignment only supports split()".to_string())),
        },
        Statement::FunctionCall { name, args, .. } => {
            if name == "validateOutputState" {
                let lowered_args = if let Some(state_arg) = args.get(1) {
                    match &state_arg.kind {
                        ExprKind::StateObject(_) => args.to_vec(),
                        _ => {
                            let state_type = TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() };
                            let scope = lowering_scope_from_types(types)?;
                            let mut lowered = args.to_vec();
                            lowered[1] = lower_struct_value_to_state_object_expr(
                                state_arg,
                                &state_type,
                                &scope,
                                structs,
                                contract_fields,
                                contract_constants,
                                contract_field_prefix_len,
                            )?;
                            lowered
                        }
                    }
                } else {
                    args.to_vec()
                };
                return compile_validate_output_state_statement(
                    &lowered_args,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    contract_fields,
                    contract_field_prefix_len,
                    script_size,
                    contract_constants,
                )
                .map(|_| Vec::new());
            }
            if name == "validateOutputStateWithTemplate" {
                let uses_local_state_layout = matches!(args.get(1).map(|arg| &arg.kind), Some(ExprKind::StateObject(_)));
                let state_type = if let Some(state_arg) = args.get(1) {
                    match &state_arg.kind {
                        ExprKind::StateObject(_) => TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() },
                        _ => {
                            let scope = lowering_scope_from_types(types)?;
                            infer_struct_expr_type(state_arg, &scope, structs, contract_fields)?
                        }
                    }
                } else {
                    TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() }
                };
                let lowered_args = if let Some(state_arg) = args.get(1) {
                    match &state_arg.kind {
                        ExprKind::StateObject(_) => args.to_vec(),
                        _ => {
                            let scope = lowering_scope_from_types(types)?;
                            let mut lowered = args.to_vec();
                            lowered[1] = lower_struct_value_to_state_object_expr(
                                state_arg,
                                &state_type,
                                &scope,
                                structs,
                                contract_fields,
                                contract_constants,
                                contract_field_prefix_len,
                            )?;
                            lowered
                        }
                    }
                } else {
                    args.to_vec()
                };
                let layout_fields = if uses_local_state_layout {
                    contract_fields
                        .iter()
                        .map(|field| StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
                        .collect::<Vec<_>>()
                } else {
                    flattened_struct_field_specs_for_type(&state_type, structs)?
                };
                return compile_validate_output_state_with_template_statement(
                    &lowered_args,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    &layout_fields,
                    script_size,
                    contract_constants,
                )
                .map(|_| Vec::new());
            }
            let function = functions.get(name).ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
            let returns = compile_inline_call(
                name,
                args,
                SourceSpan::from(stmt.span()),
                stack_bindings,
                types,
                env,
                builder,
                options,
                contract_constants,
                contract_fields,
                contract_field_prefix_len,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
                recorder,
            )?;
            if !returns.is_empty() {
                let flattened_returns = flatten_runtime_return_exprs(
                    &returns,
                    &function.return_types,
                    types,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?;
                let mut stack_depth = 0i64;
                for expr in flattened_returns {
                    compile_expr(
                        &expr,
                        env,
                        stack_bindings,
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
            Ok(Vec::new())
        }
        Statement::StateFunctionCallAssign { bindings, name, args, .. } => {
            if name == "readInputState" || name == "readInputStateWithTemplate" {
                return compile_read_input_state_statement(
                    bindings,
                    name,
                    args,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    contract_fields,
                    contract_field_prefix_len,
                    script_size,
                    contract_constants,
                    structs,
                )
                .map(|_| Vec::new());
            }
            Err(CompilerError::Unsupported(format!(
                "state destructuring assignment is only supported for readInputState()/readInputStateWithTemplate(), got '{}()'",
                name
            )))
        }
        Statement::StructDestructure { .. } => {
            let Statement::StructDestructure { bindings, expr, span } = stmt else { unreachable!() };
            for binding in bindings {
                if struct_name_from_type_ref(&binding.type_ref, structs).is_some() {
                    types.insert(binding.name.clone(), type_name_from_ref(&binding.type_ref));
                }
            }
            let mut scope = lowering_scope_from_types(types)?;
            for lowered_stmt in lower_struct_destructure_statement(
                bindings,
                expr,
                *span,
                &mut scope,
                structs,
                contract_fields,
                contract_constants,
                contract_field_prefix_len,
            )? {
                compile_statement(
                    &lowered_stmt,
                    env,
                    assigned_names,
                    identifier_uses,
                    types,
                    stack_bindings,
                    builder,
                    options,
                    enable_mutable_scalar_stack_locals,
                    contract_fields,
                    contract_field_prefix_len,
                    contract_constants,
                    structs,
                    functions,
                    function_order,
                    function_index,
                    script_size,
                    recorder,
                )?;
            }
            Ok(Vec::new())
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
                let binding_type_name = type_name_from_ref(&binding.type_ref);
                let return_type_name = type_name_from_ref(return_type);
                if binding_type_name != return_type_name {
                    return Err(CompilerError::Unsupported("function return types must match binding types".to_string()));
                }
            }
            let returns = compile_inline_call(
                name,
                args,
                SourceSpan::from(stmt.span()),
                stack_bindings,
                types,
                env,
                builder,
                options,
                contract_constants,
                contract_fields,
                contract_field_prefix_len,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
                recorder,
            )?;
            if returns.len() != bindings.len() {
                return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
            }
            let mut added_stack_locals = Vec::new();
            for (binding, expr) in bindings.iter().zip(returns.into_iter()) {
                if struct_name_from_type_ref(&binding.type_ref, structs).is_some()
                    || struct_array_name_from_type_ref(&binding.type_ref, structs).is_some()
                {
                    store_struct_binding(
                        &binding.name,
                        &binding.type_ref,
                        &expr,
                        env,
                        types,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                        false,
                    )?;
                    if struct_name_from_type_ref(&binding.type_ref, structs).is_some() {
                        added_stack_locals.extend(push_struct_leaf_stack_bindings(
                            &binding.name,
                            &binding.type_ref,
                            env,
                            assigned_names,
                            identifier_uses,
                            types,
                            stack_bindings,
                            builder,
                            options,
                            structs,
                            script_size,
                            contract_constants,
                        )?);
                    }
                } else {
                    let lowered = lower_runtime_expr(&expr, types, structs)?;
                    let binding_type_name = type_name_from_ref(&binding.type_ref);
                    types.insert(binding.name.clone(), binding_type_name.clone());
                    let existing_is_predeclared_default = is_predeclared_scalar_default(&binding.name, &binding_type_name, env);
                    if bindings.len() == 1
                        && !assigned_names.contains(&binding.name)
                        && identifier_uses.get(&binding.name).copied().unwrap_or(0) >= 2
                        && (!env.contains_key(&binding.name) || existing_is_predeclared_default)
                        && !stack_bindings.contains(&binding.name)
                        && matches!(binding_type_name.as_str(), "int" | "bool" | "byte")
                    {
                        let mut stack_depth = 0i64;
                        compile_expr(
                            &lowered,
                            env,
                            stack_bindings,
                            types,
                            builder,
                            options,
                            &mut HashSet::new(),
                            &mut stack_depth,
                            script_size,
                            contract_constants,
                        )?;
                        env.insert(binding.name.clone(), lowered);
                        stack_bindings.push_binding(&binding.name);
                        added_stack_locals.push(binding.name.clone());
                    } else {
                        env.insert(binding.name.clone(), lowered);
                    }
                }
            }
            Ok(added_stack_locals)
        }
        Statement::Assign { name, expr, .. } => {
            if let Some(type_name) = types.get(name) {
                // If this is a stack-bound scalar local, compile a real mutation instead of
                // rewriting `env[name]` (which can explode under unrolled control flow).
                if enable_mutable_scalar_stack_locals
                    && stack_bindings.contains(name)
                    && matches!(type_name.as_str(), "int" | "bool" | "byte")
                {
                    let expected_type_ref = parse_type_ref(type_name)?;
                    let lowered_expr = lower_runtime_expr(expr, types, structs)?;
                    if !expr_matches_return_type_ref(&lowered_expr, &expected_type_ref, types, contract_constants) {
                        return Err(CompilerError::Unsupported(format!(
                            "variable '{}' expects {}{}",
                            name,
                            type_name,
                            expr_matches_return_type_ref_hint(&lowered_expr, &expected_type_ref)
                                .map(|hint| format!("; {hint}"))
                                .unwrap_or_default()
                        )));
                    }

                    // Compute RHS value onto the stack.
                    let mut stack_depth = 0i64;
                    compile_expr(
                        &lowered_expr,
                        env,
                        stack_bindings,
                        types,
                        builder,
                        options,
                        &mut HashSet::new(),
                        &mut stack_depth,
                        script_size,
                        contract_constants,
                    )?;

                    // Replace the existing binding in-place without changing the overall stack layout.
                    //
                    // Stack shape after RHS:
                    //   ... [target at depth b+1] [b items above target] [new_value]
                    //
                    // We peel the b items under new_value into altstack (keeping new_value at top),
                    // drop the old target, then restore the peeled items. This makes new_value end
                    // up exactly where the old binding was.
                    stack_bindings.emit_update_stack_for_rebinding(name, builder)?;
                    return Ok(Vec::new());
                }

                let expected_type_ref = parse_type_ref(type_name)?;
                if struct_name_from_type_ref(&expected_type_ref, structs).is_some()
                    || struct_array_name_from_type_ref(&expected_type_ref, structs).is_some()
                {
                    if let ExprKind::Call { name: builtin_name, args, .. } = &expr.kind
                        && builtin_name == "readInputStateWithTemplate"
                    {
                        if struct_array_name_from_type_ref(&expected_type_ref, structs).is_some() {
                            return Err(CompilerError::Unsupported(
                                "readInputStateWithTemplate does not support struct array assignments".to_string(),
                            ));
                        }
                        let lowered_values =
                            read_input_state_with_template_values(args, &expected_type_ref, structs, contract_constants)?;
                        let layout_fields = flattened_struct_field_specs_for_type(&expected_type_ref, structs)?;
                        compile_read_input_state_with_template_validation(
                            args,
                            env,
                            stack_bindings,
                            types,
                            builder,
                            options,
                            &layout_fields,
                            script_size,
                            contract_constants,
                        )?;
                        store_struct_binding_with_stack_rebindings(
                            name,
                            &expected_type_ref,
                            lowered_values,
                            env,
                            types,
                            stack_bindings,
                            builder,
                            options,
                            structs,
                            script_size,
                            contract_constants,
                        )?;
                        return Ok(Vec::new());
                    }
                    let lowered_values = lower_runtime_struct_expr(
                        expr,
                        &expected_type_ref,
                        types,
                        structs,
                        contract_fields,
                        contract_constants,
                        contract_field_prefix_len,
                    )?;
                    store_struct_binding_with_stack_rebindings(
                        name,
                        &expected_type_ref,
                        lowered_values,
                        env,
                        types,
                        stack_bindings,
                        builder,
                        options,
                        structs,
                        script_size,
                        contract_constants,
                    )?;
                    return Ok(Vec::new());
                }
                if is_array_type(type_name) {
                    match &expr.kind {
                        ExprKind::Identifier(other) => match types.get(other) {
                            Some(other_type) if is_type_assignable(other_type, type_name, contract_constants) => {
                                env.insert(name.clone(), Expr::new(ExprKind::Identifier(other.clone()), span::Span::default()));
                                return Ok(Vec::new());
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
                let lowered_expr = lower_runtime_expr(expr, types, structs)?;
                if !expr_matches_return_type_ref(&lowered_expr, &expected_type_ref, types, contract_constants) {
                    return Err(CompilerError::Unsupported(format!(
                        "variable '{}' expects {}{}",
                        name,
                        type_name,
                        expr_matches_return_type_ref_hint(&lowered_expr, &expected_type_ref)
                            .map(|hint| format!("; {hint}"))
                            .unwrap_or_default()
                    )));
                }
                let updated =
                    if let Some(previous) = env.get(name) { replace_identifier(&lowered_expr, name, previous) } else { lowered_expr };
                let resolved = resolve_expr_for_runtime(updated, env, types, &mut HashSet::new())?;
                env.insert(name.clone(), resolved);
                return Ok(Vec::new());
            }
            let lowered_expr = lower_runtime_expr(expr, types, structs)?;
            let updated =
                if let Some(previous) = env.get(name) { replace_identifier(&lowered_expr, name, previous) } else { lowered_expr };
            let resolved = resolve_expr_for_runtime(updated, env, types, &mut HashSet::new())?;
            env.insert(name.clone(), resolved);
            Ok(Vec::new())
        }
        Statement::Console { .. } => Ok(Vec::new()),
    }
}

fn encoded_field_chunk_size<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let (payload_size, _) = fixed_state_field_payload_len(field, contract_constants)?;
    Ok(data_prefix(payload_size).len() + payload_size)
}

fn encoded_field_chunk_size_for_type_ref<'i>(
    type_ref: &TypeRef,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let (payload_size, _) = fixed_state_field_payload_len_for_type_ref(type_ref, contract_constants)?;
    Ok(data_prefix(payload_size).len() + payload_size)
}

fn encoded_state_len<'i>(
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    contract_fields.iter().try_fold(0usize, |acc, field| Ok(acc + encoded_field_chunk_size(field, contract_constants)?))
}

fn encoded_state_len_for_layout_fields<'i>(
    layout_fields: &[StructFieldSpec],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    layout_fields
        .iter()
        .try_fold(0usize, |acc, field| Ok(acc + encoded_field_chunk_size_for_type_ref(&field.type_ref, contract_constants)?))
}

fn state_start_offset<'i>(
    contract_field_prefix_len: usize,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    contract_field_prefix_len
        .checked_sub(total_state_len)
        .ok_or_else(|| CompilerError::Unsupported("state offset underflow".to_string()))
}

fn templated_input_script_size_expr<'i>(
    template_prefix_len: &Expr<'i>,
    template_suffix_len: &Expr<'i>,
    layout_fields: &[StructFieldSpec],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let total_state_len = encoded_state_len_for_layout_fields(layout_fields, contract_constants)?;
    Ok(binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, template_prefix_len.clone(), Expr::int(total_state_len as i64)),
        template_suffix_len.clone(),
    ))
}

fn read_input_state_binding_expr<'i>(
    input_idx: &Expr<'i>,
    field: &ContractFieldAst<'i>,
    state_start_offset: usize,
    field_chunk_offset: usize,
    script_size_value: i64,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let (field_payload_len, decode_numeric) = fixed_state_field_payload_len(field, contract_constants)?;
    let field_payload_offset = state_start_offset + field_chunk_offset + data_prefix(field_payload_len).len();

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

    if decode_numeric { Ok(Expr::call("OpBin2Num", vec![substr])) } else { Ok(substr) }
}

fn read_input_state_field_expr_with_type<'i>(
    input_idx: &Expr<'i>,
    field_type: &TypeRef,
    state_start_offset_expr: Expr<'i>,
    field_chunk_offset: usize,
    script_size_expr: Expr<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
    builtin_name: &str,
) -> Result<Expr<'i>, CompilerError> {
    let (field_payload_len, decode_numeric) =
        fixed_state_field_payload_len_for_type_ref(field_type, contract_constants).map_err(|_| {
            CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", type_name_from_ref(field_type)))
        })?;
    let field_payload_offset = binary_expr(
        BinaryOp::Add,
        state_start_offset_expr,
        Expr::int((field_chunk_offset + data_prefix(field_payload_len).len()) as i64),
    );
    let start = binary_expr(BinaryOp::Add, input_sigscript_base_expr(input_idx, script_size_expr), field_payload_offset);
    let end = binary_expr(BinaryOp::Add, start.clone(), Expr::int(field_payload_len as i64));
    let substr = input_sigscript_substr_expr(input_idx, start, end);

    if decode_numeric { Ok(Expr::call("OpBin2Num", vec![substr])) } else { Ok(substr) }
}

#[allow(clippy::too_many_arguments)]
fn compile_read_input_state_statement<'i>(
    bindings: &[StateBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
    env: &mut HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &mut HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    let mut bindings_by_field: HashMap<&str, &StateBindingAst<'i>> = HashMap::new();
    for binding in bindings {
        if bindings_by_field.insert(binding.field_name.as_str(), binding).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate state field '{}'", binding.field_name)));
        }
    }
    match name {
        "readInputState" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("readInputState(input_idx) expects 1 argument".to_string()));
            }
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            if bindings_by_field.len() != contract_fields.len() {
                return Err(CompilerError::Unsupported(
                    "readInputState bindings must include all contract fields exactly once".to_string(),
                ));
            }

            let script_size_value =
                script_size.ok_or_else(|| CompilerError::Unsupported("readInputState requires this.scriptSize".to_string()))?;
            let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
            let state_start_offset = contract_field_prefix_len
                .checked_sub(total_state_len)
                .ok_or_else(|| CompilerError::Unsupported("readInputState state offset underflow".to_string()))?;

            let input_idx = args[0].clone();
            let mut field_chunk_offset = 0usize;
            for field in contract_fields {
                let binding = bindings_by_field.get(field.name.as_str()).ok_or_else(|| {
                    CompilerError::Unsupported("readInputState bindings must include all contract fields exactly once".to_string())
                })?;

                let binding_type = type_name_from_ref(&binding.type_ref);
                let field_type = type_name_from_ref(&field.type_ref);
                if binding_type != field_type {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputState binding '{}' expects {}",
                        binding.name, field_type
                    )));
                }

                let binding_expr = read_input_state_binding_expr(
                    &input_idx,
                    field,
                    state_start_offset,
                    field_chunk_offset,
                    script_size_value,
                    contract_constants,
                )?;
                env.insert(binding.name.clone(), binding_expr);
                types.insert(binding.name.clone(), binding_type);

                field_chunk_offset += encoded_field_chunk_size(field, contract_constants)?;
            }

            Ok(())
        }
        "readInputStateWithTemplate" => {
            if args.len() != 4 {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                        .to_string(),
                ));
            }

            let struct_name = struct_name_for_state_bindings(bindings, structs)?;
            let struct_spec =
                structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            if bindings_by_field.len() != struct_spec.fields.len() {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                ));
            }

            let layout_fields = flattened_struct_field_specs_for_type(
                &TypeRef { base: TypeBase::Custom(struct_name.clone()), array_dims: Vec::new() },
                structs,
            )?;
            compile_read_input_state_with_template_validation(
                args,
                env,
                stack_bindings,
                types,
                builder,
                options,
                &layout_fields,
                script_size,
                contract_constants,
            )?;

            let input_idx = args[0].clone();
            let state_start_offset_expr = args[1].clone();
            let script_size_expr = templated_input_script_size_expr(&args[1], &args[2], &layout_fields, contract_constants)?;
            let mut field_chunk_offset = 0usize;

            for field in &struct_spec.fields {
                let binding = bindings_by_field.get(field.name.as_str()).ok_or_else(|| {
                    CompilerError::Unsupported(
                        "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                    )
                })?;

                if struct_name_from_type_ref(&field.type_ref, structs).is_some() {
                    return Err(CompilerError::Unsupported(
                        "readInputStateWithTemplate does not support nested struct fields in destructuring".to_string(),
                    ));
                }

                let binding_type = type_name_from_ref(&binding.type_ref);
                let field_type = type_name_from_ref(&field.type_ref);
                if binding_type != field_type {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputStateWithTemplate binding '{}' expects {}",
                        binding.name, field_type
                    )));
                }

                let binding_expr = read_input_state_field_expr_with_type(
                    &input_idx,
                    &field.type_ref,
                    state_start_offset_expr.clone(),
                    field_chunk_offset,
                    script_size_expr.clone(),
                    contract_constants,
                    "readInputStateWithTemplate",
                )?;
                env.insert(binding.name.clone(), binding_expr);
                types.insert(binding.name.clone(), binding_type);

                field_chunk_offset += encoded_field_chunk_size_for_type_ref(&field.type_ref, contract_constants)?;
            }

            Ok(())
        }
        _ => Err(CompilerError::Unsupported(format!(
            "state destructuring assignment is only supported for readInputState()/readInputStateWithTemplate(), got '{}()'",
            name
        ))),
    }
}

fn struct_name_for_state_bindings<'i>(bindings: &[StateBindingAst<'i>], structs: &StructRegistry) -> Result<String, CompilerError> {
    let matches = structs
        .iter()
        .filter_map(|(name, spec)| {
            if spec.fields.len() != bindings.len() {
                return None;
            }
            let all_match = spec.fields.iter().all(|field| {
                bindings
                    .iter()
                    .find(|binding| binding.field_name == field.name)
                    .is_some_and(|binding| binding.type_ref == field.type_ref)
            });
            all_match.then(|| name.clone())
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [name] => Ok(name.clone()),
        [] => Err(CompilerError::Unsupported("readInputStateWithTemplate bindings must match a declared struct layout".to_string())),
        _ => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate bindings match multiple struct layouts; assign into an explicitly typed struct first"
                .to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_read_input_state_with_template_validation(
    args: &[Expr<'_>],
    env: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    layout_fields: &[StructFieldSpec],
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    if args.len() != 4 {
        return Err(CompilerError::Unsupported(
            "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                .to_string(),
        ));
    }
    if layout_fields.is_empty() {
        return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
    }

    let input_idx = &args[0];
    let template_prefix_len = &args[1];
    let template_suffix_len = &args[2];
    let expected_template_hash = &args[3];
    let script_size_expr =
        templated_input_script_size_expr(template_prefix_len, template_suffix_len, layout_fields, contract_constants)?;
    let prefix_len_expr = template_prefix_len.clone();
    let suffix_len_expr = template_suffix_len.clone();
    let script_base_expr = input_sigscript_base_expr(input_idx, script_size_expr.clone());
    let prefix_end_expr = binary_expr(BinaryOp::Add, script_base_expr.clone(), prefix_len_expr.clone());
    let script_end_expr = binary_expr(BinaryOp::Add, script_base_expr.clone(), script_size_expr.clone());
    let state_len = encoded_state_len_for_layout_fields(layout_fields, contract_constants)?;
    let suffix_start_expr = binary_expr(BinaryOp::Add, prefix_end_expr.clone(), Expr::int(state_len as i64));
    let suffix_end_expr = binary_expr(BinaryOp::Add, suffix_start_expr.clone(), suffix_len_expr);

    let actual_redeem_script_expr = input_sigscript_substr_expr(input_idx, script_base_expr.clone(), script_end_expr);
    let actual_prefix_expr = input_sigscript_substr_expr(input_idx, script_base_expr, prefix_end_expr);
    let actual_suffix_expr = input_sigscript_substr_expr(input_idx, suffix_start_expr, suffix_end_expr);
    let actual_template_expr = binary_expr(BinaryOp::Add, actual_prefix_expr, actual_suffix_expr);
    let expected_input_spk_expr = Expr::new(
        ExprKind::New {
            name: "ScriptPubKeyP2SHFromRedeemScript".to_string(),
            args: vec![actual_redeem_script_expr],
            name_span: span::Span::default(),
        },
        span::Span::default(),
    );
    let actual_input_spk_expr = input_script_pubkey_expr(input_idx);

    let mut stack_depth = 0i64;

    compile_expr(
        &actual_input_spk_expr,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    compile_expr(
        &expected_input_spk_expr,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;
    stack_depth = 0;

    compile_expr(
        &actual_template_expr,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    compile_expr(
        expected_template_hash,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpSwap)?;
    builder.add_op(OpBlake2b)?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_validate_output_state_statement(
    args: &[Expr<'_>],
    env: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
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
    let mut stack_depth = compile_encoded_state_object(
        &args[1],
        env,
        stack_bindings,
        types,
        builder,
        options,
        contract_fields,
        script_size,
        contract_constants,
        "validateOutputState",
    )?;

    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    let state_start_offset = contract_field_prefix_len
        .checked_sub(total_state_len)
        .ok_or_else(|| CompilerError::Unsupported("validateOutputState state offset underflow".to_string()))?;

    let script_size_value =
        script_size.ok_or_else(|| CompilerError::Unsupported("validateOutputState requires this.scriptSize".to_string()))?;

    // Build: prefix || encoded_new_state || suffix where fields sit at [state_start_offset, contract_field_prefix_len).
    if state_start_offset > 0 {
        builder.add_op(OpTxInputIndex)?;
        stack_depth += 1;
        builder.add_op(OpDup)?;
        stack_depth += 1;
        builder.add_op(OpTxInputScriptSigLen)?;
        builder.add_i64(script_size_value)?;
        stack_depth += 1;
        builder.add_op(OpSub)?;
        stack_depth -= 1;
        builder.add_op(OpDup)?;
        stack_depth += 1;
        builder.add_i64(state_start_offset as i64)?;
        stack_depth += 1;
        builder.add_op(OpAdd)?;
        stack_depth -= 1;
        builder.add_op(OpTxInputScriptSigSubstr)?;
        stack_depth -= 2;

        // Prefix || encoded_new_state
        builder.add_op(OpSwap)?;
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

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

    // Prefix || encoded_new_state || suffix
    builder.add_op(OpCat)?;
    stack_depth -= 1;

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
        stack_bindings,
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

fn compile_validate_output_state_with_template_statement(
    args: &[Expr<'_>],
    env: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    layout_fields: &[StructFieldSpec],
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    if args.len() != 5 {
        return Err(CompilerError::Unsupported(
            "validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash) expects 5 arguments"
                .to_string(),
        ));
    }
    if layout_fields.is_empty() {
        return Err(CompilerError::Unsupported("validateOutputStateWithTemplate requires contract fields".to_string()));
    }

    let output_idx = &args[0];
    let state_expr = &args[1];
    let template_prefix = &args[2];
    let template_suffix = &args[3];
    let expected_template_hash = &args[4];

    let mut stack_depth = 0i64;

    compile_expr(
        template_prefix,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    compile_expr(
        template_suffix,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    compile_expr(
        expected_template_hash,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpSwap)?;
    builder.add_op(OpBlake2b)?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;
    stack_depth = compile_encoded_object_with_layout(
        state_expr,
        env,
        stack_bindings,
        types,
        builder,
        options,
        layout_fields,
        script_size,
        contract_constants,
        "validateOutputStateWithTemplate",
    )?;

    compile_expr(
        template_prefix,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpSwap)?;
    builder.add_op(OpCat)?;
    stack_depth -= 1;

    compile_expr(
        template_suffix,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpCat)?;
    stack_depth -= 1;

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
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;
    builder.add_op(OpTxOutputSpk)?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;

    Ok(())
}

fn compile_encoded_object_with_layout(
    state_expr: &Expr<'_>,
    env: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    layout_fields: &[StructFieldSpec],
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    let ExprKind::StateObject(state_entries) = &state_expr.kind else {
        return Err(CompilerError::Unsupported(format!("{builtin_name} second argument must be an object literal")));
    };

    let mut provided = HashMap::new();
    for entry in state_entries {
        if provided.insert(entry.name.as_str(), &entry.expr).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate state field '{}'", entry.name)));
        }
    }
    if provided.len() != layout_fields.len() {
        return Err(CompilerError::Unsupported("new_state must include all contract fields exactly once".to_string()));
    }

    let mut stack_depth = 0i64;
    for field in layout_fields {
        let Some(new_value) = provided.remove(field.name.as_str()) else {
            return Err(CompilerError::Unsupported(format!("missing state field '{}'", field.name)));
        };

        let (field_size, encode_numeric) =
            fixed_state_field_payload_len_for_type_ref(&field.type_ref, contract_constants).map_err(|_| {
                CompilerError::Unsupported(format!(
                    "{builtin_name} does not support field type {}",
                    type_name_from_ref(&field.type_ref)
                ))
            })?;

        if encode_numeric {
            compile_expr(
                new_value,
                env,
                stack_bindings,
                types,
                builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_i64(field_size as i64)?;
            stack_depth += 1;
            builder.add_op(OpNum2Bin)?;
            stack_depth -= 1;
        } else {
            compile_expr(
                new_value,
                env,
                stack_bindings,
                types,
                builder,
                options,
                &mut HashSet::new(),
                &mut stack_depth,
                script_size,
                contract_constants,
            )?;
        }
        let prefix = data_prefix(field_size);
        builder.add_data(&prefix)?;
        stack_depth += 1;
        builder.add_op(OpSwap)?;
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    for _ in 1..layout_fields.len() {
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    Ok(stack_depth)
}

fn compile_encoded_state_object(
    state_expr: &Expr<'_>,
    env: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'_>],
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    let layout_fields = contract_fields
        .iter()
        .map(|field| StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
        .collect::<Vec<_>>();
    compile_encoded_object_with_layout(
        state_expr,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &layout_fields,
        script_size,
        contract_constants,
        builtin_name,
    )
}

#[derive(Debug)]
struct InlineCallBindings<'i> {
    env: HashMap<String, Expr<'i>>,
    debug_env: HashMap<String, Expr<'i>>,
    types: HashMap<String, String>,
    stack_bindings: StackBindings,
    return_rewrites: Vec<(String, Expr<'i>)>,
    preserved_return_idents: HashSet<String>,
}

fn prepare_inline_call_bindings<'i>(
    function: &FunctionAst<'i>,
    args: &[Expr<'i>],
    caller_stack_bindings: &StackBindings,
    caller_types: &HashMap<String, String>,
    caller_env: &HashMap<String, Expr<'i>>,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
) -> Result<InlineCallBindings<'i>, CompilerError> {
    let mut types = caller_types.clone();
    let mut env: HashMap<String, Expr<'i>> = contract_constants.clone();
    env.extend(caller_env.clone());
    let mut return_rewrites = Vec::new();
    let mut preserved_return_idents = HashSet::new();
    let caller_scope = lowering_scope_from_types(caller_types)?;
    for (param, arg) in function.params.iter().zip(args.iter()) {
        let resolved = resolve_expr(arg.clone(), caller_env, &mut HashSet::new())?;
        let param_type_name = type_name_from_ref(&param.type_ref);

        preserved_return_idents.insert(param.name.clone());
        types.insert(param.name.clone(), param_type_name.clone());
        if struct_name_from_type_ref(&param.type_ref, structs).is_some() {
            return_rewrites.push((param.name.clone(), resolved.clone()));
            if !matches!(&resolved.kind, ExprKind::Identifier(identifier) if identifier == &param.name) {
                env.insert(param.name.clone(), resolved.clone());
            }
            for ((path, field_type), lowered_expr) in
                flatten_type_ref_leaves(&param.type_ref, structs)?.into_iter().zip(lower_struct_value_expr(
                    &resolved,
                    &param.type_ref,
                    &caller_scope,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                )?)
            {
                let leaf_name = flattened_struct_name(&param.name, &path);
                let lowered_expr = resolve_expr(lowered_expr, caller_env, &mut HashSet::new())?;
                types.insert(leaf_name.clone(), type_name_from_ref(&field_type));
                if !matches!(&lowered_expr.kind, ExprKind::Identifier(identifier) if identifier == &leaf_name) {
                    env.insert(leaf_name, lowered_expr);
                }
            }
        } else {
            let (lowered, rewrite_expr) = if is_array_type(&param_type_name) {
                match arg {
                    Expr { kind: ExprKind::Identifier(identifier), .. }
                        if caller_types
                            .get(identifier)
                            .is_some_and(|other_type| is_type_assignable(other_type, &param_type_name, contract_constants)) =>
                    {
                        (
                            caller_env
                                .get(identifier)
                                .cloned()
                                .unwrap_or_else(|| Expr::new(ExprKind::Identifier(identifier.clone()), span::Span::default())),
                            Expr::new(ExprKind::Identifier(identifier.clone()), span::Span::default()),
                        )
                    }
                    _ => {
                        let lowered = lower_runtime_expr(&resolved, caller_types, structs)?;
                        (lowered.clone(), lowered)
                    }
                }
            } else {
                match arg {
                    Expr { kind: ExprKind::Identifier(identifier), .. }
                        if caller_stack_bindings.contains(identifier)
                            && caller_types
                                .get(identifier)
                                .is_some_and(|other_type| is_type_assignable(other_type, &param_type_name, contract_constants)) =>
                    {
                        let ident = Expr::new(ExprKind::Identifier(identifier.clone()), span::Span::default());
                        (ident.clone(), ident)
                    }
                    _ => {
                        let lowered = lower_runtime_expr(&resolved, caller_types, structs)?;
                        (lowered.clone(), lowered)
                    }
                }
            };
            return_rewrites.push((param.name.clone(), rewrite_expr));
            if !matches!(&lowered.kind, ExprKind::Identifier(identifier) if identifier == &param.name) {
                env.insert(param.name.clone(), lowered);
            }
        }
    }

    let debug_env = env.clone();
    let stack_bindings = caller_stack_bindings.clone();

    Ok(InlineCallBindings { env, debug_env, types, stack_bindings, return_rewrites, preserved_return_idents })
}

fn rewrite_inline_returns<'i>(returns: Vec<Expr<'i>>, rewrites: &[(String, Expr<'i>)]) -> Vec<Expr<'i>> {
    if rewrites.is_empty() {
        return returns;
    }
    returns
        .into_iter()
        .map(|expr| {
            let mut current = expr;
            for (temp_name, replacement) in rewrites {
                current = replace_identifier(&current, temp_name, replacement);
            }
            current
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn compile_inline_call<'i>(
    name: &str,
    args: &[Expr<'i>],
    call_span: SourceSpan,
    caller_stack_bindings: &StackBindings,
    caller_types: &mut HashMap<String, String>,
    caller_env: &mut HashMap<String, Expr<'i>>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_constants: &HashMap<String, Expr<'i>>,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    caller_index: usize,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
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

    if args.len() == function.params.len() {
        for (param, arg) in function.params.iter().zip(args.iter()) {
            let param_type_name = type_name_from_ref(&param.type_ref);
            let matches = if struct_name_from_type_ref(&param.type_ref, structs).is_some() {
                match lower_runtime_struct_expr(
                    arg,
                    &param.type_ref,
                    caller_types,
                    structs,
                    contract_fields,
                    contract_constants,
                    contract_field_prefix_len,
                ) {
                    Ok(_) => true,
                    Err(err) if matches!(&arg.kind, ExprKind::Call { name, .. } if name == "readInputStateWithTemplate") => {
                        return Err(err);
                    }
                    Err(_) => false,
                }
            } else if struct_array_name_from_type_ref(&param.type_ref, structs).is_some() {
                match &arg.kind {
                    ExprKind::Identifier(name) => caller_types
                        .get(name)
                        .and_then(|type_name| parse_type_ref(type_name).ok())
                        .is_some_and(|type_ref| is_type_assignable_ref(&type_ref, &param.type_ref, contract_constants)),
                    _ => expr_matches_declared_type_ref(arg, &param.type_ref, structs),
                }
            } else {
                let lowered = lower_runtime_expr(arg, caller_types, structs)?;
                expr_matches_return_type_ref(&lowered, &param.type_ref, caller_types, contract_constants)
            };
            if !matches {
                return Err(CompilerError::Unsupported(format!("function argument '{}' expects {}", param.name, param_type_name)));
            }
        }
    }

    for param in &function.params {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if is_array_type(&param_type_name)
            && array_element_size(&param_type_name).is_none()
            && struct_array_name_from_type_ref(&param.type_ref, structs).is_none()
        {
            return Err(CompilerError::Unsupported(format!("array element type must have known size: {}", param_type_name)));
        }
    }

    let mut bindings = prepare_inline_call_bindings(
        function,
        args,
        caller_stack_bindings,
        caller_types,
        caller_env,
        contract_constants,
        structs,
        contract_fields,
        contract_field_prefix_len,
    )?;

    if function.entrypoint && !options.allow_entrypoint_return && function.body.iter().any(contains_return) {
        return Err(CompilerError::Unsupported("entrypoint return requires allow_entrypoint_return=true".to_string()));
    }

    let assigned_names = collect_assigned_names(&function.body);
    let identifier_uses = collect_identifier_uses(&function.body);
    let has_return = function.body.iter().any(contains_return);
    if has_return {
        if !matches!(function.body.last(), Some(Statement::Return { .. })) {
            return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
        }
        if function.body[..function.body.len() - 1].iter().any(contains_return) {
            return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
        }
    }

    let call_start = builder.script().len();
    recorder.begin_inline_call(call_span, call_start, function, &bindings.debug_env, &bindings.stack_bindings)?;

    let mut returns: Vec<Expr<'i>> = Vec::new();
    let initial_stack_binding_count = bindings.stack_bindings.len();
    for param in &function.params {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if !matches!(param_type_name.as_str(), "int" | "bool" | "byte")
            || identifier_uses.get(&param.name).copied().unwrap_or(0) < 2
            || assigned_names.contains(&param.name)
            || bindings.stack_bindings.contains(&param.name)
        {
            continue;
        }

        let Some(bound_expr) = bindings.env.get(&param.name).cloned() else {
            continue;
        };

        let mut stack_depth = 0i64;
        compile_expr(
            &bound_expr,
            &bindings.env,
            &bindings.stack_bindings,
            &bindings.types,
            builder,
            options,
            &mut HashSet::new(),
            &mut stack_depth,
            script_size,
            contract_constants,
        )?;
        bindings.stack_bindings.push_binding(&param.name);
    }
    let body_len = function.body.len();
    for (index, stmt) in function.body.iter().enumerate() {
        recorder.begin_statement_at(builder.script().len(), &bindings.env, &bindings.stack_bindings);
        if let Statement::Return { exprs, .. } = stmt {
            if index != body_len - 1 {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            validate_return_types(
                exprs,
                &function.return_types,
                &bindings.types,
                structs,
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
            )
            .map_err(|err| err.with_span(&stmt.span()))?;
            for expr in exprs {
                let resolved =
                    resolve_inline_return_expr(expr.clone(), &bindings.env, &bindings.preserved_return_idents, &mut HashSet::new())
                        .map_err(|err| err.with_span(&expr.span))?;
                returns.push(resolved);
            }
        } else {
            compile_statement(
                stmt,
                &mut bindings.env,
                &assigned_names,
                &identifier_uses,
                &mut bindings.types,
                &mut bindings.stack_bindings,
                builder,
                options,
                false,
                contract_fields,
                0,
                contract_constants,
                structs,
                functions,
                function_order,
                callee_index,
                script_size,
                recorder,
            )
            .map_err(|err| err.with_span(&stmt.span()))?;
        }
        recorder.finish_statement_at(stmt, builder.script().len(), &bindings.env, &bindings.types, &bindings.stack_bindings)?;
    }

    for _ in 0..bindings.stack_bindings.len().saturating_sub(initial_stack_binding_count) {
        builder.add_op(OpDrop)?;
    }
    let call_end = builder.script().len();
    recorder.finish_inline_call(call_span, call_end, name);

    Ok(rewrite_inline_returns(returns, &bindings.return_rewrites))
}

#[allow(clippy::too_many_arguments)]
fn compile_if_statement<'i>(
    condition: &Expr<'i>,
    then_branch: &[Statement<'i>],
    else_branch: Option<&[Statement<'i>]>,
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    enable_mutable_scalar_stack_locals: bool,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
) -> Result<(), CompilerError> {
    let condition = lower_runtime_expr(condition, types, structs)?;
    let mut stack_depth = 0i64;
    compile_expr(
        &condition,
        env,
        stack_bindings,
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
    let original_stack_bindings = stack_bindings.clone();

    let mut then_env = original_env.clone();
    let mut then_types = types.clone();
    let mut then_stack_bindings = original_stack_bindings.clone();
    predeclare_if_branch_locals(then_branch, &mut then_env, &mut then_types, structs)?;
    compile_block(
        then_branch,
        &mut then_env,
        assigned_names,
        identifier_uses,
        &mut then_types,
        &mut then_stack_bindings,
        builder,
        options,
        enable_mutable_scalar_stack_locals,
        contract_fields,
        contract_field_prefix_len,
        contract_constants,
        structs,
        functions,
        function_order,
        function_index,
        script_size,
        true,
        recorder,
    )?;

    let mut else_env = original_env.clone();
    if let Some(else_branch) = else_branch {
        builder.add_op(OpElse)?;
        let mut else_types = types.clone();
        let mut else_stack_bindings = original_stack_bindings.clone();
        predeclare_if_branch_locals(else_branch, &mut else_env, &mut else_types, structs)?;
        compile_block(
            else_branch,
            &mut else_env,
            assigned_names,
            identifier_uses,
            &mut else_types,
            &mut else_stack_bindings,
            builder,
            options,
            enable_mutable_scalar_stack_locals,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            true,
            recorder,
        )?;
        let target_order = then_stack_bindings.binding_order_top_to_bottom();
        else_stack_bindings.emit_stack_reordering(&target_order, builder)?;
        *stack_bindings = then_stack_bindings;
    } else {
        let target_order = original_stack_bindings.binding_order_top_to_bottom();
        then_stack_bindings.emit_stack_reordering(&target_order, builder)?;
        *stack_bindings = original_stack_bindings;
    }

    builder.add_op(OpEndIf)?;

    let resolved_condition = resolve_expr_for_runtime(condition, &original_env, types, &mut HashSet::new())?;
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

fn default_scalar_expr(type_name: &str) -> Option<Expr<'static>> {
    match type_name {
        "int" => Some(Expr::int(0)),
        "bool" => Some(Expr::new(ExprKind::Bool(false), span::Span::default())),
        "byte" => Some(Expr::new(ExprKind::Byte(0), span::Span::default())),
        _ => None,
    }
}

fn is_predeclared_scalar_default<'i>(name: &str, type_name: &str, env: &HashMap<String, Expr<'i>>) -> bool {
    matches!(
        (type_name, env.get(name).map(|expr| &expr.kind)),
        ("int", Some(ExprKind::Int(0))) | ("bool", Some(ExprKind::Bool(false))) | ("byte", Some(ExprKind::Byte(0)))
    )
}

fn predeclare_if_branch_locals<'i>(
    statements: &[Statement<'i>],
    env: &mut HashMap<String, Expr<'i>>,
    types: &mut HashMap<String, String>,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    for stmt in statements {
        match stmt {
            Statement::VariableDefinition { type_ref, name, .. } => {
                if types.contains_key(name) {
                    continue;
                }
                let type_name = type_name_from_ref(type_ref);
                let Some(default_expr) = default_scalar_expr(&type_name) else {
                    continue;
                };
                if struct_name_from_type_ref(type_ref, structs).is_none()
                    && struct_array_name_from_type_ref(type_ref, structs).is_none()
                {
                    types.insert(name.clone(), type_name);
                    env.insert(name.clone(), default_expr);
                }
            }
            Statement::FunctionCallAssign { bindings, .. } => {
                for binding in bindings {
                    if types.contains_key(&binding.name) {
                        continue;
                    }
                    let type_name = type_name_from_ref(&binding.type_ref);
                    let Some(default_expr) = default_scalar_expr(&type_name) else {
                        continue;
                    };
                    if struct_name_from_type_ref(&binding.type_ref, structs).is_none()
                        && struct_array_name_from_type_ref(&binding.type_ref, structs).is_none()
                    {
                        types.insert(binding.name.clone(), type_name);
                        env.insert(binding.name.clone(), default_expr);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn compile_time_op_statement<'i>(
    tx_var: &TimeVar,
    expr: &Expr<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(
        expr,
        env,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        script_size,
        contract_constants,
    )?;

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
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    enable_mutable_scalar_stack_locals: bool,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    scoped_stack_locals: bool,
    recorder: &mut DebugRecorder<'i>,
) -> Result<(), CompilerError> {
    let mut added_stack_locals = Vec::new();
    for stmt in statements {
        recorder.begin_statement_at(builder.script().len(), env, stack_bindings);
        added_stack_locals.extend(
            compile_statement(
                stmt,
                env,
                assigned_names,
                identifier_uses,
                types,
                stack_bindings,
                builder,
                options,
                enable_mutable_scalar_stack_locals,
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
                recorder,
            )
            .map_err(|err| err.with_span(&stmt.span()))?,
        );
        recorder.finish_statement_at(stmt, builder.script().len(), env, types, stack_bindings)?;
    }

    if scoped_stack_locals && !added_stack_locals.is_empty() {
        stack_bindings.emit_drop_bindings(&added_stack_locals, builder)?;
        for name in &added_stack_locals {
            types.remove(name);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_for_statement<'i>(
    ident: &str,
    start_expr: &Expr<'i>,
    end_expr: &Expr<'i>,
    max_iterations_expr: &Expr<'i>,
    body: &[Statement<'i>],
    for_span: span::Span<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    enable_mutable_scalar_stack_locals: bool,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
) -> Result<(), CompilerError> {
    let max_iterations = eval_const_int(max_iterations_expr, contract_constants)
        .map_err(|_| CompilerError::Unsupported("for loop max iterations must be a compile-time integer".to_string()))?;
    if max_iterations < 0 {
        return Err(CompilerError::Unsupported("for loop max iterations must be a non-negative compile-time integer".to_string()));
    }

    let start = lower_runtime_expr(start_expr, types, structs)?;
    let end = lower_runtime_expr(end_expr, types, structs)?;

    let name = ident.to_string();
    let loop_span = SourceSpan::from(for_span);
    let previous = env.get(&name).cloned();
    let previous_type = types.get(&name).cloned();
    types.insert(name.clone(), "int".to_string());

    let result =
        if let (Ok(start), Ok(end)) = (eval_const_int(start_expr, contract_constants), eval_const_int(end_expr, contract_constants)) {
            compile_constant_for_statement(
                &name,
                start,
                end,
                max_iterations as usize,
                body,
                loop_span,
                env,
                assigned_names,
                identifier_uses,
                types,
                stack_bindings,
                builder,
                options,
                enable_mutable_scalar_stack_locals,
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
                recorder,
            )
        } else {
            compile_runtime_for_statement(
                &name,
                start,
                end,
                max_iterations as usize,
                body,
                loop_span,
                env,
                assigned_names,
                identifier_uses,
                types,
                stack_bindings,
                builder,
                options,
                enable_mutable_scalar_stack_locals,
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
                recorder,
            )
        };

    match previous {
        Some(expr) => {
            env.insert(name, expr);
        }
        None => {
            env.remove(ident);
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

    result
}

#[allow(clippy::too_many_arguments)]
fn compile_constant_for_statement<'i>(
    ident: &str,
    start: i64,
    end: i64,
    max_iterations: usize,
    body: &[Statement<'i>],
    loop_span: SourceSpan,
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    enable_mutable_scalar_stack_locals: bool,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
) -> Result<(), CompilerError> {
    for iteration in 0..max_iterations {
        let value = start + iteration as i64;
        if value >= end {
            break;
        }

        env.insert(ident.to_string(), Expr::int(value));
        recorder.record_variable_binding(
            ident.to_string(),
            "int".to_string(),
            Expr::int(value),
            stack_bindings.depth_from_top(ident).map(|from_top| RuntimeBinding::DataStackSlot { from_top }),
            builder.script().len(),
            loop_span,
        );
        compile_block(
            body,
            env,
            assigned_names,
            identifier_uses,
            types,
            stack_bindings,
            builder,
            options,
            enable_mutable_scalar_stack_locals,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            true,
            recorder,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_runtime_for_statement<'i>(
    ident: &str,
    start: Expr<'i>,
    end: Expr<'i>,
    max_iterations: usize,
    body: &[Statement<'i>],
    loop_span: SourceSpan,
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    enable_mutable_scalar_stack_locals: bool,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    recorder: &mut DebugRecorder<'i>,
) -> Result<(), CompilerError> {
    let mut current = resolve_expr_for_runtime(start, env, types, &mut HashSet::new())?;
    let mut current_const = eval_const_int(&current, contract_constants).ok();
    for _ in 0..max_iterations {
        let loop_value = current_const.map_or_else(|| current.clone(), Expr::int);
        env.insert(ident.to_string(), loop_value.clone());
        recorder.record_variable_binding(
            ident.to_string(),
            "int".to_string(),
            loop_value,
            stack_bindings.depth_from_top(ident).map(|from_top| RuntimeBinding::DataStackSlot { from_top }),
            builder.script().len(),
            loop_span,
        );

        let condition = Expr::new(
            ExprKind::Binary { op: BinaryOp::Lt, left: Box::new(Expr::identifier(ident)), right: Box::new(end.clone()) },
            span::Span::default(),
        );
        compile_if_statement(
            &condition,
            body,
            None,
            env,
            assigned_names,
            identifier_uses,
            types,
            stack_bindings,
            builder,
            options,
            enable_mutable_scalar_stack_locals,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            recorder,
        )?;

        if let Some(value) = env.get(ident).and_then(|expr| eval_const_int(expr, contract_constants).ok()) {
            let next_value = value + 1;
            current_const = Some(next_value);
            current = Expr::int(next_value);
            continue;
        }

        let next = Expr::new(
            ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier(ident)), right: Box::new(Expr::int(1)) },
            span::Span::default(),
        );
        current_const = None;
        current = resolve_expr_for_runtime(next, env, types, &mut HashSet::new())?;
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
            if name.starts_with(SYNTHETIC_ARG_PREFIX) {
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
        ExprKind::FieldAccess { source, field, field_span } => {
            Ok(Expr::new(ExprKind::FieldAccess { source: Box::new(resolve_expr(*source, env, visiting)?), field, field_span }, span))
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

fn resolve_expr_for_runtime<'i>(
    expr: Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    types: &HashMap<String, String>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    let preserve_identifier =
        |name: &str| name.starts_with(SYNTHETIC_ARG_PREFIX) || types.get(name).is_some_and(|type_name| is_array_type(type_name));
    resolve_expr_with_policy(expr, env, visiting, &preserve_identifier)
}

fn resolve_return_expr_for_runtime<'i>(
    expr: Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    let preserve_identifier = |name: &str| {
        name.starts_with(SYNTHETIC_ARG_PREFIX)
            || stack_bindings.contains(name)
            || types.get(name).is_some_and(|type_name| is_array_type(type_name))
    };
    resolve_expr_with_policy(expr, env, visiting, &preserve_identifier)
}

fn resolve_inline_return_expr<'i>(
    expr: Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    preserved_idents: &HashSet<String>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    let preserve_identifier = |name: &str| name.starts_with(SYNTHETIC_ARG_PREFIX) || preserved_idents.contains(name);
    resolve_expr_with_policy(expr, env, visiting, &preserve_identifier)
}

fn resolve_expr_with_policy<'i, F>(
    expr: Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    visiting: &mut HashSet<String>,
    preserve_identifier: &F,
) -> Result<Expr<'i>, CompilerError>
where
    F: Fn(&str) -> bool,
{
    let Expr { kind, span } = expr;
    match kind {
        ExprKind::Identifier(name) => {
            if preserve_identifier(&name) {
                return Ok(Expr::new(ExprKind::Identifier(name), span));
            }
            if let Some(value) = env.get(&name) {
                if !visiting.insert(name.clone()) {
                    return Err(CompilerError::CyclicIdentifier(name));
                }
                let resolved = resolve_expr_with_policy(value.clone(), env, visiting, preserve_identifier)?;
                visiting.remove(&name);
                Ok(resolved)
            } else {
                Ok(Expr::new(ExprKind::Identifier(name), span))
            }
        }
        ExprKind::Unary { op, expr } => Ok(Expr::new(
            ExprKind::Unary { op, expr: Box::new(resolve_expr_with_policy(*expr, env, visiting, preserve_identifier)?) },
            span,
        )),
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op,
                left: Box::new(resolve_expr_with_policy(*left, env, visiting, preserve_identifier)?),
                right: Box::new(resolve_expr_with_policy(*right, env, visiting, preserve_identifier)?),
            },
            span,
        )),
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(resolve_expr_with_policy(*condition, env, visiting, preserve_identifier)?),
                then_expr: Box::new(resolve_expr_with_policy(*then_expr, env, visiting, preserve_identifier)?),
                else_expr: Box::new(resolve_expr_with_policy(*else_expr, env, visiting, preserve_identifier)?),
            },
            span,
        )),
        ExprKind::Array(values) => Ok(Expr::new(
            ExprKind::Array(
                values.into_iter().map(|value| resolve_expr_with_policy(value, env, visiting, preserve_identifier)).collect::<Result<
                    Vec<_>,
                    _,
                >>(
                )?,
            ),
            span,
        )),
        ExprKind::StateObject(fields) => Ok(Expr::new(
            ExprKind::StateObject(
                fields
                    .into_iter()
                    .map(|field| {
                        Ok(StateFieldExpr {
                            name: field.name,
                            expr: resolve_expr_with_policy(field.expr, env, visiting, preserve_identifier)?,
                            span: field.span,
                            name_span: field.name_span,
                        })
                    })
                    .collect::<Result<Vec<_>, CompilerError>>()?,
            ),
            span,
        )),
        ExprKind::FieldAccess { source, field, field_span } => Ok(Expr::new(
            ExprKind::FieldAccess {
                source: Box::new(resolve_expr_with_policy(*source, env, visiting, preserve_identifier)?),
                field,
                field_span,
            },
            span,
        )),
        ExprKind::Call { name, args, name_span } => Ok(Expr::new(
            ExprKind::Call {
                name,
                args: args.into_iter().map(|arg| resolve_expr_with_policy(arg, env, visiting, preserve_identifier)).collect::<Result<
                    Vec<_>,
                    _,
                >>(
                )?,
                name_span,
            },
            span,
        )),
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name,
                args: args.into_iter().map(|arg| resolve_expr_with_policy(arg, env, visiting, preserve_identifier)).collect::<Result<
                    Vec<_>,
                    _,
                >>(
                )?,
                name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(resolve_expr_with_policy(*source, env, visiting, preserve_identifier)?),
                index: Box::new(resolve_expr_with_policy(*index, env, visiting, preserve_identifier)?),
                part,
                span: split_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(resolve_expr_with_policy(*source, env, visiting, preserve_identifier)?),
                index: Box::new(resolve_expr_with_policy(*index, env, visiting, preserve_identifier)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::Introspection {
                kind,
                index: Box::new(resolve_expr_with_policy(*index, env, visiting, preserve_identifier)?),
                field_span,
            },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Ok(Expr::new(
            ExprKind::UnarySuffix {
                source: Box::new(resolve_expr_with_policy(*source, env, visiting, preserve_identifier)?),
                kind,
                span: suffix_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(resolve_expr_with_policy(*source, env, visiting, preserve_identifier)?),
                start: Box::new(resolve_expr_with_policy(*start, env, visiting, preserve_identifier)?),
                end: Box::new(resolve_expr_with_policy(*end, env, visiting, preserve_identifier)?),
                span: slice_span,
            },
            span,
        )),
        other => Ok(Expr::new(other, span)),
    }
}

/// Replace `target` identifiers in `expr` with `replacement`.
///
/// Example: for `x = x + 1`, this rewrites the right side to
/// `<previous x> + 1` before `resolve_expr` runs.
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
        ExprKind::StateObject(fields) => Expr::new(
            ExprKind::StateObject(
                fields
                    .iter()
                    .map(|field| StateFieldExpr {
                        name: field.name.clone(),
                        expr: replace_identifier(&field.expr, target, replacement),
                        span: field.span,
                        name_span: field.name_span,
                    })
                    .collect(),
            ),
            span,
        ),
        ExprKind::FieldAccess { source, field, field_span } => Expr::new(
            ExprKind::FieldAccess {
                source: Box::new(replace_identifier(source, target, replacement)),
                field: field.clone(),
                field_span: *field_span,
            },
            span,
        ),
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
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Expr::new(
            ExprKind::UnarySuffix {
                source: Box::new(replace_identifier(source, target, replacement)),
                kind: *kind,
                span: *suffix_span,
            },
            span,
        ),
        ExprKind::Int(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::NumberWithUnit { .. }
        | ExprKind::Nullary(_) => expr.clone(),
    }
}

struct CompilationScope<'a, 'i> {
    env: &'a HashMap<String, Expr<'i>>,
    stack_bindings: &'a StackBindings,
    types: &'a HashMap<String, String>,
}

fn compile_expr<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let scope = CompilationScope { env, stack_bindings, types };
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
        ExprKind::Byte(byte) => {
            builder.add_data(&[*byte])?;
            *stack_depth += 1;
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
        ExprKind::StateObject(_) => Err(CompilerError::Unsupported(
            "state object literals are only supported in validateOutputState-style builtins".to_string(),
        )),
        ExprKind::FieldAccess { .. } => {
            Err(CompilerError::Unsupported("struct field access should be lowered before compilation".to_string()))
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
            if stack_bindings.emit_copy_binding_to_top(name, stack_depth, builder)? {
                visiting.remove(name);
                return Ok(());
            }
            if let Some(resolved_expr) = env.get(name) {
                if let Some(type_name) = types.get(name) {
                    if let ExprKind::Array(values) = &resolved_expr.kind {
                        if is_array_type(type_name) {
                            let encoded = encode_array_literal(values, type_name)?;
                            builder.add_data(&encoded)?;
                            *stack_depth += 1;
                            visiting.remove(name);
                            return Ok(());
                        }
                    }
                }
                compile_expr(
                    resolved_expr,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                visiting.remove(name);
                return Ok(());
            }
            visiting.remove(name);
            Err(CompilerError::UndefinedIdentifier(name.clone()))
        }
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            compile_expr(
                condition,
                env,
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpIf)?;
            *stack_depth -= 1;
            let depth_before = *stack_depth;
            compile_expr(
                then_expr,
                env,
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpElse)?;
            *stack_depth = depth_before;
            compile_expr(
                else_expr,
                env,
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpEndIf)?;
            *stack_depth = depth_before + 1;
            Ok(())
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
                compile_expr(
                    &args[0],
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
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
                compile_expr(
                    &args[0],
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
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
                compile_expr(
                    &args[0],
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
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
            compile_expr(expr, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
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
                    stack_bindings,
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
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
            } else {
                compile_expr(
                    left,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
                compile_expr(
                    right,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
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
            stack_bindings,
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
                stack_bindings,
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
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            compile_expr(index, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
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
        ExprKind::Slice { source, start, end, .. } => {
            compile_expr(
                source,
                env,
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            compile_expr(start, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            compile_expr(end, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
            builder.add_op(OpSubstr)?;
            *stack_depth -= 2;
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
            compile_expr(index, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
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
        ExprKind::DateLiteral(value) => {
            builder.add_i64(*value)?;
            *stack_depth += 1;
            Ok(())
        }
        ExprKind::NumberWithUnit { .. } => {
            Err(CompilerError::Unsupported("number units must be normalized during parsing".to_string()))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_split_part<'i>(
    source: &Expr<'i>,
    index: &Expr<'i>,
    part: SplitPart,
    env: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    compile_expr(source, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    match part {
        SplitPart::Left => {
            compile_expr(index, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
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
            compile_expr(index, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
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
        ExprKind::Byte(_) => true,
        ExprKind::String(_) => true,
        ExprKind::Array(values) => values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))),
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
    stack_bindings: &StackBindings,
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
                compile_expr(
                    expr,
                    env,
                    stack_bindings,
                    types,
                    builder,
                    options,
                    visiting,
                    stack_depth,
                    script_size,
                    contract_constants,
                )?;
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
    compile_expr(expr, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    builder.add_op(OpSize)?;
    builder.add_op(OpSwap)?;
    builder.add_op(OpDrop)?;
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
                scope.stack_bindings,
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
        "OpTxInputDaaScore" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpTxInputDaaScore,
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
        "OpCovOutputCount" => compile_opcode_call(
            name,
            args,
            1,
            scope,
            builder,
            options,
            visiting,
            stack_depth,
            OpCovOutputCount,
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
                    scope.stack_bindings,
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
                    scope.stack_bindings,
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
                            scope.stack_bindings,
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
                        scope.stack_bindings,
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
                            scope.stack_bindings,
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
                            scope.stack_bindings,
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
                scope.stack_bindings,
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
                scope.stack_bindings,
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
                scope.stack_bindings,
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
                    scope.stack_bindings,
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
                        scope.stack_bindings,
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
                    scope.stack_bindings,
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
                scope.stack_bindings,
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
                scope.stack_bindings,
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
                scope.stack_bindings,
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
                    scope.stack_bindings,
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
            scope.stack_bindings,
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
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    compile_expr(expr, env, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    if !expr_is_bytes(expr, env, types) {
        builder.add_i64(1)?;
        *stack_depth += 1;
        builder.add_op(OpNum2Bin)?;
        *stack_depth -= 1;
    }
    Ok(())
}

fn is_bytes_type(type_name: &str) -> bool {
    if type_name == "bytes" || type_name == "byte" || matches!(type_name, "pubkey" | "sig" | "datasig" | "string") {
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
            ExprKind::Array(values) if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => {
                let bytes: Vec<u8> = values
                    .iter()
                    .filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None })
                    .collect();
                builder.add_data(&bytes)?;
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

/// Compiles a pre-resolved expression for debugger shadow evaluation.
pub fn compile_debug_expr<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    stack_bindings: &HashMap<String, i64>,
    types: &HashMap<String, String>,
) -> Result<(Vec<u8>, String), CompilerError> {
    let constants = HashMap::new();
    let mut builder = ScriptBuilder::new();
    let mut stack_depth = 0i64;
    let type_name = infer_debug_expr_value_type(expr, env, types, &mut HashSet::new())?;
    let stack_bindings = StackBindings::from_depths(stack_bindings.clone());
    compile_expr(
        expr,
        env,
        &stack_bindings,
        types,
        &mut builder,
        CompileOptions::default(),
        &mut HashSet::new(),
        &mut stack_depth,
        None,
        &constants,
    )?;
    Ok((builder.drain(), type_name))
}

pub(super) fn resolve_expr_for_debug<'i>(
    expr: Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    resolve_expr(expr, env, visiting)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kaspa_txscript::opcodes::codes::OpData1;

    use super::{Op0, OpPushData1, OpPushData2, StackBindings, data_prefix};

    #[test]
    fn data_prefix_encodes_small_pushes() {
        assert_eq!(data_prefix(0), vec![Op0]);
        assert_eq!(data_prefix(1), vec![OpData1]);
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
    fn entrypoint_stack_setup_places_contract_fields_above_params_in_depth_order() {
        let contract_field_count = 2usize;
        let flattened_param_names = ["param_a", "param_b"];
        let param_count = flattened_param_names.len();
        let mut stack_bindings = StackBindings::from_depths(
            flattened_param_names
                .iter()
                .enumerate()
                .map(|(index, name)| (name.to_string(), (param_count - 1 - index) as i64))
                .collect::<HashMap<_, _>>(),
        );
        let contract_fields = ["field_a", "field_b"];

        for (index, field) in contract_fields.iter().enumerate().rev() {
            stack_bindings.set_depth_from_top(field, (contract_field_count - 1 - index) as i64);
        }

        assert_eq!(
            stack_bindings.binding_order_top_to_bottom(),
            ["field_b", "field_a", "param_b", "param_a"].into_iter().map(str::to_string).collect::<Vec<_>>()
        );
    }
}
