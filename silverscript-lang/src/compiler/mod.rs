use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use kaspa_txscript::script_builder::ScriptBuilder;

use crate::ast::{
    ArrayDim, BinaryOp, ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, IntrospectionKind, NullaryOp,
    ParamAst, SplitPart, StateBindingAst, StateFieldExpr, Statement, TimeVar, TypeBase, TypeRef, UnaryOp, UnarySuffixKind,
    parse_contract_ast, parse_type_ref,
};
use crate::debug_info::DebugInfo;
pub use crate::errors::{CompilerError, ErrorSpan};
use crate::span;
mod covenant_declarations;
mod compile;
mod debug_value_types;
mod stack_bindings;
mod type_check;

pub use compile::{compile_debug_expr, function_branch_index};
use compile::compile_contract_impl;
pub(super) use compile::{array_element_type, eval_const_int, is_bytes_type, type_name_from_ref};
use type_check::{type_check_contract, value_matches_type_ref};

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
pub(super) struct StructFieldSpec {
    name: String,
    type_ref: TypeRef,
}

#[derive(Clone)]
pub(super) struct StructSpec {
    fields: Vec<StructFieldSpec>,
}

pub(super) type StructRegistry = HashMap<String, StructSpec>;

pub fn compile_contract<'i>(
    source: &'i str,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    let contract = parse_contract_ast(source)?;
    type_check_contract(&contract, constructor_args, options)?;
    compile_contract_impl(&contract, constructor_args, options, Some(source))
}

pub fn compile_contract_ast<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    type_check_contract(contract, constructor_args, options)?;
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

    if !value_matches_type_ref(&arg, type_ref) {
        return Err(CompilerError::Unsupported("signature script arguments must match the declared type".to_string()));
    }

    let type_name = type_name_from_ref(type_ref);
    if compile::is_array_type(&type_name) {
        match &arg.kind {
            ExprKind::Array(values) => {
                if compile::is_byte_array(&arg) {
                    let bytes: Vec<u8> = values
                        .iter()
                        .filter_map(|value| if let ExprKind::Byte(byte) = &value.kind { Some(*byte) } else { None })
                        .collect();
                    builder.add_data(&bytes)?;
                } else {
                    let bytes = compile::encode_array_literal(values, &type_name)?;
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

pub(super) fn build_struct_registry<'i>(contract: &ContractAst<'i>) -> Result<StructRegistry, CompilerError> {
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

pub(super) fn struct_name_from_type_ref<'a>(type_ref: &'a TypeRef, structs: &'a StructRegistry) -> Option<&'a str> {
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

pub(super) fn ensure_known_or_builtin_type(type_ref: &TypeRef, structs: &StructRegistry, context: &str) -> Result<(), CompilerError> {
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

pub(super) fn validate_struct_graph(structs: &StructRegistry) -> Result<(), CompilerError> {
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

pub fn flattened_struct_name(base: &str, path: &[String]) -> String {
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
