use std::collections::HashMap;

use kaspa_txscript::EngineFlags;
use kaspa_txscript::script_builder::ScriptBuilder;
use serde::{Deserialize, Serialize};

use crate::ast::{
    ArrayDim, BinaryOp, ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, IndexedIntrospectionKind,
    IntrospectionKind, ParamAst, STATE_TYPE_NAME, SplitPart, StateFieldExpr, Statement, StructBindingAst, TypeBase, TypeRef, UnaryOp,
    UnarySuffixKind, as_cast_call_name, as_cast_type, parse_contract_ast, parse_type_ref,
};
use crate::debug_info::{DebugInfo, DebugNamedValue};
pub use crate::errors::{CompilerError, ErrorSpan};
use crate::span;
mod array_append;
mod builtin_types;
mod compile;
mod covenant_declarations;
mod debug_recording;
mod r#for;
mod infer_array;
mod inline_functions;
mod locals;
mod read_input_state;
mod stack_bindings;
mod static_check;
mod structs;
mod ternary;
mod type_check;
mod type_system;
mod validate_output_state;

use compile::compile_contract_impl;
pub(super) use compile::eval_const_int;
pub(crate) use compile::resolve_constant_references;
pub use compile::{compile_debug_expr, function_branch_index};
pub(crate) use debug_recording::DebugRecorder;
use r#for::lower_for_loops;
use read_input_state::lower_read_input_state_calls;
use static_check::validate_expr_matches_type;
pub use structs::flattened_struct_name;
pub(super) use structs::{
    StructRegistry, build_struct_registry, ensure_known_struct_or_builtin_type, flatten_constructor_args_env, flatten_type_leaves,
    flattened_struct_field_specs_for_type, is_struct, is_struct_array, lower_structs_contract, struct_name, validate_struct_graph,
};
pub(super) use type_system::{append_type, array_size as array_type_size, concat_types, fixed_type_size, type_refs_equal};
use validate_output_state::lower_validate_output_state;

/// Prefix used for synthetic argument bindings during inline function expansion.
pub const SYNTHETIC_ARG_PREFIX: &str = "__arg";
pub const COMPILER_VERSION: &str = "0.1.0";
const COVENANT_POLICY_PREFIX: &str = "__covenant_policy";
pub const COVENANT_ENTRYPOINT_AUTH_PREFIX: &str = "__covenant_entrypoint_auth";
pub(super) type TypeMap = HashMap<String, TypeRef>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CovenantDeclCallOptions {
    pub is_leader: bool,
}

fn generated_covenant_policy_name(function_name: &str) -> String {
    format!("{COVENANT_POLICY_PREFIX}_{function_name}")
}

pub fn generated_covenant_auth_entrypoint_name(function_name: &str) -> String {
    format!("{COVENANT_ENTRYPOINT_AUTH_PREFIX}_{function_name}")
}

pub fn generated_covenant_leader_entrypoint_name(function_name: &str) -> String {
    format!("__leader_{function_name}")
}

pub fn generated_covenant_delegate_entrypoint_name() -> String {
    "__delegate".to_string()
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

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledContract<'i> {
    pub contract_name: String,
    pub compiler_version: String,
    pub bytecode: Vec<u8>,
    pub ast: ContractAst<'i>,
    pub abi: Vec<FunctionAbiEntry>,
    pub without_selector: bool,
    pub state_layout: CompiledStateLayout,
    pub debug_info: Option<DebugInfo<'i>>,
}

pub fn compile_contract<'i>(
    source: &'i str,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    let contract = parse_contract_ast(source)?;
    let compiled = compile_contract_impl(&contract, constructor_args, options, Some(source))?;
    let repeated_compiled = compile_contract_impl(&contract, constructor_args, options, Some(source))?;
    assert_eq!(&compiled, &repeated_compiled, "compiling the same contract twice must produce identical results");
    Ok(compiled)
}

pub fn compile_contract_ast<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<CompiledContract<'i>, CompilerError> {
    compile_contract_impl(contract, constructor_args, options, None)
}

impl<'i> ContractAst<'i> {
    // Computes the concrete state values for a contract instance.
    pub fn resolve_contract_state_values(&self, constructor_args: &[Expr<'i>]) -> Result<Vec<DebugNamedValue<'i>>, CompilerError> {
        if self.params.len() != constructor_args.len() {
            return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
        }

        let structs = build_struct_registry(self)?;
        let constants: HashMap<String, Expr<'i>> =
            self.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
        let mut env = constants.clone();

        for (param, value) in self.params.iter().zip(constructor_args.iter()) {
            let type_name = param.type_ref.type_name();
            if validate_expr_matches_type(value, &param.type_ref, &HashMap::new(), &structs, &constants, &HashMap::new(), &self.fields)
                .is_err()
            {
                return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, type_name)));
            }
            env.insert(param.name.clone(), value.clone());
        }

        let mut resolved_fields = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            if env.contains_key(&field.name) {
                return Err(CompilerError::Unsupported(format!("duplicate contract field name: {}", field.name)));
            }

            let type_name = field.type_ref.type_name();
            let resolved = resolve_constant_references(field.expr.clone(), &env, &mut std::collections::HashSet::new())?;
            if validate_expr_matches_type(
                &resolved,
                &field.type_ref,
                &HashMap::new(),
                &structs,
                &constants,
                &HashMap::new(),
                &self.fields,
            )
            .is_err()
            {
                return Err(CompilerError::Unsupported(format!("contract field '{}' expects {}", field.name, type_name)));
            }

            env.insert(field.name.clone(), resolved.clone());
            resolved_fields.push(DebugNamedValue { name: field.name.clone(), type_name, value: resolved });
        }

        Ok(resolved_fields)
    }
}

pub fn struct_object<'i>(name: &str, fields: Vec<(&str, Expr<'i>)>) -> Expr<'i> {
    Expr::new(
        ExprKind::StructLiteral {
            name: name.to_string(),
            fields: fields
                .into_iter()
                .map(|(name, expr)| StateFieldExpr {
                    name: name.to_string(),
                    expr,
                    span: Default::default(),
                    name_span: Default::default(),
                })
                .collect(),
            name_span: Default::default(),
        },
        Default::default(),
    )
}

impl<'i> CompiledContract<'i> {
    /// Calculate the canonical hash of this contract's state template.
    pub fn template_hash(&self) -> [u8; 32] {
        let state_end = self.state_layout.start + self.state_layout.len;
        crate::template::template_hash(&self.bytecode[..self.state_layout.start], &self.bytecode[state_end..])
    }

    pub fn build_sig_script(&self, function_name: &str, args: Vec<Expr<'i>>) -> Result<Vec<u8>, CompilerError> {
        let structs = build_struct_registry(&self.ast)?;
        let constants: HashMap<_, _> =
            self.ast.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
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

        let mut builder = ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() });
        for (input, arg) in function.inputs.iter().zip(args) {
            let type_ref = parse_type_ref(&input.type_name)?;
            push_typed_sigscript_arg(&mut builder, arg, &type_ref, &structs, &constants).map_err(|err| {
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
        let auth_entrypoint = generated_covenant_auth_entrypoint_name(function_name);
        if self.abi.iter().any(|entry| entry.name == auth_entrypoint) {
            return self.build_sig_script(&auth_entrypoint, args);
        }

        let leader_entrypoint = generated_covenant_leader_entrypoint_name(function_name);
        if self.abi.iter().any(|entry| entry.name == leader_entrypoint) {
            let entrypoint = if options.is_leader { leader_entrypoint } else { generated_covenant_delegate_entrypoint_name() };
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
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    validate_sigscript_arg(&arg, type_ref, structs, constants)?;

    if is_struct_array(type_ref, structs) {
        return push_struct_array_sigscript_arg(builder, arg, type_ref, structs, constants);
    }

    if is_struct(type_ref, structs) {
        return push_struct_sigscript_arg(builder, arg, structs, constants);
    }

    if type_ref.is_array() {
        return push_array_sigscript_arg(builder, arg, type_ref, constants);
    }

    push_sigscript_non_array_arg(builder, arg)
}

fn validate_sigscript_arg<'i>(
    arg: &Expr<'i>,
    type_ref: &TypeRef,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let types = HashMap::new();
    let functions = HashMap::new();
    let type_context = type_check::TypeCheckContext { types: &types, structs, constants, functions: &functions, contract_fields: &[] };
    type_check::check_expr(arg, Some(type_ref), &type_context)?;
    Ok(())
}

fn push_struct_sigscript_arg<'i>(
    builder: &mut ScriptBuilder,
    arg: Expr<'i>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let ExprKind::StructLiteral { name, fields, .. } = arg.kind else {
        return Err(CompilerError::Unsupported("signature script struct arguments must be object literals".to_string()));
    };
    let item = structs.get(&name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
    let mut provided = fields.into_iter().map(|field| (field.name, field.expr)).collect::<HashMap<_, _>>();

    for field in &item.fields {
        let value = provided
            .remove(&field.name)
            .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))?;
        push_typed_sigscript_arg(builder, value, &field.type_ref, structs, constants)?;
    }

    if let Some(extra) = provided.keys().next() {
        return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
    }
    Ok(())
}

fn push_struct_array_sigscript_arg<'i>(
    builder: &mut ScriptBuilder,
    arg: Expr<'i>,
    type_ref: &TypeRef,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let element_type = type_ref
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported("signature script struct array argument requires an array type".to_string()))?;
    let struct_name = struct_name(&element_type, structs).ok_or_else(|| {
        CompilerError::Unsupported("signature script struct array argument requires a struct element type".to_string())
    })?;
    let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let dimension = type_ref
        .array_size()
        .cloned()
        .ok_or_else(|| CompilerError::Unsupported("signature script struct array argument requires an array type".to_string()))?;
    let ExprKind::Array { values, .. } = arg.kind else {
        return Err(CompilerError::Unsupported("signature script struct array arguments must be array literals".to_string()));
    };

    let mut objects = Vec::with_capacity(values.len());
    for value in values {
        let ExprKind::StructLiteral { name, fields: entries, .. } = value.kind else {
            return Err(CompilerError::Unsupported(
                "signature script struct array arguments must contain object literals".to_string(),
            ));
        };
        if name != struct_name {
            return Err(CompilerError::Unsupported(format!("expected struct '{struct_name}', got '{name}'")));
        }
        objects.push(entries.into_iter().map(|entry| (entry.name, entry.expr)).collect::<HashMap<_, _>>());
    }

    for field in &item.fields {
        let field_values = objects
            .iter_mut()
            .map(|fields| {
                fields
                    .remove(&field.name)
                    .ok_or_else(|| CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut field_type = field.type_ref.clone();
        field_type.array_dims.push(dimension.clone());
        push_typed_sigscript_arg(builder, Expr::array(field_type.clone(), field_values), &field_type, structs, constants)?;
    }

    if let Some(extra) = objects.iter().find_map(|fields| fields.keys().next()) {
        return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
    }
    Ok(())
}

fn push_array_sigscript_arg<'i>(
    builder: &mut ScriptBuilder,
    arg: Expr<'i>,
    type_ref: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    match &arg.kind {
        ExprKind::Array { values, .. } => {
            let bytes = compile::encode_array_literal(values, type_ref, constants)?;
            builder.add_data(&bytes)?;
            Ok(())
        }
        _ => Err(CompilerError::Unsupported("signature script arguments must be literals".to_string())),
    }
}

fn push_sigscript_non_array_arg<'i>(builder: &mut ScriptBuilder, arg: Expr<'i>) -> Result<(), CompilerError> {
    match arg.kind {
        ExprKind::Int(value) | ExprKind::Temporal(value) => {
            builder.add_i64(value)?;
        }
        ExprKind::Bool(value) => {
            builder.add_i64(if value { 1 } else { 0 })?;
        }
        ExprKind::String(value) => {
            builder.add_data(value.as_bytes())?;
        }
        ExprKind::Byte(value) => {
            builder.add_data_with_push_opcode(&[value])?;
        }
        // This is not intended for byte-arrays, but for pubkey, datasig, etc.
        ExprKind::Array { values, .. } if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => {
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

fn binary_expr<'i>(op: BinaryOp, left: Expr<'i>, right: Expr<'i>) -> Expr<'i> {
    Expr::new(ExprKind::Binary { op, left: Box::new(left), right: Box::new(right) }, span::Span::default())
}

fn int_to_fixed_bytes_expr<'i>(source: Expr<'i>, size: usize) -> Expr<'i> {
    let type_ref = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(size)] };
    Expr::call(as_cast_call_name(&type_ref), vec![source])
}
