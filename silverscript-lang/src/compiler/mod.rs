use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::ast::{
    ArrayDim, BinaryOp, ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, IndexedIntrospectionKind,
    IntrospectionKind, ParamAst, STATE_TYPE_NAME, SplitPart, StateFieldExpr, Statement, StructBindingAst, TypeBase, TypeRef, UnaryOp,
    UnarySuffixKind, as_cast_call_name, as_cast_type, parse_contract_ast, parse_type_ref,
};
pub(crate) use crate::checked_arithmetic::{checked_add, checked_div, checked_mul, checked_neg, checked_rem, checked_sub};
use crate::debug_info::{DebugInfo, DebugNamedValue};
pub use crate::errors::{CompilerError, ErrorSpan};
use crate::span;
mod abi;
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

pub use abi::{artifact_value_to_expr, sil_abi_artifact, sil_abi_artifact_from_compiled, sil_abi_artifact_with_options};
use compile::compile_contract_impl;
pub use compile::compile_debug_expr;
pub(crate) use compile::resolve_constant_references;
pub(super) use compile::{eval_const_int, eval_optional_const_int};
pub(crate) use debug_recording::DebugRecorder;
use r#for::lower_for_loops;
use read_input_state::lower_read_input_state_calls;
use static_check::{validate_concrete_constructor_argument, validate_expr_matches_type};
pub use structs::flattened_struct_name;
pub(super) use structs::{
    StructArrayParamGroups, StructRegistry, build_struct_registry, dynamic_struct_array_param_groups, ensure_known_type,
    ensure_known_type_without_struct_arrays, flatten_constructor_args_env, flatten_type_leaves, flattened_struct_field_specs_for_type,
    is_struct, is_struct_array, lower_structs_contract, struct_name, validate_struct_graph,
};
pub(super) use type_system::{append_type, array_size as array_type_size, concat_types, fixed_type_size, type_refs_equal};
use validate_output_state::lower_validate_output_state;

/// Prefix used for synthetic argument bindings during inline function expansion.
pub const SYNTHETIC_ARG_PREFIX: &str = "__arg";
pub const COMPILER_VERSION: &str = "0.1.0";
const COVENANT_POLICY_PREFIX: &str = "__covenant_policy";
const COVENANT_DELEGATE_POLICY_PREFIX: &str = "__covenant_delegate_policy";
pub const COVENANT_ENTRYPOINT_AUTH_PREFIX: &str = "__covenant_entrypoint_auth";
pub(super) type TypeMap = HashMap<String, TypeRef>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CovenantDeclCallOptions {
    pub is_leader: bool,
}

fn generated_covenant_policy_name(function_name: &str) -> String {
    format!("{COVENANT_POLICY_PREFIX}_{function_name}")
}

fn generated_covenant_delegate_policy_name(function_name: &str) -> String {
    format!("{COVENANT_DELEGATE_POLICY_PREFIX}_{function_name}")
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntrypointDispatch {
    pub name: String,
    pub dispatch_tag: DispatchTag,
}

pub type DispatchTag = [u8; 4];

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
    pub dispatch_tags: BTreeMap<String, DispatchTag>,
    /// Generated leader/auth entrypoint names keyed by their pre-lowering covenant declaration names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    covenant_entrypoints: BTreeMap<String, String>,
    /// The shared delegate entrypoint generated for a cov-bound contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegate_entrypoint: Option<String>,
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
            validate_concrete_constructor_argument(param, value)?;
            let type_name = param.type_ref.type_name();
            if validate_expr_matches_type(value, &param.type_ref, &HashMap::new(), &structs, &env, &HashMap::new(), &self.fields)
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
            if validate_expr_matches_type(&resolved, &field.type_ref, &HashMap::new(), &structs, &env, &HashMap::new(), &self.fields)
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
}

fn binary_expr<'i>(op: BinaryOp, left: Expr<'i>, right: Expr<'i>) -> Expr<'i> {
    Expr::new(ExprKind::Binary { op, left: Box::new(left), right: Box::new(right) }, span::Span::default())
}

fn int_to_fixed_bytes_expr<'i>(source: Expr<'i>, size: usize) -> Expr<'i> {
    let type_ref = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(size)] };
    Expr::call(as_cast_call_name(&type_ref), vec![source])
}
