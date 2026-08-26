use std::collections::{HashMap, HashSet};

use super::compile::read_input_state_field_expr_symbolic;
use super::*;
use crate::ast::{
    ArrayDim, ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, ParamAst, STATE_TYPE_NAME, Statement,
    StructBindingAst, TypeBase, TypeRef,
};
use crate::span;

mod assignment;
mod context;
mod contract;
mod declaration;
mod destructure;
mod expr_lowering;
mod layout;
mod scalar_expr;
mod schema;
mod statement;

use assignment::lower_assignment;
pub(crate) use context::LoweringScope;
use context::StructLowerer;
pub(crate) use contract::{dynamic_struct_array_param_groups, flatten_constructor_args_env, lower_structs_contract};
use declaration::lower_variable_definition;
use destructure::lower_struct_destructure_statement;
use expr_lowering::{
    flatten_named_type, flatten_runtime_return_exprs, lower_call_args, lower_expr, lower_function_call_bindings, lower_named_expr,
    lower_struct_array_expr,
};
use layout::flatten_struct_fields;
pub use layout::flattened_struct_name;
pub(crate) use layout::{flatten_type_leaves, flattened_struct_field_specs_for_type};
use scalar_expr::lower_scalar_expr;
pub(crate) use scalar_expr::resolve_struct_access;
use schema::is_struct_like;
pub(crate) use schema::{
    StructRegistry, build_struct_registry, ensure_known_type, ensure_known_type_without_struct_arrays, is_struct, is_struct_array,
    struct_array_name, struct_name, validate_struct_graph,
};
use statement::lower_statements;

pub(crate) type StructArrayParamGroups = HashMap<String, Vec<Vec<String>>>;
