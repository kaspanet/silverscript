use super::array_append::lower_array_appends;
use super::covenant_declarations::lower_covenant_declarations;
use super::infer_array::lower_inferred_array_sizes;
use super::inline_functions::lower_inline_functions;
use super::locals::lower_local_aliases;
use super::stack_bindings::StackBindings;
use super::static_check::static_check_contract;
use super::ternary::lower_ternaries;
use super::*;
use kaspa_txscript::EngineFlags;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::serialize_i64;
use std::collections::{HashMap, HashSet};

mod analysis;
mod const_eval;
mod emitter;
mod expression;
mod helpers;
mod state;
mod statement;

use analysis::*;
pub(crate) use const_eval::{eval_const_int, resolve_constant_references};
use emitter::*;
use expression::*;
pub(super) use helpers::encode_array_literal;
use helpers::*;
use state::*;
pub(super) use state::{encoded_state_len_for_layout_field_types, encoded_type_chunk_size, read_input_state_field_expr_symbolic};
use statement::*;

fn script_builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

pub(super) fn compile_contract_impl<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
    source: Option<&'i str>,
) -> Result<CompiledContract<'i>, CompilerError> {
    let mut constants: HashMap<String, Expr<'i>> =
        contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        constants.insert(param.name.clone(), value.clone());
    }

    let mut debug_recorder = DebugRecorder::new(options, contract)?;
    let inferred_lowered_contract = lower_inferred_array_sizes(contract, &constants)?;
    static_check_contract(&inferred_lowered_contract, constructor_args, options)?;
    let covenant_lowered_contract = lower_covenant_declarations(&inferred_lowered_contract, &constants)?;
    let read_input_state_lowered_contract = lower_read_input_state_calls(&covenant_lowered_contract)?;
    let ternary_lowered_contract = lower_ternaries(&read_input_state_lowered_contract, &constants)?;
    let inline_lowered_contract = lower_inline_functions(&ternary_lowered_contract, &mut debug_recorder)?;
    let structs = build_struct_registry(&inline_lowered_contract)?;
    let validate_output_state_lowered_contract = lower_validate_output_state(&inline_lowered_contract, &structs, &constants)?;
    let struct_lowered_contract = lower_structs_contract(&validate_output_state_lowered_contract, &structs, &constants)?;
    let append_lowered_contract = lower_array_appends(&struct_lowered_contract, &constants)?;
    let for_lowered_contract = lower_for_loops(&append_lowered_contract, &constants)?;
    let lowered_contract = if options.record_debug_infos { for_lowered_contract } else { lower_local_aliases(&for_lowered_contract)? };
    let mut lowered_constants = flatten_constructor_args_env(&covenant_lowered_contract.params, constructor_args, &structs)?;
    lowered_constants.extend(lowered_contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())));

    let entrypoint_functions: Vec<&FunctionAst<'i>> = lowered_contract.functions.iter().filter(|func| func.entrypoint).collect();
    if entrypoint_functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entries".to_string()));
    }

    let without_selector = entrypoint_functions.len() == 1;

    let function_abi_entries = build_function_abi_entries(&covenant_lowered_contract);
    let uses_bytecode_size = contract_uses_bytecode_size(&lowered_contract);

    let mut bytecode_size = if uses_bytecode_size { Some(100i64) } else { None };

    for _ in 0..32 {
        debug_recorder.record_contract_scope(&inline_lowered_contract, constructor_args, &structs)?;

        let (bytecode, state_layout) = compile_contract_bytecode_iteration(
            &lowered_contract,
            &lowered_constants,
            bytecode_size,
            without_selector,
            &structs,
            &mut debug_recorder,
        )?;

        let debug_info = debug_recorder.take_debug_info(source);
        if !uses_bytecode_size {
            return Ok(build_compiled_contract(
                &lowered_contract,
                &covenant_lowered_contract,
                function_abi_entries.clone(),
                without_selector,
                bytecode,
                state_layout,
                debug_info,
            ));
        }

        let actual_size = bytecode.len() as i64;
        if Some(actual_size) == bytecode_size {
            return Ok(build_compiled_contract(
                &lowered_contract,
                &covenant_lowered_contract,
                function_abi_entries.clone(),
                without_selector,
                bytecode,
                state_layout,
                debug_info,
            ));
        }
        bytecode_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("bytecode size did not stabilize".to_string()))
}

fn compile_contract_bytecode_iteration<'i>(
    lowered_contract: &ContractAst<'i>,
    lowered_constants: &HashMap<String, Expr<'i>>,
    bytecode_size: Option<i64>,
    without_selector: bool,
    structs: &StructRegistry,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<(Vec<u8>, CompiledStateLayout), CompilerError> {
    let (_contract_fields, field_prolog_bytecode) =
        compile_contract_fields(&lowered_contract.fields, lowered_constants, bytecode_size)?;

    let selector_prefix_len = if without_selector { 0 } else { 1 };
    let contract_fields_end_offset = selector_prefix_len + field_prolog_bytecode.len();
    let state_layout = CompiledStateLayout { start: selector_prefix_len, len: field_prolog_bytecode.len() };
    let compiled_entrypoints = compile_entrypoint_bytecodes(
        lowered_contract,
        contract_fields_end_offset,
        lowered_constants,
        structs,
        bytecode_size,
        debug_recorder,
    )?;
    let bytecode = build_contract_bytecode(debug_recorder, without_selector, &field_prolog_bytecode, &compiled_entrypoints)?;
    Ok((bytecode, state_layout))
}

fn compile_entrypoint_bytecodes<'i>(
    lowered_contract: &ContractAst<'i>,
    contract_fields_end_offset: usize,
    lowered_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    bytecode_size: Option<i64>,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<Vec<(String, Vec<u8>)>, CompilerError> {
    let mut compiled_entrypoints = Vec::new();
    for func in &lowered_contract.functions {
        if func.entrypoint {
            let compiled = compile_entrypoint_function(
                func,
                &lowered_contract.params,
                &lowered_contract.fields,
                &lowered_contract.constants,
                contract_fields_end_offset,
                lowered_constants,
                structs,
                bytecode_size,
                debug_recorder,
            )?;
            compiled_entrypoints.push(compiled);
        }
    }
    Ok(compiled_entrypoints)
}

fn build_contract_bytecode(
    debug_recorder: &mut DebugRecorder<'_>,
    without_selector: bool,
    field_prolog_bytecode: &[u8],
    compiled_entrypoints: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, CompilerError> {
    if without_selector {
        let (name, entrypoint_bytecode) =
            compiled_entrypoints.first().ok_or_else(|| CompilerError::Unsupported("contract has no entries".to_string()))?;
        debug_recorder.set_entrypoint_start(name, field_prolog_bytecode.len());
        let mut bytecode = field_prolog_bytecode.to_vec();
        bytecode.extend(entrypoint_bytecode.clone());
        return Ok(bytecode);
    }

    // Preserve the selector while encoding contract state once so
    // reflection helpers can rewrite a single contiguous state segment.
    let mut builder = script_builder();
    builder.add_op(OpToAltStack)?;
    builder.add_ops(field_prolog_bytecode)?;
    builder.add_op(OpFromAltStack)?;
    let total = compiled_entrypoints.len();
    for (entrypoint_index, (name, bytecode)) in compiled_entrypoints.iter().enumerate() {
        builder.add_op(OpDup)?;
        builder.add_i64(entrypoint_index as i64)?;
        builder.add_op(OpNumEqual)?;
        builder.add_op(OpIf)?;
        builder.add_op(OpDrop)?;
        debug_recorder.set_entrypoint_start(name, builder.script().len());
        builder.add_ops(bytecode)?;
        builder.add_op(OpElse)?;
        if entrypoint_index == total - 1 {
            builder.add_op(OpReturn)?;
        }
    }

    for _ in 0..total {
        builder.add_op(OpEndIf)?;
    }

    Ok(builder.drain())
}

fn build_compiled_contract<'i>(
    lowered_contract: &ContractAst<'i>,
    covenant_lowered_contract: &ContractAst<'i>,
    function_abi_entries: Vec<FunctionAbiEntry>,
    without_selector: bool,
    bytecode: Vec<u8>,
    state_layout: CompiledStateLayout,
    debug_info: Option<DebugInfo<'i>>,
) -> CompiledContract<'i> {
    CompiledContract {
        contract_name: lowered_contract.name.clone(),
        compiler_version: COMPILER_VERSION.to_string(),
        bytecode,
        ast: covenant_lowered_contract.clone(),
        abi: function_abi_entries,
        without_selector,
        state_layout,
        debug_info,
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

/// Compiles a pre-resolved expression for debugger shadow evaluation.
pub fn compile_debug_expr<'i>(
    expr: &Expr<'i>,
    constants: &HashMap<String, Expr<'i>>,
    stack_bindings: &HashMap<String, i64>,
    types: &TypeMap,
) -> Result<(Vec<u8>, String), CompilerError> {
    let empty_constants = HashMap::new();
    let mut builder = script_builder();
    let type_ref = infer_expr_type(expr, constants, types)?;
    let stack_bindings = StackBindings::from_depths(stack_bindings.clone());
    let env = ExprEnv { constants, stack_bindings: &stack_bindings, types, bytecode_size: None, contract_constants: &empty_constants };
    let mut emitter = ScriptEmitter::new(&mut builder, 0);
    compile_expr(expr, Some(&type_ref), &env, &mut emitter)?;
    Ok((builder.drain(), type_ref.type_name()))
}
