use super::array_append::{lower_array_append_expr, lower_array_appends};
use super::covenant_declarations::lower_covenant_declarations;
use super::infer_array::lower_inferred_array_sizes;
use super::inline_functions::lower_inline_functions;
use super::stack_bindings::StackBindings;
use super::static_check::{static_check_contract, validate_concrete_constructor_argument, validate_declaration_names};
use super::ternary::lower_ternaries;
use super::*;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::serialize_i64;
use kaspa_txscript::{EngineFlags, MAX_STACK_SIZE};
use std::collections::{BTreeMap, HashMap, HashSet};

mod analysis;
mod const_eval;
mod emitter;
mod expression;
mod helpers;
mod state;
mod statement;

use analysis::*;
pub(crate) use const_eval::{eval_const_int, eval_optional_const_int, resolve_constant_references};
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
    validate_declaration_names(contract)?;
    // Constructor arguments enter the constant environment below, so reject
    // evaluatable expression forms before any inference or lowering can use them.
    if contract.params.len() != constructor_args.len() {
        return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
    }
    for (param, value) in contract.params.iter().zip(constructor_args) {
        validate_concrete_constructor_argument(param, value)?;
    }

    let mut constants: HashMap<String, Expr<'i>> =
        contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        constants.insert(param.name.clone(), value.clone());
    }

    let mut debug_recorder = DebugRecorder::new(options, contract)?;
    let inferred_lowered_contract = lower_inferred_array_sizes(contract, &constants)?;
    static_check_contract(&inferred_lowered_contract, constructor_args, options)?;
    let (covenant_lowered_contract, covenant_abi_names) = lower_covenant_declarations(&inferred_lowered_contract, &constants)?;
    validate_declaration_names(&covenant_lowered_contract)?;
    let ternary_lowered_contract = lower_ternaries(&covenant_lowered_contract, &constants)?;
    let read_input_state_lowered_contract = lower_read_input_state_calls(&ternary_lowered_contract)?;
    let inline_lowered_contract = lower_inline_functions(&read_input_state_lowered_contract, &mut debug_recorder)?;
    let structs = build_struct_registry(&inline_lowered_contract)?;
    let validate_output_state_lowered_contract = lower_validate_output_state(&inline_lowered_contract, &structs, &constants)?;
    let struct_array_param_groups = dynamic_struct_array_param_groups(&validate_output_state_lowered_contract, &structs)?;
    let struct_lowered_contract = lower_structs_contract(&validate_output_state_lowered_contract, &structs, &constants)?;
    let append_lowered_contract = lower_array_appends(&struct_lowered_contract, &constants)?;
    let for_lowered_contract = lower_for_loops(&append_lowered_contract, &constants)?;
    // TODO: Re-enable this once we make sure we don't optimize away fallible statements.
    // let lowered_contract = if options.record_debug_infos { for_lowered_contract } else { lower_local_aliases(&for_lowered_contract)? };
    let lowered_contract = for_lowered_contract;
    validate_declaration_names(&lowered_contract)?; // This is a sanity check to ensure that lowering didn't introduce any duplicate names.
    let mut lowered_constants = flatten_constructor_args_env(&covenant_lowered_contract.params, constructor_args, &structs)?;
    lowered_constants.extend(lowered_contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())));

    let BuiltAbi { function_abi_entries, cov_decl_to_abi, delegate_entry_abi } =
        build_abi(&covenant_lowered_contract, &constants, &covenant_abi_names)?;
    if function_abi_entries.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entries".to_string()));
    }
    let entrypoint_functions: Vec<&FunctionAst<'i>> = lowered_contract.functions.iter().filter(|func| func.entrypoint).collect();
    validate_entrypoint_stack_limits(&entrypoint_functions)?;
    let artifact_contract = resolve_artifact_struct_type_refs(&covenant_lowered_contract, &constants)?;

    // dispatch tag: verify no collisions and insert tags to global state
    let mut entrypoints_by_tag = HashMap::<DispatchTag, &str>::new();
    for entrypoint in &function_abi_entries {
        let tag = entrypoint.dispatch_tag();
        if let Some(existing) = entrypoints_by_tag.insert(tag, entrypoint.name.as_str()) {
            return Err(CompilerError::EntrypointDispatchTagCollision { f1: existing.to_string(), f2: entrypoint.name.clone() });
        }
    }

    let uses_bytecode_size = contract_uses_bytecode_size(&lowered_contract);

    let mut bytecode_size = if uses_bytecode_size { Some(100i64) } else { None };

    for _ in 0..32 {
        debug_recorder.record_contract_scope(&inline_lowered_contract, constructor_args, &structs)?;

        let (bytecode, state_layout) = compile_contract_bytecode_iteration(
            &lowered_contract,
            &lowered_constants,
            bytecode_size,
            &function_abi_entries,
            &structs,
            &struct_array_param_groups,
            &mut debug_recorder,
        )?;

        let debug_info = debug_recorder.take_debug_info(source);
        if !uses_bytecode_size {
            return Ok(build_compiled_contract(
                &lowered_contract,
                &artifact_contract,
                function_abi_entries.clone(),
                &cov_decl_to_abi,
                delegate_entry_abi.as_ref(),
                bytecode,
                state_layout,
                debug_info,
            ));
        }

        let actual_size = bytecode.len() as i64;
        if Some(actual_size) == bytecode_size {
            return Ok(build_compiled_contract(
                &lowered_contract,
                &artifact_contract,
                function_abi_entries.clone(),
                &cov_decl_to_abi,
                delegate_entry_abi.as_ref(),
                bytecode,
                state_layout,
                debug_info,
            ));
        }
        bytecode_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("bytecode size did not stabilize".to_string()))
}

fn validate_entrypoint_stack_limits(entrypoints: &[&FunctionAst<'_>]) -> Result<(), CompilerError> {
    for entrypoint in entrypoints {
        // At the end of P2SH signature-script execution, the stack contains
        // every flattened argument, the dispatch tag, and the redeem script.
        let initial_stack_items = checked_add(entrypoint.params.len(), 2)?;
        if initial_stack_items > MAX_STACK_SIZE {
            return Err(CompilerError::EntrypointStackTooLarge {
                function: entrypoint.name.clone(),
                actual: initial_stack_items,
                maximum: MAX_STACK_SIZE,
            });
        }
    }
    Ok(())
}

fn validate_signature_script_limits<'i>(
    bytecode: &[u8],
    entrypoints: &[&FunctionAst<'i>],
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let max_signature_script_len = MAINNET_PARAMS.new_max_signature_script_len;
    if bytecode.len() > max_signature_script_len {
        return Err(CompilerError::RedeemScriptTooLarge { actual: bytecode.len(), maximum: max_signature_script_len });
    }

    let redeem_script_push_size = ScriptBuilder::canonical_data_size(bytecode);
    let dispatch_tag_push_size = maximum_canonical_data_push_size(std::mem::size_of::<DispatchTag>())?;
    for entrypoint in entrypoints {
        let mut estimated_size = checked_add(redeem_script_push_size, dispatch_tag_push_size)?;
        for param in &entrypoint.params {
            estimated_size = checked_add(estimated_size, conservative_sigscript_argument_size(&param.type_ref, constants)?)?;
        }
        if estimated_size > max_signature_script_len {
            return Err(CompilerError::EntrypointSignatureScriptTooLarge {
                function: entrypoint.name.clone(),
                estimated: estimated_size,
                maximum: max_signature_script_len,
            });
        }
    }
    Ok(())
}

fn conservative_sigscript_argument_size<'i>(
    type_ref: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    if type_ref.is_array() {
        let payload_size = match fixed_type_size(type_ref, constants)? {
            Some(payload_size) => payload_size,
            None => {
                // Dynamic arrays are estimated with one element. Use the full
                // fixed-width encoding of that element as a worst-case estimate for the dynamic array's payload size.
                let element_type = type_ref.array_element_type().expect("array type has an element type");
                fixed_type_size(&element_type, constants)?.ok_or_else(|| {
                    CompilerError::Unsupported(format!("cannot determine dynamic ABI element size for {}", type_ref.type_name()))
                })?
            }
        };
        return maximum_canonical_data_push_size(payload_size);
    }

    match type_ref.base {
        // Int-like values can occupy the full eight-byte ScriptNum payload.
        TypeBase::Int | TypeBase::Temporal => maximum_canonical_data_push_size(8),
        TypeBase::Bool => Ok(1),
        TypeBase::Byte => maximum_canonical_data_push_size(1),
        // Treat strings as containing at least one byte for this conservative
        // feasibility estimate.
        TypeBase::String => maximum_canonical_data_push_size(1),
        TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig => {
            let payload_size = type_ref
                .base
                .fixed_byte_sequence_len()
                .ok_or_else(|| CompilerError::Unsupported(format!("cannot determine ABI size for {}", type_ref.type_name())))?;
            maximum_canonical_data_push_size(payload_size)
        }
        TypeBase::Tuple(_) | TypeBase::Custom(_) => {
            Err(CompilerError::Unsupported(format!("cannot determine flattened ABI size for {}", type_ref.type_name())))
        }
    }
}

fn maximum_canonical_data_push_size(payload_size: usize) -> Result<usize, CompilerError> {
    if payload_size == 0 {
        return Ok(1);
    }
    let prefix_size = if payload_size <= OpData75 as usize {
        1
    } else if payload_size <= u8::MAX as usize {
        2
    } else if payload_size <= u16::MAX as usize {
        3
    } else {
        5
    };
    checked_add(payload_size, prefix_size)
}

fn compile_contract_bytecode_iteration<'i>(
    lowered_contract: &ContractAst<'i>,
    lowered_constants: &HashMap<String, Expr<'i>>,
    bytecode_size: Option<i64>,
    function_abi_entries: &[FunctionAbiEntry],
    structs: &StructRegistry,
    struct_array_param_groups: &StructArrayParamGroups,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<(Vec<u8>, CompiledStateLayout), CompilerError> {
    let (_contract_fields, state_push_bytecode) = compile_contract_fields(&lowered_contract.fields, lowered_constants, bytecode_size)?;

    let state_start: usize = if state_push_bytecode.is_empty() {
        0
    } else {
        1 // The 1 accounts for OpToAltStack.
    };
    let state_end = checked_add(state_start, state_push_bytecode.len())?;
    let state_layout = CompiledStateLayout { start: state_start, len: state_push_bytecode.len() };
    let compiled_entrypoints = compile_entrypoint_bytecodes(
        lowered_contract,
        state_end,
        lowered_constants,
        structs,
        struct_array_param_groups,
        bytecode_size,
        debug_recorder,
    )?;
    let bytecode = build_contract_bytecode(debug_recorder, &state_push_bytecode, &compiled_entrypoints, function_abi_entries)?;
    let entrypoints = lowered_contract.functions.iter().filter(|function| function.entrypoint).collect::<Vec<_>>();
    validate_signature_script_limits(&bytecode, &entrypoints, lowered_constants)?;
    Ok((bytecode, state_layout))
}

fn compile_entrypoint_bytecodes<'i>(
    lowered_contract: &ContractAst<'i>,
    state_end: usize,
    lowered_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    struct_array_param_groups: &StructArrayParamGroups,
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
                state_end,
                lowered_constants,
                structs,
                bytecode_size,
                struct_array_param_groups.get(&func.name).map(Vec::as_slice).unwrap_or_default(),
                debug_recorder,
            )?;
            compiled_entrypoints.push(compiled);
        }
    }
    Ok(compiled_entrypoints)
}

fn build_contract_bytecode(
    debug_recorder: &mut DebugRecorder<'_>,
    state_push_bytecode: &[u8],
    compiled_entrypoints: &[(String, Vec<u8>)],
    function_abi_entries: &[FunctionAbiEntry],
) -> Result<Vec<u8>, CompilerError> {
    let mut builder = script_builder();
    if !state_push_bytecode.is_empty() {
        // Preserve the dispatch tag while encoding contract state once so
        // reflection helpers can rewrite a single contiguous state segment.
        builder.add_op(OpToAltStack)?;
        builder.add_ops(state_push_bytecode)?;
        builder.add_op(OpFromAltStack)?;
    }
    let total = compiled_entrypoints.len();

    let dispatch_tag_by_entry_name =
        function_abi_entries.iter().map(|entry| (entry.name.as_str(), entry.dispatch_tag())).collect::<HashMap<_, _>>();

    for (entrypoint_index, (name, bytecode)) in compiled_entrypoints.iter().enumerate() {
        let dispatch_tag = dispatch_tag_by_entry_name.get(name.as_str()).expect("compiled entrypoint must have an ABI entry");
        builder.add_op(OpDup)?;
        builder.add_data(dispatch_tag)?;
        builder.add_op(OpEqual)?;
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
    cov_decl_to_abi: &BTreeMap<String, FunctionAbiEntry>,
    delegate_entry_abi: Option<&FunctionAbiEntry>,
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
        cov_decl_to_abi: cov_decl_to_abi.clone(),
        delegate_entry_abi: delegate_entry_abi.cloned(),
        state_layout,
        debug_info,
    }
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
    let expr = lower_array_append_expr(expr, types, constants)?;
    let type_ref = infer_expr_type(&expr, constants, types)?;
    let stack_bindings = StackBindings::from_depths(stack_bindings.clone());
    let env = ExprEnv { constants, stack_bindings: &stack_bindings, types, bytecode_size: None, contract_constants: &empty_constants };
    let mut emitter = ScriptEmitter::new(&mut builder, 0);
    compile_expr(&expr, Some(&type_ref), &env, &mut emitter)?;
    Ok((builder.drain(), type_ref.type_name()))
}

#[cfg(test)]
mod signature_script_limit_tests {
    use super::*;

    #[test]
    fn conservative_argument_sizes_use_maximum_scalar_widths_and_one_dynamic_element() {
        let constants = HashMap::new();
        let cases = [
            ("int", 9),
            ("temporal", 9),
            ("bool", 1),
            ("byte", 2),
            ("string", 2),
            ("byte[1]", 2),
            ("byte[]", 2),
            ("int[]", 9),
            ("byte[2][]", 3),
            ("pubkey[]", 33),
        ];

        for (type_name, expected_size) in cases {
            let type_ref = parse_type_ref(type_name).unwrap_or_else(|err| panic!("{type_name} should parse: {err}"));
            let actual = conservative_sigscript_argument_size(&type_ref, &constants)
                .unwrap_or_else(|err| panic!("{type_name} should have a conservative size: {err}"));
            assert_eq!(actual, expected_size, "unexpected conservative size for {type_name}");
        }
    }
}
