use super::array_append::lower_array_appends;
use super::covenant_declarations::lower_covenant_declarations;
use super::debug_value_types::infer_debug_expr_value_type;
use super::infer_array::{infer_expr_type, lower_inferred_array_sizes};
use super::inline_functions::lower_inline_functions;
use super::locals::lower_local_aliases;
use super::stack_bindings::StackBindings;
use super::static_check::static_check_contract;
use super::*;
use kaspa_txscript::EngineFlags;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::serialize_i64;
use std::collections::{HashMap, HashSet};

fn script_builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

pub(super) fn read_input_state_field_expr_symbolic<'i>(
    input_idx: &Expr<'i>,
    field: &ContractFieldAst<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    field_chunk_offset: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let state_start_offset = state_start_offset(contract_field_prefix_len, contract_fields, contract_constants)?;
    let script_size_expr = Expr::new(ExprKind::Nullary(NullaryOp::ThisScriptSize), span::Span::default());
    let field_payload_len = fixed_state_field_payload_len(field, contract_constants)?;
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

    cast_read_input_state_expr(substr, &field.type_ref)
}

pub(super) fn read_input_state_with_template_values<'i>(
    args: &[Expr<'i>],
    expected_type: &TypeRef,
    structs: &StructRegistry,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let Ok([input_idx, template_prefix_len, template_suffix_len, _expected_template_hash]): Result<&[Expr<'i>; 4], _> =
        args.try_into()
    else {
        return Err(CompilerError::Unsupported(
            "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                .to_string(),
        ));
    };

    let layout_field_types = flattened_struct_field_specs_for_type(expected_type, structs)?;
    if layout_field_types.is_empty() {
        return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
    }

    let script_size_expr =
        templated_input_script_size_expr(template_prefix_len, template_suffix_len, &layout_field_types, contract_constants)?;
    let state_start_offset_expr = template_prefix_len.clone();
    let mut field_chunk_offset = 0usize;
    let mut lowered = Vec::with_capacity(layout_field_types.len());
    for type_ref in &layout_field_types {
        lowered.push(read_input_state_field_expr_with_type(
            input_idx,
            type_ref,
            state_start_offset_expr.clone(),
            field_chunk_offset,
            script_size_expr.clone(),
            contract_constants,
            "readInputStateWithTemplate",
        )?);
        field_chunk_offset += encoded_type_chunk_size(type_ref, contract_constants)?;
    }
    Ok(lowered)
}

pub(super) fn compile_contract_impl<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
    _source: Option<&'i str>,
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
    let inline_lowered_contract = lower_inline_functions(&read_input_state_lowered_contract, &mut debug_recorder)?;
    let structs = build_struct_registry(&inline_lowered_contract)?;
    let validate_output_state_lowered_contract = lower_validate_output_state(&inline_lowered_contract, &structs)?;
    let struct_lowered_contract = lower_structs_contract(&validate_output_state_lowered_contract, &structs, &constants)?;
    let append_lowered_contract = lower_array_appends(&struct_lowered_contract)?;
    let for_lowered_contract = lower_for_loops(&append_lowered_contract, &constants)?;
    let lowered_contract = if options.record_debug_infos { for_lowered_contract } else { lower_local_aliases(&for_lowered_contract)? };
    let mut lowered_constants = flatten_constructor_args_env(&covenant_lowered_contract.params, constructor_args, &structs)?;
    lowered_constants.extend(lowered_contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())));

    let entrypoint_functions: Vec<&FunctionAst<'i>> = lowered_contract.functions.iter().filter(|func| func.entrypoint).collect();
    if entrypoint_functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entrypoint functions".to_string()));
    }

    let without_selector = entrypoint_functions.len() == 1;

    let function_abi_entries = build_function_abi_entries(&covenant_lowered_contract);
    let uses_script_size = contract_uses_script_size(&lowered_contract);

    let mut script_size = if uses_script_size { Some(100i64) } else { None };

    for _ in 0..32 {
        debug_recorder.record_contract_scope(&inline_lowered_contract, constructor_args, &structs)?;

        let (script, state_layout) = compile_contract_script_iteration(
            &lowered_contract,
            &lowered_constants,
            options,
            script_size,
            without_selector,
            &structs,
            &mut debug_recorder,
        )?;

        let debug_info = debug_recorder.take_debug_info(_source);
        if !uses_script_size {
            return Ok(build_compiled_contract(
                &lowered_contract,
                &covenant_lowered_contract,
                function_abi_entries.clone(),
                without_selector,
                script,
                state_layout,
                debug_info,
            ));
        }

        let actual_size = script.len() as i64;
        if Some(actual_size) == script_size {
            return Ok(build_compiled_contract(
                &lowered_contract,
                &covenant_lowered_contract,
                function_abi_entries.clone(),
                without_selector,
                script,
                state_layout,
                debug_info,
            ));
        }
        script_size = Some(actual_size);
    }

    Err(CompilerError::Unsupported("script size did not stabilize".to_string()))
}

#[allow(clippy::too_many_arguments)]
fn compile_contract_script_iteration<'i>(
    lowered_contract: &ContractAst<'i>,
    lowered_constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    script_size: Option<i64>,
    without_selector: bool,
    structs: &StructRegistry,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<(Vec<u8>, CompiledStateLayout), CompilerError> {
    let (_contract_fields, field_prolog_script) =
        compile_contract_fields(&lowered_contract.fields, lowered_constants, options, script_size)?;

    let selector_prefix_len = if without_selector { 0 } else { 1 };
    let contract_field_prefix_len = selector_prefix_len + field_prolog_script.len();
    let state_layout = CompiledStateLayout { start: selector_prefix_len, len: field_prolog_script.len() };
    let compiled_entrypoints = compile_entrypoint_scripts(
        lowered_contract,
        contract_field_prefix_len,
        lowered_constants,
        options,
        structs,
        script_size,
        debug_recorder,
    )?;
    let script = build_contract_script(debug_recorder, without_selector, &field_prolog_script, &compiled_entrypoints)?;
    Ok((script, state_layout))
}

#[allow(clippy::too_many_arguments)]
fn compile_entrypoint_scripts<'i>(
    lowered_contract: &ContractAst<'i>,
    contract_field_prefix_len: usize,
    lowered_constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    structs: &StructRegistry,
    script_size: Option<i64>,
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
                contract_field_prefix_len,
                lowered_constants,
                options,
                structs,
                script_size,
                debug_recorder,
            )?;
            compiled_entrypoints.push(compiled);
        }
    }
    Ok(compiled_entrypoints)
}

fn build_contract_script(
    debug_recorder: &mut DebugRecorder<'_>,
    without_selector: bool,
    field_prolog_script: &[u8],
    compiled_entrypoints: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, CompilerError> {
    if without_selector {
        let (_name, entrypoint_script) = compiled_entrypoints
            .first()
            .ok_or_else(|| CompilerError::Unsupported("contract has no entrypoint functions".to_string()))?;
        debug_recorder.set_entrypoint_start(_name, field_prolog_script.len());
        let mut script = field_prolog_script.to_vec();
        script.extend(entrypoint_script.clone());
        return Ok(script);
    }

    // Preserve the selector while encoding contract state once so
    // reflection helpers can rewrite a single contiguous state segment.
    let mut builder = script_builder();
    builder.add_op(OpToAltStack)?;
    builder.add_ops(field_prolog_script)?;
    builder.add_op(OpFromAltStack)?;
    let total = compiled_entrypoints.len();
    for (entrypoint_index, (_name, script)) in compiled_entrypoints.iter().enumerate() {
        builder.add_op(OpDup)?;
        builder.add_i64(entrypoint_index as i64)?;
        builder.add_op(OpNumEqual)?;
        builder.add_op(OpIf)?;
        builder.add_op(OpDrop)?;
        debug_recorder.set_entrypoint_start(_name, builder.script().len());
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

    Ok(builder.drain())
}

fn build_compiled_contract<'i>(
    lowered_contract: &ContractAst<'i>,
    covenant_lowered_contract: &ContractAst<'i>,
    function_abi_entries: Vec<FunctionAbiEntry>,
    without_selector: bool,
    script: Vec<u8>,
    state_layout: CompiledStateLayout,
    debug_info: Option<DebugInfo<'i>>,
) -> CompiledContract<'i> {
    CompiledContract {
        contract_name: lowered_contract.name.clone(),
        compiler_version: COMPILER_VERSION.to_string(),
        script,
        ast: covenant_lowered_contract.clone(),
        abi: function_abi_entries,
        without_selector,
        state_layout,
        debug_info,
    }
}

fn contract_uses_script_size<'i>(contract: &ContractAst<'i>) -> bool {
    if contract.constants.iter().any(|constant| expr_uses_script_size(&constant.expr)) {
        return true;
    }
    if contract.fields.iter().any(|field| expr_uses_script_size(&field.expr)) {
        return true;
    }
    contract.functions.iter().any(|func| func.body.iter().any(statement_uses_script_size))
}

fn compile_contract_fields<'i>(
    fields: &[ContractFieldAst<'i>],
    base_constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    script_size: Option<i64>,
) -> Result<(HashMap<String, Expr<'i>>, Vec<u8>), CompilerError> {
    let mut field_values = HashMap::new();
    let mut field_types = HashMap::new();
    let mut builder = script_builder();
    let stack_bindings = StackBindings::default();

    for field in fields {
        let mut resolve_visiting = HashSet::new();
        let resolved = resolve_expr(field.expr.clone(), base_constants, &mut resolve_visiting)?;

        let mut compile_visiting = HashSet::new();
        let mut stack_depth = 0i64;
        if fixed_type_size_with_constants(&field.type_ref, base_constants).is_some() {
            let encoded = encode_fixed_size_value(&resolved, &field.type_ref)?;
            builder.add_data_with_push_opcode(&encoded)?;
        } else {
            compile_expr(
                &resolved,
                base_constants,
                &stack_bindings,
                &field_types,
                &mut builder,
                options,
                &mut compile_visiting,
                &mut stack_depth,
                script_size,
                base_constants,
            )?;
        }

        field_values.insert(field.name.clone(), resolved);
        field_types.insert(field.name.clone(), field.type_ref.clone());
    }

    Ok((field_values, builder.drain()))
}

fn statement_uses_script_size(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::VariableDefinition { expr, .. } => expr.as_ref().is_some_and(expr_uses_script_size),
        Statement::TupleAssignment { expr, .. } => expr_uses_script_size(expr),
        Statement::FunctionCall { name, args, .. } => {
            name == "validateOutputState"
                || name == super::validate_output_state::VALIDATE_OUTPUT_STATE_INNER
                || name == "validateOutputStateWithTemplate"
                || name == super::validate_output_state::VALIDATE_OUTPUT_STATE_WITH_TEMPLATE_INNER
                || args.iter().any(expr_uses_script_size)
        }
        Statement::FunctionCallAssign { args, .. } => args.iter().any(expr_uses_script_size),
        Statement::StateFunctionCallAssign { name, args, .. } => name == "readInputState" || args.iter().any(expr_uses_script_size),
        Statement::StructDestructure { expr, .. } => expr_uses_script_size(expr),
        Statement::Assign { expr, .. } => expr_uses_script_size(expr),
        Statement::TimeOp { expr, .. } => expr_uses_script_size(expr),
        Statement::Require { expr, .. } => expr_uses_script_size(expr),
        Statement::Block { body, .. } => body.iter().any(statement_uses_script_size),
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
        ExprKind::Append { source, args, .. } => expr_uses_script_size(source) || args.iter().any(expr_uses_script_size),
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            expr_uses_script_size(condition) || expr_uses_script_size(then_expr) || expr_uses_script_size(else_expr)
        }
        ExprKind::Array(values) => values.iter().any(expr_uses_script_size),
        ExprKind::StructLiteral(fields) => fields.iter().any(|field| expr_uses_script_size(&field.expr)),
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

pub(super) fn is_byte_array<'i>(expr: &Expr<'i>) -> bool {
    byte_array_len(expr).is_some()
}

fn byte_array_len<'i>(expr: &Expr<'i>) -> Option<usize> {
    match &expr.kind {
        ExprKind::Array(values) if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => Some(values.len()),
        _ => None,
    }
}

fn infer_expr_type_for_comparison<'i>(expr: &Expr<'i>, constants: &HashMap<String, Expr<'i>>, types: &TypeMap) -> Option<TypeRef> {
    if let ExprKind::Identifier(name) = &expr.kind {
        if let Some(type_ref) = types.get(name) {
            return Some(type_ref.clone());
        }
    }
    if let ExprKind::Call { name, .. } = &expr.kind {
        let known_cast = parse_type_ref(name).is_ok_and(|type_ref| !matches!(type_ref.base, TypeBase::Custom(_)));
        if !known_cast && builtin_types::builtin_return_type(name).is_none() {
            return None;
        }
    }
    infer_debug_expr_value_type(expr, constants, types, &mut HashSet::new()).ok()
}

pub(super) fn array_literal_matches_type_with_env<'i>(
    values: &[Expr<'i>],
    type_ref: &TypeRef,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    let Some(element_type) = type_ref.array_element_type() else {
        return false;
    };

    if let Some(expected_size) = array_size_with_constants(type_ref, constants) {
        if values.len() != expected_size {
            return false;
        }
    }

    let structs = StructRegistry::new();
    let functions = HashMap::new();
    let type_context =
        super::type_check::TypeCheckContext { types, structs: &structs, constants, functions: &functions, contract_fields: &[] };
    values.iter().all(|value| super::type_check::check_expr(value, Some(&element_type), &type_context).is_ok())
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
                .map(|param| FunctionInputAbi { name: param.name.clone(), type_name: param.type_ref.type_name() })
                .collect(),
        })
        .collect()
}

fn array_size(type_ref: &TypeRef) -> Option<usize> {
    match type_ref.array_size()? {
        ArrayDim::Fixed(size) => Some(*size),
        _ => None,
    }
}

fn array_size_with_constants<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
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
        ArrayDim::Dynamic | ArrayDim::Inferred => None,
    }
}

fn fixed_type_size(type_ref: &TypeRef) -> Option<i64> {
    if type_ref.is_array() {
        if let (Some(elem_type), Some(size)) = (type_ref.array_element_type(), array_size(type_ref)) {
            if elem_type.is_byte() {
                return Some(size as i64);
            }
            if elem_type.is_int() {
                return Some((size * 8) as i64);
            }
        }
        return None;
    }

    match type_ref.base {
        TypeBase::Int => Some(8),
        TypeBase::Bool => Some(1),
        TypeBase::Byte => Some(1),
        TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig => type_ref.base.fixed_byte_sequence_len().map(|size| size as i64),
        TypeBase::String => None,
        TypeBase::Tuple(_) | TypeBase::Custom(_) => None,
    }
}

fn fixed_type_size_with_constants<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    if !type_ref.is_array() {
        return fixed_type_size(type_ref).map(|size| size as usize);
    }

    let element_type = type_ref.array_element_type()?;
    let array_len = array_size_with_constants(type_ref, constants)?;
    let element_size = fixed_type_size_with_constants(&element_type, constants)?;
    Some(array_len * element_size)
}

fn fixed_state_payload_len<'i>(type_ref: &TypeRef, contract_constants: &HashMap<String, Expr<'i>>) -> Result<usize, CompilerError> {
    fixed_type_size_with_constants(type_ref, contract_constants)
        .ok_or_else(|| CompilerError::Unsupported(format!("readInputState does not support field type {}", type_ref.type_name())))
}

fn fixed_state_field_payload_len<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    fixed_state_payload_len(&field.type_ref, contract_constants)
}

fn array_element_size(type_ref: &TypeRef) -> Option<i64> {
    type_ref.array_element_type().and_then(|element| fixed_type_size(&element))
}

fn contains_return(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::Return { .. } => true,
        Statement::Block { body, .. } => body.iter().any(contains_return),
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
        Statement::Block { body, .. } => {
            for stmt in body {
                collect_statement_identifier_uses(stmt, uses);
            }
        }
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
        ExprKind::Append { source, args, .. } => {
            collect_expr_identifier_uses(source, uses);
            for arg in args {
                collect_expr_identifier_uses(arg, uses);
            }
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
        ExprKind::StructLiteral(fields) => {
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
            Statement::Assign { name, .. } => {
                assigned.insert(name.clone());
            }
            Statement::Block { body, .. } => {
                collect_assigned_names_into(body, assigned);
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

fn has_inferred_array_size(type_ref: &TypeRef) -> bool {
    matches!(type_ref.array_size(), Some(ArrayDim::Inferred))
}

fn coerce_expr_for_declared_scalar_type<'i>(expr: Expr<'i>, type_ref: &TypeRef) -> Expr<'i> {
    if type_ref.is_byte()
        && let ExprKind::Int(value) = expr.kind
        && (0..=255).contains(&value)
    {
        return Expr::new(ExprKind::Byte(value as u8), expr.span);
    }
    expr
}

fn coerce_rhs_byte_literal_for_comparison<'i>(left_type: Option<&TypeRef>, right: &Expr<'i>) -> Expr<'i> {
    if left_type.is_some_and(TypeRef::is_byte)
        && let ExprKind::Int(value) = right.kind
        && (0..=255).contains(&value)
    {
        return Expr::new(ExprKind::Byte(value as u8), right.span);
    }
    right.clone()
}

fn infer_fixed_array_type_from_initializer<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<TypeRef> {
    if !has_inferred_array_size(declared_type) {
        return None;
    }

    let element_type = declared_type.array_element_type()?;
    let init = initializer?;

    match &init.kind {
        ExprKind::Array(values) => {
            let mut inferred = element_type.clone();
            inferred.array_dims.push(ArrayDim::Fixed(values.len()));
            if array_literal_matches_type_with_env(values, &inferred, types, constants) { Some(inferred) } else { None }
        }
        ExprKind::Identifier(name) => {
            let other_type = types.get(name)?.clone();
            if !other_type.is_array() || !type_refs_equal(&other_type.array_element_type()?, &element_type, constants) {
                return None;
            }
            let size = array_size_with_constants(&other_type, constants)?;
            let mut inferred = element_type;
            inferred.array_dims.push(ArrayDim::Fixed(size));
            Some(inferred)
        }
        _ => None,
    }
}

fn encode_fixed_size_value<'i>(value: &Expr<'i>, type_ref: &TypeRef) -> Result<Vec<u8>, CompilerError> {
    match (&type_ref.base, type_ref.array_dims.as_slice()) {
        (TypeBase::Int, []) => {
            let number = match &value.kind {
                ExprKind::Int(number) | ExprKind::DateLiteral(number) => *number,
                _ => return Err(CompilerError::Unsupported("array literal element type mismatch".to_string())),
            };
            serialize_i64(number, Some(8usize))
                .map(|bytes| bytes.to_vec())
                .map_err(|err| CompilerError::Unsupported(format!("failed to serialize int literal {}: {err}", number)))
        }
        (TypeBase::Bool, []) => {
            let ExprKind::Bool(flag) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(vec![u8::from(*flag)])
        }
        (TypeBase::Byte, []) => {
            let ExprKind::Byte(byte) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(vec![*byte])
        }
        (base @ (TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig), []) => {
            let Some(len) = byte_array_len(value) else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            if Some(len) != base.fixed_byte_sequence_len() {
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
            if let (Some(inner_type), Some(size)) = (type_ref.array_element_type(), array_size(type_ref)) {
                if inner_type.is_byte() {
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
                let element_type = type_ref
                    .array_element_type()
                    .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
                let expected_len = array_size(type_ref)
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

pub(super) fn encode_array_literal<'i>(values: &[Expr<'i>], type_ref: &TypeRef) -> Result<Vec<u8>, CompilerError> {
    let element_type = type_ref
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
    let mut out = Vec::new();
    debug_assert!(fixed_type_size(&element_type).is_some(), "type_check must validate array element type has known size");
    for value in values {
        out.extend(encode_fixed_size_value(value, &element_type)?);
    }
    Ok(out)
}

fn infer_fixed_type_from_literal_expr<'i>(expr: &Expr<'i>) -> Option<TypeRef> {
    match &expr.kind {
        ExprKind::Int(_) | ExprKind::DateLiteral(_) => Some(TypeRef { base: TypeBase::Int, array_dims: Vec::new() }),
        ExprKind::Bool(_) => Some(TypeRef { base: TypeBase::Bool, array_dims: Vec::new() }),
        ExprKind::Byte(_) => Some(TypeRef { base: TypeBase::Byte, array_dims: Vec::new() }),
        ExprKind::Array(values) if is_byte_array(expr) => {
            Some(TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(values.len())] })
        }
        ExprKind::Array(values) => infer_fixed_array_literal_type(values)?.array_element_type(),
        _ => None,
    }
}

fn infer_fixed_array_literal_type<'i>(values: &[Expr<'i>]) -> Option<TypeRef> {
    if values.is_empty() {
        return None;
    }
    let first_type = infer_fixed_type_from_literal_expr(values.first()?)?;
    fixed_type_size(&first_type)?;
    if values.iter().skip(1).all(|value| infer_fixed_type_from_literal_expr(value).as_ref() == Some(&first_type)) {
        let mut array_type = first_type;
        array_type.array_dims.push(ArrayDim::Dynamic);
        Some(array_type)
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
    contract_params: &[ParamAst<'i>],
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &[ConstantAst<'i>],
    contract_field_prefix_len: usize,
    constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    structs: &StructRegistry,
    script_size: Option<i64>,
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<(String, Vec<u8>), CompilerError> {
    debug_recorder.begin_entrypoint(function, contract_fields, structs)?;
    let contract_field_count = contract_fields.len();
    let mut flattened_param_names = Vec::new();
    let mut types = HashMap::new();
    for param in contract_params {
        types.insert(param.name.clone(), param.type_ref.clone());
    }
    for constant in contract_constants {
        types.insert(constant.name.clone(), constant.type_ref.clone());
    }
    for param in &function.params {
        types.insert(param.name.clone(), param.type_ref.clone());
        flattened_param_names.push(param.name.clone());
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
        stack_bindings.insert_binding(&field.name, (contract_field_count - 1 - index) as i64);
    }

    for field in contract_fields {
        types.insert(field.name.clone(), field.type_ref.clone());
    }
    let mut builder = script_builder();
    let mut return_exprs: Vec<Expr> = Vec::new();
    let assigned_names = collect_assigned_names(&function.body);
    let identifier_uses = collect_identifier_uses(&function.body);
    let has_return = function.body.iter().any(contains_return);

    let body_len = function.body.len();
    let mut statement_ctx = CompileStatementContext {
        assigned_names: &assigned_names,
        identifier_uses: &identifier_uses,
        types: &mut types,
        stack_bindings: &mut stack_bindings,
        builder: &mut builder,
        options,
        contract_fields,
        contract_field_prefix_len,
        contract_constants: constants,
        structs,
        script_size,
        debug_recorder,
    };
    for (index, stmt) in function.body.iter().enumerate() {
        if let Statement::Return { exprs, .. } = stmt {
            debug_assert_eq!(index, body_len - 1, "type_check must validate return statements are last");
            for expr in exprs {
                return_exprs.push(expr.clone());
            }
            continue;
        }

        compile_statement(&mut statement_ctx, stmt).map_err(|err| err.with_span(&stmt.span()))?;
    }

    let flattened_returns = if has_return { return_exprs } else { Vec::new() };

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
                constants,
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
    debug_recorder.finish_entrypoint(script.len());
    Ok((function.name.clone(), script))
}

fn compile_statement<'i>(ctx: &mut CompileStatementContext<'_, 'i>, stmt: &Statement<'i>) -> Result<Vec<String>, CompilerError> {
    let statement_start = ctx.builder.script().len();
    ctx.debug_recorder.begin_statement_at(stmt, statement_start, ctx.types, ctx.stack_bindings);

    let added_stack_locals = match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            compile_variable_definition_statement(ctx, type_ref, name, expr.as_ref())
        }
        Statement::Require { expr, .. } => compile_require_statement(ctx, expr),
        Statement::TimeOp { tx_var, expr, .. } => compile_time_branch_statement(ctx, tx_var, expr),
        Statement::Block { body, .. } => compile_block_statement(ctx, body).map(|_| Vec::new()),
        Statement::If { condition, then_branch, else_branch, .. } => {
            compile_if_statement(ctx, stmt, condition, then_branch, else_branch.as_deref()).map(|_| Vec::new())
        }
        Statement::For { .. } => {
            unreachable!("lower_for_loops must remove for statements before codegen")
        }
        Statement::Return { .. } => compile_return_statement(),
        Statement::TupleAssignment { left_type_ref, left_name, right_type_ref, right_name, expr, .. } => {
            compile_tuple_assignment_statement(ctx, left_type_ref, left_name, right_type_ref, right_name, expr)
        }
        Statement::FunctionCall { name, args, .. } => compile_function_call_statement(ctx, name, args),
        Statement::StateFunctionCallAssign { bindings, name, args, .. } => {
            compile_state_function_call_assign_statement(ctx, bindings, name, args)
        }
        Statement::StructDestructure { .. } => compile_struct_destructure_statement(),
        Statement::FunctionCallAssign { bindings, name, args, .. } => {
            compile_function_call_assign_statement(ctx, bindings, name, args)
        }
        Statement::Assign { name, expr, .. } => compile_assign_statement(ctx, name, expr),
        Statement::Console { .. } => compile_console_statement(),
    }?;

    ctx.debug_recorder.finish_statement_at(stmt, ctx.builder.script().len(), ctx.types, ctx.stack_bindings);

    Ok(added_stack_locals)
}

struct CompileStatementContext<'a, 'i> {
    assigned_names: &'a HashSet<String>,
    identifier_uses: &'a HashMap<String, usize>,
    types: &'a mut TypeMap,
    stack_bindings: &'a mut StackBindings,
    builder: &'a mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &'a [ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &'a HashMap<String, Expr<'i>>,
    structs: &'a StructRegistry,
    script_size: Option<i64>,
    debug_recorder: &'a mut DebugRecorder<'i>,
}

impl<'a, 'i> CompileStatementContext<'a, 'i> {
    pub(crate) fn with_types_and_stack_bindings<'b>(
        &'b mut self,
        types: &'b mut TypeMap,
        stack_bindings: &'b mut StackBindings,
    ) -> CompileStatementContext<'b, 'i>
    where
        'a: 'b,
    {
        CompileStatementContext {
            assigned_names: self.assigned_names,
            identifier_uses: self.identifier_uses,
            types,
            stack_bindings,
            builder: self.builder,
            options: self.options,
            contract_fields: self.contract_fields,
            contract_field_prefix_len: self.contract_field_prefix_len,
            contract_constants: self.contract_constants,
            structs: self.structs,
            script_size: self.script_size,
            debug_recorder: self.debug_recorder,
        }
    }
}

fn compile_variable_definition_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    type_ref: &TypeRef,
    name: &str,
    expr: Option<&Expr<'i>>,
) -> Result<Vec<String>, CompilerError> {
    let effective_type = if has_inferred_array_size(type_ref) {
        infer_fixed_array_type_from_initializer(type_ref, expr, ctx.types, ctx.contract_constants).ok_or_else(|| {
            CompilerError::Unsupported(format!(
                "variable '{}' requires an initializer with inferrable size for type {}",
                name,
                type_ref.type_name()
            ))
        })?
    } else {
        type_ref.clone()
    };

    if effective_type.is_array() {
        let initial = array_initializer_expr(expr, &effective_type, ctx.types, ctx.contract_constants)?;
        return compile_runtime_variable_definition(ctx, name, effective_type, initial);
    }

    let expr = expr.cloned().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
    let expr = coerce_expr_for_declared_scalar_type(expr, &effective_type);
    compile_runtime_variable_definition(ctx, name, effective_type, expr)
}

fn array_initializer_expr<'i>(
    expr: Option<&Expr<'i>>,
    type_ref: &TypeRef,
    types: &TypeMap,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    match expr {
        Some(Expr { kind: ExprKind::Identifier(other), .. }) => match types.get(other) {
            Some(other_type) if type_refs_equal(other_type, type_ref, contract_constants) => {
                Ok(Expr::new(ExprKind::Identifier(other.clone()), span::Span::default()))
            }
            Some(_) => Err(CompilerError::Unsupported("array assignment requires identical array types".to_string())),
            None => Err(CompilerError::UndefinedIdentifier(other.clone())),
        },
        Some(expr) => Ok(expr.clone()),
        None => Ok(Expr::new(ExprKind::Array(Vec::new()), span::Span::default())),
    }
}

fn compile_runtime_variable_definition<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    name: &str,
    type_ref: TypeRef,
    expr: Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    ctx.types.insert(name.to_string(), type_ref);
    if ctx.stack_bindings.contains(name) {
        return Err(CompilerError::Unsupported(format!("variable '{}' is already defined", name)));
    }

    let mut stack_depth = 0i64;
    compile_expr(
        &expr,
        ctx.contract_constants,
        ctx.stack_bindings,
        ctx.types,
        ctx.builder,
        ctx.options,
        &mut HashSet::new(),
        &mut stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )?;
    ctx.stack_bindings.push_binding(name);
    Ok(vec![name.to_string()])
}

fn compile_stack_variable_definition<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    name: &str,
    type_ref: TypeRef,
    expr: Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    if ctx.stack_bindings.contains(name) {
        return Err(CompilerError::Unsupported(format!("variable '{}' is already defined", name)));
    }

    ctx.types.insert(name.to_string(), type_ref);
    let mut stack_depth = 0i64;
    compile_expr(
        &expr,
        ctx.contract_constants,
        ctx.stack_bindings,
        ctx.types,
        ctx.builder,
        ctx.options,
        &mut HashSet::new(),
        &mut stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )?;
    ctx.stack_bindings.push_binding(name);
    Ok(vec![name.to_string()])
}

fn compile_require_statement<'i>(ctx: &mut CompileStatementContext<'_, 'i>, expr: &Expr<'i>) -> Result<Vec<String>, CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(
        expr,
        ctx.contract_constants,
        ctx.stack_bindings,
        ctx.types,
        ctx.builder,
        ctx.options,
        &mut HashSet::new(),
        &mut stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )?;
    ctx.builder.add_op(OpVerify)?;
    Ok(Vec::new())
}

fn compile_time_branch_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    tx_var: &TimeVar,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    compile_time_op_statement(
        tx_var,
        expr,
        ctx.stack_bindings,
        ctx.types,
        ctx.builder,
        ctx.options,
        ctx.script_size,
        ctx.contract_constants,
    )
    .map(|_| Vec::new())
}

fn compile_return_statement() -> Result<Vec<String>, CompilerError> {
    unreachable!("type_check must validate return statement placement")
}

fn compile_tuple_assignment_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    left_type_ref: &TypeRef,
    left_name: &str,
    right_type_ref: &TypeRef,
    right_name: &str,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    match &expr.kind {
        ExprKind::Split { source, index, span: split_span, .. } => {
            let left_expr = Expr::new(
                ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left, span: *split_span },
                span::Span::default(),
            );
            let right_expr = Expr::new(
                ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Right, span: *split_span },
                span::Span::default(),
            );
            let mut added = compile_stack_variable_definition(ctx, left_name, left_type_ref.clone(), left_expr)?;
            added.extend(compile_stack_variable_definition(ctx, right_name, right_type_ref.clone(), right_expr)?);
            Ok(added)
        }
        _ => Err(CompilerError::Unsupported("tuple assignment only supports split()".to_string())),
    }
}

fn compile_function_call_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<Vec<String>, CompilerError> {
    if name == super::validate_output_state::VALIDATE_OUTPUT_STATE_INNER {
        return compile_validate_output_state_inner_statement(
            args,
            ctx.contract_constants,
            ctx.stack_bindings,
            ctx.types,
            ctx.builder,
            ctx.options,
            ctx.contract_fields,
            ctx.contract_field_prefix_len,
            ctx.script_size,
            ctx.contract_constants,
        )
        .map(|_| Vec::new());
    }
    if name == super::validate_output_state::VALIDATE_OUTPUT_STATE_WITH_TEMPLATE_INNER {
        return compile_validate_output_state_with_template_inner_statement(
            args,
            ctx.contract_constants,
            ctx.stack_bindings,
            ctx.types,
            ctx.builder,
            ctx.options,
            ctx.script_size,
            ctx.contract_constants,
        )
        .map(|_| Vec::new());
    }
    Err(CompilerError::Unsupported(format!(
        "inline lowering must eliminate internal function calls before compilation, found '{}()'",
        name
    )))
}

fn compile_state_function_call_assign_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<Vec<String>, CompilerError> {
    if name == "readInputState" || name == "readInputStateWithTemplate" {
        return compile_read_input_state_statement(
            ctx,
            bindings,
            name,
            args,
            ctx.contract_fields,
            ctx.contract_field_prefix_len,
            ctx.structs,
        );
    }
    Err(CompilerError::Unsupported(format!(
        "state destructuring assignment is only supported for readInputState()/readInputStateWithTemplate(), got '{}()'",
        name
    )))
}

fn compile_struct_destructure_statement() -> Result<Vec<String>, CompilerError> {
    unreachable!("lower_structs_contract must remove struct destructuring before codegen")
}

fn compile_function_call_assign_statement<'i>(
    _ctx: &mut CompileStatementContext<'_, 'i>,
    _bindings: &[ParamAst<'i>],
    name: &str,
    _args: &[Expr<'i>],
) -> Result<Vec<String>, CompilerError> {
    Err(CompilerError::Unsupported(format!(
        "inline lowering must eliminate function call assignments before compilation, found '{}()'",
        name
    )))
}

fn compile_assign_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    name: &str,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    if let Some(type_ref) = ctx.types.get(name) {
        if !ctx.stack_bindings.contains(name) {
            return Err(CompilerError::Unsupported(format!("assigned variable '{}' must be stack-bound before reassignment", name)));
        }

        let lowered_expr = coerce_expr_for_declared_scalar_type(expr.clone(), type_ref);
        let mut stack_depth = 0i64;
        compile_expr(
            &lowered_expr,
            ctx.contract_constants,
            ctx.stack_bindings,
            ctx.types,
            ctx.builder,
            ctx.options,
            &mut HashSet::new(),
            &mut stack_depth,
            ctx.script_size,
            ctx.contract_constants,
        )?;
        ctx.stack_bindings.emit_update_stack_for_rebinding(name, ctx.builder)?;
        return Ok(Vec::new());
    }

    Err(CompilerError::UndefinedIdentifier(name.to_string()))
}

fn compile_console_statement() -> Result<Vec<String>, CompilerError> {
    Ok(Vec::new())
}

pub(super) fn encoded_field_chunk_size<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let payload_size = fixed_state_field_payload_len(field, contract_constants)?;
    Ok(data_prefix(payload_size).len() + payload_size)
}

fn encoded_type_chunk_size<'i>(type_ref: &TypeRef, contract_constants: &HashMap<String, Expr<'i>>) -> Result<usize, CompilerError> {
    let payload_size = fixed_state_payload_len(type_ref, contract_constants)?;
    Ok(data_prefix(payload_size).len() + payload_size)
}

fn encoded_state_len<'i>(
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    contract_fields.iter().try_fold(0usize, |acc, field| Ok(acc + encoded_field_chunk_size(field, contract_constants)?))
}

fn encoded_state_len_for_layout_field_types<'i>(
    layout_field_types: &[TypeRef],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    layout_field_types.iter().try_fold(0usize, |acc, type_ref| Ok(acc + encoded_type_chunk_size(type_ref, contract_constants)?))
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
    layout_field_types: &[TypeRef],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let total_state_len = encoded_state_len_for_layout_field_types(layout_field_types, contract_constants)?;
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
    let field_payload_len = fixed_state_field_payload_len(field, contract_constants)?;
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

    cast_read_input_state_expr(substr, &field.type_ref)
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
    let field_payload_len = fixed_state_payload_len(field_type, contract_constants)
        .map_err(|_| CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", field_type.type_name())))?;
    let field_payload_offset = binary_expr(
        BinaryOp::Add,
        state_start_offset_expr,
        Expr::int((field_chunk_offset + data_prefix(field_payload_len).len()) as i64),
    );
    let start = binary_expr(BinaryOp::Add, input_sigscript_base_expr(input_idx, script_size_expr), field_payload_offset);
    let end = binary_expr(BinaryOp::Add, start.clone(), Expr::int(field_payload_len as i64));
    let substr = input_sigscript_substr_expr(input_idx, start, end);

    cast_read_input_state_expr(substr, field_type)
}

fn cast_read_input_state_expr<'i>(substr: Expr<'i>, type_ref: &TypeRef) -> Result<Expr<'i>, CompilerError> {
    let type_name = type_ref.type_name();
    match type_ref.base {
        TypeBase::Custom(_) => Err(CompilerError::Unsupported(format!("readInputState does not support field type {type_name}"))),
        _ => Ok(Expr::call(type_name.as_str(), vec![substr])),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_read_input_state_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    structs: &StructRegistry,
) -> Result<Vec<String>, CompilerError> {
    let mut added_stack_locals = Vec::new();
    let mut bindings_by_field: HashMap<&str, &StructBindingAst<'i>> = HashMap::new();
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
                ctx.script_size.ok_or_else(|| CompilerError::Unsupported("readInputState requires this.scriptSize".to_string()))?;
            let total_state_len = encoded_state_len(contract_fields, ctx.contract_constants)?;
            let state_start_offset = contract_field_prefix_len
                .checked_sub(total_state_len)
                .ok_or_else(|| CompilerError::Unsupported("readInputState state offset underflow".to_string()))?;

            let input_idx = args[0].clone();
            let mut field_chunk_offset = 0usize;
            for field in contract_fields {
                let binding = bindings_by_field.get(field.name.as_str()).ok_or_else(|| {
                    CompilerError::Unsupported("readInputState bindings must include all contract fields exactly once".to_string())
                })?;

                if binding.type_ref != field.type_ref {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputState binding '{}' expects {}",
                        binding.name,
                        field.type_ref.type_name()
                    )));
                }

                let binding_expr = read_input_state_binding_expr(
                    &input_idx,
                    field,
                    state_start_offset,
                    field_chunk_offset,
                    script_size_value,
                    ctx.contract_constants,
                )?;
                added_stack_locals.extend(compile_stack_variable_definition(
                    ctx,
                    &binding.name,
                    binding.type_ref.clone(),
                    binding_expr,
                )?);

                field_chunk_offset += encoded_field_chunk_size(field, ctx.contract_constants)?;
            }

            Ok(added_stack_locals)
        }
        "readInputStateWithTemplate" => {
            let Ok([input_idx, template_prefix_len, template_suffix_len, _expected_template_hash]): Result<&[Expr<'i>; 4], _> =
                args.try_into()
            else {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                        .to_string(),
                ));
            };

            let struct_name = struct_name_for_state_bindings(bindings, structs)?;
            let struct_spec =
                structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            if bindings_by_field.len() != struct_spec.fields.len() {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                ));
            }

            let layout_field_types = flattened_struct_field_specs_for_type(
                &TypeRef { base: TypeBase::Custom(struct_name.clone()), array_dims: Vec::new() },
                structs,
            )?;
            compile_read_input_state_with_template_validation(
                args,
                ctx.stack_bindings,
                ctx.types,
                ctx.builder,
                ctx.options,
                &layout_field_types,
                ctx.script_size,
                ctx.contract_constants,
            )?;

            let input_idx = input_idx.clone();
            let state_start_offset_expr = template_prefix_len.clone();
            let script_size_expr = templated_input_script_size_expr(
                template_prefix_len,
                template_suffix_len,
                &layout_field_types,
                ctx.contract_constants,
            )?;
            let mut field_chunk_offset = 0usize;

            for field in &struct_spec.fields {
                let binding = bindings_by_field.get(field.name.as_str()).ok_or_else(|| {
                    CompilerError::Unsupported(
                        "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                    )
                })?;
                debug_assert_eq!(
                    binding.type_ref, field.type_ref,
                    "type_check must validate readInputStateWithTemplate destructuring binding types"
                );

                let binding_expr = read_input_state_field_expr_with_type(
                    &input_idx,
                    &field.type_ref,
                    state_start_offset_expr.clone(),
                    field_chunk_offset,
                    script_size_expr.clone(),
                    ctx.contract_constants,
                    "readInputStateWithTemplate",
                )?;
                added_stack_locals.extend(compile_stack_variable_definition(
                    ctx,
                    &binding.name,
                    binding.type_ref.clone(),
                    binding_expr,
                )?);

                field_chunk_offset += encoded_type_chunk_size(&field.type_ref, ctx.contract_constants)?;
            }

            Ok(added_stack_locals)
        }
        _ => Err(CompilerError::Unsupported(format!(
            "state destructuring assignment is only supported for readInputState()/readInputStateWithTemplate(), got '{}()'",
            name
        ))),
    }
}

fn struct_name_for_state_bindings<'i>(bindings: &[StructBindingAst<'i>], structs: &StructRegistry) -> Result<String, CompilerError> {
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

/// Validation half of `readInputStateWithTemplate(...)`.
///
/// This builtin is stronger than `readInputState(...)`: before decoding any
/// fields, it proves that the claimed foreign redeem script matches both the
/// supplied template hash and the foreign input's actual P2SH `scriptPubKey`.
///
/// Pseudocode:
///   args = (input_idx, template_prefix_len, template_suffix_len, expected_template_hash)
///   require target state layout is a non-empty flattened struct
///
///   script_size = template_prefix_len + encoded_state_len(layout_field_types) + template_suffix_len
///   script_base = input_sigscript_len(input_idx) - script_size
///
///   actual_redeem_script = input_sigscript[script_base .. script_base + script_size]
///   prefix = input_sigscript[script_base .. script_base + template_prefix_len]
///   suffix = input_sigscript[
///       script_base + template_prefix_len + encoded_state_len(layout_field_types)
///       ..
///       script_base + script_size
///   ]
///
///   actual_template = i64le(prefix.length) || prefix || i64le(suffix.length) || suffix
///   require blake2b(actual_template) == expected_template_hash
///
///   expected_input_spk = ScriptPubKeyP2SHFromRedeemScript(actual_redeem_script)
///   require input_script_pubkey(input_idx) == expected_input_spk
///
/// The field-value reads are built separately by
/// `read_input_state_with_template_values(...)` using the same flattened
/// layout and byte offsets.
#[allow(clippy::too_many_arguments)]
fn compile_read_input_state_with_template_validation(
    args: &[Expr<'_>],
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    layout_field_types: &[TypeRef],
    current_script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    let Ok([input_idx, template_prefix_len, template_suffix_len, expected_template_hash]): Result<&[Expr<'_>; 4], _> = args.try_into()
    else {
        return Err(CompilerError::Unsupported(
            "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                .to_string(),
        ));
    };
    if layout_field_types.is_empty() {
        return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
    }

    let script_size_expr =
        templated_input_script_size_expr(template_prefix_len, template_suffix_len, layout_field_types, contract_constants)?;
    let prefix_len_expr = template_prefix_len.clone();
    let suffix_len_expr = template_suffix_len.clone();
    let script_base_expr = input_sigscript_base_expr(input_idx, script_size_expr.clone());
    let prefix_end_expr = binary_expr(BinaryOp::Add, script_base_expr.clone(), prefix_len_expr.clone());
    let script_end_expr = binary_expr(BinaryOp::Add, script_base_expr.clone(), script_size_expr.clone());
    let state_len = encoded_state_len_for_layout_field_types(layout_field_types, contract_constants)?;
    let suffix_start_expr = binary_expr(BinaryOp::Add, prefix_end_expr.clone(), Expr::int(state_len as i64));
    let suffix_end_expr = binary_expr(BinaryOp::Add, suffix_start_expr.clone(), suffix_len_expr.clone());

    let actual_redeem_script_expr = input_sigscript_substr_expr(input_idx, script_base_expr.clone(), script_end_expr);
    let actual_prefix_expr = input_sigscript_substr_expr(input_idx, script_base_expr, prefix_end_expr);
    let actual_suffix_expr = input_sigscript_substr_expr(input_idx, suffix_start_expr, suffix_end_expr);
    let encoded_prefix_len_expr = Expr::call("bytes", vec![prefix_len_expr, Expr::int(8)]);
    let encoded_suffix_len_expr = Expr::call("bytes", vec![suffix_len_expr, Expr::int(8)]);
    let actual_template_expr = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len_expr, actual_prefix_expr),
        binary_expr(BinaryOp::Add, encoded_suffix_len_expr, actual_suffix_expr),
    );
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
        contract_constants,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        current_script_size,
        contract_constants,
    )?;
    compile_expr(
        &expected_input_spk_expr,
        contract_constants,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        current_script_size,
        contract_constants,
    )?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;
    stack_depth = 0;

    compile_expr(
        &actual_template_expr,
        contract_constants,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        current_script_size,
        contract_constants,
    )?;
    compile_expr(
        expected_template_hash,
        contract_constants,
        stack_bindings,
        types,
        builder,
        options,
        &mut HashSet::new(),
        &mut stack_depth,
        current_script_size,
        contract_constants,
    )?;
    builder.add_op(OpSwap)?;
    builder.add_op(OpBlake2b)?;
    builder.add_op(OpEqual)?;
    builder.add_op(OpVerify)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_validate_output_state_inner_statement(
    args: &[Expr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'_>],
    contract_field_prefix_len: usize,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    if args.len() != contract_fields.len() + 1 {
        return Err(CompilerError::Unsupported(format!(
            "{}(output_idx, ..state_fields) expects {} state field argument(s)",
            super::validate_output_state::VALIDATE_OUTPUT_STATE_INNER,
            contract_fields.len()
        )));
    }
    let output_idx = args
        .first()
        .ok_or_else(|| CompilerError::Unsupported("validateOutputState(output_idx, new_state) expects 2 arguments".to_string()))?;
    let state_fields = contract_fields
        .iter()
        .zip(args.iter().skip(1))
        .map(|(field, expr)| StateFieldExpr {
            name: field.name.clone(),
            expr: expr.clone(),
            span: expr.span,
            name_span: span::Span::default(),
        })
        .collect::<Vec<_>>();
    if contract_fields.is_empty() {
        return Err(CompilerError::Unsupported("validateOutputState requires contract fields".to_string()));
    }

    let mut stack_depth = compile_encoded_state_object(
        &state_fields,
        constants,
        stack_bindings,
        types,
        builder,
        options,
        script_size,
        contract_constants,
        "validateOutputState",
    )?;

    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    let state_start_offset = contract_field_prefix_len.checked_sub(total_state_len).ok_or_else(|| {
        eprintln!(
            "STATE OFFSET UNDERFLOW prefix={} total={} fields={:?}",
            contract_field_prefix_len,
            total_state_len,
            contract_fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
        );
        CompilerError::Unsupported("validateOutputState state offset underflow".to_string())
    })?;

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
    builder.add_data_with_push_opcode(&[0x00, 0x00])?;
    stack_depth += 1;
    builder.add_data_with_push_opcode(&[OpBlake2b])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_data_with_push_opcode(&[0x20])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_op(OpSwap)?;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_data_with_push_opcode(&[OpEqual])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;

    compile_expr(
        output_idx,
        constants,
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

fn compile_validate_output_state_with_template_inner_statement(
    args: &[Expr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    if args.len() < 5 {
        return Err(CompilerError::Unsupported(
            "__validateOutputStateWithTemplateInner(output_idx, ..state_fields, template_prefix, template_suffix, expected_template_hash) expects at least 5 arguments"
                .to_string(),
        ));
    }
    let output_idx = &args[0];
    let state_fields = &args[1..args.len() - 3];
    let template_prefix = &args[args.len() - 3];
    let template_suffix = &args[args.len() - 2];
    let expected_template_hash = &args[args.len() - 1];
    if state_fields.is_empty() {
        return Err(CompilerError::Unsupported("validateOutputStateWithTemplate requires contract fields".to_string()));
    }

    let mut stack_depth = 0i64;

    let encoded_prefix_len = Expr::call("bytes", vec![Expr::call("length", vec![template_prefix.clone()]), Expr::int(8)]);
    let encoded_suffix_len = Expr::call("bytes", vec![Expr::call("length", vec![template_suffix.clone()]), Expr::int(8)]);
    let template_preimage = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len, template_prefix.clone()),
        binary_expr(BinaryOp::Add, encoded_suffix_len, template_suffix.clone()),
    );
    compile_expr(
        &template_preimage,
        constants,
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
        constants,
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
    stack_depth = compile_encoded_flat_state_fields(
        state_fields,
        constants,
        stack_bindings,
        types,
        builder,
        options,
        script_size,
        contract_constants,
        "validateOutputStateWithTemplate",
    )?;

    compile_expr(
        template_prefix,
        constants,
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
        constants,
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
    builder.add_data_with_push_opcode(&[0x00, 0x00])?;
    stack_depth += 1;
    builder.add_data_with_push_opcode(&[OpBlake2b])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_data_with_push_opcode(&[0x20])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_op(OpSwap)?;
    builder.add_op(OpCat)?;
    stack_depth -= 1;
    builder.add_data_with_push_opcode(&[OpEqual])?;
    stack_depth += 1;
    builder.add_op(OpCat)?;
    stack_depth -= 1;

    compile_expr(
        output_idx,
        constants,
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

fn compile_encoded_state_object(
    state_entries: &[StateFieldExpr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    let mut stack_depth = 0i64;
    for entry in state_entries {
        let new_value = &entry.expr;
        let type_ref = infer_debug_expr_value_type(new_value, constants, types, &mut HashSet::new())?;
        let field_size = fixed_state_payload_len(&type_ref, contract_constants)
            .map_err(|_| CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", type_ref.type_name())))?;

        if type_ref.is_int() || type_ref.is_bool() {
            compile_expr(
                new_value,
                constants,
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
                constants,
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
        builder.add_data_with_push_opcode(&prefix)?;
        stack_depth += 1;
        builder.add_op(OpSwap)?;
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    for _ in 1..state_entries.len() {
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    Ok(stack_depth)
}

fn compile_encoded_flat_state_fields(
    state_fields: &[Expr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    let mut stack_depth = 0i64;
    for new_value in state_fields {
        let type_ref = infer_debug_expr_value_type(new_value, constants, types, &mut HashSet::new())?;
        let field_size = fixed_state_payload_len(&type_ref, contract_constants)
            .map_err(|_| CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", type_ref.type_name())))?;

        if type_ref.is_int() || type_ref.is_bool() {
            compile_expr(
                new_value,
                constants,
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
                constants,
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
        builder.add_data_with_push_opcode(&prefix)?;
        stack_depth += 1;
        builder.add_op(OpSwap)?;
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }

    for _ in 1..state_fields.len() {
        builder.add_op(OpCat)?;
        stack_depth -= 1;
    }
    Ok(stack_depth)
}

fn compile_if_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    stmt: &Statement<'i>,
    condition: &Expr<'i>,
    then_branch: &[Statement<'i>],
    else_branch: Option<&[Statement<'i>]>,
) -> Result<(), CompilerError> {
    let condition = condition.clone();
    let mut stack_depth = 0i64;
    compile_expr(
        &condition,
        ctx.contract_constants,
        ctx.stack_bindings,
        ctx.types,
        ctx.builder,
        ctx.options,
        &mut HashSet::new(),
        &mut stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )?;
    ctx.builder.add_op(OpIf)?;
    ctx.debug_recorder.record_current_statement_source_step_at(stmt, ctx.builder.script().len(), ctx.types, ctx.stack_bindings);

    let original_stack_bindings = (*ctx.stack_bindings).clone();

    let mut then_types = (*ctx.types).clone();
    let mut then_stack_bindings = original_stack_bindings.clone();
    compile_block(&mut ctx.with_types_and_stack_bindings(&mut then_types, &mut then_stack_bindings), then_branch, true)?;

    if let Some(else_branch) = else_branch {
        ctx.builder.add_op(OpElse)?;
        let mut else_types = (*ctx.types).clone();
        let mut else_stack_bindings = original_stack_bindings.clone();
        compile_block(&mut ctx.with_types_and_stack_bindings(&mut else_types, &mut else_stack_bindings), else_branch, true)?;
        else_stack_bindings.emit_stack_reordering(&then_stack_bindings, ctx.builder)?;
        *ctx.stack_bindings = then_stack_bindings;
    } else {
        then_stack_bindings.emit_stack_reordering(&original_stack_bindings, ctx.builder)?;
        *ctx.stack_bindings = original_stack_bindings;
    }

    ctx.builder.add_op(OpEndIf)?;
    Ok(())
}

fn compile_time_op_statement<'i>(
    tx_var: &TimeVar,
    expr: &Expr<'i>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let mut stack_depth = 0i64;
    compile_expr(
        expr,
        contract_constants,
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

fn compile_block_statement<'i>(ctx: &mut CompileStatementContext<'_, 'i>, body: &[Statement<'i>]) -> Result<(), CompilerError> {
    compile_block(ctx, body, true)
}

fn compile_block<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    statements: &[Statement<'i>],
    scoped_stack_locals: bool,
) -> Result<(), CompilerError> {
    let mut added_stack_locals = Vec::new();
    for stmt in statements {
        let added = compile_statement(ctx, stmt).map_err(|err| err.with_span(&stmt.span()))?;
        added_stack_locals.extend(added);
    }

    if scoped_stack_locals && !added_stack_locals.is_empty() {
        ctx.stack_bindings.emit_drop_bindings(&added_stack_locals, ctx.builder)?;
        for name in &added_stack_locals {
            ctx.types.remove(name);
        }
    }

    Ok(())
}

pub(crate) fn eval_const_int<'i>(expr: &Expr<'i>, constants: &HashMap<String, Expr<'i>>) -> Result<i64, CompilerError> {
    match &expr.kind {
        ExprKind::Int(value) => Ok(*value),
        ExprKind::DateLiteral(value) => Ok(*value),
        ExprKind::Identifier(name) => match constants.get(name) {
            Some(value) => eval_const_int(value, constants),
            None => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
        },
        ExprKind::Unary { op: UnaryOp::Neg, expr } => {
            let value = eval_const_int(expr, constants)?;
            value.checked_neg().ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: -({value})")))
        }
        ExprKind::Unary { .. } => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
        ExprKind::Binary { op, left, right } => {
            let lhs = eval_const_int(left, constants)?;
            let rhs = eval_const_int(right, constants)?;
            match op {
                BinaryOp::Add => lhs
                    .checked_add(rhs)
                    .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} + {rhs}"))),
                BinaryOp::Sub => lhs
                    .checked_sub(rhs)
                    .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} - {rhs}"))),
                BinaryOp::Mul => lhs
                    .checked_mul(rhs)
                    .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} * {rhs}"))),
                BinaryOp::Div => {
                    if rhs == 0 {
                        return Err(CompilerError::InvalidLiteral("division by zero in for loop bounds".to_string()));
                    }
                    lhs.checked_div(rhs)
                        .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} / {rhs}")))
                }
                BinaryOp::Mod => {
                    if rhs == 0 {
                        return Err(CompilerError::InvalidLiteral("modulo by zero in for loop bounds".to_string()));
                    }
                    lhs.checked_rem(rhs)
                        .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} % {rhs}")))
                }
                _ => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
            }
        }
        _ => Err(CompilerError::Unsupported("for loop bounds must be constant integers".to_string())),
    }
}

pub(crate) fn resolve_expr<'i>(
    expr: Expr<'i>,
    constants: &HashMap<String, Expr<'i>>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    let Expr { kind, span } = expr;
    match kind {
        ExprKind::Identifier(name) => {
            if let Some(value) = constants.get(&name) {
                if matches!(&value.kind, ExprKind::Identifier(inner) if inner == &name) {
                    return Ok(Expr::new(ExprKind::Identifier(name), span));
                }
                if !visiting.insert(name.clone()) {
                    return Err(CompilerError::CyclicIdentifier(name));
                }
                let resolved = resolve_expr(value.clone(), constants, visiting)?;
                visiting.remove(&name);
                Ok(resolved)
            } else {
                Ok(Expr::new(ExprKind::Identifier(name), span))
            }
        }
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op, expr: Box::new(resolve_expr(*expr, constants, visiting)?) }, span))
        }
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op,
                left: Box::new(resolve_expr(*left, constants, visiting)?),
                right: Box::new(resolve_expr(*right, constants, visiting)?),
            },
            span,
        )),
        ExprKind::Append { source, args, span: append_span } => Ok(Expr::new(
            ExprKind::Append {
                source: Box::new(resolve_expr(*source, constants, visiting)?),
                args: args.into_iter().map(|arg| resolve_expr(arg, constants, visiting)).collect::<Result<Vec<_>, _>>()?,
                span: append_span,
            },
            span,
        )),
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(resolve_expr(*condition, constants, visiting)?),
                then_expr: Box::new(resolve_expr(*then_expr, constants, visiting)?),
                else_expr: Box::new(resolve_expr(*else_expr, constants, visiting)?),
            },
            span,
        )),
        ExprKind::Array(values) => {
            let mut resolved = Vec::with_capacity(values.len());
            for value in values {
                resolved.push(resolve_expr(value, constants, visiting)?);
            }
            Ok(Expr::new(ExprKind::Array(resolved), span))
        }
        ExprKind::StructLiteral(fields) => {
            let mut resolved_fields = Vec::with_capacity(fields.len());
            for field in fields {
                resolved_fields.push(StateFieldExpr {
                    name: field.name,
                    expr: resolve_expr(field.expr, constants, visiting)?,
                    span: field.span,
                    name_span: field.name_span,
                });
            }
            Ok(Expr::new(ExprKind::StructLiteral(resolved_fields), span))
        }
        ExprKind::FieldAccess { source, field, field_span } => Ok(Expr::new(
            ExprKind::FieldAccess { source: Box::new(resolve_expr(*source, constants, visiting)?), field, field_span },
            span,
        )),
        ExprKind::Call { name, args, name_span } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr(arg, constants, visiting)?);
            }
            Ok(Expr::new(ExprKind::Call { name, args: resolved, name_span }, span))
        }
        ExprKind::New { name, args, name_span } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_expr(arg, constants, visiting)?);
            }
            Ok(Expr::new(ExprKind::New { name, args: resolved, name_span }, span))
        }
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(resolve_expr(*source, constants, visiting)?),
                index: Box::new(resolve_expr(*index, constants, visiting)?),
                part,
                span: split_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(resolve_expr(*source, constants, visiting)?),
                index: Box::new(resolve_expr(*index, constants, visiting)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::Introspection { kind, index: Box::new(resolve_expr(*index, constants, visiting)?), field_span },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Ok(Expr::new(
            ExprKind::UnarySuffix { source: Box::new(resolve_expr(*source, constants, visiting)?), kind, span: suffix_span },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(resolve_expr(*source, constants, visiting)?),
                start: Box::new(resolve_expr(*start, constants, visiting)?),
                end: Box::new(resolve_expr(*end, constants, visiting)?),
                span: slice_span,
            },
            span,
        )),
        other => Ok(Expr::new(other, span)),
    }
}

struct CompilationScope<'a, 'i> {
    constants: &'a HashMap<String, Expr<'i>>,
    stack_bindings: &'a StackBindings,
    types: &'a TypeMap,
}

pub(super) fn compile_expr<'i>(
    expr: &Expr<'i>,
    constants: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let scope = CompilationScope { constants, stack_bindings, types };
    let mut ctx = CompileExprContext { scope, builder, options, visiting, stack_depth, script_size, contract_constants };
    match &expr.kind {
        ExprKind::Int(value) => compile_int_expr(&mut ctx, *value),
        ExprKind::Bool(value) => compile_bool_expr(&mut ctx, *value),
        ExprKind::Byte(byte) => compile_byte_expr(&mut ctx, *byte),
        ExprKind::Array(values) => compile_array_expr(&mut ctx, values),
        ExprKind::StructLiteral(_) => compile_state_object_expr(),
        ExprKind::FieldAccess { .. } => compile_field_access_expr(),
        ExprKind::String(value) => compile_string_expr(&mut ctx, value),
        ExprKind::Identifier(name) => compile_identifier_expr(&mut ctx, name),
        ExprKind::IfElse { condition, then_expr, else_expr } => compile_if_else_expr(&mut ctx, condition, then_expr, else_expr),
        ExprKind::Call { name, args, .. } => compile_call_branch_expr(&mut ctx, name, args),
        ExprKind::New { name, args, .. } => compile_new_expr(&mut ctx, name, args),
        ExprKind::Unary { op, expr } => compile_unary_expr(&mut ctx, *op, expr),
        ExprKind::Binary { op, left, right } => compile_binary_expr(&mut ctx, *op, left, right),
        ExprKind::Append { source, args, .. } => {
            let appended = Expr::new(ExprKind::Array(args.clone()), span::Span::default());
            compile_binary_expr(&mut ctx, BinaryOp::Add, source, &appended)
        }
        ExprKind::Split { source, index, part, .. } => compile_split_expr(&mut ctx, source, index, *part),
        ExprKind::UnarySuffix { source, kind, .. } => compile_unary_suffix_expr(&mut ctx, source, *kind),
        ExprKind::ArrayIndex { source, index } => compile_array_index_expr(&mut ctx, source, index),
        ExprKind::Slice { source, start, end, .. } => compile_slice_expr(&mut ctx, source, start, end),
        ExprKind::Nullary(op) => compile_nullary_expr(&mut ctx, *op),
        ExprKind::Introspection { kind, index, .. } => compile_introspection_expr(&mut ctx, *kind, index),
        ExprKind::DateLiteral(value) => compile_date_literal_expr(&mut ctx, *value),
        ExprKind::NumberWithUnit { .. } => compile_number_with_unit_expr(),
    }
}

struct CompileExprContext<'a, 'i> {
    scope: CompilationScope<'a, 'i>,
    builder: &'a mut ScriptBuilder,
    options: CompileOptions,
    visiting: &'a mut HashSet<String>,
    stack_depth: &'a mut i64,
    script_size: Option<i64>,
    contract_constants: &'a HashMap<String, Expr<'i>>,
}

fn compile_expr_with_context<'i>(ctx: &mut CompileExprContext<'_, 'i>, expr: &Expr<'i>) -> Result<(), CompilerError> {
    compile_expr(
        expr,
        ctx.scope.constants,
        ctx.scope.stack_bindings,
        ctx.scope.types,
        ctx.builder,
        ctx.options,
        ctx.visiting,
        ctx.stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )
}

fn compile_int_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, value: i64) -> Result<(), CompilerError> {
    ctx.builder.add_i64(value)?;
    *ctx.stack_depth += 1;
    Ok(())
}

fn compile_bool_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, value: bool) -> Result<(), CompilerError> {
    ctx.builder.add_op(if value { OpTrue } else { OpFalse })?;
    *ctx.stack_depth += 1;
    Ok(())
}

fn compile_byte_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, byte: u8) -> Result<(), CompilerError> {
    ctx.builder.add_data_with_push_opcode(&[byte])?;
    *ctx.stack_depth += 1;
    Ok(())
}

fn compile_array_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, values: &[Expr<'i>]) -> Result<(), CompilerError> {
    if values.is_empty() {
        ctx.builder.add_data_with_push_opcode(&[])?;
        *ctx.stack_depth += 1;
        return Ok(());
    }
    let inferred_type = infer_fixed_array_runtime_type(values, ctx.scope.constants, ctx.scope.types)
        .ok_or_else(|| CompilerError::Unsupported("array literal type cannot be inferred".to_string()))?;
    if let Ok(encoded) = encode_array_literal(values, &inferred_type) {
        ctx.builder.add_data_with_push_opcode(&encoded)?;
        *ctx.stack_depth += 1;
        return Ok(());
    }
    compile_runtime_array_literal(ctx, values, &inferred_type)
}

fn compile_runtime_array_literal<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    values: &[Expr<'i>],
    array_type: &TypeRef,
) -> Result<(), CompilerError> {
    let element_type = array_type
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported("array literal type cannot be inferred".to_string()))?;
    for (index, value) in values.iter().enumerate() {
        compile_array_literal_element(ctx, value, &element_type)?;
        if index > 0 {
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
        }
    }
    Ok(())
}

fn compile_array_literal_element<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    value: &Expr<'i>,
    element_type: &TypeRef,
) -> Result<(), CompilerError> {
    match (&element_type.base, element_type.array_dims.as_slice()) {
        (TypeBase::Int, []) => {
            compile_expr_with_context(ctx, value)?;
            ctx.builder.add_i64(8)?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpNum2Bin)?;
            *ctx.stack_depth -= 1;
            Ok(())
        }
        (TypeBase::Bool, []) => {
            let cast_expr = Expr::new(
                ExprKind::Call { name: "byte[1]".to_string(), args: vec![value.clone()], name_span: span::Span::default() },
                span::Span::default(),
            );
            compile_expr_with_context(ctx, &cast_expr)
        }
        (TypeBase::Byte, []) => compile_expr_with_context(ctx, value),
        _ => compile_expr_with_context(ctx, value),
    }
}

fn infer_fixed_array_runtime_type<'i>(values: &[Expr<'i>], constants: &HashMap<String, Expr<'i>>, types: &TypeMap) -> Option<TypeRef> {
    infer_fixed_array_literal_type(values).or_else(|| {
        let first_type = infer_debug_expr_value_type(values.first()?, constants, types, &mut HashSet::new()).ok()?;
        fixed_type_size(&first_type)?;
        if values
            .iter()
            .skip(1)
            .all(|value| infer_debug_expr_value_type(value, constants, types, &mut HashSet::new()).ok().as_ref() == Some(&first_type))
        {
            let mut array_type = first_type;
            array_type.array_dims.push(ArrayDim::Dynamic);
            Some(array_type)
        } else {
            None
        }
    })
}

fn compile_state_object_expr() -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported("state object literals are only supported in validateOutputState-style builtins".to_string()))
}

fn compile_field_access_expr() -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported("struct field access should be lowered before compilation".to_string()))
}

fn compile_string_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, value: &str) -> Result<(), CompilerError> {
    ctx.builder.add_data_with_push_opcode(value.as_bytes())?;
    *ctx.stack_depth += 1;
    Ok(())
}

fn compile_identifier_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, name: &str) -> Result<(), CompilerError> {
    if !ctx.visiting.insert(name.to_string()) {
        return Err(CompilerError::CyclicIdentifier(name.to_string()));
    }
    if ctx.scope.stack_bindings.emit_copy_binding_to_top(name, ctx.stack_depth, ctx.builder)? {
        ctx.visiting.remove(name);
        return Ok(());
    }
    if let Some(resolved_expr) = ctx.scope.constants.get(name) {
        compile_expr_with_context(ctx, resolved_expr)?;
        ctx.visiting.remove(name);
        return Ok(());
    }
    ctx.visiting.remove(name);
    Err(CompilerError::UndefinedIdentifier(name.to_string()))
}

fn compile_if_else_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    condition: &Expr<'i>,
    then_expr: &Expr<'i>,
    else_expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    compile_expr_with_context(ctx, condition)?;
    ctx.builder.add_op(OpIf)?;
    *ctx.stack_depth -= 1;
    let depth_before = *ctx.stack_depth;
    compile_expr_with_context(ctx, then_expr)?;
    ctx.builder.add_op(OpElse)?;
    *ctx.stack_depth = depth_before;
    compile_expr_with_context(ctx, else_expr)?;
    ctx.builder.add_op(OpEndIf)?;
    *ctx.stack_depth = depth_before + 1;
    Ok(())
}

fn compile_call_branch_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    compile_call_expr(
        name,
        args,
        &ctx.scope,
        ctx.builder,
        ctx.options,
        ctx.visiting,
        ctx.stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )
}

fn compile_new_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    match name {
        "ScriptPubKeyP2PK" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("ScriptPubKeyP2PK expects a single pubkey argument".to_string()));
            }
            compile_expr_with_context(ctx, &args[0])?;
            ctx.builder.add_data_with_push_opcode(&[0x00, 0x00, OpData32])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpSwap)?;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_data_with_push_opcode(&[OpCheckSig])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            Ok(())
        }
        "ScriptPubKeyP2SH" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("ScriptPubKeyP2SH expects a single bytes32 argument".to_string()));
            }
            compile_expr_with_context(ctx, &args[0])?;
            ctx.builder.add_data_with_push_opcode(&[0x00, 0x00])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_data_with_push_opcode(&[OpBlake2b])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_data_with_push_opcode(&[0x20])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_op(OpSwap)?;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_data_with_push_opcode(&[OpEqual])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            Ok(())
        }
        "ScriptPubKeyP2SHFromRedeemScript" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported(
                    "ScriptPubKeyP2SHFromRedeemScript expects a single redeem_script argument".to_string(),
                ));
            }
            compile_expr_with_context(ctx, &args[0])?;
            ctx.builder.add_op(OpBlake2b)?;
            ctx.builder.add_data_with_push_opcode(&[0x00, 0x00])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_data_with_push_opcode(&[OpBlake2b])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_data_with_push_opcode(&[0x20])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_op(OpSwap)?;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            ctx.builder.add_data_with_push_opcode(&[OpEqual])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpCat)?;
            *ctx.stack_depth -= 1;
            Ok(())
        }
        other => Err(CompilerError::Unsupported(format!("unknown constructor: {other}"))),
    }
}

fn compile_unary_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, op: UnaryOp, expr: &Expr<'i>) -> Result<(), CompilerError> {
    compile_expr_with_context(ctx, expr)?;
    match op {
        UnaryOp::Not => ctx.builder.add_op(OpNot)?,
        UnaryOp::Neg => ctx.builder.add_op(OpNegate)?,
    };
    Ok(())
}

fn compile_binary_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    op: BinaryOp,
    left: &Expr<'i>,
    right: &Expr<'i>,
) -> Result<(), CompilerError> {
    let left_cmp_type = infer_expr_type_for_comparison(left, ctx.scope.constants, ctx.scope.types);
    let coerced_right = if matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge) {
        coerce_rhs_byte_literal_for_comparison(left_cmp_type.as_ref(), right)
    } else {
        right.clone()
    };
    let left_value_type = infer_debug_expr_value_type(left, ctx.scope.constants, ctx.scope.types, &mut HashSet::new()).ok();
    let right_value_type = infer_debug_expr_value_type(&coerced_right, ctx.scope.constants, ctx.scope.types, &mut HashSet::new()).ok();
    debug_assert!(
        !matches!(op, BinaryOp::Add)
            || (!left_value_type.as_ref().is_some_and(TypeRef::is_byte) && !right_value_type.as_ref().is_some_and(TypeRef::is_byte)),
        "type_check must reject byte addition"
    );
    let bool_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne)
        && left_value_type.as_ref().is_some_and(TypeRef::is_bool)
        && right_value_type.as_ref().is_some_and(TypeRef::is_bool);
    let bytes_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne)
        && (expr_is_bytes(left, ctx.scope.types) || expr_is_bytes(&coerced_right, ctx.scope.types));
    let bytes_add = matches!(op, BinaryOp::Add) && (expr_is_bytes(left, ctx.scope.types) || expr_is_bytes(right, ctx.scope.types));
    if bytes_add {
        compile_concat_operand(
            left,
            ctx.scope.constants,
            ctx.scope.stack_bindings,
            ctx.scope.types,
            ctx.builder,
            ctx.options,
            ctx.visiting,
            ctx.stack_depth,
            ctx.script_size,
            ctx.contract_constants,
        )?;
        compile_concat_operand(
            right,
            ctx.scope.constants,
            ctx.scope.stack_bindings,
            ctx.scope.types,
            ctx.builder,
            ctx.options,
            ctx.visiting,
            ctx.stack_depth,
            ctx.script_size,
            ctx.contract_constants,
        )?;
    } else {
        compile_expr_with_context(ctx, left)?;
        compile_expr_with_context(ctx, &coerced_right)?;
    }

    if bool_eq {
        // Normalize operands to 0 or 1, so that we can use OpNumEqual and OpNumNotEqual for both equality and inequality.
        ctx.builder.add_op(OpNot)?;
        ctx.builder.add_op(OpNot)?;
        ctx.builder.add_op(OpSwap)?;
        ctx.builder.add_op(OpNot)?;
        ctx.builder.add_op(OpNot)?;
    }

    match op {
        BinaryOp::Or => {
            ctx.builder.add_op(OpBoolOr)?;
        }
        BinaryOp::And => {
            ctx.builder.add_op(OpBoolAnd)?;
        }
        BinaryOp::BitOr => {
            ctx.builder.add_op(OpOr)?;
        }
        BinaryOp::BitXor => {
            ctx.builder.add_op(OpXor)?;
        }
        BinaryOp::BitAnd => {
            ctx.builder.add_op(OpAnd)?;
        }
        BinaryOp::Eq => {
            ctx.builder.add_op(if bytes_eq { OpEqual } else { OpNumEqual })?;
        }
        BinaryOp::Ne => {
            if bytes_eq {
                ctx.builder.add_op(OpEqual)?;
                ctx.builder.add_op(OpNot)?;
            } else {
                ctx.builder.add_op(OpNumNotEqual)?;
            }
        }
        BinaryOp::Lt => {
            ctx.builder.add_op(OpLessThan)?;
        }
        BinaryOp::Le => {
            ctx.builder.add_op(OpLessThanOrEqual)?;
        }
        BinaryOp::Gt => {
            ctx.builder.add_op(OpGreaterThan)?;
        }
        BinaryOp::Ge => {
            ctx.builder.add_op(OpGreaterThanOrEqual)?;
        }
        BinaryOp::Add => {
            ctx.builder.add_op(if bytes_add { OpCat } else { OpAdd })?;
        }
        BinaryOp::Sub => {
            ctx.builder.add_op(OpSub)?;
        }
        BinaryOp::Mul => {
            ctx.builder.add_op(OpMul)?;
        }
        BinaryOp::Div => {
            ctx.builder.add_op(OpDiv)?;
        }
        BinaryOp::Mod => {
            ctx.builder.add_op(OpMod)?;
        }
    }
    *ctx.stack_depth -= 1;
    Ok(())
}

fn compile_split_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    source: &Expr<'i>,
    index: &Expr<'i>,
    part: SplitPart,
) -> Result<(), CompilerError> {
    compile_split_part(
        source,
        index,
        part,
        ctx.scope.stack_bindings,
        ctx.scope.types,
        ctx.builder,
        ctx.options,
        ctx.visiting,
        ctx.stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )
}

fn compile_unary_suffix_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    source: &Expr<'i>,
    kind: UnarySuffixKind,
) -> Result<(), CompilerError> {
    match kind {
        UnarySuffixKind::Length => compile_length_expr(
            source,
            ctx.scope.stack_bindings,
            ctx.scope.types,
            ctx.builder,
            ctx.options,
            ctx.visiting,
            ctx.stack_depth,
            ctx.script_size,
            ctx.contract_constants,
        ),
        UnarySuffixKind::Reverse => Err(CompilerError::Unsupported("reverse() is not supported".to_string())),
    }
}

fn compile_array_index_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    source: &Expr<'i>,
    index: &Expr<'i>,
) -> Result<(), CompilerError> {
    let resolved_source = match source {
        Expr { kind: ExprKind::Identifier(_), .. } => source.clone(),
        _ => resolve_expr(source.clone(), ctx.scope.constants, ctx.visiting)?,
    };
    let source_type = infer_debug_expr_value_type(&resolved_source, ctx.scope.constants, ctx.scope.types, &mut HashSet::new())?;
    let element_type = source_type
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported(format!("array index requires array source, got {}", source_type.type_name())))?;
    let element_size = fixed_type_size(&element_type)
        .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
    compile_expr_with_context(ctx, &resolved_source)?;
    compile_expr_with_context(ctx, index)?;
    ctx.builder.add_i64(element_size)?;
    *ctx.stack_depth += 1;
    ctx.builder.add_op(OpMul)?;
    *ctx.stack_depth -= 1;
    ctx.builder.add_op(OpDup)?;
    *ctx.stack_depth += 1;
    ctx.builder.add_i64(element_size)?;
    *ctx.stack_depth += 1;
    ctx.builder.add_op(OpAdd)?;
    *ctx.stack_depth -= 1;
    ctx.builder.add_op(OpSubstr)?;
    *ctx.stack_depth -= 2;
    Ok(())
}

fn compile_slice_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    source: &Expr<'i>,
    start: &Expr<'i>,
    end: &Expr<'i>,
) -> Result<(), CompilerError> {
    compile_expr_with_context(ctx, source)?;
    compile_expr_with_context(ctx, start)?;
    compile_expr_with_context(ctx, end)?;
    ctx.builder.add_op(OpSubstr)?;
    *ctx.stack_depth -= 2;
    Ok(())
}

fn compile_nullary_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, op: NullaryOp) -> Result<(), CompilerError> {
    match op {
        NullaryOp::ActiveInputIndex => {
            ctx.builder.add_op(OpTxInputIndex)?;
        }
        NullaryOp::ActiveScriptPubKey => {
            ctx.builder.add_op(OpTxInputIndex)?;
            ctx.builder.add_op(OpTxInputSpk)?;
        }
        NullaryOp::ThisScriptSize => {
            let size = ctx
                .script_size
                .ok_or_else(|| CompilerError::Unsupported("this.scriptSize is only available at compile time".to_string()))?;
            ctx.builder.add_i64(size)?;
        }
        NullaryOp::ThisScriptSizeDataPrefix => {
            let size = ctx.script_size.ok_or_else(|| {
                CompilerError::Unsupported("this.scriptSizeDataPrefix is only available at compile time".to_string())
            })?;
            let size: usize = size.try_into().map_err(|_| {
                CompilerError::Unsupported("this.scriptSizeDataPrefix requires a non-negative script size".to_string())
            })?;
            let prefix = data_prefix(size);
            ctx.builder.add_data_with_push_opcode(&prefix)?;
        }
        NullaryOp::TxInputsLength => {
            ctx.builder.add_op(OpTxInputCount)?;
        }
        NullaryOp::TxOutputsLength => {
            ctx.builder.add_op(OpTxOutputCount)?;
        }
        NullaryOp::TxVersion => {
            ctx.builder.add_op(OpTxVersion)?;
        }
        NullaryOp::TxLockTime => {
            ctx.builder.add_op(OpTxLockTime)?;
        }
    }
    *ctx.stack_depth += 1;
    Ok(())
}

fn compile_introspection_expr<'i>(
    ctx: &mut CompileExprContext<'_, 'i>,
    kind: IntrospectionKind,
    index: &Expr<'i>,
) -> Result<(), CompilerError> {
    compile_expr_with_context(ctx, index)?;
    match kind {
        IntrospectionKind::InputValue => {
            ctx.builder.add_op(OpTxInputAmount)?;
        }
        IntrospectionKind::InputScriptPubKey => {
            ctx.builder.add_op(OpTxInputSpk)?;
        }
        IntrospectionKind::InputSigScript => {
            ctx.builder.add_op(OpDup)?;
            ctx.builder.add_op(OpTxInputScriptSigLen)?;
            ctx.builder.add_i64(0)?;
            ctx.builder.add_op(OpSwap)?;
            ctx.builder.add_op(OpTxInputScriptSigSubstr)?;
        }
        IntrospectionKind::InputOutpointTransactionHash => {
            ctx.builder.add_op(OpOutpointTxId)?;
        }
        IntrospectionKind::InputOutpointIndex => {
            ctx.builder.add_op(OpOutpointIndex)?;
        }
        IntrospectionKind::InputSequenceNumber => {
            ctx.builder.add_op(OpTxInputSeq)?;
        }
        IntrospectionKind::OutputValue => {
            ctx.builder.add_op(OpTxOutputAmount)?;
        }
        IntrospectionKind::OutputScriptPubKey => {
            ctx.builder.add_op(OpTxOutputSpk)?;
        }
    }
    Ok(())
}

fn compile_date_literal_expr<'i>(ctx: &mut CompileExprContext<'_, 'i>, value: i64) -> Result<(), CompilerError> {
    ctx.builder.add_i64(value)?;
    *ctx.stack_depth += 1;
    Ok(())
}

fn compile_number_with_unit_expr() -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported("number units must be normalized during parsing".to_string()))
}

#[allow(clippy::too_many_arguments)]
fn compile_split_part<'i>(
    source: &Expr<'i>,
    index: &Expr<'i>,
    part: SplitPart,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    compile_expr(
        source,
        contract_constants,
        stack_bindings,
        types,
        builder,
        options,
        visiting,
        stack_depth,
        script_size,
        contract_constants,
    )?;
    match part {
        SplitPart::Left => {
            compile_expr(
                index,
                contract_constants,
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
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
            compile_expr(
                index,
                contract_constants,
                stack_bindings,
                types,
                builder,
                options,
                visiting,
                stack_depth,
                script_size,
                contract_constants,
            )?;
            builder.add_op(OpSwap)?;
            builder.add_op(OpSubstr)?;
            *stack_depth -= 2;
            Ok(())
        }
    }
}

fn expr_is_bytes<'i>(expr: &Expr<'i>, types: &TypeMap) -> bool {
    let mut visiting = HashSet::new();
    expr_is_bytes_inner(expr, types, &mut visiting)
}

fn expr_is_bytes_inner<'i>(expr: &Expr<'i>, types: &TypeMap, visiting: &mut HashSet<String>) -> bool {
    match &expr.kind {
        ExprKind::Byte(_) => true,
        ExprKind::String(_) => true,
        // Array literals are encoded to their packed byte representation at compile time,
        // regardless of element type, so downstream bytewise ops must treat them as bytes.
        ExprKind::Array(_) => true,
        ExprKind::Slice { .. } => true,
        ExprKind::New { name, .. } => {
            matches!(name.as_str(), "ScriptPubKeyP2PK" | "ScriptPubKeyP2SH" | "ScriptPubKeyP2SHFromRedeemScript")
        }
        ExprKind::Call { name, .. } => {
            let name = name.as_str();
            matches!(
                name,
                "bytes"
                    | "blake2b"
                    | "blake2bWithKey"
                    | "blake3"
                    | "blake3WithKey"
                    | "templateHash"
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
                    | "OpOutputCovenantId"
                    | "OpNum2Bin"
                    | "OpChainblockSeqCommit"
            ) || name.starts_with("byte[")
        }
        ExprKind::Split { .. } => true,
        ExprKind::Binary { op: BinaryOp::Add, left, right } => {
            expr_is_bytes_inner(left, types, visiting) || expr_is_bytes_inner(right, types, visiting)
        }
        ExprKind::IfElse { condition: _, then_expr, else_expr } => {
            expr_is_bytes_inner(then_expr, types, visiting) && expr_is_bytes_inner(else_expr, types, visiting)
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
                types.get(name).and_then(TypeRef::array_element_type).is_some_and(|element| element.is_array() || !element.is_int())
            }
            _ => false,
        },
        ExprKind::Identifier(name) => {
            if !visiting.insert(name.clone()) {
                return false;
            }
            visiting.remove(name);
            types.get(name).is_some_and(is_bytes_type)
        }
        ExprKind::UnarySuffix { kind, .. } => matches!(kind, UnarySuffixKind::Reverse),
        _ => false,
    }
}

fn compile_length_expr<'i>(
    expr: &Expr<'i>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if let ExprKind::Identifier(name) = &expr.kind {
        if let Some(type_ref) = types.get(name) {
            if let Some(size) = array_size_with_constants(type_ref, contract_constants) {
                builder.add_i64(size as i64)?;
                *stack_depth += 1;
                return Ok(());
            }
            if let Some(element_size) = array_element_size(type_ref) {
                compile_expr(
                    expr,
                    contract_constants,
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
    compile_expr(
        expr,
        contract_constants,
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
    let mut ctx = CompileCallContext { scope, builder, options, visiting, stack_depth, script_size, contract_constants };
    match name {
        "OpSha256" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpSHA256),
        "sha256" => compile_sha256_call(&mut ctx, args),
        "OpTxSubnetId" => compile_opcode_builtin_call(&mut ctx, name, args, 0, OpTxSubnetId),
        "OpTxGas" => compile_opcode_builtin_call(&mut ctx, name, args, 0, OpTxGas),
        "OpTxPayloadLen" => compile_opcode_builtin_call(&mut ctx, name, args, 0, OpTxPayloadLen),
        "OpTxPayloadSubstr" => compile_opcode_builtin_call(&mut ctx, name, args, 2, OpTxPayloadSubstr),
        "OpOutpointTxId" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpOutpointTxId),
        "OpOutpointIndex" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpOutpointIndex),
        "OpTxInputScriptSigLen" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpTxInputScriptSigLen),
        "OpTxInputScriptSigSubstr" => compile_opcode_builtin_call(&mut ctx, name, args, 3, OpTxInputScriptSigSubstr),
        "OpTxInputSeq" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpTxInputSeq),
        "OpTxInputDaaScore" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpTxInputDaaScore),
        "OpTxInputIsCoinbase" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpTxInputIsCoinbase),
        "OpTxInputSpkLen" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpTxInputSpkLen),
        "OpTxInputSpkSubstr" => compile_opcode_builtin_call(&mut ctx, name, args, 3, OpTxInputSpkSubstr),
        "OpTxOutputSpkLen" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpTxOutputSpkLen),
        "OpTxOutputSpkSubstr" => compile_opcode_builtin_call(&mut ctx, name, args, 3, OpTxOutputSpkSubstr),
        "OpAuthOutputCount" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpAuthOutputCount),
        "OpAuthOutputIdx" => compile_opcode_builtin_call(&mut ctx, name, args, 2, OpAuthOutputIdx),
        "OpInputCovenantId" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpInputCovenantId),
        "OpOutputCovenantId" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpOutputCovenantId),
        "OpCovInputCount" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpCovInputCount),
        "OpCovInputIdx" => compile_opcode_builtin_call(&mut ctx, name, args, 2, OpCovInputIdx),
        "OpCovOutputCount" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpCovOutputCount),
        "OpCovOutputIdx" => compile_opcode_builtin_call(&mut ctx, name, args, 2, OpCovOutputIdx),
        "OpNum2Bin" => compile_opcode_builtin_call(&mut ctx, name, args, 2, OpNum2Bin),
        "OpBin2Num" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpBin2Num),
        "OpChainblockSeqCommit" => compile_opcode_builtin_call(&mut ctx, name, args, 1, OpChainblockSeqCommit),
        "bytes" => compile_bytes_call(&mut ctx, args),
        "length" => compile_length_call(&mut ctx, args),
        "int" | "byte" | "bool" | "string" | "sig" | "pubkey" | "datasig" => compile_passthrough_cast_call(&mut ctx, name, args),
        name if parse_type_ref(name)
            .is_ok_and(|type_ref| matches!(type_ref.base, TypeBase::Byte) && type_ref.array_dims.len() == 1) =>
        {
            compile_byte_sequence_cast_call(&mut ctx, name, args)
        }
        name if parse_type_ref(name).is_ok_and(|type_ref| type_ref.is_array()) => compile_array_cast_call(&mut ctx, name, args),
        "blake2b" => compile_blake2b_call(&mut ctx, args),
        "blake2bWithKey" => compile_blake2b_with_key_call(&mut ctx, args),
        "blake3" => compile_blake3_call(&mut ctx, args),
        "blake3WithKey" => compile_blake3_with_key_call(&mut ctx, args),
        "templateHash" => compile_template_hash_call(&mut ctx, args),
        "checkSig" => compile_checksig_call(&mut ctx, args),
        "checkSigFromStack" => compile_checksigfromstack_call(&mut ctx, name, args, OpCheckSigFromStack),
        "checkSigFromStackECDSA" => compile_checksigfromstack_call(&mut ctx, name, args, OpCheckSigFromStackECDSA),
        _ => compile_unknown_function_call(name),
    }
}

struct CompileCallContext<'a, 'i> {
    scope: &'a CompilationScope<'a, 'i>,
    builder: &'a mut ScriptBuilder,
    options: CompileOptions,
    visiting: &'a mut HashSet<String>,
    stack_depth: &'a mut i64,
    script_size: Option<i64>,
    contract_constants: &'a HashMap<String, Expr<'i>>,
}

fn compile_call_arg_with_context<'i>(ctx: &mut CompileCallContext<'_, 'i>, arg: &Expr<'i>) -> Result<(), CompilerError> {
    compile_expr(
        arg,
        ctx.scope.constants,
        ctx.scope.stack_bindings,
        ctx.scope.types,
        ctx.builder,
        ctx.options,
        ctx.visiting,
        ctx.stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )
}

fn compile_opcode_builtin_call<'i>(
    ctx: &mut CompileCallContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
    expected_args: usize,
    opcode: u8,
) -> Result<(), CompilerError> {
    compile_opcode_call(
        name,
        args,
        expected_args,
        ctx.scope,
        ctx.builder,
        ctx.options,
        ctx.visiting,
        ctx.stack_depth,
        opcode,
        ctx.script_size,
        ctx.contract_constants,
    )
}

fn compile_sha256_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("sha256() expects a single argument".to_string()));
    }
    compile_call_arg_with_context(ctx, &args[0])?;
    ctx.builder.add_op(OpSHA256)?;
    Ok(())
}

fn compile_bytes_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.is_empty() || args.len() > 2 {
        return Err(CompilerError::Unsupported("bytes() expects one or two arguments".to_string()));
    }
    if args.len() == 2 {
        compile_call_arg_with_context(ctx, &args[0])?;
        compile_call_arg_with_context(ctx, &args[1])?;
        ctx.builder.add_op(OpNum2Bin)?;
        *ctx.stack_depth -= 1;
        return Ok(());
    }
    match &args[0].kind {
        ExprKind::String(value) => {
            ctx.builder.add_data_with_push_opcode(value.as_bytes())?;
            *ctx.stack_depth += 1;
            Ok(())
        }
        ExprKind::Identifier(name) => {
            if let Some(expr) = ctx.scope.constants.get(name) {
                if let ExprKind::String(value) = &expr.kind {
                    ctx.builder.add_data_with_push_opcode(value.as_bytes())?;
                    *ctx.stack_depth += 1;
                    return Ok(());
                }
            }
            if expr_is_bytes(&args[0], ctx.scope.types) {
                compile_call_arg_with_context(ctx, &args[0])?;
                return Ok(());
            }
            compile_call_arg_with_context(ctx, &args[0])?;
            ctx.builder.add_i64(8)?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpNum2Bin)?;
            *ctx.stack_depth -= 1;
            Ok(())
        }
        _ => {
            if expr_is_bytes(&args[0], ctx.scope.types) {
                compile_call_arg_with_context(ctx, &args[0])?;
                Ok(())
            } else {
                compile_call_arg_with_context(ctx, &args[0])?;
                ctx.builder.add_i64(8)?;
                *ctx.stack_depth += 1;
                ctx.builder.add_op(OpNum2Bin)?;
                *ctx.stack_depth -= 1;
                Ok(())
            }
        }
    }
}

fn compile_length_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("length() expects a single argument".to_string()));
    }
    compile_length_expr(
        &args[0],
        ctx.scope.stack_bindings,
        ctx.scope.types,
        ctx.builder,
        ctx.options,
        ctx.visiting,
        ctx.stack_depth,
        ctx.script_size,
        ctx.contract_constants,
    )
}

fn compile_passthrough_cast_call<'i>(
    ctx: &mut CompileCallContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
    }
    compile_call_arg_with_context(ctx, &args[0])
}

fn compile_byte_sequence_cast_call<'i>(
    ctx: &mut CompileCallContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let size_part = &name[5..name.len() - 1];
    if size_part.is_empty() {
        if args.len() != 1 && args.len() != 2 {
            return Err(CompilerError::Unsupported(format!("{name}() expects 1 or 2 arguments")));
        }
        compile_call_arg_with_context(ctx, &args[0])?;
        if args.len() == 2 {
            compile_call_arg_with_context(ctx, &args[1])?;
            *ctx.stack_depth += 1;
            ctx.builder.add_op(OpNum2Bin)?;
            *ctx.stack_depth -= 1;
        }
        return Ok(());
    }

    let size = size_part.parse::<i64>().map_err(|_| CompilerError::Unsupported(format!("{name}() is not supported")))?;
    if args.len() != 1 {
        return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
    }
    let source_type = infer_expr_type(&args[0], ctx.scope.types, ctx.scope.constants, &HashMap::new())
        .or_else(|| infer_debug_expr_value_type(&args[0], ctx.scope.constants, ctx.scope.types, &mut HashSet::new()).ok());
    if let Some(source_type) = source_type.as_ref() {
        if let Some(source_size) = byte_sequence_cast_size(source_type) {
            if let Some(source_size) = source_size {
                if source_size != size {
                    return Err(CompilerError::Unsupported(format!("cannot cast {} to {name}", source_type.type_name())));
                }
            }
            return compile_call_arg_with_context(ctx, &args[0]);
        }
    }
    compile_call_arg_with_context(ctx, &args[0])?;
    ctx.builder.add_i64(size)?;
    *ctx.stack_depth += 1;
    ctx.builder.add_op(OpNum2Bin)?;
    *ctx.stack_depth -= 1;
    Ok(())
}

fn compile_array_cast_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
    }
    compile_call_arg_with_context(ctx, &args[0])
}

fn compile_blake2b_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("blake2b() expects a single argument".to_string()));
    }
    compile_call_arg_with_context(ctx, &args[0])?;
    ctx.builder.add_op(OpBlake2b)?;
    Ok(())
}

fn compile_blake2b_with_key_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    let Ok([data, key]): Result<&[Expr<'i>; 2], _> = args.try_into() else {
        return Err(CompilerError::Unsupported("blake2bWithKey() expects 2 arguments".to_string()));
    };
    compile_call_arg_with_context(ctx, data)?;
    compile_call_arg_with_context(ctx, key)?;
    ctx.builder.add_op(OpBlake2bWithKey)?;
    *ctx.stack_depth -= 1;
    Ok(())
}

fn compile_blake3_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("blake3() expects a single argument".to_string()));
    }
    compile_call_arg_with_context(ctx, &args[0])?;
    ctx.builder.add_op(OpBlake3)?;
    Ok(())
}

fn compile_blake3_with_key_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    let Ok([data, key]): Result<&[Expr<'i>; 2], _> = args.try_into() else {
        return Err(CompilerError::Unsupported("blake3WithKey() expects 2 arguments".to_string()));
    };
    compile_call_arg_with_context(ctx, data)?;
    compile_call_arg_with_context(ctx, key)?;
    ctx.builder.add_op(OpBlake3WithKey)?;
    *ctx.stack_depth -= 1;
    Ok(())
}

fn compile_template_hash_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    let Ok([prefix, suffix]): Result<&[Expr<'i>; 2], _> = args.try_into() else {
        return Err(CompilerError::Unsupported("templateHash() expects 2 arguments".to_string()));
    };

    let encoded_prefix_len = Expr::call("bytes", vec![Expr::call("length", vec![prefix.clone()]), Expr::int(8)]);
    let encoded_suffix_len = Expr::call("bytes", vec![Expr::call("length", vec![suffix.clone()]), Expr::int(8)]);
    let preimage = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len, prefix.clone()),
        binary_expr(BinaryOp::Add, encoded_suffix_len, suffix.clone()),
    );
    compile_call_arg_with_context(ctx, &preimage)?;
    ctx.builder.add_op(OpBlake2b)?;
    Ok(())
}

fn compile_checksig_call<'i>(ctx: &mut CompileCallContext<'_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 2 {
        return Err(CompilerError::Unsupported("checkSig() expects 2 arguments".to_string()));
    }
    compile_call_arg_with_context(ctx, &args[0])?;
    compile_call_arg_with_context(ctx, &args[1])?;
    ctx.builder.add_op(OpCheckSig)?;
    *ctx.stack_depth -= 1;
    Ok(())
}

fn compile_checksigfromstack_call<'i>(
    ctx: &mut CompileCallContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
    opcode: u8,
) -> Result<(), CompilerError> {
    if args.len() != 3 {
        return Err(CompilerError::Unsupported(format!("{name}() expects 3 arguments (signature, digest, publicKey)")));
    }
    compile_call_arg_with_context(ctx, &args[0])?;
    compile_call_arg_with_context(ctx, &args[1])?;
    compile_call_arg_with_context(ctx, &args[2])?;
    ctx.builder.add_op(opcode)?;
    *ctx.stack_depth -= 2;
    Ok(())
}

fn compile_unknown_function_call(name: &str) -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported(format!("unknown function call: {name}")))
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
            scope.constants,
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
    constants: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    visiting: &mut HashSet<String>,
    stack_depth: &mut i64,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    compile_expr(expr, constants, stack_bindings, types, builder, options, visiting, stack_depth, script_size, contract_constants)?;
    if !expr_is_bytes(expr, types) {
        builder.add_i64(1)?;
        *stack_depth += 1;
        builder.add_op(OpNum2Bin)?;
        *stack_depth -= 1;
    }
    Ok(())
}

fn is_bytes_type(type_ref: &TypeRef) -> bool {
    type_ref.is_array()
        || type_ref.is_byte()
        || type_ref.is_string()
        || type_ref.is_pubkey()
        || type_ref.is_sig()
        || type_ref.is_datasig()
}

fn byte_sequence_cast_size(type_ref: &TypeRef) -> Option<Option<i64>> {
    if type_ref.is_string() {
        return Some(None);
    }
    if type_ref.is_byte() {
        return Some(Some(1));
    }
    if !type_ref.is_array()
        && let Some(size) = type_ref.base.fixed_byte_sequence_len()
    {
        return i64::try_from(size).ok().map(Some);
    }
    match type_ref.array_element_type() {
        Some(element) if element.is_byte() => Some(array_size(type_ref).and_then(|size| i64::try_from(size).ok())),
        _ => None,
    }
}

fn data_prefix(data_len: usize) -> Vec<u8> {
    let dummy_data = vec![0u8; data_len];
    let mut builder = script_builder();
    builder.add_data_with_push_opcode(&dummy_data).unwrap();
    let script = builder.drain();
    script[..script.len() - data_len].to_vec()
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
    let mut stack_depth = 0i64;
    let type_ref = infer_debug_expr_value_type(expr, constants, types, &mut HashSet::new())?;
    let stack_bindings = StackBindings::from_depths(stack_bindings.clone());
    compile_expr(
        expr,
        constants,
        &stack_bindings,
        types,
        &mut builder,
        CompileOptions::default(),
        &mut HashSet::new(),
        &mut stack_depth,
        None,
        &empty_constants,
    )?;
    Ok((builder.drain(), type_ref.type_name()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kaspa_txscript::opcodes::codes::OpData1;

    use crate::ast::{BinaryOp, Expr, ExprKind, UnaryOp};

    use super::{Op0, OpPushData1, OpPushData2, StackBindings, data_prefix, eval_const_int};

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
            stack_bindings.insert_binding(field, (contract_field_count - 1 - index) as i64);
        }

        assert_eq!(
            stack_bindings.binding_order(),
            ["field_b", "field_a", "param_b", "param_a"].into_iter().map(str::to_string).collect::<Vec<_>>()
        );
    }

    #[test]
    fn eval_const_int_rejects_checked_arithmetic_overflow() {
        let constants = HashMap::new();
        let cases = [
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::int(i64::MAX)), right: Box::new(Expr::int(1)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} + 1", i64::MAX),
            ),
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Sub, left: Box::new(Expr::int(-i64::MAX)), right: Box::new(Expr::int(2)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} - 2", -i64::MAX),
            ),
            (
                Expr::new(
                    ExprKind::Binary {
                        op: BinaryOp::Mul,
                        left: Box::new(Expr::int(3_037_000_500)),
                        right: Box::new(Expr::int(3_037_000_500)),
                    },
                    Default::default(),
                ),
                "constant integer overflow: 3037000500 * 3037000500".to_string(),
            ),
            (
                Expr::new(ExprKind::Unary { op: UnaryOp::Neg, expr: Box::new(Expr::int(i64::MIN)) }, Default::default()),
                format!("constant integer overflow: -({})", i64::MIN),
            ),
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Div, left: Box::new(Expr::int(i64::MIN)), right: Box::new(Expr::int(-1)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} / -1", i64::MIN),
            ),
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Mod, left: Box::new(Expr::int(i64::MIN)), right: Box::new(Expr::int(-1)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} % -1", i64::MIN),
            ),
        ];

        for (expr, expected) in cases {
            let err = eval_const_int(&expr, &constants).expect_err("overflow should be rejected");
            assert!(err.to_string().contains(&expected), "unexpected error: {err}");
        }
    }
}
