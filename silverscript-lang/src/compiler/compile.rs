use super::covenant_declarations::lower_covenant_declarations;
use super::debug_value_types::infer_debug_expr_value_type;
use super::infer_array::lower_inferred_array_sizes;
use super::inline_functions::lower_inline_functions;
use super::stack_bindings::StackBindings;
use super::*;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::serialize_i64;
use std::collections::{HashMap, HashSet};

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

    let layout_fields = flattened_struct_field_specs_for_type(expected_type, structs)?;
    if layout_fields.is_empty() {
        return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
    }

    let script_size_expr =
        templated_input_script_size_expr(template_prefix_len, template_suffix_len, &layout_fields, contract_constants)?;
    let state_start_offset_expr = template_prefix_len.clone();
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

    let covenant_lowered_contract = lower_covenant_declarations(contract, &constants)?;
    let inline_lowered_contract = lower_inline_functions(&covenant_lowered_contract)?;
    let structs = build_struct_registry(&inline_lowered_contract)?;
    let struct_lowered_contract = lower_structs_contract(&inline_lowered_contract, &structs, &constants)?;
    let lowered_contract = lower_inferred_array_sizes(&struct_lowered_contract, &constants)?;
    let mut lowered_constants = flatten_constructor_args_env(&covenant_lowered_contract.params, constructor_args, &structs)?;
    lowered_constants.extend(lowered_contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())));

    let entrypoint_functions: Vec<&FunctionAst<'i>> = lowered_contract.functions.iter().filter(|func| func.entrypoint).collect();
    if entrypoint_functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no entrypoint functions".to_string()));
    }

    let without_selector = entrypoint_functions.len() == 1;

    let functions_map = lowered_contract.functions.iter().cloned().map(|func| (func.name.clone(), func)).collect::<HashMap<_, _>>();
    let function_order = lowered_contract
        .functions
        .iter()
        .enumerate()
        .map(|(index, func)| (func.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let function_abi_entries = build_function_abi_entries(&covenant_lowered_contract);
    let uses_script_size = contract_uses_script_size(&lowered_contract);

    let mut script_size = if uses_script_size { Some(100i64) } else { None };

    for _ in 0..32 {
        let (_contract_fields, field_prolog_script) =
            compile_contract_fields(&lowered_contract.fields, &lowered_constants, options, script_size)?;

        let selector_prefix_len = if without_selector { 0 } else { 1 };
        let contract_field_prefix_len = selector_prefix_len + field_prolog_script.len();
        let state_layout = CompiledStateLayout { start: selector_prefix_len, len: field_prolog_script.len() };
        let mut compiled_entrypoints = Vec::new();
        for func in &lowered_contract.functions {
            if func.entrypoint {
                let function_index = function_order
                    .get(&func.name)
                    .copied()
                    .ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", func.name)))?;
                compiled_entrypoints.push(compile_entrypoint_function(
                    func,
                    function_index,
                    &lowered_contract.params,
                    &lowered_contract.fields,
                    &lowered_contract.constants,
                    contract_field_prefix_len,
                    &lowered_constants,
                    options,
                    &structs,
                    &functions_map,
                    &function_order,
                    script_size,
                )?);
            }
        }

        let script = if without_selector {
            let (_name, entrypoint_script) = compiled_entrypoints
                .first()
                .ok_or_else(|| CompilerError::Unsupported("contract has no entrypoint functions".to_string()))?;
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
            for (entrypoint_index, (_name, script)) in compiled_entrypoints.iter().enumerate() {
                builder.add_op(OpDup)?;
                builder.add_i64(entrypoint_index as i64)?;
                builder.add_op(OpNumEqual)?;
                builder.add_op(OpIf)?;
                builder.add_op(OpDrop)?;
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

        let debug_info = None;
        if !uses_script_size {
            return Ok(CompiledContract {
                contract_name: lowered_contract.name.clone(),
                script,
                ast: covenant_lowered_contract.clone(),
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
                ast: covenant_lowered_contract.clone(),
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

        let mut resolve_visiting = HashSet::new();
        let resolved = resolve_expr(field.expr.clone(), &env, &mut resolve_visiting)?;

        let mut compile_visiting = HashSet::new();
        let mut stack_depth = 0i64;
        if fixed_type_size_with_constants_ref(&field.type_ref, &env).is_some() {
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

pub(super) fn is_byte_array<'i>(expr: &Expr<'i>) -> bool {
    byte_array_len(expr).is_some()
}

fn byte_array_len<'i>(expr: &Expr<'i>) -> Option<usize> {
    match &expr.kind {
        ExprKind::Array(values) if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => Some(values.len()),
        _ => None,
    }
}

fn infer_expr_type_ref_for_comparison<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    types: &HashMap<String, String>,
) -> Option<TypeRef> {
    if let ExprKind::Identifier(name) = &expr.kind {
        if let Some(type_ref) = types.get(name).and_then(|type_name| parse_type_ref(type_name).ok()) {
            return Some(type_ref);
        }
    }
    if let Some((name, _)) = env.iter().find(|(_, value)| value.kind == expr.kind) {
        if let Some(type_ref) = types.get(name).and_then(|type_name| parse_type_ref(type_name).ok()) {
            return Some(type_ref);
        }
    }
    if let ExprKind::Call { name, .. } = &expr.kind {
        let is_builtin_cast = matches!(name.as_str(), "int" | "bool" | "byte" | "string" | "pubkey" | "sig" | "datasig")
            || (name.contains('[') && parse_type_ref(name).ok().is_some_and(|type_ref| !matches!(type_ref.base, TypeBase::Custom(_))));
        let is_known_builtin = matches!(
            name.as_str(),
            "int"
                | "bool"
                | "byte"
                | "string"
                | "pubkey"
                | "sig"
                | "datasig"
                | "bytes"
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
                | "OpNum2Bin"
                | "OpBin2Num"
                | "OpChainblockSeqCommit"
                | "LockingBytecodeNullData"
                | "ScriptPubKeyP2PK"
                | "ScriptPubKeyP2SH"
                | "ScriptPubKeyP2SHFromRedeemScript"
                | "OpInputCovenantId"
                | "OpTxGas"
                | "OpTxPayloadLen"
                | "OpTxInputIndex"
                | "OpTxInputIsCoinbase"
                | "OpTxInputScriptSigLen"
                | "OpTxInputSpkLen"
                | "OpOutpointIndex"
                | "OpTxOutputSpkLen"
                | "OpAuthOutputCount"
                | "OpAuthOutputIdx"
                | "OpCovInputCount"
                | "OpCovInputIdx"
                | "OpCovOutputCount"
                | "OpCovOutputIdx"
        );
        if !is_builtin_cast && !is_known_builtin {
            return None;
        }
    }
    let type_name = infer_debug_expr_value_type(expr, env, types, &mut HashSet::new()).ok()?;
    parse_type_ref(&type_name).ok()
}

fn comparison_types_compatible(left_type: &TypeRef, right_type: &TypeRef) -> bool {
    if left_type == right_type {
        return true;
    }
    matches!(
        (&left_type.base, left_type.array_dims.as_slice(), &right_type.base, right_type.array_dims.as_slice()),
        (TypeBase::Byte, [], TypeBase::Byte, [ArrayDim::Fixed(1)]) | (TypeBase::Byte, [ArrayDim::Fixed(1)], TypeBase::Byte, [])
    )
}

pub(super) fn array_literal_matches_type_with_env_ref<'i>(
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
        _ => super::type_check::value_matches_type_ref(value, &element_type),
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

pub(crate) fn type_name_from_ref(type_ref: &TypeRef) -> String {
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
        ArrayDim::Dynamic | ArrayDim::Inferred => None,
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
) -> Result<usize, CompilerError> {
    fixed_type_size_with_constants_ref(type_ref, contract_constants).ok_or_else(|| {
        CompilerError::Unsupported(format!("readInputState does not support field type {}", type_name_from_ref(type_ref)))
    })
}

fn fixed_state_field_payload_len<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
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

fn has_explicit_array_size_ref(type_ref: &TypeRef) -> bool {
    !matches!(type_ref.array_size(), Some(ArrayDim::Dynamic | ArrayDim::Inferred) | None)
}

fn has_inferred_array_size_ref(type_ref: &TypeRef) -> bool {
    matches!(type_ref.array_size(), Some(ArrayDim::Inferred))
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

pub(super) fn is_type_assignable_ref<'i>(actual: &TypeRef, expected: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> bool {
    actual == expected || is_array_type_assignable_ref(actual, expected, constants)
}

fn coerce_expr_for_declared_scalar_type<'i>(expr: Expr<'i>, type_name: &str) -> Expr<'i> {
    if type_name == "byte"
        && let ExprKind::Int(value) = expr.kind
        && (0..=255).contains(&value)
    {
        return Expr::new(ExprKind::Byte(value as u8), expr.span);
    }
    expr
}

fn coerce_rhs_byte_literal_for_comparison<'i>(left_type: Option<&TypeRef>, right: &Expr<'i>) -> Expr<'i> {
    if left_type.is_some_and(|type_ref| matches!(type_ref.base, TypeBase::Byte) && type_ref.array_dims.is_empty())
        && let ExprKind::Int(value) = right.kind
        && (0..=255).contains(&value)
    {
        return Expr::new(ExprKind::Byte(value as u8), right.span);
    }
    right.clone()
}

fn infer_fixed_array_type_from_initializer_ref<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<TypeRef> {
    if !has_inferred_array_size_ref(declared_type) {
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

pub(super) fn is_array_type(type_name: &str) -> bool {
    parse_type_ref(type_name).is_ok_and(|type_ref| is_array_type_ref(&type_ref))
}

pub(crate) fn array_element_type(type_name: &str) -> Option<String> {
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

pub(super) fn encode_array_literal<'i>(values: &[Expr<'i>], type_name: &str) -> Result<Vec<u8>, CompilerError> {
    let element_type = array_element_type(type_name)
        .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
    let mut out = Vec::new();
    debug_assert!(fixed_type_size(&element_type).is_some(), "type_check must validate array element type has known size");
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
    contract_params: &[ParamAst<'i>],
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &[ConstantAst<'i>],
    contract_field_prefix_len: usize,
    constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    script_size: Option<i64>,
) -> Result<(String, Vec<u8>), CompilerError> {
    let contract_field_count = contract_fields.len();
    let mut flattened_param_names = Vec::new();
    let mut types = HashMap::new();
    for param in contract_params {
        types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
    }
    for constant in contract_constants {
        types.insert(constant.name.clone(), type_name_from_ref(&constant.type_ref));
    }
    for param in &function.params {
        types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
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
        types.insert(field.name.clone(), type_name_from_ref(&field.type_ref));
    }
    let mut env: HashMap<String, Expr<'i>> = constants.clone();
    // Remove any constructor/constant names that collide with function param names (prioritizing function parameters on name collision).
    for param in &function.params {
        env.remove(&param.name);
    }
    let mut builder = ScriptBuilder::new();
    let mut return_exprs: Vec<Expr> = Vec::new();
    let assigned_names = collect_assigned_names(&function.body);
    let identifier_uses = collect_identifier_uses(&function.body);
    let has_return = function.body.iter().any(contains_return);

    let body_len = function.body.len();
    for (index, stmt) in function.body.iter().enumerate() {
        if let Statement::Return { exprs, .. } = stmt {
            debug_assert_eq!(index, body_len - 1, "type_check must validate return statements are last");
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
                contract_fields,
                contract_field_prefix_len,
                constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
            )
            .map_err(|err| err.with_span(&stmt.span()))?;
        }
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
    Ok((function.name.clone(), builder.drain()))
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
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
) -> Result<Vec<String>, CompilerError> {
    match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            let type_name = type_name_from_ref(type_ref);
            let effective_type_name = if has_inferred_array_size_ref(type_ref) {
                infer_fixed_array_type_from_initializer(&type_name, expr.as_ref(), types, contract_constants).ok_or_else(|| {
                    CompilerError::Unsupported(format!(
                        "variable '{}' requires an initializer with inferrable size for type {}",
                        name, type_name
                    ))
                })?
            } else {
                type_name.clone()
            };

            // Check if this is a fixed-size array (e.g., byte[N]) or dynamic array (e.g., byte[])
            let is_fixed_size_array =
                is_array_type(&effective_type_name) && array_size_with_constants(&effective_type_name, contract_constants).is_some();
            let is_dynamic_array =
                is_array_type(&effective_type_name) && array_size_with_constants(&effective_type_name, contract_constants).is_none();

            if is_dynamic_array {
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
                        e.clone()
                    }
                    Some(e @ Expr { kind: ExprKind::Array(values), .. }) => {
                        if !array_literal_matches_type_with_env(values, &effective_type_name, types, contract_constants) {
                            return Err(CompilerError::Unsupported("array initializer must be another array".to_string()));
                        }
                        resolve_expr(
                            Expr::new(ExprKind::Array(values.clone()), e.span),
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
                let expr = expr;

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
                let expr = coerce_expr_for_declared_scalar_type(expr, &effective_type_name);
                types.insert(name.clone(), effective_type_name.clone());
                let existing_is_predeclared_default = is_predeclared_scalar_default(name, &effective_type_name, env);

                // Scalars can be kept on the stack for reuse (>=2 uses with no mutation), or (optionally)
                // for mutation to avoid nested IfElse expression blowups under unrolled control flow.
                let used_at_least_twice = identifier_uses.get(name).copied().unwrap_or(0) >= 2;
                let stack_for_reuse = used_at_least_twice && !assigned_names.contains(name);
                let stack_for_mutation = assigned_names.contains(name);
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
            let element_type = array_element_type(array_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            let _element_size = array_element_size(array_type)
                .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
            let resolved_expr = resolve_expr(expr.clone(), env, &mut HashSet::new())?;
            let element_expr = if element_type == "int" {
                Expr::new(
                    ExprKind::Call { name: "byte[8]".to_string(), args: vec![resolved_expr], name_span: span::Span::default() },
                    span::Span::default(),
                )
            } else if matches!(element_type.as_str(), "bool" | "byte") {
                Expr::new(
                    ExprKind::Call { name: "byte[1]".to_string(), args: vec![resolved_expr], name_span: span::Span::default() },
                    span::Span::default(),
                )
            } else if is_bytes_type(&element_type) {
                if expr_is_bytes(&resolved_expr, env, types) {
                    resolved_expr
                } else {
                    Expr::new(
                        ExprKind::Call { name: element_type.to_string(), args: vec![resolved_expr], name_span: span::Span::default() },
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
            let expr = expr.clone();
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
            let expr = expr.clone();
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
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
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
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
        )
        .map(|_| Vec::new()),
        Statement::Return { .. } => unreachable!("type_check must validate return statement placement"),
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
                return compile_validate_output_state_statement(
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
                )
                .map(|_| Vec::new());
            }
            if name == "validateOutputStateWithTemplate" {
                let state_arg = args.get(1).ok_or_else(|| {
                    CompilerError::Unsupported(
                        "validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash) expects 5 arguments"
                            .to_string(),
                    )
                })?;
                let layout_fields = layout_fields_for_state_object_expr(state_arg, contract_fields, structs)?;
                return compile_validate_output_state_with_template_statement(
                    args,
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
            Err(CompilerError::Unsupported(format!(
                "inline lowering must eliminate internal function calls before compilation, found '{}()'",
                name
            )))
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
            unreachable!("lower_structs_contract must remove struct destructuring before codegen")
        }
        Statement::FunctionCallAssign { bindings, name, args, .. } => {
            let _ = (bindings, args, assigned_names, identifier_uses, functions, function_order, function_index);
            Err(CompilerError::Unsupported(format!(
                "inline lowering must eliminate function call assignments before compilation, found '{}()'",
                name
            )))
        }
        Statement::Assign { name, expr, .. } => {
            if let Some(type_name) = types.get(name) {
                // If this is a stack-bound scalar local, compile a real mutation instead of
                // rewriting `env[name]` (which can explode under unrolled control flow).
                if stack_bindings.contains(name) {
                    let lowered_expr = coerce_expr_for_declared_scalar_type(expr.clone(), type_name);

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
                    let updated = if let Some(previous) = env.get(name) {
                        replace_identifier(&lowered_expr, name, previous)
                    } else {
                        lowered_expr
                    };
                    let resolved = resolve_expr_for_runtime(updated, env, types, &mut HashSet::new())?;
                    env.insert(name.clone(), resolved);
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
                let lowered_expr = coerce_expr_for_declared_scalar_type(expr.clone(), type_name);
                let updated =
                    if let Some(previous) = env.get(name) { replace_identifier(&lowered_expr, name, previous) } else { lowered_expr };
                let resolved = resolve_expr_for_runtime(updated, env, types, &mut HashSet::new())?;
                env.insert(name.clone(), resolved);
                return Ok(Vec::new());
            }
            let lowered_expr = expr.clone();
            let updated =
                if let Some(previous) = env.get(name) { replace_identifier(&lowered_expr, name, previous) } else { lowered_expr };
            let resolved = resolve_expr_for_runtime(updated, env, types, &mut HashSet::new())?;
            env.insert(name.clone(), resolved);
            Ok(Vec::new())
        }
        Statement::Console { .. } => Ok(Vec::new()),
    }
}

pub(super) fn encoded_field_chunk_size<'i>(
    field: &ContractFieldAst<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let payload_size = fixed_state_field_payload_len(field, contract_constants)?;
    Ok(data_prefix(payload_size).len() + payload_size)
}

fn encoded_field_chunk_size_for_type_ref<'i>(
    type_ref: &TypeRef,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let payload_size = fixed_state_field_payload_len_for_type_ref(type_ref, contract_constants)?;
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
    let field_payload_len = fixed_state_field_payload_len_for_type_ref(field_type, contract_constants).map_err(|_| {
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

    cast_read_input_state_expr(substr, field_type)
}

fn cast_read_input_state_expr<'i>(substr: Expr<'i>, type_ref: &TypeRef) -> Result<Expr<'i>, CompilerError> {
    let type_name = type_name_from_ref(type_ref);
    match type_ref.base {
        TypeBase::Custom(_) => Err(CompilerError::Unsupported(format!("readInputState does not support field type {type_name}"))),
        _ => Ok(Expr::call(type_name.as_str(), vec![substr])),
    }
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

            let input_idx = input_idx.clone();
            let state_start_offset_expr = template_prefix_len.clone();
            let script_size_expr =
                templated_input_script_size_expr(template_prefix_len, template_suffix_len, &layout_fields, contract_constants)?;
            let mut field_chunk_offset = 0usize;

            for field in &struct_spec.fields {
                let binding = bindings_by_field.get(field.name.as_str()).ok_or_else(|| {
                    CompilerError::Unsupported(
                        "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                    )
                })?;
                let binding_type = type_name_from_ref(&binding.type_ref);
                let field_type = type_name_from_ref(&field.type_ref);
                debug_assert_eq!(
                    binding_type, field_type,
                    "type_check must validate readInputStateWithTemplate destructuring binding types"
                );

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
///   script_size = template_prefix_len + encoded_state_len(layout_fields) + template_suffix_len
///   script_base = input_sigscript_len(input_idx) - script_size
///
///   actual_redeem_script = input_sigscript[script_base .. script_base + script_size]
///   prefix = input_sigscript[script_base .. script_base + template_prefix_len]
///   suffix = input_sigscript[
///       script_base + template_prefix_len + encoded_state_len(layout_fields)
///       ..
///       script_base + script_size
///   ]
///
///   actual_template = prefix || suffix
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
    env: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &HashMap<String, String>,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    layout_fields: &[StructFieldSpec],
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
    if layout_fields.is_empty() {
        return Err(CompilerError::Unsupported("readInputStateWithTemplate requires a struct type".to_string()));
    }

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
        current_script_size,
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
        current_script_size,
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
        current_script_size,
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
    let Ok([output_idx, state_expr]): Result<&[Expr<'_>; 2], _> = args.try_into() else {
        return Err(CompilerError::Unsupported("validateOutputState(output_idx, new_state) expects 2 arguments".to_string()));
    };
    if contract_fields.is_empty() {
        return Err(CompilerError::Unsupported("validateOutputState requires contract fields".to_string()));
    }

    let mut stack_depth = compile_encoded_state_object(
        state_expr,
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

fn layout_fields_for_state_object_expr<'i>(
    state_expr: &Expr<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    structs: &StructRegistry,
) -> Result<Vec<StructFieldSpec>, CompilerError> {
    let ExprKind::StateObject(state_entries) = &state_expr.kind else {
        return Err(CompilerError::Unsupported("state object layout inference requires an object literal".to_string()));
    };

    let entry_names = state_entries.iter().map(|entry| entry.name.as_str()).collect::<HashSet<_>>();
    let local_layout = contract_fields
        .iter()
        .map(|field| StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
        .collect::<Vec<_>>();
    let local_names = local_layout.iter().map(|field| field.name.as_str()).collect::<HashSet<_>>();
    if entry_names.len() == local_names.len() && entry_names == local_names {
        return Ok(local_layout);
    }

    let matches = structs
        .keys()
        .filter_map(|name| {
            let layout = flattened_struct_field_specs_for_type(
                &TypeRef { base: TypeBase::Custom(name.clone()), array_dims: Vec::new() },
                structs,
            )
            .ok()?;
            let layout_names = layout.iter().map(|field| field.name.as_str()).collect::<HashSet<_>>();
            (layout_names.len() == entry_names.len() && layout_names == entry_names).then_some(layout)
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [layout] => Ok(layout.clone()),
        [] => Err(CompilerError::Unsupported("new_state must include all contract fields exactly once".to_string())),
        _ => Err(CompilerError::Unsupported("state object layout is ambiguous".to_string())),
    }
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
    let Ok([output_idx, state_expr, template_prefix, template_suffix, expected_template_hash]): Result<&[Expr<'_>; 5], _> =
        args.try_into()
    else {
        return Err(CompilerError::Unsupported(
            "validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash) expects 5 arguments"
                .to_string(),
        ));
    };
    if layout_fields.is_empty() {
        return Err(CompilerError::Unsupported("validateOutputStateWithTemplate requires contract fields".to_string()));
    }

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

        let field_size = fixed_state_field_payload_len_for_type_ref(&field.type_ref, contract_constants).map_err(|_| {
            CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", type_name_from_ref(&field.type_ref)))
        })?;

        if field.type_ref.array_dims.is_empty() && matches!(field.type_ref.base, TypeBase::Int | TypeBase::Bool) {
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
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let condition = condition.clone();
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
        predeclare_if_branch_locals(then_branch, &mut then_env, &mut then_types)?;
    compile_block(
        then_branch,
        &mut then_env,
        assigned_names,
        identifier_uses,
        &mut then_types,
        &mut then_stack_bindings,
        builder,
        options,
        contract_fields,
        contract_field_prefix_len,
        contract_constants,
        structs,
        functions,
        function_order,
        function_index,
        script_size,
        true,
    )?;

    let mut else_env = original_env.clone();
    if let Some(else_branch) = else_branch {
        builder.add_op(OpElse)?;
        let mut else_types = types.clone();
        let mut else_stack_bindings = original_stack_bindings.clone();
        predeclare_if_branch_locals(else_branch, &mut else_env, &mut else_types)?;
        compile_block(
            else_branch,
            &mut else_env,
            assigned_names,
            identifier_uses,
            &mut else_types,
            &mut else_stack_bindings,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            true,
        )?;
        else_stack_bindings.emit_stack_reordering(&then_stack_bindings, builder)?;
        *stack_bindings = then_stack_bindings;
    } else {
        then_stack_bindings.emit_stack_reordering(&original_stack_bindings, builder)?;
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
                types.insert(name.clone(), type_name);
                env.insert(name.clone(), default_expr);
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
                    types.insert(binding.name.clone(), type_name);
                    env.insert(binding.name.clone(), default_expr);
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
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
    scoped_stack_locals: bool,
) -> Result<(), CompilerError> {
    let mut added_stack_locals = Vec::new();
    for stmt in statements {
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
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
            )
            .map_err(|err| err.with_span(&stmt.span()))?,
        );
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
    _for_span: span::Span<'i>,
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let max_iterations = match eval_const_int(max_iterations_expr, contract_constants) {
        Ok(value) => value,
        Err(CompilerError::InvalidLiteral(message)) => return Err(CompilerError::InvalidLiteral(message)),
        Err(_) => return Err(CompilerError::Unsupported("for loop max iterations must be a compile-time integer".to_string())),
    };
    if max_iterations < 0 {
        return Err(CompilerError::Unsupported("for loop max iterations must be a non-negative compile-time integer".to_string()));
    }

    let start = start_expr.clone();
    let end = end_expr.clone();

    let name = ident.to_string();
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
                env,
                assigned_names,
                identifier_uses,
                types,
                stack_bindings,
                builder,
                options,
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
            )
        } else {
            compile_runtime_for_statement(
                &name,
                start,
                end,
                max_iterations as usize,
                body,
                env,
                assigned_names,
                identifier_uses,
                types,
                stack_bindings,
                builder,
                options,
                contract_fields,
                contract_field_prefix_len,
                contract_constants,
                structs,
                functions,
                function_order,
                function_index,
                script_size,
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
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    for iteration in 0..max_iterations {
        let value = start + iteration as i64;
        if value >= end {
            break;
        }

        env.insert(ident.to_string(), Expr::int(value));
        compile_block(
            body,
            env,
            assigned_names,
            identifier_uses,
            types,
            stack_bindings,
            builder,
            options,
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
            true,
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
    env: &mut HashMap<String, Expr<'i>>,
    assigned_names: &HashSet<String>,
    identifier_uses: &HashMap<String, usize>,
    types: &mut HashMap<String, String>,
    stack_bindings: &mut StackBindings,
    builder: &mut ScriptBuilder,
    options: CompileOptions,
    contract_fields: &[ContractFieldAst<'i>],
    contract_field_prefix_len: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    functions: &HashMap<String, FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    script_size: Option<i64>,
) -> Result<(), CompilerError> {
    let mut current = resolve_expr_for_runtime(start, env, types, &mut HashSet::new())?;
    let mut current_const = eval_const_int(&current, contract_constants).ok();
    for _ in 0..max_iterations {
        let loop_value = current_const.map_or_else(|| current.clone(), Expr::int);
        env.insert(ident.to_string(), loop_value.clone());

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
            contract_fields,
            contract_field_prefix_len,
            contract_constants,
            structs,
            functions,
            function_order,
            function_index,
            script_size,
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

pub(super) fn resolve_expr_for_runtime<'i>(
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
pub(super) fn replace_identifier<'i>(expr: &Expr<'i>, target: &str, replacement: &Expr<'i>) -> Expr<'i> {
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

pub(super) fn compile_expr<'i>(
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
            let left_cmp_type = infer_expr_type_ref_for_comparison(left, env, types);
            let coerced_right =
                if matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge) {
                    coerce_rhs_byte_literal_for_comparison(left_cmp_type.as_ref(), right)
                } else {
                    right.as_ref().clone()
                };
            if matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge) {
                if let (Some(left_type), Some(right_type)) =
                    (left_cmp_type.clone(), infer_expr_type_ref_for_comparison(&coerced_right, env, types))
                {
                    debug_assert!(
                        comparison_types_compatible(&left_type, &right_type),
                        "type_check must validate comparison operand compatibility"
                    );
                }
            }
            let left_value_type = infer_debug_expr_value_type(left, env, types, &mut HashSet::new()).ok();
            let right_value_type = infer_debug_expr_value_type(&coerced_right, env, types, &mut HashSet::new()).ok();
            debug_assert!(
                !matches!(op, BinaryOp::Add)
                    || (left_value_type.as_deref() != Some("byte") && right_value_type.as_deref() != Some("byte")),
                "type_check must reject byte addition"
            );
            let bytes_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne)
                && (expr_is_bytes(left, env, types) || expr_is_bytes(&coerced_right, env, types));
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
                    &coerced_right,
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
        // Array literals are encoded to their packed byte representation at compile time,
        // regardless of element type, so downstream bytewise ops must treat them as bytes.
        ExprKind::Array(_) => true,
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
        "byte" | "bool" | "string" => {
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
                let source_type = infer_debug_expr_value_type(&args[0], scope.env, scope.types, &mut HashSet::new()).ok();
                if let Some(source_type) = source_type.as_deref() {
                    if let Some(source_size) = byte_sequence_cast_size(source_type) {
                        if let Some(source_size) = source_size {
                            if source_size != size {
                                return Err(CompilerError::Unsupported(format!("cannot cast {source_type} to {name}")));
                            }
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
                        return Ok(());
                    }
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
        name if parse_type_ref(name).is_ok_and(|type_ref| is_array_type_ref(&type_ref)) => {
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

pub(crate) fn is_bytes_type(type_name: &str) -> bool {
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

pub(super) fn byte_sequence_cast_size(type_name: &str) -> Option<Option<i64>> {
    match type_name {
        "bytes" | "byte[]" | "string" => Some(None),
        "byte" => Some(Some(1)),
        "pubkey" => Some(Some(32)),
        "sig" => Some(Some(65)),
        "datasig" => Some(Some(64)),
        _ => match array_element_type(type_name).as_deref() {
            Some("byte") => Some(array_size(type_name).map(|size| size as i64)),
            _ => None,
        },
    }
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
