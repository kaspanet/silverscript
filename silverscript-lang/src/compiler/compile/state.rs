use super::*;
use crate::compiler::builtin_types::{builtin_return_type, constructor_return_type};

fn scalar_type(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn byte_array_type(dimension: ArrayDim) -> TypeRef {
    TypeRef { base: TypeBase::Byte, array_dims: vec![dimension] }
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

pub(in crate::compiler) fn read_input_state_field_expr_symbolic<'i>(
    input_idx: &Expr<'i>,
    field: &ContractFieldAst<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    contract_fields_end_offset: usize,
    field_chunk_offset: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let state_start_offset = state_start_offset(contract_fields_end_offset, contract_fields, contract_constants)?;
    let script_size_expr = Expr::new(ExprKind::Nullary(NullaryOp::ThisScriptSize), span::Span::default());
    read_input_state_field_expr(
        input_idx,
        &field.type_ref,
        Expr::int(state_start_offset as i64),
        field_chunk_offset,
        script_size_expr,
        contract_constants,
        "readInputState",
    )
}

fn fixed_state_payload_len<'i>(type_ref: &TypeRef, contract_constants: &HashMap<String, Expr<'i>>) -> Result<usize, CompilerError> {
    fixed_type_size(type_ref, contract_constants)
        .ok_or_else(|| CompilerError::Unsupported(format!("readInputState does not support field type {}", type_ref.type_name())))
}

pub(in crate::compiler) fn encoded_type_chunk_size<'i>(
    type_ref: &TypeRef,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let payload_size = fixed_state_payload_len(type_ref, contract_constants)?;
    Ok(data_prefix(payload_size)?.len() + payload_size)
}

pub(super) fn encoded_state_len<'i>(
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    contract_fields.iter().try_fold(0usize, |acc, field| Ok(acc + encoded_type_chunk_size(&field.type_ref, contract_constants)?))
}

pub(in crate::compiler) fn encoded_state_len_for_layout_field_types<'i>(
    layout_field_types: &[TypeRef],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    layout_field_types.iter().try_fold(0usize, |acc, type_ref| Ok(acc + encoded_type_chunk_size(type_ref, contract_constants)?))
}

pub(super) fn state_start_offset<'i>(
    contract_fields_end_offset: usize,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    contract_fields_end_offset
        .checked_sub(total_state_len)
        .ok_or_else(|| CompilerError::Unsupported("state offset underflow".to_string()))
}

pub(super) fn templated_input_script_size_expr<'i>(
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

pub(super) fn read_input_state_field_expr<'i>(
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
        Expr::int((field_chunk_offset + data_prefix(field_payload_len)?.len()) as i64),
    );
    let start = binary_expr(BinaryOp::Add, input_sigscript_base_expr(input_idx, script_size_expr), field_payload_offset);
    let end = binary_expr(BinaryOp::Add, start.clone(), Expr::int(field_payload_len as i64));
    let substr = input_sigscript_substr_expr(input_idx, start, end);

    cast_read_input_state_expr(substr, field_type)
}

pub(super) fn cast_read_input_state_expr<'i>(substr: Expr<'i>, type_ref: &TypeRef) -> Result<Expr<'i>, CompilerError> {
    let type_name = type_ref.type_name();
    match type_ref.base {
        TypeBase::Custom(_) => Err(CompilerError::Unsupported(format!("readInputState does not support field type {type_name}"))),
        _ => Ok(Expr::call(type_name.as_str(), vec![substr])),
    }
}

pub(super) fn struct_name_for_state_bindings<'i>(
    bindings: &[StructBindingAst<'i>],
    structs: &StructRegistry,
) -> Result<String, CompilerError> {
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
/// The field-value reads are built separately by the statement compiler using
/// the same flattened layout and byte offsets.
#[allow(clippy::too_many_arguments)]
pub(super) fn compile_read_input_state_with_template_validation(
    args: &[Expr<'_>],
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
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
    let script_base_expr = input_sigscript_base_expr(input_idx, script_size_expr.clone());
    let prefix_end_expr = binary_expr(BinaryOp::Add, script_base_expr.clone(), template_prefix_len.clone());
    let script_end_expr = binary_expr(BinaryOp::Add, script_base_expr.clone(), script_size_expr.clone());
    let state_len = encoded_state_len_for_layout_field_types(layout_field_types, contract_constants)?;
    let suffix_start_expr = binary_expr(BinaryOp::Add, prefix_end_expr.clone(), Expr::int(state_len as i64));
    let suffix_end_expr = binary_expr(BinaryOp::Add, suffix_start_expr.clone(), template_suffix_len.clone());

    let input_redeem_script_expr = input_sigscript_substr_expr(input_idx, script_base_expr.clone(), script_end_expr);
    let prefix_expr = input_sigscript_substr_expr(input_idx, script_base_expr, prefix_end_expr);
    let suffix_expr = input_sigscript_substr_expr(input_idx, suffix_start_expr, suffix_end_expr);
    let encoded_prefix_len_expr = Expr::call("bytes", vec![template_prefix_len.clone(), Expr::int(8)]);
    let encoded_suffix_len_expr = Expr::call("bytes", vec![template_suffix_len.clone(), Expr::int(8)]);
    let template_expr = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len_expr, prefix_expr),
        binary_expr(BinaryOp::Add, encoded_suffix_len_expr, suffix_expr),
    );
    let expected_input_spk_expr = Expr::new(
        ExprKind::New {
            name: "ScriptPubKeyP2SHFromRedeemScript".to_string(),
            args: vec![input_redeem_script_expr],
            name_span: span::Span::default(),
        },
        span::Span::default(),
    );
    let actual_input_spk_expr = input_script_pubkey_expr(input_idx);

    let env = ExprEnv { constants: contract_constants, stack_bindings, types, script_size: current_script_size, contract_constants };
    let mut emitter = ScriptEmitter::new(builder, 0);
    let dynamic_bytes = byte_array_type(ArrayDim::Dynamic);
    let p2sh_script_type = constructor_return_type("ScriptPubKeyP2SHFromRedeemScript").expect("known constructor type");
    let hash_type = builtin_return_type("blake2b").expect("known builtin type");

    compile_expr(&actual_input_spk_expr, Some(&dynamic_bytes), &env, &mut emitter)?;
    compile_expr(&expected_input_spk_expr, Some(&p2sh_script_type), &env, &mut emitter)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    compile_expr(expected_template_hash, Some(&hash_type), &env, &mut emitter)?;
    compile_expr(&template_expr, Some(&dynamic_bytes), &env, &mut emitter)?;
    emitter.emit_op(OpBlake2b, 0)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_validate_output_state_inner_statement(
    args: &[Expr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    contract_fields: &[ContractFieldAst<'_>],
    contract_fields_end_offset: usize,
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

    let stack_depth = compile_encoded_state_object(
        &state_fields,
        constants,
        stack_bindings,
        types,
        builder,
        script_size,
        contract_constants,
        "validateOutputState",
    )?;

    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    let state_start_offset = contract_fields_end_offset
        .checked_sub(total_state_len)
        .ok_or_else(|| CompilerError::Unsupported("validateOutputState state offset underflow".to_string()))?;

    let script_size_value =
        script_size.ok_or_else(|| CompilerError::Unsupported("validateOutputState requires this.scriptSize".to_string()))?;
    let mut emitter = ScriptEmitter::new(builder, stack_depth);

    // Rebuild `prefix || encoded_new_state || suffix`. The redeem script starts
    // at `input_sigscript_len - script_size_value`.
    if state_start_offset > 0 {
        // Extract the bytes before the old state and prepend them to the new state.
        emitter.emit_op(OpTxInputIndex, 1)?;
        emitter.emit_op(OpDup, 1)?;
        emitter.emit_op(OpTxInputScriptSigLen, 0)?;
        emitter.push_int(script_size_value)?;
        emitter.emit_op(OpSub, -1)?;
        emitter.emit_op(OpDup, 1)?;
        emitter.push_int(state_start_offset as i64)?;
        emitter.emit_op(OpAdd, -1)?;
        emitter.emit_op(OpTxInputScriptSigSubstr, -2)?;
        emitter.emit_op(OpSwap, 0)?;
        emitter.emit_op(OpCat, -1)?;
    }

    // Extract the bytes after the old state.
    emitter.emit_op(OpTxInputIndex, 1)?;
    emitter.emit_op(OpDup, 1)?;
    emitter.emit_op(OpTxInputScriptSigLen, 0)?;
    emitter.emit_op(OpDup, 1)?;

    // Compute `suffix_start = input_sigscript_len + contract_fields_end_offset - script_size_value`.`
    emitter.push_int(contract_fields_end_offset as i64 - script_size_value)?;
    emitter.emit_op(OpAdd, -1)?;
    emitter.emit_op(OpSwap, 0)?;
    emitter.emit_op(OpTxInputScriptSigSubstr, -2)?;

    // Complete `prefix || encoded_new_state || suffix`.
    emitter.emit_op(OpCat, -1)?;

    // Wrap the reconstructed redeem-script hash in a P2SH scriptPubKey.
    emitter.emit_op(OpBlake2b, 0)?;
    emitter.push_data(&[0x00, 0x00])?;
    emitter.push_data(&[OpBlake2b])?;
    emitter.emit_op(OpCat, -1)?;
    emitter.push_data(&[0x20])?;
    emitter.emit_op(OpCat, -1)?;
    emitter.emit_op(OpSwap, 0)?;
    emitter.emit_op(OpCat, -1)?;
    emitter.push_data(&[OpEqual])?;
    emitter.emit_op(OpCat, -1)?;

    // Require the selected output to use that scriptPubKey.
    let env = ExprEnv { constants, stack_bindings, types, script_size: Some(script_size_value), contract_constants };
    let int_type = scalar_type(TypeBase::Int);
    compile_expr(output_idx, Some(&int_type), &env, &mut emitter)?;
    emitter.emit_op(OpTxOutputSpk, 0)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    Ok(())
}

pub(super) fn compile_validate_output_state_with_template_inner_statement(
    args: &[Expr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
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

    let env = ExprEnv { constants, stack_bindings, types, script_size, contract_constants };
    let dynamic_bytes_type = byte_array_type(ArrayDim::Dynamic);
    let hash_type = builtin_return_type("blake2b").expect("known builtin type");
    let int_type = scalar_type(TypeBase::Int);

    let encoded_prefix_len = Expr::call("bytes", vec![Expr::call("length", vec![template_prefix.clone()]), Expr::int(8)]);
    let encoded_suffix_len = Expr::call("bytes", vec![Expr::call("length", vec![template_suffix.clone()]), Expr::int(8)]);
    let template_preimage = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len, template_prefix.clone()),
        binary_expr(BinaryOp::Add, encoded_suffix_len, template_suffix.clone()),
    );
    {
        let mut emitter = ScriptEmitter::new(builder, 0);
        compile_expr(expected_template_hash, Some(&hash_type), &env, &mut emitter)?;
        compile_expr(&template_preimage, Some(&dynamic_bytes_type), &env, &mut emitter)?;
        emitter.emit_op(OpBlake2b, 0)?;
        emitter.emit_op(OpEqualVerify, -2)?;
    }
    let stack_depth = compile_encoded_flat_state_fields(
        state_fields,
        constants,
        stack_bindings,
        types,
        builder,
        script_size,
        contract_constants,
        "validateOutputStateWithTemplate",
    )?;
    let mut emitter = ScriptEmitter::new(builder, stack_depth);

    compile_expr(template_prefix, Some(&dynamic_bytes_type), &env, &mut emitter)?;
    emitter.emit_op(OpSwap, 0)?;
    emitter.emit_op(OpCat, -1)?;

    compile_expr(template_suffix, Some(&dynamic_bytes_type), &env, &mut emitter)?;
    emitter.emit_op(OpCat, -1)?;

    emitter.emit_op(OpBlake2b, 0)?;
    emitter.push_data(&[0x00, 0x00])?;
    emitter.push_data(&[OpBlake2b])?;
    emitter.emit_op(OpCat, -1)?;
    emitter.push_data(&[0x20])?;
    emitter.emit_op(OpCat, -1)?;
    emitter.emit_op(OpSwap, 0)?;
    emitter.emit_op(OpCat, -1)?;
    emitter.push_data(&[OpEqual])?;
    emitter.emit_op(OpCat, -1)?;

    compile_expr(output_idx, Some(&int_type), &env, &mut emitter)?;
    emitter.emit_op(OpTxOutputSpk, 0)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    Ok(())
}

pub(super) fn compile_encoded_state_object(
    state_entries: &[StateFieldExpr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    compile_encoded_state_fields(
        state_entries.iter().map(|entry| &entry.expr),
        constants,
        stack_bindings,
        types,
        builder,
        script_size,
        contract_constants,
        builtin_name,
    )
}

pub(super) fn compile_encoded_flat_state_fields(
    state_fields: &[Expr<'_>],
    constants: &HashMap<String, Expr<'_>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    compile_encoded_state_fields(
        state_fields.iter(),
        constants,
        stack_bindings,
        types,
        builder,
        script_size,
        contract_constants,
        builtin_name,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_encoded_state_fields<'a, 'i>(
    state_fields: impl ExactSizeIterator<Item = &'a Expr<'i>>,
    constants: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    script_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
    builtin_name: &str,
) -> Result<i64, CompilerError>
where
    'i: 'a,
{
    let field_count = state_fields.len();
    let env = ExprEnv { constants, stack_bindings, types, script_size, contract_constants };
    let mut emitter = ScriptEmitter::new(builder, 0);
    for new_value in state_fields {
        let type_ref = infer_expr_type(new_value, constants, types)?;
        let field_size = fixed_state_payload_len(&type_ref, contract_constants)
            .map_err(|_| CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", type_ref.type_name())))?;

        let prefix = data_prefix(field_size)?;
        emitter.push_data(&prefix)?;
        compile_expr(new_value, Some(&type_ref), &env, &mut emitter)?;
        if type_ref.is_int() || type_ref.is_bool() {
            emitter.push_int(field_size as i64)?;
            emitter.emit_op(OpNum2Bin, -1)?;
        }
        emitter.emit_op(OpCat, -1)?;
    }

    for _ in 1..field_count {
        emitter.emit_op(OpCat, -1)?;
    }
    Ok(emitter.stack_depth())
}
