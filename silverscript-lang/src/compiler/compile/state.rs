use super::*;
use crate::compiler::builtin_types::{builtin_return_type, constructor_return_type};

fn scalar_type(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn byte_array_type(dimension: ArrayDim) -> TypeRef {
    TypeRef { base: TypeBase::Byte, array_dims: vec![dimension] }
}

fn input_sigscript_base_expr<'i>(input_idx: &Expr<'i>, bytecode_size_expr: Expr<'i>) -> Expr<'i> {
    binary_expr(BinaryOp::Sub, Expr::call("OpTxInputScriptSigLen", vec![input_idx.clone()]), bytecode_size_expr)
}

fn input_sigscript_substr_expr<'i>(input_idx: &Expr<'i>, start: Expr<'i>, end: Expr<'i>) -> Expr<'i> {
    Expr::call("OpTxInputScriptSigSubstr", vec![input_idx.clone(), start, end])
}

fn input_script_pubkey_expr<'i>(input_idx: &Expr<'i>) -> Expr<'i> {
    Expr::new(
        ExprKind::IndexedIntrospection {
            kind: IndexedIntrospectionKind::InputScriptPubKey,
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
    state_end: usize,
    field_chunk_offset: usize,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let state_start_offset = state_start_offset(state_end, contract_fields, contract_constants)?;
    let bytecode_size_expr = Expr::new(ExprKind::Introspection(IntrospectionKind::ThisBytecodeSize), span::Span::default());
    read_input_state_field_expr(
        input_idx,
        &field.type_ref,
        Expr::int(state_start_offset as i64),
        field_chunk_offset,
        bytecode_size_expr,
        contract_constants,
        "readInputState",
    )
}

fn fixed_state_payload_len<'i>(type_ref: &TypeRef, contract_constants: &HashMap<String, Expr<'i>>) -> Result<usize, CompilerError> {
    fixed_type_size(type_ref, contract_constants)?
        .ok_or_else(|| CompilerError::Unsupported(format!("readInputState does not support field type {}", type_ref.type_name())))
}

pub(in crate::compiler) fn encoded_type_chunk_size<'i>(
    type_ref: &TypeRef,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let payload_size = fixed_state_payload_len(type_ref, contract_constants)?;
    let prefix_size = data_prefix(payload_size)?.len();
    checked_add(prefix_size, payload_size)
}

pub(super) fn encoded_state_len<'i>(
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    contract_fields.iter().try_fold(0usize, |acc, field| {
        let field_size = encoded_type_chunk_size(&field.type_ref, contract_constants)?;
        checked_add(acc, field_size)
    })
}

pub(in crate::compiler) fn encoded_state_len_for_layout_field_types<'i>(
    layout_field_types: &[TypeRef],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    layout_field_types.iter().try_fold(0usize, |acc, type_ref| {
        let field_size = encoded_type_chunk_size(type_ref, contract_constants)?;
        checked_add(acc, field_size)
    })
}

pub(super) fn state_start_offset<'i>(
    state_end: usize,
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<usize, CompilerError> {
    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    checked_sub(state_end, total_state_len)
}

pub(super) fn templated_input_bytecode_size_expr<'i>(
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

/// Pins the push framing of a foreign input's state region.
///
/// State fields are decoded at offsets fixed at compile time, which is only
/// meaningful if every field is encoded with the canonical push header the
/// state encoder emits. The script engine also accepts non-minimal push
/// encodings, so without this guard a foreign input can widen one field's
/// header and narrow another's, keep the region's total length identical, and
/// move every later field read onto bytes of its own choosing.
///
/// Requiring each field's header to equal `data_prefix(payload_len)` at its
/// constant offset forces the whole region to be canonically framed: the first
/// header sits at the region start, and each header it pins determines its own
/// payload width and therefore the offset of the next header.
///
/// The state region is read once and kept on the stack, so the guard costs one
/// sigscript introspection per call site plus one comparison per field:
///
///   region = input_sigscript[state_region_start .. state_region_end]
///   for each field:
///     require(region[field_header_start .. field_header_end] == data_prefix(payload_len))
fn emit_state_framing_guard(
    input_idx: &Expr<'_>,
    state_start_offset_expr: &Expr<'_>,
    layout_field_types: &[TypeRef],
    bytecode_size_expr: &Expr<'_>,
    env: &ExprEnv<'_, '_>,
    emitter: &mut ScriptEmitter<'_>,
) -> Result<(), CompilerError> {
    let int_type = scalar_type(TypeBase::Int);
    let region_len = encoded_state_len_for_layout_field_types(layout_field_types, env.contract_constants)?;

    // region_start = input_sigscript_len(idx) - bytecode_size + state_start_offset
    compile_expr(input_idx, Some(&int_type), env, emitter)?;
    emitter.emit_op(OpDup, 1)?;
    emitter.emit_op(OpTxInputScriptSigLen, 0)?;
    compile_expr(bytecode_size_expr, Some(&int_type), env, emitter)?;
    emitter.emit_op(OpSub, -1)?;
    compile_expr(state_start_offset_expr, Some(&int_type), env, emitter)?;
    emitter.emit_op(OpAdd, -1)?;

    emitter.emit_op(OpDup, 1)?;
    emitter.push_int(region_len as i64)?;
    emitter.emit_op(OpAdd, -1)?;
    emitter.emit_op(OpTxInputScriptSigSubstr, -2)?;

    let mut field_chunk_offset = 0usize;
    for field_type in layout_field_types {
        let payload_len = fixed_state_payload_len(field_type, env.contract_constants)?;
        let expected_prefix = data_prefix(payload_len)?;
        let header_end = checked_add(field_chunk_offset, expected_prefix.len())?;

        emitter.emit_op(OpDup, 1)?;
        emitter.push_int(field_chunk_offset as i64)?;
        emitter.push_int(header_end as i64)?;
        emitter.emit_op(OpSubstr, -2)?;
        emitter.push_data(&expected_prefix)?;
        emitter.emit_op(OpEqualVerify, -2)?;

        field_chunk_offset = checked_add(header_end, payload_len)?;
    }
    emitter.emit_op(OpDrop, -1)?;

    Ok(())
}

/// Binds a plain `readInputState` window to the foreign input's own scriptPubKey.
///
/// The window is placed at `sigscript_len(idx) - this.bytecodeSize`, which describes the READER
/// and not the script being read. Nothing else in the plain decoder constrains the foreign
/// script's length, so a longer one shifts every field read — and the framing guard, which pins
/// headers at those offsets, simply follows the window onto bytes the forger chose. Pinning the
/// framing of a window whose position is unconstrained proves nothing.
///
/// Requiring `P2SH(window) == input_script_pubkey(idx)` fixes the position, because a
/// scriptPubKey commits to the WHOLE redeem script: if the foreign script were longer, the window
/// would be a proper suffix of it, and the P2SH of a suffix is not the P2SH of the script. So the
/// foreign script is exactly `bytecodeSize` bytes and is the one its own UTXO committed to.
///
/// This is the check `readInputStateWithTemplate` already makes, which is why only the plain
/// decoder needed it.
pub(super) fn compile_input_script_binding(
    input_idx: &Expr<'_>,
    bytecode_size_expr: &Expr<'_>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    bytecode_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    let base = input_sigscript_base_expr(input_idx, bytecode_size_expr.clone());
    let end = binary_expr(BinaryOp::Add, base.clone(), bytecode_size_expr.clone());
    let redeem = input_sigscript_substr_expr(input_idx, base, end);
    let expected_spk = Expr::new(
        ExprKind::New { name: "ScriptPubKeyP2SHFromRedeemScript".to_string(), args: vec![redeem], name_span: span::Span::default() },
        span::Span::default(),
    );

    let env = ExprEnv { constants: contract_constants, stack_bindings, types, bytecode_size, contract_constants };
    let mut emitter = ScriptEmitter::new(builder, 0);
    let dynamic_bytes = byte_array_type(ArrayDim::Dynamic);
    let p2sh_script_type = constructor_return_type("ScriptPubKeyP2SHFromRedeemScript").expect("known constructor type");

    compile_expr(&input_script_pubkey_expr(input_idx), Some(&dynamic_bytes), &env, &mut emitter)?;
    compile_expr(&expected_spk, Some(&p2sh_script_type), &env, &mut emitter)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    Ok(())
}

/// Builds the expression environment and emitter for [`emit_state_framing_guard`].
pub(super) fn compile_state_framing_guard(
    input_idx: &Expr<'_>,
    state_start_offset_expr: &Expr<'_>,
    layout_field_types: &[TypeRef],
    bytecode_size_expr: &Expr<'_>,
    stack_bindings: &StackBindings,
    types: &TypeMap,
    builder: &mut ScriptBuilder,
    bytecode_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
) -> Result<(), CompilerError> {
    let env = ExprEnv { constants: contract_constants, stack_bindings, types, bytecode_size, contract_constants };
    let mut emitter = ScriptEmitter::new(builder, 0);
    emit_state_framing_guard(input_idx, state_start_offset_expr, layout_field_types, bytecode_size_expr, &env, &mut emitter)
}

pub(super) fn read_input_state_field_expr<'i>(
    input_idx: &Expr<'i>,
    field_type: &TypeRef,
    state_start_offset_expr: Expr<'i>,
    field_chunk_offset: usize,
    bytecode_size_expr: Expr<'i>,
    contract_constants: &HashMap<String, Expr<'i>>,
    builtin_name: &str,
) -> Result<Expr<'i>, CompilerError> {
    let field_payload_len = fixed_state_payload_len(field_type, contract_constants).map_err(|err| match err {
        CompilerError::ArithmeticOverflow(_) => err,
        _ => CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", field_type.type_name())),
    })?;
    let field_prefix_len = data_prefix(field_payload_len)?.len();
    let field_data_offset = checked_add(field_chunk_offset, field_prefix_len)?;
    let field_payload_offset = binary_expr(BinaryOp::Add, state_start_offset_expr, Expr::int(field_data_offset as i64));
    let start = binary_expr(BinaryOp::Add, input_sigscript_base_expr(input_idx, bytecode_size_expr), field_payload_offset);
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
///   bytecode_size = template_prefix_len + encoded_state_len(layout_field_types) + template_suffix_len
///   bytecode_base = input_sigscript_len(input_idx) - bytecode_size
///
///   actual_redeem_script = input_sigscript[bytecode_base .. bytecode_base + bytecode_size]
///   prefix = input_sigscript[bytecode_base .. bytecode_base + template_prefix_len]
///   suffix = input_sigscript[
///       bytecode_base + template_prefix_len + encoded_state_len(layout_field_types)
///       ..
///       bytecode_base + bytecode_size
///   ]
///
///   actual_template = i64le(prefix.length) || prefix || i64le(suffix.length) || suffix
///   require blake3(actual_template) == expected_template_hash
///
///   expected_input_spk = ScriptPubKeyP2SHFromRedeemScript(actual_redeem_script)
///   require input_script_pubkey(input_idx) == expected_input_spk
///
///   for each field: require the field's push header at its constant offset
///                   equals the header the state encoder emits for its width
///
/// The template hash and the P2SH commitment authenticate the foreign script's
/// code and its total length; the framing guard is what makes the constant
/// offsets the field reads use meaningful. See [`emit_state_framing_guard`].
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
    current_bytecode_size: Option<i64>,
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

    let bytecode_size_expr =
        templated_input_bytecode_size_expr(template_prefix_len, template_suffix_len, layout_field_types, contract_constants)?;
    let bytecode_base_expr = input_sigscript_base_expr(input_idx, bytecode_size_expr.clone());
    let prefix_end_expr = binary_expr(BinaryOp::Add, bytecode_base_expr.clone(), template_prefix_len.clone());
    let bytecode_end_expr = binary_expr(BinaryOp::Add, bytecode_base_expr.clone(), bytecode_size_expr.clone());
    let state_len = encoded_state_len_for_layout_field_types(layout_field_types, contract_constants)?;
    let suffix_start_expr = binary_expr(BinaryOp::Add, prefix_end_expr.clone(), Expr::int(state_len as i64));
    let suffix_end_expr = binary_expr(BinaryOp::Add, suffix_start_expr.clone(), template_suffix_len.clone());

    let input_redeem_script_expr = input_sigscript_substr_expr(input_idx, bytecode_base_expr.clone(), bytecode_end_expr);
    let prefix_expr = input_sigscript_substr_expr(input_idx, bytecode_base_expr, prefix_end_expr);
    let suffix_expr = input_sigscript_substr_expr(input_idx, suffix_start_expr, suffix_end_expr);
    let encoded_prefix_len_expr = int_to_fixed_bytes_expr(template_prefix_len.clone(), 8);
    let encoded_suffix_len_expr = int_to_fixed_bytes_expr(template_suffix_len.clone(), 8);
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

    let env =
        ExprEnv { constants: contract_constants, stack_bindings, types, bytecode_size: current_bytecode_size, contract_constants };
    let mut emitter = ScriptEmitter::new(builder, 0);
    let dynamic_bytes = byte_array_type(ArrayDim::Dynamic);
    let p2sh_script_type = constructor_return_type("ScriptPubKeyP2SHFromRedeemScript").expect("known constructor type");
    let hash_type = builtin_return_type("blake3").expect("known builtin type");

    compile_expr(&actual_input_spk_expr, Some(&dynamic_bytes), &env, &mut emitter)?;
    compile_expr(&expected_input_spk_expr, Some(&p2sh_script_type), &env, &mut emitter)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    compile_expr(expected_template_hash, Some(&hash_type), &env, &mut emitter)?;
    compile_expr(&template_expr, Some(&dynamic_bytes), &env, &mut emitter)?;
    emitter.emit_op(OpBlake3, 0)?;
    emitter.emit_op(OpEqualVerify, -2)?;

    // The state region starts `template_prefix_len` bytes into the redeem script.
    emit_state_framing_guard(input_idx, template_prefix_len, layout_field_types, &bytecode_size_expr, &env, &mut emitter)?;

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
    state_end: usize,
    bytecode_size: Option<i64>,
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
        bytecode_size,
        contract_constants,
        "validateOutputState",
    )?;

    let total_state_len = encoded_state_len(contract_fields, contract_constants)?;
    let state_start_offset = checked_sub(state_end, total_state_len)?;

    let bytecode_size_value =
        bytecode_size.ok_or_else(|| CompilerError::Unsupported("validateOutputState requires this.bytecodeSize".to_string()))?;
    let mut emitter = ScriptEmitter::new(builder, stack_depth);

    // Rebuild `prefix || encoded_new_state || suffix`. The redeem script starts
    // at `input_sigscript_len - bytecode_size_value`.
    if state_start_offset > 0 {
        // Extract the bytes before the old state and prepend them to the new state.
        emitter.emit_op(OpTxInputIndex, 1)?;
        emitter.emit_op(OpDup, 1)?;
        emitter.emit_op(OpTxInputScriptSigLen, 0)?;
        emitter.push_int(bytecode_size_value)?;
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

    // Compute `suffix_start = input_sigscript_len + state_end - bytecode_size_value`.`
    emitter.push_int(state_end as i64 - bytecode_size_value)?;
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
    let env = ExprEnv { constants, stack_bindings, types, bytecode_size: Some(bytecode_size_value), contract_constants };
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
    bytecode_size: Option<i64>,
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

    let env = ExprEnv { constants, stack_bindings, types, bytecode_size, contract_constants };
    let dynamic_bytes_type = byte_array_type(ArrayDim::Dynamic);
    let hash_type = builtin_return_type("blake3").expect("known builtin type");
    let int_type = scalar_type(TypeBase::Int);

    let encoded_prefix_len = int_to_fixed_bytes_expr(Expr::call("length", vec![template_prefix.clone()]), 8);
    let encoded_suffix_len = int_to_fixed_bytes_expr(Expr::call("length", vec![template_suffix.clone()]), 8);
    let template_preimage = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len, template_prefix.clone()),
        binary_expr(BinaryOp::Add, encoded_suffix_len, template_suffix.clone()),
    );
    {
        let mut emitter = ScriptEmitter::new(builder, 0);
        compile_expr(expected_template_hash, Some(&hash_type), &env, &mut emitter)?;
        compile_expr(&template_preimage, Some(&dynamic_bytes_type), &env, &mut emitter)?;
        emitter.emit_op(OpBlake3, 0)?;
        emitter.emit_op(OpEqualVerify, -2)?;
    }
    let stack_depth = compile_encoded_flat_state_fields(
        state_fields,
        constants,
        stack_bindings,
        types,
        builder,
        bytecode_size,
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
    bytecode_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    compile_encoded_state_fields(
        state_entries.iter().map(|entry| &entry.expr),
        constants,
        stack_bindings,
        types,
        builder,
        bytecode_size,
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
    bytecode_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'_>>,
    builtin_name: &str,
) -> Result<i64, CompilerError> {
    compile_encoded_state_fields(
        state_fields.iter(),
        constants,
        stack_bindings,
        types,
        builder,
        bytecode_size,
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
    bytecode_size: Option<i64>,
    contract_constants: &HashMap<String, Expr<'i>>,
    builtin_name: &str,
) -> Result<i64, CompilerError>
where
    'i: 'a,
{
    let field_count = state_fields.len();
    let env = ExprEnv { constants, stack_bindings, types, bytecode_size, contract_constants };
    let mut emitter = ScriptEmitter::new(builder, 0);
    for new_value in state_fields {
        let type_ref = infer_expr_type(new_value, constants, types)?;
        let field_size = fixed_state_payload_len(&type_ref, contract_constants)
            .map_err(|_| CompilerError::Unsupported(format!("{builtin_name} does not support field type {}", type_ref.type_name())))?;

        let prefix = data_prefix(field_size)?;
        emitter.push_data(&prefix)?;
        compile_expr(new_value, Some(&type_ref), &env, &mut emitter)?;
        if type_ref.is_bool() {
            emitter.emit_op(Op0NotEqual, 0)?;
            emitter.push_int(field_size as i64)?;
            emitter.emit_op(OpNum2Bin, -1)?;
        } else if type_ref.is_int_like() {
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
