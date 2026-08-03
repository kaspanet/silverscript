use super::*;
use crate::compiler::builtin_types::builtin_parameters;
use kaspa_txscript::zk_precompiles::tags::ZkTag;
use kaspa_txscript_zk_sdk::append_r0_groth16_verifier_dynamic_image_id;

pub(super) fn compile_call_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    if let Some(cast_type) = as_cast_type(name) {
        return compile_as_cast(ctx, args, &cast_type);
    }
    if let Some(opcode) = opcode_builtin(name) {
        return compile_opcode_call(ctx, name, args, opcode);
    }

    match name {
        "sha256" => compile_sha256_call(ctx, args),
        "length" => compile_length_call(ctx, args),
        "int" | "byte" | "bool" | "string" | "sig" | "pubkey" | "datasig" => compile_passthrough_cast_call(ctx, name, args),
        name if parse_type_ref(name)
            .is_ok_and(|type_ref| matches!(type_ref.base, TypeBase::Byte) && type_ref.array_dims.len() == 1) =>
        {
            compile_byte_sequence_cast_call(ctx, name, args)
        }
        name if parse_type_ref(name).is_ok_and(|type_ref| type_ref.is_array()) => compile_array_cast_call(ctx, name, args),
        "blake2b" => compile_blake2b_call(ctx, args),
        "blake2bWithKey" => compile_blake2b_with_key_call(ctx, args),
        "blake3" => compile_blake3_call(ctx, args),
        "blake3WithKey" => compile_blake3_with_key_call(ctx, args),
        "templateHash" => compile_template_hash_call(ctx, args),
        "checkSig" => compile_checksig_call(ctx, args),
        "checkMsgSig" => compile_checksigfromstack_call(ctx, name, args, OpCheckSigFromStack),
        "checkSigFromStackECDSA" => compile_checksigfromstack_call(ctx, name, args, OpCheckSigFromStackECDSA),
        "r0.g16.verify" => compile_r0_groth16_verify_call(ctx, args),
        "r0.succinct.verify" | "r0.succinct.blake2b.verify" | "r0.succinct.poseidon2.verify" | "r0.succinct.sha256.verify" => {
            compile_r0_succinct_verify_call(ctx, name, args)
        }
        _ => compile_unknown_function_call(name),
    }
}

fn opcode_builtin(name: &str) -> Option<u8> {
    Some(match name {
        "OpTxSubnetId" => OpTxSubnetId,
        "OpTxGas" => OpTxGas,
        "OpTxPayloadLen" => OpTxPayloadLen,
        "OpTxPayloadSubstr" => OpTxPayloadSubstr,
        "OpOutpointTxId" => OpOutpointTxId,
        "OpOutpointIndex" => OpOutpointIndex,
        "OpTxInputScriptSigLen" => OpTxInputScriptSigLen,
        "OpTxInputScriptSigSubstr" => OpTxInputScriptSigSubstr,
        "OpTxInputSeq" => OpTxInputSeq,
        "OpTxInputDaaScore" => OpTxInputDaaScore,
        "OpTxInputIsCoinbase" => OpTxInputIsCoinbase,
        "OpTxInputSpkLen" => OpTxInputSpkLen,
        "OpTxInputSpkSubstr" => OpTxInputSpkSubstr,
        "OpTxOutputSpkLen" => OpTxOutputSpkLen,
        "OpTxOutputSpkSubstr" => OpTxOutputSpkSubstr,
        "OpAuthOutputCount" => OpAuthOutputCount,
        "OpAuthOutputIdx" => OpAuthOutputIdx,
        "OpInputCovenantId" => OpInputCovenantId,
        "OpOutputCovenantId" => OpOutputCovenantId,
        "OpCovInputCount" => OpCovInputCount,
        "OpCovInputIdx" => OpCovInputIdx,
        "OpCovOutputCount" => OpCovOutputCount,
        "OpCovOutputIdx" => OpCovOutputIdx,
        "OpNum2Bin" => OpNum2Bin,
        "OpBin2Num" => OpBin2Num,
        "OpChainblockSeqCommit" => OpChainblockSeqCommit,
        _ => return None,
    })
}

fn compile_call_arg_with_context<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, arg: &Expr<'i>) -> Result<(), CompilerError> {
    compile_expr_with_context(ctx, arg, None)
}

fn compile_typed_builtin_args<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let parameters = builtin_parameters(name).ok_or_else(|| CompilerError::Unsupported(format!("missing signature for {name}()")))?;
    if parameters.len() != args.len() {
        return Err(CompilerError::Unsupported(format!("{name}() expects {} arguments", parameters.len())));
    }
    for (arg, (_, expected_type)) in args.iter().zip(&parameters) {
        compile_expr_with_context(ctx, arg, Some(expected_type))?;
    }
    Ok(())
}

fn compile_sha256_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("sha256() expects a single argument".to_string()));
    }
    compile_typed_builtin_args(ctx, "sha256", args)?;
    ctx.emit_op(OpSHA256, 0)?;
    Ok(())
}

fn compile_as_cast<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>], cast_type: &TypeRef) -> Result<(), CompilerError> {
    let [source] = args else {
        return Err(CompilerError::Unsupported("'as' conversion expects one source expression".to_string()));
    };
    let size = array_type_size(cast_type, ctx.env.constants)
        .ok_or_else(|| CompilerError::Unsupported("byte size in 'as byte[N]' must be known at compile time".to_string()))?;
    compile_call_arg_with_context(ctx, source)?;
    ctx.push_int(i64::try_from(size).map_err(|_| CompilerError::Unsupported("byte size is too large".to_string()))?)?;
    ctx.emit_op(OpNum2Bin, -1)?;
    Ok(())
}

fn compile_length_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("length() expects a single argument".to_string()));
    }
    compile_length_expr(ctx, &args[0])
}

fn compile_passthrough_cast_call<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
    }
    compile_call_arg_with_context(ctx, &args[0])
}

fn compile_byte_sequence_cast_call<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let size_part = &name[5..name.len() - 1];
    if size_part.is_empty() {
        if args.len() != 1 {
            return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
        }
        compile_call_arg_with_context(ctx, &args[0])?;
        return Ok(());
    }

    let size = size_part.parse::<i64>().map_err(|_| CompilerError::Unsupported(format!("{name}() is not supported")))?;
    if args.len() != 1 {
        return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
    }
    if size == 1
        && let ExprKind::Int(value) = args[0].kind
    {
        let byte = u8::try_from(value)
            .map_err(|_| CompilerError::Unsupported(format!("integer literal {value} is out of range for byte")))?;
        return ctx.push_data(&[byte]);
    }
    let source_type = infer_expr_type(&args[0], ctx.env.constants, ctx.env.types)?;
    if let Some(source_size) = byte_sequence_cast_size(&source_type, ctx.env.constants)
        && let Some(source_size) = source_size
        && source_size != size
    {
        return Err(CompilerError::Unsupported(format!("cannot cast {} to {name}", source_type.type_name())));
    }
    compile_call_arg_with_context(ctx, &args[0])
}

fn compile_array_cast_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported(format!("{name}() expects a single argument")));
    }
    compile_call_arg_with_context(ctx, &args[0])
}

fn compile_blake2b_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("blake2b() expects a single argument".to_string()));
    }
    compile_typed_builtin_args(ctx, "blake2b", args)?;
    ctx.emit_op(OpBlake2b, 0)?;
    Ok(())
}

fn compile_blake2b_with_key_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 2 {
        return Err(CompilerError::Unsupported("blake2bWithKey() expects 2 arguments".to_string()));
    }
    compile_typed_builtin_args(ctx, "blake2bWithKey", args)?;
    ctx.emit_op(OpBlake2bWithKey, -1)?;
    Ok(())
}

fn compile_blake3_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 1 {
        return Err(CompilerError::Unsupported("blake3() expects a single argument".to_string()));
    }
    compile_typed_builtin_args(ctx, "blake3", args)?;
    ctx.emit_op(OpBlake3, 0)?;
    Ok(())
}

fn compile_blake3_with_key_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 2 {
        return Err(CompilerError::Unsupported("blake3WithKey() expects 2 arguments".to_string()));
    }
    compile_typed_builtin_args(ctx, "blake3WithKey", args)?;
    ctx.emit_op(OpBlake3WithKey, -1)?;
    Ok(())
}

fn compile_template_hash_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    let Ok([prefix, suffix]): Result<&[Expr<'i>; 2], _> = args.try_into() else {
        return Err(CompilerError::Unsupported("templateHash() expects 2 arguments".to_string()));
    };

    let encoded_prefix_len = int_to_fixed_bytes_expr(Expr::call("length", vec![prefix.clone()]), 8);
    let encoded_suffix_len = int_to_fixed_bytes_expr(Expr::call("length", vec![suffix.clone()]), 8);
    let preimage = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, encoded_prefix_len, prefix.clone()),
        binary_expr(BinaryOp::Add, encoded_suffix_len, suffix.clone()),
    );
    compile_call_arg_with_context(ctx, &preimage)?;
    ctx.emit_op(OpBlake2b, 0)?;
    Ok(())
}

fn compile_checksig_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    if args.len() != 2 {
        return Err(CompilerError::Unsupported("checkSig() expects 2 arguments".to_string()));
    }
    compile_typed_builtin_args(ctx, "checkSig", args)?;
    ctx.emit_op(OpCheckSig, -1)?;
    Ok(())
}

fn compile_checksigfromstack_call<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
    opcode: u8,
) -> Result<(), CompilerError> {
    if args.len() != 3 {
        return Err(CompilerError::Unsupported(format!("{name}() expects 3 arguments (signature, digest, publicKey)")));
    }
    compile_typed_builtin_args(ctx, name, args)?;
    ctx.emit_op(opcode, -2)?;
    Ok(())
}

fn compile_r0_groth16_verify_call<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    compile_typed_builtin_args(ctx, "r0.g16.verify", args)?;
    let (builder, stack_depth) = ctx.emitter.parts();
    append_r0_groth16_verifier_dynamic_image_id(builder)
        .map_err(|err| CompilerError::Unsupported(format!("failed to append r0 Groth16 verifier: {err}")))?;
    *stack_depth -= 2;
    ctx.emit_op(OpDrop, -1)?; // OpDrop the OpTrue that is pushed by the verifier
    Ok(())
}

fn compile_r0_succinct_verify_call<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let hash_fn_id = match name {
        "r0.succinct.verify" | "r0.succinct.poseidon2.verify" => 1,
        "r0.succinct.blake2b.verify" | "r0.succinct.sha256.verify" => {
            return Err(CompilerError::Unsupported(format!(
                "{name}() is reserved for future use by the Kaspa script engine; only Poseidon2 R0 Succinct verification is currently supported"
            )));
        }
        _ => return Err(CompilerError::Unsupported(format!("unknown R0 Succinct verifier '{name}'"))),
    };

    compile_typed_builtin_args(ctx, name, args)?;
    ctx.push_data(&[hash_fn_id])?;
    ctx.push_data(&[ZkTag::R0Succinct as u8])?;
    ctx.emit_op(OpZkPrecompile, -8)?;
    ctx.emit_op(OpDrop, -1)?; // OpDrop the OpTrue that is pushed by the verifier
    Ok(())
}

fn compile_unknown_function_call(name: &str) -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported(format!("unknown function call: {name}")))
}

fn compile_opcode_call<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    args: &[Expr<'i>],
    opcode: u8,
) -> Result<(), CompilerError> {
    compile_typed_builtin_args(ctx, name, args)?;
    ctx.emit_op(opcode, 1 - args.len() as i64)?;
    Ok(())
}
