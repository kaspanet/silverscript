use super::*;
use crate::compiler::builtin_types::constructor_parameters;

mod builtin;

use builtin::compile_call_expr;

pub(super) fn compile_void_builtin_call<'i>(
    name: &str,
    args: &[Expr<'i>],
    env: &ExprEnv<'_, 'i>,
    emitter: &mut ScriptEmitter<'_>,
) -> Result<(), CompilerError> {
    let initial_depth = emitter.stack_depth();
    let mut visiting = HashSet::new();
    let mut ctx = CompileExprContext { env, emitter, visiting: &mut visiting };
    compile_call_expr(&mut ctx, name, args)?;
    assert!(ctx.emitter.stack_depth() == initial_depth, "void builtin compilation should leave stack depth unchanged");
    Ok(())
}

pub(super) struct ExprEnv<'a, 'i> {
    pub constants: &'a HashMap<String, Expr<'i>>,
    pub stack_bindings: &'a StackBindings,
    pub types: &'a TypeMap,
    pub bytecode_size: Option<i64>,
    pub contract_constants: &'a HashMap<String, Expr<'i>>,
}

pub(super) fn compile_expr<'i>(
    expr: &Expr<'i>,
    expected_type: Option<&TypeRef>,
    env: &ExprEnv<'_, 'i>,
    emitter: &mut ScriptEmitter<'_>,
) -> Result<(), CompilerError> {
    let initial_depth = emitter.stack_depth();
    let mut visiting = HashSet::new();
    let mut ctx = CompileExprContext { env, emitter, visiting: &mut visiting };
    compile_expr_with_context(&mut ctx, expr, expected_type)?;
    assert!(
        ctx.emitter.stack_depth() == initial_depth + 1,
        "expression compilation should leave exactly one additional value on the stack"
    );
    Ok(())
}

fn compile_expr_with_context<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    expr: &Expr<'i>,
    expected_type: Option<&TypeRef>,
) -> Result<(), CompilerError> {
    match &expr.kind {
        ExprKind::Int(value) => compile_int_expr(ctx, *value, expected_type),
        ExprKind::Bool(value) => compile_bool_expr(ctx, *value),
        ExprKind::Byte(byte) => compile_byte_expr(ctx, *byte),
        ExprKind::Array { type_ref, values } => compile_array_expr(ctx, values, Some(type_ref)),
        ExprKind::StructLiteral { .. } => compile_state_object_expr(),
        ExprKind::FieldAccess { .. } => compile_field_access_expr(),
        ExprKind::String(value) => compile_string_expr(ctx, value),
        ExprKind::Identifier(name) => compile_identifier_expr(ctx, name, expected_type),
        ExprKind::Ternary { condition, then_expr, else_expr } => {
            compile_ternary_expr(ctx, condition, then_expr, else_expr, expected_type)
        }
        ExprKind::Call { name, args, .. } => compile_call_expr(ctx, name, args),
        ExprKind::New { name, args, .. } => compile_new_expr(ctx, name, args),
        ExprKind::Unary { op, expr } => compile_unary_expr(ctx, *op, expr),
        ExprKind::Binary { op, left, right } => compile_binary_expr(ctx, *op, left, right),
        ExprKind::Append { source, args, .. } => compile_append_expr(ctx, source, args),
        ExprKind::Split { source, index, part, .. } => compile_split_part(ctx, source, index, *part),
        ExprKind::UnarySuffix { source, kind, .. } => compile_unary_suffix_expr(ctx, source, *kind),
        ExprKind::ArrayIndex { source, index } => compile_array_index_expr(ctx, source, index),
        ExprKind::Slice { source, start, end, .. } => compile_slice_expr(ctx, source, start, end),
        ExprKind::Nullary(op) => compile_nullary_expr(ctx, *op),
        ExprKind::Introspection { kind, index, .. } => compile_introspection_expr(ctx, *kind, index),
        ExprKind::DateLiteral(value) => compile_date_literal_expr(ctx, *value),
        ExprKind::NumberWithUnit { .. } => compile_number_with_unit_expr(),
    }
}

struct CompileExprContext<'a, 'b, 'i> {
    env: &'a ExprEnv<'a, 'i>,
    emitter: &'a mut ScriptEmitter<'b>,
    visiting: &'a mut HashSet<String>,
}

impl CompileExprContext<'_, '_, '_> {
    fn push_int(&mut self, value: i64) -> Result<(), CompilerError> {
        self.emitter.push_int(value)
    }

    fn push_data(&mut self, value: &[u8]) -> Result<(), CompilerError> {
        self.emitter.push_data(value)
    }

    fn emit_op(&mut self, opcode: u8, stack_delta: i64) -> Result<(), CompilerError> {
        self.emitter.emit_op(opcode, stack_delta)
    }
}

fn scalar_type(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn compile_int_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    value: i64,
    expected_type: Option<&TypeRef>,
) -> Result<(), CompilerError> {
    if expected_type.is_some_and(TypeRef::is_byte) {
        let byte = u8::try_from(value)
            .map_err(|_| CompilerError::Unsupported(format!("integer literal {value} is out of range for byte")))?;
        ctx.push_data(&[byte])?;
    } else {
        ctx.push_int(value)?;
    }
    Ok(())
}

fn compile_bool_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, value: bool) -> Result<(), CompilerError> {
    ctx.emit_op(if value { OpTrue } else { OpFalse }, 1)?;
    Ok(())
}

fn compile_byte_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, byte: u8) -> Result<(), CompilerError> {
    ctx.push_data(&[byte])?;
    Ok(())
}

fn compile_array_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    values: &[Expr<'i>],
    expected_type: Option<&TypeRef>,
) -> Result<(), CompilerError> {
    if values.is_empty() {
        ctx.push_data(&[])?;
        return Ok(());
    }
    let array_type = expected_type
        .filter(|type_ref| type_ref.is_array())
        .cloned()
        .or_else(|| infer_array_literal_type(values, ctx.env.constants, ctx.env.types))
        .ok_or_else(|| CompilerError::Unsupported("array literal type cannot be inferred".to_string()))?;

    // First we try to encode the array literal as a single constant value. If that fails, we fall back to compiling it as a runtime expression.
    if let Ok(encoded) = encode_array_literal(values, &array_type, ctx.env.constants) {
        ctx.push_data(&encoded)?;
        return Ok(());
    }
    compile_runtime_array_literal(ctx, values, &array_type)
}

fn compile_runtime_array_literal<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    values: &[Expr<'i>],
    array_type: &TypeRef,
) -> Result<(), CompilerError> {
    let element_type = array_type
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported("array literal type cannot be inferred".to_string()))?;
    for (index, value) in values.iter().enumerate() {
        compile_array_literal_element(ctx, value, &element_type)?;
        if index > 0 {
            ctx.emit_op(OpCat, -1)?;
        }
    }
    Ok(())
}

fn compile_array_literal_element<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    value: &Expr<'i>,
    element_type: &TypeRef,
) -> Result<(), CompilerError> {
    match (&element_type.base, element_type.array_dims.as_slice()) {
        (TypeBase::Int, []) => {
            compile_expr_with_context(ctx, value, Some(element_type))?;
            ctx.push_int(8)?;
            ctx.emit_op(OpNum2Bin, -1)?;
            Ok(())
        }
        (TypeBase::Bool, []) => {
            let cast_expr = Expr::new(
                ExprKind::Call { name: "byte[1]".to_string(), args: vec![value.clone()], name_span: span::Span::default() },
                span::Span::default(),
            );
            compile_expr_with_context(ctx, &cast_expr, None)
        }
        _ => compile_expr_with_context(ctx, value, Some(element_type)),
    }
}

fn infer_array_literal_type<'i>(values: &[Expr<'i>], constants: &HashMap<String, Expr<'i>>, types: &TypeMap) -> Option<TypeRef> {
    let first_type = infer_expr_type(values.first()?, constants, types).ok()?;
    fixed_type_size(&first_type, constants)?;
    if values
        .iter()
        .skip(1)
        .all(|value| infer_expr_type(value, constants, types).is_ok_and(|type_ref| type_refs_equal(&type_ref, &first_type, constants)))
    {
        let mut array_type = first_type;
        array_type.array_dims.push(ArrayDim::Dynamic);
        Some(array_type)
    } else {
        None
    }
}

fn compile_state_object_expr() -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported("state object literals are only supported in validateOutputState-style builtins".to_string()))
}

fn compile_field_access_expr() -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported("struct field access should be lowered before compilation".to_string()))
}

fn compile_string_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, value: &str) -> Result<(), CompilerError> {
    ctx.push_data(value.as_bytes())?;
    Ok(())
}

fn compile_identifier_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    name: &str,
    expected_type: Option<&TypeRef>,
) -> Result<(), CompilerError> {
    if !ctx.visiting.insert(name.to_string()) {
        return Err(CompilerError::CyclicIdentifier(name.to_string()));
    }

    // This will be false if the identifier is a constant that is not stored on the stack.
    let copied_to_stack_top = {
        let (builder, stack_depth) = ctx.emitter.parts();
        ctx.env.stack_bindings.emit_copy_binding_to_top(name, stack_depth, builder)?
    };
    if copied_to_stack_top {
        ctx.visiting.remove(name);
        return Ok(());
    }

    if let Some(resolved_expr) = ctx.env.constants.get(name) {
        compile_expr_with_context(ctx, resolved_expr, expected_type)?;
        ctx.visiting.remove(name);
        return Ok(());
    }

    ctx.visiting.remove(name);
    Err(CompilerError::UndefinedIdentifier(name.to_string()))
}

fn compile_ternary_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    condition: &Expr<'i>,
    then_expr: &Expr<'i>,
    else_expr: &Expr<'i>,
    expected_type: Option<&TypeRef>,
) -> Result<(), CompilerError> {
    let bool_type = scalar_type(TypeBase::Bool);
    compile_expr_with_context(ctx, condition, Some(&bool_type))?;
    ctx.emit_op(OpIf, -1)?;
    let depth_before = ctx.emitter.stack_depth();
    let branch_type = expected_type.cloned().or_else(|| infer_expr_type(then_expr, ctx.env.constants, ctx.env.types).ok());
    compile_expr_with_context(ctx, then_expr, branch_type.as_ref())?;
    ctx.emit_op(OpElse, 0)?;
    ctx.emitter.set_stack_depth(depth_before);
    compile_expr_with_context(ctx, else_expr, branch_type.as_ref())?;
    ctx.emit_op(OpEndIf, 0)?;
    ctx.emitter.set_stack_depth(depth_before + 1);
    Ok(())
}

fn compile_constructor_args<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    let parameters =
        constructor_parameters(name).ok_or_else(|| CompilerError::Unsupported(format!("missing signature for constructor {name}")))?;
    if parameters.len() != args.len() {
        return Err(CompilerError::Unsupported(format!("{name} expects {} argument(s)", parameters.len())));
    }
    for (arg, (_, expected_type)) in args.iter().zip(&parameters) {
        compile_expr_with_context(ctx, arg, Some(expected_type))?;
    }
    Ok(())
}

fn compile_new_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
    match name {
        "ScriptPubKeyP2PK" => {
            ctx.push_data(&[0x00, 0x00, OpData32])?;
            compile_constructor_args(ctx, name, args)?;
            ctx.emit_op(OpCat, -1)?;
            ctx.push_data(&[OpCheckSig])?;
            ctx.emit_op(OpCat, -1)?;
            Ok(())
        }
        "ScriptPubKeyP2SH" => {
            compile_constructor_args(ctx, name, args)?;
            emit_p2sh_locking_script(ctx)
        }
        "ScriptPubKeyP2SHFromRedeemScript" => {
            compile_constructor_args(ctx, name, args)?;
            ctx.emit_op(OpBlake2b, 0)?;
            emit_p2sh_locking_script(ctx)
        }
        other => Err(CompilerError::Unsupported(format!("unknown constructor: {other}"))),
    }
}

fn emit_p2sh_locking_script(ctx: &mut CompileExprContext<'_, '_, '_>) -> Result<(), CompilerError> {
    ctx.push_data(&[0x00, 0x00])?;
    ctx.push_data(&[OpBlake2b])?;
    ctx.emit_op(OpCat, -1)?;
    ctx.push_data(&[0x20])?;
    ctx.emit_op(OpCat, -1)?;
    ctx.emit_op(OpSwap, 0)?;
    ctx.emit_op(OpCat, -1)?;
    ctx.push_data(&[OpEqual])?;
    ctx.emit_op(OpCat, -1)
}

fn compile_unary_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, op: UnaryOp, expr: &Expr<'i>) -> Result<(), CompilerError> {
    let operand_type = scalar_type(match op {
        UnaryOp::Not => TypeBase::Bool,
        UnaryOp::Neg => TypeBase::Int,
    });
    compile_expr_with_context(ctx, expr, Some(&operand_type))?;
    match op {
        UnaryOp::Not => ctx.emit_op(OpNot, 0)?,
        UnaryOp::Neg => ctx.emit_op(OpNegate, 0)?,
    };
    Ok(())
}

fn compile_binary_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    op: BinaryOp,
    left: &Expr<'i>,
    right: &Expr<'i>,
) -> Result<(), CompilerError> {
    let left_value_type = infer_expr_type(left, ctx.env.constants, ctx.env.types).ok();
    let right_value_type = if matches!(op, BinaryOp::Add)
        && let Some(element_type) = left_value_type.as_ref().and_then(TypeRef::array_element_type)
        && let ExprKind::Array { values, .. } = &right.kind
    {
        let mut type_ref = element_type;
        type_ref.array_dims.push(ArrayDim::Fixed(values.len()));
        Some(type_ref)
    } else {
        infer_expr_type(right, ctx.env.constants, ctx.env.types).ok()
    };
    debug_assert!(
        !matches!(op, BinaryOp::Add)
            || (!left_value_type.as_ref().is_some_and(TypeRef::is_byte) && !right_value_type.as_ref().is_some_and(TypeRef::is_byte)),
        "type_check must reject byte addition"
    );
    let bool_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne)
        && left_value_type.as_ref().is_some_and(TypeRef::is_bool)
        && right_value_type.as_ref().is_some_and(TypeRef::is_bool);
    let bytes_eq = matches!(op, BinaryOp::Eq | BinaryOp::Ne) && left_value_type.as_ref().is_some_and(uses_bytewise_equality);
    let bytes_add = matches!(op, BinaryOp::Add) && left_value_type.as_ref().is_some_and(uses_concat_for_add);
    if bytes_add {
        compile_expr_with_context(ctx, left, left_value_type.as_ref())?;
        compile_expr_with_context(ctx, right, right_value_type.as_ref())?;
    } else {
        let bool_type = scalar_type(TypeBase::Bool);
        let int_type = scalar_type(TypeBase::Int);
        let operand_type = match op {
            BinaryOp::Or | BinaryOp::And => Some(&bool_type),
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => Some(&int_type),
            BinaryOp::BitOr | BinaryOp::BitXor | BinaryOp::BitAnd => left_value_type.as_ref(),
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => None,
        };
        compile_expr_with_context(ctx, left, operand_type)?;
        let right_expected_type =
            if matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge) {
                left_value_type.as_ref()
            } else {
                operand_type
            };
        compile_expr_with_context(ctx, right, right_expected_type)?;
    }

    if bool_eq {
        // Normalize operands to 0 or 1, so that we can use OpNumEqual and OpNumNotEqual for both equality and inequality.
        ctx.emit_op(OpNot, 0)?;
        ctx.emit_op(OpNot, 0)?;
        ctx.emit_op(OpSwap, 0)?;
        ctx.emit_op(OpNot, 0)?;
        ctx.emit_op(OpNot, 0)?;
    }

    match op {
        BinaryOp::Or => {
            ctx.emit_op(OpBoolOr, -1)?;
        }
        BinaryOp::And => {
            ctx.emit_op(OpBoolAnd, -1)?;
        }
        BinaryOp::BitOr => {
            ctx.emit_op(OpOr, -1)?;
        }
        BinaryOp::BitXor => {
            ctx.emit_op(OpXor, -1)?;
        }
        BinaryOp::BitAnd => {
            ctx.emit_op(OpAnd, -1)?;
        }
        BinaryOp::Eq => {
            ctx.emit_op(if bytes_eq { OpEqual } else { OpNumEqual }, -1)?;
        }
        BinaryOp::Ne => {
            if bytes_eq {
                ctx.emit_op(OpEqual, -1)?;
                ctx.emit_op(OpNot, 0)?;
            } else {
                ctx.emit_op(OpNumNotEqual, -1)?;
            }
        }
        BinaryOp::Lt => {
            ctx.emit_op(OpLessThan, -1)?;
        }
        BinaryOp::Le => {
            ctx.emit_op(OpLessThanOrEqual, -1)?;
        }
        BinaryOp::Gt => {
            ctx.emit_op(OpGreaterThan, -1)?;
        }
        BinaryOp::Ge => {
            ctx.emit_op(OpGreaterThanOrEqual, -1)?;
        }
        BinaryOp::Add => {
            ctx.emit_op(if bytes_add { OpCat } else { OpAdd }, -1)?;
        }
        BinaryOp::Sub => {
            ctx.emit_op(OpSub, -1)?;
        }
        BinaryOp::Mul => {
            ctx.emit_op(OpMul, -1)?;
        }
        BinaryOp::Div => {
            ctx.emit_op(OpDiv, -1)?;
        }
        BinaryOp::Mod => {
            ctx.emit_op(OpMod, -1)?;
        }
    }
    Ok(())
}

// TODO: Get rid of this function, since it should already be handled by earlier lowering.
fn compile_append_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    source: &Expr<'i>,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let source_type = infer_expr_type(source, ctx.env.constants, ctx.env.types)?;
    let mut appended_type =
        source_type.array_element_type().ok_or_else(|| CompilerError::Unsupported("append target must be an array".to_string()))?;
    appended_type.array_dims.push(ArrayDim::Fixed(args.len()));
    let appended = Expr::array(appended_type.clone(), args.to_vec());

    compile_expr_with_context(ctx, source, Some(&source_type))?;
    compile_expr_with_context(ctx, &appended, Some(&appended_type))?;
    ctx.emit_op(OpCat, -1)?;
    Ok(())
}

fn compile_unary_suffix_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    source: &Expr<'i>,
    kind: UnarySuffixKind,
) -> Result<(), CompilerError> {
    match kind {
        UnarySuffixKind::Length => compile_length_expr(ctx, source),
        UnarySuffixKind::Reverse => Err(CompilerError::Unsupported("reverse() is not supported".to_string())),
    }
}

fn compile_array_index_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    source: &Expr<'i>,
    index: &Expr<'i>,
) -> Result<(), CompilerError> {
    let source_type = infer_expr_type(source, ctx.env.constants, ctx.env.types)?;
    let element_type = source_type
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported(format!("array index requires array source, got {}", source_type.type_name())))?;
    let element_size = i64::try_from(
        fixed_type_size(&element_type, ctx.env.constants)
            .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?,
    )
    .map_err(|_| CompilerError::Unsupported("array element size is too large".to_string()))?;
    compile_expr_with_context(ctx, source, Some(&source_type))?;
    let int_type = scalar_type(TypeBase::Int);
    compile_expr_with_context(ctx, index, Some(&int_type))?;
    ctx.push_int(element_size)?;
    ctx.emit_op(OpMul, -1)?;
    ctx.emit_op(OpDup, 1)?;
    ctx.push_int(element_size)?;
    ctx.emit_op(OpAdd, -1)?;
    ctx.emit_op(OpSubstr, -2)?;
    Ok(())
}

fn compile_slice_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    source: &Expr<'i>,
    start: &Expr<'i>,
    end: &Expr<'i>,
) -> Result<(), CompilerError> {
    let source_type = infer_expr_type(source, ctx.env.constants, ctx.env.types)?;
    let element_size = array_element_size(&source_type, ctx.env.contract_constants);
    let int_type = scalar_type(TypeBase::Int);
    compile_expr_with_context(ctx, source, Some(&source_type))?;
    compile_expr_with_context(ctx, start, Some(&int_type))?;
    if let Some(element_size) = element_size.filter(|size| *size != 1) {
        ctx.push_int(element_size)?;
        ctx.emit_op(OpMul, -1)?;
    }
    compile_expr_with_context(ctx, end, Some(&int_type))?;
    if let Some(element_size) = element_size.filter(|size| *size != 1) {
        ctx.push_int(element_size)?;
        ctx.emit_op(OpMul, -1)?;
    }
    ctx.emit_op(OpSubstr, -2)?;
    Ok(())
}

fn compile_nullary_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, op: NullaryOp) -> Result<(), CompilerError> {
    match op {
        NullaryOp::ActiveInputIndex => {
            ctx.emit_op(OpTxInputIndex, 1)?;
        }
        NullaryOp::ActiveScriptPubKey => {
            ctx.emit_op(OpTxInputIndex, 1)?;
            ctx.emit_op(OpTxInputSpk, 0)?;
        }
        NullaryOp::ThisBytecodeSize => {
            let size = ctx
                .env
                .bytecode_size
                .ok_or_else(|| CompilerError::Unsupported("this.bytecodeSize is only available at compile time".to_string()))?;
            ctx.push_int(size)?;
        }
        NullaryOp::ThisBytecodeSizeDataPrefix => {
            let size = ctx.env.bytecode_size.ok_or_else(|| {
                CompilerError::Unsupported("this.bytecodeSizeDataPrefix is only available at compile time".to_string())
            })?;
            let size: usize = size.try_into().map_err(|_| {
                CompilerError::Unsupported("this.bytecodeSizeDataPrefix requires a non-negative bytecode size".to_string())
            })?;
            let prefix = data_prefix(size)?;
            ctx.push_data(&prefix)?;
        }
        NullaryOp::TxInputsLength => {
            ctx.emit_op(OpTxInputCount, 1)?;
        }
        NullaryOp::TxOutputsLength => {
            ctx.emit_op(OpTxOutputCount, 1)?;
        }
        NullaryOp::TxVersion => {
            ctx.emit_op(OpTxVersion, 1)?;
        }
        NullaryOp::TxLockTime => {
            ctx.emit_op(OpTxLockTime, 1)?;
        }
    }
    Ok(())
}

fn compile_introspection_expr<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    kind: IntrospectionKind,
    index: &Expr<'i>,
) -> Result<(), CompilerError> {
    let int_type = scalar_type(TypeBase::Int);
    compile_expr_with_context(ctx, index, Some(&int_type))?;
    match kind {
        IntrospectionKind::InputValue => {
            ctx.emit_op(OpTxInputAmount, 0)?;
        }
        IntrospectionKind::InputScriptPubKey => {
            ctx.emit_op(OpTxInputSpk, 0)?;
        }
        IntrospectionKind::InputSigScript => {
            ctx.emit_op(OpDup, 1)?;
            ctx.emit_op(OpTxInputScriptSigLen, 0)?;
            ctx.push_int(0)?;
            ctx.emit_op(OpSwap, 0)?;
            ctx.emit_op(OpTxInputScriptSigSubstr, -2)?;
        }
        IntrospectionKind::InputOutpointTransactionHash => {
            ctx.emit_op(OpOutpointTxId, 0)?;
        }
        IntrospectionKind::InputOutpointIndex => {
            ctx.emit_op(OpOutpointIndex, 0)?;
        }
        IntrospectionKind::InputSequenceNumber => {
            ctx.emit_op(OpTxInputSeq, 0)?;
        }
        IntrospectionKind::OutputValue => {
            ctx.emit_op(OpTxOutputAmount, 0)?;
        }
        IntrospectionKind::OutputScriptPubKey => {
            ctx.emit_op(OpTxOutputSpk, 0)?;
        }
    }
    Ok(())
}

fn compile_date_literal_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, value: i64) -> Result<(), CompilerError> {
    ctx.push_int(value)?;
    Ok(())
}

fn compile_number_with_unit_expr() -> Result<(), CompilerError> {
    Err(CompilerError::Unsupported("number units must be normalized during parsing".to_string()))
}

fn compile_split_part<'i>(
    ctx: &mut CompileExprContext<'_, '_, 'i>,
    source: &Expr<'i>,
    index: &Expr<'i>,
    part: SplitPart,
) -> Result<(), CompilerError> {
    let source_type = infer_expr_type(source, ctx.env.constants, ctx.env.types)?;
    let element_size = array_element_size(&source_type, ctx.env.contract_constants);
    let int_type = scalar_type(TypeBase::Int);
    compile_expr_with_context(ctx, source, Some(&source_type))?;
    match part {
        SplitPart::Left => {
            ctx.push_int(0)?;
            compile_expr_with_context(ctx, index, Some(&int_type))?;
            if let Some(element_size) = element_size.filter(|size| *size != 1) {
                ctx.push_int(element_size)?;
                ctx.emit_op(OpMul, -1)?;
            }
            ctx.emit_op(OpSubstr, -2)?;
            Ok(())
        }
        SplitPart::Right => {
            ctx.emit_op(OpSize, 1)?;
            compile_expr_with_context(ctx, index, Some(&int_type))?;
            if let Some(element_size) = element_size.filter(|size| *size != 1) {
                ctx.push_int(element_size)?;
                ctx.emit_op(OpMul, -1)?;
            }
            ctx.emit_op(OpSwap, 0)?;
            ctx.emit_op(OpSubstr, -2)?;
            Ok(())
        }
    }
}

fn compile_length_expr<'i>(ctx: &mut CompileExprContext<'_, '_, 'i>, expr: &Expr<'i>) -> Result<(), CompilerError> {
    let expr_type = infer_expr_type(expr, ctx.env.constants, ctx.env.types)?;
    if let Some(size) = array_type_size(&expr_type, ctx.env.contract_constants) {
        let is_literal_or_identifier = matches!(expr.kind, ExprKind::Identifier(_) | ExprKind::Array { .. });
        if !is_literal_or_identifier {
            compile_expr_with_context(ctx, expr, Some(&expr_type))?;
            ctx.emit_op(OpDrop, -1)?;
        }
        ctx.push_int(size as i64)?;
        return Ok(());
    }
    if let ExprKind::Identifier(name) = &expr.kind {
        if let Some(type_ref) = ctx.env.types.get(name) {
            if let Some(element_size) = array_element_size(type_ref, ctx.env.contract_constants) {
                compile_expr_with_context(ctx, expr, Some(type_ref))?;
                ctx.emit_op(OpSize, 1)?;
                ctx.emit_op(OpSwap, 0)?;
                ctx.emit_op(OpDrop, -1)?;
                ctx.push_int(element_size)?;
                ctx.emit_op(OpDiv, -1)?;
                return Ok(());
            }
        }
    }
    compile_expr_with_context(ctx, expr, None)?;
    ctx.emit_op(OpSize, 1)?;
    ctx.emit_op(OpSwap, 0)?;
    ctx.emit_op(OpDrop, -1)?;
    Ok(())
}

fn is_byte_encoded_type(type_ref: &TypeRef) -> bool {
    type_ref.is_array() || type_ref.is_byte() || type_ref.is_string() || type_ref.base.fixed_byte_sequence_len().is_some()
}

fn uses_bytewise_equality(type_ref: &TypeRef) -> bool {
    is_byte_encoded_type(type_ref)
}

fn uses_concat_for_add(type_ref: &TypeRef) -> bool {
    type_ref.is_array() || type_ref.is_string()
}

fn byte_sequence_cast_size<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<Option<i64>> {
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
        Some(element) if element.is_byte() => Some(array_type_size(type_ref, constants).and_then(|size| i64::try_from(size).ok())),
        _ => None,
    }
}

pub(super) fn data_prefix(data_len: usize) -> Result<Vec<u8>, CompilerError> {
    let dummy_data = vec![0u8; data_len];
    let mut builder = script_builder();
    builder.add_data_with_push_opcode(&dummy_data)?;
    let bytecode = builder.drain();
    Ok(bytecode[..bytecode.len() - data_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_prefix_encodes_small_pushes() {
        assert_eq!(data_prefix(0).unwrap(), vec![Op0]);
        assert_eq!(data_prefix(1).unwrap(), vec![OpData1]);
        assert_eq!(data_prefix(2).unwrap(), vec![2u8]);
        assert_eq!(data_prefix(75).unwrap(), vec![75u8]);
    }

    #[test]
    fn data_prefix_encodes_pushdata1() {
        assert_eq!(data_prefix(76).unwrap(), vec![OpPushData1, 76u8]);
        assert_eq!(data_prefix(255).unwrap(), vec![OpPushData1, 255u8]);
    }

    #[test]
    fn data_prefix_encodes_pushdata2() {
        assert_eq!(data_prefix(256).unwrap(), vec![OpPushData2, 0x00, 0x01]);
    }
}
