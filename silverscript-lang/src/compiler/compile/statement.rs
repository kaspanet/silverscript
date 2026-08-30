use super::*;
use crate::compiler::builtin_types::{BuiltinReturn, builtin_return};

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_entrypoint_function<'i>(
    function: &FunctionAst<'i>,
    contract_params: &[ParamAst<'i>],
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &[ConstantAst<'i>],
    state_end: usize,
    constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    bytecode_size: Option<i64>,
    struct_array_param_groups: &[Vec<String>],
    debug_recorder: &mut DebugRecorder<'i>,
) -> Result<(String, Vec<u8>), CompilerError> {
    debug_recorder.begin_entrypoint(function, contract_fields, structs)?;
    let mut types = HashMap::new();
    for param in contract_params {
        types.insert(param.name.clone(), param.type_ref.clone());
    }
    for constant in contract_constants {
        types.insert(constant.name.clone(), constant.type_ref.clone());
    }
    for param in &function.params {
        types.insert(param.name.clone(), param.type_ref.clone());
    }

    let param_count = function.params.len();
    let mut stack_bindings = StackBindings::from_depths(
        function
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| (param.name.clone(), (param_count - 1 - index) as i64))
            .collect::<HashMap<_, _>>(),
    );

    for field in contract_fields {
        stack_bindings.push_binding(&field.name);
    }

    for field in contract_fields {
        types.insert(field.name.clone(), field.type_ref.clone());
    }
    let mut builder = script_builder();
    compile_param_size_validations(function, constants, struct_array_param_groups, &stack_bindings, &mut builder)?;
    let mut return_exprs: Vec<Expr> = Vec::new();

    let body_len = function.body.len();
    let mut statement_ctx = CompileStatementContext {
        types: &mut types,
        stack_bindings: &mut stack_bindings,
        builder: &mut builder,
        contract_fields,
        state_end,
        contract_constants: constants,
        structs,
        bytecode_size,
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

    let return_count = return_exprs.len();
    if return_count == 0 {
        for _ in 0..stack_bindings.len() {
            builder.add_op(OpDrop)?;
        }
        builder.add_op(OpTrue)?;
    } else {
        let env = ExprEnv { constants, stack_bindings: &stack_bindings, types: &types, bytecode_size, contract_constants: constants };
        let mut emitter = ScriptEmitter::new(&mut builder, 0);
        for (expr, expected_type) in return_exprs.iter().zip(&function.return_types) {
            compile_expr(expr, Some(expected_type), &env, &mut emitter)?;
        }
        for _ in 0..stack_bindings.len() {
            builder.add_i64(return_count as i64)?;
            builder.add_op(OpRoll)?;
            builder.add_op(OpDrop)?;
        }
    }
    let bytecode = builder.drain();
    debug_recorder.finish_entrypoint(bytecode.len());
    Ok((function.name.clone(), bytecode))
}

fn compile_param_size_validations<'i>(
    function: &FunctionAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
    struct_array_param_groups: &[Vec<String>],
    stack_bindings: &StackBindings,
    builder: &mut ScriptBuilder,
) -> Result<(), CompilerError> {
    let grouped_leaf_names = struct_array_param_groups.iter().flatten().map(String::as_str).collect::<HashSet<_>>();

    for param in &function.params {
        // Grouped leaves are always dynamic arrays. Their OP_MOD shape check
        // is fused with the cardinality check below so OP_SIZE can be reused.
        if grouped_leaf_names.contains(param.name.as_str()) {
            continue;
        }

        let exact_size = if param.type_ref.is_array() {
            fixed_type_size(&param.type_ref, constants)?
        } else if param.type_ref.is_byte() {
            Some(1)
        } else {
            param.type_ref.base.fixed_byte_sequence_len()
        };
        let is_dynamic_array = param.type_ref.is_dynamic_array();
        if exact_size.is_none() && !is_dynamic_array && !param.type_ref.is_int_like() && !param.type_ref.is_bool() {
            continue;
        }

        let mut stack_depth = 0;
        let copied = stack_bindings.emit_copy_binding_to_top(&param.name, &mut stack_depth, builder)?;
        debug_assert!(copied, "entrypoint parameter must have a stack binding");

        builder.add_op(OpSize)?;
        if let Some(expected_size) = exact_size {
            let expected_size = i64::try_from(expected_size)
                .map_err(|_| CompilerError::Unsupported(format!("entrypoint parameter '{}' is too large", param.name)))?;
            builder.add_i64(expected_size)?;
            builder.add_op(OpNumEqualVerify)?;
        } else if is_dynamic_array {
            let element_size = array_element_size(&param.type_ref, constants)?
                .expect("type_check must validate dynamic array element types have known size");
            builder.add_i64(element_size)?;
            builder.add_op(OpMod)?;
            builder.add_i64(0)?;
            builder.add_op(OpNumEqualVerify)?;
        } else {
            // VM script numbers may use zero through eight bytes. Bools use
            // the empty encoding for false and a single byte for true. Reject
            // wider values before their interpretation can depend on the
            // opcode consuming them.
            let exclusive_max_size = if param.type_ref.is_bool() { 2 } else { 9 };
            builder.add_i64(exclusive_max_size)?;
            builder.add_op(OpLessThan)?;
            builder.add_op(OpVerify)?;
        }
        builder.add_op(OpDrop)?;
    }

    for leaf_names in struct_array_param_groups {
        let Some((first, rest)) = leaf_names.split_first() else {
            continue;
        };
        let mut transient_stack_depth = 0;
        emit_checked_dynamic_array_length(function, first, constants, stack_bindings, &mut transient_stack_depth, builder)?;
        for leaf_name in rest {
            builder.add_op(OpDup)?;
            transient_stack_depth += 1;
            emit_checked_dynamic_array_length(function, leaf_name, constants, stack_bindings, &mut transient_stack_depth, builder)?;
            builder.add_op(OpNumEqualVerify)?;
            transient_stack_depth -= 2;
        }
        debug_assert_eq!(transient_stack_depth, 1);
        builder.add_op(OpDrop)?;
    }

    Ok(())
}

/// Copies a dynamic-array parameter, verifies that its encoded byte size is
/// divisible by its fixed element stride, and leaves the resulting element
/// count on top of the stack. On success, `stack_depth` therefore increases
/// by exactly one.
fn emit_checked_dynamic_array_length<'i>(
    function: &FunctionAst<'i>,
    param_name: &str,
    constants: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    stack_depth: &mut i64,
    builder: &mut ScriptBuilder,
) -> Result<(), CompilerError> {
    let param = function
        .params
        .iter()
        .find(|param| param.name == param_name)
        .expect("struct lowering must retain every grouped leaf parameter");
    let element_size =
        array_element_size(&param.type_ref, constants)?.expect("type checking must validate dynamic struct-array leaf element sizes");

    let copied = stack_bindings.emit_copy_binding_to_top(param_name, stack_depth, builder)?;
    debug_assert!(copied, "entrypoint parameter must have a stack binding");
    builder.add_op(OpSize)?;
    builder.add_op(OpDup)?;
    builder.add_i64(element_size)?;
    builder.add_op(OpMod)?;
    builder.add_i64(0)?;
    builder.add_op(OpNumEqualVerify)?;
    builder.add_op(OpSwap)?;
    builder.add_op(OpDrop)?;
    if element_size != 1 {
        builder.add_i64(element_size)?;
        builder.add_op(OpDiv)?;
    }
    Ok(())
}

fn compile_statement<'i>(ctx: &mut CompileStatementContext<'_, 'i>, stmt: &Statement<'i>) -> Result<Vec<String>, CompilerError> {
    let statement_start = ctx.builder.script().len();
    ctx.debug_recorder.begin_statement_at(stmt, statement_start, ctx.types, ctx.stack_bindings);

    let added_stack_locals = match stmt {
        Statement::VariableDefinition { type_ref, name, expr, .. } => {
            compile_variable_definition_statement(ctx, type_ref, name, expr.as_ref())
        }
        Statement::Require { expr, .. } => compile_require_statement(ctx, expr),
        Statement::RequireAgeDaa { expr, .. } => compile_require_age_daa_statement(ctx, expr),
        Statement::RequireTxDaa { expr, .. } => compile_require_tx_daa_statement(ctx, expr),
        Statement::RequireTxTime { expr, .. } => compile_require_tx_time_statement(ctx, expr),
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
        Statement::StateFunctionCallAssign { target_struct, bindings, name, args, .. } => {
            compile_state_function_call_assign_statement(ctx, target_struct, bindings, name, args)
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
    types: &'a mut TypeMap,
    stack_bindings: &'a mut StackBindings,
    builder: &'a mut ScriptBuilder,
    contract_fields: &'a [ContractFieldAst<'i>],
    state_end: usize,
    contract_constants: &'a HashMap<String, Expr<'i>>,
    structs: &'a StructRegistry,
    bytecode_size: Option<i64>,
    debug_recorder: &'a mut DebugRecorder<'i>,
}

impl<'a, 'i> CompileStatementContext<'a, 'i> {
    fn compile_expr(&mut self, expr: &Expr<'i>, expected_type: Option<&TypeRef>) -> Result<(), CompilerError> {
        let env = ExprEnv {
            constants: self.contract_constants,
            stack_bindings: self.stack_bindings,
            types: self.types,
            bytecode_size: self.bytecode_size,
            contract_constants: self.contract_constants,
        };
        let mut emitter = ScriptEmitter::new(self.builder, 0);
        super::compile_expr(expr, expected_type, &env, &mut emitter)
    }

    fn compile_void_builtin_call(&mut self, name: &str, args: &[Expr<'i>]) -> Result<(), CompilerError> {
        let env = ExprEnv {
            constants: self.contract_constants,
            stack_bindings: self.stack_bindings,
            types: self.types,
            bytecode_size: self.bytecode_size,
            contract_constants: self.contract_constants,
        };
        let mut emitter = ScriptEmitter::new(self.builder, 0);
        super::compile_void_builtin_call(name, args, &env, &mut emitter)
    }

    pub(crate) fn with_types_and_stack_bindings<'b>(
        &'b mut self,
        types: &'b mut TypeMap,
        stack_bindings: &'b mut StackBindings,
    ) -> CompileStatementContext<'b, 'i>
    where
        'a: 'b,
    {
        CompileStatementContext {
            types,
            stack_bindings,
            builder: self.builder,
            contract_fields: self.contract_fields,
            state_end: self.state_end,
            contract_constants: self.contract_constants,
            structs: self.structs,
            bytecode_size: self.bytecode_size,
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
    if type_ref.is_array() {
        let initial = expr.cloned().unwrap_or_else(|| Expr::array(type_ref.clone(), Vec::new()));
        return compile_stack_variable_definition(ctx, name, type_ref.clone(), initial);
    }

    let expr = expr.cloned().ok_or_else(|| CompilerError::Unsupported("variable definition requires initializer".to_string()))?;
    compile_stack_variable_definition(ctx, name, type_ref.clone(), expr)
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

    ctx.types.insert(name.to_string(), type_ref.clone());
    ctx.compile_expr(&expr, Some(&type_ref))?;
    ctx.stack_bindings.push_binding(name);
    Ok(vec![name.to_string()])
}

fn compile_require_statement<'i>(ctx: &mut CompileStatementContext<'_, 'i>, expr: &Expr<'i>) -> Result<Vec<String>, CompilerError> {
    let bool_type = TypeRef { base: TypeBase::Bool, array_dims: Vec::new() };
    ctx.compile_expr(expr, Some(&bool_type))?;
    ctx.builder.add_op(OpVerify)?;
    Ok(Vec::new())
}

fn compile_require_age_daa_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    let expected_type = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
    ctx.compile_expr(expr, Some(&expected_type))?;
    ctx.builder.add_op(OpDup)?;
    ctx.builder.add_i64(0)?;
    ctx.builder.add_i64(1_i64 << 32)?;
    ctx.builder.add_op(OpWithin)?;
    ctx.builder.add_op(OpVerify)?;
    ctx.builder.add_op(OpCheckSequenceVerify)?;
    Ok(Vec::new())
}

fn compile_require_tx_daa_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    let expected_type = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
    ctx.compile_expr(expr, Some(&expected_type))?;
    ctx.builder.add_op(OpDup)?;
    ctx.builder.add_i64(0)?;
    ctx.builder.add_i64(kaspa_txscript::LOCK_TIME_THRESHOLD as i64)?;
    ctx.builder.add_op(OpWithin)?;
    ctx.builder.add_op(OpVerify)?;
    ctx.builder.add_op(OpCheckLockTimeVerify)?;
    Ok(Vec::new())
}

fn compile_require_tx_time_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    let expected_type = TypeRef { base: TypeBase::Temporal, array_dims: Vec::new() };
    ctx.compile_expr(expr, Some(&expected_type))?;
    ctx.builder.add_op(OpDup)?;
    ctx.builder.add_i64(kaspa_txscript::LOCK_TIME_THRESHOLD as i64)?;
    ctx.builder.add_op(OpGreaterThanOrEqual)?;
    ctx.builder.add_op(OpVerify)?;
    ctx.builder.add_op(OpCheckLockTimeVerify)?;
    Ok(Vec::new())
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
            ctx.contract_fields,
            ctx.state_end,
            ctx.bytecode_size,
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
            ctx.bytecode_size,
            ctx.contract_constants,
        )
        .map(|_| Vec::new());
    }
    match builtin_return(name) {
        Some(BuiltinReturn::Void) => {
            ctx.compile_void_builtin_call(name, args)?;
            return Ok(Vec::new());
        }
        Some(BuiltinReturn::Value(return_type)) => {
            ctx.compile_expr(&Expr::call(name, args.to_vec()), Some(&return_type))?;
            ctx.builder.add_op(OpDrop)?;
            return Ok(Vec::new());
        }
        None => {}
    }
    Err(CompilerError::Unsupported(format!(
        "inline lowering must eliminate internal function calls before compilation, found '{}()'",
        name
    )))
}

fn compile_state_function_call_assign_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    target_struct: &str,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<Vec<String>, CompilerError> {
    if name == "readInputState" || name == "readInputStateWithTemplate" {
        return compile_read_input_state_statement(
            ctx,
            target_struct,
            bindings,
            name,
            args,
            ctx.contract_fields,
            ctx.state_end,
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

        let expected_type = type_ref.clone();
        ctx.compile_expr(expr, Some(&expected_type))?;
        ctx.stack_bindings.emit_update_stack_for_rebinding(name, ctx.builder)?;
        return Ok(Vec::new());
    }

    Err(CompilerError::UndefinedIdentifier(name.to_string()))
}

fn compile_console_statement() -> Result<Vec<String>, CompilerError> {
    Ok(Vec::new())
}

fn compile_read_input_state_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    target_struct: &str,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
    contract_fields: &[ContractFieldAst<'i>],
    state_end: usize,
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

            let bytecode_size_value = ctx
                .bytecode_size
                .ok_or_else(|| CompilerError::Unsupported("readInputState requires this.bytecodeSize".to_string()))?;
            let total_state_len = encoded_state_len(contract_fields, ctx.contract_constants)?;
            let state_start_offset = checked_sub(state_end, total_state_len)?;

            let input_idx = args[0].clone();
            // Fix WHERE the reads are measured from before pinning what they land on: the guard
            // below pins each field's header at a constant offset, and those offsets are only
            // meaningful once the window itself cannot move.
            compile_input_script_binding(
                &input_idx,
                &Expr::int(bytecode_size_value),
                ctx.stack_bindings,
                ctx.types,
                ctx.builder,
                ctx.bytecode_size,
                ctx.contract_constants,
            )?;

            let layout_field_types = contract_fields.iter().map(|field| field.type_ref.clone()).collect::<Vec<_>>();
            compile_state_framing_guard(
                &input_idx,
                &Expr::int(state_start_offset as i64),
                &layout_field_types,
                &Expr::int(bytecode_size_value),
                ctx.stack_bindings,
                ctx.types,
                ctx.builder,
                ctx.bytecode_size,
                ctx.contract_constants,
            )?;

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

                let binding_expr = read_input_state_field_expr(
                    &input_idx,
                    &field.type_ref,
                    Expr::int(state_start_offset as i64),
                    field_chunk_offset,
                    Expr::int(bytecode_size_value),
                    ctx.contract_constants,
                    "readInputState",
                )?;
                added_stack_locals.extend(compile_stack_variable_definition(
                    ctx,
                    &binding.name,
                    binding.type_ref.clone(),
                    binding_expr,
                )?);

                let field_chunk_size = encoded_type_chunk_size(&field.type_ref, ctx.contract_constants)?;
                field_chunk_offset = checked_add(field_chunk_offset, field_chunk_size)?;
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

            let struct_spec =
                structs.get(target_struct).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{target_struct}'")))?;
            if bindings_by_field.len() != struct_spec.fields.len() {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                ));
            }

            let layout_field_types = flattened_struct_field_specs_for_type(
                &TypeRef { base: TypeBase::Custom(target_struct.to_string()), array_dims: Vec::new() },
                structs,
            )?;
            compile_read_input_state_with_template_validation(
                args,
                ctx.stack_bindings,
                ctx.types,
                ctx.builder,
                &layout_field_types,
                ctx.bytecode_size,
                ctx.contract_constants,
            )?;

            let input_idx = input_idx.clone();
            let state_start_offset_expr = template_prefix_len.clone();
            let bytecode_size_expr = templated_input_bytecode_size_expr(
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

                let binding_expr = read_input_state_field_expr(
                    &input_idx,
                    &field.type_ref,
                    state_start_offset_expr.clone(),
                    field_chunk_offset,
                    bytecode_size_expr.clone(),
                    ctx.contract_constants,
                    "readInputStateWithTemplate",
                )?;
                added_stack_locals.extend(compile_stack_variable_definition(
                    ctx,
                    &binding.name,
                    binding.type_ref.clone(),
                    binding_expr,
                )?);

                let field_chunk_size = encoded_type_chunk_size(&field.type_ref, ctx.contract_constants)?;
                field_chunk_offset = checked_add(field_chunk_offset, field_chunk_size)?;
            }

            Ok(added_stack_locals)
        }
        _ => Err(CompilerError::Unsupported(format!(
            "state destructuring assignment is only supported for readInputState()/readInputStateWithTemplate(), got '{}()'",
            name
        ))),
    }
}

fn compile_if_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    stmt: &Statement<'i>,
    condition: &Expr<'i>,
    then_branch: &[Statement<'i>],
    else_branch: Option<&[Statement<'i>]>,
) -> Result<(), CompilerError> {
    let condition = condition.clone();
    let bool_type = TypeRef { base: TypeBase::Bool, array_dims: Vec::new() };
    ctx.compile_expr(&condition, Some(&bool_type))?;
    ctx.builder.add_op(OpIf)?;
    ctx.debug_recorder.record_current_statement_source_step_at(stmt, ctx.builder.script().len(), ctx.types, ctx.stack_bindings);

    let original_stack_bindings = (*ctx.stack_bindings).clone();

    let mut then_types = (*ctx.types).clone();
    let mut then_stack_bindings = original_stack_bindings.clone();
    compile_block(&mut ctx.with_types_and_stack_bindings(&mut then_types, &mut then_stack_bindings), then_branch)?;

    if let Some(else_branch) = else_branch {
        ctx.builder.add_op(OpElse)?;
        let mut else_types = (*ctx.types).clone();
        let mut else_stack_bindings = original_stack_bindings.clone();
        compile_block(&mut ctx.with_types_and_stack_bindings(&mut else_types, &mut else_stack_bindings), else_branch)?;
        else_stack_bindings.emit_stack_reordering(&then_stack_bindings, ctx.builder)?;
        *ctx.stack_bindings = then_stack_bindings;
    } else {
        then_stack_bindings.emit_stack_reordering(&original_stack_bindings, ctx.builder)?;
        *ctx.stack_bindings = original_stack_bindings;
    }

    ctx.builder.add_op(OpEndIf)?;
    Ok(())
}

fn compile_block_statement<'i>(ctx: &mut CompileStatementContext<'_, 'i>, body: &[Statement<'i>]) -> Result<(), CompilerError> {
    compile_block(ctx, body)
}

fn compile_block<'i>(ctx: &mut CompileStatementContext<'_, 'i>, statements: &[Statement<'i>]) -> Result<(), CompilerError> {
    let mut added_stack_locals = Vec::new();
    for stmt in statements {
        let added = compile_statement(ctx, stmt).map_err(|err| err.with_span(&stmt.span()))?;
        added_stack_locals.extend(added);
    }

    if !added_stack_locals.is_empty() {
        ctx.stack_bindings.emit_drop_bindings(&added_stack_locals, ctx.builder)?;
        for name in &added_stack_locals {
            ctx.types.remove(name);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrypoint_stack_setup_places_contract_fields_above_params_in_depth_order() {
        let param_names = ["param_a", "param_b"];
        let param_count = param_names.len();
        let mut stack_bindings = StackBindings::from_depths(
            param_names
                .iter()
                .enumerate()
                .map(|(index, name)| (name.to_string(), (param_count - 1 - index) as i64))
                .collect::<HashMap<_, _>>(),
        );
        let contract_fields = ["field_a", "field_b"];

        for field in contract_fields {
            stack_bindings.push_binding(field);
        }

        assert_eq!(
            stack_bindings.binding_order(),
            ["field_b", "field_a", "param_b", "param_a"].into_iter().map(str::to_string).collect::<Vec<_>>()
        );
    }
}
