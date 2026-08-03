use super::*;
use crate::compiler::builtin_types::{BuiltinReturn, builtin_return};

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_entrypoint_function<'i>(
    function: &FunctionAst<'i>,
    contract_params: &[ParamAst<'i>],
    contract_fields: &[ContractFieldAst<'i>],
    contract_constants: &[ConstantAst<'i>],
    contract_fields_end_offset: usize,
    constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    script_size: Option<i64>,
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
    compile_fixed_size_param_validations(function, constants, &stack_bindings, &mut builder)?;
    let mut return_exprs: Vec<Expr> = Vec::new();

    let body_len = function.body.len();
    let mut statement_ctx = CompileStatementContext {
        types: &mut types,
        stack_bindings: &mut stack_bindings,
        builder: &mut builder,
        contract_fields,
        contract_fields_end_offset,
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

    let return_count = return_exprs.len();
    if return_count == 0 {
        for _ in 0..stack_bindings.len() {
            builder.add_op(OpDrop)?;
        }
        builder.add_op(OpTrue)?;
    } else {
        let env = ExprEnv { constants, stack_bindings: &stack_bindings, types: &types, script_size, contract_constants: constants };
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
    let script = builder.drain();
    debug_recorder.finish_entrypoint(script.len());
    Ok((function.name.clone(), script))
}

fn compile_fixed_size_param_validations<'i>(
    function: &FunctionAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
    stack_bindings: &StackBindings,
    builder: &mut ScriptBuilder,
) -> Result<(), CompilerError> {
    for param in &function.params {
        if !param.type_ref.is_array() {
            continue;
        }
        let Some(expected_size) = fixed_type_size(&param.type_ref, constants) else {
            continue;
        };
        let expected_size = i64::try_from(expected_size)
            .map_err(|_| CompilerError::Unsupported(format!("entrypoint parameter '{}' is too large", param.name)))?;

        let mut stack_depth = 0;
        let copied = stack_bindings.emit_copy_binding_to_top(&param.name, &mut stack_depth, builder)?;
        debug_assert!(copied, "entrypoint parameter must have a stack binding");

        builder.add_op(OpSize)?;
        builder.add_i64(expected_size)?;
        builder.add_op(OpNumEqualVerify)?;
        builder.add_op(OpDrop)?;
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
        Statement::TimeOp { tx_var, expr, .. } => compile_time_op_statement(ctx, tx_var, expr),
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
    contract_fields_end_offset: usize,
    contract_constants: &'a HashMap<String, Expr<'i>>,
    structs: &'a StructRegistry,
    script_size: Option<i64>,
    debug_recorder: &'a mut DebugRecorder<'i>,
}

impl<'a, 'i> CompileStatementContext<'a, 'i> {
    fn compile_expr(&mut self, expr: &Expr<'i>, expected_type: Option<&TypeRef>) -> Result<(), CompilerError> {
        let env = ExprEnv {
            constants: self.contract_constants,
            stack_bindings: self.stack_bindings,
            types: self.types,
            script_size: self.script_size,
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
            script_size: self.script_size,
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
            contract_fields_end_offset: self.contract_fields_end_offset,
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
    if type_ref.is_array() {
        let initial = expr.cloned().unwrap_or_else(|| Expr::new(ExprKind::Array(Vec::new()), span::Span::default()));
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

fn compile_time_op_statement<'i>(
    ctx: &mut CompileStatementContext<'_, 'i>,
    tx_var: &TimeVar,
    expr: &Expr<'i>,
) -> Result<Vec<String>, CompilerError> {
    let int_type = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
    ctx.compile_expr(expr, Some(&int_type))?;
    ctx.builder.add_op(match tx_var {
        TimeVar::ThisAge => OpCheckSequenceVerify,
        TimeVar::TxTime => OpCheckLockTimeVerify,
    })?;
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
            ctx.contract_fields_end_offset,
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
            ctx.script_size,
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
            ctx.contract_fields_end_offset,
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
    contract_fields_end_offset: usize,
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
            let state_start_offset = contract_fields_end_offset
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

                let binding_expr = read_input_state_field_expr(
                    &input_idx,
                    &field.type_ref,
                    Expr::int(state_start_offset as i64),
                    field_chunk_offset,
                    Expr::int(script_size_value),
                    ctx.contract_constants,
                    "readInputState",
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

                let binding_expr = read_input_state_field_expr(
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
