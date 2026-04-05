use super::*;
use std::collections::{HashMap, HashSet};

pub(super) fn static_check_contract<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<(), CompilerError> {
    if contract.functions.is_empty() {
        return Err(CompilerError::Unsupported("contract has no functions".to_string()));
    }
    if contract.params.len() != constructor_args.len() {
        return Err(CompilerError::Unsupported("constructor argument count mismatch".to_string()));
    }

    let structs = build_struct_registry(contract)?;
    validate_struct_graph(&structs)?;
    validate_contract_struct_usage(contract, &structs)?;
    let constants: HashMap<String, Expr<'i>> =
        contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    validate_contract_field_initializers(contract, &structs, &constants)?;
    validate_function_signatures(contract, &structs, &constants, options)?;

    for (param, value) in contract.params.iter().zip(constructor_args.iter()) {
        let param_type_name = type_name_from_ref(&param.type_ref);
        if !expr_matches_declared_type_ref(value, &param.type_ref, &structs) {
            return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, param_type_name)));
        }
    }

    Ok(())
}

pub(crate) fn validate_return_types<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    if return_types.is_empty() {
        return Err(CompilerError::Unsupported("return requires function return types".to_string()));
    }
    if return_types.len() != exprs.len() {
        return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
    }
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        if !expr_matches_return_type_ref(expr, return_type, types, structs, constants) {
            let type_name = type_name_from_ref(return_type);
            return Err(CompilerError::Unsupported(format!("return value expects {type_name}")));
        }
    }
    Ok(())
}

fn validate_contract_struct_usage<'i>(contract: &ContractAst<'i>, structs: &StructRegistry) -> Result<(), CompilerError> {
    for param in &contract.params {
        ensure_known_or_builtin_type(&param.type_ref, structs, "contract parameter")?;
    }
    for field in &contract.fields {
        ensure_known_or_builtin_type(&field.type_ref, structs, "contract field")?;
    }
    for constant in &contract.constants {
        ensure_known_or_builtin_type(&constant.type_ref, structs, "constant")?;
    }

    Ok(())
}

fn validate_function_signatures<'i>(
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
) -> Result<(), CompilerError> {
    let functions = contract.functions.iter().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let function_order =
        contract.functions.iter().enumerate().map(|(index, function)| (function.name.clone(), index)).collect::<HashMap<_, _>>();

    for (function_index, function) in contract.functions.iter().enumerate() {
        for param in &function.params {
            ensure_array_elements_have_known_size(&param.type_ref, structs, &type_name_from_ref(&param.type_ref))?;
        }
        for return_type in &function.return_types {
            ensure_array_elements_have_known_size(return_type, structs, &type_name_from_ref(return_type))?;
        }

        if function.entrypoint && !options.allow_entrypoint_return && !function.return_types.is_empty() {
            return Err(CompilerError::Unsupported("entrypoint return requires allow_entrypoint_return=true".to_string()));
        }

        let has_return = function.body.iter().any(statement_contains_return);
        if has_return {
            if !matches!(function.body.last(), Some(Statement::Return { .. })) {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            if function.body[..function.body.len() - 1].iter().any(statement_contains_return) {
                return Err(CompilerError::Unsupported("return statement must be the last statement".to_string()));
            }
            if function.return_types.is_empty() {
                return Err(CompilerError::Unsupported("return requires function return types".to_string()));
            }
        }

        let mut types = initial_function_types(contract, function, structs)?;
        let mut env = constants.clone();
        let mut prefer_env_for_comparison = HashSet::new();
        let mut ctx = ValidateStatementShapesContext {
            env: &mut env,
            prefer_env_for_comparison: &mut prefer_env_for_comparison,
            types: &mut types,
            return_types: &function.return_types,
            structs,
            constants,
            functions: &functions,
            function_order: &function_order,
            function_index,
            contract_fields: &contract.fields,
        };
        validate_statement_shapes(&mut ctx, &function.body)?;
    }

    Ok(())
}

fn validate_contract_field_initializers<'i>(
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let mut types = HashMap::new();
    for param in &contract.params {
        types.insert(param.name.clone(), type_name_from_ref(&param.type_ref));
    }
    for constant in &contract.constants {
        types.insert(constant.name.clone(), type_name_from_ref(&constant.type_ref));
    }

    for field in &contract.fields {
        let type_name = type_name_from_ref(&field.type_ref);
        validate_expr_semantics(&field.expr, constants, &HashSet::new(), &types, structs, &contract.fields)?;
        ensure_array_elements_have_known_size(&field.type_ref, structs, &type_name)?;
        validate_expr_assignable_to_type(&field.expr, &field.type_ref, &types, structs, constants, &contract.fields)
            .map_err(|_| CompilerError::Unsupported(format!("contract field '{}' expects {}", field.name, type_name)))?;
        types.insert(field.name.clone(), type_name);
    }

    Ok(())
}

fn validate_statement_shapes<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    statements: &[Statement<'i>],
) -> Result<(), CompilerError> {
    for stmt in statements {
        match stmt {
            Statement::VariableDefinition { type_ref, name, expr, .. } => {
                validate_variable_definition_statement_shape(ctx, type_ref, name, expr.as_ref())?
            }
            Statement::TupleAssignment { left_type_ref, left_name, right_type_ref, right_name, expr, .. } => {
                validate_tuple_assignment_statement_shape(ctx, left_type_ref, left_name, right_type_ref, right_name, expr)?
            }
            Statement::StateFunctionCallAssign { bindings, name, args, .. } => {
                validate_state_function_call_assign_statement_shape(ctx, bindings, name, args)?
            }
            Statement::StructDestructure { bindings, expr, .. } => validate_struct_destructure_statement_shape(ctx, bindings, expr)?,
            Statement::FunctionCall { name, args, .. } => validate_function_call_statement_shape(ctx, name, args)?,
            Statement::FunctionCallAssign { bindings, name, args, .. } => {
                validate_function_call_assign_statement_shape(ctx, bindings, name, args)?
            }
            Statement::Return { exprs, .. } => validate_return_statement_shape(ctx, exprs)?,
            Statement::Require { expr, .. } => validate_require_statement_shape(ctx, expr)?,
            Statement::TimeOp { expr, .. } => validate_time_op_statement_shape(ctx, expr)?,
            Statement::Console { args, .. } => validate_console_statement_shape(ctx, args)?,
            Statement::Assign { name, expr, .. } => validate_assign_statement_shape(ctx, name, expr)?,
            Statement::Block { body, .. } => validate_block_statement_shape(ctx, body)?,
            Statement::If { then_branch, else_branch, .. } => {
                validate_if_statement_shape(ctx, stmt, then_branch, else_branch.as_deref())?
            }
            Statement::For { ident, start, end, max_iterations, body, .. } => {
                validate_for_statement_shape(ctx, ident, start, end, max_iterations, body)?
            }
            Statement::ArrayPush { expr, .. } => validate_array_push_statement_shape(ctx, expr)?,
        }
    }

    Ok(())
}

struct ValidateStatementShapesContext<'a, 'i> {
    env: &'a mut HashMap<String, Expr<'i>>,
    prefer_env_for_comparison: &'a mut HashSet<String>,
    types: &'a mut HashMap<String, String>,
    return_types: &'a [TypeRef],
    structs: &'a StructRegistry,
    constants: &'a HashMap<String, Expr<'i>>,
    functions: &'a HashMap<String, &'a FunctionAst<'i>>,
    function_order: &'a HashMap<String, usize>,
    function_index: usize,
    contract_fields: &'a [ContractFieldAst<'i>],
}

fn validate_variable_definition_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    type_ref: &TypeRef,
    name: &str,
    expr: Option<&Expr<'i>>,
) -> Result<(), CompilerError> {
    let effective_type_ref = infer_fixed_array_type_from_initializer_type_check(type_ref, expr, ctx.types, ctx.constants)
        .unwrap_or_else(|| type_ref.clone());
    let type_name = type_name_from_ref(&effective_type_ref);
    ensure_array_elements_have_known_size(&effective_type_ref, ctx.structs, &type_name)?;
    if effective_type_ref.is_array() {
        validate_array_initializer(expr, &effective_type_ref, ctx.types, ctx.constants)?;
    }
    if let Some(expr) = expr {
        validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
        validate_expr_assignable_to_type(expr, type_ref, ctx.types, ctx.structs, ctx.constants, ctx.contract_fields).map_err(
            |err| {
                map_declared_type_error(
                    err,
                    "variable",
                    name,
                    &type_name_from_ref(type_ref),
                    expr,
                    type_ref,
                    ctx.types,
                    ctx.structs,
                    ctx.constants,
                )
            },
        )?;
        ctx.env.insert(name.to_string(), expr.clone());
        ctx.prefer_env_for_comparison.remove(name);
    }
    insert_type_binding(ctx.types, name, &effective_type_ref, ctx.structs)
}

fn validate_array_initializer<'i>(
    expr: Option<&Expr<'i>>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let type_name = type_name_from_ref(type_ref);
    match expr {
        Some(Expr { kind: ExprKind::Identifier(other), .. }) => match types.get(other) {
            Some(other_type) => match parse_type_ref(other_type) {
                Ok(other_type_ref) if is_type_assignable_ref(&other_type_ref, type_ref, constants) => Ok(()),
                Ok(_) => Err(CompilerError::Unsupported("array assignment requires compatible array types".to_string())),
                Err(_) => Err(CompilerError::Unsupported("array assignment requires compatible array types".to_string())),
            },
            None => Err(CompilerError::UndefinedIdentifier(other.clone())),
        },
        Some(Expr { kind: ExprKind::Array(values), .. }) => {
            if let Some(expected_size) = array_size_with_constants_ref(type_ref, constants)
                && values.len() != expected_size
            {
                return Err(CompilerError::Unsupported(format!(
                    "array size mismatch: expected {} elements for type {}, got {}",
                    expected_size,
                    type_name,
                    values.len()
                )));
            }
            if !array_literal_matches_type_with_env_ref(values, type_ref, types, constants) {
                return Err(CompilerError::Unsupported(format!("array element type mismatch for type {}", type_name)));
            }
            Ok(())
        }
        Some(_) => Ok(()),
        None if array_size_with_constants_ref(type_ref, constants).is_none() => Ok(()),
        None => Err(CompilerError::Unsupported("variable definition requires initializer".to_string())),
    }
}

fn validate_tuple_assignment_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    left_type_ref: &TypeRef,
    left_name: &str,
    right_type_ref: &TypeRef,
    right_name: &str,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    ensure_array_elements_have_known_size(left_type_ref, ctx.structs, &type_name_from_ref(left_type_ref))?;
    ensure_array_elements_have_known_size(right_type_ref, ctx.structs, &type_name_from_ref(right_type_ref))?;
    if let ExprKind::Split { source, index, span: split_span, .. } = &expr.kind {
        let left_expr = Expr::new(
            ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Left, span: *split_span },
            span::Span::default(),
        );
        let right_expr = Expr::new(
            ExprKind::Split { source: source.clone(), index: index.clone(), part: SplitPart::Right, span: *split_span },
            span::Span::default(),
        );
        ctx.env.insert(left_name.to_string(), left_expr);
        ctx.env.insert(right_name.to_string(), right_expr);
        ctx.prefer_env_for_comparison.insert(left_name.to_string());
        ctx.prefer_env_for_comparison.insert(right_name.to_string());
    }
    insert_type_binding(ctx.types, left_name, left_type_ref, ctx.structs)?;
    insert_type_binding(ctx.types, right_name, right_type_ref, ctx.structs)
}

fn validate_state_function_call_assign_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    bindings: &[StateBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    for arg in args {
        validate_expr_semantics(arg, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    }
    validate_state_function_call_assign(bindings, name, args, ctx.structs, ctx.contract_fields)?;
    for binding in bindings {
        ensure_array_elements_have_known_size(&binding.type_ref, ctx.structs, &type_name_from_ref(&binding.type_ref))?;
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref, ctx.structs)?;
    }
    Ok(())
}

fn validate_struct_destructure_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    bindings: &[StateBindingAst<'i>],
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    validate_struct_destructure_bindings(bindings, expr, ctx.types, ctx.structs, ctx.contract_fields)?;
    for binding in bindings {
        ensure_array_elements_have_known_size(&binding.type_ref, ctx.structs, &type_name_from_ref(&binding.type_ref))?;
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref, ctx.structs)?;
    }
    Ok(())
}

fn validate_function_call_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    for arg in args {
        validate_expr_semantics(arg, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    }
    if ctx.functions.contains_key(name) {
        validate_internal_call(
            name,
            args,
            ctx.types,
            ctx.structs,
            ctx.constants,
            ctx.functions,
            ctx.function_order,
            ctx.function_index,
            ctx.contract_fields,
        )?;
    }
    Ok(())
}

fn validate_function_call_assign_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    bindings: &[ParamAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    for arg in args {
        validate_expr_semantics(arg, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    }
    let function = validate_internal_call(
        name,
        args,
        ctx.types,
        ctx.structs,
        ctx.constants,
        ctx.functions,
        ctx.function_order,
        ctx.function_index,
        ctx.contract_fields,
    )?;
    if bindings.len() != function.return_types.len() {
        return Err(CompilerError::Unsupported("function call assignment return count mismatch".to_string()));
    }
    for (binding, return_type) in bindings.iter().zip(function.return_types.iter()) {
        if binding.type_ref != *return_type {
            return Err(CompilerError::Unsupported(format!(
                "function return binding '{}' expects {}",
                binding.name,
                type_name_from_ref(return_type)
            )));
        }
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref, ctx.structs)?;
    }
    Ok(())
}

fn validate_return_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    exprs: &[Expr<'i>],
) -> Result<(), CompilerError> {
    for expr in exprs {
        validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    }
    validate_return_types(exprs, ctx.return_types, ctx.types, ctx.structs, ctx.constants)
}

fn validate_require_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)
}

fn validate_time_op_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)
}

fn validate_console_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    for arg in args {
        validate_expr_semantics(arg, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    }
    Ok(())
}

fn validate_assign_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    name: &str,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    if let Some(type_name) = ctx.types.get(name).cloned() {
        let type_ref = parse_type_ref(&type_name)?;
        validate_expr_assignable_to_type(expr, &type_ref, ctx.types, ctx.structs, ctx.constants, ctx.contract_fields).map_err(
            |err| map_declared_type_error(err, "variable", name, &type_name, expr, &type_ref, ctx.types, ctx.structs, ctx.constants),
        )?;
    }
    ctx.env.insert(name.to_string(), expr.clone());
    ctx.prefer_env_for_comparison.remove(name);
    Ok(())
}

fn validate_if_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    stmt: &Statement<'i>,
    then_branch: &[Statement<'i>],
    else_branch: Option<&[Statement<'i>]>,
) -> Result<(), CompilerError> {
    if let Statement::If { condition, .. } = stmt {
        validate_expr_semantics(condition, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    }
    let mut then_types = ctx.types.clone();
    let mut then_env = ctx.env.clone();
    let mut then_prefer_env = ctx.prefer_env_for_comparison.clone();
    let mut then_ctx = ValidateStatementShapesContext {
        env: &mut then_env,
        prefer_env_for_comparison: &mut then_prefer_env,
        types: &mut then_types,
        return_types: ctx.return_types,
        structs: ctx.structs,
        constants: ctx.constants,
        functions: ctx.functions,
        function_order: ctx.function_order,
        function_index: ctx.function_index,
        contract_fields: ctx.contract_fields,
    };
    validate_statement_shapes(&mut then_ctx, then_branch)?;
    if let Some(else_branch) = else_branch {
        let mut else_types = ctx.types.clone();
        let mut else_env = ctx.env.clone();
        let mut else_prefer_env = ctx.prefer_env_for_comparison.clone();
        let mut else_ctx = ValidateStatementShapesContext {
            env: &mut else_env,
            prefer_env_for_comparison: &mut else_prefer_env,
            types: &mut else_types,
            return_types: ctx.return_types,
            structs: ctx.structs,
            constants: ctx.constants,
            functions: ctx.functions,
            function_order: ctx.function_order,
            function_index: ctx.function_index,
            contract_fields: ctx.contract_fields,
        };
        validate_statement_shapes(&mut else_ctx, else_branch)?;
    }
    Ok(())
}

fn validate_block_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    body: &[Statement<'i>],
) -> Result<(), CompilerError> {
    let mut block_types = ctx.types.clone();
    let mut block_env = ctx.env.clone();
    let mut block_prefer_env = ctx.prefer_env_for_comparison.clone();
    let mut block_ctx = ValidateStatementShapesContext {
        env: &mut block_env,
        prefer_env_for_comparison: &mut block_prefer_env,
        types: &mut block_types,
        return_types: ctx.return_types,
        structs: ctx.structs,
        constants: ctx.constants,
        functions: ctx.functions,
        function_order: ctx.function_order,
        function_index: ctx.function_index,
        contract_fields: ctx.contract_fields,
    };
    validate_statement_shapes(&mut block_ctx, body)
}

fn validate_for_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    ident: &str,
    start: &Expr<'i>,
    end: &Expr<'i>,
    max_iterations: &Expr<'i>,
    body: &[Statement<'i>],
) -> Result<(), CompilerError> {
    validate_expr_semantics(start, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    validate_expr_semantics(end, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    validate_expr_semantics(max_iterations, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)?;
    let mut body_types = ctx.types.clone();
    let mut body_env = ctx.env.clone();
    let mut body_prefer_env = ctx.prefer_env_for_comparison.clone();
    body_types.insert(ident.to_string(), "int".to_string());
    let mut body_ctx = ValidateStatementShapesContext {
        env: &mut body_env,
        prefer_env_for_comparison: &mut body_prefer_env,
        types: &mut body_types,
        return_types: ctx.return_types,
        structs: ctx.structs,
        constants: ctx.constants,
        functions: ctx.functions,
        function_order: ctx.function_order,
        function_index: ctx.function_index,
        contract_fields: ctx.contract_fields,
    };
    validate_statement_shapes(&mut body_ctx, body)
}

fn validate_array_push_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    validate_expr_semantics(expr, ctx.env, ctx.prefer_env_for_comparison, ctx.types, ctx.structs, ctx.contract_fields)
}

fn validate_struct_destructure_bindings<'i>(
    bindings: &[StateBindingAst<'i>],
    expr: &Expr<'i>,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    let expr_type = infer_struct_destructure_expr_type(expr, types, structs, contract_fields)?;
    let struct_name = struct_name_from_type_ref(&expr_type, structs)
        .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string()))?;
    let struct_ast = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let direct_read_input_state = matches!(&expr.kind, ExprKind::Call { name, .. } if name == "readInputState");
    let mut seen_fields = HashSet::new();
    let mut seen_names = HashSet::new();

    for binding in bindings {
        ensure_known_or_builtin_type(&binding.type_ref, structs, "struct destructuring")?;
        if !seen_fields.insert(binding.field_name.clone()) {
            return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", binding.field_name)));
        }
        if !seen_names.insert(binding.name.clone()) {
            return Err(CompilerError::Unsupported(format!("duplicate binding name '{}'", binding.name)));
        }
    }

    if bindings.len() != struct_ast.fields.len() {
        return Err(CompilerError::Unsupported("struct destructuring must bind all fields exactly once".to_string()));
    }

    for field in &struct_ast.fields {
        let Some(binding) = bindings.iter().find(|binding| binding.field_name == field.name) else {
            return Err(CompilerError::Unsupported("struct destructuring must bind all fields exactly once".to_string()));
        };
        if binding.type_ref != field.type_ref {
            return Err(CompilerError::Unsupported(format!(
                "struct field '{}' expects {}",
                field.name,
                type_name_from_ref(&field.type_ref)
            )));
        }
        if direct_read_input_state && struct_name_from_type_ref(&binding.type_ref, structs).is_some() {
            return Err(CompilerError::Unsupported("readInputState does not support nested struct fields".to_string()));
        }
    }

    Ok(())
}

fn validate_state_function_call_assign<'i>(
    bindings: &[StateBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    match name {
        "readInputState" => {
            if args.len() != 1 {
                return Err(CompilerError::Unsupported("readInputState(input_idx) expects 1 argument".to_string()));
            }
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            if bindings.len() != contract_fields.len() {
                return Err(CompilerError::Unsupported(
                    "readInputState bindings must include all contract fields exactly once".to_string(),
                ));
            }
            for field in contract_fields {
                let Some(binding) = bindings.iter().find(|binding| binding.field_name == field.name) else {
                    return Err(CompilerError::Unsupported(
                        "readInputState bindings must include all contract fields exactly once".to_string(),
                    ));
                };
                if binding.type_ref != field.type_ref {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputState binding '{}' expects {}",
                        binding.name,
                        type_name_from_ref(&field.type_ref)
                    )));
                }
            }
            Ok(())
        }
        "readInputStateWithTemplate" => {
            let Ok([_, _, _, _]): Result<&[Expr<'i>; 4], _> = args.try_into() else {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate(input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 4 arguments"
                        .to_string(),
                ));
            };
            let struct_name = struct_name_for_state_bindings_ref(bindings, structs)?;
            let struct_spec =
                structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            if bindings.len() != struct_spec.fields.len() {
                return Err(CompilerError::Unsupported(
                    "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                ));
            }
            for field in &struct_spec.fields {
                let Some(binding) = bindings.iter().find(|binding| binding.field_name == field.name) else {
                    return Err(CompilerError::Unsupported(
                        "readInputStateWithTemplate bindings must include all target fields exactly once".to_string(),
                    ));
                };
                if struct_name_from_type_ref(&field.type_ref, structs).is_some() {
                    return Err(CompilerError::Unsupported(
                        "readInputStateWithTemplate does not support nested struct fields in destructuring".to_string(),
                    ));
                }
                if binding.type_ref != field.type_ref {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputStateWithTemplate binding '{}' expects {}",
                        binding.name,
                        type_name_from_ref(&field.type_ref)
                    )));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_expr_semantics<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    prefer_env_for_comparison: &HashSet<String>,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    match &expr.kind {
        ExprKind::Binary { op, left, right } => {
            validate_expr_semantics(left, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(right, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            let left_value_type = super::debug_value_types::infer_debug_expr_value_type(left, env, types, &mut HashSet::new()).ok();
            let right_value_type = super::debug_value_types::infer_debug_expr_value_type(right, env, types, &mut HashSet::new()).ok();
            if matches!(op, BinaryOp::Add)
                && (left_value_type.as_deref() == Some("byte") || right_value_type.as_deref() == Some("byte"))
            {
                return Err(CompilerError::Unsupported("byte values do not support '+'".to_string()));
            }
            if matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge) {
                let left_type =
                    infer_expr_type_ref_for_comparison_ref(left, env, prefer_env_for_comparison, types, structs, contract_fields);
                let coerced_right = coerce_rhs_byte_literal_for_comparison_ref(left_type.as_ref(), right);
                let right_type = infer_expr_type_ref_for_comparison_ref(
                    &coerced_right,
                    env,
                    prefer_env_for_comparison,
                    types,
                    structs,
                    contract_fields,
                );
                if let (Some(left_type), Some(right_type)) = (left_type, right_type)
                    && !comparison_types_compatible_ref(&left_type, &right_type)
                {
                    return Err(CompilerError::Unsupported(format!(
                        "type mismatch: cannot compare {} and {}",
                        type_name_from_ref(&left_type),
                        type_name_from_ref(&right_type)
                    )));
                }
            }
            Ok(())
        }
        ExprKind::Unary { expr, .. } => validate_expr_semantics(expr, env, prefer_env_for_comparison, types, structs, contract_fields),
        ExprKind::IfElse { condition, then_expr, else_expr } => {
            validate_expr_semantics(condition, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(then_expr, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(else_expr, env, prefer_env_for_comparison, types, structs, contract_fields)
        }
        ExprKind::Array(values) => {
            for value in values {
                validate_expr_semantics(value, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            }
            Ok(())
        }
        ExprKind::Call { args, .. } | ExprKind::New { args, .. } => {
            for arg in args {
                validate_expr_semantics(arg, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            }
            Ok(())
        }
        ExprKind::Split { source, index, .. } => {
            validate_expr_semantics(source, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(index, env, prefer_env_for_comparison, types, structs, contract_fields)
        }
        ExprKind::Slice { source, start, end, .. } => {
            validate_expr_semantics(source, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(start, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(end, env, prefer_env_for_comparison, types, structs, contract_fields)
        }
        ExprKind::ArrayIndex { source, index } => {
            validate_expr_semantics(source, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            validate_expr_semantics(index, env, prefer_env_for_comparison, types, structs, contract_fields)
        }
        ExprKind::Introspection { index, .. } => {
            validate_expr_semantics(index, env, prefer_env_for_comparison, types, structs, contract_fields)
        }
        ExprKind::StateObject(fields) => {
            for field in fields {
                validate_expr_semantics(&field.expr, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            }
            Ok(())
        }
        ExprKind::FieldAccess { source, .. } | ExprKind::UnarySuffix { source, .. } => {
            validate_expr_semantics(source, env, prefer_env_for_comparison, types, structs, contract_fields)
        }
        ExprKind::Identifier(name) => {
            if types.contains_key(name) || env.contains_key(name) {
                Ok(())
            } else {
                Err(CompilerError::UndefinedIdentifier(name.clone()))
            }
        }
        _ => Ok(()),
    }
}

fn infer_expr_type_ref_for_comparison_ref<'i>(
    expr: &Expr<'i>,
    env: &HashMap<String, Expr<'i>>,
    prefer_env_for_comparison: &HashSet<String>,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Option<TypeRef> {
    match &expr.kind {
        ExprKind::Identifier(name) => {
            if prefer_env_for_comparison.contains(name)
                && let Some(value) = env.get(name)
            {
                let type_name = super::debug_value_types::infer_debug_expr_value_type(value, env, types, &mut HashSet::new()).ok()?;
                parse_type_ref(&type_name).ok()
            } else {
                types.get(name).and_then(|type_name| parse_type_ref(type_name).ok())
            }
        }
        ExprKind::FieldAccess { source, field, .. } => {
            let source_type =
                infer_expr_type_ref_for_comparison_ref(source, env, prefer_env_for_comparison, types, structs, contract_fields)?;
            let struct_name = struct_name_from_type_ref(&source_type, structs)?;
            let struct_ast = structs.get(struct_name)?;
            struct_ast.fields.iter().find(|candidate| candidate.name == *field).map(|candidate| candidate.type_ref.clone())
        }
        ExprKind::ArrayIndex { source, .. } => {
            infer_expr_type_ref_for_comparison_ref(source, env, prefer_env_for_comparison, types, structs, contract_fields)
                .and_then(|type_ref| type_ref.element_type())
        }
        ExprKind::Call { name, .. } if name == "readInputState" && !contract_fields.is_empty() => {
            Some(TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() })
        }
        _ => {
            let type_name = super::debug_value_types::infer_debug_expr_value_type(expr, env, types, &mut HashSet::new()).ok()?;
            parse_type_ref(&type_name).ok()
        }
    }
}

fn coerce_rhs_byte_literal_for_comparison_ref<'i>(left_type: Option<&TypeRef>, right: &Expr<'i>) -> Expr<'i> {
    if left_type.is_some_and(|type_ref| matches!(type_ref.base, TypeBase::Byte) && type_ref.array_dims.is_empty())
        && let ExprKind::Int(value) = right.kind
        && (0..=255).contains(&value)
    {
        return Expr::new(ExprKind::Byte(value as u8), right.span);
    }
    right.clone()
}

fn comparison_types_compatible_ref(left_type: &TypeRef, right_type: &TypeRef) -> bool {
    if left_type == right_type {
        return true;
    }
    matches!(
        (&left_type.base, left_type.array_dims.as_slice(), &right_type.base, right_type.array_dims.as_slice()),
        (TypeBase::Byte, [], TypeBase::Byte, [ArrayDim::Fixed(1)]) | (TypeBase::Byte, [ArrayDim::Fixed(1)], TypeBase::Byte, [])
    )
}

fn struct_name_for_state_bindings_ref<'i>(
    bindings: &[StateBindingAst<'i>],
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

fn infer_struct_destructure_expr_type<'i>(
    expr: &Expr<'i>,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<TypeRef, CompilerError> {
    match &expr.kind {
        ExprKind::Identifier(name) => types
            .get(name)
            .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))
            .and_then(|type_name| parse_type_ref(type_name)),
        ExprKind::FieldAccess { source, field, .. } => {
            let source_type = infer_struct_destructure_expr_type(source, types, structs, contract_fields)?;
            let struct_name = struct_name_from_type_ref(&source_type, structs)
                .ok_or_else(|| CompilerError::Unsupported("field access requires a struct value".to_string()))?;
            let struct_ast =
                structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
            struct_ast
                .fields
                .iter()
                .find(|candidate| candidate.name == *field)
                .map(|candidate| candidate.type_ref.clone())
                .ok_or_else(|| CompilerError::Unsupported(format!("struct '{}' has no field '{}'", struct_name, field)))
        }
        ExprKind::ArrayIndex { source, .. } => match &source.kind {
            ExprKind::Identifier(name) => types
                .get(name)
                .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))
                .and_then(|type_name| parse_type_ref(type_name))
                .and_then(|type_ref| {
                    type_ref
                        .element_type()
                        .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string()))
                }),
            _ => Err(CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
        },
        ExprKind::Call { name, .. } if name == "readInputState" => {
            if contract_fields.is_empty() {
                return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
            }
            Ok(TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() })
        }
        ExprKind::Call { name, .. } if name == "readInputStateWithTemplate" => Err(CompilerError::Unsupported(
            "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
        )),
        _ => Err(CompilerError::Unsupported("struct destructuring requires a struct value".to_string())),
    }
}

fn initial_function_types<'i>(
    contract: &ContractAst<'i>,
    function: &FunctionAst<'i>,
    structs: &StructRegistry,
) -> Result<HashMap<String, String>, CompilerError> {
    let mut types = HashMap::new();

    for param in &contract.params {
        insert_type_binding(&mut types, &param.name, &param.type_ref, structs)?;
    }
    for field in &contract.fields {
        insert_type_binding(&mut types, &field.name, &field.type_ref, structs)?;
    }
    for constant in &contract.constants {
        insert_type_binding(&mut types, &constant.name, &constant.type_ref, structs)?;
    }
    for param in &function.params {
        insert_type_binding(&mut types, &param.name, &param.type_ref, structs)?;
    }

    Ok(types)
}

fn insert_type_binding(
    types: &mut HashMap<String, String>,
    name: &str,
    type_ref: &TypeRef,
    structs: &StructRegistry,
) -> Result<(), CompilerError> {
    types.insert(name.to_string(), type_name_from_ref(type_ref));
    if (struct_name_from_type_ref(type_ref, structs).is_some() || struct_array_name_from_type_ref(type_ref, structs).is_some())
        && let Ok(leaves) = flatten_type_ref_leaves(type_ref, structs)
    {
        for (path, leaf_type) in leaves {
            types.insert(flattened_struct_name(name, &path), type_name_from_ref(&leaf_type));
        }
    }
    Ok(())
}

fn validate_internal_call<'i>(
    name: &str,
    args: &[Expr<'i>],
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    functions: &'i HashMap<String, &'i FunctionAst<'i>>,
    function_order: &HashMap<String, usize>,
    function_index: usize,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<&'i FunctionAst<'i>, CompilerError> {
    let Some(function) = functions.get(name).copied() else {
        return Err(CompilerError::Unsupported(format!("function '{}' not found", name)));
    };

    let callee_index =
        function_order.get(name).copied().ok_or_else(|| CompilerError::Unsupported(format!("function '{}' not found", name)))?;
    if callee_index > function_index {
        return Err(CompilerError::Unsupported("functions may only call earlier-defined functions".to_string()));
    }
    if callee_index == function_index {
        return Err(CompilerError::Unsupported(format!("unknown function '{}'", name)));
    }
    if function.params.len() != args.len() {
        return Err(CompilerError::Unsupported(format!("function '{}' expects {} arguments", name, function.params.len())));
    }

    for (param, arg) in function.params.iter().zip(args.iter()) {
        if matches!(&arg.kind, ExprKind::Call { name, .. } if name == "readInputStateWithTemplate") {
            return Err(CompilerError::Unsupported(
                "readInputStateWithTemplate must be assigned to a struct variable or destructured directly".to_string(),
            ));
        }
        let param_type_name = type_name_from_ref(&param.type_ref);
        validate_expr_assignable_to_type(arg, &param.type_ref, types, structs, constants, contract_fields).map_err(|err| {
            if matches!(&arg.kind, ExprKind::Call { name, .. } if name == "readInputStateWithTemplate") {
                err
            } else {
                CompilerError::Unsupported(format!("function argument '{}' expects {}", param.name, param_type_name))
            }
        })?;
    }

    Ok(function)
}

fn validate_expr_assignable_to_type<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    if matches!(type_ref.base, TypeBase::Byte)
        && type_ref.array_dims.is_empty()
        && matches!(expr.kind, ExprKind::Int(value) if (0..=255).contains(&value))
    {
        return Ok(());
    }

    if type_ref.is_array()
        && let ExprKind::Array(values) = &expr.kind
    {
        if let Some(expected_size) = array_size_with_constants_ref(type_ref, constants)
            && values.len() != expected_size
        {
            return Err(CompilerError::Unsupported("size mismatch".to_string()));
        }
        if !array_literal_matches_type_with_env_ref(values, type_ref, types, constants) {
            return Err(CompilerError::Unsupported("type mismatch".to_string()));
        }
        return Ok(());
    }

    if struct_name_from_type_ref(type_ref, structs).is_some() {
        if let ExprKind::Call { name, args, .. } = &expr.kind
            && name == "readInputState"
            && struct_name_from_type_ref(type_ref, structs) == Some("State")
            && !contract_fields.is_empty()
            && args.len() == 1
        {
            return Ok(());
        }
        if let ExprKind::Call { name, args, .. } = &expr.kind
            && name == "readInputStateWithTemplate"
        {
            return compile::read_input_state_with_template_values(args, type_ref, structs, constants).map(|_| ());
        }
        if matches!(expr.kind, ExprKind::StateObject(_)) {
            return validate_struct_literal_matches_type(expr, type_ref, types, structs, constants);
        }
        lower_runtime_struct_expr(expr, type_ref, types, structs, contract_fields, constants, 0).map(|_| ())
    } else if struct_array_name_from_type_ref(type_ref, structs).is_some() {
        if let ExprKind::Call { name, .. } = &expr.kind
            && name == "readInputStateWithTemplate"
        {
            return Err(CompilerError::Unsupported(
                "readInputStateWithTemplate does not support struct array assignments".to_string(),
            ));
        }
        let matches = match &expr.kind {
            ExprKind::Identifier(name) => types
                .get(name)
                .and_then(|type_name| parse_type_ref(type_name).ok())
                .is_some_and(|actual_type| is_type_assignable_ref(&actual_type, type_ref, constants)),
            _ => expr_matches_declared_type_ref(expr, type_ref, structs),
        };
        if matches { Ok(()) } else { Err(CompilerError::Unsupported("type mismatch".to_string())) }
    } else {
        if type_ref.is_array()
            && let Ok(actual_type_name) =
                super::debug_value_types::infer_debug_expr_value_type(expr, &HashMap::new(), types, &mut HashSet::new())
            && let Ok(actual_type) = parse_type_ref(&actual_type_name)
            && is_type_assignable_ref(&actual_type, type_ref, constants)
        {
            return Ok(());
        }
        let lowered = lower_runtime_expr(expr, types, structs)?;
        if expr_matches_return_type_ref(&lowered, type_ref, types, structs, constants) {
            Ok(())
        } else {
            Err(CompilerError::Unsupported("type mismatch".to_string()))
        }
    }
}

fn validate_struct_literal_matches_type<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) else {
        return Err(CompilerError::Unsupported("type mismatch".to_string()));
    };
    let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let ExprKind::StateObject(fields) = &expr.kind else {
        return Err(CompilerError::Unsupported("type mismatch".to_string()));
    };
    let mut provided = HashMap::new();
    for field in fields {
        if provided.insert(field.name.clone(), &field.expr).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate struct field '{}'", field.name)));
        }
    }
    for field in &item.fields {
        let Some(value) = provided.remove(&field.name) else {
            return Err(CompilerError::Unsupported(format!("struct field '{}' must be initialized", field.name)));
        };
        validate_expr_assignable_to_type(value, &field.type_ref, types, structs, constants, &[]).map_err(|_| {
            CompilerError::Unsupported(format!("struct field '{}' expects {}", field.name, field.type_ref.type_name()))
        })?;
    }
    if let Some(extra) = provided.keys().next() {
        return Err(CompilerError::Unsupported(format!("unknown struct field '{}'", extra)));
    }
    Ok(())
}

fn map_declared_type_error<'i>(
    err: CompilerError,
    kind: &str,
    name: &str,
    type_name: &str,
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> CompilerError {
    match err {
        CompilerError::Unsupported(message) if message == "type mismatch" => {
            let hint = expr_matches_return_type_ref_hint(expr, type_ref, types, structs, constants)
                .map(|hint| format!("; {hint}"))
                .unwrap_or_default();
            CompilerError::Unsupported(format!("{kind} '{}' expects {}{}", name, type_name, hint))
        }
        other => other,
    }
}

fn ensure_array_elements_have_known_size(type_ref: &TypeRef, structs: &StructRegistry, type_name: &str) -> Result<(), CompilerError> {
    if !type_ref.array_dims.is_empty() && fixed_type_size_ref(type_ref.element_type().as_ref().unwrap_or(type_ref), structs).is_none()
    {
        return Err(CompilerError::Unsupported(format!("array element type must have known size: {type_name}")));
    }
    Ok(())
}

fn infer_fixed_array_type_from_initializer_type_check<'i>(
    declared_type: &TypeRef,
    initializer: Option<&Expr<'i>>,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<TypeRef> {
    if !matches!(declared_type.array_size(), Some(ArrayDim::Inferred)) {
        return None;
    }

    let element_type = declared_type.element_type()?;
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

fn fixed_type_size_ref(type_ref: &TypeRef, structs: &StructRegistry) -> Option<i64> {
    match &type_ref.base {
        TypeBase::Int => Some(8),
        TypeBase::Bool | TypeBase::Byte => Some(1),
        TypeBase::Pubkey => Some(32),
        TypeBase::Sig => Some(65),
        TypeBase::Datasig => Some(64),
        TypeBase::String => None,
        TypeBase::Custom(name) if type_ref.array_dims.is_empty() => {
            let struct_spec = structs.get(name)?;
            let mut total = 0i64;
            for field in &struct_spec.fields {
                total += fixed_type_size_ref(&field.type_ref, structs)?;
            }
            Some(total)
        }
        TypeBase::Custom(_) => None,
    }
    .and_then(|base_size| {
        type_ref.array_dims.iter().try_fold(base_size, |acc, dim| match dim {
            ArrayDim::Fixed(size) => Some(acc.checked_mul(*size as i64)?),
            ArrayDim::Dynamic | ArrayDim::Inferred | ArrayDim::Constant(_) => None,
        })
    })
}

fn statement_contains_return(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::Return { .. } => true,
        Statement::Block { body, .. } => body.iter().any(statement_contains_return),
        Statement::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(statement_contains_return)
                || else_branch.as_ref().is_some_and(|branch| branch.iter().any(statement_contains_return))
        }
        Statement::For { body, .. } => body.iter().any(statement_contains_return),
        _ => false,
    }
}

pub(super) fn expr_matches_declared_type_ref<'i>(expr: &Expr<'i>, type_ref: &TypeRef, structs: &StructRegistry) -> bool {
    if let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) {
        let Some(item) = structs.get(struct_name) else {
            return false;
        };
        let ExprKind::StateObject(fields) = &expr.kind else {
            return false;
        };
        if fields.len() != item.fields.len() {
            return false;
        }
        for field in &item.fields {
            let Some(value) = fields.iter().find(|entry| entry.name == field.name).map(|entry| &entry.expr) else {
                return false;
            };
            if !expr_matches_declared_type_ref(value, &field.type_ref, structs) {
                return false;
            }
        }
        return true;
    }

    if let Some(element_type) = type_ref.element_type() {
        if struct_name_from_type_ref(&element_type, structs).is_some() {
            return matches!(&expr.kind, ExprKind::Array(values) if values.iter().all(|value| expr_matches_declared_type_ref(value, &element_type, structs)));
        }
    }

    expr_matches_type_ref(expr, type_ref)
}

pub(super) fn expr_matches_return_type_ref<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    if let ExprKind::Identifier(name) = &expr.kind {
        return types
            .get(name)
            .and_then(|type_name| parse_type_ref(type_name).ok())
            .is_some_and(|actual| is_type_assignable_ref(&actual, type_ref, constants));
    }

    if let Some(struct_name) = struct_name_from_type_ref(type_ref, structs) {
        let Some(item) = structs.get(struct_name) else {
            return false;
        };
        let ExprKind::StateObject(fields) = &expr.kind else {
            return false;
        };
        if fields.len() != item.fields.len() {
            return false;
        }
        for field in &item.fields {
            let Some(value) = fields.iter().find(|entry| entry.name == field.name).map(|entry| &entry.expr) else {
                return false;
            };
            if !expr_matches_return_type_ref(value, &field.type_ref, types, structs, constants) {
                return false;
            }
        }
        return true;
    }

    if let Some(element_type) = type_ref.element_type()
        && struct_name_from_type_ref(&element_type, structs).is_some()
    {
        return matches!(&expr.kind, ExprKind::Array(values) if values.iter().all(|value| expr_matches_return_type_ref(value, &element_type, types, structs, constants)));
    }

    match &expr.kind {
        ExprKind::Array(values) => {
            expr_matches_declared_type_ref(expr, type_ref, structs)
                || (is_array_type_ref(type_ref) && array_literal_matches_type_ref(values, type_ref))
        }
        ExprKind::Int(_) | ExprKind::DateLiteral(_) | ExprKind::Bool(_) | ExprKind::Byte(_) | ExprKind::String(_) => {
            expr_matches_type_ref(expr, type_ref)
        }
        _ => true,
    }
}

pub(super) fn expr_matches_type_ref<'i>(expr: &Expr<'i>, type_ref: &TypeRef) -> bool {
    if !type_ref.array_dims.is_empty() {
        if let Some(size) = fixed_array_size(type_ref) {
            if let Some(element_type) = type_ref.element_type() {
                if element_type.base == TypeBase::Byte {
                    return byte_array_len(expr) == Some(size);
                }
                return matches!(&expr.kind, ExprKind::Array(values) if values.len() == size && values.iter().all(|value| expr_matches_type_ref(value, &element_type)));
            }
        }
        return byte_array_len(expr).is_some()
            || matches!(&expr.kind, ExprKind::Array(values) if type_ref.element_type().is_some_and(|element_type| values.iter().all(|value| expr_matches_type_ref(value, &element_type))));
    }

    match type_ref.base {
        TypeBase::Int => matches!(&expr.kind, ExprKind::Int(_) | ExprKind::DateLiteral(_)),
        TypeBase::Bool => matches!(&expr.kind, ExprKind::Bool(_)),
        TypeBase::String => matches!(&expr.kind, ExprKind::String(_)),
        TypeBase::Byte => matches!(&expr.kind, ExprKind::Byte(_)),
        TypeBase::Pubkey => byte_array_len(expr) == Some(32),
        TypeBase::Sig => byte_array_len(expr) == Some(65),
        TypeBase::Datasig => byte_array_len(expr) == Some(64),
        TypeBase::Custom(_) => false,
    }
}

pub(super) fn value_matches_type_ref<'i>(expr: &Expr<'i>, type_ref: &TypeRef) -> bool {
    expr_matches_type_ref(expr, type_ref)
}

fn type_name_from_ref(type_ref: &TypeRef) -> String {
    type_ref.type_name()
}

fn byte_array_len<'i>(expr: &Expr<'i>) -> Option<usize> {
    match &expr.kind {
        ExprKind::Array(values) if values.iter().all(|value| matches!(&value.kind, ExprKind::Byte(_))) => Some(values.len()),
        _ => None,
    }
}

fn fixed_array_size(type_ref: &TypeRef) -> Option<usize> {
    match type_ref.array_dims.last() {
        Some(ArrayDim::Fixed(size)) => Some(*size),
        _ => None,
    }
}

fn is_array_type_ref(type_ref: &TypeRef) -> bool {
    !type_ref.array_dims.is_empty()
}

fn array_element_type_ref(type_ref: &TypeRef) -> Option<TypeRef> {
    type_ref.element_type()
}

pub(super) fn array_literal_matches_type_ref<'i>(values: &[Expr<'i>], type_ref: &TypeRef) -> bool {
    let Some(element_type) = array_element_type_ref(type_ref) else {
        return false;
    };

    if let Some(expected_size) = fixed_array_size(type_ref)
        && values.len() != expected_size
    {
        return false;
    }

    values.iter().all(|value| expr_matches_type_ref(value, &element_type))
}

fn array_literal_matches_type_with_env_ref<'i>(
    values: &[Expr<'i>],
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    constants: &HashMap<String, Expr<'i>>,
) -> bool {
    let Some(element_type) = array_element_type_ref(type_ref) else {
        return false;
    };

    if let Some(expected_size) = array_size_with_constants_ref(type_ref, constants)
        && values.len() != expected_size
    {
        return false;
    }

    values.iter().all(|value| match &value.kind {
        ExprKind::Identifier(name) => types
            .get(name)
            .and_then(|value_type| parse_type_ref(value_type).ok())
            .is_some_and(|value_type| is_type_assignable_ref(&value_type, &element_type, constants)),
        _ => expr_matches_type_ref(value, &element_type),
    })
}

fn has_explicit_array_size_ref(type_ref: &TypeRef) -> bool {
    !matches!(type_ref.array_size(), Some(ArrayDim::Dynamic | ArrayDim::Inferred) | None)
}

fn array_size_with_constants_ref<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    match type_ref.array_size() {
        Some(ArrayDim::Fixed(size)) => Some(*size),
        Some(ArrayDim::Constant(name)) => constants.get(name).and_then(|expr| match expr.kind {
            ExprKind::Int(value) if value >= 0 => Some(value as usize),
            _ => None,
        }),
        _ => None,
    }
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

fn is_type_assignable_ref<'i>(actual: &TypeRef, expected: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> bool {
    actual == expected || is_array_type_assignable_ref(actual, expected, constants)
}

fn expr_matches_return_type_ref_hint<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &HashMap<String, String>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<String> {
    if validate_expr_assignable_to_type(expr, type_ref, types, structs, constants, &[]).is_ok() {
        return None;
    }
    match (&expr.kind, &type_ref.base, type_ref.array_dims.is_empty()) {
        (ExprKind::Array(values), TypeBase::Byte, true) if values.len() == 1 => match values[0].kind {
            ExprKind::Byte(byte) => {
                Some(format!("hex literals are byte arrays; use byte({byte:#04x}) to cast a one-byte hex literal to byte"))
            }
            _ => None,
        },
        _ => None,
    }
}
