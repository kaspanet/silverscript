use super::*;
use semver::{Version, VersionReq};
use std::collections::{HashMap, HashSet};

pub(super) fn static_check_contract<'i>(
    contract: &ContractAst<'i>,
    constructor_args: &[Expr<'i>],
    options: CompileOptions,
) -> Result<(), CompilerError> {
    validate_pragma_versions(contract)?;

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
        let param_type_name = param.type_ref.type_name();
        if validate_expr_matches_type(value, &param.type_ref, &HashMap::new(), &structs, &constants, &HashMap::new(), &contract.fields)
            .is_err()
        {
            return Err(CompilerError::Unsupported(format!("constructor argument '{}' expects {}", param.name, param_type_name)));
        }
    }

    Ok(())
}

fn validate_pragma_versions<'i>(contract: &ContractAst<'i>) -> Result<(), CompilerError> {
    let Some(pragma) = &contract.pragma else {
        return Ok(());
    };

    let compiler_version = Version::parse(COMPILER_VERSION)
        .map_err(|err| CompilerError::Unsupported(format!("invalid SilverScript compiler version '{COMPILER_VERSION}': {err}")))?;
    if pragma.name != "silverscript" {
        return Err(CompilerError::Unsupported(format!("unknown pragma '{}'", pragma.name)).with_span(&pragma.name_span));
    }
    let req = VersionReq::parse(&pragma.value).map_err(|err| {
        CompilerError::Unsupported(format!("invalid SilverScript version requirement '{}': {err}", pragma.value))
            .with_span(&pragma.value_span)
    })?;
    if !req.matches(&compiler_version) {
        return Err(CompilerError::Unsupported(format!(
            "SilverScript compiler version {COMPILER_VERSION} does not satisfy pragma {}",
            pragma.value
        ))
        .with_span(&pragma.value_span));
    }

    Ok(())
}

pub(crate) fn validate_return_types<'i>(
    exprs: &[Expr<'i>],
    return_types: &[TypeRef],
    types: &TypeMap,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    if return_types.is_empty() {
        return Err(CompilerError::Unsupported("return requires function return types".to_string()));
    }
    if return_types.len() != exprs.len() {
        return Err(CompilerError::Unsupported("return values count must match function return types".to_string()));
    }
    for (expr, return_type) in exprs.iter().zip(return_types.iter()) {
        if validate_expr_matches_type(expr, return_type, types, structs, constants, functions, contract_fields).is_err() {
            let type_name = return_type.type_name();
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

    for function in &contract.functions {
        for param in &function.params {
            ensure_array_elements_have_known_size(&param.type_ref, structs, constants, &param.type_ref.type_name())?;
        }
        for return_type in &function.return_types {
            ensure_array_elements_have_known_size(return_type, structs, constants, &return_type.type_name())?;
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

        let mut types = initial_function_types(contract, function)?;
        validate_statement_shapes(
            &function.body,
            &mut types,
            &function.return_types,
            structs,
            constants,
            &functions,
            &contract.fields,
        )?;
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
        types.insert(param.name.clone(), param.type_ref.clone());
    }
    for constant in &contract.constants {
        types.insert(constant.name.clone(), constant.type_ref.clone());
    }

    for field in &contract.fields {
        let type_name = field.type_ref.type_name();
        ensure_array_elements_have_known_size(&field.type_ref, structs, constants, &type_name)?;
        validate_expr_matches_type(&field.expr, &field.type_ref, &types, structs, constants, &HashMap::new(), &contract.fields)
            .map_err(|_| CompilerError::Unsupported(format!("contract field '{}' expects {}", field.name, type_name)))?;
        types.insert(field.name.clone(), field.type_ref.clone());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_statement_shapes<'i>(
    statements: &[Statement<'i>],
    types: &mut TypeMap,
    return_types: &[TypeRef],
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    let mut ctx = ValidateStatementShapesContext { types, return_types, structs, constants, functions, contract_fields };

    for stmt in statements {
        match stmt {
            Statement::VariableDefinition { type_ref, name, expr, .. } => {
                validate_variable_definition_statement_shape(&mut ctx, type_ref, name, expr.as_ref())?
            }
            Statement::TupleAssignment { left_type_ref, left_name, right_type_ref, right_name, expr, .. } => {
                validate_tuple_assignment_statement_shape(&mut ctx, left_type_ref, left_name, right_type_ref, right_name, expr)?
            }
            Statement::StateFunctionCallAssign { bindings, name, args, .. } => {
                validate_state_function_call_assign_statement_shape(&mut ctx, bindings, name, args)?
            }
            Statement::StructDestructure { bindings, expr, .. } => {
                validate_struct_destructure_statement_shape(&mut ctx, bindings, expr)?
            }
            Statement::FunctionCall { name, args, .. } => validate_function_call_statement_shape(&mut ctx, name, args)?,
            Statement::FunctionCallAssign { bindings, name, args, .. } => {
                validate_function_call_assign_statement_shape(&mut ctx, bindings, name, args)?
            }
            Statement::Return { exprs, .. } => validate_return_statement_shape(&mut ctx, exprs)?,
            Statement::Require { expr, .. } => validate_require_statement_shape(&mut ctx, expr)?,
            Statement::TimeOp { expr, .. } => validate_time_op_statement_shape(&mut ctx, expr)?,
            Statement::Console { args, .. } => validate_console_statement_shape(&mut ctx, args)?,
            Statement::Assign { name, expr, .. } => validate_assign_statement_shape(&mut ctx, name, expr)?,
            Statement::Block { body, .. } => validate_block_statement_shape(&mut ctx, body)?,
            Statement::If { condition, then_branch, else_branch, .. } => {
                validate_if_statement_shape(&mut ctx, condition, then_branch, else_branch.as_deref())?
            }
            Statement::For { ident, start, end, max_iterations, body, .. } => {
                validate_for_statement_shape(&mut ctx, ident, start, end, max_iterations, body)?
            }
        }
    }

    Ok(())
}

struct ValidateStatementShapesContext<'a, 'i> {
    types: &'a mut TypeMap,
    return_types: &'a [TypeRef],
    structs: &'a StructRegistry,
    constants: &'a HashMap<String, Expr<'i>>,
    functions: &'a HashMap<String, &'a FunctionAst<'i>>,
    contract_fields: &'a [ContractFieldAst<'i>],
}

impl<'a, 'i> ValidateStatementShapesContext<'a, 'i> {
    fn type_check_context(&self) -> type_check::TypeCheckContext<'_, 'i> {
        type_check::TypeCheckContext {
            types: self.types,
            structs: self.structs,
            constants: self.constants,
            functions: self.functions,
            contract_fields: self.contract_fields,
        }
    }

    fn check_expr(&self, expr: &Expr<'i>, expected: Option<&TypeRef>) -> Result<TypeRef, CompilerError> {
        type_check::check_expr(expr, expected, &self.type_check_context())
    }

    fn check_call(&self, name: &str, args: &[Expr<'i>], expected: Option<&TypeRef>) -> Result<Option<TypeRef>, CompilerError> {
        type_check::check_call(name, name, args, expected, &self.type_check_context())
    }
}

fn validate_variable_definition_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    type_ref: &TypeRef,
    name: &str,
    expr: Option<&Expr<'i>>,
) -> Result<(), CompilerError> {
    let type_name = type_ref.type_name();
    ensure_array_elements_have_known_size(type_ref, ctx.structs, ctx.constants, &type_name)?;
    if expr.is_none() && type_ref.is_array() && array_type_size(type_ref, ctx.constants).is_some() {
        return Err(CompilerError::Unsupported("variable definition requires initializer".to_string()));
    }
    if let Some(expr) = expr {
        ctx.check_expr(expr, Some(type_ref)).map_err(|err| {
            if type_ref.is_array()
                && matches!(expr.kind, ExprKind::Array(_))
                && !matches!(&err, CompilerError::Unsupported(message) if message == "size mismatch")
            {
                return CompilerError::Unsupported(format!("array element type mismatch for type {type_name}"));
            }
            map_declared_type_error(
                err,
                "variable",
                name,
                &type_ref.type_name(),
                expr,
                type_ref,
                ctx.types,
                ctx.structs,
                ctx.constants,
            )
        })?;
    }
    insert_type_binding(ctx.types, name, type_ref);
    Ok(())
}

fn validate_tuple_assignment_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    left_type_ref: &TypeRef,
    left_name: &str,
    right_type_ref: &TypeRef,
    right_name: &str,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    ctx.check_expr(expr, None)?;
    ensure_array_elements_have_known_size(left_type_ref, ctx.structs, ctx.constants, &left_type_ref.type_name())?;
    ensure_array_elements_have_known_size(right_type_ref, ctx.structs, ctx.constants, &right_type_ref.type_name())?;
    insert_type_binding(ctx.types, left_name, left_type_ref);
    insert_type_binding(ctx.types, right_name, right_type_ref);
    Ok(())
}

fn validate_state_function_call_assign_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    match name {
        "readInputState" => {
            ctx.check_call(name, args, None)?;
        }
        "readInputStateWithTemplate" => {
            let struct_name = struct_name_for_state_bindings(bindings, ctx.structs, ctx.constants)?;
            let expected = TypeRef { base: TypeBase::Custom(struct_name), array_dims: Vec::new() };
            ctx.check_call(name, args, Some(&expected))?;
        }
        _ => {
            return Err(CompilerError::Unsupported(format!(
                "state destructuring assignment is only supported for readInputState()/readInputStateWithTemplate(), got '{name}()'"
            )));
        }
    }
    validate_state_function_call_assign(bindings, name, args, ctx.structs, ctx.constants, ctx.contract_fields)?;
    for binding in bindings {
        ensure_array_elements_have_known_size(&binding.type_ref, ctx.structs, ctx.constants, &binding.type_ref.type_name())?;
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref);
    }
    Ok(())
}

fn validate_struct_destructure_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    bindings: &[StructBindingAst<'i>],
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    let expr_type = ctx.check_expr(expr, None)?;
    let direct_read_input_state = matches!(&expr.kind, ExprKind::Call { name, .. } if name == "readInputState");
    validate_struct_destructure_bindings(bindings, &expr_type, direct_read_input_state, ctx.structs, ctx.constants)?;
    for binding in bindings {
        ensure_array_elements_have_known_size(&binding.type_ref, ctx.structs, ctx.constants, &binding.type_ref.type_name())?;
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref);
    }
    Ok(())
}

fn validate_function_call_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    if matches!(name, "validateOutputState" | "validateOutputStateWithTemplate") {
        return validate_output_state_call(ctx, name, args);
    }
    ctx.check_call(name, args, None).map(|_| ())
}

fn validate_output_state_call<'i>(
    ctx: &ValidateStatementShapesContext<'_, 'i>,
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let int_type = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
    match (name, args) {
        ("validateOutputState", [output_index, state]) => {
            let state_type = TypeRef { base: TypeBase::Custom(STATE_TYPE_NAME.to_string()), array_dims: Vec::new() };
            ctx.check_expr(output_index, Some(&int_type))?;
            ctx.check_expr(state, Some(&state_type)).map_err(|err| {
                if matches!(state.kind, ExprKind::StructLiteral(_)) {
                    err
                } else {
                    CompilerError::Unsupported("validateOutputState requires a State value".to_string())
                }
            })?;
            Ok(())
        }
        ("validateOutputState", _) => {
            Err(CompilerError::Unsupported("validateOutputState(output_idx, new_state) expects 2 arguments".to_string()))
        }
        ("validateOutputStateWithTemplate", [output_index, state, prefix, suffix, template_hash]) => {
            ctx.check_expr(output_index, Some(&int_type))?;
            let state_type = ctx.check_expr(state, None)?;
            if !is_struct(&state_type, ctx.structs) {
                return Err(CompilerError::Unsupported(
                    "validateOutputStateWithTemplate requires a struct value".to_string(),
                ));
            }
            for expression in [prefix, suffix, template_hash] {
                ctx.check_expr(expression, None)?;
            }
            Ok(())
        }
        ("validateOutputStateWithTemplate", _) => Err(CompilerError::Unsupported(
            "validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash) expects 5 arguments"
                .to_string(),
        )),
        _ => unreachable!(),
    }
}

fn validate_function_call_assign_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    bindings: &[ParamAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    if !ctx.functions.contains_key(name) {
        return Err(CompilerError::Unsupported(format!("function '{name}' not found")));
    }
    let return_type = ctx
        .check_call(name, args, None)?
        .ok_or_else(|| CompilerError::Unsupported(format!("function '{name}' does not return a value")))?;
    let return_types = return_type.tuple_elements().map(<[_]>::to_vec).unwrap_or_else(|| vec![return_type.clone()]);
    if bindings.len() != return_types.len() {
        return Err(CompilerError::Unsupported("function call assignment return count mismatch".to_string()));
    }
    for (binding, return_type) in bindings.iter().zip(&return_types) {
        if !type_refs_equal(&binding.type_ref, return_type, ctx.constants) {
            return Err(CompilerError::Unsupported(format!(
                "function return binding '{}' expects {}",
                binding.name,
                return_type.type_name()
            )));
        }
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref);
    }
    Ok(())
}

fn validate_return_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    exprs: &[Expr<'i>],
) -> Result<(), CompilerError> {
    validate_return_types(exprs, ctx.return_types, ctx.types, ctx.structs, ctx.constants, ctx.functions, ctx.contract_fields)
}

fn validate_require_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    ctx.check_expr(expr, Some(&TypeRef { base: TypeBase::Bool, array_dims: Vec::new() })).map(|_| ())
}

fn validate_time_op_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    ctx.check_expr(expr, Some(&TypeRef { base: TypeBase::Int, array_dims: Vec::new() })).map(|_| ())
}

fn validate_console_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    for arg in args {
        ctx.check_expr(arg, None)?;
    }
    Ok(())
}

fn validate_assign_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    name: &str,
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    if let Some(type_ref) = ctx.types.get(name).cloned() {
        let type_name = type_ref.type_name();
        ctx.check_expr(expr, Some(&type_ref)).map_err(|err| {
            map_declared_type_error(err, "variable", name, &type_name, expr, &type_ref, ctx.types, ctx.structs, ctx.constants)
        })?;
    }
    Ok(())
}

fn validate_if_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    condition: &Expr<'i>,
    then_branch: &[Statement<'i>],
    else_branch: Option<&[Statement<'i>]>,
) -> Result<(), CompilerError> {
    ctx.check_expr(condition, Some(&TypeRef { base: TypeBase::Bool, array_dims: Vec::new() }))?;
    let mut then_types = ctx.types.clone();
    validate_statement_shapes(
        then_branch,
        &mut then_types,
        ctx.return_types,
        ctx.structs,
        ctx.constants,
        ctx.functions,
        ctx.contract_fields,
    )?;
    if let Some(else_branch) = else_branch {
        let mut else_types = ctx.types.clone();
        validate_statement_shapes(
            else_branch,
            &mut else_types,
            ctx.return_types,
            ctx.structs,
            ctx.constants,
            ctx.functions,
            ctx.contract_fields,
        )?;
    }
    Ok(())
}

fn validate_block_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    body: &[Statement<'i>],
) -> Result<(), CompilerError> {
    let mut block_types = ctx.types.clone();
    validate_statement_shapes(body, &mut block_types, ctx.return_types, ctx.structs, ctx.constants, ctx.functions, ctx.contract_fields)
}

fn validate_for_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    ident: &str,
    start: &Expr<'i>,
    end: &Expr<'i>,
    max_iterations: &Expr<'i>,
    body: &[Statement<'i>],
) -> Result<(), CompilerError> {
    let int_type = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
    ctx.check_expr(start, Some(&int_type))?;
    ctx.check_expr(end, Some(&int_type))?;
    ctx.check_expr(max_iterations, Some(&int_type))?;
    let mut body_types = ctx.types.clone();
    body_types.insert(ident.to_string(), int_type);
    validate_statement_shapes(body, &mut body_types, ctx.return_types, ctx.structs, ctx.constants, ctx.functions, ctx.contract_fields)
}

fn validate_struct_destructure_bindings<'i>(
    bindings: &[StructBindingAst<'i>],
    expr_type: &TypeRef,
    direct_read_input_state: bool,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let struct_name = struct_name(expr_type, structs)
        .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string()))?;
    let struct_ast = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
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
        if !type_refs_equal(&binding.type_ref, &field.type_ref, constants) {
            return Err(CompilerError::Unsupported(format!("struct field '{}' expects {}", field.name, field.type_ref.type_name())));
        }
        if direct_read_input_state && is_struct(&binding.type_ref, structs) {
            return Err(CompilerError::Unsupported("readInputState does not support nested struct fields".to_string()));
        }
    }

    Ok(())
}

// TODO: Remove this special case and destructure the State struct like any other struct.
fn validate_state_function_call_assign<'i>(
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
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
                if !type_refs_equal(&binding.type_ref, &field.type_ref, constants) {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputState binding '{}' expects {}",
                        binding.name,
                        field.type_ref.type_name()
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
            let struct_name = struct_name_for_state_bindings(bindings, structs, constants)?;
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
                if is_struct(&field.type_ref, structs) {
                    return Err(CompilerError::Unsupported(
                        "readInputStateWithTemplate does not support nested struct fields in destructuring".to_string(),
                    ));
                }
                if !type_refs_equal(&binding.type_ref, &field.type_ref, constants) {
                    return Err(CompilerError::Unsupported(format!(
                        "readInputStateWithTemplate binding '{}' expects {}",
                        binding.name,
                        field.type_ref.type_name()
                    )));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn struct_name_for_state_bindings<'i>(
    bindings: &[StructBindingAst<'i>],
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
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
                    .is_some_and(|binding| type_refs_equal(&binding.type_ref, &field.type_ref, constants))
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

fn initial_function_types<'i>(contract: &ContractAst<'i>, function: &FunctionAst<'i>) -> Result<TypeMap, CompilerError> {
    let mut types = HashMap::new();

    for param in &contract.params {
        insert_type_binding(&mut types, &param.name, &param.type_ref);
    }
    for field in &contract.fields {
        insert_type_binding(&mut types, &field.name, &field.type_ref);
    }
    for constant in &contract.constants {
        insert_type_binding(&mut types, &constant.name, &constant.type_ref);
    }
    for param in &function.params {
        insert_type_binding(&mut types, &param.name, &param.type_ref);
    }

    Ok(types)
}

fn insert_type_binding(types: &mut TypeMap, name: &str, type_ref: &TypeRef) {
    types.insert(name.to_string(), type_ref.clone());
}

pub(crate) fn validate_expr_matches_type<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &TypeMap,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    let ctx = type_check::TypeCheckContext { types, structs, constants, functions, contract_fields };
    type_check::check_expr(expr, Some(type_ref), &ctx).map(|_| ())
}

fn map_declared_type_error<'i>(
    err: CompilerError,
    kind: &str,
    name: &str,
    type_name: &str,
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &TypeMap,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> CompilerError {
    match err {
        CompilerError::Unsupported(message) if message == "type mismatch" => {
            let hint = expr_matches_return_type_hint(expr, type_ref, types, structs, constants)
                .map(|hint| format!("; {hint}"))
                .unwrap_or_default();
            CompilerError::Unsupported(format!("{kind} '{}' expects {}{}", name, type_name, hint))
        }
        other => other,
    }
}

fn ensure_array_elements_have_known_size<'i>(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    type_name: &str,
) -> Result<(), CompilerError> {
    if type_ref.is_array() && fixed_type_size(type_ref.array_element_type().as_ref().unwrap_or(type_ref), structs, constants).is_none()
    {
        return Err(CompilerError::Unsupported(format!("array element type must have known size: {type_name}")));
    }
    Ok(())
}

fn fixed_type_size<'i>(type_ref: &TypeRef, structs: &StructRegistry, constants: &HashMap<String, Expr<'i>>) -> Option<usize> {
    if type_ref.is_array() {
        let element_type = type_ref.array_element_type()?;
        let array_len = array_type_size(type_ref, constants)?;
        return fixed_type_size(&element_type, structs, constants)?.checked_mul(array_len);
    }

    match &type_ref.base {
        TypeBase::Int => Some(8),
        TypeBase::Bool | TypeBase::Byte => Some(1),
        TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig => type_ref.base.fixed_byte_sequence_len(),
        TypeBase::String => None,
        TypeBase::Custom(name) => {
            let struct_spec = structs.get(name)?;
            let mut total = 0usize;
            for field in &struct_spec.fields {
                total = total.checked_add(fixed_type_size(&field.type_ref, structs, constants)?)?;
            }
            Some(total)
        }
        TypeBase::Tuple(_) => None,
    }
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

fn expr_matches_return_type_hint<'i>(
    expr: &Expr<'i>,
    type_ref: &TypeRef,
    types: &TypeMap,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<String> {
    if validate_expr_matches_type(expr, type_ref, types, structs, constants, &HashMap::new(), &[]).is_ok() {
        return None;
    }
    match (&expr.kind, &type_ref.base, !type_ref.is_array()) {
        (ExprKind::Array(values), TypeBase::Byte, true) if values.len() == 1 => match values[0].kind {
            ExprKind::Byte(byte) => {
                Some(format!("hex literals are byte arrays; use byte({byte:#04x}) to cast a one-byte hex literal to byte"))
            }
            _ => None,
        },
        _ => None,
    }
}
