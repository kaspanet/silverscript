use super::*;
use semver::{Comparator, Op, Version, VersionReq};
use std::collections::{HashMap, HashSet};

pub(super) fn validate_declaration_names(contract: &ContractAst<'_>) -> Result<(), CompilerError> {
    let mut names = HashSet::new();
    for param in &contract.params {
        if !names.insert(param.name.as_str()) {
            return Err(
                CompilerError::Unsupported(format!("duplicate contract parameter name '{}'", param.name)).with_span(&param.name_span)
            );
        }
    }

    names.clear();
    for constant in &contract.constants {
        if !names.insert(constant.name.as_str()) {
            return Err(
                CompilerError::Unsupported(format!("duplicate constant name '{}'", constant.name)).with_span(&constant.name_span)
            );
        }
    }

    let mut contract_names = HashSet::new();
    for (name, span) in contract
        .params
        .iter()
        .map(|param| (param.name.as_str(), &param.name_span))
        .chain(contract.constants.iter().map(|constant| (constant.name.as_str(), &constant.name_span)))
        .chain(contract.fields.iter().map(|field| (field.name.as_str(), &field.name_span)))
    {
        insert_variable_name(&mut contract_names, name, span)?;
    }

    for function in &contract.functions {
        names.clear();
        for param in &function.params {
            if !names.insert(param.name.as_str()) {
                return Err(CompilerError::Unsupported(format!(
                    "duplicate parameter name '{}' in function '{}'",
                    param.name, function.name
                ))
                .with_span(&param.name_span));
            }
        }

        let mut function_names = contract_names.clone();
        for param in &function.params {
            insert_variable_name(&mut function_names, &param.name, &param.name_span)?;
        }
        validate_statement_declaration_names(&function.body, &mut function_names)?;
    }

    Ok(())
}

fn insert_variable_name<'i>(names: &mut HashSet<&'i str>, name: &'i str, span: &span::Span<'i>) -> Result<(), CompilerError> {
    if !names.insert(name) {
        return Err(CompilerError::Unsupported(format!("variable '{name}' is already defined")).with_span(span));
    }
    Ok(())
}

fn validate_statement_declaration_names<'i>(
    statements: &'i [Statement<'i>],
    names: &mut HashSet<&'i str>,
) -> Result<(), CompilerError> {
    for statement in statements {
        match statement {
            Statement::VariableDefinition { name, name_span, .. } => insert_variable_name(names, name, name_span)?,
            Statement::TupleAssignment { left_name, left_name_span, right_name, right_name_span, .. } => {
                insert_variable_name(names, left_name, left_name_span)?;
                insert_variable_name(names, right_name, right_name_span)?;
            }
            Statement::FunctionCallAssign { bindings, .. } => {
                for binding in bindings {
                    insert_variable_name(names, &binding.name, &binding.name_span)?;
                }
            }
            Statement::StateFunctionCallAssign { bindings, .. } | Statement::StructDestructure { bindings, .. } => {
                for binding in bindings {
                    insert_variable_name(names, &binding.name, &binding.name_span)?;
                }
            }
            Statement::Block { body, .. } => {
                let mut block_names = names.clone();
                validate_statement_declaration_names(body, &mut block_names)?;
            }
            Statement::If { then_branch, else_branch, .. } => {
                let mut then_names = names.clone();
                validate_statement_declaration_names(then_branch, &mut then_names)?;
                if let Some(else_branch) = else_branch {
                    let mut else_names = names.clone();
                    validate_statement_declaration_names(else_branch, &mut else_names)?;
                }
            }
            Statement::For { ident, ident_span, body, .. } => {
                let mut loop_names = names.clone();
                insert_variable_name(&mut loop_names, ident, ident_span)?;
                validate_statement_declaration_names(body, &mut loop_names)?;
            }
            Statement::FunctionCall { .. }
            | Statement::Assign { .. }
            | Statement::TimeOp { .. }
            | Statement::Require { .. }
            | Statement::Return { .. }
            | Statement::Console { .. } => {}
        }
    }
    Ok(())
}

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
    let mut constants: HashMap<String, Expr<'i>> =
        contract.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    for (param, value) in contract.params.iter().zip(constructor_args) {
        constants.insert(param.name.clone(), value.clone());
    }
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
    if covers_future_major_versions(&req, &compiler_version) {
        return Err(CompilerError::Unsupported(
            "SilverScript compiler cannot support pragmas that cover future major versions because they may have breaking changes"
                .to_string(),
        )
        .with_span(&pragma.value_span));
    }
    if !req.matches(&compiler_version) {
        return Err(CompilerError::Unsupported(format!(
            "SilverScript compiler version {COMPILER_VERSION} does not satisfy pragma {}",
            pragma.value
        ))
        .with_span(&pragma.value_span));
    }

    Ok(())
}

fn covers_future_major_versions(req: &VersionReq, compiler_version: &Version) -> bool {
    let Some(next_major) = compiler_version.major.checked_add(1) else {
        return false;
    };

    !req.comparators.iter().any(|comparator| comparator_excludes_future_majors(comparator, compiler_version.major, next_major))
}

fn comparator_excludes_future_majors(comparator: &Comparator, current_major: u64, next_major: u64) -> bool {
    match comparator.op {
        Op::Exact | Op::Tilde | Op::Caret | Op::Wildcard => comparator.major <= current_major,
        Op::Less => {
            comparator.major <= current_major
                || (comparator.major == next_major
                    && comparator.minor.unwrap_or(0) == 0
                    && comparator.patch.unwrap_or(0) == 0
                    && comparator.pre.is_empty())
        }
        Op::LessEq => comparator.major <= current_major,
        Op::Greater | Op::GreaterEq => false,
        _ => false,
    }
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
        ensure_known_struct_or_builtin_type(&param.type_ref, structs, "contract parameter")?;
    }
    for field in &contract.fields {
        ensure_known_struct_or_builtin_type(&field.type_ref, structs, "contract field")?;
    }
    for constant in &contract.constants {
        ensure_known_struct_or_builtin_type(&constant.type_ref, structs, "constant")?;
    }

    Ok(())
}

fn validate_function_signatures<'i>(
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    options: CompileOptions,
) -> Result<(), CompilerError> {
    let mut function_names = HashSet::new();
    for function in &contract.functions {
        if !function_names.insert(function.name.as_str()) {
            return Err(CompilerError::Unsupported(format!("duplicate function name '{}'", function.name)));
        }
    }
    let functions = contract.functions.iter().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();

    for function in &contract.functions {
        if function.entrypoint {
            for param in &function.params {
                if contract.fields.iter().any(|field| field.name == param.name) {
                    return Err(CompilerError::Unsupported(format!(
                        "entrypoint parameter '{}' conflicts with contract field of the same name",
                        param.name
                    )));
                }
            }
        }
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
            Statement::StateFunctionCallAssign { target_struct, bindings, name, args, .. } => {
                validate_state_function_call_assign_statement_shape(&mut ctx, target_struct, bindings, name, args)?
            }
            Statement::StructDestructure { struct_name, bindings, expr, .. } => {
                validate_struct_destructure_statement_shape(&mut ctx, struct_name, bindings, expr)?
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
        type_check::check_call(name, args, expected, &self.type_check_context())
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
                && matches!(expr.kind, ExprKind::Array { .. })
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
    target_struct: &str,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    args: &[Expr<'i>],
) -> Result<(), CompilerError> {
    let expected = TypeRef { base: TypeBase::Custom(target_struct.to_string()), array_dims: Vec::new() };
    ctx.check_call(name, args, Some(&expected))?;
    validate_state_function_call_assign(target_struct, bindings, name, ctx.structs, ctx.constants, ctx.contract_fields)?;
    for binding in bindings {
        ensure_array_elements_have_known_size(&binding.type_ref, ctx.structs, ctx.constants, &binding.type_ref.type_name())?;
        insert_type_binding(ctx.types, &binding.name, &binding.type_ref);
    }
    Ok(())
}

fn validate_struct_destructure_statement_shape<'i>(
    ctx: &mut ValidateStatementShapesContext<'_, 'i>,
    expected_struct_name: &str,
    bindings: &[StructBindingAst<'i>],
    expr: &Expr<'i>,
) -> Result<(), CompilerError> {
    let expected_type = TypeRef { base: TypeBase::Custom(expected_struct_name.to_string()), array_dims: Vec::new() };
    let expr_type = ctx.check_expr(expr, Some(&expected_type))?;
    let direct_read_input_state = matches!(&expr.kind, ExprKind::Call { name, .. } if name == "readInputState");
    validate_struct_destructure_bindings(
        bindings,
        &expr_type,
        direct_read_input_state.then_some("readInputState"),
        ctx.structs,
        ctx.constants,
    )?;
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
    if matches!(name, "validateOutputState" | "validateOutputStateWithTemplate" | "validateOutputStateWithInputTemplate") {
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
    let bytes_type = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Dynamic] };
    let hash_type = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(32)] };
    match (name, args) {
        ("validateOutputState", [output_index, state]) => {
            let state_type = TypeRef { base: TypeBase::Custom(STATE_TYPE_NAME.to_string()), array_dims: Vec::new() };
            ctx.check_expr(output_index, Some(&int_type))?;
            ctx.check_expr(state, Some(&state_type)).map_err(|err| {
                if matches!(state.kind, ExprKind::StructLiteral { .. }) {
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
            ctx.check_expr(prefix, Some(&bytes_type))?;
            ctx.check_expr(suffix, Some(&bytes_type))?;
            ctx.check_expr(template_hash, Some(&hash_type))?;
            Ok(())
        }
        ("validateOutputStateWithTemplate", _) => Err(CompilerError::Unsupported(
            "validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash) expects 5 arguments"
                .to_string(),
        )),
        (
            "validateOutputStateWithInputTemplate",
            [output_index, state, template_input_index, template_prefix_len, template_suffix_len, template_hash],
        ) => {
            ctx.check_expr(output_index, Some(&int_type))?;
            let state_type = ctx.check_expr(state, None)?;
            if !is_struct(&state_type, ctx.structs) {
                return Err(CompilerError::Unsupported(
                    "validateOutputStateWithInputTemplate requires a struct value".to_string(),
                ));
            }
            for expression in [template_input_index, template_prefix_len, template_suffix_len] {
                ctx.check_expr(expression, Some(&int_type))?;
            }
            ctx.check_expr(template_hash, Some(&hash_type))?;
            Ok(())
        }
        ("validateOutputStateWithInputTemplate", _) => Err(CompilerError::Unsupported(
            "validateOutputStateWithInputTemplate(output_idx, new_state, template_input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 6 arguments"
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
    state_reader: Option<&str>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(), CompilerError> {
    let struct_name = struct_name(expr_type, structs)
        .ok_or_else(|| CompilerError::Unsupported("struct destructuring requires a struct value".to_string()))?;
    let struct_ast = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
    let mut seen_fields = HashSet::new();
    let mut seen_names = HashSet::new();

    for binding in bindings {
        ensure_known_struct_or_builtin_type(&binding.type_ref, structs, "struct destructuring")?;
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
        if let Some(state_reader) = state_reader
            && is_struct(&binding.type_ref, structs)
        {
            return Err(CompilerError::Unsupported(format!("{state_reader} does not support nested struct fields")));
        }
    }

    Ok(())
}

fn validate_state_function_call_assign<'i>(
    target_struct: &str,
    bindings: &[StructBindingAst<'i>],
    name: &str,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    if name == "readInputState" && contract_fields.is_empty() {
        return Err(CompilerError::Unsupported("readInputState requires contract fields".to_string()));
    }
    let expected = TypeRef { base: TypeBase::Custom(target_struct.to_string()), array_dims: Vec::new() };
    validate_struct_destructure_bindings(bindings, &expected, Some(name), structs, constants)
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
    for dimension in &type_ref.array_dims {
        let ArrayDim::Constant(name) = dimension else {
            continue;
        };
        let expr =
            constants.get(name).ok_or_else(|| CompilerError::UndefinedIdentifier(format!("array dimension constant '{name}'")))?;
        let value = eval_const_int(expr, constants)?;
        usize::try_from(value)
            .map_err(|_| CompilerError::InvalidLiteral(format!("array dimension '{name}' must be a non-negative integer")))?;
    }

    if type_ref.is_array()
        && fixed_type_size_with_structs(type_ref.array_element_type().as_ref().unwrap_or(type_ref), structs, constants).is_none()
    {
        return Err(CompilerError::Unsupported(format!("array element type must have known size: {type_name}")));
    }
    Ok(())
}

fn fixed_type_size_with_structs<'i>(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Option<usize> {
    if type_ref.is_array() {
        let element_type = type_ref.array_element_type()?;
        let array_len = array_type_size(type_ref, constants)?;
        return fixed_type_size_with_structs(&element_type, structs, constants)?.checked_mul(array_len);
    }

    match &type_ref.base {
        TypeBase::Custom(name) => {
            let struct_spec = structs.get(name)?;
            let mut total = 0usize;
            for field in &struct_spec.fields {
                total = total.checked_add(fixed_type_size_with_structs(&field.type_ref, structs, constants)?)?;
            }
            Some(total)
        }
        _ => fixed_type_size(type_ref, constants),
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
    None
}
