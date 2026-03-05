use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CovenantBinding {
    Auth,
    Cov,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CovenantMode {
    Verification,
    Transition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CovenantGroups {
    Single,
    Multiple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CovenantTermination {
    Disallowed,
    Allowed,
}

#[derive(Debug, Clone)]
struct CovenantDeclaration<'i> {
    binding: CovenantBinding,
    mode: CovenantMode,
    groups: CovenantGroups,
    singleton: bool,
    termination: CovenantTermination,
    from_expr: Expr<'i>,
    to_expr: Expr<'i>,
}

#[derive(Debug, Clone)]
enum OutputStateSource<'i> {
    Single(Expr<'i>),
    PerOutputArrays {
        // field_name -> array_binding_name
        field_arrays: Vec<(String, String)>,
        length_expr: Expr<'i>,
    },
}

#[derive(Debug, Clone)]
struct VerificationShape<'i> {
    prev_field_values: Vec<(String, String)>,
    new_field_arrays: Vec<(String, String)>,
    entrypoint_params: Vec<crate::ast::ParamAst<'i>>,
    call_args: Vec<Expr<'i>>,
}

#[derive(Debug, Clone)]
struct TransitionShape<'i> {
    entrypoint_params: Vec<crate::ast::ParamAst<'i>>,
    call_args: Vec<Expr<'i>>,
}

pub(super) fn lower_covenant_declarations<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let mut lowered = Vec::new();

    let mut used_names: HashSet<String> =
        contract.functions.iter().filter(|function| function.attributes.is_empty()).map(|function| function.name.clone()).collect();

    for function in &contract.functions {
        if function.attributes.is_empty() {
            lowered.push(function.clone());
            continue;
        }

        let declaration = parse_covenant_declaration(function, constants)?;

        let policy_name = format!("__covenant_policy_{}", function.name);
        if used_names.contains(&policy_name) {
            return Err(CompilerError::Unsupported(format!(
                "generated policy function name '{}' conflicts with existing function",
                policy_name
            )));
        }
        used_names.insert(policy_name.clone());

        let mut policy = function.clone();
        policy.name = policy_name.clone();
        policy.entrypoint = false;
        policy.attributes.clear();
        lowered.push(policy);

        match declaration.binding {
            CovenantBinding::Auth => {
                let entrypoint_name = function.name.clone();
                if used_names.contains(&entrypoint_name) {
                    return Err(CompilerError::Unsupported(format!(
                        "generated entrypoint '{}' conflicts with existing function",
                        entrypoint_name
                    )));
                }
                used_names.insert(entrypoint_name.clone());
                lowered.push(build_auth_wrapper(function, &policy_name, declaration, entrypoint_name, &contract.fields)?);
            }
            CovenantBinding::Cov => {
                let leader_name = format!("{}_leader", function.name);
                if used_names.contains(&leader_name) {
                    return Err(CompilerError::Unsupported(format!(
                        "generated entrypoint '{}' conflicts with existing function",
                        leader_name
                    )));
                }
                used_names.insert(leader_name.clone());
                lowered.push(build_cov_wrapper(function, &policy_name, declaration.clone(), leader_name, true, &contract.fields)?);

                let delegate_name = format!("{}_delegate", function.name);
                if used_names.contains(&delegate_name) {
                    return Err(CompilerError::Unsupported(format!(
                        "generated entrypoint '{}' conflicts with existing function",
                        delegate_name
                    )));
                }
                used_names.insert(delegate_name.clone());
                lowered.push(build_cov_wrapper(function, &policy_name, declaration, delegate_name, false, &contract.fields)?);
            }
        }
    }

    let mut lowered_contract = contract.clone();
    lowered_contract.functions = lowered;
    Ok(lowered_contract)
}

fn parse_covenant_declaration<'i>(
    function: &FunctionAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<CovenantDeclaration<'i>, CompilerError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CovenantSyntax {
        Canonical,
        Singleton,
        Fanout,
    }

    if function.entrypoint {
        return Err(CompilerError::Unsupported(
            "#[covenant(...)] must be applied to a policy function, not an entrypoint".to_string(),
        ));
    }

    if function.attributes.len() != 1 {
        return Err(CompilerError::Unsupported("covenant declarations support exactly one #[covenant(...)] attribute".to_string()));
    }

    let attribute = &function.attributes[0];
    let syntax = match attribute.path.as_slice() {
        [head] if head == "covenant" => CovenantSyntax::Canonical,
        [head, tail] if head == "covenant" && tail == "singleton" => CovenantSyntax::Singleton,
        [head, tail] if head == "covenant" && tail == "fanout" => CovenantSyntax::Fanout,
        _ => {
            return Err(CompilerError::Unsupported(format!(
                "unsupported function attribute #[{}]; expected #[covenant(...)], #[covenant.singleton], or #[covenant.fanout(...)]",
                attribute.path.join(".")
            )));
        }
    };

    let mut args_by_name: HashMap<&str, &Expr<'i>> = HashMap::new();
    for arg in &attribute.args {
        if args_by_name.insert(arg.name.as_str(), &arg.expr).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate covenant attribute argument '{}'", arg.name)));
        }
    }

    let allowed_keys: HashSet<&str> = ["binding", "from", "to", "mode", "groups", "termination"].into_iter().collect();
    for arg in &attribute.args {
        if !allowed_keys.contains(arg.name.as_str()) {
            return Err(CompilerError::Unsupported(format!("unknown covenant attribute argument '{}'", arg.name)));
        }
    }

    let (from_expr, to_expr) = match syntax {
        CovenantSyntax::Canonical => {
            let from_expr = args_by_name
                .get("from")
                .copied()
                .ok_or_else(|| CompilerError::Unsupported("missing covenant attribute argument 'from'".to_string()))?
                .clone();
            let to_expr = args_by_name
                .get("to")
                .copied()
                .ok_or_else(|| CompilerError::Unsupported("missing covenant attribute argument 'to'".to_string()))?
                .clone();
            (from_expr, to_expr)
        }
        CovenantSyntax::Singleton => {
            if args_by_name.contains_key("from") || args_by_name.contains_key("to") {
                return Err(CompilerError::Unsupported(
                    "covenant.singleton is sugar and does not accept 'from' or 'to' arguments".to_string(),
                ));
            }
            (Expr::int(1), Expr::int(1))
        }
        CovenantSyntax::Fanout => {
            if args_by_name.contains_key("from") {
                return Err(CompilerError::Unsupported(
                    "covenant.fanout is sugar and does not accept a 'from' argument (it is always 1)".to_string(),
                ));
            }
            let to_expr = args_by_name
                .get("to")
                .copied()
                .ok_or_else(|| CompilerError::Unsupported("missing covenant attribute argument 'to'".to_string()))?
                .clone();
            (Expr::int(1), to_expr)
        }
    };

    let from_value = eval_const_int(&from_expr, constants)
        .map_err(|_| CompilerError::Unsupported("covenant 'from' must be a compile-time integer".to_string()))?;
    let to_value = eval_const_int(&to_expr, constants)
        .map_err(|_| CompilerError::Unsupported("covenant 'to' must be a compile-time integer".to_string()))?;
    if from_value < 1 {
        return Err(CompilerError::Unsupported("covenant 'from' must be >= 1".to_string()));
    }
    if to_value < 1 {
        return Err(CompilerError::Unsupported("covenant 'to' must be >= 1".to_string()));
    }

    let default_binding = if from_value == 1 { CovenantBinding::Auth } else { CovenantBinding::Cov };
    let binding = match args_by_name.get("binding").copied() {
        Some(expr) => {
            let binding_name = parse_attr_ident_arg("binding", Some(expr))?;
            match binding_name.as_str() {
                "auth" => CovenantBinding::Auth,
                "cov" => CovenantBinding::Cov,
                other => {
                    return Err(CompilerError::Unsupported(format!("covenant binding must be auth|cov, got '{}'", other)));
                }
            }
        }
        None => default_binding,
    };

    let mode = match args_by_name.get("mode").copied() {
        Some(expr) => {
            let mode_name = parse_attr_ident_arg("mode", Some(expr))?;
            match mode_name.as_str() {
                "verification" => CovenantMode::Verification,
                "transition" => CovenantMode::Transition,
                other => {
                    return Err(CompilerError::Unsupported(format!("covenant mode must be verification|transition, got '{}'", other)));
                }
            }
        }
        None => {
            if function.return_types.is_empty() {
                CovenantMode::Verification
            } else {
                CovenantMode::Transition
            }
        }
    };

    let groups = match args_by_name.get("groups").copied() {
        Some(expr) => {
            let groups_name = parse_attr_ident_arg("groups", Some(expr))?;
            match groups_name.as_str() {
                "single" => CovenantGroups::Single,
                "multiple" => CovenantGroups::Multiple,
                other => {
                    return Err(CompilerError::Unsupported(format!("covenant groups must be single|multiple, got '{}'", other)));
                }
            }
        }
        None => match binding {
            CovenantBinding::Auth => CovenantGroups::Multiple,
            CovenantBinding::Cov => CovenantGroups::Single,
        },
    };

    let termination = match args_by_name.get("termination").copied() {
        Some(expr) => {
            let termination_name = parse_attr_ident_arg("termination", Some(expr))?;
            match termination_name.as_str() {
                "disallowed" => CovenantTermination::Disallowed,
                "allowed" => CovenantTermination::Allowed,
                other => {
                    return Err(CompilerError::Unsupported(format!(
                        "covenant termination must be disallowed|allowed, got '{}'",
                        other
                    )));
                }
            }
        }
        None => CovenantTermination::Disallowed,
    };

    if binding == CovenantBinding::Auth && from_value != 1 {
        return Err(CompilerError::Unsupported("binding=auth requires from = 1".to_string()));
    }
    if binding == CovenantBinding::Cov && from_value == 1 && args_by_name.contains_key("binding") {
        eprintln!(
            "warning: #[covenant(...)] on function '{}' uses binding=cov with from=1; binding=auth is usually a better default",
            function.name
        );
    }
    if binding == CovenantBinding::Cov && groups == CovenantGroups::Multiple {
        return Err(CompilerError::Unsupported("binding=cov with groups=multiple is not supported yet".to_string()));
    }

    if args_by_name.contains_key("termination") && mode != CovenantMode::Transition {
        return Err(CompilerError::Unsupported("termination is only supported in mode=transition".to_string()));
    }
    if args_by_name.contains_key("termination") && !(from_value == 1 && to_value == 1) {
        return Err(CompilerError::Unsupported("termination is only supported for singleton covenants (from=1, to=1)".to_string()));
    }

    if mode == CovenantMode::Verification && !function.return_types.is_empty() {
        return Err(CompilerError::Unsupported("verification mode policy functions must not declare return values".to_string()));
    }
    if mode == CovenantMode::Transition && function.return_types.is_empty() {
        return Err(CompilerError::Unsupported("transition mode policy functions must declare return values".to_string()));
    }

    Ok(CovenantDeclaration {
        binding,
        mode,
        groups,
        singleton: from_value == 1 && to_value == 1,
        termination,
        from_expr: from_expr.clone(),
        to_expr: to_expr.clone(),
    })
}

fn parse_attr_ident_arg<'i>(name: &str, value: Option<&Expr<'i>>) -> Result<String, CompilerError> {
    let value = value.ok_or_else(|| CompilerError::Unsupported(format!("missing covenant attribute argument '{}'", name)))?;
    match &value.kind {
        ExprKind::Identifier(identifier) => Ok(identifier.clone()),
        _ => Err(CompilerError::Unsupported(format!("covenant attribute argument '{}' must be an identifier", name))),
    }
}

fn build_auth_wrapper<'i>(
    policy: &FunctionAst<'i>,
    policy_name: &str,
    declaration: CovenantDeclaration<'i>,
    entrypoint_name: String,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut body = Vec::new();
    let mut entrypoint_params = policy.params.clone();

    let active_input = active_input_index_expr();
    let out_count_name = "__cov_out_count";
    body.push(var_def_statement(int_type_ref(), out_count_name, Expr::call("OpAuthOutputCount", vec![active_input.clone()])));

    if declaration.groups == CovenantGroups::Single {
        let cov_id_name = "__cov_id";
        body.push(var_def_statement(bytes32_type_ref(), cov_id_name, Expr::call("OpInputCovenantId", vec![active_input.clone()])));
        let cov_out_count_name = "__cov_shared_out_count";
        body.push(var_def_statement(
            int_type_ref(),
            cov_out_count_name,
            Expr::call("OpCovOutCount", vec![identifier_expr(cov_id_name)]),
        ));
        body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(cov_out_count_name), identifier_expr(out_count_name))));
    }

    if declaration.mode == CovenantMode::Verification && !contract_fields.is_empty() {
        let shape = parse_verification_shape(policy, contract_fields, CovenantBinding::Auth)?;
        entrypoint_params = shape.entrypoint_params.clone();
        body.push(call_statement(policy_name, shape.call_args));
        body.push(require_statement(binary_expr(BinaryOp::Le, identifier_expr(out_count_name), declaration.to_expr.clone())));
        append_auth_output_array_state_checks(
            &mut body,
            &active_input,
            out_count_name,
            declaration.to_expr.clone(),
            shape.new_field_arrays,
            contract_fields,
        );
    } else {
        let mut call_args: Vec<Expr<'i>> = policy.params.iter().map(|param| identifier_expr(&param.name)).collect();
        if declaration.mode == CovenantMode::Transition && !contract_fields.is_empty() {
            let shape = parse_transition_shape(policy, contract_fields, CovenantBinding::Auth)?;
            entrypoint_params = shape.entrypoint_params;
            call_args = shape.call_args;
        }
        let state_source = append_policy_call_and_capture_next_state(
            &mut body,
            policy,
            policy_name,
            declaration.mode,
            declaration.singleton,
            declaration.termination,
            contract_fields,
            call_args,
        )?;
        if !contract_fields.is_empty() {
            match state_source {
                OutputStateSource::Single(next_state_expr) => {
                    if declaration.mode == CovenantMode::Transition || declaration.singleton {
                        body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(out_count_name), Expr::int(1))));
                        let out_idx_name = "__cov_out_idx";
                        body.push(var_def_statement(
                            int_type_ref(),
                            out_idx_name,
                            Expr::call("OpAuthOutputIdx", vec![active_input.clone(), Expr::int(0)]),
                        ));
                        body.push(call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]));
                    } else {
                        body.push(require_statement(binary_expr(
                            BinaryOp::Le,
                            identifier_expr(out_count_name),
                            declaration.to_expr.clone(),
                        )));
                        append_auth_output_state_checks(
                            &mut body,
                            &active_input,
                            out_count_name,
                            declaration.to_expr.clone(),
                            next_state_expr,
                        );
                    }
                }
                OutputStateSource::PerOutputArrays { field_arrays, length_expr } => {
                    body.push(require_statement(binary_expr(
                        BinaryOp::Le,
                        identifier_expr(out_count_name),
                        declaration.to_expr.clone(),
                    )));
                    body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(out_count_name), length_expr.clone())));
                    append_auth_output_array_state_checks(
                        &mut body,
                        &active_input,
                        out_count_name,
                        declaration.to_expr.clone(),
                        field_arrays,
                        contract_fields,
                    );
                }
            }
        } else {
            body.push(require_statement(binary_expr(BinaryOp::Le, identifier_expr(out_count_name), declaration.to_expr.clone())));
        }
    }

    Ok(generated_entrypoint(policy, entrypoint_name, entrypoint_params, body))
}

fn build_cov_wrapper<'i>(
    policy: &FunctionAst<'i>,
    policy_name: &str,
    declaration: CovenantDeclaration<'i>,
    entrypoint_name: String,
    leader: bool,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut body = Vec::new();
    let mut leader_params = policy.params.clone();

    let active_input = active_input_index_expr();
    let cov_id_name = "__cov_id";
    body.push(var_def_statement(bytes32_type_ref(), cov_id_name, Expr::call("OpInputCovenantId", vec![active_input.clone()])));

    let leader_idx_expr = Expr::call("OpCovInputIdx", vec![identifier_expr(cov_id_name), Expr::int(0)]);
    body.push(require_statement(binary_expr(if leader { BinaryOp::Eq } else { BinaryOp::Ne }, leader_idx_expr, active_input)));

    if leader {
        let in_count_name = "__cov_in_count";
        body.push(var_def_statement(int_type_ref(), in_count_name, Expr::call("OpCovInputCount", vec![identifier_expr(cov_id_name)])));
        body.push(require_statement(binary_expr(BinaryOp::Le, identifier_expr(in_count_name), declaration.from_expr.clone())));

        let out_count_name = "__cov_out_count";
        body.push(var_def_statement(int_type_ref(), out_count_name, Expr::call("OpCovOutCount", vec![identifier_expr(cov_id_name)])));

        if declaration.mode == CovenantMode::Verification && !contract_fields.is_empty() {
            let shape = parse_verification_shape(policy, contract_fields, CovenantBinding::Cov)?;
            leader_params = shape.entrypoint_params.clone();

            append_cov_input_state_reads_into_policy_prev_arrays(
                &mut body,
                cov_id_name,
                in_count_name,
                declaration.from_expr.clone(),
                contract_fields,
                &shape.prev_field_values,
            );
            body.push(call_statement(policy_name, shape.call_args));
            body.push(require_statement(binary_expr(BinaryOp::Le, identifier_expr(out_count_name), declaration.to_expr.clone())));
            append_cov_output_array_state_checks(
                &mut body,
                cov_id_name,
                out_count_name,
                declaration.to_expr.clone(),
                shape.new_field_arrays,
                contract_fields,
            );
        } else {
            let mut transition_shape: Option<TransitionShape<'i>> = None;
            if declaration.mode == CovenantMode::Transition && !contract_fields.is_empty() {
                let shape = parse_transition_shape(policy, contract_fields, CovenantBinding::Cov)?;
                leader_params = shape.entrypoint_params.clone();
                transition_shape = Some(shape);
            }
            append_cov_input_state_reads(&mut body, cov_id_name, in_count_name, declaration.from_expr.clone(), contract_fields);
            let call_args = transition_shape
                .map(|shape| shape.call_args)
                .unwrap_or_else(|| policy.params.iter().map(|param| identifier_expr(&param.name)).collect());
            let state_source = append_policy_call_and_capture_next_state(
                &mut body,
                policy,
                policy_name,
                declaration.mode,
                declaration.singleton,
                declaration.termination,
                contract_fields,
                call_args,
            )?;
            if !contract_fields.is_empty() {
                match state_source {
                    OutputStateSource::Single(next_state_expr) => {
                        if declaration.mode == CovenantMode::Transition || declaration.singleton {
                            body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(out_count_name), Expr::int(1))));
                            let out_idx_name = "__cov_out_idx";
                            body.push(var_def_statement(
                                int_type_ref(),
                                out_idx_name,
                                Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), Expr::int(0)]),
                            ));
                            body.push(call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]));
                        } else {
                            body.push(require_statement(binary_expr(
                                BinaryOp::Le,
                                identifier_expr(out_count_name),
                                declaration.to_expr.clone(),
                            )));
                            append_cov_output_state_checks(
                                &mut body,
                                cov_id_name,
                                out_count_name,
                                declaration.to_expr.clone(),
                                next_state_expr,
                            );
                        }
                    }
                    OutputStateSource::PerOutputArrays { field_arrays, length_expr } => {
                        body.push(require_statement(binary_expr(
                            BinaryOp::Le,
                            identifier_expr(out_count_name),
                            declaration.to_expr.clone(),
                        )));
                        body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(out_count_name), length_expr.clone())));
                        append_cov_output_array_state_checks(
                            &mut body,
                            cov_id_name,
                            out_count_name,
                            declaration.to_expr.clone(),
                            field_arrays,
                            contract_fields,
                        );
                    }
                }
            } else {
                body.push(require_statement(binary_expr(BinaryOp::Le, identifier_expr(out_count_name), declaration.to_expr.clone())));
            }
        }
    }

    let params = if leader { leader_params } else { Vec::new() };
    Ok(generated_entrypoint(policy, entrypoint_name, params, body))
}

fn generated_entrypoint<'i>(
    policy: &FunctionAst<'i>,
    entrypoint_name: String,
    params: Vec<crate::ast::ParamAst<'i>>,
    body: Vec<Statement<'i>>,
) -> FunctionAst<'i> {
    FunctionAst {
        name: entrypoint_name,
        attributes: Vec::new(),
        params,
        entrypoint: true,
        return_types: Vec::new(),
        body,
        return_type_spans: Vec::new(),
        span: policy.span,
        name_span: policy.name_span,
        body_span: policy.body_span,
    }
}

fn int_type_ref() -> TypeRef {
    TypeRef { base: TypeBase::Int, array_dims: Vec::new() }
}

fn bytes32_type_ref() -> TypeRef {
    TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(32)] }
}

fn active_input_index_expr<'i>() -> Expr<'i> {
    Expr::new(ExprKind::Nullary(NullaryOp::ActiveInputIndex), span::Span::default())
}

fn identifier_expr<'i>(name: &str) -> Expr<'i> {
    Expr::new(ExprKind::Identifier(name.to_string()), span::Span::default())
}

fn binary_expr<'i>(op: BinaryOp, left: Expr<'i>, right: Expr<'i>) -> Expr<'i> {
    Expr::new(ExprKind::Binary { op, left: Box::new(left), right: Box::new(right) }, span::Span::default())
}

fn var_def_statement<'i>(type_ref: TypeRef, name: &str, expr: Expr<'i>) -> Statement<'i> {
    Statement::VariableDefinition {
        type_ref,
        modifiers: Vec::new(),
        name: name.to_string(),
        expr: Some(expr),
        span: span::Span::default(),
        type_span: span::Span::default(),
        modifier_spans: Vec::new(),
        name_span: span::Span::default(),
    }
}

fn var_decl_statement<'i>(type_ref: TypeRef, name: &str) -> Statement<'i> {
    Statement::VariableDefinition {
        type_ref,
        modifiers: Vec::new(),
        name: name.to_string(),
        expr: None,
        span: span::Span::default(),
        type_span: span::Span::default(),
        modifier_spans: Vec::new(),
        name_span: span::Span::default(),
    }
}

fn require_statement<'i>(expr: Expr<'i>) -> Statement<'i> {
    Statement::Require { expr, message: None, span: span::Span::default(), message_span: None }
}

fn call_statement<'i>(name: &str, args: Vec<Expr<'i>>) -> Statement<'i> {
    Statement::FunctionCall { name: name.to_string(), args, span: span::Span::default(), name_span: span::Span::default() }
}

fn function_call_assign_statement<'i>(bindings: Vec<crate::ast::ParamAst<'i>>, name: &str, args: Vec<Expr<'i>>) -> Statement<'i> {
    Statement::FunctionCallAssign {
        bindings,
        name: name.to_string(),
        args,
        span: span::Span::default(),
        name_span: span::Span::default(),
    }
}

fn array_push_statement<'i>(name: &str, expr: Expr<'i>) -> Statement<'i> {
    Statement::ArrayPush { name: name.to_string(), expr, span: span::Span::default(), name_span: span::Span::default() }
}

fn typed_binding<'i>(type_ref: TypeRef, name: &str) -> crate::ast::ParamAst<'i> {
    crate::ast::ParamAst {
        type_ref,
        name: name.to_string(),
        span: span::Span::default(),
        type_span: span::Span::default(),
        name_span: span::Span::default(),
    }
}

fn if_statement<'i>(condition: Expr<'i>, then_branch: Vec<Statement<'i>>) -> Statement<'i> {
    Statement::If {
        condition,
        then_branch,
        else_branch: None,
        span: span::Span::default(),
        then_span: span::Span::default(),
        else_span: None,
    }
}

fn for_statement<'i>(ident: &str, start: Expr<'i>, end: Expr<'i>, body: Vec<Statement<'i>>) -> Statement<'i> {
    Statement::For {
        ident: ident.to_string(),
        start,
        end,
        body,
        span: span::Span::default(),
        ident_span: span::Span::default(),
        body_span: span::Span::default(),
    }
}

fn state_binding<'i>(field_name: &str, type_ref: TypeRef, name: &str) -> StateBindingAst<'i> {
    StateBindingAst {
        field_name: field_name.to_string(),
        type_ref,
        name: name.to_string(),
        span: span::Span::default(),
        field_span: span::Span::default(),
        type_span: span::Span::default(),
        name_span: span::Span::default(),
    }
}

fn state_call_assign_statement<'i>(bindings: Vec<StateBindingAst<'i>>, name: &str, args: Vec<Expr<'i>>) -> Statement<'i> {
    Statement::StateFunctionCallAssign {
        bindings,
        name: name.to_string(),
        args,
        span: span::Span::default(),
        name_span: span::Span::default(),
    }
}

fn state_object_expr_from_contract_fields<'i>(contract_fields: &[ContractFieldAst<'i>]) -> Expr<'i> {
    let fields = contract_fields
        .iter()
        .map(|field| StateFieldExpr {
            name: field.name.clone(),
            expr: identifier_expr(&field.name),
            span: span::Span::default(),
            name_span: span::Span::default(),
        })
        .collect();
    Expr::new(ExprKind::StateObject(fields), span::Span::default())
}

fn state_object_expr_from_field_bindings<'i>(
    contract_fields: &[ContractFieldAst<'i>],
    binding_by_field: &HashMap<String, String>,
) -> Expr<'i> {
    let fields = contract_fields
        .iter()
        .map(|field| {
            let binding_name = binding_by_field
                .get(&field.name)
                .cloned()
                .unwrap_or_else(|| panic!("missing state binding for field '{}'", field.name));
            StateFieldExpr {
                name: field.name.clone(),
                expr: identifier_expr(&binding_name),
                span: span::Span::default(),
                name_span: span::Span::default(),
            }
        })
        .collect();
    Expr::new(ExprKind::StateObject(fields), span::Span::default())
}

fn state_object_expr_from_field_arrays_at_index<'i>(
    contract_fields: &[ContractFieldAst<'i>],
    field_arrays: &[(String, String)],
    index_expr: Expr<'i>,
) -> Expr<'i> {
    let by_field = field_arrays.iter().cloned().collect::<HashMap<_, _>>();
    let fields = contract_fields
        .iter()
        .map(|field| {
            let array_name =
                by_field.get(&field.name).cloned().unwrap_or_else(|| panic!("missing state array binding for field '{}'", field.name));
            StateFieldExpr {
                name: field.name.clone(),
                expr: Expr::new(
                    ExprKind::ArrayIndex { source: Box::new(identifier_expr(&array_name)), index: Box::new(index_expr.clone()) },
                    span::Span::default(),
                ),
                span: span::Span::default(),
                name_span: span::Span::default(),
            }
        })
        .collect();
    Expr::new(ExprKind::StateObject(fields), span::Span::default())
}

fn length_expr<'i>(expr: Expr<'i>) -> Expr<'i> {
    Expr::new(
        ExprKind::UnarySuffix { source: Box::new(expr), kind: UnarySuffixKind::Length, span: span::Span::default() },
        span::Span::default(),
    )
}

fn return_type_is_per_output_array(return_type: &TypeRef, field_type: &TypeRef) -> bool {
    return_type.base == field_type.base
        && return_type.array_dims.len() == field_type.array_dims.len() + 1
        && return_type.array_dims[..field_type.array_dims.len()] == field_type.array_dims[..]
}

fn dynamic_array_of(type_ref: &TypeRef) -> TypeRef {
    let mut array_type = type_ref.clone();
    array_type.array_dims.push(ArrayDim::Dynamic);
    array_type
}

fn parse_verification_shape<'i>(
    policy: &FunctionAst<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    binding: CovenantBinding,
) -> Result<VerificationShape<'i>, CompilerError> {
    let field_count = contract_fields.len();
    let required = field_count * 2;
    let binding_name = match binding {
        CovenantBinding::Auth => "auth",
        CovenantBinding::Cov => "cov",
    };
    let prev_label = match binding {
        CovenantBinding::Auth => "params",
        CovenantBinding::Cov => "arrays",
    };
    let new_label = match binding {
        CovenantBinding::Auth => "array params",
        CovenantBinding::Cov => "arrays",
    };
    if policy.params.len() < required {
        return Err(CompilerError::Unsupported(format!(
            "mode=verification with binding={} on function '{}' requires {} prev-state {} + {} new-state {} (one per contract field)",
            binding_name, policy.name, field_count, prev_label, field_count, new_label
        )));
    }

    let mut prev_field_values = Vec::with_capacity(field_count);
    let mut new_field_arrays = Vec::with_capacity(field_count);
    for (idx, field) in contract_fields.iter().enumerate() {
        let prev_expected = match binding {
            CovenantBinding::Auth => field.type_ref.clone(),
            CovenantBinding::Cov => dynamic_array_of(&field.type_ref),
        };
        let prev_param = &policy.params[idx];
        if prev_param.type_ref != prev_expected {
            return Err(CompilerError::Unsupported(format!(
                "mode=verification with binding={} on function '{}' expects prev-state param '{}' to be '{}', got '{}'",
                binding_name,
                policy.name,
                prev_param.name,
                type_name_from_ref(&prev_expected),
                type_name_from_ref(&prev_param.type_ref)
            )));
        }
        prev_field_values.push((field.name.clone(), prev_param.name.clone()));

        let new_expected = dynamic_array_of(&field.type_ref);
        let new_param = &policy.params[field_count + idx];
        if new_param.type_ref != new_expected {
            return Err(CompilerError::Unsupported(format!(
                "mode=verification with binding={} on function '{}' expects new-state param '{}' to be '{}', got '{}'",
                binding_name,
                policy.name,
                new_param.name,
                type_name_from_ref(&new_expected),
                type_name_from_ref(&new_param.type_ref)
            )));
        }
        new_field_arrays.push((field.name.clone(), new_param.name.clone()));
    }

    let entrypoint_params = policy.params[field_count..].to_vec();
    let call_args = match binding {
        CovenantBinding::Auth => {
            let mut args = Vec::with_capacity(policy.params.len());
            for field in contract_fields {
                args.push(identifier_expr(&field.name));
            }
            for param in &entrypoint_params {
                args.push(identifier_expr(&param.name));
            }
            args
        }
        CovenantBinding::Cov => policy.params.iter().map(|param| identifier_expr(&param.name)).collect(),
    };

    Ok(VerificationShape { prev_field_values, new_field_arrays, entrypoint_params, call_args })
}

fn parse_transition_shape<'i>(
    policy: &FunctionAst<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    binding: CovenantBinding,
) -> Result<TransitionShape<'i>, CompilerError> {
    let field_count = contract_fields.len();
    let binding_name = match binding {
        CovenantBinding::Auth => "auth",
        CovenantBinding::Cov => "cov",
    };
    let prev_label = match binding {
        CovenantBinding::Auth => "params",
        CovenantBinding::Cov => "arrays",
    };
    if policy.params.len() < field_count {
        return Err(CompilerError::Unsupported(format!(
            "mode=transition with binding={} on function '{}' requires {} prev-state {} (one per contract field) before call args",
            binding_name, policy.name, field_count, prev_label
        )));
    }

    for (idx, field) in contract_fields.iter().enumerate() {
        let prev_expected = match binding {
            CovenantBinding::Auth => field.type_ref.clone(),
            CovenantBinding::Cov => dynamic_array_of(&field.type_ref),
        };
        let prev_param = &policy.params[idx];
        if prev_param.type_ref != prev_expected {
            return Err(CompilerError::Unsupported(format!(
                "mode=transition with binding={} on function '{}' expects prev-state param '{}' to be '{}', got '{}'",
                binding_name,
                policy.name,
                prev_param.name,
                type_name_from_ref(&prev_expected),
                type_name_from_ref(&prev_param.type_ref)
            )));
        }
    }

    match binding {
        CovenantBinding::Auth => {
            let entrypoint_params = policy.params[field_count..].to_vec();
            let mut call_args = Vec::with_capacity(policy.params.len());
            for field in contract_fields {
                call_args.push(identifier_expr(&field.name));
            }
            for param in &entrypoint_params {
                call_args.push(identifier_expr(&param.name));
            }
            Ok(TransitionShape { entrypoint_params, call_args })
        }
        CovenantBinding::Cov => Ok(TransitionShape {
            entrypoint_params: policy.params.clone(),
            call_args: policy.params.iter().map(|param| identifier_expr(&param.name)).collect(),
        }),
    }
}

fn append_policy_call_and_capture_next_state<'i>(
    body: &mut Vec<Statement<'i>>,
    policy: &FunctionAst<'i>,
    policy_name: &str,
    mode: CovenantMode,
    singleton: bool,
    termination: CovenantTermination,
    contract_fields: &[ContractFieldAst<'i>],
    call_args: Vec<Expr<'i>>,
) -> Result<OutputStateSource<'i>, CompilerError> {
    match mode {
        CovenantMode::Verification => {
            body.push(call_statement(policy_name, call_args));
            Ok(OutputStateSource::Single(state_object_expr_from_contract_fields(contract_fields)))
        }
        CovenantMode::Transition => {
            if policy.return_types.len() != contract_fields.len() {
                return Err(CompilerError::Unsupported(format!(
                    "transition mode policy function '{}' must return exactly {} values (one per contract field)",
                    policy.name,
                    contract_fields.len()
                )));
            }

            let mut shape_is_single = true;
            let mut shape_is_per_output_arrays = true;
            for (field, return_type) in contract_fields.iter().zip(policy.return_types.iter()) {
                shape_is_single &= type_name_from_ref(return_type) == type_name_from_ref(&field.type_ref);
                shape_is_per_output_arrays &= return_type_is_per_output_array(return_type, &field.type_ref);
            }
            if !shape_is_single && !shape_is_per_output_arrays {
                return Err(CompilerError::Unsupported(format!(
                    "transition mode policy function '{}' returns must be either exactly State fields or per-field arrays",
                    policy.name
                )));
            }
            if singleton && shape_is_per_output_arrays && termination != CovenantTermination::Allowed {
                return Err(CompilerError::Unsupported(format!(
                    "transition mode singleton policy function '{}' must return a single State (arrays are not allowed unless termination=allowed)",
                    policy.name
                )));
            }

            let mut bindings = Vec::new();
            let mut binding_by_field = HashMap::new();
            for (field, return_type) in contract_fields.iter().zip(policy.return_types.iter()) {
                let binding_name = format!("__cov_new_{}", field.name);
                bindings.push(typed_binding(return_type.clone(), &binding_name));
                binding_by_field.insert(field.name.clone(), binding_name);
            }

            body.push(function_call_assign_statement(bindings, policy_name, call_args));
            if shape_is_single {
                Ok(OutputStateSource::Single(state_object_expr_from_field_bindings(contract_fields, &binding_by_field)))
            } else {
                let first_field = &contract_fields[0].name;
                let first_array_name = binding_by_field
                    .get(first_field)
                    .cloned()
                    .unwrap_or_else(|| panic!("missing transition binding for field '{}'", first_field));
                let expected_len_expr = length_expr(identifier_expr(&first_array_name));
                for field in contract_fields.iter().skip(1) {
                    let array_name = binding_by_field
                        .get(&field.name)
                        .cloned()
                        .unwrap_or_else(|| panic!("missing transition binding for field '{}'", field.name));
                    body.push(require_statement(binary_expr(
                        BinaryOp::Eq,
                        length_expr(identifier_expr(&array_name)),
                        expected_len_expr.clone(),
                    )));
                }

                let field_arrays = contract_fields
                    .iter()
                    .map(|field| {
                        let name = binding_by_field
                            .get(&field.name)
                            .cloned()
                            .unwrap_or_else(|| panic!("missing transition binding for field '{}'", field.name));
                        (field.name.clone(), name)
                    })
                    .collect();
                Ok(OutputStateSource::PerOutputArrays { field_arrays, length_expr: expected_len_expr })
            }
        }
    }
}

fn append_auth_output_state_checks<'i>(
    body: &mut Vec<Statement<'i>>,
    active_input: &Expr<'i>,
    out_count_name: &str,
    to_expr: Expr<'i>,
    next_state_expr: Expr<'i>,
) {
    let loop_var = "__cov_k";
    let out_idx_name = "__cov_out_idx";
    let cond = binary_expr(BinaryOp::Lt, identifier_expr(loop_var), identifier_expr(out_count_name));
    let then_branch = vec![
        var_def_statement(
            int_type_ref(),
            out_idx_name,
            Expr::call("OpAuthOutputIdx", vec![active_input.clone(), identifier_expr(loop_var)]),
        ),
        call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]),
    ];
    body.push(for_statement(loop_var, Expr::int(0), to_expr, vec![if_statement(cond, then_branch)]));
}

fn append_cov_input_state_reads<'i>(
    body: &mut Vec<Statement<'i>>,
    cov_id_name: &str,
    in_count_name: &str,
    from_expr: Expr<'i>,
    contract_fields: &[ContractFieldAst<'i>],
) {
    if contract_fields.is_empty() {
        return;
    }
    let loop_var = "__cov_in_k";
    let in_idx_name = "__cov_in_idx";
    let cond = binary_expr(BinaryOp::Lt, identifier_expr(loop_var), identifier_expr(in_count_name));
    let mut then_branch = Vec::new();
    then_branch.push(var_def_statement(
        int_type_ref(),
        in_idx_name,
        Expr::call("OpCovInputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
    ));
    let bindings = contract_fields
        .iter()
        .map(|field| state_binding(&field.name, field.type_ref.clone(), &format!("__cov_prev_{}", field.name)))
        .collect();
    then_branch.push(state_call_assign_statement(bindings, "readInputState", vec![identifier_expr(in_idx_name)]));
    body.push(for_statement(loop_var, Expr::int(0), from_expr, vec![if_statement(cond, then_branch)]));
}

fn append_cov_input_state_reads_into_policy_prev_arrays<'i>(
    body: &mut Vec<Statement<'i>>,
    cov_id_name: &str,
    in_count_name: &str,
    from_expr: Expr<'i>,
    contract_fields: &[ContractFieldAst<'i>],
    prev_field_arrays: &[(String, String)],
) {
    if contract_fields.is_empty() {
        return;
    }
    let prev_by_field: HashMap<_, _> = prev_field_arrays.iter().cloned().collect();
    for field in contract_fields {
        let array_name =
            prev_by_field.get(&field.name).unwrap_or_else(|| panic!("missing prev-state array param for field '{}'", field.name));
        body.push(var_decl_statement(dynamic_array_of(&field.type_ref), array_name));
    }

    let loop_var = "__cov_in_k";
    let in_idx_name = "__cov_in_idx";
    let cond = binary_expr(BinaryOp::Lt, identifier_expr(loop_var), identifier_expr(in_count_name));
    let mut then_branch = Vec::new();
    then_branch.push(var_def_statement(
        int_type_ref(),
        in_idx_name,
        Expr::call("OpCovInputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
    ));
    let bindings = contract_fields
        .iter()
        .map(|field| state_binding(&field.name, field.type_ref.clone(), &format!("__cov_prev_{}", field.name)))
        .collect();
    then_branch.push(state_call_assign_statement(bindings, "readInputState", vec![identifier_expr(in_idx_name)]));
    for field in contract_fields {
        let array_name =
            prev_by_field.get(&field.name).unwrap_or_else(|| panic!("missing prev-state array param for field '{}'", field.name));
        then_branch.push(array_push_statement(array_name, identifier_expr(&format!("__cov_prev_{}", field.name))));
    }
    body.push(for_statement(loop_var, Expr::int(0), from_expr, vec![if_statement(cond, then_branch)]));
}

fn append_cov_output_state_checks<'i>(
    body: &mut Vec<Statement<'i>>,
    cov_id_name: &str,
    out_count_name: &str,
    to_expr: Expr<'i>,
    next_state_expr: Expr<'i>,
) {
    let loop_var = "__cov_k";
    let out_idx_name = "__cov_out_idx";
    let cond = binary_expr(BinaryOp::Lt, identifier_expr(loop_var), identifier_expr(out_count_name));
    let then_branch = vec![
        var_def_statement(
            int_type_ref(),
            out_idx_name,
            Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
        ),
        call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]),
    ];
    body.push(for_statement(loop_var, Expr::int(0), to_expr, vec![if_statement(cond, then_branch)]));
}

fn append_auth_output_array_state_checks<'i>(
    body: &mut Vec<Statement<'i>>,
    active_input: &Expr<'i>,
    out_count_name: &str,
    to_expr: Expr<'i>,
    field_arrays: Vec<(String, String)>,
    contract_fields: &[ContractFieldAst<'i>],
) {
    let loop_var = "__cov_k";
    let out_idx_name = "__cov_out_idx";
    let cond = binary_expr(BinaryOp::Lt, identifier_expr(loop_var), identifier_expr(out_count_name));
    let mut then_branch = Vec::new();
    then_branch.push(var_def_statement(
        int_type_ref(),
        out_idx_name,
        Expr::call("OpAuthOutputIdx", vec![active_input.clone(), identifier_expr(loop_var)]),
    ));
    let next_state_expr = state_object_expr_from_field_arrays_at_index(contract_fields, &field_arrays, identifier_expr(loop_var));
    then_branch.push(call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]));
    body.push(for_statement(loop_var, Expr::int(0), to_expr, vec![if_statement(cond, then_branch)]));
}

fn append_cov_output_array_state_checks<'i>(
    body: &mut Vec<Statement<'i>>,
    cov_id_name: &str,
    out_count_name: &str,
    to_expr: Expr<'i>,
    field_arrays: Vec<(String, String)>,
    contract_fields: &[ContractFieldAst<'i>],
) {
    let loop_var = "__cov_k";
    let out_idx_name = "__cov_out_idx";
    let cond = binary_expr(BinaryOp::Lt, identifier_expr(loop_var), identifier_expr(out_count_name));
    let mut then_branch = Vec::new();
    then_branch.push(var_def_statement(
        int_type_ref(),
        out_idx_name,
        Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
    ));
    let next_state_expr = state_object_expr_from_field_arrays_at_index(contract_fields, &field_arrays, identifier_expr(loop_var));
    then_branch.push(call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]));
    body.push(for_statement(loop_var, Expr::int(0), to_expr, vec![if_statement(cond, then_branch)]));
}
