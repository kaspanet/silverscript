use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CovenantDeclBinding {
    Auth,
    Cov,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CovenantDeclMode {
    Verification,
    Transition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CovenantSourceParam {
    name: String,
    type_ref: TypeRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantDeclInfo {
    pub source_name: String,
    pub binding: CovenantDeclBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_param: Option<CovenantSourceParam>,
}

impl CovenantDeclInfo {
    pub fn policy_function_name(&self) -> String {
        generated_covenant_policy_name(&self.source_name)
    }

    pub fn generated_entrypoint_name(&self, is_leader: bool) -> String {
        match self.binding {
            CovenantDeclBinding::Auth => generated_covenant_entrypoint_name(&self.source_name),
            CovenantDeclBinding::Cov => {
                if is_leader {
                    generated_covenant_leader_entrypoint_name(&self.source_name)
                } else {
                    generated_covenant_delegate_entrypoint_name(&self.source_name)
                }
            }
        }
    }

    pub fn matches_generated_name(&self, function_name: &str) -> bool {
        if self.policy_function_name() == function_name {
            return true;
        }
        match self.binding {
            CovenantDeclBinding::Auth => self.generated_entrypoint_name(true) == function_name,
            CovenantDeclBinding::Cov => {
                self.generated_entrypoint_name(true) == function_name || self.generated_entrypoint_name(false) == function_name
            }
        }
    }

    pub fn display_name_for_function(&self, function_name: &str) -> Option<String> {
        if self.policy_function_name() == function_name {
            return Some(self.source_name.clone());
        }
        match self.binding {
            CovenantDeclBinding::Auth => {
                if self.generated_entrypoint_name(true) == function_name {
                    Some(self.source_name.clone())
                } else {
                    None
                }
            }
            CovenantDeclBinding::Cov => {
                if self.generated_entrypoint_name(true) == function_name {
                    Some(format!("{} [leader]", self.source_name))
                } else if self.generated_entrypoint_name(false) == function_name {
                    Some(format!("{} [delegate]", self.source_name))
                } else {
                    None
                }
            }
        }
    }

    pub fn source_param(&self) -> Option<(&str, &TypeRef)> {
        self.source_param.as_ref().map(|param| (param.name.as_str(), &param.type_ref))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCovenantCallTarget {
    pub info: CovenantDeclInfo,
    pub is_leader: bool,
}

impl ResolvedCovenantCallTarget {
    pub fn generated_entrypoint_name(&self) -> String {
        self.info.generated_entrypoint_name(self.is_leader)
    }

    pub fn display_name(&self) -> String {
        match self.info.binding {
            CovenantDeclBinding::Auth => self.info.source_name.clone(),
            CovenantDeclBinding::Cov => {
                if self.is_leader {
                    format!("{} [leader]", self.info.source_name)
                } else {
                    format!("{} [delegate]", self.info.source_name)
                }
            }
        }
    }
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
    binding: CovenantDeclBinding,
    mode: CovenantDeclMode,
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

pub(super) fn lower_covenant_declarations<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(ContractAst<'i>, Vec<CovenantDeclInfo>), CompilerError> {
    let mut lowered = Vec::new();
    let mut infos = Vec::new();

    for function in &contract.functions {
        if function.attributes.is_empty() {
            lowered.push(function.clone());
            continue;
        }

        let declaration = parse_covenant_declaration(function, constants, true)?;
        validate_covenant_policy_state_shape(function, &declaration, &contract.fields)?;

        infos.push(build_covenant_decl_info(function, declaration.binding));

        let policy_name = generated_covenant_policy_name(&function.name);

        let mut policy = function.clone();
        policy.name = policy_name.clone();
        policy.entrypoint = false;
        policy.attributes.clear();
        lowered.push(policy.clone());

        match declaration.binding {
            CovenantDeclBinding::Auth => {
                let entrypoint_name = generated_covenant_entrypoint_name(&function.name);
                let mut wrapper = build_auth_wrapper(&policy, &policy_name, declaration.clone(), entrypoint_name, &contract.fields)?;
                wrapper.params = preserved_entrypoint_params(function, declaration, true, &contract.fields);
                lowered.push(wrapper);
            }
            CovenantDeclBinding::Cov => {
                let leader_name = generated_covenant_leader_entrypoint_name(&function.name);
                let mut leader_wrapper =
                    build_cov_wrapper(&policy, &policy_name, declaration.clone(), leader_name, true, &contract.fields)?;
                leader_wrapper.params = preserved_entrypoint_params(function, declaration.clone(), true, &contract.fields);
                lowered.push(leader_wrapper);

                let delegate_name = generated_covenant_delegate_entrypoint_name(&function.name);
                let mut delegate_wrapper =
                    build_cov_wrapper(&policy, &policy_name, declaration.clone(), delegate_name, false, &contract.fields)?;
                delegate_wrapper.params = preserved_entrypoint_params(function, declaration, false, &contract.fields);
                lowered.push(delegate_wrapper);
            }
        }
    }

    let mut lowered_contract = contract.clone();
    lowered_contract.functions = lowered;
    infos.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    Ok((lowered_contract, infos))
}

fn build_covenant_decl_info<'i>(function: &FunctionAst<'i>, binding: CovenantDeclBinding) -> CovenantDeclInfo {
    let source_param =
        function.params.first().map(|param| CovenantSourceParam { name: param.name.clone(), type_ref: param.type_ref.clone() });
    CovenantDeclInfo { source_name: function.name.clone(), binding, source_param }
}

fn parse_covenant_declaration<'i>(
    function: &FunctionAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
    emit_warnings: bool,
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

    let default_binding = if from_value == 1 { CovenantDeclBinding::Auth } else { CovenantDeclBinding::Cov };
    let binding = match args_by_name.get("binding").copied() {
        Some(expr) => {
            let binding_name = parse_attr_ident_arg("binding", Some(expr))?;
            match binding_name.as_str() {
                "auth" => CovenantDeclBinding::Auth,
                "cov" => CovenantDeclBinding::Cov,
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
                "verification" => CovenantDeclMode::Verification,
                "transition" => CovenantDeclMode::Transition,
                other => {
                    return Err(CompilerError::Unsupported(format!("covenant mode must be verification|transition, got '{}'", other)));
                }
            }
        }
        None => {
            if function.return_types.is_empty() {
                CovenantDeclMode::Verification
            } else {
                CovenantDeclMode::Transition
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
            CovenantDeclBinding::Auth => CovenantGroups::Multiple,
            CovenantDeclBinding::Cov => CovenantGroups::Single,
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

    if binding == CovenantDeclBinding::Auth && from_value != 1 {
        return Err(CompilerError::Unsupported("binding=auth requires from = 1".to_string()));
    }
    if emit_warnings && binding == CovenantDeclBinding::Cov && from_value == 1 && args_by_name.contains_key("binding") {
        eprintln!(
            "warning: #[covenant(...)] on function '{}' uses binding=cov with from=1; binding=auth is usually a better default",
            function.name
        );
    }
    if binding == CovenantDeclBinding::Cov && groups == CovenantGroups::Multiple {
        return Err(CompilerError::Unsupported("binding=cov with groups=multiple is not supported yet".to_string()));
    }

    if args_by_name.contains_key("termination") && mode != CovenantDeclMode::Transition {
        return Err(CompilerError::Unsupported("termination is only supported in mode=transition".to_string()));
    }
    if args_by_name.contains_key("termination") && !(from_value == 1 && to_value == 1) {
        return Err(CompilerError::Unsupported("termination is only supported for singleton covenants (from=1, to=1)".to_string()));
    }

    if mode == CovenantDeclMode::Verification && !function.return_types.is_empty() {
        return Err(CompilerError::Unsupported("verification mode policy functions must not declare return values".to_string()));
    }
    if mode == CovenantDeclMode::Transition && function.return_types.is_empty() {
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

fn validate_covenant_policy_state_shape<'i>(
    policy: &FunctionAst<'i>,
    declaration: &CovenantDeclaration<'i>,
    contract_fields: &[ContractFieldAst<'i>],
) -> Result<(), CompilerError> {
    if contract_fields.is_empty() {
        return Ok(());
    }

    match (declaration.binding, declaration.mode) {
        (CovenantDeclBinding::Auth, CovenantDeclMode::Verification) => {
            if policy.params.len() < 2
                || !is_state_type_ref(&policy.params[0].type_ref)
                || !is_state_array_type_ref(&policy.params[1].type_ref)
            {
                return Err(CompilerError::Unsupported(format!(
                    "mode=verification with binding=auth on function '{}' expects parameters '(State prev_state, State[] new_states, ...)'",
                    policy.name
                )));
            }
        }
        (CovenantDeclBinding::Cov, CovenantDeclMode::Verification) => {
            if policy.params.len() < 2
                || !is_state_array_type_ref(&policy.params[0].type_ref)
                || !is_state_array_type_ref(&policy.params[1].type_ref)
            {
                return Err(CompilerError::Unsupported(format!(
                    "mode=verification with binding=cov on function '{}' expects parameters '(State[] prev_states, State[] new_states, ...)'",
                    policy.name
                )));
            }
        }
        (CovenantDeclBinding::Auth, CovenantDeclMode::Transition) => {
            if policy.params.is_empty() || !is_state_type_ref(&policy.params[0].type_ref) {
                return Err(CompilerError::Unsupported(format!(
                    "mode=transition with binding=auth on function '{}' expects parameters '(State prev_state, ...)'",
                    policy.name
                )));
            }
        }
        (CovenantDeclBinding::Cov, CovenantDeclMode::Transition) => {
            if policy.params.is_empty() || !is_state_array_type_ref(&policy.params[0].type_ref) {
                return Err(CompilerError::Unsupported(format!(
                    "mode=transition with binding=cov on function '{}' expects parameters '(State[] prev_states, ...)'",
                    policy.name
                )));
            }
        }
    }

    if declaration.mode == CovenantDeclMode::Transition {
        if policy.return_types.len() != 1 {
            return Err(CompilerError::Unsupported(format!(
                "mode=transition on function '{}' with contract state expects exactly one return type: 'State' or 'State[]'",
                policy.name
            )));
        }

        let return_type = &policy.return_types[0];
        if !is_state_type_ref(return_type) && !is_state_array_type_ref(return_type) {
            return Err(CompilerError::Unsupported(format!(
                "mode=transition on function '{}' with contract state expects return type 'State' or 'State[]'",
                policy.name
            )));
        }

        if declaration.singleton && is_state_array_type_ref(return_type) && declaration.termination != CovenantTermination::Allowed {
            return Err(CompilerError::Unsupported(format!(
                "transition mode singleton policy function '{}' must return a single State (arrays are not allowed unless termination=allowed)",
                policy.name
            )));
        }
    }

    Ok(())
}

fn preserved_entrypoint_params<'i>(
    function: &FunctionAst<'i>,
    declaration: CovenantDeclaration<'i>,
    leader: bool,
    contract_fields: &[ContractFieldAst<'i>],
) -> Vec<crate::ast::ParamAst<'i>> {
    if contract_fields.is_empty() {
        return match (declaration.binding, leader) {
            (CovenantDeclBinding::Cov, false) => Vec::new(),
            _ => function.params.clone(),
        };
    }

    match (declaration.binding, declaration.mode, leader) {
        (CovenantDeclBinding::Auth, _, _) => function.params.iter().skip(1).cloned().collect(),
        (CovenantDeclBinding::Cov, CovenantDeclMode::Verification, true) => function.params.iter().skip(1).cloned().collect(),
        (CovenantDeclBinding::Cov, CovenantDeclMode::Transition, true) => function.params.iter().skip(1).cloned().collect(),
        (CovenantDeclBinding::Cov, _, false) => Vec::new(),
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
            Expr::call("OpCovOutputCount", vec![identifier_expr(cov_id_name)]),
        ));
        body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(cov_out_count_name), identifier_expr(out_count_name))));
    }

    if !contract_fields.is_empty() {
        match declaration.mode {
            CovenantDeclMode::Verification => {
                entrypoint_params = policy.params.iter().skip(1).cloned().collect();
                let prev_state_name = &policy.params[0].name;
                let new_states_name = &policy.params[1].name;
                body.push(var_def_statement(
                    state_type_ref(),
                    prev_state_name,
                    state_object_expr_from_contract_fields(contract_fields),
                ));
                body.push(call_statement(policy_name, policy.params.iter().map(|param| identifier_expr(&param.name)).collect()));
                body.push(require_statement(binary_expr(BinaryOp::Le, identifier_expr(out_count_name), declaration.to_expr.clone())));
                body.push(require_statement(binary_expr(
                    BinaryOp::Eq,
                    identifier_expr(out_count_name),
                    length_expr(identifier_expr(new_states_name)),
                )));
                append_auth_output_state_array_checks_from_state_array(
                    &mut body,
                    &active_input,
                    out_count_name,
                    declaration.to_expr.clone(),
                    new_states_name,
                );
            }
            CovenantDeclMode::Transition => {
                entrypoint_params = policy.params.iter().skip(1).cloned().collect();
                let prev_state_name = &policy.params[0].name;
                body.push(var_def_statement(
                    state_type_ref(),
                    prev_state_name,
                    state_object_expr_from_contract_fields(contract_fields),
                ));
                let call_args = policy.params.iter().map(|param| identifier_expr(&param.name)).collect();
                if is_state_type_ref(&policy.return_types[0]) {
                    let next_state_name = "__cov_new_state";
                    body.push(function_call_assign_statement(
                        vec![typed_binding(state_type_ref(), next_state_name)],
                        policy_name,
                        call_args,
                    ));
                    body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(out_count_name), Expr::int(1))));
                    let out_idx_name = "__cov_out_idx";
                    body.push(var_def_statement(
                        int_type_ref(),
                        out_idx_name,
                        Expr::call("OpAuthOutputIdx", vec![active_input.clone(), Expr::int(0)]),
                    ));
                    body.push(call_statement(
                        "validateOutputState",
                        vec![identifier_expr(out_idx_name), identifier_expr(next_state_name)],
                    ));
                } else {
                    let next_states_name = "__cov_new_states";
                    body.push(function_call_assign_statement(
                        vec![typed_binding(state_array_type_ref(), next_states_name)],
                        policy_name,
                        call_args,
                    ));
                    body.push(require_statement(binary_expr(
                        BinaryOp::Le,
                        identifier_expr(out_count_name),
                        declaration.to_expr.clone(),
                    )));
                    body.push(require_statement(binary_expr(
                        BinaryOp::Eq,
                        identifier_expr(out_count_name),
                        length_expr(identifier_expr(next_states_name)),
                    )));
                    append_auth_output_state_array_checks_from_state_array(
                        &mut body,
                        &active_input,
                        out_count_name,
                        declaration.to_expr.clone(),
                        next_states_name,
                    );
                }
            }
        }
    } else {
        let call_args: Vec<Expr<'i>> = policy.params.iter().map(|param| identifier_expr(&param.name)).collect();
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
                    if declaration.mode == CovenantDeclMode::Transition || declaration.singleton {
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
        body.push(var_def_statement(
            int_type_ref(),
            out_count_name,
            Expr::call("OpCovOutputCount", vec![identifier_expr(cov_id_name)]),
        ));

        if !contract_fields.is_empty() {
            match declaration.mode {
                CovenantDeclMode::Verification => {
                    leader_params = policy.params.iter().skip(1).cloned().collect();
                    let prev_states_name = &policy.params[0].name;
                    let new_states_name = &policy.params[1].name;
                    append_cov_input_state_reads_into_state_array(
                        &mut body,
                        cov_id_name,
                        in_count_name,
                        declaration.from_expr.clone(),
                        prev_states_name,
                    );
                    body.push(call_statement(policy_name, policy.params.iter().map(|param| identifier_expr(&param.name)).collect()));
                    body.push(require_statement(binary_expr(
                        BinaryOp::Le,
                        identifier_expr(out_count_name),
                        declaration.to_expr.clone(),
                    )));
                    body.push(require_statement(binary_expr(
                        BinaryOp::Eq,
                        identifier_expr(out_count_name),
                        length_expr(identifier_expr(new_states_name)),
                    )));
                    append_cov_output_state_array_checks_from_state_array(
                        &mut body,
                        cov_id_name,
                        out_count_name,
                        declaration.to_expr.clone(),
                        new_states_name,
                    );
                }
                CovenantDeclMode::Transition => {
                    leader_params = policy.params.iter().skip(1).cloned().collect();
                    let prev_states_name = &policy.params[0].name;
                    append_cov_input_state_reads_into_state_array(
                        &mut body,
                        cov_id_name,
                        in_count_name,
                        declaration.from_expr.clone(),
                        prev_states_name,
                    );
                    let call_args = policy.params.iter().map(|param| identifier_expr(&param.name)).collect();
                    if is_state_type_ref(&policy.return_types[0]) {
                        let next_state_name = "__cov_new_state";
                        body.push(function_call_assign_statement(
                            vec![typed_binding(state_type_ref(), next_state_name)],
                            policy_name,
                            call_args,
                        ));
                        body.push(require_statement(binary_expr(BinaryOp::Eq, identifier_expr(out_count_name), Expr::int(1))));
                        let out_idx_name = "__cov_out_idx";
                        body.push(var_def_statement(
                            int_type_ref(),
                            out_idx_name,
                            Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), Expr::int(0)]),
                        ));
                        body.push(call_statement(
                            "validateOutputState",
                            vec![identifier_expr(out_idx_name), identifier_expr(next_state_name)],
                        ));
                    } else {
                        let next_states_name = "__cov_new_states";
                        body.push(function_call_assign_statement(
                            vec![typed_binding(state_array_type_ref(), next_states_name)],
                            policy_name,
                            call_args,
                        ));
                        body.push(require_statement(binary_expr(
                            BinaryOp::Le,
                            identifier_expr(out_count_name),
                            declaration.to_expr.clone(),
                        )));
                        body.push(require_statement(binary_expr(
                            BinaryOp::Eq,
                            identifier_expr(out_count_name),
                            length_expr(identifier_expr(next_states_name)),
                        )));
                        append_cov_output_state_array_checks_from_state_array(
                            &mut body,
                            cov_id_name,
                            out_count_name,
                            declaration.to_expr.clone(),
                            next_states_name,
                        );
                    }
                }
            }
        } else {
            append_cov_input_state_reads(&mut body, cov_id_name, in_count_name, declaration.from_expr.clone(), contract_fields);
            let call_args = policy.params.iter().map(|param| identifier_expr(&param.name)).collect();
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
                        if declaration.mode == CovenantDeclMode::Transition || declaration.singleton {
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

fn state_type_ref() -> TypeRef {
    TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: Vec::new() }
}

fn state_array_type_ref() -> TypeRef {
    TypeRef { base: TypeBase::Custom("State".to_string()), array_dims: vec![ArrayDim::Dynamic] }
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

fn array_index_expr<'i>(name: &str, index: Expr<'i>) -> Expr<'i> {
    Expr::new(ExprKind::ArrayIndex { source: Box::new(identifier_expr(name)), index: Box::new(index) }, span::Span::default())
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

fn for_statement<'i>(
    ident: &str,
    start: Expr<'i>,
    end: Expr<'i>,
    max_iterations: Expr<'i>,
    body: Vec<Statement<'i>>,
) -> Statement<'i> {
    Statement::For {
        ident: ident.to_string(),
        start,
        end,
        max_iterations,
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

fn is_state_type_ref(type_ref: &TypeRef) -> bool {
    type_ref.array_dims.is_empty() && matches!(&type_ref.base, TypeBase::Custom(name) if name == "State")
}

fn is_state_array_type_ref(type_ref: &TypeRef) -> bool {
    !type_ref.array_dims.is_empty() && matches!(&type_ref.base, TypeBase::Custom(name) if name == "State")
}

fn append_policy_call_and_capture_next_state<'i>(
    body: &mut Vec<Statement<'i>>,
    policy: &FunctionAst<'i>,
    policy_name: &str,
    mode: CovenantDeclMode,
    singleton: bool,
    termination: CovenantTermination,
    contract_fields: &[ContractFieldAst<'i>],
    call_args: Vec<Expr<'i>>,
) -> Result<OutputStateSource<'i>, CompilerError> {
    match mode {
        CovenantDeclMode::Verification => {
            body.push(call_statement(policy_name, call_args));
            Ok(OutputStateSource::Single(state_object_expr_from_contract_fields(contract_fields)))
        }
        CovenantDeclMode::Transition => {
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
    let then_branch = vec![
        var_def_statement(
            int_type_ref(),
            out_idx_name,
            Expr::call("OpAuthOutputIdx", vec![active_input.clone(), identifier_expr(loop_var)]),
        ),
        call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]),
    ];
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(out_count_name), to_expr, then_branch));
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
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(in_count_name), from_expr, then_branch));
}

fn append_cov_input_state_reads_into_state_array<'i>(
    body: &mut Vec<Statement<'i>>,
    cov_id_name: &str,
    in_count_name: &str,
    from_expr: Expr<'i>,
    prev_states_name: &str,
) {
    let loop_var = "__cov_in_k";
    body.push(var_decl_statement(state_array_type_ref(), prev_states_name));
    let then_branch = vec![array_push_statement(
        prev_states_name,
        Expr::call("readInputState", vec![Expr::call("OpCovInputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)])]),
    )];
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(in_count_name), from_expr, then_branch));
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
    let then_branch = vec![
        var_def_statement(
            int_type_ref(),
            out_idx_name,
            Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
        ),
        call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]),
    ];
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(out_count_name), to_expr, then_branch));
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
    let mut then_branch = Vec::new();
    then_branch.push(var_def_statement(
        int_type_ref(),
        out_idx_name,
        Expr::call("OpAuthOutputIdx", vec![active_input.clone(), identifier_expr(loop_var)]),
    ));
    let next_state_expr = state_object_expr_from_field_arrays_at_index(contract_fields, &field_arrays, identifier_expr(loop_var));
    then_branch.push(call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]));
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(out_count_name), to_expr, then_branch));
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
    let mut then_branch = Vec::new();
    then_branch.push(var_def_statement(
        int_type_ref(),
        out_idx_name,
        Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
    ));
    let next_state_expr = state_object_expr_from_field_arrays_at_index(contract_fields, &field_arrays, identifier_expr(loop_var));
    then_branch.push(call_statement("validateOutputState", vec![identifier_expr(out_idx_name), next_state_expr]));
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(out_count_name), to_expr, then_branch));
}

fn append_auth_output_state_array_checks_from_state_array<'i>(
    body: &mut Vec<Statement<'i>>,
    active_input: &Expr<'i>,
    out_count_name: &str,
    to_expr: Expr<'i>,
    state_array_name: &str,
) {
    let loop_var = "__cov_k";
    let out_idx_name = "__cov_out_idx";
    let then_branch = vec![
        var_def_statement(
            int_type_ref(),
            out_idx_name,
            Expr::call("OpAuthOutputIdx", vec![active_input.clone(), identifier_expr(loop_var)]),
        ),
        call_statement(
            "validateOutputState",
            vec![identifier_expr(out_idx_name), array_index_expr(state_array_name, identifier_expr(loop_var))],
        ),
    ];
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(out_count_name), to_expr, then_branch));
}

fn append_cov_output_state_array_checks_from_state_array<'i>(
    body: &mut Vec<Statement<'i>>,
    cov_id_name: &str,
    out_count_name: &str,
    to_expr: Expr<'i>,
    state_array_name: &str,
) {
    let loop_var = "__cov_k";
    let out_idx_name = "__cov_out_idx";
    let then_branch = vec![
        var_def_statement(
            int_type_ref(),
            out_idx_name,
            Expr::call("OpCovOutputIdx", vec![identifier_expr(cov_id_name), identifier_expr(loop_var)]),
        ),
        call_statement(
            "validateOutputState",
            vec![identifier_expr(out_idx_name), array_index_expr(state_array_name, identifier_expr(loop_var))],
        ),
    ];
    body.push(for_statement(loop_var, Expr::int(0), identifier_expr(out_count_name), to_expr, then_branch));
}
