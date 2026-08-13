use super::*;

fn initial_contract_scope<'i>(contract: &ContractAst<'i>) -> LoweringScope {
    let mut scope = LoweringScope::default();
    for param in &contract.params {
        scope.declare(param.name.clone(), param.type_ref.clone());
    }
    for constant in &contract.constants {
        scope.declare(constant.name.clone(), constant.type_ref.clone());
    }
    for field in &contract.fields {
        scope.declare(field.name.clone(), field.type_ref.clone());
    }
    scope
}

fn flatten_param<'i>(param: &ParamAst<'i>, structs: &StructRegistry) -> Result<Vec<ParamAst<'i>>, CompilerError> {
    Ok(flatten_named_type(&param.name, &param.type_ref, structs)?
        .into_iter()
        .map(|(name, type_ref)| ParamAst { type_ref, name, span: param.span, type_span: param.type_span, name_span: param.name_span })
        .collect())
}

pub(crate) fn flatten_constructor_args_env<'i>(
    params: &[ParamAst<'i>],
    constructor_args: &[Expr<'i>],
    structs: &StructRegistry,
) -> Result<HashMap<String, Expr<'i>>, CompilerError> {
    let scope = LoweringScope::default();
    let functions = HashMap::new();
    let constants = HashMap::new();
    let lowerer = StructLowerer::new(structs, &functions, &[], &constants, 0);
    let mut env = HashMap::new();
    for (param, arg) in params.iter().zip(constructor_args.iter()) {
        for (name, _, expr) in lower_named_expr(param.name.as_str(), &param.type_ref, arg, &scope, &lowerer)? {
            env.insert(name, expr);
        }
    }
    Ok(env)
}

pub(crate) fn lower_structs_contract<'i>(
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    contract_constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions_map =
        contract.functions.iter().cloned().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let lowerer = StructLowerer::new(structs, &functions_map, &contract.fields, contract_constants, 0);
    let mut scope = LoweringScope::default();
    let mut lowered_params = Vec::new();
    for param in &contract.params {
        scope.declare(param.name.clone(), param.type_ref.clone());
        lowered_params.extend(flatten_param(param, structs)?);
    }

    let mut lowered_constants = Vec::new();
    for constant in &contract.constants {
        scope.declare(constant.name.clone(), constant.type_ref.clone());
        for (name, type_ref, expr) in lower_named_expr(&constant.name, &constant.type_ref, &constant.expr, &scope, &lowerer)? {
            lowered_constants.push(ConstantAst {
                type_ref,
                name,
                expr,
                span: constant.span,
                type_span: constant.type_span,
                name_span: constant.name_span,
            });
        }
    }

    let mut lowered_fields = Vec::new();
    for field in &contract.fields {
        scope.declare(field.name.clone(), field.type_ref.clone());
        for (name, type_ref, expr) in lower_named_expr(&field.name, &field.type_ref, &field.expr, &scope, &lowerer)? {
            lowered_fields.push(ContractFieldAst {
                type_ref,
                name,
                expr,
                span: field.span,
                type_span: field.type_span,
                name_span: field.name_span,
            });
        }
    }

    let mut lowered_functions = Vec::new();
    for function in &contract.functions {
        let mut function_scope = initial_contract_scope(contract);
        for param in &function.params {
            function_scope.declare(param.name.clone(), param.type_ref.clone());
        }

        let mut lowered_function_params = Vec::new();
        for param in &function.params {
            lowered_function_params.extend(flatten_param(param, structs)?);
        }

        let mut lowered_return_types = Vec::new();
        for return_type in &function.return_types {
            for leaf in flatten_type_leaves(return_type, structs)? {
                lowered_return_types.push(leaf.type_ref);
            }
        }

        let lowered_body = lower_statements(&function.body, &mut function_scope, &function.return_types, &lowerer)?;

        lowered_functions.push(FunctionAst {
            name: function.name.clone(),
            attributes: function.attributes.clone(),
            params: lowered_function_params,
            entrypoint: function.entrypoint,
            return_types: lowered_return_types,
            returns_tuple: function.returns_tuple,
            body: lowered_body,
            return_type_spans: function.return_type_spans.clone(),
            span: function.span,
            name_span: function.name_span,
            body_span: function.body_span,
        });
    }

    Ok(ContractAst {
        pragma: contract.pragma.clone(),
        name: contract.name.clone(),
        params: lowered_params,
        structs: Vec::new(),
        fields: lowered_fields,
        constants: lowered_constants,
        functions: lowered_functions,
        span: contract.span,
        name_span: contract.name_span,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parse_contract_ast;

    #[test]
    fn struct_array_append_groups_values_by_leaf() {
        let source = r#"
            contract C() {
                struct S {
                    int a;
                    byte[2] b;
                }

                entry main(S[] values) {
                    values = values.append(S {a: 1, b: byte[_](0x0102)}, S {a: 2, b: byte[_](0x0304)});
                    require(values.length == 2);
                }
            }
        "#;
        let contract = parse_contract_ast(source).expect("contract should parse");
        let structs = build_struct_registry(&contract).expect("struct registry should build");
        let lowered = lower_structs_contract(&contract, &structs, &HashMap::new()).expect("struct array append should lower");

        let Statement::Block { body, .. } = &lowered.functions[0].body[0] else {
            panic!("multi-leaf struct array append should lower through an atomic block");
        };
        let append_assignments = body
            .iter()
            .filter_map(|statement| {
                let Statement::VariableDefinition { name, expr: Some(expr), .. } = statement else {
                    return None;
                };
                let ExprKind::Append { args, .. } = &expr.kind else {
                    return None;
                };
                Some((name, args))
            })
            .collect::<Vec<_>>();

        assert_eq!(append_assignments.len(), 2, "one append assignment should be emitted per struct leaf");
        assert!(append_assignments.iter().all(|(name, _)| name.starts_with("__struct_assignment_")));
        assert!(append_assignments.iter().all(|(_, args)| args.len() == 2), "each leaf append should contain both values");
        assert!(
            matches!(&body[2], Statement::Assign { expr, .. } if matches!(&expr.kind, ExprKind::Identifier(name) if name == "__struct_assignment_0"))
        );
        assert!(
            matches!(&body[3], Statement::Assign { expr, .. } if matches!(&expr.kind, ExprKind::Identifier(name) if name == "__struct_assignment_1"))
        );
    }
}
