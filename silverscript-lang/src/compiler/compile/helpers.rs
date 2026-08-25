use super::*;
use crate::compiler::covenant_declarations::CovenantDeclarationAbiNames;

pub(super) fn compile_contract_fields<'i>(
    fields: &[ContractFieldAst<'i>],
    base_constants: &HashMap<String, Expr<'i>>,
    bytecode_size: Option<i64>,
) -> Result<(HashMap<String, Expr<'i>>, Vec<u8>), CompilerError> {
    let mut field_values = HashMap::new();
    let mut field_types = HashMap::new();
    let mut builder = script_builder();
    let stack_bindings = StackBindings::default();

    for field in fields {
        let mut resolve_visiting = HashSet::new();
        let resolved = resolve_constant_references(field.expr.clone(), base_constants, &mut resolve_visiting)?;

        if fixed_type_size(&field.type_ref, base_constants).is_some() {
            let encoded = encode_value_with_constant_size(&resolved, &field.type_ref, base_constants)?;
            builder.add_data_with_push_opcode(&encoded)?;
        } else {
            let env = ExprEnv {
                constants: base_constants,
                stack_bindings: &stack_bindings,
                types: &field_types,
                bytecode_size,
                contract_constants: base_constants,
            };
            let mut emitter = ScriptEmitter::new(&mut builder, 0);
            compile_expr(&resolved, Some(&field.type_ref), &env, &mut emitter)?;
        }

        field_values.insert(field.name.clone(), resolved);
        field_types.insert(field.name.clone(), field.type_ref.clone());
    }

    Ok((field_values, builder.drain()))
}

pub(super) fn infer_expr_type<'i>(
    expr: &Expr<'i>,
    constants: &HashMap<String, Expr<'i>>,
    types: &TypeMap,
) -> Result<TypeRef, CompilerError> {
    let structs = StructRegistry::new();
    let functions = HashMap::new();
    let ctx = type_check::TypeCheckContext { types, structs: &structs, constants, functions: &functions, contract_fields: &[] };
    type_check::check_expr(expr, None, &ctx)
}

pub(super) fn build_abi<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
    covenant_abi_names: &CovenantDeclarationAbiNames,
) -> Result<(Vec<FunctionAbiEntry>, HashMap<String, FunctionAbiEntry>, Option<FunctionAbiEntry>), CompilerError> {
    let source_name_by_entrypoint = covenant_abi_names
        .entrypoints
        .iter()
        .map(|(source_name, entrypoint_name)| (entrypoint_name.as_str(), source_name.as_str()))
        .collect::<HashMap<_, _>>();
    let delegate_entrypoint = covenant_abi_names.delegate_entrypoint.as_deref();
    let mut entries = Vec::new();
    let mut cov_decl_to_abi = HashMap::new();
    let mut delegate_entry_abi = None;

    for func in contract.functions.iter().filter(|func| func.entrypoint) {
        let inputs = func
            .params
            .iter()
            .map(|param| {
                let mut type_ref = param.type_ref.clone();
                for dimension in &mut type_ref.array_dims {
                    if matches!(dimension, ArrayDim::Inferred) {
                        return Err(CompilerError::NonCanonicalEntrypointParameter {
                            function: func.name.clone(),
                            param: param.name.clone(),
                        });
                    }
                    if let ArrayDim::Constant(name) = dimension {
                        let value = constants
                            .get(name)
                            .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))
                            .and_then(|expr| eval_const_int(expr, constants))?;
                        let size = usize::try_from(value).map_err(|_| {
                            CompilerError::Unsupported(format!("array size constant '{name}' must be a non-negative integer"))
                        })?;
                        *dimension = ArrayDim::Fixed(size);
                    }
                }
                Ok(FunctionInputAbi { name: param.name.clone(), type_name: type_ref.type_name() })
            })
            .collect::<Result<Vec<_>, CompilerError>>()?;
        let entry = FunctionAbiEntry { name: func.name.clone(), inputs };

        if let Some(source_name) = source_name_by_entrypoint.get(func.name.as_str()) {
            cov_decl_to_abi.insert((*source_name).to_string(), entry.clone());
        }
        if delegate_entrypoint == Some(func.name.as_str()) {
            delegate_entry_abi = Some(entry.clone());
        }
        entries.push(entry);
    }

    if let Some((source_name, entrypoint_name)) =
        covenant_abi_names.entrypoints.iter().find(|(source_name, _)| !cov_decl_to_abi.contains_key(*source_name))
    {
        return Err(CompilerError::Unsupported(format!(
            "generated covenant entrypoint '{entrypoint_name}' for declaration '{source_name}' is missing from the ABI"
        )));
    }
    if let Some(entrypoint_name) = delegate_entrypoint.filter(|_| delegate_entry_abi.is_none()) {
        return Err(CompilerError::Unsupported(format!(
            "generated covenant delegate entrypoint '{entrypoint_name}' is missing from the ABI"
        )));
    }

    Ok((entries, cov_decl_to_abi, delegate_entry_abi))
}

pub(super) fn array_element_size<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Option<i64> {
    let element_type = type_ref.array_element_type()?;
    i64::try_from(fixed_type_size(&element_type, constants)?).ok()
}

pub(super) fn encode_value_with_constant_size<'i>(
    value: &Expr<'i>,
    type_ref: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<u8>, CompilerError> {
    let value = match &value.kind {
        ExprKind::Call { name, args, .. }
            if parse_type_ref(name).is_ok_and(|cast_type| cast_type.is_array())
                && matches!(args.as_slice(), [Expr { kind: ExprKind::Array { .. }, .. }]) =>
        {
            args.first().unwrap_or(value)
        }
        _ => value,
    };
    match (&type_ref.base, type_ref.array_dims.as_slice()) {
        (TypeBase::Int | TypeBase::Temporal, []) => {
            let number = match &value.kind {
                ExprKind::Int(number) | ExprKind::Temporal(number) | ExprKind::DateLiteral(number) => *number,
                _ => return Err(CompilerError::Unsupported("array literal element type mismatch".to_string())),
            };
            serialize_i64(number, Some(8usize))
                .map(|bytes| bytes.to_vec())
                .map_err(|err| CompilerError::Unsupported(format!("failed to serialize int literal {}: {err}", number)))
        }
        (TypeBase::Bool, []) => {
            let ExprKind::Bool(flag) = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            Ok(vec![u8::from(*flag)])
        }
        (TypeBase::Byte, []) => {
            let byte = match &value.kind {
                ExprKind::Byte(byte) => *byte,
                ExprKind::Int(value) => {
                    (*value).try_into().map_err(|_| CompilerError::Unsupported("array literal element type mismatch".to_string()))?
                }
                _ => return Err(CompilerError::Unsupported("array literal element type mismatch".to_string())),
            };
            Ok(vec![byte])
        }
        (base @ (TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig), []) => {
            let ExprKind::Array { values: bytes_exprs, .. } = &value.kind else {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            };
            if Some(bytes_exprs.len()) != base.fixed_byte_sequence_len() {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            }
            bytes_exprs
                .iter()
                .map(|value| match &value.kind {
                    ExprKind::Byte(byte) => Ok(*byte),
                    _ => Err(CompilerError::Unsupported("array literal element type mismatch".to_string())),
                })
                .collect()
        }
        _ => {
            // Handle fixed-size byte arrays like byte[N]
            if let (Some(inner_type), Some(size)) = (type_ref.array_element_type(), array_type_size(type_ref, constants)) {
                if inner_type.is_byte() {
                    let ExprKind::Array { values, .. } = &value.kind else {
                        return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                    };
                    if values.len() != size {
                        return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                    }
                    return values
                        .iter()
                        .map(|value| encode_value_with_constant_size(value, &inner_type, constants))
                        .collect::<Result<Vec<_>, _>>()
                        .map(|chunks| chunks.concat());
                }
            }

            // Handle nested fixed-size arrays with known element sizes.
            if let ExprKind::Array { values, .. } = &value.kind {
                let element_type = type_ref
                    .array_element_type()
                    .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
                let expected_len = array_type_size(type_ref, constants)
                    .ok_or_else(|| CompilerError::Unsupported("array literal element type mismatch".to_string()))?;
                if values.len() != expected_len {
                    return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
                }

                let mut encoded = Vec::new();
                for value in values {
                    encoded.extend(encode_value_with_constant_size(value, &element_type, constants)?);
                }
                return Ok(encoded);
            }

            Err(CompilerError::Unsupported("array literal element type mismatch".to_string()))
        }
    }
}

pub(in crate::compiler) fn encode_array_literal<'i>(
    values: &[Expr<'i>],
    type_ref: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<u8>, CompilerError> {
    let element_type = type_ref
        .array_element_type()
        .ok_or_else(|| CompilerError::Unsupported("array element type must have known size".to_string()))?;
    let mut out = Vec::new();
    debug_assert!(fixed_type_size(&element_type, constants).is_some(), "type_check must validate array element type has known size");
    for value in values {
        out.extend(encode_value_with_constant_size(value, &element_type, constants)?);
    }
    Ok(out)
}
