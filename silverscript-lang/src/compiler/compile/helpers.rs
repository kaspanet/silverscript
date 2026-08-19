use super::*;

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

pub(super) fn build_function_abi_entries<'i>(contract: &ContractAst<'i>) -> Vec<FunctionAbiEntry> {
    contract
        .functions
        .iter()
        .filter(|func| func.entrypoint)
        .map(|func| FunctionAbiEntry {
            name: func.name.clone(),
            inputs: func
                .params
                .iter()
                .map(|param| FunctionInputAbi { name: param.name.clone(), type_name: param.type_ref.type_name() })
                .collect(),
        })
        .collect()
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
