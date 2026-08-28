use super::*;
use crate::compiler::covenant_declarations::CovenantDeclarationAbiNames;

pub(super) struct EntrypointMetadata {
    pub(super) dispatches: Vec<EntrypointDispatch>,
    pub(super) covenant_entrypoints: BTreeMap<String, String>,
    pub(super) delegate_entrypoint: Option<String>,
}

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

        if fixed_type_size(&field.type_ref, base_constants)?.is_some() {
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
    type_check::infer_expr_type(expr, &ctx)
}

/// assumption: no inferred dimensions array param on entrypoint parameters before calling this function
fn write_dispatch_type_name<'i>(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
    signature: &mut String,
) -> Result<(), CompilerError> {
    match &type_ref.base {
        TypeBase::Custom(name) => {
            let item = structs
                .get(name)
                .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}' in entrypoint dispatch type")))?;
            signature.push('{');
            for (index, field) in item.fields.iter().enumerate() {
                if index != 0 {
                    signature.push(',');
                }
                write_dispatch_type_name(&field.type_ref, structs, constants, signature)?;
            }
            signature.push('}');
        }
        _ => signature.push_str(&type_ref.base.type_name()),
    }

    for dimension in &type_ref.array_dims {
        match dimension {
            ArrayDim::Dynamic => signature.push_str("[]"),
            ArrayDim::Fixed(size) => signature.push_str(&format!("[{size}]")),
            ArrayDim::Constant(name) => {
                let value = constants
                    .get(name)
                    .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))
                    .and_then(|expr| eval_const_int(expr, constants))?;
                let size = usize::try_from(value)
                    .map_err(|_| CompilerError::Unsupported(format!("array size constant '{name}' must be a non-negative integer")))?;
                signature.push_str(&format!("[{size}]"));
            }
            ArrayDim::Inferred => panic!("inferred array dimensions must be rejected before writing a dispatch type name"),
        }
    }

    Ok(())
}

pub(super) fn build_entrypoint_metadata<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
    structs: &StructRegistry,
    covenant_abi_names: &CovenantDeclarationAbiNames,
) -> Result<EntrypointMetadata, CompilerError> {
    let source_name_by_entrypoint = covenant_abi_names
        .entrypoints
        .iter()
        .map(|(source_name, entrypoint_name)| (entrypoint_name.as_str(), source_name.as_str()))
        .collect::<HashMap<_, _>>();
    let delegate_entrypoint = covenant_abi_names.delegate_entrypoint.as_deref();
    let mut dispatches = Vec::new();
    let mut covenant_entrypoints = BTreeMap::new();
    let mut built_delegate_entrypoint = None;

    for func in contract.functions.iter().filter(|func| func.entrypoint) {
        let signature_types = func
            .params
            .iter()
            .map(|param| {
                let type_ref = resolve_abi_type_ref(&param.type_ref, constants, &func.name, &param.name)?;
                let mut signature_type = String::new();
                write_dispatch_type_name(&type_ref, structs, constants, &mut signature_type)?;
                Ok(signature_type)
            })
            .collect::<Result<Vec<_>, CompilerError>>()?;
        let signature = format!("{}({})", func.name, signature_types.join(","));
        let hash = blake3::hash(signature.as_bytes());
        let mut dispatch_tag = [0; 4];
        dispatch_tag.copy_from_slice(&hash.as_bytes()[..4]);
        let entry = EntrypointDispatch { name: func.name.clone(), dispatch_tag };

        if let Some(source_name) = source_name_by_entrypoint.get(func.name.as_str()) {
            covenant_entrypoints.insert((*source_name).to_string(), func.name.clone());
        }
        if delegate_entrypoint == Some(func.name.as_str()) {
            built_delegate_entrypoint = Some(func.name.clone());
        }
        dispatches.push(entry);
    }

    if let Some((source_name, entrypoint_name)) =
        covenant_abi_names.entrypoints.iter().find(|(source_name, _)| !covenant_entrypoints.contains_key(*source_name))
    {
        return Err(CompilerError::Unsupported(format!(
            "generated covenant entrypoint '{entrypoint_name}' for declaration '{source_name}' is missing from dispatch metadata"
        )));
    }
    if let Some(entrypoint_name) = delegate_entrypoint.filter(|_| built_delegate_entrypoint.is_none()) {
        return Err(CompilerError::Unsupported(format!(
            "generated covenant delegate entrypoint '{entrypoint_name}' is missing from dispatch metadata"
        )));
    }

    Ok(EntrypointMetadata { dispatches, covenant_entrypoints, delegate_entrypoint: built_delegate_entrypoint })
}

pub(super) fn resolve_artifact_struct_type_refs<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let mut resolved = contract.clone();
    for item in &mut resolved.structs {
        for field in &mut item.fields {
            field.type_ref =
                resolve_abi_type_ref(&field.type_ref, constants, "artifact struct schema", &format!("{}.{}", item.name, field.name))?;
        }
    }
    Ok(resolved)
}

pub(super) fn resolve_abi_type_ref<'i>(
    type_ref: &TypeRef,
    constants: &HashMap<String, Expr<'i>>,
    function_name: &str,
    parameter_name: &str,
) -> Result<TypeRef, CompilerError> {
    let mut resolved = type_ref.clone();
    if let TypeBase::Tuple(elements) = &mut resolved.base {
        for element in elements {
            *element = resolve_abi_type_ref(element, constants, function_name, parameter_name)?;
        }
    }
    for dimension in &mut resolved.array_dims {
        match dimension {
            ArrayDim::Inferred => {
                return Err(CompilerError::NonCanonicalEntrypointParameter {
                    function: function_name.to_string(),
                    param: parameter_name.to_string(),
                });
            }
            ArrayDim::Constant(name) => {
                let value = constants
                    .get(name)
                    .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))
                    .and_then(|expr| eval_const_int(expr, constants))?;
                let size = usize::try_from(value)
                    .map_err(|_| CompilerError::Unsupported(format!("array size constant '{name}' must be a non-negative integer")))?;
                *dimension = ArrayDim::Fixed(size);
            }
            ArrayDim::Dynamic | ArrayDim::Fixed(_) => {}
        }
    }
    Ok(resolved)
}

pub(super) fn array_element_size<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Result<Option<i64>, CompilerError> {
    let Some(element_type) = type_ref.array_element_type() else { return Ok(None) };
    let Some(size) = fixed_type_size(&element_type, constants)? else { return Ok(None) };
    let size = i64::try_from(size)
        .map_err(|_| CompilerError::ArithmeticOverflow(format!("array element size {size} does not fit in i64")))?;
    Ok(Some(size))
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
                _ => return Err(array_literal_encoding_error(value)),
            };
            serialize_i64(number, Some(8usize))
                .map(|bytes| bytes.to_vec())
                .map_err(|err| CompilerError::Unsupported(format!("failed to serialize int literal {}: {err}", number)))
        }
        (TypeBase::Bool, []) => {
            let ExprKind::Bool(flag) = &value.kind else {
                return Err(array_literal_encoding_error(value));
            };
            Ok(vec![u8::from(*flag)])
        }
        (TypeBase::Byte, []) => {
            let byte = match &value.kind {
                ExprKind::Byte(byte) => *byte,
                ExprKind::Int(value) => {
                    (*value).try_into().map_err(|_| CompilerError::Unsupported("array literal element type mismatch".to_string()))?
                }
                _ => return Err(array_literal_encoding_error(value)),
            };
            Ok(vec![byte])
        }
        (base @ (TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig), []) => {
            let ExprKind::Array { values: bytes_exprs, .. } = &value.kind else {
                return Err(array_literal_encoding_error(value));
            };
            if Some(bytes_exprs.len()) != base.fixed_byte_sequence_len() {
                return Err(CompilerError::Unsupported("array literal element type mismatch".to_string()));
            }
            bytes_exprs
                .iter()
                .map(|value| match &value.kind {
                    ExprKind::Byte(byte) => Ok(*byte),
                    _ => Err(array_literal_encoding_error(value)),
                })
                .collect()
        }
        _ => {
            // Handle fixed-size byte arrays like byte[N]
            if let (Some(inner_type), Some(size)) = (type_ref.array_element_type(), array_type_size(type_ref, constants)?) {
                if inner_type.is_byte() {
                    let ExprKind::Array { values, .. } = &value.kind else {
                        return Err(array_literal_encoding_error(value));
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
                let expected_len = array_type_size(type_ref, constants)?
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

            Err(array_literal_encoding_error(value))
        }
    }
}

fn array_literal_encoding_error(value: &Expr<'_>) -> CompilerError {
    match &value.kind {
        ExprKind::Int(_)
        | ExprKind::Temporal(_)
        | ExprKind::Bool(_)
        | ExprKind::Byte(_)
        | ExprKind::String(_)
        | ExprKind::DateLiteral(_)
        | ExprKind::Array { .. }
        | ExprKind::StructLiteral { .. }
        | ExprKind::NumberWithUnit { .. } => CompilerError::Unsupported("array literal element type mismatch".to_string()),
        _ => CompilerError::RuntimeEvaluationRequired,
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
    debug_assert!(fixed_type_size(&element_type, constants)?.is_some(), "type_check must validate array element type has known size");
    for value in values {
        out.extend(encode_value_with_constant_size(value, &element_type, constants)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_element_size_reports_i64_conversion_overflow() {
        let type_ref = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Fixed(usize::MAX), ArrayDim::Dynamic] };

        let err = array_element_size(&type_ref, &HashMap::new()).expect_err("an element size larger than i64 must be rejected");
        assert!(matches!(err, CompilerError::ArithmeticOverflow(_)), "unexpected error: {err}");
    }

    #[test]
    fn constant_value_encoding_only_requests_runtime_fallback_for_runtime_expressions() {
        let int_type = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
        let constants = HashMap::new();

        let err = encode_value_with_constant_size(&Expr::identifier("runtime_value"), &int_type, &constants)
            .expect_err("a runtime value cannot be encoded ahead of time");
        assert!(matches!(err, CompilerError::RuntimeEvaluationRequired), "unexpected error: {err}");

        let err = encode_value_with_constant_size(&Expr::bool(true), &int_type, &constants)
            .expect_err("an invalid literal must not request runtime fallback");
        assert!(matches!(err, CompilerError::Unsupported(_)), "unexpected error: {err}");
    }
}
