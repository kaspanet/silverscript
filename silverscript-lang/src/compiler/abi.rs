use std::collections::{HashMap, HashSet};

use silverscript_abi::{
    ArtifactValue, CompiledContractArtifact, FieldArtifact, ParamArtifact, RuntimeFieldArtifact, RuntimeStateArtifact,
    SIL_ABI_SCHEMA_VERSION, SilAbiArtifact, SilContractArtifact, SilEntryArtifact, StateArtifact, StateSpanArtifact, TypeArtifact,
    encode_hex,
};

use super::*;

fn artifact_values_to_constructor_args<'i>(
    values: &[ArtifactValue],
    contract: &ContractAst<'i>,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    if values.len() != contract.params.len() {
        return Err(CompilerError::Unsupported(format!(
            "constructor argument count mismatch: expected {}, got {}",
            contract.params.len(),
            values.len()
        )));
    }

    values.iter().zip(&contract.params).map(|(value, param)| artifact_value_to_expr(value, &param.type_ref, contract)).collect()
}

/// Converts a portable ABI value to a concrete expression of the declared SilverScript type.
pub fn artifact_value_to_expr<'i>(
    value: &ArtifactValue,
    expected_type: &TypeRef,
    contract: &ContractAst<'i>,
) -> Result<Expr<'i>, CompilerError> {
    if expected_type.is_array() {
        if matches!(expected_type.base, TypeBase::Byte) && expected_type.array_dims.len() == 1 {
            let ArtifactValue::Bytes(bytes) = value else {
                return Err(artifact_value_type_mismatch(value, expected_type));
            };
            return Ok(Expr::array(expected_type.clone(), bytes.iter().copied().map(Expr::byte).collect()));
        }

        let ArtifactValue::Array(values) = value else {
            return Err(artifact_value_type_mismatch(value, expected_type));
        };
        let element_type = expected_type
            .array_element_type()
            .ok_or_else(|| CompilerError::Unsupported(format!("invalid array type '{}'", expected_type.type_name())))?;
        let values = values
            .iter()
            .map(|value| artifact_value_to_expr(value, &element_type, contract))
            .collect::<Result<Vec<_>, CompilerError>>()?;
        return Ok(Expr::array(expected_type.clone(), values));
    }

    match (&expected_type.base, value) {
        (TypeBase::Int, ArtifactValue::Int(value)) => Ok(Expr::int(*value)),
        (TypeBase::Temporal, ArtifactValue::Int(value)) => Ok(Expr::temporal(*value)),
        (TypeBase::Bool, ArtifactValue::Bool(value)) => Ok(Expr::bool(*value)),
        (TypeBase::Byte, ArtifactValue::Byte(value)) => Ok(Expr::byte(*value)),
        (TypeBase::String, ArtifactValue::Text(value)) => Ok(Expr::string(value)),
        (TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig, ArtifactValue::Bytes(value)) => Ok(Expr::bytes(value.clone())),
        (TypeBase::Custom(name), ArtifactValue::Object(values)) => {
            let struct_ = contract
                .structs
                .iter()
                .find(|struct_| struct_.name == *name)
                .ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
            let expected_fields = struct_.fields.iter().map(|field| field.name.as_str()).collect::<HashSet<_>>();
            if let Some(field) = values.keys().find(|field| !expected_fields.contains(field.as_str())) {
                return Err(CompilerError::Unsupported(format!("unknown field '{name}.{field}'")));
            }
            let fields = struct_
                .fields
                .iter()
                .map(|field| {
                    let value = values
                        .get(&field.name)
                        .ok_or_else(|| CompilerError::Unsupported(format!("missing field '{name}.{}'", field.name)))?;
                    Ok(StateFieldExpr {
                        name: field.name.clone(),
                        expr: artifact_value_to_expr(value, &field.type_ref, contract)?,
                        span: Default::default(),
                        name_span: Default::default(),
                    })
                })
                .collect::<Result<Vec<_>, CompilerError>>()?;
            Ok(Expr::new(ExprKind::StructLiteral { name: name.clone(), fields, name_span: Default::default() }, Default::default()))
        }
        (TypeBase::Tuple(_), _) => {
            Err(CompilerError::Unsupported(format!("portable ABI values do not support tuple type '{}'", expected_type.type_name())))
        }
        _ => Err(artifact_value_type_mismatch(value, expected_type)),
    }
}

fn artifact_value_type_mismatch(value: &ArtifactValue, expected_type: &TypeRef) -> CompilerError {
    let actual = match value {
        ArtifactValue::Int(_) => "int",
        ArtifactValue::Bool(_) => "bool",
        ArtifactValue::Byte(_) => "byte",
        ArtifactValue::Bytes(_) => "bytes",
        ArtifactValue::Text(_) => "string",
        ArtifactValue::Array(_) => "array",
        ArtifactValue::Object(_) => "object",
    };
    CompilerError::Unsupported(format!("cannot convert artifact {actual} to {}", expected_type.type_name()))
}

/// Compiles one SilverScript contract into a complete portable ABI artifact.
pub fn sil_abi_artifact(source: &str, constructor_args: &[ArtifactValue]) -> Result<SilAbiArtifact, CompilerError> {
    sil_abi_artifact_with_options(source, constructor_args, CompileOptions::default())
}

/// Compiles one SilverScript contract into a complete portable ABI artifact
/// using the requested compiler options.
pub fn sil_abi_artifact_with_options(
    source: &str,
    constructor_args: &[ArtifactValue],
    options: CompileOptions,
) -> Result<SilAbiArtifact, CompilerError> {
    let contract = parse_contract_ast(source)?;
    let constructor_args = artifact_values_to_constructor_args(constructor_args, &contract)?;
    let compiled = compile_contract(source, &constructor_args, options)?;
    sil_abi_artifact_from_compiled(&compiled, &constructor_args)
}

/// Builds a portable ABI artifact from an already compiled contract.
pub fn sil_abi_artifact_from_compiled<'i>(
    compiled: &CompiledContract<'i>,
    constructor_args: &[Expr<'i>],
) -> Result<SilAbiArtifact, CompilerError> {
    let constants = artifact_constants(compiled, constructor_args);
    let states = compiled
        .ast
        .structs
        .iter()
        .map(|struct_| {
            let fields = struct_
                .fields
                .iter()
                .map(|field| Ok(FieldArtifact { name: field.name.clone(), ty: type_artifact(&field.type_ref, &constants)? }))
                .collect::<Result<Vec<_>, CompilerError>>()?;
            Ok(StateArtifact { name: struct_.name.clone(), fields })
        })
        .collect::<Result<Vec<_>, CompilerError>>()?;
    let contract = contract_artifact_from_compiled(compiled, constructor_args)?;

    Ok(SilAbiArtifact {
        schema_version: SIL_ABI_SCHEMA_VERSION,
        compiler_version: compiled.compiler_version.clone(),
        states,
        contracts: vec![contract],
    })
}

fn contract_artifact_from_compiled<'i>(
    compiled: &CompiledContract<'i>,
    constructor_args: &[Expr<'i>],
) -> Result<SilContractArtifact, CompilerError> {
    let constants = artifact_constants(compiled, constructor_args);

    let runtime_fields = compiled
        .ast
        .fields
        .iter()
        .map(|field| Ok(RuntimeFieldArtifact { name: field.name.clone(), ty: type_artifact(&field.type_ref, &constants)? }))
        .collect::<Result<Vec<_>, CompilerError>>()?;
    let entries = compiled
        .ast
        .functions
        .iter()
        .filter(|function| function.entrypoint)
        .map(|function| {
            let compiled_entry = compiled.entry_by_name(&function.name).ok_or_else(|| {
                CompilerError::Unsupported(format!(
                    "compiled contract '{}' has no ABI entry for function '{}'",
                    compiled.contract_name, function.name
                ))
            })?;
            let params = function
                .params
                .iter()
                .map(|param| Ok(ParamArtifact { name: param.name.clone(), ty: type_artifact(&param.type_ref, &constants)? }))
                .collect::<Result<Vec<_>, CompilerError>>()?;
            Ok(SilEntryArtifact { name: function.name.clone(), dispatch_tag: compiled_entry.dispatch_tag.into(), params })
        })
        .collect::<Result<Vec<_>, CompilerError>>()?;
    let artifact_entry = |entry: &FunctionAbiEntry| {
        entries.iter().find(|artifact| artifact.name == entry.name).cloned().ok_or_else(|| {
            CompilerError::Unsupported(format!(
                "compiled contract '{}' has no portable ABI entry for generated function '{}'",
                compiled.contract_name, entry.name
            ))
        })
    };
    let cov_decl_to_abi = compiled
        .cov_decl_to_abi
        .iter()
        .map(|(name, entry)| Ok((name.clone(), artifact_entry(entry)?)))
        .collect::<Result<_, CompilerError>>()?;
    let delegate_entry_abi = compiled.delegate_entry_abi.as_ref().map(artifact_entry).transpose()?;

    let layout = compiled.state_layout;
    let state_end = checked_add(layout.start, layout.len)?;
    if layout.start > compiled.bytecode.len() || state_end > compiled.bytecode.len() {
        return Err(CompilerError::Unsupported(format!(
            "compiled contract '{}' reported invalid state span start={} len={} for script len={}",
            compiled.contract_name,
            layout.start,
            layout.len,
            compiled.bytecode.len()
        )));
    }

    let template_hash = compiled.template_hash();
    Ok(SilContractArtifact {
        name: compiled.contract_name.clone(),
        source_path: format!("sil/{}.sil", compiled.contract_name),
        runtime_state: RuntimeStateArtifact { source: STATE_TYPE_NAME.to_string(), fields: runtime_fields },
        entries,
        cov_decl_to_abi,
        delegate_entry_abi,
        compiled: CompiledContractArtifact {
            bytecode: compiled.bytecode.clone(),
            script_hex: encode_hex(&compiled.bytecode),
            template_hash,
            template_hash_hex: encode_hex(&template_hash),
            state_span: StateSpanArtifact { offset: layout.start, len: layout.len },
        },
    })
}

fn artifact_constants<'i>(compiled: &CompiledContract<'i>, constructor_args: &[Expr<'i>]) -> HashMap<String, Expr<'i>> {
    let mut constants: HashMap<String, Expr<'i>> =
        compiled.ast.constants.iter().map(|constant| (constant.name.clone(), constant.expr.clone())).collect();
    constants.extend(compiled.ast.params.iter().zip(constructor_args).map(|(param, value)| (param.name.clone(), value.clone())));
    constants
}

fn type_artifact<'i>(type_ref: &TypeRef, constants: &HashMap<String, Expr<'i>>) -> Result<TypeArtifact, CompilerError> {
    let mut artifact = match &type_ref.base {
        TypeBase::Int => TypeArtifact::Int,
        TypeBase::Temporal => TypeArtifact::Temporal,
        TypeBase::Bool => TypeArtifact::Bool,
        TypeBase::Byte => TypeArtifact::Byte,
        TypeBase::String => TypeArtifact::Text,
        TypeBase::Pubkey => TypeArtifact::Pubkey,
        TypeBase::Sig => TypeArtifact::Sig,
        TypeBase::Datasig => TypeArtifact::Datasig,
        TypeBase::Custom(name) => TypeArtifact::Struct { name: name.clone() },
        TypeBase::Tuple(_) => {
            return Err(CompilerError::Unsupported(format!("portable ABI does not support tuple type '{}'", type_ref.type_name())));
        }
    };

    for dimension in &type_ref.array_dims {
        let len =
            match dimension {
                ArrayDim::Dynamic => None,
                ArrayDim::Fixed(len) => Some(*len),
                ArrayDim::Constant(name) => {
                    let value = constants
                        .get(name)
                        .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))
                        .and_then(|expr| eval_const_int(expr, constants))?;
                    Some(usize::try_from(value).map_err(|_| {
                        CompilerError::Unsupported(format!("array size constant '{name}' must be a non-negative integer"))
                    })?)
                }
                ArrayDim::Inferred => {
                    return Err(CompilerError::Unsupported(
                        "portable ABI array dimension was not inferred during compilation".to_string(),
                    ));
                }
            };
        artifact = match (artifact, len) {
            (TypeArtifact::Byte, Some(len)) => TypeArtifact::FixedBytes { len },
            (TypeArtifact::Byte, None) => TypeArtifact::Bytes,
            (item, Some(len)) => TypeArtifact::FixedArray { item: Box::new(item), len },
            (item, None) => TypeArtifact::DynamicArray { item: Box::new(item) },
        };
    }

    Ok(artifact)
}
