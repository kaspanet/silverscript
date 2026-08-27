use std::collections::HashMap;

use silverscript_abi::{
    CompiledContractArtifact, FieldArtifact, ParamArtifact, RuntimeFieldArtifact, RuntimeStateArtifact, SIL_ABI_SCHEMA_VERSION,
    SilAbiArtifact, SilContractArtifact, SilEntryArtifact, StateArtifact, StateSpanArtifact, TypeArtifact, encode_hex,
};

use super::*;

/// Compiles one SilverScript contract into a complete portable ABI artifact.
pub fn sil_abi_artifact<'i>(source: &'i str, constructor_args: &[Expr<'i>]) -> Result<SilAbiArtifact, CompilerError> {
    let compiled = compile_contract(source, constructor_args, CompileOptions::default())?;
    let constants = artifact_constants(&compiled, constructor_args);
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
    let contract = contract_artifact_from_compiled(&compiled, constructor_args)?;

    Ok(SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION, states, contracts: vec![contract] })
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

    Ok(SilContractArtifact {
        name: compiled.contract_name.clone(),
        source_path: format!("sil/{}.sil", compiled.contract_name),
        runtime_state: RuntimeStateArtifact { source: STATE_TYPE_NAME.to_string(), fields: runtime_fields },
        entries,
        compiled: CompiledContractArtifact {
            script_hex: encode_hex(&compiled.bytecode),
            template_hash_hex: encode_hex(&compiled.template_hash()),
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
