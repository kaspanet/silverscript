use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, SilContractArtifact};
use silverscript_lang::ast::parse_contract_ast;
use silverscript_lang::compiler::{
    CompileOptions, CompilerError, artifact_value_to_expr, compile_contract as compile_internal_contract,
    sil_abi_artifact_from_compiled,
};
use silverscript_lang::debug_info::DebugInfo;

/// A portable SilverScript ABI artifact accompanied by compiler debug metadata
/// for each contract it contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilDebugArtifact<'i> {
    pub abi: SilAbiArtifact,
    pub contract_debug_info: BTreeMap<String, DebugInfo<'i>>,
}

impl<'i> SilDebugArtifact<'i> {
    pub fn contract(&self, name: &str) -> Option<&SilContractArtifact> {
        self.abi.contract(name)
    }

    pub fn debug_info(&self, contract_name: &str) -> Option<&DebugInfo<'i>> {
        self.contract_debug_info.get(contract_name)
    }
}

/// Compiles one contract into its portable ABI and associated debug metadata.
pub fn compile_contract<'i>(
    source: &'i str,
    constructor_args: &[ArtifactValue],
    mut options: CompileOptions,
) -> Result<SilDebugArtifact<'i>, CompilerError> {
    let contract = parse_contract_ast(source)?;
    if constructor_args.len() != contract.params.len() {
        return Err(CompilerError::Unsupported(format!(
            "constructor argument count mismatch: expected {}, got {}",
            contract.params.len(),
            constructor_args.len()
        )));
    }
    let constructor_args = constructor_args
        .iter()
        .zip(&contract.params)
        .map(|(value, param)| artifact_value_to_expr(value, &param.type_ref, &contract))
        .collect::<Result<Vec<_>, CompilerError>>()?;

    // A debug artifact always records debug information regardless of the
    // caller's normal compilation preference.
    options.record_debug_infos = true;
    let compiled = compile_internal_contract(source, &constructor_args, options)?;
    let abi = sil_abi_artifact_from_compiled(&compiled, &constructor_args)?;
    let contract_name = compiled.contract_name.clone();
    let debug_info = compiled
        .debug_info
        .ok_or_else(|| CompilerError::Unsupported(format!("compiled contract '{contract_name}' has no debug information")))?;

    Ok(SilDebugArtifact { abi, contract_debug_info: BTreeMap::from([(contract_name, debug_info)]) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_portable_artifact_with_per_contract_debug_info() {
        let source = "contract C(int initial) { int value = initial; entry main() { require(value > 0); } }";
        let artifact = compile_contract(source, &[1.into()], CompileOptions::default()).expect("debug artifact compiles");

        let contract = artifact.contract("C").expect("portable contract exists");
        assert!(!contract.compiled.bytecode.is_empty());
        let debug_info = artifact.debug_info("C").expect("contract debug information exists");
        assert_eq!(debug_info.source, source);
        assert!(!debug_info.steps.is_empty());
    }
}
