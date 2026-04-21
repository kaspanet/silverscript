use std::collections::HashSet;

use silverscript_lang::ast::{ContractAst, FunctionAst};
use silverscript_lang::compiler::CompiledContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CovenantBinding {
    Auth,
    Cov,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CovenantMode {
    Verification,
    Transition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovenantSourceBinding {
    pub param_name: String,
    pub param_type_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCovenantCallTarget {
    pub source_name: String,
    pub binding: CovenantBinding,
    pub mode: CovenantMode,
    pub source_binding: Option<CovenantSourceBinding>,
    pub generated_entrypoint_name: String,
    pub policy_function_name: String,
    pub generated_function_names: HashSet<String>,
}

impl ResolvedCovenantCallTarget {
    pub fn display_name(&self) -> String {
        self.source_name.clone()
    }

    pub fn matches_generated_name(&self, function_name: &str) -> bool {
        self.generated_function_names.contains(function_name)
    }

    pub fn generated_entrypoint_name_for(&self, is_leader: bool) -> String {
        match self.binding {
            CovenantBinding::Auth => generated_covenant_entrypoint_name(&self.source_name),
            CovenantBinding::Cov => {
                if is_leader {
                    generated_covenant_leader_entrypoint_name(&self.source_name)
                } else {
                    generated_covenant_delegate_entrypoint_name(&self.source_name)
                }
            }
        }
    }
}

pub fn resolve_covenant_call_target<'i>(
    contract: &ContractAst<'i>,
    compiled: &CompiledContract<'i>,
    function_name: &str,
) -> Option<ResolvedCovenantCallTarget> {
    let function =
        contract.functions.iter().find(|function| function.name == function_name && is_covenant_source_function(function))?;

    let auth_entrypoint_name = generated_covenant_entrypoint_name(function_name);
    let leader_entrypoint_name = generated_covenant_leader_entrypoint_name(function_name);
    let has_auth_entrypoint = abi_contains_function(compiled, &auth_entrypoint_name);
    let has_leader_entrypoint = abi_contains_function(compiled, &leader_entrypoint_name);

    let binding = if has_auth_entrypoint {
        CovenantBinding::Auth
    } else if has_leader_entrypoint {
        CovenantBinding::Cov
    } else {
        return None;
    };

    let generated_entrypoint_name = match binding {
        CovenantBinding::Auth => auth_entrypoint_name.clone(),
        CovenantBinding::Cov => {
            if !has_leader_entrypoint {
                return None;
            }
            leader_entrypoint_name.clone()
        }
    };

    let mut generated_function_names = HashSet::from([generated_covenant_policy_name(function_name)]);
    if has_auth_entrypoint {
        generated_function_names.insert(auth_entrypoint_name);
    }
    if has_leader_entrypoint {
        generated_function_names.insert(leader_entrypoint_name);
    }

    Some(ResolvedCovenantCallTarget {
        source_name: function.name.clone(),
        binding,
        mode: if function.return_types.is_empty() { CovenantMode::Verification } else { CovenantMode::Transition },
        source_binding: function
            .params
            .first()
            .map(|param| CovenantSourceBinding { param_name: param.name.clone(), param_type_name: param.type_ref.type_name() }),
        generated_entrypoint_name,
        policy_function_name: generated_covenant_policy_name(function_name),
        generated_function_names,
    })
}

fn abi_contains_function(compiled: &CompiledContract<'_>, function_name: &str) -> bool {
    compiled.abi.iter().any(|entry| entry.name == function_name)
}

fn is_covenant_source_function(function: &FunctionAst<'_>) -> bool {
    function.attributes.iter().any(|attribute| attribute.path.first().is_some_and(|segment| segment == "covenant"))
}

fn generated_covenant_policy_name(function_name: &str) -> String {
    format!("__covenant_policy_{function_name}")
}

fn generated_covenant_entrypoint_name(function_name: &str) -> String {
    format!("__{function_name}")
}

fn generated_covenant_leader_entrypoint_name(function_name: &str) -> String {
    format!("__leader_{function_name}")
}

fn generated_covenant_delegate_entrypoint_name(function_name: &str) -> String {
    format!("__delegate_{function_name}")
}
