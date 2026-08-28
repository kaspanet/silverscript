use std::collections::HashSet;

use silverscript_abi::SilContractArtifact;
use silverscript_lang::ast::{ContractAst, FunctionAst};

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
pub struct CovenantDelegateBodyTarget {
    pub source_name: String,
    pub policy_function_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCovenantCallTarget {
    pub source_name: String,
    pub binding: CovenantBinding,
    pub mode: CovenantMode,
    pub source_binding: Option<CovenantSourceBinding>,
    pub generated_entrypoint_name: String,
    pub delegate_entrypoint_name: Option<String>,
    pub delegate_body: Option<CovenantDelegateBodyTarget>,
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

    pub fn display_name_for(&self, function_name: &str) -> Option<&str> {
        if let Some(body) = &self.delegate_body
            && body.policy_function_name == function_name
        {
            return Some(body.source_name.as_str());
        }
        (self.policy_function_name == function_name || self.matches_generated_name(function_name)).then_some(self.source_name.as_str())
    }

    pub fn generated_entrypoint_name_for(&self, is_leader: bool) -> String {
        match self.binding {
            CovenantBinding::Auth => self.generated_entrypoint_name.clone(),
            CovenantBinding::Cov => {
                if is_leader {
                    self.generated_entrypoint_name.clone()
                } else {
                    self.delegate_entrypoint_name.clone().expect("a resolved cov-bound declaration has a shared delegate entrypoint")
                }
            }
        }
    }
}

pub fn resolve_covenant_call_target<'i>(
    contract: &ContractAst<'i>,
    artifact: &SilContractArtifact,
    function_name: &str,
) -> Option<ResolvedCovenantCallTarget> {
    let function =
        contract.functions.iter().find(|function| function.name == function_name && is_covenant_source_function(function))?;

    let generated_entrypoint_name = artifact.cov_decl_to_abi.get(function_name)?.clone();
    let nonleader_entrypoint_name = artifact.delegate_entry_abi.clone().unwrap_or_else(|| generated_entrypoint_name.clone());
    let binding = if generated_entrypoint_name == nonleader_entrypoint_name { CovenantBinding::Auth } else { CovenantBinding::Cov };
    let delegate_entrypoint_name = (binding == CovenantBinding::Cov).then_some(nonleader_entrypoint_name);
    let delegate_body = (binding == CovenantBinding::Cov)
        .then(|| contract.functions.iter().find(|function| is_covenant_delegate_source_function(function)))
        .flatten()
        .map(|function| CovenantDelegateBodyTarget {
            source_name: function.name.clone(),
            policy_function_name: generated_covenant_delegate_policy_name(&function.name),
        });

    let mut generated_function_names = HashSet::from([generated_covenant_policy_name(function_name)]);
    generated_function_names.insert(generated_entrypoint_name.clone());
    if let Some(delegate_entrypoint_name) = &delegate_entrypoint_name {
        generated_function_names.insert(delegate_entrypoint_name.clone());
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
        delegate_entrypoint_name,
        delegate_body,
        policy_function_name: generated_covenant_policy_name(function_name),
        generated_function_names,
    })
}

fn is_covenant_delegate_source_function(function: &FunctionAst<'_>) -> bool {
    function.attributes.iter().any(|attribute| {
        matches!(
            attribute.path.as_slice(),
            [head, tail] if head == "covenant" && tail == "delegate"
        )
    })
}

fn is_covenant_source_function(function: &FunctionAst<'_>) -> bool {
    function.attributes.iter().any(|attribute| {
        matches!(
            attribute.path.as_slice(),
            [head] if head == "covenant"
        ) || matches!(
            attribute.path.as_slice(),
            [head, tail] if head == "covenant" && (tail == "singleton" || tail == "fanout")
        )
    })
}

fn generated_covenant_policy_name(function_name: &str) -> String {
    format!("__covenant_policy_{function_name}")
}

fn generated_covenant_delegate_policy_name(function_name: &str) -> String {
    format!("__covenant_delegate_policy_{function_name}")
}
