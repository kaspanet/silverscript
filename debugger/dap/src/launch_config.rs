use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dap::requests::LaunchRequestArguments;
use debugger_session::args::values_to_args;
use debugger_session::test_runner::{TestTxScenario, TestTxScenarioResolved, resolve_tx_scenario};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchConfig {
    pub script_path: Option<String>,
    pub function: Option<String>,
    pub constructor_args: Option<ArgInput>,
    pub args: Option<ArgInput>,
    pub tx: Option<TestTxScenario>,
    pub no_debug: Option<bool>,
    pub stop_on_entry: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ResolvedLaunchConfig {
    pub script_path: PathBuf,
    pub function: Option<String>,
    pub constructor_args: Option<ArgInput>,
    pub args: Option<ArgInput>,
    pub tx: Option<TestTxScenarioResolved>,
    pub no_debug: bool,
    pub stop_on_entry: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ArgInput {
    Values(Vec<Value>),
    Named(BTreeMap<String, Value>),
}

impl LaunchConfig {
    pub fn from_launch_args(args: &LaunchRequestArguments) -> Result<Self, String> {
        let value = args.additional_data.clone().unwrap_or(Value::Null);
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self, String> {
        let config: Self = serde_json::from_value(value).map_err(|err| format!("invalid launch config: {err}"))?;

        if config.script_path.is_none() {
            return Err("launch config must include 'scriptPath'".to_string());
        }

        Ok(config)
    }

    pub fn resolve(self, workspace_root: Option<&Path>) -> Result<ResolvedLaunchConfig, String> {
        let script_path = self.resolve_script_path(workspace_root)?;
        let tx = self.tx.map(resolve_tx_scenario).transpose()?;

        Ok(ResolvedLaunchConfig {
            script_path,
            function: self.function,
            constructor_args: self.constructor_args,
            args: self.args,
            tx,
            no_debug: self.no_debug.unwrap_or(false),
            stop_on_entry: self.stop_on_entry.unwrap_or(!self.no_debug.unwrap_or(false)),
        })
    }

    fn resolve_script_path(&self, workspace_root: Option<&Path>) -> Result<PathBuf, String> {
        let raw = self.script_path.as_deref().ok_or_else(|| "scriptPath is required".to_string())?;
        canonicalize_with_workspace(raw, workspace_root)
    }
}

fn canonicalize_with_workspace(raw: &str, workspace_root: Option<&Path>) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(raw);
    let resolved = if candidate.is_absolute() {
        candidate
    } else if let Some(root) = workspace_root {
        root.join(candidate)
    } else {
        std::env::current_dir().map_err(|err| format!("failed to resolve current_dir: {err}"))?.join(candidate)
    };

    std::fs::canonicalize(&resolved).map_err(|err| format!("failed to canonicalize '{}': {err}", resolved.display()))
}

pub fn resolve_arg_input(input: Option<&ArgInput>, param_names: &[String], label: &str) -> Result<Vec<String>, String> {
    match input {
        None => Ok(Vec::new()),
        Some(ArgInput::Values(values)) => values_to_args(values),
        Some(ArgInput::Named(named)) => {
            let mut remaining = named.clone();
            let mut ordered = Vec::with_capacity(param_names.len());

            for name in param_names {
                let value = remaining.remove(name).ok_or_else(|| format!("{label} missing value for '{name}'"))?;
                ordered.push(value);
            }

            if !remaining.is_empty() {
                let extras = remaining.keys().cloned().collect::<Vec<_>>().join(", ");
                return Err(format!("{label} has unknown name(s): {extras}"));
            }

            values_to_args(&ordered)
        }
    }
}
