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
    pub params_file: Option<String>,
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParamsFileConfig {
    pub function: Option<String>,
    #[serde(default, alias = "constructor_args")]
    pub constructor_args: Option<ArgInput>,
    #[serde(default)]
    pub args: Option<ArgInput>,
    #[serde(default)]
    pub tx: Option<TestTxScenario>,
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
        let params_file = self.resolve_params_file(workspace_root, &script_path)?;

        let function = self.function.or(params_file.function);
        let constructor_args = self.constructor_args.or(params_file.constructor_args);
        let args = self.args.or(params_file.args);
        let tx = self.tx.or(params_file.tx).map(resolve_tx_scenario).transpose()?;

        Ok(ResolvedLaunchConfig {
            script_path,
            function,
            constructor_args,
            args,
            tx,
            no_debug: self.no_debug.unwrap_or(false),
            stop_on_entry: self.stop_on_entry.unwrap_or(!self.no_debug.unwrap_or(false)),
        })
    }

    fn resolve_script_path(&self, workspace_root: Option<&Path>) -> Result<PathBuf, String> {
        let raw = self.script_path.as_deref().ok_or_else(|| "scriptPath is required".to_string())?;
        canonicalize_with_workspace(raw, workspace_root)
    }

    fn resolve_params_file(&self, workspace_root: Option<&Path>, script_path: &Path) -> Result<ParamsFileConfig, String> {
        if let Some(raw) = self.params_file.as_deref() {
            let path = canonicalize_with_workspace(raw, workspace_root)?;
            return read_params_file(&path);
        }

        let inferred = infer_params_file_path(script_path)?;
        if inferred.exists() {
            return read_params_file(&inferred);
        }

        Ok(ParamsFileConfig::default())
    }
}

fn read_params_file(path: &Path) -> Result<ParamsFileConfig, String> {
    let raw = std::fs::read_to_string(path).map_err(|err| format!("failed to read params file '{}': {err}", path.display()))?;
    serde_json::from_str::<ParamsFileConfig>(&raw).map_err(|err| format!("invalid params file '{}': {err}", path.display()))
}

fn infer_params_file_path(script_path: &Path) -> Result<PathBuf, String> {
    let stem = script_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| format!("failed to derive stem from '{}'", script_path.display()))?;
    Ok(script_path.with_file_name(format!("{stem}.debug.json")))
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
