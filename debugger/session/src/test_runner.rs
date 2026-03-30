use std::path::{Path, PathBuf};

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_txscript::covenants::CovenantsContext;
use serde::Deserialize;
use serde_json::Value;

use crate::args::parse_hex_bytes;

#[derive(Debug, Clone, Deserialize)]
pub struct ContractTestFile {
    pub tests: Vec<ContractTestCase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContractTestCase {
    pub name: String,
    pub function: String,
    #[serde(default)]
    pub delegate: bool,
    #[serde(default)]
    pub constructor_args: Vec<Value>,
    #[serde(default)]
    pub args: Option<Vec<Value>>,
    pub expect: TestExpectation,
    #[serde(default)]
    pub tx: Option<TestTxScenario>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestExpectation {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestTxScenario {
    #[serde(default = "default_tx_version")]
    pub version: u16,
    #[serde(default)]
    pub lock_time: u64,
    #[serde(default)]
    pub active_input_index: usize,
    pub inputs: Vec<TestTxInputScenario>,
    pub outputs: Vec<TestTxOutputScenario>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestTxInputScenario {
    #[serde(default)]
    pub prev_txid: Option<String>,
    #[serde(default)]
    pub prev_index: u32,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default = "default_sig_op_count")]
    pub sig_op_count: u8,
    #[serde(default)]
    pub utxo_value: u64,
    #[serde(default)]
    pub covenant_id: Option<Value>,
    #[serde(default)]
    pub constructor_args: Option<Vec<Value>>,
    #[serde(default)]
    pub state: Option<Value>,
    #[serde(default)]
    pub signature_script_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestTxOutputScenario {
    pub value: u64,
    #[serde(default)]
    pub covenant_id: Option<Value>,
    #[serde(default)]
    pub authorizing_input: Option<u16>,
    #[serde(default)]
    pub constructor_args: Option<Vec<Value>>,
    #[serde(default)]
    pub state: Option<Value>,
    #[serde(default)]
    pub script_hex: Option<String>,
    #[serde(default)]
    pub p2pk_pubkey: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedContractTest {
    pub script_path: PathBuf,
    pub test_file_path: PathBuf,
    pub test: ContractTestCaseResolved,
}

#[derive(Debug, Clone)]
pub struct ContractTestCaseResolved {
    pub name: String,
    pub function: String,
    pub delegate: bool,
    pub constructor_args: Vec<String>,
    pub args: Option<Vec<String>>,
    pub expect: TestExpectation,
    pub tx: Option<TestTxScenarioResolved>,
}

#[derive(Debug, Clone)]
pub struct TestTxScenarioResolved {
    pub version: u16,
    pub lock_time: u64,
    pub active_input_index: usize,
    pub inputs: Vec<TestTxInputScenarioResolved>,
    pub outputs: Vec<TestTxOutputScenarioResolved>,
}

#[derive(Debug, Clone)]
pub struct TestTxInputScenarioResolved {
    pub prev_txid: Option<String>,
    pub prev_index: u32,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub utxo_value: u64,
    pub covenant_id: Option<String>,
    pub constructor_args: Option<Vec<String>>,
    pub state: Option<String>,
    pub signature_script_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TestTxOutputScenarioResolved {
    pub value: u64,
    pub covenant_id: Option<String>,
    pub authorizing_input: Option<u16>,
    pub constructor_args: Option<Vec<String>>,
    pub state: Option<String>,
    pub script_hex: Option<String>,
    pub p2pk_pubkey: Option<String>,
}

fn default_tx_version() -> u16 {
    1
}

fn default_sig_op_count() -> u8 {
    100
}

pub fn discover_sidecar_path(script_path: &Path) -> Result<PathBuf, String> {
    let stem = script_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| format!("failed to derive stem from '{}'", script_path.display()))?;
    let sidecar_name = format!("{stem}.test.json");
    Ok(script_path.with_file_name(sidecar_name))
}

pub fn read_contract_test_file(test_file_path: &Path) -> Result<ContractTestFile, String> {
    let raw = std::fs::read_to_string(test_file_path)
        .map_err(|err| format!("failed to read test file '{}': {err}", test_file_path.display()))?;
    serde_json::from_str::<ContractTestFile>(&raw).map_err(|err| format!("invalid test file '{}': {err}", test_file_path.display()))
}

pub fn resolve_contract_test(
    test_file_path: &Path,
    test_name: &str,
    script_path_override: Option<&Path>,
) -> Result<ResolvedContractTest, String> {
    let script_path = if let Some(script_path) = script_path_override {
        std::fs::canonicalize(script_path)
            .map_err(|err| format!("failed to canonicalize script path '{}': {err}", script_path.display()))?
    } else {
        let inferred = infer_script_path_from_sidecar(test_file_path)?;
        std::fs::canonicalize(&inferred)
            .map_err(|err| format!("failed to canonicalize inferred script path '{}': {err}", inferred.display()))?
    };

    let canonical_test_file = std::fs::canonicalize(test_file_path)
        .map_err(|err| format!("failed to canonicalize test file '{}': {err}", test_file_path.display()))?;

    let parsed = read_contract_test_file(&canonical_test_file)?;
    let test = parsed
        .tests
        .into_iter()
        .find(|entry| entry.name == test_name)
        .ok_or_else(|| format!("test '{test_name}' not found in '{}'", canonical_test_file.display()))?;

    let resolved = ContractTestCaseResolved {
        name: test.name,
        function: test.function,
        delegate: test.delegate,
        constructor_args: values_to_args(&test.constructor_args)?,
        args: test.args.as_ref().map(|values| values_to_args(values)).transpose()?,
        expect: test.expect,
        tx: test.tx.map(resolve_tx_scenario).transpose()?,
    };

    Ok(ResolvedContractTest { script_path, test_file_path: canonical_test_file, test: resolved })
}

fn infer_script_path_from_sidecar(test_file_path: &Path) -> Result<PathBuf, String> {
    let file_name = test_file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid test file name '{}'", test_file_path.display()))?;

    let script_name = file_name
        .strip_suffix(".test.json")
        .ok_or_else(|| format!("test file '{}' must end with '.test.json'", test_file_path.display()))?;

    Ok(test_file_path.with_file_name(format!("{script_name}.sil")))
}

pub fn resolve_tx_scenario(tx: TestTxScenario) -> Result<TestTxScenarioResolved, String> {
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for input in tx.inputs {
        inputs.push(TestTxInputScenarioResolved {
            prev_txid: input.prev_txid,
            prev_index: input.prev_index,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            utxo_value: input.utxo_value,
            covenant_id: input.covenant_id.as_ref().map(value_to_arg).transpose()?,
            constructor_args: input.constructor_args.as_ref().map(|values| values_to_args(values)).transpose()?,
            state: input.state.as_ref().map(value_to_arg).transpose()?,
            signature_script_hex: input.signature_script_hex,
        });
    }

    let mut outputs = Vec::with_capacity(tx.outputs.len());
    for output in tx.outputs {
        outputs.push(TestTxOutputScenarioResolved {
            value: output.value,
            covenant_id: output.covenant_id.as_ref().map(value_to_arg).transpose()?,
            authorizing_input: output.authorizing_input,
            constructor_args: output.constructor_args.as_ref().map(|values| values_to_args(values)).transpose()?,
            state: output.state.as_ref().map(value_to_arg).transpose()?,
            script_hex: output.script_hex,
            p2pk_pubkey: output.p2pk_pubkey,
        });
    }

    Ok(TestTxScenarioResolved {
        version: tx.version,
        lock_time: tx.lock_time,
        active_input_index: tx.active_input_index,
        inputs,
        outputs,
    })
}

pub fn build_covenants_context_for_test_tx(tx: &TestTxScenarioResolved) -> Result<CovenantsContext, String> {
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()));
    }

    let inputs = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_bytes(u64_to_hash_bytes(index as u64)),
                index: input.prev_index,
            },
            signature_script: vec![],
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
        })
        .collect::<Vec<_>>();
    let outputs = tx
        .outputs
        .iter()
        .map(|output| {
            let covenant = output
                .covenant_id
                .as_deref()
                .map(|raw| {
                    Ok::<CovenantBinding, String>(CovenantBinding {
                        covenant_id: parse_test_hash32(raw)?,
                        authorizing_input: output.authorizing_input.unwrap_or(tx.active_input_index as u16),
                    })
                })
                .transpose()?;
            Ok(TransactionOutput {
                value: output.value,
                script_public_key: ScriptPublicKey::new(0, Vec::<u8>::new().into()),
                covenant,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let utxos = tx
        .inputs
        .iter()
        .map(|input| {
            let covenant_id = input.covenant_id.as_deref().map(parse_test_hash32).transpose()?;
            Ok(UtxoEntry::new(0, ScriptPublicKey::new(0, Vec::<u8>::new().into()), 0, false, covenant_id))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let tx = Transaction::new(tx.version, inputs, outputs, tx.lock_time, Default::default(), 0, vec![]);
    let populated_tx = PopulatedTransaction::new(&tx, utxos);
    CovenantsContext::from_tx(&populated_tx).map_err(|err| err.to_string())
}

pub fn values_to_args(values: &[Value]) -> Result<Vec<String>, String> {
    values.iter().map(value_to_arg).collect()
}

fn value_to_arg(value: &Value) -> Result<String, String> {
    match value {
        Value::String(raw) => Ok(raw.clone()),
        Value::Number(raw) => Ok(raw.to_string()),
        Value::Bool(raw) => Ok(raw.to_string()),
        Value::Null => Ok("null".to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).map_err(|err| format!("invalid arg value: {err}")),
    }
}

fn parse_test_hash32(raw: &str) -> Result<Hash, String> {
    if raw.starts_with("0x") || raw.starts_with("0X") {
        return Ok(Hash::from_bytes(parse_short_or_full_hex_32(raw, "hash")?));
    }

    if let Ok(value) = raw.parse::<u64>() {
        return Ok(Hash::from_bytes(u64_to_hash_bytes(value)));
    }

    Ok(Hash::from_bytes(parse_fixed_hex_32(raw, "hash")?))
}

fn parse_fixed_hex_32(raw: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() != 32 {
        return Err(format!("{name} expects 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn parse_short_or_full_hex_32(raw: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() > 32 {
        return Err(format!("{name} expects at most 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(array)
}

fn u64_to_hash_bytes(value: u64) -> [u8; 32] {
    let mut array = [0u8; 32];
    array[24..].copy_from_slice(&value.to_be_bytes());
    array
}
