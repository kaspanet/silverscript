//! Portable ABI and codec data for generated Silverscript contracts.
//!
//! This crate owns only bytecode-facing facts: contract scripts, entrypoint
//! dispatch tags and parameters, runtime state field order, structural field types,
//! template state spans and hashes, and the codec for encoding those values.
//!
//! It must not know why a field exists. Argent coordination semantics such as
//! hidden template fields, route-family tables, route roots, observed actors,
//! witness purposes, and any future covenant-routing meaning belong in the
//! outer `argent-artifact` crate. Keep that boundary sharp so this ABI can be
//! replaced by a native Silverscript portable artifact later.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher as Blake3Hasher;
use kaspa_txscript::{
    EngineFlags, deserialize_i64 as deserialize_script_i64,
    opcodes::codes::{
        Op0 as OP_0, Op1 as OP_1, Op1Negate as OP_1_NEGATE, Op16 as OP_16, OpData1 as OP_DATA_1, OpData75 as OP_DATA_75,
        OpPushData1 as OP_PUSH_DATA_1, OpPushData2 as OP_PUSH_DATA_2, OpPushData4 as OP_PUSH_DATA_4,
    },
    script_builder::{ScriptBuilder, ScriptBuilderError},
    serialize_i64 as serialize_script_i64,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

mod json;

pub use json::to_pretty_json;

pub const SIL_ABI_SCHEMA_VERSION: u32 = 1;
const TEMPLATE_PART_LENGTH_BYTES: usize = 8;

/// A Sil entrypoint's fixed-width signature dispatch tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DispatchTag([u8; 4]);

impl DispatchTag {
    /// Borrow the four bytes placed in the entry signature script.
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Return the four bytes placed in the entry signature script.
    pub const fn into_bytes(self) -> [u8; 4] {
        self.0
    }

    /// Parse the eight-character representation stored in portable artifacts.
    pub fn from_hex(hex: &str) -> Result<Self, DispatchTagParseError> {
        if hex.len() != 8 {
            return Err(DispatchTagParseError::InvalidLength(hex.len()));
        }

        let mut bytes = [0; 4];
        faster_hex::hex_decode(hex.as_bytes(), &mut bytes).map_err(|err| DispatchTagParseError::InvalidHex(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Encode the tag using the portable artifact's lowercase hex form.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl From<[u8; 4]> for DispatchTag {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl Serialize for DispatchTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for DispatchTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        Self::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

/// An invalid portable dispatch-tag representation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DispatchTagParseError {
    #[error("dispatch tag must contain exactly 8 hexadecimal characters, found {0}")]
    InvalidLength(usize),
    #[error("invalid dispatch tag hex: {0}")]
    InvalidHex(String),
}

/// Calculate the canonical hash of a state-bearing Silverscript template.
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let prefix_len = i64::try_from(prefix.len()).unwrap();
    let suffix_len = i64::try_from(suffix.len()).unwrap();
    let encoded_prefix_len = serialize_script_i64(prefix_len, Some(TEMPLATE_PART_LENGTH_BYTES)).unwrap();
    let encoded_suffix_len = serialize_script_i64(suffix_len, Some(TEMPLATE_PART_LENGTH_BYTES)).unwrap();

    Blake3Hasher::new().update(&encoded_prefix_len).update(prefix).update(&encoded_suffix_len).update(suffix).finalize().into()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unsupported {artifact} schema version {found}; expected {supported}")]
pub struct ArtifactVersionError {
    pub artifact: &'static str,
    pub supported: u32,
    pub found: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructArtifact {
    pub fields: Vec<FieldArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeArtifact {
    Int,
    Temporal,
    Bool,
    Byte,
    Bytes,
    #[serde(rename = "string")]
    Text,
    Pubkey,
    Sig,
    Datasig,
    FixedBytes {
        len: usize,
    },
    FixedArray {
        item: Box<TypeArtifact>,
        len: usize,
    },
    DynamicArray {
        item: Box<TypeArtifact>,
    },
    Struct {
        name: String,
    },
}

impl TypeArtifact {
    pub fn from_parts(name: &str, array_len: Option<usize>) -> Self {
        match (name, array_len) {
            ("byte", Some(len)) => Self::FixedBytes { len },
            (_, Some(len)) => Self::FixedArray { item: Box::new(Self::scalar(name)), len },
            (_, None) => Self::scalar(name),
        }
    }

    pub fn dynamic_array(item: Self) -> Self {
        Self::DynamicArray { item: Box::new(item) }
    }

    fn scalar(name: &str) -> Self {
        match name {
            "int" => Self::Int,
            "temporal" => Self::Temporal,
            "bool" => Self::Bool,
            "byte" => Self::Byte,
            "bytes" => Self::Bytes,
            "string" => Self::Text,
            "pubkey" => Self::Pubkey,
            "sig" => Self::Sig,
            "datasig" => Self::Datasig,
            _ => Self::Struct { name: name.to_string() },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilAbiArtifact {
    pub schema_version: u32,
    pub compiler_version: String,
    pub structs: BTreeMap<String, StructArtifact>,
    pub contracts: BTreeMap<String, SilContractArtifact>,
}

impl SilAbiArtifact {
    pub fn check_schema_version(&self) -> std::result::Result<(), ArtifactVersionError> {
        if self.schema_version == SIL_ABI_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ArtifactVersionError { artifact: "Sil ABI artifact", supported: SIL_ABI_SCHEMA_VERSION, found: self.schema_version })
        }
    }

    /// Verify each compiled script, runtime-state span, and template hash.
    pub fn verify(&self) -> std::result::Result<(), SilAbiVerificationError> {
        self.check_schema_version()?;
        for (contract_name, contract) in &self.contracts {
            verify_compiled_contract(self, contract_name, contract)?;
        }
        Ok(())
    }

    pub fn contract(&self, name: &str) -> Option<&SilContractArtifact> {
        self.contracts.get(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilContractArtifact {
    pub source_path: String,
    pub runtime_state: RuntimeStateArtifact,
    pub entries: BTreeMap<String, SilEntryArtifact>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cov_decl_to_abi: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_entry_abi: Option<String>,
    pub compiled: CompiledContractArtifact,
}

impl SilContractArtifact {
    pub fn entry(&self, name: &str) -> Option<&SilEntryArtifact> {
        self.entries.get(name)
    }

    pub fn cov_binding_leader_decl_entry(&self, name: &str) -> Option<&SilEntryArtifact> {
        self.entries.get(self.cov_decl_to_abi.get(name)?)
    }

    pub fn auth_decl_entry(&self, name: &str) -> Option<&SilEntryArtifact> {
        self.entries.get(self.cov_decl_to_abi.get(name)?)
    }

    /// Resolve a source covenant declaration to its public entrypoint.
    pub fn covenant_decl_entry(&self, name: &str, is_leader: bool) -> Option<&SilEntryArtifact> {
        let leader = self.entries.get(self.cov_decl_to_abi.get(name)?)?;
        if is_leader || self.delegate_entry_abi.is_none() { Some(leader) } else { self.entries.get(self.delegate_entry_abi.as_ref()?) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateArtifact {
    pub source: String,
    pub fields: Vec<RuntimeFieldArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFieldArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilEntryArtifact {
    pub dispatch_tag: DispatchTag,
    pub params: Vec<ParamArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledContractArtifact {
    /// Compiled contract bytes.
    #[serde(with = "serde_bytes")]
    pub bytecode: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub template_hash: [u8; 32],
    pub state_span: StateSpanArtifact,
}

impl CompiledContractArtifact {
    /// Split decoded script bytes into the template prefix, runtime state, and
    /// template suffix declared by this artifact.
    pub fn script_parts<'a>(&self, script: &'a [u8]) -> Option<(&'a [u8], &'a [u8], &'a [u8])> {
        let state_end = self.state_span.offset.checked_add(self.state_span.len)?;
        Some((script.get(..self.state_span.offset)?, script.get(self.state_span.offset..state_end)?, script.get(state_end..)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledTemplateArtifact {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSpanArtifact {
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SilAbiVerificationError {
    #[error(transparent)]
    Version(#[from] ArtifactVersionError),
    #[error("contract `{contract}` has state span offset {offset} length {len}, but its compiled script has {script_len} bytes")]
    InvalidStateSpan { contract: String, offset: usize, len: usize, script_len: usize },
    #[error("contract `{contract}` runtime state field `{field}` has unsupported type `{ty}`")]
    UnsupportedRuntimeStateType { contract: String, field: String, ty: String },
    #[error("contract `{contract}` state span does not encode its runtime state: {message}")]
    InvalidRuntimeStateEncoding { contract: String, message: String },
    #[error("contract `{contract}` state span is not canonically encoded")]
    NonCanonicalRuntimeStateEncoding { contract: String },
    #[error("contract `{contract}` template hash mismatch: expected `{expected}`, found `{found}`")]
    TemplateHashMismatch { contract: String, expected: String, found: String },
    #[error("contract `{contract}` entries `{first}` and `{second}` have the same dispatch tag `{tag}`")]
    DispatchTagCollision { contract: String, first: String, second: String, tag: String },
    #[error("contract `{contract}` metadata references unknown entry `{entry}`")]
    UnknownEntryReference { contract: String, entry: String },
}

pub type CodecResult<T> = std::result::Result<T, CodecError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ArtifactValue {
    Int(i64),
    Bool(bool),
    Byte(u8),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<ArtifactValue>),
    Object(BTreeMap<String, ArtifactValue>),
}

impl From<i64> for ArtifactValue {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<i32> for ArtifactValue {
    fn from(value: i32) -> Self {
        Self::Int(i64::from(value))
    }
}

impl From<bool> for ArtifactValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u8> for ArtifactValue {
    fn from(value: u8) -> Self {
        Self::Byte(value)
    }
}

impl From<Vec<u8>> for ArtifactValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<Vec<i64>> for ArtifactValue {
    fn from(value: Vec<i64>) -> Self {
        Self::Array(value.into_iter().map(Self::Int).collect())
    }
}

impl From<String> for ArtifactValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for ArtifactValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

impl From<Vec<ArtifactValue>> for ArtifactValue {
    fn from(value: Vec<ArtifactValue>) -> Self {
        Self::Array(value)
    }
}

impl From<BTreeMap<String, ArtifactValue>> for ArtifactValue {
    fn from(value: BTreeMap<String, ArtifactValue>) -> Self {
        Self::Object(value)
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum CodecError {
    #[error("unknown contract `{0}`")]
    UnknownContract(String),
    #[error("unknown entry `{contract}::{entry}`")]
    UnknownEntry { contract: String, entry: String },
    #[error("unknown struct `{0}`")]
    UnknownStruct(String),
    #[error("entry `{entry}` expects {expected} arguments, got {actual}")]
    WrongArgumentCount { entry: String, expected: usize, actual: usize },
    #[error("missing field `{0}`")]
    MissingField(String),
    #[error("unknown field `{0}`")]
    UnknownField(String),
    #[error("duplicate field `{0}`")]
    DuplicateField(String),
    #[error("expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },
    #[error("unsupported artifact type `{0}`")]
    UnsupportedType(String),
    #[error("`{name}` expects {expected} bytes, got {actual}")]
    InvalidLength { name: String, expected: usize, actual: usize },
    #[error("number {value} does not fit in {size} bytes")]
    InvalidNumber { value: i64, size: usize },
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] faster_hex::Error),
    #[error("script builder error: {0}")]
    ScriptBuilder(#[from] ScriptBuilderError),
    #[error("invalid push-only script: {0}")]
    InvalidPush(String),
    #[error("state script has {len} trailing bytes at offset {offset}")]
    TrailingStateBytes { offset: usize, len: usize },
}

pub fn encode_contract_entry_sig_script(
    abi: &SilAbiArtifact,
    contract_name: &str,
    entry_name: &str,
    args: &[ArtifactValue],
) -> CodecResult<Vec<u8>> {
    let contract = abi.contracts.get(contract_name).ok_or_else(|| CodecError::UnknownContract(contract_name.to_string()))?;
    let entry = contract
        .entries
        .get(entry_name)
        .ok_or_else(|| CodecError::UnknownEntry { contract: contract_name.to_string(), entry: entry_name.to_string() })?;
    encode_entry_sig_script(abi, contract_name, contract, entry_name, entry, args)
}

pub fn encode_contract_covenant_decl_sig_script(
    abi: &SilAbiArtifact,
    contract_name: &str,
    declaration_name: &str,
    is_leader: bool,
    args: &[ArtifactValue],
) -> CodecResult<Vec<u8>> {
    let contract = abi.contracts.get(contract_name).ok_or_else(|| CodecError::UnknownContract(contract_name.to_string()))?;
    let entry_name = if is_leader || contract.delegate_entry_abi.is_none() {
        contract.cov_decl_to_abi.get(declaration_name)
    } else {
        contract.delegate_entry_abi.as_ref()
    }
    .ok_or_else(|| CodecError::UnknownEntry { contract: contract_name.to_string(), entry: declaration_name.to_string() })?;
    let entry = contract
        .entries
        .get(entry_name)
        .ok_or_else(|| CodecError::UnknownEntry { contract: contract_name.to_string(), entry: declaration_name.to_string() })?;
    encode_entry_sig_script(abi, contract_name, contract, entry_name, entry, args)
}

pub fn encode_entry_sig_script(
    abi: &SilAbiArtifact,
    contract_name: &str,
    contract: &SilContractArtifact,
    entry_name: &str,
    entry: &SilEntryArtifact,
    args: &[ArtifactValue],
) -> CodecResult<Vec<u8>> {
    let params = entry_params(entry);
    if params.len() != args.len() {
        return Err(CodecError::WrongArgumentCount {
            entry: format!("{contract_name}::{entry_name}"),
            expected: params.len(),
            actual: args.len(),
        });
    }

    let ctx = TypeContext::new(abi, contract);
    let mut builder = script_builder();
    for ((name, ty), value) in params.iter().zip(args) {
        push_sig_arg(&mut builder, &ctx, name, ty, value)?;
    }
    builder.add_data(entry.dispatch_tag.as_bytes())?;
    Ok(builder.drain())
}

pub fn encode_runtime_state_script(
    abi: &SilAbiArtifact,
    runtime_state: &RuntimeStateArtifact,
    values: &BTreeMap<String, ArtifactValue>,
) -> CodecResult<Vec<u8>> {
    for name in values.keys() {
        if runtime_state.fields.iter().all(|field| &field.name != name) {
            return Err(CodecError::UnknownField(name.clone()));
        }
    }

    let mut builder = script_builder();
    for field in &runtime_state.fields {
        let value = values.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
        for (leaf_ty, leaf_value) in flatten_sruct_value(abi, &field.name, &field.ty, value)? {
            let payload = encode_state_payload(&field.name, &leaf_ty, &leaf_value)?;
            builder.add_data_with_push_opcode(&payload)?;
        }
    }
    Ok(builder.drain())
}

pub fn decode_runtime_state_script(
    abi: &SilAbiArtifact,
    runtime_state: &RuntimeStateArtifact,
    state_script: &[u8],
) -> CodecResult<BTreeMap<String, ArtifactValue>> {
    let pushes = parse_pushes(state_script)?;
    let field_leaf_types =
        runtime_state.fields.iter().map(|field| flatten_struct_types(abi, &field.ty)).collect::<CodecResult<Vec<_>>>()?;
    let expected_pushes = field_leaf_types.iter().map(Vec::len).sum::<usize>();
    if pushes.len() < expected_pushes {
        return Err(CodecError::InvalidPush(format!("expected {expected_pushes} state pushes, got {}", pushes.len())));
    }
    if pushes.len() > expected_pushes {
        let offset = pushes[expected_pushes].0;
        return Err(CodecError::TrailingStateBytes { offset, len: state_script.len() - offset });
    }

    let mut values = BTreeMap::new();
    let mut pushes = pushes.into_iter();
    for (field, leaf_types) in runtime_state.fields.iter().zip(field_leaf_types) {
        let leaf_values = leaf_types
            .iter()
            .map(|leaf_ty| {
                let (_, payload) = pushes.next().expect("state push count was checked");
                decode_state_payload(&field.name, leaf_ty, &payload)
            })
            .collect::<CodecResult<Vec<_>>>()?;
        let (value, consumed) = reconstruct_struct_value(abi, &field.name, &field.ty, &leaf_values)?;
        if consumed != leaf_values.len() {
            return Err(CodecError::UnsupportedType(format!("invalid flattened state layout for {}", field.name)));
        }
        values.insert(field.name.clone(), value);
    }
    Ok(values)
}

fn flatten_struct_types(abi: &SilAbiArtifact, ty: &TypeArtifact) -> CodecResult<Vec<TypeArtifact>> {
    fn flatten(abi: &SilAbiArtifact, ty: &TypeArtifact, visiting: &mut BTreeSet<String>) -> CodecResult<Vec<TypeArtifact>> {
        match ty {
            TypeArtifact::Struct { name } => {
                if !visiting.insert(name.clone()) {
                    return Err(CodecError::UnsupportedType(format!("cyclic struct {name}")));
                }
                let structure = abi.structs.get(name).ok_or_else(|| CodecError::UnknownStruct(name.clone()))?;
                let mut leaves = Vec::new();
                for field in &structure.fields {
                    leaves.extend(flatten(abi, &field.ty, visiting)?);
                }
                visiting.remove(name);
                Ok(leaves)
            }
            TypeArtifact::FixedArray { item, len } => {
                let item_leaves = flatten(abi, item, visiting)?;
                if is_single_state_leaf(item, &item_leaves) {
                    Ok(vec![ty.clone()])
                } else {
                    Ok(item_leaves.into_iter().map(|item| array_type(item, Some(*len))).collect())
                }
            }
            TypeArtifact::DynamicArray { item } => {
                let item_leaves = flatten(abi, item, visiting)?;
                if is_single_state_leaf(item, &item_leaves) {
                    Ok(vec![ty.clone()])
                } else {
                    Ok(item_leaves.into_iter().map(|item| array_type(item, None)).collect())
                }
            }
            _ => Ok(vec![ty.clone()]),
        }
    }

    flatten(abi, ty, &mut BTreeSet::new())
}

fn flatten_sruct_value(
    abi: &SilAbiArtifact,
    name: &str,
    ty: &TypeArtifact,
    value: &ArtifactValue,
) -> CodecResult<Vec<(TypeArtifact, ArtifactValue)>> {
    fn flatten(
        abi: &SilAbiArtifact,
        name: &str,
        ty: &TypeArtifact,
        value: &ArtifactValue,
        visiting: &mut BTreeSet<String>,
    ) -> CodecResult<Vec<(TypeArtifact, ArtifactValue)>> {
        match ty {
            TypeArtifact::Struct { name: struct_name } => {
                if !visiting.insert(struct_name.clone()) {
                    return Err(CodecError::UnsupportedType(format!("cyclic struct {struct_name}")));
                }
                let structure = abi.structs.get(struct_name).ok_or_else(|| CodecError::UnknownStruct(struct_name.clone()))?;
                let fields = object_fields(value)?;
                assert_no_extra_fields(fields, &structure.fields)?;
                let mut leaves = Vec::new();
                for field in &structure.fields {
                    let field_value = fields.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
                    leaves.extend(flatten(abi, &field.name, &field.ty, field_value, visiting)?);
                }
                visiting.remove(struct_name);
                Ok(leaves)
            }
            TypeArtifact::FixedArray { item, len } => flatten_struct_array(abi, name, item, Some(*len), value, visiting),
            TypeArtifact::DynamicArray { item } => flatten_struct_array(abi, name, item, None, value, visiting),
            _ => Ok(vec![(ty.clone(), value.clone())]),
        }
    }

    fn flatten_struct_array(
        abi: &SilAbiArtifact,
        name: &str,
        item: &TypeArtifact,
        fixed_len: Option<usize>,
        value: &ArtifactValue,
        visiting: &mut BTreeSet<String>,
    ) -> CodecResult<Vec<(TypeArtifact, ArtifactValue)>> {
        let item_leaf_types = flatten_struct_types(abi, item)?;
        if is_single_state_leaf(item, &item_leaf_types) {
            return Ok(vec![(array_type(item.clone(), fixed_len), value.clone())]);
        }

        let values = expect_array(value)?;
        if let Some(expected) = fixed_len {
            require_len(name, expected, values.len())?;
        }
        let grouped_values = group_flattened_array_items(abi, name, item, values, &item_leaf_types, visiting)?;

        Ok(item_leaf_types
            .into_iter()
            .zip(grouped_values)
            .map(|(item, values)| (array_type(item, fixed_len), ArtifactValue::Array(values)))
            .collect())
    }

    fn group_flattened_array_items(
        abi: &SilAbiArtifact,
        name: &str,
        item: &TypeArtifact,
        values: &[ArtifactValue],
        item_leaf_types: &[TypeArtifact],
        visiting: &mut BTreeSet<String>,
    ) -> CodecResult<Vec<Vec<ArtifactValue>>> {
        let mut grouped_values = vec![Vec::with_capacity(values.len()); item_leaf_types.len()];
        for value in values {
            let item_leaves = flatten(abi, name, item, value, visiting)?;
            if item_leaves.len() != item_leaf_types.len() {
                return Err(invalid_flattened_state_layout(name));
            }
            for ((expected_ty, group), (actual_ty, value)) in item_leaf_types.iter().zip(&mut grouped_values).zip(item_leaves) {
                if expected_ty != &actual_ty {
                    return Err(invalid_flattened_state_layout(name));
                }
                group.push(value);
            }
        }
        Ok(grouped_values)
    }

    flatten(abi, name, ty, value, &mut BTreeSet::new())
}

fn is_single_state_leaf(item: &TypeArtifact, item_leaf_types: &[TypeArtifact]) -> bool {
    item_leaf_types == std::slice::from_ref(item)
}

fn array_type(item: TypeArtifact, fixed_len: Option<usize>) -> TypeArtifact {
    match fixed_len {
        Some(len) => TypeArtifact::FixedArray { item: Box::new(item), len },
        None => TypeArtifact::DynamicArray { item: Box::new(item) },
    }
}

fn invalid_flattened_state_layout(name: &str) -> CodecError {
    CodecError::UnsupportedType(format!("invalid flattened state layout for {name}"))
}

fn reconstruct_struct_value(
    abi: &SilAbiArtifact,
    name: &str,
    ty: &TypeArtifact,
    leaves: &[ArtifactValue],
) -> CodecResult<(ArtifactValue, usize)> {
    match ty {
        TypeArtifact::Struct { name: struct_name } => {
            let structure = abi.structs.get(struct_name).ok_or_else(|| CodecError::UnknownStruct(struct_name.clone()))?;
            let mut fields = BTreeMap::new();
            let mut consumed = 0;
            for field in &structure.fields {
                let (value, field_consumed) = reconstruct_struct_value(abi, &field.name, &field.ty, &leaves[consumed..])?;
                consumed += field_consumed;
                fields.insert(field.name.clone(), value);
            }
            Ok((ArtifactValue::Object(fields), consumed))
        }
        TypeArtifact::FixedArray { item, len } => reconstruct_struct_array(abi, name, item, Some(*len), leaves),
        TypeArtifact::DynamicArray { item } => reconstruct_struct_array(abi, name, item, None, leaves),
        _ => leaves
            .first()
            .cloned()
            .map(|value| (value, 1))
            .ok_or_else(|| CodecError::InvalidPush(format!("missing flattened state value for {name}"))),
    }
}

fn reconstruct_struct_array(
    abi: &SilAbiArtifact,
    name: &str,
    item: &TypeArtifact,
    expected_len: Option<usize>,
    leaves: &[ArtifactValue],
) -> CodecResult<(ArtifactValue, usize)> {
    let item_leaf_types = flatten_struct_types(abi, item)?;
    if item_leaf_types.as_slice() == std::slice::from_ref(item) {
        return leaves
            .first()
            .cloned()
            .map(|value| (value, 1))
            .ok_or_else(|| CodecError::InvalidPush(format!("missing flattened state value for {name}")));
    }
    if item_leaf_types.is_empty() {
        return Err(CodecError::UnsupportedType(format!("zero-field struct array {name}")));
    }

    let leaf_values = leaves
        .get(..item_leaf_types.len())
        .ok_or_else(|| CodecError::InvalidPush(format!("missing flattened state values for {name}")))?;
    let arrays = leaf_values.iter().map(expect_array).collect::<CodecResult<Vec<_>>>()?;
    let actual_len = arrays[0].len();
    if let Some(expected) = expected_len {
        require_len(name, expected, actual_len)?;
    }
    for array in &arrays[1..] {
        require_len(name, actual_len, array.len())?;
    }

    let mut values = Vec::with_capacity(actual_len);
    for index in 0..actual_len {
        let item_leaves = arrays.iter().map(|array| array[index].clone()).collect::<Vec<_>>();
        let (value, consumed) = reconstruct_struct_value(abi, name, item, &item_leaves)?;
        if consumed != item_leaves.len() {
            return Err(CodecError::UnsupportedType(format!("invalid flattened state layout for {name}")));
        }
        values.push(value);
    }
    Ok((ArtifactValue::Array(values), item_leaf_types.len()))
}

pub fn encode_struct_payload(
    abi: &SilAbiArtifact,
    contract: &SilContractArtifact,
    struct_name: &str,
    values: &BTreeMap<String, ArtifactValue>,
) -> CodecResult<Vec<u8>> {
    let ctx = TypeContext::new(abi, contract);
    encode_struct_fields_payload(ctx.struct_by_name(struct_name)?, values)
}

pub fn decode_hex(hex: &str) -> CodecResult<Vec<u8>> {
    let mut bytes = vec![0; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes)?;
    Ok(bytes)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = vec![0; bytes.len() * 2];
    faster_hex::hex_encode(bytes, &mut out).expect("hex output buffer is exactly twice the input length");
    String::from_utf8(out).expect("hex is always valid ascii")
}

fn verify_compiled_contract(
    abi: &SilAbiArtifact,
    contract_name: &str,
    contract: &SilContractArtifact,
) -> std::result::Result<(), SilAbiVerificationError> {
    let script = &contract.compiled.bytecode;

    for entry_name in contract.cov_decl_to_abi.values().chain(contract.delegate_entry_abi.iter()) {
        if !contract.entries.contains_key(entry_name) {
            return Err(SilAbiVerificationError::UnknownEntryReference {
                contract: contract_name.to_string(),
                entry: entry_name.clone(),
            });
        }
    }

    let mut entries_by_tag = BTreeMap::<DispatchTag, &str>::new();
    for (entry_name, entry) in &contract.entries {
        let tag = entry.dispatch_tag;
        if let Some(first) = entries_by_tag.insert(tag, entry_name) {
            return Err(SilAbiVerificationError::DispatchTagCollision {
                contract: contract_name.to_string(),
                first: first.to_string(),
                second: entry_name.clone(),
                tag: tag.to_hex(),
            });
        }
    }

    let span = &contract.compiled.state_span;
    let Some((prefix, state_script, suffix)) = contract.compiled.script_parts(script) else {
        return Err(SilAbiVerificationError::InvalidStateSpan {
            contract: contract_name.to_string(),
            offset: span.offset,
            len: span.len,
            script_len: script.len(),
        });
    };
    for field in &contract.runtime_state.fields {
        if !is_supported_runtime_state_type(abi, &field.ty) {
            return Err(SilAbiVerificationError::UnsupportedRuntimeStateType {
                contract: contract_name.to_string(),
                field: field.name.clone(),
                ty: type_name(&field.ty),
            });
        }
    }
    let state_values = decode_runtime_state_script(abi, &contract.runtime_state, state_script).map_err(|err| {
        SilAbiVerificationError::InvalidRuntimeStateEncoding { contract: contract_name.to_string(), message: err.to_string() }
    })?;
    let canonical_state = encode_runtime_state_script(abi, &contract.runtime_state, &state_values).map_err(|err| {
        SilAbiVerificationError::InvalidRuntimeStateEncoding { contract: contract_name.to_string(), message: err.to_string() }
    })?;
    if canonical_state != state_script {
        return Err(SilAbiVerificationError::NonCanonicalRuntimeStateEncoding { contract: contract_name.to_string() });
    }
    let expected_hash = template_hash(prefix, suffix);
    if contract.compiled.template_hash != expected_hash {
        return Err(SilAbiVerificationError::TemplateHashMismatch {
            contract: contract_name.to_string(),
            expected: encode_hex(&expected_hash),
            found: encode_hex(&contract.compiled.template_hash),
        });
    }
    Ok(())
}

fn is_supported_runtime_state_type(abi: &SilAbiArtifact, ty: &TypeArtifact) -> bool {
    fn is_supported(abi: &SilAbiArtifact, ty: &TypeArtifact, visiting: &mut BTreeSet<String>) -> bool {
        match ty {
            TypeArtifact::Struct { name } => {
                if !visiting.insert(name.clone()) {
                    // We don't support cyclic structs.
                    return false;
                }
                let supported = abi
                    .structs
                    .get(name)
                    .is_some_and(|structure| structure.fields.iter().all(|field| is_supported(abi, &field.ty, visiting)));
                visiting.remove(name);
                supported
            }
            TypeArtifact::FixedArray { item, .. } => is_supported(abi, item, visiting),
            _ => fixed_payload_len(ty).is_some(),
        }
    }

    is_supported(abi, ty, &mut BTreeSet::new())
}

fn entry_params(entry: &SilEntryArtifact) -> Vec<(&str, &TypeArtifact)> {
    entry.params.iter().map(|param| (param.name.as_str(), &param.ty)).collect()
}

struct TypeContext<'a> {
    structs: &'a BTreeMap<String, StructArtifact>,
    runtime_state: StructArtifact,
}

impl<'a> TypeContext<'a> {
    fn new(abi: &'a SilAbiArtifact, contract: &'a SilContractArtifact) -> Self {
        Self {
            structs: &abi.structs,
            runtime_state: StructArtifact {
                fields: contract
                    .runtime_state
                    .fields
                    .iter()
                    .map(|field| FieldArtifact { name: field.name.clone(), ty: field.ty.clone() })
                    .collect(),
            },
        }
    }

    fn struct_by_name(&self, name: &str) -> CodecResult<&StructArtifact> {
        if name == "State" {
            return Ok(&self.runtime_state);
        }
        self.structs.get(name).ok_or_else(|| CodecError::UnknownStruct(name.to_string()))
    }
}

fn script_builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

fn push_sig_arg(
    builder: &mut ScriptBuilder,
    ctx: &TypeContext<'_>,
    name: &str,
    ty: &TypeArtifact,
    value: &ArtifactValue,
) -> CodecResult<()> {
    match ty {
        TypeArtifact::Struct { name: struct_name } => {
            let fields = object_fields(value)?;
            push_struct_fields(builder, ctx, ctx.struct_by_name(struct_name)?, fields)
        }
        TypeArtifact::FixedArray { item, len } if matches!(item.as_ref(), TypeArtifact::Struct { .. }) => {
            push_struct_array_fields(builder, ctx, item, Some(*len), value)
        }
        TypeArtifact::DynamicArray { item } if matches!(item.as_ref(), TypeArtifact::Struct { .. }) => {
            push_struct_array_fields(builder, ctx, item, None, value)
        }
        TypeArtifact::Int | TypeArtifact::Temporal => push_i64(builder, expect_int(value)?),
        TypeArtifact::Bool => push_i64(builder, i64::from(expect_bool(value)?)),
        TypeArtifact::Byte => {
            push_data(builder, &[expect_byte(value)?])?;
            Ok(())
        }
        TypeArtifact::Bytes => {
            push_data(builder, expect_bytes(value)?)?;
            Ok(())
        }
        TypeArtifact::Text => {
            push_data(builder, expect_text(value)?.as_bytes())?;
            Ok(())
        }
        TypeArtifact::Pubkey => push_fixed_bytes(builder, name, value, 32),
        TypeArtifact::Sig => push_fixed_bytes(builder, name, value, 65),
        TypeArtifact::Datasig => push_fixed_bytes(builder, name, value, 64),
        TypeArtifact::FixedBytes { len } => push_fixed_bytes(builder, name, value, *len),
        TypeArtifact::FixedArray { item, len } => {
            let payload = encode_array_payload(name, item, Some(*len), value)?;
            push_data(builder, &payload)?;
            Ok(())
        }
        TypeArtifact::DynamicArray { item } => {
            let payload = encode_array_payload(name, item, None, value)?;
            push_data(builder, &payload)?;
            Ok(())
        }
    }
}

fn push_struct_fields(
    builder: &mut ScriptBuilder,
    ctx: &TypeContext<'_>,
    structure: &StructArtifact,
    fields: &BTreeMap<String, ArtifactValue>,
) -> CodecResult<()> {
    assert_no_extra_fields(fields, &structure.fields)?;
    for field in &structure.fields {
        let value = fields.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
        push_sig_arg(builder, ctx, &field.name, &field.ty, value)?;
    }
    Ok(())
}

fn push_struct_array_fields(
    builder: &mut ScriptBuilder,
    ctx: &TypeContext<'_>,
    item: &TypeArtifact,
    expected_len: Option<usize>,
    value: &ArtifactValue,
) -> CodecResult<()> {
    let TypeArtifact::Struct { name } = item else {
        return Err(CodecError::UnsupportedType(type_name(item)));
    };
    let structure = ctx.struct_by_name(name)?;
    let values = expect_array(value)?;
    if let Some(expected) = expected_len {
        require_len(name, expected, values.len())?;
    }

    let mut object_values = Vec::with_capacity(values.len());
    for value in values {
        let fields = object_fields(value)?;
        assert_no_extra_fields(fields, &structure.fields)?;
        object_values.push(fields);
    }

    for field in &structure.fields {
        let mut field_values = Vec::with_capacity(object_values.len());
        for object in &object_values {
            field_values.push(object.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?.clone());
        }
        push_sig_arg(
            builder,
            ctx,
            &field.name,
            &TypeArtifact::DynamicArray { item: Box::new(field.ty.clone()) },
            &ArtifactValue::Array(field_values),
        )?;
    }
    Ok(())
}

fn encode_state_payload(name: &str, ty: &TypeArtifact, value: &ArtifactValue) -> CodecResult<Vec<u8>> {
    match ty {
        TypeArtifact::Bytes => Ok(expect_bytes(value)?.to_vec()),
        TypeArtifact::Text => Ok(expect_text(value)?.as_bytes().to_vec()),
        TypeArtifact::DynamicArray { item } => encode_array_payload(name, item, None, value),
        _ => encode_fixed_payload(name, ty, value),
    }
}

fn encode_struct_fields_payload(structure: &StructArtifact, fields: &BTreeMap<String, ArtifactValue>) -> CodecResult<Vec<u8>> {
    assert_no_extra_fields(fields, &structure.fields)?;
    let mut out = Vec::new();
    for field in &structure.fields {
        let value = fields.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
        out.extend(encode_state_payload(&field.name, &field.ty, value)?);
    }
    Ok(out)
}

fn decode_state_payload(name: &str, ty: &TypeArtifact, payload: &[u8]) -> CodecResult<ArtifactValue> {
    match ty {
        TypeArtifact::Int | TypeArtifact::Temporal => {
            require_len(name, 8, payload.len())?;
            Ok(ArtifactValue::Int(deserialize_fixed_i64(payload)?))
        }
        TypeArtifact::Bool => {
            require_len(name, 1, payload.len())?;
            match payload[0] {
                0 => Ok(ArtifactValue::Bool(false)),
                1 => Ok(ArtifactValue::Bool(true)),
                value => Err(CodecError::TypeMismatch { expected: "bool byte 0 or 1".to_string(), actual: value.to_string() }),
            }
        }
        TypeArtifact::Byte => {
            require_len(name, 1, payload.len())?;
            Ok(ArtifactValue::Byte(payload[0]))
        }
        TypeArtifact::Bytes => Ok(ArtifactValue::Bytes(payload.to_vec())),
        TypeArtifact::Text => String::from_utf8(payload.to_vec())
            .map(ArtifactValue::Text)
            .map_err(|err| CodecError::TypeMismatch { expected: "utf-8 string".to_string(), actual: err.to_string() }),
        TypeArtifact::Pubkey => decode_fixed_bytes(name, payload, 32),
        TypeArtifact::Sig => decode_fixed_bytes(name, payload, 65),
        TypeArtifact::Datasig => decode_fixed_bytes(name, payload, 64),
        TypeArtifact::FixedBytes { len } => decode_fixed_bytes(name, payload, *len),
        TypeArtifact::FixedArray { item, len } => decode_array_payload(name, item, Some(*len), payload),
        TypeArtifact::DynamicArray { item } => decode_array_payload(name, item, None, payload),
        TypeArtifact::Struct { name } => Err(CodecError::UnsupportedType(format!("state struct {name}"))),
    }
}

fn decode_fixed_bytes(name: &str, payload: &[u8], expected: usize) -> CodecResult<ArtifactValue> {
    require_len(name, expected, payload.len())?;
    Ok(ArtifactValue::Bytes(payload.to_vec()))
}

fn decode_array_payload(name: &str, item: &TypeArtifact, expected_len: Option<usize>, payload: &[u8]) -> CodecResult<ArtifactValue> {
    let item_len = fixed_payload_len(item).ok_or_else(|| CodecError::UnsupportedType(type_name(item)))?;
    if item_len == 0 || !payload.len().is_multiple_of(item_len) {
        return Err(CodecError::InvalidLength { name: name.to_string(), expected: item_len, actual: payload.len() });
    }
    let actual_len = payload.len() / item_len;
    if let Some(expected) = expected_len {
        require_len(name, expected, actual_len)?;
    }
    payload
        .chunks_exact(item_len)
        .map(|chunk| decode_state_payload(name, item, chunk))
        .collect::<CodecResult<Vec<_>>>()
        .map(ArtifactValue::Array)
}

fn encode_array_payload(name: &str, item: &TypeArtifact, expected_len: Option<usize>, value: &ArtifactValue) -> CodecResult<Vec<u8>> {
    if matches!(item, TypeArtifact::Struct { .. }) {
        return Err(CodecError::UnsupportedType(type_name(item)));
    }
    let values = expect_array(value)?;
    if let Some(expected) = expected_len {
        require_len(name, expected, values.len())?;
    }
    let mut out = Vec::new();
    for value in values {
        out.extend(encode_fixed_payload(name, item, value)?);
    }
    Ok(out)
}

fn encode_fixed_payload(name: &str, ty: &TypeArtifact, value: &ArtifactValue) -> CodecResult<Vec<u8>> {
    match ty {
        TypeArtifact::Int | TypeArtifact::Temporal => serialize_fixed_i64(expect_int(value)?, 8),
        TypeArtifact::Bool => Ok(vec![u8::from(expect_bool(value)?)]),
        TypeArtifact::Byte => Ok(vec![expect_byte(value)?]),
        TypeArtifact::Pubkey => fixed_bytes(name, value, 32),
        TypeArtifact::Sig => fixed_bytes(name, value, 65),
        TypeArtifact::Datasig => fixed_bytes(name, value, 64),
        TypeArtifact::FixedBytes { len } => fixed_bytes(name, value, *len),
        TypeArtifact::FixedArray { item, len } => encode_array_payload(name, item, Some(*len), value),
        TypeArtifact::Bytes | TypeArtifact::Text | TypeArtifact::DynamicArray { .. } | TypeArtifact::Struct { .. } => {
            Err(CodecError::UnsupportedType(type_name(ty)))
        }
    }
}

fn fixed_payload_len(ty: &TypeArtifact) -> Option<usize> {
    match ty {
        TypeArtifact::Int | TypeArtifact::Temporal => Some(8),
        TypeArtifact::Bool => Some(1),
        TypeArtifact::Byte => Some(1),
        TypeArtifact::Pubkey => Some(32),
        TypeArtifact::Sig => Some(65),
        TypeArtifact::Datasig => Some(64),
        TypeArtifact::FixedBytes { len } => Some(*len),
        TypeArtifact::FixedArray { item, len } => fixed_payload_len(item).and_then(|item_len| item_len.checked_mul(*len)),
        TypeArtifact::Bytes | TypeArtifact::Text | TypeArtifact::DynamicArray { .. } | TypeArtifact::Struct { .. } => None,
    }
}

fn push_fixed_bytes(builder: &mut ScriptBuilder, name: &str, value: &ArtifactValue, expected: usize) -> CodecResult<()> {
    let bytes = fixed_bytes(name, value, expected)?;
    push_data(builder, &bytes)?;
    Ok(())
}

fn fixed_bytes(name: &str, value: &ArtifactValue, expected: usize) -> CodecResult<Vec<u8>> {
    let bytes = expect_bytes(value)?;
    require_len(name, expected, bytes.len())?;
    Ok(bytes.to_vec())
}

fn push_i64(builder: &mut ScriptBuilder, value: i64) -> CodecResult<()> {
    if value == i64::MIN {
        return Err(CodecError::InvalidNumber { value, size: 8 });
    }
    builder.add_i64(value)?;
    Ok(())
}

fn push_data(builder: &mut ScriptBuilder, data: &[u8]) -> CodecResult<()> {
    builder.add_data(data)?;
    Ok(())
}

fn parse_pushes(script: &[u8]) -> CodecResult<Vec<(usize, Vec<u8>)>> {
    let mut pushes = Vec::new();
    let mut offset = 0;
    while offset < script.len() {
        let start = offset;
        let opcode = script[offset];
        offset += 1;
        let len = match opcode {
            OP_0 => {
                pushes.push((start, Vec::new()));
                continue;
            }
            OP_DATA_1..=OP_DATA_75 => opcode as usize,
            OP_PUSH_DATA_1 => {
                let bytes = read_len(script, &mut offset, 1)?;
                bytes[0] as usize
            }
            OP_PUSH_DATA_2 => {
                let bytes = read_len(script, &mut offset, 2)?;
                u16::from_le_bytes([bytes[0], bytes[1]]) as usize
            }
            OP_PUSH_DATA_4 => {
                let bytes = read_len(script, &mut offset, 4)?;
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
            OP_1_NEGATE | OP_1..=OP_16 => {
                return Err(CodecError::InvalidPush(format!("small-int opcode {opcode:#x} is not valid in state span")));
            }
            _ => return Err(CodecError::InvalidPush(format!("opcode {opcode:#x} is not a push-data opcode"))),
        };
        let data = read_len(script, &mut offset, len)?.to_vec();
        pushes.push((start, data));
    }
    Ok(pushes)
}

fn read_len<'a>(script: &'a [u8], offset: &mut usize, len: usize) -> CodecResult<&'a [u8]> {
    let end = offset.checked_add(len).ok_or_else(|| CodecError::InvalidPush("push length overflow".to_string()))?;
    if end > script.len() {
        return Err(CodecError::InvalidPush(format!(
            "push at offset {} needs {} bytes, only {} remain",
            *offset,
            len,
            script.len().saturating_sub(*offset)
        )));
    }
    let bytes = &script[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn serialize_fixed_i64(value: i64, size: usize) -> CodecResult<Vec<u8>> {
    serialize_script_i64(value, Some(size)).map(|bytes| bytes.into_vec()).map_err(|_| CodecError::InvalidNumber { value, size })
}

fn deserialize_fixed_i64(bytes: &[u8]) -> CodecResult<i64> {
    deserialize_script_i64(bytes, false).map_err(|err| CodecError::InvalidPush(err.to_string()))
}

fn expect_int(value: &ArtifactValue) -> CodecResult<i64> {
    match value {
        ArtifactValue::Int(value) => Ok(*value),
        other => type_mismatch("int", other),
    }
}

fn expect_bool(value: &ArtifactValue) -> CodecResult<bool> {
    match value {
        ArtifactValue::Bool(value) => Ok(*value),
        other => type_mismatch("bool", other),
    }
}

fn expect_byte(value: &ArtifactValue) -> CodecResult<u8> {
    match value {
        ArtifactValue::Byte(value) => Ok(*value),
        other => type_mismatch("byte", other),
    }
}

fn expect_bytes(value: &ArtifactValue) -> CodecResult<&[u8]> {
    match value {
        ArtifactValue::Bytes(value) => Ok(value),
        other => type_mismatch("bytes", other),
    }
}

fn expect_text(value: &ArtifactValue) -> CodecResult<&str> {
    match value {
        ArtifactValue::Text(value) => Ok(value),
        other => type_mismatch("string", other),
    }
}

fn expect_array(value: &ArtifactValue) -> CodecResult<&[ArtifactValue]> {
    match value {
        ArtifactValue::Array(value) => Ok(value),
        other => type_mismatch("array", other),
    }
}

fn object_fields(value: &ArtifactValue) -> CodecResult<&BTreeMap<String, ArtifactValue>> {
    match value {
        ArtifactValue::Object(fields) => Ok(fields),
        other => type_mismatch("object", other),
    }
}

fn type_mismatch<T>(expected: &str, actual: &ArtifactValue) -> CodecResult<T> {
    Err(CodecError::TypeMismatch { expected: expected.to_string(), actual: value_name(actual).to_string() })
}

fn value_name(value: &ArtifactValue) -> &'static str {
    match value {
        ArtifactValue::Int(_) => "int",
        ArtifactValue::Bool(_) => "bool",
        ArtifactValue::Byte(_) => "byte",
        ArtifactValue::Bytes(_) => "bytes",
        ArtifactValue::Text(_) => "string",
        ArtifactValue::Array(_) => "array",
        ArtifactValue::Object(_) => "object",
    }
}

fn assert_no_extra_fields(fields: &BTreeMap<String, ArtifactValue>, expected: &[FieldArtifact]) -> CodecResult<()> {
    for name in fields.keys() {
        if expected.iter().all(|field| &field.name != name) {
            return Err(CodecError::UnknownField(name.clone()));
        }
    }
    Ok(())
}

fn require_len(name: &str, expected: usize, actual: usize) -> CodecResult<()> {
    if expected == actual { Ok(()) } else { Err(CodecError::InvalidLength { name: name.to_string(), expected, actual }) }
}

fn type_name(ty: &TypeArtifact) -> String {
    match ty {
        TypeArtifact::Int => "int".to_string(),
        TypeArtifact::Temporal => "temporal".to_string(),
        TypeArtifact::Bool => "bool".to_string(),
        TypeArtifact::Byte => "byte".to_string(),
        TypeArtifact::Bytes => "bytes".to_string(),
        TypeArtifact::Text => "string".to_string(),
        TypeArtifact::Pubkey => "pubkey".to_string(),
        TypeArtifact::Sig => "sig".to_string(),
        TypeArtifact::Datasig => "datasig".to_string(),
        TypeArtifact::FixedBytes { len } => format!("byte[{len}]"),
        TypeArtifact::FixedArray { item, len } => format!("{}[{len}]", type_name(item)),
        TypeArtifact::DynamicArray { item } => format!("{}[]", type_name(item)),
        TypeArtifact::Struct { name } => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_values_support_ergonomic_from_conversions() {
        let values: Vec<ArtifactValue> = vec![1.into(), vec![2u8; 4].into(), true.into(), 3u8.into(), "ready".into()];
        assert_eq!(
            values,
            vec![
                ArtifactValue::Int(1),
                ArtifactValue::Bytes(vec![2; 4]),
                ArtifactValue::Bool(true),
                ArtifactValue::Byte(3),
                ArtifactValue::Text("ready".to_string()),
            ]
        );
        assert_eq!(ArtifactValue::from(vec![ArtifactValue::Int(1)]), ArtifactValue::Array(vec![ArtifactValue::Int(1)]));
        assert_eq!(ArtifactValue::from(vec![1i64, 2]), ArtifactValue::Array(vec![ArtifactValue::Int(1), ArtifactValue::Int(2)]));
        assert_eq!(
            ArtifactValue::from(BTreeMap::from([("value".to_string(), ArtifactValue::Int(1))])),
            ArtifactValue::Object(BTreeMap::from([("value".to_string(), ArtifactValue::Int(1))]))
        );
    }

    // Locks the ABI copy to Sil's canonical implementation. Ideally, Sil will
    // expose this from a small shared core crate instead of requiring a copy.
    #[test]
    fn template_hash_matches_silverscript() {
        let cases: &[(&[u8], &[u8])] = &[(b"", b""), (b"a", b"bc"), (b"ab", b"c"), (&[0, 1, 2, 3], &[0xff, 0x80, 0x40])];

        for (prefix, suffix) in cases {
            assert_eq!(template_hash(prefix, suffix), silverscript_lang::template::template_hash(prefix, suffix));
        }

        let kcc1_vectors: &[(&[u8], &[u8], &str)] = &[
            (&[], &[], "e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e"),
            (b"a", b"bc", "405e183e2494cdbe2df89349cc0ffa5b77fb885ad97a1d5660ecd0692ef8142a"),
            (b"ab", b"c", "a0968c014f3fc7bd1a7d9a8d1ad1177eb379bd2f05e56309eb4e20347c5e7eba"),
            (&[0x00, 0xff], &[0x10, 0x00, 0x80], "6616a66757315de0221cb2acba729113cebde31f8d3ca7fa93878a0584b96905"),
        ];
        for (prefix, suffix, expected) in kcc1_vectors {
            assert_eq!(encode_hex(&template_hash(prefix, suffix)), *expected);
        }
    }

    #[test]
    fn verifies_compiled_contract_against_its_script() {
        let mut abi = tiny_sil_abi();
        let prefix = [0xaa];
        abi.contracts.get_mut("Foo").unwrap().runtime_state.fields =
            vec![RuntimeFieldArtifact { name: "value".to_string(), ty: TypeArtifact::Byte }];
        let state = encode_runtime_state_script(
            &abi,
            &abi.contracts["Foo"].runtime_state,
            &BTreeMap::from([("value".to_string(), ArtifactValue::Byte(2))]),
        )
        .expect("state encodes");
        let suffix = [0xbb, 0xcc];
        let contract = abi.contracts.get_mut("Foo").unwrap();
        contract.compiled.bytecode = [prefix.as_slice(), state.as_slice(), suffix.as_slice()].concat();
        contract.compiled.template_hash = template_hash(&prefix, &suffix);
        contract.compiled.state_span = StateSpanArtifact { offset: prefix.len(), len: state.len() };

        abi.verify().expect("compiled template matches its contract script");

        abi.contracts.get_mut("Foo").unwrap().compiled.template_hash = [0; 32];
        assert!(matches!(
            abi.verify(),
            Err(SilAbiVerificationError::TemplateHashMismatch { ref contract, .. }) if contract == "Foo"
        ));

        abi.contracts.get_mut("Foo").unwrap().compiled.template_hash = template_hash(&prefix, &suffix);
        abi.contracts.get_mut("Foo").unwrap().compiled.bytecode = [&[0xff], state.as_slice(), suffix.as_slice()].concat();
        assert!(matches!(
            abi.verify(),
            Err(SilAbiVerificationError::TemplateHashMismatch { ref contract, .. }) if contract == "Foo"
        ));
    }

    #[test]
    fn rejects_invalid_dispatch_tags_during_deserialization() {
        let wrong_length = serde_json::from_str::<DispatchTag>(r#""00""#).expect_err("short tag should fail");
        assert!(wrong_length.to_string().contains("exactly 8 hexadecimal characters"));

        let invalid_hex = serde_json::from_str::<DispatchTag>(r#""zzzzzzzz""#).expect_err("invalid hex should fail");
        assert!(invalid_hex.to_string().contains("invalid dispatch tag hex"));
    }

    #[test]
    fn rejects_colliding_dispatch_tags() {
        let mut abi = tiny_sil_abi();
        let step_tag = abi.contracts["Foo"].entries["step"].dispatch_tag;
        abi.contracts.get_mut("Foo").unwrap().entries.get_mut("other").unwrap().dispatch_tag = step_tag;
        assert!(matches!(
            abi.verify(),
            Err(SilAbiVerificationError::DispatchTagCollision { ref contract, ref first, ref second, .. })
                if contract == "Foo" && first == "other" && second == "step"
        ));
    }

    #[test]
    fn rejects_unknown_entry_metadata_references() {
        let mut abi = tiny_sil_abi();
        abi.contracts.get_mut("Foo").unwrap().cov_decl_to_abi.insert("spend".to_string(), "missing".to_string());

        assert_eq!(
            abi.verify(),
            Err(SilAbiVerificationError::UnknownEntryReference { contract: "Foo".to_string(), entry: "missing".to_string() })
        );
    }

    #[test]
    fn rejects_state_spans_that_do_not_match_the_runtime_state() {
        let mut abi = tiny_sil_abi();
        abi.contracts.get_mut("Foo").unwrap().runtime_state.fields =
            vec![RuntimeFieldArtifact { name: "value".to_string(), ty: TypeArtifact::Byte }];
        let prefix = [0xaa];
        let state = encode_runtime_state_script(
            &abi,
            &abi.contracts["Foo"].runtime_state,
            &BTreeMap::from([("value".to_string(), ArtifactValue::Byte(2))]),
        )
        .expect("state encodes");
        let suffix = [0xbb];
        let contract = abi.contracts.get_mut("Foo").unwrap();
        contract.compiled.bytecode = [prefix.as_slice(), state.as_slice(), suffix.as_slice()].concat();

        contract.compiled.state_span = StateSpanArtifact { offset: 0, len: prefix.len() + state.len() };
        contract.compiled.template_hash = template_hash(&[], &suffix);
        assert!(matches!(
            abi.verify(),
            Err(SilAbiVerificationError::InvalidRuntimeStateEncoding { ref contract, .. }) if contract == "Foo"
        ));

        let contract = abi.contracts.get_mut("Foo").unwrap();
        contract.compiled.state_span = StateSpanArtifact { offset: prefix.len(), len: state.len() - 1 };
        contract.compiled.template_hash = template_hash(&prefix, &[state[state.len() - 1], suffix[0]]);
        assert!(matches!(
            abi.verify(),
            Err(SilAbiVerificationError::InvalidRuntimeStateEncoding { ref contract, .. }) if contract == "Foo"
        ));
    }

    #[test]
    fn rejects_noncanonical_and_variable_runtime_state_encodings() {
        let mut abi = tiny_sil_abi();
        let contract = abi.contracts.get_mut("Foo").unwrap();
        contract.runtime_state.fields = vec![RuntimeFieldArtifact { name: "value".to_string(), ty: TypeArtifact::Byte }];
        let prefix = [0xaa];
        let state = [OP_PUSH_DATA_1, 1, 2];
        let suffix = [0xbb];
        contract.compiled.bytecode = [prefix.as_slice(), state.as_slice(), suffix.as_slice()].concat();
        contract.compiled.template_hash = template_hash(&prefix, &suffix);
        contract.compiled.state_span = StateSpanArtifact { offset: prefix.len(), len: state.len() };
        assert_eq!(abi.verify(), Err(SilAbiVerificationError::NonCanonicalRuntimeStateEncoding { contract: "Foo".to_string() }));

        abi.contracts.get_mut("Foo").unwrap().runtime_state.fields[0].ty = TypeArtifact::Bytes;
        assert_eq!(
            abi.verify(),
            Err(SilAbiVerificationError::UnsupportedRuntimeStateType {
                contract: "Foo".to_string(),
                field: "value".to_string(),
                ty: "bytes".to_string(),
            })
        );
    }

    #[test]
    fn validates_struct_runtime_state_types_recursively() {
        let mut abi = tiny_sil_abi();
        abi.structs = BTreeMap::from([
            (
                "Inner".to_string(),
                StructArtifact { fields: vec![FieldArtifact { name: "value".to_string(), ty: TypeArtifact::Byte }] },
            ),
            (
                "Outer".to_string(),
                StructArtifact {
                    fields: vec![
                        FieldArtifact { name: "inner".to_string(), ty: TypeArtifact::Struct { name: "Inner".to_string() } },
                        FieldArtifact {
                            name: "values".to_string(),
                            ty: TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Int), len: 2 },
                        },
                    ],
                },
            ),
        ]);

        assert!(is_supported_runtime_state_type(&abi, &TypeArtifact::Struct { name: "Outer".to_string() }));

        abi.structs.get_mut("Inner").unwrap().fields[0].ty = TypeArtifact::Bytes;
        assert!(!is_supported_runtime_state_type(&abi, &TypeArtifact::Struct { name: "Outer".to_string() }));

        abi.structs.get_mut("Inner").unwrap().fields[0].ty = TypeArtifact::Struct { name: "Outer".to_string() };
        assert!(!is_supported_runtime_state_type(&abi, &TypeArtifact::Struct { name: "Outer".to_string() }));
    }

    #[test]
    fn encodes_sigscript_arguments_canonically() {
        let artifact = tiny_sil_abi();
        let sigscript = encode_contract_entry_sig_script(
            &artifact,
            "Foo",
            "step",
            &[ArtifactValue::Int(17), ArtifactValue::Bytes(vec![1, 2, 3, 4]), ArtifactValue::Bool(true), ArtifactValue::Byte(1)],
        )
        .expect("sigscript encodes");

        assert_eq!(encode_hex(&sigscript), "011104010203045151042c49ed65");
    }

    #[test]
    fn encodes_temporal_values_with_integer_payloads() {
        assert_eq!(TypeArtifact::from_parts("temporal", None), TypeArtifact::Temporal);
        assert_eq!(serde_json::to_value(TypeArtifact::Temporal).unwrap(), serde_json::json!({ "kind": "temporal" }));

        let mut artifact = tiny_sil_abi();
        artifact.contracts.get_mut("Foo").unwrap().entries.get_mut("other").unwrap().params =
            vec![param("at", TypeArtifact::Temporal), param("history", TypeArtifact::dynamic_array(TypeArtifact::Temporal))];
        let history = ArtifactValue::Array(vec![ArtifactValue::Int(1), ArtifactValue::Int(-2)]);
        let sigscript = encode_contract_entry_sig_script(&artifact, "Foo", "other", &[ArtifactValue::Int(-5), history.clone()])
            .expect("temporal arguments encode");
        let pushes = parse_pushes(&sigscript).expect("signature script contains only data pushes");
        assert_eq!(
            pushes.iter().map(|(_, data)| data.clone()).collect::<Vec<_>>(),
            vec![
                vec![0x85],
                [serialize_fixed_i64(1, 8).unwrap(), serialize_fixed_i64(-2, 8).unwrap()].concat(),
                vec![0xde, 0xad, 0xbe, 0xef],
            ]
        );

        let runtime_state = RuntimeStateArtifact {
            source: "ClockState".to_string(),
            fields: vec![
                RuntimeFieldArtifact { name: "at".to_string(), ty: TypeArtifact::Temporal },
                RuntimeFieldArtifact {
                    name: "history".to_string(),
                    ty: TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Temporal), len: 2 },
                },
            ],
        };
        let values = BTreeMap::from([("at".to_string(), ArtifactValue::Int(-5)), ("history".to_string(), history)]);
        let encoded = encode_runtime_state_script(&artifact, &runtime_state, &values).expect("temporal state encodes");
        assert_eq!(decode_runtime_state_script(&artifact, &runtime_state, &encoded).expect("temporal state decodes"), values);
    }

    #[test]
    fn hex_helpers_use_faster_hex_and_report_invalid_input() {
        assert_eq!(decode_hex("01110401020304515100").expect("hex decodes"), vec![1, 17, 4, 1, 2, 3, 4, 81, 81, 0]);
        assert!(matches!(decode_hex("abc"), Err(CodecError::InvalidHex(_))));
        assert!(matches!(decode_hex("zz"), Err(CodecError::InvalidHex(_))));
    }

    #[test]
    fn encodes_struct_payload_without_push_framing() {
        let mut abi = tiny_sil_abi();
        abi.structs.insert(
            "Memory".to_string(),
            StructArtifact {
                fields: vec![
                    FieldArtifact { name: "hunger".to_string(), ty: TypeArtifact::Int },
                    FieldArtifact { name: "tag".to_string(), ty: TypeArtifact::FixedBytes { len: 2 } },
                ],
            },
        );
        let values = BTreeMap::from([
            ("hunger".to_string(), ArtifactValue::Int(17)),
            ("tag".to_string(), ArtifactValue::Bytes(vec![0xaa, 0xbb])),
        ]);

        let payload = encode_struct_payload(&abi, abi.contract("Foo").expect("contract exists"), "Memory", &values)
            .expect("struct payload encodes");

        assert_eq!(encode_hex(&payload), "1100000000000000aabb");
    }

    #[test]
    fn deserializes_sil_abi_without_argent_coordination_metadata() {
        let json = r#"
        {
          "schema_version": 1,
          "compiler_version": "0.1.0",
          "structs": {
            "FooState": {
              "fields": [{ "name": "count", "type": { "kind": "int" } }]
            }
          },
          "contracts": {
            "Foo": {
              "source_path": "sil/Foo.sil",
              "runtime_state": {
                "source": "FooState",
                "fields": [{ "name": "count", "type": { "kind": "int" } }]
              },
              "entries": {
                "step": {
                  "dispatch_tag": "2c49ed65",
                  "params": [{ "name": "amount", "type": { "kind": "int" } }]
                }
              },
              "compiled": {
                "bytecode": [0],
                "template_hash": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "state_span": { "offset": 0, "len": 1 }
              }
            }
          }
        }
        "#;

        let abi: SilAbiArtifact = serde_json::from_str(json).expect("sil abi should deserialize");
        abi.check_schema_version().expect("sil abi schema version should be supported");
        assert_eq!(abi.contract("Foo").expect("contract exists").compiled.bytecode, vec![0]);
        assert_eq!(
            abi.contract("Foo").and_then(|contract| contract.entry("step")).map(|entry| entry.dispatch_tag),
            Some(DispatchTag::from([0x2c, 0x49, 0xed, 0x65]))
        );
        assert_eq!(
            abi.contract("Foo").and_then(|contract| contract.entry("step")).map(|entry| entry.params[0].name.as_str()),
            Some("amount")
        );
        let serialized = serde_json::to_value(&abi).expect("Sil ABI artifact serializes");
        assert_eq!(serialized["contracts"]["Foo"]["entries"]["step"]["dispatch_tag"], "2c49ed65");
        assert_eq!(serialized["contracts"]["Foo"]["compiled"]["bytecode"], serde_json::json!([0]));
        assert_eq!(
            serialized["contracts"]["Foo"]["compiled"]["template_hash"],
            serde_json::to_value([0u8; 32]).expect("template hash serializes")
        );
    }

    #[test]
    fn pretty_json_wraps_byte_arrays_at_fixed_boundaries() {
        let mut abi = tiny_sil_abi();
        abi.contracts.get_mut("Foo").unwrap().compiled.bytecode = (0..=64).collect();

        let json = to_pretty_json(&abi).expect("Sil ABI artifact serializes");
        let lines = json.lines().collect::<Vec<_>>();
        let bytecode_line = lines.iter().position(|line| line.trim() == r#""bytecode": ["#).expect("bytecode field exists");
        assert_eq!(lines[bytecode_line + 1].split(", ").count(), 64);
        assert_eq!(lines[bytecode_line + 2].trim(), "64");
        assert_eq!(lines[bytecode_line + 3].trim(), "],");
        assert!(lines.iter().any(|line| line.trim_start().starts_with(r#""template_hash": [0, 0, 0"#)));

        let decoded: SilAbiArtifact = serde_json::from_str(&json).expect("Sil ABI artifact deserializes");
        assert_eq!(decoded.contracts["Foo"].compiled.bytecode, (0..=64).collect::<Vec<_>>());
    }

    #[test]
    fn rejects_sigscript_ints_that_do_not_fit_silverscript_script_number() {
        let artifact = tiny_sil_abi();
        let err = encode_contract_entry_sig_script(
            &artifact,
            "Foo",
            "step",
            &[ArtifactValue::Int(i64::MIN), ArtifactValue::Bytes(vec![1, 2, 3, 4]), ArtifactValue::Bool(true), ArtifactValue::Byte(1)],
        )
        .expect_err("i64::MIN needs 9 bytes and should match txscript rejection");

        assert_eq!(err, CodecError::InvalidNumber { value: i64::MIN, size: 8 });
    }

    #[test]
    fn round_trips_runtime_state_script() {
        let abi = tiny_sil_abi();
        let runtime_state = RuntimeStateArtifact {
            source: "FooState".to_string(),
            fields: vec![
                RuntimeFieldArtifact { name: "gen__foo_template".to_string(), ty: TypeArtifact::FixedBytes { len: 32 } },
                RuntimeFieldArtifact { name: "count".to_string(), ty: TypeArtifact::Int },
                RuntimeFieldArtifact { name: "flag".to_string(), ty: TypeArtifact::Bool },
            ],
        };
        let values = BTreeMap::from([
            ("gen__foo_template".to_string(), ArtifactValue::Bytes(vec![7; 32])),
            ("count".to_string(), ArtifactValue::Int(-5)),
            ("flag".to_string(), ArtifactValue::Bool(true)),
        ]);

        let encoded = encode_runtime_state_script(&abi, &runtime_state, &values).expect("state encodes");
        let decoded = decode_runtime_state_script(&abi, &runtime_state, &encoded).expect("state decodes");

        assert_eq!(encode_hex(&encoded), format!("20{}0805000000000000800101", "07".repeat(32)));
        assert_eq!(decoded, values);
        assert_eq!(encode_runtime_state_script(&abi, &runtime_state, &decoded).expect("state re-encodes"), encoded);

        let mut extra = values;
        extra.insert("extra".to_string(), ArtifactValue::Int(1));
        assert_eq!(
            encode_runtime_state_script(&abi, &runtime_state, &extra).expect_err("extra fields should be rejected"),
            CodecError::UnknownField("extra".to_string())
        );
    }

    #[test]
    fn round_trips_nested_struct_and_struct_array_runtime_state() {
        let mut abi = tiny_sil_abi();
        abi.structs = BTreeMap::from([
            (
                "Inner".to_string(),
                StructArtifact { fields: vec![FieldArtifact { name: "marker".to_string(), ty: TypeArtifact::Byte }] },
            ),
            (
                "Outer".to_string(),
                StructArtifact {
                    fields: vec![
                        FieldArtifact { name: "inner".to_string(), ty: TypeArtifact::Struct { name: "Inner".to_string() } },
                        FieldArtifact { name: "active".to_string(), ty: TypeArtifact::Bool },
                    ],
                },
            ),
            (
                "Pair".to_string(),
                StructArtifact {
                    fields: vec![
                        FieldArtifact { name: "amount".to_string(), ty: TypeArtifact::Int },
                        FieldArtifact { name: "code".to_string(), ty: TypeArtifact::FixedBytes { len: 2 } },
                    ],
                },
            ),
        ]);
        let runtime_state = RuntimeStateArtifact {
            source: "FooState".to_string(),
            fields: vec![
                RuntimeFieldArtifact { name: "current".to_string(), ty: TypeArtifact::Struct { name: "Outer".to_string() } },
                RuntimeFieldArtifact {
                    name: "pairs".to_string(),
                    ty: TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Struct { name: "Pair".to_string() }), len: 2 },
                },
            ],
        };
        let pair = |amount, code| {
            ArtifactValue::Object(BTreeMap::from([
                ("amount".to_string(), ArtifactValue::Int(amount)),
                ("code".to_string(), ArtifactValue::Bytes(code)),
            ]))
        };
        let values = BTreeMap::from([
            (
                "current".to_string(),
                ArtifactValue::Object(BTreeMap::from([
                    ("inner".to_string(), ArtifactValue::Object(BTreeMap::from([("marker".to_string(), ArtifactValue::Byte(7))]))),
                    ("active".to_string(), ArtifactValue::Bool(true)),
                ])),
            ),
            ("pairs".to_string(), ArtifactValue::Array(vec![pair(11, vec![0xaa, 0xbb]), pair(12, vec![0xcc, 0xdd])])),
        ]);

        let encoded = encode_runtime_state_script(&abi, &runtime_state, &values).expect("structured state encodes");
        let pushes = parse_pushes(&encoded).expect("structured state uses push-only encoding");

        assert_eq!(
            pushes.into_iter().map(|(_, payload)| payload).collect::<Vec<_>>(),
            vec![
                vec![7],
                vec![1],
                [serialize_fixed_i64(11, 8).unwrap(), serialize_fixed_i64(12, 8).unwrap()].concat(),
                vec![0xaa, 0xbb, 0xcc, 0xdd],
            ]
        );
        assert_eq!(decode_runtime_state_script(&abi, &runtime_state, &encoded).expect("structured state decodes"), values);
    }

    fn tiny_sil_abi() -> SilAbiArtifact {
        SilAbiArtifact {
            schema_version: SIL_ABI_SCHEMA_VERSION,
            compiler_version: "0.1.0".to_string(),
            structs: BTreeMap::new(),
            contracts: BTreeMap::from([(
                "Foo".to_string(),
                SilContractArtifact {
                    source_path: "sil/Foo.sil".to_string(),
                    runtime_state: RuntimeStateArtifact { source: "FooState".to_string(), fields: Vec::new() },
                    entries: BTreeMap::from([
                        (
                            "step".to_string(),
                            SilEntryArtifact {
                                dispatch_tag: DispatchTag::from([0x2c, 0x49, 0xed, 0x65]),
                                params: vec![
                                    param("n", TypeArtifact::Int),
                                    param("hash", TypeArtifact::FixedBytes { len: 4 }),
                                    param("flag", TypeArtifact::Bool),
                                    param("b", TypeArtifact::Byte),
                                ],
                            },
                        ),
                        (
                            "other".to_string(),
                            SilEntryArtifact { dispatch_tag: DispatchTag::from([0xde, 0xad, 0xbe, 0xef]), params: Vec::new() },
                        ),
                    ]),
                    cov_decl_to_abi: BTreeMap::new(),
                    delegate_entry_abi: None,
                    compiled: CompiledContractArtifact {
                        bytecode: Vec::new(),
                        template_hash: [0; 32],
                        state_span: StateSpanArtifact { offset: 0, len: 0 },
                    },
                },
            )]),
        }
    }

    fn param(name: &str, ty: TypeArtifact) -> ParamArtifact {
        ParamArtifact { name: name.to_string(), ty }
    }
}
