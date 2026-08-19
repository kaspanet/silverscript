use crate::ast::{ArrayDim, IndexedIntrospectionKind, IntrospectionKind, TypeBase, TypeRef};

use super::STATE_TYPE_NAME;

fn scalar(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn byte_array(dimension: ArrayDim) -> TypeRef {
    TypeRef { base: TypeBase::Byte, array_dims: vec![dimension] }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BuiltinReturn {
    Value(TypeRef),
    Void,
}

pub(super) struct G16VerifyParameterTypes {
    pub(super) verifying_key: TypeRef,
    pub(super) proof: TypeRef,
    pub(super) public_input: TypeRef,
}

pub(super) fn g16_verify_parameter_types() -> G16VerifyParameterTypes {
    G16VerifyParameterTypes {
        verifying_key: byte_array(ArrayDim::Dynamic),
        proof: byte_array(ArrayDim::Dynamic),
        public_input: byte_array(ArrayDim::Fixed(32)),
    }
}

pub(super) fn introspection_type(op: IntrospectionKind) -> TypeRef {
    match op {
        IntrospectionKind::ActiveScriptPubKey | IntrospectionKind::ThisBytecodeSizeDataPrefix => byte_array(ArrayDim::Dynamic),
        IntrospectionKind::ActiveInputIndex
        | IntrospectionKind::ThisBytecodeSize
        | IntrospectionKind::TxInputsLength
        | IntrospectionKind::TxOutputsLength
        | IntrospectionKind::TxVersion
        | IntrospectionKind::TxLockTime => scalar(TypeBase::Int),
    }
}

pub(super) fn indexed_introspection_type(kind: IndexedIntrospectionKind) -> TypeRef {
    match kind {
        IndexedIntrospectionKind::InputScriptPubKey
        | IndexedIntrospectionKind::InputSigScript
        | IndexedIntrospectionKind::OutputScriptPubKey => byte_array(ArrayDim::Dynamic),
        IndexedIntrospectionKind::InputOutpointTxId => byte_array(ArrayDim::Fixed(32)),
        IndexedIntrospectionKind::InputSequence => byte_array(ArrayDim::Fixed(8)),
        IndexedIntrospectionKind::InputValue
        | IndexedIntrospectionKind::InputOutpointIndex
        | IndexedIntrospectionKind::OutputValue => scalar(TypeBase::Int),
    }
}

pub(super) fn builtin_return(name: &str) -> Option<BuiltinReturn> {
    let value_type = match name {
        "int" | "signed" | "unsigned" => scalar(TypeBase::Int),
        "temporal" => scalar(TypeBase::Temporal),
        "bool" => scalar(TypeBase::Bool),
        "byte" => scalar(TypeBase::Byte),
        "string" => scalar(TypeBase::String),
        "pubkey" => scalar(TypeBase::Pubkey),
        "sig" => scalar(TypeBase::Sig),
        "datasig" => scalar(TypeBase::Datasig),
        "OpBin2Num"
        | "OpTxInputDaaScore"
        | "OpTxGas"
        | "OpTxPayloadLen"
        | "OpTxInputIndex"
        | "OpTxInputScriptSigLen"
        | "OpTxInputSpkLen"
        | "OpOutpointIndex"
        | "OpTxOutputSpkLen"
        | "OpAuthOutputCount"
        | "OpAuthOutputIdx"
        | "OpCovInputCount"
        | "OpCovInputIdx"
        | "OpCovOutputCount"
        | "OpCovOutputIdx" => scalar(TypeBase::Int),
        "length" => scalar(TypeBase::Int),
        "OpTxInputIsCoinbase" | "checkSig" | "checkMsgSig" | "checkSigFromStackECDSA" => scalar(TypeBase::Bool),
        "g16.verify"
        | "r0.g16.verify"
        | "r0.succinct.verify"
        | "r0.succinct.blake2b.verify"
        | "r0.succinct.poseidon2.verify"
        | "r0.succinct.sha256.verify" => return Some(BuiltinReturn::Void),
        "blake2b"
        | "blake2bWithKey"
        | "blake3"
        | "blake3WithKey"
        | "templateHash"
        | "sha256"
        | "OpOutpointTxId"
        | "OpChainblockSeqCommit"
        | "OpInputCovenantId"
        | "OpOutputCovenantId" => byte_array(ArrayDim::Fixed(32)),
        "OpTxSubnetId" => byte_array(ArrayDim::Fixed(20)),
        "OpTxInputSeq" => byte_array(ArrayDim::Fixed(8)),
        "OpTxPayloadSubstr" | "OpTxInputScriptSigSubstr" | "OpTxInputSpkSubstr" | "OpTxOutputSpkSubstr" | "OpNum2Bin" => {
            byte_array(ArrayDim::Dynamic)
        }
        _ => return None,
    };
    Some(BuiltinReturn::Value(value_type))
}

pub(super) fn builtin_return_type(name: &str) -> Option<TypeRef> {
    match builtin_return(name)? {
        BuiltinReturn::Value(type_ref) => Some(type_ref),
        BuiltinReturn::Void => None,
    }
}

pub(super) fn constructor_return_type(name: &str) -> Option<TypeRef> {
    Some(match name {
        "ScriptPubKeyP2PK" => byte_array(ArrayDim::Fixed(34)),
        "ScriptPubKeyP2SH" | "ScriptPubKeyP2SHFromRedeemScript" => byte_array(ArrayDim::Fixed(35)),
        _ => return None,
    })
}

pub(super) fn constructor_parameters(name: &str) -> Option<Vec<(&'static str, TypeRef)>> {
    Some(match name {
        "ScriptPubKeyP2PK" => vec![("publicKey", scalar(TypeBase::Pubkey))],
        "ScriptPubKeyP2SH" => vec![("scriptHash", byte_array(ArrayDim::Fixed(32)))],
        "ScriptPubKeyP2SHFromRedeemScript" => vec![("redeemScript", byte_array(ArrayDim::Dynamic))],
        _ => return None,
    })
}

pub(super) fn is_builtin_name(name: &str) -> bool {
    builtin_return(name).is_some() || builtin_parameters(name).is_some() || constructor_return_type(name).is_some()
}

pub(super) fn builtin_parameters(name: &str) -> Option<Vec<(&'static str, TypeRef)>> {
    Some(match name {
        "signed" | "unsigned" => vec![("value", scalar(TypeBase::Byte))],
        "length" | "sha256" | "blake2b" | "blake3" => vec![("data", byte_array(ArrayDim::Dynamic))],
        "blake2bWithKey" => vec![("data", byte_array(ArrayDim::Dynamic)), ("key", byte_array(ArrayDim::Dynamic))],
        "blake3WithKey" => vec![("data", byte_array(ArrayDim::Dynamic)), ("key", byte_array(ArrayDim::Fixed(32)))],
        "templateHash" => vec![("templatePrefix", byte_array(ArrayDim::Dynamic)), ("templateSuffix", byte_array(ArrayDim::Dynamic))],
        "checkSig" => vec![("signature", scalar(TypeBase::Sig)), ("publicKey", scalar(TypeBase::Pubkey))],
        "checkMsgSig" => vec![
            ("signature", scalar(TypeBase::Datasig)),
            ("digest", byte_array(ArrayDim::Fixed(32))),
            ("publicKey", scalar(TypeBase::Pubkey)),
        ],
        "checkSigFromStackECDSA" => vec![
            ("signature", scalar(TypeBase::Datasig)),
            ("digest", byte_array(ArrayDim::Fixed(32))),
            ("publicKey", byte_array(ArrayDim::Fixed(33))),
        ],
        "OpTxSubnetId" | "OpTxGas" | "OpTxPayloadLen" | "OpTxInputIndex" => vec![],
        "OpOutpointTxId"
        | "OpOutpointIndex"
        | "OpTxInputScriptSigLen"
        | "OpTxInputSeq"
        | "OpTxInputDaaScore"
        | "OpTxInputIsCoinbase"
        | "OpTxInputSpkLen"
        | "OpTxOutputSpkLen"
        | "OpInputCovenantId"
        | "OpOutputCovenantId" => vec![("idx", scalar(TypeBase::Int))],
        "OpTxPayloadSubstr" => vec![("start", scalar(TypeBase::Int)), ("end", scalar(TypeBase::Int))],
        "OpTxInputScriptSigSubstr" | "OpTxInputSpkSubstr" | "OpTxOutputSpkSubstr" => {
            vec![("idx", scalar(TypeBase::Int)), ("start", scalar(TypeBase::Int)), ("end", scalar(TypeBase::Int))]
        }
        "OpAuthOutputCount" => vec![("input_idx", scalar(TypeBase::Int))],
        "OpAuthOutputIdx" => vec![("input_idx", scalar(TypeBase::Int)), ("k", scalar(TypeBase::Int))],
        "OpCovInputCount" | "OpCovOutputCount" => vec![("covenant_id", byte_array(ArrayDim::Fixed(32)))],
        "OpCovInputIdx" | "OpCovOutputIdx" => {
            vec![("covenant_id", byte_array(ArrayDim::Fixed(32))), ("k", scalar(TypeBase::Int))]
        }
        "OpNum2Bin" => vec![("num", scalar(TypeBase::Int)), ("size", scalar(TypeBase::Int))],
        "OpBin2Num" => vec![("num", byte_array(ArrayDim::Dynamic))],
        "OpChainblockSeqCommit" => vec![("block", byte_array(ArrayDim::Fixed(32)))],
        "readInputState" => vec![("input_idx", scalar(TypeBase::Int))],
        "readInputStateWithTemplate" => vec![
            ("input_idx", scalar(TypeBase::Int)),
            ("template_prefix_len", scalar(TypeBase::Int)),
            ("template_suffix_len", scalar(TypeBase::Int)),
            ("expected_template_hash", byte_array(ArrayDim::Fixed(32))),
        ],
        "r0.g16.verify" => vec![
            ("journal_hash", byte_array(ArrayDim::Fixed(32))),
            ("proof", byte_array(ArrayDim::Dynamic)),
            ("image_id", byte_array(ArrayDim::Fixed(32))),
        ],
        "r0.succinct.verify" | "r0.succinct.blake2b.verify" | "r0.succinct.poseidon2.verify" | "r0.succinct.sha256.verify" => {
            vec![
                ("claim", byte_array(ArrayDim::Fixed(32))),
                ("control_index", byte_array(ArrayDim::Fixed(4))),
                ("control_digests", byte_array(ArrayDim::Dynamic)),
                ("seal", byte_array(ArrayDim::Dynamic)),
                ("journal", byte_array(ArrayDim::Fixed(32))),
                ("image_id", byte_array(ArrayDim::Fixed(32))),
                ("control_id", byte_array(ArrayDim::Fixed(32))),
            ]
        }
        "validateOutputState" => {
            vec![("outputIndex", scalar(TypeBase::Int)), ("newState", scalar(TypeBase::Custom(STATE_TYPE_NAME.to_string())))]
        }
        "validateOutputStateWithTemplate" => vec![
            ("outputIndex", scalar(TypeBase::Int)),
            ("newState", scalar(TypeBase::Custom(STATE_TYPE_NAME.to_string()))),
            ("templatePrefix", byte_array(ArrayDim::Dynamic)),
            ("templateSuffix", byte_array(ArrayDim::Dynamic)),
            ("expectedTemplateHash", byte_array(ArrayDim::Fixed(32))),
        ],
        "validateOutputStateWithInputTemplate" => vec![
            ("outputIndex", scalar(TypeBase::Int)),
            ("newState", scalar(TypeBase::Custom(STATE_TYPE_NAME.to_string()))),
            ("templateInputIndex", scalar(TypeBase::Int)),
            ("templatePrefixLen", scalar(TypeBase::Int)),
            ("templateSuffixLen", scalar(TypeBase::Int)),
            ("expectedTemplateHash", byte_array(ArrayDim::Fixed(32))),
        ],
        _ => return None,
    })
}
