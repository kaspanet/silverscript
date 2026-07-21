use crate::ast::{ArrayDim, IntrospectionKind, NullaryOp, TypeBase, TypeRef};

fn scalar(base: TypeBase) -> TypeRef {
    TypeRef { base, array_dims: Vec::new() }
}

fn byte_array(dimension: ArrayDim) -> TypeRef {
    TypeRef { base: TypeBase::Byte, array_dims: vec![dimension] }
}

pub(super) fn nullary_type(op: NullaryOp) -> TypeRef {
    match op {
        NullaryOp::ActiveScriptPubKey | NullaryOp::ThisScriptSizeDataPrefix => byte_array(ArrayDim::Dynamic),
        NullaryOp::ActiveInputIndex
        | NullaryOp::ThisScriptSize
        | NullaryOp::TxInputsLength
        | NullaryOp::TxOutputsLength
        | NullaryOp::TxVersion
        | NullaryOp::TxLockTime => scalar(TypeBase::Int),
    }
}

pub(super) fn introspection_type(kind: IntrospectionKind) -> TypeRef {
    match kind {
        IntrospectionKind::InputScriptPubKey
        | IntrospectionKind::InputSigScript
        | IntrospectionKind::InputOutpointTransactionHash
        | IntrospectionKind::OutputScriptPubKey => byte_array(ArrayDim::Dynamic),
        IntrospectionKind::InputValue
        | IntrospectionKind::InputOutpointIndex
        | IntrospectionKind::InputSequenceNumber
        | IntrospectionKind::OutputValue => scalar(TypeBase::Int),
    }
}

pub(super) fn builtin_return_type(name: &str) -> Option<TypeRef> {
    Some(match name {
        "int" => scalar(TypeBase::Int),
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
        "OpTxInputIsCoinbase" | "checkSig" | "checkSigFromStack" | "checkSigFromStackECDSA" => scalar(TypeBase::Bool),
        "blake2b" | "blake2bWithKey" | "blake3" | "blake3WithKey" | "templateHash" | "sha256" | "OpSha256" => {
            byte_array(ArrayDim::Fixed(32))
        }
        "OpInputCovenantId" | "OpOutputCovenantId" => byte_array(ArrayDim::Fixed(32)),
        "bytes"
        | "OpTxSubnetId"
        | "OpTxPayloadSubstr"
        | "OpOutpointTxId"
        | "OpTxInputScriptSigSubstr"
        | "OpTxInputSeq"
        | "OpTxInputSpkSubstr"
        | "OpTxOutputSpkSubstr"
        | "OpNum2Bin"
        | "OpChainblockSeqCommit" => byte_array(ArrayDim::Dynamic),
        _ => return None,
    })
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

pub(super) fn builtin_parameters(name: &str) -> Option<Vec<(&'static str, TypeRef)>> {
    match name {
        "checkSigFromStack" => Some(vec![
            ("signature", scalar(TypeBase::Datasig)),
            ("digest", byte_array(ArrayDim::Fixed(32))),
            ("publicKey", scalar(TypeBase::Pubkey)),
        ]),
        "checkSigFromStackECDSA" => Some(vec![
            ("signature", scalar(TypeBase::Datasig)),
            ("digest", byte_array(ArrayDim::Fixed(32))),
            ("publicKey", byte_array(ArrayDim::Fixed(33))),
        ]),
        "blake3WithKey" => Some(vec![("data", byte_array(ArrayDim::Dynamic)), ("key", byte_array(ArrayDim::Fixed(32)))]),
        _ => None,
    }
}
