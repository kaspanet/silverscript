use crate::ast::{IntrospectionKind, NullaryOp, TypeRef, parse_type_ref};

pub(super) fn nullary_type(op: NullaryOp) -> TypeRef {
    parse_type_ref(match op {
        NullaryOp::ActiveScriptPubKey | NullaryOp::ThisScriptSizeDataPrefix => "byte[]",
        NullaryOp::ActiveInputIndex
        | NullaryOp::ThisScriptSize
        | NullaryOp::TxInputsLength
        | NullaryOp::TxOutputsLength
        | NullaryOp::TxVersion
        | NullaryOp::TxLockTime => "int",
    })
    .expect("builtin type is valid")
}

pub(super) fn introspection_type(kind: IntrospectionKind) -> TypeRef {
    parse_type_ref(match kind {
        IntrospectionKind::InputScriptPubKey
        | IntrospectionKind::InputSigScript
        | IntrospectionKind::InputOutpointTransactionHash
        | IntrospectionKind::OutputScriptPubKey => "byte[]",
        IntrospectionKind::InputValue
        | IntrospectionKind::InputOutpointIndex
        | IntrospectionKind::InputSequenceNumber
        | IntrospectionKind::OutputValue => "int",
    })
    .expect("builtin type is valid")
}

pub(super) fn builtin_return_type(name: &str) -> Option<TypeRef> {
    let name = match name {
        "int" | "bool" | "byte" | "string" | "pubkey" | "sig" | "datasig" => name,
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
        | "OpCovOutputIdx" => "int",
        "OpTxInputIsCoinbase" | "checkSig" | "checkSigFromStack" | "checkSigFromStackECDSA" => "bool",
        "blake2b" | "blake2bWithKey" | "blake3" | "blake3WithKey" | "templateHash" | "sha256" | "OpSha256" => "byte[32]",
        "OpInputCovenantId" | "OpOutputCovenantId" => "byte[32]",
        "bytes"
        | "OpTxSubnetId"
        | "OpTxPayloadSubstr"
        | "OpOutpointTxId"
        | "OpTxInputScriptSigSubstr"
        | "OpTxInputSeq"
        | "OpTxInputSpkSubstr"
        | "OpTxOutputSpkSubstr"
        | "OpNum2Bin"
        | "OpChainblockSeqCommit"
        | "LockingBytecodeNullData" => "byte[]",
        _ => return None,
    };
    parse_type_ref(name).ok()
}

pub(super) fn constructor_return_type(name: &str) -> Option<TypeRef> {
    parse_type_ref(match name {
        "LockingBytecodeNullData" => "byte[]",
        "ScriptPubKeyP2PK" => "byte[34]",
        "ScriptPubKeyP2SH" | "ScriptPubKeyP2SHFromRedeemScript" => "byte[35]",
        _ => return None,
    })
    .ok()
}

pub(super) fn builtin_parameters(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match name {
        "checkSigFromStack" => Some(&[("signature", "datasig"), ("digest", "byte[32]"), ("publicKey", "pubkey")]),
        "checkSigFromStackECDSA" => Some(&[("signature", "datasig"), ("digest", "byte[32]"), ("publicKey", "byte[33]")]),
        "blake3WithKey" => Some(&[("data", "byte[]"), ("key", "byte[32]")]),
        _ => None,
    }
}
