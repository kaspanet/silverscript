use crate::ast::{ArrayDim, IntrospectionKind, NullaryOp, TypeBase, TypeRef};

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

pub(super) fn builtin_return(name: &str) -> Option<BuiltinReturn> {
    let value_type = match name {
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
        "length" => scalar(TypeBase::Int),
        "OpTxInputIsCoinbase" | "checkSig" | "checkSigFromStack" | "checkSigFromStackECDSA" => scalar(TypeBase::Bool),
        "r0.g16.verify"
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

pub(super) fn builtin_parameters(name: &str) -> Option<Vec<(&'static str, TypeRef)>> {
    match name {
        "readInputStateWithTemplate" => Some(vec![
            ("input_idx", scalar(TypeBase::Int)),
            ("template_prefix_len", scalar(TypeBase::Int)),
            ("template_suffix_len", scalar(TypeBase::Int)),
            ("expected_template_hash", byte_array(ArrayDim::Fixed(32))),
        ]),
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
        "r0.g16.verify" => Some(vec![
            ("journal_hash", byte_array(ArrayDim::Fixed(32))),
            ("proof", byte_array(ArrayDim::Dynamic)),
            ("image_id", byte_array(ArrayDim::Fixed(32))),
        ]),
        "r0.succinct.verify" | "r0.succinct.blake2b.verify" | "r0.succinct.poseidon2.verify" | "r0.succinct.sha256.verify" => {
            Some(vec![
                ("claim", byte_array(ArrayDim::Fixed(32))),
                ("control_index", byte_array(ArrayDim::Fixed(4))),
                ("control_digests", byte_array(ArrayDim::Dynamic)),
                ("seal", byte_array(ArrayDim::Dynamic)),
                ("journal", byte_array(ArrayDim::Fixed(32))),
                ("image_id", byte_array(ArrayDim::Fixed(32))),
                ("control_id", byte_array(ArrayDim::Fixed(32))),
            ])
        }
        "blake3WithKey" => Some(vec![("data", byte_array(ArrayDim::Dynamic)), ("key", byte_array(ArrayDim::Fixed(32)))]),
        _ => None,
    }
}
