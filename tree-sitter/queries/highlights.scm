(comment) @comment

(string_literal) @string

(number_literal) @number

(hex_literal) @number

(boolean_literal) @boolean

(date_literal) @function.builtin

(type_name) @type

(array_type) @type

(instantiation
  (identifier) @type.builtin
  (#match? @type.builtin "^(ScriptPubKeyP2PK|ScriptPubKeyP2SH|ScriptPubKeyP2SHFromRedeemScript)$"))

(instantiation
  (identifier) @type)

(contract_definition
  name: (identifier) @type)

(function_definition
  name: (identifier) @function)

(constant_definition
  name: (identifier) @constant)

(contract_field_definition
  name: (identifier) @property)

(variable_definition
  name: (identifier) @variable)

(parameter
  (identifier) @variable.parameter)

(tx_var) @variable.builtin

(introspection) @variable.builtin

(output_root) @variable.builtin

(input_root) @variable.builtin

(tuple_index
  "[" @operator
  "]" @operator)

(output_field
  "." @operator)

(input_field
  "." @operator)

(output_field_name) @property

(input_field_name) @property

(state_entry
  (identifier) @property)

(state_typed_binding
  (identifier) @property
  ":"
  (type_name)
  (identifier) @variable)

(function_call
  (identifier) @function.builtin
  (#match? @function.builtin
    "^(readInputState|readInputStateWithTemplate|validateOutputState|validateOutputStateWithTemplate|validateOutputStateWithInputTemplate|verifyOutputState|verifyOutputStates|sha256|OpTxSubnetId|OpTxGas|OpTxPayloadLen|OpTxPayloadSubstr|OpOutpointTxId|OpOutpointIndex|OpTxInputScriptSigLen|OpTxInputScriptSigSubstr|OpTxInputSeq|OpTxInputIsCoinbase|OpTxInputSpkLen|OpTxInputSpkSubstr|OpTxOutputSpkLen|OpTxOutputSpkSubstr|OpAuthOutputCount|OpAuthOutputIdx|OpInputCovenantId|OpOutputCovenantId|OpCovInputCount|OpCovInputIdx|OpCovOutputCount|OpCovOutputIdx|OpNum2Bin|OpBin2Num|OpChainblockSeqCommit|checkMsgSig|checkMsgSigEcdsa|checkSigEcdsa|checkSig|checkMultiSig|blake2b|blake2bWithKey|blake3|blake3WithKey|templateHash)$"))

(call_statement
  (member_access
    name: (identifier) @function.builtin)
  .
  (call_suffix))

(postfix
  (postfix_op
    (member_access
      name: (identifier) @function.builtin))
  .
  (postfix_op
    (call_suffix)))

(unary_suffix) @property

(split_call
  ".split" @function.method)

(slice_call
  ".slice" @function.method)

(array_bound) @number

[
  "pragma"
  "silverscript"
  "contract"
  "entry"
  "function"
  "constant"
  "if"
  "else"
  "for"
  "new"
  "as"
  "require"
  "return"
  "console.log"
] @keyword

[
  "||"
  "&&"
  "=="
  "!="
  "<"
  "<="
  ">"
  ">="
  "+"
  "-"
  "*"
  "/"
  "%"
  "!"
  "&"
  "|"
  "^"
  "="
] @operator
