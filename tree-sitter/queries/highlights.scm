(comment) @comment

(string_literal) @string

(number_literal) @number

(hex_literal) @number

(boolean_literal) @boolean

(date_literal) @function.builtin

(type_name) @type

(instantiation
  (identifier) @type.builtin
  (#match? @type.builtin
    "^(LockingBytecodeNullData|ScriptPubKeyP2PK|ScriptPubKeyP2SH|ScriptPubKeyP2SHFromRedeemScript)$"))

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

(nullary_op) @variable.builtin

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
    "^(readInputState|readInputStateWithTemplate|validateOutputState|validateOutputStateWithTemplate|verifyOutputState|verifyOutputStates|OpSha256|sha256|OpTxSubnetId|OpTxGas|OpTxPayloadLen|OpTxPayloadSubstr|OpOutpointTxId|OpOutpointIndex|OpTxInputScriptSigLen|OpTxInputScriptSigSubstr|OpTxInputSeq|OpTxInputIsCoinbase|OpTxInputSpkLen|OpTxInputSpkSubstr|OpTxOutputSpkLen|OpTxOutputSpkSubstr|OpAuthOutputCount|OpAuthOutputIdx|OpInputCovenantId|OpCovInputCount|OpCovInputIdx|OpCovOutputCount|OpCovOutputIdx|OpNum2Bin|OpBin2Num|OpChainblockSeqCommit|checkDataSig|checkSig|checkMultiSig|blake2b)$"))

(unary_suffix) @property

(split_call
  ".split" @function.method)

(slice_call
  ".slice" @function.method)

(reverse_call
  ".reverse" @function.method)

(array_bound) @number

[
  "pragma"
  "silverscript"
  "contract"
  "entrypoint"
  "function"
  "constant"
  "if"
  "else"
  "for"
  "new"
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
