(comment) @comment

(string_literal) @string

(number_literal) @number

(hex_literal) @number

(boolean_literal) @boolean

(date_literal) @function.builtin

(type_name) @type

(bytes_type) @type

(contract_definition
  name: (identifier) @type)

(function_definition
  name: (identifier) @function)

(constant_definition
  name: (identifier) @constant)

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

(unknown_field
  "." @operator)

(output_field_name) @property

(input_field_name) @property

(unknown_field
  name: (identifier) @property)

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
  "yield"
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
