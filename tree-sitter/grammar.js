/**
 * @file Kaspa SilverScript Lang
 * @author Kaspa Developers
 * @license ISC
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

const PREC = {
  LOGICAL_OR: 1,
  LOGICAL_AND: 2,
  BIT_OR: 3,
  BIT_XOR: 4,
  BIT_AND: 5,
  EQUALITY: 6,
  COMPARISON: 7,
  TERM: 8,
  FACTOR: 9,
  UNARY: 10,
  POSTFIX: 11,
};

export default grammar({
  name: "silverscript",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) =>
      choice($.contract_source_file, $.declaration_source_file),

    contract_source_file: ($) =>
      seq(repeat($.pragma_directive), $.contract_definition),

    declaration_source_file: ($) => repeat1($.builtin_function_declaration),

    pragma_directive: ($) => seq("pragma", "silverscript", $.pragma_value, ";"),

    pragma_value: ($) =>
      seq($.version_constraint, optional($.version_constraint)),

    version_constraint: ($) =>
      seq(optional($.version_operator), $.version_literal),

    version_operator: (_) => choice("^", "~", ">=", ">", "<=", "<", "="),

    version_literal: (_) => token(/\d+\.\d+\.\d+/),

    contract_definition: ($) =>
      seq(
        "contract",
        field("name", $.identifier),
        $.parameter_list,
        "{",
        repeat($.contract_item),
        "}",
      ),

    contract_item: ($) =>
      choice(
        $.struct_definition,
        $.constant_definition,
        $.contract_field_definition,
        $.function_definition,
      ),

    struct_definition: ($) =>
      seq(
        "struct",
        field("name", $.identifier),
        "{",
        repeat($.struct_field_definition),
        "}",
      ),

    struct_field_definition: ($) =>
      seq($.type_name, field("name", $.identifier), ";"),

    function_definition: ($) =>
      seq(
        repeat($.function_attribute),
        optional("entrypoint"),
        "function",
        field("name", $.identifier),
        $.parameter_list,
        optional($.return_type_list),
        $.braced_block,
      ),

    builtin_function_declaration: ($) =>
      seq(
        "function",
        field("name", $.identifier),
        $.parameter_list,
        optional($.return_type_list),
        ";",
      ),

    function_attribute: ($) =>
      seq("#[", $.attribute_path, optional($.attribute_args), "]"),

    attribute_path: ($) => seq($.identifier, repeat(seq(".", $.identifier))),

    attribute_args: ($) => seq("(", optional(commaSep($.attribute_arg)), ")"),

    attribute_arg: ($) =>
      seq(field("name", $.identifier), "=", field("value", $.expression)),

    constant_definition: ($) =>
      seq(
        $.type_name,
        "constant",
        field("name", $.identifier),
        "=",
        field("value", $.expression),
        ";",
      ),

    contract_field_definition: ($) =>
      seq(
        $.type_name,
        field("name", $.identifier),
        "=",
        field("value", $.expression),
        ";",
      ),

    parameter_list: ($) => seq("(", optional(commaSep($.parameter)), ")"),

    parameter: ($) => seq($.type_name, $.identifier),

    return_type_list: ($) =>
      seq(
        ":",
        choice($.type_name, seq("(", optional(commaSep($.type_name)), ")")),
      ),

    block: ($) => $.statement,

    braced_block: ($) => seq("{", repeat($.statement), "}"),

    statement: ($) =>
      choice(
        $.variable_definition,
        $.tuple_assignment,
        $.push_statement,
        $.state_function_call_assignment,
        $.struct_destructure_assignment,
        $.function_call_assignment,
        $.call_statement,
        $.return_statement,
        $.assign_statement,
        $.time_op_statement,
        $.require_statement,
        $.if_statement,
        $.for_statement,
        $.braced_block,
        $.console_statement,
      ),

    variable_definition: ($) =>
      seq(
        $.type_name,
        repeat($.modifier),
        field("name", $.identifier),
        optional(seq("=", field("value", $.expression))),
        ";",
      ),

    tuple_assignment: ($) =>
      seq(
        $.type_name,
        $.identifier,
        ",",
        $.type_name,
        $.identifier,
        "=",
        $.expression,
        ";",
      ),

    push_statement: ($) =>
      seq(field("name", $.identifier), ".push", "(", $.expression, ")", ";"),

    function_call_assignment: ($) =>
      seq("(", commaSep($.typed_binding), ")", "=", $.function_call, ";"),

    state_function_call_assignment: ($) =>
      prec(
        1,
        seq(
          "{",
          commaSep($.state_typed_binding),
          "}",
          "=",
          $.function_call,
          ";",
        ),
      ),

    struct_destructure_assignment: ($) =>
      seq("{", commaSep($.state_typed_binding), "}", "=", $.expression, ";"),

    typed_binding: ($) => seq($.type_name, $.identifier),

    state_typed_binding: ($) =>
      seq($.identifier, ":", $.type_name, $.identifier),

    call_statement: ($) => seq($.function_call, ";"),

    return_statement: ($) =>
      seq("return", choice($.return_expression_list, $.expression), ";"),

    return_expression_list: ($) =>
      seq(
        "(",
        $.expression,
        ",",
        optional(
          seq($.expression, repeat(seq(",", $.expression)), optional(",")),
        ),
        ")",
      ),

    assign_statement: ($) =>
      seq(field("name", $.identifier), "=", field("value", $.expression), ";"),

    time_op_statement: ($) =>
      seq(
        "require",
        "(",
        $.tx_var,
        ">=",
        $.expression,
        optional(seq(",", $.require_message)),
        ")",
        ";",
      ),

    require_statement: ($) =>
      seq(
        "require",
        "(",
        $.expression,
        optional(seq(",", $.require_message)),
        ")",
        ";",
      ),

    require_message: ($) => $.string_literal,

    if_statement: ($) =>
      prec.right(
        seq(
          "if",
          "(",
          $.expression,
          ")",
          $.statement,
          optional(seq("else", $.statement)),
        ),
      ),

    for_statement: ($) =>
      seq(
        "for",
        "(",
        $.identifier,
        ",",
        $.expression,
        ",",
        $.expression,
        ",",
        $.expression,
        ")",
        $.statement,
      ),

    console_statement: ($) => seq("console.log", $.console_parameter_list, ";"),

    console_parameter_list: ($) =>
      seq("(", optional(commaSep($.console_parameter)), ")"),

    console_parameter: ($) => $.expression,

    expression: ($) => $.logical_or,

    logical_or: ($) =>
      prec.left(
        PREC.LOGICAL_OR,
        seq($.logical_and, repeat(seq("||", $.logical_and))),
      ),

    logical_and: ($) =>
      prec.left(PREC.LOGICAL_AND, seq($.bit_or, repeat(seq("&&", $.bit_or)))),

    bit_or: ($) =>
      prec.left(PREC.BIT_OR, seq($.bit_xor, repeat(seq("|", $.bit_xor)))),

    bit_xor: ($) =>
      prec.left(PREC.BIT_XOR, seq($.bit_and, repeat(seq("^", $.bit_and)))),

    bit_and: ($) =>
      prec.left(PREC.BIT_AND, seq($.equality, repeat(seq("&", $.equality)))),

    equality: ($) =>
      prec.left(
        PREC.EQUALITY,
        seq($.comparison, repeat(seq(choice("==", "!="), $.comparison))),
      ),

    comparison: ($) =>
      prec.left(
        PREC.COMPARISON,
        seq($.term, repeat(seq(choice("<=", "<", ">=", ">"), $.term))),
      ),

    term: ($) =>
      prec.left(
        PREC.TERM,
        seq($.factor, repeat(seq(choice("+", "-"), $.factor))),
      ),

    factor: ($) =>
      prec.left(
        PREC.FACTOR,
        seq($.unary, repeat(seq(choice("*", "/", "%"), $.unary))),
      ),

    unary: ($) => prec.right(PREC.UNARY, seq(repeat($.unary_op), $.postfix)),

    unary_op: (_) => choice("!", "-"),

    postfix: ($) =>
      prec.left(PREC.POSTFIX, seq($.primary, repeat($.postfix_op))),

    postfix_op: ($) =>
      choice(
        $.tuple_index,
        $.unary_suffix,
        $.split_call,
        $.slice_call,
        $.reverse_call,
        $.field_access,
      ),

    tuple_index: ($) => seq("[", $.expression, "]"),

    unary_suffix: (_) => ".length",

    split_call: ($) => seq(".split", "(", $.expression, ")"),

    slice_call: ($) => seq(".slice", "(", $.expression, ",", $.expression, ")"),

    reverse_call: (_) => seq(".reverse", "(", ")"),

    field_access: ($) => seq(".", field("name", $.identifier)),

    primary: ($) =>
      choice(
        $.parenthesized,
        $.cast,
        $.function_call,
        $.instantiation,
        $.state_object,
        $.introspection,
        $.array,
        $.nullary_op,
        $.identifier,
        $.literal,
      ),

    parenthesized: ($) => seq("(", $.expression, ")"),

    // type_name("(" expression ("," expression)? ","? ")"
    cast: ($) =>
      seq(
        $.cast_type_name,
        "(",
        $.expression,
        optional(seq(",", $.expression)),
        optional(","),
        ")",
      ),

    cast_type_name: ($) => seq($.builtin_type, repeat($.array_suffix)),

    function_call: ($) => seq($.identifier, $.expression_list),

    expression_list: ($) => seq("(", optional(commaSep($.expression)), ")"),

    instantiation: ($) => seq("new", $.identifier, $.expression_list),

    state_object: ($) => seq("{", optional(commaSep($.state_entry)), "}"),

    state_entry: ($) => seq($.identifier, ":", $.expression),

    introspection: ($) =>
      choice(
        seq(
          field("root", $.output_root),
          field("index", $.tuple_index),
          field("field", $.output_field),
        ),
        seq(
          field("root", $.input_root),
          field("index", $.tuple_index),
          field("field", $.input_field),
        ),
      ),

    output_root: (_) => "tx.outputs",

    input_root: (_) => "tx.inputs",

    output_field: ($) => seq(".", field("name", $.output_field_name)),

    output_field_name: (_) => choice("value", "scriptPubKey"),

    input_field: ($) => seq(".", field("name", $.input_field_name)),

    input_field_name: (_) =>
      choice(
        "value",
        "scriptPubKey",
        "outpointTransactionHash",
        "outpointIndex",
        "sigScript",
      ),

    array: ($) => seq("[", optional(commaSep($.expression)), "]"),

    modifier: (_) => "constant",

    type_name: ($) => seq($.base_type, repeat($.array_suffix)),

    base_type: ($) => choice($.builtin_type, $.identifier),

    builtin_type: (_) =>
      choice("int", "bool", "string", "pubkey", "sig", "datasig", "byte"),

    array_suffix: ($) => seq("[", optional($.array_size), "]"),

    array_size: ($) => choice("_", $.identifier, $.array_bound),

    array_bound: (_) => token(/[1-9][0-9]*/),

    literal: ($) =>
      choice(
        $.boolean_literal,
        $.number_literal,
        $.string_literal,
        $.date_literal,
        $.hex_literal,
      ),

    boolean_literal: (_) => choice("true", "false"),

    number_literal: ($) => seq($.number, optional($.number_unit)),

    number_unit: (_) =>
      choice(
        "litras",
        "grains",
        "kas",
        "seconds",
        "minutes",
        "hours",
        "days",
        "weeks",
      ),

    // Pest: NumberLiteral = "-"? NumberPart ExponentPart?
    number: (_) => token(/-?\d+(?:_\d+)*(?:[eE]\d+(?:_\d+)*)?/),

    string_literal: (_) =>
      token(choice(/"([^"\\\n]|\\.)*"/, /'([^'\\\n]|\\.)*'/)),

    date_literal: ($) => seq("date", "(", $.string_literal, ")"),

    hex_literal: (_) => token(/0[xX][0-9a-fA-F]*/),

    tx_var: (_) => choice("this.age", "tx.time"),

    nullary_op: (_) =>
      choice(
        "this.activeInputIndex",
        "this.activeScriptPubKey",
        "this.scriptSizeDataPrefix",
        "this.scriptSize",
        "tx.inputs.length",
        "tx.outputs.length",
        "tx.version",
        "tx.locktime",
      ),

    identifier: (_) => token(prec(-1, /[A-Za-z][A-Za-z0-9_]*/)),

    comment: (_) =>
      token(choice(/\/\/[^\n]*/, /\/\*[^*]*\*+([^/*][^*]*\*+)*\//)),
  },
});

// item ("," item)* ","?
/**
 * @param {RuleOrLiteral} rule
 */
function commaSep(rule) {
  return seq(rule, repeat(seq(",", rule)), optional(","));
}
