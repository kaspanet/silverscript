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
    source_file: ($) => seq(repeat($.pragma_directive), $.contract_definition),

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

    contract_item: ($) => choice($.constant_definition, $.function_definition),

    function_definition: ($) =>
      seq(
        optional("entrypoint"),
        "function",
        field("name", $.identifier),
        $.parameter_list,
        optional($.return_type_list),
        "{",
        repeat($.statement),
        "}",
      ),

    constant_definition: ($) =>
      seq(
        $.type_name,
        "constant",
        field("name", $.identifier),
        "=",
        field("value", $.expression),
        ";",
      ),

    parameter_list: ($) => seq("(", optional(commaSep($.parameter)), ")"),

    parameter: ($) => seq($.type_name, $.identifier),

    return_type_list: ($) =>
      seq(":", "(", optional(commaSep($.type_name)), ")"),

    block: ($) => choice(seq("{", repeat($.statement), "}"), $.statement),

    block_no_else: ($) =>
      choice(seq("{", repeat($.statement), "}"), $.statement_no_else),

    statement: ($) =>
      choice(
        $.variable_definition,
        $.tuple_assignment,
        $.push_statement,
        $.function_call_assignment,
        $.call_statement,
        $.return_statement,
        $.assign_statement,
        $.time_op_statement,
        $.require_statement,
        $.if_statement,
        $.for_statement,
        $.yield_statement,
        $.console_statement,
      ),

    statement_no_else: ($) =>
      choice(
        $.variable_definition,
        $.tuple_assignment,
        $.push_statement,
        $.function_call_assignment,
        $.call_statement,
        $.return_statement,
        $.assign_statement,
        $.time_op_statement,
        $.require_statement,
        $.if_statement_no_else,
        $.for_statement,
        $.yield_statement,
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

    typed_binding: ($) => seq($.type_name, $.identifier),

    call_statement: ($) => seq($.function_call, ";"),

    return_statement: ($) => seq("return", $.expression_list, ";"),

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
        seq("if", "(", $.expression, ")", $.block_no_else, "else", $.block),
      ),

    if_statement_no_else: ($) =>
      prec.right(seq("if", "(", $.expression, ")", $.block_no_else)),

    for_statement: ($) =>
      seq(
        "for",
        "(",
        $.identifier,
        ",",
        $.expression,
        ",",
        $.expression,
        ")",
        $.block,
      ),

    yield_statement: ($) => seq("yield", $.expression_list, ";"),

    console_statement: ($) => seq("console.log", $.console_parameter_list, ";"),

    console_parameter_list: ($) =>
      seq("(", optional(commaSep($.console_parameter)), ")"),

    console_parameter: ($) => choice($.identifier, $.literal),

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
      choice($.tuple_index, $.unary_suffix, $.split_call, $.slice_call),

    tuple_index: ($) => seq("[", $.expression, "]"),

    unary_suffix: (_) => ".length",

    split_call: ($) => seq(".split", "(", $.expression, ")"),

    slice_call: ($) => seq(".slice", "(", $.expression, ",", $.expression, ")"),

    primary: ($) =>
      choice(
        $.parenthesized,
        $.cast,
        $.function_call,
        $.instantiation,
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
        $.type_name,
        "(",
        $.expression,
        optional(seq(",", $.expression)),
        optional(","),
        ")",
      ),

    function_call: ($) => seq($.identifier, $.expression_list),

    expression_list: ($) => seq("(", optional(commaSep($.expression)), ")"),

    instantiation: ($) => seq("new", $.identifier, $.expression_list),

    introspection: ($) =>
      choice(
        seq("tx.outputs", "[", $.expression, "]", $.output_field),
        seq("tx.inputs", "[", $.expression, "]", $.input_field),
      ),

    output_field: ($) =>
      seq(
        ".",
        choice(
          "value",
          "lockingBytecode",
          "tokenCategory",
          "nftCommitment",
          "tokenAmount",
        ),
      ),

    input_field: ($) =>
      seq(
        ".",
        choice(
          "value",
          "lockingBytecode",
          "outpointTransactionHash",
          "outpointIndex",
          "unlockingBytecode",
          "sequenceNumber",
          "tokenCategory",
          "nftCommitment",
          "tokenAmount",
        ),
      ),

    array: ($) => seq("[", optional(commaSep($.expression)), "]"),

    modifier: (_) => "constant",

    type_name: ($) => seq($.base_type, optional($.array_suffix)),

    base_type: ($) =>
      choice("int", "bool", "string", "pubkey", "sig", "datasig", $.bytes_type),

    array_suffix: (_) => "[]",

    bytes_type: (_) =>
      choice("byte", "bytes", token(prec(1, /bytes[1-9][0-9]*/))),

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
        "this.activeBytecode",
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
