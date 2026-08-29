# Undefined behaviour

SilverScript has undefined behaviour when a source operation reaches a case
outside the language's defined semantics. The compiler is not required to
reject such a contract.

Undefined behaviour is not guaranteed to make execution fail. The compiler
may remove, replace, fold, or avoid evaluating a statement, expression, or
subexpression which would encounter undefined behaviour. If the resulting
contract completes successfully, its result is `true` and the spend succeeds.
It is also permitted to fail. Intermediate expression values are not
specified.

In particular, a contract must never use undefined behaviour as an implicit
check which it expects to reject a transaction. A failure caused only by
undefined behaviour is not an observable side effect whose evaluation the
compiler must preserve.

For example, the compiler may remove the unused definition below, including
the division. The contract is permitted to succeed:

```sil
contract C() {
    entry main() {
        int unused = 1 / 0;
        require(true);
    }
}
```

Before relying on an operation's result, the contract must validate all
run-time values needed to satisfy the preconditions below. A failed `require`,
an unsatisfied time constraint, an explicit termination, or a failed
zero-knowledge proof is an intentional validation failure and is not
classified as undefined behaviour here.

## Integer expressions

Run-time integers must be representable by the script integer format. In
practice, an integer used by a numeric expression must fit in at most eight
signed-magnitude bytes. The value `-2^63` is therefore not a usable run-time
integer, even though it fits in Rust's `i64` type.

The following cases are undefined behaviour:

- Unary negation when the result is not representable.
- Integer addition, subtraction, or multiplication when the result is not
  representable.
- Division when the divisor is zero, or when the result is not representable.
- Remainder (`%`) when the divisor is zero.
- Numeric, comparison, or boolean expressions applied to a value whose actual
  run-time representation is not a valid integer for that operation. This can
  happen after a cast which asserts a type without validating the bytes.

For example, `b` must be checked before the division:

```sil
entry main(int a, int b) {
    require(b != 0);
    int quotient = a / b;
}
```

Arithmetic overflow must likewise be ruled out by the contract's accepted
input range:

```sil
entry main(int a, int b) {
    // Undefined if the mathematical sum is outside the supported range.
    int sum = a + b;
}
```

Converting an integer to `byte[N]` is undefined if the value does not fit in
exactly `N` signed-magnitude bytes. The same requirement applies when an
integer is encoded as an element of `int[]` or as an integer state field.

```sil
entry main(int value) {
    // Undefined when value cannot be represented in two bytes.
    byte[2] encoded = value as byte[2];
}
```

The low-level forms which convert bytes to an integer or request a run-time
integer encoding width have the corresponding requirements: the input must be
at most eight bytes, the requested width must be between zero and eight, and
the integer must fit in the requested width.

## Arrays, strings, and fixed-byte values

### Evaluation and fixed lengths

When the size of a value is known statically, the compiler may replace
`.length` with that size without evaluating the value used as its receiver.
Expressions inside an array literal are therefore not guaranteed to run when
only the array's fixed length is observed.

```sil
contract C() {
    entry main() {
        // The length may be folded to 1 and the division omitted.
        require(int[1]{1 / 0}.length == 1);
    }
}
```

The same optimization freedom applies when the fixed-size value is reached
through a constant, cast, function result, conditional expression, or another
compound expression.

### Indexing

For `value[index]`, `index` must be non-negative and strictly less than
`value.length`. This applies to every array element type, including arrays of
structs and multidimensional arrays.

```sil
entry main(byte[] data, int index) {
    require(index >= 0);
    require(index < data.length);
    byte selected = data[index];
}
```

### Struct arrays

A struct array is represented by a separate encoded array for every scalar
leaf of the struct. Nested struct fields therefore produce additional leaf
arrays. A valid struct-array value must satisfy both of these conditions:

- Every leaf array contains the same number of struct elements.
- Every leaf array's byte length is a multiple of that leaf's encoded element
  size.

Supplying or producing a struct array which violates either condition, and
then using it as a struct array, is undefined behaviour. This includes field
access, indexing, assignment, function arguments and returns, `.split()`,
`.slice()`, and `.append()`.

The value of `items.length` may be obtained from only one leaf. It does not
validate the cardinality of the other leaves. Consequently, checking
`items.length` before indexing is insufficient unless the external encoding
or the code which constructed `items` already guarantees that all leaves have
matching cardinalities.

```sil
struct Item { int number; byte[2] tag; }

entry main(Item[] items) {
    // Suppose the encoded `number` leaf contains one element while the
    // encoded `tag` leaf is empty. This check may still pass because length
    // can be derived from the `number` leaf.
    require(items.length == 1);

    // This is undefined: the complete Item at index zero does not exist.
    // Execution may fail, but it is not guaranteed to fail; if it returns,
    // the contract result is true.
    Item first = items[0];
}
```

Only the leaf used to determine the length needs to be retained. Expressions
which construct other leaves may be omitted entirely:

```sil
contract C() {
    struct Item { int safe; int checked; }

    entry main() {
        // The `safe` leaf is enough to determine the length. Construction of
        // the `checked` leaf, including its division, may be optimized away.
        require(Item[]{Item {safe: 1, checked: 1 / 0}}.length == 1);
    }
}
```

Neither malformed leaf cardinality nor an undefined expression in an omitted
leaf is guaranteed to cause failure. If the resulting contract completes, its
result is `true`.

### Splitting

For `value.split(index)`, the index must satisfy
`0 <= index <= value.length`. An index equal to the length is allowed and
produces an empty right part.

```sil
entry main(byte[] data, int index) {
    require(index >= 0);
    require(index <= data.length);
    (byte[] left, byte[] right) = data.split(index);
}
```

### Slicing

For `value.slice(start, end)`, the bounds must satisfy
`0 <= start <= end <= value.length`. The end is exclusive.

```sil
entry main(byte[] data, int start, int end) {
    require(start >= 0);
    require(start <= end);
    require(end <= data.length);
    byte[] part = data.slice(start, end);
}
```

These split and slice rules also apply to strings, fixed-byte values such as
public keys and signatures, arrays whose elements occupy multiple bytes, and
arrays of structs. Bounds are counted in source-level elements, not bytes.

### Bitwise expressions

Both operands of byte-array `&`, `|`, and `^` expressions must have the same
run-time byte length. Equal dynamic types alone do not guarantee equal lengths.

```sil
entry main(byte[] a, byte[] b) {
    require(a.length == b.length);
    byte[] combined = a ^ b;
}
```

### Concatenation, literals, and append

A run-time array literal, string or array concatenation, and `.append()` must
not create a single encoded value larger than the execution environment's
maximum element size. The current limit is 1,000,000 bytes.

```sil
entry main(byte[] prefix, byte[] suffix) {
    // The caller must ensure the combined value remains within the limit.
    byte[] combined = prefix + suffix;
    byte[] extended = combined.append(byte(0xff));
}
```

The same limit applies to the encoded leaves of struct arrays and to temporary
values created while constructing or replacing structs.

### Cast layout assumptions

Casts between byte-backed types assert that the source already has the target
layout; they do not necessarily validate that layout at run time. Any later
index, split, slice, bitwise expression, signature check, or state operation is
undefined if that assertion was false.

```sil
entry main(byte[] raw) {
    byte[4] claimed = byte[4](raw);
    // Undefined unless raw really contained four bytes.
    byte last = claimed[3];
}
```

## Transaction and state expressions

Every expression which selects a transaction input or output requires a
non-negative index below the corresponding transaction count. This applies to
value, script-public-key, signature-script, outpoint, sequence, DAA-score,
coinbase, covenant-id, and related lookups.

```sil
entry main(int inputIndex, int outputIndex) {
    require(inputIndex >= 0);
    require(inputIndex < tx.inputs.length);
    require(outputIndex >= 0);
    require(outputIndex < tx.outputs.length);

    int inputValue = tx.inputs[inputIndex].value;
    int outputValue = tx.outputs[outputIndex].value;
}
```

Low-level transaction substring expressions additionally require
`0 <= start <= end <= selectedValue.length`. A selected substring must also
fit within the maximum element size.

Expressions which select the `k`th authorizing output, covenant input, or
covenant output require `k` to be non-negative and below the corresponding
count. The input index used for an authorizing-output lookup must itself be a
valid transaction input index.

State-reading expressions require both a valid input index and an input whose
signature script contains the expected contract and state layout. Template
prefix and suffix lengths must be non-negative, must describe ranges within
the actual script, and must not overflow while offsets are calculated.

How the selected state region is framed is not part of that precondition. The
compiler emits a check that each field carries the canonical push header for
its width, so a region framed any other way fails validation rather than
producing an unspecified field value.

```sil
entry main(int inputIndex) {
    require(inputIndex >= 0);
    require(inputIndex < tx.inputs.length);
    State previous = readInputState(inputIndex);
}
```

The same rules apply to `readInputStateWithTemplate`. In addition, its supplied
template lengths must match the template layout used by the selected input.

Output-state validation requires a valid output index. Variants which obtain a
template from an input also require a valid template-input index and valid
template ranges. State values must be encodable in their declared layouts, and
the reconstructed script must stay within the maximum element size.

```sil
entry main(int outputIndex, int nextValue) {
    require(outputIndex >= 0);
    require(outputIndex < tx.outputs.length);
    validateOutputState(outputIndex, State { value: nextValue });
}
```

A chain-block sequence-commit lookup is undefined when the supplied block is
unknown or already pruned, is not in the selected chain, or is deeper than the
available commitment window.

## Cryptographic expressions

Signature-checking expressions require structurally valid signatures and
public keys. A structurally valid but cryptographically incorrect signature
evaluates to `false`; malformed encoding, an unsupported signature hash type,
or a malformed public key is undefined behaviour. Message-signature checks
also require a digest of the required length.

```sil
entry main(byte[] rawSignature, byte[] rawKey) {
    // These casts assert the layouts. The caller must supply valid encodings.
    sig signature = sig(rawSignature);
    pubkey key = pubkey(rawKey);
    bool valid = checkSig(signature, key);
}
```

For keyed hashing, the Blake2b key must be at most 64 bytes and the Blake3 key
must be exactly 32 bytes. A cast to a fixed-size key does not make a value with
the wrong run-time length valid.

```sil
entry main(byte[] data, byte[] key) {
    require(key.length <= 64);
    byte[32] digest = blake2bWithKey(data, key);
}
```

## Loops

A run-time `for` range uses integer subtraction to validate its range and
integer addition to advance it. Both `end - start` and every increment through
the final iteration must remain representable. The loop body inherits all
other undefined-behaviour rules in this document.

```sil
entry main(int start, int end) {
    // The accepted bounds must also rule out arithmetic overflow.
    for (i, start, end, 100) {
        require(i >= start);
    }
}
```