# SilverScript Tutorial

## Table of Contents

1. [Introduction](#introduction)
2. [Compiling Contracts](#compiling-contracts)
   - [Using the CLI (silverc)](#using-the-cli-silverc)
   - [Programmatic Compilation](#programmatic-compilation)
3. [Language Basics](#language-basics)
   - [Contract Structure](#contract-structure)
   - [Pragma Directives](#pragma-directives)
   - [Data Types](#data-types)
   - [Variables](#variables)
   - [Comments](#comments)
4. [Functions](#functions)
   - [Function Definition](#function-definition)
   - [Entrypoint Functions](#entrypoint-functions)
   - [Function Parameters and Return Types](#function-parameters-and-return-types)
5. [Operators](#operators)
   - [Arithmetic Operators](#arithmetic-operators)
   - [Comparison Operators](#comparison-operators)
   - [Logical Operators](#logical-operators)
   - [Bitwise Operators](#bitwise-operators)
   - [Ternary Operator](#ternary-operator)
6. [Control Flow](#control-flow)
   - [If Statements](#if-statements)
   - [Require Statements](#require-statements)
   - [Time and DAA Locks](#time-and-daa-locks)
   - [For Loops](#for-loops)
7. [Working with Data](#working-with-data)
   - [Literals](#literals)
   - [Number Units](#number-units)
   - [Date Literals](#date-literals)
   - [Arrays](#arrays)
   - [String Operations](#string-operations)
   - [Bytes Operations](#bytes-operations)
8. [Type Casting](#type-casting)
9. [Built-in Functions](#built-in-functions)
   - [Cryptographic Functions](#cryptographic-functions)
   - [Type Conversions](#type-conversions)
10. [Transaction Introspection](#transaction-introspection)
    - [Transaction Fields](#transaction-fields)
    - [Input Introspection](#input-introspection)
    - [Output Introspection](#output-introspection)
11. [Covenants](#covenants)
    - [Creating ScriptPubKey](#creating-scriptpubkey)
    - [State Transition Builtins](#state-transition-builtins)
    - [Covenant Examples](#covenant-examples)
12. [Advanced Features](#advanced-features)
    - [Constants](#constants)
    - [Tuple Unpacking](#tuple-unpacking)
    - [Split and Slice Operations](#split-and-slice-operations)
13. [Complete Examples](#complete-examples)
    - [Pay-to-Public-Key (P2PK)](#pay-to-public-key-p2pk)
    - [Transfer with Timeout](#transfer-with-timeout)
    - [Recurring Payment (Mecenas)](#recurring-payment-mecenas)

---

## Introduction

SilverScript is a CashScript-inspired smart contract language that compiles to Kaspa script. It enables you to write Kaspa smart contracts with a high-level, Solidity-like syntax. SilverScript contracts can enforce complex spending conditions, create covenants, and enable advanced cryptocurrency applications on the Kaspa network.

---

## Compiling Contracts

### Using the CLI (silverc)

The `silverc` command-line tool compiles `.sil` source files into JSON artifacts containing the compiled bytecode and ABI.

**Basic Usage:**

```bash
silverc contract.sil
```

This reads `contract.sil` and outputs `contract.json` by default.

**Specify Output File:**

```bash
silverc contract.sil -o output.json
```

**With Constructor Arguments:**

If your contract has constructor parameters, you can provide their values via a JSON file:

```bash
silverc contract.sil --constructor-args args.json
```

The `args.json` file should contain an array of portable ABI values. For example:

```json
[
  {"kind": "bytes", "value": [1, 2, 3, 4]},
  {"kind": "int", "value": 12345}
]
```

The output is a portable `SilAbiArtifact` JSON document containing:

- `schema_version`: The portable ABI schema version
- `states`: Struct definitions referenced by contract inputs and runtime state
- `contracts`: The compiled contract, its entries, dispatch tags, script, template hash, and state span

### Programmatic Compilation

You can also compile contracts programmatically using the SilverScript Rust library:

```rust
use silverscript_lang::compiler::sil_abi_artifact;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        pragma silverscript ^0.1.0;
        
        contract MyContract(int x) {
            entry spend(int y) {
                require(y > x);
            }
        }
    "#;
    
    // Constructor arguments (x = 100)
    let artifact = sil_abi_artifact(source, &[100.into()])?;
    let (contract_name, contract) = artifact.contracts.get_key_value("MyContract").expect("contract exists");

    println!("Contract name: {contract_name}");
    println!("Bytecode length: {} bytes", contract.compiled.bytecode.len());
    println!("Entries: {:?}", contract.entries);
    
    Ok(())
}
```

**Building Signature Scripts Programmatically:**

After compiling a contract, you can build signature scripts for its entries:

```rust
use silverscript_abi::encode_contract_entry_sig_script;
use silverscript_lang::compiler::sil_abi_artifact;

let source = r#"
    pragma silverscript ^0.1.0;
    
    contract TransferWithTimeout(pubkey sender, pubkey recipient, temporal timeout) {
        entry transfer(sig recipientSig) {
            require(checkSig(recipientSig, recipient));
        }
        
        entry reclaim(sig senderSig) {
            require(checkSig(senderSig, sender));
            require(tx.time >= timeout);
        }
    }
"#;

let sender_pk = vec![3u8; 32];
let recipient_pk = vec![4u8; 32];
let timeout = 1640000000000i64;
let artifact = sil_abi_artifact(
    source,
    &[sender_pk.into(), recipient_pk.into(), timeout.into()],
)?;

// Build sigscript for multiple entrypoints
let sig = vec![5u8; 65];

// For the 'transfer' entrypoint
let transfer_sigscript = encode_contract_entry_sig_script(
    &artifact,
    "TransferWithTimeout",
    "transfer",
    &[sig.clone().into()],
)?;
// transfer_sigscript contains: <signature> <4-byte KCC-01 dispatch tag>

// For the 'reclaim' entrypoint
let reclaim_sigscript = encode_contract_entry_sig_script(
    &artifact,
    "TransferWithTimeout",
    "reclaim",
    &[sig.into()],
)?;
// reclaim_sigscript contains: <signature> <4-byte KCC-01 dispatch tag>
```

`encode_contract_entry_sig_script` automatically:
- Validates argument count and types
- Encodes arguments properly for the Kaspa script stack
- Appends the KCC-01 function-signature dispatch tag

---

## Language Basics

### Contract Structure

Every SilverScript program defines a single contract. A contract has a name, optional constructor parameters, and one or more functions:

```javascript
pragma silverscript ^0.1.0;

contract MyContract(int param1, byte[32] param2) {
    // Contract constants (optional)
    int constant MAX_VALUE = 1000;
    
    // Functions
    entry spend(sig s, pubkey pk) {
        require(checkSig(s, pk));
    }
}
```

### Pragma Directives

Every contract should start with a pragma directive specifying the SilverScript version requirement:

```javascript
pragma silverscript ^0.1.0;
```

Pragma values use standard semver requirements. See [semver.org](https://semver.org/) for more details.

### Data Types

SilverScript supports the following data types:

| Type | Description | Example |
|------|-------------|---------|
| `int` | 64-bit signed integer | `42`, `-100`, `1000` |
| `temporal` | 64-bit signed time value in milliseconds | `temporal(1640000000000)`, `30 seconds` |
| `bool` | Boolean value | `true`, `false` |
| `string` | UTF-8 string | `"hello"`, `'world'` |
| `byte` | Single byte | `byte` |
| `pubkey` | Public key (32 bytes) | `pubkey` |
| `sig` | Signature (65 bytes) | `sig` |
| `datasig` | Data signature (64 bytes) | `datasig` |

`temporal` has the same representation and operators as `int`, including arithmetic,
negation, equality, and ordered comparisons. The types are deliberately distinct:
an operation cannot combine an `int` and a `temporal` without an explicit conversion.
Use `temporal(integerExpression)` or `int(temporalExpression)` to cross the boundary. Both
casts are compile-time type changes and emit no runtime conversion opcode.

**Array Types:**

You can create arrays by appending `[]` or `[N]` to any type:

```javascript
int[] numbers = int[]{};
int[4] fixedNumbers = int[4]{0, 0, 0, 0};
byte[] data = byte[]{};
byte[32] hash = byte[32](0x0000000000000000000000000000000000000000000000000000000000000000);
byte[32][] hashes = byte[32][]{};
pubkey[] publicKeys = pubkey[]{};
```

- `type[]` = dynamically sized array type.
- `type[_]` = fixed-size array type inferred from its initializer.
- `type[N]` = fixed-size array type with compile-time size `N`.

When a `type[]` variable is initialized with a literal, SilverScript infers a fixed size from context:

```javascript
byte[_] data = byte[_](0x1234abcd);  // inferred as byte[4]
int[_] nums = int[_]{1, 2, 3};   // inferred as int[3]
```

### Variables

Variables must be declared with their type before use:

```javascript
entry example() {
    // Variable declaration
    int myNumber = 42;
    bool flag = true;
    string message = "Hello World";

    // Array initialization
    byte[_] data = byte[_](0x1234abcd);
    int[_] nums = int[_]{1, 2, 3};
    int[4] fixed = int[4]{10, 20, 30, 40};
    
    // Variables require an initializer
    int initializedValue = 0;
    
    // Variable reassignment
    myNumber = 100;
}
```

### Comments

SilverScript supports both single-line and multi-line comments:

```javascript
// This is a single-line comment

/*
 * This is a multi-line comment
 * It can span multiple lines
 */

int x = 10; // Comments can appear at the end of lines
```

---

## Functions

### Function Definition

Functions are defined with the `function` keyword:

```javascript
function helper(int x, int y) {
    // function body
}
```

### Entrypoint Functions

Entrypoint functions are callable from outside the contract. Declare them with the `entry` keyword:

```javascript
entry spend(sig s, pubkey pk) {
    require(checkSig(s, pk));
}
```

A contract must have at least one entry. All contracts use KCC-01 dispatch tags technique.

### Function Parameters and Return Types

Functions can have multiple parameters. A function with one plain return value writes the
type directly after `:`:

```javascript
function add(int a, int b): int {
    return a + b;
}

// Using the return value
entry example() {
    int result = add(5, 10);
    require(result == 15);
}
```

Tuple return types are written in parentheses. A tuple with more than one value
can be destructured into typed bindings:

```javascript
function getPair(): (int, int) {
    return (10, 20);
}

entry example() {
    (int left, int right) = getPair();
    require(left + right == 30);
}
```

A parenthesized single return type is a one-element tuple, not the same as a
plain scalar return:

```javascript
function getWrapped(): (int) {
    return (7);
}

entry example() {
    int value = getWrapped().0;
    require(value == 7);
}
```

---

## Operators

### Arithmetic Operators

```javascript
int a = 10;
int b = 3;

int sum = a + b;        // 13
int difference = a - b;  // 7
int product = a * b;     // 30
int quotient = a / b;    // 3
int remainder = a % b;   // 1
int negative = -a;       // -10
```

### Comparison Operators

```javascript
int a = 10;
int b = 3;

bool eq = (a == b);   // false (equality)
bool ne = (a != b);   // true (inequality)
bool lt = (a < b);    // false (less than)
bool le = (a <= b);   // false (less than or equal)
bool gt = (a > b);    // true (greater than)
bool ge = (a >= b);   // true (greater than or equal)
```

The ordered operators `<`, `<=`, `>`, and `>=` accept only `int` operands.
Convert a `byte` explicitly with `unsigned(byteValue)` or `signed(byteValue)`
before ordering it. Equality and inequality remain available for other
compatible types.

### Logical Operators

```javascript
bool t = true;
bool f = false;

bool and = t && f;  // false (logical AND)
bool or = t || f;   // true (logical OR)
bool not = !t;      // false (logical NOT)
```

### Bitwise Operators

**Note:** Bitwise operators operate on two bytes or two equal-sized byte arrays. Two dynamic byte arrays may be used, but their sizes must match at runtime.

```javascript
byte[1] x = byte[_](0x0F);  // 00001111
byte[1] y = byte[_](0xF0);  // 11110000

byte[1] bitAnd = x & y;  // 0x00 (bitwise AND)
byte[1] bitOr = x | y;   // 0xFF (bitwise OR)
byte[1] bitXor = x ^ y;  // 0xFF (bitwise XOR)
```

### Ternary Operator

Use the ternary operator to choose between two expressions:

```javascript
bool condition = true;
int thenValue = 100;
int elseValue = 50;
int value = condition ? thenValue : elseValue;
```

The condition must evaluate to `bool`, and both result branches must have the same type. The ternary expression's result must also match the declared type where it is assigned or returned:

```javascript
entry example(int amount, bool useBonus) {
    int payout = useBonus ? amount + 100 : amount;
    require(payout >= amount);
}
```

---

## Control Flow

### If Statements

Basic if-else structure:

```javascript
entry example(int x) {
    if (x > 10) {
        require(true);
    } else if (x < 0) {
        require(false);
    } else {
        require(x == 5);
    }
}
```

Single-statement branches don't require braces:

```javascript
int x = 1;
if (x > 0)
    require(true);
else
    require(false);
```

### Require Statements

The `require` statement enforces conditions. If the condition is false, the contract execution fails:

```javascript
int x = 1;
require(x > 0);  // Passes if x > 0, fails otherwise

// With error message
require(x > 0, "x must be positive");
```

Time-based require statements:

```javascript
// Require transaction time
require(tx.time >= temporal(1640000000000));

// Require contract age
require(this.ageDaa >= 86400);  // 86,400 DAA-score units
```

### Time and DAA Locks

Absolute transaction locktimes have separate DAA-score and timestamp domains,
while relative UTXO ages use sequence locks:

- `tx.daa` accepts only an `int` threshold and emits an absolute CLTV lock in
  the DAA-score domain.
- `tx.time` accepts only a `temporal` threshold and emits an absolute CLTV lock
  in the Unix-millisecond timestamp domain. `date(...)` values are measured in
  milliseconds.
- `this.ageDaa` accepts only an `int` threshold. Its value is a relative
  DAA-score difference, not a duration in seconds or milliseconds.
- `tx.daa` values must satisfy `0 <= value < LOCK_TIME_THRESHOLD`, while
  `tx.time` values must satisfy `value >= LOCK_TIME_THRESHOLD`.
- A `this.ageDaa` threshold must satisfy `0 <= value < 2^32`. Known constants
  outside that range are rejected during compilation, and generated bytecode
  checks both bounds again for runtime values.

`LOCK_TIME_THRESHOLD` is `500_000_000_000`, corresponding to
1985-11-05T00:53:20Z in Unix milliseconds. Known out-of-domain constants are
rejected during compilation; dynamic thresholds are checked by the generated
script before CLTV executes.

```javascript
contract Locks(temporal unlockAt, int absoluteDaaScore, int relativeDaaAge) {
    entry absoluteTime() {
        require(tx.time >= unlockAt);
    }

    entry absoluteDaa() {
        require(tx.daa >= absoluteDaaScore);
    }

    entry relative() {
        require(this.ageDaa >= relativeDaaAge);
    }
}
```

Plain integers do not implicitly become times, and duration literals do not
implicitly become DAA ages. Convert only when the unit relationship is explicit:

```javascript
int rawMilliseconds = 5_000;
temporal delay = temporal(rawMilliseconds);  // no-op conversion
int serialized = int(delay);         // no-op conversion

require(tx.time >= date("2030-01-01T00:00:00"));
// require(tx.time >= 5000);          // error: expected temporal
// require(this.ageDaa >= 5 seconds); // error: expected int
```

### For Loops

For loops iterate over a runtime range of integers, but the unroll bound must be known at compile time:

```javascript
contract ForLoop() {
    int constant MAX_ITERATIONS = 4;
    int constant MIN_OUT = 1000;

    entry check(int start, int end) {
        for(i, start, end, MAX_ITERATIONS) {
            require(tx.outputs[i].value >= MIN_OUT + i);
        }
    }
}
```

The loop variable `i` takes values from `start` to `end - 1` (exclusive end). The range length must not exceed the compile-time unroll bound, so `end - start <= MAX_ITERATIONS` must hold. If the compiler can prove that a constant range exceeds the bound, compilation fails. For runtime bounds, the generated script currently checks the same condition before entering the loop and fails if the provided range is too large.

If `start >= end`, the loop performs no iterations. Otherwise, the compiler emits exactly `MAX_ITERATIONS` guarded iterations, and each guarded iteration runs only while the current loop variable is still below `end`.

This fails during compilation because the constant range has 4 values, but the unroll bound is only 3:

```text
contract CompileTimeLoopFailure() {
    entry check() {
        for(i, 0, 4, 3) {
            require(i >= 0);
        }
    }
}
```

This compiles because the range bounds are provided at runtime, but calling `check(2, 6)` fails during execution because `6 - 2` is greater than the unroll bound of 3:

```javascript
contract RuntimeLoopFailure() {
    entry check(int start, int end) {
        for(i, start, end, 3) {
            require(i >= start);
        }
    }
}
```

**Warning:** The runtime assertion is a current compiler behavior and may be removed in a later version. Do not rely on its existence as a stable validation mechanism; validate runtime loop bounds explicitly when the contract depends on that validation.

---

## Working with Data

### Literals

**Integer Literals:**

```javascript
int decimal = 42;
int negative = -100;
int withUnderscore = 1_000_000;  // Underscores for readability
int exponential = 1e6;  // 1,000,000
```

**Boolean Literals:**

```javascript
bool t = true;
bool f = false;
```

**String Literals:**

```javascript
string s1 = "Hello World";
string s2 = 'Single quotes work too';
string escaped = "Line 1\nLine 2\tTabbed";
string quote = "He said \"Hello\"";
string apostrophe = 'It\'s working';
```

**Hex Literals:**

```javascript
byte[] data = byte[](0x1234abcd);
byte[] empty = byte[](0x);
byte[] pubkeyBytes = byte[](0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef);
int mask = 0xff00;
byte tag = 0xff;
```

Hex literals of up to eight bytes are numerals and can initialize `int` or `byte` values. To use the hexadecimal spelling as raw bytes, cast it directly to a byte-array type. Literals longer than eight bytes are accepted only in such an immediate cast:

```javascript
byte[_] id = byte[_](0x010203040506070809);
```

### Number Units

SilverScript supports convenient number units for values and time:

**Value Units:**

```javascript
int amount1 = 1000 litras;
int amount2 = 10 grains;
int amount3 = 1 kas;
```

**Time Units:**

```javascript
temporal time1 = 30 seconds; // 30,000 milliseconds
temporal time2 = 5 minutes;  // 300,000 milliseconds
temporal time3 = 2 hours;    // 7,200,000 milliseconds
temporal time4 = 7 days;     // 604,800,000 milliseconds
temporal time5 = 4 weeks;    // 2,419,200,000 milliseconds
```

Example usage:

```javascript
entry withdraw() {
    require(this.ageDaa >= 2_592_000);
    require(tx.outputs[0].value >= 10000 litras);
}
```

### Date Literals

Convert ISO 8601 date strings to Unix timestamps in milliseconds:

```javascript
temporal timestamp = date("2021-02-17T01:30:00");
require(tx.time >= timestamp);
```

Format: `YYYY-MM-DDThh:mm:ss`

### Arrays

SilverScript supports both direct array initialization and dynamic building with `.append()`:

Array literals include their element type and use braces: `T[]{a, b, c}`. Nested element types retain their inner dimensions, for example `byte[2][]{byte[2](0x0102)}`.

```javascript
// Dynamic array initialization
int[] nums = int[]{1, 2, 3};
byte[] data = byte[](0x1234abcd);

// Explicit fixed-size initialization
int[4] fixedNums = int[4]{1, 2, 3, 4};
byte[4] tag = byte[4](0x01020304);

// Dynamic building with append
int[] numbers;
numbers = numbers.append(1, 2, 3, 4, 5);

// Build byte[32] array dynamically
byte[32][] hashes;
hashes = hashes.append(byte[32](0x1111111111111111111111111111111111111111111111111111111111111111));
hashes = hashes.append(byte[32](0x2222222222222222222222222222222222222222222222222222222222222222));

// Access array elements
int first = numbers[0];
int second = numbers[1];

// Array length
int count = numbers.length;

// For fixed-size arrays (including inferred ones), length is compile-time
require(nums.length == 3);
require(data.length == 4);
```

**Array Concatenation:**

You can concatenate arrays with `+` when element types are compatible.

This works for array types whose element size is known at compile time, including:
- `byte[]` (element type `byte`)
- `int[]` (element type `int`)
- `bool[]` (element type `bool`)
- `pubkey[]` (element type `pubkey`)
- `byte[N][]` (element type `byte[N]`)

Examples:

```javascript
// int[] + int[]
int[_] a = int[_]{1, 2};
int[_] b = int[_]{3, 4};
int[_] c = a + b;

require(c.length == 4);
require(c[0] == 1);
require(c[1] == 2);
require(c[2] == 3);
require(c[3] == 4);

// byte[] + byte[]
byte[_] p = byte[_](0x0102);
byte[_] q = byte[_](0x0304);
byte[_] r = p + q;
require(r == byte[4](0x01020304));

// bool[] + bool[]
bool[_] f1 = bool[_]{true, false};
bool[_] f2 = bool[_]{true, false};
bool[_] f = f1 + f2;
require(f[0]);
require(!f[1]);
require(f[2]);
require(!f[3]);

// pubkey[] + pubkey[]
pubkey k1 = pubkey(0x0202020202020202020202020202020202020202020202020202020202020202);
pubkey k2 = pubkey(0x0303030303030303030303030303030303030303030303030303030303030303);
pubkey[_] ks1 = pubkey[_]{k1};
pubkey[_] ks2 = pubkey[_]{k2};
pubkey[_] ks = ks1 + ks2;
require(ks[0] == k1);
require(ks[1] == k2);

// byte[N][] + byte[N][]
byte[2][_] x = byte[2][_]{byte[2](0x0102), byte[2](0x0304)};
byte[2][_] y = byte[2][_]{byte[2](0x0506)};
byte[2][_] z = x + y;
require(z.length == 3);
require(z[2] == byte[2](0x0506));
```

**Array comparison:**

`==` and `!=` are supported only when the array's base type has an unambiguous
byte representation:

- byte arrays at any supported dimension, such as `byte[]`, `byte[32][]`, and
  `byte[2][3]`;
- arrays of fixed-byte sequence types (`pubkey`, `sig`, and `datasig`), including
  multidimensional forms such as `pubkey[2][]`.

Arrays of `int`, `bool`, structs, and other element types cannot be compared as
whole values. Compare their lengths and elements explicitly instead.

### String Operations

**Concatenation:**

```javascript
string hello = "Hello";
string world = "World";
string message = hello + " " + world;  // "Hello World"

// Length
int len = message.length;  // 11
```

### Bytes Operations

**Concatenation:**

```javascript
byte[] a = byte[](0x1234);
byte[] b = byte[](0x5678);
byte[] combined = a + b;  // 0x12345678
```

**Split:**

`split(int)` divides an array at a specific index and returns a two-value tuple.
Both parts are dynamic arrays with the same element type as the source. Use `.0`
for the left part and `.1` for the right part:

```javascript
byte[] data = byte[](0x1234567890abcdef);
byte[] left = data.split(4).0;   // 0x12345678
byte[] right = data.split(4).1;  // 0x90abcdef
```

You can also destructure both parts at once:

```javascript
byte[] data = byte[](0x1234567890abcdef);
(byte[] left, byte[] right) = data.split(4);
```

**Slice:**

Extract a range of bytes:

```javascript
byte[] data = byte[](0x123456789abcdef);
byte[] middle = data.slice(2, 5);  // byte[] from index 2 to 5 (exclusive)
```

**Length:**

```javascript
byte[] data = byte[](0x1234);
int size = data.length;  // 2
```

---

## Type Casting

SilverScript supports explicit type casting:

```javascript
entry casts(byte[32] data, byte[65] sigBytes, byte[32] keyBytes, byte[8] someData) {
    // Cast between byte-compatible types
    byte[] fromString = byte[]("hello");

    // Cast to specific byte size
    byte[32] hash = byte[32](data);
    byte[65] signatureBytes = byte[65](sigBytes);

    // Cast a one-byte hex literal to scalar byte
    byte b = byte(0x00);

    // Cast to pubkey or sig
    pubkey pk = pubkey(keyBytes);
    sig signature = sig(signatureBytes);

    // Cast to int
    int number = int(someData); // source must be byte[N] where N <= 8
}
```

The scalar `byte(...)` conversion accepts an existing `byte` value or an integer
literal in the range `0..=255`. It does not narrow variables or other non-literal
`int` expressions. `int(byteValue)` is not allowed for scalar `byte` expressions,
and `int(bytes)` requires a fixed `byte[N]` source where `N <= 8`;
use `signed(byteValue)` or `unsigned(byteValue)` to select the intended numeric
interpretation. Scalar `byte` expressions cannot be used directly with
arithmetic operators.

### Casts are unchecked type assertions

Representation-preserving casts assume that the runtime value already has the
representation required by the target type. They do not emit a runtime length or
format check. The compiler rejects incompatibilities it can prove at compile
time, but a cast from a dynamically sized value to a fixed-size or opaque byte
type trusts the programmer's assertion.

For example, check a dynamic value before treating it as `byte[32]`:

```javascript
entry checkedCast(byte[] data) {
    require(data.length == 32);
    byte[32] hash = byte[32](data);
}
```

Without the explicit `require`, `byte[32](data)` does not prove that `data`
contains 32 bytes. Code using casts to `byte[N]`, `pubkey`, `sig`, or `datasig`
is responsible for validating any runtime size or format properties on which it
relies. After a cast, compile-time properties such as a fixed array's `.length`
come from the asserted target type and are not evidence that the runtime value
was checked.

Use `value as byte` to encode a runtime `int` as one byte. It fails at runtime when the value does
not fit the VM's one-byte signed-magnitude script-number encoding (for example,
`128`).

**Example:**

```javascript
entry example(pubkey pk, byte[65] sigBytes) {
    sig s = sig(sigBytes);
    require(checkSig(s, pk));
}
```

---

## Built-in Functions

### Cryptographic Functions

**`blake2b(byte[] data): byte[32]`**

Compute the BLAKE2b hash of the input:

```javascript
entry hashes(byte[] data, pubkey pk) {
    byte[32] hash = blake2b(data);
    byte[32] pkh = blake2b(byte[](pk));
    require(hash != pkh);
}
```

**`sha256(byte[] data): byte[32]`**

Compute the SHA-256 hash:

```javascript
entry hash(byte[] data) {
    byte[32] hash = sha256(data);
    require(hash == hash);
}
```

**`checkSig(sig signature, pubkey publicKey): bool`**

Verify a transaction signature (with its sighash byte) against a schnorr public key

```javascript
entry verify(sig s, pubkey pk) {
    require(checkSig(s, pk));
}
```

**`checkSigEcdsa(sig signature, byte[33] publicKey): bool`**

Verify a transaction signature (with its sighash byte) against a compressed ECDSA public key

```javascript
entry verify(sig s, byte[33] pk) {
    require(checkSigEcdsa(s, pk));
}
```

**`checkMsgSig(datasig signature, byte[32] digest, pubkey publicKey): bool`**

Verify a 64-byte Schnorr signature against a 32-byte digest supplied by the
contract. Hash the message explicitly with the hash function required by your
protocol:

```javascript
entry verify(datasig oracleSig, byte[] oracleMessage, pubkey oraclePk) {
    require(checkMsgSig(oracleSig, sha256(oracleMessage), oraclePk));
}
```

**`checkMsgSigEcdsa(datasig signature, byte[32] digest, byte[33] publicKey): bool`**

Verify a compact 64-byte ECDSA signature against a 32-byte digest and compressed
33-byte ECDSA public key:

```javascript
entry verify(datasig oracleSig, byte[] oracleMessage, byte[33] oraclePk) {
    require(checkMsgSigEcdsa(oracleSig, sha256(oracleMessage), oraclePk));
}
```

**`g16.verify(byte[] verifyingKey, byte[] proof, byte[32] ...publicInputs)`**

Verify a Groth16 proof with a compressed verifying key, compressed proof, and
zero or more 32-byte public inputs. Verification failure aborts script execution:

```javascript
entry verify(byte[] verifyingKey, byte[] proof, byte[32] publicInput0, byte[32] publicInput1) {
    g16.verify(verifyingKey, proof, publicInput0, publicInput1);
}
```

### Type Conversions

Use `temporal(...)` and `int(...)` for no-op conversions between the two numeric
domains:

```javascript
temporal timestamp = temporal(1640000000000);
int rawTimestamp = int(timestamp);
```

The conversion changes only the SilverScript type; the encoded integer is
unchanged.

Use `as byte[N]` to convert an integer to a fixed-size byte array:

```javascript
int amount = 1234;
byte[8] encodedAmount = amount as byte[8];
```

The source value must be an `int`, and `N` must be known at compile time and
between 1 and 8. The conversion expression has type `byte[N]`.

**`boolValue as int`**

Convert boolean to integer (true = 1, false = 0):

```javascript
int x = false as int;  // 0
```

The conversion normalizes every truthy boolean representation to `1` and every
false boolean representation to `0`.

**`signed(byte value): int`**

Interpret a scalar byte as a one-byte signed-magnitude script number. This is a
pass-through cast and does not change its byte encoding:

```javascript
byte b = 0xff;
int x = signed(b);  // -127
```

**`unsigned(byte value): int`**

Interpret the byte's full unsigned value by appending a zero byte to its numeric
encoding:

```javascript
int i = 255;
byte b = 255;
require(unsigned(b) == i);
```

---

## Transaction Introspection

Transaction introspection allows contracts to examine the transaction that is spending them.

### Transaction Fields

**Introspection Fields** (no index):

```javascript
// Current active input index
int inputIdx = this.activeInputIndex;

// Active bytecode (current contract's scriptPubKey)
byte[] script = this.activeScriptPubKey;

// Number of inputs
int inputCount = tx.inputs.length;

// Number of outputs
int outputCount = tx.outputs.length;

// Transaction version
int version = tx.version;
```

**Time-based Fields:**

```javascript
// Age of the UTXO being spent (in DAA-score units)
require(this.ageDaa >= 0);

// Absolute transaction DAA-score locktime
require(tx.daa >= 1000000);

// Absolute transaction timestamp locktime
require(tx.time >= date("2030-01-01T00:00:00"));
```

The special `tx.daa` and `tx.time` forms are available only in their respective
`require(... >= threshold)` statements and enforce the consensus locktime domain
before calling CLTV.

### Input Introspection

Access properties of transaction inputs:

```javascript
// Access input at index i
int i = 0;
int inputValue = tx.inputs[i].value;
byte[] inputScript = tx.inputs[i].scriptPubKey;
byte[32] outpointTxId = tx.inputs[i].outpointTxId;
int outpointIndex = tx.inputs[i].outpointIndex;
```

**Example:**

```javascript
entry spend() {
    int currentValue = tx.inputs[this.activeInputIndex].value;
    require(currentValue >= 1000);
}
```

### Output Introspection

Access properties of transaction outputs:

```javascript
// Access output at index i
int i = 0;
int outputValue = tx.outputs[i].value;
byte[] outputScriptPubKey = tx.outputs[i].scriptPubKey;
```

**Example:**

```javascript
entry transfer() {
    // Ensure first output has at least 10000 litras
    require(tx.outputs[0].value >= 10000);
}
```

---

## Covenants

Covenants are contracts that enforce conditions on how funds can be spent. They use transaction introspection to validate outputs.

### Creating ScriptPubKey

**`new ScriptPubKeyP2PK(pubkey pk): byte[36]`**

Create a Pay-to-Public-Key scriptPubKey:

```javascript
entry checkOutput(pubkey recipientPubkey) {
    byte[36] outputScriptPubKey = new ScriptPubKeyP2PK(recipientPubkey);
    require(tx.outputs[0].scriptPubKey == byte[](outputScriptPubKey));
}
```

**`new ScriptPubKeyP2SH(byte[32] scriptHash): byte[37]`**

Create a Pay-to-Script-Hash scriptPubKey:

```javascript
entry checkOutput(byte[] redeemScript) {
    byte[32] redeemScriptHash = blake2b(redeemScript);
    byte[37] outputScriptPubKey = new ScriptPubKeyP2SH(redeemScriptHash);
    require(tx.outputs[0].scriptPubKey == byte[](outputScriptPubKey));
}
```

**`new ScriptPubKeyP2SHFromRedeemScript(byte[] redeemScript): byte[37]`**

Create a P2SH scriptPubKey directly from a redeem script:

```javascript
entry build(byte[] redeemScript) {
    byte[37] outputScriptPubKey = new ScriptPubKeyP2SHFromRedeemScript(redeemScript);
    require(outputScriptPubKey == outputScriptPubKey);
}
```

### State Transition Builtins

SilverScript provides five builtins for state routing and cross-template state inspection.

- **Validate Output State**: validate continuation into the same contract template. `newState` must provide every state field exactly once in the local `State` layout.

```js
validateOutputState(int outputIndex, object newState)
```

- **Validate Output State With Template**: validate continuation into a foreign contract template. `newState` is encoded using the struct layout implied by the value you pass, then inserted between `templatePrefix` and `templateSuffix`.

```js
validateOutputStateWithTemplate(
    int outputIndex,
    object newState,
    byte[] templatePrefix,
    byte[] templateSuffix,
    byte[32] expectedTemplateHash
)
```

- **Validate Output State With Input Template**: validate a foreign output while
  reusing the template bytes from another input's redeem script. The prefix and
  suffix lengths locate those bytes at the end of the selected input's sigscript.

```js
validateOutputStateWithInputTemplate(
    int outputIndex,
    object newState,
    int templateInputIndex,
    int templatePrefixLen,
    int templateSuffixLen,
    byte[32] expectedTemplateHash
)
```

- **Read Input State**: read another input as this contract's own `State`.

```js
readInputState(int inputIndex)
```

- **Read Input State With Template**: read another input using a foreign struct layout. It checks the foreign template hash and the foreign input's P2SH commitment before decoding.

```js
readInputStateWithTemplate(
    int inputIndex,
    int templatePrefixLen,
    int templateSuffixLen,
    byte[32] expectedTemplateHash
)
```

Use it with a direct struct binding or destructuring assignment:

```js
OtherState other = readInputStateWithTemplate(inputIndex, templatePrefixLen, templateSuffixLen, expectedTemplateHash);
```

Same-template example:

```js
pragma silverscript ^0.1.0;

contract Counter(int initCount, byte[2] initTag) {
    int count = initCount;
    byte[2] tag = initTag;

    entry step() {
        validateOutputState(0, State { count: count + 1, tag: tag });
    }
}
```

Input-side note:

- `readInputState(...)` and `readInputStateWithTemplate(...)` are input-state decoders. They read bytes from another input's sigscript and decode them as state.
- `readInputState(...)` is appropriate when the surrounding covenant domain guarantees a single allowed contract/layout for the foreign input.
- `readInputStateWithTemplate(...)` is appropriate when multiple templates may share a covenant domain; it additionally validates the foreign input's template hash and checks that the claimed redeem-script bytes match the foreign input's P2SH `scriptPubKey`.
- Without those surrounding guarantees, plain `readInputState(...)` would also need extra correlation checks between the foreign input and the inspected part of its sigscript.
- Both decoders read each field at an offset fixed at compile time, and the compiler emits a check — one comparison per field — that the region is framed the way the state encoder writes it, with the canonical push header for each field's width. Without it, since the script engine accepts non-minimal push encodings, a foreign input could widen one field's header and narrow another's, leave the region's total length unchanged, and move every later field read onto bytes it chose. The check makes the offsets meaningful; it does not by itself tie the region to the right script, which is still what the guarantees above are for.

### Covenant Examples

**Simple Covenant (Send to Specific Address):**

```javascript
pragma silverscript ^0.1.0;

contract SimpleCovenant(pubkey recipient) {
    entry spend() {
        // First output must go to the recipient
        byte[36] recipientScriptPubKey = new ScriptPubKeyP2PK(recipient);
        require(tx.outputs[0].scriptPubKey == byte[](recipientScriptPubKey));
    }
}
```

**Recurring Payment Covenant:**

```javascript
pragma silverscript ^0.1.0;

contract RecurringPayment(pubkey recipient, int paymentAmount, int period) {
    entry withdraw() {
        // Must wait for the period to elapse
        require(this.ageDaa >= period);
        
        // First output must pay the recipient
        byte[36] recipientScriptPubKey = new ScriptPubKeyP2PK(recipient);
        require(tx.outputs[0].scriptPubKey == byte[](recipientScriptPubKey));
        require(tx.outputs[0].value >= paymentAmount);
        
        // Calculate change
        int inputValue = tx.inputs[this.activeInputIndex].value;
        int minerFee = 1000;
        int changeValue = inputValue - paymentAmount - minerFee;
        
        // If sufficient funds remain, send change back to contract
        if (changeValue >= paymentAmount + minerFee) {
            byte[] changeScriptPubKey = tx.inputs[this.activeInputIndex].scriptPubKey;
            require(tx.outputs[1].scriptPubKey == changeScriptPubKey);
            require(tx.outputs[1].value == changeValue);
        }
    }
}
```

---

## Advanced Features

### Constants

Define contract-level constants:

```javascript
contract MyContract() {
    int constant MAX_VALUE = 1000;
    int constant MIN_VALUE = 100;
    string constant MESSAGE = "hello";
    
    entry check(int x) {
        require(x >= MIN_VALUE);
        require(x <= MAX_VALUE);
    }
}
```

Constants can only be declared at contract level.

### Tuple Unpacking

Unpack multiple values from tuple-returning functions or tuple-returning
built-ins such as `split(int)`:

```javascript
function getPair(): (int, int) {
    return (10, 20);
}

entry example(byte[32] data) {
    (byte[] left, byte[] right) = data.split(16);
    (int x, int y) = getPair();
}
```

Tuple fields can also be accessed directly with numeric field access:

```javascript
function getPair(): (int, int) {
    return (10, 20);
}

entry example() {
    int first = getPair().0;
    int second = getPair().1;
    require(first + second == 30);
}
```

A one-element tuple uses the same field access:

```javascript
function getOnly(): (int) {
    return (5);
}

entry example() {
    require(getOnly().0 == 5);
}
```

### Split and Slice Operations

**Split:**

Divide an array into two dynamic parts at a given index. Both parts retain the
source array's element type. The result is accessed like other tuple returns:

```javascript
byte[] data = byte[](0x1122334455667788);

// Split at byte 4
byte[] left = data.split(4).0;   // 0x11223344
byte[] right = data.split(4).1;  // 0x55667788

// Destructure both parts with types
(byte[] a, byte[] b) = data.split(4);
```

**Slice:**

Extract a substring of bytes:

```javascript
byte[] data = byte[](0x1122334455667788);

// Get byte[] from index 2 to 5 (exclusive)
byte[] middle = data.slice(2, 5);  // 0x334455

// Variable indices
int start = 1;
int end = 4;
byte[] extracted = data.slice(start, end);
```

---

## Complete Examples

### Pay-to-Public-Key (P2PK)

```javascript
pragma silverscript ^0.1.0;

contract P2PK(pubkey pk) {
    entry spend(sig s) {
        // Verify the signature
        require(checkSig(s, pk));
    }
}
```

**Constructor arguments:**
- `pk`: The recipient's public key

**Spend arguments:**
- `s`: A signature from the private key corresponding to `pk`

### Transfer with Timeout

```javascript
pragma silverscript ^0.1.0;

contract TransferWithTimeout(
    pubkey sender,
    pubkey recipient,
    temporal timeout
) {
    // Recipient can spend at any time
    entry transfer(sig recipientSig) {
        require(checkSig(recipientSig, recipient));
    }

    // Sender can reclaim after timeout
    entry reclaim(sig senderSig) {
        require(checkSig(senderSig, sender));
        require(tx.time >= timeout);
    }
}
```

**Constructor arguments:**
- `sender`: Public key of the sender (who can reclaim)
- `recipient`: Public key of the recipient (who can spend)
- `timeout`: Unix timestamp in milliseconds after which sender can reclaim

**Spend paths:**
1. **Transfer:** Recipient signs to claim funds
2. **Reclaim:** Sender signs after timeout to reclaim funds

### Recurring Payment (Mecenas)

A contract that releases periodic payments to a beneficiary:

```javascript
pragma silverscript ^0.1.0;

contract Mecenas(pubkey recipient, byte[32] funder, int pledge, int period) {
    // Periodic payment to recipient
    entry receive() {
        // Must wait for the period to elapse
        require(this.ageDaa >= period);

        // Check that the first output sends to the recipient
        byte[36] recipientScriptPubKey = new ScriptPubKeyP2PK(recipient);
        require(tx.outputs[0].scriptPubKey == byte[](recipientScriptPubKey));

        // Calculate the value that's left
        int minerFee = 1000;
        int currentValue = tx.inputs[this.activeInputIndex].value;
        int changeValue = currentValue - pledge - minerFee;

        // If there is not enough left for another pledge after this one,
        // send the remainder to the recipient. Otherwise send the
        // pledge to the recipient and the change back to the contract
        if (changeValue <= pledge + minerFee) {
            require(tx.outputs[0].value == currentValue - minerFee);
        } else {
            require(tx.outputs[0].value == pledge);
            byte[] changeScriptPubKey = tx.inputs[this.activeInputIndex].scriptPubKey;
            require(tx.outputs[1].scriptPubKey == changeScriptPubKey);
            require(tx.outputs[1].value == changeValue);
        }
    }

    // Funder can reclaim at any time
    entry reclaim(pubkey pk, sig s) {
        require(blake2b(byte[](pk)) == funder);
        require(checkSig(s, pk));
    }
}
```

**Constructor arguments:**
- `recipient`: Public key of the beneficiary
- `funder`: Hash of the funder's public key (for reclaim)
- `pledge`: Amount to pay per period
- `period`: Relative DAA-score units between payments

**Spend paths:**
1. **Receive:** Anyone can trigger a payment after the period elapses
2. **Reclaim:** Funder can reclaim all funds at any time

---

## Best Practices

1. **Always use pragma directives** to specify the language version
2. **Use descriptive variable and function names** for better readability
3. **Add comments** to explain complex logic
4. **Validate all inputs** with `require` statements
5. **Be mindful of miner fees** when calculating output values in covenants
6. **Test extensively** before deploying to mainnet
7. **Use constants** for magic numbers and repeated values
8. **Keep contracts simple** - complexity increases the risk of bugs
