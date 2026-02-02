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
6. [Control Flow](#control-flow)
   - [If Statements](#if-statements)
   - [Require Statements](#require-statements)
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
   - [Type Conversion Functions](#type-conversion-functions)
10. [Transaction Introspection](#transaction-introspection)
    - [Transaction Fields](#transaction-fields)
    - [Input Introspection](#input-introspection)
    - [Output Introspection](#output-introspection)
11. [Covenants](#covenants)
    - [Creating Locking Bytecode](#creating-locking-bytecode)
    - [Covenant Examples](#covenant-examples)
12. [Advanced Features](#advanced-features)
    - [Constants](#constants)
    - [Tuple Unpacking](#tuple-unpacking)
    - [Split and Slice Operations](#split-and-slice-operations)
    - [Console Logging (Debug)](#console-logging-debug)
13. [Complete Examples](#complete-examples)
    - [Pay-to-Public-Key-Hash (P2PKH)](#pay-to-public-key-hash-p2pkh)
    - [Multi-Signature (2-of-3)](#multi-signature-2-of-3)
    - [Transfer with Timeout](#transfer-with-timeout)
    - [Recurring Payment (Mecenas)](#recurring-payment-mecenas)

---

## Introduction

SilverScript is a CashScript-inspired smart contract language that compiles to Kaspa script. It enables you to write Bitcoin-like smart contracts with a high-level, JavaScript-like syntax. SilverScript contracts can enforce complex spending conditions, create covenants, and enable advanced cryptocurrency applications on the Kaspa network.

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

The `args.json` file should contain an array of constructor argument expressions. For example:

```json
[
  {"kind": "bytes", "data": [1, 2, 3, 4]},
  {"kind": "int", "data": 12345}
]
```

The compiled JSON output includes:
- `contract_name`: The name of the contract
- `script`: The compiled bytecode (as an array of bytes)
- `ast`: The abstract syntax tree of the parsed contract
- `abi`: An array of entrypoint functions with their parameter types

### Programmatic Compilation

You can also compile contracts programmatically using the SilverScript Rust library:

```rust
use silverscript_lang::compiler::{compile_contract, CompileOptions};
use silverscript_lang::ast::Expr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        pragma silverscript ^0.1.0;
        
        contract MyContract(int x) {
            entrypoint function spend(int y) {
                require(y > x);
            }
        }
    "#;
    
    // Constructor arguments (x = 100)
    let constructor_args = vec![Expr::Int(100)];
    
    // Compile with default options
    let options = CompileOptions::default();
    let compiled = compile_contract(source, &constructor_args, options)?;
    
    println!("Contract name: {}", compiled.contract_name);
    println!("Script length: {} bytes", compiled.script.len());
    println!("ABI: {:?}", compiled.abi);
    
    Ok(())
}
```

**Building Signature Scripts Programmatically:**

After compiling a contract, you can build signature scripts (unlocking scripts) for its entrypoint functions:

```rust
use silverscript_lang::ast::Expr;

let source = r#"
    pragma silverscript ^0.1.0;
    
    contract TransferWithTimeout(pubkey sender, pubkey recipient, int timeout) {
        entrypoint function transfer(sig recipientSig) {
            require(checkSig(recipientSig, recipient));
        }
        
        entrypoint function reclaim(sig senderSig) {
            require(checkSig(senderSig, sender));
            require(tx.time >= timeout);
        }
    }
"#;

let sender_pk = vec![3u8; 32];
let recipient_pk = vec![4u8; 32];
let timeout = 1640000000i64;
let compiled = compile_contract(
    source,
    &[sender_pk.into(), recipient_pk.into(), timeout.into()],
    CompileOptions::default()
)?;

// Build sigscript for multiple entrypoints
let sig = vec![5u8; 64];

// For 'transfer' function (selector = 0)
let transfer_sigscript = compiled.build_sig_script(
    "transfer",
    vec![sig.clone().into()]
)?;
// transfer_sigscript contains: <signature> <0> (selector 0)

// For 'reclaim' function (selector = 1)
let reclaim_sigscript = compiled.build_sig_script(
    "reclaim",
    vec![sig.into()]
)?;
// reclaim_sigscript contains: <signature> <1> (selector 1)
```

The `build_sig_script` method automatically:
- Validates argument count and types
- Encodes arguments properly for the Kaspa script stack
- Appends the function selector for contracts with multiple entrypoints
- Omits the selector for contracts with a single entrypoint

---

## Language Basics

### Contract Structure

Every SilverScript program defines a single contract. A contract has a name, optional constructor parameters, and one or more functions:

```javascript
pragma silverscript ^0.1.0;

contract MyContract(int param1, bytes32 param2) {
    // Contract constants (optional)
    int constant MAX_VALUE = 1000;
    
    // Functions
    entrypoint function spend(sig s, pubkey pk) {
        require(checkSig(s, pk));
    }
}
```

### Pragma Directives

Every contract should start with a pragma directive specifying the SilverScript version:

```javascript
pragma silverscript ^0.1.0;
```

Version operators:
- `^0.1.0` - Compatible with 0.1.x
- `~0.1.0` - Compatible with 0.1.0 only
- `>=0.1.0` - Greater than or equal
- `>0.1.0` - Greater than
- `<0.2.0` - Less than
- `<=0.1.5` - Less than or equal
- `=0.1.0` - Exactly this version

### Data Types

SilverScript supports the following data types:

| Type | Description | Example |
|------|-------------|---------|
| `int` | 64-bit signed integer | `42`, `-100`, `1000` |
| `bool` | Boolean value | `true`, `false` |
| `string` | UTF-8 string | `"hello"`, `'world'` |
| `bytes` | Dynamic byte array | `0x1234`, `0xabcdef` |
| `byteN` | Fixed-size byte array (N = 1-255) | `bytes32`, `bytes65` |
| `byte` | Single byte (alias for `bytes1`) | `byte` |
| `pubkey` | Public key (32 bytes) | `pubkey` |
| `sig` | Signature (64 or 65 bytes) | `sig` |
| `datasig` | Data signature (64 or 65 bytes) | `datasig` |

**Array Types:**

You can create arrays by appending `[]` to any type:

```javascript
int[] numbers;
bytes32[] hashes;
pubkey[] publicKeys;
```

### Variables

Variables must be declared with their type before use:

```javascript
entrypoint function example() {
    // Variable declaration
    int myNumber = 42;
    bool flag = true;
    string message = "Hello World";
    bytes data = 0x1234abcd;
    
    // Declaration without initialization
    int uninitializedValue;
    
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

Entrypoint functions are callable from outside the contract. Mark them with the `entrypoint` keyword:

```javascript
entrypoint function spend(sig s, pubkey pk) {
    require(checkSig(s, pk));
}
```

A contract must have at least one entrypoint function. Contracts with multiple entrypoints use function selectors automatically.

### Function Parameters and Return Types

Functions can have multiple parameters and return values:

```javascript
// Function with return type
function add(int a, int b): (int) {
    return (a + b);
}

// Multiple return values
function split(bytes32 data): (bytes16, bytes16) {
    bytes16 left, bytes16 right = data.split(16);
    return (left, right);
}

// Using the return value
entrypoint function example() {
    int result = add(5, 10);
    require(result == 15);
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
bool eq = (a == b);   // false (equality)
bool ne = (a != b);   // true (inequality)
bool lt = (a < b);    // false (less than)
bool le = (a <= b);   // false (less than or equal)
bool gt = (a > b);    // true (greater than)
bool ge = (a >= b);   // true (greater than or equal)
```

### Logical Operators

```javascript
bool t = true;
bool f = false;

bool and = t && f;  // false (logical AND)
bool or = t || f;   // true (logical OR)
bool not = !t;      // false (logical NOT)
```

### Bitwise Operators

**Note:** Bitwise operators require covenant features to be enabled.

```javascript
int x = 0x0F;  // 00001111
int y = 0xF0;  // 11110000

int bitAnd = x & y;  // 0x00 (bitwise AND)
int bitOr = x | y;   // 0xFF (bitwise OR)
int bitXor = x ^ y;  // 0xFF (bitwise XOR)
```

---

## Control Flow

### If Statements

Basic if-else structure:

```javascript
entrypoint function example(int x) {
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
if (x > 0)
    require(true);
else
    require(false);
```

### Require Statements

The `require` statement enforces conditions. If the condition is false, the contract execution fails:

```javascript
require(x > 0);  // Passes if x > 0, fails otherwise

// With error message
require(x > 0, "x must be positive");
```

Time-based require statements:

```javascript
// Require transaction time
require(tx.time >= 1640000000);

// Require contract age
require(this.age >= 86400);  // 1 day in seconds
```

### For Loops

For loops iterate over a range of integers. The bounds must be compile-time constants:

```javascript
contract ForLoop() {
    int constant START = 0;
    int constant END = 4;
    int constant MIN_OUT = 1000;

    entrypoint function check() {
        for(i, START, END) {
            require(tx.outputs[i].value >= MIN_OUT + i);
        }
    }
}
```

The loop variable `i` takes values from `START` to `END - 1` (exclusive end).

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
bytes data = 0x1234abcd;
bytes empty = 0x;
bytes pubkeyBytes = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
```

### Number Units

SilverScript supports convenient number units for values and time:

**Value Units:**

```javascript
int amount1 = 1000 satoshis;  // or 'sats'
int amount2 = 10 finney;
int amount3 = 100 bits;
int amount4 = 1 bitcoin;
```

**Time Units:**

```javascript
int time1 = 30 seconds;
int time2 = 5 minutes;  // 300 seconds
int time3 = 2 hours;    // 7200 seconds
int time4 = 7 days;     // 604800 seconds
int time5 = 4 weeks;    // 2419200 seconds
```

Example usage:

```javascript
entrypoint function withdraw() {
    require(this.age >= 30 days);
    require(tx.outputs[0].value >= 10000 satoshis);
}
```

### Date Literals

Convert ISO 8601 date strings to Unix timestamps:

```javascript
int timestamp = date("2021-02-17T01:30:00");
require(tx.time >= timestamp);
```

Format: `YYYY-MM-DDThh:mm:ss`

### Arrays

Arrays must be built dynamically using the `.push()` method:

```javascript
// Declare an array
int[] numbers;
bytes32[] hashes;

// Build array with push
numbers.push(1);
numbers.push(2);
numbers.push(3);
numbers.push(4);
numbers.push(5);

// Build bytes32 array
hashes.push(0x1111111111111111111111111111111111111111111111111111111111111111);
hashes.push(0x2222222222222222222222222222222222222222222222222222222222222222);

// Access array elements
int first = numbers[0];
int second = numbers[1];

// Array length
int count = numbers.length;
```

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
bytes a = 0x1234;
bytes b = 0x5678;
bytes combined = a + b;  // 0x12345678
```

**Split:**

Split bytes at a specific index:

```javascript
bytes data = 0x1234567890abcdef;
bytes left = data.split(4)[0];   // 0x12345678
bytes right = data.split(4)[1];  // 0x90abcdef
```

**Slice:**

Extract a range of bytes:

```javascript
bytes data = 0x123456789abcdef;
bytes middle = data.slice(2, 5);  // bytes from index 2 to 5 (exclusive)
```

**Length:**

```javascript
bytes data = 0x1234;
int size = data.length;  // 2
```

---

## Type Casting

SilverScript supports explicit type casting:

```javascript
// Cast to bytes
bytes fromInt = bytes(42);
bytes fromString = bytes("hello");

// Cast to specific byte size
bytes32 hash = bytes32(data);
bytes65 signatureBytes = bytes65(sigBytes);

// Cast to pubkey or sig
pubkey pk = pubkey(keyBytes);
sig signature = sig(signatureBytes);

// Cast to int
int number = int(someData);
```

**Example:**

```javascript
entrypoint function example(pubkey pk, bytes65 sigBytes) {
    sig s = sig(sigBytes);
    require(checkSig(s, pk));
}
```

---

## Built-in Functions

### Cryptographic Functions

**`blake2b(bytes data): bytes32`**

Compute the BLAKE2b hash of the input:

```javascript
bytes32 hash = blake2b(data);
bytes32 pkh = blake2b(pk);
```

**`sha256(bytes data): bytes32`**

Compute the SHA-256 hash:

```javascript
bytes32 hash = sha256(data);
```

**`checkSig(sig signature, pubkey publicKey): bool`**

Verify a signature against a public key:

```javascript
require(checkSig(s, pk));
```

### Type Conversion Functions

**`bytes(value): bytes`**

Convert to bytes:

```javascript
bytes b1 = bytes(42);
bytes b2 = bytes("hello");
```

**`bytes(int value, int size): bytes`**

Convert integer to bytes with specific size:

```javascript
bytes8 b = bytes(1234, 8);
```

**`int(bool value): int`**

Convert boolean to integer (true = 1, false = 0):

```javascript
int x = int(false);  // 0
```

**`length(bytes value): int`**

Get the length of a byte array:

```javascript
int size = length(data);
```

---

## Transaction Introspection

Transaction introspection allows contracts to examine the transaction that is spending them.

### Transaction Fields

**Nullary Operations** (no parameters):

```javascript
// Current active input index
int inputIdx = this.activeInputIndex;

// Active bytecode (current contract's locking script)
bytes script = this.activeBytecode;

// Number of inputs
int inputCount = tx.inputs.length;

// Number of outputs
int outputCount = tx.outputs.length;

// Transaction version
int version = tx.version;

// Transaction locktime
int locktime = tx.locktime;
```

**Time-based Fields:**

```javascript
// Age of the UTXO being spent (in seconds)
require(this.age >= 0);

// Transaction locktime
require(tx.time >= 0);
```

### Input Introspection

Access properties of transaction inputs:

```javascript
// Access input at index i
int inputValue = tx.inputs[i].value;
bytes inputScript = tx.inputs[i].lockingBytecode;
```

**Example:**

```javascript
entrypoint function spend() {
    int currentValue = tx.inputs[this.activeInputIndex].value;
    require(currentValue >= 1000);
}
```

### Output Introspection

Access properties of transaction outputs:

```javascript
// Access output at index i
int outputValue = tx.outputs[i].value;
bytes lockingScript = tx.outputs[i].lockingBytecode;
```

**Example:**

```javascript
entrypoint function transfer() {
    // Ensure first output has at least 10000 satoshis
    require(tx.outputs[0].value >= 10000);
}
```

---

## Covenants

Covenants are contracts that enforce conditions on how funds can be spent. They use transaction introspection to validate outputs.

### Creating Locking Bytecode

**`new LockingBytecodeP2PK(pubkey pk): bytes34`**

Create a Pay-to-Public-Key locking script:

```javascript
bytes34 lockScript = new LockingBytecodeP2PK(recipientPubkey);
require(tx.outputs[0].lockingBytecode == lockScript);
```

**`new LockingBytecodeP2SH(bytes32 scriptHash): bytes35`**

Create a Pay-to-Script-Hash locking script:

```javascript
bytes32 redeemScriptHash = blake2b(redeemScript);
bytes35 lockScript = new LockingBytecodeP2SH(redeemScriptHash);
require(tx.outputs[0].lockingBytecode == lockScript);
```

**`new LockingBytecodeP2SHFromRedeemScript(bytes redeemScript): bytes35`**

Create P2SH locking script directly from redeem script:

```javascript
bytes35 lockScript = new LockingBytecodeP2SHFromRedeemScript(redeemScript);
```

### Covenant Examples

**Simple Covenant (Send to Specific Address):**

```javascript
pragma silverscript ^0.1.0;

contract SimpleCovenant(pubkey recipient) {
    entrypoint function spend() {
        // First output must go to the recipient
        bytes34 recipientLock = new LockingBytecodeP2PK(recipient);
        require(tx.outputs[0].lockingBytecode == recipientLock);
    }
}
```

**Recurring Payment Covenant:**

```javascript
pragma silverscript ^0.1.0;

contract RecurringPayment(pubkey recipient, int paymentAmount, int period) {
    entrypoint function withdraw() {
        // Must wait for the period to elapse
        require(this.age >= period);
        
        // First output must pay the recipient
        bytes34 recipientLock = new LockingBytecodeP2PK(recipient);
        require(tx.outputs[0].lockingBytecode == recipientLock);
        require(tx.outputs[0].value >= paymentAmount);
        
        // Calculate change
        int inputValue = tx.inputs[this.activeInputIndex].value;
        int minerFee = 1000;
        int changeValue = inputValue - paymentAmount - minerFee;
        
        // If sufficient funds remain, send change back to contract
        if (changeValue >= paymentAmount + minerFee) {
            bytes changeBytecode = tx.inputs[this.activeInputIndex].lockingBytecode;
            require(tx.outputs[1].lockingBytecode == changeBytecode);
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
    
    entrypoint function check(int x) {
        require(x >= MIN_VALUE);
        require(x <= MAX_VALUE);
    }
}
```

Constants can also be declared inside functions:

```javascript
entrypoint function example() {
    string constant greeting = "Hello";
    require(sha256(greeting) != 0x);
}
```

### Tuple Unpacking

Unpack multiple values from function returns or split operations:

```javascript
// Function with multiple returns
function getPair(): (int, int) {
    return (10, 20);
}

// Unpack split results and function results
entrypoint function example(bytes32 data) {
    bytes16 left, bytes16 right = data.split(16);
    (int x, int y) = getPair();
}
```

**In Function Parameters:**

```javascript
entrypoint function example(bytes32 data) {
    bytes16 x, bytes16 y = data.split(16);
    require(x == y);
}
```

### Split and Slice Operations

**Split:**

Divide bytes into two parts at a given index:

```javascript
bytes data = 0x1122334455667788;

// Split at byte 4
bytes left = data.split(4)[0];   // 0x11223344
bytes right = data.split(4)[1];  // 0x55667788

// Direct tuple unpacking with types
bytes4 a, bytes4 b = data.split(4);
```

**Slice:**

Extract a substring of bytes:

```javascript
bytes data = 0x1122334455667788;

// Get bytes from index 2 to 5 (exclusive)
bytes middle = data.slice(2, 5);  // 0x334455

// Variable indices
int start = 1;
int end = 4;
bytes extracted = data.slice(start, end);
```

---

## Complete Examples

### Pay-to-Public-Key (P2PK)

```javascript
pragma silverscript ^0.1.0;

contract P2PK(pubkey pk) {
    entrypoint function spend(sig s) {      
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
    int timeout
) {
    // Recipient can spend at any time
    entrypoint function transfer(sig recipientSig) {
        require(checkSig(recipientSig, recipient));
    }

    // Sender can reclaim after timeout
    entrypoint function reclaim(sig senderSig) {
        require(checkSig(senderSig, sender));
        require(tx.time >= timeout);
    }
}
```

**Constructor arguments:**
- `sender`: Public key of the sender (who can reclaim)
- `recipient`: Public key of the recipient (who can spend)
- `timeout`: Unix timestamp after which sender can reclaim

**Spend paths:**
1. **Transfer:** Recipient signs to claim funds
2. **Reclaim:** Sender signs after timeout to reclaim funds

### Recurring Payment (Mecenas)

A contract that releases periodic payments to a beneficiary:

```javascript
pragma silverscript ^0.1.0;

contract Mecenas(pubkey recipient, bytes32 funder, int pledge, int period) {
    // Periodic payment to recipient
    entrypoint function receive() {
        // Must wait for the period to elapse
        require(this.age >= period);

        // Check that the first output sends to the recipient
        bytes34 recipientLockingBytecode = new LockingBytecodeP2PK(recipient);
        require(tx.outputs[0].lockingBytecode == recipientLockingBytecode);

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
            bytes changeBytecode = tx.inputs[this.activeInputIndex].lockingBytecode;
            require(tx.outputs[1].lockingBytecode == changeBytecode);
            require(tx.outputs[1].value == changeValue);
        }
    }

    // Funder can reclaim at any time
    entrypoint function reclaim(pubkey pk, sig s) {
        require(blake2b(pk) == funder);
        require(checkSig(s, pk));
    }
}
```

**Constructor arguments:**
- `recipient`: Public key of the beneficiary
- `funder`: Hash of the funder's public key (for reclaim)
- `pledge`: Amount to pay per period
- `period`: Time in seconds between payments

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