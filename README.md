# SilverScript

SilverScript is a CashScript-inspired smart contract language that compiles to Kaspa script bytecode. It provides a readable, type-safe DSL for writing covenant-style contracts without dealing with raw opcodes.

**Why it exists**

- Type-safe contract development with explicit types
- Familiar, C-like syntax
- Built-in transaction introspection for covenants
- Compile-time validation and error reporting

## Project Structure

This is a Rust workspace with the following components:

```
silverscript/
├── silverscript-lang/          # Language, compiler, debugger
│   ├── src/
│   │   ├── ast.rs              # AST definitions
│   │   ├── parser.rs           # Parser interface (Pest)
│   │   ├── silverscript.pest   # Grammar definition
│   │   ├── compiler.rs         # Bytecode compiler
│   │   ├── debug/              # Debug engine/session
│   │   └── bin/                # Debugger binaries
│   └── tests/                  # Parser/compiler/debugger tests
├── covenants/
│   └── sdk/                    # Kaspa covenant SDK utilities
└── analysis/                   # Design notes
```

## How It Works

The Silverscript compiler follows a standard multi-stage compilation pipeline:

### 1. Parsing (Parser → AST)

The compiler uses [Pest](https://pest.rs/) parser generator with a PEG grammar defined in `silverscript.pest`:

```
Source Code (.sil) → Parser → Pairs (parse tree) → AST
```

**Location:** `silverscript-lang/src/parser.rs` and `silverscript-lang/src/silverscript.pest`

The grammar defines:
- Contract structure (pragma, parameters, functions)
- Type system (int, bool, bytes, pubkey, sig, datasig)
- Expressions with operator precedence
- Statements (require, if/else, for loops, assignments)
- Transaction introspection syntax

### 2. Abstract Syntax Tree (AST)

The parse tree is converted to a typed AST representation:

**Location:** `silverscript-lang/src/ast.rs`

**Key AST Types:**
- `ContractAst` - Represents the entire contract (name, parameters, functions, constants)
- `FunctionAst` - Function definitions with typed parameters and statement body
- `Statement` - Control flow and validation statements
- `Expr` - Type-safe expressions (literals, operations, function calls, introspection)

### 3. Compilation (AST → Bytecode)

The compiler translates AST nodes to Kaspa script opcodes:

**Location:** `silverscript-lang/src/compiler.rs`

**Compilation Process:**

1. **Parameter Binding**: Contract constructor parameters are bound to provided values
2. **Constant Evaluation**: Compile-time constants are evaluated
3. **Code Generation**: Statements and expressions are converted to opcodes
4. **Stack Management**: The compiler tracks stack depth for proper execution
5. **Introspection**: Transaction field access compiles to covenant opcodes

**Key Functions:**
- `compile_contract()` - Main entry point, parses and compiles source
- `compile_contract_ast()` - Compiles AST to bytecode
- `compile_statement()` - Generates opcodes for each statement type
- `compile_expression()` - Handles expression evaluation on the stack

**Compilation Options:**
```rust
CompileOptions {
    covenants_enabled: bool,    // Enable transaction introspection
    without_selector: bool,     // Omit function selector for single-function contracts
    record_debug_spans: bool,   // Record source spans for debugging (optional)
}
```

### 4. Output

The compiler produces:
```rust
CompiledContract {
    contract_name: String,      // Name of the contract
    script: Vec<u8>,            // Executable bytecode (includes dispatcher unless without_selector)
    ast: ContractAst,           // Parsed AST
    abi: FunctionAbi,           // Function input types for building sigscripts
    without_selector: bool,     // Whether selector dispatch was omitted
    debug_info: Option<DebugInfo>, // Optional statement spans + variable updates
}
```

This bytecode can be used as:
- Locking scripts in Kaspa transaction outputs
- Spending conditions that must be satisfied to unlock funds
- Covenant constraints on how funds can be spent

## Debugger

The debugger runs compiled bytecode in a debug session that tracks the current program counter and source spans. When `record_debug_spans` is enabled, the compiler emits debug metadata so the debugger can reconstruct variable values even though the VM only has a stack.

At a glance:

- **Compile time**: record `DebugVariableUpdate`, `DebugParamMapping`, and `DebugMapping` tied to bytecode offsets.
- **Debug time**: select the latest update for each variable at the current PC and evaluate the stored AST expression tree.

This bridges source-level variables to a stack-based VM and enables stepping, breakpoints, and variable inspection.

## Language Features

### Contract Structure

Every Silverscript file starts with a pragma and defines a single contract:

```silverscript
pragma silverscript ^0.1.0;

contract ContractName(type1 param1, type2 param2) {
    // Constants (compile-time evaluated)
    int constant MAX_VALUE = 1000;

    // Functions
    function functionName(type3 arg1) {
        // Contract logic
    }
}
```

### Type System

**Primitive Types:**
- `int` - 64-bit signed integers
- `bool` - Boolean values (true/false)
- `string` - String literals
- `bytes`, `bytes4`, `bytes20`, etc. - Fixed or variable length byte arrays
- `pubkey` - Public keys (33 bytes)
- `sig` - ECDSA signatures
- `datasig` - Data signatures for oracle messages

### Operators

**Arithmetic:** `+`, `-`, `*`, `/`, `%`
**Comparison:** `==`, `!=`, `<`, `>`, `<=`, `>=`
**Logical:** `&&`, `||`, `!`
**Bitwise:** `&`, `|`, `^`

### Control Flow

```silverscript
// If-else
if (condition) {
    // ...
} else {
    // ...
}

// For loops
for (i, 0, 10) {
    // Loop body
}
```

### Require Statements

Validation is done through `require()` statements. If the condition fails, the script fails:

```silverscript
require(checkSig(sig, pubkey));
require(tx.time >= minBlock, "Timelock not expired");
```

### Transaction Introspection

Access transaction data during script execution:

```silverscript
// Transaction-level data
tx.version
tx.locktime
tx.time
tx.inputs.length
tx.outputs.length

// Input inspection
tx.inputs[0].value
tx.inputs[i].lockingBytecode
tx.inputs[i].outpointTransactionHash
tx.inputs[i].sequenceNumber

// Output inspection
tx.outputs[0].value
tx.outputs[i].lockingBytecode
tx.outputs[i].tokenCategory
tx.outputs[i].tokenAmount

// Contract introspection
this.activeInputIndex
this.activeBytecode
this.age
```

### Built-in Functions

```silverscript
// Cryptographic
checkSig(sig, pubkey)           // Verify signature
checkDataSig(sig, msg, pubkey)  // Verify data signature
blake2b(data)                   // Hash function

// Byte manipulation
data.length                     // Get byte length
data.reverse()                  // Reverse bytes
data.split(index)              // Split at index
data.slice(start, end)         // Extract substring

// Type conversion
int(bytes)                     // Convert bytes to integer
bytes(int)                     // Convert integer to bytes
```

### Functions (Inlining + Returns)

Silverscript supports calling user-defined functions. Calls are inlined at compile-time (the compiler currently enforces that a function may only call earlier-defined functions).

Return values require an explicit return signature and a `return(...)` statement:

```silverscript
contract Math() {
    function addMul(int a, int b) : (int, int) {
        return(a + b, a * b);
    }

    function main() {
        (int sum, int prod) = addMul(2, 3);
        require(sum == 5);
        require(prod == 6);
    }
}
```

### Arrays

Dynamic arrays are supported for element types with known sizes (e.g. `int[]`, `byte[]`, `bytes20[]`). Key operations:

- `arr.push(x)` appends an element
- `arr.length` yields the element count
- `arr[i]` indexes an element

Example (end-to-end covered by tests):

```silverscript
contract Sum() {
    int constant MAX_ARRAY_SIZE = 5;

    function sumArray(int[] arr) : (int) {
        require(arr.length <= MAX_ARRAY_SIZE);
        int sum = 0;
        for (i, 0, MAX_ARRAY_SIZE) {
            if (i < arr.length) {
                sum = sum + arr[i];
            }
        }
        return(sum);
    }

    function main() {
        int[] x;
        x.push(1);
        x.push(2);
        x.push(3);
        (int total) = sumArray(x);
        require(total == 6);
    }
}
```

### Units and Literals

```silverscript
// Amount units
1 satoshis, 1 sats
1 bitcoin

// Time units
30 seconds
60 minutes
24 hours
7 days

// Hex literals
0xdeadbeef

// Date literals
date("2024-12-31")
```

## Getting Started

### Prerequisites

- Rust 1.85.0 or later
- Cargo (comes with Rust)

### Building

```bash
cargo build --release
```

### Running Tests

```bash
# Test the entire workspace
cargo test

# Test only the language compiler
cargo test -p silverscript-lang

# Run a specific test
cargo test -p silverscript-lang parser_tests
```

### Compiling a Contract

```rust
use silverscript_lang::{compiler::compile_contract, ast::Expr, compiler::CompileOptions};

let source = r#"
    pragma silverscript ^0.1.0;

    contract P2PKH(bytes20 pkh) {
        function spend(pubkey pk, sig s) {
            require(blake2b(pk) == pkh);
            require(checkSig(s, pk));
        }
    }
"#;

// Provide constructor arguments
let pkh = vec![0u8; 20]; // Example public key hash
let constructor_args = vec![Expr::Bytes(pkh)];

// Compile with default options
let compiled = compile_contract(source, &constructor_args, CompileOptions::default())?;

// Use the bytecode
let script_bytes = compiled.script;
```

## Example Contracts

### P2PKH (Pay-to-Public-Key-Hash)

Basic signature check contract:

```silverscript
pragma silverscript ^0.1.0;

contract P2PKH(bytes20 pkh) {
    function spend(pubkey pk, sig s) {
        require(blake2b(pk) == pkh);
        require(checkSig(s, pk));
    }
}
```

**Location:** `silverscript-lang/tests/examples/p2pkh.sil`

### HODL Vault

Time and price oracle-based release contract:

```silverscript
pragma silverscript ^0.1.0;

contract HodlVault(
    pubkey ownerPk,
    pubkey oraclePk,
    int minBlock,
    int priceTarget
) {
    function spend(sig ownerSig, datasig oracleSig, bytes oracleMessage) {
        // Parse oracle message
        bytes4 blockHeightBin, bytes4 priceBin = oracleMessage.split(4);
        int blockHeight = int(blockHeightBin);
        int price = int(priceBin);

        // Validate conditions
        require(blockHeight >= minBlock);
        require(tx.time >= blockHeight);
        require(price >= priceTarget);

        // Verify signatures
        require(checkDataSig(oracleSig, oracleMessage, oraclePk));
        require(checkSig(ownerSig, ownerPk));
    }
}
```

**Location:** `silverscript-lang/tests/examples/hodl_vault.sil`

### More Examples

The `silverscript-lang/tests/examples/` directory contains many more examples:

- **announcement.sil** - On-chain data announcement
- **covenant_escrow.sil** - Multi-party escrow with arbitration
- **covenant_mecenas.sil** - Recurring payment covenant
- **transfer_with_timeout.sil** - Time-bounded transfer
- **token.sil** - Token covenant example

## Development

### Project Dependencies

**Core Dependencies:**
- `pest` - Parser generator
- `kaspa-txscript` - Kaspa script opcodes and execution
- `kaspa-consensus-core` - Kaspa consensus primitives
- `secp256k1` - Cryptographic operations
- `blake2b_simd` - Blake2b hashing

**Source:** Dependencies are pulled from the `rusty-kaspa` repository, branch `covpp-reset1`.

### Code Organization

**Parser (`parser.rs`):**
- Thin wrapper around Pest parser
- Exposes `parse_source_file()` and `parse_expression()`

**AST (`ast.rs`):**
- Defines all AST node types
- Implements parsing from Pest pairs to AST
- Includes `Serialize`/`Deserialize` for JSON export

**Compiler (`compiler.rs`):**
- Core compilation logic
- Stack-based code generation
- Error types and validation
- Handles covenant introspection opcodes

### Testing

The test suite includes:

- **parser_tests.rs** - Parsing validation
- **compiler_tests.rs** - Compilation correctness
- **examples_tests.rs** - All example contracts compile successfully
- **ast_json_tests.rs** - AST serialization tests

### Contributing

When working on the compiler:

1. Add test cases for new features
2. Update the grammar in `silverscript.pest`
3. Extend AST types in `ast.rs`
4. Implement compilation logic in `compiler.rs`
5. Run `cargo clippy` to check for issues
6. Run the full test suite

### Formatting

The project uses custom Rust formatting defined in `.rustfmt.toml`:

```bash
cargo fmt
```

### Linting

```bash
cargo clippy --all-targets --all-features
```

## Notes

- Kaspa dependencies are pulled from https://github.com/kaspanet/rusty-kaspa (branch `covpp-reset1`)
- The language is inspired by CashScript but targets Kaspa's scripting system
- Covenant support is experimental and requires `covenants_enabled: true`

## License

MIT License - See LICENSE file for details

## Authors

Kaspa developers
