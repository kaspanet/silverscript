
# Silverscript

Silverscript is a CashScript-inspired language and compiler that targets Kaspa script.

## Workspace

This repository is a Rust workspace. The main crate is `silverscript-lang`.

## Build & Test

```bash
cargo test -p silverscript-lang
```

## Running `silverc`

Run the compiler from the workspace with Cargo:

```bash
cargo run -p silverscript-lang --bin silverc -- contract.sil
```

By default, `silverc` writes the compiled JSON artifact beside the source file as
`contract.json`. Use `-o` to choose another output path, or `-c` to write the
artifact to standard output:

```bash
cargo run -p silverscript-lang --bin silverc -- contract.sil -o artifact.json
cargo run -p silverscript-lang --bin silverc -- contract.sil -c
```

For a contract such as `contract Limit(int limit)`, put its constructor arguments
in a JSON array:

```json
[{ "kind": "int", "value": 100 }]
```

Then pass the file to `silverc`:

```bash
cargo run -p silverscript-lang --bin silverc -- \
  contract.sil --constructor-args args.json
```

Constructor arguments are positional and use SilverScript's portable ABI JSON
format. See [Constructor argument JSON](docs/CONSTRUCTOR_ARGS.md) for every
supported value type and more examples.

Use `--ast-only` to parse the source and emit AST JSON without compiling it:

```bash
cargo run -p silverscript-lang --bin silverc -- contract.sil --ast-only
```

Run with `--help` to see all available options.

### Compute budget estimates

Spending an output of a compiled contract requires committing a compute budget
on the input, and the script engine rejects the input if execution needs more
script units than the budget allows. Every entry in the artifact carries a
static upper bound of the script units it charges, so the budget can be chosen
without a trial submission:

```json
"verify": {
  "dispatch_tag": "…",
  "params": [ … ],
  "compute": {
    "script_units": 25001088,
    "script_units_per_byte": { "control_digests": 1, "redeem_script": 2, "seal": 2 },
    "sig_ops": 0
  }
}
```

The bound is `script_units + Σ script_units_per_byte[key] × length(key)`,
evaluated with the byte length of each variable-length argument's
signature-script push (`seal`, or `point.tag` for a struct leaf), of each
variable-length state field (`state.<name>`), of the redeem script the spender
pushes (`redeem_script`, hashed by the pay-to-script-hash output script), and
of each transaction field the entry reads through introspection (`tx.payload`,
`tx.inputs[<i>].signature_script`, `tx.inputs[<i>].script_public_key`,
`tx.outputs[<i>].script_public_key`; script public keys count their two-byte
version prefix, and a `*` index stands for any input or output, so use the
largest such length in the transaction). The bound follows the most expensive
path through the entry and prices signature operations at mainnet's rate.
Copies, concatenations, splits at known offsets, hashes, and verifications are
tracked exactly; comparison and arithmetic results and the encoded size of a
variable length are rounded up to their largest encoding, so the bound exceeds
the metered units by at most a few units per such operation.

`silverscript_abi::entry_argument_byte_lengths` computes the argument lengths
for a call, `ComputeEstimateArtifact::compute_budget_with` turns the bound
into the smallest sufficient `computeBudget`, and the debugger prints the
units a completed `--run` actually metered next to that budget.

## Debugger

The workspace includes a source-level debugger for stepping through scripts:

```bash
cargo run -p cli-debugger -- \
  silverscript-lang/tests/examples/if_statement.sil \
  --function hello \
  --ctor-arg 3 --ctor-arg 10 \
  --arg 1 --arg 2
```

## Layout

- `silverscript-lang/` – compiler, parser, and tests
- `debugger/session/` – `DebugSession` runtime (stepping, variable inspection)
- `debugger/cli/` – `sil-debug` CLI REPL
- `silverscript-lang/tests/examples/` – example contracts (`.sil` files)

## Documentation

See [TUTORIAL.md](docs/TUTORIAL.md) for a full language and usage tutorial, [DECL.md](docs/DECL.md) for the covenant declaration spec, and the [KCC20 book](https://kaspanet.github.io/silverscript/kcc20-book/).

## Credits

See [CREDITS.md](CREDITS.md) for acknowledgements and credits.

## Security

To report a security vulnerability privately, follow the instructions in the
[security policy](SECURITY.md).

## Notes

- Kaspa dependencies are pulled from https://github.com/kaspanet/rusty-kaspa.
