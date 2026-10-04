
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

- Kaspa dependencies use the rusty-kaspa 2.1.0 crates published on crates.io.
