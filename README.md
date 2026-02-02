
# Silverscript

Silverscript is a CashScript-inspired language and compiler that targets Kaspa script.

**Status:** Experimental — the project is unstable and may introduce breaking changes without notice. Use with caution and expect language syntax, APIs and output formats to change.

**Note:** The compiled scripts produced by this repository are valid only on Kaspa Testnet 12. Do not assume compatibility with other Kaspa networks or mainnet.

## Workspace

This repository is a Rust workspace. The main crate is `silverscript-lang`.

## Build & Test

```bash
cargo test -p silverscript-lang
```

## Layout

- `silverscript-lang/` – compiler, parser, and tests
- `silverscript-lang/tests/examples/` – example contracts (`.sil` files)

## Documentation

See [TUTORIAL.md](TUTORIAL.md) for a full language and usage tutorial.

## Credits

See [CREDITS.md](CREDITS.md) for acknowledgements and credits.

## Notes

- Kaspa dependencies are pulled from https://github.com/kaspanet/rusty-kaspa (branch `covpp-reset1`).
