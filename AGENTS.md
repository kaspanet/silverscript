# AGENTS.md

This repository contains the SilverScript compiler, examples, tests, and source-level debugger. Treat this file as the root operating guide for agents working in this checkout.

## Project Facts

- SilverScript is a CashScript-inspired Rust language/compiler targeting Kaspa script.
- The workspace is experimental and may change language syntax, APIs, and artifact formats without compatibility guarantees.
- Compiled scripts produced by this repository are valid only on Kaspa Testnet 10. Do not assume mainnet compatibility, and verify `Cargo.toml` branch/revision details before changing dependency targets.
- The main crate is `silverscript-lang`; debugger crates live under `debugger/`.

## Read First

| Area | Read before editing |
| --- | --- |
| General orientation | `README.md` |
| Language syntax and examples | `docs/TUTORIAL.md` |
| Covenant declarations | `docs/DECL.md` |
| KCC20 examples | `docs/kcc20-book/README.md` |
| Debugger behavior | `debugger/cli/README.md` |
| Small fixtures | `silverscript-lang/tests/examples/` |
| App-style fixtures | `silverscript-lang/tests/apps/` |

## Build And Test

Use narrower tests while iterating, then run the relevant full command before handing work back.

| Change type | Verification |
| --- | --- |
| Rust formatting | `cargo fmt --all --check` |
| Compiler, parser, language, stdlib, examples | `cargo test -p silverscript-lang` |
| Debugger session runtime | `cargo test -p debugger-session` |
| Debugger CLI behavior | `cargo test -p cli-debugger` |
| Workspace-level dependency or shared behavior | Run all relevant package tests above |

Do not claim a test passed unless you ran it in this checkout. If a relevant command is too slow or blocked by the environment, report the exact command and blocker.

## Repo Map

- `silverscript-lang/src/parser.rs` and `silverscript-lang/src/silverscript.pest` define parsing.
- `silverscript-lang/src/ast/` owns AST structures and traversal.
- `silverscript-lang/src/compiler/` owns lowering, static checks, bytecode generation, debug recording, and covenant declaration support.
- `silverscript-lang/src/diagnostic/` owns parser/compiler diagnostics.
- `silverscript-lang/src/bin/silverc.rs` is the compiler CLI.
- `silverscript-lang/tests/` contains compiler, parser, diagnostics, covenant, CLI, tutorial, and app fixture tests.
- `debugger/session/` contains the source-level debugging runtime.
- `debugger/cli/` contains the interactive debugger CLI.
- `tree-sitter/` and `extensions/` are outside the Rust workspace; inspect their local READMEs before changing them.

## Change Routing

- Parser or syntax changes usually need grammar updates, AST/span checks, parser diagnostics, and examples.
- Compiler changes usually need targeted tests in `silverscript-lang/tests/` plus fixture coverage when behavior changes.
- Covenant declaration changes should update or check `docs/DECL.md` and covenant declaration tests.
- `silverc` output changes should update CLI tests and any affected docs/examples.
- Debugger changes should cover both `debugger-session` behavior and `cli-debugger` UX when user-visible.
- App examples belong in `silverscript-lang/tests/apps/`; small language examples belong in `silverscript-lang/tests/examples/`.

## Development Workflow

- Prefer existing compiler, debugger, and test patterns before adding new abstractions.
- Keep edits scoped to the crate or subsystem implied by the task.
- Add or update tests for changed behavior, especially parser/compiler diagnostics and covenant validation rules.
- Use the source-level debugger before guessing from raw VM errors such as `EvalFalse` or `VerifyError`.
- Keep examples generic unless this repo explicitly owns the full app workflow.
- Keep generated state, keys, wallet files, transaction artifacts, and local run outputs out of commits.
- Do not introduce secrets, mnemonics, private keys, or live wallet material into source, tests, logs, docs, or committed fixtures.

## Debugging

Start an interactive debugger session with:

```bash
cargo run -p cli-debugger -- <contract.sil> --function <entrypoint>
```

The debugger supports stepping, breakpoints, variable inspection, stack inspection, expression evaluation, and covenant `.test.json` scenarios. See `debugger/cli/README.md` for full commands, including `--run-all` and `--run --test-name`.

## Covenant Rules

- Test covenant behavior with real transaction contexts, not only successful compilation.
- Do not treat local VM validation, dry-run transaction construction, and network broadcast as the same layer.
- A contract passing local VM validation does not prove the corresponding transaction is ready to broadcast.
- Keep contract patterns separate from product-specific CLI, wallet, and network orchestration unless maintainers explicitly ask for the full workflow.
- For app-style tooling, keep artifact/state formats explicit: contract name, network, redeem script, serialized script public key, state fields, and txid/outpoint metadata used by later transitions.

## Covenant Pitfalls

- `tx.outputs[i].scriptPubKey` is serialized `ScriptPublicKey` bytes, including version bytes, not only the script body.
- P2SH covenant spends need the redeem script and function arguments wrapped as the expected P2SH signature script.
- `validateOutputStateWithTemplate` depends on the target contract state layout, template prefix, template suffix, and template hash all matching.
- `OpBin2Num` uses script-number signed interpretation; be explicit when converting hash bytes to numbers.
- `this.age` depends on input sequence and relative-lock semantics in the transaction being validated.

## Common App Patterns

- Commit-reveal flows.
- Offer/accept transitions into a state UTXO.
- Timeout and reclaim paths.
- Validating exact output value and `scriptPubKey`.
- Template-bound transitions between cooperating contracts.
