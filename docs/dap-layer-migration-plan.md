# DAP Layer Migration Plan

## Current Git State

- Working branch: `dap-and-vsc-debugger`
- New base: `origin/covpp-reset2` at `efd4293` (`Fix State[] field access for array fields (#111)`)
- Backup branch before rebasing: `codex/dap-and-vsc-debugger-pre-covpp-reset2-rebase`
- Preserved pre-rebase dirty worktree: `stash@{0}` (`pre-rebase dap-vscode dirty worktree`)
- The rebased branch still contains the historical combined DAP and VS Code extension changes. The next cleanup step should split the PR surface before implementation continues.

## Goal

Prepare a first PR that reintroduces only the DAP layer on top of the covenant-aware debugger/session work from `covpp-reset2`.

The VS Code extension should be a later PR that consumes the stable DAP binary/protocol behavior after the DAP layer has landed.

The concrete end-to-end target for this migration is debugging the full KCC20 token flow from an initialized minter branch, through token creation, token burn, and created-token transfer. The JSON launch fixtures for that flow live under `debugger/fixtures/kcc20-flow/`.

## Scope For The DAP PR

Keep:

- `debugger/dap/**`
- Workspace wiring needed to build the DAP crate:
  - `Cargo.toml`
  - `Cargo.lock`
- Minimal shared debugger/session API changes that are required by the DAP layer and are not VS Code specific.
- DAP tests that exercise the adapter and launch/runtime behavior.

Defer:

- `extensions/vscode/**`
- Extension packaging, CodeLens, quick launch UI, webviews, and adapter bootstrap scripts.
- Any UX or editor-specific launch configuration migration.

## Important Upstream Changes To Preserve

The reset branch has deliberate covenant support inside the debugger/session layer. The DAP migration should reuse it instead of duplicating older launch/runtime logic.

Relevant upstream pieces:

- `debugger/session/src/covenant.rs`
  - Resolves source covenant functions to generated entrypoints.
  - Tracks auth/cov binding, verification/transition mode, generated names, and source binding metadata.
- `DebugSession::with_covenant_mode`
  - Activates covenant display names and synthetic binding overlays.
  - Preserves source-level stepping behavior by hiding generated covenant internals.
- `debugger/session/src/args.rs`
  - Parses constructor/call args from the contract AST rather than ABI strings.
  - Supports structured `State`, `State[]`, custom structs, fixed byte arrays, and explicit state values.
- `debugger/cli/src/main.rs`
  - Is the current reference implementation for covenant launch behavior, including generated covenant entrypoint selection, synthesized prefix args, and explicit state materialization.

## Migration Plan

1. Split the branch surface.
   - Create or keep a DAP-only branch based on the current rebased `dap-and-vsc-debugger`.
   - Remove VS Code extension commits/files from the DAP PR branch.
   - Keep the pre-rebase backup branch and stash until both DAP and VS Code follow-up work are accounted for.

2. Rebase-normalize the DAP crate against covenant-aware APIs.
   - Replace older ABI-string argument parsing in `debugger/dap/src/runtime_builder.rs` with the contract-AST based parser used by the CLI.
   - Resolve user-selected source covenant functions through `resolve_covenant_call_target`.
   - Launch generated covenant entrypoints where appropriate, while displaying source covenant function names through `DebugSession`.
   - Pass `with_covenant_mode(...)` and covenant state values into the session when debugging covenant flows.

3. Align transaction and state setup with CLI behavior.
   - Reuse the CLI’s covenant transaction semantics rather than adding a parallel DAP-only interpretation.
   - Support `prev_state`/`prev_states`, generated leader/delegate entrypoints, and explicit state scripts consistently with the CLI/test runner.
   - Keep DAP launch JSON as a transport format only; do not make it an alternate contract semantics layer.

4. Rework DAP tests around the new base.
   - Keep adapter protocol tests focused on DAP behavior: launch, breakpoints, stack trace, scopes, variables, stepping, and errors.
   - Add covenant-oriented DAP launch cases only after the runtime path is using the upstream covenant session support.
   - Avoid importing VS Code fixtures or extension behavior into DAP tests.

5. Verify the DAP-only PR.
   - `cargo fmt`
   - `cargo check -p debugger-dap`
   - `cargo test -p debugger-dap`
   - Relevant `debugger-session` tests if shared session APIs are touched.

## Known Cleanup Before Implementation

- The rebased diff still includes `extensions/vscode/**`; those files must be removed from the DAP PR branch before opening the first PR.
- `debugger/dap/src/runtime_builder.rs` still reflects the older pre-reset launch path and must be reconciled with the covenant-aware CLI/session path.
- `debugger/session/src/args.rs` currently keeps a small `values_to_args` helper for the DAP launch config. If the DAP launch parser is refactored, either keep this as shared utility or move it into DAP-local config parsing.

## Resolved Build Blockers

The initial post-rebase `cargo check -p debugger-dap` failures have been resolved:

- `DebugSession::format_value` no longer exists as a session method; DAP formatting should use the current `debugger_session::format_value` helper pattern used by the CLI.
- `DebugSession::current_function_name` now returns `Option<String>`, so DAP stack frame naming needs to drop the old borrowed-string conversion.
- `parse_call_args` now takes `(&ContractAst, function_name, raw_args)` rather than ABI input type strings.
- `EngineFlags` gained `sigop_script_units`.
- `TestTxInputScenarioResolved` and `TestTxOutputScenarioResolved` gained `state`.
- `TransactionInput` uses `mass` rather than `sig_op_count`.
- `VariableOrigin` now includes `ContractField` and `ConstructorArg`, and DAP variable presentation must account for both.

Verification now passes with:

- `cargo check -p debugger-dap`
- `cargo test -p debugger-dap`
- all `debugger/fixtures/kcc20-flow/*.json` through `debugger-dap --run-config-json`
