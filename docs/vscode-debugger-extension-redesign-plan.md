# VS Code Debugger Extension Redesign Plan

## Positioning

The VS Code extension should be rebuilt after the DAP layer lands. It should treat `debugger-dap` as the product boundary and avoid duplicating compiler, covenant, transaction, or state semantics in TypeScript.

The extension PR should not be part of the DAP PR.

## Product Goal

Make it easy to debug real covenant flows, including KCC20, without asking users to hand-author large launch objects from memory.

The initial extension success case should be:

- open `kcc20.sil`
- choose a saved KCC20 fixture/run profile
- launch the DAP adapter
- stop in source-level covenant code
- inspect `prevStates`, `newStates`, constructor args, contract fields, locals, and stack scopes
- run to completion or failure with the same error report as the CLI/DAP layer

## Design Direction

1. Keep the adapter boring.
   - Use the DAP binary directly.
   - Do not embed a second debug adapter in TypeScript.
   - Do not reimplement transaction/state construction in the extension.

2. Make launch configuration file-first.
   - Support opening and running JSON launch files like `debugger/fixtures/kcc20-flow/*.json`.
   - Keep VS Code `launch.json` support, but do not make it the only workflow.
   - Let users save named run profiles next to the contract or in a workspace debug folder.

3. Build a covenant-aware run profile editor.
   - Inspect the contract for constructor params and source covenant functions.
   - Present structured `State` and `State[]` editors as JSON objects/arrays.
   - Provide transaction input/output sections with covenant IDs, authorizing input, constructor args, and explicit state.
   - Show generated entrypoint details only as advanced/debug information.

4. Prefer validation over generation magic.
   - Validate JSON shape before launch.
   - Validate missing function, constructor arg count, active input index, and state object shape by asking the DAP/CLI validation path where possible.
   - Surface errors in the VS Code UI without rewriting them.

5. Keep KCC20 as the acceptance fixture.
   - Ship or document the KCC20 flow fixtures as examples.
   - Add extension tests that launch those profiles through the actual DAP binary.

## Proposed Extension PR Slices

1. Minimal adapter host.
   - Register the SilverScript debug type.
   - Resolve or build `debugger-dap`.
   - Launch existing JSON configs.

2. Run profile explorer.
   - Discover `*.debug.json` or selected fixture files.
   - Provide run/debug buttons for saved profiles.
   - Avoid custom webview UI initially unless native VS Code tree/detail views are insufficient.

3. Covenant profile editor.
   - Add a focused editor or webview only for editing structured tx/state JSON.
   - Keep it backed by the same JSON file on disk.

4. KCC20 workflow polish.
   - Add commands for the four KCC20 flow profiles.
   - Make failures navigable to source locations reported by DAP.

## Non-Goals

- No TypeScript implementation of covenant state materialization.
- No extension-specific transaction semantics.
- No bundled fork of the DAP protocol.
- No custom UI before the JSON profile workflow is stable.

