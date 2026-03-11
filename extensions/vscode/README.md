### Pre-release

Build a platform-specific VSIX that bundles the native Rust debug adapter:

```bash
npm run package:vsix
```

By default this packages the adapter for the current host platform into `bin/<platform-arch>/`.

For CI or cross-target release jobs, set:

- `SILVERSCRIPT_VSCODE_TARGET`, for example `darwin-arm64` or `linux-x64`
- `SILVERSCRIPT_CARGO_TARGET`, for example `aarch64-apple-darwin`

Then run `npm run package:vsix`.

### Development

- Requirement: Node.js 22+.
- In `extensions/vscode`, install dependencies with `npm i`.
- Build the extension once with `npm run compile` (or keep it rebuilding with `npm run watch`).
- Open `extensions/vscode` in VS Code.
- Press `F5` and run `Run Extension` to start an Extension Development Host with this extension loaded.
- In a full repo checkout, the extension can still auto-build `debugger-dap` on demand for local development. Published VSIX builds should use the bundled adapter path instead.

#### Live Grammar Changes

Build the grammar from your working tree and sync the WASM used by the VS Code extension:

```bash
cd tree-sitter
npm run build:vscode
```

This also refreshes shared highlighting queries (`extensions/vscode/queries/highlights.scm`).

Then in the Extension Development Host, press `Ctrl+R` to reload and apply parser/query updates.

### Contract Debugging

This extension provides a lean DAP-based contract debugger.

#### Launch Flow

- Run `SilverScript: Run / Debug Contract` on an open `.sil` file, or press `F5`.
- The extension opens a lightweight runner panel for the current `.sil` file.
- The panel owns the current run/debug session state for constructor args and function args.
- Use `Load Saved` to pull an existing `silverscript` launch config for the current file into the panel.
- Use `Save Scenario` to write the current panel state back to `launch.json`.
- The debugger launches through the bundled Rust DAP adapter when available, with repo checkouts falling back to a local workspace build.

If you need a custom adapter build, set `silverscript.debugAdapterPath` to an absolute path and the extension will use that binary instead.

#### Parameters

Launch configurations can provide:

```json
{
  "type": "silverscript",
  "request": "launch",
  "name": "SilverScript: Debug Contract",
  "scriptPath": "${file}",
  "function": "main",
  "constructorArgs": {
    "x": "3",
    "y": "10"
  },
  "args": {
    "a": "5",
    "b": "5"
  },
  "stopOnEntry": true
}
```

The panel does not live-edit `launch.json`. It edits the current session state and can load/save named launch configs when you want persistence. Advanced fields such as `tx` stay in `launch.json` and are preserved when a saved scenario is loaded and updated through the panel.

For contracts that need identity-like values, launch args can use symbolic tokens instead of concrete key material:

```json
{
  "function": "spend",
  "args": {
    "pk": "keypair1.pubkey",
    "s": "keypair1.secret"
  }
}
```

Supported identity tokens are:

- `keypair<N>.pubkey`
- `keypair<N>.secret`
- `keypair<N>.pkh`

They are resolved lazily by the Rust runtime and stay consistent within a single launch/run only.

The panel includes an `Identities` helper that fills these tokens directly into `pubkey`, `sig`, and `pkh`-style fields.

#### Transaction Context

The debugger runs against a small synthetic transaction context by default so `sig` arguments can be auto-signed from a 32-byte secret key. Advanced users can override that runtime context by adding a `tx` object to `launch.json`; this is intentionally kept out of the panel UI.
