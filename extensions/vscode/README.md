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
- The extension opens a small runner panel with constructor args, entrypoint args, and `Run` / `Debug` buttons.
- The panel also includes a key helper that can generate a keypair and insert `secret_key`, `pubkey`, or `pkh` into the currently focused field.
- The panel persists the latest values into an adjacent `*.debug.json` file so the next run opens with the same inputs.
- The debugger launches through the bundled Rust DAP adapter when available, with repo checkouts falling back to a local workspace build.

Use `SilverScript: Open Debug Params` if you still want to edit the sidecar file directly.

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
  "constructorArgs": ["3", "10"],
  "args": ["5", "5"],
  "stopOnEntry": true
}
```

If `function`, `constructorArgs`, or `args` are omitted, the debugger also looks for an adjacent `*.debug.json` file next to the `.sil` file:

```json
{
  "function": "main",
  "constructorArgs": {
    "x": 3,
    "y": 10
  },
  "args": {
    "a": 5,
    "b": 5
  }
}
```

The sidecar file also accepts arrays when needed, but keyed objects are easier to read and edit because names stay attached to values.

Launch configuration values override the sidecar file.

#### Transaction Context

The debugger now runs against a small synthetic transaction context by default so `sig` arguments can be auto-signed from a 32-byte secret key. Advanced users can override that runtime context by adding a `tx` object to `launch.json` or `*.debug.json`; this is intentionally kept out of the panel UI.
