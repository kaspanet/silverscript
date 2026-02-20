### Pre-release

`npm exec vsce package -- --pre-release`

### Development

- Requirement: Node.js 22+.
- In `extensions/vscode`, install dependencies with `npm i`.
- Build the extension once with `npm run compile` (or keep it rebuilding with `npm run watch`).
- Open `extensions/vscode` in VS Code.
- Press `F5` and run `Run Extension` to start an Extension Development Host with this extension loaded.

#### Live Grammar Changes

Build the grammar from your working tree and sync the WASM used by the VS Code extension:

```bash
cd tree-sitter
npm run build:vscode
```

This also refreshes shared highlighting queries (`extensions/vscode/queries/highlights.scm`).

Then in the Extension Development Host, press `Ctrl+R` to reload and apply parser/query updates.
