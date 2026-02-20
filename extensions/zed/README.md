### Development

- Set `repository` in `extensions\zed\extension.toml` to this repository root (absolute path required).
- In Zed, press `Ctrl+Shift+P` and run `install dev extension`, then pick `extensions/zed`.

#### Live Grammar Changes

Build the grammar from your working tree and copy the wasm into the dev extension:

```bash
cd tree-sitter
npm run build:zed
```

Then in Zed run `zed: reload extensions`.

### Release

Before sharing or committing extension metadata updates, set `rev` to a real commit SHA in
`extensions\zed\extension.toml`.

### Syntax highlight (`highlights.scm`)

https://tree-sitter.github.io/tree-sitter/3-syntax-highlighting.html
