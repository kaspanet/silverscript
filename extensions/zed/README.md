### Development

- Change `extensions\zed\extension.toml` the root of this repository (absolute path required)

Optional, if you want to change the grammar:

1. generate `tree-sitter` (in `/tree-sitter`) and create a local commit
2. change the `rev` field with the git HEAD revision (`git rev-parse HEAD`)

Press ctrl+shift+p and enter: "install dev extension", pick this folder (`/extensions/zed`), click open.

### Syntax highlight (`highlights.scm`)

https://tree-sitter.github.io/tree-sitter/3-syntax-highlighting.html
