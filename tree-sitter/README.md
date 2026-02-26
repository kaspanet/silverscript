Attempt at being 1:1 with Pest. Interesting file: `tree-sitter\grammar.js`.

- Install: `cargo install tree-sitter-cli --locked`
- Generate + sync highlights to editor extensions: `npm run generate`
- Build parser wasm (includes generate + sync): `npm run build`
- Standalone generate only: `npm run generate:raw`
- Standalone build only: `npm run build:raw`
- Open playground: `tree-sitter playground`

- Grammar DSL Documentation: https://tree-sitter.github.io/tree-sitter/creating-parsers/2-the-grammar-dsl.html
