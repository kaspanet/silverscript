TODO: automate installation process
TODO: share highlights with Zed (./queries/highlights.scm)

- requirement node 22+
- `npm i`
- from `../../tree-sitter` - `npx tree-sitter build --wasm -o ..\extensions\vscode\assets\tree-sitter-silverscript.wasm`
- npm run compile (or watch mode: `npm run watch` - auto recompile on file changed)

Open a VsCode instance, and press F5, it should have a task named: "Run Extension", it will open a new VsCode instance with this extension installed.

Pro tip: Press ctrl+R on the extension host to apply changes
