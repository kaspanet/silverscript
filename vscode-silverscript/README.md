# SilverScript for Visual Studio Code

Syntax highlighting and code snippets for [SilverScript](https://github.com/kaspanet/silverscript) — a smart contract language for Kaspa.

## Features

- Full syntax highlighting for `.sil` files
- 18 code snippets for common contract patterns
- Bracket matching, auto-closing pairs, and code folding
- Indentation support

## Syntax Highlighting

The grammar covers all SilverScript language constructs:

| Element | Scope | Examples |
|---------|-------|---------|
| Control flow | `keyword.control` | `if`, `else`, `for`, `return`, `yield`, `require` |
| Declarations | `keyword.other` | `pragma`, `contract`, `entrypoint`, `function`, `new`, `constant` |
| Types | `storage.type` | `int`, `bool`, `string`, `pubkey`, `sig`, `datasig`, `byte`, `bytes`, `bytes32` |
| Booleans | `constant.language.boolean` | `true`, `false` |
| Numbers | `constant.numeric` | `42`, `1_000`, `1e6`, `0xFF` |
| Strings | `string.quoted` | `"hello"`, `'world'` |
| Comments | `comment` | `// line`, `/* block */` |
| `this.*` introspection | `variable.language.this` | `this.activeInputIndex`, `this.activeBytecode`, `this.age` |
| `tx.*` introspection | `variable.language.tx` | `tx.version`, `tx.inputs.length`, `tx.outputs[0].value` |
| Built-in functions | `support.function.builtin` | `blake2b`, `sha256`, `checkSig`, `checkMultiSig`, `checkDataSig` |
| Locking bytecode classes | `support.class` | `LockingBytecodeP2PK`, `LockingBytecodeP2SH`, etc. |
| Operators | `keyword.operator` | `+`, `-`, `==`, `!=`, `&&`, `\|\|` |
| Number units | `support.constant.unit` | `litras`, `grains`, `kas`, `seconds`, `days`, `weeks` |
| Contract name | `entity.name.type.contract` | name after `contract` |
| Function name | `entity.name.function` | name after `function` |
| Postfix methods | `support.function.method` | `.split()`, `.slice()`, `.push()` |
| Postfix properties | `support.variable.property` | `.length`, `.value`, `.lockingBytecode` |
| `console.log` | `keyword.other.debug` | `console.log(...)` |
| `date(...)` | `support.function.date` | `date("2021-01-01T00:00:00")` |

## Snippets

| Prefix | Description |
|--------|-------------|
| `pragma` | Pragma directive |
| `contract` | Complete contract with pragma |
| `entrypoint` | Entrypoint function |
| `function` | Internal function |
| `functionret` | Function with return type |
| `require` | Require assertion |
| `requiremsg` | Require with error message |
| `if` | If statement |
| `ifelse` | If-else statement |
| `for` | For loop |
| `constant` | Constant declaration |
| `p2pkh` | P2PK contract template |
| `covenant` | Covenant output check pattern |
| `checksig` | Signature verification |
| `timelock` | Time lock check |
| `yield` | Yield statement |
| `consolelog` | Debug console.log |
| `transfertimeout` | Transfer with timeout contract |

## Example

```sil
pragma silverscript ^0.1.0;

contract TransferWithTimeout(
    pubkey sender,
    pubkey recipient,
    int timeout
) {
    entrypoint function transfer(sig recipientSig) {
        require(checkSig(recipientSig, recipient));
    }

    entrypoint function reclaim(sig senderSig) {
        require(checkSig(senderSig, sender));
        require(tx.time >= timeout);
    }
}
```

## Installation

### From VSIX (local)

```bash
cd vscode-silverscript
npx @vscode/vsce package
code --install-extension silverscript-0.1.0.vsix
```

### From Source (development)

```bash
code --extensionDevelopmentPath=/path/to/silverscript/vscode-silverscript
```

## Links

- [SilverScript Repository](https://github.com/kaspanet/silverscript)
- [SilverScript Tutorial](https://github.com/kaspanet/silverscript/blob/main/TUTORIAL.md)
- [Kaspa](https://kaspa.org)

## License

MIT
