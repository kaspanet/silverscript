# Constructor argument JSON

`silverc` accepts constructor values through `--constructor-args`. The file must
contain one JSON array whose elements correspond, in order, to the parameters in
the contract declaration.

For example:

```silverscript
contract Vault(int limit, bool enabled, byte[4] tag) {
    entry spend() {
        require(enabled);
    }
}
```

Its constructor argument file can be:

```json
[
  { "kind": "int", "value": 100 },
  { "kind": "bool", "value": true },
  { "kind": "bytes", "value": [83, 73, 76, 86] }
]
```

Compile it with:

```bash
cargo run -p silverscript-lang --bin silverc -- \
  vault.sil --constructor-args vault.args.json
```

The number and order of values must match the constructor parameters. Each value
is an object with a `kind` tag and a `value` of the corresponding JSON type.

| SilverScript type | Portable ABI JSON |
| --- | --- |
| `int` | `{ "kind": "int", "value": -42 }` |
| `temporal` | `{ "kind": "int", "value": 1000 }` |
| `bool` | `{ "kind": "bool", "value": true }` |
| `byte` | `{ "kind": "byte", "value": 255 }` |
| `string` | `{ "kind": "text", "value": "hello" }` |
| `byte[]`, `byte[N]` | `{ "kind": "bytes", "value": [1, 2, 3] }` |
| `pubkey`, `sig`, `datasig` | `{ "kind": "bytes", "value": [1, 2, 3] }` |
| Other arrays | `{ "kind": "array", "value": [...] }` |
| Struct | `{ "kind": "object", "value": {...} }` |

Byte values must be integers from 0 through 255. Fixed-size byte arrays must
contain exactly the declared number of bytes. Public keys and signatures are also
represented as byte arrays and must have the length required by their
SilverScript type.

Array elements are themselves portable ABI values. For `int[] values`, use:

```json
{
  "kind": "array",
  "value": [
    { "kind": "int", "value": 10 },
    { "kind": "int", "value": 20 }
  ]
}
```

Structs use `object`, with one entry for every field. Given:

```silverscript
contract Configured(Config config) {
    struct Config {
        int limit;
        bool enabled;
    }

    entry spend() {
        require(config.enabled);
    }
}
```

the complete constructor argument file is:

```json
[
  {
    "kind": "object",
    "value": {
      "limit": { "kind": "int", "value": 100 },
      "enabled": { "kind": "bool", "value": true }
    }
  }
]
```

Nested arrays and structs follow the same rule: every nested value includes its
own `kind` and `value`. Unknown or missing struct fields are rejected.

Tuple constructor parameters are not supported by the portable ABI value format.
