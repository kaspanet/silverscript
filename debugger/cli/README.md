# SilverScript CLI Debugger

A light-weight, GDB-like attempt at stepping through and testing SilverScript contracts.

### Quick Start

```bash
cli-debugger <path> -f <function> [--ctor-arg <val>]... [--arg <val>]...
```

**Example:**
```bash
cli-debugger ./counter.sil -f check --ctor-arg 10 --arg 7
```

Structured `State` and custom `struct` args use JSON:

```bash
cli-debugger ./vault.sil -f inspect --arg '{"amount":7,"tag":"0xbeef"}'
cli-debugger ./vault.sil -f inspect_many --arg '[{"amount":7},{"amount":9}]'
```

---

## Interactive Debugging

Launch a session to explore how your contract behaves line-by-line.

```javascript
// counter.sil
contract Counter(int threshold) {
    entrypoint function check(int value) {
        int doubled = value + value;
        require(doubled > threshold);
    }
}
```

When the session starts, you'll see your source context and the `(sdb)` prompt:

```text
Stepping through 42 bytes of script
     1 | pragma silverscript ^0.1.0;
     2 | 
     3 | contract Counter(int threshold) {
     4 |     entrypoint function check(int value) {
→    5 |         int doubled = value + value;
     6 |         require(doubled > threshold);
     7 |     }
     8 | }
(sdb) n
→    6 |         require(doubled > threshold);
(sdb) vars
Constructor Args:
  threshold (int) = 10
Call Arguments:
  value (int) = 7
Locals:
  doubled (int) = 14
(sdb) eval doubled + 1
doubled + 1 = (int) 15
(sdb) c
Done.
```

### Commands

| Command | Action |
|---|---|
| `n` (`next`, `over`) | **Next**: Step over to the next statement |
| `s` (`step`, `into`) | **Step**: Step into a function |
| `si` | **Step Opcode**: Advance by one VM opcode |
| `finish` (`out`) | **Step Out**: Continue until the current frame returns |
| `c` (`continue`) | **Continue**: Run until the next breakpoint or completion |
| `b [line]` (`break [line]`) | **Break**: Set a breakpoint (e.g. `b 10`) or list current breakpoints |
| `vars` | **Variables**: List all variables and constants in scope |
| `e <expr>` (`eval <expr>`) | **Evaluate**: Run an expression in the current debugger scope |
| `p <name>` (`print <name>`) | **Print**: Show the value of a specific variable |
| `stack` | **Stack**: Inspect the raw Kaspa VM execution stack |
| `l` (`list`) | **List**: Show the source code around your current position |
| `h` / `?` (`help`) | **Help**: Show the command summary |
| `q` (`quit`) | **Quit**: Exit the debugger |

---

## Testing

Run `.test.json` suites non-interactively to verify logic in bulk. If you pass a contract path without `--test-file`, the debugger will infer `name.test.json` from `name.sil`. If you pass `--test-file`, that exact file is used. Each test case defines the function, constructor arguments, call arguments, and expected result:

```json
{
  "tests": [
    {
      "name": "valid_transfer",
      "function": "transfer",
      "constructor_args": [100],
      "args": [50],
      "expect": "pass"
    }
  ]
}
```

The debugger will report `PASS` if the script result matches your `expect` field (either `pass` or `fail`).

Structured args use the same JSON object and object-array form inside `.test.json`:

```json
{
  "tests": [
    {
      "name": "inspect_state",
      "function": "inspect",
      "args": [{ "amount": 7, "tag": "0xbeef" }],
      "expect": "pass"
    },
    {
      "name": "inspect_many_states",
      "function": "inspect_many",
      "args": [[{ "amount": 7 }, { "amount": 9 }]],
      "expect": "pass"
    }
  ]
}
```

For covenant tests, add a `tx` section to describe the spend:
- `active_input_index` chooses which input you want to debug
- `covenant_id` links related covenant inputs and outputs
- each input or output state can be described with either `constructor_args` or an explicit `state` object

For covenant verification functions, you usually do not need to pass state values in `args`:
- `prev_state` / `prev_states` come from the spent inputs
- `new_state` / `new_states` come from the outputs

So `args` only needs the remaining non-state function arguments. If there are none, you can leave `args` out.

```json
{
  "tests": [
    {
      "name": "source_leader",
      "function": "step",
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [
          {
            "utxo_value": 1000,
            "covenant_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "state": { "value": 7 }
          },
          {
            "utxo_value": 1000,
            "covenant_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "state": { "value": 9 }
          }
        ],
        "outputs": [
          {
            "value": 1000,
            "covenant_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "state": { "value": 11 }
          },
          {
            "value": 1000,
            "covenant_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "state": { "value": 13 }
          }
        ]
      }
    }
  ]
}
```

If an output is authorized by a different input, set `authorizing_input` on that output explicitly.

### Test Commands

```bash
# Run all tests using the matching `.test.json` file inferred from the contract path
cli-debugger <contract-path> --run-all

# Run a specific test case using the matching `.test.json` file inferred from the contract path
cli-debugger <contract-path> --run --test-name <name>
```

Add `--test-file <path>` to either form to use an explicit test file instead of the inferred `.test.json` path.

**Output Example:**
```text
  PASS  valid_transfer
  FAIL  insufficient_funds
        FAIL: expected failure but script passed

10 tests: 9 passed, 1 failed
```
