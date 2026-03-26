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
Contract Constants:
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

### Inspection

Use `vars` to inspect the current source-level scope and `eval` to check expressions in that scope. This works for scalars, `State`, `State[]`, and custom `struct` values.

```bash
cli-debugger examples/debug_struct_state_matrix.sil --function inspect_state \
  --ctor-arg '{"amount":3,"code":"0x1234"}' \
  --arg '{"amount":5,"active":true,"tag":"0xaa"}'
```

```text
(sdb) vars
Contract Constants:
  seed_pair (Pair) = {amount: 3, code: 0x1234}
Contract State:
  amount (int) = 1
  active (bool) = true
  tag (byte[1]) = 0xaa
Call Arguments:
  next_state (State) = {amount: 5, active: true, tag: 0xaa}

(sdb) eval next_state.amount + amount
next_state.amount + amount = (int) 6
```

If the contract executes a source-level `console.log(...)`, its output appears under `Console:` while stepping. The same `vars` and `eval` flow also works for custom structs such as `Pair`.

---

## Testing

Run `.test.json` suites non-interactively to verify logic in bulk. If you pass a contract path without `--test-file`, the debugger will infer `name.test.json` from `name.sil`. If you pass `--test-file`, that exact file is used. Each test case defines the entrypoint, constructor arguments, call arguments, and expected result:

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
