# SilverScript CLI Debugger

A light-weight tool for stepping through and testing SilverScript smart contracts.

### Quick Start

```bash
cli-debugger <path> -f <function> [--ctor-arg <val>]... [--arg <val>]...
```

**Example:**
```bash
cli-debugger ./counter.sil -f check --ctor-arg 10 --arg 7
```

---

## Interactive Debugging

Launch a session to explore how your contract behaves line-by-line.

```solidity
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
value (int) = 7
doubled (int) = 14
threshold (const) (int) = 10
(sdb) c
Done.
```

### Essential Commands

| Command | Action |
|---|---|
| `n` | **Next**: Step over to the next statement |
| `s` | **Step**: Step into a function |
| `c` | **Continue**: Run until the next breakpoint or completion |
| `b <line>` | **Break**: Set a breakpoint (e.g., `b 10`) |
| `vars` | **Variables**: List all variables and constants in scope |
| `p <name>` | **Print**: Show the value of a specific variable |
| `stack` | **Stack**: Inspect the raw Kaspa VM execution stack |
| `l` | **List**: Show the source code around your current position |
| `q` | **Quit**: Exit the debugger |

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

### Commands

```bash
# Run all tests using the sidecar inferred from the contract path
cli-debugger <contract-path> --run-all

# Run a specific test case using the sidecar inferred from the contract path
cli-debugger <contract-path> --run --test-name <name>
```

Add `--test-file <path>` to either form to use an explicit test file instead of the inferred json file path

**Output Example:**
```text
  PASS  valid_transfer
  FAIL  insufficient_funds
        FAIL: expected failure but script passed

10 tests: 9 passed, 1 failed
```
