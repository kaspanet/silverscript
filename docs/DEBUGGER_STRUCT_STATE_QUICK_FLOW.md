# Struct/State Debugger Quick Flow

This is the short version of [`DEBUGGER_STRUCT_STATE_OVERVIEW.md`](./DEBUGGER_STRUCT_STATE_OVERVIEW.md).

Use this if you already understand:

- the compiler records debug info while compiling

and you want the missing piece:

- how `State`, custom `struct`s, and covenant prior-state values fit into that model

If that stepping sentence is still fuzzy, here is the plain version:

- each source statement is recorded as a `DebugStep`
- each `DebugStep` has a bytecode range: `bytecode_start..bytecode_end`
- while debugging, the session executes one opcode at a time
- after each opcode, the session knows its current bytecode offset
- it finds which recorded step covers that offset
- that is how it knows "we are currently at this source statement"

So source stepping is not magic. It is just:

- run opcodes
- keep track of the current byte offset
- look up which recorded source step owns that byte range

Example:

```text
statement A -> bytecode 20..27
statement B -> bytecode 27..33
statement C -> bytecode 33..41
```

If the VM is currently executing bytecode offset `29`, the session says:

- offset `29` is inside `27..33`
- so the active source step is statement B

That is what "mapping bytecode offsets back to recorded source steps" means.

## The 5 facts that matter

1. `State` and custom `struct`s are source-level shapes, not runtime objects.
2. The compiler flattens them into hidden leaf bindings like `__struct_next_state_amount`.
3. Debug info records enough metadata to rebuild the source-level shape later.
4. `vars` shows source-level objects, not hidden leaf names.
5. `eval` lowers structured access inside the session by using recorded structured metadata.

If you keep those 5 facts in your head, the rest of the debugger becomes much easier to read.

## Before structs: how stepping works

The debugger has two different notions of position:

- opcode position: where the VM currently is in the compiled script
- source position: which source statement that bytecode belongs to

The compiler creates the bridge between them by recording `DebugStep`s.

Conceptually:

```text
source:
  int bumped = next_state.amount + amount;   -> step range 120..129
  require(next_state.active == active);      -> step range 129..138
```

During debugging, the session:

1. executes opcodes
2. tracks the current bytecode offset
3. finds the `DebugStep` whose range contains that offset
4. treats that step's source span as the current source location

So when you run `si` or `next`, the session is not stepping by source code directly.

It is:

- executing bytecode
- watching when the active recorded step changes

That is the base debugger model. Struct/state support sits on top of that.

## One concrete contract

Use:

- [`examples/debug_struct_state_matrix.sil`](../examples/debug_struct_state_matrix.sil)

Relevant part:

```sil
contract DebugStructStateMatrix(Pair seed_pair) {
    struct Pair {
        int amount;
        byte[2] code;
    }

    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;

    entrypoint function inspect_state(State next_state) {
        int bumped = next_state.amount + amount;
        require(next_state.active == active);
    }

    function inspect_inner(State inner_state, Pair inner_pair) {
        int bumped = inner_state.amount + amount;
        require(bumped > 0);
    }

    entrypoint function inspect_inline(State next_state, Pair next_pair) {
        inspect_inner(next_state, next_pair);
        require(next_state.active == active);
    }
}
```

## The core idea

At source level:

```sil
next_state.amount
```

At runtime/debug leaf level:

```text
__struct_next_state_amount
```

A whole `State next_state` is really treated as:

```text
__struct_next_state_amount : int
__struct_next_state_active : bool
__struct_next_state_tag    : byte[1]
```

So the debugger always does two opposite things:

- for compilation/eval, it lowers source-level field access to leaf names
- for display, it rebuilds a source-level object from leaf values

## One end-to-end flow

Take this statement:

```sil
int bumped = next_state.amount + amount;
```

and this debugger command:

```text
eval next_state.amount + amount
```

### 1. Compiler view

The compiler knows `State` from the contract fields:

```text
State:
  amount -> int
  active -> bool
  tag    -> byte[1]
```

For bytecode generation it lowers:

```text
next_state.amount + amount
```

to:

```text
__struct_next_state_amount + amount
```

That is the runtime form.

### 2. Debug recording view

The recorder stores:

- param metadata for `next_state`
- a source step for the statement
- a variable update for `bumped`

In Rust terms, this lives inside `DebugInfo`:

- `DebugInfo.entrypoint_param_bindings: Vec<DebugParamMapping>`
- `DebugInfo.steps: Vec<DebugStep>`

For a structured param like `next_state: State`, the important internal shape is:

- `DebugParamMapping`
- with `binding: DebugParamBinding::StructuredValue`
- containing `leaf_bindings: Vec<DebugLeafBinding>`

Conceptually the param metadata says:

```text
next_state : State
  amount -> stack slot
  active -> stack slot
  tag    -> stack slot
```

So the debugger is not tracking `next_state` as one opaque runtime thing.

It is tracking:

- one visible source name: `next_state`
- plus leaf metadata for `amount`, `active`, `tag`
- plus the runtime slot for each leaf

That is the internal bridge between source-level structs and runtime stack values.

For step-local structured values, the same idea appears in a different Rust struct:

- `DebugVariableUpdate`
- with `structured_leaf_bindings: Option<Vec<DebugLeafBinding>>`

That is how inline names like `inner_state` can also be treated as structured values, not just entrypoint params.

That is enough for the session to later rebuild both:

- the visible object `next_state`
- the hidden leaf bindings `__struct_next_state_amount`, `__struct_next_state_active`, `__struct_next_state_tag`

### 3. Session view for `vars`

When stopped on that statement, the session builds scope from:

- param mappings
- contract fields
- variable updates seen so far
- inline snapshots if needed

Internally, scope contains both:

- visible names like `next_state`
- hidden names like `__struct_next_state_amount`

This is the main job of `session.rs`.

The important change is: the session now owns the bridge from recorded metadata to debugger-visible scope.

It does that in two steps:

1. `scope_state(...)` / `scope_state_from_visible(...)`
2. `collect_variables_map(...)`

`scope_state_from_visible(...)` reads the recorded metadata and creates `ScopeBinding`s for both views of the same value:

- one visible structured binding for `next_state`
- one hidden leaf binding per field, like `__struct_next_state_amount`

For a structured value, the visible binding uses:

- `ScopeValueSource::StructuredBinding { base_name, leaf_bindings }`

and for each hidden leaf:

- `ScopeValueSource::RuntimeSlot { ... }`

Then `collect_variables_map(...)` iterates the scope and resolves only the visible bindings into user-facing variables.

That is why `vars` shows:

```text
next_state = { amount: 5, active: true, tag: 0xaa }
amount = 1
bumped = 6
```

and does not show:

```text
__struct_next_state_amount
__struct_next_state_active
__struct_next_state_tag
```

Those hidden names still exist in scope. They are just debugger-internal.

One more small session change matters here:

- `VariableOrigin` now distinguishes `Param` from `ContractField`

That is why the CLI can print:

- `Contract State`
- `Call Arguments`
- `Locals`

### 4. Session view for `eval`

For:

```text
eval next_state.amount + amount
```

the session:

1. parses the user expression
2. builds current `scope_state`
3. checks whether the expression is already a direct structured value like `next_state`
4. if it is scalar structured access, lowers it inside `session.rs`

The important session-side lowering helpers are:

- `lower_structured_field_access_for_eval(...)`
- `lower_structured_length_for_eval(...)`
- `lower_expr_for_eval(...)`

So for:

```text
next_state.amount + amount
```

the session lowers it to:

```text
__struct_next_state_amount + amount
```

using the current `ScopeValueSource::StructuredBinding` metadata, not by reparsing contract source through the compiler.

Then it:

5. builds shadow bindings with `scope_state_eval_context(...)`
6. calls `compile_debug_expr(...)`
7. runs the shadow expression
8. decodes the result

So the current design is:

- compiler records struct/state metadata
- session reconstructs scope from that metadata
- session lowers structured eval using that metadata
- compiler still compiles the final scalar debug expression

## Why whole structured values are different

These two cases are different:

```text
eval next_state.amount + amount
eval next_state
```

The first one is scalar, so the debugger:

- lowers it
- compiles it
- runs it in the shadow VM

The second one is structured, so the debugger:

- does not need a scalar shadow expression
- reconstructs the object directly from leaf values

That distinction explains a lot of the code shape.

In `session.rs`, that split appears here:

- `evaluate_expr_in_scope(...)` first checks `direct_expr_type_name(...)`
- if the result type is structured, it reconstructs the value directly
- otherwise it uses `lower_expr_for_eval(...)` and shadow execution

## Why inline calls are tricky

Inside:

```sil
inspect_inner(next_state, next_pair)
```

the source-level values are stable, but live stack slots can drift as the inline body executes.

So the session snapshots caller-visible immutable values at `InlineCallEnter`.

That is why these keep working inside the inline frame:

- `vars`
- `eval inner_state`
- `eval inner_state.amount`

without trusting whatever the live stack happens to look like later.

## The missing top half: what happens before stepping starts

Everything above explains how a stopped session reconstructs source-level values.

But there is an earlier half of the flow:

1. the CLI loads source and parses the contract AST
2. constructor args are parsed into typed AST expressions
3. the contract is compiled with debug recording enabled
4. call args are parsed against the selected callable
5. the CLI builds the sigscript for that callable
6. the CLI builds a transaction scenario around it
7. the session starts from bytecode plus `DebugInfo`
8. the session runs forward until the first real source statement

That is the full debugger pipeline.

In code, the start of that flow is mainly in:

- `debugger/cli/src/main.rs`
- `debugger/session/src/args.rs`

Conceptually it looks like this:

```text
source text
  -> parse contract AST
  -> parse ctor args / call args
  -> compile contract + DebugInfo
  -> build sigscript
  -> build debug tx context
  -> create DebugSession
  -> run to first executed source statement
  -> vars / eval / stepping
```

## Constructor args, constants, and contract state

There are 3 different categories of source-level values that the user sees very early:

- constructor args
- contract fields
- call arguments

They do not all come from the same place.

### Constructor args

Constructor args are parsed first by the CLI and compiled into the contract script.

For debugger display, recorded constructor arg values are later inserted into scope from `DebugInfo`:

- `record_debug_named_values(..., &self.debug_info.constructor_args, ...)`

Those are not read from the live VM stack at inspection time.

They are already known debug values.

### Contract fields

Contract fields are source-level state, but at runtime they are still just normal lowered bindings.

The session reconstructs them from param metadata and then classifies them by source contract field name:

- `param_origin(...)`

That is why the CLI can separate:

- `Contract State`
- `Call Arguments`

instead of dumping everything into one flat variable list.

### Call arguments

Call arguments come from the selected function signature.

For normal entrypoints, `parse_call_args(...)` parses them directly against the chosen function in the lowered AST.

For covenant declarations, there is one extra translation layer, described below.

## Why `run_to_first_executed_statement()` matters

When the session is first created, the VM is still at the start of the compiled script.

That does not necessarily mean the user is at the first meaningful source statement.

There may be:

- dispatch/setup opcodes
- selector handling
- covenant wrapper prelude bytecode
- other synthetic setup ranges

So the CLI calls:

- `run_to_first_executed_statement()`

That method keeps stepping raw opcodes until:

- the engine is executing
- the current byte offset falls inside a steppable `DebugStep`

Only then does the REPL show the initial source location.

That is why the first debugger screen already feels source-oriented instead of exposing compiler setup bytecode.

## The covenant-specific flow

Struct/state support and covenant support meet in one important place:

- the debugger should show source-level covenant names and source-level prior state values

not the generated wrapper names and hidden covenant temporaries.

### Function selection

For a normal function, the CLI path is simple:

- parse args against that function
- call `build_sig_script(...)`

For a source-level covenant declaration like:

```sil
#[covenant(binding = cov, from = 2, to = 2, mode = verification)]
function rebalance(State[] prev_states, State[] new_states) { ... }
```

the CLI does something more careful:

1. parse the original contract AST
2. analyze covenant declarations with `analyze_covenant_declarations(...)`
3. resolve `rebalance` plus role into a generated lowered entrypoint with `resolve_covenant_decl_call_target(...)`
4. parse call args against that generated lowered entrypoint name
5. build the sigscript through `build_sig_script_for_covenant_decl(...)`

That distinction matters because:

- source-level covenant params include implicit prior-state params like `prev_state` or `prev_states`
- the lowered callable signature is what the current argument parser understands
- the user-facing function name should still stay source-level

For `binding = cov`:

- leader is the default
- `--delegate` opts into the delegate path
- in `.test.json`, `"delegate": true` does the same thing

### Prior state injection

For covenant debugging, source-level prior state is not read from normal local updates.

Instead, the CLI builds a debug-only shadow transaction context:

- it resolves constructor args into source-level state values
- it attaches those values to `ShadowTxContext`
- the session receives that context via `with_shadow_tx_context(...)`

Then `session.rs` injects source-level bindings with:

- `inject_covenant_prev_state_bindings(...)`

That means:

- auth covenants get `prev_state`
- cov covenants get `prev_states`

as real debugger-visible names.

So commands like:

- `vars`
- `p prev_states`
- `eval prev_states[0].value`

work through the same structured binding machinery as any other `State` or `State[]` value.

If the shadow tx context does not contain those values, the bindings still exist conceptually, but resolve as unavailable instead of silently disappearing.

### Source-level covenant names

The session also parses the source AST at startup and analyzes covenant declarations again.

That allows it to normalize lowered names like:

- `__leader_rebalance`
- `__delegate_rebalance`
- `__covenant_policy_rebalance`

back into source-oriented labels like:

- `rebalance [leader]`
- `rebalance [delegate]`
- `rebalance`

That normalization is used in:

- current function display
- call stack display
- failure reports

So the debugger stays focused on source intent, not lowering internals.

## One compressed end-to-end pipeline

If you want the whole thing in one pass, this is the shortest accurate version:

1. The CLI parses source into a contract AST.
2. It parses constructor args into typed expressions with `parse_ctor_args(...)`.
3. It compiles the contract with debug recording enabled, producing bytecode plus `DebugInfo`.
4. It resolves the selected function.
5. For covenant declarations, it resolves source name plus role to a lowered target for arg parsing, but still builds the action script from the source-level declaration name.
6. It parses call args into typed expressions with `parse_call_args(...)`.
7. It builds the sigscript with `build_sig_script(...)` or `build_sig_script_for_covenant_decl(...)`.
8. It builds a debug transaction scenario and stores prior state values in `ShadowTxContext`.
9. It creates `DebugSession::full(...)` and calls `run_to_first_executed_statement()`.
10. While stepping, the session maps bytecode offsets to `DebugStep`s, reconstructs visible scope from param mappings plus variable updates plus inline snapshots plus covenant prior-state injection, and then serves `vars` / `print` / `eval`.

That is the entire flow.

## Arrays and nested structured values

One subtle point is that arrays of structured values are still flattened leaf-first.

For:

```sil
State[] next_states
```

the runtime/debug leaf model is conceptually:

```text
__struct_next_states_amount : int[]
__struct_next_states_active : bool[]
__struct_next_states_tag    : byte[1][]
```

So:

```text
eval next_states[1].amount
```

becomes a leaf-array access:

```text
__struct_next_states_amount[1]
```

This is why the same design works for:

- `State`
- `State[]`
- custom `struct`
- custom `struct[]`

The debugger never needs a separate object runtime.

It just keeps rebuilding source-level shapes from flattened leaves.

## If you want to read the code

Use this map:

- CLI entry + tx setup: `main.rs`
- CLI arg parsing: `parse_ctor_args(...)`, `parse_call_args(...)`
- covenant source-level resolution: `analyze_covenant_declarations(...)`, `resolve_covenant_decl_call_target(...)`
- covenant sigscript building: `build_sig_script_for_covenant_decl(...)`
- state reconstruction from ctor args: `resolve_contract_state_values(...)`
- compiler lowering: `lower_expr(...)`, `lower_runtime_struct_expr(...)`
- debug recording: `DebugRecorder`
- session startup: `DebugSession::full(...)`, `run_to_first_executed_statement(...)`
- session scope reconstruction: `scope_state(...)`, `scope_state_from_visible(...)`, `collect_variables_map(...)`
- covenant binding injection: `inject_covenant_prev_state_bindings(...)`
- inline scope freezing: `freeze_inline_snapshot_bindings(...)`
- session eval lowering: `lower_structured_field_access_for_eval(...)`, `lower_structured_length_for_eval(...)`, `lower_expr_for_eval(...)`
- session eval execution: `evaluate_expr_in_scope(...)`, `scope_state_eval_context(...)`

## If you want to explore it live

```bash
cli-debugger examples/debug_struct_state_matrix.sil --function inspect_state \
  --ctor-arg '{"amount":3,"code":"0x1234"}' \
  --arg '{"amount":5,"active":true,"tag":"0xaa"}'
```

Then try:

- `vars`
- `eval next_state`
- `eval next_state.amount`
- `eval next_state.amount + amount`

For inline behavior:

```bash
cli-debugger examples/debug_struct_state_matrix.sil --function inspect_inline \
  --ctor-arg '{"amount":3,"code":"0x1234"}' \
  --arg '{"amount":5,"active":true,"tag":"0xaa"}' \
  --arg '{"amount":9,"code":"0x1234"}'
```

Then:

- `si`
- `si`
- `vars`
- `eval inner_state.amount`
