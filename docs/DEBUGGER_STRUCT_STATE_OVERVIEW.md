# Struct/State Debugger Overview

If you want the shorter version first, read [`DEBUGGER_STRUCT_STATE_QUICK_FLOW.md`](./DEBUGGER_STRUCT_STATE_QUICK_FLOW.md).

## Why this document exists

This document is meant to explain the debugger as a system, not just list the struct/state feature work.

The key question is:

- how do we go from source code with `State`, custom `struct`s, inline calls, and source-level names
- to compiled bytecode
- and then back to a source-level debugging experience

If you already understand this much:

- the compiler records debug info while compiling
- that debug info maps source steps to bytecode ranges
- the session steps through those recorded ranges

then this document fills in the missing middle:

- what happens to `State` and `struct` values during compilation
- what extra metadata had to be recorded
- how `vars` and `eval` reconstruct source-level values from flattened runtime data

This doc uses one concrete contract as the running example:

- [`examples/debug_struct_state_matrix.sil`](../examples/debug_struct_state_matrix.sil)

Its constructor args live in:

- [`examples/debug_struct_state_matrix.ctor.json`](../examples/debug_struct_state_matrix.ctor.json)

## One Mental Model

There are really 4 layers:

1. Source layer
   `State`, `Pair`, `next_state.amount`, `next_pairs[1].code`
2. Runtime layer
   flattened leaf bindings like `__struct_next_state_amount`
3. Debug metadata layer
   bytecode ranges, variable updates, structured leaf metadata, param mappings
4. Session layer
   reconstruct source-level variables and evaluate expressions while stepping

The most important fact is this:

- `State` and custom `struct`s are source-level concepts
- the runtime does not keep them as one opaque object
- the compiler lowers them into leaf values

So the debugger has to do two opposite jobs:

- during compile/eval lowering, go from source-level struct access to flattened leaf access
- during display, go from flattened leaf values back to source-level objects and arrays

That is the whole story.

## The Reference Contract

Here is the important part of the example contract:

```sil
contract DebugStructStateMatrix(Pair seed_pair) {
    struct Pair {
        int amount;
        byte[2] code;
    }

    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;

    function inspect_inner(State inner_state, Pair inner_pair) {
        int bumped = inner_state.amount + amount;
        require(bumped > 0);
        inspect_deeper(inner_state, inner_pair);
    }

    entrypoint function inspect_state(State next_state) {
        int bumped = next_state.amount + amount;
        require(next_state.active == active);
    }

    entrypoint function inspect_state_array(State[] next_states) {
        int delta = next_states[1].amount - next_states[0].amount;
        require(next_states.length == 2);
    }

    entrypoint function inspect_pair(Pair next_pair) {
        byte[2] pair_code = next_pair.code;
        require(pair_code == next_pair.code);
    }

    entrypoint function inspect_inline(State next_state, Pair next_pair) {
        inspect_inner(next_state, next_pair);
        require(next_state.active == active);
    }
}
```

This one file exercises all the interesting debugger cases:

- top-level `State`
- top-level `State[]`
- custom `struct`
- custom `struct[]`
- inline structured params
- constructor args visible in debugger scope

One practical note:

- `seed_pair` is included so the debugger can expose a structured constructor arg
- in this example it is not used inside contract logic

## Part 1: What the Compiler Does With `State` and `struct`

### Source view

At the source level you can write:

```sil
next_state.amount
next_states[0].amount
next_pair.code
```

This reads like object/field access.

### Runtime view

The compiler does not keep a `State` value as one runtime object.

Instead it flattens it into leaf bindings.

If `State` is:

- `amount: int`
- `active: bool`
- `tag: byte[1]`

then a source binding:

```sil
State next_state
```

becomes the runtime/debug leaf model:

```text
__struct_next_state_amount : int
__struct_next_state_active : bool
__struct_next_state_tag    : byte[1]
```

For arrays of structs, each leaf becomes its own array:

```text
__struct_next_states_amount : int[]
__struct_next_states_active : bool[]
__struct_next_states_tag    : byte[1][]
```

For `Pair[]`:

```text
__struct_next_pairs_amount : int[]
__struct_next_pairs_code   : byte[2][]
```

### Why flattening exists

This is not debugger-specific. This is how the compiler already reasons about structured runtime data.

The useful helpers are:

- `flattened_struct_name(base, path)`
- `flatten_type_ref_leaves(...)`
- `lower_expr(...)`
- `lower_runtime_struct_expr(...)`
- `lower_struct_array_value_expr(...)`

They do different jobs.

### Scalar structured access

For a scalar expression like:

```sil
next_state.amount + amount
```

the compiler lowers only the structured access part:

```text
__struct_next_state_amount + amount
```

This is what `lower_expr(...)` is for.

Another example:

```sil
next_states[1].amount - next_states[0].amount
```

becomes:

```text
__struct_next_states_amount[1] - __struct_next_states_amount[0]
```

Again, this is still one scalar expression, just rewritten to hidden leaf names.

### Whole structured values

Now look at a different category:

```sil
next_state
next_states
next_pair
```

These are not scalar expressions over one value. They are structured values.

When the compiler already knows the expected type is structured, it lowers the whole value into many leaf expressions.

Examples:

- `lower_runtime_struct_expr(...)` handles a whole `State` or custom struct value
- `lower_struct_array_value_expr(...)` handles a whole `State[]` or `Pair[]`

So:

```sil
next_state
```

does not lower to one expression. It lowers conceptually to:

```text
[
  __struct_next_state_amount,
  __struct_next_state_active,
  __struct_next_state_tag,
]
```

And:

```sil
next_pairs
```

conceptually lowers to:

```text
[
  __struct_next_pairs_amount,
  __struct_next_pairs_code,
]
```

This distinction matters a lot:

- scalar structured access becomes one lowered `Expr`
- whole structured values become a list of leaf expressions

That is why there are multiple lowering helpers in the compiler.

## Part 2: What the Debug Recorder Adds

Compiling the contract already produces bytecode.

When debug recording is enabled, the compiler also builds `DebugInfo`.

At a high level `DebugInfo` contains:

- `source`
- `steps`
- `params`
- `functions`
- `constructor_args`
- `constants`

### `functions`

These map source-level functions to bytecode ranges.

This lets the session answer questions like:

- which function is active at byte offset `X`?

### `steps`

Each `DebugStep` says:

- the bytecode range for one source step
- the source span
- the step kind
- the call depth and frame id
- variable updates that became true at that step

The important step kinds are:

- `Source`
- `InlineCallEnter`
- `InlineCallExit`

This is the bridge from bytecode execution back to source stepping.

For example, the statement:

```sil
int bumped = next_state.amount + amount;
```

is conceptually recorded like this:

```text
DebugStep {
  bytecode_start: ...,
  bytecode_end: ...,
  span: line/col for "int bumped = ...",
  kind: Source,
  variable_updates: [
    DebugVariableUpdate {
      name: "bumped",
      type_name: "int",
      expr: resolved source expression for bumped,
      runtime_binding: stack slot for bumped
    }
  ]
}
```

For this example, that `expr` is conceptually still source-shaped:

```text
next_state.amount + amount
```

The important distinction is:

- the recorder stores a resolved expression useful for debugger-side evaluation
- the debugger later calls `prepare_debug_expr(...)` to lower any structured access when the user actually evaluates something

The real data is richer, but this is the right mental model:

- one source statement
- one bytecode span
- the variables that became visible or changed there

### `params`

Function params are special because the debugger needs them before any local statement update occurs.

For plain params, debug info stores one runtime slot.

For structured params, debug info stores leaf bindings.

Example for:

```sil
entrypoint function inspect_state(State next_state)
```

the debugger metadata is conceptually:

```text
next_state : State
  amount -> stack slot S1
  active -> stack slot S2
  tag    -> stack slot S3
```

In actual terms that means:

```text
DebugParamMapping {
  name: "next_state",
  type_name: "State",
  binding: StructuredValue {
    leaf_bindings: [
      { field_path: ["amount"], type_name: "int", stack_index: S1 },
      { field_path: ["active"], type_name: "bool", stack_index: S2 },
      { field_path: ["tag"], type_name: "byte[1]", stack_index: S3 },
    ]
  }
}
```

For source display, `next_state` is the public name.

For runtime resolution, the hidden leaf bindings are what matter.

### `variable_updates`

Locals and inline values show up as step-local updates.

For structured values, a `DebugVariableUpdate` can now carry:

- `type_name`
- `expr`
- optional `runtime_binding`
- optional `structured_binding`

That optional `structured_binding` says:

- this visible variable is a structured value
- these are its leaf paths and leaf types

Without that, the session would know a name like `inner_state` exists, but not how to reconstruct its fields.

For an inline param alias like `inner_state`, the update is conceptually:

```text
DebugVariableUpdate {
  name: "inner_state",
  type_name: "State",
  structured_binding: {
    leaf_bindings: [
      { field_path: ["amount"], type_name: "int" },
      { field_path: ["active"], type_name: "bool" },
      { field_path: ["tag"], type_name: "byte[1]" },
    ]
  }
}
```

That is what tells the session:

- `inner_state` is not a scalar
- it should be reconstructed as a source-level object
- and it should also synthesize matching hidden leaf names for internal resolution

## Part 3: How Stepping Works

The stepping model is still the same one you already understand:

- compile script
- record debug steps with bytecode ranges
- parse the script in the session
- step opcodes
- use current byte offset to locate the current source step

The extra detail that matters for structs is how variable scope is built at each step.

### Building scope for the current step

When the session wants `vars` or `eval`, it builds a source-level scope from 4 ingredients:

1. function param mappings from `debug_info.entrypoint_param_bindings`
2. constructor args and constants from `debug_info`
3. latest visible variable updates up to the current step
4. inline call snapshots when inside an inline frame

This becomes a `ScopeState`.

Each binding in that scope is one of:

- a direct runtime slot
- a structured binding with leaf metadata
- a pre-resolved expression

The important consequence is:

- visible names like `next_state` stay source-level
- hidden names like `__struct_next_state_amount` can still exist internally for evaluation
- `vars` filters out the hidden ones before presentation

## Part 4: One End-to-End Trace for `inspect_state`

Look at:

```sil
entrypoint function inspect_state(State next_state) {
    int bumped = next_state.amount + amount;
    require(next_state.active == active);
}
```

This is the clearest single flow to keep in your head.

We will follow just one source expression all the way through:

```sil
next_state.amount + amount
```

and then the debugger command:

```text
eval next_state.amount + amount
```

### Step A: the compiler parses the contract

From this contract, the compiler knows:

- `State` comes from the contract fields
- `State` has leaves `amount`, `active`, `tag`
- `next_state` has type `State`
- `amount` has type `int`

Conceptually the struct registry for this contract contains:

```text
State:
  amount -> int
  active -> bool
  tag    -> byte[1]
```

### Step B: param bindings are flattened for runtime/debug use

For:

```sil
entrypoint function inspect_state(State next_state)
```

the compiler records one structured param plus the contract fields.

Conceptually:

```text
visible param:
  next_state : State

hidden runtime leaves:
  __struct_next_state_amount -> stack slot S1
  __struct_next_state_active -> stack slot S2
  __struct_next_state_tag    -> stack slot S3

contract field bindings:
  amount -> stack slot S4
  active -> stack slot S5
  tag    -> stack slot S6
```

The exact slot numbers depend on layout, but this is the shape that matters.

### Step C: the statement is compiled

The source statement is:

```sil
int bumped = next_state.amount + amount;
```

For bytecode generation, the compiler lowers the structured field access:

```text
next_state.amount + amount
```

becomes:

```text
__struct_next_state_amount + amount
```

That lowered expression is what matters for actual bytecode generation.

### Step D: the recorder stores a source step

While compiling that statement, the recorder creates a `DebugStep` covering the bytecode range for that statement.

Conceptually:

```text
DebugStep {
  span: "int bumped = next_state.amount + amount;",
  kind: Source,
  variable_updates: [
    {
      name: "bumped",
      type_name: "int",
      expr: next_state.amount + amount,
      runtime_binding: slot for bumped
    }
  ]
}
```

The important point is:

- debug steps stay source-oriented
- struct/state lowering for ad hoc debugger eval happens later

### Step E: the session stops on that step and builds scope

At runtime, when the debugger is stopped on this statement, the session builds `ScopeState`.

Conceptually it contains:

```text
visible:
  next_state : StructuredBinding(State)
  amount     : RuntimeSlot
  active     : RuntimeSlot
  tag        : RuntimeSlot
  bumped     : RuntimeSlot or Expr, depending on point in execution

hidden:
  __struct_next_state_amount : RuntimeSlot
  __struct_next_state_active : RuntimeSlot
  __struct_next_state_tag    : RuntimeSlot
```

This is why both of these can be true at the same time:

- `vars` shows `next_state`
- `eval next_state.amount + amount` can still work through hidden leaf bindings

### Step F: user runs `vars`

`vars` resolves the visible bindings:

- `next_state` is reconstructed as an object from its hidden leaves
- `amount`, `active`, and `tag` are read normally
- hidden `__struct_*` names are filtered out

So the user sees something like:

```text
next_state = { amount: 5, active: true, tag: 0xaa }
amount = 1
active = true
tag = 0xaa
bumped = 6
```

### Step G: user runs `eval next_state.amount + amount`

Now the debugger goes through a second pipeline, separate from the original contract compilation.

#### G1. Parse the user expression

The session parses:

```text
next_state.amount + amount
```

into an expression AST.

#### G2. Build eval context

From current scope, the session builds:

- `eval_types`
- `env`
- `stack_bindings`
- `shadow_bindings`

Conceptually:

```text
eval_types:
  next_state -> State
  __struct_next_state_amount -> int
  __struct_next_state_active -> bool
  __struct_next_state_tag -> byte[1]
  amount -> int
  active -> bool
  tag -> byte[1]

stack_bindings:
  __struct_next_state_amount -> S1
  __struct_next_state_active -> S2
  __struct_next_state_tag -> S3
  amount -> S4
  active -> S5
  tag -> S6
```

`env` only contains bindings represented as expressions rather than runtime slots.

#### G3. Prepare the expression for eval

The session calls:

```text
prepare_debug_expr(next_state.amount + amount, eval_types, source)
```

The compiler then:

- sees that `next_state.amount` is structured access
- parses the contract source if needed
- rebuilds the struct registry
- lowers the expression
- infers the result type

The prepared result is:

```text
lowered expr: __struct_next_state_amount + amount
type: int
```

#### G4. Compile and run the shadow expression

Now the session calls:

```text
compile_debug_expr(__struct_next_state_amount + amount, env, stack_bindings, eval_types)
```

That produces bytecode for just the debug expression.

The session prepends the needed shadow stack values, runs the shadow script, and decodes the result.

Final result:

```text
6
```

So the debugger is not inventing struct lowering rules itself.

It asks the compiler to do the same lowering the compiler already understands.

## Part 5: Concrete Flow for `inspect_state_array`

Look at:

```sil
entrypoint function inspect_state_array(State[] next_states) {
    int delta = next_states[1].amount - next_states[0].amount;
    require(next_states.length == 2);
}
```

### Field access over an array of structs

This:

```sil
next_states[1].amount - next_states[0].amount
```

lowers to:

```text
__struct_next_states_amount[1] - __struct_next_states_amount[0]
```

### `.length`

This:

```sil
next_states.length
```

lowers to the length of any one leaf array:

```text
__struct_next_states_amount.length
```

That works because all leaf arrays for one structured array must have the same length.

### What `eval next_states` does

This is different from scalar eval.

`next_states` is a structured result type, so the session does not need to compile a scalar shadow expression for it.

Instead it reconstructs the visible array by zipping the leaf arrays back together by index.

Conceptually:

```text
index 0 -> { amount, active, tag }
index 1 -> { amount, active, tag }
```

That is how whole structured values are presented back to the user.

## Part 6: Concrete Flow for `inspect_pair`

Look at:

```sil
entrypoint function inspect_pair(Pair next_pair) {
    byte[2] pair_code = next_pair.code;
    require(pair_code == next_pair.code);
}
```

This is the same model as `State`, just with a user-declared struct.

Examples:

```sil
next_pair.code
```

lowers to:

```text
__struct_next_pair_code
```

And:

```sil
eval next_pair
```

returns an object:

```text
{ amount: ..., code: ... }
```

The debugger does not treat `State` as magical. `State` is just one particular structured type the compiler knows how to flatten and reconstruct.

## Part 7: Why Inline Debugging Was Hard

Look at:

```sil
entrypoint function inspect_inline(State next_state, Pair next_pair) {
    inspect_inner(next_state, next_pair);
    require(next_state.active == active);
}
```

and:

```sil
function inspect_inner(State inner_state, Pair inner_pair) {
    int bumped = inner_state.amount + amount;
    require(bumped > 0);
}
```

At the source level, this is simple:

- `inner_state` is the callee name
- `next_state` is the caller name
- logically they refer to the same immutable value

At runtime, this is harder:

- stepping into the inline call changes stack shape
- temporaries appear and disappear
- a slot that used to mean "the source value I care about" can stop being reliable for debugger display

### The failed idea

The original idea was:

- record more inline leaf updates
- keep reading live runtime slots

That was not enough.

The source-level value was stable, but the stack layout was not.

### The final fix

On `InlineCallEnter`, the session takes a snapshot of caller-visible immutable values:

- function params
- contract fields

When building scope inside the inline frame:

- those snapshot values are frozen
- structured values are decomposed back into hidden leaf bindings
- aliases like `inner_state` can resolve against those frozen values

Conceptually, right after stepping into:

```sil
inspect_inner(next_state, next_pair);
```

the snapshot is roughly:

```text
frame 1 snapshot:
  next_state = { amount: 5, active: true, tag: 0xaa }
  next_pair  = { amount: 9, code: 0x1234 }
  amount     = 1
  active     = true
  tag        = 0xaa
```

Inside the inline frame, `inner_state` and `inner_pair` can then be rebuilt from that frozen caller data instead of trusting live slots.

So inside the callee:

- `vars` shows `inner_state` and `inner_pair` correctly
- `eval inner_state.amount`
- `eval inner_pair.code`

keep working even after more stack traffic happens inside the inline body.

This is the part that makes inline debugging feel source-level instead of stack-level.

## Part 8: What `eval` Does for Different Kinds of Expressions

### Plain scalar expression

Example:

```sil
amount + 1
```

Flow:

- parse expression
- no struct lowering needed
- no contract source parse needed
- compile scalar shadow expression
- run shadow VM

### Scalar expression with struct/state access

Example:

```sil
next_state.amount + amount
```

Flow:

- parse expression
- compiler detects structured lowering is needed
- compiler parses source if needed
- compiler rebuilds struct registry
- compiler lowers to hidden leaf names
- session compiles and executes shadow expression

### Whole structured value

Example:

```sil
next_state
next_states
next_pair
```

Flow:

- parse expression
- compiler still prepares the expression and infers the result type
- session sees the final type is structured
- session resolves the value directly from scope data instead of running a scalar shadow script

That split is important:

- structured access inside a scalar expression still goes through compiler lowering
- whole structured results are reconstructed directly by the session

## Part 9: Why Source Text Is Sometimes Required

This rule becomes simple once you keep the lowering model in mind.

### Source text is not required

For expressions like:

```sil
amount + 1
```

there is no need to know struct layout, so source text is irrelevant.

### Source text is required

For expressions like:

```sil
next_state.amount
next_states[0].amount
next_pair.code
```

the compiler needs to know:

- is `next_state` a `State`?
- is `next_pair` a `Pair`?
- what fields exist?
- what are their types?

So the compiler must be able to parse the contract source and rebuild the struct registry.

That is why missing or invalid source is an error only when the expression actually needs structured lowering.

## Part 10: How to Read the Debugger Architecture

If you want a compact mental map of the codebase, use this:

### Compiler

- lowers source expressions to runtime form
- compiles bytecode
- records debug steps and variable metadata

Important pieces:

- `lower_expr(...)`
- `lower_runtime_struct_expr(...)`
- `lower_struct_array_value_expr(...)`
- `prepare_debug_expr(...)`
- `compile_debug_expr(...)`
- `DebugRecorder`

### Debug info

- stores source-to-bytecode mapping
- stores param mappings
- stores step-local variable updates
- stores structured leaf metadata

Important types:

- `DebugInfo`
- `DebugStep`
- `DebugParamMapping`
- `DebugVariableUpdate`
- `DebugStructuredBinding`

### Session

- executes the script opcode by opcode
- finds the active source step for the current byte offset
- builds current source-level scope
- reconstructs structured values
- compiles/evaluates shadow expressions

Important pieces:

- `DebugSession`
- `scope_state(...)`
- `capture_inline_scope_snapshot(...)`
- `prepare_expr_for_eval(...)`
- `evaluate_expr_in_scope(...)`

## Part 11: Practical Ways to Explore This

Use the example contract directly.

### Top-level `State`

```bash
cli-debugger examples/debug_struct_state_matrix.sil --function inspect_state \
  --ctor-arg '{"amount":3,"code":"0x1234"}' \
  --arg '{"amount":5,"active":true,"tag":"0xaa"}'
```

Try:

- `vars`
- `eval next_state`
- `eval next_state.amount`
- `eval next_state.amount + amount`

### `State[]`

```bash
cli-debugger examples/debug_struct_state_matrix.sil --function inspect_state_array \
  --ctor-arg '{"amount":3,"code":"0x1234"}' \
  --arg '[{"amount":5,"active":true,"tag":"0xaa"},{"amount":7,"active":true,"tag":"0xaa"}]'
```

Try:

- `eval next_states`
- `eval next_states.length`
- `eval next_states[1].amount - next_states[0].amount`

### Inline structured scope

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
- `eval inner_state`
- `eval inner_state.amount`
- `eval inner_pair.code`
- `eval seed_pair`

That last session is the best one for understanding why inline snapshots exist.

## Summary

If you only keep 5 facts in your head, keep these:

1. `State` and custom `struct`s are source-level shapes, not runtime opaque objects.
2. The compiler flattens them into leaf bindings like `__struct_next_state_amount`.
3. Debug info records enough metadata to map bytecode back to source steps and reconstruct structured values.
4. The session hides flattened names from the user, but still uses them internally for eval and reconstruction.
5. Inline debugging needs snapshots because source-level immutable values stay stable while live stack slots do not.

Once that model is clear, the rest of the debugger becomes much easier to read:

- stepping is bytecode range tracking
- `vars` is source-scope reconstruction
- `eval` is compiler-assisted lowering plus either shadow execution or direct structured reconstruction
