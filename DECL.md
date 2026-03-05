```
Title: Covenant Declarations
Status: Draft
Created: 2026-02-23
```

# Covenant Declarations (Proposal)

## Proposal summary

This document proposes a minimal declaration API for covenant patterns, where users declare policy functions and the compiler generates covenant entrypoints/wrappers.

Context: today these patterns are written manually with `OpAuth*`/`OpCov*` plus `readInputState`/`validateOutputState`. The goal here is to standardize the pattern and remove user boilerplate.

Scope: syntax + semantics only. This is not claiming implementation is finalized.

1. Dev writes only a transition/verification function and annotates it with a covenant macro.
2. Entrypoint(s) are derived by the compiler from that function’s shape.
3. For `N:M`, the compiler generates two entrypoints: leader + delegate.
4. In verification mode, the entrypoint args are `new_states` plus optional extra call args.
5. State is treated as one implicit unnamed struct synthesized from all contract fields.

   * `1:1` uses `State prev_state` / `State new_state`
   * `1:N` uses `State prev_state` / `State[] new_states`
   * `N:M` uses `State[] prev_states` / `State[] new_states`
6. In `1:N`, the authorizing input is always the currently executing input (`this.activeInputIndex`).
7. In `N:M`, the covenant id is taken from the currently executing input (`OpInputCovenantId(this.activeInputIndex)`).

## Macro surface

Only policy functions are annotated.

Canonical form:

```js
#[covenant(binding = auth|cov, from = X, to = Y, mode = verification|transition, groups = multiple|single, termination = disallowed|allowed)]
```

Minimal common form (defaults inferred):

```js
#[covenant(from = X, to = Y)]
```

Sugar (aliases over `from/to`):

```js
#[covenant.singleton]     // == #[covenant(from = 1, to = 1)]
#[covenant.fanout(to = Y)] // == #[covenant(from = 1, to = Y)]
```

Rules:

1. `binding = auth` means auth-context lowering (`OpAuth*`).
2. `binding = cov` means shared covenant-context lowering (`OpCov*`).
3. `groups` applies to both bindings.
4. Defaults: `auth -> groups = multiple`, `cov -> groups = single`.
5. If `binding` is omitted: `from == 1 -> auth`, otherwise `cov`.
6. If `mode` is omitted: no returns -> `verification`, has returns -> `transition`.
7. `binding = auth` with `from > 1` is compile error.
8. `binding = cov` with `groups = multiple` is compile error in v1.
9. `termination` is only relevant for singleton transition (`from = 1, to = 1, mode = transition`).
10. If omitted in singleton transition, `termination` defaults to `disallowed`.
11. Using `termination` outside singleton transition is a compile error.

### 1:N verification

```js
#[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = multiple)]
function split(State prev_state, State[] new_states, sig[] approvals) {
    // require(...) rules
}
```

```js
#[covenant(binding = auth, from = 1, to = max_outs, mode = verification, groups = single)]
function split_single_group(State prev_state, State[] new_states, sig[] approvals) {
    // require(...) rules
}
```

### N:M verification

```js
#[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
function transition_ok(
    int[] prev_amount,
    byte[32][] prev_owner,
    int[] prev_round,
    int[] new_amount,
    byte[32][] new_owner,
    int[] new_round,
    sig leader_sig
) {
    // require(...) rules
}
```

### N:M transition

```js
#[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
function transition(State[] prev_states, int fee) : (State[] new_states) {
    // compute and return new_states
}
```

### 1:1 transition

```js
#[covenant(binding = auth, from = 1, to = 1, mode = transition)]
function roll(State prev_state, byte[32] block_hash) : (State new_state) {
    // compute and return next state
}
```

## Semantics

### Verification mode

Verification mode is the default convenience mode.

1. Generated entrypoint args are `new_states` plus optional extra call args.
2. Wrapper reads prior state from tx context (`prev_state` or `prev_states`) and calls the policy verification with `(prev_state(s), new_states, call_args...)`.
3. Wrapper validates each output with `validateOutputState(...)` against `new_states`.
4. `new_states` are structurally committed via output validation, but extra call args are not directly committed by tx structure.

Current compiler shape for `binding = cov` + `mode = verification`:

1. Policy params must start with one dynamic array per contract field for previous state values.
2. Then one dynamic array per contract field for new state values.
3. Remaining params are optional extra call args.
4. Leader entrypoint exposes only `new_*` arrays + extra args; it reconstructs and passes `prev_*` arrays from `readInputState(...)`.

### Transition mode

Transition mode allows extra call args (`fee` above, etc.) and the policy computes `new_states`.

Important: in both verification and transition modes, any extra call args (beyond state values that are validated on outputs) are not directly committed by tx structure. The compiler/runtime must define a commitment story (and enforce determinism) for those args.

Current compiler shape for `binding = cov` + `mode = transition`:

1. Policy params must start with one dynamic array per contract field for previous state values (`prev_*`).
2. Remaining params are optional extra call args.
3. Compiler enforces this shape; invalid `prev_*` prefix types are compile errors.
4. In current lowering, transition leader entrypoint still receives these `prev_*` arrays explicitly (shape-enforced), while wrapper also performs covenant input/output structural checks.

Cardinality in transition mode:

1. Single-state return shape -> exact one continuation (`out_count == 1`) with direct `validateOutputState(...)` (no loop).
2. Per-field array return shape -> exact cardinality by returned length (`out_count == returned_len`) and per-output validation in a loop.
3. For singleton (`from=1,to=1`), per-field arrays are rejected by default.
4. Singleton per-field arrays are allowed only with `termination = allowed`; this enables explicit zero-or-one continuation.

### Singleton termination opt-in

Default singleton transition is strict continuation:

```js
#[covenant.singleton(mode = transition)]
function bump(int delta) : (int) {
    return(value + delta);
}
```

Termination-enabled singleton transition:

```js
#[covenant.singleton(mode = transition, termination = allowed)]
function bump_or_terminate(int[] next_values) : (int[]) {
    // [] => terminate
    // [x] => continue with one successor
    return(next_values);
}
```

### `groups`

`binding = auth, groups = multiple` (default): no global uniqueness check across the tx.

`binding = auth, groups = single`: enforce that current covenant id has a single continuation auth group in this tx:

```js
byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
require(OpCovOutCount(cov_id) == OpAuthOutputCount(this.activeInputIndex));
```

No explicit `cov_id != false` check is needed; `OpCovOutCount(cov_id)` fails if `cov_id` is not valid covenant-id data.

`binding = cov`: `groups = single` only (v1). `groups = multiple` is rejected.

## Inferred entrypoints

Given policy function `f`:

1. `1:N` generates one entrypoint:

   * `f`
2. `N:M` generates two entrypoints:

   * `f_leader`
   * `f_delegate`

`f_delegate` does not call policy. It enforces delegation-path invariants only.

## Complex example

### Source (user writes this only)

```js
pragma silverscript ^0.1.0;

contract VaultNM(
    int max_ins,
    int max_outs,
    int init_amount,
    byte[32] init_owner,
    int init_round
) {
    int amount = init_amount;
    byte[32] owner = init_owner;
    int round = init_round;

    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
    function conserve_and_bump(State[] prev_states, State[] new_states, sig leader_sig) {
        require(new_states.length > 0);

        int in_sum = 0;
        for(i, 0, max_ins) {
            if (i < prev_states.length) {
                in_sum = in_sum + prev_states[i].amount;
            }
        }

        int out_sum = 0;
        for(i, 0, max_outs) {
            if (i < new_states.length) {
                out_sum = out_sum + new_states[i].amount;

                // all outputs keep same owner as leader input
                require(new_states[i].owner == prev_states[0].owner);

                // round must advance exactly by 1
                require(new_states[i].round == prev_states[0].round + 1);
            }
        }

        require(in_sum >= out_sum);
    }
}
```

### Generated code (full expansion, conceptual)

```js
pragma silverscript ^0.1.0;

contract VaultNM(
    int max_ins,
    int max_outs,
    int init_amount,
    byte[32] init_owner,
    int init_round
) {
    int amount = init_amount;
    byte[32] owner = init_owner;
    int round = init_round;

    function conserve_and_bump(State[] prev_states, State[] new_states, sig leader_sig) {
        require(new_states.length > 0);

        int in_sum = 0;
        for(i, 0, max_ins) {
            if (i < prev_states.length) {
                in_sum = in_sum + prev_states[i].amount;
            }
        }

        int out_sum = 0;
        for(i, 0, max_outs) {
            if (i < new_states.length) {
                out_sum = out_sum + new_states[i].amount;
                require(new_states[i].owner == prev_states[0].owner);
                require(new_states[i].round == prev_states[0].round + 1);
            }
        }

        require(in_sum >= out_sum);
    }

    // Generated for N:M leader path
    entrypoint function conserve_and_bump_leader(State[] new_states, sig leader_sig) {
        byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

        int in_count = OpCovInputCount(cov_id);
        int out_count = OpCovOutCount(cov_id);
        require(out_count == new_states.length);

        // k=0 must execute leader path
        require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

        State[] prev_states = [];
        for(k, 0, max_ins) {
            if (k < in_count) {
                int in_idx = OpCovInputIdx(cov_id, k);
                {
                    amount: int p_amount,
                    owner: byte[32] p_owner,
                    round: int p_round
                } = readInputState(in_idx);

                prev_states.push({
                    amount: p_amount,
                    owner: p_owner,
                    round: p_round
                });
            }
        }

        conserve_and_bump(prev_states, new_states, leader_sig);

        for(k, 0, max_outs) {
            if (k < out_count) {
                int out_idx = OpCovOutputIdx(cov_id, k);
                validateOutputState(out_idx, {
                    amount: new_states[k].amount,
                    owner: new_states[k].owner,
                    round: new_states[k].round
                });
            }
        }
    }

    // Generated for N:M delegate path
    entrypoint function conserve_and_bump_delegate() {
        byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
        // delegate path must not be leader
        require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
    }
}
```

## Additional example: 1:1 transition with `OpChainblockSeqCommit`

State is `seqcommit`; call arg is `block_hash`.

### Source (user writes this only)

```js
pragma silverscript ^0.1.0;

contract SeqCommitMirror(byte[32] init_seqcommit) {
    byte[32] seqcommit = init_seqcommit;

    #[covenant(binding = auth, from = 1, to = 1, mode = transition)]
    function roll_seqcommit(State prev_state, byte[32] block_hash) : (State new_state) {
        byte[32] new_seqcommit = OpChainblockSeqCommit(block_hash);
        return {
            seqcommit: new_seqcommit
        };
    }
}
```

### Generated code (full expansion, conceptual)

```js
pragma silverscript ^0.1.0;

contract SeqCommitMirror(byte[32] init_seqcommit) {
    byte[32] seqcommit = init_seqcommit;

    // Compiler-lowered policy function (renamed to avoid entrypoint name collision)
    function __roll_seqcommit_policy(State prev_state, byte[32] block_hash) : (State new_state) {
        byte[32] new_seqcommit = OpChainblockSeqCommit(block_hash);
        return {
            seqcommit: new_seqcommit
        };
    }

    // Generated 1:1 covenant entrypoint
    entrypoint function roll_seqcommit(byte[32] block_hash) {
        State prev_state = {
            seqcommit: seqcommit
        };

        (State new_state) = __roll_seqcommit_policy(prev_state, block_hash);

        require(OpAuthOutputCount(this.activeInputIndex) == 1);
        int out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
        validateOutputState(out_idx, {
            seqcommit: new_state.seqcommit
        });
    }
}
```

## Implementation notes

1. `State` is an implicit compiler type synthesized from contract fields.
2. Internally the compiler can lower `State`/`State[]` into any representation; this doc only fixes the user-facing API.
3. Existing `readInputState`/`validateOutputState` remain the codegen backbone.
4. v1 keeps one `N:M` transition group per tx.
