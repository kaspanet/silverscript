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

1. Dev writes only a transition/predicate function and annotates it with a covenant macro.
2. Entrypoint(s) are derived by the compiler from that function’s shape.
3. For `N:M`, the compiler generates two entrypoints: leader + delegate.
4. In predicate mode, the entrypoint args are `new_states` plus optional extra call args.
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
#[covenant(binding = auth|cov, from = X, to = Y, mode = predicate|transition, groups = multiple|single)]
```

Rules:

1. `binding = auth` means auth-context lowering (`OpAuth*`).
2. `binding = cov` means shared covenant-context lowering (`OpCov*`).
3. `groups` applies to both bindings.
4. Defaults: `auth -> groups = multiple`, `cov -> groups = single`.
5. `binding = auth` with `from > 1` is compile error.
6. `binding = cov` with `groups = multiple` is compile error in v1.

### 1:N predicate

```js
#[covenant(binding = auth, from = 1, to = max_outs, mode = predicate, groups = multiple)]
function split(State prev_state, State[] new_states, sig[] approvals) {
    // require(...) rules
}
```

```js
#[covenant(binding = auth, from = 1, to = max_outs, mode = predicate, groups = single)]
function split_single_group(State prev_state, State[] new_states, sig[] approvals) {
    // require(...) rules
}
```

### N:M predicate

```js
#[covenant(binding = cov, from = max_ins, to = max_outs, mode = predicate)]
function transition_ok(State[] prev_states, State[] new_states, sig leader_sig) {
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

### Predicate mode

Predicate mode is the default convenience mode.

1. Generated entrypoint args are `new_states` plus optional extra call args.
2. Wrapper reads prior state from tx context (`prev_state` or `prev_states`) and calls the policy predicate with `(prev_state(s), new_states, call_args...)`.
3. Wrapper validates each output with `validateOutputState(...)` against `new_states`.
4. `new_states` are structurally committed via output validation, but extra call args are not directly committed by tx structure.

### Transition mode

Transition mode allows extra call args (`fee` above, etc.) and the policy computes `new_states`.

Important: in both predicate and transition modes, any extra call args (beyond state values that are validated on outputs) are not directly committed by tx structure. The compiler/runtime must define a commitment story (and enforce determinism) for those args.

### `for(i, 0, dyn_len, const_max)` lowering (follow-up)

The 4-arg `for` form is planned as a compiler primitive (not a macro/precompile transform). Covenant declaration lowering in this effort should keep using existing 3-arg `for` + inner `if`.

Lowering semantics:

```js
for(i, 0, dyn_len, const_max) { BODY }
```

is equivalent to:

```js
require(dyn_len <= const_max);
for(i, 0, const_max) {
    if (i < dyn_len) { BODY }
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

    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = predicate)]
    function conserve_and_bump(State[] prev_states, State[] new_states, sig leader_sig) {
        require(new_states.length > 0);

        int in_sum = 0;
        for(i, 0, prev_states.length, max_ins) {
            in_sum = in_sum + prev_states[i].amount;
        }

        int out_sum = 0;
        for(i, 0, new_states.length, max_outs) {
            out_sum = out_sum + new_states[i].amount;

            // all outputs keep same owner as leader input
            require(new_states[i].owner == prev_states[0].owner);

            // round must advance exactly by 1
            require(new_states[i].round == prev_states[0].round + 1);
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
        for(i, 0, prev_states.length, max_ins) {
            in_sum = in_sum + prev_states[i].amount;
        }

        int out_sum = 0;
        for(i, 0, new_states.length, max_outs) {
            out_sum = out_sum + new_states[i].amount;
            require(new_states[i].owner == prev_states[0].owner);
            require(new_states[i].round == prev_states[0].round + 1);
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
        for(k, 0, in_count, max_ins) {
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

        conserve_and_bump(prev_states, new_states, leader_sig);

        for(k, 0, out_count, max_outs) {
            int out_idx = OpCovOutputIdx(cov_id, k);
            validateOutputState(out_idx, {
                amount: new_states[k].amount,
                owner: new_states[k].owner,
                round: new_states[k].round
            });
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
5. `for(i, 0, dyn_len, const_max)` is compiler-level syntax, lowered as specified above.
