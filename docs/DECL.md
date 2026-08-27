# Covenant Declarations

## Summary

This document specifies the covenant declaration API, where users declare policy functions and the compiler generates the corresponding covenant entrypoints and wrappers.

Without declarations, these patterns are written manually with `OpAuth*`/`OpCov*` plus `readInputState`/`validateOutputState` (or `validateOutputStateWithTemplate` for cross-template routing). The declaration layer standardizes that pattern, removes user boilerplate, and acts as a security guard so users do not need to be experts in covenant opcodes to write secure covenants.

Scope: syntax and lowering semantics.

1. Dev writes only a transition/verification policy function and annotates it with a covenant macro.
2. Entrypoint(s) are inferred by the compiler from that function’s shape.
3. State is treated as one implicit `State` struct synthesized from all contract fields:
   * `1:1` uses `State prev_state` / `State new_state`
   * `1:N` uses `State prev_state` / `State[] new_states`
   * `N:M` uses `State[] prev_states` / `State[] new_states`
4. `1:N` auth always binds to `this.activeInputIndex`; `N:M` cov id is always `OpInputCovenantId(this.activeInputIndex)`.

## Macro surface

Only policy functions are annotated.

Canonical form:

```js
#[covenant(binding = auth|cov, from = X, to = Y, mode = verification|transition, groups = multiple|single, termination = disallowed|allowed, name = public_name, delegate_name = public_delegate_name)]
```

Common form (with inferred defaults):

```js
#[covenant(from = X, to = Y)]
```

Sugar (aliases over `from/to`):

```js
#[covenant.singleton]     // == #[covenant(from = 1, to = 1)]
#[covenant.fanout(to = Y)] // == #[covenant(from = 1, to = Y)]
```

Manual-entrypoint acknowledgment in a leader contract:

```js
#[covenant.allow(rule = manual_entrypoint_in_leader_contract)]
entry recover(...) {
    // Manual covenant-group checks.
}
```

Optional contract-wide delegate verification body:

```js
#[covenant.delegate]
function authorizeDelegate(byte[] witness) {
    verifyOwner(owner, ownerScheme, witness);
}
```

Rules:

1. `binding = auth` means auth-context lowering (`OpAuth*`).
2. `binding = cov` means shared covenant-context lowering (`OpCov*`).
3. `groups` applies to both bindings.
4. Defaults: `auth -> groups = multiple`, `cov -> groups = single`.
5. If `binding` is omitted: `from == 1 -> auth`, otherwise `cov`.
6. If `mode` is omitted: no returns -> `verification`, has returns -> `transition`.
7. `binding = auth` with `from > 1` is compile error.
8. `binding = cov` with `from = 1` is allowed but emits a compiler warning recommending `binding = auth`.
9. `binding = cov` with `groups = multiple` is a compile error.
10. `termination` is valid only for singleton transition (`from = 1, to = 1, mode = transition`); there it defaults to `disallowed`, and using it elsewhere is a compile error.
11. A contract with any `binding = cov` declaration is a *leader contract*. Its
    other covenant declarations must also use `binding = cov`.
12. A handwritten entrypoint in a leader contract is rejected unless it carries
    `#[covenant.allow(rule = manual_entrypoint_in_leader_contract)]`.
13. `name` overrides the public name of the generated auth or leader wrapper.
14. `delegate_name` is valid only on `binding = cov` declarations and overrides
    the public name of the one shared delegate wrapper. All cov-bound
    declarations in a contract must resolve to the same delegate name, including
    the `__delegate` default.
15. A contract may contain at most one `#[covenant.delegate]` function. It must
    be a non-entrypoint verification function with no return values, and the
    annotation accepts no properties. A delegate body is rejected unless the
    contract also has at least one `binding = cov` declaration.

Covenant declaration policies and delegate bodies are compiler-invoked hooks
and cannot be called directly from source. Extract shared logic into an
unannotated helper function instead.

`name` and `delegate_name` values are identifiers, not strings. Generated
public names undergo the same duplicate-function and reserved-name validation
as handwritten names.

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
contract C(int max_ins, int max_outs) {
    int amount;
    byte[32] owner;
    int round;

    #[covenant(binding = cov, from = max_ins, to = max_outs, mode = verification)]
    function transition_ok(
        State[] prev_states,
        State[] new_states,
        sig leader_sig
    ) {
        // require(...) rules
    }
}
```

### N:M transition

```js
#[covenant(binding = cov, from = max_ins, to = max_outs, mode = transition)]
function transition(State[] prev_states, int fee) : (State[] new_states) {
    // compute and return new_states
}
```

### KCC20-shaped transfer interface

Here `State` is the contract's implicit KCC20 state type. The final ABI is
`transfer(State[],byte[])` and `transfer_delegator(byte[])`:

```js
#[covenant(
    binding = cov,
    from = max_token_inputs,
    to = max_token_outputs,
    name = transfer,
    delegate_name = transfer_delegator
)]
function transferPolicy(State[] prev_states, State[] next_states, byte[] witness) {
    // Validate the complete shared transition and the leader's local owner.
    verifyOwner(owner, ownerScheme, witness);
}

#[covenant.delegate]
function authorizeDelegate(byte[] witness) {
    // `owner` and `ownerScheme` are fields of this active input's instance.
    verifyOwner(owner, ownerScheme, witness);
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
3. Wrapper enforces exact cardinality: `out_count == new_states.length`.
4. Wrapper validates each output with `validateOutputState(...)` against `new_states`.

Verification mode shape (`mode = verification`, both bindings):

1. Policy params must begin with prior-state parameters:
    `binding = auth` -> `State prev_state`
    `binding = cov` -> `State[] prev_states`
2. Then comes `State[] new_states`.
3. Remaining params are optional extra call args.
4. Generated entrypoint exposes only `new_states` + extra args (not prior-state params).
5. Wrapper reconstructs/injects prior state from tx context:
    `auth` from current input state, `cov` from covenant input set via `readInputState(...)`.

### Transition mode

Transition mode allows extra call args (`fee` above, etc.) and the policy computes `new_states`.

Security note (both modes): extra call args (beyond state values validated on outputs) are not directly committed by tx structure. Compiler/runtime must enforce a commitment story and determinism for them.

Transition mode shape (`mode = transition`, both bindings):

1. Policy params must begin with prior-state parameters:
    `binding = auth` -> `State prev_state`
    `binding = cov` -> `State[] prev_states`
2. Remaining params are optional extra call args.
3. Compiler enforces this prefix exactly; invalid prior-state parameter types are compile errors.
4. Wrapper sources prior state from tx context according to binding.
5. Generated ABI behavior:
    `auth` entrypoint exposes only extra call args.
    `cov` leader entrypoint exposes `new_states` or extra call args according to mode, while wrapper also enforces covenant structure checks.

Cardinality in transition mode:

1. Single-state return shape -> exact one continuation (`out_count == 1`) with direct `validateOutputState(...)` (no loop).
2. `State[]` return shape -> exact cardinality by returned length (`out_count == returned_len`) and per-output validation in a loop.
3. For singleton (`from=1,to=1`), `State[]` returns are rejected by default.
4. Singleton `State[]` returns are allowed only with `termination = allowed`; this enables explicit zero-or-one continuation.

### Singleton termination opt-in

Default singleton transition is strict continuation:

```js
#[covenant.singleton(mode = transition)]
function bump(State prev_state, int delta) : (State) {
    return(State { value: prev_state.value + delta });
}
```

Termination-enabled singleton transition:

```js
#[covenant.singleton(mode = transition, termination = allowed)]
function bump_or_terminate(State prev_state, State[] next_states) : (State[]) {
    // [] => terminate
    // [x] => continue with one successor
    return(next_states);
}
```

### `groups`

`binding = auth, groups = multiple` (default): no global uniqueness check across the tx.

`binding = auth, groups = single`: enforce that current covenant id has a single continuation auth group in this tx:

```js
byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
require(OpCovOutputCount(cov_id) == OpAuthOutputCount(this.activeInputIndex));
```

No explicit `cov_id != false` check is needed; `OpCovOutputCount(cov_id)` fails if `cov_id` is not valid covenant-id data.

`binding = cov`: `groups = single` only. `groups = multiple` is rejected.

## Inferred entrypoints

Given policy function `f`:

1. An auth-bound declaration generates one entrypoint:

    * `__covenant_entrypoint_auth_f` by default; or
    * the declaration's `name` value.
2. The first `N:M` declaration makes the contract a leader contract. Each
   declaration generates its own leader entrypoint, while the contract has one
   shared delegate entrypoint:

    * `__leader_f` by default, or the declaration's `name` value;
    * `__delegate` by default, or the common `delegate_name` value.

Public ABI dispatch tags are calculated after lowering, from the final public
name and final exposed parameter types:

```text
blake3("entryName(type1,type2,...)")[0..4]
```

Consequently, a name override changes the protocol-visible dispatch tag.
Compiler-internal policy names remain derived from source policy names and do
not use public overrides. Covenant sigscript helpers and debugger routing resolve
the final public wrapper names.

### Shared delegate body

Every cov-bound declaration in a contract uses the same generated delegate
wrapper and, when present, the same `#[covenant.delegate]` body. The wrapper:

1. derives the active input's covenant ID;
2. rejects the first input in that covenant-ID group;
3. calls the delegate body with the wrapper's ABI arguments.

The delegate body's parameters become the public delegate entrypoint's
parameters in the same order and with the same types. Its body may read current
contract fields directly; no `State` argument is injected. It must return no
values.

There is deliberately no declaration property that selects a delegate body.
Allowing each leader route to choose independently would let delegators invoke
the weakest policy unless every leader authenticated the route selected by
every input.

For source compatibility, a leader contract with no `#[covenant.delegate]`
body still receives the inert default delegate. That wrapper checks only that
the active input is not the group leader and has no parameters. Protocols whose
delegators have local obligations, including the default KCC20 transfer
configuration, must declare a delegate body.

## Leader contracts

A `binding = cov` declaration generates its own leader entrypoint. A leader
contract generates exactly one shared delegate entrypoint, regardless of how
many cov-bound declarations it contains. The leader runs at covenant input zero
and validates the shared covenant transition. A delegate runs at another
covenant input, runs the shared delegate body if declared, and relies on input
zero to perform the complete shared-transition validation.

This makes delegation a contract-wide property. A generated delegate
authenticates the contract at input zero, but cannot determine which entrypoint
that input selected. If the same contract also exposed an auth-bound declaration,
that auth entrypoint could occupy input zero without validating the complete
covenant input group. Silverscript therefore rejects contracts that mix
auth-bound and cov-bound covenant declarations.

Handwritten entrypoints remain available as a low-level escape hatch. In a
leader contract they must explicitly choose one of these roles:

1. reject shared execution by requiring `OpCovInputCount(cov_id) == 1`;
2. act as a delegate by rejecting covenant input zero; or
3. act as a leader by requiring covenant input zero and validating the complete
   covenant input/output group.

After implementing the corresponding checks, the author must acknowledge the
manual proof with:

```js
#[covenant.allow(rule = manual_entrypoint_in_leader_contract)]
```

This attribute suppresses the compiler error and generates no checks. The
compiler does not verify the handwritten covenant-group logic.

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

    #[covenant.delegate]
    function authorizeDelegate(sig owner_sig) {
        // Example local delegate authorization.
        require(checkSig(owner_sig, pubkey(owner)));
    }
}
```

### Generated code (illustrative; policy body unchanged)

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

    // Compiler-lowered policy function (renamed to avoid collision with generated entrypoints)
    // same body as source:
    function __covenant_policy_conserve_and_bump(State[] prev_states, State[] new_states, sig leader_sig) { ... }
    function __covenant_delegate_policy_authorizeDelegate(sig owner_sig) { ... }

    // Generated for N:M leader path
    entry __leader_conserve_and_bump(State[] new_states, sig leader_sig) {
        byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);

        int in_count = OpCovInputCount(cov_id);
        int out_count = OpCovOutputCount(cov_id);
        require(out_count == new_states.length);

        // k=0 must execute leader path
        require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);

        State[] prev_states = State[]{};
        for(k, 0, in_count, max_ins) {
            int in_idx = OpCovInputIdx(cov_id, k);
            {
                amount: int p_amount,
                owner: byte[32] p_owner,
                round: int p_round
            } = readInputState(in_idx);

            prev_states = prev_states.append({
                amount: p_amount,
                owner: p_owner,
                round: p_round
            });
        }

        __covenant_policy_conserve_and_bump(prev_states, new_states, leader_sig);

        for(k, 0, out_count, max_outs) {
            int out_idx = OpCovOutputIdx(cov_id, k);
            validateOutputState(out_idx, State {
                amount: new_states[k].amount,
                owner: new_states[k].owner,
                round: new_states[k].round
            });
        }
    }

    // Generated for N:M delegate path
    entry __delegate(sig owner_sig) {
        byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);
        // delegate path must not be leader
        require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);
        __covenant_delegate_policy_authorizeDelegate(owner_sig);
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
        return State {
            seqcommit: new_seqcommit
        };
    }
}
```

### Generated code (illustrative; policy body unchanged)

```js
pragma silverscript ^0.1.0;

contract SeqCommitMirror(byte[32] init_seqcommit) {
    byte[32] seqcommit = init_seqcommit;

    // Compiler-lowered policy function (renamed to avoid entrypoint name collision)
    // same body as source:
    function __covenant_policy_roll_seqcommit(State prev_state, byte[32] block_hash) : (State new_state) { ... }

    // Generated 1:1 covenant entrypoint
    entry __roll_seqcommit(byte[32] block_hash) {
        State prev_state = State {
            seqcommit: seqcommit
        };

        (State new_state) = __covenant_policy_roll_seqcommit(prev_state, block_hash);

        require(OpAuthOutputCount(this.activeInputIndex) == 1);
        int out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
        validateOutputState(out_idx, State {
            seqcommit: new_state.seqcommit
        });
    }
}
```

## Implementation notes

1. `State` is an implicit compiler type synthesized from contract fields.
2. Internally the compiler can lower `State`/`State[]` into any representation; this doc only fixes the user-facing API.
3. Existing `readInputState`/`validateOutputState` remain the codegen backbone; `validateOutputStateWithTemplate` is available for manual cross-template routing, not declaration lowering.
4. `N:M` lowering keeps one transition group per transaction.

## Homogeneous-template assumption

Stateful covenant declarations assume that every selected input and every
continuation output in the active covenant-ID group uses this contract's exact
program template and implicit `State` layout. In particular:

1. generated prior-state reconstruction uses raw `readInputState` with this
   contract's field offsets and types;
2. generated continuation checks use same-template `validateOutputState`;
3. a shared covenant ID is therefore treated by this abstraction as one
   homogeneous contract family, even though the underlying covenant mechanism
   can represent more general arrangements.

Reading an input with another layout can misinterpret its bytes, and a
continuation with another template will fail same-template validation. A
heterogeneous covenant family must use handwritten validation with the
templated state builtins, authenticate each participating template and layout,
and must not rely on covenant-declaration state wrappers for that route.
