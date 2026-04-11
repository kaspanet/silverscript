# The Dog20Minter Contract

Source: `silverscript-lang/tests/examples/dog20-minter.sil`

## Full Source

```sil
contract Dog20Minter(pubkey owner, byte[32] initDog20Covid, int initAmount,
    bool initInitialized, int templatePrefixLen, int templateSuffixLen, byte[32] expectedTemplateHash,
    byte[] templatePrefix, byte[] templateSuffix) {

    byte[32] dog20Covid = initDog20Covid;
    int amount = initAmount;
    bool initialized = initInitialized;

    struct Dog20State {
        byte[32] ownerIdentifier;
        byte identifierType;
        int amount;
        bool isMinter;
    }

    function calcInAmount() : (int) {
        Dog20State dogPrevState = readInputStateWithTemplate(
            OpCovInputIdx(dog20Covid, 0),
            templatePrefixLen,
            templateSuffixLen,
            expectedTemplateHash
        );
        return (dogPrevState.amount);
    }

    function checkDogNewState(Dog20State dogNewState){
        validateOutputStateWithTemplate(
            OpCovOutputIdx(dog20Covid, 0),
            dogNewState,
            templatePrefix,
            templateSuffix,
            expectedTemplateHash
        );
    }

    #[covenant.singleton]
    function init(State prevState, State newState, sig s) {
        require(!initialized);
        require(newState.dog20Covid == OpOutputCovenantId(0));
        require(newState.amount == prevState.amount);
        require(newState.initialized);
        require(checkSig(s, owner));

    }

    #[covenant.singleton]
    function mint(State prevState, State newState, sig s, Dog20State dogNewState) {
        require(initialized);
        require(newState.amount >= 0);
        require(newState.initialized);
        require(newState.dog20Covid == prevState.dog20Covid);

        require(OpCovOutputCount(dog20Covid) == 1);
        require(OpCovInputCount(dog20Covid) == 1);
        checkDogNewState(dogNewState);

        int inAmount = calcInAmount();
        int mintedAmount = dogNewState.amount - inAmount;
        require(newState.amount == amount - mintedAmount);
        require(checkSig(s, owner));
    }
}
```

## Purpose

`Dog20Minter` is a companion covenant that controls minting for one Dog20 covenant instance.

The key idea is that mint policy is not embedded directly into Dog20's constructor or entrypoint arguments. Instead a separate covenant holds:

- which Dog20 covenant it governs
- how much issuance remains
- whether the cross-contract binding has already been initialized

## Constructor And State

The constructor takes:

- `owner`
- `initDog20Covid`
- `initAmount`
- `initInitialized`
- `templatePrefixLen`
- `templateSuffixLen`
- `expectedTemplateHash`
- `templatePrefix`
- `templateSuffix`

The state fields derived from those constructor args are:

```sil
byte[32] dog20Covid = initDog20Covid;
int amount = initAmount;
bool initialized = initInitialized;
```

The template-related constructor fields are not mutable state. They are contract parameters baked into the script instance.

## Embedded `Dog20State`

The minter declares:

```sil
struct Dog20State {
    byte[32] ownerIdentifier;
    byte identifierType;
    int amount;
    bool isMinter;
}
```

This local struct gives the minter an explicit schema for reading and validating Dog20 state.

## Why Template Metadata Exists

The minter needs to reason about a Dog20 output. It cannot safely trust "some output at index X has the right fields". It must ensure that the output really belongs to the intended Dog20 template.

That is why the contract stores:

- prefix length
- suffix length
- expected template hash
- the actual prefix bytes
- the actual suffix bytes

These values come from the Dog20 script with its encoded state region removed. Conceptually, they identify the fixed template around the mutable Dog20 state payload.

## `calcInAmount`

```sil
function calcInAmount() : (int)
```

This function reads the previous Dog20 state from the covenant input selected by:

```sil
OpCovInputIdx(dog20Covid, 0)
```

That means:

- find the first covenant input whose covenant ID equals `dog20Covid`
- parse it using the expected template metadata
- return its `amount`

This is how the minter learns the old token supply before minting.

## `checkDogNewState`

```sil
function checkDogNewState(Dog20State dogNewState)
```

This validates the new Dog20 output with:

```sil
validateOutputStateWithTemplate(
    OpCovOutputIdx(dog20Covid, 0),
    dogNewState,
    templatePrefix,
    templateSuffix,
    expectedTemplateHash
);
```

This does two jobs:

- it selects the first output for the governed Dog20 covenant ID
- it ensures that output matches the expected Dog20 template and state payload

This is much safer than trusting an arbitrary output index or script shape.

## `init`

The first entrypoint is:

```sil
#[covenant.singleton]
function init(State prevState, State newState, sig s)
```

This binds a previously uninitialized minter to a freshly created Dog20 covenant.

Its key checks are:

```sil
require(!initialized);
require(newState.dog20Covid == OpOutputCovenantId(0));
require(newState.amount == prevState.amount);
require(newState.initialized);
require(checkSig(s, owner));
```

Interpretation:

- the minter must not already be initialized
- the new minter state must point at the covenant ID of output 0
- the mint allowance is preserved during initialization
- the new state flips `initialized` to true
- the owner authorizes the operation

The critical piece is `OpOutputCovenantId(0)`. That lets the minter learn the covenant ID of the Dog20 output created in the same transaction.

Without that step there would be no secure way for the minter to bind itself to the exact Dog20 covenant instance it just created.

## Initialization Diagram

```text
before init:
  initialized = false
  dog20Covid = placeholder

after init:
  initialized = true
  dog20Covid = covenant ID of the newly created Dog20 output
```

## `mint`

The second entrypoint is:

```sil
#[covenant.singleton]
function mint(State prevState, State newState, sig s, Dog20State dogNewState)
```

This is the issuance step.

The checks break down into four groups.

### Minter state invariants

```sil
require(initialized);
require(newState.amount >= 0);
require(newState.initialized);
require(newState.dog20Covid == prevState.dog20Covid);
```

The minter must stay initialized, cannot go negative, and cannot switch to a different Dog20 covenant.

### Dog20 cardinality

```sil
require(OpCovOutputCount(dog20Covid) == 1);
require(OpCovInputCount(dog20Covid) == 1);
```

The example only allows minting when exactly one Dog20 covenant input and one Dog20 covenant output are involved. That keeps the accounting simple.

### Dog20 template validation

```sil
checkDogNewState(dogNewState);
```

This ensures the supplied `dogNewState` matches the actual Dog20 output in the transaction.

### Issuance accounting

```sil
int inAmount = calcInAmount();
int mintedAmount = dogNewState.amount - inAmount;
require(newState.amount == amount - mintedAmount);
```

This means:

- compute previous Dog20 amount
- compute how much was added in the new Dog20 state
- decrement the minter's remaining allowance by exactly that amount

If someone tries to mint more than the allowance permits, the minter state cannot satisfy the final equality and the transaction fails.

## Mint Accounting Diagram

```text
mintedAmount = new Dog20 amount - previous Dog20 amount

new minter allowance
  = old minter allowance - mintedAmount
```

## Why A Separate Minter Covenant Matters

This design cleanly demonstrates covenant composition.

- Dog20 knows how to authorize token state transitions.
- Dog20Minter knows how to constrain issuance.

Dog20 can be reused with different issuance policies because mint control is externalized into another covenant rather than welded into the token contract itself.
