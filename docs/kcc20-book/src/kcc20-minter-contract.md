# The KCC20Minter Contract

Source: `silverscript-lang/tests/examples/kcc20-minter.sil` [[Link]](https://github.com/kaspanet/silverscript/blob/cd3857d93e53c320d2a8b8eebb391773a12b38f4/silverscript-lang/tests/examples/kcc20-minter.sil)

## Full Source

```sil
contract KCC20Minter(pubkey owner, byte[32] initKCC20Covid, int initAmount,
    bool initInitialized, int templatePrefixLen, int templateSuffixLen, byte[32] expectedTemplateHash,
    byte[] templatePrefix, byte[] templateSuffix) {

    byte[32] kcc20Covid = initKCC20Covid;
    int amount = initAmount;
    bool initialized = initInitialized;

    struct KCC20State {
        byte[32] ownerIdentifier;
        byte identifierType;
        int amount;
        bool isMinter;
    }

    byte constant IDENTIFIER_COVENANT_ID = 0x02;

    function calcInAmount() : (int) {
        KCC20State dogPrevState = readInputStateWithTemplate(
            OpCovInputIdx(kcc20Covid, 0),
            templatePrefixLen,
            templateSuffixLen,
            expectedTemplateHash
        );
        return (dogPrevState.amount);
    }

    function checkMinterDogNewState(KCC20State minterDogNewState){
        require(minterDogNewState.ownerIdentifier == byte[32](owner)); // We do not allow the minter to delegate minting authority to another party.
        require(minterDogNewState.identifierType == IDENTIFIER_COVENANT_ID);
        require(minterDogNewState.isMinter); // The minter cannot stop being a minter.

        validateOutputStateWithTemplate(
            OpCovOutputIdx(kcc20Covid, 0),
            minterDogNewState,
            templatePrefix,
            templateSuffix,
            expectedTemplateHash
        );
    }

    function checkRecipientDogNewState(KCC20State recipientDogNewState){
        require(!recipientDogNewState.isMinter); // We do not allow the minter to designate another minter.
        validateOutputStateWithTemplate(
            OpCovOutputIdx(kcc20Covid, 1),
            recipientDogNewState,
            templatePrefix,
            templateSuffix,
            expectedTemplateHash
        );
    }

    #[covenant.singleton]
    function init(State prevState, State newState, sig s) {
        require(!initialized);
        require(newState.kcc20Covid == OpOutputCovenantId(0));
        require(newState.amount == prevState.amount);
        require(newState.initialized);
        require(checkSig(s, owner));

    }

    #[covenant.singleton]
    function mint(State prevState, State newState, sig s, KCC20State minterDogNewState, KCC20State recipientDogNewState) {
        require(initialized);
        require(newState.amount >= 0);
        require(newState.initialized);
        require(newState.kcc20Covid == prevState.kcc20Covid);

        // We focus on the simple case 1-2 minting transfer.
        require(OpCovOutputCount(kcc20Covid) == 2);
        require(OpCovInputCount(kcc20Covid) == 1);

        checkMinterDogNewState(minterDogNewState);
        checkRecipientDogNewState(recipientDogNewState);

        int inAmount = calcInAmount();
        int mintedAmount = minterDogNewState.amount + recipientDogNewState.amount - inAmount;
        require(newState.amount == amount - mintedAmount);
        require(checkSig(s, owner));
    }
}
```

## Purpose

`KCC20Minter` is a companion covenant that controls minting for one KCC20 covenant instance.

The key idea is that mint policy is not embedded directly into KCC20's constructor or entrypoint arguments. Instead a separate covenant holds:

- which KCC20 covenant it governs
- how much issuance remains
- whether the cross-contract binding has already been initialized

## Constructor And State

The constructor takes:

- `owner`
- `initKCC20Covid`
- `initAmount`
- `initInitialized`
- `templatePrefixLen`
- `templateSuffixLen`
- `expectedTemplateHash`
- `templatePrefix`
- `templateSuffix`

The state fields derived from those constructor args are:

```sil
byte[32] kcc20Covid = initKCC20Covid;
int amount = initAmount;
bool initialized = initInitialized;
```

The template-related constructor fields are not mutable state. They are contract parameters baked into the script instance.

## Embedded `KCC20State`

The minter declares:

```sil
struct KCC20State {
    byte[32] ownerIdentifier;
    byte identifierType;
    int amount;
    bool isMinter;
}
```

This local struct gives the minter an explicit schema for reading and validating KCC20 state.

## Why Template Metadata Exists

The minter needs to reason about a KCC20 output. It cannot safely trust "some output at index X has the right fields". It must ensure that the output really belongs to the intended KCC20 template.

That is why the contract stores:

- prefix length
- suffix length
- expected template hash
- the actual prefix bytes
- the actual suffix bytes

These values come from the KCC20 script with its encoded state region removed. Conceptually, they identify the fixed template around the mutable KCC20 state payload.

## `calcInAmount`

```sil
function calcInAmount() : (int)
```

This function reads the previous KCC20 state from the covenant input selected by:

```sil
OpCovInputIdx(kcc20Covid, 0)
```

That means:

- find the first covenant input whose covenant ID equals `kcc20Covid`
- parse it using the expected template metadata
- return its `amount`

This is how the minter learns the old token supply before minting.

## `checkMinterDogNewState`

```sil
function checkMinterDogNewState(KCC20State minterDogNewState)
```

This validates the continuing minter-owned KCC20 branch.

It enforces three things:

- the branch must remain owned by the minter's `owner` value encoded as `byte[32]`
- the branch must remain covenant-ID owned
- the branch must remain marked as a minter

Then it validates the actual output with:

```sil
validateOutputStateWithTemplate(
    OpCovOutputIdx(kcc20Covid, 0),
    minterDogNewState,
    templatePrefix,
    templateSuffix,
    expectedTemplateHash
);
```

This does two jobs:

- it selects the first KCC20 output for the governed covenant ID
- it ensures that output matches the expected KCC20 template and state payload

This is much safer than trusting an arbitrary output index or script shape.

## `checkRecipientDogNewState`

```sil
function checkRecipientDogNewState(KCC20State recipientDogNewState)
```

This validates the newly minted recipient output.

It enforces that the recipient output is not itself a minter branch, and then checks that the second KCC20 output in the transaction matches the supplied state.

That means each mint transaction has a fixed shape:

- output 0 is the continuing minter KCC20 branch
- output 1 is the freshly minted recipient KCC20 branch

## `init`

The first entrypoint is:

```sil
#[covenant.singleton]
function init(State prevState, State newState, sig s)
```

This binds a previously uninitialized minter to a freshly created KCC20 covenant.

Its key checks are:

```sil
require(!initialized);
require(newState.kcc20Covid == OpOutputCovenantId(0));
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

The critical piece is `OpOutputCovenantId(0)`. That lets the minter learn the covenant ID of the KCC20 output created in the same transaction.

Without that step there would be no secure way for the minter to bind itself to the exact KCC20 covenant instance it just created.

## Initialization Diagram

```text
before init:
  initialized = false
  kcc20Covid = placeholder

after init:
  initialized = true
  kcc20Covid = covenant ID of the newly created KCC20 output
```

## `mint`

The second entrypoint is:

```sil
#[covenant.singleton]
function mint(State prevState, State newState, sig s, KCC20State minterDogNewState, KCC20State recipientDogNewState)
```

This is the issuance step.

The checks break down into four groups.

### Minter state invariants

```sil
require(initialized);
require(newState.amount >= 0);
require(newState.initialized);
require(newState.kcc20Covid == prevState.kcc20Covid);
```

The minter must stay initialized, cannot go negative, and cannot switch to a different KCC20 covenant.

### KCC20 cardinality

```sil
require(OpCovOutputCount(kcc20Covid) == 2);
require(OpCovInputCount(kcc20Covid) == 1);
```

The example only allows minting when exactly one KCC20 covenant input and two KCC20 covenant outputs are involved. That keeps the accounting simple and makes the split between the persistent minter branch and the recipient branch explicit.

### KCC20 template validation

```sil
checkMinterDogNewState(minterDogNewState);
checkRecipientDogNewState(recipientDogNewState);
```

This ensures both supplied KCC20 successor states match the actual outputs in the transaction.

### Issuance accounting

```sil
int inAmount = calcInAmount();
int mintedAmount = minterDogNewState.amount + recipientDogNewState.amount - inAmount;
require(newState.amount == amount - mintedAmount);
```

This means:

- compute previous KCC20 amount
- compute the total amount in the two new KCC20 outputs
- subtract the old amount to get the newly minted quantity
- decrement the minter's remaining allowance by exactly that amount

If someone tries to mint more than the allowance permits, the minter state cannot satisfy the final equality and the transaction fails.

## Mint Accounting Diagram

```text
mintedAmount
  = (new minter-branch amount + new recipient amount)
    - previous minter-branch amount

new minter allowance
  = old minter allowance - mintedAmount
```

## Mint Shape Diagram

```text
before mint:
  KCC20 minter branch amount = old amount
  KCC20Minter allowance = remaining budget

after mint:
  KCC20 minter branch amount = 0
  KCC20 recipient branch amount = minted tokens for this transaction
  KCC20Minter allowance = reduced by minted amount
```

## Why A Separate Minter Covenant Matters

This design cleanly demonstrates covenant composition.

- KCC20 knows how to authorize token state transitions.
- KCC20Minter knows how to constrain issuance.

KCC20 can be reused with different issuance policies because mint control is externalized into another covenant rather than welded into the token contract itself.
