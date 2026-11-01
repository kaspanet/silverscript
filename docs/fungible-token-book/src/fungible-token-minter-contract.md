# The FungibleTokenMinter Contract

Source: `silverscript-lang/tests/examples/fungible-token-minter.sil` [[Link]](https://github.com/kaspanet/silverscript/blob/master/silverscript-lang/tests/examples/fungible-token-minter.sil)

## Full Source

```js
// This companion minter is just an example. It may contain errors and is not
// guaranteed to be secure. For the actual token standard, see:
// https://github.com/kaspanet/kccs/blob/main/kcc-0020.md
contract FungibleTokenMinter(pubkey owner, byte[32] initFungibleTokenCovid, int initAmount,
    bool initInitialized, int templatePrefixLen, int templateSuffixLen, byte[32] expectedTemplateHash) {

    byte[32] fungibleTokenCovid = initFungibleTokenCovid;
    int amount = initAmount;
    bool initialized = initInitialized;

    struct FungibleTokenState {
        byte[32] ownerIdentifier;
        byte identifierType;
        int amount;
        bool isMinter;
    }

    byte constant IDENTIFIER_COVENANT_ID = 0x02;

    function calcInAmount(int fungibleTokenInputIdx) : int {
        FungibleTokenState fungibleTokenPrevState = readInputStateWithTemplate(
            fungibleTokenInputIdx,
            templatePrefixLen,
            templateSuffixLen,
            expectedTemplateHash
        );
        return fungibleTokenPrevState.amount;
    }

    function checkMinterFungibleTokenNewState(FungibleTokenState minterFungibleTokenNewState, int fungibleTokenInputIdx){
        byte[32] controllerId = OpInputCovenantId(this.activeInputIndex);
        require(minterFungibleTokenNewState.ownerIdentifier == controllerId); // We do not allow the minter to delegate minting authority to another party.
        require(minterFungibleTokenNewState.identifierType == IDENTIFIER_COVENANT_ID);
        require(minterFungibleTokenNewState.isMinter); // The minter cannot stop being a minter.

        validateOutputStateWithInputTemplate(
            OpCovOutputIdx(fungibleTokenCovid, 0),
            minterFungibleTokenNewState,
            fungibleTokenInputIdx,
            templatePrefixLen,
            templateSuffixLen,
            expectedTemplateHash
        );
    }

    function checkRecipientFungibleTokenNewState(FungibleTokenState recipientFungibleTokenNewState, int fungibleTokenInputIdx){
        require(!recipientFungibleTokenNewState.isMinter); // We do not allow the minter to designate another minter.
        validateOutputStateWithInputTemplate(
            OpCovOutputIdx(fungibleTokenCovid, 1),
            recipientFungibleTokenNewState,
            fungibleTokenInputIdx,
            templatePrefixLen,
            templateSuffixLen,
            expectedTemplateHash
        );
    }

    #[covenant.singleton]
    function init(State prevState, State newState, sig s) {
        require(!initialized);
        require(newState.fungibleTokenCovid == OpOutputCovenantId(0));
        require(newState.amount == prevState.amount);
        require(newState.initialized);
        require(checkSig(s, owner));

    }

    #[covenant.singleton]
    function mint(State prevState, State newState, sig s, FungibleTokenState minterFungibleTokenNewState, FungibleTokenState recipientFungibleTokenNewState) {
        require(initialized);
        require(newState.amount >= 0);
        require(newState.initialized);
        require(newState.fungibleTokenCovid == prevState.fungibleTokenCovid);

        // We focus on the simple case 1-2 minting transfer.
        require(OpCovOutputCount(fungibleTokenCovid) == 2);
        require(OpCovInputCount(fungibleTokenCovid) == 1);
        int fungibleTokenInputIdx = OpCovInputIdx(fungibleTokenCovid, 0);

        checkMinterFungibleTokenNewState(minterFungibleTokenNewState, fungibleTokenInputIdx);
        checkRecipientFungibleTokenNewState(recipientFungibleTokenNewState, fungibleTokenInputIdx);

        int inAmount = calcInAmount(fungibleTokenInputIdx);
        int mintedAmount = minterFungibleTokenNewState.amount + recipientFungibleTokenNewState.amount - inAmount;
        require(newState.amount == amount - mintedAmount);
        require(checkSig(s, owner));
    }
}
```

## Purpose

`FungibleTokenMinter` is the example controller covenant for one FungibleToken covenant instance.

The key idea is that issuance policy is not embedded directly into FungibleToken's constructor or entrypoint arguments. Instead a separate controller covenant holds:

- which FungibleToken covenant it governs
- how much issuance allowance remains
- whether the cross-contract binding has already been initialized

## Constructor And State

The constructor takes:

- `owner`
- `initFungibleTokenCovid`
- `initAmount`
- `initInitialized`
- `templatePrefixLen`
- `templateSuffixLen`
- `expectedTemplateHash`

The state fields derived from those constructor args are:

```js
byte[32] fungibleTokenCovid = initFungibleTokenCovid;
int amount = initAmount;
bool initialized = initInitialized;
```

The template-related constructor fields are not mutable state. They are contract parameters baked into the script instance.

## Embedded `FungibleTokenState`

The minter declares:

```js
struct FungibleTokenState {
    byte[32] ownerIdentifier;
    byte identifierType;
    int amount;
    bool isMinter;
}
```

This local struct gives the minter an explicit schema for reading and validating FungibleToken state.

## Why Template Metadata Exists

The minter needs to reason about a FungibleToken output. It cannot safely trust "some output at index X has the right fields". It must ensure that the output really belongs to the intended FungibleToken template.

That is why the contract stores:

- prefix length
- suffix length
- expected template hash

The lengths locate the fixed template bytes around the state payload in the
co-spent FungibleToken input. The expected hash authenticates those bytes. The minter
therefore does not embed or receive a second copy of the full template.

## `calcInAmount`

```js
function calcInAmount(int fungibleTokenInputIdx) : int
```

The `mint` entrypoint selects the sole FungibleToken input with:

```js
OpCovInputIdx(fungibleTokenCovid, 0)
```

It passes that index into `calcInAmount`. The function then:

- parse it using the expected template metadata
- return its `amount`

This is how the minter learns the old token supply before minting.

## `checkMinterFungibleTokenNewState`

```js
function checkMinterFungibleTokenNewState(FungibleTokenState minterFungibleTokenNewState, int fungibleTokenInputIdx)
```

This validates the continuing controller-owned FungibleToken minter branch.

It enforces three things:

- the branch must remain owned by the current `FungibleTokenMinter` covenant ID
- the branch must remain covenant-ID owned
- the branch must remain marked as a minter

The first check deliberately uses the active input's covenant ID:

```js
byte[32] controllerId = OpInputCovenantId(this.activeInputIndex);
require(minterFungibleTokenNewState.ownerIdentifier == controllerId);
```

This separates two identities:

- `owner` is the admin key that signs minter actions
- `controllerId` is the covenant ID that owns the FungibleToken minter branch

So the admin key authorizes the controller, but the FungibleToken branch remains owned by the controller covenant.

Then it validates the actual output with:

```js
validateOutputStateWithInputTemplate(
    OpCovOutputIdx(fungibleTokenCovid, 0),
    minterFungibleTokenNewState,
    fungibleTokenInputIdx,
    templatePrefixLen,
    templateSuffixLen,
    expectedTemplateHash
);
```

This does three jobs:

- it selects the first FungibleToken output for the governed covenant ID
- it extracts the FungibleToken template bytes from the co-spent FungibleToken input
- it authenticates those bytes against `expectedTemplateHash`
- it ensures that the output matches that template and the supplied state

This is much safer than trusting an arbitrary output index or script shape.

## `checkRecipientFungibleTokenNewState`

```js
function checkRecipientFungibleTokenNewState(FungibleTokenState recipientFungibleTokenNewState, int fungibleTokenInputIdx)
```

This validates the newly minted recipient output.

It enforces that the recipient output is not itself a minter branch, and then checks that the second FungibleToken output in the transaction matches the supplied state.

That means each mint transaction has a fixed shape:

- output 0 is the continuing minter FungibleToken branch
- output 1 is the freshly minted recipient FungibleToken branch

## `init`

The first entrypoint is:

```js
#[covenant.singleton]
function init(State prevState, State newState, sig s)
```

This binds a previously uninitialized controller covenant to a freshly created FungibleToken covenant.

The controller covenant already has its own covenant ID before this entrypoint runs. In the bootstrap flow, a plain funding UTXO first creates the uninitialized controller covenant `C`. Then the asset genesis transaction spends `C` through `init`, creates the FungibleToken asset covenant `A`, and recreates `C` as initialized and bound to `A`.

Its key checks are:

```js
require(!initialized);
require(newState.fungibleTokenCovid == OpOutputCovenantId(0));
require(newState.amount == prevState.amount);
require(newState.initialized);
require(checkSig(s, owner));
```

Interpretation:

- the minter must not already be initialized
- the new minter state must point at the covenant ID of output 0
- the issuance allowance is preserved during initialization
- the new state flips `initialized` to true
- the owner authorizes the operation

The critical piece is `OpOutputCovenantId(0)`. That lets the minter learn the covenant ID of the FungibleToken output created in the same transaction.

Without this check, this single transaction would not prove that the initialized minter bound itself to the exact FungibleToken covenant output created beside it.

## Initialization Diagram

```text
plain funding utxo
    |
    v
[minter genesis tx] -> C covenant id
    |
    v
[asset genesis/init tx] -> A covenant id + C binds to A

before asset genesis/init:
  C.initialized = false
  C.fungibleTokenCovid = placeholder

after asset genesis/init:
  C.initialized = true
  C.fungibleTokenCovid = A
  A.ownerIdentifier = C
```

## `mint`

The second entrypoint is:

```js
#[covenant.singleton]
function mint(State prevState, State newState, sig s, FungibleTokenState minterFungibleTokenNewState, FungibleTokenState recipientFungibleTokenNewState)
```

This is the transaction-level minting step that enforces the issuance policy.

The checks break down into four groups.

### Minter state invariants

```js
require(initialized);
require(newState.amount >= 0);
require(newState.initialized);
require(newState.fungibleTokenCovid == prevState.fungibleTokenCovid);
```

The minter must stay initialized, cannot go negative, and cannot switch to a different FungibleToken covenant.

### FungibleToken cardinality

```js
require(OpCovOutputCount(fungibleTokenCovid) == 2);
require(OpCovInputCount(fungibleTokenCovid) == 1);
int fungibleTokenInputIdx = OpCovInputIdx(fungibleTokenCovid, 0);
```

The example only allows minting when exactly one FungibleToken covenant input and two FungibleToken covenant outputs are involved. That keeps the accounting simple and makes the split between the persistent minter branch and the recipient branch explicit.

### FungibleToken template validation

```js
checkMinterFungibleTokenNewState(minterFungibleTokenNewState, fungibleTokenInputIdx);
checkRecipientFungibleTokenNewState(recipientFungibleTokenNewState, fungibleTokenInputIdx);
```

This ensures both supplied FungibleToken successor states match the actual outputs in
the transaction. Both checks reuse the same template source because the
cardinality rule establishes exactly one FungibleToken input.

### Issuance accounting

```js
int inAmount = calcInAmount(fungibleTokenInputIdx);
int mintedAmount = minterFungibleTokenNewState.amount + recipientFungibleTokenNewState.amount - inAmount;
require(newState.amount == amount - mintedAmount);
```

This means:

- compute previous FungibleToken amount
- compute the total amount in the two new FungibleToken outputs
- subtract the old amount to get the newly minted quantity
- decrement the minter's remaining issuance allowance by exactly that amount

If someone tries to mint more than the issuance allowance permits, the minter state cannot satisfy the final equality and the transaction fails.

## Mint Accounting Diagram

```text
mintedAmount
  = (new minter-branch amount + new recipient amount)
    - previous minter-branch amount

new issuance allowance
  = old issuance allowance - mintedAmount
```

## Mint Shape Diagram

```text
before mint:
  FungibleToken minter branch amount = old amount
  FungibleTokenMinter issuance allowance = remaining budget

after mint:
  FungibleToken minter branch amount = 0
  FungibleToken recipient branch amount = minted tokens for this transaction
  FungibleTokenMinter issuance allowance = reduced by minted amount
```

## Why A Separate Minter Covenant Matters

This design cleanly demonstrates covenant composition.

- FungibleToken knows how to authorize token state transitions.
- FungibleTokenMinter knows how to constrain issuance.

FungibleToken can be reused with different issuance policies because issuance control is externalized into another covenant rather than welded into the token contract itself.
