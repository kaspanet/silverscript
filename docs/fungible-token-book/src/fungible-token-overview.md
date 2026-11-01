# FungibleToken At A Glance

The example is split into two contracts with different responsibilities.

## FungibleToken

`FungibleToken` is the token state machine.

Each FungibleToken covenant output represents token state with four fields:

- `ownerIdentifier`
- `identifierType`
- `amount`
- `isMinter`

The meaning of `ownerIdentifier` depends on `identifierType`.

- If `identifierType == IDENTIFIER_PUBKEY`, the owner identifier is a pubkey and a matching signature is required.
- If `identifierType == IDENTIFIER_SCRIPT_HASH`, the owner identifier is a P2SH script hash and the transaction must include an input whose scriptPubKey matches that hash.
- If `identifierType == IDENTIFIER_COVENANT_ID`, the owner identifier is a covenant ID and the transaction must include an input whose covenant ID matches it.

So the same token contract supports multiple ownership modes without changing the contract code.

`FungibleToken` also uses `isMinter` to distinguish ordinary token branches from mint-authorized branches.

- Ordinary branches must conserve supply.
- Minter branches may increase or decrease supply.

## FungibleTokenMinter

`FungibleTokenMinter` is the controller covenant used by this example. It controls issuance against a particular FungibleToken covenant instance.

Its state is:

- `fungibleTokenCovid`
- `amount`
- `initialized`

The field name `fungibleTokenCovid` is just the name used in the example source. Functionally, it stores the FungibleToken covenant ID that this minter controls.

`FungibleTokenMinter` also carries template metadata for the FungibleToken contract:

- `templatePrefixLen`
- `templateSuffixLen`
- `expectedTemplateHash`

That metadata lets the minter locate the template bytes in the co-spent FungibleToken
input and authenticate them against the expected hash. It reuses those bytes
to validate the FungibleToken outputs rather than embedding another copy of the
template or trusting that an output merely "looks like" FungibleToken.

## Controller Covenant Terminology

This book uses **controller covenant** for the external policy covenant whose covenant ID owns a privileged FungibleToken minter branch.

In this book, **issuance** means the policy governing when new token supply may be created; **minting** means the concrete transaction-level act of creating that supply.

In this example:

- `A` is the FungibleToken asset covenant ID
- `C` is the controller covenant ID
- `FungibleTokenMinter` is one concrete controller covenant implementation
- `owner` is the admin pubkey that signs controller actions

The distinction matters. The FungibleToken minter branch is not owned by the admin pubkey directly. It is owned by covenant ID `C`. The admin key authorizes the `FungibleTokenMinter` script, and that script decides how its authority over asset `A` may be used.

## How They Fit Together

The two contracts are meant to be read as one system.

FungibleToken is the asset contract. It defines what a token state looks like, how ownership works, and when supply may or may not change.

FungibleTokenMinter is the controller covenant. It does not redefine what a FungibleToken token is. Instead, it binds itself to one FungibleToken covenant instance and restricts how that particular FungibleToken branch may be expanded over time.

So the relationship is:

- FungibleToken answers: "what counts as a valid token transition?"
- FungibleTokenMinter answers: "under what policy may new FungibleToken tokens be issued?"

The contracts fit together through covenant-ID ownership, template validation, and a concrete transaction-level proof of control.

### Inter-Covenant Communication

These examples also illustrate a practical form of inter-covenant communication, often abbreviated as ICC.

The key constraint is that there is no `eval` mechanism here. One covenant cannot directly execute another covenant's code by reference inside the current script.

So when FungibleToken wants to treat a token branch as "owned by another covenant", it uses a different proof model:

- the FungibleToken state stores a covenant ID as the owner identifier
- the spending transaction must include an input owned by that covenant
- FungibleToken checks that one of the chosen witness inputs has the matching covenant ID

In other words, the proof that "this token is owned by that contract" is not an abstract reference. The proof is that the FungibleToken transaction actually spends a UTXO owned by that contract.

That is why covenant-ID ownership is so important in this example. It gives a concrete, transaction-level way for one covenant to demonstrate control over another covenant's state.

### Lifecycle

At a high level, the system is meant to work in three phases:

- a minter genesis phase, where the controller covenant is created and receives covenant ID `C`
- an asset genesis phase, where the FungibleToken asset covenant is created with covenant ID `A`, while `C` binds itself to `A`
- an issuance phase, where FungibleToken and FungibleTokenMinter are spent together and each checks its side of the rules

The intended lifecycle is:

1. Spend a plain funding UTXO into an uninitialized `FungibleTokenMinter`.
2. The minter genesis transaction creates the controller covenant ID `C` using normal covenant genesis hashing.
3. Spend `C` through `init`.
4. In the same asset genesis transaction, create:
   - a FungibleToken minter branch with amount `0`
   - a new initialized minter output
5. The FungibleToken minter branch is owned by `C`.
6. `init` stores the newly created FungibleToken covenant ID `A` in the minter state.
7. Later, spend both contracts together:
   - the FungibleToken minter branch
   - the FungibleTokenMinter output
8. In each mint transaction, create:
   - a fresh zero-amount FungibleToken minter branch
   - a separate FungibleToken recipient output holding the newly minted amount
   - the next FungibleTokenMinter output with reduced issuance allowance
9. FungibleToken authorizes the token transition.
10. FungibleTokenMinter verifies the issuance rule and decrements its remaining issuance allowance.

This means the token contract and the minter contract do not collapse into one script with one giant policy. They stay separate, and each one verifies the part of the transaction it is responsible for.

### Separation Of Responsibility

This cleanly separates concerns:

- FungibleToken defines ownership and transfer semantics.
- FungibleTokenMinter defines issuance policy.

That split is the main architectural point of the example. The token contract is reusable as a token state machine, while the minter contract provides one particular issuance model on top of it.

## System Diagram

```text
FungibleTokenMinter
  |
  | governs issuance for
  v
FungibleToken
```

## Lifecycle Diagram

```mermaid
flowchart TD
    F[Plain funding UTXO]

    MG[minter_genesis_tx<br/>creates controller covenant C]
    C0[C: FungibleTokenMinter<br/>initialized = false<br/>fungibleTokenCovid = placeholder]

    AG[asset_genesis_tx<br/>spends C through init]
    A0[A: FungibleToken minter branch<br/>ownerIdentifier = C<br/>amount = 0]
    C1[C: FungibleTokenMinter<br/>initialized = true<br/>fungibleTokenCovid = A]

    MT[later mint transactions<br/>spend A and C together]
    A1[A: recreated minter branch<br/>amount = 0]
    R[FungibleToken recipient branch<br/>newly minted amount]
    C2[C: FungibleTokenMinter<br/>reduced issuance allowance]

    F --> MG --> C0 --> AG
    AG --> A0
    AG --> C1
    A0 --> MT
    C1 --> MT
    MT --> A1
    MT --> R
    MT --> C2
```
