# Dog20 At A Glance

The example is split into two contracts with different responsibilities.

## Dog20

`Dog20` is the token state machine.

Each Dog20 covenant output represents token state with four fields:

- `ownerIdentifier`
- `identifierType`
- `amount`
- `isMinter`

The meaning of `ownerIdentifier` depends on `identifierType`.

- If `identifierType == IDENTIFIER_PUBKEY`, the owner identifier is a pubkey and a matching signature is required.
- If `identifierType == IDENTIFIER_SCRIPT_HASH`, the owner identifier is a P2SH script hash and the transaction must include an input whose scriptPubKey matches that hash.
- If `identifierType == IDENTIFIER_COVENANT_ID`, the owner identifier is a covenant ID and the transaction must include an input whose covenant ID matches it.

So the same token contract supports multiple ownership modes without changing the contract code.

`Dog20` also uses `isMinter` to distinguish ordinary token branches from mint-authorized branches.

- Ordinary branches must conserve supply.
- Minter branches may increase or decrease supply.

## Dog20Minter

`Dog20Minter` is a separate covenant that controls issuance against a particular Dog20 covenant instance.

Its state is:

- `dog20Covid`
- `amount`
- `initialized`

The field name `dog20Covid` is just the name used in the example source. Functionally, it stores the Dog20 covenant ID that this minter controls.

`Dog20Minter` also carries template metadata for the Dog20 contract:

- `templatePrefixLen`
- `templateSuffixLen`
- `expectedTemplateHash`
- `templatePrefix`
- `templateSuffix`

That metadata lets the minter read and validate Dog20 state by template rather than blindly trusting that some output "looks like" a Dog20 output.

## How They Fit Together

The two contracts are meant to be read as one system.

Dog20 is the asset contract. It defines what a token state looks like, how ownership works, and when supply may or may not change.

Dog20Minter is the policy contract. It does not redefine what a Dog20 token is. Instead, it binds itself to one Dog20 covenant instance and restricts how that particular Dog20 branch may be expanded over time.

So the relationship is:

- Dog20 answers: "what counts as a valid token transition?"
- Dog20Minter answers: "under what policy may new Dog20 tokens be issued?"

The contracts fit together through covenant-ID ownership, template validation, and a concrete transaction-level proof of control.

### Inter-Covenant Communication

These examples also illustrate a practical form of inter-covenant communication, often abbreviated as ICC.

The key constraint is that there is no `eval` mechanism here. One covenant cannot directly execute another covenant's code by reference inside the current script.

So when Dog20 wants to treat a token branch as "owned by another covenant", it uses a different proof model:

- the Dog20 state stores a covenant ID as the owner identifier
- the spending transaction must include an input owned by that covenant
- Dog20 checks that one of the chosen witness inputs has the matching covenant ID

In other words, the proof that "this token is owned by that contract" is not an abstract reference. The proof is that the Dog20 transaction actually spends a UTXO owned by that contract.

That is why covenant-ID ownership is so important in this example. It gives a concrete, transaction-level way for one covenant to demonstrate control over another covenant's state.

### Lifecycle

At a high level, the system is meant to work in two phases:

- a binding phase, where the minter learns which Dog20 covenant it controls
- an issuance phase, where Dog20 and Dog20Minter are spent together and each checks its side of the rules

The intended lifecycle is:

1. Create an uninitialized `Dog20Minter`.
2. Spend it through `init`.
3. In the same transaction, create:
   - a Dog20 minter branch with amount `0`
   - a new initialized minter output
4. `init` stores the newly created Dog20 covenant ID in the minter state.
5. Later, spend both contracts together:
   - the Dog20 minter branch
   - the Dog20Minter output
6. In each mint transaction, create:
   - a fresh zero-amount Dog20 minter branch
   - a separate Dog20 recipient output holding the newly minted amount
   - the next Dog20Minter output with reduced allowance
7. Dog20 authorizes the token transition.
8. Dog20Minter verifies the minting rule and decrements its remaining allowance.

This means the token contract and the minter contract do not collapse into one script with one giant policy. They stay separate, and each one verifies the part of the transaction it is responsible for.

### Separation Of Responsibility

This cleanly separates concerns:

- Dog20 defines ownership and transfer semantics.
- Dog20Minter defines issuance policy.

That split is the main architectural point of the example. The token contract is reusable as a token state machine, while the minter contract provides one particular issuance model on top of it.

## System Diagram

```text
Dog20Minter
  |
  | governs issuance for
  v
Dog20
```

## Lifecycle Diagram

```text
uninitialized minter
        |
        v
init transaction
        |
        +--> creates zero-amount Dog20 minter branch
        |
        +--> creates initialized minter output bound to that Dog20
        |
        v
later mint transactions spend both together
        |
        +--> recreate zero-amount minter branch
        |
        +--> create separate recipient token output
```
