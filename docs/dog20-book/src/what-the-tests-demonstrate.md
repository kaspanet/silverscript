# What The Examples Demonstrate

This chapter lists the main properties these examples are meant to exhibit.

At a high level, the two contracts play different roles:

- `Dog20` is the main example of a fungible covenant state machine with flexible ownership rules.
- `Dog20Minter` is the main example of covenant composition, where one covenant governs the issuance policy of another.

These examples are easiest to understand as a small set of recurring stories:

- a token can be handed off, split, and merged
- non-minter branches must conserve supply
- minter branches can expand or shrink supply
- ownership can belong to a key, a script hash, or another covenant
- a separate covenant can bind itself to a token covenant and control future minting

## 1. Dog20 Behaves Like A Fungible Token State Machine

Dog20 can:

- move a full balance from one owner to another
- split one balance into several balances
- merge several balances back into one

That means Dog20 supports the basic transformations people expect from a fungible asset model.

## 2. Ordinary Dog20 Branches Conserve Supply

Non-minter branches cannot:

- create value out of nothing
- destroy value arbitrarily
- turn themselves into minter branches

This is the ordinary-token part of the contract.

## 3. Minter Branches Can Expand Or Shrink Supply

When a branch is marked with `isMinter = true`, it can:

- mint more tokens
- burn tokens

This means mint authority is represented directly in covenant state.

## 4. Ownership Is Flexible

The examples demonstrate three ownership models inside one token contract:

- signature ownership
- script-hash ownership
- covenant-ID ownership

This is one of the strongest parts of the example. It shows that ownership can mean:

- "the holder of this key may spend"
- "a transaction containing this script-controlled input may spend"
- "this other covenant may spend"

That is much more expressive than a token model that only understands pubkeys.

## 5. Another Covenant Can Own Dog20

A Dog20 branch can be owned by a covenant ID, and that ownership mode is what allows Dog20Minter to control minting.

This is the bridge from "programmable ownership" to "cross-contract policy".

## 6. Dog20Minter Controls Issuance, Not Dog20 Alone

The two-contract example shows a clean split:

- Dog20 defines token semantics
- Dog20Minter defines issuance policy

This matters because it keeps the token contract reusable. Different issuance policies could be modeled by different companion covenants.

## 7. Initialization Can Bind Contracts Together

One of the most important properties proven by the examples is that a contract can initialize itself against another covenant created in the same transaction.

That is what `init` in Dog20Minter does when it records:

- the covenant ID of the newly created Dog20 output

This is the mechanism that binds the minter to one specific Dog20 instance.

## 8. Template Validation Makes Cross-Contract Checks Safer

Dog20Minter does not merely inspect some Dog20-looking output. It validates:

- the expected template shape
- the expected template hash
- the expected state payload

This is critical because it means the minter is validating a real Dog20 state transition, not trusting a lookalike output.

## 9. The Issuance Budget Is Enforced Across Transactions

The Dog20Minter flow walks through several minting steps and shows that:

- each successful mint reduces remaining allowance
- each successful mint keeps a zero-amount Dog20 minter branch alive for the next mint
- each successful mint creates a separate ordinary Dog20 recipient output for the newly minted amount
- those recipient outputs can later be spent like ordinary Dog20 branches
- minting continues to work while allowance remains
- minting fails when the requested increase would overspend the budget

This is the clearest statement of what Dog20Minter is for.

## 10. The Whole Example Is About Covenant Composition

The biggest idea behind these files is not just "here is a token".

It is:

- one covenant can represent an asset
- another covenant can own or govern that asset
- both can participate in the same transaction
- each contract can verify its own side of the policy

That is why these examples matter. They show how SilverScript can express systems of cooperating covenants, not just isolated spending scripts.
