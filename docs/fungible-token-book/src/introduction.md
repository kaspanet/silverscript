# Introduction

This book explains two SilverScript examples together:

- `silverscript-lang/tests/examples/fungible-token.sil` [[Link]](https://github.com/kaspanet/silverscript/blob/master/silverscript-lang/tests/examples/fungible-token.sil)
- `silverscript-lang/tests/examples/fungible-token-minter.sil` [[Link]](https://github.com/kaspanet/silverscript/blob/master/silverscript-lang/tests/examples/fungible-token-minter.sil)

Together they form a worked example of a covenant-controlled fungible token system in SilverScript.

The example is interesting because it is not just "a token owned by a pubkey". It demonstrates:

- token state carried in covenant state
- ownership by pubkey, by script hash, or by covenant ID
- mint-capable and non-mint-capable token branches
- a separate controller covenant that controls issuance
- cross-contract linkage through covenant IDs
- template-based validation of another contract's state shape
- covenant declaration flows for initialization, transfer, and minting

The contracts are just examples, not token standards. They may contain errors and are not guaranteed to be secure. For the actual standard, see [KCC-20](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md). Their value is that they show what the SilverScript covenant model can express.

The rest of this book is organized as follows:

- `FungibleToken At A Glance` describes the system as a whole.
- `The FungibleToken Contract` explains the token covenant itself.
- `The FungibleTokenMinter Contract` explains the companion issuance controller.
- `How The Examples Are Used` explains the kinds of situations these examples are meant to model.
- `Example Walkthroughs` explains the main flows and failure cases.
- `What The Examples Demonstrate` summarizes the larger ideas these contracts are designed to show.
