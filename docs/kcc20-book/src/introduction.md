# Introduction

This book explains two SilverScript examples together:

- `silverscript-lang/tests/examples/kcc20.sil`
- `silverscript-lang/tests/examples/kcc20-minter.sil`

Together they form a worked example of a covenant-controlled fungible token system in SilverScript.

The example is interesting because it is not just "a token owned by a pubkey". It demonstrates:

- token state carried in covenant state
- ownership by pubkey, by script hash, or by covenant ID
- mint-capable and non-mint-capable token branches
- a separate minter covenant that controls issuance
- cross-contract linkage through covenant IDs
- template-based validation of another contract's state shape
- covenant declaration flows for initialization, transfer, and minting

The contracts are examples, not a production token standard. Their value is that they show what the SilverScript covenant model can express.

The rest of this book is organized as follows:

- `KCC20 At A Glance` describes the system as a whole.
- `The KCC20 Contract` explains the token covenant itself.
- `The KCC20Minter Contract` explains the companion issuance controller.
- `How The Examples Are Used` explains the kinds of situations these examples are meant to model.
- `Example Walkthroughs` explains the main flows and failure cases.
- `What The Examples Demonstrate` summarizes the larger ideas these contracts are designed to show.
