# KCC20 Debug Flow Fixtures

These launch JSON files define the first debugger target for the rebased DAP work.

They intentionally focus on the `KCC20` token covenant in `silverscript-lang/tests/examples/kcc20.sil` and avoid pubkey signatures by using covenant-ID ownership. That makes the flow deterministic while still exercising covenant state, generated covenant entrypoints, `State[]` arguments, witness inputs, minting, burning, and non-minter transfer checks.

Flow:

1. `01-init-kcc20-minter-branch.json` initializes a zero-amount minter branch.
2. `02-create-tokens-from-minter.json` creates token supply from that minter branch.
3. `03-burn-tokens-from-minter.json` burns part of the minter branch supply.
4. `04-transfer-created-tokens.json` transfers a created non-minter token branch through a covenant-ID witness input.

The final DAP goal is to launch each file, stop in source-level covenant code, inspect `prevStates`/`newStates`, continue to completion, and report success.
