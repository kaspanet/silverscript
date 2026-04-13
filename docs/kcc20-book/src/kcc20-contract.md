# The KCC20 Contract

Source: `silverscript-lang/tests/examples/kcc20.sil`

## Full Source

```sil
contract KCC20(byte[32] genesisPk, int genesisAmount, byte genesisIdentifierType, bool genesisIsMinter, int maxCovIns, int maxCovOuts) {
    byte constant IDENTIFIER_PUBKEY = 0x00;
    byte constant IDENTIFIER_SCRIPT_HASH = 0x01;
    byte constant IDENTIFIER_COVENANT_ID = 0x02;
    
    byte[32] ownerIdentifier = genesisPk;
    byte identifierType = genesisIdentifierType;
    int amount = genesisAmount;
    bool isMinter = genesisIsMinter;

    function checkSigs(State[] prevStates, sig[] sigs, byte[] witnesses) {
        for(i, 0, prevStates.length, maxCovIns) {
            if(prevStates[i].identifierType == IDENTIFIER_PUBKEY){
                require(checkSig(sigs[i], prevStates[i].ownerIdentifier));
            } else if(prevStates[i].identifierType == IDENTIFIER_SCRIPT_HASH){
                byte[] spk = new ScriptPubKeyP2SH(prevStates[i].ownerIdentifier);
                require(tx.inputs[witnesses[i]].scriptPubKey == spk);
            } else if(prevStates[i].identifierType == IDENTIFIER_COVENANT_ID){
                require(OpInputCovenantId(witnesses[i]) == prevStates[i].ownerIdentifier);
            } else {
                require(false);
            }
        }
    }

    function checkAmounts(State[] prevStates, State[] newStates) {
        if(!isMinter){
            int totalIn = 0;
            for(i, 0, prevStates.length, maxCovIns) {
                totalIn = totalIn + prevStates[i].amount;
            }

            int totalOut = 0;
            for(i, 0, newStates.length, maxCovOuts) {
                totalOut = totalOut + newStates[i].amount;
            }

            require(totalIn == totalOut);
        }
    }

    function checkMintingTransfer(State[] newStates){
        if(!isMinter){
            for(i, 0, newStates.length, maxCovOuts) {
                require(!newStates[i].isMinter);
            }
        }
    }

    #[covenant(binding = cov, from = maxCovIns, to = maxCovOuts)]
    function transfer(State[] prevStates, State[] newStates, sig[] sigs, byte[] witnesses) {
        checkSigs(prevStates, sigs, witnesses);
        checkAmounts(prevStates, newStates);
        checkMintingTransfer(newStates);
    }
}
```

## Constructor Parameters

The contract constructor is:

```sil
contract KCC20(
    byte[32] genesisPk,
    int genesisAmount,
    byte genesisIdentifierType,
    bool genesisIsMinter,
    int maxCovIns,
    int maxCovOuts
)
```

These constructor values become the initial state and loop bounds.

- `genesisPk` becomes the initial `ownerIdentifier`
- `genesisAmount` becomes the initial `amount`
- `genesisIdentifierType` becomes the initial ownership mode
- `genesisIsMinter` marks whether the branch starts with mint privileges
- `maxCovIns` and `maxCovOuts` cap covenant fan-in and fan-out loops

## State Layout

The contract state is encoded as contract fields:

```sil
byte[32] ownerIdentifier = genesisPk;
byte identifierType = genesisIdentifierType;
int amount = genesisAmount;
bool isMinter = genesisIsMinter;
```

Every covenant transition reads and writes these fields as `State`.

## Ownership Modes

KCC20 defines three constants:

```sil
byte constant IDENTIFIER_PUBKEY = 0x00;
byte constant IDENTIFIER_SCRIPT_HASH = 0x01;
byte constant IDENTIFIER_COVENANT_ID = 0x02;
```

These constants drive `checkSigs`.

### Pubkey ownership

```sil
require(checkSig(sigs[i], prevStates[i].ownerIdentifier));
```

The spender must supply a signature matching the previous state's pubkey.

### Script-hash ownership

```sil
byte[] spk = new ScriptPubKeyP2SH(prevStates[i].ownerIdentifier);
require(tx.inputs[witnesses[i]].scriptPubKey == spk);
```

Here KCC20 does not validate signatures itself. Instead it requires that the transaction include an input whose scriptPubKey corresponds to the owner script hash. In other words, the script-hash-owned KCC20 branch is authorized by the presence of a matching P2SH-controlled input.

### Covenant-ID ownership

```sil
require(OpInputCovenantId(witnesses[i]) == prevStates[i].ownerIdentifier);
```

This lets a KCC20 branch be owned by another covenant. Spending it requires a witness input whose covenant ID matches the owner identifier.

## Ownership Diagram

```text
identifierType = 0x00  -> pubkey ownership
identifierType = 0x01  -> script-hash ownership
identifierType = 0x02  -> covenant-ID ownership
```

## `checkSigs`

The first major function is:

```sil
function checkSigs(State[] prevStates, sig[] sigs, byte[] witnesses)
```

It iterates over previous states and checks authorization according to each state's ownership mode.

Important details:

- `prevStates` is an array because the contract supports covenant fan-in.
- `sigs` is parallel to `prevStates` for pubkey-owned branches.
- `witnesses` gives input indexes that the contract should inspect for script-hash and covenant-ID ownership.
- `witnesses` exists so the contract can jump directly to the relevant transaction inputs instead of scanning all inputs to discover which one should authorize each previous state.
- the loop upper bound is controlled by `maxCovIns`

This function is the core of KCC20's flexible ownership model.

For the non-pubkey ownership case, see the [Inter-Covenant Communication](./kcc20-overview.md#inter-covenant-communication) explanation in the overview chapter.

## `checkAmounts`

The supply rule lives in:

```sil
function checkAmounts(State[] prevStates, State[] newStates)
```

It only enforces conservation when the active branch is not a minter:

```sil
if(!isMinter) {
    ...
    require(totalIn == totalOut);
}
```

So KCC20 has two distinct modes:

- `isMinter == false`: token supply must be preserved across the transition
- `isMinter == true`: the branch may increase or decrease `amount`

This design makes mint and burn behavior a property of a particular branch of token state rather than a separate opcode or special-case function.

### Supply Rule Diagram

```text
ordinary branch:
  total input amount == total output amount

minter branch:
  total output amount may change
```

## `checkMintingTransfer`

The third function is:

```sil
function checkMintingTransfer(State[] newStates)
```

It prevents non-minter branches from creating minter-marked outputs:

```sil
if(!isMinter) {
    for(i, 0, newStates.length, maxCovOuts) {
        require(!newStates[i].isMinter);
    }
}
```

This matters because otherwise an ordinary KCC20 branch could escape the supply rules simply by setting `isMinter = true` in a child state.

## The Covenant Entrypoint

KCC20 exposes one covenant declaration:

```sil
#[covenant(binding = cov, from = maxCovIns, to = maxCovOuts)]
function transfer(State[] prevStates, State[] newStates, sig[] sigs, byte[] witnesses)
```

The important parts are:

- `binding = cov`: this is a covenant-bound transition, not an auth-only wrapper
- `from = maxCovIns`: the transition may consume up to that many covenant inputs
- `to = maxCovOuts`: the transition may produce up to that many covenant outputs

The body is intentionally small:

```sil
checkSigs(prevStates, sigs, witnesses);
checkAmounts(prevStates, newStates);
checkMintingTransfer(newStates);
```

That compact entrypoint is possible because the real policy is factored into the three functions above.