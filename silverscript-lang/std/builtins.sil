// SilverScript standard-library reference.
//
// This file is documentation-first: it records builtin signatures and intended
// semantics for editor discovery and future standard-library organization.
// It is not compiled as a normal contract.

/**
 * Role:
 *      Validate a state transition into the same contract template.
 *
 * Definition:
 *      Rebuild this contract's redeem script with `newState` and require
 *      `tx.outputs[outputIndex]` to use the matching P2SH `scriptPubKey`.
 *      `newState` must provide every state field exactly once in this
 *      contract's own `State` layout.
 *
 * Example:
 * ```js
 * validateOutputState(0, { count: count + 1, owner: owner });
 * ```
 *
 * Pseudo logic:
 *   1. Encode `newState` using this contract's own `State` layout.
 *   2. Keep the current contract's non-state prefix and suffix.
 *   3. Rebuild the redeem script as `prefix || encoded_state || suffix`.
 *   4. Require `tx.outputs[outputIndex]` to use the matching P2SH `scriptPubKey`.
 *
 * Security notes:
 *   - Only checks same-template continuation with the given state.
 *   - It does not on its own constrain amount or transaction shape.
 */
function validateOutputState(int outputIndex, object newState);

/**
 * Role:
 *      Validate a state transition into a foreign contract template.
 *
 * Definition:
 *      Encode `newState` using its static struct layout, splice it into the
 *      supplied foreign template, and require `tx.outputs[outputIndex]` to use
 *      the matching P2SH `scriptPubKey`.
 *
 * Example:
 * ```js
 * Receipt receipt = { order_id: order_id, buyer: buyer, amount: amount };
 * validateOutputStateWithTemplate(1, receipt, receipt_prefix, receipt_suffix, receipt_hash);
 * ```
 *
 * Pseudo logic:
 *   1. Check that `blake2b(templatePrefix || templateSuffix)` matches `expectedTemplateHash`.
 *   2. Encode `newState` using its static struct layout.
 *   3. Rebuild the foreign redeem script as `templatePrefix || encoded_state || templateSuffix`.
 *   4. Require `tx.outputs[outputIndex]` to use the matching P2SH `scriptPubKey`.
 *
 * Security notes:
 *   - `expectedTemplateHash` should come from trusted protocol data such as
 *     contract state or a verified route commitment, not from an untrusted caller.
 */
function validateOutputStateWithTemplate(
    int outputIndex,
    object newState,
    byte[] templatePrefix,
    byte[] templateSuffix,
    byte[32] expectedTemplateHash
);

/**
 * Role:
 *      Read another input as this same contract's `State`.
 *
 * Definition:
 *      Decode fixed-size state fields out of another input's sigscript using
 *      this contract's own `State` layout and the current template's known
 *      script structure.
 *
 * Example:
 * ```js
 * {x: int in_x, y: byte[2] in_y} = readInputState(1);
 * require(in_x > 7);
 * ```
 *
 * Pseudo logic:
 *   1. Assume the foreign input uses the same contract template as the current one.
 *   2. Use this contract's script structure and local `State` layout to
 *      locate each fixed-size field in the foreign sigscript.
 *   3. Slice out each field's bytes.
 *   4. Decode numeric fields such as `int` and `bool`.
 *   5. Return the decoded value as this contract's `State`, or bind the
 *      requested destructured fields.
 *
 * Security notes:
 *   - This builtin is intentionally lightweight. It does not independently prove
 *     which redeem script inside the foreign sigscript is being decoded.
 *   - It is appropriate when the covenant domain guarantees a single allowed
 *     foreign contract/layout, so there is no ambiguity about what foreign state
 *     is being read.
 *   - Without that surrounding guarantee, you need extra checks tying the
 *     inspected sigscript bytes to the foreign input.
 */
function readInputState(int inputIndex) : (State);

/**
 * Role:
 *      Read another input using a foreign contract template and an explicitly
 *      chosen struct layout.
 *
 * Definition:
 *      Slice a claimed foreign redeem script out of the input sigscript, verify
 *      its template hash and P2SH commitment, and then decode the state bytes
 *      using the passed struct layout. The returned `object` is interpreted
 *      using the struct type implied by the assignment or destructuring target.
 *
 * Example:
 * ```js
 * Receipt receipt = readInputStateWithTemplate(2, receipt_prefix_len, receipt_suffix_len, receipt_hash);
 * require(receipt.amount == expected_amount);
 * ```
 *
 * Pseudo logic:
 *   1. Determine the encoded byte size of the struct layout you want to read.
 *   2. Use `templatePrefixLen`, that state size, and `templateSuffixLen` to
 *      slice a claimed redeem script out of the foreign input sigscript.
 *   3. Split the claimed redeem script into `claimed_prefix`, `claimed_state`, and `claimed_suffix`.
 *   4. Check that `blake2b(claimed_prefix || claimed_suffix)` matches `expectedTemplateHash`.
 *   5. Require the claimed redeem script to match the foreign input's actual
 *      P2SH `scriptPubKey`.
 *   6. Decode `claimed_state` using the passed struct layout and return the result.
 *
 * Security notes:
 *   - `expectedTemplateHash` should be trusted protocol data.
 *   - Also proves the claimed redeem script matches the foreign input's P2SH
 *     `scriptPubKey` before decoding.
 */
function readInputStateWithTemplate(
    int inputIndex,
    int templatePrefixLen,
    int templateSuffixLen,
    byte[32] expectedTemplateHash
) : (object);
