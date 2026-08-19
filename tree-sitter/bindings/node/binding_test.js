import assert from "node:assert";
import { test } from "node:test";
import Parser from "tree-sitter";

test("can load grammar", () => {
  const parser = new Parser();
  assert.doesNotReject(async () => {
    const { default: language } = await import("./index.js");
    parser.setLanguage(language);
  });
});

test("distinguishes indexed and unindexed introspection", async () => {
  const parser = new Parser();
  const { default: language } = await import("./index.js");
  parser.setLanguage(language);

  const tree = parser.parse(`
    contract Introspection() {
      entry main(int index) {
        int inputCount = tx.inputs.length;
        int outputValue = tx.outputs[index].value;
        byte[32] outpointTxId = tx.inputs[index].outpointTxId;
        byte[8] sequence = OpTxInputSeq(index);
        require(inputCount > 0 && outputValue >= 0);
      }
    }
  `);
  const syntaxTree = tree.rootNode.toString();

  assert.match(syntaxTree, /\(introspection\b/);
  assert.match(syntaxTree, /\(indexed_introspection\b/);
  assert.doesNotMatch(syntaxTree, /nullary/);
});

test("parses temporal values and lock domains", async () => {
  const parser = new Parser();
  const { default: language } = await import("./index.js");
  parser.setLanguage(language);

  const tree = parser.parse(`
    contract Locks(temporal unlockAt, int daaAge) {
      entry absolute() {
        require(tx.time >= unlockAt);
      }
      entry absoluteDaa() {
        require(tx.daa >= daaAge);
      }
      entry relative() {
        require(this.ageDaa >= daaAge);
      }
    }
  `);

  assert.equal(tree.rootNode.hasError, false);
  assert.match(tree.rootNode.toString(), /\(base_type\)/);
  assert.match(tree.rootNode.toString(), /\(tx_var\)/);
});
