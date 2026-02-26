#!/usr/bin/env node

import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const treeSitterDir = path.resolve(scriptDir, "..");
const repoRoot = path.resolve(treeSitterDir, "..");

const source = path.join(treeSitterDir, "tree-sitter-silverscript.wasm");
const target = path.join(
  repoRoot,
  "extensions",
  "vscode",
  "assets",
  "tree-sitter-silverscript.wasm",
);

async function main() {
  await mkdir(path.dirname(target), { recursive: true });
  await copyFile(source, target);
  const relativeTarget = path.relative(repoRoot, target);
  console.log(`synced ${relativeTarget}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
