#!/usr/bin/env node

import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const treeSitterDir = path.resolve(scriptDir, "..");
const repoRoot = path.resolve(treeSitterDir, "..");

const source = path.join(treeSitterDir, "queries", "highlights.scm");
const targets = [
  path.join(repoRoot, "extensions", "vscode", "queries", "highlights.scm"),
  path.join(
    repoRoot,
    "extensions",
    "zed",
    "languages",
    "silverscript",
    "highlights.scm",
  ),
  path.join(
    repoRoot,
    "extensions",
    "silverscript.nvim",
    "queries",
    "silverscript",
    "highlights.scm",
  ),
];

async function main() {
  for (const target of targets) {
    await mkdir(path.dirname(target), { recursive: true });
    await copyFile(source, target);
    const relativeTarget = path.relative(repoRoot, target);
    console.log(`synced ${relativeTarget}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
