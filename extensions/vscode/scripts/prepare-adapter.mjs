import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function readFlag(flagName) {
  const index = process.argv.indexOf(flagName);
  if (index < 0) {
    return undefined;
  }
  return process.argv[index + 1];
}

function resolveCurrentTarget() {
  return `${process.platform}-${process.arch}`;
}

function resolveExecutableName(target) {
  return target.startsWith("win32-")
    ? "debugger-dap.exe"
    : "debugger-dap";
}

function absoluteFrom(base, value) {
  return path.isAbsolute(value) ? value : path.resolve(base, value);
}

const extensionRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(extensionRoot, "..", "..");
const vscodeTarget =
  readFlag("--target") ??
  process.env.SILVERSCRIPT_VSCODE_TARGET ??
  resolveCurrentTarget();
const cargoTarget =
  readFlag("--cargo-target") ??
  process.env.SILVERSCRIPT_CARGO_TARGET;
const explicitBinary =
  readFlag("--binary") ??
  process.env.SILVERSCRIPT_DEBUGGER_DAP_BIN;
const executableName = resolveExecutableName(vscodeTarget);

let builtBinary;
if (explicitBinary) {
  builtBinary = absoluteFrom(process.cwd(), explicitBinary);
} else {
  const args = ["build", "--release", "-p", "debugger-dap"];
  if (cargoTarget) {
    args.push("--target", cargoTarget);
  }

  const result = spawnSync("cargo", args, {
    cwd: repoRoot,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }

  const buildDir = cargoTarget
    ? path.join(repoRoot, "target", cargoTarget, "release")
    : path.join(repoRoot, "target", "release");
  builtBinary = path.join(buildDir, executableName);
}

if (!existsSync(builtBinary)) {
  throw new Error(`debugger-dap binary not found: ${builtBinary}`);
}

const destinationDir = path.join(extensionRoot, "bin", vscodeTarget);
const destinationBinary = path.join(destinationDir, executableName);
mkdirSync(destinationDir, { recursive: true });
copyFileSync(builtBinary, destinationBinary);

if (!vscodeTarget.startsWith("win32-")) {
  chmodSync(destinationBinary, 0o755);
}

console.log(
  `[bundle] copied ${builtBinary} -> ${destinationBinary}`,
);
