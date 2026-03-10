import * as childProcess from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";

const autoBuildAttempted = new Set<string>();
const ADAPTER_BASENAME =
  process.platform === "win32" ? "debugger-dap.exe" : "debugger-dap";

function findWorkspaceRoot(): string | undefined {
  const activeUri = vscode.window.activeTextEditor?.document.uri;
  if (activeUri) {
    const folder = vscode.workspace.getWorkspaceFolder(activeUri);
    if (folder) {
      return folder.uri.fsPath;
    }
  }
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function hasDebuggerWorkspaceLayout(root: string): boolean {
  return (
    fs.existsSync(path.join(root, "Cargo.toml")) &&
    fs.existsSync(path.join(root, "debugger", "dap", "Cargo.toml"))
  );
}

function currentPlatformTarget(): string {
  return `${process.platform}-${process.arch}`;
}

function findExistingFile(candidates: string[]): string | undefined {
  return candidates.find((candidate) => fs.existsSync(candidate));
}

function workspaceBinaryCandidates(root: string): string[] {
  return ["release", "debug"].map((profile) =>
    path.join(root, "target", profile, ADAPTER_BASENAME),
  );
}

function bundledBinaryCandidates(
  ctx: vscode.ExtensionContext,
): string[] {
  return [
    path.join(
      ctx.extensionPath,
      "bin",
      currentPlatformTarget(),
      ADAPTER_BASENAME,
    ),
  ];
}

function expandUserPath(raw: string): string {
  if (raw === "~") {
    return os.homedir();
  }
  if (raw.startsWith("~/") || raw.startsWith("~\\")) {
    return path.join(os.homedir(), raw.slice(2));
  }
  return raw;
}

function configuredAdapterCandidates(
  ctx: vscode.ExtensionContext,
): string[] {
  const configured = vscode.workspace
    .getConfiguration("silverscript")
    .get<string>("debugAdapterPath", "")
    .trim();

  if (!configured) {
    return [];
  }

  const raw = expandUserPath(configured);
  if (path.isAbsolute(raw)) {
    return [raw];
  }

  const workspaceRoot = findWorkspaceRoot();
  const candidates = [
    workspaceRoot ? path.resolve(workspaceRoot, raw) : undefined,
    path.resolve(ctx.extensionPath, raw),
  ].filter((candidate): candidate is string => Boolean(candidate));

  return [...new Set(candidates)];
}

export function resolveRepoRoot(
  ctx: vscode.ExtensionContext,
): string {
  const candidates: string[] = [];
  const workspaceRoot = findWorkspaceRoot();
  if (workspaceRoot) {
    candidates.push(workspaceRoot);
  }
  candidates.push(path.resolve(ctx.extensionPath, "..", ".."));

  for (const candidate of candidates) {
    if (hasDebuggerWorkspaceLayout(candidate)) {
      return candidate;
    }
  }

  return candidates[0] ?? path.resolve(ctx.extensionPath, "..", "..");
}

export function summarizeCommandFailure(
  command: string,
  args: string[],
  result: {
    stdout?: string;
    stderr?: string;
    error?: Error;
    status?: number | null;
  },
): string {
  const cmd = [command, ...args].join(" ");
  const stdout = (result.stdout ?? "").trim();
  const stderr = (result.stderr ?? "").trim();
  const details = [stderr, stdout].filter(Boolean).slice(0, 2).join(" | ");

  if (result.error) {
    return `${cmd} failed: ${result.error.message}`;
  }
  if (result.status !== 0) {
    return `${cmd} exited with code ${result.status}${details ? `: ${details}` : ""}`;
  }
  return `${cmd} failed`;
}

async function spawnCommand(
  command: string,
  args: string[],
  cwd: string,
): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(command, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({ stdout, stderr, status });
    });
  });
}

export async function ensureDebuggerAdapterBinary(
  ctx: vscode.ExtensionContext,
  out?: vscode.OutputChannel,
): Promise<{ root: string; bin: string; source: string }> {
  const root = resolveRepoRoot(ctx);

  const configuredCandidates = configuredAdapterCandidates(ctx);
  if (configuredCandidates.length > 0) {
    const configured = findExistingFile(configuredCandidates);
    if (!configured) {
      throw new Error(
        `Configured debug adapter path not found. Checked: ${configuredCandidates.join(", ")}`,
      );
    }
    return {
      root: path.dirname(configured),
      bin: configured,
      source: "configured",
    };
  }

  const bundled = findExistingFile(bundledBinaryCandidates(ctx));
  if (bundled) {
    return {
      root: path.dirname(bundled),
      bin: bundled,
      source: "bundled",
    };
  }

  const hasWorkspaceLayout = hasDebuggerWorkspaceLayout(root);
  const existingWorkspaceBinary = hasWorkspaceLayout
    ? findExistingFile(workspaceBinaryCandidates(root))
    : undefined;
  if (existingWorkspaceBinary) {
    return {
      root,
      bin: existingWorkspaceBinary,
      source: "workspace",
    };
  }

  const allowAutoBuild = vscode.workspace
    .getConfiguration("silverscript")
    .get<boolean>("autoBuildDebuggerAdapter", true);

  if (
    hasWorkspaceLayout &&
    allowAutoBuild &&
    !autoBuildAttempted.has(root)
  ) {
    autoBuildAttempted.add(root);
    const cmd = "cargo";
    const args = ["build", "-p", "debugger-dap"];
    const result = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Building SilverScript debugger adapter",
      cancellable: false,
    }, async (progress) => {
      progress.report({
        message: `${cmd} ${args.join(" ")}`,
      });
      out?.appendLine(
        `[debug] adapter missing, running: ${cmd} ${args.join(" ")} (cwd=${root})`,
      );
      return spawnCommand(cmd, args, root);
    });
    if (result.stdout) {
      out?.appendLine(result.stdout);
    }
    if (result.stderr) {
      out?.appendLine(result.stderr);
    }
    if (result.status !== 0) {
      throw new Error(summarizeCommandFailure(cmd, args, result));
    }
  }

  const builtWorkspaceBinary = hasWorkspaceLayout
    ? findExistingFile(workspaceBinaryCandidates(root))
    : undefined;
  if (builtWorkspaceBinary) {
    return {
      root,
      bin: builtWorkspaceBinary,
      source: autoBuildAttempted.has(root) ? "workspace-built" : "workspace",
    };
  }

  const target = currentPlatformTarget();
  const installMessage =
    `No bundled SilverScript debug adapter was found for ${target}. ` +
    "Package a platform-specific VSIX that includes bin/<platform-arch>/debugger-dap, " +
    "or set `silverscript.debugAdapterPath` to a compatible binary.";

  if (!hasWorkspaceLayout) {
    throw new Error(installMessage);
  }

  if (!allowAutoBuild) {
    throw new Error(
      `${installMessage} Auto-build is disabled, so build it manually with: cargo build -p debugger-dap`,
    );
  }

  throw new Error(
    `${installMessage} Development fallback also failed. Run: cargo build -p debugger-dap`,
  );
}

export async function runDebuggerAdapterCommand(
  ctx: vscode.ExtensionContext,
  args: string[],
  out?: vscode.OutputChannel,
): Promise<string> {
  const { root, bin, source } = await ensureDebuggerAdapterBinary(
    ctx,
    out,
  );
  out?.appendLine(`[debug] running ${bin} ${args.join(" ")} [${source}]`);

  const result = await spawnCommand(bin, args, root);
  if (result.stdout) {
    out?.appendLine(result.stdout);
  }
  if (result.stderr) {
    out?.appendLine(result.stderr);
  }
  if (result.status !== 0) {
    throw new Error(summarizeCommandFailure(bin, args, result));
  }
  return (result.stdout ?? "").trim();
}
