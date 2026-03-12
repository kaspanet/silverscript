import * as fs from "fs";
import * as vscode from "vscode";
import {
  defaultsObjectFromParams,
  type DebugArgInput,
  parseContractModel,
} from "./contractModel";
import {
  debuggerTraceEnabled,
  ensureDebuggerAdapterBinary,
} from "./debugAdapter";
import { resolveLaunchScriptPath } from "./launchConfigs";

function isDebugArgInput(value: unknown): value is DebugArgInput {
  return (
    Array.isArray(value) ||
    (value !== null && typeof value === "object")
  );
}

function resolveActiveScriptUri(uri?: vscode.Uri): vscode.Uri | undefined {
  if (uri) {
    return uri;
  }
  const activeDoc = vscode.window.activeTextEditor?.document;
  if (activeDoc?.languageId === "silverscript") {
    return activeDoc.uri;
  }
  return undefined;
}

function expandActiveFileVariable(raw: string): string | undefined {
  if (!raw.includes("${file}")) {
    return raw;
  }
  const active = resolveActiveScriptUri();
  return active?.fsPath
    ? raw.replaceAll("${file}", active.fsPath)
    : undefined;
}

function ensureTrustedWorkspace(feature: string): boolean {
  if (vscode.workspace.isTrusted) {
    return true;
  }

  void vscode.window.showWarningMessage(
    `SilverScript ${feature} requires a trusted workspace.`,
  );
  return false;
}

function resolveConfigScriptPath(
  raw: string,
  folder: vscode.WorkspaceFolder | undefined,
): string | undefined {
  return resolveLaunchScriptPath(
    raw,
    folder,
    resolveActiveScriptUri(),
  );
}

function isBenignAdapterShutdownError(
  error: Error,
  exitCode: number | undefined,
): boolean {
  const isReadError = error.message.trim().toLowerCase() === "read error";
  return isReadError && (exitCode === 0 || !debuggerTraceEnabled());
}

class SilverScriptDebugAdapterFactory
  implements vscode.DebugAdapterDescriptorFactory
{
  constructor(
    private readonly ctx: vscode.ExtensionContext,
    private readonly out: vscode.OutputChannel,
  ) {}

  async createDebugAdapterDescriptor(): Promise<vscode.DebugAdapterDescriptor> {
    if (!ensureTrustedWorkspace("debugging")) {
      throw new Error("SilverScript debugging requires a trusted workspace.");
    }

    const { root, bin, source } = await ensureDebuggerAdapterBinary(
      this.ctx,
      this.out,
    );
    if (debuggerTraceEnabled()) {
      this.out.appendLine(`[debug] launching ${bin} [${source}]`);
    }
    return new vscode.DebugAdapterExecutable(bin, [], {
      cwd: root,
    });
  }
}

class SilverScriptConfigProvider
  implements vscode.DebugConfigurationProvider
{
  private makeDefaultLaunchConfig():
    | vscode.DebugConfiguration
    | undefined {
    const scriptUri = resolveActiveScriptUri();
    if (!scriptUri) {
      return undefined;
    }
    return {
      type: "silverscript",
      request: "launch",
      name: "SilverScript: Debug Contract",
      scriptPath: scriptUri.fsPath,
      stopOnEntry: true,
    };
  }

  private async applyContractDefaults(
    folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
  ): Promise<void> {
    if (typeof config.scriptPath !== "string" || !config.scriptPath.trim()) {
      return;
    }

    const resolvedScriptPath = resolveConfigScriptPath(
      config.scriptPath,
      folder,
    );
    if (!resolvedScriptPath) {
      throw new Error(`Unable to resolve scriptPath '${config.scriptPath}'.`);
    }

    config.scriptPath = resolvedScriptPath;
    const source = await fs.promises.readFile(config.scriptPath, "utf8");
    const model = parseContractModel(source);

    if (!isDebugArgInput(config.constructorArgs)) {
      config.constructorArgs = defaultsObjectFromParams(
        model.constructorParams,
      );
    }

    if (!config.function && model.entrypoints.length > 0) {
      config.function = model.entrypoints[0].name;
    }

    if (!isDebugArgInput(config.args) && config.function) {
      const entrypoint = model.entrypoints.find(
        (item) => item.name === config.function,
      );
      if (entrypoint) {
        config.args = defaultsObjectFromParams(
          entrypoint.params,
        );
      }
    }
  }
  async resolveDebugConfiguration(
    _folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
  ): Promise<vscode.DebugConfiguration | null | undefined> {
    if (!ensureTrustedWorkspace("debugging")) {
      return null;
    }

    if (!config.type && !config.request) {
      const defaultConfig = this.makeDefaultLaunchConfig();
      if (!defaultConfig) {
        return undefined;
      }
      config = defaultConfig;
    }

    if (
      config.type !== "silverscript" ||
      config.request !== "launch"
    ) {
      return config;
    }

    if (typeof config.scriptPath === "string") {
      const expanded = expandActiveFileVariable(config.scriptPath);
      if (expanded === undefined) {
        vscode.window.showErrorMessage(
          "No active file to resolve ${file}.",
        );
        return null;
      }
      config.scriptPath = expanded;
    }

    if (!config.scriptPath) {
      const active = resolveActiveScriptUri();
      if (active) {
        config.scriptPath = active.fsPath;
      }
    }

    try {
      await this.applyContractDefaults(_folder, config);
    } catch (error) {
      vscode.window.showErrorMessage(
        `SilverScript debug configuration failed: ${(error as Error).message}`,
      );
      return null;
    }

    config.noDebug ??= false;
    config.stopOnEntry ??= !config.noDebug;
    return config;
  }
}

export function registerSilverScriptDebugger(
  ctx: vscode.ExtensionContext,
  out: vscode.OutputChannel,
): void {
  const configProvider = new SilverScriptConfigProvider();

  ctx.subscriptions.push(
    vscode.debug.registerDebugAdapterDescriptorFactory(
      "silverscript",
      new SilverScriptDebugAdapterFactory(ctx, out),
    ),
  );
  ctx.subscriptions.push(
    vscode.debug.registerDebugConfigurationProvider(
      "silverscript",
      configProvider,
    ),
  );
  ctx.subscriptions.push(
    vscode.debug.registerDebugAdapterTrackerFactory(
      "silverscript",
      {
        createDebugAdapterTracker: () => {
          let exitCode: number | undefined;

          return {
            onWillStartSession: () => {
              if (debuggerTraceEnabled()) {
                out.appendLine("[debug] session starting");
              }
            },
            onError: (error: Error) => {
              if (isBenignAdapterShutdownError(error, exitCode)) {
                return;
              }
              out.appendLine(`[debug] error: ${error}`);
            },
            onExit: (
              code: number | undefined,
              signal: string | undefined,
            ) => {
              exitCode = code;
              if (code === 0 && !signal && !debuggerTraceEnabled()) {
                return;
              }
              out.appendLine(
                `[debug] exit: code=${code}, signal=${signal}`,
              );
            },
          };
        },
      },
    ),
  );
}
