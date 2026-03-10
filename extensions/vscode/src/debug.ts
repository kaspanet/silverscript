import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import {
  defaultsObjectFromParams,
  type DebugArgInput,
  inferDebugParamsPath,
  parseContractModel,
  readDebugParams,
} from "./contractModel";
import { ensureDebuggerAdapterBinary } from "./debugAdapter";

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

async function ensureDebugParamsFile(
  scriptUri: vscode.Uri,
): Promise<{
  path: string;
  created: boolean;
}> {
  const scriptPath = scriptUri.fsPath;
  const paramsPath = inferDebugParamsPath(scriptPath);
  if (fs.existsSync(paramsPath)) {
    return { path: paramsPath, created: false };
  }

  const source = await fs.promises.readFile(scriptPath, "utf8");
  const model = parseContractModel(source);
  const functionName = model.entrypoints[0]?.name;
  const entrypoint = functionName
    ? model.entrypoints.find((item) => item.name === functionName)
    : undefined;
  const template = {
    function: functionName,
    constructorArgs: defaultsObjectFromParams(model.constructorParams),
    args: defaultsObjectFromParams(entrypoint?.params ?? []),
  };

  await fs.promises.writeFile(
    paramsPath,
    JSON.stringify(template, null, 2) + "\n",
    "utf8",
  );
  return { path: paramsPath, created: true };
}

async function openDebugParamsFile(
  scriptUri: vscode.Uri,
): Promise<void> {
  const result = await ensureDebugParamsFile(scriptUri);
  const doc = await vscode.workspace.openTextDocument(result.path);
  await vscode.window.showTextDocument(doc, {
    preview: false,
    preserveFocus: false,
    viewColumn: vscode.ViewColumn.Beside,
  });

  if (result.created) {
    void vscode.window.showInformationMessage(
      `Created ${path.basename(result.path)} for debug arguments.`,
    );
  }
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
    this.out.appendLine(`[debug] launching ${bin} [${source}]`);
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
    config: vscode.DebugConfiguration,
  ): Promise<void> {
    if (typeof config.scriptPath !== "string" || !config.scriptPath.trim()) {
      return;
    }

    const source = await fs.promises.readFile(config.scriptPath, "utf8");
    const model = parseContractModel(source);
    const paramsFile =
      typeof config.paramsFile === "string" && config.paramsFile.trim()
        ? config.paramsFile
        : undefined;
    const debugParams = await readDebugParams(
      config.scriptPath,
      paramsFile,
    );

    if (!config.function && debugParams?.function) {
      config.function = debugParams.function;
    }

    const hasCtorArgs = isDebugArgInput(config.constructorArgs);
    if (!hasCtorArgs && debugParams?.constructorArgs !== undefined) {
      config.constructorArgs = debugParams.constructorArgs;
    }
    if (!isDebugArgInput(config.constructorArgs)) {
      config.constructorArgs = defaultsObjectFromParams(
        model.constructorParams,
      );
    }

    if (!config.function && model.entrypoints.length > 0) {
      config.function = model.entrypoints[0].name;
    }

    const hasArgs = isDebugArgInput(config.args);
    if (!hasArgs && debugParams?.args !== undefined) {
      config.args = debugParams.args;
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

    for (const key of ["scriptPath", "paramsFile"] as const) {
      if (typeof config[key] === "string") {
        const expanded = expandActiveFileVariable(config[key] as string);
        if (expanded === undefined) {
          vscode.window.showErrorMessage(
            "No active file to resolve ${file}.",
          );
          return null;
        }
        config[key] = expanded;
      }
    }

    if (!config.scriptPath) {
      const active = resolveActiveScriptUri();
      if (active) {
        config.scriptPath = active.fsPath;
      }
    }

    try {
      await this.applyContractDefaults(config);
    } catch (error) {
      vscode.window.showErrorMessage(
        `SilverScript debug configuration failed: ${(error as Error).message}`,
      );
      return null;
    }

    config.noDebug ??= false;
    config.stopOnEntry ??= true;
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
        createDebugAdapterTracker: () => ({
          onWillStartSession: () =>
            out.appendLine("[debug] session starting"),
          onError: (error: Error) =>
            out.appendLine(`[debug] error: ${error}`),
          onExit: (
            code: number | undefined,
            signal: string | undefined,
          ) => {
            out.appendLine(
              `[debug] exit: code=${code}, signal=${signal}`,
            );
          },
        }),
      },
    ),
  );
  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.debug.openParamsFile",
      async (uri?: vscode.Uri) => {
        const scriptUri = resolveActiveScriptUri(uri);
        if (!scriptUri) {
          vscode.window.showErrorMessage(
            "Open a .sil file to edit SilverScript debug arguments.",
          );
          return;
        }

        try {
          await openDebugParamsFile(scriptUri);
        } catch (error) {
          vscode.window.showErrorMessage(
            `Failed to open debug params: ${(error as Error).message}`,
          );
        }
      },
    ),
  );
}
