import * as path from "path";
import * as vscode from "vscode";

export type RawLaunchConfiguration = vscode.DebugConfiguration & Record<string, unknown>;

export type SilverScriptLaunchConfigRecord = {
  id: string;
  folder: vscode.WorkspaceFolder;
  index: number;
  config: RawLaunchConfiguration;
  scriptPathValue: string;
  resolvedScriptPath: string;
};

export type SilverScriptSavedScenarioCounts = {
  total: number;
  byFunction: Record<string, number>;
};

function normalizePath(fsPath: string): string {
  const normalized = path.normalize(fsPath);
  return process.platform === "win32"
    ? normalized.toLowerCase()
    : normalized;
}

function expandPathVariables(
  raw: string,
  folder?: vscode.WorkspaceFolder,
  activeScriptUri?: vscode.Uri,
): string | undefined {
  let expanded = raw;

  if (folder) {
    expanded = expanded.replaceAll("${workspaceFolder}", folder.uri.fsPath);
    expanded = expanded.replaceAll(
      "${workspaceFolderBasename}",
      path.basename(folder.uri.fsPath),
    );
  }

  if (activeScriptUri?.fsPath) {
    expanded = expanded.replaceAll("${file}", activeScriptUri.fsPath);
  }

  if (expanded.includes("${")) {
    return undefined;
  }

  return expanded;
}

export function resolveLaunchScriptPath(
  raw: string,
  folder?: vscode.WorkspaceFolder,
  activeScriptUri?: vscode.Uri,
): string | undefined {
  const expanded = expandPathVariables(raw, folder, activeScriptUri);
  if (!expanded) {
    return undefined;
  }

  const candidate = path.isAbsolute(expanded)
    ? expanded
    : folder
      ? path.resolve(folder.uri.fsPath, expanded)
      : path.resolve(expanded);
  return path.normalize(candidate);
}

export function launchConfigMatchesScript(
  record: SilverScriptLaunchConfigRecord,
  scriptUri: vscode.Uri,
): boolean {
  return normalizePath(record.resolvedScriptPath) === normalizePath(scriptUri.fsPath);
}

export function defaultLaunchScriptPathValue(
  scriptUri: vscode.Uri,
  folder: vscode.WorkspaceFolder,
): string {
  const relative = path.relative(folder.uri.fsPath, scriptUri.fsPath);
  if (
    !relative ||
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
    return scriptUri.fsPath;
  }
  return relative;
}

function readFolderLaunchConfigurations(
  folder: vscode.WorkspaceFolder,
): RawLaunchConfiguration[] {
  return vscode.workspace
    .getConfiguration("launch", folder.uri)
    .get<RawLaunchConfiguration[]>("configurations", []);
}

async function writeFolderLaunchConfigurations(
  folder: vscode.WorkspaceFolder,
  configs: RawLaunchConfiguration[],
): Promise<void> {
  await vscode.workspace
    .getConfiguration("launch", folder.uri)
    .update(
      "configurations",
      configs,
      vscode.ConfigurationTarget.WorkspaceFolder,
    );
}

export function listSilverScriptLaunchConfigs(
  activeScriptUri?: vscode.Uri,
): SilverScriptLaunchConfigRecord[] {
  const folders = vscode.workspace.workspaceFolders ?? [];
  const records: SilverScriptLaunchConfigRecord[] = [];

  for (const folder of folders) {
    const configs = readFolderLaunchConfigurations(folder);
    configs.forEach((config, index) => {
      if (
        config.type !== "silverscript" ||
        config.request !== "launch" ||
        typeof config.scriptPath !== "string"
      ) {
        return;
      }

      const scriptPathValue = config.scriptPath.trim();
      if (!scriptPathValue) {
        return;
      }

      const resolvedScriptPath = resolveLaunchScriptPath(
        scriptPathValue,
        folder,
        activeScriptUri,
      );
      if (!resolvedScriptPath) {
        return;
      }

      records.push({
        id: `${folder.uri.toString()}::${index}`,
        folder,
        index,
        config,
        scriptPathValue,
        resolvedScriptPath,
      });
    });
  }

  return records;
}

export function listMatchingSilverScriptLaunchConfigs(
  scriptUri: vscode.Uri,
): SilverScriptLaunchConfigRecord[] {
  return listSilverScriptLaunchConfigs(scriptUri).filter((record) =>
    launchConfigMatchesScript(record, scriptUri),
  );
}

export function countSilverScriptSavedScenarios(
  scriptUri: vscode.Uri,
): SilverScriptSavedScenarioCounts {
  const records = listMatchingSilverScriptLaunchConfigs(scriptUri);
  const byFunction: Record<string, number> = {};

  for (const record of records) {
    const functionName =
      typeof record.config.function === "string"
        ? record.config.function.trim()
        : "";
    if (!functionName) {
      continue;
    }

    byFunction[functionName] = (byFunction[functionName] ?? 0) + 1;
  }

  return {
    total: records.length,
    byFunction,
  };
}

export async function updateSilverScriptLaunchConfig(
  record: SilverScriptLaunchConfigRecord,
  nextConfig: RawLaunchConfiguration,
): Promise<SilverScriptLaunchConfigRecord> {
  const configs = [...readFolderLaunchConfigurations(record.folder)];
  if (record.index >= configs.length) {
    throw new Error(`Launch config '${record.config.name ?? record.id}' no longer exists.`);
  }

  configs[record.index] = nextConfig;
  await writeFolderLaunchConfigurations(record.folder, configs);

  return {
    ...record,
    config: nextConfig,
    scriptPathValue:
      typeof nextConfig.scriptPath === "string"
        ? nextConfig.scriptPath
        : record.scriptPathValue,
    resolvedScriptPath: resolveLaunchScriptPath(
      String(nextConfig.scriptPath ?? record.scriptPathValue),
      record.folder,
    ) ?? record.resolvedScriptPath,
  };
}

export async function createSilverScriptLaunchConfig(
  folder: vscode.WorkspaceFolder,
  config: RawLaunchConfiguration,
): Promise<SilverScriptLaunchConfigRecord> {
  const configs = [...readFolderLaunchConfigurations(folder), config];
  const index = configs.length - 1;
  await writeFolderLaunchConfigurations(folder, configs);

  const scriptPathValue = String(config.scriptPath ?? "").trim();
  const resolvedScriptPath = resolveLaunchScriptPath(
    scriptPathValue,
    folder,
  );
  if (!resolvedScriptPath) {
    throw new Error(`Unable to resolve scriptPath '${scriptPathValue}'.`);
  }

  return {
    id: `${folder.uri.toString()}::${index}`,
    folder,
    index,
    config,
    scriptPathValue,
    resolvedScriptPath,
  };
}

export async function deleteSilverScriptLaunchConfig(
  record: SilverScriptLaunchConfigRecord,
): Promise<void> {
  const configs = [...readFolderLaunchConfigurations(record.folder)];
  if (record.index >= configs.length) {
    throw new Error(`Launch config '${record.config.name ?? record.id}' no longer exists.`);
  }

  configs.splice(record.index, 1);
  await writeFolderLaunchConfigurations(record.folder, configs);
}
