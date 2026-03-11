import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import {
  defaultForType,
  type DebugArgInput,
  type DebugArgObject,
  parseContractModel,
  type ContractModel,
  type ContractParam,
} from "./contractModel";
import { runDebuggerAdapterCommand } from "./debugAdapter";
import {
  countSilverScriptSavedScenarios,
  createSilverScriptLaunchConfig,
  defaultLaunchScriptPathValue,
  listMatchingSilverScriptLaunchConfigs,
  type RawLaunchConfiguration,
  type SilverScriptLaunchConfigRecord,
  updateSilverScriptLaunchConfig,
} from "./launchConfigs";

type LaunchKind = "run" | "debug";
type IdentityLabels = Record<string, string>;

type PanelFormState = {
  function: string;
  constructorArgs: Record<string, string>;
  argsByFunction: Record<string, Record<string, string>>;
  keyAliases: string[];
  identityLabels: IdentityLabels;
};

type PanelHostState = {
  scriptUri: vscode.Uri;
  model: ContractModel;
  form: PanelFormState;
  baseConfig: RawLaunchConfiguration;
  record?: SilverScriptLaunchConfigRecord;
  loadedConfigName: string | null;
};

type PanelMessage =
  | { kind: "run"; form: PanelFormState }
  | { kind: "debug"; form: PanelFormState }
  | { kind: "loadSaved"; form: PanelFormState }
  | { kind: "saveSaved"; form: PanelFormState };

type PanelControlMessage = {
  kind: "triggerLaunch";
  launchKind: LaunchKind;
};

type WebviewState = {
  function: string;
  constructorArgs: Record<string, string>;
  argsByFunction: Record<string, Record<string, string>>;
  keyAliases: string[];
  identityLabels: IdentityLabels;
  loadedConfigName: string | null;
  savedCountsByFunction: Record<string, number>;
  savedTotalCount: number;
};

const RUN_SUCCESS_MESSAGE = "Execution completed successfully.";

let panel: vscode.WebviewPanel | undefined;
let activeState: PanelHostState | undefined;
let launchInProgress = false;
let restoringPrimaryEditor = false;
const panelStateEmitter = new vscode.EventEmitter<void>();
const IDENTITY_ALIAS_RE =
  /^(?:keypair|identity)([1-9]\d*)(?:\.(pubkey|secret|pkh))?$/;

function emitPanelStateChanged(): void {
  panelStateEmitter.fire();
}

export const onDidChangeSilverScriptPanelState =
  panelStateEmitter.event;

function isDebugArgInput(value: unknown): value is DebugArgInput {
  return (
    Array.isArray(value) ||
    (value !== null && typeof value === "object")
  );
}

function activeSilverScriptSession(): vscode.DebugSession | undefined {
  const session = vscode.debug.activeDebugSession;
  return session?.type === "silverscript" ? session : undefined;
}

export function hasOpenSilverScriptPanelForUri(
  uri?: vscode.Uri,
): boolean {
  if (!panel || !activeState || !uri) {
    return false;
  }

  return activeState.scriptUri.fsPath === uri.fsPath;
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

function ensureTrustedWorkspace(): boolean {
  if (vscode.workspace.isTrusted) {
    return true;
  }

  void vscode.window.showWarningMessage(
    "SilverScript run/debug requires a trusted workspace.",
  );
  return false;
}

function getNonce(): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let value = "";
  for (let index = 0; index < 32; index += 1) {
    value += alphabet.charAt(
      Math.floor(Math.random() * alphabet.length),
    );
  }
  return value;
}

function stringifyForInlineScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function stringifyLaunchArg(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (
    Array.isArray(value) ||
    (value !== null && typeof value === "object")
  ) {
    return JSON.stringify(value);
  }
  return String(value);
}

function defaultsForParams(
  params: ContractParam[],
): Record<string, string> {
  return Object.fromEntries(
    params.map((param) => [
      param.name,
      stringifyLaunchArg(defaultForType(param.type)),
    ]),
  );
}

function valuesForParams(
  params: ContractParam[],
  input: DebugArgInput | undefined,
): Record<string, string> {
  const defaults = defaultsForParams(params);
  if (Array.isArray(input)) {
    for (const [index, param] of params.entries()) {
      if (index < input.length) {
        defaults[param.name] = stringifyLaunchArg(input[index]);
      }
    }
    return defaults;
  }
  if (input && typeof input === "object") {
    for (const param of params) {
      if (Object.prototype.hasOwnProperty.call(input, param.name)) {
        defaults[param.name] = stringifyLaunchArg(input[param.name]);
      }
    }
  }
  return defaults;
}

function defaultLaunchName(
  model: ContractModel,
  scriptPath: string,
): string {
  return model.name && model.name !== "Unknown"
    ? `SilverScript: ${model.name}`
    : `SilverScript: ${path.basename(scriptPath)}`;
}

function normalizeKeyAliases(
  aliases: readonly string[],
  constructorArgs: Record<string, string>,
  argsByFunction: Record<string, Record<string, string>>,
): string[] {
  const found = new Map<number, string>();

  const consider = (raw: string | undefined) => {
    if (!raw) {
      return;
    }
    const match = IDENTITY_ALIAS_RE.exec(raw.trim());
    if (!match) {
      return;
    }
    const index = Number(match[1]);
    if (!found.has(index)) {
      found.set(index, `keypair${index}`);
    }
  };

  aliases.forEach(consider);
  Object.values(constructorArgs).forEach((value) => consider(value));
  Object.values(argsByFunction).forEach((args) => {
    Object.values(args).forEach((value) => consider(value));
  });

  const normalized = [...found.entries()]
    .sort((left, right) => left[0] - right[0])
    .map(([, alias]) => alias);
  return normalized;
}

function normalizeIdentityLabels(
  aliases: readonly string[],
  labels: IdentityLabels,
): IdentityLabels {
  const normalized: IdentityLabels = {};
  for (const alias of aliases) {
    const label = labels[alias]?.trim();
    if (label && label !== alias) {
      normalized[alias] = label;
    }
  }
  return normalized;
}

async function focusPrimaryEditor(
  scriptUri: vscode.Uri,
): Promise<void> {
  if (restoringPrimaryEditor) {
    return;
  }

  restoringPrimaryEditor = true;
  try {
    const document = await vscode.workspace.openTextDocument(scriptUri);
    await vscode.window.showTextDocument(document, {
      viewColumn: vscode.ViewColumn.One,
      preview: false,
      preserveFocus: false,
    });
  } finally {
    restoringPrimaryEditor = false;
  }
}

async function keepSilverScriptEditorOnPrimary(
  editor: vscode.TextEditor | undefined,
): Promise<void> {
  if (
    restoringPrimaryEditor ||
    !panel ||
    !editor ||
    editor.document.languageId !== "silverscript" ||
    editor.viewColumn === vscode.ViewColumn.One ||
    panel.viewColumn === undefined ||
    editor.viewColumn !== panel.viewColumn
  ) {
    return;
  }

  await focusPrimaryEditor(editor.document.uri);
  if (panel) {
    panel.reveal(vscode.ViewColumn.Beside, true);
  }
}

async function followActiveSilverScript(
  editor: vscode.TextEditor | undefined,
): Promise<void> {
  if (
    !panel ||
    !editor ||
    editor.document.languageId !== "silverscript" ||
    !activeState ||
    activeState.scriptUri.fsPath === editor.document.uri.fsPath
  ) {
    return;
  }

  activeState = await buildInitialState(editor.document.uri);
  emitPanelStateChanged();
  await renderActiveState();
}

async function handleActiveEditorChange(
  editor: vscode.TextEditor | undefined,
): Promise<void> {
  await keepSilverScriptEditorOnPrimary(editor);
  await followActiveSilverScript(editor);
}

function defaultPanelFormState(
  model: ContractModel,
  initialFunction?: string,
): PanelFormState {
  const selectedFunction =
    initialFunction &&
    model.entrypoints.some((entry) => entry.name === initialFunction)
      ? initialFunction
      : model.entrypoints[0]?.name ?? "";

  const argsByFunction: Record<string, Record<string, string>> = {};
  for (const entrypoint of model.entrypoints) {
    argsByFunction[entrypoint.name] = defaultsForParams(
      entrypoint.params,
    );
  }

  return {
    function: selectedFunction,
    constructorArgs: defaultsForParams(model.constructorParams),
    argsByFunction,
    keyAliases: normalizeKeyAliases(
      [],
      defaultsForParams(model.constructorParams),
      argsByFunction,
    ),
    identityLabels: {},
  };
}

function formFromLaunchConfig(
  model: ContractModel,
  config: RawLaunchConfiguration,
  initialFunction: string | undefined,
  keyAliases: string[],
  identityLabels: IdentityLabels,
): PanelFormState {
  const configuredFunction =
    typeof config.function === "string" ? config.function : undefined;
  const selectedFunction =
    initialFunction &&
    model.entrypoints.some((entry) => entry.name === initialFunction)
      ? initialFunction
      : configuredFunction &&
          model.entrypoints.some(
            (entry) => entry.name === configuredFunction,
          )
        ? configuredFunction
        : model.entrypoints[0]?.name ?? "";

  const constructorArgs = isDebugArgInput(config.constructorArgs)
    ? config.constructorArgs
    : undefined;
  const configuredArgs =
    configuredFunction === selectedFunction &&
    isDebugArgInput(config.args)
      ? config.args
      : undefined;

  const argsByFunction: Record<string, Record<string, string>> = {};
  for (const entrypoint of model.entrypoints) {
    argsByFunction[entrypoint.name] = valuesForParams(
      entrypoint.params,
      entrypoint.name === selectedFunction ? configuredArgs : undefined,
    );
  }

  const constructorValues = valuesForParams(
    model.constructorParams,
    constructorArgs,
  );
  const normalizedAliases = normalizeKeyAliases(
    keyAliases,
    constructorValues,
    argsByFunction,
  );
  const form = {
    function: selectedFunction,
    constructorArgs: constructorValues,
    argsByFunction,
    keyAliases: normalizedAliases,
    identityLabels: normalizeIdentityLabels(
      normalizedAliases,
      identityLabels,
    ),
  };
  return form;
}

function currentArgs(
  form: PanelFormState,
): DebugArgObject {
  return { ...(form.argsByFunction[form.function] ?? {}) };
}

function applyMessageState(
  state: PanelHostState,
  form: PanelFormState,
): void {
  const normalizedAliases = normalizeKeyAliases(
    form.keyAliases,
    form.constructorArgs,
    form.argsByFunction,
  );
  state.form = {
    function: form.function,
    constructorArgs: { ...form.constructorArgs },
    argsByFunction: Object.fromEntries(
      Object.entries(form.argsByFunction).map(
        ([entrypoint, args]) => [entrypoint, { ...args }],
      ),
    ),
    keyAliases: normalizedAliases,
    identityLabels: normalizeIdentityLabels(
      normalizedAliases,
      form.identityLabels,
    ),
  };
}

function matchingLaunchConfigs(
  scriptUri: vscode.Uri,
): SilverScriptLaunchConfigRecord[] {
  return listMatchingSilverScriptLaunchConfigs(scriptUri);
}

async function readModel(
  scriptUri: vscode.Uri,
): Promise<ContractModel> {
  const source = await fs.promises.readFile(scriptUri.fsPath, "utf8");
  return parseContractModel(source);
}

async function buildInitialState(
  scriptUri: vscode.Uri,
  initialFunction?: string,
  keyAliases: string[] = [],
  identityLabels: IdentityLabels = {},
): Promise<PanelHostState> {
  const model = await readModel(scriptUri);
  const record = matchingLaunchConfigs(scriptUri)[0];

  if (record) {
    return {
      scriptUri,
      model,
      form: formFromLaunchConfig(
        model,
        record.config,
        initialFunction,
        keyAliases,
        identityLabels,
      ),
      baseConfig: { ...record.config },
      record,
      loadedConfigName:
        typeof record.config.name === "string"
          ? record.config.name
          : null,
    };
  }

  return {
    scriptUri,
    model,
    form: defaultPanelFormState(model, initialFunction),
    baseConfig: {
      type: "silverscript",
      request: "launch",
      name: defaultLaunchName(model, scriptUri.fsPath),
      stopOnEntry: true,
    },
    loadedConfigName: null,
  };
}

function launchConfigForPanel(
  state: PanelHostState,
  noDebug: boolean,
): RawLaunchConfiguration {
  return {
    ...state.baseConfig,
    type: "silverscript",
    request: "launch",
    name:
      typeof state.baseConfig.name === "string" &&
      state.baseConfig.name.trim()
        ? state.baseConfig.name
        : defaultLaunchName(state.model, state.scriptUri.fsPath),
    scriptPath: state.scriptUri.fsPath,
    function: state.form.function,
    constructorArgs: { ...state.form.constructorArgs },
    args: currentArgs(state.form),
    noDebug,
    stopOnEntry: !noDebug,
  };
}

function savedLaunchConfigForPanel(
  state: PanelHostState,
  name: string,
): RawLaunchConfiguration {
  const folder = vscode.workspace.getWorkspaceFolder(state.scriptUri);
  if (!folder) {
    throw new Error(
      "SilverScript launch configs require the script to be inside a workspace folder.",
    );
  }

  const config: RawLaunchConfiguration = {
    ...state.baseConfig,
    type: "silverscript",
    request: "launch",
    name,
    scriptPath: defaultLaunchScriptPathValue(state.scriptUri, folder),
    function: state.form.function,
    constructorArgs: { ...state.form.constructorArgs },
    args: currentArgs(state.form),
  };
  delete config.paramsFile;
  delete config.noDebug;
  return config;
}

async function loadSavedScenario(
  keyAliases: string[],
  identityLabels: IdentityLabels,
  functionName?: string,
  suppressEmptyMessage = false,
): Promise<void> {
  if (!activeState) {
    return;
  }

  const records = matchingLaunchConfigs(activeState.scriptUri).filter(
    (record) => {
      if (!functionName) {
        return true;
      }
      return record.config.function === functionName;
    },
  );
  if (records.length === 0) {
    if (!suppressEmptyMessage) {
      void vscode.window.showInformationMessage(
        functionName
          ? `No saved SilverScript launch configs were found for '${functionName}'.`
          : "No saved SilverScript launch configs were found for this file.",
      );
    }
    return;
  }

  const picked = await vscode.window.showQuickPick(
    functionName
      ? records.map((record) => ({
          label:
            typeof record.config.name === "string"
              ? record.config.name
              : path.basename(record.resolvedScriptPath),
          description: record.scriptPathValue,
          record,
        }))
      : (() => {
          const groups = new Map<string, SilverScriptLaunchConfigRecord[]>();
          for (const record of records) {
            const group =
              typeof record.config.function === "string" &&
              record.config.function.trim()
                ? record.config.function.trim()
                : "Other";
            const existing = groups.get(group) ?? [];
            existing.push(record);
            groups.set(group, existing);
          }

          const orderedGroups: string[] = [];
          for (const entrypoint of activeState.model.entrypoints) {
            if (groups.has(entrypoint.name)) {
              orderedGroups.push(entrypoint.name);
            }
          }
          for (const group of [...groups.keys()].sort()) {
            if (!orderedGroups.includes(group)) {
              orderedGroups.push(group);
            }
          }

          return orderedGroups.flatMap((group) => {
            const groupRecords = groups.get(group) ?? [];
            return [
              {
                kind: vscode.QuickPickItemKind.Separator,
                label: group,
              },
              ...groupRecords.map((record) => ({
                label:
                  typeof record.config.name === "string"
                    ? record.config.name
                    : path.basename(record.resolvedScriptPath),
                description: record.scriptPathValue,
                record,
              })),
            ];
          });
        })(),
    {
      title: functionName
        ? `Load Saved Scenario for '${functionName}'`
        : "Load SilverScript Launch Config",
      placeHolder: functionName
        ? `Select a saved launch config for '${functionName}'`
        : "Select a saved launch config for this contract, grouped by entrypoint",
    },
  );

  if (!picked || !("record" in picked) || !picked.record) {
    return;
  }

  const model = await readModel(activeState.scriptUri);
  activeState = {
    scriptUri: activeState.scriptUri,
    model,
    form: formFromLaunchConfig(
      model,
      picked.record.config,
      undefined,
      keyAliases,
      identityLabels,
    ),
    baseConfig: { ...picked.record.config },
    record: picked.record,
    loadedConfigName:
      typeof picked.record.config.name === "string"
        ? picked.record.config.name
        : null,
  };
  await renderActiveState();
}

function selectEntrypoint(
  state: PanelHostState,
  initialFunction?: string,
): void {
  if (!initialFunction) {
    return;
  }

  const entrypoint = state.model.entrypoints.find(
    (item) => item.name === initialFunction,
  );
  if (!entrypoint) {
    return;
  }

  state.form.function = initialFunction;
  if (!state.form.argsByFunction[initialFunction]) {
    state.form.argsByFunction[initialFunction] = defaultsForParams(
      entrypoint.params,
    );
  }
}

async function saveScenario(): Promise<void> {
  if (!activeState) {
    return;
  }

  const folder = vscode.workspace.getWorkspaceFolder(activeState.scriptUri);
  if (!folder) {
    void vscode.window.showErrorMessage(
      "SilverScript launch configs require the script to be inside a workspace folder.",
    );
    return;
  }

  if (activeState.record) {
    const name =
      typeof activeState.baseConfig.name === "string" &&
      activeState.baseConfig.name.trim()
        ? activeState.baseConfig.name
        : defaultLaunchName(
            activeState.model,
            activeState.scriptUri.fsPath,
          );
    const config = savedLaunchConfigForPanel(activeState, name);
    const updated = await updateSilverScriptLaunchConfig(
      activeState.record,
      config,
    );
    activeState.baseConfig = config;
    activeState.record = updated;
    activeState.loadedConfigName = name;
    await renderActiveState();
    void vscode.window.showInformationMessage(
      `Updated '${name}' in launch.json.`,
    );
    return;
  }

  const name = await vscode.window.showInputBox({
    title: "Save SilverScript Launch Config",
    prompt: "Name for this saved debugger scenario",
    value: defaultLaunchName(
      activeState.model,
      activeState.scriptUri.fsPath,
    ),
    ignoreFocusOut: true,
    validateInput: (value) =>
      value.trim() ? null : "Name is required.",
  });

  if (!name) {
    return;
  }

  const config = savedLaunchConfigForPanel(activeState, name.trim());
  const record = await createSilverScriptLaunchConfig(folder, config);
  activeState.baseConfig = config;
  activeState.record = record;
  activeState.loadedConfigName = name.trim();
  await renderActiveState();
  void vscode.window.showInformationMessage(
    `Saved '${name.trim()}' to launch.json.`,
  );
}

async function launchFromPanel(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
  kind: LaunchKind,
): Promise<void> {
  if (!activeState) {
    return;
  }

  if (launchInProgress) {
    void vscode.window.showWarningMessage(
      "A SilverScript run/debug launch is already in progress.",
    );
    return;
  }

  const existingSession = activeSilverScriptSession();
  if (existingSession) {
    await vscode.commands.executeCommand(
      "workbench.action.debug.continue",
    );
    return;
  }

  try {
    launchInProgress = true;
    const config = launchConfigForPanel(activeState, kind === "run");
    const folder =
      vscode.workspace.getWorkspaceFolder(activeState.scriptUri) ??
      vscode.workspace.workspaceFolders?.[0];

    if (kind === "run") {
      const output = await runDebuggerAdapterCommand(
        context,
        ["--run-config-json", JSON.stringify(config)],
        out,
      );
      if (output && output !== RUN_SUCCESS_MESSAGE) {
        out.show(true);
      }
      void vscode.window.showInformationMessage(
        RUN_SUCCESS_MESSAGE,
      );
      return;
    }

    await vscode.debug.startDebugging(folder, config, {
      noDebug: false,
    });
  } catch (error) {
    out.show(true);
    void vscode.window.showErrorMessage(
      `SilverScript ${kind} failed: ${(error as Error).message}`,
    );
  } finally {
    launchInProgress = false;
  }
}

async function renderActiveState(): Promise<void> {
  if (!panel || !activeState) {
    return;
  }

  const savedCounts = countSilverScriptSavedScenarios(
    activeState.scriptUri,
  );
  panel.title = activeState.model.name;
  panel.webview.html = buildHtml(
    activeState.model,
    activeState.scriptUri.fsPath,
    {
      function: activeState.form.function,
      constructorArgs: { ...activeState.form.constructorArgs },
      argsByFunction: Object.fromEntries(
        Object.entries(activeState.form.argsByFunction).map(
          ([entrypoint, args]) => [entrypoint, { ...args }],
        ),
      ),
      keyAliases: [...activeState.form.keyAliases],
      identityLabels: { ...activeState.form.identityLabels },
      loadedConfigName: activeState.loadedConfigName,
      savedCountsByFunction: savedCounts.byFunction,
      savedTotalCount: savedCounts.total,
    },
  );
}

async function openPanel(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
  uri?: vscode.Uri,
  initialFunction?: string,
): Promise<void> {
  if (!ensureTrustedWorkspace()) {
    return;
  }

  const scriptUri = resolveActiveScriptUri(uri);
  if (!scriptUri) {
    vscode.window.showErrorMessage("Open a .sil file first.");
    return;
  }

  if (
    panel &&
    activeState &&
    activeState.scriptUri.fsPath === scriptUri.fsPath
  ) {
    selectEntrypoint(activeState, initialFunction);
    await renderActiveState();
    panel.reveal(vscode.ViewColumn.Beside, true);
    await focusPrimaryEditor(scriptUri);
    return;
  }

  activeState = await buildInitialState(scriptUri, initialFunction);
  emitPanelStateChanged();

  if (!panel) {
    panel = vscode.window.createWebviewPanel(
      "silverscriptRunner",
      activeState.model.name,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [],
        retainContextWhenHidden: true,
      },
    );

    panel.webview.onDidReceiveMessage(
      async (message: PanelMessage) => {
        if (!activeState) {
          return;
        }

        applyMessageState(activeState, message.form);

        switch (message.kind) {
          case "loadSaved":
            await loadSavedScenario(
              message.form.keyAliases,
              message.form.identityLabels,
            );
            return;
          case "saveSaved":
            await saveScenario();
            return;
          case "run":
            await launchFromPanel(context, out, "run");
            return;
          case "debug":
            await launchFromPanel(context, out, "debug");
            return;
          default:
            return;
        }
      },
      undefined,
      [],
    );

    panel.onDidDispose(() => {
      panel = undefined;
      activeState = undefined;
      launchInProgress = false;
      emitPanelStateChanged();
    });
  } else {
    panel.reveal(vscode.ViewColumn.Beside, true);
  }

  await renderActiveState();
  await focusPrimaryEditor(scriptUri);
}

async function showSavedScenarios(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
  uri?: vscode.Uri,
  initialFunction?: string,
  showPicker = true,
): Promise<void> {
  await openPanel(context, out, uri, initialFunction);
  if (!showPicker || !activeState) {
    return;
  }

  await loadSavedScenario(
    activeState.form.keyAliases,
    activeState.form.identityLabels,
    initialFunction,
    true,
  );
}

async function handlePrimaryCodeLensAction(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
  uri?: vscode.Uri,
): Promise<void> {
  const scriptUri = resolveActiveScriptUri(uri);
  if (scriptUri && hasOpenSilverScriptPanelForUri(scriptUri)) {
    await triggerPanelLaunch("run");
    return;
  }

  await openPanel(context, out, uri);
}

async function triggerPanelLaunch(
  launchKind: LaunchKind,
): Promise<void> {
  if (!panel) {
    return;
  }

  await panel.webview.postMessage({
    kind: "triggerLaunch",
    launchKind,
  } satisfies PanelControlMessage);
}

async function handlePanelF5(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
  uri?: vscode.Uri,
  initialFunction?: string,
): Promise<void> {
  const scriptUri = resolveActiveScriptUri(uri);
  if (
    panel &&
    activeState &&
    (!scriptUri || activeState.scriptUri.fsPath === scriptUri.fsPath)
  ) {
    await triggerPanelLaunch("debug");
    return;
  }

  await openPanel(context, out, uri, initialFunction);
}

function escHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildHtml(
  model: ContractModel,
  scriptPath: string,
  initialState: WebviewState,
): string {
  const nonce = getNonce();
  const modelJson = stringifyForInlineScript(model);
  const stateJson = stringifyForInlineScript(initialState);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta
  http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';"
/>
<style nonce="${nonce}">
  :root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --input-bg: var(--vscode-input-background);
    --input-fg: var(--vscode-input-foreground);
    --input-border: var(--vscode-input-border, transparent);
    --panel-bg: rgba(127, 127, 127, 0.03);
    --panel-hover: var(--vscode-toolbar-hoverBackground, rgba(128, 128, 128, 0.1));
    --btn: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --btn-hover: var(--vscode-button-hoverBackground);
    --btn-secondary-bg: transparent;
    --btn-secondary-fg: var(--fg);
    --btn-secondary-hover: var(--panel-hover);
    --focus: var(--vscode-focusBorder);
    --muted: rgba(127, 127, 127, 0.75);
    --sep: var(--vscode-widget-border, rgba(128, 128, 128, 0.25));
    --badge: var(--vscode-badge-background);
    --badge-fg: var(--vscode-badge-foreground);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 16px;
    color: var(--fg);
    background: var(--bg);
    font: 13px/1.45 var(--vscode-font-family, system-ui, sans-serif);
  }
  .header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin: 0 0 14px;
  }
  h1 {
    flex: 1;
    min-width: 0;
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .topbar {
    display: flex;
    align-items: center;
    flex: none;
  }
  .topbar-actions {
    display: flex;
    gap: 6px;
  }
  section {
    margin-bottom: 14px;
  }
  h2 {
    margin: 0 0 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--muted);
  }
  label {
    display: block;
    margin: 10px 0 4px;
    font-size: 12px;
  }
  .meta {
    color: var(--muted);
    font-size: 11px;
    margin-left: 6px;
  }
  .badge {
    margin-left: 6px;
    padding: 1px 5px;
    border-radius: 3px;
    background: var(--badge);
    color: var(--badge-fg);
    font-size: 10px;
    font-weight: 600;
    vertical-align: middle;
  }
  input, select {
    width: 100%;
    min-height: 34px;
    padding: 6px 10px;
    border-radius: 4px;
    border: 1px solid var(--input-border);
    background: var(--input-bg);
    color: var(--input-fg);
    outline: none;
    font: 13px var(--vscode-editor-font-family, monospace);
  }
  input:focus, select:focus {
    border-color: var(--focus);
  }
  .empty {
    margin: 0;
    color: var(--muted);
    font-style: italic;
  }
  .actions {
    display: flex;
    gap: 8px;
    margin-top: 16px;
  }
  button {
    flex: 1;
    min-height: 36px;
    padding: 8px 0;
    border: 0;
    border-radius: 4px;
    background: var(--btn);
    color: var(--btn-fg);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  button:hover {
    background: var(--btn-hover);
  }
  .secondary-button {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: auto;
    min-width: 0;
    min-height: 32px;
    padding: 0 12px;
    border: 1px solid var(--sep);
    border-radius: 4px;
    background: var(--btn-secondary-bg);
    color: var(--btn-secondary-fg);
    font-size: 11px;
    font-weight: 600;
    line-height: 1;
  }
  .secondary-button:hover {
    background: var(--btn-secondary-hover);
  }
  .compact-button {
    flex: none;
  }
  .field-row {
    position: relative;
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .field-row input {
    flex: 1;
  }
  .field-row input.crypto-input {
    cursor: pointer;
  }
  .field-row .field-action {
    min-width: 64px;
    padding: 0 10px;
  }
  .section-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 8px;
  }
  .section-head h2 {
    margin: 0;
  }
  .identity-dropdown {
    position: absolute;
    z-index: 100;
    top: calc(100% + 4px);
    left: 0;
    right: 0;
    padding: 4px 0;
    border: 1px solid var(--sep);
    border-radius: 6px;
    background: var(--input-bg);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.28);
  }
  .identity-choice {
    display: flex;
    align-items: center;
    gap: 8px;
    justify-content: space-between;
    margin: 0 4px;
    padding: 7px 10px;
    border-radius: 4px;
    cursor: pointer;
  }
  .identity-choice:hover {
    background: var(--btn);
    color: var(--btn-fg);
  }
  .identity-choice-name {
    display: block;
    font-weight: 700;
  }
  .identity-choice-main {
    flex: 1;
    min-width: 0;
  }
  .identity-choice-value {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 11px;
    opacity: 0.72;
  }
  .identity-choice-delete {
    flex: none;
    min-width: 18px;
    min-height: 18px;
    padding: 0;
    border: 0;
    border-radius: 3px;
    background: transparent;
    color: var(--muted);
    font-size: 14px;
    line-height: 1;
  }
  .identity-choice-delete:hover {
    background: var(--panel-hover);
    color: var(--vscode-errorForeground, var(--fg));
  }
  .identity-divider {
    margin: 4px 0;
    border-top: 1px solid var(--sep);
  }
</style>
</head>
<body>
  <div class="header-row">
    <h1>${escHtml(model.name)}</h1>
    <div class="topbar">
      <div class="topbar-actions">
        <button id="load-button" class="secondary-button compact-button" type="button">Load</button>
        <button id="save-button" class="secondary-button compact-button" type="button">Save</button>
      </div>
    </div>
  </div>

  <section>
    <h2>Constructor</h2>
    <div id="constructor-fields"></div>
  </section>

  <section>
    <h2>Entrypoint</h2>
    <select id="function-select"></select>
  </section>

  <section>
    <h2>Function Args</h2>
    <div id="arg-fields"></div>
  </section>

  <div class="actions">
    <button id="run-button">Run</button>
    <button id="debug-button">Debug</button>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const model = ${modelJson};
    const state = ${stateJson};

    const ctorFields = document.getElementById("constructor-fields");
    const argFields = document.getElementById("arg-fields");
    const functionSelect = document.getElementById("function-select");
    const loadButton = document.getElementById("load-button");
    state.identityLabels = state.identityLabels && typeof state.identityLabels === "object"
      ? state.identityLabels
      : {};
    state.savedCountsByFunction =
      state.savedCountsByFunction && typeof state.savedCountsByFunction === "object"
        ? state.savedCountsByFunction
        : {};
    state.savedTotalCount = Number(state.savedTotalCount) || 0;

    function fieldValue(defaultValue) {
      return typeof defaultValue === "string" ? defaultValue : String(defaultValue ?? "");
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }

    function normalizedType(typeName) {
      return String(typeName ?? "").trim().toLowerCase();
    }

    function helperSlot(param) {
      const typeName = normalizedType(param.type);
      const name = String(param.name ?? "").toLowerCase();
      if (typeName === "pubkey") {
        return "pubkey";
      }
      if (typeName === "sig") {
        return "secret";
      }
      if ((typeName === "bytes32" || typeName === "byte[32]" || typeName === "bytes") && name.includes("pkh")) {
        return "pkh";
      }
      return null;
    }

    function tokenFor(alias, slot) {
      return alias + "." + slot;
    }

    function canonicalIdentityToken(raw) {
      const trimmed = String(raw ?? "").trim();
      const match = /^(?:keypair|identity)([1-9][0-9]*)(?:[.](pubkey|secret|pkh))?$/.exec(trimmed);
      if (!match) {
        return null;
      }
      const [, index, slot] = match;
      return slot ? "keypair" + index + "." + slot : "keypair" + index;
    }

    function displayLabelFor(alias) {
      const label = state.identityLabels[alias];
      return typeof label === "string" && label.trim()
        ? label.trim()
        : alias;
    }

    function syncAliasesFromFields() {
      state.constructorArgs = collectFields(ctorFields, "constructor");
      syncCurrentArgState();

      const found = new Map();
      const consider = (raw) => {
        const canonical = canonicalIdentityToken(raw);
        if (!canonical) {
          return;
        }
        const index = Number(canonical.slice("keypair".length).split(".")[0]);
        if (!found.has(index)) {
          found.set(index, "keypair" + index);
        }
      };

      state.keyAliases.forEach(consider);
      Object.values(state.constructorArgs).forEach(consider);
      Object.values(state.argsByFunction).forEach((args) => {
        Object.values(args).forEach(consider);
      });

      state.keyAliases = [...found.entries()]
        .sort((left, right) => left[0] - right[0])
        .map(([, alias]) => alias);
      state.identityLabels = Object.fromEntries(
        state.keyAliases
          .map((alias) => [alias, state.identityLabels[alias]])
          .filter(([alias, label]) => typeof label === "string" && label.trim() && label.trim() !== alias)
          .map(([alias, label]) => [alias, label.trim()]),
      );
    }

    function nextAlias() {
      syncAliasesFromFields();
      let max = 0;
      state.keyAliases.forEach((alias) => {
        const match = /^keypair([0-9]+)$/.exec(String(alias).trim());
        if (match) {
          max = Math.max(max, Number(match[1]));
        }
      });
      return "keypair" + (max + 1);
    }

    function addAlias(fillInput, fillSlot) {
      syncAliasesFromFields();
      const alias = nextAlias();
      state.keyAliases.push(alias);
      syncAliasesFromFields();
      if (fillInput && fillSlot) {
        fillFieldWithToken(fillInput, fillSlot, alias);
      }
      return alias;
    }

    function renderFields(container, params, values, group) {
      if (!params.length) {
        container.innerHTML = '<p class="empty">No parameters</p>';
        return;
      }

      container.innerHTML = params.map((param) => {
        const value = fieldValue(values[param.name]);
        const helper = helperSlot(param);
        const escapedValue = value
          .replace(/&/g, "&amp;")
          .replace(/"/g, "&quot;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");
        return '<label>' +
          param.name +
          '<span class="meta">' + param.type + '</span>' +
          (helper ? '<span class="badge">key</span>' : '') +
          '</label>' +
          '<div class="field-row">' +
            '<input data-group="' + group + '" data-name="' + param.name + '" value="' + escapedValue + '" placeholder="' + param.type + '"' +
              (helper ? ' class="crypto-input" data-helper-slot="' + helper + '"' : '') +
            ' />' +
            (helper
              ? '<button type="button" class="secondary-button field-action key-button" data-helper-slot="' + helper + '" data-field-name="' + param.name + '">Pick</button>'
              : '') +
          '</div>';
      }).join("");
    }

    function currentEntrypoint() {
      return model.entrypoints.find((entry) => entry.name === functionSelect.value) ?? model.entrypoints[0];
    }

    function ensureArgState(functionName) {
      if (!state.argsByFunction[functionName]) {
        state.argsByFunction[functionName] = {};
      }
      return state.argsByFunction[functionName];
    }

    function collectFields(container, group) {
      const out = {};
      container.querySelectorAll('input[data-group="' + group + '"]').forEach((input) => {
        out[input.dataset.name] = canonicalIdentityToken(input.value) ?? input.value;
      });
      return out;
    }

    function syncCurrentArgState() {
      const entrypoint = currentEntrypoint();
      if (!entrypoint) {
        return;
      }
      state.argsByFunction[entrypoint.name] = collectFields(argFields, "args");
    }

    function currentForm() {
      syncAliasesFromFields();
      state.function = functionSelect.value;
      return {
        function: state.function,
        constructorArgs: state.constructorArgs,
        argsByFunction: state.argsByFunction,
        keyAliases: state.keyAliases,
        identityLabels: state.identityLabels,
      };
    }

    function renderFunctionOptions() {
      functionSelect.innerHTML = model.entrypoints.map((entry) => {
        const signature = entry.params.map((param) => param.type + " " + param.name).join(", ");
        const selected = entry.name === state.function ? " selected" : "";
        return '<option value="' + entry.name + '"' + selected + '>' +
          entry.name + '(' + signature + ')' +
          '</option>';
      }).join("");
    }

    function renderArgs() {
      const entrypoint = currentEntrypoint();
      if (!entrypoint) {
        argFields.innerHTML = '<p class="empty">No entrypoints</p>';
        return;
      }
      renderFields(
        argFields,
        entrypoint.params,
        ensureArgState(entrypoint.name),
        "args",
      );
    }

    function renderLoadButton() {
      const functionName = String(functionSelect.value || state.function || "");
      const currentCount = Number(state.savedCountsByFunction[functionName] ?? 0);
      loadButton.textContent = currentCount > 0 ? 'Load (' + currentCount + ')' : 'Load';

      if (state.savedTotalCount === 0) {
        loadButton.title = "No saved scenarios for this contract yet.";
        return;
      }

      if (functionName && currentCount !== state.savedTotalCount) {
        loadButton.title =
          currentCount > 0
            ? currentCount + ' saved for ' + functionName + ', ' + state.savedTotalCount + ' total for this contract.'
            : 'No saved scenarios for ' + functionName + '. ' + state.savedTotalCount + ' saved for this contract.';
        return;
      }

      loadButton.title = state.savedTotalCount + ' saved for this contract.';
    }

    function renderAllFields() {
      renderFields(
        ctorFields,
        model.constructorParams,
        state.constructorArgs,
        "constructor",
      );
      renderArgs();
    }

    function fillFieldWithToken(input, slot, alias) {
      input.value = tokenFor(alias, slot);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.focus();
    }

    function closeDropdowns() {
      document.querySelectorAll(".identity-dropdown").forEach((node) => node.remove());
    }

    function clearAliasTokens(alias) {
      const tokens = new Set(["pubkey", "secret", "pkh"].map((slot) => tokenFor(alias, slot)));
      const clearValues = (values) => Object.fromEntries(
        Object.entries(values).map(([name, raw]) => {
          const canonical = canonicalIdentityToken(raw);
          return [name, canonical && tokens.has(canonical) ? "" : raw];
        }),
      );

      state.constructorArgs = clearValues(state.constructorArgs);
      state.argsByFunction = Object.fromEntries(
        Object.entries(state.argsByFunction).map(([name, values]) => [
          name,
          clearValues(values),
        ]),
      );
    }

    function deleteAlias(alias) {
      state.keyAliases = state.keyAliases.filter((entry) => entry !== alias);
      delete state.identityLabels[alias];
      clearAliasTokens(alias);
      renderAllFields();
      closeDropdowns();
    }

    function showDropdown(input, slot) {
      syncAliasesFromFields();
      const fieldRow = input.closest(".field-row");
      if (!fieldRow) {
        return;
      }
      closeDropdowns();

      const dropdown = document.createElement("div");
      dropdown.className = "identity-dropdown";

      state.keyAliases.forEach((alias) => {
        const item = document.createElement("div");
        item.className = "identity-choice";
        const main = document.createElement("div");
        main.className = "identity-choice-main";
        const name = document.createElement("span");
        name.className = "identity-choice-name";
        name.textContent = displayLabelFor(alias);
        const value = document.createElement("span");
        value.className = "identity-choice-value";
        value.textContent = tokenFor(alias, slot);
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "identity-choice-delete";
        remove.textContent = "X";
        remove.title = "Delete " + displayLabelFor(alias);
        remove.addEventListener("click", (event) => {
          event.stopPropagation();
          deleteAlias(alias);
        });
        main.append(name, value);
        item.append(main, remove);
        item.addEventListener("click", () => {
          fillFieldWithToken(input, slot, alias);
          closeDropdowns();
        });
        dropdown.appendChild(item);
      });

      if (state.keyAliases.length) {
        const divider = document.createElement("div");
        divider.className = "identity-divider";
        dropdown.appendChild(divider);
      }

      const add = document.createElement("div");
      add.className = "identity-choice";
      const addName = document.createElement("span");
      addName.className = "identity-choice-name";
      addName.textContent = "Add " + nextAlias();
      const addValue = document.createElement("span");
      addValue.className = "identity-choice-value";
      addValue.textContent = tokenFor(nextAlias(), slot);
      add.append(addName, addValue);
      add.addEventListener("click", () => {
        addAlias(input, slot);
        closeDropdowns();
      });
      dropdown.appendChild(add);

      fieldRow.appendChild(dropdown);
    }

    function send(kind) {
      vscode.postMessage({
        kind,
        form: currentForm(),
      });
    }

    functionSelect.addEventListener("change", () => {
      syncCurrentArgState();
      state.function = functionSelect.value;
      renderArgs();
      renderLoadButton();
      closeDropdowns();
    });

    renderFunctionOptions();
    renderAllFields();
    renderLoadButton();

    document.addEventListener("click", (event) => {
      const target = event.target instanceof Element
        ? event.target
        : event.target?.parentElement ?? null;
      if (!target) {
        return;
      }

      const button = target.closest(".key-button");
      if (button) {
        const row = button.closest(".field-row");
        const input = row?.querySelector("input.crypto-input");
        const slot = button.dataset.helperSlot;
        if (input && slot) {
          event.stopPropagation();
          showDropdown(input, slot);
        }
        return;
      }

      const input = target.closest("input.crypto-input");
      if (input && input.dataset.helperSlot) {
        event.stopPropagation();
        showDropdown(input, input.dataset.helperSlot);
        return;
      }

      if (!target.closest(".identity-dropdown")) {
        closeDropdowns();
      }
    });

    document.getElementById("load-button").addEventListener("click", () => send("loadSaved"));
    document.getElementById("save-button").addEventListener("click", () => send("saveSaved"));
    document.getElementById("run-button").addEventListener("click", () => send("run"));
    document.getElementById("debug-button").addEventListener("click", () => send("debug"));

    window.addEventListener("message", (event) => {
      const message = event.data;
      if (!message || typeof message !== "object") {
        return;
      }
      if (message.kind === "triggerLaunch" && (message.launchKind === "run" || message.launchKind === "debug")) {
        send(message.launchKind);
      }
    });
  </script>
</body>
</html>`;
}

export function registerSilverScriptQuickLaunchPanel(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.debug.configureLaunch",
      (uri?: vscode.Uri, initialFunction?: string) =>
        openPanel(context, out, uri, initialFunction),
    ),
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.debug.f5",
      (uri?: vscode.Uri, initialFunction?: string) =>
        handlePanelF5(context, out, uri, initialFunction),
    ),
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.debug.primaryCodeLensAction",
      (uri?: vscode.Uri) =>
        handlePrimaryCodeLensAction(context, out, uri),
    ),
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.debug.showSavedScenarios",
      (
        uri?: vscode.Uri,
        initialFunction?: string,
        showPicker?: boolean,
      ) =>
        showSavedScenarios(
          context,
          out,
          uri,
          initialFunction,
          showPicker ?? true,
        ),
    ),
  );
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      void handleActiveEditorChange(editor);
    }),
  );
}
