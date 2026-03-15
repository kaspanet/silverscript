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
} from "../contractModel";
import { runDebuggerAdapterCommand } from "../debugAdapter";
import {
  countSilverScriptSavedScenarios,
  createSilverScriptLaunchConfig,
  defaultLaunchScriptPathValue,
  listMatchingSilverScriptLaunchConfigs,
  type RawLaunchConfiguration,
  type SilverScriptLaunchConfigRecord,
  updateSilverScriptLaunchConfig,
} from "../launchConfigs";
import {
  buildQuickLaunchHtml,
  quickLaunchWebviewRoot,
  type QuickLaunchWebviewState,
} from "./view";

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

const RUN_SUCCESS_MESSAGE = "Execution completed successfully.";

let panel: vscode.WebviewPanel | undefined;
let activeState: PanelHostState | undefined;
let launchInProgress = false;
let restoringPrimaryEditor = false;
let extensionContext: vscode.ExtensionContext | undefined;
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

function resolvedLaunchName(
  state: PanelHostState,
): string {
  return typeof state.baseConfig.name === "string" &&
    state.baseConfig.name.trim()
    ? state.baseConfig.name
    : defaultLaunchName(state.model, state.scriptUri.fsPath);
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
  const constructorDefaults = defaultsForParams(
    model.constructorParams,
  );
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
    constructorArgs: constructorDefaults,
    argsByFunction,
    keyAliases: normalizeKeyAliases(
      [],
      constructorDefaults,
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

function cloneArgsByFunction(
  argsByFunction: Record<string, Record<string, string>>,
): Record<string, Record<string, string>> {
  return Object.fromEntries(
    Object.entries(argsByFunction).map(
      ([entrypoint, args]) => [entrypoint, { ...args }],
    ),
  );
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
    argsByFunction: cloneArgsByFunction(form.argsByFunction),
    keyAliases: normalizedAliases,
    identityLabels: normalizeIdentityLabels(
      normalizedAliases,
      form.identityLabels,
    ),
  };
}

function launchConfigLabel(
  record: SilverScriptLaunchConfigRecord,
): string {
  return typeof record.config.name === "string"
    ? record.config.name
    : path.basename(record.resolvedScriptPath);
}

type SavedScenarioPickItem = vscode.QuickPickItem & {
  record?: SilverScriptLaunchConfigRecord;
};

function buildSavedScenarioPickItems(
  model: ContractModel,
  records: SilverScriptLaunchConfigRecord[],
  functionName?: string,
): SavedScenarioPickItem[] {
  if (functionName) {
    return records.map((record) => ({
      label: launchConfigLabel(record),
      description: record.scriptPathValue,
      record,
    }));
  }

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
  for (const entrypoint of model.entrypoints) {
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
        label: launchConfigLabel(record),
        description: record.scriptPathValue,
        record,
      })),
    ];
  });
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
  const record = listMatchingSilverScriptLaunchConfigs(scriptUri)[0];

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
    name: resolvedLaunchName(state),
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

function buildWebviewState(
  state: PanelHostState,
): QuickLaunchWebviewState {
  const savedCounts = countSilverScriptSavedScenarios(
    state.scriptUri,
  );
  return {
    function: state.form.function,
    constructorArgs: { ...state.form.constructorArgs },
    argsByFunction: cloneArgsByFunction(state.form.argsByFunction),
    keyAliases: [...state.form.keyAliases],
    identityLabels: { ...state.form.identityLabels },
    savedCountsByFunction: savedCounts.byFunction,
    savedTotalCount: savedCounts.total,
  };
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

  const records = listMatchingSilverScriptLaunchConfigs(
    activeState.scriptUri,
  ).filter(
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
    buildSavedScenarioPickItems(
      activeState.model,
      records,
      functionName,
    ),
    {
      title: functionName
        ? `Load Saved Scenario for '${functionName}'`
        : "Load SilverScript Launch Config",
      placeHolder: functionName
        ? `Select a saved launch config for '${functionName}'`
        : "Select a saved launch config for this contract, grouped by entrypoint",
    },
  );

  if (!picked?.record) {
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
    const name = resolvedLaunchName(activeState);
    const config = savedLaunchConfigForPanel(activeState, name);
    const updated = await updateSilverScriptLaunchConfig(
      activeState.record,
      config,
    );
    activeState.baseConfig = config;
    activeState.record = updated;
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
  if (!extensionContext) {
    throw new Error("SilverScript quick launch panel is not initialized.");
  }

  panel.title = activeState.model.name;
  panel.webview.html = await buildQuickLaunchHtml(
    extensionContext,
    panel.webview,
    activeState.model,
    buildWebviewState(activeState),
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
        localResourceRoots: [quickLaunchWebviewRoot(context)],
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

export function registerSilverScriptQuickLaunchPanel(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
): void {
  extensionContext = context;
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
