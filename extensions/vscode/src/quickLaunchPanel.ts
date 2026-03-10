import * as fs from "fs";
import * as vscode from "vscode";
import {
  defaultForType,
  type DebugArgInput,
  type DebugParamsFile,
  parseContractModel,
  readDebugParams,
  writeDebugParams,
  type ContractModel,
  type ContractParam,
  type DebugArgObject,
} from "./contractModel";
import { runDebuggerAdapterCommand } from "./debugAdapter";

type LaunchPanelMessage = {
  kind: "run" | "debug";
  function: string;
  constructorArgs: DebugArgObject;
  args: DebugArgObject;
};
type KeygenPanelMessage = { kind: "generateKeyMaterial" };
type PanelMessage = LaunchPanelMessage | KeygenPanelMessage;

type GeneratedKeyMaterial = {
  pubkey: string;
  secret_key: string;
  pkh: string;
};

type WebviewState = {
  function: string;
  constructorArgs: Record<string, string>;
  argsByFunction: Record<string, Record<string, string>>;
  keys: GeneratedKeyMaterial[];
};

type WebviewMessage =
  | { kind: "keyMaterial"; keyMaterial: GeneratedKeyMaterial }
  | { kind: "error"; message: string };
type PanelControlMessage = {
  kind: "triggerLaunch";
  launchKind: "run" | "debug";
};

let panel: vscode.WebviewPanel | undefined;
let activeScriptUri: vscode.Uri | undefined;
let launchInProgress = false;

function activeSilverScriptSession(): vscode.DebugSession | undefined {
  const session = vscode.debug.activeDebugSession;
  return session?.type === "silverscript" ? session : undefined;
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
  if (Array.isArray(value) || (value !== null && typeof value === "object")) {
    return JSON.stringify(value);
  }
  return String(value);
}

function defaultsForParams(params: ContractParam[]): Record<string, string> {
  return Object.fromEntries(
    params.map((param) => [param.name, stringifyLaunchArg(defaultForType(param.type))]),
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

  const source = await fs.promises.readFile(scriptUri.fsPath, "utf8");
  const model = parseContractModel(source);
  const debugParams = await readDebugParams(scriptUri.fsPath);
  const selectedFunction =
    initialFunction && model.entrypoints.some((entry) => entry.name === initialFunction)
      ? initialFunction
      : debugParams?.function && model.entrypoints.some((entry) => entry.name === debugParams.function)
        ? debugParams.function
        : model.entrypoints[0]?.name ?? "";

  const entrypointValues: Record<string, Record<string, string>> = {};
  for (const entrypoint of model.entrypoints) {
    const argsInput =
      entrypoint.name === selectedFunction ? debugParams?.args : undefined;
    entrypointValues[entrypoint.name] = valuesForParams(
      entrypoint.params,
      argsInput,
    );
  }

  activeScriptUri = scriptUri;

  if (!panel) {
    panel = vscode.window.createWebviewPanel(
      "silverscriptRunner",
      model.name,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [],
        retainContextWhenHidden: true,
      },
    );

    panel.webview.onDidReceiveMessage(
      async (msg: PanelMessage) => {
        if (!activeScriptUri) {
          return;
        }

        if (msg.kind === "generateKeyMaterial") {
          try {
            const raw = await runDebuggerAdapterCommand(
              context,
              ["--keygen"],
              out,
            );
            const keyMaterial = JSON.parse(raw) as GeneratedKeyMaterial;
            await panel?.webview.postMessage({
              kind: "keyMaterial",
              keyMaterial,
            } satisfies WebviewMessage);
          } catch (error) {
            await panel?.webview.postMessage({
              kind: "error",
              message: `Failed to generate key material: ${(error as Error).message}`,
            } satisfies WebviewMessage);
          }
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
          const existingParams =
            (await readDebugParams(activeScriptUri.fsPath)) ?? {};
          const nextParams: DebugParamsFile = {
            ...existingParams,
            function: msg.function,
            constructorArgs: msg.constructorArgs,
            args: msg.args,
          };
          await writeDebugParams(activeScriptUri.fsPath, nextParams);

          const folder =
            vscode.workspace.getWorkspaceFolder(activeScriptUri) ??
            vscode.workspace.workspaceFolders?.[0];
          const config: vscode.DebugConfiguration = {
            type: "silverscript",
            request: "launch",
            name: `SilverScript: ${msg.function}`,
            scriptPath: activeScriptUri.fsPath,
            function: msg.function,
            constructorArgs: msg.constructorArgs,
            args: msg.args,
            noDebug: msg.kind === "run",
            stopOnEntry: msg.kind === "debug",
          };

          if (msg.kind === "run") {
            const output = await runDebuggerAdapterCommand(
              context,
              ["--run-config-json", JSON.stringify(config)],
              out,
            );
            out.show(true);
            void vscode.window.showInformationMessage(
              output || "Execution completed successfully.",
            );
            return;
          }

          await vscode.debug.startDebugging(folder, config, {
            noDebug: false,
          });
        } catch (error) {
          out.show(true);
          void vscode.window.showErrorMessage(
            `SilverScript ${msg.kind} failed: ${(error as Error).message}`,
          );
        } finally {
          launchInProgress = false;
        }
      },
      undefined,
      [],
    );

    panel.onDidDispose(() => {
      panel = undefined;
      activeScriptUri = undefined;
      launchInProgress = false;
    });
  } else {
    panel.reveal(vscode.ViewColumn.Beside);
  }

  panel.title = model.name;
  panel.webview.html = buildHtml(model, scriptUri.fsPath, {
    function: selectedFunction,
    constructorArgs: valuesForParams(
      model.constructorParams,
      debugParams?.constructorArgs,
    ),
    argsByFunction: entrypointValues,
    keys: [],
  });
}

async function triggerPanelLaunch(kind: "run" | "debug"): Promise<void> {
  if (!panel) {
    return;
  }
  await panel.webview.postMessage({
    kind: "triggerLaunch",
    launchKind: kind,
  } satisfies PanelControlMessage);
}

async function handlePanelF5(
  context: vscode.ExtensionContext,
  out: vscode.OutputChannel,
  uri?: vscode.Uri,
  initialFunction?: string,
): Promise<void> {
  if (panel && activeScriptUri) {
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
    --btn: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --btn-hover: var(--vscode-button-hoverBackground);
    --focus: var(--vscode-focusBorder);
    --muted: rgba(127, 127, 127, 0.75);
    --sep: var(--vscode-widget-border, rgba(128, 128, 128, 0.25));
    --badge: var(--vscode-badge-background);
    --badge-fg: var(--vscode-badge-foreground);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 18px;
    color: var(--fg);
    background: var(--bg);
    font: 13px/1.45 var(--vscode-font-family, system-ui, sans-serif);
  }
  h1 {
    margin: 0 0 4px;
    font-size: 16px;
    font-weight: 600;
  }
  .path {
    margin: 0 0 18px;
    color: var(--muted);
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  section {
    margin-bottom: 18px;
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
    padding: 7px 8px;
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
    gap: 10px;
    margin-top: 24px;
  }
  button {
    flex: 1;
    padding: 10px 0;
    border: 0;
    border-radius: 5px;
    background: var(--btn);
    color: var(--btn-fg);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  button:hover {
    background: var(--btn-hover);
  }
  .field-row {
    position: relative;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .field-row input {
    flex: 1;
  }
  .field-row input.crypto-input {
    cursor: pointer;
  }
  .field-row button {
    flex: none;
    width: 58px;
    padding: 7px 0;
    background: transparent;
    border: 1px solid var(--sep);
    color: var(--fg);
    font-size: 12px;
    font-weight: 600;
  }
  .field-row button:hover {
    background: rgba(128, 128, 128, 0.12);
  }
  .key-wallet {
    margin-top: 16px;
    border-top: 1px solid var(--sep);
    padding-top: 14px;
  }
  .key-wallet summary {
    cursor: pointer;
    font-size: 12px;
    font-weight: 700;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .key-wallet-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-top: 10px;
  }
  .key-wallet-actions button {
    flex: none;
    width: auto;
    min-width: 160px;
    padding: 8px 14px;
  }
  .key-help {
    color: var(--muted);
    font-size: 11px;
  }
  .key-list {
    display: grid;
    gap: 8px;
    margin-top: 10px;
  }
  .key-row {
    display: grid;
    grid-template-columns: 76px 1fr auto;
    gap: 8px;
    align-items: center;
    padding: 8px 10px;
    border: 1px solid var(--sep);
    border-radius: 6px;
    background: rgba(128, 128, 128, 0.05);
    font: 12px var(--vscode-editor-font-family, monospace);
  }
  .key-name {
    font-weight: 700;
  }
  .key-value {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .key-row button {
    flex: none;
    width: 64px;
    padding: 6px 0;
    background: transparent;
    border: 1px solid var(--sep);
    color: var(--fg);
    font-size: 11px;
  }
  .key-dropdown {
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
  .key-choice {
    margin: 0 4px;
    padding: 7px 10px;
    border-radius: 4px;
    cursor: pointer;
  }
  .key-choice:hover {
    background: var(--btn);
    color: var(--btn-fg);
  }
  .key-choice-name {
    display: block;
    font-weight: 700;
  }
  .key-choice-value {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 11px;
    opacity: 0.72;
  }
  .key-divider {
    margin: 4px 0;
    border-top: 1px solid var(--sep);
  }
  .status {
    min-height: 16px;
    margin-top: 10px;
    color: var(--muted);
    font-size: 11px;
  }
  .status.error {
    color: var(--vscode-errorForeground);
  }
</style>
</head>
<body>
  <h1>${escHtml(model.name)}</h1>
  <div class="path">${escHtml(scriptPath)}</div>

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

  <details class="key-wallet" id="key-wallet">
    <summary>Keys</summary>
    <div class="key-wallet-actions">
      <button id="keygen-button" type="button">Generate Key Pair</button>
      <span class="key-help">Click a crypto field to fill it directly from a generated key.</span>
    </div>
    <div id="key-list" class="key-list"></div>
    <div id="wallet-status" class="status"></div>
  </details>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const model = ${modelJson};
    const state = ${stateJson};

    const ctorFields = document.getElementById("constructor-fields");
    const argFields = document.getElementById("arg-fields");
    const functionSelect = document.getElementById("function-select");
    const keyList = document.getElementById("key-list");
    const walletStatus = document.getElementById("wallet-status");
    const keyWallet = document.getElementById("key-wallet");
    let pendingFill = null;

    function fieldValue(defaultValue) {
      return typeof defaultValue === "string" ? defaultValue : String(defaultValue ?? "");
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
        return "secret_key";
      }
      if ((typeName === "bytes32" || typeName === "byte[32]" || typeName === "bytes") && name.includes("pkh")) {
        return "pkh";
      }
      return null;
    }

    function isDefaultCryptoValue(slot, value) {
      const normalized = String(value ?? "").trim().toLowerCase();
      if (!normalized) {
        return true;
      }
      const body = normalized.startsWith("0x") ? normalized.slice(2) : normalized;
      if (!body) {
        return true;
      }
      return /^0+$/.test(body);
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
            (helper ? '<button type="button" class="key-button" data-helper-slot="' + helper + '" data-field-name="' + param.name + '">Fill</button>' : '') +
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
        out[input.dataset.name] = input.value;
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

    function setStatus(message, isError) {
      walletStatus.textContent = message ?? "";
      walletStatus.className = isError ? "status error" : "status";
    }

    function keyName(index) {
      return "key_" + (index + 1);
    }

    function renderKeyList() {
      if (!state.keys.length) {
        keyList.innerHTML = "";
        return;
      }

      keyList.innerHTML = state.keys.map((key, index) => (
        '<div class="key-row">' +
          '<span class="key-name">' + keyName(index) + '</span>' +
          '<span class="key-value" title="' + key.pubkey + '">' + key.pubkey + '</span>' +
          '<button type="button" data-key-index="' + index + '">Copy</button>' +
        '</div>'
      )).join("");
    }

    function fillFieldFromKey(input, slot, key) {
      const value = key[slot];
      if (!value) {
        return;
      }
      input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.focus();
      setStatus('Filled ' + (input.dataset.name || 'field') + ' from ' + slot + '.', false);
    }

    function autoFillEmptyCryptoFields(key) {
      document.querySelectorAll("input.crypto-input").forEach((input) => {
        const slot = input.dataset.helperSlot;
        if (!slot || !key[slot]) {
          return;
        }
        if (!isDefaultCryptoValue(slot, input.value)) {
          return;
        }
        input.value = key[slot];
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
    }

    function closeDropdowns() {
      document.querySelectorAll(".key-dropdown").forEach((node) => node.remove());
    }

    function showDropdown(input, slot) {
      const fieldRow = input.closest(".field-row");
      if (!fieldRow) {
        return;
      }
      closeDropdowns();

      const dropdown = document.createElement("div");
      dropdown.className = "key-dropdown";

      state.keys.forEach((key, index) => {
        const item = document.createElement("div");
        item.className = "key-choice";
        const name = document.createElement("span");
        name.className = "key-choice-name";
        name.textContent = keyName(index);
        const value = document.createElement("span");
        value.className = "key-choice-value";
        value.textContent = key[slot];
        item.append(name, value);
        item.addEventListener("click", () => {
          fillFieldFromKey(input, slot, key);
          closeDropdowns();
        });
        dropdown.appendChild(item);
      });

      if (state.keys.length) {
        const divider = document.createElement("div");
        divider.className = "key-divider";
        dropdown.appendChild(divider);
      }

      const generate = document.createElement("div");
      generate.className = "key-choice";
      const generateName = document.createElement("span");
      generateName.className = "key-choice-name";
      generateName.textContent = "Generate new";
      const generateValue = document.createElement("span");
      generateValue.className = "key-choice-value";
      generateValue.textContent = slot + " for this field";
      generate.append(generateName, generateValue);
      generate.addEventListener("click", () => {
        pendingFill = { name: input.dataset.name, slot: slot };
        setStatus("Generating key material...", false);
        vscode.postMessage({ kind: "generateKeyMaterial" });
        closeDropdowns();
      });
      dropdown.appendChild(generate);

      fieldRow.appendChild(dropdown);
    }

    function findField(group, name) {
      return document.querySelector('input[data-group="' + group + '"][data-name="' + name + '"]');
    }

    function findPendingField(name) {
      return findField("constructor", name) || findField("args", name);
    }

    function send(kind) {
      state.constructorArgs = collectFields(ctorFields, "constructor");
      syncCurrentArgState();
      vscode.postMessage({
        kind,
        function: functionSelect.value,
        constructorArgs: state.constructorArgs,
        args: state.argsByFunction[functionSelect.value] ?? {},
      });
    }

    functionSelect.addEventListener("change", () => {
      syncCurrentArgState();
      state.function = functionSelect.value;
      renderArgs();
      closeDropdowns();
    });

    renderFunctionOptions();
    renderFields(
      ctorFields,
      model.constructorParams,
      state.constructorArgs,
      "constructor",
    );
    renderArgs();
    renderKeyList();

    document.addEventListener("click", (event) => {
      const button = event.target.closest(".key-button");
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

      const input = event.target.closest("input.crypto-input");
      if (input && input.dataset.helperSlot) {
        event.stopPropagation();
        showDropdown(input, input.dataset.helperSlot);
        return;
      }

      const copyButton = event.target.closest("[data-key-index]");
      if (copyButton) {
        const keyIndex = Number(copyButton.dataset.keyIndex);
        const key = state.keys[keyIndex];
        if (!key || !navigator.clipboard || !navigator.clipboard.writeText) {
          setStatus("Clipboard API unavailable.", true);
          return;
        }
        navigator.clipboard.writeText(key.secret_key).then(
          () => setStatus("Copied secret_key.", false),
          (error) => setStatus("Copy failed: " + error, true),
        );
        return;
      }

      if (!event.target.closest(".key-dropdown")) {
        closeDropdowns();
      }
    });

    document.getElementById("keygen-button").addEventListener("click", () => {
      pendingFill = null;
      setStatus("Generating key material...", false);
      vscode.postMessage({ kind: "generateKeyMaterial" });
    });
    document.getElementById("run-button").addEventListener("click", () => send("run"));
    document.getElementById("debug-button").addEventListener("click", () => send("debug"));

    window.addEventListener("message", (event) => {
      const message = event.data;
      if (!message || typeof message !== "object") {
        return;
      }
      if (message.kind === "triggerLaunch" && (message.launchKind === "run" || message.launchKind === "debug")) {
        send(message.launchKind);
        return;
      }
      if (message.kind === "keyMaterial") {
        const key = message.keyMaterial;
        state.keys.push(key);
        renderKeyList();
        keyWallet.open = true;

        if (pendingFill) {
          const input = findPendingField(pendingFill.name);
          if (input) {
            fillFieldFromKey(input, pendingFill.slot, key);
          }
          pendingFill = null;
        } else {
          autoFillEmptyCryptoFields(key);
          setStatus("Generated key material and filled empty crypto fields.", false);
        }
        return;
      }
      if (message.kind === "error") {
        pendingFill = null;
        setStatus(message.message ?? "Request failed.", true);
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
}
