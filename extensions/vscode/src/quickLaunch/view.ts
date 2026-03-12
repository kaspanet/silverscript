import * as fs from "fs/promises";
import * as path from "path";
import * as vscode from "vscode";
import type { ContractModel } from "../contractModel";

export type QuickLaunchWebviewState = {
  function: string;
  constructorArgs: Record<string, string>;
  argsByFunction: Record<string, Record<string, string>>;
  keyAliases: string[];
  identityLabels: Record<string, string>;
  savedCountsByFunction: Record<string, number>;
  savedTotalCount: number;
};

const QUICK_LAUNCH_TEMPLATE = ["webviews", "quickLaunch", "panel.html"];
const QUICK_LAUNCH_SCRIPT = ["webviews", "quickLaunch", "panel.js"];
const QUICK_LAUNCH_STYLE = ["webviews", "quickLaunch", "panel.css"];

let quickLaunchTemplatePromise: Promise<string> | undefined;

function webviewAssetUri(
  context: vscode.ExtensionContext,
  ...segments: string[]
): vscode.Uri {
  return vscode.Uri.joinPath(context.extensionUri, ...segments);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function stringifyForHtml(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

async function loadTemplate(
  context: vscode.ExtensionContext,
): Promise<string> {
  if (!quickLaunchTemplatePromise) {
    quickLaunchTemplatePromise = fs.readFile(
      path.join(context.extensionPath, ...QUICK_LAUNCH_TEMPLATE),
      "utf8",
    );
  }
  return quickLaunchTemplatePromise;
}

export function quickLaunchWebviewRoot(
  context: vscode.ExtensionContext,
): vscode.Uri {
  return webviewAssetUri(context, "webviews", "quickLaunch");
}

export async function buildQuickLaunchHtml(
  context: vscode.ExtensionContext,
  webview: vscode.Webview,
  model: ContractModel,
  initialState: QuickLaunchWebviewState,
): Promise<string> {
  const template = await loadTemplate(context);
  const replacements = {
    "{{CSP_SOURCE}}": webview.cspSource,
    "{{STYLE_URI}}": webview
      .asWebviewUri(webviewAssetUri(context, ...QUICK_LAUNCH_STYLE))
      .toString(),
    "{{SCRIPT_URI}}": webview
      .asWebviewUri(webviewAssetUri(context, ...QUICK_LAUNCH_SCRIPT))
      .toString(),
    "{{TITLE}}": escapeHtml(model.name),
    "{{MODEL_JSON}}": stringifyForHtml(model),
    "{{STATE_JSON}}": stringifyForHtml(initialState),
  } as const;

  return Object.entries(replacements).reduce(
    (html, [needle, value]) => html.replaceAll(needle, value),
    template,
  );
}
