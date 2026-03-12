import * as vscode from "vscode";
import { countSilverScriptSavedScenarios } from "./launchConfigs";
import {
  hasOpenSilverScriptPanelForUri,
  onDidChangeSilverScriptPanelState,
} from "./quickLaunch/panel";

const CONTRACT_RE = /^\s*contract\s+([A-Za-z_]\w*)\s*\(/;
const ENTRYPOINT_RE =
  /^\s*entrypoint\s+function\s+([A-Za-z_]\w*)\s*\(/;

type EntrypointTarget = {
  functionName: string;
  range: vscode.Range;
};

function findContractRange(
  document: vscode.TextDocument,
): vscode.Range | undefined {
  for (let line = 0; line < document.lineCount; line += 1) {
    const text = document.lineAt(line).text;
    const contractMatch = CONTRACT_RE.exec(text);
    if (!contractMatch) {
      continue;
    }

    const start = new vscode.Position(
      line,
      contractMatch[0].search(/\S|$/),
    );
    return new vscode.Range(start, start);
  }

  return undefined;
}

function findEntrypointTargets(
  document: vscode.TextDocument,
): EntrypointTarget[] {
  const targets: EntrypointTarget[] = [];

  for (let line = 0; line < document.lineCount; line += 1) {
    const text = document.lineAt(line).text;
    const entrypointMatch = ENTRYPOINT_RE.exec(text);
    if (!entrypointMatch) {
      continue;
    }

    const start = new vscode.Position(
      line,
      entrypointMatch[0].search(/\S|$/),
    );
    targets.push({
      functionName: entrypointMatch[1],
      range: new vscode.Range(start, start),
    });
  }

  return targets;
}

function savedLensTitle(count: number): string {
  return count === 1
    ? "1 scenario saved"
    : `${count} scenarios saved`;
}

function primaryLensTitle(document: vscode.TextDocument): string {
  return hasOpenSilverScriptPanelForUri(document.uri)
    ? "Run"
    : "Open Debug Panel...";
}

class SilverScriptCodeLensProvider
  implements vscode.CodeLensProvider
{
  private readonly onDidChangeEmitter =
    new vscode.EventEmitter<void>();

  readonly onDidChangeCodeLenses = this.onDidChangeEmitter.event;

  triggerRefresh(): void {
    this.onDidChangeEmitter.fire();
  }

  provideCodeLenses(
    document: vscode.TextDocument,
  ): vscode.CodeLens[] {
    if (document.languageId !== "silverscript") {
      return [];
    }

    const contractRange = findContractRange(document);
    const entrypointTargets = findEntrypointTargets(document);
    if (!contractRange && entrypointTargets.length === 0) {
      return [];
    }

    const counts = countSilverScriptSavedScenarios(document.uri);
    const lenses: vscode.CodeLens[] = [];

    if (contractRange) {
      lenses.push(
        new vscode.CodeLens(contractRange, {
          title: primaryLensTitle(document),
          command: "silverscript.debug.primaryCodeLensAction",
          arguments: [document.uri],
        }),
      );
    }

    for (const target of entrypointTargets) {
      const count = counts.byFunction[target.functionName] ?? 0;
      lenses.push(
        new vscode.CodeLens(target.range, {
          title: savedLensTitle(count),
          command: "silverscript.debug.showSavedScenarios",
          arguments: [document.uri, target.functionName, count > 0],
        }),
      );
    }

    return lenses;
  }
}

export function registerSilverScriptCodeLens(
  context: vscode.ExtensionContext,
): void {
  const provider = new SilverScriptCodeLensProvider();

  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { language: "silverscript" },
      provider,
    ),
  );
  context.subscriptions.push(
    onDidChangeSilverScriptPanelState(() => {
      provider.triggerRefresh();
    }),
  );
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (event.document.languageId === "silverscript") {
        provider.triggerRefresh();
      }
    }),
  );
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("launch")) {
        provider.triggerRefresh();
      }
    }),
  );
}
