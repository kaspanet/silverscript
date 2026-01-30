import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs/promises";
import { Language, Parser, Query } from "web-tree-sitter";
import type { QueryCapture } from "web-tree-sitter";

const TOKEN_TYPES = [
  "comment",
  "string",
  "number",
  "keyword",
  "operator",
  "function",
  "constant",
  "variable",
  "type",
  "property",
  "parameter",
  "boolean",
] as const;

const TOKEN_MODIFIERS = ["defaultLibrary"] as const;

const legend = new vscode.SemanticTokensLegend(
  [...TOKEN_TYPES],
  [...TOKEN_MODIFIERS],
);

const LOG_DEBUG = true;
let outputChannel: vscode.OutputChannel | null = null;

function logInfo(message: string) {
  if (!outputChannel) return;
  outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
}

function logDebug(message: string) {
  if (!LOG_DEBUG) return;
  logInfo(message);
}

function logError(message: string, error: unknown) {
  const err =
    error instanceof Error
      ? `${error.message}\n${error.stack ?? ""}`
      : String(error);
  logInfo(`${message}\n${err}`);
}

type TokenType = (typeof TOKEN_TYPES)[number];
type TokenModifier = (typeof TOKEN_MODIFIERS)[number];

const TOKEN_TYPE_TO_INDEX = new Map<TokenType, number>(
  TOKEN_TYPES.map((token, index) => [token, index]),
);
const TOKEN_MODIFIER_TO_MASK = new Map<TokenModifier, number>(
  TOKEN_MODIFIERS.map((modifier, index) => [modifier, 1 << index]),
);

function mapCaptureToToken(captureName: string): {
  type: TokenType | null;
  modifiers: TokenModifier[];
} {
  const parts = captureName.split(".");
  const base = parts[0];
  const mods = new Set<TokenModifier>();

  if (parts.includes("builtin")) mods.add("defaultLibrary");

  switch (base) {
    case "comment":
      return { type: "comment", modifiers: [...mods] };
    case "string":
      return { type: "string", modifiers: [...mods] };
    case "number":
      return { type: "number", modifiers: [...mods] };
    case "boolean":
      return { type: "boolean", modifiers: [...mods] };
    case "keyword":
      return { type: "keyword", modifiers: [...mods] };
    case "operator":
      return { type: "operator", modifiers: [...mods] };
    case "function":
      return { type: "function", modifiers: [...mods] };
    case "constant":
      return { type: "constant", modifiers: [...mods] };
    case "type":
      return { type: "type", modifiers: [...mods] };
    case "property":
      return { type: "property", modifiers: [...mods] };
    case "variable":
      if (parts.includes("parameter"))
        return { type: "parameter", modifiers: [...mods] };
      return { type: "variable", modifiers: [...mods] };
    default:
      return { type: null, modifiers: [] };
  }
}

function tokenTypeIndex(t: TokenType) {
  return TOKEN_TYPE_TO_INDEX.get(t);
}

function tokenModifierMask(mods: readonly TokenModifier[]) {
  let mask = 0;
  for (const m of mods) {
    const bit = TOKEN_MODIFIER_TO_MASK.get(m);
    if (bit !== undefined) mask |= bit;
  }
  return mask;
}

let initPromise: Promise<void> | null = null;
let cachedLanguage: Language | null = null;
let cachedQuery: Query | null = null;

async function initTreeSitter(context: vscode.ExtensionContext) {
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const runtimeWasmPath = context.asAbsolutePath(
        path.join("node_modules", "web-tree-sitter", "web-tree-sitter.wasm"),
      );
      logDebug(`runtime wasm: ${runtimeWasmPath}`);

      // web-tree-sitter needs its runtime wasm (tree-sitter.wasm). Provide it via locateFile.
      await Parser.init({
        locateFile: (scriptName?: string) => {
          const resolved = scriptName
            ? context.asAbsolutePath(
                path.join("node_modules", "web-tree-sitter", scriptName),
              )
            : runtimeWasmPath;
          logDebug(`locateFile(${scriptName ?? "undefined"}): ${resolved}`);
          return resolved;
        },
      });

      const parserWasmPath = context.asAbsolutePath(
        path.join("assets", "tree-sitter-silverscript.wasm"),
      );
      logDebug(`language wasm: ${parserWasmPath}`);
      cachedLanguage = await Language.load(parserWasmPath);

      const highlightsPath = context.asAbsolutePath(
        path.join("queries", "highlights.scm"),
      );
      logDebug(`highlights: ${highlightsPath}`);
      const highlightsSource = await fs.readFile(highlightsPath, "utf8");
      cachedQuery = new Query(cachedLanguage, highlightsSource);
    } catch (error) {
      logError("Tree-sitter init failed.", error);
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

function compareCaptures(a: QueryCapture, b: QueryCapture) {
  const ap = a.node.startPosition;
  const bp = b.node.startPosition;
  if (ap.row !== bp.row) return ap.row - bp.row;
  if (ap.column !== bp.column) return ap.column - bp.column;
  // stable tie-break
  const ae = a.node.endPosition;
  const be = b.node.endPosition;
  if (ae.row !== be.row) return ae.row - be.row;
  return ae.column - be.column;
}

function splitMultiLineToken(
  document: vscode.TextDocument,
  start: vscode.Position,
  end: vscode.Position,
) {
  const ranges: vscode.Range[] = [];
  if (start.line === end.line) {
    ranges.push(new vscode.Range(start, end));
    return ranges;
  }

  // start line segment
  const startLineLen = document.lineAt(start.line).text.length;
  ranges.push(
    new vscode.Range(start, new vscode.Position(start.line, startLineLen)),
  );

  // middle full lines
  for (let line = start.line + 1; line < end.line; line++) {
    const len = document.lineAt(line).text.length;
    if (len > 0)
      ranges.push(
        new vscode.Range(
          new vscode.Position(line, 0),
          new vscode.Position(line, len),
        ),
      );
  }

  // end line segment
  if (end.character > 0) {
    ranges.push(new vscode.Range(new vscode.Position(end.line, 0), end));
  }

  return ranges;
}

class SilverScriptSemanticTokensProvider
  implements vscode.DocumentSemanticTokensProvider
{
  private _onDidChange = new vscode.EventEmitter<void>();
  onDidChangeSemanticTokens = this._onDidChange.event;

  public triggerRefresh() {
    this._onDidChange.fire();
  }

  async provideDocumentSemanticTokens(
    document: vscode.TextDocument,
    _cancellationToken: vscode.CancellationToken,
  ): Promise<vscode.SemanticTokens> {
    logDebug(
      `semantic tokens request: ${document.uri.toString()} (${document.languageId})`,
    );

    try {
      await initTreeSitter(this.context);
    } catch (error) {
      logError("Tree-sitter init error during tokenization.", error);
      return new vscode.SemanticTokens(new Uint32Array());
    }

    const language = cachedLanguage;
    const query = cachedQuery;

    if (!language || !query) {
      logInfo("Tree-sitter language/query not initialized.");
      return new vscode.SemanticTokens(new Uint32Array());
    }

    const parser = new Parser();
    parser.setLanguage(language);

    const text = document.getText();
    const tree = parser.parse(text);
    if (!tree) {
      parser.delete();
      return new vscode.SemanticTokens(new Uint32Array());
    }

    try {
      const captures: QueryCapture[] = query.captures(tree.rootNode);
      logDebug(`captures: ${captures.length}`);
      captures.sort(compareCaptures);

      const priority = (name: string) => {
        if (name.startsWith("function")) return 100;
        if (name.startsWith("type")) return 90;
        if (name.startsWith("keyword")) return 80;
        if (name.startsWith("string")) return 70;
        if (name.startsWith("number") || name.startsWith("boolean")) return 70;
        if (name.startsWith("comment")) return 60;
        if (name.startsWith("operator")) return 50;
        if (name.startsWith("property")) return 40;
        if (name.startsWith("constant")) return 35;
        if (name.startsWith("variable")) return 30;
        return 0;
      };

      const bestByRange = new Map<string, QueryCapture>();
      for (const capture of captures) {
        const sp = capture.node.startPosition;
        const ep = capture.node.endPosition;
        const key = `${sp.row}:${sp.column}-${ep.row}:${ep.column}`;
        const existing = bestByRange.get(key);
        if (!existing || priority(capture.name) > priority(existing.name)) {
          bestByRange.set(key, capture);
        }
      }

      const finalCaps = [...bestByRange.values()].sort(compareCaptures);
      const builder = new vscode.SemanticTokensBuilder(legend);

      for (const cap of finalCaps) {
        const mapped = mapCaptureToToken(cap.name);
        if (!mapped.type) continue;

        const typeIndex = tokenTypeIndex(mapped.type);
        if (typeIndex === undefined) continue;

        const sp = cap.node.startPosition;
        const ep = cap.node.endPosition;

        // Assumption: your language is mostly ASCII; if you rely heavily on non-ASCII,
        // you'll want a UTF conversion layer for columns.
        const start = new vscode.Position(sp.row, sp.column);
        const end = new vscode.Position(ep.row, ep.column);

        for (const range of splitMultiLineToken(document, start, end)) {
          const length = range.end.character - range.start.character;
          if (length <= 0) continue;

          builder.push(
            range.start.line,
            range.start.character,
            length,
            typeIndex,
            tokenModifierMask(mapped.modifiers),
          );
        }
      }

      return builder.build();
    } finally {
      tree.delete();
      parser.delete();
    }
  }

  constructor(private readonly context: vscode.ExtensionContext) {}
}

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("SilverScript");
  context.subscriptions.push(outputChannel);
  logInfo("SilverScript extension activated.");

  const provider = new SilverScriptSemanticTokensProvider(context);

  context.subscriptions.push(
    vscode.languages.registerDocumentSemanticTokensProvider(
      { language: "silverscript" },
      provider,
      legend,
    ),
  );

  // Refresh semantic tokens when docs change
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.languageId === "silverscript") provider.triggerRefresh();
    }),
  );
}

export function deactivate() {}
