import * as fs from "fs/promises";
import * as path from "path";

export type ContractParam = { name: string; type: string };
export type Entrypoint = { name: string; params: ContractParam[] };
export type ContractModel = {
  name: string;
  constructorParams: ContractParam[];
  entrypoints: Entrypoint[];
};

export type DebugArgObject = Record<string, unknown>;
export type DebugArgInput = unknown[] | DebugArgObject;
export type DebugTxInput = {
  prev_txid?: string;
  prev_index?: number;
  sequence?: number;
  sig_op_count?: number;
  utxo_value: number;
  covenant_id?: string;
  constructor_args?: DebugArgInput;
  signature_script_hex?: string;
  utxo_script_hex?: string;
};
export type DebugTxOutput = {
  value: number;
  covenant_id?: string;
  authorizing_input?: number;
  constructor_args?: DebugArgInput;
  script_hex?: string;
  p2pk_pubkey?: string;
};
export type DebugTxScenario = {
  version?: number;
  lock_time?: number;
  active_input_index?: number;
  inputs: DebugTxInput[];
  outputs: DebugTxOutput[];
};

export type DebugParamsFile = {
  function?: string;
  constructorArgs?: DebugArgInput;
  args?: DebugArgInput;
  tx?: DebugTxScenario;
};

export function inferDebugParamsPath(scriptPath: string): string {
  const base = path.basename(scriptPath, path.extname(scriptPath));
  return path.join(path.dirname(scriptPath), `${base}.debug.json`);
}

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
}

function parseParams(raw: string): ContractParam[] {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((part, index) => {
      const [typeName, name] = part.split(/\s+/).filter(Boolean);
      return { type: typeName ?? "int", name: name ?? `arg${index}` };
    });
}

export function parseContractModel(source: string): ContractModel {
  const clean = stripComments(source);
  const header = clean.match(
    /contract\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/m,
  );
  const name = header?.[1] ?? "Unknown";
  const constructorParams = header?.[2]?.trim()
    ? parseParams(header[2])
    : [];
  const entrypoints: Entrypoint[] = [];
  const re =
    /entrypoint\s+function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/g;
  for (let match; (match = re.exec(clean)); ) {
    entrypoints.push({
      name: match[1],
      params: parseParams(match[2]),
    });
  }
  return { name, constructorParams, entrypoints };
}

function hex(n: number): string {
  return `0x${"00".repeat(Math.max(0, n))}`;
}

export function defaultForType(typeName: string): unknown {
  const normalized = typeName.trim();
  if (normalized.endsWith("[]")) {
    return [];
  }
  switch (normalized) {
    case "int":
      return 0;
    case "bool":
      return false;
    case "string":
      return "";
    case "byte":
      return hex(1);
    case "bytes":
      return hex(0);
    case "pubkey":
      return hex(32);
    case "sig":
      return hex(65);
    case "datasig":
      return hex(64);
  }
  let match = normalized.match(/^bytes(\d+)$/);
  if (match) {
    return hex(Number(match[1]));
  }
  match = normalized.match(/^byte\[(\d+)\]$/);
  if (match) {
    return hex(Number(match[1]));
  }
  return 0;
}

export function defaultsFromParams(params: ContractParam[]): unknown[] {
  return params.map((param) => defaultForType(param.type));
}

export function defaultsObjectFromParams(
  params: ContractParam[],
): DebugArgObject {
  return Object.fromEntries(
    params.map((param) => [param.name, defaultForType(param.type)]),
  );
}

function isDebugArgObject(value: unknown): value is DebugArgObject {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

export async function readDebugParams(
  scriptPath: string,
  explicitPath?: string,
): Promise<DebugParamsFile | undefined> {
  const paramsPath = explicitPath ?? inferDebugParamsPath(scriptPath);
  try {
    const parsed = JSON.parse(
      await fs.readFile(paramsPath, "utf8"),
    ) as Record<string, unknown>;
    return {
      function:
        typeof parsed.function === "string"
          ? parsed.function
          : undefined,
      constructorArgs:
        Array.isArray(parsed.constructorArgs) ||
        isDebugArgObject(parsed.constructorArgs)
          ? (parsed.constructorArgs as DebugArgInput)
          : Array.isArray(parsed.constructor_args) ||
              isDebugArgObject(parsed.constructor_args)
            ? (parsed.constructor_args as DebugArgInput)
            : undefined,
      args:
        Array.isArray(parsed.args) || isDebugArgObject(parsed.args)
          ? (parsed.args as DebugArgInput)
          : undefined,
      tx:
        parsed.tx && typeof parsed.tx === "object"
          ? (parsed.tx as DebugTxScenario)
          : undefined,
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

export async function writeDebugParams(
  scriptPath: string,
  params: DebugParamsFile,
  explicitPath?: string,
): Promise<string> {
  const paramsPath = explicitPath ?? inferDebugParamsPath(scriptPath);
  await fs.writeFile(
    paramsPath,
    JSON.stringify(params, null, 2) + "\n",
    "utf8",
  );
  return paramsPath;
}
