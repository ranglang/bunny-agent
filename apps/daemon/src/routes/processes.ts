import { execFile } from "node:child_process";
import { promisify } from "node:util";
import psList from "ps-list";
import type { AppState } from "../utils.js";
import { AppError, ok } from "../utils.js";

const execFileAsync = promisify(execFile);
const EXCLUDED_PORTS = new Set([3080, 9002]);

export interface SandboxProcessSnapshot {
  pid: number;
  ppid?: number;
  name: string;
  cmd?: string;
  path?: string;
  cpu?: number;
  memory?: number;
}

interface ListeningSocket {
  pid: number;
  port: number;
}

interface SandboxProcessInspectors {
  listProcesses: () => Promise<SandboxProcessSnapshot[]>;
  listListeningSockets: () => Promise<ListeningSocket[]>;
}

const defaultInspectors: SandboxProcessInspectors = {
  async listProcesses() {
    const processes = await psList();
    return processes.map((process) => ({
      pid: process.pid,
      ppid: process.ppid,
      name: process.name,
      cmd: process.cmd,
      path: process.path,
      cpu: process.cpu,
      memory: process.memory,
    }));
  },
  listListeningSockets,
};

let inspectors: SandboxProcessInspectors = defaultInspectors;

export function __setSandboxProcessInspectorsForTests(
  next: Partial<SandboxProcessInspectors>,
): void {
  inspectors = { ...defaultInspectors, ...next };
}

export function __resetSandboxProcessInspectorsForTests(): void {
  inspectors = defaultInspectors;
}

export async function sandboxProcesses(_state: AppState) {
  const [processes, sockets] = await Promise.all([
    inspectors.listProcesses(),
    inspectors.listListeningSockets(),
  ]);

  const portsByPid = new Map<number, number[]>();
  for (const socket of sockets) {
    if (EXCLUDED_PORTS.has(socket.port)) continue;
    const ports = portsByPid.get(socket.pid) ?? [];
    if (!ports.includes(socket.port)) {
      ports.push(socket.port);
      ports.sort((left, right) => left - right);
    }
    portsByPid.set(socket.pid, ports);
  }

  const data = processes
    .map((process) => ({
      pid: process.pid,
      ppid: process.ppid,
      name: process.name,
      cmd: process.cmd,
      path: process.path,
      cpu: process.cpu,
      memory: process.memory,
      ports: portsByPid.get(process.pid) ?? [],
    }))
    .filter((process) => process.ports.length > 0)
    .sort((left, right) => {
      const leftPort = left.ports[0] ?? Number.MAX_SAFE_INTEGER;
      const rightPort = right.ports[0] ?? Number.MAX_SAFE_INTEGER;
      if (leftPort !== rightPort) return leftPort - rightPort;
      return left.name.localeCompare(right.name);
    });

  return ok({ processes: data });
}

async function listListeningSockets(): Promise<ListeningSocket[]> {
  const attempts = [readListeningSocketsFromLsof, readListeningSocketsFromSs];
  const failures: string[] = [];

  for (const attempt of attempts) {
    try {
      return await attempt();
    } catch (error) {
      if (!isMissingCommandError(error)) {
        throw error;
      }
      failures.push(error.message);
    }
  }

  throw new AppError(
    500,
    `sandbox process inspection requires lsof or ss: ${failures.join("; ")}`,
  );
}

async function readListeningSocketsFromLsof(): Promise<ListeningSocket[]> {
  try {
    const { stdout } = await execFileAsync("lsof", [
      "-nP",
      "-iTCP",
      "-sTCP:LISTEN",
      "-Fpn",
    ]);
    return parseLsof(stdout);
  } catch (error) {
    if (isMissingCommandError(error)) throw error;
    if (isExecFileErrorWithCode(error, 1)) {
      return parseLsof(error.stdout ?? "");
    }
    throw normalizeInspectorError("lsof", error);
  }
}

async function readListeningSocketsFromSs(): Promise<ListeningSocket[]> {
  try {
    const { stdout } = await execFileAsync("ss", ["-ltnpH"]);
    return parseSs(stdout);
  } catch (error) {
    if (isMissingCommandError(error)) throw error;
    throw normalizeInspectorError("ss", error);
  }
}

function parseLsof(stdout: string): ListeningSocket[] {
  const sockets: ListeningSocket[] = [];
  let currentPid: number | null = null;

  for (const rawLine of stdout.split(/\r?\n/u)) {
    if (!rawLine) continue;
    const prefix = rawLine[0];
    const value = rawLine.slice(1);
    if (prefix === "p") {
      const pid = Number.parseInt(value, 10);
      currentPid = Number.isFinite(pid) ? pid : null;
      continue;
    }
    if (prefix !== "n" || currentPid == null) continue;
    const port = parsePort(value);
    if (port != null) {
      sockets.push({ pid: currentPid, port });
    }
  }

  return sockets;
}

function parseSs(stdout: string): ListeningSocket[] {
  const sockets: ListeningSocket[] = [];

  for (const rawLine of stdout.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/u);
    const localAddress = parts[3];
    const pidMatch = line.match(/pid=(\d+)/u);
    if (!localAddress || !pidMatch) continue;
    const pid = Number.parseInt(pidMatch[1], 10);
    const port = parsePort(localAddress);
    if (Number.isFinite(pid) && port != null) {
      sockets.push({ pid, port });
    }
  }

  return sockets;
}

function parsePort(value: string): number | null {
  const match = value.match(/:(\d+)(?:\s|$)/u) ?? value.match(/:(\d+)$/u);
  if (!match) return null;
  const port = Number.parseInt(match[1], 10);
  return Number.isFinite(port) ? port : null;
}

function normalizeInspectorError(command: string, error: unknown): AppError {
  if (error instanceof AppError) {
    return error;
  }
  const message = error instanceof Error ? error.message : String(error);
  return new AppError(
    500,
    `failed to inspect sandbox ports via ${command}: ${message}`,
  );
}

function isMissingCommandError(error: unknown): error is NodeJS.ErrnoException {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function isExecFileErrorWithCode(
  error: unknown,
  code: number,
): error is Error & { code: number; stdout?: string } {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}
