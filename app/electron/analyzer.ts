// Starts the Python analyzer as a sidecar and talks to it over stdio pipes.
// No network port is opened (security checklist #3).

import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import readline from "node:readline";
import type { AnalyzerEvent, RequestType } from "../src/shared/protocol";

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout };

const REQUEST_TIMEOUT_MS = 5 * 60 * 1000;

export function repoRoot(): string {
  // dist-electron/electron/analyzer.js -> repo root
  return path.resolve(__dirname, "..", "..", "..");
}

export function pythonExecutable(root: string): string {
  if (process.env.SHADOW_PYTHON) return process.env.SHADOW_PYTHON;
  const venv =
    process.platform === "win32"
      ? path.join(root, ".venv", "Scripts", "python.exe")
      : path.join(root, ".venv", "bin", "python");
  return fs.existsSync(venv) ? venv : process.platform === "win32" ? "python" : "python3";
}

export class AnalyzerClient {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private nextId = 1;
  private pending = new Map<number, Pending>();

  constructor(private onEvent: (event: AnalyzerEvent) => void) {}

  /** The analyzer's process id, for the self-audit target (null if not running). */
  get pid(): number | null {
    return this.proc?.pid ?? null;
  }

  start(): void {
    const root = repoRoot();
    // -s: ignore user site-packages. -m with cwd=root imports only the repo's packages.
    const env: NodeJS.ProcessEnv = { ...process.env, PYTHONUNBUFFERED: "1", PYTHONIOENCODING: "utf-8" };
    delete env.PYTHONPATH;
    delete env.PYTHONSTARTUP;
    const proc = spawn(pythonExecutable(root), ["-s", "-m", "analyzer"], {
      cwd: root,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.proc = proc;

    readline.createInterface({ input: proc.stdout }).on("line", (line) => this.handleLine(line));
    // Analyzer diagnostics only; it never writes captured content to stderr.
    proc.stderr.on("data", (chunk: Buffer) => process.stderr.write(chunk));
    proc.on("exit", (code) => {
      this.proc = null;
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.reject(new Error("analyzer exited"));
      }
      this.pending.clear();
      this.onEvent({ type: "exit", payload: { code } });
    });
  }

  request(type: RequestType, payload: Record<string, unknown> = {}): Promise<unknown> {
    const proc = this.proc;
    if (!proc) return Promise.reject(new Error("analyzer not running"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("analyzer timed out"));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      proc.stdin.write(JSON.stringify({ id, type, payload }) + "\n");
    });
  }

  stop(): void {
    // Closing stdin lets the analyzer checkpoint the WAL and exit cleanly.
    this.proc?.stdin.end();
  }

  private handleLine(line: string): void {
    let msg: { id?: number; type?: string; payload?: unknown };
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (typeof msg.id === "number" && this.pending.has(msg.id)) {
      const p = this.pending.get(msg.id)!;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.type === "result") p.resolve(msg.payload);
      else {
        const err = msg.payload as { code?: string; message?: string } | undefined;
        p.reject(new Error(`${err?.code ?? "error"}: ${err?.message ?? ""}`));
      }
      return;
    }
    if (msg.type === "ready" || msg.type === "progress") {
      this.onEvent(msg as AnalyzerEvent);
    }
  }
}
