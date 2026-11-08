// Runs one audit at a time: creates it in the analyzer, then runs
// `python -m recorder audit --id N` as a child process for the audit's duration.
// Nothing records outside an audit, and an audit never outlives Doppel.

import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import type { AnalyzerClient } from "./analyzer";
import { pythonExecutable, repoRoot } from "./analyzer";
import type { AnalyzerEvent, Audit, AuditControlResult } from "../src/shared/protocol";

const MAX_APPS = 20;
const MAX_MINUTES = 240;
const SELF_AUDIT_MINUTES = [2, 5, 15];
const BACKSTOP_MS = 30_000;

interface Running {
  audit: Audit;
  child: ChildProcess;
  backstop: NodeJS.Timeout;
}

type AppTarget = { path: string; name: string; capture: "full" | "metadata_only"; pids?: number[] };

function cleanString(v: unknown, max: number): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  // No control characters; commas would break the recorder's process filter.
  if (!s || s.length > max || /[\u0000-\u001f\u007f,]/.test(s)) return null;
  return s;
}

/** Validates renderer input for `start`. Returns an error message or the cleaned payload. */
export function parseStart(payload: unknown): { apps: AppTarget[]; minutes: number; label?: string } | string {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return "bad payload";
  const p = payload as Record<string, unknown>;
  if (!Array.isArray(p.apps) || p.apps.length < 1 || p.apps.length > MAX_APPS) return `pick 1 to ${MAX_APPS} apps`;
  const minutes = p.minutes;
  if (typeof minutes !== "number" || !Number.isInteger(minutes) || minutes < 1 || minutes > MAX_MINUTES) {
    return `duration must be 1 to ${MAX_MINUTES} minutes`;
  }
  const apps: AppTarget[] = [];
  for (const a of p.apps) {
    if (!a || typeof a !== "object") return "bad app";
    const app = a as Record<string, unknown>;
    const appPath = cleanString(app.path, 4096);
    const name = cleanString(app.name, 200);
    if (!appPath || !path.isAbsolute(appPath) || !name) return "bad app";
    const capture = app.capture === "metadata_only" ? "metadata_only" : "full";
    apps.push({ path: appPath, name, capture });
  }
  let label: string | undefined;
  if (p.label !== undefined && p.label !== "") {
    const l = typeof p.label === "string" ? p.label.trim().slice(0, 120) : "";
    if (l && !/[\u0000-\u001f\u007f]/.test(l)) label = l;
  }
  return { apps, minutes, label };
}

/** /x/Electron.app/Contents/MacOS/Electron -> /x/Electron.app (the bundle covers its helpers). */
export function bundleRoot(execPath: string): string {
  const i = execPath.indexOf(".app/Contents/MacOS/");
  return i >= 0 ? execPath.slice(0, i + 4) : execPath;
}

export class AuditController {
  private running: Running | null = null;

  constructor(
    private analyzer: () => AnalyzerClient | null,
    private sendEvent: (event: AnalyzerEvent) => void,
  ) {}

  state(): AuditControlResult {
    return { ok: true, audit: this.running?.audit ?? null };
  }

  async start(payload: unknown): Promise<AuditControlResult> {
    const parsed = parseStart(payload);
    if (typeof parsed === "string") return { ok: false, audit: null, error: parsed };
    return this.begin({ apps: parsed.apps, minutes: parsed.minutes, label: parsed.label });
  }

  async self(payload: unknown): Promise<AuditControlResult> {
    const minutes = payload && typeof payload === "object" ? (payload as Record<string, unknown>).minutes : undefined;
    if (typeof minutes !== "number" || !SELF_AUDIT_MINUTES.includes(minutes)) {
      return { ok: false, audit: null, error: `duration must be one of ${SELF_AUDIT_MINUTES.join(", ")} minutes` };
    }
    const analyzerPid = this.analyzer()?.pid;
    const pids = [process.pid, ...(analyzerPid ? [analyzerPid] : [])];
    // Built here, never from renderer input: Doppel's own window, helpers and analyzer.
    const apps: AppTarget[] = [{ path: bundleRoot(process.execPath), name: "Doppel", capture: "full", pids }];
    return this.begin({ apps, minutes, label: "Doppel self-audit", self_audit: true });
  }

  stop(): AuditControlResult {
    const r = this.running;
    if (!r) return { ok: false, audit: null, error: "no audit is running" };
    r.child.kill("SIGTERM"); // the recorder flushes and marks the audit done
    return { ok: true, audit: r.audit };
  }

  /** Called when Doppel quits. */
  shutdown(): void {
    this.running?.child.kill("SIGTERM");
  }

  private async begin(body: Record<string, unknown>): Promise<AuditControlResult> {
    if (this.running) return { ok: false, audit: null, error: "an audit is already running" };
    const analyzer = this.analyzer();
    if (!analyzer) return { ok: false, audit: null, error: "analyzer not running" };
    let audit: Audit;
    try {
      audit = ((await analyzer.request("create_audit", body)) as { audit: Audit }).audit;
    } catch (e) {
      return { ok: false, audit: null, error: e instanceof Error ? e.message : String(e) };
    }
    if (this.running) {
      // Lost a race with another start.
      await this.finish(audit.id, "failed", "another audit started first");
      return { ok: false, audit: null, error: "an audit is already running" };
    }

    const root = repoRoot();
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.PYTHONPATH;
    delete env.PYTHONSTARTUP;
    let child: ChildProcess;
    try {
      child = spawn(pythonExecutable(root), ["-s", "-m", "recorder", "audit", "--id", String(audit.id)], {
        cwd: root,
        env,
        stdio: ["ignore", "ignore", "pipe"],
        windowsHide: true,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      await this.finish(audit.id, "failed", msg);
      return { ok: false, audit: null, error: msg };
    }
    // Recorder diagnostics are fixed-text only (no captured content).
    child.stderr?.on("data", (chunk: Buffer) => process.stderr.write(chunk));

    const backstop = setTimeout(() => child.kill("SIGTERM"), Math.max(0, audit.ends_at - Date.now()) + BACKSTOP_MS);
    const running: Running = { audit, child, backstop };
    this.running = running;

    let settled = false;
    const settle = (ok: boolean, message?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(backstop);
      if (this.running === running) this.running = null;
      void this.finish(audit.id, ok ? "done" : "failed", message).then(() =>
        this.sendEvent({ type: "audit", payload: { audit_id: audit.id, state: "ended", ok, message } }),
      );
    };
    // A failed spawn (e.g. Python missing) emits "error" and may never emit "exit".
    child.on("error", (err) => settle(false, err.message));
    child.on("exit", (code, signal) => {
      // Only we send SIGTERM (stop, end-of-audit backstop, quit), so it is a normal ending.
      const ok = code === 0 || signal === "SIGTERM";
      settle(ok, ok ? undefined : `recorder exited with code ${code ?? signal}`);
    });

    this.sendEvent({ type: "audit", payload: { audit_id: audit.id, state: "started", ok: true } });
    return { ok: true, audit };
  }

  private async finish(auditId: number, status: "done" | "failed", error?: string): Promise<void> {
    try {
      await this.analyzer()?.request("finish_audit", { audit_id: auditId, status, ...(error ? { error } : {}) });
    } catch {
      // The analyzer may already be gone when Doppel quits; it settles stale audits on next start.
    }
  }
}
