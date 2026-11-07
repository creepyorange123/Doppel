import { useCallback, useEffect, useRef, useState } from "react";
import type { AnalyzeResult, ProgressEvent, StatusResult } from "./shared/protocol";
import { recorderHealth } from "./lib/health";
import { Consent } from "./screens/Consent";
import { AppList } from "./screens/AppList";
import { Report } from "./screens/Report";
import { Settings } from "./screens/Settings";

// Captured text is always rendered as React text nodes, never as HTML
// (security checklist #5). Never inject raw HTML anywhere; tests/test_security_static.py checks this.

type Tab = "report" | "overview" | "apps" | "settings";

function formatTime(ms: number | null): string {
  return ms === null ? "never" : new Date(ms).toLocaleString();
}

export function App() {
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("report");
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [lastRun, setLastRun] = useState<AnalyzeResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const started = useRef(false);

  const load = useCallback(
    () =>
      window.shadow
        .request("status")
        .then((s) => {
          setStatus(s);
          setError(null);
        })
        .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e))),
    [],
  );

  useEffect(() => {
    const off = window.shadow.onEvent((ev) => {
      if (ev.type === "ready") void load();
      if (ev.type === "progress") setProgress(ev.payload);
      if (ev.type === "exit") setError("The analyzer stopped.");
    });
    void load();
    return off;
  }, [load]);

  const consented = Boolean(status?.consent_at);

  // Steps 1-4 run once each time the app opens.
  useEffect(() => {
    if (!consented || started.current) return;
    started.current = true; // once per open, even if it fails
    setAnalyzing(true);
    window.shadow
      .request("analyze_since_last_open")
      .then((r) => {
        setLastRun(r);
        void load();
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setAnalyzing(false));
  }, [consented, load]);

  const health = status ? recorderHealth(status.recorder_heartbeat_at) : null;

  return (
    <main className="shell">
      <header className="row spread">
        <div>
          <h1>Shadow Profile</h1>
          <p className="muted">Everything stays on this computer.</p>
        </div>
        {consented && (
          <nav className="row">
            {(["report", "overview", "apps", "settings"] as Tab[]).map((t) => (
              <button key={t} className={tab === t ? "tab active" : "tab"} onClick={() => setTab(t)}>
                {{ report: "Report", overview: "Status", apps: "Apps", settings: "Settings" }[t]}
              </button>
            ))}
          </nav>
        )}
      </header>
      {error && <p className="error">{error}</p>}
      {!status && !error && <p className="muted">Starting analyzer…</p>}
      {status && !consented && <Consent onDone={() => void load()} />}
      {consented && health && health.state !== "ok" && <p className="warning">{health.message}</p>}
      {analyzing && progress && (
        <div className="progress">
          <p>{progress.label}</p>
          <progress max={Math.max(progress.total, 1)} value={progress.done} />
        </div>
      )}
      {status && consented && tab === "overview" && (
        <dl className="status">
          <dt>Requests logged</dt>
          <dd>{status.request_count.toLocaleString()}</dd>
          <dt>Not yet analyzed</dt>
          <dd>{status.unanalyzed_count.toLocaleString()}</dd>
          <dt>Last opened</dt>
          <dd>{formatTime(status.last_opened_at)}</dd>
          <dt>Recorder last seen</dt>
          <dd>{formatTime(status.recorder_heartbeat_at)}</dd>
        </dl>
      )}
      {consented && tab === "report" && !analyzing && lastRun && <Report />}
      {consented && tab === "apps" && <AppList />}
      {consented && tab === "settings" && <Settings />}
    </main>
  );
}
