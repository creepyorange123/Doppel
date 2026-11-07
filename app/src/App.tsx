import { useCallback, useEffect, useState } from "react";
import type { StatusResult } from "./shared/protocol";
import { recorderHealth } from "./lib/health";
import { Consent } from "./screens/Consent";
import { AppList } from "./screens/AppList";

// Captured text is always rendered as React text nodes, never as HTML
// (security checklist #5). Do not use dangerouslySetInnerHTML anywhere.

type Tab = "overview" | "apps";

function formatTime(ms: number | null): string {
  return ms === null ? "never" : new Date(ms).toLocaleString();
}

export function App() {
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

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
      if (ev.type === "exit") setError("The analyzer stopped.");
    });
    void load();
    return off;
  }, [load]);

  const consented = Boolean(status?.consent_at);
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
            <button className={tab === "overview" ? "tab active" : "tab"} onClick={() => setTab("overview")}>
              Overview
            </button>
            <button className={tab === "apps" ? "tab active" : "tab"} onClick={() => setTab("apps")}>
              Apps
            </button>
          </nav>
        )}
      </header>
      {error && <p className="error">{error}</p>}
      {!status && !error && <p className="muted">Starting analyzer…</p>}
      {status && !consented && <Consent onDone={() => void load()} />}
      {consented && health && health.state !== "ok" && <p className="warning">{health.message}</p>}
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
      {consented && tab === "apps" && <AppList />}
    </main>
  );
}
