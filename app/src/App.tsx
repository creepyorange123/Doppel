import { useEffect, useState } from "react";
import type { StatusResult } from "./shared/protocol";

// Captured text is always rendered as React text nodes, never as HTML
// (security checklist #5). Do not use dangerouslySetInnerHTML anywhere.

function formatTime(ms: number | null): string {
  return ms === null ? "never" : new Date(ms).toLocaleString();
}

export function App() {
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () =>
      window.shadow
        .request("status")
        .then((s) => {
          setStatus(s);
          setError(null);
        })
        .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
    const off = window.shadow.onEvent((ev) => {
      if (ev.type === "ready") void load();
      if (ev.type === "exit") setError("The analyzer stopped.");
    });
    void load();
    return off;
  }, []);

  return (
    <main className="shell">
      <h1>Shadow Profile</h1>
      <p className="muted">Everything stays on this computer.</p>
      {error && <p className="error">{error}</p>}
      {!status && !error && <p className="muted">Starting analyzer…</p>}
      {status && (
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
    </main>
  );
}
