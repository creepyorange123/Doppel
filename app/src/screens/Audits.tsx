import { useCallback, useEffect, useState } from "react";
import type { AppCapture, Audit, AuditLive, ProgressEvent, RunningApp } from "../shared/protocol";
import { Modal } from "../components/ui";
import { RefreshIcon, SearchIcon, ShieldCheckIcon, XIcon } from "../components/icons";
import { DURATIONS, STATUS_LABELS, appList, auditDuration, auditRange, auditTitle, countdown } from "../lib/audit";
import { num, when } from "../lib/format";

// App names, process names and domains are captured metadata: rendered as text only.

export function Audits({
  audits,
  active,
  analyzing,
  progress,
  selectedId,
  onStart,
  onStop,
  onSelect,
  onDelete,
}: {
  audits: Audit[];
  active: Audit | null;
  analyzing: number | null;
  progress: ProgressEvent | null;
  selectedId: number | null;
  onStart: (apps: { path: string; name: string; capture: AppCapture }[], minutes: number, label: string) => Promise<boolean>;
  onStop: () => void;
  onSelect: (id: number) => void;
  onDelete: (audit: Audit) => void;
}) {
  return (
    <div className="view">
      <header className="view-head">
        <h1 className="title">Audits</h1>
        <p className="muted">Doppel records nothing in the background. It only looks at the apps you pick, for as long as you say.</p>
      </header>
      {active ? (
        <LivePanel audit={active} onStop={onStop} />
      ) : analyzing !== null ? (
        <AnalyzingPanel progress={progress} />
      ) : (
        <StartPanel onStart={onStart} />
      )}
      <PastAudits audits={audits} selectedId={selectedId} onSelect={onSelect} onDelete={onDelete} />
    </div>
  );
}

function StartPanel({
  onStart,
}: {
  onStart: (apps: { path: string; name: string; capture: AppCapture }[], minutes: number, label: string) => Promise<boolean>;
}) {
  const [apps, setApps] = useState<RunningApp[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<Map<string, AppCapture>>(new Map());
  const [minutes, setMinutes] = useState<number>(30);
  const [label, setLabel] = useState("");
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    window.shadow
      .request("list_running_apps")
      .then((r) => {
        setApps(r.apps);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);
  useEffect(load, [load]);

  const toggle = (path: string) =>
    setPicked((m) => {
      const next = new Map(m);
      if (next.has(path)) next.delete(path);
      else next.set(path, "full");
      return next;
    });
  const setCapture = (path: string, capture: AppCapture) =>
    setPicked((m) => {
      const next = new Map(m);
      next.set(path, capture);
      return next;
    });

  const q = query.trim().toLowerCase();
  const shown = (apps ?? []).filter((a) => !q || a.name.toLowerCase().includes(q));
  const chosen = (apps ?? []).filter((a) => picked.has(a.path));

  const start = async () => {
    setStarting(true);
    const ok = await onStart(
      chosen.map((a) => ({ path: a.path, name: a.name, capture: picked.get(a.path) ?? "full" })),
      minutes,
      label.trim(),
    );
    setStarting(false);
    if (ok) {
      setPicked(new Map());
      setLabel("");
    }
  };

  return (
    <section className="audit-card" aria-labelledby="start-title">
      <h2 id="start-title" className="h2">
        Start an audit
      </h2>
      <p className="muted small">
        Use these apps as you normally would. Only their traffic, and that of the processes they start, goes through Doppel;
        everything else on your computer, including your VPN and ad blocker, is left alone. Recording stops on its own.
      </p>

      <div className="toolbar">
        <label className="search">
          <SearchIcon />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find an app" aria-label="Find an app" />
        </label>
        <button className="btn btn-quiet btn-sm" onClick={load} disabled={loading} title="Reload the list of running apps">
          <RefreshIcon className={loading ? "spin" : undefined} /> Running apps
        </button>
      </div>
      {error && <p className="notice notice-error">{error}</p>}
      {!apps && !error && <p className="empty">Looking for running apps…</p>}
      {apps && (
        <ul className="app-pick" aria-label="Running apps">
          {shown.map((a) => {
            const on = picked.has(a.path);
            return (
              <li key={a.path} className={on ? "app-pick-row is-on" : "app-pick-row"}>
                <label className="app-pick-main" title={a.path}>
                  <input type="checkbox" checked={on} onChange={() => toggle(a.path)} />
                  <span className="row-name">{a.name}</span>
                  <span className="row-meta">
                    {a.is_browser ? "Browser · " : ""}
                    {a.processes} {a.processes === 1 ? "process" : "processes"}
                  </span>
                </label>
                {on && (
                  <div className="seg" role="group" aria-label={`What to record from ${a.name}`}>
                    <button aria-pressed={picked.get(a.path) === "full"} onClick={() => setCapture(a.path, "full")}>
                      Full
                    </button>
                    <button
                      aria-pressed={picked.get(a.path) === "metadata_only"}
                      onClick={() => setCapture(a.path, "metadata_only")}
                      title="Only which sites it contacts and how much it sends, not what"
                    >
                      Metadata only
                    </button>
                  </div>
                )}
                {on && a.hint && <p className="app-pick-hint small">{a.hint}</p>}
              </li>
            );
          })}
          {shown.length === 0 && <li className="empty">{apps.length ? "No running app matches." : "No apps are running."}</li>}
        </ul>
      )}
      <p className="muted small">
        Browsers are reported by the sites you visit; other apps by who they phone home to. Safari can't be audited: it
        loads pages in shared system processes.
      </p>

      <div className="audit-form">
        <div className="field">
          <span className="field-label">For</span>
          <div className="seg" role="group" aria-label="Duration">
            {DURATIONS.map((d) => (
              <button key={d.minutes} aria-pressed={minutes === d.minutes} onClick={() => setMinutes(d.minutes)}>
                {d.label}
              </button>
            ))}
          </div>
        </div>
        <label className="field">
          <span className="field-label">Name</span>
          <input
            className="text-input"
            value={label}
            maxLength={120}
            onChange={(e) => setLabel(e.target.value)}
            placeholder={chosen.length ? appList(chosen.map((a) => a.name)) : "Optional"}
          />
        </label>
        <button className="btn btn-primary" disabled={chosen.length === 0 || starting} onClick={() => void start()}>
          {starting ? "Starting…" : chosen.length ? `Audit ${appList(chosen.map((a) => a.name), 2)}` : "Pick at least one app"}
        </button>
      </div>
    </section>
  );
}

function LivePanel({ audit, onStop }: { audit: Audit; onStop: () => void }) {
  const [live, setLive] = useState<AuditLive | null>(null);
  const [now, setNow] = useState(Date.now());
  const [stopping, setStopping] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const poll = () =>
      window.shadow
        .request("audit_live", { audit_id: audit.id })
        .then((l) => !cancelled && setLive(l))
        .catch(() => undefined);
    void poll();
    const timer = window.setInterval(poll, 2000);
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
      window.clearInterval(tick);
    };
  }, [audit.id]);

  return (
    <section className="audit-card audit-live" aria-labelledby="live-title" aria-live="polite">
      <header className="audit-live-head">
        <div>
          <h2 id="live-title" className="h2">
            <span className="dot dot-ok" /> {audit.self_audit ? "Auditing Doppel itself" : `Auditing ${auditTitle(audit)}`}
          </h2>
          <p className="muted small">
            Keep using {audit.self_audit ? "Doppel" : appList(audit.apps.map((a) => a.name))} as usual. Nothing else is recorded.
          </p>
        </div>
        <div className="audit-clock">
          <span className="audit-countdown">{countdown(audit.ends_at, now)}</span>
          <span className="muted small">left</span>
        </div>
        <button
          className="btn btn-danger btn-sm"
          disabled={stopping}
          onClick={() => {
            setStopping(true);
            onStop();
          }}
        >
          <XIcon /> {stopping ? "Stopping…" : "Stop now"}
        </button>
      </header>

      <dl className="stats stats-sm">
        <div>
          <dt>Requests</dt>
          <dd>{num(live?.requests ?? 0)}</dd>
        </div>
        <div>
          <dt>Sites</dt>
          <dd>{num(live?.domains.length ?? 0)}</dd>
        </div>
        <div>
          <dt>Processes</dt>
          <dd>{num(live?.processes.length ?? 0)}</dd>
        </div>
        <div>
          <dt>Last request</dt>
          <dd className="small">{live?.last_at ? when(live.last_at) : "None yet"}</dd>
        </div>
      </dl>

      <div className="two-col">
        <section>
          <h3 className="h3">By process</h3>
          {live && live.processes.length > 0 ? (
            <ul className="count-list">
              {live.processes.map((p) => (
                <li key={`${p.app}\u0000${p.process}`}>
                  <span className="count-name">
                    {p.process} <span className="muted">({p.app})</span>
                  </span>
                  <span className="count-n">{num(p.requests)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">Waiting for traffic…</p>
          )}
        </section>
        <section>
          <h3 className="h3">Top sites</h3>
          {live && live.domains.length > 0 ? (
            <ul className="count-list">
              {live.domains.slice(0, 12).map((d) => (
                <li key={d.domain}>
                  <span className="count-name mono">{d.domain}</span>
                  <span className="count-n">{num(d.requests)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">None yet.</p>
          )}
        </section>
      </div>
    </section>
  );
}

function AnalyzingPanel({ progress }: { progress: ProgressEvent | null }) {
  const total = progress?.total ?? 0;
  const done = progress?.done ?? 0;
  return (
    <section className="audit-card" aria-live="polite">
      <h2 className="h2">Analysing the audit</h2>
      <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
        <span style={{ transform: `scaleX(${total ? Math.min(1, done / total) : 0})` }} />
      </div>
      <p className="muted small">{progress?.label ?? "Starting"}</p>
    </section>
  );
}

function PastAudits({
  audits,
  selectedId,
  onSelect,
  onDelete,
}: {
  audits: Audit[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onDelete: (audit: Audit) => void;
}) {
  const [deleting, setDeleting] = useState<Audit | null>(null);
  const past = audits.filter((a) => a.status !== "running");
  return (
    <section className="block">
      <h2 className="h2">Past audits</h2>
      {past.length === 0 ? (
        <p className="empty">No audits yet. Start your first one above.</p>
      ) : (
        <ul className="rows">
          {past.map((a) => (
            <li key={a.id} className="row audit-row">
              <button className="row-main" aria-current={a.id === selectedId ? "true" : undefined} onClick={() => onSelect(a.id)}>
                <span className="row-name">
                  {auditTitle(a)}
                  {a.self_audit && (
                    <span className="mini-chip self-chip">
                      <ShieldCheckIcon /> Self-audit
                    </span>
                  )}
                  {a.status !== "done" && <span className="mini-chip">{STATUS_LABELS[a.status]}</span>}
                </span>
                <span className="row-meta">
                  {[auditRange(a), auditDuration(a), `${num(a.requests)} ${a.requests === 1 ? "request" : "requests"}`].join(" · ")}
                </span>
              </button>
              <button className="btn btn-quiet btn-sm" onClick={() => setDeleting(a)}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
      {deleting && (
        <Modal
          title={`Delete “${auditTitle(deleting)}”?`}
          onClose={() => setDeleting(null)}
          footer={
            <>
              <button className="btn btn-quiet btn-sm" onClick={() => setDeleting(null)}>
                Cancel
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => {
                  const a = deleting;
                  setDeleting(null);
                  onDelete(a);
                }}
              >
                Delete
              </button>
            </>
          }
        >
          <p className="muted">
            Removes the audit and all {num(deleting.requests)} requests recorded in it. This can’t be undone.
          </p>
        </Modal>
      )}
    </section>
  );
}
