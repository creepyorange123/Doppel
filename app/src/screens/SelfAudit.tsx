import { useEffect, useState } from "react";
import type { Audit, SelfAuditResult } from "../shared/protocol";
import { AlertIcon, CheckIcon, ShieldCheckIcon, XIcon } from "../components/icons";
import { SELF_AUDIT_DURATIONS, auditDuration, auditRange, countdown } from "../lib/audit";
import { num } from "../lib/format";

/** "Audit Doppel itself": records Doppel's own processes with the same recorder used for
 *  any other app, then checks every connection against the outgoing-calls ledger. */
export function SelfAudit({
  active,
  latest,
  analyzing,
  onStart,
  onStop,
}: {
  active: Audit | null;
  latest: Audit | null;
  analyzing: boolean;
  onStart: (minutes: number) => void;
  onStop: () => void;
}) {
  const [minutes, setMinutes] = useState<number>(5);
  const [result, setResult] = useState<SelfAuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const running = active?.self_audit ? active : null;

  useEffect(() => {
    if (!latest || latest.status === "running" || analyzing) return;
    window.shadow
      .request("self_audit_result", { audit_id: latest.id })
      .then((r) => {
        setResult(r);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, [latest, analyzing]);

  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [running]);

  return (
    <section className="audit-card self-audit" aria-labelledby="self-title">
      <h2 id="self-title" className="h2">
        <ShieldCheckIcon /> Audit Doppel itself
      </h2>
      <p className="muted small">
        Don’t take our word for it. This runs the same recorder on Doppel’s own processes (the window and the analyzer) while
        you use Doppel normally. Every connection it makes should be one of the company-name searches in Outgoing calls, or
        there should be none at all.
      </p>

      {running ? (
        <div className="self-row">
          <span>
            <span className="dot dot-ok" /> Recording Doppel · {countdown(running.ends_at, now)} left
          </span>
          <button className="btn btn-quiet btn-sm" onClick={onStop}>
            Stop now
          </button>
        </div>
      ) : analyzing && latest?.self_audit ? (
        <p className="muted small">Checking what Doppel sent…</p>
      ) : (
        <div className="self-row">
          <div className="seg" role="group" aria-label="Self-audit duration">
            {SELF_AUDIT_DURATIONS.map((m) => (
              <button key={m} aria-pressed={minutes === m} onClick={() => setMinutes(m)}>
                {m} min
              </button>
            ))}
          </div>
          <button className="btn btn-primary btn-sm" disabled={Boolean(active)} onClick={() => onStart(minutes)}>
            {active ? "Another audit is running" : "Start self-audit"}
          </button>
        </div>
      )}

      {error && <p className="notice notice-error">{error}</p>}
      {result && !running && <SelfAuditVerdict result={result} />}
    </section>
  );
}

const VERDICTS: Record<SelfAuditResult["verdict"], string> = {
  no_traffic: "Doppel made no connections at all.",
  clean: "Every connection Doppel made is in the outgoing-calls ledger.",
  unexpected: "Doppel made connections that are not in the outgoing-calls ledger.",
};

function SelfAuditVerdict({ result }: { result: SelfAuditResult }) {
  const bad = result.verdict === "unexpected";
  return (
    <div className="self-result">
      <p className={`proof-summary ${bad ? "proof-bad" : "proof-ok"}`} role="status">
        {bad ? <AlertIcon /> : <CheckIcon />}
        {VERDICTS[result.verdict]}
      </p>
      <p className="muted small">
        Last self-audit: {auditRange(result.audit)} ({auditDuration(result.audit)}).{" "}
        {result.ledger_entries
          ? `${num(result.ledger_entries)} outgoing ${result.ledger_entries === 1 ? "call was" : "calls were"} logged in that time.`
          : "No outgoing calls were logged in that time."}
        {bad ? ` ${num(result.unexpected)} unexpected.` : ""}
      </p>
      {result.connections.length > 0 && (
        <ul className="count-list">
          {result.connections.map((c) => (
            <li key={`${c.process}\u0000${c.domain}`} className={c.in_ledger ? undefined : "is-unexpected"}>
              <span className="count-name">
                <span className="mono">{c.domain}</span> <span className="muted">({c.process})</span>
              </span>
              <span className={c.in_ledger ? "mini-chip" : "mini-chip chip-warn"}>
                {c.in_ledger ? <CheckIcon /> : <XIcon />} {c.in_ledger ? "In ledger" : "Not in ledger"}
              </span>
              <span className="count-n">{num(c.requests)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
