import type { Audit } from "../shared/protocol";
import { STATUS_LABELS, appList, auditDuration, auditRange, auditTitle, labelIsAppNames } from "../lib/audit";
import { ShieldCheckIcon } from "./icons";

/** Which audit a report screen is showing. */
export function AuditHeader({ title, audit }: { title: string; audit: Audit }) {
  return (
    <header className="view-head">
      <h1 className="title">{title}</h1>
      <p className="muted">
        {audit.self_audit && (
          <span className="mini-chip self-chip">
            <ShieldCheckIcon /> Self-audit
          </span>
        )}{" "}
        {auditTitle(audit)}
        {labelIsAppNames(audit) ? "" : ` (${appList(audit.apps.map((a) => a.name))})`} · {auditRange(audit)} · {auditDuration(audit)}
        {audit.status !== "done" ? ` · ${STATUS_LABELS[audit.status]}` : ""}
      </p>
    </header>
  );
}

/** Shown on report screens before any audit exists or is selected. */
export function NoAudit({ title, onStart }: { title: string; onStart: () => void }) {
  return (
    <div className="view">
      <header className="view-head">
        <h1 className="title">{title}</h1>
      </header>
      <div className="empty-state">
        <p>Doppel only looks at traffic during an audit. Pick the apps you want to check and use them for a while.</p>
        <button className="btn btn-primary" onClick={onStart}>
          Start your first audit
        </button>
      </div>
    </div>
  );
}
