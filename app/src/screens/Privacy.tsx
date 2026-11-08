import { useCallback, useEffect, useState } from "react";
import type { Audit, PrivacyChecks } from "../shared/protocol";
import { SelfAudit } from "./SelfAudit";
import { CheckIcon, RefreshIcon, XIcon } from "../components/icons";
import { clock } from "../lib/format";
import { privacySummary } from "../lib/privacy";

/** Live proof of the privacy promises: every row is a check run on this computer just now. */
export function Privacy({
  active,
  latestSelfAudit,
  analyzing,
  onStartSelf,
  onStop,
}: {
  active: Audit | null;
  latestSelfAudit: Audit | null;
  analyzing: boolean;
  onStartSelf: (minutes: number) => void;
  onStop: () => void;
}) {
  const [data, setData] = useState<PrivacyChecks | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(() => {
    setRunning(true);
    setError(null);
    window.shadow
      .request("privacy_checks")
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setRunning(false));
  }, []);

  useEffect(run, [run]);

  const summary = data ? privacySummary(data.checks) : null;

  return (
    <div className="view">
      <header className="view-head view-head-row">
        <div>
          <h1 className="title">Privacy</h1>
          <p className="muted">
            Not promises: each line is a test run on the data on this computer
            {data ? ` at ${clock(new Date(data.ran_at), true)}` : ""}.
          </p>
        </div>
        <button className="btn btn-quiet btn-sm" onClick={run} disabled={running}>
          <RefreshIcon className={running ? "spin" : undefined} />
          {running ? "Checking…" : "Run again"}
        </button>
      </header>
      <SelfAudit active={active} latest={latestSelfAudit} analyzing={analyzing} onStart={onStartSelf} onStop={onStop} />
      <h2 className="h2 block">Checks on your data</h2>
      {error && <p className="notice notice-error">{error}</p>}
      {!data && !error && <p className="empty">Running checks…</p>}
      {data && summary && (
        <>
          <p className={`proof-summary proof-${summary.state}`} role="status">
            {summary.state === "bad" ? <XIcon /> : <CheckIcon />}
            {summary.text}
          </p>
          <ul className="proof-list">
            {data.checks.map((c) => {
              const state = c.ok === true ? "pass" : c.ok === false ? "fail" : "na";
              return (
                <li key={c.id} className={`proof proof-${state}`}>
                  <span className="proof-mark" aria-label={state === "pass" ? "Passed" : state === "fail" ? "Failed" : "Not applicable"}>
                    {state === "pass" ? <CheckIcon /> : state === "fail" ? <XIcon /> : "–"}
                  </span>
                  <span className="proof-body">
                    <span className="proof-title">{c.title}</span>
                    <span className="proof-detail">{c.detail}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
