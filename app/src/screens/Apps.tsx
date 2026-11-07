import { useCallback, useEffect, useState } from "react";
import type { AppEntry, AppList, CaptureRule } from "../shared/protocol";
import { RULE_LABELS } from "../lib/health";
import { Modal } from "../components/ui";
import { num, when } from "../lib/format";

const RULES: CaptureRule[] = ["track", "metadata_only", "dont_track"];

export function Apps({ onToast }: { onToast: (text: string) => void }) {
  const [data, setData] = useState<AppList | null>(null);
  const [domain, setDomain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<AppEntry | null>(null);

  const load = useCallback(() => {
    window.shadow
      .request("list_apps")
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const run = (p: Promise<unknown>, toast?: string) =>
    p
      .then(() => {
        load();
        if (toast) onToast(toast);
      })
      .catch((e: Error) => setError(e.message));

  if (!data) return <p className="empty">{error ?? "Loading apps…"}</p>;
  const defaultRule: CaptureRule = data.mode === "allowlist" ? "dont_track" : "track";

  return (
    <div className="view">
      <header className="view-head">
        <h1 className="title">Apps</h1>
        <p className="muted">Choose what the recorder logs from each app. System processes are never logged.</p>
      </header>
      {error && <p className="notice notice-error">{error}</p>}

      <div className="pref">
        <span className="pref-name">Default</span>
        <div className="seg" role="group" aria-label="Tracking mode">
          <button aria-pressed={data.mode === "blocklist"} onClick={() => run(window.shadow.request("set_tracking_mode", { mode: "blocklist" }))}>
            Track everything except blocked
          </button>
          <button aria-pressed={data.mode === "allowlist"} onClick={() => run(window.shadow.request("set_tracking_mode", { mode: "allowlist" }))}>
            Track only allowed
          </button>
        </div>
      </div>

      <div className="table-wrap block">
        <table className="apps-table">
          <thead>
            <tr>
              <th scope="col">App</th>
              <th scope="col" className="num">
                Requests
              </th>
              <th scope="col">Last seen</th>
              <th scope="col">Rule</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {data.apps.map((a) => (
              <tr key={a.key}>
                <td title={a.path}>
                  <span className="row-name">{a.name ?? a.path}</span>
                  {a.running && <span className="mini-chip">Running</span>}
                  {a.rule_source === "auto" && (
                    <span className="mini-chip" title="This app pins its certificates, so only metadata can be logged">
                      Pinned certificate
                    </span>
                  )}
                </td>
                <td className="num">{num(a.requests)}</td>
                <td className="cell-time">{a.last_seen_at ? when(a.last_seen_at) : "—"}</td>
                <td>
                  <select
                    className="select"
                    aria-label={`Rule for ${a.name ?? a.path}`}
                    value={a.rule ?? ""}
                    onChange={(e) => run(window.shadow.request("set_app_rule", { key: a.key, rule: e.target.value || null }))}
                  >
                    <option value="">Default ({RULE_LABELS[defaultRule]})</option>
                    {RULES.map((r) => (
                      <option key={r} value={r}>
                        {RULE_LABELS[r]}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="num">
                  {a.requests > 0 && (
                    <button className="btn btn-quiet btn-sm" onClick={() => setDeleting(a)}>
                      Delete data
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.apps.length === 0 && <p className="empty">No apps seen yet.</p>}
      </div>

      <section className="block">
        <h2 className="h2">Sites</h2>
        <p className="muted small">Site rules apply across every app, for example: never log anything sent to my bank.</p>
        <ul className="rows">
          {data.domains.map((d) => (
            <li key={d.domain} className="row site-row">
              <span className="row-main">
                <span className="row-name mono">{d.domain}</span>
                <span className="row-meta">{RULE_LABELS[d.rule]}</span>
              </span>
              <button className="btn btn-quiet btn-sm" onClick={() => run(window.shadow.request("set_domain_rule", { domain: d.domain, rule: null }))}>
                Remove
              </button>
            </li>
          ))}
        </ul>
        <form
          className="site-form"
          onSubmit={(e) => {
            e.preventDefault();
            const d = domain.trim();
            run(window.shadow.request("set_domain_rule", { domain: d, rule: "dont_track" }), `${d} will never be logged`).then(() => setDomain(""));
          }}
        >
          <label className="search">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="mybank.com" aria-label="Site" />
          </label>
          <button type="submit" className="btn btn-secondary btn-sm" disabled={!domain.trim()}>
            Never log this site
          </button>
        </form>
      </section>

      {deleting && (
        <Modal
          title={`Delete data from ${deleting.name ?? deleting.path}?`}
          onClose={() => setDeleting(null)}
          footer={
            <>
              <button className="btn btn-quiet btn-sm" onClick={() => setDeleting(null)}>
                Cancel
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => {
                  const label = deleting.name ?? deleting.path;
                  setDeleting(null);
                  void run(window.shadow.request("delete_app_data", { key: deleting.key }), `Deleted data from ${label}`);
                }}
              >
                Delete
              </button>
            </>
          }
        >
          <p className="muted">All {num(deleting.requests)} logged requests from this app. This can’t be undone.</p>
        </Modal>
      )}
    </div>
  );
}
