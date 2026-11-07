import { useCallback, useEffect, useState } from "react";
import type { AppList as AppListData, CaptureRule } from "../shared/protocol";
import { RULE_LABELS } from "../lib/health";

const RULES: CaptureRule[] = ["track", "metadata_only", "dont_track"];

export function AppList() {
  const [data, setData] = useState<AppListData | null>(null);
  const [domain, setDomain] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    window.shadow.request("list_apps").then(setData).catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const run = (p: Promise<unknown>) => p.then(load).catch((e: Error) => setError(e.message));

  if (!data) return <p className="muted">Loading apps…</p>;
  const defaultRule: CaptureRule = data.mode === "allowlist" ? "dont_track" : "track";

  return (
    <section>
      <h2>Apps</h2>
      {error && <p className="error">{error}</p>}
      <fieldset className="row">
        <label>
          <input
            type="radio"
            checked={data.mode === "blocklist"}
            onChange={() => run(window.shadow.request("set_tracking_mode", { mode: "blocklist" }))}
          />
          Track everything except my blocklist
        </label>
        <label>
          <input
            type="radio"
            checked={data.mode === "allowlist"}
            onChange={() => run(window.shadow.request("set_tracking_mode", { mode: "allowlist" }))}
          />
          Track only my allowlist
        </label>
      </fieldset>

      <table className="list">
        <thead>
          <tr>
            <th>App</th>
            <th>Requests</th>
            <th>Rule</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data.apps.map((a) => (
            <tr key={a.key}>
              <td title={a.path}>
                {a.name ?? a.path}
                {a.running && <span className="tag">running</span>}
                {a.rule_source === "auto" && <span className="tag">pinned certificate</span>}
              </td>
              <td>{a.requests.toLocaleString()}</td>
              <td>
                <select
                  value={a.rule ?? ""}
                  onChange={(e) =>
                    run(window.shadow.request("set_app_rule", { key: a.key, rule: e.target.value || null }))
                  }
                >
                  <option value="">Default ({RULE_LABELS[defaultRule]})</option>
                  {RULES.map((r) => (
                    <option key={r} value={r}>
                      {RULE_LABELS[r]}
                    </option>
                  ))}
                </select>
              </td>
              <td>
                {a.requests > 0 && (
                  <button
                    onClick={() => {
                      const label = a.name ?? a.path;
                      if (confirm(`Delete all ${a.requests} logged requests from ${label}? This cannot be undone.`))
                        run(window.shadow.request("delete_app_data", { key: a.key }));
                    }}
                  >
                    Delete its data
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Sites</h3>
      <p className="muted">Site rules apply across every app, for example: never log anything sent to my bank.</p>
      <ul className="plain">
        {data.domains.map((d) => (
          <li key={d.domain} className="row">
            <span>{d.domain}</span>
            <span className="muted">{RULE_LABELS[d.rule]}</span>
            <button onClick={() => run(window.shadow.request("set_domain_rule", { domain: d.domain, rule: null }))}>
              Remove
            </button>
          </li>
        ))}
      </ul>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          run(window.shadow.request("set_domain_rule", { domain, rule: "dont_track" }).then(() => setDomain("")));
        }}
      >
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="mybank.com" />
        <button type="submit" disabled={!domain.trim()}>
          Never log this site
        </button>
      </form>
    </section>
  );
}
