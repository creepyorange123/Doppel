import { useCallback, useEffect, useState } from "react";
import type { LedgerEntry, LedgerVerify, Settings as SettingsData } from "../shared/protocol";

const TOGGLES: { key: keyof SettingsData; label: string; help: string }[] = [
  {
    key: "zero_network",
    label: "Zero-network mode",
    help: "Turns off company research entirely. Profile cards then come from the bundled snapshot and nothing leaves this computer.",
  },
  { key: "gpc", label: "Global Privacy Control", help: "Adds the Sec-GPC signal to every request the recorder can see." },
  { key: "local_ai", label: "Use the local AI model (Ollama)", help: "Runs on this computer only. Off: keyword rules and templates." },
  { key: "california", label: "I live in California", help: "Shows the California DROP option on company pages." },
];

export function Settings() {
  const [s, setS] = useState<SettingsData | null>(null);
  const [ledger, setLedger] = useState<{ entries: LedgerEntry[]; latest_hash: string } | null>(null);
  const [verify, setVerify] = useState<LedgerVerify | null>(null);

  const load = useCallback(() => {
    window.shadow.request("get_settings").then(setS);
    window.shadow.request("ledger_list").then(setLedger);
  }, []);
  useEffect(load, [load]);

  if (!s) return <p className="muted">Loading…</p>;
  return (
    <section>
      <h2>Settings</h2>
      {TOGGLES.map((t) => (
        <label key={t.key} className="toggle">
          <input
            type="checkbox"
            checked={Boolean(s[t.key])}
            onChange={(e) => window.shadow.request("set_setting", { key: t.key, value: e.target.checked }).then(load)}
          />
          <span>
            <strong>{t.label}</strong>
            <br />
            <span className="muted">{t.help}</span>
          </span>
        </label>
      ))}

      <h2>What left this device</h2>
      <p className="muted">
        Every outgoing call, chained by hash so any edit or deletion shows. Latest hash:{" "}
        <code>{ledger?.latest_hash.slice(0, 16)}…</code>
      </p>
      <div className="row">
        <button onClick={() => window.shadow.request("ledger_verify").then(setVerify)}>Verify</button>
        {verify && (
          <span className={verify.ok ? "ok" : "error"}>
            {verify.ok
              ? `Chain intact (${verify.entries} entries).`
              : `Chain broken at entry ${verify.broken_at}. The ledger was edited.`}
          </span>
        )}
      </div>
      <table className="list">
        <thead>
          <tr>
            <th>When</th>
            <th>To</th>
            <th>What was sent</th>
          </tr>
        </thead>
        <tbody>
          {ledger?.entries.length === 0 && (
            <tr>
              <td colSpan={3} className="muted">
                Nothing has left this device.
              </td>
            </tr>
          )}
          {ledger?.entries.map((e) => (
            <tr key={e.id}>
              <td>{new Date(e.sent_at).toLocaleString()}</td>
              <td>{e.destination}</td>
              <td>
                <code>{JSON.stringify(e.payload)}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
