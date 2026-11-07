import { useCallback, useEffect, useState } from "react";
import type { ActionName, CompanyDetail, Report as ReportData, RequestRow, Settings } from "../shared/protocol";
import { ACTION_LABELS, safeExternalLink, summaryLine, tierClass } from "../lib/report";

// All captured and researched text is rendered as plain React text, never HTML.

function TierBadge({ row }: { row: RequestRow }) {
  const [open, setOpen] = useState(false);
  return (
    <span>
      <button className={tierClass(row.tier)} onClick={() => setOpen(!open)} title="Why this score?">
        {row.tier} · {row.score}
      </button>
      {open && (
        <ul className="breakdown">
          {row.breakdown.length === 0 && <li>No signals.</li>}
          {row.breakdown.map((b) => (
            <li key={b.signal}>
              <span>{b.label}</span>
              <span className="pts">+{b.points}</span>
            </li>
          ))}
        </ul>
      )}
    </span>
  );
}

function CompanyPanel({ name, onChanged }: { name: string; onChanged: () => void }) {
  const [detail, setDetail] = useState<CompanyDetail | null>(null);
  const [letter, setLetter] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    window.shadow.request("company_detail", { company: name }).then(setDetail);
  }, [name]);
  useEffect(load, [load]);

  if (!detail) return <p className="muted">Loading…</p>;
  const { card } = detail;
  const optOut = safeExternalLink(card.opt_out_url, card.opt_out_domain);

  const act = async (action: ActionName) => {
    if (action === "opt-out") return;
    const res = await window.shadow.request("take_action", { company: name, action });
    if (res.letter) setLetter(res.letter);
    if (action === "block") setMsg(`Blocked. Requests to ${name} stop from now on, even while this window is closed.`);
    if (action === "strip") setMsg(`Identifiers will be removed from requests to ${name} from now on.`);
    onChanged();
  };

  return (
    <div className="panel">
      <section className="card">
        <h3>{card.name}</h3>
        {card.is_data_broker && <p className="warning">Registered data broker.</p>}
        <ul className="plain card-lines">
          {card.lines.map((l, i) => (
            <li key={i}>
              <span className={l.kind === "measured" ? "tag measured" : "tag inferred"}>{l.kind}</span> {l.text}
              {l.source && <span className="muted small"> — source: {l.source}</span>}
            </li>
          ))}
        </ul>
        {!card.policy_summary && <p className="muted">No research yet for this company.</p>}
        {card.from_snapshot && <p className="muted small">Research from the bundled, signed snapshot.</p>}
      </section>

      <div className="row">
        {detail.actions.map((a) =>
          a === "opt-out" && optOut ? (
            <a key={a} className="button" href={optOut} target="_blank" rel="noreferrer noopener">
              {ACTION_LABELS[a]} ({card.opt_out_domain})
            </a>
          ) : a === "opt-out" ? null : (
            <button key={a} onClick={() => void act(a)}>
              {ACTION_LABELS[a]}
            </button>
          ),
        )}
        {detail.california && (
          <a className="button" href="https://cppa.ca.gov/" target="_blank" rel="noreferrer noopener">
            California DROP (cppa.ca.gov)
          </a>
        )}
      </div>
      {msg && <p className="ok">{msg}</p>}
      {letter && (
        <>
          <p className="muted small">This letter is a template, not legal advice.</p>
          <textarea className="letter" readOnly value={letter} rows={16} />
        </>
      )}

      <h3>Requests behind this</h3>
      <ul className="plain requests">
        {detail.requests.map((r) => (
          <li key={r.id}>
            <TierBadge row={r} />
            <span className="muted"> {new Date(r.captured_at).toLocaleString()} · {r.app_name} · {r.dest_domain}</span>
            <div>{r.summary}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Report() {
  const [data, setData] = useState<ReportData | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(() => {
    window.shadow.request("report").then(setData);
    window.shadow.request("get_settings").then(setSettings);
  }, []);
  useEffect(load, [load]);

  if (!data) return <p className="muted">Building report…</p>;

  return (
    <section>
      <h2>{summaryLine(data.summary)}</h2>
      {settings && !settings.gpc && (
        <p className="row">
          <span className="muted">Global Privacy Control tells sites not to sell or share your data.</span>
          <button onClick={() => window.shadow.request("set_setting", { key: "gpc", value: true }).then(load)}>
            Turn on GPC
          </button>
        </p>
      )}
      <ul className="plain companies">
        {data.companies.map((c) => (
          <li key={c.name}>
            <button className="company" onClick={() => setOpen(open === c.name ? null : c.name)}>
              <span className={tierClass(c.tier)}>
                {c.tier} · {c.max_score}
              </span>
              <strong>{c.name}</strong>
              <span className="muted">
                {c.category} · {c.requests} {c.requests === 1 ? "request" : "requests"} · {c.apps.join(", ")}
              </span>
              {c.actions_taken.map((a) => (
                <span key={a} className="tag">
                  {a}
                </span>
              ))}
            </button>
            {open === c.name && <CompanyPanel name={c.name} onChanged={load} />}
          </li>
        ))}
      </ul>
    </section>
  );
}
