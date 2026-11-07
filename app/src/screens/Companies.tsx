import { useCallback, useEffect, useState } from "react";
import type { ActionName, CompanyDetail, CompanyRow, RequestRow } from "../shared/protocol";
import { RiskFilter, TierBadge, allTiers } from "../components/ui";
import { CheckIcon, EraserIcon, ExternalIcon, LandmarkIcon, MailIcon, ShieldOffIcon, UndoIcon } from "../components/icons";
import { emptyCounts, tierKey, type TierKey } from "../lib/tiers";
import { safeExternalLink } from "../lib/report";
import { SENSITIVE_TOPICS, flagLabel } from "../lib/signals";
import { monthDay, num, when } from "../lib/format";

// All captured and researched text is rendered as plain React text, never HTML.

const DROP_URL = "https://cppa.ca.gov/";

export function Companies({
  companies,
  selected,
  onSelect,
  onAct,
  onUndo,
  onOpenRequest,
  version,
}: {
  companies: CompanyRow[];
  selected: string | null;
  onSelect: (name: string) => void;
  onAct: (company: string, action: ActionName) => Promise<void>;
  onUndo: (company: string, action: "block" | "strip") => Promise<void>;
  onOpenRequest: (r: RequestRow, company: string) => void;
  /** Bumped after an action so the profile reloads. */
  version: number;
}) {
  const [filter, setFilter] = useState<Set<TierKey>>(allTiers);
  const counts = emptyCounts();
  companies.forEach((c) => counts[tierKey(c.tier)]++);
  const shown = companies.filter((c) => filter.has(tierKey(c.tier)));
  const current = companies.find((c) => c.name === selected) ?? companies[0];

  if (companies.length === 0) {
    return (
      <div className="view">
        <header className="view-head">
          <h1 className="title">Companies</h1>
        </header>
        <p className="empty">No companies received data since you last opened.</p>
      </div>
    );
  }

  return (
    <div className="view split">
      <div className="list-pane">
        <RiskFilter value={filter} onChange={setFilter} counts={counts} />
        <ul className="company-list">
          {shown.map((c) => (
            <li key={c.name}>
              <button className="company-item" aria-current={c.name === current.name ? "true" : undefined} onClick={() => onSelect(c.name)}>
                <TierBadge tier={c.tier} score={c.max_score} compact />
                <span className="company-item-name">{c.name}</span>
                {c.actions_taken.includes("block") && <span className="mini-chip">Blocked</span>}
              </button>
            </li>
          ))}
        </ul>
        {shown.length === 0 && <p className="empty">Select a risk level to see companies.</p>}
      </div>
      <Profile key={current.name} row={current} onAct={onAct} onUndo={onUndo} onOpenRequest={onOpenRequest} version={version} />
    </div>
  );
}

function Profile({
  row,
  onAct,
  onUndo,
  onOpenRequest,
  version,
}: {
  row: CompanyRow;
  onAct: (company: string, action: ActionName) => Promise<void>;
  onUndo: (company: string, action: "block" | "strip") => Promise<void>;
  onOpenRequest: (r: RequestRow, company: string) => void;
  version: number;
}) {
  const [detail, setDetail] = useState<CompanyDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    window.shadow
      .request("company_detail", { company: row.name })
      .then(setDetail)
      .catch((e: Error) => setError(e.message));
  }, [row.name]);
  useEffect(load, [load, version]);

  const done = new Set(row.actions_taken);
  const card = detail?.card;
  const optOut = card ? safeExternalLink(card.opt_out_url, card.opt_out_domain) : null;
  const available = new Set(detail?.actions ?? []);
  const apps = Object.entries(card?.exposure.apps ?? {}).sort((a, b) => b[1] - a[1]);
  const topics = Object.entries(card?.exposure.topics ?? {})
    .filter(([t]) => t && t !== "null" && t !== "Uncategorized")
    .sort((a, b) => b[1] - a[1]);
  const flags = Object.entries(card?.exposure.flags ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <article className="profile" aria-label={row.name}>
      <header className="profile-head">
        <div>
          <h1 className="title">{row.name}</h1>
          {row.category && <p className="muted">{row.category}</p>}
        </div>
        <TierBadge tier={row.tier} score={row.max_score} />
      </header>

      <div className="action-bar" role="group" aria-labelledby="actions-label">
        <span id="actions-label" className="action-bar-label">
          Actions
        </span>
        {(["block", "strip"] as const).map((a) =>
          done.has(a) ? (
            <span key={a} className="done-chip">
              <CheckIcon /> {a === "block" ? "Blocked" : "Stripping identifiers"}
              <button className="chip-undo" onClick={() => void onUndo(row.name, a)} aria-label={`Undo ${a}`} title="Undo">
                <UndoIcon />
              </button>
            </span>
          ) : available.has(a) && !(a === "strip" && done.has("block")) ? (
            <button
              key={a}
              className={a === "block" ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"}
              onClick={() => void onAct(row.name, a)}
            >
              {a === "block" ? <ShieldOffIcon /> : <EraserIcon />} {a === "block" ? "Block" : "Strip identifiers"}
            </button>
          ) : null,
        )}
        {optOut && card && (
          <a
            className="btn btn-secondary btn-sm"
            href={optOut}
            target="_blank"
            rel="noreferrer noopener"
            title={`Opens ${card.opt_out_domain} in your browser`}
            onClick={() => void onAct(row.name, "opt-out")}
          >
            <ExternalIcon /> Opt out
          </a>
        )}
        {available.has("letter") && (
          <button className="btn btn-secondary btn-sm" onClick={() => void onAct(row.name, "letter")}>
            <MailIcon /> {done.has("letter") ? "Request data again" : "Request data"}
          </button>
        )}
        {detail?.california && card?.is_data_broker && (
          <a className="btn btn-secondary btn-sm" href={DROP_URL} target="_blank" rel="noreferrer noopener" title="California Delete Request and Opt-out Platform (cppa.ca.gov)">
            <LandmarkIcon /> Delete via DROP
          </a>
        )}
      </div>

      {error && <p className="notice notice-error">{error}</p>}

      <dl className="stats stats-sm">
        <div>
          <dt>Apps</dt>
          <dd>{row.apps.length}</dd>
        </div>
        <div>
          <dt>Requests</dt>
          <dd>{num(row.requests)}</dd>
        </div>
        <div>
          <dt>Data broker</dt>
          <dd>{card?.is_data_broker == null ? "Unknown" : card.is_data_broker ? "Yes" : "No"}</dd>
        </div>
      </dl>

      {!detail && !error && <p className="empty">Loading…</p>}
      {card && detail && (
        <>
          <div className="halves">
            <section className="half">
              <h2 className="h2">Observed</h2>
              <h3 className="h3">Apps</h3>
              <ul className="site-chips">
                {apps.map(([app, n]) => (
                  <li key={app} className="site-chip" title={`${num(n)} requests`}>
                    {app === "null" ? "Unknown app" : app}
                  </li>
                ))}
              </ul>
              {topics.length > 0 && (
                <>
                  <h3 className="h3">Topics</h3>
                  <ul className="site-chips">
                    {topics.map(([t, n]) => (
                      <li
                        key={t}
                        className={SENSITIVE_TOPICS.has(t) ? "site-chip is-sensitive" : "site-chip"}
                        title={`${SENSITIVE_TOPICS.has(t) ? "Sensitive. " : ""}${num(n)} requests`}
                      >
                        {t}
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {flags.length > 0 && (
                <>
                  <h3 className="h3">What was sent</h3>
                  <ul className="plain">
                    {flags.map(([f, n]) => (
                      <li key={f}>
                        {flagLabel(f)} <span className="muted">({num(n)})</span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </section>

            <section className="half">
              <h2 className="h2">Research</h2>
              {card.policy_summary ? (
                <>
                  <h3 className="h3">Policy</h3>
                  <p>{card.policy_summary}</p>
                </>
              ) : (
                <p className="muted">No research yet for this company.</p>
              )}
              {card.news.length > 0 && (
                <>
                  <h3 className="h3">News</h3>
                  <ul className="plain">
                    {card.news.map((n) => (
                      <li key={n}>{n}</li>
                    ))}
                  </ul>
                </>
              )}
              {card.sources.length > 0 && (
                <>
                  <h3 className="h3">Sources</h3>
                  <ol className="sources">
                    {card.sources.map((s) => (
                      <li key={s} title={s}>
                        {s}
                      </li>
                    ))}
                  </ol>
                </>
              )}
              {(card.researched_at || card.from_snapshot) && (
                <p className="muted small research-note">
                  {card.from_snapshot ? "From the bundled snapshot" : "Researched"}
                  {card.researched_at ? ` ${monthDay(new Date(card.researched_at))}` : ""}
                </p>
              )}
            </section>
          </div>

          <section className="block">
            <h2 className="h2">Requests</h2>
            <ul className="rows">
              {detail.requests.map((r) => (
                <li key={r.id}>
                  <button className="row row-button" onClick={() => onOpenRequest(r, row.name)}>
                    <TierBadge tier={r.tier} score={r.score} compact />
                    <span className="row-main">
                      <span className="row-name">{r.summary}</span>
                      <span className="row-meta">
                        {r.app_name ?? "Unknown app"}, {when(r.captured_at)}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </article>
  );
}
