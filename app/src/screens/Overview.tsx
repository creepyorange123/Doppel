import type { Report, ReportGroup } from "../shared/protocol";
import { DayChart, TierBadge, TierBar } from "../components/ui";
import { AuditHeader } from "../components/AuditHeader";
import { BlockWithYourTools } from "../components/BlockWithYourTools";
import { countsByKey, tierKey } from "../lib/tiers";
import { summaryLine } from "../lib/report";
import { num } from "../lib/format";

export function Overview({
  report,
  onOpenCompany,
  onToast,
}: {
  report: Report;
  onOpenCompany: (name: string) => void;
  onToast: (text: string) => void;
}) {
  const { summary, companies, audit } = report;
  const count = (k: string) => companies.filter((c) => tierKey(c.tier) === k).length;
  const risky = companies.filter((c) => ["high", "profile"].includes(tierKey(c.tier)));
  const days = report.by_day.map((d) => ({ date: d.date, counts: countsByKey(d.counts) }));

  return (
    <div className="view">
      <AuditHeader title="Overview" audit={audit} />
      <p className="lead">{summaryLine(summary)}</p>
      <dl className="stats">
        <div>
          <dt>Requests</dt>
          <dd>{num(summary.requests)}</dd>
        </div>
        <div>
          <dt>Companies</dt>
          <dd>{num(summary.companies)}</dd>
        </div>
        <div>
          <dt>High concern</dt>
          <dd>{count("high")}</dd>
        </div>
        <div>
          <dt>Profile building</dt>
          <dd>{count("profile")}</dd>
        </div>
      </dl>

      <section className="block">
        <h2 className="h2">By app</h2>
        {report.apps.length === 0 ? (
          <p className="empty">None of the audited apps sent anything.</p>
        ) : (
          <ul className="app-cards">
            {report.apps.map((a) => (
              <li key={a.name} className="app-card">
                <header className="app-card-head">
                  <TierBadge tier={a.tier} score={a.max_score} compact />
                  <span className="row-name">{a.name}</span>
                  <span className="row-meta">
                    {a.is_browser ? "Browser · " : ""}
                    {num(a.requests)} {a.requests === 1 ? "request" : "requests"} to {num(a.companies)}{" "}
                    {a.companies === 1 ? "company" : "companies"}
                  </span>
                </header>
                <GroupList
                  title={a.is_browser ? "Sites you visited" : "Phones home to"}
                  groups={(a.is_browser ? a.sites : a.destinations) ?? []}
                  empty={a.is_browser ? "No pages could be told apart." : "Nothing."}
                />
                {a.processes.length > 0 && (
                  <ul className="count-list" aria-label={`${a.name} processes`}>
                    {a.processes.map((p) => (
                      <li key={p.name}>
                        <span className="count-name">{p.name}</span>
                        <span className="count-n">{num(p.requests)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="block">
        <h2 className="h2">Highest risk</h2>
        {risky.length === 0 ? (
          <p className="empty">Nothing high risk in this audit.</p>
        ) : (
          <ul className="rows">
            {risky.map((c) => (
              <li key={c.name} className="row">
                <TierBadge tier={c.tier} score={c.max_score} compact />
                <button className="row-main" onClick={() => onOpenCompany(c.name)}>
                  <span className="row-name">{c.name}</span>
                  <span className="row-meta">
                    {[c.category, `${c.apps.length} ${c.apps.length === 1 ? "app" : "apps"}`, `${num(c.requests)} requests`]
                      .filter(Boolean)
                      .join(", ")}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <BlockWithYourTools auditId={audit.id} onToast={onToast} />

      <h2 className="title section-title">Statistics</h2>
      <div className="two-col">
        <section>
          <h2 className="h2">By risk</h2>
          <TierBar totals={countsByKey(report.tier_requests)} />
        </section>
        <section>
          <h2 className="h2">By day</h2>
          <DayChart days={days} />
        </section>
      </div>
    </div>
  );
}

/** Browsers: each site and the companies it brought along. Apps: who they phone home to. */
function GroupList({ title, groups, empty }: { title: string; groups: ReportGroup[]; empty: string }) {
  const shown = groups.slice(0, 8);
  return (
    <div className="group-list">
      <h3 className="group-title">{title}</h3>
      {shown.length === 0 ? (
        <p className="muted small">{empty}</p>
      ) : (
        <ul>
          {shown.map((g) => (
            <li key={`${g.name}`}>
              <TierBadge tier={g.tier} score={g.max_score} compact />
              <span className="group-name">{g.own ? <em>{g.name}</em> : g.name}</span>
              <span className="group-meta">
                {g.companies.length > 0 && g.name !== g.companies[0]
                  ? `${g.companies.slice(0, 3).join(", ")}${g.companies.length > 3 ? ` +${g.companies.length - 3}` : ""}`
                  : `${num(g.requests)} ${g.requests === 1 ? "request" : "requests"}`}
              </span>
            </li>
          ))}
          {groups.length > shown.length && <li className="muted small">and {groups.length - shown.length} more</li>}
        </ul>
      )}
    </div>
  );
}
