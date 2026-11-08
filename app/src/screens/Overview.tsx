import type { Report } from "../shared/protocol";
import { DayChart, TierBadge, TierBar } from "../components/ui";
import { AlertIcon, CheckIcon, ShieldOffIcon } from "../components/icons";
import { countsByKey, tierKey } from "../lib/tiers";
import { num, when } from "../lib/format";

export function Overview({
  report,
  notice,
  onDismissNotice,
  onOpenCompany,
  onBlock,
}: {
  report: Report;
  notice: string | null;
  onDismissNotice: () => void;
  onOpenCompany: (name: string) => void;
  onBlock: (name: string) => void;
}) {
  const { summary, companies } = report;
  const count = (k: string) => companies.filter((c) => tierKey(c.tier) === k).length;
  const risky = companies.filter((c) => ["high", "profile"].includes(tierKey(c.tier)));
  const days = report.by_day.map((d) => ({ date: d.date, counts: countsByKey(d.counts) }));

  return (
    <div className="view">
      {notice && (
        <div className="notice" role="status">
          <AlertIcon />
          <p>{notice}</p>
          <button className="btn btn-quiet btn-sm" onClick={onDismissNotice}>
            Dismiss
          </button>
        </div>
      )}
      <header className="view-head">
        <h1 className="title">Overview</h1>
        <p className="muted">{summary.since ? `Since ${when(summary.since)}` : "Since you installed Doppel"}</p>
      </header>
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
          <dt>Severe risk</dt>
          <dd>{count("high")}</dd>
        </div>
        <div>
          <dt>High risk</dt>
          <dd>{count("profile")}</dd>
        </div>
      </dl>

      <section className="block">
        <h2 className="h2">Highest risk</h2>
        {risky.length === 0 ? (
          <p className="empty">Nothing high risk since you last opened.</p>
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
                {c.actions_taken.includes("block") ? (
                  <span className="done-chip">
                    <CheckIcon /> Blocked
                  </span>
                ) : (
                  <button className="btn btn-quiet btn-sm" onClick={() => onBlock(c.name)}>
                    <ShieldOffIcon /> Block
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

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
