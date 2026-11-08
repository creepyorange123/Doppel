import { useEffect, useState } from "react";
import type { Audit, RequestListItem } from "../shared/protocol";
import { AuditHeader } from "../components/AuditHeader";
import { RiskFilter, TierBadge, allTiers } from "../components/ui";
import { SearchIcon } from "../components/icons";
import { emptyCounts, tierKey, type TierKey } from "../lib/tiers";
import { num, when } from "../lib/format";

export function Requests({
  audit,
  onOpenRequest,
}: {
  audit: Audit;
  onOpenRequest: (r: RequestListItem) => void;
}) {
  const [data, setData] = useState<{ requests: RequestListItem[]; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Set<TierKey>>(allTiers);
  const [query, setQuery] = useState("");

  useEffect(() => {
    window.shadow
      .request("list_requests", { audit_id: audit.id })
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [audit.id]);

  const requests = data?.requests ?? [];
  const counts = emptyCounts();
  requests.forEach((r) => counts[tierKey(r.tier)]++);
  const q = query.trim().toLowerCase();
  const shown = requests.filter(
    (r) =>
      filter.has(tierKey(r.tier)) &&
      (!q || [r.summary, r.company, r.app_name, r.process_name, r.dest_domain].some((v) => v?.toLowerCase().includes(q))),
  );

  return (
    <div className="view requests">
      <AuditHeader title="Requests" audit={audit} />
      {data?.truncated && <p className="muted small">Newest {num(requests.length)} shown.</p>}
      <div className="toolbar">
        <label className="search">
          <SearchIcon />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search" aria-label="Search requests" />
        </label>
        <RiskFilter value={filter} onChange={setFilter} counts={counts} />
      </div>
      {error && <p className="notice notice-error">{error}</p>}
      <div className="table-wrap">
        <table className="req-table">
          <thead>
            <tr>
              <th scope="col">Score</th>
              <th scope="col">Sent</th>
              <th scope="col">Company</th>
              <th scope="col">App</th>
              <th scope="col">Time</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id} tabIndex={0} onClick={() => onOpenRequest(r)} onKeyDown={(e) => e.key === "Enter" && onOpenRequest(r)}>
                <td>
                  <TierBadge tier={r.tier} score={r.score} compact />
                </td>
                <td className="cell-summary">{r.summary}</td>
                <td>{r.company ?? <span className="muted">First party</span>}</td>
                <td>
                  {r.app_name ?? "Unknown"}
                  {r.process_name && r.process_name !== r.app_name && <span className="cell-sub">{r.process_name}</span>}
                  {r.sensitive && <span className="sensitive">Sensitive</span>}
                </td>
                <td className="cell-time">{when(r.captured_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!data && !error && <p className="empty">Loading…</p>}
        {data && shown.length === 0 && <p className="empty">{requests.length ? "No matches." : "No requests in this audit."}</p>}
      </div>
    </div>
  );
}
