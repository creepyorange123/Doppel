import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { LedgerEntry, LedgerVerify } from "../shared/protocol";
import { Drawer, JsonView } from "../components/ui";
import { SearchIcon, XIcon } from "../components/icons";
import { bytes, clock, monthDay, weekday } from "../lib/format";
import { payloadSummary, serviceName } from "../lib/signals";

const size = (e: LedgerEntry) => new TextEncoder().encode(JSON.stringify(e.payload)).length;

function Service({ host }: { host: string }) {
  const name = serviceName(host);
  return <span className={`svc svc-${name === host ? "other" : name.toLowerCase()}`}>{name}</span>;
}

/** "What left this device": every outgoing call, hash-chained by the analyzer. */
export function Ledger() {
  const [data, setData] = useState<{ entries: LedgerEntry[]; latest_hash: string } | null>(null);
  const [verify, setVerify] = useState<LedgerVerify | null>(null);
  const [service, setService] = useState("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [tab, setTab] = useState<"payload" | "details">("payload");
  const rows = useRef<Record<number, HTMLTableRowElement | null>>({});

  useEffect(() => {
    window.shadow.request("ledger_list").then(setData);
  }, []);

  const entries = useMemo(() => data?.entries ?? [], [data]);
  const services = useMemo(() => [...new Set(entries.map((e) => serviceName(e.destination)))].sort(), [entries]);
  const q = query.trim().toLowerCase();
  const shown = useMemo(
    () =>
      entries.filter(
        (e) => (service === "all" || serviceName(e.destination) === service) && (!q || payloadSummary(e.payload).toLowerCase().includes(q)),
      ),
    [entries, service, q],
  );
  const current = shown.find((e) => e.id === open) ?? null;
  const sent = shown.reduce((s, e) => s + size(e), 0);

  useEffect(() => {
    if (open !== null) rows.current[open]?.scrollIntoView({ block: "nearest" });
  }, [open]);

  const step = useCallback(
    (d: number) => {
      const i = shown.findIndex((e) => e.id === open);
      const next = shown[Math.min(shown.length - 1, Math.max(0, i + d))];
      if (next) setOpen(next.id);
    },
    [shown, open],
  );

  useEffect(() => {
    if (open === null) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      e.preventDefault();
      step(e.key === "ArrowDown" ? 1 : -1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, step]);

  return (
    <div className="ledger-layout">
      <header className="ledger-head">
        <div>
          <h1 className="title">Outgoing calls</h1>
          <p className="muted">
            {shown.length} {shown.length === 1 ? "call" : "calls"}, {bytes(sent)} sent. Nothing else leaves this computer.
          </p>
        </div>
        <div className="toolbar">
          <label className="search">
            <SearchIcon />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter" aria-label="Filter calls" />
          </label>
          {services.length > 0 && (
            <div className="seg" role="group" aria-label="Service">
              <button aria-pressed={service === "all"} onClick={() => setService("all")}>
                All <span className="seg-count">{entries.length}</span>
              </button>
              {services.map((s) => (
                <button key={s} aria-pressed={service === s} onClick={() => setService(s)}>
                  {(s === "Tavily" || s === "Exa") && <span className={`svc-dot svc-dot-${s.toLowerCase()}`} />} {s}{" "}
                  <span className="seg-count">{entries.filter((e) => serviceName(e.destination) === s).length}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </header>

      <div className="chain-bar">
        <span className="muted">
          Chained by hash, so any edit or deletion shows. Latest <span className="mono">{data?.latest_hash.slice(0, 16)}…</span>
        </span>
        {verify ? (
          <span className={verify.ok ? "status-ok" : "status-bad"}>
            {!verify.ok && <XIcon />}
            {verify.ok ? `Chain intact (${verify.entries} entries)` : `Chain broken at entry ${verify.broken_at}. The ledger was edited.`}
          </span>
        ) : null}
        <button className="btn btn-quiet btn-sm" onClick={() => window.shadow.request("ledger_verify").then(setVerify)}>
          Verify
        </button>
      </div>

      <div className="net-wrap">
        <table className="net-table">
          <colgroup>
            <col className="col-time" />
            <col className="col-svc" />
            <col />
            <col className="col-num" />
          </colgroup>
          <thead>
            <tr>
              <th scope="col">Time</th>
              <th scope="col">Service</th>
              <th scope="col">Query</th>
              <th scope="col" className="num">
                Sent
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map((e) => {
              const at = new Date(e.sent_at);
              return (
                <tr
                  key={e.id}
                  ref={(el) => {
                    rows.current[e.id] = el;
                  }}
                  tabIndex={0}
                  aria-selected={e.id === open}
                  onClick={() => setOpen(e.id)}
                  onKeyDown={(ev) => ev.key === "Enter" && setOpen(e.id)}
                >
                  <td className="dim" title={`${weekday(at)} ${monthDay(at)}`}>
                    {clock(at, true)}
                  </td>
                  <td>
                    <Service host={e.destination} />
                  </td>
                  <td className="ellipsis" title={payloadSummary(e.payload)}>
                    {payloadSummary(e.payload)}
                  </td>
                  <td className="num dim">{bytes(size(e))}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {data && shown.length === 0 && <p className="empty">{entries.length ? "No matches." : "Nothing has left this device."}</p>}
        {!data && <p className="empty">Loading…</p>}
      </div>

      {current && (
        <Drawer label="Call details" onClose={() => setOpen(null)} flush>
          <header className="insp-head">
            <div className="insp-row">
              <Service host={current.destination} />
              <span className="dim insp-meta">
                {weekday(new Date(current.sent_at))} {monthDay(new Date(current.sent_at))} {clock(new Date(current.sent_at), true)}
              </span>
              <button className="icon-btn insp-close" onClick={() => setOpen(null)} aria-label="Close panel">
                <XIcon />
              </button>
            </div>
            <p className="insp-url">POST https://{current.destination}</p>
          </header>
          <div className="tabs insp-tabs" role="tablist">
            {(
              [
                ["payload", "Payload"],
                ["details", "Details"],
              ] as const
            ).map(([id, label]) => (
              <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>
                {label}
              </button>
            ))}
          </div>
          <div className="insp-body" role="tabpanel">
            {tab === "payload" && <JsonView value={current.payload} />}
            {tab === "details" && (
              <section className="kv-block">
                <h3 className="kv-title">Ledger entry</h3>
                <dl className="kv-grid">
                  <div>
                    <dt>Entry</dt>
                    <dd>{current.id}</dd>
                  </div>
                  <div>
                    <dt>Destination</dt>
                    <dd>{current.destination}</dd>
                  </div>
                  <div>
                    <dt>Time</dt>
                    <dd>{new Date(current.sent_at).toUTCString()}</dd>
                  </div>
                  <div>
                    <dt>Size</dt>
                    <dd>{bytes(size(current))}</dd>
                  </div>
                  <div>
                    <dt>Hash</dt>
                    <dd className="mono">{current.hash}</dd>
                  </div>
                </dl>
              </section>
            )}
          </div>
        </Drawer>
      )}
    </div>
  );
}
