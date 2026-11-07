import { useEffect, useRef, type ReactNode } from "react";
import type { BreakdownItem, Tier } from "../shared/protocol";
import { TIER_INFO, TIER_KEYS, tierKey, type TierKey } from "../lib/tiers";
import { dayLabel, num } from "../lib/format";
import { XIcon } from "./icons";

// All captured and researched text is rendered as plain React text, never HTML.

export function TierBadge({ tier, score, compact = false }: { tier: Tier; score?: number; compact?: boolean }) {
  const k = tierKey(tier);
  const info = TIER_INFO[k];
  return (
    <span className={`tier tier-${k}`} title={`${info.label} risk (${info.range}). ${info.behavior}: ${info.meaning}`}>
      {score !== undefined && <span className="tier-score">{score}</span>}
      {!compact && <span className="tier-label">{info.label}</span>}
    </span>
  );
}

export function TierBar({ totals }: { totals: Record<TierKey, number> }) {
  const total = TIER_KEYS.reduce((s, k) => s + totals[k], 0);
  return (
    <div className="tierbar">
      <div className="tierbar-track" role="img" aria-label="Requests by risk level">
        {TIER_KEYS.map((k) => (
          <span key={k} className={`tierbar-seg fill-${k}`} style={{ flexGrow: totals[k] }} />
        ))}
      </div>
      <ul className="tierbar-legend">
        {TIER_KEYS.map((k) => (
          <li key={k} title={`${TIER_INFO[k].behavior}: ${TIER_INFO[k].meaning}`}>
            <span className={`swatch fill-${k}`} />
            <span className="tierbar-name">{TIER_INFO[k].label}</span>
            <span className="tierbar-count">{num(totals[k])}</span>
            <span className="tierbar-pct">{total ? Math.round((totals[k] / total) * 100) : 0}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface DayCounts {
  date: string;
  counts: Record<TierKey, number>;
}

const W = 440;
const H = 170;
const PAD = { l: 36, r: 8, t: 10, b: 26 };
const STACK: TierKey[] = ["minimum", "measurement", "profile", "high"];

export function DayChart({ days }: { days: DayCounts[] }) {
  if (days.length === 0) return <p className="empty">No requests yet.</p>;
  const shown = days.slice(-14);
  const totals = shown.map((d) => STACK.reduce((s, k) => s + d.counts[k], 0));
  const step = Math.max(...totals) > 100 ? 100 : 10;
  const max = Math.max(step, Math.ceil(Math.max(...totals) / step) * step);
  const colW = (W - PAD.l - PAD.r) / shown.length;
  const y = (v: number) => PAD.t + (H - PAD.t - PAD.b) * (1 - v / max);
  const longRange = shown.length > 7;
  return (
    <svg className="daychart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Requests per day by risk">
      {[0, max / 2, max].map((v) => (
        <g key={v}>
          <line x1={PAD.l} x2={W - PAD.r} y1={y(v)} y2={y(v)} className="grid" />
          <text x={PAD.l - 6} y={y(v) + 4} textAnchor="end" className="axis">
            {num(v)}
          </text>
        </g>
      ))}
      {shown.map((d, i) => {
        let acc = 0;
        const x = PAD.l + i * colW + colW * 0.25;
        const w = colW * 0.5;
        const label = dayLabel(d.date, longRange);
        return (
          <g key={d.date}>
            {STACK.map((k) => {
              const v = d.counts[k];
              const rect = (
                <rect key={k} x={x} width={w} y={y(acc + v)} height={Math.max(0, y(acc) - y(acc + v))} className={`fill-${k}`} />
              );
              acc += v;
              return rect;
            })}
            {(!longRange || i % 2 === shown.length % 2) && (
              <text x={x + w / 2} y={162} textAnchor="middle" className="axis">
                {label}
              </text>
            )}
            <title>{`${dayLabel(d.date, true)}: ${num(totals[i])} requests, ${num(d.counts.high)} severe risk`}</title>
          </g>
        );
      })}
    </svg>
  );
}

export function RiskFilter({
  value,
  onChange,
  counts,
}: {
  value: Set<TierKey>;
  onChange: (v: Set<TierKey>) => void;
  counts: Record<TierKey, number>;
}) {
  return (
    <fieldset className="risk-filter">
      <legend className="sr-only">Risk</legend>
      {TIER_KEYS.map((k) => (
        <label key={k} className="risk-opt" title={`${TIER_INFO[k].behavior}: ${TIER_INFO[k].meaning}`}>
          <input
            type="checkbox"
            checked={value.has(k)}
            onChange={(e) => {
              const next = new Set(value);
              if (e.target.checked) next.add(k);
              else next.delete(k);
              onChange(next);
            }}
          />
          <span className={`risk-swatch fill-${k}`} aria-hidden />
          {TIER_INFO[k].label}
          <span className="risk-count">{counts[k]}</span>
        </label>
      ))}
    </fieldset>
  );
}

export const allTiers = () => new Set<TierKey>(TIER_KEYS);

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} className="toggle" onClick={() => onChange(!checked)}>
      <span className="toggle-knob" />
    </button>
  );
}

function useEscape(onClose: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
}

export function Modal({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEscape(onClose);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    return () => prev?.focus();
  }, []);
  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <header className="modal-head">
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <XIcon />
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  );
}

export function Drawer({
  label,
  onClose,
  flush = false,
  children,
}: {
  label: string;
  onClose: () => void;
  flush?: boolean;
  children: ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);
  useEscape(onClose);
  useEffect(() => ref.current?.focus(), []);
  return (
    <div className="drawer-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className={flush ? "drawer drawer-flush" : "drawer"} role="dialog" aria-modal="true" aria-label={label} tabIndex={-1} ref={ref}>
        {children}
      </aside>
    </div>
  );
}

export interface ToastItem {
  id: number;
  text: string;
}

export function Toasts({ items, onDismiss }: { items: ToastItem[]; onDismiss: (id: number) => void }) {
  return (
    <div className="toasts" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className="toast">
          <span>{t.text}</span>
          <button className="icon-btn" onClick={() => onDismiss(t.id)} aria-label="Dismiss">
            <XIcon />
          </button>
        </div>
      ))}
    </div>
  );
}

export function Breakdown({ items, score }: { items: BreakdownItem[]; score: number }) {
  return (
    <table className="breakdown">
      <tbody>
        {items.length === 0 && (
          <tr>
            <td className="muted">No signals</td>
            <td className="bd-pts">0</td>
          </tr>
        )}
        {items.map((b) => (
          <tr key={b.signal}>
            <td>{b.label}</td>
            <td className={b.points < 0 ? "bd-pts neg" : "bd-pts"}>{b.points > 0 ? `+${b.points}` : `−${Math.abs(b.points)}`}</td>
          </tr>
        ))}
      </tbody>
      <tfoot>
        <tr className="bd-total">
          <td>Total{items.reduce((s, b) => s + b.points, 0) > score ? " (max 100)" : ""}</td>
          <td className="bd-pts">{score}</td>
        </tr>
      </tfoot>
    </table>
  );
}

const JSON_TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

/** Syntax-coloured JSON built from text nodes (never HTML). */
export function JsonView({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2) ?? "null";
  const parts: ReactNode[] = [];
  let last = 0;
  let key = 0;
  JSON_TOKEN.lastIndex = 0;
  for (let m = JSON_TOKEN.exec(text); m; m = JSON_TOKEN.exec(text)) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) {
      parts.push(
        <span key={key++} className={m[2] ? "j-key" : "j-str"}>
          {m[1]}
        </span>,
      );
      if (m[2]) parts.push(m[2]);
    } else if (m[3]) {
      parts.push(
        <span key={key++} className="j-lit">
          {m[3]}
        </span>,
      );
    } else if (m[4]) {
      parts.push(
        <span key={key++} className="j-num">
          {m[4]}
        </span>,
      );
    }
    last = JSON_TOKEN.lastIndex;
  }
  parts.push(text.slice(last));
  return <pre className="json">{parts}</pre>;
}
