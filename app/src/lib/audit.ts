import type { Audit, AuditStatus } from "../shared/protocol";
import { clock, monthDay } from "./format";

export const DURATIONS = [
  { minutes: 15, label: "15 min" },
  { minutes: 30, label: "30 min" },
  { minutes: 60, label: "1 h" },
  { minutes: 120, label: "2 h" },
] as const;

export const SELF_AUDIT_DURATIONS = [2, 5, 15] as const;

/** "1 h 5 min", "45 min", "under a minute". */
export function durationLabel(ms: number): string {
  const min = Math.round(ms / 60_000);
  if (min < 1) return "under a minute";
  const h = Math.floor(min / 60);
  const m = min % 60;
  if (!h) return `${m} min`;
  return m ? `${h} h ${m} min` : `${h} h`;
}

/** Time left as "12:34" or "1:02:03"; "0:00" once past. */
export function countdown(endsAt: number, now: number = Date.now()): string {
  const total = Math.max(0, Math.ceil((endsAt - now) / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = (total % 60).toString().padStart(2, "0");
  return h ? `${h}:${m.toString().padStart(2, "0")}:${s}` : `${m}:${s}`;
}

/** "Nov 8, 2:00 pm – 2:30 pm" (end is the actual end, or the planned one while running). */
export function auditRange(a: Pick<Audit, "started_at" | "ends_at" | "ended_at">): string {
  const start = new Date(a.started_at);
  const end = new Date(a.ended_at ?? a.ends_at);
  const sameDay = start.toDateString() === end.toDateString();
  return `${monthDay(start)}, ${clock(start)} – ${sameDay ? "" : `${monthDay(end)}, `}${clock(end)}`;
}

export function auditDuration(a: Pick<Audit, "started_at" | "ends_at" | "ended_at">): string {
  return durationLabel((a.ended_at ?? a.ends_at) - a.started_at);
}

export const STATUS_LABELS: Record<AuditStatus, string> = {
  running: "Recording",
  done: "Finished",
  interrupted: "Interrupted",
  failed: "Failed",
};

/** "Slack, Zoom and 2 more". */
export function appList(names: string[], max = 3): string {
  if (names.length === 0) return "No apps";
  if (names.length <= max) {
    return names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  }
  return `${names.slice(0, max).join(", ")} and ${names.length - max} more`;
}

/** True when the label is just the app names (the analyzer's default), so they needn't be repeated. */
export function labelIsAppNames(a: Pick<Audit, "label" | "apps">): boolean {
  return !a.label || a.label === a.apps.map((x) => x.name).join(", ").slice(0, 120);
}

export function auditTitle(a: Pick<Audit, "label" | "apps">): string {
  return a.label || appList(a.apps.map((x) => x.name));
}
