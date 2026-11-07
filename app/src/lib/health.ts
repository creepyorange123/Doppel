import type { CaptureRule } from "../shared/protocol";

export const STALE_AFTER_MS = 2 * 60 * 1000;

export const RULE_LABELS: Record<CaptureRule, string> = {
  track: "Track fully",
  metadata_only: "Metadata only",
  dont_track: "Don't track",
};

export function humanDuration(ms: number): string {
  const min = Math.round(ms / 60_000);
  if (min < 60) return `${min} minute${min === 1 ? "" : "s"}`;
  const h = Math.round(min / 60);
  if (h < 48) return `${h} hour${h === 1 ? "" : "s"}`;
  const d = Math.round(h / 24);
  return `${d} days`;
}

export function recorderHealth(heartbeat: number | null, now: number = Date.now()) {
  if (heartbeat === null) {
    return { state: "never" as const, message: "The recorder has not run yet, so nothing has been logged." };
  }
  const gap = now - heartbeat;
  if (gap <= STALE_AFTER_MS) return { state: "ok" as const, message: "The recorder is running." };
  return {
    state: "stale" as const,
    message: `The recorder hasn't been seen for ${humanDuration(gap)}. Traffic in that gap was not logged.`,
  };
}
