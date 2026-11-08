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

/** Whether `recorder status` says the recorder process is running; null if unknown. */
export function recorderRunning(statusOutput: string): boolean | null {
  try {
    const parsed: unknown = JSON.parse(statusOutput);
    if (parsed && typeof parsed === "object" && typeof (parsed as { running?: unknown }).running === "boolean") {
      return (parsed as { running: boolean }).running;
    }
  } catch {
    // not JSON: fall through
  }
  return null;
}

export interface RecorderLine {
  text: string;
  state: "ok" | "warn" | "off";
}

/** Sidebar/Settings status for the recorder. `running` (is the process alive) wins
 *  over the heartbeat, so the dot changes the moment the recorder is turned on or off. */
export function recorderStatusLine(running: boolean | null, heartbeat: number | null, now: number = Date.now()): RecorderLine {
  const health = recorderHealth(heartbeat, now);
  if (running === false) return { text: "Recorder off", state: "warn" };
  if (running === true) {
    return health.state === "stale" ? { text: "Recorder not responding", state: "warn" } : { text: "Recorder on", state: "ok" };
  }
  if (health.state === "ok") return { text: "Recorder on", state: "ok" };
  if (health.state === "never") return { text: "Recorder not started", state: "off" };
  return { text: "Recorder stopped", state: "warn" };
}
