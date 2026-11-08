import { describe, expect, it } from "vitest";
import { appList, auditRange, auditTitle, countdown, durationLabel, labelIsAppNames } from "./audit";

describe("audit helpers", () => {
  it("formats durations", () => {
    expect(durationLabel(20_000)).toBe("under a minute");
    expect(durationLabel(45 * 60_000)).toBe("45 min");
    expect(durationLabel(60 * 60_000)).toBe("1 h");
    expect(durationLabel(65 * 60_000)).toBe("1 h 5 min");
  });

  it("counts down and stops at zero", () => {
    expect(countdown(1_000 + 754_000, 1_000)).toBe("12:34");
    expect(countdown(3_723_000, 0)).toBe("1:02:03");
    expect(countdown(0, 5_000)).toBe("0:00");
  });

  it("lists apps", () => {
    expect(appList(["Slack"])).toBe("Slack");
    expect(appList(["Slack", "Zoom"])).toBe("Slack and Zoom");
    expect(appList(["A", "B", "C", "D", "E"])).toBe("A, B, C and 2 more");
    expect(auditTitle({ label: "", apps: [{ name: "Slack", path: "/A/Slack.app", capture: "full", is_browser: false }] })).toBe("Slack");
    expect(auditTitle({ label: "Work apps", apps: [] })).toBe("Work apps");
    const app = (name: string) => ({ name, path: `/A/${name}.app`, capture: "full" as const, is_browser: false });
    expect(labelIsAppNames({ label: "Discord, Zen", apps: [app("Discord"), app("Zen")] })).toBe(true);
    expect(labelIsAppNames({ label: "Evening browsing", apps: [app("Zen")] })).toBe(false);
  });

  it("shows a same-day range once", () => {
    const start = new Date(2026, 10, 8, 14, 0).getTime();
    expect(auditRange({ started_at: start, ends_at: start + 30 * 60_000, ended_at: null })).toBe("Nov 8, 2:00 pm – 2:30 pm");
  });
});
