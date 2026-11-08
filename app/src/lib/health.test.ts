import { describe, expect, it } from "vitest";
import { recorderHealth, recorderRunning, recorderStatusLine, RULE_LABELS } from "./health";

describe("recorderHealth", () => {
  const now = 1_000_000_000;
  it("reports never when no heartbeat", () => expect(recorderHealth(null, now).state).toBe("never"));
  it("is ok within two minutes", () => expect(recorderHealth(now - 60_000, now).state).toBe("ok"));
  it("reports a gap after two minutes", () => {
    const h = recorderHealth(now - 3 * 3_600_000, now);
    expect(h.state).toBe("stale");
    expect(h.message).toMatch(/3 hours/);
  });
});

describe("RULE_LABELS", () => {
  it("has plain labels for every rule", () => {
    expect(RULE_LABELS.track).toBe("Track fully");
    expect(RULE_LABELS.metadata_only).toBe("Metadata only");
    expect(RULE_LABELS.dont_track).toBe("Don't track");
  });
});

describe("recorderRunning", () => {
  it("reads running from status output", () => {
    expect(recorderRunning(JSON.stringify({ running: true, requests_logged: 3 }))).toBe(true);
    expect(recorderRunning(JSON.stringify({ running: false }))).toBe(false);
  });
  it("is unknown for garbage or missing field", () => {
    expect(recorderRunning("Traceback ...")).toBeNull();
    expect(recorderRunning("{}")).toBeNull();
  });
});

describe("recorderStatusLine", () => {
  const now = 1_000_000_000;
  it("is red as soon as the recorder is turned off, even with a fresh heartbeat", () =>
    expect(recorderStatusLine(false, now - 1000, now)).toEqual({ text: "Recorder off", state: "warn" }));
  it("is green when running with a fresh heartbeat", () =>
    expect(recorderStatusLine(true, now - 1000, now)).toEqual({ text: "Recorder on", state: "ok" }));
  it("is green right after turning on, before the first heartbeat", () =>
    expect(recorderStatusLine(true, null, now).state).toBe("ok"));
  it("warns when running but no heartbeat for minutes", () =>
    expect(recorderStatusLine(true, now - 10 * 60_000, now)).toEqual({ text: "Recorder not responding", state: "warn" }));
  it("falls back to the heartbeat when the state is unknown", () => {
    expect(recorderStatusLine(null, now - 1000, now).state).toBe("ok");
    expect(recorderStatusLine(null, now - 10 * 60_000, now)).toEqual({ text: "Recorder stopped", state: "warn" });
    expect(recorderStatusLine(null, null, now)).toEqual({ text: "Recorder not started", state: "off" });
  });
});
