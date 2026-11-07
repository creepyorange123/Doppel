import { describe, expect, it } from "vitest";
import { recorderHealth, RULE_LABELS } from "./health";

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
