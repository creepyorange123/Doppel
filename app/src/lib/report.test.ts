import { describe, expect, it } from "vitest";
import { ACTION_LABELS, summaryLine, safeExternalLink } from "./report";
import { countsByKey, TIER_INFO, TIER_KEYS, tierKey } from "./tiers";

describe("summaryLine", () => {
  it("matches the plan's wording", () => {
    expect(summaryLine({ requests: 1240, companies: 38, high_concern: 12 })).toBe(
      "1,240 requests to 38 companies, 12 high concern.",
    );
  });
  it("handles singulars and an empty audit", () => {
    expect(summaryLine({ requests: 1, companies: 1, high_concern: 0 })).toBe("1 request to 1 company, none high concern.");
    expect(summaryLine({ requests: 0, companies: 0, high_concern: 0 })).toBe("No requests were recorded in this audit.");
  });
});

describe("tiers", () => {
  it("maps every analyzer tier to a display level", () => {
    expect(tierKey("High concern")).toBe("high");
    expect(tierKey("Profile building")).toBe("profile");
    expect(tierKey("Measurement")).toBe("measurement");
    expect(tierKey("Minimum utility")).toBe("minimum");
    expect(
      countsByKey({ "Minimum utility": 2, Measurement: 3, "Profile building": 4, "High concern": 1 }),
    ).toEqual({ high: 1, profile: 4, measurement: 3, minimum: 2 });
  });
  it("labels and ranges match analyzer/score.py", () => {
    expect(TIER_KEYS.map((k) => [TIER_INFO[k].label, TIER_INFO[k].range])).toEqual([
      ["High concern", "80–100"],
      ["Profile building", "50–79"],
      ["Measurement", "20–49"],
      ["Minimum utility", "0–19"],
    ]);
  });
});

describe("safeExternalLink", () => {
  it("allows https on the stated domain only", () => {
    expect(safeExternalLink("https://www.criteo.com/x", "www.criteo.com")).toBe("https://www.criteo.com/x");
    expect(safeExternalLink("https://evil.example/x", "www.criteo.com")).toBeNull();
    expect(safeExternalLink("javascript:alert(1)", "www.criteo.com")).toBeNull();
    expect(safeExternalLink(null, null)).toBeNull();
  });
});

it("labels every action", () => {
  expect(Object.keys(ACTION_LABELS).sort()).toEqual(["letter", "opt-out"]);
});
