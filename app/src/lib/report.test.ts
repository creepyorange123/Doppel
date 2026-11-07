import { describe, expect, it } from "vitest";
import { ACTION_LABELS, summaryLine, safeExternalLink } from "./report";
import { countsByKey, tierKey } from "./tiers";

describe("summaryLine", () => {
  it("matches the plan's wording", () => {
    expect(summaryLine({ since: 0, requests: 1240, companies: 38, high_concern: 12 })).toBe(
      "Since you last opened: 1,240 requests to 38 companies, 12 high concern.",
    );
  });
  it("handles singulars and nothing new", () => {
    expect(summaryLine({ since: 0, requests: 1, companies: 1, high_concern: 0 })).toBe(
      "Since you last opened: 1 request to 1 company, none high concern.",
    );
    expect(summaryLine({ since: 0, requests: 0, companies: 0, high_concern: 0 })).toBe(
      "Nothing new since you last opened.",
    );
  });
});

describe("tiers", () => {
  it("maps every analyzer tier to a display level", () => {
    expect(tierKey("High concern")).toBe("high");
    expect(tierKey("Profile-building")).toBe("profile");
    expect(tierKey("Moderate")).toBe("measurement");
    expect(tierKey("Low")).toBe("minimum");
    expect(countsByKey({ Low: 2, "High concern": 1 })).toEqual({ high: 1, profile: 0, measurement: 0, minimum: 2 });
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
  expect(Object.keys(ACTION_LABELS).sort()).toEqual(["block", "letter", "opt-out", "strip"]);
});
