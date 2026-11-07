import { describe, expect, it } from "vitest";
import { ACTION_LABELS, summaryLine, tierClass, safeExternalLink } from "./report";

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

describe("tierClass", () => {
  it("maps every tier", () => {
    expect(tierClass("High concern")).toBe("tier tier-high");
    expect(tierClass("Profile-building")).toBe("tier tier-profile");
    expect(tierClass("Moderate")).toBe("tier tier-moderate");
    expect(tierClass("Low")).toBe("tier tier-low");
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
