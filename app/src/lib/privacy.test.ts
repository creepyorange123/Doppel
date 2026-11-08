import { describe, expect, it } from "vitest";
import { privacySummary } from "./privacy";

const c = (ok: boolean | null) => ({ id: "x", title: "t", detail: "d", ok });

describe("privacySummary", () => {
  it("counts only checks that apply", () =>
    expect(privacySummary([c(true), c(true), c(null)])).toEqual({ text: "All 2 checks passed", state: "ok" }));
  it("leads with problems", () =>
    expect(privacySummary([c(true), c(false), c(false)])).toEqual({ text: "2 problems found", state: "bad" }));
  it("singular problem", () => expect(privacySummary([c(false)]).text).toBe("1 problem found"));
  it("nothing applicable", () => expect(privacySummary([c(null)]).state).toBe("none"));
});
