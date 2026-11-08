import { describe, expect, it } from "vitest";
import { certificateStatus } from "./certificate";

describe("certificateStatus", () => {
  it("reads recorder status output", () => {
    const ok = certificateStatus(JSON.stringify({ ca: { valid: true, expires: "2026-12-01T00:00:00+00:00", sha1: "x" } }));
    expect(ok).toMatchObject({ installed: true, valid: true, state: "ok" });
    expect(ok.expires?.toISOString()).toBe("2026-12-01T00:00:00.000Z");
    expect(certificateStatus(JSON.stringify({ ca: { valid: false } }))).toMatchObject({ installed: true, valid: false, text: "Expired" });
    expect(certificateStatus(JSON.stringify({ ca: null }))).toMatchObject({ installed: false, text: "Not installed" });
  });
  it("is unknown when the output can't be read", () => {
    expect(certificateStatus(null).text).toBe("Couldn't check");
    expect(certificateStatus("Traceback ...").text).toBe("Couldn't check");
  });
});
