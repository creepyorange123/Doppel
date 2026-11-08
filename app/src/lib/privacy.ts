import type { PrivacyCheck } from "../shared/protocol";

export function privacySummary(checks: PrivacyCheck[]): { text: string; state: "ok" | "bad" | "none" } {
  const failed = checks.filter((c) => c.ok === false).length;
  const passed = checks.filter((c) => c.ok === true).length;
  if (failed) return { text: `${failed} problem${failed === 1 ? "" : "s"} found`, state: "bad" };
  if (!passed) return { text: "No checks apply yet", state: "none" };
  return { text: `All ${passed} check${passed === 1 ? "" : "s"} passed`, state: "ok" };
}
