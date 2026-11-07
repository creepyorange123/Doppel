import type { ActionName, ReportSummary } from "../shared/protocol";

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

export function summaryLine(s: ReportSummary): string {
  if (s.requests === 0) return "Nothing new since you last opened.";
  const high = s.high_concern === 0 ? "none" : s.high_concern.toLocaleString("en-US");
  return `Since you last opened: ${plural(s.requests, "request", "requests")} to ${plural(
    s.companies,
    "company",
    "companies",
  )}, ${high} high concern.`;
}

export const ACTION_LABELS: Record<ActionName, string> = {
  block: "Block this company",
  strip: "Strip identifiers",
  "opt-out": "Open opt-out page",
  letter: "Data access request letter",
};

/** Only https links whose host is exactly the domain shown to the user. */
export function safeExternalLink(url: string | null, domain: string | null): string | null {
  if (!url || !domain) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" && u.hostname === domain ? u.toString() : null;
  } catch {
    return null;
  }
}
