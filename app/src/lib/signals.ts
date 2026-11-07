// Mirrors analyzer/score.py LABELS and analyzer/topics.py SENSITIVE_TOPICS.

export const FLAG_LABELS: Record<string, string> = {
  raw_email: "Your email address",
  hashed_email: "A hash of your email",
  hashed_phone: "A hash of your phone number",
  cross_site_id: "The same ID seen on other sites or apps",
  tracking_id: "A long-lived ID",
  cookie_syncing: "The same ID shared between companies",
  fingerprinting: "Device fingerprinting values",
  behavioural_events: "Mouse or keyboard activity",
  email_address: "An email address",
  page_url: "The page you were on",
  cname_cloaked: "Disguised as the site's own address",
};

export const SENSITIVE_TOPICS = new Set([
  "Medical Health",
  "Healthy Living",
  "Personal Finance",
  "Dating",
  "Religion & Spirituality",
]);

export const flagLabel = (flag: string) => FLAG_LABELS[flag] ?? flag.replace(/_/g, " ");

/** Short service name for an outgoing-call host, e.g. api.tavily.com -> Tavily. */
export function serviceName(host: string): string {
  const h = host.toLowerCase();
  if (h === "tavily.com" || h.endsWith(".tavily.com")) return "Tavily";
  if (h === "exa.ai" || h.endsWith(".exa.ai")) return "Exa";
  return host;
}

/** The human-readable part of an outgoing payload: its query, if it has one. */
export function payloadSummary(payload: Record<string, unknown>): string {
  for (const key of ["query", "q", "company", "url"]) {
    const v = payload[key];
    if (typeof v === "string" && v) return v;
  }
  return JSON.stringify(payload);
}
