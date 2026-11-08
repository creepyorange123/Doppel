// Mirrors analyzer/score.py LABELS and analyzer/topics.py SENSITIVE_TOPICS.

export const FLAG_LABELS: Record<string, string> = {
  // Sensitive data inside the request (analyzer/datatypes.py).
  data_health: "Health information",
  data_sexuality: "Information about sexuality",
  data_religion: "Religious information",
  data_children: "Information about children",
  data_politics: "Political information",
  data_ethnicity: "Information about ethnicity",
  data_finance: "Banking or financial details",
  data_personal: "Personal details (name, birth date, address, gender or ID)",
  data_location: "Your precise location",
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

/** Flags for sensitive data found inside the request itself. */
export const isDataFlag = (flag: string) => flag.startsWith("data_");

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
