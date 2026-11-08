export interface CertificateStatus {
  installed: boolean;
  valid: boolean;
  expires: Date | null;
  text: string;
  state: "ok" | "warn" | "off";
}

/** Reads `recorder status` JSON ({ca: null | {valid, expires}}); null output = unknown. */
export function certificateStatus(output: string | null): CertificateStatus {
  const unknown: CertificateStatus = { installed: false, valid: false, expires: null, text: "Couldn't check", state: "off" };
  if (output === null) return unknown;
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    return unknown;
  }
  if (!parsed || typeof parsed !== "object" || !("ca" in parsed)) return unknown;
  const ca = (parsed as { ca: unknown }).ca;
  if (ca === null) return { installed: false, valid: false, expires: null, text: "Not installed", state: "warn" };
  if (!ca || typeof ca !== "object") return unknown;
  const c = ca as { valid?: unknown; expires?: unknown };
  const expires = typeof c.expires === "string" && !Number.isNaN(Date.parse(c.expires)) ? new Date(c.expires) : null;
  return c.valid === true
    ? { installed: true, valid: true, expires, text: "Installed", state: "ok" }
    : { installed: true, valid: false, expires, text: "Expired", state: "warn" };
}
