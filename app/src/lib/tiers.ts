import type { Tier } from "../shared/protocol";

/** Display keys for the analyzer's four tiers (they double as CSS class suffixes). */
export type TierKey = "minimum" | "measurement" | "profile" | "high";

/** Most severe first. */
export const TIER_KEYS: TierKey[] = ["high", "profile", "measurement", "minimum"];

export const TIER_KEY: Record<Tier, TierKey> = {
  "Minimum utility": "minimum",
  Measurement: "measurement",
  "Profile building": "profile",
  "High concern": "high",
};

// Names, score ranges and meanings match analyzer/score.py TIERS and the README.
export const TIER_INFO: Record<TierKey, { label: string; behavior: string; range: string; meaning: string }> = {
  minimum: {
    label: "Minimum utility",
    behavior: "Essential",
    range: "0–19",
    meaning: "needed for the app or page to work, with no identifier that follows you",
  },
  measurement: {
    label: "Measurement",
    behavior: "Analytics",
    range: "20–49",
    meaning: "counts your visit or behaviour on one site, not across sites",
  },
  profile: {
    label: "Profile building",
    behavior: "Tracking",
    range: "50–79",
    meaning: "links your activity across sites or ties it to an identity",
  },
  high: {
    label: "High concern",
    behavior: "Profiling",
    range: "80–100",
    meaning: "profile building plus sensitive topics, personal identifiers or data sharing",
  },
};

export function tierKey(tier: Tier): TierKey {
  return TIER_KEY[tier] ?? "minimum";
}

export function emptyCounts(): Record<TierKey, number> {
  return { high: 0, profile: 0, measurement: 0, minimum: 0 };
}

/** Converts a {Tier: n} map from the analyzer to display keys. */
export function countsByKey(counts: Partial<Record<Tier, number>>): Record<TierKey, number> {
  const out = emptyCounts();
  for (const [tier, n] of Object.entries(counts) as [Tier, number][]) out[tierKey(tier)] += n;
  return out;
}
