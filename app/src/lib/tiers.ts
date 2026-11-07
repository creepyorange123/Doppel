import type { Tier } from "../shared/protocol";

/** Display keys for the analyzer's four tiers (they double as CSS class suffixes). */
export type TierKey = "minimum" | "measurement" | "profile" | "high";

/** Most severe first. */
export const TIER_KEYS: TierKey[] = ["high", "profile", "measurement", "minimum"];

export const TIER_KEY: Record<Tier, TierKey> = {
  Low: "minimum",
  Moderate: "measurement",
  "Profile-building": "profile",
  "High concern": "high",
};

export const TIER_OF_KEY: Record<TierKey, Tier> = {
  minimum: "Low",
  measurement: "Moderate",
  profile: "Profile-building",
  high: "High concern",
};

// Score ranges match analyzer/score.py TIERS.
export const TIER_INFO: Record<TierKey, { label: string; behavior: string; range: string; meaning: string }> = {
  minimum: {
    label: "Low",
    behavior: "Essential",
    range: "0–24",
    meaning: "needed for the app or page to work, with nothing that follows you",
  },
  measurement: {
    label: "Moderate",
    behavior: "Analytics",
    range: "25–49",
    meaning: "counts usage without linking it across sites or apps",
  },
  profile: {
    label: "High",
    behavior: "Tracking",
    range: "50–74",
    meaning: "follows you across sites or apps, or ties activity to you",
  },
  high: {
    label: "Severe",
    behavior: "Profiling",
    range: "75–100",
    meaning: "tracking plus sensitive topics, personal identifiers or data sharing",
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
