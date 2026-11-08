import { useEffect, useRef, useState } from "react";
import type { Blocklist, BlocklistFormat, Tier } from "../shared/protocol";
import { CopyIcon } from "./icons";

// Doppel finds the trackers; the tools people already trust do the blocking.
// The list is built on this computer and only ever copied or saved to a file you pick.

const TOOLS: { format: BlocklistFormat; label: string; steps: string[] }[] = [
  {
    format: "ublock",
    label: "uBlock Origin / AdGuard",
    steps: [
      "uBlock Origin: open its dashboard, go to My filters, paste the list, then Apply changes.",
      "AdGuard: Settings → Filters → User rules, then paste or Import the saved file.",
      "Brave: brave://settings/shields/filters → Create custom filters, then paste.",
    ],
  },
  {
    format: "domains",
    label: "NextDNS / Pi-hole",
    steps: [
      "NextDNS: Denylist → add each domain (subdomains are blocked too).",
      "Pi-hole or AdGuard Home: Domains / Blocked services → add the domains as wildcard denies.",
      "Cloudflare Gateway (WARP for Teams): create a DNS policy blocking these domains.",
    ],
  },
  {
    format: "little_snitch",
    label: "Little Snitch",
    steps: ["Save the file, then double-click it: Little Snitch adds it as a rule group you can turn on or off."],
  },
  {
    format: "hosts",
    label: "hosts file",
    steps: [
      "Add the lines to /etc/hosts (needs an administrator), or load the file in Gas Mask or SwitchHosts.",
      "A hosts file can't block whole domains, so every host seen in the audit is listed.",
    ],
  },
];

const LEVELS: { tier: Tier; label: string }[] = [
  { tier: "High concern", label: "High concern" },
  { tier: "Profile building", label: "Profile building and up" },
  { tier: "Measurement", label: "Measurement and up" },
];

export function BlockWithYourTools({ auditId, onToast }: { auditId: number; onToast: (t: string) => void }) {
  const [format, setFormat] = useState<BlocklistFormat>("ublock");
  const [tier, setTier] = useState<Tier>("Profile building");
  const [list, setList] = useState<Blocklist | null>(null);
  const [error, setError] = useState<string | null>(null);
  const area = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let live = true;
    window.shadow
      .request("export_blocklist", { audit_id: auditId, format, min_tier: tier })
      .then((l) => live && (setList(l), setError(null)))
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [auditId, format, tier]);

  const tool = TOOLS.find((t) => t.format === format)!;

  const copy = async () => {
    if (!list) return;
    try {
      await navigator.clipboard.writeText(list.content);
      onToast(`Copied ${list.count} domain${list.count === 1 ? "" : "s"}`);
    } catch {
      // The sandboxed window may deny clipboard access; fall back to a selection copy.
      area.current?.select();
      onToast(document.execCommand("copy") ? "Copied" : "Copy failed. Select the text instead.");
    }
  };

  const save = async () => {
    if (!list) return;
    try {
      if (await window.shadow.saveFile(list.filename, list.content)) onToast(`Saved ${list.filename}`);
    } catch (e) {
      onToast(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section className="block" aria-labelledby="block-tools-title">
      <h2 id="block-tools-title" className="h2">
        Block them with your own tools
      </h2>
      <p className="muted small">
        Doppel only watches. Hand what this audit found to the blocker you already use: the list holds the tracker
        domains, never a site you visited, and is made on this computer.
      </p>
      <div className="export-controls">
        <div className="seg" role="group" aria-label="Your tool">
          {TOOLS.map((t) => (
            <button key={t.format} aria-pressed={format === t.format} onClick={() => setFormat(t.format)}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Which trackers">
          {LEVELS.map((l) => (
            <button key={l.tier} aria-pressed={tier === l.tier} onClick={() => setTier(l.tier)}>
              {l.label}
            </button>
          ))}
        </div>
      </div>
      {error && <p className="notice notice-error">{error}</p>}
      {list && list.count === 0 && <p className="empty">No trackers at this level in this audit.</p>}
      {list && list.count > 0 && (
        <>
          <textarea ref={area} className="letter export-preview" readOnly value={list.content} aria-label="Blocklist" />
          <div className="export-actions">
            <span className="muted small">
              {list.count} domain{list.count === 1 ? "" : "s"} · works with {list.works_with}
            </span>
            <button className="btn btn-quiet btn-sm" onClick={() => void copy()}>
              <CopyIcon /> Copy
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => void save()}>
              Save file…
            </button>
          </div>
          {list.skipped.length > 0 && (
            <p className="muted small">
              Left out of this format because you may visit them directly: {list.skipped.join(", ")}. Use the uBlock
              Origin / AdGuard list to block them only when other sites load them.
            </p>
          )}
          <ol className="export-steps small">
            {tool.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
