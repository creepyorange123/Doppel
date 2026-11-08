import { useCallback, useEffect, useState } from "react";
import type { DomainRule, Settings as SettingsData } from "../shared/protocol";
import { Modal, Toggle } from "../components/ui";
import { certificateStatus, type CertificateStatus } from "../lib/certificate";
import { monthDay } from "../lib/format";

export type Theme = "system" | "light" | "dark";

const TOGGLES: { key: keyof SettingsData; label: string; hint: string }[] = [
  { key: "california", label: "California resident", hint: "Enables DROP" },
  { key: "zero_network", label: "Zero-network mode", hint: "No company research; cards come from the bundled snapshot" },
  { key: "local_ai", label: "Local AI model", hint: "Ollama on this computer. Off: keyword rules" },
];

const RULE_LABELS: Record<DomainRule, string> = {
  dont_track: "Never recorded",
  metadata_only: "Site name only",
};

const errorText = (e: unknown) =>
  e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : String(e);

export function Settings({
  settings,
  onChange,
  auditRunning,
  theme,
  onTheme,
  onToast,
}: {
  settings: SettingsData;
  onChange: (key: keyof SettingsData, value: boolean) => void;
  auditRunning: boolean;
  theme: Theme;
  onTheme: (t: Theme) => void;
  onToast: (text: string) => void;
}) {
  const [cert, setCert] = useState<CertificateStatus | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [busy, setBusy] = useState(false);

  const checkCert = useCallback(async () => {
    try {
      const res = await window.shadow.recorder("status");
      setCert(certificateStatus(res.ok ? res.output : null));
    } catch {
      setCert(certificateStatus(null));
    }
  }, []);
  useEffect(() => void checkCert(), [checkCert]);

  const recorderAction = async (action: "install" | "uninstall") => {
    setBusy(true);
    try {
      const res = await window.shadow.recorder(action);
      onToast(res.output.trim().split("\n")[0] || (res.ok ? "Done" : "Command failed"));
    } catch (e) {
      onToast(errorText(e));
    } finally {
      setBusy(false);
      void checkCert();
    }
  };

  return (
    <div className="view prefs">
      <header className="view-head">
        <h1 className="title">Settings</h1>
      </header>
      {TOGGLES.map((t) => (
        <div key={t.key} className="pref">
          <span className="pref-name">
            {t.label} <span className="muted pref-hint">{t.hint}</span>
          </span>
          <Toggle checked={settings[t.key]} onChange={(v) => onChange(t.key, v)} label={t.label} />
        </div>
      ))}
      <div className="pref">
        <span className="pref-name">Theme</span>
        <select className="select" value={theme} onChange={(e) => onTheme(e.target.value as Theme)} aria-label="Theme">
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </div>

      <DomainRules onToast={onToast} />

      <h2 className="h2 block">Certificate</h2>
      <div className="pref">
        <span className="pref-name">
          <span className={`dot dot-${cert?.state ?? "off"}`} /> Audit certificate
          <span className="muted pref-hint">
            {cert ? cert.text : "Checking…"}
            {cert?.expires ? ` (expires ${monthDay(cert.expires)})` : ""}
          </span>
        </span>
        <span className="pref-actions">
          {cert && !cert.valid && (
            <button className="btn btn-secondary btn-sm" disabled={busy || auditRunning} onClick={() => void recorderAction("install")}>
              {cert.installed ? "Renew" : "Install"}
            </button>
          )}
          <button className="btn btn-danger btn-sm" disabled={busy || auditRunning || !cert?.installed} onClick={() => setConfirmRemove(true)}>
            Remove
          </button>
        </span>
      </div>
      <p className="muted small">
        Used only during audits, to read the encrypted traffic of the apps you pick. Nothing runs between audits.
      </p>

      {confirmRemove && (
        <Modal
          title="Remove the certificate?"
          onClose={() => setConfirmRemove(false)}
          footer={
            <>
              <button className="btn btn-quiet btn-sm" onClick={() => setConfirmRemove(false)}>
                Cancel
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => {
                  setConfirmRemove(false);
                  void recorderAction("uninstall");
                }}
              >
                Remove
              </button>
            </>
          }
        >
          <p className="muted">
            Audits can then only see which sites an app contacts, not what it sends, until you install it again. Your past
            audits are kept until you delete them, or run <span className="mono">recorder uninstall --wipe</span>.
          </p>
        </Modal>
      )}
    </div>
  );
}

function DomainRules({ onToast }: { onToast: (text: string) => void }) {
  const [domains, setDomains] = useState<{ domain: string; rule: DomainRule }[] | null>(null);
  const [domain, setDomain] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    window.shadow
      .request("list_domain_rules")
      .then((r) => setDomains(r.domains))
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const set = (d: string, rule: DomainRule | null, toast?: string) =>
    window.shadow
      .request("set_domain_rule", { domain: d, rule })
      .then(() => {
        load();
        setError(null);
        if (toast) onToast(toast);
        return true;
      })
      .catch((e: Error) => {
        setError(e.message);
        return false;
      });

  return (
    <section className="block">
      <h2 className="h2">Never record these sites</h2>
      <p className="muted small">Applies to every audit, for example: never record anything sent to my bank.</p>
      {error && <p className="notice notice-error">{error}</p>}
      <ul className="rows">
        {(domains ?? []).map((d) => (
          <li key={d.domain} className="row site-row">
            <span className="row-main">
              <span className="row-name mono">{d.domain}</span>
              <span className="row-meta">{RULE_LABELS[d.rule]}</span>
            </span>
            <button className="btn btn-quiet btn-sm" onClick={() => void set(d.domain, null)}>
              Remove
            </button>
          </li>
        ))}
      </ul>
      <form
        className="site-form"
        onSubmit={(e) => {
          e.preventDefault();
          const d = domain.trim();
          void set(d, "dont_track", `${d} will never be recorded`).then((ok) => ok && setDomain(""));
        }}
      >
        <label className="search">
          <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="mybank.com" aria-label="Site" />
        </label>
        <button type="submit" className="btn btn-secondary btn-sm" disabled={!domain.trim()}>
          Never record this site
        </button>
      </form>
    </section>
  );
}
