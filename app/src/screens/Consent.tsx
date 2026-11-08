import { useState } from "react";

// Shown on first run, before anything is installed.
export function Consent({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const agree = async () => {
    setBusy(true);
    setError(null);
    const res = await window.shadow.recorder("install");
    setBusy(false);
    if (res.ok) onDone();
    else setError(res.output || "Install failed. Nothing was left installed.");
  };

  return (
    <div className="opening">
      <div className="consent">
        <span className="wordmark">Doppel</span>
        <h1 className="title">Before we start</h1>
        <p>
          Doppel audits the apps you choose: for a set time, it shows what they send and who receives it. It never watches
          your computer in the background.
        </p>
        <h2 className="h3">If you agree</h2>
        <ul>
          <li>
            A certificate that only this computer trusts is added to your user trust store, once, so audits can read the
            encrypted traffic of the apps you pick. Its private key stays in your system keychain. It expires after 30 days.
          </li>
          <li>Nothing starts at login and nothing runs in the background.</li>
        </ul>
        <h2 className="h3">How audits work</h2>
        <ul>
          <li>Recording happens only during an audit you start, only for the apps you pick, and stops on its own.</li>
          <li>Every other app, and your VPN or ad blocker, is left alone.</li>
          <li>What an audit records is saved in an encrypted file only your account can open.</li>
        </ul>
        <h2 className="h3">Never recorded</h2>
        <ul>
          <li>System processes, and any site you set to never record.</li>
          <li>Passwords, login forms, and cookie or authorization values.</li>
          <li>Search queries.</li>
        </ul>
        <p className="muted small">Nothing is sent anywhere. Removing the certificate in Settings undoes the install.</p>
        {error && <p className="notice notice-error">{error}</p>}
        <div className="consent-actions">
          <button className="btn btn-primary" disabled={busy} onClick={agree}>
            {busy ? "Installing…" : "I agree, install the certificate"}
          </button>
        </div>
      </div>
    </div>
  );
}
