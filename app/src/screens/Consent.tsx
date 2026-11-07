import { useState } from "react";

// Shown on first run, before anything is installed or recorded.
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
          Doppel records the network requests that apps on this computer send, so it can show you who receives your
          data.
        </p>
        <h2 className="h3">If you agree</h2>
        <ul>
          <li>
            A certificate that only this computer trusts is added to your user trust store. Its private key stays in your
            system keychain. It expires after 30 days.
          </li>
          <li>A background recorder starts when you log in. It has no window.</li>
          <li>Requests are saved in an encrypted file only your account can open.</li>
        </ul>
        <h2 className="h3">Never recorded</h2>
        <ul>
          <li>System processes, and any app or site you set to “Don’t track”.</li>
          <li>Passwords, login forms, and cookie or authorization values.</li>
          <li>Search queries.</li>
        </ul>
        <p className="muted small">Nothing is sent anywhere. Uninstalling removes the certificate and the login item.</p>
        {error && <p className="notice notice-error">{error}</p>}
        <div className="consent-actions">
          <button className="btn btn-primary" disabled={busy} onClick={agree}>
            {busy ? "Installing…" : "I agree, install the recorder"}
          </button>
        </div>
      </div>
    </div>
  );
}
