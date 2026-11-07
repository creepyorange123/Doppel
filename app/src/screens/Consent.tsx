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
    <section className="card">
      <h2>Before we start</h2>
      <p>
        Shadow Profile records the network requests that apps on this computer send, so it can show you who
        receives your data.
      </p>
      <h3>If you agree</h3>
      <ul>
        <li>
          A certificate that only this computer trusts is added to your user trust store. Its private key stays in
          your system keychain. It expires after 30 days.
        </li>
        <li>
          A background recorder starts when you log in. It has no window. Windows will ask permission to start its
          capture driver.
        </li>
        <li>Requests are saved in an encrypted file only your account can open.</li>
      </ul>
      <h3>Never recorded</h3>
      <ul>
        <li>System processes, and any app or site you set to &quot;Don&apos;t track&quot;.</li>
        <li>Passwords, login forms, and cookie or authorization values.</li>
        <li>Search queries.</li>
      </ul>
      <p className="muted">Nothing is sent anywhere. Uninstalling removes the certificate and the login item.</p>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button className="primary" disabled={busy} onClick={agree}>
          {busy ? "Installing…" : "I agree, install the recorder"}
        </button>
      </div>
    </section>
  );
}
