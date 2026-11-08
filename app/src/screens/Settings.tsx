import { useEffect, useState } from "react";
import type { Settings as SettingsData } from "../shared/protocol";
import { Modal, Toggle } from "../components/ui";
import type { StatusLine } from "../components/Sidebar";
import { recorderRunning } from "../lib/health";

export type Theme = "system" | "light" | "dark";

const TOGGLES: { key: "gpc" | "california" | "zero_network" | "local_ai"; label: string; hint: string }[] = [
  { key: "gpc", label: "Global Privacy Control", hint: "Tells sites not to sell or share your data" },
  { key: "california", label: "California resident", hint: "Enables DROP" },
  { key: "zero_network", label: "Zero-network mode", hint: "No company research; cards come from the bundled snapshot" },
  { key: "local_ai", label: "Local AI model", hint: "Ollama on this computer. Off: keyword rules" },
];

export function Settings({
  settings,
  onChange,
  recorder,
  theme,
  onTheme,
  onToast,
}: {
  settings: SettingsData;
  onChange: (key: keyof SettingsData, value: boolean) => void;
  recorder: StatusLine;
  theme: Theme;
  onTheme: (t: Theme) => void;
  onToast: (text: string) => void;
}) {
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState<boolean | null>(null);

  const refreshRunning = async () => {
    try {
      const res = await window.shadow.recorder("status");
      setRunning(res.ok ? recorderRunning(res.output) : null);
    } catch {
      setRunning(null);
    }
  };

  useEffect(() => {
    void refreshRunning();
  }, []);

  const recorderAction = async (action: "status" | "uninstall" | "start" | "stop") => {
    setBusy(true);
    try {
      const res = await window.shadow.recorder(action);
      const first = res.output.trim().split("\n")[0];
      if (action === "status") {
        setRunning(res.ok ? recorderRunning(res.output) : null);
        onToast(res.ok ? (recorderRunning(res.output) ? "Recorder is running" : "Recorder is off") : first || "Recorder command failed");
      } else {
        onToast(first || (res.ok ? "Done" : "Recorder command failed"));
        await refreshRunning();
      }
    } catch (e) {
      onToast(e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : "Recorder command failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="view prefs">
      <header className="view-head">
        <h1 className="title">Settings</h1>
      </header>
      <div className="pref">
        <span className="pref-name">
          <span className={`dot dot-${running === false ? "off" : recorder.state}`} /> Recorder
          <span className="muted pref-hint">{running === false ? "Recorder off" : recorder.text}</span>
        </span>
        <span className="pref-actions">
          <button className="btn btn-quiet btn-sm" disabled={busy} onClick={() => void recorderAction("status")}>
            Check
          </button>
          <button
            className="btn btn-quiet btn-sm pref-btn-fixed"
            disabled={busy || running === null}
            title={running ? "Pause recording until you turn it back on or next log in" : "Start recording now"}
            onClick={() => void recorderAction(running ? "stop" : "start")}
          >
            {running === null ? " " : running ? "Turn off" : "Turn on"}
          </button>
        </span>
      </div>
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
      <div className="pref">
        <span className="pref-name">
          Uninstall recorder <span className="muted pref-hint">Removes the certificate and login item</span>
        </span>
        <button className="btn btn-danger btn-sm" disabled={busy} onClick={() => setConfirmUninstall(true)}>
          Uninstall
        </button>
      </div>
      {confirmUninstall && (
        <Modal
          title="Uninstall the recorder?"
          onClose={() => setConfirmUninstall(false)}
          footer={
            <>
              <button className="btn btn-quiet btn-sm" onClick={() => setConfirmUninstall(false)}>
                Cancel
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => {
                  setConfirmUninstall(false);
                  void recorderAction("uninstall");
                }}
              >
                Uninstall
              </button>
            </>
          }
        >
          <p className="muted">
            Recording stops and the certificate and login item are removed. Your encrypted log stays until you delete it
            with <span className="mono">recorder uninstall --wipe</span>.
          </p>
        </Modal>
      )}
    </div>
  );
}
