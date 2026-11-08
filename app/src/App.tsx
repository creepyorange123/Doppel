import { useCallback, useEffect, useRef, useState } from "react";
import type {
  ActionName,
  AnalyzeResult,
  ProgressEvent,
  Report,
  RequestRow,
  Settings as SettingsData,
  StatusResult,
} from "./shared/protocol";
import { recorderHealth, recorderRunning, recorderStatusLine } from "./lib/health";
import { Sidebar, type StatusLine, type View } from "./components/Sidebar";
import { Opening } from "./components/Opening";
import { Modal, Toasts, type ToastItem } from "./components/ui";
import { CopyIcon } from "./components/icons";
import { Consent } from "./screens/Consent";
import { Overview } from "./screens/Overview";
import { Companies } from "./screens/Companies";
import { Requests } from "./screens/Requests";
import { RequestDrawer } from "./screens/RequestDrawer";
import { Ledger } from "./screens/Ledger";
import { Apps } from "./screens/Apps";
import { Settings, type Theme } from "./screens/Settings";

// Captured text is always rendered as React text nodes, never as HTML
// (security checklist #5). Never inject raw HTML anywhere; tests/test_security_static.py checks this.

function stored<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return allowed.includes(v as T) ? (v as T) : fallback;
  } catch {
    return fallback;
  }
}

function store(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* per-viewer convenience only */
  }
}

interface OpenRequest {
  row: RequestRow;
  company: string | null;
  topic?: string | null;
  sensitive?: boolean;
}

const ACTION_TOASTS: Record<ActionName, (c: string) => string> = {
  block: (c) => `Blocked ${c}. Requests stop from now on, even while this window is closed.`,
  strip: (c) => `Identifiers will be removed from requests to ${c}`,
  "opt-out": (c) => `Opened the ${c} opt-out page in your browser`,
  letter: (c) => `Letter for ${c} ready`,
};

export function App() {
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [lastRun, setLastRun] = useState<AnalyzeResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [skipped, setSkipped] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [recorderOn, setRecorderOn] = useState<boolean | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [company, setCompany] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [openRequest, setOpenRequest] = useState<OpenRequest | null>(null);
  const [letter, setLetter] = useState<{ company: string; text: string } | null>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [noticeDismissed, setNoticeDismissed] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => stored("doppel-theme", ["system", "light", "dark"] as const, "system"));
  const [collapsed, setCollapsed] = useState(() => stored("doppel-sidebar", ["open", "collapsed"] as const, "open") === "collapsed");
  const started = useRef(false);
  const toastId = useRef(0);
  const main = useRef<HTMLElement>(null);

  const loadStatus = useCallback(
    () =>
      window.shadow
        .request("status")
        .then((s) => {
          setStatus(s);
          setError(null);
        })
        .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e))),
    [],
  );

  const loadReport = useCallback(() => {
    window.shadow.request("report").then(setReport).catch((e: Error) => setError(e.message));
    window.shadow.request("get_settings").then(setSettings).catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    const off = window.shadow.onEvent((ev) => {
      if (ev.type === "ready") void loadStatus();
      if (ev.type === "progress") setProgress(ev.payload);
      if (ev.type === "exit") setError("The analyzer stopped. Restart Doppel to continue.");
    });
    void loadStatus();
    return off;
  }, [loadStatus]);

  const consented = Boolean(status?.consent_at);

  // Steps 1-4 run once each time the app opens.
  useEffect(() => {
    if (!consented || started.current) return;
    started.current = true; // once per open, even if it fails
    setAnalyzing(true);
    window.shadow
      .request("analyze_since_last_open")
      .then((r) => {
        setLastRun(r);
        void loadStatus();
        loadReport();
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setAnalyzing(false));
  }, [consented, loadStatus, loadReport]);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    store("doppel-theme", theme);
  }, [theme]);

  // Whether the recorder process is running: checked at startup, then every 30 s, so
  // the status dot follows the recorder even if it stops on its own. Settings also
  // updates it right after Check / Turn on / Turn off.
  useEffect(() => {
    const check = () => {
      window.shadow
        .recorder("status")
        .then((res) => setRecorderOn(res.ok ? recorderRunning(res.output) : null))
        .catch(() => setRecorderOn(null));
      void loadStatus(); // fresh heartbeat
    };
    check();
    const timer = window.setInterval(check, 30_000);
    return () => window.clearInterval(timer);
  }, [loadStatus]);

  // Sidebar Refresh: analyse what the recorder logged since the last run, in place
  // (no opening screen), then reload the report.
  const refresh = () => {
    if (refreshing || analyzing) return;
    setRefreshing(true);
    window.shadow
      .request("analyze_since_last_open")
      .then((r) => {
        setLastRun(r);
        loadReport();
        toast(r.analyzed ? `Analysed ${r.analyzed.toLocaleString()} new request${r.analyzed === 1 ? "" : "s"}` : "No new requests");
      })
      .catch((e: Error) => toast(e.message))
      .finally(() => {
        void loadStatus();
        setRefreshing(false);
      });
  };

  const onRecorderRunning = (running: boolean | null) => {
    setRecorderOn(running);
    void loadStatus();
  };

  useEffect(() => store("doppel-sidebar", collapsed ? "collapsed" : "open"), [collapsed]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "\\") {
        e.preventDefault();
        setCollapsed((c) => !c);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (text: string) => {
      const id = ++toastId.current;
      setToasts((t) => [...t.slice(-2), { id, text }]);
      window.setTimeout(() => dismissToast(id), 5000);
    },
    [dismissToast],
  );

  const navigate = (v: View) => {
    setView(v);
    main.current?.scrollTo({ top: 0 });
  };
  const openCompany = (name: string) => {
    setCompany(name);
    setOpenRequest(null);
    navigate("companies");
  };

  const act = async (name: string, action: ActionName) => {
    try {
      const res = await window.shadow.request("take_action", { company: name, action });
      if (res.letter) setLetter({ company: name, text: res.letter });
      else toast(ACTION_TOASTS[action](name));
    } catch (e) {
      // Opening the opt-out page already happened in the browser; recording it is best effort.
      if (action !== "opt-out") toast(e instanceof Error ? e.message : String(e));
    }
    loadReport();
    setVersion((v) => v + 1);
  };

  const undo = async (name: string, action: "block" | "strip") => {
    try {
      await window.shadow.request("undo_action", { company: name, action });
      toast(action === "block" ? `Unblocked ${name}` : `Stopped stripping identifiers from ${name}`);
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e));
    }
    loadReport();
    setVersion((v) => v + 1);
  };

  const changeSetting = (key: keyof SettingsData, value: boolean) => {
    window.shadow
      .request("set_setting", { key, value })
      .then(() => window.shadow.request("get_settings"))
      .then(setSettings)
      .catch((e: Error) => toast(e.message));
  };

  const health = status ? recorderHealth(status.recorder_heartbeat_at) : null;
  const recorderLine: StatusLine =
    !status && recorderOn === null
      ? { text: "Recorder", state: "off" }
      : recorderStatusLine(recorderOn, status?.recorder_heartbeat_at ?? null);
  const statusLines: StatusLine[] = [
    recorderLine,
    settings?.local_ai ? { text: "Local AI on", state: "ok" } : { text: "Keyword rules", state: "ok" },
    ...(settings?.zero_network ? [{ text: "Zero-network", state: "ok" as const }] : []),
  ];

  if (error && !status) {
    return (
      <div className="app-container">
        <div className="opening">
          <div className="opening-box">
            <span className="wordmark">Doppel</span>
            <p className="notice notice-error">{error}</p>
          </div>
        </div>
      </div>
    );
  }
  if (!status) {
    return (
      <div className="app-container">
        <Opening progress={null} onSkip={() => undefined} />
      </div>
    );
  }
  if (!consented) {
    return (
      <div className="app-container">
        <Consent onDone={() => void loadStatus()} />
      </div>
    );
  }
  if (analyzing && !skipped) {
    return (
      <div className="app-container">
        <Opening progress={progress} onSkip={() => setSkipped(true)} />
      </div>
    );
  }

  const notice = noticeDismissed
    ? null
    : recorderOn === false
      ? "The recorder is off, so nothing is being logged. Turn it on in Settings."
      : recorderOn === true && health?.state === "never"
        ? null
        : health && health.state !== "ok"
          ? health.message
          : null;
  const waiting = (
    <div className="view">
      <p className="empty">{analyzing ? `${progress?.label ?? "Analyzing"}…` : lastRun ? "Building report…" : "No report yet."}</p>
    </div>
  );

  return (
    <div className="app-container">
      <div className={collapsed ? "app is-collapsed" : "app"}>
        <Sidebar
          view={view}
          onNavigate={navigate}
          counts={report ? { companies: report.summary.companies, requests: report.summary.requests } : {}}
          collapsed={collapsed}
          onToggle={() => setCollapsed((c) => !c)}
          status={statusLines}
          onRefresh={refresh}
          refreshing={refreshing}
        />
        <main className={view === "ledger" ? "main main-fill" : "main"} ref={main}>
          {error && <p className="notice notice-error">{error}</p>}
          {view === "overview" &&
            (report ? (
              <Overview
                report={report}
                notice={notice}
                onDismissNotice={() => setNoticeDismissed(true)}
                onOpenCompany={openCompany}
                onBlock={(c) => void act(c, "block")}
              />
            ) : (
              waiting
            ))}
          {view === "companies" &&
            (report ? (
              <Companies
                companies={report.companies}
                selected={company}
                onSelect={setCompany}
                onAct={act}
                onUndo={undo}
                onOpenRequest={(row, c) => setOpenRequest({ row, company: c })}
                version={version}
              />
            ) : (
              waiting
            ))}
          {view === "requests" &&
            (report ? (
              <Requests
                key={version}
                since={report.summary.since}
                onOpenRequest={(r) => setOpenRequest({ row: r, company: r.company, topic: r.topic, sensitive: r.sensitive })}
              />
            ) : (
              waiting
            ))}
          {view === "ledger" && <Ledger />}
          {view === "apps" && <Apps onToast={toast} />}
          {view === "settings" &&
            (settings ? (
              <Settings settings={settings} onChange={changeSetting} recorder={recorderLine} running={recorderOn} onRunning={onRecorderRunning} theme={theme} onTheme={setTheme} onToast={toast} />
            ) : (
              waiting
            ))}
        </main>
      </div>

      {openRequest && (
        <RequestDrawer
          request={openRequest.row}
          company={openRequest.company}
          topic={openRequest.topic}
          sensitive={openRequest.sensitive}
          onClose={() => setOpenRequest(null)}
          onOpenCompany={
            openRequest.company && report?.companies.some((c) => c.name === openRequest.company)
              ? () => openCompany(openRequest.company!)
              : undefined
          }
        />
      )}
      {letter && <LetterModal company={letter.company} text={letter.text} onClose={() => setLetter(null)} onToast={toast} />}
      <Toasts items={toasts} onDismiss={dismissToast} />
    </div>
  );
}

function LetterModal({
  company,
  text,
  onClose,
  onToast,
}: {
  company: string;
  text: string;
  onClose: () => void;
  onToast: (t: string) => void;
}) {
  const area = useRef<HTMLTextAreaElement>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      onToast("Copied");
    } catch {
      // The sandboxed window denies permissions; fall back to a selection copy.
      area.current?.select();
      onToast(document.execCommand("copy") ? "Copied" : "Copy failed. Select the text instead.");
    }
  };
  return (
    <Modal
      title={`Request data from ${company}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-quiet btn-sm" onClick={() => void copy()}>
            <CopyIcon /> Copy
          </button>
          <button className="btn btn-primary btn-sm" onClick={onClose}>
            Done
          </button>
        </>
      }
    >
      <textarea ref={area} className="letter" readOnly value={text} aria-label="Letter text" />
      <p className="muted small">Generated on this computer; nothing was sent. Template only, not legal advice.</p>
    </Modal>
  );
}
