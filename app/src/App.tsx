import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type {
  ActionName,
  AppCapture,
  Audit,
  ProgressEvent,
  Report,
  RequestRow,
  Settings as SettingsData,
  StatusResult,
} from "./shared/protocol";
import { Sidebar, type StatusLine, type View } from "./components/Sidebar";
import { Opening } from "./components/Opening";
import { NoAudit } from "./components/AuditHeader";
import { Modal, Toasts, type ToastItem } from "./components/ui";
import { CopyIcon } from "./components/icons";
import { countdown } from "./lib/audit";
import { Consent } from "./screens/Consent";
import { Audits } from "./screens/Audits";
import { Overview } from "./screens/Overview";
import { Companies } from "./screens/Companies";
import { Requests } from "./screens/Requests";
import { RequestDrawer } from "./screens/RequestDrawer";
import { Ledger } from "./screens/Ledger";
import { Privacy } from "./screens/Privacy";
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

const errorText = (e: unknown) =>
  e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : String(e);

interface OpenRequest {
  row: RequestRow;
  company: string | null;
  topic?: string | null;
  sensitive?: boolean;
}

const REPORT_VIEWS: View[] = ["overview", "companies", "requests"];

export function App() {
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [active, setActive] = useState<Audit | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [analyzingId, setAnalyzingId] = useState<number | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [view, setView] = useState<View>("audits");
  const [company, setCompany] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [openRequest, setOpenRequest] = useState<OpenRequest | null>(null);
  const [letter, setLetter] = useState<{ company: string; text: string } | null>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [now, setNow] = useState(Date.now());
  const [theme, setTheme] = useState<Theme>(() => stored("doppel-theme", ["system", "light", "dark"] as const, "system"));
  const [collapsed, setCollapsed] = useState(() => stored("doppel-sidebar", ["open", "collapsed"] as const, "open") === "collapsed");
  const started = useRef(false);
  const toastId = useRef(0);
  const main = useRef<HTMLElement>(null);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (text: string) => {
      const id = ++toastId.current;
      setToasts((t) => [...t.slice(-2), { id, text }]);
      window.setTimeout(() => dismissToast(id), 5000);
    },
    [dismissToast],
  );

  const navigate = useCallback((v: View) => {
    setView(v);
    main.current?.scrollTo({ top: 0 });
  }, []);

  const loadStatus = useCallback(
    () =>
      window.shadow
        .request("status")
        .then((s) => {
          setStatus(s);
          setError(null);
          return s;
        })
        .catch((e: unknown) => {
          setError(errorText(e));
          return null;
        }),
    [],
  );

  /** Reloads the audit list; selects the newest finished audit if none is selected. */
  const loadAudits = useCallback(
    () =>
      window.shadow
        .request("list_audits")
        .then((r) => {
          setAudits(r.audits);
          setSelectedId((id) =>
            id !== null && r.audits.some((a) => a.id === id) ? id : (r.audits.find((a) => a.status !== "running")?.id ?? null),
          );
          return r.audits;
        })
        .catch((e: unknown) => {
          setError(errorText(e));
          return [] as Audit[];
        }),
    [],
  );

  const syncActive = useCallback(
    () =>
      window.shadow
        .audit("state")
        .then((r) => setActive(r.audit))
        .catch(() => setActive(null)),
    [],
  );

  /** Analyse a finished audit, then show its report (or the self-audit verdict). */
  const analyze = useCallback(
    async (auditId: number) => {
      setAnalyzingId(auditId);
      setProgress(null);
      try {
        await window.shadow.request("analyze_audit", { audit_id: auditId });
      } catch (e) {
        toast(errorText(e));
      }
      const list = await loadAudits();
      setAnalyzingId(null);
      setSelectedId(auditId);
      setVersion((v) => v + 1);
      const audit = list.find((a) => a.id === auditId);
      navigate(audit?.self_audit ? "privacy" : "overview");
      void loadStatus();
    },
    [loadAudits, loadStatus, navigate, toast],
  );

  useEffect(() => {
    const off = window.shadow.onEvent((ev) => {
      if (ev.type === "ready") void loadStatus();
      if (ev.type === "progress") setProgress(ev.payload);
      if (ev.type === "exit") setError("The analyzer stopped. Restart Doppel to continue.");
      if (ev.type === "audit") {
        if (ev.payload.state === "started") {
          void syncActive();
          void loadAudits();
        } else {
          setActive(null);
          if (!ev.payload.ok && ev.payload.message) toast(`The audit stopped early: ${ev.payload.message}`);
          void analyze(ev.payload.audit_id);
        }
      }
    });
    void loadStatus();
    return off;
  }, [loadStatus, syncActive, loadAudits, analyze, toast]);

  const consented = Boolean(status?.consent_at);

  // Once per open: load audits, and quietly analyse anything left unanalysed
  // (e.g. Doppel quit before an audit was analysed).
  useEffect(() => {
    if (!consented || started.current || !status) return;
    started.current = true;
    void syncActive();
    void loadAudits();
    window.shadow.request("get_settings").then(setSettings).catch((e: Error) => setError(e.message));
    if (status.unanalyzed_count > 0 && status.active_audit_id === null) {
      window.shadow
        .request("analyze_audit")
        .then(() => {
          void loadAudits();
          setVersion((v) => v + 1);
        })
        .catch(() => undefined);
    }
  }, [consented, status, syncActive, loadAudits]);

  // Report for the selected audit.
  useEffect(() => {
    if (selectedId === null || analyzingId === selectedId) {
      setReport(null);
      return;
    }
    let cancelled = false;
    window.shadow
      .request("report", { audit_id: selectedId })
      .then((r) => !cancelled && setReport(r))
      .catch((e: Error) => !cancelled && toast(e.message));
    return () => {
      cancelled = true;
    };
  }, [selectedId, analyzingId, version, toast]);

  // Sidebar countdown.
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [active]);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    store("doppel-theme", theme);
  }, [theme]);

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

  const startAudit = async (apps: { path: string; name: string; capture: AppCapture }[], minutes: number, label: string) => {
    try {
      const res = await window.shadow.audit("start", { apps, minutes, ...(label ? { label } : {}) });
      if (!res.ok) {
        toast(res.error ?? "Couldn't start the audit");
        return false;
      }
      setActive(res.audit);
      void loadAudits();
      return true;
    } catch (e) {
      toast(errorText(e));
      return false;
    }
  };

  const startSelfAudit = async (minutes: number) => {
    try {
      const res = await window.shadow.audit("self", { minutes });
      if (!res.ok) toast(res.error ?? "Couldn't start the self-audit");
      else {
        setActive(res.audit);
        void loadAudits();
      }
    } catch (e) {
      toast(errorText(e));
    }
  };

  const stopAudit = () => {
    window.shadow
      .audit("stop")
      .then((r) => !r.ok && r.error && toast(r.error))
      .catch((e: unknown) => toast(errorText(e)));
  };

  const deleteAudit = (a: Audit) => {
    window.shadow
      .request("delete_audit", { audit_id: a.id })
      .then(() => {
        toast("Audit deleted");
        if (selectedId === a.id) setSelectedId(null);
        void loadAudits();
        void loadStatus();
      })
      .catch((e: unknown) => toast(errorText(e)));
  };

  const selectAudit = (id: number) => {
    setSelectedId(id);
    setCompany(null);
    setOpenRequest(null);
    const a = audits.find((x) => x.id === id);
    navigate(a?.self_audit ? "privacy" : "overview");
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
      else toast(`Opened the ${name} opt-out page in your browser`);
    } catch (e) {
      // Opening the opt-out page already happened in the browser; recording it is best effort.
      if (action !== "opt-out") toast(errorText(e));
    }
    setVersion((v) => v + 1);
  };

  const changeSetting = (key: keyof SettingsData, value: boolean) => {
    window.shadow
      .request("set_setting", { key, value })
      .then(() => window.shadow.request("get_settings"))
      .then(setSettings)
      .catch((e: Error) => toast(e.message));
  };

  const statusLines: StatusLine[] = [
    active
      ? { text: `${active.self_audit ? "Self-audit" : "Audit"} running · ${countdown(active.ends_at, now)} left`, state: "ok" }
      : analyzingId !== null
        ? { text: "Analysing audit", state: "ok" }
        : { text: "No audit running", state: "off" },
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
        <Opening progress={null} />
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

  const selected = audits.find((a) => a.id === selectedId) ?? null;
  const latestSelfAudit = audits.find((a) => a.self_audit) ?? null;
  const reportReady = report && selected && report.audit.id === selected.id ? report : null;
  const reportView = (title: string, body: (r: Report) => ReactNode) =>
    !selected ? (
      <NoAudit title={title} onStart={() => navigate("audits")} />
    ) : reportReady ? (
      body(reportReady)
    ) : (
      <div className="view">
        <p className="empty">{analyzingId === selected.id ? `${progress?.label ?? "Analysing"}…` : "Loading report…"}</p>
      </div>
    );

  return (
    <div className="app-container">
      <div className={collapsed ? "app is-collapsed" : "app"}>
        <Sidebar
          view={view}
          onNavigate={navigate}
          counts={
            reportReady && REPORT_VIEWS.includes(view)
              ? { companies: reportReady.summary.companies, requests: reportReady.summary.requests }
              : {}
          }
          collapsed={collapsed}
          onToggle={() => setCollapsed((c) => !c)}
          status={statusLines}
        />
        <main className={view === "ledger" ? "main main-fill" : "main"} ref={main}>
          {error && <p className="notice notice-error">{error}</p>}
          {view === "audits" && (
            <Audits
              audits={audits}
              active={active}
              analyzing={analyzingId}
              progress={progress}
              selectedId={selectedId}
              onStart={startAudit}
              onStop={stopAudit}
              onSelect={selectAudit}
              onDelete={deleteAudit}
            />
          )}
          {view === "overview" && reportView("Overview", (r) => <Overview report={r} onOpenCompany={openCompany} onToast={toast} />)}
          {view === "companies" &&
            reportView("Companies", (r) => (
              <Companies
                auditId={r.audit.id}
                companies={r.companies}
                selected={company}
                onSelect={setCompany}
                onAct={act}
                onOpenRequest={(row, c) => setOpenRequest({ row, company: c })}
                version={version}
              />
            ))}
          {view === "requests" &&
            reportView("Requests", (r) => (
              <Requests
                key={`${r.audit.id}-${version}`}
                audit={r.audit}
                onOpenRequest={(row) => setOpenRequest({ row, company: row.company, topic: row.topic, sensitive: row.sensitive })}
              />
            ))}
          {view === "ledger" && <Ledger />}
          {view === "privacy" && (
            <Privacy
              active={active}
              latestSelfAudit={latestSelfAudit}
              analyzing={analyzingId !== null}
              onStartSelf={(m) => void startSelfAudit(m)}
              onStop={stopAudit}
            />
          )}
          {view === "settings" &&
            (settings ? (
              <Settings
                settings={settings}
                onChange={changeSetting}
                auditRunning={Boolean(active)}
                theme={theme}
                onTheme={setTheme}
                onToast={toast}
              />
            ) : (
              <div className="view">
                <p className="empty">Loading…</p>
              </div>
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
            openRequest.company && reportReady?.companies.some((c) => c.name === openRequest.company)
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
