// Analyzer <-> app message format. See shared/PROTOCOL.md.
// Keep REQUEST_TYPES in sync with shared/protocol.py.

export const PROTOCOL_VERSION = "0.2.0";

export const REQUEST_TYPES = [
  "hello",
  "status",
  // Audits
  "list_running_apps",
  "list_audits",
  "audit_live",
  "analyze_audit",
  "delete_audit",
  "self_audit_result",
  // Capture rules (domains that are never recorded, or kept as metadata only)
  "list_domain_rules",
  "set_domain_rule",
  // Settings and outgoing calls
  "get_settings",
  "set_setting",
  "ledger_verify",
  "ledger_list",
  // Report for one audit
  "report",
  "company_detail",
  "take_action",
  "list_requests",
  // Hand findings to your own blocker (uBlock Origin, NextDNS, Little Snitch, ...)
  "export_blocklist",
  // Privacy screen
  "privacy_checks",
  // Main process only: the renderer may not send these (see RENDERER_REQUEST_TYPES).
  "create_audit",
  "finish_audit",
] as const;
export type RequestType = (typeof REQUEST_TYPES)[number];

/** Audits are started and stopped by the main process (shadow:audit), never by a
 *  renderer request, so it alone decides which processes are captured. */
export const MAIN_ONLY_REQUEST_TYPES = ["create_audit", "finish_audit"] as const;
export type RendererRequestType = Exclude<RequestType, (typeof MAIN_ONLY_REQUEST_TYPES)[number]>;

export interface HelloResult {
  version: string;
  db_path_set: boolean;
}

export interface StatusResult {
  request_count: number;
  unanalyzed_count: number;
  install_at: number | null;
  consent_at: number | null;
  /** The audit being recorded right now, if any. */
  active_audit_id: number | null;
}

/** An app that is running now and can be audited (helpers are folded into their app). */
export interface RunningApp {
  path: string;
  name: string;
  processes: number;
  is_browser: boolean;
  /** Setup advice for this browser (e.g. Firefox-based ones and the certificate), or null. */
  hint: string | null;
}

export type AuditStatus = "running" | "done" | "interrupted" | "failed";
export type AppCapture = "full" | "metadata_only";

export interface AuditApp {
  path: string;
  name: string;
  capture: AppCapture;
  is_browser: boolean;
}

export interface Audit {
  id: number;
  label: string;
  apps: AuditApp[];
  self_audit: boolean;
  started_at: number;
  ends_at: number;
  ended_at: number | null;
  status: AuditStatus;
  requests: number;
  analyzed: boolean;
  error: string | null;
}

/** Live, metadata-only counts while an audit records (polled every few seconds). */
export interface AuditLive {
  audit: Audit;
  requests: number;
  last_at: number | null;
  apps: { name: string; requests: number }[];
  processes: { app: string; process: string; requests: number }[];
  domains: { domain: string; requests: number }[];
}

export type DomainRule = "metadata_only" | "dont_track";

export interface SelfAuditConnection {
  process: string;
  domain: string;
  requests: number;
  /** True when the connection matches an entry in the outgoing-calls ledger. */
  in_ledger: boolean;
}

export interface SelfAuditResult {
  audit: Audit;
  connections: SelfAuditConnection[];
  ledger_entries: number;
  unexpected: number;
  verdict: "clean" | "unexpected" | "no_traffic";
}

export type Ok = { ok: true };

export interface ResultMap {
  hello: HelloResult;
  status: StatusResult;
  list_running_apps: { apps: RunningApp[] };
  list_audits: { audits: Audit[] };
  audit_live: AuditLive;
  analyze_audit: AnalyzeResult;
  delete_audit: { deleted: number };
  self_audit_result: SelfAuditResult;
  list_domain_rules: { domains: { domain: string; rule: DomainRule }[] };
  set_domain_rule: Ok;
  get_settings: Settings;
  set_setting: Ok;
  ledger_verify: LedgerVerify;
  ledger_list: { entries: LedgerEntry[]; latest_hash: string };
  report: Report;
  company_detail: CompanyDetail;
  take_action: { ok: true; letter?: string };
  list_requests: { requests: RequestListItem[]; truncated: boolean };
  export_blocklist: Blocklist;
  privacy_checks: PrivacyChecks;
  create_audit: { audit: Audit };
  finish_audit: { audit: Audit };
}

/** One live privacy check. ok: true verified, false problem found, null not applicable. */
export interface PrivacyCheck {
  id: string;
  title: string;
  ok: boolean | null;
  detail: string;
}
export interface PrivacyChecks {
  checks: PrivacyCheck[];
  ran_at: number;
  passed: number;
  failed: number;
}

export type BlocklistFormat = "ublock" | "hosts" | "domains" | "little_snitch";

/** An audit's tracker domains, ready to import into another tool. Never includes sites you visited. */
export interface Blocklist {
  format: BlocklistFormat;
  min_tier: Tier;
  domains: string[];
  count: number;
  works_with: string;
  /** DNS-level formats only: tracker domains left out because people also visit them directly. */
  skipped: string[];
  filename: string;
  content: string;
}

export type Tier = "Minimum utility" | "Measurement" | "Profile building" | "High concern";
export type ActionName = "opt-out" | "letter";

export interface Settings {
  zero_network: boolean;
  local_ai: boolean;
  california: boolean;
}

export interface LedgerVerify {
  ok: boolean;
  entries: number;
  broken_at: number | null;
  latest_hash: string;
}

export interface LedgerEntry {
  id: number;
  sent_at: number;
  destination: string;
  payload: Record<string, unknown>;
  hash: string;
}

export interface ReportSummary {
  requests: number;
  companies: number;
  high_concern: number;
}

export interface CompanyRow {
  name: string;
  category: string | null;
  max_score: number;
  tier: Tier;
  apps: string[];
  requests: number;
  actions_taken: ActionName[];
}

/** One audited app, with the processes it spawned that sent traffic. */
/** A site visited in a browser, or a destination an app phones home to. */
export interface ReportGroup {
  name: string;
  requests: number;
  companies: string[];
  max_score: number;
  tier: Tier;
  /** Destinations only: the app maker's own servers. */
  own?: boolean;
}

export interface ReportApp {
  name: string;
  is_browser: boolean;
  /** Browsers: sites you visited, with the companies each one brought along. */
  sites?: ReportGroup[];
  /** Other apps: who they phone home to (their maker, bundled SDKs, trackers). */
  destinations?: ReportGroup[];
  requests: number;
  companies: number;
  max_score: number;
  tier: Tier;
  processes: { name: string; requests: number }[];
}

export interface Report {
  audit: Audit;
  summary: ReportSummary;
  apps: ReportApp[];
  companies: CompanyRow[];
  /** Requests per tier in this audit (exact, not per company). */
  tier_requests: Record<Tier, number>;
  /** Requests per local day, oldest first. */
  by_day: { date: string; counts: Record<Tier, number> }[];
}

export interface BreakdownItem {
  signal: string;
  label: string;
  points: number;
}

export interface RequestRow {
  id: number;
  captured_at: number;
  app_name: string | null;
  process_name: string | null;
  dest_domain: string;
  summary: string;
  score: number;
  tier: Tier;
  breakdown: BreakdownItem[];
}

export interface RequestListItem extends RequestRow {
  company: string | null;
  topic: string | null;
  sensitive: boolean;
}

export interface CompanyDetail {
  card: {
    name: string;
    policy_summary: string | null;
    is_data_broker: boolean | null;
    opt_out_url: string | null;
    opt_out_domain: string | null;
    news: string[];
    sources: string[];
    researched_at: number | null;
    from_snapshot: boolean | null;
    exposure: { requests: number; apps: Record<string, number>; topics: Record<string, number>; flags: Record<string, number> };
  };
  requests: RequestRow[];
  actions: ActionName[];
  california: boolean;
}

export interface AnalyzeResult {
  analyzed: number;
  audit_id: number | null;
  finished_at: number;
}

/** Certificate controls, handled by the Electron main process (not the analyzer).
 *  There is no background service: the recorder only runs during an audit. */
export const RECORDER_ACTIONS = ["install", "uninstall", "status"] as const;
export type RecorderAction = (typeof RECORDER_ACTIONS)[number];
export interface RecorderResult {
  ok: boolean;
  output: string;
}

/** Audit controls on the shadow:audit channel, handled by the main process. */
export const AUDIT_ACTIONS = ["start", "self", "stop", "state"] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];
export interface StartAuditPayload {
  apps: { path: string; name: string; capture?: AppCapture }[];
  minutes: number;
  label?: string;
}
export interface AuditControlResult {
  ok: boolean;
  audit: Audit | null;
  error?: string;
}

export interface ProgressEvent {
  done: number;
  total: number;
  label: string;
}

export type AnalyzerEvent =
  | { type: "ready"; payload: { version: string } }
  | { type: "progress"; payload: ProgressEvent }
  | { type: "exit"; payload: { code: number | null } }
  | { type: "audit"; payload: { audit_id: number; state: "started" | "ended"; ok: boolean; message?: string } };

export interface ShadowApi {
  request<T extends RendererRequestType>(type: T, payload?: Record<string, unknown>): Promise<ResultMap[T]>;
  onEvent(listener: (event: AnalyzerEvent) => void): () => void;
  recorder(action: RecorderAction): Promise<RecorderResult>;
  /** Save text to a file the user picks in a save dialog. Resolves false if cancelled. */
  saveFile(filename: string, content: string): Promise<boolean>;
  /** start: StartAuditPayload; self: {minutes}; stop / state: no payload. */
  audit(action: AuditAction, payload?: Record<string, unknown>): Promise<AuditControlResult>;
}

export function isRecorderAction(value: unknown): value is RecorderAction {
  return typeof value === "string" && (RECORDER_ACTIONS as readonly string[]).includes(value);
}

export function isAuditAction(value: unknown): value is AuditAction {
  return typeof value === "string" && (AUDIT_ACTIONS as readonly string[]).includes(value);
}

export function isRequestType(value: unknown): value is RequestType {
  return typeof value === "string" && (REQUEST_TYPES as readonly string[]).includes(value);
}

/** What the renderer may send: every request type except the main-only ones. */
export function isRendererRequestType(value: unknown): value is RendererRequestType {
  return isRequestType(value) && !(MAIN_ONLY_REQUEST_TYPES as readonly string[]).includes(value);
}
