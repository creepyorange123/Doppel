// Analyzer <-> app message format. See shared/PROTOCOL.md.
// Keep REQUEST_TYPES in sync with shared/protocol.py.

export const PROTOCOL_VERSION = "0.1.0";

export const REQUEST_TYPES = [
  "hello",
  "status",
  // Phase 1: app list
  "list_apps",
  "set_app_rule",
  "set_domain_rule",
  "set_tracking_mode",
  "delete_app_data",
  // Phase 2
  "analyze_since_last_open",
  // Phase 5
  "get_settings",
  "set_setting",
  "ledger_verify",
  "ledger_list",
  // Phase 6
  "report",
  "company_detail",
  "take_action",
  "undo_action",
  "list_requests",
] as const;
export type RequestType = (typeof REQUEST_TYPES)[number];

export interface HelloResult {
  version: string;
  db_path_set: boolean;
}

export interface StatusResult {
  request_count: number;
  unanalyzed_count: number;
  install_at: number | null;
  last_opened_at: number | null;
  recorder_heartbeat_at: number | null;
  consent_at: number | null;
}

export type CaptureRule = "track" | "metadata_only" | "dont_track";

export interface AppEntry {
  key: string;
  path: string;
  name: string | null;
  requests: number;
  last_seen_at: number | null;
  running: boolean;
  rule: CaptureRule | null;
  rule_source: "user" | "auto" | null;
}

export interface AppList {
  mode: "blocklist" | "allowlist";
  apps: AppEntry[];
  domains: { domain: string; rule: CaptureRule }[];
}

export type Ok = { ok: true };

export interface ResultMap {
  hello: HelloResult;
  status: StatusResult;
  list_apps: AppList;
  set_app_rule: Ok;
  set_domain_rule: Ok;
  set_tracking_mode: Ok;
  delete_app_data: { deleted: number };
  analyze_since_last_open: AnalyzeResult;
  get_settings: Settings;
  set_setting: Ok;
  ledger_verify: LedgerVerify;
  ledger_list: { entries: LedgerEntry[]; latest_hash: string };
  report: Report;
  company_detail: CompanyDetail;
  take_action: { ok: true; letter?: string; domains?: string[] };
  undo_action: Ok;
  list_requests: { requests: RequestListItem[]; truncated: boolean };
}

export type Tier = "Low" | "Moderate" | "Profile-building" | "High concern";
export type ActionName = "block" | "strip" | "opt-out" | "letter";

export interface Settings {
  zero_network: boolean;
  gpc: boolean;
  local_ai: boolean;
  california: boolean;
  tracking_mode: "blocklist" | "allowlist";
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
  since: number;
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

export interface Report {
  summary: ReportSummary;
  companies: CompanyRow[];
  /** Requests per tier since the last open (exact, not per company). */
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
  since: number;
  finished_at: number;
}

/** Recorder controls, handled by the Electron main process (not the analyzer). */
export const RECORDER_ACTIONS = ["install", "uninstall", "status"] as const;
export type RecorderAction = (typeof RECORDER_ACTIONS)[number];
export interface RecorderResult {
  ok: boolean;
  output: string;
}

export interface ProgressEvent {
  done: number;
  total: number;
  label: string;
}

export type AnalyzerEvent =
  | { type: "ready"; payload: { version: string } }
  | { type: "progress"; payload: ProgressEvent }
  | { type: "exit"; payload: { code: number | null } };

export interface ShadowApi {
  request<T extends RequestType>(type: T, payload?: Record<string, unknown>): Promise<ResultMap[T]>;
  onEvent(listener: (event: AnalyzerEvent) => void): () => void;
  recorder(action: RecorderAction): Promise<RecorderResult>;
}

export function isRecorderAction(value: unknown): value is RecorderAction {
  return typeof value === "string" && (RECORDER_ACTIONS as readonly string[]).includes(value);
}

export function isRequestType(value: unknown): value is RequestType {
  return typeof value === "string" && (REQUEST_TYPES as readonly string[]).includes(value);
}
