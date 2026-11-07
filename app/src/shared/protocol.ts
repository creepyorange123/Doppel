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
