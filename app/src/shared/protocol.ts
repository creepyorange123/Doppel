// Analyzer <-> app message format. See shared/PROTOCOL.md.
// Keep REQUEST_TYPES in sync with shared/protocol.py.

export const PROTOCOL_VERSION = "0.1.0";

export const REQUEST_TYPES = ["hello", "status"] as const;
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
}

export interface ResultMap {
  hello: HelloResult;
  status: StatusResult;
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
}

export function isRequestType(value: unknown): value is RequestType {
  return typeof value === "string" && (REQUEST_TYPES as readonly string[]).includes(value);
}
