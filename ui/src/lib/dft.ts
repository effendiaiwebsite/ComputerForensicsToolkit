import { invoke } from "@tauri-apps/api/core";

export type SidecarPong = {
  ok: boolean;
  sidecar_version?: string;
  schema_version?: number;
  python_version?: string;
  platform?: string;
  error?: string;
};

export type ForensicEvent = {
  event_id: string;
  collection_id: string;
  timestamp: string | null;
  timestamp_source: "direct" | "inferred" | "none";
  host_os: string;
  host_id: string;
  user: string | null;
  source_artifact: string;
  source_path: string;
  event_type: string;
  summary: string;
  evidence: Record<string, unknown>;
  raw: Record<string, unknown>;
  parser_version: string;
};

export type TriageHiveResult = {
  ok: boolean;
  collection_id: string;
  host_id: string;
  kind?: string;
  source_path: string;
  sha256: string;
  size_bytes: number;
  event_count: number;
  by_event_type: Record<string, number>;
  error?: string;
};

export type DirectoryHiveOutcome = {
  kind: string;
  path: string;
  user_hint: string | null;
  sha256?: string;
  size_bytes?: number;
  event_count?: number;
  error?: string;
};

export type TriageDirectoryResult = {
  ok: boolean;
  collection_id: string;
  host_id: string;
  dir_path: string;
  event_count: number;
  by_event_type: Record<string, number>;
  by_source_artifact: Record<string, number>;
  hives: DirectoryHiveOutcome[];
  error?: string;
};

export type QueryEventsArgs = {
  collection_id?: string;
  event_type?: string;
  event_types?: string[];
  source_artifact?: string;
  source_artifacts?: string[];
  summary_contains?: string;
  sort_by?: "timestamp" | "event_type" | "source_artifact" | "host_id" | "user" | "summary";
  sort_dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
};

export type QueryEventsResult = {
  ok: boolean;
  events: ForensicEvent[];
  total: number;
  by_event_type: Record<string, number>;
  by_source_artifact: Record<string, number>;
  error?: string;
};

export async function pingSidecar(): Promise<SidecarPong> {
  return invoke<SidecarPong>("ping_sidecar");
}

export async function runTriageSystemHive(hivePath: string): Promise<TriageHiveResult> {
  return invoke<TriageHiveResult>("run_triage_system_hive", { hivePath });
}

export async function runTriageHive(args: {
  hive_path: string;
  kind?: string;
  user_hint?: string;
  collection_id?: string;
  host_id_hint?: string;
}): Promise<TriageHiveResult> {
  return invoke<TriageHiveResult>("run_triage_hive", { args });
}

export async function runTriageDirectory(dirPath: string): Promise<TriageDirectoryResult> {
  return invoke<TriageDirectoryResult>("run_triage_directory", { dirPath });
}

export async function queryEvents(args: QueryEventsArgs): Promise<QueryEventsResult> {
  return invoke<QueryEventsResult>("query_events", { args });
}
