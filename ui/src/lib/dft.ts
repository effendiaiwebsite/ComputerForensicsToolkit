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

export type DirectoryArtifactOutcome = {
  kind: string;
  path: string;
  channel?: string;
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
  artifacts: DirectoryArtifactOutcome[];
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
  browser_kind?: "chrome" | "edge" | "brave" | "unknown";
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

export type ExecutionCompositeRow = {
  program_path: string;
  first_seen: string | null;
  last_seen: string | null;
  sources: string[];
  event_count: number;
  total_runs: number;
};

export type ExecutionCompositeResult = {
  ok: boolean;
  rows: ExecutionCompositeRow[];
  total: number;
  error?: string;
};

export async function queryProgramExecutionComposite(args: {
  collection_id?: string;
  limit?: number;
  offset?: number;
}): Promise<ExecutionCompositeResult> {
  return invoke<ExecutionCompositeResult>("query_program_execution_composite", { args });
}

export type TimelinePoint = {
  event_id: string;
  ts_ms: number;
  category_idx: number;
  event_type: string;
  summary: string;
};

export type TimelineResult = {
  ok: boolean;
  categories: string[];
  points: TimelinePoint[];
  total: number;
  skipped_unparsable_ts: number;
  skipped_null_ts: number;
  error?: string;
};

export async function queryTimeline(args: {
  collection_id?: string;
  event_types?: string[];
  source_artifacts?: string[];
  summary_contains?: string;
  limit?: number;
}): Promise<TimelineResult> {
  return invoke<TimelineResult>("query_timeline", { args });
}

export type UsbDevice = {
  serial: string | null;
  vendor: string | null;
  product: string | null;
  device_name: string | null;
  first_installed: string | null;
  last_connected: string | null;
  last_removed: string | null;
  event_count: number;
  first_event_id: string | null;
};

export type UsbDevicesResult = {
  ok: boolean;
  devices: UsbDevice[];
  total: number;
  error?: string;
};

export async function queryUsbDevices(args: {
  collection_id?: string;
  limit?: number;
}): Promise<UsbDevicesResult> {
  return invoke<UsbDevicesResult>("query_usb_devices", { args });
}

export type BrowserDomain = {
  host: string;
  visit_count: number;
  download_count: number;
  search_count: number;
  first_seen: string | null;
  last_seen: string | null;
  browsers: string[];
  event_count: number;
};

export type BrowserDomainsResult = {
  ok: boolean;
  domains: BrowserDomain[];
  total: number;
  error?: string;
};

export async function queryBrowserDomains(args: {
  collection_id?: string;
  limit?: number;
}): Promise<BrowserDomainsResult> {
  return invoke<BrowserDomainsResult>("query_browser_domains", { args });
}

export type ActivityDay = {
  date: string;
  count: number;
  by_event_type: Record<string, number>;
  busy: boolean;
};

export type ActivityByDayResult = {
  ok: boolean;
  days: ActivityDay[];
  mean: number;
  stddev: number;
  threshold: number;
  k: number;
  busy_dates: string[];
  error?: string;
};

export async function queryActivityByDay(args: {
  collection_id?: string;
  k?: number;
}): Promise<ActivityByDayResult> {
  return invoke<ActivityByDayResult>("query_activity_by_day", { args });
}

export type GenerateReportResult = {
  ok: boolean;
  collection_id: string;
  output_path: string;
  size_bytes: number;
  sha256: string;
  error?: string;
};

export async function generateReport(args: {
  collection_id: string;
  output_path: string;
  case_name?: string;
  examiner?: string;
}): Promise<GenerateReportResult> {
  return invoke<GenerateReportResult>("generate_report", { args });
}

export type PhysicalDrive = {
  device: string;
  model: string;
  size_bytes: number;
  serial: string | null;
};

export type EnumerateDrivesResult = {
  ok: boolean;
  drives: PhysicalDrive[];
  error?: string;
};

export type LiveCollectionStart = {
  ok: boolean;
  collection_id: string;
  source: string;
  dest_dir: string;
  phase: string;
  error?: string;
};

export type ProgressSnapshot = {
  collection_id: string;
  phase: "pending" | "running" | "done" | "error";
  label: string;
  current_item: string;
  completed: number;
  total: number;
  started_at: string;
  updated_at: string;
  finished_at: string | null;
  error: string | null;
  by_category: Record<string, number>;
};

export type ProgressResult = {
  ok: boolean;
  progress?: ProgressSnapshot;
  error?: string;
};

export async function isElevated(): Promise<boolean> {
  return invoke<boolean>("is_elevated");
}

export async function defaultCollectionDir(): Promise<string> {
  return invoke<string>("default_collection_dir");
}

export async function enumerateDrives(): Promise<EnumerateDrivesResult> {
  return invoke<EnumerateDrivesResult>("enumerate_drives");
}

export async function runLiveCollection(args: {
  source: string;
  dest_dir: string;
}): Promise<LiveCollectionStart> {
  return invoke<LiveCollectionStart>("run_live_collection", { args });
}

export async function getProgress(collectionId: string): Promise<ProgressResult> {
  return invoke<ProgressResult>("get_progress", { collectionId });
}

export type FileEntry = {
  name: string;
  kind: "dir" | "file" | "symlink" | "junction" | "other";
  size: number | null;
  mtime: string | null;
  hidden: boolean;
};

export type ListDirResult = {
  ok: boolean;
  path: string;
  parent: string | null;
  source_kind: "directory" | "image" | "device" | "unknown";
  source_path: string;
  entries: FileEntry[];
  error?: string;
};

export async function listDir(args: {
  collection_id: string;
  path: string;
}): Promise<ListDirResult> {
  return invoke<ListDirResult>("list_dir", { args });
}

export type ExportFolderResult = {
  ok: boolean;
  progress_key: string;
  collection_id: string;
  src_path: string;
  dest_dir: string;
  phase: string;
  error?: string;
};

export async function exportFolder(args: {
  collection_id: string;
  src_path: string;
  dest_dir: string;
}): Promise<ExportFolderResult> {
  return invoke<ExportFolderResult>("export_folder", { args });
}

export type HashReportResult = {
  ok: boolean;
  audit_path: string;
  output_path: string;
  format: "txt" | "csv";
  rows: number;
  size_bytes: number;
  error?: string;
};

export async function exportHashReport(args: {
  audit_path: string;
  output_path: string;
  format?: "txt" | "csv";
}): Promise<HashReportResult> {
  return invoke<HashReportResult>("export_hash_report", { args });
}

export type ExportEventsResult = {
  ok: boolean;
  output_path: string;
  format: "csv" | "ndjson";
  rows: number;
  size_bytes: number;
  error?: string;
};

export async function exportEvents(args: QueryEventsArgs & {
  output_path: string;
  format?: "csv" | "ndjson";
}): Promise<ExportEventsResult> {
  return invoke<ExportEventsResult>("export_events", { args });
}

export type GetEventResult = {
  ok: boolean;
  event?: ForensicEvent;
  error?: string;
};

export async function getEvent(eventId: string): Promise<GetEventResult> {
  return invoke<GetEventResult>("get_event", { eventId });
}

export type Finding = {
  finding_id: string;
  rule_id: string;
  rule_title: string;
  severity: "low" | "medium" | "high" | "critical";
  mitre_techniques: string[];
  mitre_tactics: string[];
  evidence_event_ids: string[];
  collection_id: string;
  created_at: string;
  summary: string;
  examiner_status: string;
};

export type EvaluateRulesResult = {
  ok: boolean;
  collection_id: string;
  rules_loaded: number;
  findings_count: number;
  by_severity: Record<string, number>;
  by_rule: Record<string, number>;
  error?: string;
};

export type QueryFindingsResult = {
  ok: boolean;
  findings: Finding[];
  total: number;
  by_severity: Record<string, number>;
  error?: string;
};

export async function evaluateRules(collectionId: string): Promise<EvaluateRulesResult> {
  return invoke<EvaluateRulesResult>("evaluate_rules", { collectionId });
}

export async function queryFindings(args: {
  collection_id?: string;
  severities?: string[];
  tactic?: string;
  examiner_status?: string;
  limit?: number;
  offset?: number;
}): Promise<QueryFindingsResult> {
  return invoke<QueryFindingsResult>("query_findings", { args });
}
