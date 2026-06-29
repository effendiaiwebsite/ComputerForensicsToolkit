import { useCallback, useEffect, useMemo, useState } from "react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { Activity, AlertTriangle, ArrowDown, ArrowUp, FileText, Files, FolderOpen, FolderTree, Globe, HardDrive, Layers, ShieldAlert, Table2, Usb, X } from "lucide-react";

import { DetailPane } from "@/components/DetailPane";
import { FilesBrowser } from "@/components/FilesBrowser";
import { Timeline } from "@/components/Timeline";
import { Welcome } from "@/components/Welcome";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  enumerateDrives,
  evaluateRules,
  exportEvents,
  generateReport,
  getEvent,
  getProgress,
  isElevated,
  pingSidecar,
  queryBrowserDomains,
  queryEvents,
  queryFindings,
  queryProgramExecutionComposite,
  queryTimeline,
  queryUsbDevices,
  runLiveCollection,
  runTriageDirectory,
  runTriageHive,
  type BrowserDomain,
  type ExecutionCompositeRow,
  type Finding,
  type ForensicEvent,
  type PhysicalDrive,
  type ProgressSnapshot,
  type SidecarPong,
  type TimelinePoint,
  type UsbDevice,
} from "@/lib/dft";
import { cn } from "@/lib/utils";

type ViewMode = "events" | "execution" | "timeline" | "findings" | "devices" | "browser" | "files";

const SEVERITY_BADGE: Record<Finding["severity"], string> = {
  critical: "bg-error/20 text-error border-error/40",
  high: "bg-warning/20 text-warning border-warning/40",
  medium: "bg-accent/20 text-accent border-accent/40",
  low: "bg-muted/40 text-muted-foreground border-border",
};

const SEVERITY_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low"];

type SidecarState =
  | { kind: "idle" }
  | { kind: "running"; what: string }
  | { kind: "ok"; info: SidecarPong }
  | { kind: "error"; message: string };

type Collection = {
  collection_id: string;
  host_id: string;
  label: string;
  event_count: number;
  by_event_type: Record<string, number>;
  by_source_artifact: Record<string, number>;
};

const columns: ColumnDef<ForensicEvent>[] = [
  {
    accessorKey: "timestamp",
    header: "Time",
    cell: ({ getValue }) => {
      const v = getValue<string | null>();
      return v ? <span className="whitespace-nowrap">{v}</span> : <span className="text-muted-foreground">—</span>;
    },
  },
  { accessorKey: "source_artifact", header: "Source" },
  { accessorKey: "event_type", header: "Event" },
  { accessorKey: "host_id", header: "Host" },
  {
    accessorKey: "user",
    header: "User",
    cell: ({ getValue }) => {
      const v = getValue<string | null>();
      return v ?? <span className="text-muted-foreground">—</span>;
    },
  },
  {
    accessorKey: "summary",
    header: "Summary",
    cell: ({ getValue }) => (
      <span className="block max-w-[640px] truncate">{getValue<string>()}</span>
    ),
  },
];

const SORTABLE_COLS = new Set([
  "timestamp",
  "source_artifact",
  "event_type",
  "host_id",
  "user",
  "summary",
]);

const EVENT_TYPE_PRIORITY: string[] = [
  "program_execution",
  "program_install",
  "persistence_entry",
  "usb_connection",
  "service_install",
  "account_change",
  "browser_download",
  "browser_visit",
  "browser_search",
  "file_access",
  "shell_command",
  "system_config_change",
];

function rankEventType(t: string): number {
  const idx = EVENT_TYPE_PRIORITY.indexOf(t);
  return idx === -1 ? 999 : idx;
}

function StatusPill({ state }: { state: SidecarState }) {
  const base =
    "inline-flex items-center gap-2 rounded-full border border-border px-3 py-1 text-xs font-mono";
  switch (state.kind) {
    case "idle":
      return (
        <span className={base}>
          <span className="h-2 w-2 rounded-full bg-muted-foreground" />
          sidecar: idle
        </span>
      );
    case "running":
      return (
        <span className={base}>
          <span className="h-2 w-2 rounded-full bg-warning animate-pulse" />
          sidecar: {state.what}…
        </span>
      );
    case "ok":
      return (
        <span className={base} title={JSON.stringify(state.info)}>
          <span className="h-2 w-2 rounded-full bg-success" />
          sidecar: v{state.info.sidecar_version} · py{state.info.python_version} · {state.info.platform}
        </span>
      );
    case "error":
      return (
        <span className={base} title={state.message}>
          <span className="h-2 w-2 rounded-full bg-error" />
          sidecar: error — <span className="max-w-[280px] truncate">{state.message}</span>
        </span>
      );
  }
}

function Chip({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-mono transition-colors",
        active
          ? "border-accent bg-accent/20 text-foreground"
          : "border-border bg-muted/30 text-muted-foreground hover:text-foreground hover:border-muted-foreground",
      )}
    >
      <span>{label}</span>
      <span className={cn("rounded px-1.5 py-0 text-[10px]", active ? "bg-accent/30" : "bg-muted/60")}>{count}</span>
    </button>
  );
}

export default function App() {
  const [sidecar, setSidecar] = useState<SidecarState>({ kind: "idle" });
  const [collection, setCollection] = useState<Collection | null>(null);
  const [events, setEvents] = useState<ForensicEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<ForensicEvent | null>(null);
  const [filter, setFilter] = useState("");
  const [debouncedFilter, setDebouncedFilter] = useState("");
  const [sorting, setSorting] = useState<SortingState>([{ id: "timestamp", desc: false }]);
  const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set());
  const [view, setView] = useState<ViewMode>("events");
  const [execRows, setExecRows] = useState<ExecutionCompositeRow[]>([]);
  const [execTotal, setExecTotal] = useState(0);
  const [timelineCategories, setTimelineCategories] = useState<string[]>([]);
  const [timelinePoints, setTimelinePoints] = useState<TimelinePoint[]>([]);
  const [timelineSkippedNull, setTimelineSkippedNull] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsBySeverity, setFindingsBySeverity] = useState<Record<string, number>>({});
  const [activeSeverity, setActiveSeverity] = useState<Set<Finding["severity"]>>(new Set());
  const [usbDevices, setUsbDevices] = useState<UsbDevice[]>([]);
  const [browserDomains, setBrowserDomains] = useState<BrowserDomain[]>([]);
  const [reportOpen, setReportOpen] = useState(false);
  const [elevated, setElevated] = useState<boolean | null>(null);
  const [liveOpen, setLiveOpen] = useState(false);
  const [liveProgress, setLiveProgress] = useState<ProgressSnapshot | null>(null);

  useEffect(() => {
    pingSidecar()
      .then((info) =>
        info.ok
          ? setSidecar({ kind: "ok", info })
          : setSidecar({ kind: "error", message: info.error ?? "ok=false" }),
      )
      .catch((err) =>
        setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) }),
      );
    isElevated().then(setElevated).catch(() => setElevated(false));
  }, []);

  useEffect(() => {
    if (!liveProgress || liveProgress.phase !== "running") return;
    const id = liveProgress.collection_id;
    const handle = window.setInterval(async () => {
      try {
        const r = await getProgress(id);
        if (r.ok && r.progress) setLiveProgress(r.progress);
      } catch {
        // transient errors — keep polling
      }
    }, 500);
    return () => window.clearInterval(handle);
  }, [liveProgress?.collection_id, liveProgress?.phase]);

  // When a live collection finishes, switch the active view to it so the
  // examiner sees the just-collected events without a manual reload.
  useEffect(() => {
    if (!liveProgress || liveProgress.phase !== "done") return;
    const cid = liveProgress.collection_id;
    (async () => {
      try {
        const res = await queryEvents({ collection_id: cid, limit: 1 });
        if (!res.ok) return;
        setCollection({
          collection_id: cid,
          host_id: "—",
          label: liveProgress.label,
          event_count: res.total,
          by_event_type: res.by_event_type,
          by_source_artifact: res.by_source_artifact,
        });
        setSelected(null);
        setActiveTypes(new Set());
        setActiveSeverity(new Set());
        setView("events");
      } catch (err) {
        console.warn("auto-load after live collection failed", err);
      }
    })();
  }, [liveProgress?.collection_id, liveProgress?.phase]);

  useEffect(() => {
    const id = setTimeout(() => setDebouncedFilter(filter), 250);
    return () => clearTimeout(id);
  }, [filter]);

  const refresh = useCallback(async () => {
    if (!collection) return;
    if (view === "execution") {
      try {
        const res = await queryProgramExecutionComposite({
          collection_id: collection.collection_id,
          limit: 1000,
        });
        if (res.ok) {
          setExecRows(res.rows);
          setExecTotal(res.total);
        } else {
          setSidecar({ kind: "error", message: res.error ?? "composite query failed" });
        }
      } catch (err) {
        setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      }
      return;
    }
    if (view === "timeline") {
      try {
        const res = await queryTimeline({
          collection_id: collection.collection_id,
          summary_contains: debouncedFilter || undefined,
          event_types: activeTypes.size ? Array.from(activeTypes) : undefined,
          limit: 100_000,
        });
        if (res.ok) {
          setTimelineCategories(res.categories);
          setTimelinePoints(res.points);
          setTimelineSkippedNull(res.skipped_null_ts);
        } else {
          setSidecar({ kind: "error", message: res.error ?? "timeline query failed" });
        }
      } catch (err) {
        setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      }
      return;
    }
    if (view === "devices") {
      try {
        const res = await queryUsbDevices({
          collection_id: collection.collection_id,
          limit: 1000,
        });
        if (res.ok) {
          setUsbDevices(res.devices);
        } else {
          setSidecar({ kind: "error", message: res.error ?? "usb devices query failed" });
        }
      } catch (err) {
        setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      }
      return;
    }
    if (view === "browser") {
      try {
        const res = await queryBrowserDomains({
          collection_id: collection.collection_id,
          limit: 1000,
        });
        if (res.ok) {
          setBrowserDomains(res.domains);
        } else {
          setSidecar({ kind: "error", message: res.error ?? "browser domains query failed" });
        }
      } catch (err) {
        setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      }
      return;
    }
    if (view === "findings") {
      try {
        const res = await queryFindings({
          collection_id: collection.collection_id,
          severities: activeSeverity.size ? Array.from(activeSeverity) : undefined,
          limit: 500,
        });
        if (res.ok) {
          setFindings(res.findings);
          setFindingsTotal(res.total);
          setFindingsBySeverity(res.by_severity);
        } else {
          setSidecar({ kind: "error", message: res.error ?? "findings query failed" });
        }
      } catch (err) {
        setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      }
      return;
    }
    const sortCol = sorting[0]?.id;
    const sort_by = sortCol && SORTABLE_COLS.has(sortCol) ? (sortCol as never) : "timestamp";
    const sort_dir = sorting[0]?.desc ? "desc" : "asc";
    try {
      const res = await queryEvents({
        collection_id: collection.collection_id,
        summary_contains: debouncedFilter || undefined,
        event_types: activeTypes.size ? Array.from(activeTypes) : undefined,
        sort_by,
        sort_dir,
        limit: 1000,
      });
      if (res.ok) {
        setEvents(res.events);
        setTotal(res.total);
        setCollection((c) =>
          c
            ? {
                ...c,
                event_count: res.total,
                by_event_type: res.by_event_type,
                by_source_artifact: res.by_source_artifact,
              }
            : c,
        );
      } else {
        setSidecar({ kind: "error", message: res.error ?? "query failed" });
      }
    } catch (err) {
      setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }, [collection, view, debouncedFilter, sorting, activeTypes, activeSeverity]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function openHive() {
    let path: string | null = null;
    try {
      const selection = await openDialog({
        multiple: false,
        directory: false,
        title: "Select a registry hive",
      });
      path = typeof selection === "string" ? selection : null;
    } catch (err) {
      setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      return;
    }
    if (!path) return;

    setSidecar({ kind: "running", what: "parsing hive" });
    setSelected(null);
    setEvents([]);
    setActiveTypes(new Set());
    setActiveSeverity(new Set());
    setFindings([]);
    setFindingsTotal(0);
    setFindingsBySeverity({});
    try {
      const res = await runTriageHive({ hive_path: path });
      if (!res.ok) {
        setSidecar({ kind: "error", message: res.error ?? "triage failed" });
        return;
      }
      setCollection({
        collection_id: res.collection_id,
        host_id: res.host_id,
        label: `${res.kind ?? "hive"}: ${res.source_path}`,
        event_count: res.event_count,
        by_event_type: res.by_event_type,
        by_source_artifact: {},
      });
      setSidecar({ kind: "running", what: "evaluating rules" });
      try {
        const ev = await evaluateRules(res.collection_id);
        if (ev.ok) setFindingsBySeverity(ev.by_severity);
      } catch (err) {
        console.warn("rule eval failed", err);
      }
      const pong = await pingSidecar();
      if (pong.ok) setSidecar({ kind: "ok", info: pong });
    } catch (err) {
      setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  async function openDirectory() {
    let dir: string | null = null;
    try {
      const selection = await openDialog({
        multiple: false,
        directory: true,
        title: "Select a triage directory of hives",
      });
      dir = typeof selection === "string" ? selection : null;
    } catch (err) {
      setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      return;
    }
    if (!dir) return;

    setSidecar({ kind: "running", what: "parsing directory" });
    setSelected(null);
    setEvents([]);
    setActiveTypes(new Set());
    setActiveSeverity(new Set());
    setFindings([]);
    setFindingsTotal(0);
    setFindingsBySeverity({});
    try {
      const res = await runTriageDirectory(dir);
      if (!res.ok) {
        setSidecar({ kind: "error", message: res.error ?? "directory triage failed" });
        return;
      }
      setCollection({
        collection_id: res.collection_id,
        host_id: res.host_id,
        label: `directory: ${res.dir_path} (${res.artifacts.length} artifacts)`,
        event_count: res.event_count,
        by_event_type: res.by_event_type,
        by_source_artifact: res.by_source_artifact,
      });
      setSidecar({ kind: "running", what: "evaluating rules" });
      try {
        const ev = await evaluateRules(res.collection_id);
        if (ev.ok) setFindingsBySeverity(ev.by_severity);
      } catch (err) {
        console.warn("rule eval failed", err);
      }
      const pong = await pingSidecar();
      if (pong.ok) setSidecar({ kind: "ok", info: pong });
    } catch (err) {
      setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  function toggleType(t: string) {
    setActiveTypes((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  }

  async function exportCurrentEventView(fmt: "csv" | "ndjson") {
    if (!collection) return;
    try {
      const sel = await saveDialog({
        title: `Export Events view as ${fmt.toUpperCase()}`,
        defaultPath: `dft-events.${fmt}`,
        filters: fmt === "csv"
          ? [{ name: "CSV", extensions: ["csv"] }]
          : [{ name: "NDJSON", extensions: ["ndjson", "jsonl"] }],
      });
      if (typeof sel !== "string" || !sel) return;
      const sortCol = sorting[0]?.id;
      const sort_by = sortCol && SORTABLE_COLS.has(sortCol) ? (sortCol as never) : "timestamp";
      const sort_dir = sorting[0]?.desc ? "desc" : "asc";
      const res = await exportEvents({
        collection_id: collection.collection_id,
        summary_contains: debouncedFilter || undefined,
        event_types: activeTypes.size ? Array.from(activeTypes) : undefined,
        sort_by,
        sort_dir,
        limit: 1_000_000,
        output_path: sel,
        format: fmt,
      });
      if (!res.ok) {
        setSidecar({ kind: "error", message: res.error ?? "event export failed" });
      }
    } catch (err) {
      setSidecar({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  const table = useReactTable({
    data: events,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
  });

  const chipEntries = useMemo(() => {
    if (!collection) return [] as [string, number][];
    return Object.entries(collection.by_event_type).sort(
      ([a, ac], [b, bc]) => rankEventType(a) - rankEventType(b) || bc - ac,
    );
  }, [collection]);

  return (
    <div className="flex h-full flex-col bg-background text-foreground">
      <header className="flex flex-col border-b border-border bg-muted/30">
        <div className="flex items-center justify-between gap-3 px-4 py-2">
          <div className="flex items-baseline gap-3 min-w-0">
            <h1 className="font-mono text-sm font-semibold tracking-tight whitespace-nowrap">
              DFT — Digital Forensics Triage Toolkit
            </h1>
            <span className="font-mono text-xs text-muted-foreground whitespace-nowrap">
              Phase 1 · Windows · M14
            </span>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <StatusPill state={sidecar} />
            <Button onClick={openHive} disabled={sidecar.kind === "running"} size="sm">
              <FolderOpen className="h-4 w-4" />
              Open hive…
            </Button>
            <Button
              onClick={openDirectory}
              disabled={sidecar.kind === "running"}
              size="sm"
              variant="secondary"
            >
              <FolderTree className="h-4 w-4" />
              Open directory…
            </Button>
            <Button
              onClick={() => setReportOpen(true)}
              disabled={sidecar.kind === "running" || !collection}
              size="sm"
              variant="secondary"
            >
              <FileText className="h-4 w-4" />
              Generate report…
            </Button>
            <Button
              onClick={() => setLiveOpen(true)}
              disabled={sidecar.kind === "running" || liveProgress?.phase === "running"}
              size="sm"
              title={
                elevated === false
                  ? "Image files work without admin; physical drives require administrator."
                  : "Collect artifacts from a live physical drive or disk image"
              }
            >
              <HardDrive className="h-4 w-4" />
              Collect live…
            </Button>
          </div>
        </div>
        <div className="flex items-center gap-2 px-4 pb-2 overflow-x-auto">
          <div className="flex rounded-md border border-border overflow-hidden shrink-0">
            <button
              type="button"
              onClick={() => setView("events")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5",
                view === "events"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <Table2 className="h-3 w-3" />
              Events
            </button>
            <button
              type="button"
              onClick={() => setView("execution")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5 border-l border-border",
                view === "execution"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <Layers className="h-3 w-3" />
              Execution
            </button>
            <button
              type="button"
              onClick={() => setView("timeline")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5 border-l border-border",
                view === "timeline"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <Activity className="h-3 w-3" />
              Timeline
            </button>
            <button
              type="button"
              onClick={() => setView("findings")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5 border-l border-border",
                view === "findings"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <ShieldAlert className="h-3 w-3" />
              Findings
              {findingsBySeverity && (findingsBySeverity.critical || findingsBySeverity.high) ? (
                <span className="rounded bg-error/20 text-error border border-error/40 px-1.5 py-0 text-[10px]">
                  {(findingsBySeverity.critical ?? 0) + (findingsBySeverity.high ?? 0)}
                </span>
              ) : null}
            </button>
            <button
              type="button"
              onClick={() => setView("devices")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5 border-l border-border",
                view === "devices"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <Usb className="h-3 w-3" />
              Devices
            </button>
            <button
              type="button"
              onClick={() => setView("browser")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5 border-l border-border",
                view === "browser"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <Globe className="h-3 w-3" />
              Browser
            </button>
            <button
              type="button"
              onClick={() => setView("files")}
              className={cn(
                "px-3 py-1.5 text-xs font-mono inline-flex items-center gap-1.5 border-l border-border",
                view === "files"
                  ? "bg-accent text-accent-foreground"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
              disabled={!collection}
            >
              <Files className="h-3 w-3" />
              Files
            </button>
          </div>
        </div>
      </header>

      {elevated === false && (
        <div className="flex items-center gap-2 border-b border-warning/40 bg-warning/10 px-4 py-1.5 font-mono text-xs text-warning">
          <AlertTriangle className="h-3.5 w-3.5" />
          <span>
            Running without administrator privileges. Hive / directory triage and disk-image
            ingest work; physical-drive enumeration (live system) requires admin. Relaunch as
            administrator to read <span className="font-mono">\\.\PhysicalDriveN</span>.
          </span>
        </div>
      )}

      {liveProgress && (
        <LiveProgressBar
          snap={liveProgress}
          onDismiss={() => setLiveProgress(null)}
        />
      )}

      {reportOpen && collection && (
        <ReportModal
          collection={collection}
          onClose={() => setReportOpen(false)}
          onGenerated={(path) =>
            setSidecar({ kind: "ok", info: { ok: true, sidecar_version: `saved: ${path}` } })
          }
          onError={(message) => setSidecar({ kind: "error", message })}
        />
      )}

      {liveOpen && (
        <LiveCollectModal
          onClose={() => setLiveOpen(false)}
          onStart={(snap) => {
            setLiveProgress(snap);
            setLiveOpen(false);
          }}
          onError={(message) => setSidecar({ kind: "error", message })}
        />
      )}

      <div className="flex items-center gap-3 border-b border-border bg-muted/10 px-4 py-2">
        <div className="w-80 shrink-0">
          <Input
            placeholder="filter summary…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            disabled={!collection}
          />
        </div>
        <div className="flex-1 truncate font-mono text-xs text-muted-foreground">
          {collection ? (
            <>
              <span className="text-foreground">{collection.host_id}</span>
              {" · "}
              <span title={collection.label}>{collection.label}</span>
            </>
          ) : (
            <span>no collection loaded — open a hive or a triage directory to begin</span>
          )}
        </div>
      </div>

      {view !== "execution" && view !== "devices" && view !== "browser" && view !== "files" && collection && chipEntries.length > 0 && (
        <div className="flex flex-wrap gap-2 border-b border-border bg-muted/5 px-4 py-2">
          {chipEntries.map(([type, count]) => (
            <Chip
              key={type}
              label={type}
              count={count}
              active={activeTypes.has(type)}
              onClick={() => toggleType(type)}
            />
          ))}
          {activeTypes.size > 0 && (
            <button
              type="button"
              onClick={() => setActiveTypes(new Set())}
              className="text-xs font-mono text-muted-foreground underline hover:text-foreground"
            >
              clear
            </button>
          )}
          {view === "events" && (
            <div className="ml-auto flex items-center gap-1">
              <button
                type="button"
                onClick={() => void exportCurrentEventView("csv")}
                className="text-xs font-mono text-muted-foreground underline hover:text-foreground"
                title="Export the currently-filtered Events view as CSV"
              >
                export csv
              </button>
              <span className="text-muted-foreground">·</span>
              <button
                type="button"
                onClick={() => void exportCurrentEventView("ndjson")}
                className="text-xs font-mono text-muted-foreground underline hover:text-foreground"
                title="Export the currently-filtered Events view as NDJSON (one JSON object per line)"
              >
                ndjson
              </button>
            </div>
          )}
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <main className="flex-1 overflow-hidden">
          <div className="h-full overflow-auto">
            {!collection ? (
              <Welcome
                elevated={elevated}
                onOpenHive={openHive}
                onOpenDirectory={openDirectory}
                onCollectLive={() => setLiveOpen(true)}
              />
            ) : view === "events" ? (
              <table className="w-full border-collapse text-left font-mono text-xs">
                <thead className="sticky top-0 bg-muted/60 backdrop-blur">
                  {table.getHeaderGroups().map((hg) => (
                    <tr key={hg.id} className="border-b border-border">
                      {hg.headers.map((h) => {
                        const sortDir = h.column.getIsSorted();
                        return (
                          <th
                            key={h.id}
                            className={cn(
                              "select-none px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground",
                              SORTABLE_COLS.has(h.column.id) && "cursor-pointer hover:text-foreground",
                            )}
                            onClick={
                              SORTABLE_COLS.has(h.column.id)
                                ? h.column.getToggleSortingHandler()
                                : undefined
                            }
                          >
                            <span className="inline-flex items-center gap-1">
                              {flexRender(h.column.columnDef.header, h.getContext())}
                              {sortDir === "asc" && <ArrowUp className="h-3 w-3" />}
                              {sortDir === "desc" && <ArrowDown className="h-3 w-3" />}
                            </span>
                          </th>
                        );
                      })}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {table.getRowModel().rows.length === 0 ? (
                    <tr>
                      <td
                        colSpan={columns.length}
                        className="px-3 py-16 text-center text-muted-foreground"
                      >
                        {collection ? (
                          <>No events match the current filter.</>
                        ) : (
                          <>
                            No events. Click <span className="text-foreground">Open hive…</span>
                            {" "}or <span className="text-foreground">Open directory…</span> to begin.
                          </>
                        )}
                      </td>
                    </tr>
                  ) : (
                    table.getRowModel().rows.map((row) => {
                      const isSelected = selected?.event_id === row.original.event_id;
                      return (
                        <tr
                          key={row.id}
                          className={cn(
                            "cursor-pointer border-b border-border",
                            isSelected ? "bg-accent/20" : "hover:bg-muted/40",
                          )}
                          onClick={() => setSelected(row.original)}
                        >
                          {row.getVisibleCells().map((cell) => (
                            <td key={cell.id} className="px-3 py-1.5 align-top">
                              {flexRender(cell.column.columnDef.cell, cell.getContext())}
                            </td>
                          ))}
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            ) : view === "execution" ? (
              <ExecutionTable rows={execRows} hasCollection={!!collection} />
            ) : view === "timeline" ? (
              <Timeline
                categories={timelineCategories}
                points={timelinePoints}
                onEventClick={async (eventId) => {
                  try {
                    const res = await getEvent(eventId);
                    if (res.ok && res.event) setSelected(res.event);
                  } catch (err) {
                    setSidecar({
                      kind: "error",
                      message: err instanceof Error ? err.message : String(err),
                    });
                  }
                }}
              />
            ) : view === "findings" ? (
              <FindingsTable
                findings={findings}
                hasCollection={!!collection}
                activeSeverity={activeSeverity}
                onToggleSeverity={(s) =>
                  setActiveSeverity((prev) => {
                    const next = new Set(prev);
                    next.has(s) ? next.delete(s) : next.add(s);
                    return next;
                  })
                }
                bySeverity={findingsBySeverity}
                onJump={async (eventId) => {
                  try {
                    const res = await getEvent(eventId);
                    if (res.ok && res.event) setSelected(res.event);
                  } catch (err) {
                    setSidecar({
                      kind: "error",
                      message: err instanceof Error ? err.message : String(err),
                    });
                  }
                }}
              />
            ) : view === "devices" ? (
              <DevicesTable
                devices={usbDevices}
                hasCollection={!!collection}
                onSelect={async (eventId) => {
                  try {
                    const res = await getEvent(eventId);
                    if (res.ok && res.event) setSelected(res.event);
                  } catch (err) {
                    setSidecar({
                      kind: "error",
                      message: err instanceof Error ? err.message : String(err),
                    });
                  }
                }}
              />
            ) : view === "browser" ? (
              <BrowserTable domains={browserDomains} hasCollection={!!collection} />
            ) : (
              <FilesBrowser
                collectionId={collection?.collection_id ?? null}
                onError={(msg) => setSidecar({ kind: "error", message: msg })}
              />
            )}
          </div>
        </main>
        <DetailPane event={selected} onClose={() => setSelected(null)} />
      </div>

      <footer className="border-t border-border bg-muted/30 px-4 py-1 font-mono text-xs text-muted-foreground">
        {view === "events"
          ? `events: ${events.length} of ${total} · findings: ${findingsTotal} · M9`
          : view === "execution"
          ? `unique programs: ${execRows.length} of ${execTotal} · findings: ${findingsTotal} · M9`
          : view === "timeline"
          ? `timeline: ${timelinePoints.length} dated points across ${timelineCategories.length} tracks (${timelineSkippedNull} undated) · findings: ${findingsTotal} · M9`
          : view === "findings"
          ? `findings: ${findings.length} of ${findingsTotal} · M9`
          : view === "devices"
          ? `usb devices: ${usbDevices.length} · findings: ${findingsTotal} · M14`
          : view === "browser"
          ? `browser hosts: ${browserDomains.length} · findings: ${findingsTotal} · M14`
          : `image filesystem browser · M14`}
      </footer>
    </div>
  );
}

function FindingsTable({
  findings,
  hasCollection,
  activeSeverity,
  onToggleSeverity,
  bySeverity,
  onJump,
}: {
  findings: Finding[];
  hasCollection: boolean;
  activeSeverity: Set<Finding["severity"]>;
  onToggleSeverity: (s: Finding["severity"]) => void;
  bySeverity: Record<string, number>;
  onJump: (eventId: string) => void;
}) {
  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/10 px-4 py-2">
        {SEVERITY_ORDER.map((sev) => {
          const count = bySeverity[sev] ?? 0;
          const active = activeSeverity.has(sev);
          return (
            <button
              key={sev}
              type="button"
              onClick={() => onToggleSeverity(sev)}
              disabled={count === 0}
              className={cn(
                "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-mono uppercase tracking-wide transition-colors",
                count === 0 && "opacity-30 pointer-events-none",
                active ? SEVERITY_BADGE[sev] : "border-border bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
            >
              <span>{sev}</span>
              <span className="rounded bg-background/40 px-1.5 py-0 text-[10px]">{count}</span>
            </button>
          );
        })}
      </div>
      <div className="flex-1 overflow-auto">
        {!hasCollection ? (
          <div className="px-3 py-16 text-center text-muted-foreground font-mono text-xs">
            No collection. Open a hive or a triage directory to evaluate rules.
          </div>
        ) : findings.length === 0 ? (
          <div className="px-3 py-16 text-center text-muted-foreground font-mono text-xs">
            No findings match the current severity filter.
          </div>
        ) : (
          <table className="w-full border-collapse text-left font-mono text-xs">
            <thead className="sticky top-0 bg-muted/60 backdrop-blur">
              <tr className="border-b border-border">
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Severity</th>
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Rule</th>
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">MITRE</th>
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.finding_id}
                  className="border-b border-border hover:bg-muted/40 cursor-pointer"
                  onClick={() => f.evidence_event_ids[0] && onJump(f.evidence_event_ids[0])}
                >
                  <td className="px-3 py-1.5 align-top">
                    <span
                      className={cn(
                        "inline-flex rounded border px-1.5 py-0 text-[10px] uppercase tracking-wide",
                        SEVERITY_BADGE[f.severity],
                      )}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 align-top">
                    <div className="text-foreground">{f.rule_title}</div>
                    <div className="text-muted-foreground text-[10px]">{f.rule_id}</div>
                  </td>
                  <td className="px-3 py-1.5 align-top">
                    <div className="flex flex-wrap gap-1">
                      {f.mitre_techniques.map((t) => (
                        <span
                          key={t}
                          className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0 text-[10px] text-accent"
                          title={f.mitre_tactics.join(", ")}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 align-top">
                    <span className="block max-w-[640px] truncate" title={f.summary}>
                      {f.summary}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ExecutionTable({
  rows,
  hasCollection,
}: {
  rows: ExecutionCompositeRow[];
  hasCollection: boolean;
}) {
  if (rows.length === 0) {
    return (
      <table className="w-full border-collapse text-left font-mono text-xs">
        <tbody>
          <tr>
            <td className="px-3 py-16 text-center text-muted-foreground">
              {hasCollection ? (
                <>No program_execution events in this collection.</>
              ) : (
                <>
                  No collection loaded. Click <span className="text-foreground">Open directory…</span>{" "}
                  on a folder that includes Prefetch, AmCache, or a SYSTEM hive.
                </>
              )}
            </td>
          </tr>
        </tbody>
      </table>
    );
  }
  return (
    <table className="w-full border-collapse text-left font-mono text-xs">
      <thead className="sticky top-0 bg-muted/60 backdrop-blur">
        <tr className="border-b border-border">
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Program</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">First seen</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Last seen</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Sources</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Events</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Runs</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.program_path} className="border-b border-border hover:bg-muted/40">
            <td className="px-3 py-1.5 align-top">
              <span className="block max-w-[640px] truncate" title={row.program_path}>
                {row.program_path}
              </span>
            </td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap text-muted-foreground">
              {row.first_seen ?? "—"}
            </td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap">{row.last_seen ?? "—"}</td>
            <td className="px-3 py-1.5 align-top">
              <div className="flex flex-wrap gap-1">
                {row.sources.map((s) => (
                  <span
                    key={s}
                    className="rounded border border-border bg-muted/30 px-1.5 py-0 text-[10px]"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </td>
            <td className="px-3 py-1.5 align-top text-right">{row.event_count}</td>
            <td className="px-3 py-1.5 align-top text-right">
              {row.total_runs > 0 ? row.total_runs : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DevicesTable({
  devices,
  hasCollection,
  onSelect,
}: {
  devices: UsbDevice[];
  hasCollection: boolean;
  onSelect: (eventId: string) => void;
}) {
  if (devices.length === 0) {
    return (
      <table className="w-full border-collapse text-left font-mono text-xs">
        <tbody>
          <tr>
            <td className="px-3 py-16 text-center text-muted-foreground">
              {hasCollection ? (
                <>
                  No USB devices in this collection. Load a SYSTEM hive to populate
                  <span className="text-foreground"> usb_connection</span> events.
                </>
              ) : (
                <>
                  No collection loaded. Click <span className="text-foreground">Open directory…</span> to begin.
                </>
              )}
            </td>
          </tr>
        </tbody>
      </table>
    );
  }
  return (
    <table className="w-full border-collapse text-left font-mono text-xs">
      <thead className="sticky top-0 bg-muted/60 backdrop-blur">
        <tr className="border-b border-border">
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Vendor / Product</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Friendly name</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Serial</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">First installed</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Last connected</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Last removed</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Events</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr
            key={d.serial ?? `unknown-${d.first_event_id}`}
            className={cn(
              "border-b border-border hover:bg-muted/40",
              d.first_event_id ? "cursor-pointer" : "",
            )}
            onClick={() => d.first_event_id && onSelect(d.first_event_id)}
          >
            <td className="px-3 py-1.5 align-top">
              <span className="text-foreground">{d.vendor ?? "?"}</span>
              <span className="text-muted-foreground"> · </span>
              <span>{d.product ?? "?"}</span>
            </td>
            <td className="px-3 py-1.5 align-top">
              {d.device_name ? (
                <span title={d.device_name}>{d.device_name}</span>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </td>
            <td className="px-3 py-1.5 align-top">
              <span className="break-all" title={d.serial ?? undefined}>
                {d.serial ?? "—"}
              </span>
            </td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap text-muted-foreground">
              {d.first_installed ?? "—"}
            </td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap">{d.last_connected ?? "—"}</td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap text-muted-foreground">
              {d.last_removed ?? "—"}
            </td>
            <td className="px-3 py-1.5 align-top text-right">{d.event_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function BrowserTable({
  domains,
  hasCollection,
}: {
  domains: BrowserDomain[];
  hasCollection: boolean;
}) {
  if (domains.length === 0) {
    return (
      <table className="w-full border-collapse text-left font-mono text-xs">
        <tbody>
          <tr>
            <td className="px-3 py-16 text-center text-muted-foreground">
              {hasCollection ? (
                <>
                  No browser activity in this collection. Load a Chromium-family
                  <span className="text-foreground"> History</span> DB to populate
                  <span className="text-foreground"> browser_visit</span>,
                  <span className="text-foreground"> browser_download</span>, and
                  <span className="text-foreground"> browser_search</span> events.
                </>
              ) : (
                <>
                  No collection loaded. Click <span className="text-foreground">Open hive…</span> to begin.
                </>
              )}
            </td>
          </tr>
        </tbody>
      </table>
    );
  }
  return (
    <table className="w-full border-collapse text-left font-mono text-xs">
      <thead className="sticky top-0 bg-muted/60 backdrop-blur">
        <tr className="border-b border-border">
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Host</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Browsers</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Visits</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Downloads</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Searches</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">First seen</th>
          <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {domains.map((d) => (
          <tr key={d.host} className="border-b border-border hover:bg-muted/40">
            <td className="px-3 py-1.5 align-top">
              <span className="break-all text-foreground" title={d.host}>{d.host}</span>
            </td>
            <td className="px-3 py-1.5 align-top text-muted-foreground">
              {d.browsers.length ? d.browsers.join(", ") : "—"}
            </td>
            <td className="px-3 py-1.5 align-top text-right">{d.visit_count}</td>
            <td
              className={cn(
                "px-3 py-1.5 align-top text-right",
                d.download_count > 0 ? "text-warning" : "",
              )}
            >
              {d.download_count}
            </td>
            <td className="px-3 py-1.5 align-top text-right">{d.search_count}</td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap text-muted-foreground">
              {d.first_seen ?? "—"}
            </td>
            <td className="px-3 py-1.5 align-top whitespace-nowrap">{d.last_seen ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LiveCollectModal({
  onClose,
  onStart,
  onError,
}: {
  onClose: () => void;
  onStart: (snap: ProgressSnapshot) => void;
  onError: (message: string) => void;
}) {
  const [drives, setDrives] = useState<PhysicalDrive[] | null>(null);
  const [mode, setMode] = useState<"live" | "image">("live");
  const [imagePath, setImagePath] = useState("");
  const [destDir, setDestDir] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    enumerateDrives()
      .then((r) => setDrives(r.ok ? r.drives : []))
      .catch(() => setDrives([]));
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    setDestDir(`collected/${ts}`);
  }, []);

  async function browseImage() {
    try {
      const sel = await openDialog({
        multiple: false,
        directory: false,
        title: "Pick a disk image (E01 / raw)",
      });
      if (typeof sel === "string") {
        setImagePath(sel);
        setMode("image");
      }
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function browseDestDir() {
    try {
      const sel = await openDialog({
        multiple: false,
        directory: true,
        title: "Pick destination folder for collected artifacts",
      });
      if (typeof sel === "string") setDestDir(sel);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function submit() {
    if (busy) return;
    const source = mode === "live" ? "local" : imagePath;
    if (!source) {
      onError(mode === "image" ? "pick a disk image" : "no live source available");
      return;
    }
    if (!destDir) {
      onError("pick a destination folder");
      return;
    }
    setBusy(true);
    try {
      const res = await runLiveCollection({ source, dest_dir: destDir });
      if (!res.ok) {
        onError(res.error ?? "live collection failed to start");
        return;
      }
      onStart({
        collection_id: res.collection_id,
        phase: "running",
        label: `live collection from ${res.source}`,
        current_item: "starting…",
        completed: 0,
        total: 0,
        started_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        finished_at: null,
        error: null,
        by_category: {},
      });
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-[560px] rounded-md border border-border bg-card p-4 font-mono text-xs shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold">Live disk collection</div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="mb-3">
          <div className="mb-1 text-muted-foreground">Source</div>
          <label
            className={cn(
              "mb-1 flex cursor-pointer items-start gap-2 rounded border border-border p-2 hover:bg-muted/40",
              mode === "live" ? "bg-accent/20" : "",
            )}
          >
            <input
              type="radio"
              name="src-mode"
              checked={mode === "live"}
              onChange={() => setMode("live")}
              className="mt-0.5"
            />
            <div className="min-w-0 flex-1">
              <div className="text-foreground">Live local system (all mounted volumes)</div>
              <div className="text-muted-foreground">
                Reads via dissect.target's local loader — requires administrator.
              </div>
              {drives && drives.length > 0 && (
                <ul className="mt-1 space-y-0.5 text-muted-foreground">
                  {drives.map((d) => (
                    <li key={d.device}>
                      <span className="text-foreground">{d.device}</span>
                      <span> · {d.model}</span>
                      <span> · {(d.size_bytes / 1_000_000_000).toFixed(0)} GB</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </label>

          <label
            className={cn(
              "flex cursor-pointer items-start gap-2 rounded border border-border p-2 hover:bg-muted/40",
              mode === "image" ? "bg-accent/20" : "",
            )}
          >
            <input
              type="radio"
              name="src-mode"
              checked={mode === "image"}
              onChange={() => setMode("image")}
              className="mt-0.5"
            />
            <div className="min-w-0 flex-1">
              <div className="text-foreground">Disk image (E01 / raw)</div>
              <div className="mt-1 flex items-center gap-2">
                <Input
                  placeholder="path to .E01 / .img / .dd"
                  value={imagePath}
                  onChange={(e) => setImagePath(e.target.value)}
                  className="flex-1"
                  onFocus={() => setMode("image")}
                />
                <Button variant="secondary" size="sm" onClick={browseImage}>
                  Browse…
                </Button>
              </div>
            </div>
          </label>
        </div>

        <div className="mb-3">
          <div className="mb-1 text-muted-foreground">Destination folder</div>
          <div className="flex items-center gap-2">
            <Input
              value={destDir}
              onChange={(e) => setDestDir(e.target.value)}
              className="flex-1"
            />
            <Button variant="secondary" size="sm" onClick={browseDestDir}>
              Browse…
            </Button>
          </div>
          <div className="mt-1 text-muted-foreground">
            Each collected file is SHA-256 hashed; audit.jsonl is written alongside.
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={submit} disabled={busy}>
            {busy ? "Starting…" : "Start collection"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function LiveProgressBar({
  snap,
  onDismiss,
}: {
  snap: ProgressSnapshot;
  onDismiss: () => void;
}) {
  const pct = snap.total > 0 ? Math.min(100, Math.round((snap.completed / snap.total) * 100)) : 0;
  const tone =
    snap.phase === "error" ? "border-error/40 bg-error/10 text-error"
    : snap.phase === "done" ? "border-accent/40 bg-accent/10 text-accent"
    : "border-accent/40 bg-accent/10 text-foreground";
  return (
    <div className={cn("border-b px-4 py-2 font-mono text-xs", tone)}>
      <div className="mb-1 flex items-center gap-3">
        <HardDrive className="h-3.5 w-3.5" />
        <span className="font-semibold">{snap.label}</span>
        <span className="text-muted-foreground">
          {snap.completed.toLocaleString()} / {snap.total > 0 ? snap.total.toLocaleString() : "?"}
        </span>
        <span className="ml-auto text-muted-foreground">{snap.phase}</span>
        {(snap.phase === "done" || snap.phase === "error") && (
          <Button variant="ghost" size="icon" onClick={onDismiss} aria-label="Dismiss">
            <X className="h-3 w-3" />
          </Button>
        )}
      </div>
      <div className="h-1 w-full overflow-hidden rounded bg-muted/40">
        <div
          className={cn(
            "h-full transition-all duration-300",
            snap.phase === "error" ? "bg-error" : "bg-accent",
          )}
          style={{ width: snap.phase === "done" ? "100%" : `${pct}%` }}
        />
      </div>
      <div className="mt-1 truncate text-muted-foreground" title={snap.current_item}>
        {snap.error ? snap.error : snap.current_item || "—"}
      </div>
    </div>
  );
}

function ReportModal({
  collection,
  onClose,
  onGenerated,
  onError,
}: {
  collection: Collection;
  onClose: () => void;
  onGenerated: (path: string) => void;
  onError: (message: string) => void;
}) {
  const [caseName, setCaseName] = useState(`Triage — ${collection.host_id}`);
  const [examiner, setExaminer] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (busy) return;
    setBusy(true);
    try {
      const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const defaultName = `dft-report-${collection.host_id}-${today}.html`;
      const target = await saveDialog({
        title: "Save DFT report",
        defaultPath: defaultName,
        filters: [{ name: "HTML", extensions: ["html"] }],
      });
      if (!target) {
        setBusy(false);
        return;
      }
      const res = await generateReport({
        collection_id: collection.collection_id,
        output_path: target,
        case_name: caseName.trim() || "Untitled case",
        examiner: examiner.trim() || "—",
      });
      if (res.ok) {
        onGenerated(res.output_path);
        onClose();
      } else {
        onError(res.error ?? "report generation failed");
      }
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-[420px] rounded-md border border-border bg-card p-4 font-mono text-xs shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold">Generate report</div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="mb-3">
          <label className="mb-1 block text-muted-foreground">Case name</label>
          <Input value={caseName} onChange={(e) => setCaseName(e.target.value)} autoFocus />
        </div>
        <div className="mb-3">
          <label className="mb-1 block text-muted-foreground">Examiner</label>
          <Input
            value={examiner}
            onChange={(e) => setExaminer(e.target.value)}
            placeholder="your name"
          />
        </div>
        <div className="mb-3 text-muted-foreground">
          {collection.event_count.toLocaleString()} events from{" "}
          <span className="text-foreground">{collection.host_id}</span> will be summarised. PDF
          export: open the HTML in your browser, Ctrl+P → Save as PDF.
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={submit} disabled={busy}>
            {busy ? "Generating…" : "Save report…"}
          </Button>
        </div>
      </div>
    </div>
  );
}
