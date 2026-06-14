import { useCallback, useEffect, useMemo, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { Activity, ArrowDown, ArrowUp, FolderOpen, FolderTree, Globe, Layers, ShieldAlert, Table2, Usb, X } from "lucide-react";

import { Timeline } from "@/components/Timeline";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  evaluateRules,
  getEvent,
  pingSidecar,
  queryBrowserDomains,
  queryEvents,
  queryFindings,
  queryProgramExecutionComposite,
  queryTimeline,
  queryUsbDevices,
  runTriageDirectory,
  runTriageHive,
  type BrowserDomain,
  type ExecutionCompositeRow,
  type Finding,
  type ForensicEvent,
  type SidecarPong,
  type TimelinePoint,
  type UsbDevice,
} from "@/lib/dft";
import { cn } from "@/lib/utils";

type ViewMode = "events" | "execution" | "timeline" | "findings" | "devices" | "browser";

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

function DetailPane({ event, onClose }: { event: ForensicEvent | null; onClose: () => void }) {
  if (!event) return null;
  return (
    <aside className="flex w-[480px] flex-col border-l border-border bg-muted/20">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <div className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
          Event detail
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
          <X className="h-4 w-4" />
        </Button>
      </div>
      <div className="flex-1 overflow-auto p-3 font-mono text-xs">
        <div className="mb-2">
          <div className="text-muted-foreground">summary</div>
          <div className="text-foreground">{event.summary}</div>
        </div>
        <div className="mb-2 grid grid-cols-2 gap-x-3 gap-y-1">
          <Field k="time" v={event.timestamp ?? "—"} />
          <Field k="time source" v={event.timestamp_source} />
          <Field k="event_type" v={event.event_type} />
          <Field k="source" v={event.source_artifact} />
          <Field k="host" v={event.host_id} />
          <Field k="user" v={event.user ?? "—"} />
          <Field k="parser" v={event.parser_version} />
          <Field k="event_id" v={event.event_id} />
        </div>
        <Section title="evidence" data={event.evidence} />
        <Section title="raw" data={event.raw} />
        <div className="mt-3 break-all text-muted-foreground">
          source_path: <span className="text-foreground">{event.source_path}</span>
        </div>
      </div>
    </aside>
  );
}

function Field({ k, v }: { k: string; v: string }) {
  return (
    <>
      <div className="text-muted-foreground">{k}</div>
      <div className="truncate text-foreground" title={v}>
        {v}
      </div>
    </>
  );
}

function Section({ title, data }: { title: string; data: Record<string, unknown> }) {
  return (
    <div className="mt-3">
      <div className="mb-1 text-muted-foreground uppercase tracking-wide">{title}</div>
      <pre className="overflow-auto rounded border border-border bg-background/50 p-2 text-[11px] leading-[1.35]">
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
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
  }, []);

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
      <header className="flex items-center justify-between gap-3 border-b border-border bg-muted/30 px-4 py-2">
        <div className="flex items-baseline gap-3">
          <h1 className="font-mono text-sm font-semibold tracking-tight">
            DFT — Digital Forensics Triage Toolkit
          </h1>
          <span className="font-mono text-xs text-muted-foreground">
            Phase 1 · Windows · M9
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-md border border-border overflow-hidden">
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
          </div>
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
        </div>
      </header>

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

      {view !== "execution" && view !== "devices" && view !== "browser" && collection && chipEntries.length > 0 && (
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
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <main className="flex-1 overflow-hidden">
          <div className="h-full overflow-auto">
            {view === "events" ? (
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
            ) : (
              <BrowserTable domains={browserDomains} hasCollection={!!collection} />
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
          ? `usb devices: ${usbDevices.length} · findings: ${findingsTotal} · M9`
          : `browser hosts: ${browserDomains.length} · findings: ${findingsTotal} · M9`}
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
