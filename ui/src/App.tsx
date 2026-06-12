import { useCallback, useEffect, useMemo, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, FolderOpen, FolderTree, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  pingSidecar,
  queryEvents,
  runTriageDirectory,
  runTriageHive,
  type ForensicEvent,
  type SidecarPong,
} from "@/lib/dft";
import { cn } from "@/lib/utils";

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
  }, [collection, debouncedFilter, sorting, activeTypes]);

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
    try {
      const res = await runTriageDirectory(dir);
      if (!res.ok) {
        setSidecar({ kind: "error", message: res.error ?? "directory triage failed" });
        return;
      }
      setCollection({
        collection_id: res.collection_id,
        host_id: res.host_id,
        label: `directory: ${res.dir_path} (${res.hives.length} hives)`,
        event_count: res.event_count,
        by_event_type: res.by_event_type,
        by_source_artifact: res.by_source_artifact,
      });
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
            Phase 1 · Windows · M3
          </span>
        </div>
        <div className="flex items-center gap-3">
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

      {collection && chipEntries.length > 0 && (
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
          </div>
        </main>
        <DetailPane event={selected} onClose={() => setSelected(null)} />
      </div>

      <footer className="border-t border-border bg-muted/30 px-4 py-1 font-mono text-xs text-muted-foreground">
        events: {events.length} of {total} · findings: 0 · M3
      </footer>
    </div>
  );
}
