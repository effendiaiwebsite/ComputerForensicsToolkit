import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp } from "lucide-react";
import { useMemo } from "react";

import { Input } from "@/components/ui/input";
import type { ActorConfidence, Deletion, DeletionMethod, DeletionsResult } from "@/lib/dft";
import { cn } from "@/lib/utils";

export type DeletionFilters = {
  method: DeletionMethod | "";
  confidence: ActorConfidence | "";
  user: string;
  path: string;
};

const EMPTY_FILTERS: DeletionFilters = {
  method: "",
  confidence: "",
  user: "",
  path: "",
};

const METHODS: DeletionMethod[] = ["recycle_bin", "usn_journal", "mft_unallocated"];
const CONFIDENCES: ActorConfidence[] = ["direct", "likely", "ambiguous", "unknown"];

const METHOD_LABEL: Record<DeletionMethod, string> = {
  recycle_bin: "recycle bin",
  usn_journal: "USN journal",
  mft_unallocated: "$MFT unallocated",
};

const METHOD_TITLE: Record<DeletionMethod, string> = {
  recycle_bin: "Recycle Bin $I record: file was sent to the bin; time is exact; the bin folder's SID names the deleter.",
  usn_journal: "USN change journal FILE_DELETE record: covers Shift+Delete and programmatic deletes; time is exact.",
  mft_unallocated: "Unallocated $MFT record: the file existed and its record is now free; time is an upper bound only.",
};

const METHOD_CHIP: Record<DeletionMethod, string> = {
  recycle_bin: "border-accent/40 bg-accent/10 text-accent",
  usn_journal: "border-border bg-muted/40 text-foreground",
  mft_unallocated: "border-warning/40 bg-warning/10 text-warning",
};

const CONFIDENCE_CHIP: Record<ActorConfidence, string> = {
  direct: "border-accent bg-accent text-accent-foreground",
  likely: "border-accent bg-transparent text-accent",
  ambiguous: "border-dashed border-warning bg-transparent text-warning",
  unknown: "border-border bg-muted/40 text-muted-foreground",
};

const HINT_LABEL: Record<string, [string, string]> = {
  recycle_bin_blob: ["$R blob", "A matching $R content file still exists in the Recycle Bin: content is recoverable by copying it."],
  data_runs_present: ["clusters listed", "The $MFT record still lists its data runs: content may be recoverable if the clusters were not reused (no carving is done)."],
  resident: ["resident", "The data lived inside the $MFT record itself and is still there."],
  unknown: ["—", "No recoverability evidence."],
};

const SORTABLE = new Set(["deleted_at", "path", "actor_user"]);

function humanBytes(n: number | null | undefined): string {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function MethodChip({ method }: { method: string }) {
  const m = method as DeletionMethod;
  return (
    <span
      className={cn(
        "inline-flex whitespace-nowrap rounded border px-1.5 py-0 text-[10px]",
        METHOD_CHIP[m] ?? "border-border bg-muted/40 text-muted-foreground",
      )}
      title={METHOD_TITLE[m] ?? method}
    >
      {METHOD_LABEL[m] ?? method}
    </span>
  );
}

export function ConfidenceChip({
  confidence,
  reason,
}: {
  confidence: string;
  reason: string | null | undefined;
}) {
  const c = confidence as ActorConfidence;
  return (
    <span
      className={cn(
        "inline-flex whitespace-nowrap rounded border px-1.5 py-0 text-[10px]",
        CONFIDENCE_CHIP[c] ?? CONFIDENCE_CHIP.unknown,
      )}
      title={reason || confidence}
    >
      {confidence}
    </span>
  );
}

// Left-truncated path: the outer box lays out right-to-left so the ellipsis
// lands on the left and the file name stays visible; <bdi dir="ltr"> keeps the
// path's own characters in reading order.
function PathCell({ path }: { path: string }) {
  return (
    <span dir="rtl" className="block max-w-[520px] truncate text-left font-mono" title={path}>
      <bdi dir="ltr">{path}</bdi>
    </span>
  );
}

const columns: ColumnDef<Deletion>[] = [
  {
    accessorKey: "deleted_at",
    header: "Time",
    cell: ({ row }) => {
      const d = row.original;
      if (!d.deleted_at) return <span className="text-muted-foreground">—</span>;
      if (d.time_basis === "upper_bound") {
        return (
          <span
            className="whitespace-nowrap"
            title="Upper bound: the $MFT record's last $STANDARD_INFORMATION change. The file last existed by this time; the deletion itself is not timestamped."
          >
            <span className="text-warning">≤ </span>
            {d.deleted_at}
          </span>
        );
      }
      return <span className="whitespace-nowrap">{d.deleted_at}</span>;
    },
  },
  {
    accessorKey: "path",
    header: "Path",
    cell: ({ row }) => {
      const d = row.original;
      const isDir = d.is_directory === true || d.is_directory === 1;
      return (
        <span className="flex items-center gap-1">
          {isDir && (
            <span className="shrink-0 text-[10px] text-muted-foreground" title="directory">
              dir
            </span>
          )}
          <PathCell path={d.path || d.name || "—"} />
        </span>
      );
    },
  },
  {
    accessorKey: "method",
    header: "Method",
    cell: ({ getValue }) => <MethodChip method={getValue<string>()} />,
  },
  {
    accessorKey: "actor_user",
    header: "User",
    cell: ({ row }) => {
      const d = row.original;
      return (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span className={d.actor_user ? "text-foreground" : "text-muted-foreground"} title={d.actor_sid ?? undefined}>
            {d.actor_user ?? "—"}
          </span>
          <ConfidenceChip confidence={d.actor_confidence} reason={d.actor_reason} />
        </span>
      );
    },
  },
  {
    accessorKey: "owner_user",
    header: "Owner",
    cell: ({ row }) => {
      const d = row.original;
      if (d.owner_user) return <span title={d.owner_sid ?? undefined}>{d.owner_user}</span>;
      if (d.owner_sid)
        return (
          <span className="block max-w-[180px] truncate text-muted-foreground" title={d.owner_sid}>
            {d.owner_sid}
          </span>
        );
      return <span className="text-muted-foreground">—</span>;
    },
  },
  {
    accessorKey: "size",
    header: () => <span className="block text-right">Size</span>,
    cell: ({ getValue }) => (
      <span className="block whitespace-nowrap text-right text-muted-foreground">{humanBytes(getValue<number | null>())}</span>
    ),
  },
  {
    accessorKey: "recoverable_hint",
    header: "Recoverable",
    cell: ({ getValue }) => {
      const v = getValue<string | null>() ?? "unknown";
      const [label, title] = HINT_LABEL[v] ?? [v, v];
      return (
        <span className={cn("whitespace-nowrap", label === "—" ? "text-muted-foreground" : "")} title={title}>
          {label}
        </span>
      );
    },
  },
];

const selectClass =
  "h-8 rounded-md border border-border bg-muted/40 px-2 text-xs font-mono outline-none focus-visible:ring-2 focus-visible:ring-accent";

export function DeletedFiles({
  result,
  hasCollection,
  filters,
  onFiltersChange,
  sorting,
  onSortingChange,
  selectedEventId,
  onSelect,
}: {
  result: DeletionsResult | null;
  hasCollection: boolean;
  filters: DeletionFilters;
  onFiltersChange: (next: DeletionFilters) => void;
  sorting: SortingState;
  onSortingChange: (updater: SortingState | ((old: SortingState) => SortingState)) => void;
  selectedEventId: string | null;
  onSelect: (eventId: string) => void;
}) {
  const rows = useMemo(() => result?.deletions ?? [], [result]);

  // eslint-disable-next-line react-hooks/incompatible-library -- React Compiler is not enabled; this only warns that auto-memoization would be skipped
  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange,
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
  });

  const topActors = useMemo(() => {
    if (!result) return [];
    return [...result.by_actor]
      .filter((a) => a.actor_user)
      .sort((a, b) => b.count - a.count)
      .slice(0, 3);
  }, [result]);

  const filtersActive =
    filters.method !== "" || filters.confidence !== "" || filters.user !== "" || filters.path !== "";

  return (
    <div className="flex h-full flex-col font-mono text-xs">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border bg-muted/10 px-4 py-2">
        <Stat label="deleted" value={result ? result.total.toLocaleString() : "—"} />
        {METHODS.map((m) => (
          <span key={m} className="inline-flex items-center gap-1.5">
            <MethodChip method={m} />
            <span className="text-foreground">{(result?.by_method[m] ?? 0).toLocaleString()}</span>
          </span>
        ))}
        {result && result.bursts > 0 && (
          <span
            className="inline-flex items-center gap-1.5 rounded border border-error/40 bg-error/10 px-1.5 py-0 text-[10px] text-error"
            title="Bulk deletions: 20 or more by one method inside a 120-second window"
          >
            bursts {result.bursts}
          </span>
        )}
        {topActors.length > 0 && (
          <span className="inline-flex items-center gap-2">
            <span className="text-muted-foreground">top users</span>
            {topActors.map((a) => (
              <button
                key={`${a.actor_user}:${a.actor_confidence}`}
                type="button"
                className="inline-flex items-center gap-1 hover:underline"
                title={`filter by ${a.actor_user}`}
                onClick={() => onFiltersChange({ ...filters, user: a.actor_user ?? "" })}
              >
                <span className="text-foreground">{a.actor_user}</span>
                <ConfidenceChip confidence={a.actor_confidence} reason={null} />
                <span className="text-muted-foreground">{a.count}</span>
              </button>
            ))}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/5 px-4 py-2">
        <select
          className={selectClass}
          value={filters.method}
          onChange={(e) => onFiltersChange({ ...filters, method: e.target.value as DeletionFilters["method"] })}
          disabled={!hasCollection}
          aria-label="method"
        >
          <option value="">any method</option>
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {METHOD_LABEL[m]}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={filters.confidence}
          onChange={(e) =>
            onFiltersChange({ ...filters, confidence: e.target.value as DeletionFilters["confidence"] })
          }
          disabled={!hasCollection}
          aria-label="actor confidence"
        >
          <option value="">any confidence</option>
          {CONFIDENCES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <Input
          className="w-44"
          placeholder="user…"
          value={filters.user}
          onChange={(e) => onFiltersChange({ ...filters, user: e.target.value })}
          disabled={!hasCollection}
        />
        <Input
          className="w-80"
          placeholder="path contains…"
          value={filters.path}
          onChange={(e) => onFiltersChange({ ...filters, path: e.target.value })}
          disabled={!hasCollection}
        />
        {filtersActive && (
          <button
            type="button"
            onClick={() => onFiltersChange(EMPTY_FILTERS)}
            className="text-muted-foreground underline hover:text-foreground"
          >
            clear
          </button>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-left">
          <thead className="sticky top-0 bg-muted/60 backdrop-blur">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-b border-border">
                {hg.headers.map((h) => {
                  const sortDir = h.column.getIsSorted();
                  const sortable = SORTABLE.has(h.column.id);
                  return (
                    <th
                      key={h.id}
                      className={cn(
                        "select-none px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground",
                        sortable && "cursor-pointer hover:text-foreground",
                      )}
                      onClick={sortable ? h.column.getToggleSortingHandler() : undefined}
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
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-3 py-16 text-center text-muted-foreground">
                  {!hasCollection ? (
                    <>No collection loaded. Open a directory or run a live collection to begin.</>
                  ) : filtersActive ? (
                    <>No deletions match the current filters.</>
                  ) : (
                    <>
                      No deletions in this collection. Load a <span className="text-foreground">$Recycle.Bin</span>,
                      <span className="text-foreground"> $UsnJrnl:$J</span> or <span className="text-foreground">$MFT</span>{" "}
                      artifact to populate <span className="text-foreground">file_delete</span> events.
                    </>
                  )}
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => {
                const isSelected = selectedEventId === row.original.event_id;
                return (
                  <tr
                    key={row.id}
                    className={cn(
                      "cursor-pointer border-b border-border",
                      isSelected ? "bg-accent/20" : "hover:bg-muted/40",
                    )}
                    onClick={() => onSelect(row.original.event_id)}
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
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-baseline gap-1.5">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-sm font-semibold text-foreground">{value}</span>
    </span>
  );
}
