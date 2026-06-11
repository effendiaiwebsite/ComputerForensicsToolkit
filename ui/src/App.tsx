import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";

import { Button } from "@/components/ui/button";

type ForensicEvent = {
  timestamp: string;
  source_artifact: string;
  event_type: string;
  host: string;
  user: string;
  summary: string;
};

type SidecarPong = {
  ok: boolean;
  sidecar_version?: string;
  schema_version?: string;
  python_version?: string;
  platform?: string;
  error?: string;
};

type SidecarState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "ok"; info: SidecarPong }
  | { kind: "error"; message: string };

const columns: ColumnDef<ForensicEvent>[] = [
  { accessorKey: "timestamp", header: "Timestamp" },
  { accessorKey: "source_artifact", header: "Source" },
  { accessorKey: "event_type", header: "Event" },
  { accessorKey: "host", header: "Host" },
  { accessorKey: "user", header: "User" },
  { accessorKey: "summary", header: "Summary" },
];

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
          sidecar: pinging…
        </span>
      );
    case "ok":
      return (
        <span className={base} title={JSON.stringify(state.info)}>
          <span className="h-2 w-2 rounded-full bg-success" />
          sidecar: v{state.info.sidecar_version} · py{state.info.python_version}{" "}
          · {state.info.platform}
        </span>
      );
    case "error":
      return (
        <span className={base} title={state.message}>
          <span className="h-2 w-2 rounded-full bg-error" />
          sidecar: error — {state.message}
        </span>
      );
  }
}

export default function App() {
  const [sidecar, setSidecar] = useState<SidecarState>({ kind: "idle" });
  const [events] = useState<ForensicEvent[]>([]);

  const table = useReactTable({
    data: events,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  async function runTriage() {
    setSidecar({ kind: "running" });
    try {
      const response = await invoke<SidecarPong>("ping_sidecar");
      if (response.ok) {
        setSidecar({ kind: "ok", info: response });
      } else {
        setSidecar({
          kind: "error",
          message: response.error ?? "sidecar returned ok=false",
        });
      }
    } catch (err) {
      setSidecar({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return (
    <div className="flex h-full flex-col bg-background text-foreground">
      <header className="flex items-center justify-between border-b border-border bg-muted/30 px-4 py-2">
        <div className="flex items-baseline gap-3">
          <h1 className="font-mono text-sm font-semibold tracking-tight">
            DFT — Digital Forensics Triage Toolkit
          </h1>
          <span className="font-mono text-xs text-muted-foreground">
            Phase 1 · Windows
          </span>
        </div>
        <div className="flex items-center gap-3">
          <StatusPill state={sidecar} />
          <Button
            onClick={runTriage}
            disabled={sidecar.kind === "running"}
            size="sm"
          >
            Run Triage
          </Button>
        </div>
      </header>

      <main className="flex-1 overflow-hidden">
        <div className="h-full overflow-auto">
          <table className="w-full border-collapse text-left font-mono text-xs">
            <thead className="sticky top-0 bg-muted/60 backdrop-blur">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id} className="border-b border-border">
                  {hg.headers.map((h) => (
                    <th
                      key={h.id}
                      className="px-3 py-2 font-semibold text-muted-foreground uppercase tracking-wide"
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  ))}
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
                    No events. Click <span className="text-foreground">Run Triage</span> to test the sidecar.
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr key={row.id} className="border-b border-border hover:bg-muted/40">
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-3 py-1.5">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </main>

      <footer className="border-t border-border bg-muted/30 px-4 py-1 font-mono text-xs text-muted-foreground">
        events: {events.length} · findings: 0 · M1 scaffold
      </footer>
    </div>
  );
}
