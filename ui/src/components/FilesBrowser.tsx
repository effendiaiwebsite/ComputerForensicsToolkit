import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { ChevronRight, Download, File, FileDigit, Folder, HardDrive } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  exportFolder,
  exportHashReport,
  getProgress,
  listDir,
  type FileEntry,
  type ListDirResult,
  type ProgressSnapshot,
} from "@/lib/dft";
import { cn } from "@/lib/utils";

// App.tsx remounts this component (key=collectionId) per collection, so all
// state here — listing, export progress, last export destination — is
// per-collection by construction.
export function FilesBrowser({
  collectionId,
  onError,
}: {
  collectionId: string | null;
  onError: (msg: string) => void;
}) {
  const [path, setPath] = useState("/");
  const [data, setData] = useState<ListDirResult | null>(null);
  const [loading, setLoading] = useState(collectionId !== null);
  const [showHidden, setShowHidden] = useState(true);
  const [filter, setFilter] = useState("");
  const [exportProgress, setExportProgress] = useState<ProgressSnapshot | null>(null);
  const [lastExportDest, setLastExportDest] = useState<string | null>(null);

  // App.tsx passes a fresh onError function every render, which would make
  // `load` (and the effect that calls it) re-fire forever. Capture the latest
  // onError in a ref so the load callback stays stable across renders.
  const onErrorRef = useRef(onError);
  useEffect(() => {
    onErrorRef.current = onError;
  }, [onError]);

  // State is only touched inside promise callbacks, so the mount effect below
  // can call this without a synchronous setState (initial `loading` is true).
  const fetchDir = useCallback(
    (p: string) => {
      if (!collectionId) return;
      listDir({ collection_id: collectionId, path: p })
        .then((res) => {
          if (res.ok) {
            setData(res);
            setPath(res.path);
          } else {
            onErrorRef.current(res.error ?? "list_dir failed");
          }
        })
        .catch((err: unknown) => onErrorRef.current(err instanceof Error ? err.message : String(err)))
        .finally(() => setLoading(false));
    },
    [collectionId],
  );

  function load(p: string) {
    setLoading(true);
    fetchDir(p);
  }

  useEffect(() => {
    fetchDir("/");
  }, [fetchDir]);

  // Poll export progress while a job is running. One poll at a time: a slow
  // sidecar op must not pile up hundreds of get_progress calls.
  const exportKey = exportProgress?.collection_id;
  const exportPhase = exportProgress?.phase;
  useEffect(() => {
    if (!exportKey || exportPhase !== "running") return;
    let inFlight = false;
    const handle = window.setInterval(async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const r = await getProgress(exportKey);
        if (r.ok && r.progress) setExportProgress(r.progress);
      } catch {
        // transient
      } finally {
        inFlight = false;
      }
    }, 500);
    return () => window.clearInterval(handle);
  }, [exportKey, exportPhase]);

  async function saveHashReport(fmt: "txt" | "csv") {
    if (!lastExportDest) return;
    try {
      const sel = await saveDialog({
        title: "Save hash report",
        defaultPath: `dft-hash-report.${fmt}`,
        filters: fmt === "csv"
          ? [{ name: "CSV", extensions: ["csv"] }]
          : [{ name: "Text", extensions: ["txt"] }],
      });
      if (typeof sel !== "string" || !sel) return;
      const auditPath = `${lastExportDest.replace(/[\\/]+$/, "")}/audit.jsonl`;
      const res = await exportHashReport({
        audit_path: auditPath,
        output_path: sel,
        format: fmt,
      });
      if (!res.ok) {
        onError(res.error ?? "hash report failed");
        return;
      }
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function startExport() {
    if (!collectionId || !data) return;
    try {
      const sel = await openDialog({
        multiple: false,
        directory: true,
        title: `Pick destination for ${path}`,
      });
      if (typeof sel !== "string" || !sel) return;
      const res = await exportFolder({
        collection_id: collectionId,
        src_path: path,
        dest_dir: sel,
      });
      if (!res.ok) {
        onError(res.error ?? "export failed");
        return;
      }
      setLastExportDest(sel);
      setExportProgress({
        // ProgressTracker keys this job under its own progress_key, not the
        // collection_id; we reuse the snapshot's collection_id field as the
        // poll id since ProgressTracker writes it back as the snapshot id.
        collection_id: res.progress_key,
        phase: "running",
        label: `exporting ${path} → ${sel}`,
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
    }
  }

  const counts = useMemo(() => {
    if (!data) return { dirs: 0, files: 0, hidden: 0 };
    let dirs = 0;
    let files = 0;
    let hidden = 0;
    for (const e of data.entries) {
      if (e.kind === "dir") dirs += 1;
      else if (e.kind === "file") files += 1;
      if (e.hidden) hidden += 1;
    }
    return { dirs, files, hidden };
  }, [data]);

  const visibleEntries = useMemo(() => {
    if (!data) return [];
    const term = filter.trim().toLowerCase();
    return data.entries.filter((e) => {
      if (!showHidden && e.hidden) return false;
      if (term && !e.name.toLowerCase().includes(term)) return false;
      return true;
    });
  }, [data, filter, showHidden]);

  if (!collectionId) {
    return (
      <div className="flex h-full items-center justify-center font-mono text-xs text-muted-foreground">
        No collection loaded. Open a hive, directory, or run a live collection first.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col font-mono text-xs">
      <div className="flex items-center gap-2 border-b border-border bg-muted/30 px-3 py-2">
        <HardDrive className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        <Breadcrumbs
          path={path}
          sourceKind={data?.source_kind ?? "unknown"}
          onNavigate={load}
        />
        <div className="ml-auto flex items-center gap-2">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filter…"
            className="h-7 w-48"
          />
          <label className="inline-flex items-center gap-1 text-muted-foreground">
            <input
              type="checkbox"
              checked={showHidden}
              onChange={(e) => setShowHidden(e.target.checked)}
            />
            hidden
          </label>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => data?.parent != null && load(data.parent)}
            disabled={!data?.parent}
          >
            up
          </Button>
          <Button
            size="sm"
            onClick={startExport}
            disabled={!data || exportProgress?.phase === "running"}
            title={`Export ${path} (recursive, hashed, audit-logged)`}
          >
            <Download className="h-3.5 w-3.5" />
            Export folder…
          </Button>
        </div>
      </div>

      {exportProgress && (
        <div
          className={cn(
            "border-b px-3 py-1.5 text-xs",
            exportProgress.phase === "error"
              ? "border-error/40 bg-error/10 text-error"
              : exportProgress.phase === "done"
              ? "border-accent/40 bg-accent/10 text-accent"
              : "border-accent/40 bg-accent/10 text-foreground",
          )}
        >
          <div className="flex items-center gap-2">
            <Download className="h-3 w-3" />
            <span className="font-semibold truncate">{exportProgress.label}</span>
            <span className="text-muted-foreground">
              {exportProgress.completed.toLocaleString()} / {exportProgress.total > 0 ? exportProgress.total.toLocaleString() : "?"}
            </span>
            <span className="ml-auto text-muted-foreground">{exportProgress.phase}</span>
            {(exportProgress.phase === "done" || exportProgress.phase === "error") && (
              <button type="button" className="text-muted-foreground hover:text-foreground" onClick={() => setExportProgress(null)}>
                ×
              </button>
            )}
          </div>
          <div className="mt-0.5 h-1 w-full overflow-hidden rounded bg-muted/40">
            <div
              className={cn(
                "h-full transition-all duration-300",
                exportProgress.phase === "error" ? "bg-error" : "bg-accent",
              )}
              style={{
                width:
                  exportProgress.phase === "done"
                    ? "100%"
                    : exportProgress.total > 0
                    ? `${Math.min(100, Math.round((exportProgress.completed / exportProgress.total) * 100))}%`
                    : "0%",
              }}
            />
          </div>
          <div className="mt-0.5 truncate text-muted-foreground" title={exportProgress.current_item}>
            {exportProgress.error ?? exportProgress.current_item ?? "—"}
          </div>
          {exportProgress.phase === "done" && lastExportDest && (
            <div className="mt-1 flex items-center gap-2">
              <FileDigit className="h-3 w-3" />
              <span className="text-muted-foreground">Save hash report:</span>
              <Button size="sm" variant="ghost" onClick={() => void saveHashReport("txt")}>
                .txt
              </Button>
              <Button size="sm" variant="ghost" onClick={() => void saveHashReport("csv")}>
                .csv
              </Button>
            </div>
          )}
        </div>
      )}

      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="px-3 py-4 text-muted-foreground">loading…</div>
        ) : data == null ? null : visibleEntries.length === 0 ? (
          <div className="px-3 py-4 text-muted-foreground">
            empty directory{!showHidden && counts.hidden > 0 ? ` (${counts.hidden} hidden — toggle to show)` : ""}
          </div>
        ) : (
          <table className="w-full border-collapse text-left text-xs">
            <thead className="sticky top-0 bg-muted/60 backdrop-blur">
              <tr className="border-b border-border">
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Name</th>
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground text-right">Size</th>
                <th className="px-3 py-2 font-semibold uppercase tracking-wide text-muted-foreground">Modified (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {visibleEntries.map((entry) => (
                <Row
                  key={entry.name}
                  entry={entry}
                  onOpen={(name) => load(joinPath(path, name))}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex items-center gap-3 border-t border-border bg-muted/30 px-3 py-1 text-muted-foreground">
        <span>{counts.dirs} dirs</span>
        <span>·</span>
        <span>{counts.files} files</span>
        <span>·</span>
        <span>{counts.hidden} hidden</span>
        {data && (
          <>
            <span className="ml-auto">{data.source_kind}</span>
            <span className="truncate" title={data.source_path}>{data.source_path}</span>
          </>
        )}
      </div>
    </div>
  );
}

function Breadcrumbs({
  path,
  sourceKind,
  onNavigate,
}: {
  path: string;
  sourceKind: string;
  onNavigate: (p: string) => void;
}) {
  const parts = path === "/" ? [] : path.split("/").filter(Boolean);
  return (
    <div className="flex items-center gap-1 overflow-x-auto whitespace-nowrap">
      <button
        type="button"
        onClick={() => onNavigate("/")}
        className="text-foreground hover:underline"
        title={sourceKind === "device" ? "Image / drive root" : "Collection root"}
      >
        {sourceKind === "directory" ? "[dir root]" : "[image root]"}
      </button>
      {parts.map((p, i) => {
        const target = "/" + parts.slice(0, i + 1).join("/");
        return (
          <span key={target} className="flex items-center gap-1">
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
            <button
              type="button"
              onClick={() => onNavigate(target)}
              className="text-foreground hover:underline"
            >
              {p}
            </button>
          </span>
        );
      })}
    </div>
  );
}

function Row({ entry, onOpen }: { entry: FileEntry; onOpen: (name: string) => void }) {
  const isDir = entry.kind === "dir";
  const isJunction = entry.kind === "junction";
  return (
    <tr className={cn("border-b border-border", isDir ? "hover:bg-muted/40" : "hover:bg-muted/20")}>
      <td className="px-3 py-1.5 align-top">
        {isDir ? (
          <button
            type="button"
            onClick={() => onOpen(entry.name)}
            className="inline-flex w-full items-center gap-2 text-left cursor-pointer"
          >
            <Folder className="h-3.5 w-3.5 text-accent shrink-0" />
            <span
              className={cn(
                "break-all hover:underline",
                entry.hidden ? "text-muted-foreground italic" : "text-foreground",
              )}
              title={entry.hidden ? "hidden" : undefined}
            >
              {entry.name}
            </span>
          </button>
        ) : isJunction ? (
          <span
            className="inline-flex items-center gap-2"
            title="Windows backwards-compat junction — navigate via the modern equivalent (e.g. Users)"
          >
            <Folder className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            <span className="break-all text-muted-foreground italic line-through">
              {entry.name}
            </span>
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground border border-border rounded px-1">
              junction
            </span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-2">
            <File className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            <span
              className={cn(
                "break-all",
                entry.hidden ? "text-muted-foreground italic" : "text-foreground",
              )}
              title={entry.hidden ? "hidden" : undefined}
            >
              {entry.name}
            </span>
          </span>
        )}
      </td>
      <td className="px-3 py-1.5 align-top text-right text-muted-foreground">
        {entry.size == null ? "—" : humanBytes(entry.size)}
      </td>
      <td className="px-3 py-1.5 align-top text-muted-foreground">{entry.mtime ?? "—"}</td>
    </tr>
  );
}

function joinPath(parent: string, name: string): string {
  if (parent === "/") return "/" + name;
  return parent.replace(/\/$/, "") + "/" + name;
}

function humanBytes(n: number): string {
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
