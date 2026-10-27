import { Check, ChevronDown, ChevronRight, Copy, X } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import type { ForensicEvent } from "@/lib/dft";
import { cn } from "@/lib/utils";

export function DetailPane({
  event,
  onClose,
}: {
  event: ForensicEvent | null;
  onClose: () => void;
}) {
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
        <div className="mb-3">
          <div className="text-muted-foreground">summary</div>
          <div className="break-words text-foreground">{event.summary}</div>
        </div>
        <div className="mb-3 grid grid-cols-2 gap-x-3 gap-y-1">
          <Field k="time" v={event.timestamp ?? "—"} />
          <Field k="time source" v={event.timestamp_source} />
          <Field k="event_type" v={event.event_type} />
          <Field k="source" v={event.source_artifact} />
          <Field k="host" v={event.host_id} />
          <Field k="user" v={event.user ?? "—"} />
          <Field k="parser" v={event.parser_version} />
          <Field k="event_id" v={event.event_id} />
        </div>

        {renderBody(event)}

        <div className="mt-4 break-all text-muted-foreground">
          source_path: <span className="text-foreground">{event.source_path}</span>
        </div>
      </div>
    </aside>
  );
}

// ---------- primitives -------------------------------------------------------

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

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-1 text-muted-foreground uppercase tracking-wide">{children}</div>
  );
}

function KVList({
  rows,
  className,
}: {
  rows: Array<[string, React.ReactNode]>;
  className?: string;
}) {
  if (rows.length === 0) return null;
  return (
    <div className={cn("grid grid-cols-[minmax(120px,1fr)_2fr] gap-x-3 gap-y-1", className)}>
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <div className="text-muted-foreground">{k}</div>
          <div className="min-w-0 break-words text-foreground">{v}</div>
        </div>
      ))}
    </div>
  );
}

function Pill({
  children,
  tone = "default",
  title,
}: {
  children: React.ReactNode;
  tone?: "default" | "accent" | "warning" | "error" | "muted";
  title?: string;
}) {
  const toneClass: Record<string, string> = {
    default: "bg-muted/60 text-foreground border-border",
    accent: "bg-accent/20 text-accent border-accent/40",
    warning: "bg-warning/20 text-warning border-warning/40",
    error: "bg-error/20 text-error border-error/40",
    muted: "bg-muted/40 text-muted-foreground border-border",
  };
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0 text-[10px]",
        toneClass[tone],
      )}
    >
      {children}
    </span>
  );
}

function CodeBlock({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <pre
      className={cn(
        "overflow-auto rounded border border-border bg-background/50 p-2 text-[11px] leading-[1.35]",
        className,
      )}
    >
      {children}
    </pre>
  );
}

function CollapsibleRaw({ data, title = "raw" }: { data: unknown; title?: string }) {
  const [open, setOpen] = useState(false);
  if (data === undefined || data === null) return null;
  if (typeof data === "object" && Object.keys(data as object).length === 0) return null;
  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1 text-muted-foreground uppercase tracking-wide hover:text-foreground"
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {title}
      </button>
      {open && <CodeBlock className="mt-1">{JSON.stringify(data, null, 2)}</CodeBlock>}
    </div>
  );
}

// URLs come from suspect evidence: never a live link (clicking would fetch the
// suspect's URL from the examiner's workstation, and javascript:/file: schemes
// are unfiltered), so render as text with copy-to-clipboard instead.
function UrlText({ url }: { url: string }) {
  const [copied, setCopied] = useState(false);
  if (!url) return <span className="text-muted-foreground">—</span>;
  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // clipboard unavailable — the text is still selectable
    }
  }
  return (
    <span className="inline-flex items-start gap-1">
      <span className="break-all text-foreground select-all">{url}</span>
      <button
        type="button"
        onClick={() => void copy()}
        title="Copy URL"
        aria-label="Copy URL"
        className="mt-0.5 shrink-0 text-muted-foreground hover:text-foreground"
      >
        {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
      </button>
    </span>
  );
}

// Anything that isn't a primitive renders to a JSON string for KVList rows.
function val(x: unknown): React.ReactNode {
  if (x === null || x === undefined || x === "") return <span className="text-muted-foreground">—</span>;
  if (typeof x === "string") return x;
  if (typeof x === "number" || typeof x === "boolean") return String(x);
  return <code className="text-[11px]">{JSON.stringify(x)}</code>;
}

function bytes(n: unknown): string {
  if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${units[i]}`;
}

// ---------- dispatcher -------------------------------------------------------

type RendererProps = { event: ForensicEvent };

function renderBody(event: ForensicEvent): React.ReactElement {
  switch (event.event_type) {
    case "browser_visit":
      return <BrowserVisitView event={event} />;
    case "browser_download":
      return <BrowserDownloadView event={event} />;
    case "browser_search":
      return <BrowserSearchView event={event} />;
    case "browser_bookmark":
      return <BrowserBookmarkView event={event} />;
    case "program_execution":
      return <ProgramExecutionView event={event} />;
    case "persistence_entry":
      return <PersistenceView event={event} />;
    case "system_config_change":
      return <RegistryKVView event={event} />;
    case "usb_connection":
      return <UsbConnectionView event={event} />;
    case "service_install":
      return <ServiceInstallView event={event} />;
    case "account_change":
      return event.source_artifact === "registry.sam"
        ? <AccountView event={event} />
        : <EvtxRecordView event={event} />;
    case "shell_command":
    case "scheduled_task":
    case "security_event":
      return <EvtxRecordView event={event} />;
    case "file_access":
      return <FileAccessView event={event} />;
    case "file_delete":
      return <FileDeleteView event={event} />;
    case "file_delete_burst":
      return <FileDeleteBurstView event={event} />;
    case "program_install":
      return <ProgramInstallView event={event} />;
    default:
      return <GenericView event={event} />;
  }
}

// ---------- generic fallback -------------------------------------------------

function GenericView({ event }: RendererProps) {
  return (
    <>
      <SectionHeader>evidence</SectionHeader>
      <CodeBlock>{JSON.stringify(event.evidence, null, 2)}</CodeBlock>
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- browser views ----------------------------------------------------

function BrowserVisitView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const url = String(e.url ?? "");
  const host = String(e.host ?? "");
  const title = String(e.title ?? "");
  const qualifiers = (e.transition_qualifiers as string[]) ?? [];
  const transition = String(e.transition ?? "");
  return (
    <>
      <SectionHeader>visit</SectionHeader>
      {title && <div className="mb-2 text-foreground">{title}</div>}
      <div className="mb-2">
        <UrlText url={url} />
      </div>
      <div className="mb-2 flex flex-wrap gap-1">
        {host && <Pill tone="accent">{host}</Pill>}
        {transition && <Pill>transition: {transition}</Pill>}
        {qualifiers.map((q) => (
          <Pill key={q} tone="muted">
            {q}
          </Pill>
        ))}
      </div>
      <KVList
        rows={[
          ["visit count", val(e.visit_count)],
          ["typed count", val(e.typed_count)],
          ["duration (ms)", val(e.visit_duration_ms)],
          ["from visit", val(e.from_visit)],
        ]}
      />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

function BrowserDownloadView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const filename = String(e.filename ?? "");
  const target = String(e.target_path ?? "");
  const total = e.total_bytes as number | undefined;
  const received = e.received_bytes as number | undefined;
  const sourceUrl = String(e.source_url ?? "");
  const sourceHost = String(e.source_host ?? "");
  const chain = (e.url_chain as string[]) ?? [];
  return (
    <>
      <SectionHeader>download</SectionHeader>
      <div className="mb-2 break-all text-foreground">{filename || target || "—"}</div>
      <div className="mb-2 flex flex-wrap gap-1">
        {sourceHost && <Pill tone="accent">{sourceHost}</Pill>}
        {typeof total === "number" && total > 0 && <Pill>{bytes(total)}</Pill>}
        {typeof e.mime_type === "string" && e.mime_type && <Pill tone="muted">{e.mime_type as string}</Pill>}
        {e.opened === 1 && <Pill tone="warning">opened</Pill>}
      </div>
      <KVList
        rows={[
          ["target path", <span className="break-all">{target}</span>],
          ["received", val(received !== undefined ? bytes(received) : undefined)],
          ["end time", val(e.end_time)],
          ["referrer", <span className="break-all">{val(e.referrer)}</span>],
          ["tab url", <span className="break-all">{val(e.tab_url)}</span>],
        ]}
      />
      {chain.length > 0 && (
        <div className="mt-3">
          <SectionHeader>url chain</SectionHeader>
          <ol className="ml-4 list-decimal space-y-0.5">
            {chain.map((u, i) => (
              <li key={`${i}-${u}`} className="break-all">
                <span className={cn(i === chain.length - 1 ? "text-foreground" : "text-muted-foreground")}>{u}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
      <div className="mt-3">
        <SectionHeader>source url</SectionHeader>
        <UrlText url={sourceUrl} />
      </div>
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

function BrowserSearchView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const term = String(e.term ?? "");
  const host = String(e.host ?? "");
  const url = String(e.url ?? "");
  return (
    <>
      <SectionHeader>search</SectionHeader>
      <div className="mb-2 text-base font-semibold text-foreground">{term || "—"}</div>
      <div className="mb-2 flex flex-wrap gap-1">{host && <Pill tone="accent">{host}</Pill>}</div>
      <KVList
        rows={[
          ["visit count", val(e.visit_count)],
          ["search url", <span className="break-all">{url}</span>],
        ]}
      />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

function BrowserBookmarkView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const url = String(e.url ?? "");
  const host = String(e.host ?? "");
  const title = String(e.title ?? "");
  return (
    <>
      <SectionHeader>bookmark</SectionHeader>
      {title && <div className="mb-2 text-foreground">{title}</div>}
      <div className="mb-2">
        <UrlText url={url} />
      </div>
      <div className="mb-2 flex flex-wrap gap-1">{host && <Pill tone="accent">{host}</Pill>}</div>
      <KVList rows={[["last modified", val(e.last_modified)]]} />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- execution --------------------------------------------------------

function ProgramExecutionView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const programPath = String(e.program_path ?? e.executable_filename ?? e.program_name ?? "—");
  const runs = (e.previous_run_times as string[] | undefined) ?? [];
  const last = (e.last_run_time as string | null | undefined) ?? event.timestamp;
  const isPrefetch = event.source_artifact === "prefetch";
  const isAmcache = event.source_artifact === "registry.amcache";
  const volumes = (e.volumes as Array<Record<string, unknown>> | undefined) ?? [];
  return (
    <>
      <SectionHeader>program</SectionHeader>
      <div className="mb-2 break-all text-foreground">{programPath}</div>
      <div className="mb-2 flex flex-wrap gap-1">
        <Pill tone="muted">{event.source_artifact}</Pill>
        {typeof e.run_count === "number" && <Pill>runs: {e.run_count as number}</Pill>}
        {isAmcache && e.signed === true && <Pill tone="accent">signed</Pill>}
        {isAmcache && e.signed === false && <Pill tone="warning">unsigned</Pill>}
      </div>
      {isPrefetch && (
        <KVList
          rows={[
            ["last run", val(last)],
            ["prefetch hash", val(e.prefetch_hash)],
            ["format version", val(e.format_version)],
            ["accessed files", val(e.accessed_files_count)],
            ["volumes", val(e.volume_count)],
          ]}
        />
      )}
      {isAmcache && (
        <KVList
          rows={[
            ["sha1", <span className="break-all">{val(e.sha1)}</span>],
            ["size", val(typeof e.size_bytes === "number" ? bytes(e.size_bytes) : e.size_bytes)],
            ["publisher", val(e.publisher)],
            ["product", val(e.product_name)],
            ["product version", val(e.product_version)],
            ["link date", val(e.link_date)],
          ]}
        />
      )}
      {!isPrefetch && !isAmcache && (
        <KVList
          rows={Object.entries(e)
            .filter(([k]) => k !== "program_path" && k !== "program_name")
            .map(([k, v]) => [k, val(v)])}
        />
      )}
      {runs.length > 0 && (
        <div className="mt-3">
          <SectionHeader>run history (newest first)</SectionHeader>
          <ol className="ml-4 list-decimal space-y-0.5 text-foreground">
            {last && <li className="font-semibold">{last}</li>}
            {runs.map((t) => (
              <li key={t} className="text-muted-foreground">
                {t}
              </li>
            ))}
          </ol>
        </div>
      )}
      {volumes.length > 0 && (
        <div className="mt-3">
          <SectionHeader>volumes</SectionHeader>
          <KVList
            rows={volumes.flatMap((v, i) => [
              [`vol ${i} device`, val(v.device_path)],
              [`vol ${i} serial`, val(v.serial_number)],
              [`vol ${i} created`, val(v.creation_time)],
            ])}
          />
        </div>
      )}
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- registry-shaped --------------------------------------------------

function isUserWritable(path: string): boolean {
  const p = path.toLowerCase();
  return (
    p.includes("\\appdata\\") ||
    p.includes("\\users\\public\\") ||
    p.includes("\\temp\\") ||
    p.includes("\\downloads\\") ||
    p.includes("\\programdata\\temp")
  );
}

function PersistenceView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const data = String(e.value_data ?? "");
  const writable = isUserWritable(data);
  return (
    <>
      <SectionHeader>persistence</SectionHeader>
      <KVList
        rows={[
          ["key path", <span className="break-all">{val(e.key_path)}</span>],
          ["value name", val(e.value_name)],
          [
            "value data",
            <span className={cn("break-all", writable ? "text-warning" : "text-foreground")}>{val(e.value_data)}</span>,
          ],
        ]}
      />
      {writable && (
        <div className="mt-2">
          <Pill tone="warning">value points at a user-writable path</Pill>
        </div>
      )}
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

function RegistryKVView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  return (
    <>
      <SectionHeader>{event.event_type.replace(/_/g, " ")}</SectionHeader>
      <KVList rows={Object.entries(e).map(([k, v]) => [k, val(v)])} />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

function UsbConnectionView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  return (
    <>
      <SectionHeader>USB device</SectionHeader>
      <div className="mb-2 text-foreground">
        <span className="font-semibold">{String(e.vendor ?? "?")}</span>
        <span className="text-muted-foreground"> · </span>
        <span>{String(e.product ?? "?")}</span>
      </div>
      <div className="mb-2 flex flex-wrap gap-1">
        {typeof e.serial === "string" && e.serial && (
          <Pill tone="accent" title={String(e.serial)}>
            SN: {String(e.serial)}
          </Pill>
        )}
        {typeof e.drive_letter_hint === "string" && e.drive_letter_hint && (
          <Pill>{String(e.drive_letter_hint)}</Pill>
        )}
      </div>
      <KVList
        rows={[
          ["device name", val(e.device_name)],
          ["version", val(e.version)],
          ["first installed", val(e.first_installed)],
          ["last installed", val(e.last_installed)],
          ["last connected", val(e.last_connected)],
          ["last removed", val(e.last_removed)],
          ["disk GUID", val(e.disk_guid)],
          ["registry key", <span className="break-all">{val(e.key_path)}</span>],
        ]}
      />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

function ServiceInstallView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  // 7045 events from evtx pass through evidence keys named by the schema; SYSTEM-hive
  // service entries use service_name/display_name/image_path. Render both shapes.
  const isHive = "service_name" in e;
  if (isHive) {
    return (
      <>
        <SectionHeader>service</SectionHeader>
        <div className="mb-2 text-foreground">
          <span className="font-semibold">{String(e.display_name ?? e.service_name ?? "?")}</span>
          {e.service_name !== e.display_name && (
            <span className="text-muted-foreground"> ({String(e.service_name ?? "")})</span>
          )}
        </div>
        <KVList
          rows={[
            ["image path", <span className="break-all">{val(e.image_path)}</span>],
            ["start type", val(e.start_type)],
            ["service type", val(e.service_type)],
            ["control set", val(e.control_set)],
          ]}
        />
        <CollapsibleRaw data={event.raw} />
      </>
    );
  }
  return <EvtxRecordView event={event} />;
}

// ---------- evtx -------------------------------------------------------------

function EvtxRecordView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const channel = String(e.channel ?? "");
  const evtId = e.event_id;
  const provider = e.provider;
  const recordId = e.record_id;
  // Anything beyond the well-known evtx envelope keys is per-EventID data.
  const dataRows = Object.entries(e)
    .filter(([k]) => !["channel", "event_id", "provider", "record_id", "level", "message"].includes(k))
    .map(([k, v]) => [k, val(v)] as [string, React.ReactNode]);
  return (
    <>
      <SectionHeader>event log record</SectionHeader>
      <div className="mb-2 flex flex-wrap gap-1">
        {channel && <Pill tone="accent">{channel}</Pill>}
        {typeof evtId === "number" && <Pill>EID {evtId}</Pill>}
        {typeof e.level === "string" && <Pill tone="muted">{e.level as string}</Pill>}
      </div>
      <KVList
        rows={[
          ["provider", val(provider)],
          ["record id", val(recordId)],
        ]}
      />
      {typeof e.message === "string" && e.message && (
        <div className="mt-3">
          <SectionHeader>message</SectionHeader>
          <div className="break-words text-foreground">{e.message as string}</div>
        </div>
      )}
      {dataRows.length > 0 && (
        <div className="mt-3">
          <SectionHeader>data</SectionHeader>
          <KVList rows={dataRows} />
        </div>
      )}
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- file_access (LNK + JumpList) -------------------------------------

function FileAccessView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const isJumplist = event.source_artifact === "jumplist";
  const target = String(e.target_path ?? "");
  return (
    <>
      <SectionHeader>{isJumplist ? "JumpList entry" : "shortcut"}</SectionHeader>
      <div className="mb-2 break-all text-foreground">{target || "—"}</div>
      <div className="mb-2 flex flex-wrap gap-1">
        {typeof e.app_name === "string" && e.app_name && <Pill tone="accent">{e.app_name as string}</Pill>}
        {typeof e.app_id === "string" && e.app_id && (
          <Pill tone="muted" title={e.app_id as string}>
            app_id
          </Pill>
        )}
        {e.pin_status === "pinned" && <Pill tone="warning">pinned</Pill>}
      </div>
      <KVList
        rows={[
          ["arguments", val(e.arguments)],
          ["working dir", <span className="break-all">{val(e.working_directory)}</span>],
          ["description", val(e.description)],
          ["target size", val(typeof e.target_file_size === "number" ? bytes(e.target_file_size) : e.target_file_size)],
          ["target created", val(e.target_created)],
          ["target modified", val(e.target_modified)],
          ["target accessed", val(e.target_accessed)],
          ["last used", val(e.last_used)],
          ["volume label", val(e.volume_label)],
          ["drive type", val(e.drive_type)],
          ["drive serial", val(e.drive_serial)],
        ]}
      />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- SAM local account ------------------------------------------------

function AccountView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const username = String(e.username ?? "—");
  return (
    <>
      <SectionHeader>local account</SectionHeader>
      <div className="mb-2 text-base font-semibold text-foreground">{username}</div>
      <div className="mb-2 flex flex-wrap gap-1">
        {e.rid != null && <Pill tone="accent">RID {String(e.rid)}</Pill>}
        {e.account_disabled === true && <Pill tone="warning">disabled</Pill>}
        {e.account_locked === true && <Pill tone="warning">locked</Pill>}
      </div>
      <KVList
        rows={[
          ["SID", <span className="break-all mono">{val(e.sid)}</span>],
          ["full name", val(e.full_name)],
          ["last logon", val(e.last_logon)],
          ["password last set", val(e.password_last_set)],
          ["login count", val(e.login_count)],
          ["machine SID", <span className="break-all mono">{val(e.machine_sid)}</span>],
        ]}
      />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- file_delete (Recycle Bin, USN journal, $MFT unallocated) ----------

const DELETION_METHOD_TEXT: Record<string, string> = {
  recycle_bin: "Recycle Bin ($I record) — the file was sent to the bin",
  usn_journal: "USN change journal — FILE_DELETE record (covers Shift+Delete and programmatic deletes)",
  mft_unallocated: "$MFT unallocated record — the file existed and its record is now free",
};

const RECOVERABLE_TEXT: Record<string, string> = {
  recycle_bin_blob: "yes — a matching $R content file still exists in the Recycle Bin",
  data_runs_present: "maybe — the $MFT record still lists its data clusters; content survives only if they were not reused (no carving)",
  resident: "yes — the data was stored inside the $MFT record itself",
  unknown: "unknown — no recoverability evidence",
};

function FileDeleteView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const original = String(e.original_path ?? "");
  const name = String(e.deleted_name ?? "");
  const size = e.deleted_size;
  const method = typeof e.deletion_method === "string" ? e.deletion_method : "recycle_bin";
  const isBound = method === "mft_unallocated" || event.timestamp_source === "inferred";
  const isDir = e.is_directory === true || e.is_directory === 1;
  const reasons = Array.isArray(e.usn_reason) ? (e.usn_reason as unknown[]).map(String) : null;
  const hint = typeof e.recoverable_hint === "string" ? e.recoverable_hint : "unknown";
  const rows: Array<[string, React.ReactNode]> = [
    ["method", DELETION_METHOD_TEXT[method] ?? method],
    [
      "when",
      event.timestamp ? (
        isBound ? (
          <span>
            <span className="text-warning">on or before </span>
            {event.timestamp}
            <span className="text-muted-foreground"> (last $STANDARD_INFORMATION change; the deletion itself is not timestamped)</span>
          </span>
        ) : (
          <span>
            {event.timestamp}
            <span className="text-muted-foreground"> (exact, recorded by the artifact)</span>
          </span>
        )
      ) : (
        val(null)
      ),
    ],
    ["original path", <span className="break-all">{val(original)}</span>],
    ["name", val(name)],
    ["kind", isDir ? "directory" : "file"],
    ["size", typeof size === "number" ? `${bytes(size)} (${size.toLocaleString()} bytes)` : val(size)],
    [
      "owner SID",
      <span className="break-all">
        {val(e.owner_sid)}
        {e.owner_sid != null && (
          <span className="text-muted-foreground">
            {method === "recycle_bin" ? " (owner of the $Recycle.Bin folder = the deleter)" : " (file owner from $Secure, not necessarily the deleter)"}
          </span>
        )}
      </span>,
    ],
    [
      "actor SID",
      <span className="break-all">
        {val(e.actor_sid)}
        {e.actor_sid == null && (
          <span className="text-muted-foreground"> (artifact does not name the deleter; see the Deleted files tab for the inferred user)</span>
        )}
      </span>,
    ],
  ];
  if (e.security_id != null) rows.push(["NTFS security id", `${val(e.security_id)} (raw $Secure index)`]);
  if (e.mft_segment != null) rows.push(["MFT record", val(e.mft_segment)]);
  if (e.usn != null) rows.push(["USN", val(e.usn)]);
  if (reasons && reasons.length > 0) {
    rows.push([
      "USN reasons",
      <span className="flex flex-wrap gap-1">
        {reasons.map((r) => (
          <Pill key={r} tone={r === "FILE_DELETE" ? "warning" : "muted"} title={USN_REASON_TEXT[r] ?? r}>
            {r}
          </Pill>
        ))}
      </span>,
    ]);
  }
  rows.push(["recoverable", RECOVERABLE_TEXT[hint] ?? hint]);
  if (typeof e.recovered_name === "string" && e.recovered_name) rows.push(["$R blob", val(e.recovered_name)]);
  if (e.last_known_modified != null) rows.push(["last known modified", val(e.last_known_modified)]);
  if (e.last_known_created != null) rows.push(["last known created", val(e.last_known_created)]);
  if (e.format_version != null) rows.push(["$I format", val(e.format_version)]);
  return (
    <>
      <SectionHeader>deleted {isDir ? "directory" : "file"}</SectionHeader>
      <div className="mb-2 break-all text-foreground">{name || original || "—"}</div>
      <div className="mb-2 flex flex-wrap gap-1">
        <Pill tone={method === "mft_unallocated" ? "warning" : "accent"}>{method.replace(/_/g, " ")}</Pill>
        {isBound && <Pill tone="warning" title="MFT time is an upper bound, not the deletion time">time ≤</Pill>}
        {typeof size === "number" && size > 0 && <Pill>{bytes(size)}</Pill>}
        {hint !== "unknown" && <Pill tone="muted">{hint.replace(/_/g, " ")}</Pill>}
      </div>
      <KVList rows={rows} />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

const USN_REASON_TEXT: Record<string, string> = {
  FILE_DELETE: "the file or directory was deleted",
  CLOSE: "the handle was closed (the record is final)",
  FILE_CREATE: "the file or directory was created",
  RENAME_OLD_NAME: "old name in a rename",
  RENAME_NEW_NAME: "new name in a rename",
  DATA_OVERWRITE: "data was overwritten",
  DATA_EXTEND: "data was appended",
  DATA_TRUNCATION: "data was truncated",
  BASIC_INFO_CHANGE: "attributes or timestamps changed",
  SECURITY_CHANGE: "security descriptor changed",
  HARD_LINK_CHANGE: "hard link added or removed",
  STREAM_CHANGE: "named stream added, removed or renamed",
};

function FileDeleteBurstView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  const samples = Array.isArray(e.sample_paths) ? (e.sample_paths as unknown[]).map(String) : [];
  const method = typeof e.method === "string" ? e.method : "—";
  const count = typeof e.count === "number" ? e.count : null;
  return (
    <>
      <SectionHeader>bulk deletion</SectionHeader>
      <div className="mb-2 text-foreground">
        <span className="text-base font-semibold">{count ?? "—"}</span>
        <span className="text-muted-foreground"> deletions by one method inside a 120-second window</span>
      </div>
      <div className="mb-2 flex flex-wrap gap-1">
        <Pill tone="error">burst</Pill>
        <Pill tone="accent">{method.replace(/_/g, " ")}</Pill>
        {typeof e.actor_user === "string" && e.actor_user && <Pill>{e.actor_user as string}</Pill>}
      </div>
      <KVList
        rows={[
          ["window start", val(e.window_start)],
          ["window end", val(e.window_end)],
          ["method", DELETION_METHOD_TEXT[method] ?? method],
          ["attributed user", val(e.actor_user)],
        ]}
      />
      {samples.length > 0 && (
        <div className="mt-3">
          <SectionHeader>sample paths ({samples.length}{count && count > samples.length ? ` of ${count}` : ""})</SectionHeader>
          <ol className="ml-4 list-decimal space-y-0.5">
            {samples.map((p, i) => (
              <li key={`${i}-${p}`} className="break-all text-foreground">
                {p}
              </li>
            ))}
          </ol>
        </div>
      )}
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

// ---------- program_install --------------------------------------------------

function ProgramInstallView({ event }: RendererProps) {
  const e = event.evidence as Record<string, unknown>;
  return (
    <>
      <SectionHeader>installed program</SectionHeader>
      <div className="mb-2 text-foreground">{String(e.display_name ?? e.product_name ?? "—")}</div>
      <div className="mb-2 flex flex-wrap gap-1">
        {typeof e.publisher === "string" && e.publisher && <Pill tone="accent">{e.publisher as string}</Pill>}
        {typeof e.display_version === "string" && e.display_version && <Pill>{e.display_version as string}</Pill>}
      </div>
      <KVList
        rows={[
          ["install location", <span className="break-all">{val(e.install_location)}</span>],
          ["install source", <span className="break-all">{val(e.install_source)}</span>],
          ["install date", val(e.install_date_raw ?? e.install_date)],
          ["uninstall string", <span className="break-all">{val(e.uninstall_string)}</span>],
          ["size (KB)", val(e.estimated_size_kb)],
          ["registry path", <span className="break-all">{val(e.registry_path ?? e.key_path)}</span>],
        ]}
      />
      <CollapsibleRaw data={event.raw} />
    </>
  );
}

