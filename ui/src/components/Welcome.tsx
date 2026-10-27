import { AlertTriangle, FolderOpen, FolderTree, HardDrive, Lock } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Empty-state landing card. Rendered when no collection is loaded so the
 * examiner has a clear "where do I start?" instead of an empty table.
 */
export function Welcome({
  elevated,
  busy = false,
  onOpenHive,
  onOpenDirectory,
  onCollectLive,
}: {
  elevated: boolean | null;
  busy?: boolean;
  onOpenHive: () => void;
  onOpenDirectory: () => void;
  onCollectLive: () => void;
}) {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="w-full max-w-3xl">
        <div className="mb-6 text-center">
          <h2 className="font-mono text-base font-semibold tracking-tight text-foreground">
            Digital Forensics Triage Toolkit
          </h2>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            Parse Windows hives, evtx, prefetch, LNK, JumpLists, browser History.
            Auto-flag with MITRE ATT&amp;CK rules. Export an HTML report.
            <br />
            Deleted-file attribution: Recycle Bin, USN journal and $MFT, each deletion
            tied to a user with a stated confidence and reason.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Tile
            icon={<FolderOpen className="h-5 w-5" />}
            title="Open hive"
            body="Parse a single registry hive file (SYSTEM, NTUSER.DAT, AmCache, or browser History) and view its events."
            footnote="No admin required"
            onClick={onOpenHive}
            disabled={busy}
          />
          <Tile
            icon={<FolderTree className="h-5 w-5" />}
            title="Open directory"
            body="Triage a folder of mirrored Windows artifacts — registry hives, .evtx, .pf, .lnk, JumpLists, browser History."
            footnote="No admin required"
            onClick={onOpenDirectory}
            disabled={busy}
          />
          <Tile
            icon={<HardDrive className="h-5 w-5" />}
            title="Collect live"
            body="Read straight off this running system via dissect.target, or ingest an E01 / raw disk image. Mirrors artifacts, hashes everything, writes an audit log."
            footnote={
              elevated === false ? (
                <span className="inline-flex items-center gap-1 text-warning">
                  <Lock className="h-3 w-3" />
                  Image OK · physical drive needs admin
                </span>
              ) : (
                "Physical drive or disk image"
              )
            }
            onClick={onCollectLive}
            disabled={busy}
          />
        </div>

        {elevated === false && (
          <div className="mt-6 flex items-start gap-2 rounded border border-warning/40 bg-warning/10 px-3 py-2 font-mono text-xs text-warning">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              You're running unelevated. Hive / directory triage and disk-image ingest
              all work; only physical-drive enumeration (live system) needs administrator.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Tile({
  icon,
  title,
  body,
  footnote,
  onClick,
  disabled,
}: {
  icon: ReactNode;
  title: string;
  body: string;
  footnote: ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "flex h-full flex-col rounded-md border border-border bg-card p-4 text-left font-mono text-xs transition",
        disabled
          ? "cursor-not-allowed opacity-60"
          : "cursor-pointer hover:border-accent/60 hover:bg-accent/5",
      )}
    >
      <div className="mb-2 inline-flex items-center gap-2 text-foreground">
        <span className="text-accent">{icon}</span>
        <span className="text-sm font-semibold">{title}</span>
      </div>
      <p className="flex-1 text-muted-foreground">{body}</p>
      <div className="mt-3 text-muted-foreground">{footnote}</div>
    </button>
  );
}
