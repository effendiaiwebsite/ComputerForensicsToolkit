import { useMemo } from "react";

import type { ActivityDay } from "@/lib/dft";

/**
 * Compact per-day activity histogram shown above the timeline. Bars are scaled
 * to the busiest day; statistically "busy" days (count > mean + k·σ, flagged by
 * the sidecar) are highlighted and labelled. Clicking a day zooms the timeline
 * to that 24h window.
 */
export function BusyDayStrip({
  days,
  threshold,
  selected,
  onSelectDay,
}: {
  days: ActivityDay[];
  threshold: number;
  selected: string | null;
  onSelectDay: (date: string) => void;
}) {
  const max = useMemo(
    () => days.reduce((m, d) => Math.max(m, d.count), 1),
    [days],
  );

  if (days.length === 0) return null;

  const busyCount = days.filter((d) => d.busy).length;

  return (
    <div className="mb-2 rounded border border-border bg-card/40 px-3 py-2">
      <div className="mb-1.5 flex items-center justify-between text-[11px] text-muted-foreground">
        <span>
          activity by day · {days.length} day{days.length === 1 ? "" : "s"}
          {busyCount > 0 && (
            <span className="ml-2 text-warning">
              {busyCount} busy day{busyCount === 1 ? "" : "s"} (&gt; {Math.round(threshold)} events)
            </span>
          )}
        </span>
        <span className="text-muted-foreground/70">click a day to zoom</span>
      </div>
      <div className="flex items-end gap-[2px]" style={{ height: 56 }}>
        {days.map((d) => {
          const h = Math.max(3, Math.round((d.count / max) * 52));
          const isSel = d.date === selected;
          const color = d.busy ? "var(--color-warning)" : "var(--color-accent)";
          return (
            <button
              key={d.date}
              type="button"
              onClick={() => onSelectDay(d.date)}
              title={`${d.date} · ${d.count} events${d.busy ? " · BUSY" : ""}`}
              className="group flex min-w-[6px] flex-1 flex-col justify-end"
              style={{ height: 52 }}
            >
              <div
                style={{
                  height: h,
                  background: color,
                  opacity: d.busy ? 0.95 : 0.45,
                  outline: isSel ? "1px solid var(--color-foreground)" : "none",
                }}
                className="w-full rounded-sm transition-opacity group-hover:opacity-100"
              />
            </button>
          );
        })}
      </div>
    </div>
  );
}
