import { useEffect, useMemo, useRef } from "react";
import ReactECharts from "echarts-for-react";
import type { EChartsOption, ECharts } from "echarts";

import type { TimelinePoint } from "@/lib/dft";

const EVENT_TYPE_COLORS: Record<string, string> = {
  program_execution: "#5b8def",
  program_install: "#22d3ee",
  persistence_entry: "#f87171",
  usb_connection: "#a78bfa",
  service_install: "#fbbf24",
  account_change: "#f472b6",
  file_access: "#34d399",
  file_delete: "#e11d48",
  shell_command: "#fb7185",
  system_config_change: "#94a3b8",
  logon: "#4ade80",
  logoff: "#64748b",
  scheduled_task: "#facc15",
  security_event: "#ef4444",
};

function colorFor(eventType: string): string {
  return EVENT_TYPE_COLORS[eventType] ?? "#9ca3af";
}

export function Timeline({
  categories,
  points,
  onEventClick,
  focus,
}: {
  categories: string[];
  points: TimelinePoint[];
  onEventClick: (eventId: string) => void;
  focus?: { startMs: number; endMs: number } | null;
}) {
  const ref = useRef<ReactECharts | null>(null);

  // Zoom the x-axis to the requested window (e.g. a clicked busy day).
  useEffect(() => {
    if (!focus) return;
    const chart = ref.current?.getEchartsInstance();
    if (!chart) return;
    chart.dispatchAction({
      type: "dataZoom",
      startValue: focus.startMs,
      endValue: focus.endMs,
    });
  }, [focus]);

  const option = useMemo<EChartsOption>(() => {
    const seriesByType: Record<string, TimelinePoint[]> = {};
    for (const p of points) {
      (seriesByType[p.event_type] ??= []).push(p);
    }

    const series = Object.entries(seriesByType).map(([eventType, ps]) => ({
      name: eventType,
      type: "scatter" as const,
      large: true,
      largeThreshold: 2000,
      symbolSize: 6,
      progressive: 5000,
      progressiveThreshold: 5000,
      itemStyle: { color: colorFor(eventType), opacity: 0.85 },
      data: ps.map((p) => [p.ts_ms, p.category_idx, p.event_id, p.summary]),
    }));

    return {
      backgroundColor: "transparent",
      animation: false,
      grid: { left: 220, right: 24, top: 28, bottom: 60 },
      xAxis: {
        type: "time",
        axisLine: { lineStyle: { color: "#232730" } },
        axisLabel: { color: "#8b9099", fontFamily: "JetBrains Mono, monospace", fontSize: 11 },
        splitLine: { lineStyle: { color: "#1a1d23" } },
      },
      yAxis: {
        type: "category",
        data: categories,
        axisLine: { lineStyle: { color: "#232730" } },
        axisTick: { show: false },
        axisLabel: {
          color: "#e6e8eb",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 11,
          formatter: (v: string) => v.length > 28 ? v.slice(0, 27) + "…" : v,
        },
        splitLine: { show: true, lineStyle: { color: "#1a1d23" } },
      },
      tooltip: {
        trigger: "item",
        backgroundColor: "#0b0d11",
        borderColor: "#232730",
        textStyle: { color: "#e6e8eb", fontFamily: "JetBrains Mono, monospace", fontSize: 11 },
        formatter: (params: unknown) => {
          const p = params as { data: [number, number, string, string]; seriesName: string };
          const [tsMs, catIdx, _eventId, summary] = p.data;
          const when = new Date(tsMs).toISOString();
          const cat = categories[catIdx] ?? "?";
          return `<div style="max-width:480px;white-space:normal">`
            + `<div style="color:#8b9099">${when}</div>`
            + `<div style="color:#8b9099">${cat} · ${p.seriesName}</div>`
            + `<div style="margin-top:4px">${escapeHtml(summary)}</div>`
            + `</div>`;
        },
      },
      dataZoom: [
        { type: "inside", filterMode: "filter" },
        {
          type: "slider",
          height: 22,
          bottom: 18,
          borderColor: "#232730",
          backgroundColor: "#0b0d11",
          fillerColor: "rgba(91,141,239,0.15)",
          handleStyle: { color: "#5b8def" },
          textStyle: { color: "#8b9099", fontFamily: "JetBrains Mono, monospace", fontSize: 10 },
        },
      ],
      legend: {
        type: "scroll",
        top: 0,
        textStyle: { color: "#8b9099", fontFamily: "JetBrains Mono, monospace", fontSize: 10 },
        inactiveColor: "#404652",
      },
      series,
    };
  }, [categories, points]);

  return (
    <div className="h-full w-full">
      <ReactECharts
        ref={(node) => {
          ref.current = node;
        }}
        option={option}
        notMerge
        lazyUpdate
        style={{ height: "100%", width: "100%" }}
        onEvents={{
          click: (params: { data?: [number, number, string, string] }) => {
            const eventId = params.data?.[2];
            if (eventId) onEventClick(eventId);
          },
        }}
        opts={{ renderer: "canvas" }}
      />
    </div>
  );
}

// echarts requires a getEchartsInstance helper; expose if needed later.
export function getInstance(ref: React.RefObject<ReactECharts | null>): ECharts | undefined {
  return ref.current?.getEchartsInstance();
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
