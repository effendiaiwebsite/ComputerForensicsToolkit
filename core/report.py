"""Single-file HTML report generator.

Pure stdlib — no jinja2, no matplotlib. The report is one self-contained
HTML file (inline CSS + inline SVG) so the examiner can email it, archive
it, or print it from a browser without external dependencies.

Sections, in order:
  1. Case header (case name, examiner, generated-at, host, collection)
  2. Summary stats (event totals, time span, findings by severity)
  3. MITRE ATT&CK heat-map (tactics × technique counts, color-tiered)
  4. Timeline (inline SVG lane chart, one lane per source_artifact)
  5. Findings (rule, severity, technique chips, sample evidence)
  6. Per-source-artifact sections (top events per artifact)

PDF export is intentionally out of scope here — the examiner uses their
browser's Print → Save as PDF. Keeps the toolkit dep-free.
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.store import EventStore

REPORT_VERSION = "report/0.1.0"

# Enterprise ATT&CK tactic order — used to lay out the heat-map left-to-right.
_TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


def generate_report(
    store: EventStore,
    collection_id: str,
    *,
    case_name: str,
    examiner: str,
) -> str:
    """Return a self-contained HTML report for ``collection_id``."""
    meta = _gather_meta(store, collection_id, case_name=case_name, examiner=examiner)
    events_summary = _gather_events_summary(store, collection_id)
    findings = list(store.query_findings(collection_id=collection_id, limit=10_000))
    findings_by_severity = store.counts_by_severity(collection_id=collection_id)
    timeline_points = store.query_timeline_points(collection_id=collection_id, limit=100_000)
    per_artifact = _gather_per_artifact(store, collection_id, events_summary["by_source_artifact"])

    body = "\n".join([
        _render_header(meta),
        _render_summary(meta, events_summary, findings_by_severity, len(findings)),
        _render_mitre_heatmap(findings),
        _render_timeline(timeline_points, events_summary["by_source_artifact"]),
        _render_findings(findings),
        _render_per_artifact(per_artifact),
        _render_footer(meta),
    ])

    return _HTML_SHELL.format(
        title=html.escape(f"DFT Report — {case_name}"),
        css=_CSS,
        body=body,
    )


# ----- meta / aggregation ----------------------------------------------------


def _gather_meta(
    store: EventStore,
    collection_id: str,
    *,
    case_name: str,
    examiner: str,
) -> dict[str, Any]:
    collection = store.get_collection(collection_id)
    return {
        "case_name": case_name,
        "examiner": examiner,
        "generated_at": _utc_now(),
        "collection_id": collection_id,
        "host_id": (collection or {}).get("host_id", "—"),
        "host_os": (collection or {}).get("host_os", "—"),
        "collection_created_at": (collection or {}).get("created_at", "—"),
        "collection_note": (collection or {}).get("note", ""),
    }


def _gather_events_summary(store: EventStore, collection_id: str) -> dict[str, Any]:
    total = store.count_events(collection_id=collection_id)
    by_type = store.counts_by_event_type(collection_id=collection_id)
    by_artifact = store.counts_by_source_artifact(collection_id=collection_id)
    time_min, time_max = store.timestamp_range(collection_id=collection_id)
    return {
        "total": total,
        "by_event_type": by_type,
        "by_source_artifact": by_artifact,
        "time_min": time_min,
        "time_max": time_max,
    }


def _gather_per_artifact(
    store: EventStore,
    collection_id: str,
    by_artifact: dict[str, int],
) -> list[dict[str, Any]]:
    """For each source_artifact in the collection, fetch a few recent events."""
    out: list[dict[str, Any]] = []
    for artifact in sorted(by_artifact, key=lambda a: -by_artifact[a]):
        rows = store.query_events(
            collection_id=collection_id,
            source_artifact=artifact,
            sort_by="timestamp",
            sort_dir="desc",
            limit=10,
        )
        out.append({
            "artifact": artifact,
            "count": by_artifact[artifact],
            "samples": rows,
        })
    return out


# ----- HTML helpers ----------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _render_header(meta: dict[str, Any]) -> str:
    return f"""
<section class="case-header">
  <h1>DFT — {esc(meta['case_name'])}</h1>
  <div class="case-grid">
    <div><span class="k">Examiner</span><span class="v">{esc(meta['examiner'])}</span></div>
    <div><span class="k">Generated</span><span class="v">{esc(meta['generated_at'])}</span></div>
    <div><span class="k">Host</span><span class="v">{esc(meta['host_id'])} ({esc(meta['host_os'])})</span></div>
    <div><span class="k">Collection ID</span><span class="v mono">{esc(meta['collection_id'])}</span></div>
    <div><span class="k">Collected at</span><span class="v">{esc(meta['collection_created_at'])}</span></div>
    <div><span class="k">Source</span><span class="v mono small">{esc(meta['collection_note'])}</span></div>
  </div>
</section>
"""


def _render_summary(
    meta: dict[str, Any],
    summary: dict[str, Any],
    by_severity: dict[str, int],
    findings_total: int,
) -> str:
    sev_chips = "".join(
        f'<span class="chip sev-{esc(s)}">{esc(s)}: <strong>{by_severity.get(s, 0)}</strong></span>'
        for s in ("critical", "high", "medium", "low")
    )
    span = (
        f"{esc(summary['time_min'])} → {esc(summary['time_max'])}"
        if summary["time_min"] and summary["time_max"]
        else "<span class='muted'>no dated events</span>"
    )
    type_rows = "".join(
        f"<tr><td>{esc(t)}</td><td class='r'>{c:,}</td></tr>"
        for t, c in sorted(summary["by_event_type"].items(), key=lambda kv: -kv[1])
    )
    artifact_rows = "".join(
        f"<tr><td>{esc(a)}</td><td class='r'>{c:,}</td></tr>"
        for a, c in sorted(summary["by_source_artifact"].items(), key=lambda kv: -kv[1])
    )
    return f"""
<section class="summary">
  <h2>Summary</h2>
  <div class="cards">
    <div class="card">
      <div class="big">{summary['total']:,}</div>
      <div class="muted">events</div>
    </div>
    <div class="card">
      <div class="big">{findings_total:,}</div>
      <div class="muted">findings</div>
      <div class="chips">{sev_chips}</div>
    </div>
    <div class="card span">
      <div class="muted">Time span</div>
      <div class="mono">{span}</div>
    </div>
  </div>
  <div class="two-col">
    <div>
      <h3>Events by type</h3>
      <table class="kvtable">{type_rows or '<tr><td>—</td><td>0</td></tr>'}</table>
    </div>
    <div>
      <h3>Events by source artifact</h3>
      <table class="kvtable">{artifact_rows or '<tr><td>—</td><td>0</td></tr>'}</table>
    </div>
  </div>
</section>
"""


def _render_mitre_heatmap(findings: list[dict[str, Any]]) -> str:
    """ATT&CK tactic columns; cells = techniques with hit counts, color-tiered."""
    by_tactic: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        techniques = f.get("mitre_techniques") or []
        tactics = f.get("mitre_tactics") or ["uncategorized"]
        for tactic in tactics:
            for technique in techniques:
                by_tactic[tactic][technique] += 1

    if not by_tactic:
        return (
            '<section class="mitre"><h2>MITRE ATT&amp;CK heat-map</h2>'
            '<div class="muted">No findings — nothing to plot.</div></section>'
        )

    ordered_tactics = [t for t in _TACTIC_ORDER if t in by_tactic] + [
        t for t in by_tactic if t not in _TACTIC_ORDER
    ]

    cols = []
    for tactic in ordered_tactics:
        techniques = by_tactic[tactic]
        cells = "".join(
            f'<div class="cell {_heat_tier(c)}" title="{esc(tech)} ({c} finding{"" if c == 1 else "s"})">'
            f'<div class="tech">{esc(tech)}</div><div class="cnt">{c}</div></div>'
            for tech, c in sorted(techniques.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        cols.append(
            f'<div class="tcol"><div class="tcol-h">{esc(tactic)}</div>{cells}</div>'
        )
    return f"""
<section class="mitre">
  <h2>MITRE ATT&amp;CK heat-map</h2>
  <div class="tactics">{''.join(cols)}</div>
</section>
"""


def _heat_tier(count: int) -> str:
    if count >= 10:
        return "tier-crit"
    if count >= 4:
        return "tier-high"
    if count >= 2:
        return "tier-med"
    return "tier-low"


def _render_timeline(points: list[dict[str, Any]], by_artifact: dict[str, int]) -> str:
    """Multi-lane SVG: one lane per source_artifact (only those with dated events)."""
    ts_points: list[tuple[int, str]] = []
    for p in points:
        ms = _iso_to_ms(p["timestamp"])
        if ms is not None:
            ts_points.append((ms, p["source_artifact"]))
    if not ts_points:
        return (
            '<section class="timeline"><h2>Timeline</h2>'
            '<div class="muted">No dated events to plot.</div></section>'
        )

    lanes = sorted({a for _, a in ts_points})
    t_min = min(t for t, _ in ts_points)
    t_max = max(t for t, _ in ts_points)
    if t_max == t_min:
        t_max = t_min + 1  # avoid div-by-zero on single-event timelines.

    label_w = 160
    width = 1100
    lane_h = 22
    plot_x0 = label_w + 10
    plot_w = width - plot_x0 - 10
    height = len(lanes) * lane_h + 56  # +56 for x-axis labels + padding

    # Background lane stripes.
    lane_bg = "".join(
        f'<rect x="0" y="{i * lane_h + 8}" width="{width}" height="{lane_h}" '
        f'class="lane-bg{i % 2}"/>'
        for i in range(len(lanes))
    )
    # Lane labels.
    lane_labels = "".join(
        f'<text x="{label_w}" y="{i * lane_h + 8 + lane_h / 2 + 3}" '
        f'class="lane-label" text-anchor="end">{esc(a)} '
        f'<tspan class="lane-count">{by_artifact.get(a, 0):,}</tspan></text>'
        for i, a in enumerate(lanes)
    )
    # Dots per event (one per timestamp), each on its lane's row.
    lane_idx = {a: i for i, a in enumerate(lanes)}
    dots = []
    seen: set[tuple[int, int]] = set()  # de-dupe pixel-identical dots for size.
    for ms, artifact in ts_points:
        cx = plot_x0 + int((ms - t_min) / (t_max - t_min) * plot_w)
        cy = lane_idx[artifact] * lane_h + 8 + lane_h // 2
        key = (cx, cy)
        if key in seen:
            continue
        seen.add(key)
        dots.append(f'<circle cx="{cx}" cy="{cy}" r="1.6" class="dot"/>')

    # X-axis: a few date ticks across the range.
    n_ticks = 6
    tick_xs = []
    for i in range(n_ticks):
        frac = i / (n_ticks - 1)
        t = t_min + (t_max - t_min) * frac
        x = plot_x0 + int(frac * plot_w)
        lbl = _ms_to_short(int(t))
        tick_xs.append(
            f'<line x1="{x}" y1="{len(lanes) * lane_h + 10}" x2="{x}" y2="{len(lanes) * lane_h + 16}" class="tick"/>'
            f'<text x="{x}" y="{len(lanes) * lane_h + 30}" class="tick-label" text-anchor="middle">{lbl}</text>'
        )
    axis = (
        f'<line x1="{plot_x0}" y1="{len(lanes) * lane_h + 10}" x2="{plot_x0 + plot_w}" '
        f'y2="{len(lanes) * lane_h + 10}" class="axis"/>'
    )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'preserveAspectRatio="xMidYMid meet" class="timeline-svg">'
        f"{lane_bg}{''.join(dots)}{lane_labels}{axis}{''.join(tick_xs)}"
        f"</svg>"
    )
    return f"""
<section class="timeline">
  <h2>Timeline</h2>
  <div class="muted small">{len(ts_points):,} dated events across {len(lanes)} sources · {_ms_to_short(t_min)} → {_ms_to_short(t_max)}</div>
  {svg}
</section>
"""


def _render_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return (
            '<section class="findings"><h2>Findings</h2>'
            '<div class="muted">No findings.</div></section>'
        )
    # Group by rule_id so a noisy rule occupies one row, not 40.
    grouped: dict[str, dict[str, Any]] = {}
    for f in findings:
        rid = f["rule_id"]
        g = grouped.setdefault(rid, {
            "rule_id": rid,
            "rule_title": f["rule_title"],
            "severity": f["severity"],
            "mitre_techniques": f.get("mitre_techniques") or [],
            "mitre_tactics": f.get("mitre_tactics") or [],
            "count": 0,
            "first_summary": f.get("summary", ""),
        })
        g["count"] += 1

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = []
    for g in sorted(grouped.values(), key=lambda r: (sev_rank.get(r["severity"], 9), -r["count"])):
        chips = "".join(f'<span class="chip mitre">{esc(t)}</span>' for t in g["mitre_techniques"])
        rows.append(
            f'<tr>'
            f'<td><span class="chip sev-{esc(g["severity"])}">{esc(g["severity"])}</span></td>'
            f'<td><div class="rule-title">{esc(g["rule_title"])}</div>'
            f'<div class="muted small mono">{esc(g["rule_id"])}</div></td>'
            f'<td>{chips}</td>'
            f'<td class="r">{g["count"]:,}</td>'
            f'<td><div class="sample">{esc(g["first_summary"])}</div></td>'
            f'</tr>'
        )
    return f"""
<section class="findings">
  <h2>Findings <span class="muted">({len(grouped)} rules · {len(findings):,} total hits)</span></h2>
  <table class="findings-table">
    <thead><tr><th>Severity</th><th>Rule</th><th>MITRE</th><th class="r">Hits</th><th>Example evidence</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>
"""


def _render_per_artifact(per_artifact: list[dict[str, Any]]) -> str:
    if not per_artifact:
        return ""
    blocks = []
    for entry in per_artifact:
        sample_rows = "".join(
            f"<tr><td class='mono small'>{esc(s.get('timestamp') or '—')}</td>"
            f"<td>{esc(s.get('event_type'))}</td>"
            f"<td>{esc(s.get('summary'))}</td></tr>"
            for s in entry["samples"]
        )
        blocks.append(
            f'<div class="artifact">'
            f'<h3>{esc(entry["artifact"])} <span class="muted">({entry["count"]:,} events)</span></h3>'
            f'<table class="artifact-table">'
            f'<thead><tr><th>Time</th><th>Event type</th><th>Summary</th></tr></thead>'
            f'<tbody>{sample_rows or "<tr><td colspan=3 class=muted>no events</td></tr>"}</tbody>'
            f'</table></div>'
        )
    return f"""
<section class="per-artifact">
  <h2>Per-source-artifact detail</h2>
  <div class="muted small">Top 10 most-recent events per source.</div>
  {''.join(blocks)}
</section>
"""


def _render_footer(meta: dict[str, Any]) -> str:
    return f"""
<footer class="report-footer">
  <div>Digital Forensics Triage Toolkit · {esc(REPORT_VERSION)}</div>
  <div class="muted">{esc(meta['generated_at'])}</div>
</footer>
"""


# ----- date conversion -------------------------------------------------------


def _iso_to_ms(s: str | None) -> int | None:
    if not s:
        return None
    txt = s.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        if "." in txt:
            head, _, tail = txt.partition(".")
            tz_idx = -1
            for i, ch in enumerate(tail):
                if ch in "+-Z":
                    tz_idx = i
                    break
            tz = tail[tz_idx:] if tz_idx >= 0 else ""
            frac = (tail[:tz_idx] if tz_idx >= 0 else tail)[:6]
            try:
                dt = datetime.fromisoformat(f"{head}.{frac}{tz}")
            except ValueError:
                return None
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _ms_to_short(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


# ----- HTML shell ------------------------------------------------------------

_HTML_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"""

_CSS = """
  :root {
    --bg: #0c0d10; --fg: #e8e9ea; --muted: #8b909a;
    --border: #21242c; --card: #14161b; --accent: #5fa9ff;
    --warn: #f0b75e; --err: #ef6b6b; --crit: #d34d4d;
    --med: #62b9f7; --low: #6b7280; --high: #f0b75e;
  }
  @media print {
    :root { --bg:#fff; --fg:#111; --muted:#666; --border:#ddd; --card:#fafafa; }
    section { page-break-inside: avoid; }
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--fg); margin: 0;
    font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
  main { max-width: 1200px; margin: 0 auto; padding: 20px; }
  h1 { font-size: 22px; margin: 0 0 8px; font-weight: 600; }
  h2 { font-size: 16px; margin: 24px 0 10px; padding-bottom: 4px;
    border-bottom: 1px solid var(--border); font-weight: 600;
    letter-spacing: 0.02em; text-transform: uppercase; color: var(--muted); }
  h3 { font-size: 13px; margin: 14px 0 6px; font-weight: 600; }
  .muted { color: var(--muted); }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  .small { font-size: 11px; }
  .r { text-align: right; }
  /* header */
  .case-header { border: 1px solid var(--border); border-radius: 6px;
    padding: 14px 16px; background: var(--card); }
  .case-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px 16px;
    margin-top: 8px; font-size: 12px; }
  .case-grid .k { color: var(--muted); display: inline-block; min-width: 110px; }
  .case-grid .v { color: var(--fg); }
  /* summary */
  .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;
    margin-bottom: 16px; }
  .card { border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px;
    background: var(--card); }
  .card.span { grid-column: span 1; }
  .card .big { font-size: 26px; font-weight: 600; line-height: 1; margin-bottom: 4px; }
  .chips { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; }
  .chip { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px;
    background: rgba(255,255,255,0.05); color: var(--fg);
    border: 1px solid var(--border); }
  .chip.mitre { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  .chip.sev-critical { background: rgba(211,77,77,0.18); color: var(--crit); border-color: rgba(211,77,77,0.4); }
  .chip.sev-high { background: rgba(240,183,94,0.18); color: var(--high); border-color: rgba(240,183,94,0.4); }
  .chip.sev-medium { background: rgba(98,185,247,0.16); color: var(--med); border-color: rgba(98,185,247,0.4); }
  .chip.sev-low { background: rgba(255,255,255,0.06); color: var(--muted); border-color: var(--border); }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .kvtable { width: 100%; border-collapse: collapse; font-size: 12px; }
  .kvtable td { padding: 3px 6px; border-bottom: 1px solid var(--border); }
  /* mitre */
  .tactics { display: flex; flex-wrap: wrap; gap: 8px; }
  .tcol { min-width: 140px; flex: 1 1 140px; border: 1px solid var(--border);
    border-radius: 6px; padding: 6px; background: var(--card); }
  .tcol-h { font-size: 11px; color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.04em; margin-bottom: 6px; padding-bottom: 4px;
    border-bottom: 1px solid var(--border); }
  .cell { display: flex; justify-content: space-between; align-items: center;
    padding: 4px 6px; margin-bottom: 3px; border-radius: 3px; font-size: 11px;
    border: 1px solid var(--border); }
  .cell .tech { font-family: ui-monospace, Menlo, Consolas, monospace; }
  .cell .cnt { font-weight: 600; }
  .tier-low { background: rgba(98,185,247,0.10); border-color: rgba(98,185,247,0.30); }
  .tier-med { background: rgba(98,185,247,0.22); border-color: rgba(98,185,247,0.55); }
  .tier-high { background: rgba(240,183,94,0.25); border-color: rgba(240,183,94,0.55); color: var(--high); }
  .tier-crit { background: rgba(211,77,77,0.30); border-color: rgba(211,77,77,0.7); color: var(--crit); }
  /* timeline */
  .timeline-svg { display: block; margin-top: 10px; max-width: 100%; }
  .lane-bg0 { fill: rgba(255,255,255,0.02); }
  .lane-bg1 { fill: rgba(255,255,255,0.05); }
  .lane-label { font: 11px ui-monospace, Menlo, Consolas, monospace; fill: var(--muted); }
  .lane-count { fill: var(--fg); }
  .dot { fill: var(--accent); }
  .axis, .tick { stroke: var(--border); stroke-width: 1; }
  .tick-label { font: 10px ui-monospace, Menlo, Consolas, monospace; fill: var(--muted); }
  /* findings table */
  .findings-table, .artifact-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .findings-table th, .artifact-table th { text-align: left; padding: 6px 8px;
    border-bottom: 1px solid var(--border); color: var(--muted);
    text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; }
  .findings-table td, .artifact-table td { padding: 6px 8px;
    border-bottom: 1px solid var(--border); vertical-align: top; }
  .rule-title { font-weight: 600; }
  .sample { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px;
    color: var(--muted); }
  /* per artifact */
  .artifact { margin-bottom: 18px; }
  /* footer */
  .report-footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--border);
    display: flex; justify-content: space-between; font-size: 11px; color: var(--muted); }
"""
