"""Single-file HTML report generator.

Pure stdlib — no jinja2, no matplotlib. The report is one self-contained
HTML file (inline CSS + inline SVG) so the examiner can email it, archive
it, or print it from a browser without external dependencies.

Sections, in order:
  1. Case header (case name, examiner, generated-at, host, collection)
  2. Summary stats (event totals, time span, findings by severity)
  3. MITRE ATT&CK heat-map (tactics by technique counts, color-tiered)
  4. Timeline (inline SVG lane chart, one lane per source_artifact)
  5. Findings (rule, severity, technique chips, sample evidence)
  6. Per-source-artifact sections (top events per artifact)

PDF export is intentionally out of scope here — the examiner uses their
browser's Print → Save as PDF. Keeps the toolkit dep-free.
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from core.timeutil import iso_to_ms

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
    findings_total = store.count_findings(collection_id=collection_id)
    findings_by_severity = store.counts_by_severity(collection_id=collection_id)
    timeline_points = store.query_timeline_points(collection_id=collection_id, limit=100_000)
    per_artifact = _gather_per_artifact(store, collection_id, events_summary["by_source_artifact"])

    body = "\n".join([
        _render_header(meta),
        _render_summary(meta, events_summary, findings_by_severity, findings_total),
        _render_mitre_heatmap(findings),
        _render_timeline(timeline_points, events_summary["by_source_artifact"]),
        _render_per_day(store, collection_id),
        _render_findings(findings),
        _render_deletions(store, collection_id),
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
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _render_header(meta: dict[str, Any]) -> str:
    return f"""
<section class="case-header">
  <h1>DFT — {esc(meta['case_name'])}</h1>
  <div class="case-grid">
    <div><span class="k">Examiner</span><span class="v">{esc(meta['examiner'])}</span></div>
    <div><span class="k">Generated</span><span class="v">{esc(meta['generated_at'])}</span></div>
    <div><span class="k">Host</span><span class="v">{esc(meta['host_id'])} \
({esc(meta['host_os'])})</span></div>
    <div><span class="k">Collection ID</span><span class="v mono">\
{esc(meta['collection_id'])}</span></div>
    <div><span class="k">Collected at</span><span class="v">\
{esc(meta['collection_created_at'])}</span></div>
    <div><span class="k">Source</span><span class="v mono small">\
{esc(meta['collection_note'])}</span></div>
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
            f'<div class="cell {_heat_tier(c)}" '
            f'title="{esc(tech)} ({c} finding{"" if c == 1 else "s"})">'
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
        ms = iso_to_ms(p["timestamp"])
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
    axis_y = len(lanes) * lane_h + 10
    tick_xs = []
    for i in range(n_ticks):
        frac = i / (n_ticks - 1)
        t = t_min + (t_max - t_min) * frac
        x = plot_x0 + int(frac * plot_w)
        lbl = _ms_to_short(int(t))
        tick_xs.append(
            f'<line x1="{x}" y1="{axis_y}" x2="{x}" y2="{axis_y + 6}" class="tick"/>'
            f'<text x="{x}" y="{axis_y + 20}" class="tick-label" text-anchor="middle">{lbl}</text>'
        )
    axis = (
        f'<line x1="{plot_x0}" y1="{axis_y}" x2="{plot_x0 + plot_w}" '
        f'y2="{axis_y}" class="axis"/>'
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
  <div class="muted small">{len(ts_points):,} dated events across {len(lanes)} sources · \
{_ms_to_short(t_min)} → {_ms_to_short(t_max)}</div>
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
    <thead><tr><th>Severity</th><th>Rule</th><th>MITRE</th><th class="r">Hits</th>\
<th>Example evidence</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>
"""


_CONFIDENCE_ORDER = ("direct", "likely", "ambiguous", "unknown")
_METHOD_LABELS = {
    "recycle_bin": "Recycle Bin",
    "usn_journal": "USN journal",
    "mft_unallocated": "MFT (unallocated)",
}
_DELETIONS_RECENT_LIMIT = 50

_CONFIDENCE_EXPLAINER = (
    "<strong>How to read the user column.</strong> "
    "<em>direct</em>: the artifact itself names the account (the file sat in "
    "that user's <code>$Recycle.Bin\\&lt;SID&gt;</code> folder). "
    "<em>likely</em>: exactly one interactive logon session (Security 4624 "
    "type 2/7/10/11, closed by 4634/4647) covered the deletion time, or for an "
    "MFT record the file owner is the only interactive user in the logs. "
    "<em>ambiguous</em>: several users had sessions open, or the time is only "
    "an upper bound; the owner is named when it is one of them. "
    "<em>unknown</em>: no session evidence covers the time. The reason column "
    "states exactly which records the attribution rests on."
)

_DELETION_LIMITS = (
    "<strong>Limits.</strong> No carving: content of files whose clusters were "
    "reused is not recovered. The USN journal has a finite retention window "
    "(commonly days to weeks); older deletions survive only as MFT bounds or not "
    "at all. An unallocated <code>$MFT</code> record gives a <em>last existed "
    "by</em> time (its last <code>$STANDARD_INFORMATION</code> change), not a "
    "deletion time, shown with a &le; prefix. For USN and MFT rows the user is "
    "inferred from who was logged on; a service or scheduled task running as "
    "another account can delete files during a user's session, so a "
    "<em>likely</em> label is an inference, not an observation."
)


def _gather_deletions(store: EventStore, collection_id: str) -> dict[str, Any]:
    recent = store.query_deletions(
        collection_id=collection_id, limit=_DELETIONS_RECENT_LIMIT,
        sort_by="deleted_at", sort_dir="desc",
    )
    bursts = store.query_events(
        collection_id=collection_id, event_type="file_delete_burst",
        sort_by="timestamp", sort_dir="asc", limit=200,
    )
    return {
        "total": store.count_deletions(collection_id=collection_id),
        "by_method": store.deletions_by_method(collection_id=collection_id),
        "by_confidence": store.deletions_by_confidence(collection_id=collection_id),
        "by_actor": store.deletions_by_actor(collection_id=collection_id),
        "exact": store.count_deletions(collection_id=collection_id, time_basis="exact"),
        "recent": recent,
        "bursts": bursts,
    }


def _render_deletions(store: EventStore, collection_id: str) -> str:
    data = _gather_deletions(store, collection_id)
    total = data["total"]
    if not total:
        return (
            '<section class="deletions"><h2>Deleted files</h2>'
            '<div class="muted">No Recycle Bin, USN journal or $MFT deletion '
            'records in this collection.</div>'
            f'<p class="small muted">{_DELETION_LIMITS}</p></section>'
        )
    upper = total - data["exact"]
    method_chips = "".join(
        f'<span class="chip">{esc(_METHOD_LABELS.get(m, m))}: <strong>{c:,}</strong></span>'
        for m, c in data["by_method"].items()
    )
    conf_chips = "".join(
        f'<span class="chip conf-{c}">{c}: <strong>{data["by_confidence"].get(c, 0):,}</strong>'
        f'</span>'
        for c in _CONFIDENCE_ORDER if data["by_confidence"].get(c)
    )
    actor_rows = "".join(
        f"<tr><td>{esc(a['actor_user'] or '—')}</td>"
        f"<td><span class='chip conf-{esc(a['actor_confidence'])}'>"
        f"{esc(a['actor_confidence'])}</span></td>"
        f"<td class='r'>{a['count']:,}</td></tr>"
        for a in data["by_actor"]
    )
    recent_rows = "".join(
        f"<tr><td class='mono small'>"
        f"{'&le; ' if r['time_basis'] == 'upper_bound' else ''}{esc(r['deleted_at'] or '—')}</td>"
        f"<td class='mono small' title='{esc(r['actor_reason'])}'>{esc(r['path'] or r['name'])}"
        f"</td>"
        f"<td>{esc(_METHOD_LABELS.get(r['method'], r['method']))}</td>"
        f"<td>{esc(r['actor_user'] or '—')}</td>"
        f"<td><span class='chip conf-{esc(r['actor_confidence'])}'>"
        f"{esc(r['actor_confidence'])}</span></td>"
        f"<td class='small'>{esc(r['recoverable_hint'] or 'unknown')}</td></tr>"
        for r in data["recent"]
    )
    burst_rows = "".join(
        f"<tr><td class='mono small'>{esc(b['evidence'].get('window_start'))} → "
        f"{esc(b['evidence'].get('window_end'))}</td>"
        f"<td class='r'>{int(b['evidence'].get('count') or 0):,}</td>"
        f"<td>{esc(_METHOD_LABELS.get(b['evidence'].get('method'), b['evidence'].get('method')))}"
        f"</td>"
        f"<td>{esc(b['evidence'].get('actor_user') or '—')}</td>"
        f"<td class='mono small'>"
        f"{esc('; '.join((b['evidence'].get('sample_paths') or [])[:3]))}</td></tr>"
        for b in data["bursts"]
    )
    bursts_html = (
        f'<h3>Deletion bursts <span class="muted">({len(data["bursts"])})</span></h3>'
        f'<table class="artifact-table"><thead><tr><th>Window (UTC)</th><th class="r">Files'
        f'</th><th>Method</th><th>User</th><th>Sample paths</th></tr></thead>'
        f'<tbody>{burst_rows}</tbody></table>'
        if data["bursts"] else
        '<div class="muted small">No deletion bursts (&ge; 20 deletions by one method '
        'within 120 s).</div>'
    )
    return f"""
<section class="deletions">
  <h2>Deleted files <span class="muted">({total:,} total)</span></h2>
  <div class="cards">
    <div class="card"><div class="big">{total:,}</div><div class="muted">deleted files</div></div>
    <div class="card"><div class="big">{data['exact']:,}</div><div class="muted">exact time</div>
      <div class="small muted">{upper:,} upper-bound (MFT)</div></div>
    <div class="card"><div class="muted">By method</div><div class="chips">{method_chips}</div>
      <div class="muted" style="margin-top:6px">By confidence</div>
      <div class="chips">{conf_chips}</div></div>
  </div>
  <h3>By user</h3>
  <table class="artifact-table"><thead><tr><th>User</th><th>Confidence</th>\
<th class="r">Deletions</th></tr></thead><tbody>{actor_rows}</tbody></table>
  <h3>Most recent deletions <span class="muted">(up to {_DELETIONS_RECENT_LIMIT}; \
hover a path for the attribution reason)</span></h3>
  <table class="artifact-table">
    <thead><tr><th>Time (UTC)</th><th>Path</th><th>Method</th><th>User</th>\
<th>Confidence</th><th>Recoverable</th></tr></thead>
    <tbody>{recent_rows}</tbody>
  </table>
  {bursts_html}
  <p class="small muted">{_CONFIDENCE_EXPLAINER}</p>
  <p class="small muted">{_DELETION_LIMITS}</p>
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
            f'<h3>{esc(entry["artifact"])} '
            f'<span class="muted">({entry["count"]:,} events)</span></h3>'
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


# A day's digest leads with high-signal activity (deletions, executions,
# persistence, account/USB events) and fills the remainder with lower-signal
# browsing/file-access so late-day smoking guns aren't crowded out by morning
# web traffic on a busy day.
_HIGH_VALUE_DAY_TYPES = (
    "file_delete", "program_execution", "browser_download", "persistence_entry",
    "account_change", "service_install", "scheduled_task", "shell_command",
    "usb_connection",
)
_FILLER_DAY_TYPES = ("browser_visit", "file_access")
_DAY_SAMPLE_LIMIT = 15
_PER_TYPE_CAP = 5  # up to this many of each high-value type, so every type is represented
_DAY_SAMPLE_MAX = max(_DAY_SAMPLE_LIMIT, _PER_TYPE_CAP * len(_HIGH_VALUE_DAY_TYPES))


def _day_samples(store: EventStore, collection_id: str, day: str) -> list[dict[str, Any]]:
    """Representative sample of a day's activity for the digest.

    Takes up to ``_PER_TYPE_CAP`` of *each* high-value type (so a late-day
    deletion isn't crowded out by a morning of program executions), then fills
    the remaining slots with lower-signal browsing/file-access. High-value picks
    are always kept; the result is sorted by time for display.
    """
    seen: set[str] = set()
    high: list[dict[str, Any]] = []
    for etype in _HIGH_VALUE_DAY_TYPES:
        for r in store.events_on_day(
            day, collection_id=collection_id, event_types=[etype], limit=_PER_TYPE_CAP,
        ):
            if r["event_id"] not in seen:
                seen.add(r["event_id"])
                high.append(r)

    fill = max(0, _DAY_SAMPLE_LIMIT - len(high))
    filler: list[dict[str, Any]] = []
    if fill:
        for r in store.events_on_day(
            day, collection_id=collection_id, event_types=list(_FILLER_DAY_TYPES), limit=fill,
        ):
            if r["event_id"] not in seen:
                seen.add(r["event_id"])
                filler.append(r)

    out = high + filler
    if not out:  # collection has only types outside both lists
        out = store.events_on_day(day, collection_id=collection_id, limit=_DAY_SAMPLE_LIMIT)
    out.sort(key=lambda s: s.get("timestamp") or "")
    return out


def _render_per_day(store: EventStore, collection_id: str) -> str:
    """Per-busy-day activity digest — answers "what was the user doing on day X?".

    Reuses the same ``mean + k * sigma`` busy-day rule as the Timeline tab so the two
    views agree on which days stand out.
    """
    from core.activity import compute_activity

    analysis = compute_activity(store.activity_by_day(collection_id=collection_id))
    busy = [d for d in analysis["days"] if d["busy"]]
    if not busy:
        peak = max((d["count"] for d in analysis["days"]), default=0)
        return (
            '<section class="per-day"><h2>Daily activity</h2>'
            f'<div class="muted small">No statistically busy days '
            f'(threshold {analysis["threshold"]:.0f} events/day; busiest day {peak}).'
            '</div></section>'
        )

    blocks = []
    for d in sorted(busy, key=lambda x: -x["count"]):
        chips = "".join(
            f'<span class="chip">{esc(t)}: {c:,}</span>'
            for t, c in sorted(d["by_event_type"].items(), key=lambda kv: -kv[1])
        )
        samples = _day_samples(store, collection_id, d["date"])
        sample_rows = "".join(
            f"<tr><td class='mono small'>{esc((s.get('timestamp') or '—')[11:19] or '—')}</td>"
            f"<td>{esc(s.get('event_type'))}</td>"
            f"<td>{esc(s.get('summary'))}</td></tr>"
            for s in samples
        )
        blocks.append(
            f'<div class="artifact">'
            f'<h3>{esc(d["date"])} <span class="muted">({d["count"]:,} events)</span> '
            f'<span class="chip sev-high">busy</span></h3>'
            f'<div class="chips">{chips}</div>'
            f'<table class="artifact-table">'
            f'<thead><tr><th>Time (UTC)</th><th>Event type</th><th>Activity</th></tr></thead>'
            f'<tbody>{sample_rows}</tbody></table></div>'
        )
    return f"""
<section class="per-day">
  <h2>Daily activity <span class="muted">({len(busy)} busy day{"" if len(busy) == 1 else "s"} \
· &gt; {analysis['threshold']:.0f} events/day)</span></h2>
  <div class="muted small">Days whose event count exceeds mean + 1.5&sigma; \
({analysis['mean']:.0f} ± {analysis['stddev']:.0f}). Up to {_DAY_SAMPLE_MAX} notable events \
shown per day: up to {_PER_TYPE_CAP} of each high-signal type, then browsing/file-access \
filler.</div>
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


def _ms_to_short(ms: int) -> str:
    # epoch + timedelta avoids datetime.fromtimestamp's platform limits
    # (Windows raises OSError on negative / far-out-of-range values that can
    # slip in from a malformed artifact timestamp).
    try:
        dt = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=ms)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (OverflowError, ValueError, OSError):
        return "—"


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
  .chip.sev-critical { background: rgba(211,77,77,0.18); color: var(--crit);
    border-color: rgba(211,77,77,0.4); }
  .chip.sev-high { background: rgba(240,183,94,0.18); color: var(--high);
    border-color: rgba(240,183,94,0.4); }
  .chip.sev-medium { background: rgba(98,185,247,0.16); color: var(--med);
    border-color: rgba(98,185,247,0.4); }
  .chip.sev-low { background: rgba(255,255,255,0.06); color: var(--muted);
    border-color: var(--border); }
  .chip.conf-direct { background: rgba(95,169,255,0.25); border-color: var(--accent); }
  .chip.conf-likely { border-color: var(--accent); color: var(--accent); }
  .chip.conf-ambiguous { border-style: dashed; color: var(--warn); border-color: var(--warn); }
  .chip.conf-unknown { color: var(--muted); }
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
  .tier-high { background: rgba(240,183,94,0.25); border-color: rgba(240,183,94,0.55);
    color: var(--high); }
  .tier-crit { background: rgba(211,77,77,0.30); border-color: rgba(211,77,77,0.7);
    color: var(--crit); }
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
