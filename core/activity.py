"""Busy-day detection over per-day activity counts.

Rule-based and explainable (no ML, per project policy): a day is "busy" when
its event count exceeds ``mean + k·sigma`` of all active days' counts — a standard,
defensible statistical threshold. The mean, population standard deviation, and
the resulting threshold are returned alongside the flags so a finding can be
justified in a report ("July 14 had 312 events vs a 41 ± 28 baseline").
"""

from __future__ import annotations

from statistics import mean, pstdev
from typing import Any

DEFAULT_K = 1.5


def compute_activity(daily: list[dict[str, Any]], *, k: float = DEFAULT_K) -> dict[str, Any]:
    """Annotate ``daily`` rows with a ``busy`` flag and return the threshold stats.

    ``daily`` is the output of ``EventStore.activity_by_day`` — a list of
    ``{date, count, by_event_type}`` in ascending date order. A day is flagged
    ``busy`` when ``count > mean + k·sigma`` (and strictly above the mean, so a flat
    distribution flags nothing).
    """
    counts = [int(d["count"]) for d in daily]
    if not counts:
        return {"days": [], "mean": 0.0, "stddev": 0.0, "threshold": 0.0, "k": k, "busy_dates": []}

    mu = mean(counts)
    sigma = pstdev(counts) if len(counts) > 1 else 0.0
    threshold = mu + k * sigma

    days: list[dict[str, Any]] = []
    busy_dates: list[str] = []
    for d in daily:
        is_busy = d["count"] > threshold and d["count"] > mu
        days.append({**d, "busy": is_busy})
        if is_busy:
            busy_dates.append(d["date"])

    return {
        "days": days,
        "mean": mu,
        "stddev": sigma,
        "threshold": threshold,
        "k": k,
        "busy_dates": busy_dates,
    }
