"""Deleted-file attribution engine: who deleted what, and when.

Consumes the ``file_delete`` events the Recycle Bin, USN journal and $MFT
parsers emit (evidence contract in ``docs/DELETIONS.md``), collapses the
same deletion seen by several sources into one row, names the most likely
actor with an explicit confidence label and a sentence saying *why*, and
flags bursts of deletions as synthetic ``file_delete_burst`` events so a
YAML rule can pick them up.

Everything here is rule-based. The confidence ladder:

* ``direct``    — the artifact itself names the deleter (Recycle Bin folder SID)
* ``likely``    — exactly one interactive logon session covers the deletion time
* ``ambiguous`` — several sessions do, or the time is only an upper bound
* ``unknown``   — no session evidence at all
"""

from __future__ import annotations

import logging
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from core.events import Event, make_event
from core.timeutil import iso_to_ms

if TYPE_CHECKING:
    from core.store import EventStore

log = logging.getLogger(__name__)

DERIVED_SOURCE_ARTIFACT = "derived.deletions"
ENGINE_VERSION = "deletions/0.1.0"

BURST_MIN_COUNT = 20
BURST_WINDOW_SECONDS = 120

METHOD_RECYCLE_BIN = "recycle_bin"
METHOD_USN = "usn_journal"
METHOD_MFT = "mft_unallocated"

_METHOD_LABEL = {
    METHOD_RECYCLE_BIN: "the Recycle Bin",
    METHOD_USN: "the USN journal",
    METHOD_MFT: "the MFT",
}

WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators",
}

# Security 4624 LogonType values that put a human at the console / RDP / unlock.
INTERACTIVE_LOGON_TYPES = frozenset({"2", "7", "10", "11"})

_NON_HUMAN_ACCOUNTS = frozenset({
    "", "-", "SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE",
})
# Window Manager / font driver pseudo-accounts log on with type 2 on Win8+.
_PSEUDO_ACCOUNT_PREFIXES = ("DWM-", "UMFD-")

# Stable ids across rebuilds so examiner statuses on burst findings survive.
_NAMESPACE = uuid.UUID("7a9f7a3e-3d5c-4a0f-9d7b-0e6b5d0c5a11")

_RECYCLE_BIN_PATH = re.compile(r"\$recycle\.bin\\", re.IGNORECASE)


@dataclass
class DeletionsSummary:
    total: int = 0
    by_method: dict[str, int] = field(default_factory=dict)
    by_actor_confidence: dict[str, int] = field(default_factory=dict)
    by_actor_user: dict[str, int] = field(default_factory=dict)
    bursts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "by_method": dict(self.by_method),
            "by_actor_confidence": dict(self.by_actor_confidence),
            "by_actor_user": dict(self.by_actor_user),
            "bursts": self.bursts,
        }


@dataclass
class Session:
    """One interactive logon session reconstructed from Security 4624/4634/4647."""

    user: str
    start: str
    start_ms: int
    logon_type: str
    logon_id: str | None = None
    end: str | None = None
    end_ms: int | None = None

    def covers(self, t_ms: int) -> bool:
        return self.start_ms <= t_ms and (self.end_ms is None or self.end_ms >= t_ms)

    def describe(self) -> str:
        if self.end is None:
            closing = "still logged on at the end of the data"
        elif self.end[:10] == self.start[:10]:
            closing = f"logoff {self.end[11:]}"
        else:
            closing = f"logoff {self.end}"
        return f"4624 type {self.logon_type} at {self.start}, {closing}"


@dataclass
class _Row:
    event_id: str
    method: str
    deleted_at: str | None
    deleted_ms: int | None
    time_basis: str
    path: str | None
    name: str | None
    size: int | None
    is_directory: bool
    owner_sid: str | None
    actor_sid: str | None
    mft_segment: int | None
    recoverable_hint: str | None
    source_path: str | None
    user_hint: str | None
    recovered_name: str | None
    # (method, deleted_at) of the other sources that saw this same deletion.
    also_seen: list[tuple[str, str | None]] = field(default_factory=list)


# ----- public entry point ----------------------------------------------------


def build_deletions(store: EventStore, collection_id: str) -> DeletionsSummary:
    """Rebuild the ``deletions`` table and the derived burst events for a collection."""
    events = store.query_events(
        collection_id=collection_id, event_type="file_delete", limit=10_000_000,
    )
    rows = _dedup([r for r in (_row_from_event(e) for e in events) if r is not None])

    context = store.query_events(
        collection_id=collection_id,
        event_types=["account_change", "system_config_change", "logon", "logoff",
                     "security_event"],
        limit=10_000_000,
    )
    sid_map = build_sid_map(context)
    sessions = build_sessions(context)
    interactive_users = {s.user for s in sessions}

    out_rows: list[dict[str, Any]] = []
    for row in rows:
        out_rows.append(_attribute(row, sessions, sid_map, interactive_users, collection_id))

    collection = store.get_collection(collection_id) or {}
    bursts = detect_bursts(
        out_rows,
        collection_id=collection_id,
        host_id=str(collection.get("host_id") or "unknown"),
    )
    store.delete_events_by_source(collection_id, DERIVED_SOURCE_ARTIFACT)
    store.insert_events(bursts)
    store.replace_deletions(collection_id, out_rows)

    summary = DeletionsSummary(total=len(out_rows), bursts=len(bursts))
    for r in out_rows:
        summary.by_method[r["method"]] = summary.by_method.get(r["method"], 0) + 1
        conf = r["actor_confidence"]
        summary.by_actor_confidence[conf] = summary.by_actor_confidence.get(conf, 0) + 1
        if r["actor_user"]:
            summary.by_actor_user[r["actor_user"]] = (
                summary.by_actor_user.get(r["actor_user"], 0) + 1
            )
    return summary


# ----- row extraction --------------------------------------------------------


def _method_of(event: dict[str, Any]) -> str:
    ev = event.get("evidence") or {}
    method = ev.get("deletion_method")
    if isinstance(method, str) and method:
        return method
    artifact = str(event.get("source_artifact") or "").lower()
    if "recycle" in artifact:
        return METHOD_RECYCLE_BIN
    if "usn" in artifact:
        return METHOD_USN
    if "mft" in artifact:
        return METHOD_MFT
    return "unknown"


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1] or None


def _row_from_event(event: dict[str, Any]) -> _Row | None:
    event_id = event.get("event_id")
    if not event_id:
        return None
    ev = event.get("evidence") or {}
    method = _method_of(event)
    deleted_at = event.get("timestamp")
    path = ev.get("original_path") if isinstance(ev.get("original_path"), str) else None
    name = ev.get("deleted_name") if isinstance(ev.get("deleted_name"), str) else None
    actor_sid = ev.get("actor_sid")
    if actor_sid is None and method == METHOD_RECYCLE_BIN:
        actor_sid = ev.get("sid")  # pre-contract Recycle Bin parser key
    owner_sid = ev.get("owner_sid") or (actor_sid if method == METHOD_RECYCLE_BIN else None)
    upper_bound = method == METHOD_MFT or event.get("timestamp_source") == "inferred"
    return _Row(
        event_id=str(event_id),
        method=method,
        deleted_at=deleted_at,
        deleted_ms=iso_to_ms(deleted_at),
        time_basis="upper_bound" if upper_bound else "exact",
        path=path,
        name=name or _basename(path),
        size=_as_int(ev.get("deleted_size")),
        is_directory=bool(ev.get("is_directory")),
        owner_sid=str(owner_sid) if owner_sid else None,
        actor_sid=str(actor_sid) if actor_sid else None,
        mft_segment=_as_int(ev.get("mft_segment")),
        recoverable_hint=ev.get("recoverable_hint") or (
            "recycle_bin_blob" if method == METHOD_RECYCLE_BIN and ev.get("recovered_name")
            else None
        ),
        source_path=event.get("source_path"),
        user_hint=event.get("user"),
        recovered_name=ev.get("recovered_name") if isinstance(ev.get("recovered_name"), str)
        else None,
    )


# ----- dedup across sources --------------------------------------------------

_HINT_RANK = {"recycle_bin_blob": 3, "data_runs_present": 2, "resident": 2, "unknown": 0}


def _dedup(rows: list[_Row]) -> list[_Row]:
    """Collapse one physical deletion seen by several artifacts into one row.

    * Recycle Bin ``$I`` record + USN ``FILE_DELETE`` of its ``$R``/``$I`` blob.
    * USN ``FILE_DELETE`` + unallocated MFT record with the same segment number
      *and* file name (segment numbers are reused, so the name must agree too).
    The survivor keeps the exact time and the strongest actor evidence; the
    other methods are listed in ``also_seen`` for the reason sentence.
    """
    by_blob: dict[str, _Row] = {}
    for r in rows:
        if r.method == METHOD_RECYCLE_BIN and r.recovered_name:
            key = r.recovered_name.lower()
            by_blob[key] = r
            if key.startswith("$r"):
                by_blob["$i" + key[2:]] = r

    survivors: list[_Row] = []
    usn_by_segment: dict[tuple[int, str], _Row] = {}
    for r in rows:
        if r.method == METHOD_USN:
            name_key = (r.name or "").lower()
            if r.path and _RECYCLE_BIN_PATH.search(r.path) and name_key in by_blob:
                by_blob[name_key].also_seen.append((METHOD_USN, r.deleted_at))
                continue
            if r.mft_segment is not None and name_key:
                usn_by_segment[(r.mft_segment, name_key)] = r
        survivors.append(r)

    merged: list[_Row] = []
    for r in survivors:
        if r.method == METHOD_MFT and r.mft_segment is not None:
            twin = usn_by_segment.get((r.mft_segment, (r.name or "").lower()))
            if twin is not None:
                twin.also_seen.append((METHOD_MFT, r.deleted_at))
                twin.owner_sid = twin.owner_sid or r.owner_sid
                if _HINT_RANK.get(r.recoverable_hint or "unknown", 0) > _HINT_RANK.get(
                    twin.recoverable_hint or "unknown", 0,
                ):
                    twin.recoverable_hint = r.recoverable_hint
                if not twin.path or "<unresolved>" in twin.path:
                    twin.path = r.path or twin.path
                continue
        merged.append(r)
    return merged


# ----- SID → user and logon sessions ----------------------------------------


def build_sid_map(events: list[dict[str, Any]]) -> dict[str, str]:
    """SID → account name from SAM (``sid`` + ``username``), ProfileList
    (``sid`` + ``profile_path``) and Security 4624 (``TargetUserSid`` +
    ``TargetUserName``), plus the well-known SIDs."""
    out = dict(WELL_KNOWN_SIDS)
    for e in events:
        ev = e.get("evidence") or {}
        sid = ev.get("sid")
        name = ev.get("username")
        if not (isinstance(sid, str) and sid):
            sid = ev.get("TargetUserSid")
            name = ev.get("TargetUserName")
            if not (isinstance(sid, str) and sid.startswith("S-1-5-21-")):
                continue
        if not (isinstance(name, str) and name):
            profile = ev.get("profile_path")
            if isinstance(profile, str) and profile:
                name = _basename(profile)
        if isinstance(name, str) and name and name.upper() not in _NON_HUMAN_ACCOUNTS:
            out.setdefault(str(sid), name)
    return out


def _event_id_of(e: dict[str, Any]) -> int | None:
    return _as_int((e.get("evidence") or {}).get("event_id"))


def _is_human(user: str | None) -> bool:
    if not isinstance(user, str):
        return False
    u = user.strip()
    if u.upper() in _NON_HUMAN_ACCOUNTS or u.endswith("$"):
        return False
    return not u.upper().startswith(_PSEUDO_ACCOUNT_PREFIXES)


def build_sessions(events: list[dict[str, Any]]) -> list[Session]:
    """Interactive sessions from Security 4624 (types 2/7/10/11) closed by the
    4634/4647 with the same ``TargetLogonId`` (or, lacking one, the same user).
    Unclosed sessions stay open to the end of the data."""
    timed = [
        (e.get("timestamp"), i, e) for i, e in enumerate(events)
        if e.get("timestamp") and e.get("event_type") in ("logon", "logoff", "security_event")
    ]
    timed.sort(key=lambda t: (t[0], t[1]))

    open_sessions: list[Session] = []
    done: list[Session] = []
    for ts, _, e in timed:
        ev = e.get("evidence") or {}
        eid = _event_id_of(e)
        user = ev.get("TargetUserName")
        logon_id = ev.get("TargetLogonId")
        logon_type = str(ev.get("LogonType")) if ev.get("LogonType") is not None else None
        ms = iso_to_ms(ts)
        if ms is None or not _is_human(user):
            continue
        if eid == 4624 and logon_type in INTERACTIVE_LOGON_TYPES:
            if logon_id and any(s.logon_id == logon_id for s in open_sessions):
                continue  # duplicate record of the same logon
            open_sessions.append(Session(
                user=str(user), start=str(ts), start_ms=ms, logon_type=logon_type,
                logon_id=str(logon_id) if logon_id else None,
            ))
        elif eid in (4634, 4647):
            match = next(
                (s for s in open_sessions if logon_id and s.logon_id == logon_id), None,
            )
            if match is None and (eid == 4647 or logon_type in INTERACTIVE_LOGON_TYPES):
                match = next((s for s in open_sessions if s.user == user), None)
            if match is None:
                continue
            match.end, match.end_ms = str(ts), ms
            open_sessions.remove(match)
            done.append(match)
    done.extend(open_sessions)
    done.sort(key=lambda s: s.start_ms)
    return done


# ----- attribution -----------------------------------------------------------


def _sessions_covering(sessions: list[Session], t_ms: int) -> list[Session]:
    """One session per user (earliest start) among those covering ``t_ms``."""
    per_user: dict[str, Session] = {}
    for s in sessions:
        if s.covers(t_ms) and s.user not in per_user:
            per_user[s.user] = s
    return list(per_user.values())


def _attribute(
    row: _Row,
    sessions: list[Session],
    sid_map: dict[str, str],
    interactive_users: set[str],
    collection_id: str,
) -> dict[str, Any]:
    owner_user = sid_map.get(row.owner_sid) if row.owner_sid else None
    actor_user: str | None = None
    actor_sid: str | None = None
    notes: list[str] = []

    if row.actor_sid:
        confidence = "direct"
        actor_sid = row.actor_sid
        actor_user = sid_map.get(actor_sid) or row.user_hint or actor_sid
        label = f"({actor_user})" if actor_user != actor_sid else "(account name not resolved)"
        notes.append(f"Found in the Recycle Bin folder of {actor_sid} {label}.")
    elif row.deleted_ms is None:
        confidence = "unknown"
        notes.append("No deletion time is recorded, so no logon session can be matched.")
    elif row.time_basis == "upper_bound":
        confidence, actor_user, actor_sid, text = _attribute_bounded(
            row, sessions, owner_user, interactive_users,
        )
        notes.append(text)
    else:
        confidence, actor_user, actor_sid, text = _attribute_exact(row, sessions, owner_user)
        notes.append(text)

    if row.owner_sid and confidence != "direct":
        if owner_user:
            notes.append(f"File owner: {owner_user} ({row.owner_sid}).")
        else:
            notes.append(f"File owner SID {row.owner_sid} could not be resolved to a name.")
    for method, when in row.also_seen:
        if method == METHOD_USN:
            notes.append(
                f"Also recorded by the USN journal (FILE_DELETE at {when or 'unknown time'})."
            )
        elif method == METHOD_MFT:
            notes.append(
                f"Also present as an unallocated MFT record (last changed {when or 'unknown'})."
            )
        else:
            notes.append(f"Also seen via {method}.")

    return {
        "deletion_id": str(uuid.uuid5(_NAMESPACE, f"{collection_id}|{row.event_id}")),
        "collection_id": collection_id,
        "event_id": row.event_id,
        "deleted_at": row.deleted_at,
        "time_basis": row.time_basis,
        "path": row.path,
        "name": row.name,
        "size": row.size,
        "is_directory": row.is_directory,
        "method": row.method,
        "owner_sid": row.owner_sid,
        "owner_user": owner_user,
        "actor_user": actor_user,
        "actor_sid": actor_sid,
        "actor_confidence": confidence,
        "actor_reason": " ".join(notes),
        "recoverable_hint": row.recoverable_hint or "unknown",
        "source_path": row.source_path,
    }


def _attribute_exact(
    row: _Row, sessions: list[Session], owner_user: str | None,
) -> tuple[str, str | None, str | None, str]:
    assert row.deleted_ms is not None
    covering = _sessions_covering(sessions, row.deleted_ms)
    source = _METHOD_LABEL.get(row.method, row.method)
    if len(covering) == 1:
        s = covering[0]
        return (
            "likely", s.user, None,
            f"{s.user} was the only interactive user logged on ({s.describe()}) "
            f"when {source} recorded the delete.",
        )
    if covering:
        listed = "; ".join(f"{s.user} ({s.describe()})" for s in covering)
        actor = owner_user if owner_user in {s.user for s in covering} else None
        text = (
            f"{len(covering)} users had sessions open when {source} recorded the delete: "
            f"{listed}."
        )
        if actor:
            text += f" {actor} is named because the file was owned by that account."
        return "ambiguous", actor, (row.owner_sid if actor else None), text
    return (
        "unknown", None, None,
        f"No interactive logon session covers {row.deleted_at} "
        f"(the Security log may not span this time).",
    )


def _attribute_bounded(
    row: _Row, sessions: list[Session], owner_user: str | None, interactive_users: set[str],
) -> tuple[str, str | None, str | None, str]:
    assert row.deleted_ms is not None
    bound = (
        f"Record time {row.deleted_at} is an upper bound (last $STANDARD_INFORMATION "
        f"change), not the deletion time."
    )
    if owner_user and interactive_users == {owner_user}:
        return (
            "likely", owner_user, row.owner_sid,
            f"{bound} File owner {owner_user} is the only interactive user in the logon records.",
        )
    covering = _sessions_covering(sessions, row.deleted_ms)
    if covering:
        listed = "; ".join(f"{s.user} ({s.describe()})" for s in covering)
        actor = owner_user if owner_user in {s.user for s in covering} else None
        noun = "user had a session" if len(covering) == 1 else "users had sessions"
        text = (
            f"{bound} {len(covering)} {noun} open at that time: {listed}; "
            f"the file may have been deleted later."
        )
        if actor:
            text += f" {actor} is named because the file was owned by that account."
        return "ambiguous", actor, (row.owner_sid if actor else None), text
    return "unknown", None, None, f"{bound} No interactive logon session covers it."


# ----- bursts ----------------------------------------------------------------


def detect_bursts(
    rows: list[dict[str, Any]],
    *,
    collection_id: str,
    host_id: str,
    min_count: int = BURST_MIN_COUNT,
    window_seconds: int = BURST_WINDOW_SECONDS,
) -> list[Event]:
    """One ``file_delete_burst`` per maximal run of ≥ ``min_count`` exact-time
    deletions by one method where every ``window_seconds`` slice qualifies.
    Upper-bound (MFT) times are excluded: they cluster on last-write, not delete."""
    by_method: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for r in rows:
        ms = iso_to_ms(r.get("deleted_at")) if r.get("time_basis") == "exact" else None
        if ms is None:
            continue
        by_method.setdefault(r["method"], []).append((ms, r))

    window_ms = window_seconds * 1000
    events: list[Event] = []
    for method, timed in sorted(by_method.items()):
        timed.sort(key=lambda t: t[0])
        times = [t for t, _ in timed]
        intervals: list[list[int]] = []
        j = 0
        for i in range(len(times)):
            if j < i:
                j = i
            while j + 1 < len(times) and times[j + 1] - times[i] <= window_ms:
                j += 1
            if j - i + 1 >= min_count:
                if intervals and i <= intervals[-1][1]:
                    intervals[-1][1] = max(intervals[-1][1], j)
                else:
                    intervals.append([i, j])
        for lo, hi in intervals:
            members = [r for _, r in timed[lo:hi + 1]]
            events.append(_burst_event(members, method, collection_id, host_id))
    return events


def _burst_event(
    members: list[dict[str, Any]], method: str, collection_id: str, host_id: str,
) -> Event:
    start = members[0]["deleted_at"]
    end = members[-1]["deleted_at"]
    actors = Counter(r["actor_user"] for r in members if r.get("actor_user"))
    actor = actors.most_common(1)[0][0] if actors else None
    span_s = max(0, (iso_to_ms(end) or 0) - (iso_to_ms(start) or 0)) // 1000
    who = f" — {actor}" if actor else ""
    event = make_event(
        host_os="windows",
        host_id=host_id,
        source_artifact=DERIVED_SOURCE_ARTIFACT,
        source_path="derived",
        event_type="file_delete_burst",
        summary=f"Bulk deletion: {len(members)} files via {method} within {span_s}s{who}",
        evidence={
            "count": len(members),
            "window_start": start,
            "window_end": end,
            "method": method,
            "actor_user": actor,
            "sample_paths": [r["path"] for r in members[:10] if r.get("path")],
            "deletion_ids": [r["deletion_id"] for r in members],
        },
        collection_id=collection_id,
        parser_version=ENGINE_VERSION,
        timestamp=start,
        timestamp_source="inferred",
        user=actor,
    )
    event.event_id = str(uuid.uuid5(_NAMESPACE, f"{collection_id}|burst|{method}|{start}|{end}"))
    return event
