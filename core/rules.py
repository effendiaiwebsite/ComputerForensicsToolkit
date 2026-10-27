"""YAML rule loader + evaluator.

A rule is a YAML document conforming to ``docs/DETECTIONS.md``. Predicates
operate on the normalized ``Event`` schema and use dot notation to reach
nested fields (``evidence.value_data``, ``raw.scriptblock``, etc.).

The engine is rule-based on purpose: every flag must be defensible in
court. "The model said so" doesn't pass that bar — a YAML rule does.
"""

from __future__ import annotations

import fnmatch
import logging
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml

Severity = Literal["low", "medium", "high", "critical"]

logger = logging.getLogger(__name__)

_VALID_SEVERITIES: set[Severity] = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    references: tuple[str, ...]
    match: dict[str, Any]
    author: str | None = None
    date: str | None = None
    source_path: str | None = None

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return _match_spec(event, self.match)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    rule_title: str
    severity: Severity
    mitre_techniques: tuple[str, ...]
    mitre_tactics: tuple[str, ...]
    evidence_event_ids: tuple[str, ...]
    collection_id: str
    created_at: str
    summary: str
    examiner_status: str = "new"


def load_rules_from_dir(root: str | Path) -> list[Rule]:
    """Load every ``.yml`` rule under ``root`` (recursively); unparseable files are logged."""
    rules, _failed = load_rules_from_dir_with_errors(root)
    return rules


def load_rules_from_dir_with_errors(root: str | Path) -> tuple[list[Rule], dict[str, str]]:
    """Like :func:`load_rules_from_dir` but also returns ``{file: error}`` for
    rule files that could not be loaded. Raises ``FileNotFoundError`` when
    ``root`` is not a directory, so a misconfigured rules path is not mistaken
    for an empty rule set."""
    root_path = Path(root)
    if not root_path.is_dir():
        raise FileNotFoundError(f"rules directory not found: {root_path}")
    rules: list[Rule] = []
    failed: dict[str, str] = {}
    seen_ids: dict[str, str] = {}
    for yml in sorted(root_path.rglob("*.yml")):
        try:
            rule = load_rule_file(yml)
        except Exception as exc:
            logger.error("could not load rule %s: %s", yml, exc)
            failed[str(yml)] = f"{type(exc).__name__}: {exc}"
            continue
        if rule.id in seen_ids:
            raise ValueError(
                f"duplicate rule id {rule.id!r}: {seen_ids[rule.id]} and {yml}"
            )
        seen_ids[rule.id] = str(yml)
        rules.append(rule)
    return rules, failed


def load_rule_file(path: str | Path) -> Rule:
    path_obj = Path(path)
    raw = yaml.safe_load(path_obj.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"rule file must contain a mapping at the top level: {path}")
    rule = _rule_from_dict(raw)
    object.__setattr__(rule, "source_path", str(path_obj))
    return rule


def _rule_from_dict(d: dict[str, Any]) -> Rule:
    for required in ("id", "title", "severity", "mitre", "match"):
        if required not in d:
            raise ValueError(f"rule is missing required key: {required!r}")

    severity = d["severity"]
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"invalid severity {severity!r}; must be one of {sorted(_VALID_SEVERITIES)}"
        )

    mitre = d["mitre"] or {}
    techniques = _string_tuple(mitre.get("techniques"), f"rule {d['id']!r}: mitre.techniques")
    tactics = _string_tuple(mitre.get("tactics"), f"rule {d['id']!r}: mitre.tactics")
    if not techniques:
        raise ValueError(f"rule {d['id']!r} must declare at least one MITRE technique")

    match = d["match"]
    if not isinstance(match, dict):
        raise ValueError(f"rule {d['id']!r}: 'match' must be a mapping")
    _validate_spec(match, f"rule {d['id']!r}: match")

    return Rule(
        id=str(d["id"]),
        title=str(d["title"]),
        description=str(d.get("description") or ""),
        severity=severity,
        techniques=techniques,
        tactics=tactics,
        references=tuple(d.get("references") or ()),
        match=match,
        author=d.get("author"),
        date=str(d["date"]) if d.get("date") else None,
    )


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    """Normalize a YAML scalar-or-list into a tuple of strings.

    A bare ``techniques: T1547.001`` must become ``("T1547.001",)``, not the
    characters of the string.
    """
    if value is None:
        return ()
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)):
        raise ValueError(f"{label} must be a string or a list of strings")
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{label} entries must be non-empty strings, got {item!r}")
    return tuple(items)


_NUMERIC_OPS = frozenset({"gt", "lt", "gte", "lte"})


def _validate_spec(spec: Mapping[str, Any], label: str) -> None:
    """Reject predicate arguments that could never compare sensibly at runtime."""
    for field_key, predicate in spec.items():
        if field_key == "any_of":
            if not isinstance(predicate, list):
                raise ValueError(f"{label}.any_of must be a list of mappings")
            for i, branch in enumerate(predicate):
                if not isinstance(branch, Mapping):
                    raise ValueError(f"{label}.any_of[{i}] must be a mapping")
                _validate_spec(branch, f"{label}.any_of[{i}]")
            continue
        if not isinstance(predicate, Mapping):
            continue
        for op, op_arg in predicate.items():
            if op in _NUMERIC_OPS and _safe_num(op_arg) is None:
                raise ValueError(
                    f"{label}.{field_key}.{op} needs a numeric argument, got {op_arg!r}"
                )


# --- predicate evaluation -------------------------------------------------

def _match_spec(event: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    """AND across all top-level keys; ``any_of`` short-circuits as OR."""
    if "any_of" in spec:
        branches = spec["any_of"]
        if not isinstance(branches, list):
            return False
        if not any(_match_spec(event, sub) for sub in branches if isinstance(sub, dict)):
            return False
    for field_key, predicate in spec.items():
        if field_key == "any_of":
            continue
        value = _get_field(event, field_key)
        if not _match_predicate(value, predicate):
            return False
    return True


def _get_field(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def _match_predicate(value: Any, predicate: Any) -> bool:
    if isinstance(predicate, dict):
        return all(_apply_op(value, op, op_arg) for op, op_arg in predicate.items())
    return value == predicate


def _apply_op(value: Any, op: str, op_arg: Any) -> bool:
    if op == "in":
        return value in (op_arg or [])
    if op == "regex":
        return isinstance(value, str) and re.search(op_arg, value) is not None
    if op == "glob":
        return isinstance(value, str) and fnmatch.fnmatchcase(value, op_arg)
    if op == "iglob":
        return isinstance(value, str) and fnmatch.fnmatchcase(value.lower(), op_arg.lower())
    if op in _NUMERIC_OPS:
        num, bound = _safe_num(value), _safe_num(op_arg)
        if num is None or bound is None:
            return False
        if op == "gt":
            return num > bound
        if op == "lt":
            return num < bound
        if op == "gte":
            return num >= bound
        return num <= bound
    if op == "exists":
        return (value is not None) == bool(op_arg)
    if op == "not":
        return value != op_arg
    if op == "contains":
        if isinstance(value, str):
            return op_arg in value
        if isinstance(value, (list, tuple, set)):
            return op_arg in value
        return False
    if op == "icontains":
        if isinstance(value, str) and isinstance(op_arg, str):
            return op_arg.lower() in value.lower()
        return False
    raise ValueError(f"unknown predicate operator: {op!r}")


def _safe_num(value: Any) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


# --- evaluation against an event stream ----------------------------------

def evaluate_rules(
    rules: Iterable[Rule],
    events: Iterable[Mapping[str, Any]],
    *,
    collection_id: str,
) -> list[Finding]:
    """Evaluate every rule against every event; emit one Finding per match."""
    rule_list = list(rules)
    findings: list[Finding] = []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for event in events:
        event_id = event.get("event_id")
        if not event_id:
            continue
        for rule in rule_list:
            try:
                hit = rule.evaluate(event)
            except Exception:
                logger.exception("rule %s threw on event %s", rule.id, event_id)
                continue
            if not hit:
                continue
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    mitre_techniques=rule.techniques,
                    mitre_tactics=rule.tactics,
                    evidence_event_ids=(str(event_id),),
                    collection_id=collection_id,
                    created_at=now,
                    summary=_finding_summary(rule, event),
                )
            )
    return findings


def _finding_summary(rule: Rule, event: Mapping[str, Any]) -> str:
    snippet = str(event.get("summary") or "")
    if len(snippet) > 200:
        snippet = snippet[:197] + "…"
    return f"{rule.title} — {snippet}" if snippet else rule.title
