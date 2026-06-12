"""Parametrized rule fixture tests.

For every YAML rule under ``rules/`` there must be a matching directory
under ``tests/rules/<rule_id>/`` containing ``positive.json`` (events that
MUST match) and ``negative.json`` (events that MUST NOT match). This is
the contract per ``docs/DETECTIONS.md`` — a rule cannot ship without both.

The unit tests here also exercise the engine: predicate operators, OR
groups, dot-notation field access, and the evaluation entry point that
wraps a rule list against an event stream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.rules import (
    Rule,
    evaluate_rules,
    load_rule_file,
    load_rules_from_dir,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = Path(__file__).resolve().parent / "rules"


def _all_rules() -> list[Rule]:
    return load_rules_from_dir(RULES_DIR)


def _fixture_pairs() -> list[tuple[Rule, Path, Path]]:
    pairs: list[tuple[Rule, Path, Path]] = []
    for rule in _all_rules():
        rule_dir = FIXTURES_DIR / rule.id
        pos = rule_dir / "positive.json"
        neg = rule_dir / "negative.json"
        pairs.append((rule, pos, neg))
    return pairs


@pytest.mark.parametrize(
    "rule,positive,negative",
    _fixture_pairs(),
    ids=lambda x: x.id if isinstance(x, Rule) else "",
)
def test_rule_fixtures(rule: Rule, positive: Path, negative: Path) -> None:
    assert positive.exists(), f"missing positive.json for rule {rule.id}"
    assert negative.exists(), f"missing negative.json for rule {rule.id}"

    positives = json.loads(positive.read_text(encoding="utf-8"))
    negatives = json.loads(negative.read_text(encoding="utf-8"))

    assert isinstance(positives, list) and positives, (
        f"{rule.id}: positive.json must be a non-empty list"
    )
    assert isinstance(negatives, list) and negatives, (
        f"{rule.id}: negative.json must be a non-empty list"
    )

    for i, ev in enumerate(positives):
        assert rule.evaluate(ev), f"{rule.id}: positive[{i}] should have matched: {ev}"

    for i, ev in enumerate(negatives):
        assert not rule.evaluate(ev), (
            f"{rule.id}: negative[{i}] should NOT have matched: {ev}"
        )


# --- Engine-level tests ---------------------------------------------------

def test_load_rules_from_dir_loads_every_yaml() -> None:
    rules = _all_rules()
    assert len(rules) >= 15, "expected the M7 starter rule set to load"
    ids = {r.id for r in rules}
    assert len(ids) == len(rules), "rule ids must be unique"


def test_load_rule_rejects_missing_mitre(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "id: x\ntitle: x\nseverity: low\nmitre:\n  techniques: []\nmatch:\n  event_type: x\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="MITRE"):
        load_rule_file(bad)


def test_load_rule_rejects_bad_severity(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "id: x\ntitle: x\nseverity: yolo\nmitre:\n  techniques: [T1]\nmatch:\n  event_type: x\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="severity"):
        load_rule_file(bad)


def test_load_rule_rejects_duplicate_ids(tmp_path: Path) -> None:
    body = (
        "id: dup-001\ntitle: A\nseverity: low\nmitre:\n  techniques: [T1]\n"
        "match:\n  event_type: x\n"
    )
    (tmp_path / "a.yml").write_text(body, encoding="utf-8")
    (tmp_path / "b.yml").write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_rules_from_dir(tmp_path)


def test_evaluate_rules_emits_finding_per_match() -> None:
    rules = _all_rules()
    powerful = next(r for r in rules if r.id == "defense_evasion-audit-log-cleared-001")
    events = [
        {
            "event_id": "ev-1",
            "source_artifact": "evtx.security",
            "event_type": "security_event",
            "summary": "Audit log cleared (Security 1102)",
            "evidence": {"event_id": 1102},
        },
        {
            "event_id": "ev-2",
            "source_artifact": "evtx.security",
            "event_type": "logon",
            "summary": "ok",
            "evidence": {"event_id": 4624},
        },
    ]
    findings = evaluate_rules([powerful], events, collection_id="col-x")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == powerful.id
    assert finding.evidence_event_ids == ("ev-1",)
    assert finding.severity == "critical"
    assert "T1070.001" in finding.mitre_techniques


def test_evaluate_rules_skips_events_without_event_id() -> None:
    rules = _all_rules()
    powerful = next(r for r in rules if r.id == "defense_evasion-audit-log-cleared-001")
    events = [{"source_artifact": "evtx.security", "evidence": {"event_id": 1102}}]
    findings = evaluate_rules([powerful], events, collection_id="col-x")
    assert findings == []


def test_predicate_dot_notation_handles_missing_intermediate() -> None:
    rules = _all_rules()
    any_run = next(r for r in rules if r.id == "persistence-run-key-userwritable-001")
    # evidence missing entirely should not match
    ev = {
        "event_id": "x",
        "event_type": "persistence_entry",
        "source_artifact": "registry.ntuser",
    }
    assert any_run.evaluate(ev) is False
