# Detection Rules

Rule-based, YAML, MITRE ATT&CK mapped. Inspired by Sigma but tailored to our normalized event schema.

**Why rules, not ML**: Forensic findings must be defensible. An examiner has to explain in writing (and sometimes in court) *why* something is flagged. "The model said so" doesn't pass that bar. Every YAML rule is an explainable, auditable assertion.

## Rule file format

```yaml
id: persistence-run-key-appdata-001
title: Run key entry pointing to user-writable location
description: |
  A Run/RunOnce registry value pointing to a binary in %APPDATA%, %TEMP%, or
  %LOCALAPPDATA% is suspicious — legitimate persistence typically lives in
  Program Files or system paths. This pattern is heavily used by commodity
  malware and post-exploitation frameworks.
severity: high             # low | medium | high | critical
mitre:
  techniques: [T1547.001]
  tactics: [persistence]
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: <your name>
date: 2026-06-09

match:
  event_type: persistence_entry
  source_artifact:
    in: [registry.ntuser, registry.software]
  evidence.key_name:
    in: [Run, RunOnce]
  evidence.value_path:
    regex: '(?i)\\(AppData|Local\\Temp|Roaming)\\'

# Optional: aggregate across events
# correlate:
#   group_by: [user]
#   timeframe: 1h
#   min_count: 3
```

## Match operators

The `match` block is an AND of field predicates. Each predicate is one of:

| Operator | Example |
|---|---|
| equality (scalar) | `event_type: persistence_entry` |
| `in` | `source_artifact: { in: [a, b] }` |
| `regex` | `evidence.value_path: { regex: '(?i)temp' }` |
| `glob` | `evidence.program_path: { glob: '*\\Temp\\*' }` |
| `gt`, `lt`, `gte`, `lte` | `evidence.size_bytes: { gt: 10485760 }` |
| `exists` | `evidence.sha1: { exists: true }` |
| `not` | `evidence.signed: { not: true }` |

Nested fields use dot notation: `evidence.value_path`, `raw.user_assist.run_count`.

## OR logic and groups

```yaml
match:
  any_of:
    - event_type: program_execution
      evidence.program_path: { regex: '(?i)\\Temp\\' }
    - event_type: program_execution
      evidence.program_path: { regex: '(?i)\\AppData\\Local\\' }
```

## Correlation rules

For rules that need multiple events to fire together (rare in Phase 1):

```yaml
correlate:
  group_by: [host_id, user]
  timeframe: 1h
  min_count: 5
  sub_match:
    event_type: logon
    evidence.logon_result: failure
```

## Severity levels

| Level | Meaning |
|---|---|
| `low` | Worth noting; benign in most contexts |
| `medium` | Suspicious; warrants examiner review |
| `high` | Strong indicator of compromise or policy violation |
| `critical` | Almost certainly malicious unless explained |

## MITRE ATT&CK mapping is mandatory

Every rule MUST declare at least one technique ID under `mitre.techniques`. This is the differentiator that signals examiner-grade thinking. Tactic is derived but should also be explicit for filtering.

## Phase 1 initial rule set

Target: ~30 rules at Phase 1 ship, covering these tactics. Each row is one or more rules.

| Tactic | Examples |
|---|---|
| Persistence | Run/RunOnce in user-writable path; IFEO debugger keys set; Service ImagePath in temp; Winlogon Shell/Userinit tampered; AppInit_DLLs non-empty; suspicious Scheduled Tasks; Active Setup; LSA Notification Packages |
| Defense Evasion | Defender disabled via registry (`DisableAntiSpyware`, `DisableRealtimeMonitoring`); UAC `EnableLUA=0`; SmartScreen disabled; event log cleared (Event ID 1102) |
| Execution | LOLBins observed in AmCache or Prefetch with anomalous parent: `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, `cscript`/`wscript` running scripts from `%TEMP%` |
| Discovery | RDP MRU populated unexpectedly; network enumeration binaries in ShimCache |
| Lateral Movement | RDP-related logon events from unexpected source IP; PsExec/SMBExec service install patterns; ADMIN$ share access |
| Collection | Recent archive tool execution (7z, rar, WinRAR portable) with large output volume nearby |
| Exfiltration | USB connection event correlated with mass file access in same window |
| Credential Access | LSASS access via known dump tools (procdump.exe to lsass dump); SAM hive copy via reg.exe save |
| Impact / anti-forensics (deletions) | see below |

### Deletion and anti-forensic rules

These rules consume the deleted-file pipeline described in
[DELETIONS.md](DELETIONS.md). Each has a fixture pair under `tests/rules/`.

| Rule id | Fires on | Techniques | Severity |
|---|---|---|---|
| `defense_evasion-anti-forensic-tool-executed-001` | `program_execution` of sdelete, sdelete64, eraser, eraserl, ccleaner, ccleaner64, bleachbit, bleachbit_console, cipher, privazer, wipefile, shred (any of `program_path`, `executable_filename`, `program_name`) | T1070.004, T1485 | high (cipher.exe and CCleaner have routine uses; the description says so) |
| `defense_evasion-referenced-file-missing-001` | `program_execution` / `file_access` with `evidence.referenced_path_exists == false` (set by the ghost-reference pass) | T1070.004 | medium |
| `impact-bulk-deletion-001` | the derived `file_delete_burst` event (≥ 20 deletions by one method inside 120 s) | T1485 | high |
| `defense_evasion-usn-journal-deleted-001` | `file_delete` whose `original_path` ends in `$UsnJrnl`, `$UsnJrnl:$J` or `$J`, or `program_execution` of fsutil.exe | T1070.004 | high |

The equality predicate compares with Python `==`, so `evidence.flag: false`
matches a stored JSON `false` and nothing else (a missing key is `None`).

## Rule authoring conventions

- One rule per file
- Filename: `<short-slug>.yml`
- Organized under `rules/<tactic>/`
- Rule `id`: `<tactic>-<slug>-<3-digit-num>` (must be globally unique)
- Always provide `references` to ATT&CK page or vendor write-up
- Test fixtures for each rule under `tests/rules/<rule_id>/` containing:
  - `positive.json` — events that MUST match
  - `negative.json` — events that MUST NOT match
- Rule tests run in CI; a rule cannot ship without both fixtures

## Suppression and tuning

Findings carry an `examiner_status` field. The UI lets an examiner mark findings as `suppressed`, `confirmed_benign`, or `confirmed_malicious`. Suppression is per-case, not global; rules themselves don't get edited as a tuning workflow.
