# Project Orientation for Claude

> **This file is the entry point for any new chat working on this project. Read it first.**

## Project

**Name (working)**: Digital Forensics Triage Toolkit

**Mission**: A portable, cross-platform forensic triage tool that runs from a USB drive, collects and parses host artifacts (Windows registry hives first, then macOS, then Linux), and presents them in a dense, examiner-grade UI with MITRE ATT&CK-mapped automatic flagging, timeline view, and relationship graphs.

**User context**: This is a portfolio project for an engineer applying to digital forensics firms. Code quality, clean architecture, and forensic correctness matter more than feature breadth. Every detection finding must be defensible (rule-based, explainable — NOT ML).

**Current phase**: Phase 1 — Windows. See [docs/PHASE1_WINDOWS.md](docs/PHASE1_WINDOWS.md).

## Read first

Before doing any work in this repo:

1. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — modular collector/parser/UI design
2. [docs/EVENT_SCHEMA.md](docs/EVENT_SCHEMA.md) — normalized event schema (the universal glue)
3. [docs/DETECTIONS.md](docs/DETECTIONS.md) — YAML rule format, MITRE ATT&CK mapping
4. [docs/ROADMAP.md](docs/ROADMAP.md) — phase plan
5. [docs/PHASE1_WINDOWS.md](docs/PHASE1_WINDOWS.md) — current phase detail

## Stack

- **Shell**: Tauri (Rust) — small portable binary (~10MB)
- **Parsing core**: Python 3.11+ as sidecar process, bundled with PyInstaller. Key libraries:
  - `dissect.target` (Fox-IT) — registry, $MFT, evtx, shellbags, USB, prefetch, AmCache
  - `regipy` — registry plugin ecosystem (fallback / cross-check)
  - `python-evtx`, `Evtx` — Windows event logs
  - `LnkParse3` — LNK files
- **UI**: Vite + React + TypeScript, shadcn/ui + Tailwind, TanStack Table, Apache ECharts (timeline), react-flow (graphs), Zustand (state)
- **Event store**: SQLite, file-based
- **IPC**: JSON over stdio between Tauri shell and Python sidecar

## Conventions

- **Python**: type hints required, `ruff` for lint, `pytest` for tests
- **TypeScript**: strict mode, `biome` for lint/format
- **Detection rules**: YAML in `rules/`, organized by MITRE tactic. Every rule MUST map to one or more MITRE ATT&CK technique IDs.
- **Events**: every parsed artifact emits the normalized event schema in [docs/EVENT_SCHEMA.md](docs/EVENT_SCHEMA.md)
- **No ML for detections** — rule-based only, for explainability and court defensibility
- **No writes to source artifacts**. All operations logged to an audit trail. Hashes recorded for every collected file.

## Directory layout

```
collectors/   # OS-specific artifact collection (windows/, macos/, linux/)
parsers/      # per-artifact parsers, output normalized events
rules/        # YAML detection rules, MITRE-mapped, organized by tactic
core/         # event store, timeline engine, rule evaluator, reports
ui/           # Tauri + React frontend
tests/        # pytest suites, including rule fixtures
docs/         # design docs (this folder)
test_data/    # local-only artifact samples (gitignored)
```

## Key architectural decisions (locked in)

| Decision | Why |
|---|---|
| Windows first, then macOS, then Linux | Target market priority; macOS = portfolio differentiator (Phase 2) |
| Tauri over Electron | 10MB vs 150MB matters for a pendrive tool |
| Python sidecar over pure Rust | `dissect.target` + `regipy` ecosystem is unbeatable in Rust |
| Rule-based over ML for detections | Court-defensible; "the model said so" is not admissible |
| MITRE ATT&CK mapping mandatory | Industry standard; signals examiner-grade thinking |
| Normalized event schema across all parsers | Lets UI, store, and rules stay OS-agnostic; new OS = new collectors + parsers only |
| SQLite event store | Ubiquitous, queryable, file-based, portable |
| OS auto-detect + user confirmation screen on boot | Plus per-OS elevation prompt; no silent elevation |

## Chat refresh protocol

This project may span multiple chats (to manage token costs). When starting a fresh chat:

1. Read this file first
2. Read the phase doc for the current work (e.g. `docs/PHASE1_WINDOWS.md`)
3. `git log --oneline -20` to see recent progress
4. Browse existing code under `collectors/`, `parsers/`, etc.
5. Check `docs/PROGRESS.md` if it exists — running log of completed milestones

## Coding behavior

- **Do not over-engineer**. Ship a working artifact end-to-end before adding more breadth.
- **Do not write speculative comments** — code should be self-documenting, comments reserved for non-obvious *why*.
- **Test fixtures** for every parser and every rule live under `tests/`.
- **Documentation lives in `docs/`**, kept current as features land.
- **The user prefers concise updates**, not verbose summaries. Short, direct status reports during work.
