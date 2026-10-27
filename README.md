# Digital Forensics Triage Toolkit

I built this for my computer forensics coursework as a single tool that can be run off a USB stick, pointed at a Windows machine or a disk image, and give a quick, readable picture of what happened on that system — what programs ran, who logged in, which USB drives were connected, what was browsed and downloaded, what got deleted, and roughly when it all happened.

The motivation was mostly frustration with the usual workflow. A lot of the free tooling in this space is a drawer full of separate single-purpose utilities: one for prefetch, one for browser history, one for USB devices, another for the recycle bin, and so on. Each exports to its own format and you end up stitching timelines together by hand in a spreadsheet. I wanted one place that collects the common Windows artifacts, parses them into a single timeline, and points out the things an examiner would actually stop and look at — with every finding traceable back to the exact artifact it came from, so nothing is a black box.

## What it does

Point it at a live system, a folder of already-collected artifacts, or an E01 / raw disk image, and it will:

- Pull the usual Windows artifacts — registry hives (SYSTEM, SOFTWARE, SAM, NTUSER, UsrClass, AmCache), Windows event logs, prefetch, ShimCache, USB device history, LNK files and JumpLists, browser history (Chrome/Edge/Brave, Firefox, plus legacy IE `index.dat` and the newer WebCache ESE database), Recycle Bin `$I` records, the NTFS USN change journal and unallocated `$MFT` records.
- Normalize all of it into one event schema, so search and the timeline behave the same no matter which artifact an event originally came from.
- Answer "who deleted what, and when": Recycle Bin, USN journal and `$MFT` evidence is merged into one Deleted files view, each row carrying the actor with a confidence label (`direct`, `likely`, `ambiguous`, `unknown`) and a sentence saying which records the attribution rests on. Twenty or more deletions inside two minutes are flagged as a burst, and LNK / JumpList / Prefetch entries that point at files no longer on the volume are marked as ghost references.
- Flag suspicious activity using plain YAML rules mapped to MITRE ATT&CK techniques. The rules are deliberately simple and rule-based rather than machine learning — in a forensic context you have to be able to explain *why* something was flagged, and "the model decided" doesn't survive cross-examination.
- Show everything in a dense, examiner-style interface: filterable event tables, a zoomable multi-track timeline (with a busy-day detector that highlights unusually active days), a per-device USB view, a browser-history rollup by domain, and a filesystem browser you can export files out of.
- Produce a self-contained HTML report you can print straight to PDF for a case file.

It's read-only against the source the whole way through. Every file it collects is SHA-256 hashed, every action is written to an audit log, and it never modifies the original artifacts.

## How it's built

The shell is a small Tauri (Rust) app, which keeps the binary around 10 MB — small enough to live on a pendrive. It doesn't do any parsing itself; instead it launches a Python "sidecar" process and talks to it with JSON over stdio. All the forensic heavy lifting happens in Python, where the library ecosystem for this stuff (`dissect.target`, `regipy`, and friends) is far stronger than in Rust.

```
  Tauri shell (Rust, UI host)
        |  JSON over stdio
  Python sidecar
    ├── collectors/   read artifacts off a live disk / image
    ├── parsers/      turn each artifact into normalized events
    ├── rules/        YAML detection rules, MITRE-mapped
    └── core/         SQLite event store, timeline, rule engine, reports
```

The frontend is React + TypeScript (Vite, Tailwind, TanStack Table, ECharts for the timeline). Events live in a SQLite store. Adding support for a new artifact is meant to be just a new collector plus a new parser — everything downstream (UI, search, rules, reports) is artifact-agnostic because it all speaks the same event schema.

Design docs are under [`docs/`](docs/) — the architecture, the event schema, the detection-rule format, and the phase roadmap.

## Running it

You'll need Rust, Node, and Python 3.11+.

```bash
# Python side
python -m venv .venv
.venv/Scripts/pip install -e .[dev]     # Windows; use .venv/bin/pip on macOS/Linux
pytest                                   # run the test suite

# App (dev mode)
cd ui
npm install
npm run tauri dev
```

To produce the portable, no-install build (a folder you can drop on a USB drive and double-click `app.exe`):

```powershell
pwsh -File tools/build-portable.ps1      # output lands in dist/portable/
```

From there: **Open hive…** parses a single registry hive, **Open directory…** triages a folder of collected artifacts, and **Collect live…** reads straight off a running system or a disk image (live physical-drive access needs Administrator; parsing a hive or an image doesn't).

## Scope and status

This is Phase 1, which is Windows. macOS and Linux modules are on the roadmap but not built yet. It's a *triage* tool by design — the goal is to get oriented fast, not to replace the specialist tools. It doesn't do disk imaging (use FTK Imager), memory analysis (Volatility), or network captures (Wireshark); ask it for those and it points you at the right tool instead.

A few honest limits on the deleted-file side, which the report also states:

- No carving. If a deleted file's clusters were reused, its content is gone; the tool reports that the file existed, not what was in it.
- The USN journal has a finite retention window (commonly days to weeks). Older deletions survive only as `$MFT` bounds, or not at all.
- An unallocated `$MFT` record gives a *last existed by* time (its last `$STANDARD_INFORMATION` change), not a deletion time. Those rows are shown with a `≤` prefix.
- Only the Recycle Bin names the deleter directly. For USN and `$MFT` deletions the "who" is inferred from the interactive logon sessions (Security 4624/4634/4647) that cover the deletion time, so a service or scheduled task running as another account during a user's session will be attributed to that user. The confidence label and reason text say exactly what the inference rests on; a `likely` is an inference, not an observation.
- The ghost-reference check needs the volume itself (a live disk, an image, or a complete directory mirror of `C:\`); a folder holding only collected artifacts is skipped rather than guessed at, so nothing is reported missing by mistake.

It's been developed and tested against my own machine's artifacts and public training images (the SANS "Wes Mantooth" Vista image, among others). Some of the more interesting bugs came from that older Vista data — its registry stores USB history in a layout a common library choked on, and its IE history is the pre-IE10 `index.dat` format rather than the modern one — so the parsers had to be made a good bit more defensive than the happy-path versions.

## Tech notes

- Python: type-hinted, `ruff` for linting, `pytest` for tests (200+ covering parsers, rules, and the sidecar ops).
- No writes to source artifacts; SHA-256 on everything collected; full audit trail.
- Detection rules are YAML, and every rule maps to at least one MITRE ATT&CK technique.

## License

This project's own code is released under the [MIT License](LICENSE).

It depends on third-party libraries with their own terms, which apply to any build that bundles them (the portable `dft-sidecar` folder does):

| Library | License | Used for |
|---|---|---|
| `dissect.target` and the other `dissect.*` packages (Fox-IT / NCC Group) | AGPL-3.0-or-later | live disk and image access, NTFS, ESE databases |
| `libscca-python`, `libmsiecf-python`, `libfwsi-python` (libyal) | LGPL-3.0-or-later | Prefetch, legacy IE `index.dat`, shell items |
| `python-evtx` | Apache-2.0 | Windows event logs |
| `regipy`, `LnkParse3`, `PyYAML` | MIT | registry plugins, LNK files, rules |
| `olefile` | BSD | JumpList OLE containers |
| Tauri, React, ECharts and the rest of the UI stack | MIT / Apache-2.0 | desktop shell and interface |

The AGPL is the one to be aware of: a distributed build that includes `dissect.target` must make its complete corresponding source available under AGPL terms. This repository already satisfies that for the builds it produces. If you fork the project into something closed-source, swap out or isolate the `dissect` dependency first.
