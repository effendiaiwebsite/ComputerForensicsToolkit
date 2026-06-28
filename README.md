# Digital Forensics Triage Toolkit

A portable, cross-platform forensic triage tool that runs from a USB drive. Collects and parses host forensic artifacts, then presents them with dense examiner-grade tables, a timeline view, relationship graphs, and automated suspicious-activity flagging mapped to MITRE ATT&CK.

> **Status**: In active development. Phase 1 (Windows) underway.

## What it does

- **Collects** forensic artifacts from a live host: registry hives, event logs, prefetch, AmCache, ShimCache, USB device history, LNK files, JumpLists, browser history.
- **Parses** each artifact into a unified normalized event schema.
- **Flags** suspicious activity using explainable YAML rules mapped to MITRE ATT&CK techniques.
- **Presents** events in three complementary views:
  - **Artifact tables** — filterable, sortable, virtualized for 100k+ rows
  - **Timeline** — multi-track, zoomable, multi-source correlation
  - **Relationship graphs** — users ↔ devices ↔ processes ↔ time
- **Reports** — exportable HTML / PDF for case files.

## Roadmap

- **Phase 1** — Windows artifact triage *(in progress)*
- **Phase 2** — macOS module (KnowledgeC, unified logs, plists, FSEvents, TCC)
- **Phase 3** — Linux module (journald, auth.log, shell histories, systemd persistence)

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestone detail.

## Architecture at a glance

```
       +----------------+
       |  Tauri Shell   |    Rust, ~10MB
       +-------+--------+
               | JSON over stdio
       +-------v--------+
       | Python Sidecar |    Parsing + rules
       +-------+--------+
       |       |        |
+------v+ +----v---+ +--v-----+
|Collect| |Parsers | |Rule    |
|ors    | |        | |Engine  |
+-------+ +--------+ +--------+
               |
        +------v-------+
        | SQLite Event |
        |    Store     |
        +------+-------+
               |
       +-------v--------+
       | Tauri Webview  |
       | React + shadcn |
       +----------------+
```

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Design principles

- **Explainable detections** — rule-based, no ML. Every finding cites a YAML rule and ATT&CK technique.
- **Information density first** — examiners scan thousands of rows; pretty-but-sparse loses to dense-and-fast.
- **Forensic soundness** — no writes to source; SHA-256 logged for every collected artifact; full audit log of operations.
- **OS detection + explicit consent** — boot screen confirms target OS and requests elevation; no silent privilege escalation.

## Quickstart (developers)

```powershell
git clone <this-repo>
cd DigitalForensicsToolkit

# 1. Python sidecar
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"

# 2. UI dependencies
cd ui ; npm install ; cd ..

# 3. Run
cd ui ; npm run tauri dev
```

Pytest: `.venv/Scripts/python -m pytest -q` (currently 148 cases).

## Portable build (USB-ready)

```powershell
# Produces dist/portable/ — drop the folder onto a USB drive.
pwsh -File tools/build-portable.ps1
```

The portable layout:

```
portable/
  app.exe              Tauri shell, launches on double-click
  dft-sidecar/         PyInstaller-bundled parsing core (~80 MB)
    dft-sidecar.exe
    _internal/         Python runtime + DLLs + rules/
  README.txt           quickstart for the recipient
```

No Python, Node, or Tauri SDK is required on the target machine. Live disk
collection still needs administrator privileges on the host — the app shows
an in-UI banner when running unelevated.

### Heads-up: antivirus and PyInstaller

PyInstaller-bundled EXEs trip heuristic AV scanners (Norton, Defender,
Bitdefender) because the bootloader unpacks a Python interpreter at runtime —
structurally identical to malware packing. The `dist/` and `build/` directories
should be whitelisted before running `tools/build-portable.ps1`, or the AV will
quarantine `dft-sidecar.exe` mid-write and break the build.

For the final USB drop the recipient will see the same SmartScreen warning;
click *More info → Run anyway*. Authenticode signing would silence both
warnings but requires a code-signing certificate, which is out of scope for
the portfolio build.

## Workflows

| Workflow | What it does | Admin? |
|---|---|---|
| **Open hive** | Parse one registry hive (SYSTEM/NTUSER/AmCache/etc.) or browser History DB | No |
| **Open directory** | Walk a folder of mirrored Windows artifacts and ingest everything found | No |
| **Collect live** | Read straight off this system's mounted volumes via `dissect.target`, mirror + hash + audit everything, auto-ingest | **Yes** |
| **Generate report** | Self-contained HTML (case header + MITRE heat-map + SVG timeline + findings + per-artifact section) | No |

Phase 1 covers: registry (SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/UsrClass/AmCache),
event logs (.evtx), Prefetch, ShimCache, AmCache execution evidence, LNK,
JumpLists, Chrome/Edge/Brave History. 17 MITRE-mapped YAML rules ship in
`rules/`; the engine evaluates them automatically after every triage.

## Distribution

Each OS gets its own binary on the USB:

- Windows: portable `app.exe` + `dft-sidecar/` folder (this milestone)
- macOS (Phase 2): signed + notarized `.app` in a `.dmg`
- Linux (Phase 3): `.AppImage`

Windows SmartScreen will warn on first launch since the build isn't
Authenticode-signed — click *More info → Run anyway*. Signing requires a
code-signing certificate which is out of scope for the portfolio build.

## License

TBD.
