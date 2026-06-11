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

## Distribution

Each OS gets its own signed binary on the USB:

- Windows: signed `.exe` (Authenticode)
- macOS: signed + notarized `.app` in a `.dmg` (Developer ID, not App Store — sandbox forbids Full Disk Access)
- Linux: signed `.AppImage`

## License

TBD.
