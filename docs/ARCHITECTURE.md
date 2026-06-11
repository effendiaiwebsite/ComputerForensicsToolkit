# Architecture

## Component diagram

```
+----------------------+
|    Tauri Shell       |   Rust binary, ~10MB
|  (window, dialogs,   |
|   elevation, USB     |
|   enumeration)       |
+----------+-----------+
           |
           |  spawns + IPC (JSON over stdio)
           |
+----------v-----------+
|   Python Sidecar     |   Bundled via PyInstaller, ~30MB
|   (parsing core)     |
+----------+-----------+
           |
   +-------+-------+-------+--------+
   |               |       |        |
+--v------+   +----v---+ +-v----+ +-v-----+
|Collec-  |   |Parsers | |Rules | |Event  |
|tors     |   |        | |Engine| |Store  |
|(per OS) |   |        | |      | |(SQLite)|
+----+----+   +---+----+ +--+---+ +---+---+
     |            |         |         |
     | reads      | reads   | queries | queries
     v            v         v         v
+----------+  raw bytes  events   findings
|  Host    |
|  System  |
+----------+

+----------------------+
|   Tauri WebView      |   Vite + React + TS, shadcn/ui
|   UI                 |   - Artifact tables (TanStack Table)
|                      |   - Timeline (Apache ECharts)
|                      |   - Graphs (react-flow)
|                      |   - Detail panes, tagging, reports
+----------------------+
```

## Data flow

1. **Boot**: Tauri shell starts. Detects host OS, displays confirmation screen ("I detect this is Windows — is this correct?").
2. **Elevation**: User clicks **Begin Triage**. Shell requests OS-appropriate elevation:
   - Windows: UAC prompt (`runas` / manifest `requireAdministrator`)
   - macOS: Full Disk Access permission grant via System Settings
   - Linux: `pkexec` / `sudo` prompt
3. **Collection**: The active OS collector reads target artifacts. SHA-256 recorded for each, source paths logged. Output is a `CollectionBundle` — a directory of raw artifact files plus a manifest JSON.
4. **Parsing**: Each parser consumes raw bytes for its artifact type and emits a stream of normalized `Event` objects.
5. **Storage**: Events written to SQLite (in-memory for live triage, optional on-disk for case files).
6. **Detection**: Rule engine evaluates each rule against the event store. Matches become `Finding` records (rule_id, evidence event_ids, MITRE techniques, severity).
7. **Presentation**: UI queries event + findings stores via the Python sidecar's IPC interface.

## Module responsibilities

### `collectors/`

Per-OS modules. Their job is to know **where** artifacts live and how to read them safely.

- `collectors/windows/` — VSS or raw NTFS (via `dissect.target`) to read locked hives, event logs, etc.
- `collectors/macos/` — relies on Full Disk Access; reads `.tracev3`, plists, sqlite DBs directly.
- `collectors/linux/` — root access; reads `/var/log`, `/etc`, journald binaries.

Output: a `CollectionBundle` directory with raw artifact files + `manifest.json` containing source paths, SHA-256, timestamps.

### `parsers/`

Per-artifact modules. Each takes raw bytes for one artifact type and yields `Event` objects. **Parsers are OS-agnostic** — a parser for the Windows registry hive doesn't care that the collector ran on Windows. This is what makes the architecture pluggable.

Examples:
- `parsers/registry_hive.py` — SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/UsrClass
- `parsers/amcache.py`
- `parsers/evtx.py`
- `parsers/prefetch.py`
- `parsers/lnk.py`
- `parsers/chrome_history.py`

### `core/`

- `core/events.py` — `Event` dataclass, validation, schema versioning
- `core/store.py` — SQLite-backed event + findings store
- `core/rules.py` — YAML rule loader, rule evaluator (matches event fields against rule predicates)
- `core/timeline.py` — timeline aggregation queries (binning, multi-track grouping)
- `core/reports.py` — HTML + PDF report generation
- `core/ipc.py` — stdio JSON protocol with Tauri shell

### `rules/`

YAML files, one rule per file. Organized by MITRE tactic:

```
rules/
  persistence/
    registry_run_key_appdata.yml
    ifeo_debugger_set.yml
  defense_evasion/
    defender_disabled_via_registry.yml
    event_log_cleared.yml
  execution/
    lolbin_in_amcache.yml
  ...
```

### `ui/`

Vite + React + TypeScript app served from the Tauri webview. Talks to the Python sidecar via Tauri's IPC bridge (`invoke('query', { ... })` → Tauri shell → Python stdin/stdout).

State via Zustand stores:
- `eventStore` — current filter, paged events, selected event
- `timelineStore` — zoom level, visible range, tracks
- `findingStore` — findings list, active finding
- `caseStore` — case metadata, tags, bookmarks, notes

## Why these tech choices

| Decision | Reasoning |
|---|---|
| Tauri over Electron | ~10MB vs ~150MB; faster startup; lower RAM; critical for pendrive use |
| Python sidecar over pure Rust | `dissect.target` (Fox-IT) covers registry, $MFT, USN, EVTX, ShellBags, AmCache in one library — replicating in Rust is months of work |
| PyInstaller bundling | Self-contained Python runtime per OS; no system Python dependency on target machines |
| SQLite event store | File-based, portable, queryable, no server; perfect fit for portable forensic tool |
| Rule-based detection | Court-defensible; explainable; auditable rule changes |
| MITRE ATT&CK mapping | Industry standard; differentiator for portfolio review |
| shadcn/ui + Tailwind | Free, AI-friendly, owned components, no runtime dependency on a UI vendor |
| TanStack Table | Battle-tested for very large tables; built-in virtualization, column resizing, multi-sort |
| Apache ECharts | Best free option for dense timelines with millions of points |
| react-flow | Cleanest React API for graph visualizations |
| Zustand | Minimal boilerplate; fits a moderately complex desktop app well |

## Cross-platform extension plan

The architecture is built so that adding a new OS requires only:

1. A new `collectors/<os>/` module that produces a `CollectionBundle`
2. New `parsers/<artifact>.py` for any OS-specific artifact types (e.g. `parsers/macos_unified_log.py`)
3. New rules under `rules/` referencing those new artifacts
4. Possibly UI-side detail-pane components for new artifact types

The event schema, store, rule engine, timeline view, and graphs are OS-agnostic.

## Out of scope (deliberate)

- Full disk imaging (E01/Ex01) — FTK Imager is free and trusted; no value in re-implementing
- Memory forensics — Volatility/Rekall exist; orthogonal scope
- Network forensics — different tool category entirely
- Mobile forensics — different tool category, different artifacts
