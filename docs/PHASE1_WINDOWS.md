# Phase 1 — Windows

## Artifacts and parser libraries

| Artifact | Source path (typical) | Parser library |
|---|---|---|
| SYSTEM hive | `C:\Windows\System32\config\SYSTEM` | `dissect.target`, `regipy`, `python-registry` |
| SOFTWARE hive | `C:\Windows\System32\config\SOFTWARE` | same |
| SAM hive | `C:\Windows\System32\config\SAM` | same |
| SECURITY hive | `C:\Windows\System32\config\SECURITY` | same |
| NTUSER.DAT (per user) | `C:\Users\<user>\NTUSER.DAT` | same |
| UsrClass.dat (per user) | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | same |
| AmCache.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | `regipy`, `dissect.target` |
| ShimCache | embedded in `SYSTEM` (AppCompatCache key) | `regipy.plugins.shimcache` |
| Event logs | `C:\Windows\System32\winevt\Logs\*.evtx` | `python-evtx`, `Evtx`, `dissect.eventlog` |
| Prefetch | `C:\Windows\Prefetch\*.pf` | `dissect.target.plugins.os.windows.prefetch` |
| LNK files | various (Recent, Desktop, etc.) | `LnkParse3`, `dissect.target` |
| JumpLists | `%APPDATA%\Microsoft\Windows\Recent\(Automatic\|Custom)Destinations\` | custom parser / `dissect.target` |
| USB history (setupapi log) | `C:\Windows\INF\setupapi.dev.log` | custom text parser |
| Chrome History | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (SQLite) | stdlib `sqlite3` |
| Edge History | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` (SQLite) | stdlib `sqlite3` |
| Firefox history | `%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite` (SQLite) | stdlib `sqlite3` |
| IE / legacy-Edge history+downloads (IE10+) | `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat` (ESE) | `dissect.database.ese` |
| IE history/cache (legacy, IE5–9 / Vista) | `...\History\History.IE5\index.dat`, `...\Content.IE5\index.dat`, `...\Cookies\index.dat` (MSIE Cache File) | `pymsiecf` (libmsiecf) |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\$I*` ($I metadata records) | custom parser (struct) |

## Collection strategy

**Locked files**: SYSTEM, SOFTWARE, SAM, NTUSER, UsrClass, AmCache, and live event logs are locked by the OS while running. Two acceptable approaches:

1. **VSS snapshot**: create a Volume Shadow Copy via `vssadmin` or the Win32 VSS API, mount it, read files from the snapshot. Requires admin.
2. **Raw NTFS read via `dissect.target`**: Fox-IT's `dissect.target` can read NTFS volumes at the file-system layer, bypassing OS locks. Works on a live raw `\\.\PhysicalDrive0` if running as admin.

**Our default**: approach 2 (dissect.target on `\\.\PhysicalDriveN`), with VSS as a fallback on older Windows or if raw disk access fails.

**Dev workflow**: work against extracted hive files in `test_data/personal/` (gitignored). `dissect.target` also reads disk images (E01, raw `dd`) — useful for testing against public corpora.

## Test data plan

- **Your own hives**: dump from your machine into `test_data/personal/` after copying via shadow copy or after boot from a separate USB
- **Public DFIR test images**: Digital Corpora, NIST CFReDS, the SANS Hacking Case
- **Synthetic**: write a script that produces a tiny hive with known artifacts for deterministic rule testing

## Milestones

### M1 — Project scaffold + IPC plumbing

- Tauri shell project initialized
- Python sidecar that exchanges JSON over stdio with the shell
- Smoke test: shell sends `{"op": "ping"}` → sidecar responds `{"ok": true}`
- React UI shell with empty table and a "Run triage" button (no-op for now)
- Build pipeline: `npm run dev`, `npm run tauri build`

### M2 — First artifact end-to-end: SYSTEM hive

- Collector reads a SYSTEM hive file (path provided by user for now; live disk access in M9+)
- Parser emits events for: ComputerName, TimeZoneInformation, USBSTOR entries, Services list, ShimCache
- Store: SQLite event store with `events` table matching the schema
- UI: table view with column filter, sort, detail pane (clicking a row shows the `raw` JSON)
- Verify: dump your own SYSTEM hive, run end-to-end, see USB history populate

### M3 — Remaining registry hives

- Parsers for: SOFTWARE, SAM, NTUSER, UsrClass, AmCache
- Per-user hive discovery (walk `C:\Users\*\`)
- UI: artifact-type filter chips above the table

### M4 — Event Logs

- `.evtx` parser
- Focus channels:
  - Security: 4624 (logon success), 4625 (logon failure), 4634 (logoff), 4672 (special privileges), 4720 (account create), 4732 (member added to local group), 1102 (log cleared)
  - System: 7045 (service installed), 7036 (service state change)
  - `Microsoft-Windows-PowerShell/Operational`: 4104 (script block logging)
  - `Microsoft-Windows-TaskScheduler/Operational`: 106/140/141 (task registered/updated/deleted)

### M5 — Prefetch + AmCache + ShimCache execution evidence

- Three parsers emitting `program_execution` events
- A "Program Execution" composite view: union of the three, deduplicated by program path
- This is the first time the user sees real cross-source correlation

### M6 — Timeline view

- Apache ECharts timeline component
- Multi-track (one track per `source_artifact`, configurable grouping)
- Zoomable, filterable, click event → detail pane
- Performance target: smooth pan/zoom at 100k events

### M7 — Rule engine + initial rule set

- YAML rule loader (`core/rules.py`)
- Rule evaluator running over event store
- 30+ initial rules across MITRE tactics (see [DETECTIONS.md](DETECTIONS.md))
- Findings panel showing rule_id, title, severity, MITRE technique chips, evidence event preview
- Click a finding → jump to evidence event in the table

### M8 — LNK + JumpList + USB history correlation

- Parsers for LNK files, automatic/custom destinations JumpLists
- USB history view: per device, first-seen, last-seen, drive letter, user
- "What did this user do on date X?" canned query — surfaces LNK opens, JumpList entries, browser visits, program executions in a single timeline

### M9 — Browser artifacts

- Chrome and Edge History DB parsers (SQLite)
- Events: `browser_visit`, `browser_download`, `browser_search`

### M10 — Detail panes per artifact type

- Per-type rendering (registry value vs evtx record vs Prefetch run history)
- Optional hex view for raw bytes

### M11 — Report generation

- HTML report with: case header, findings summary, MITRE heat-map, timeline image, per-artifact section
- PDF export via headless Chromium

### M12 — Live disk collection (the "plug in pendrive" workflow)

- OS detection on boot
- Confirmation screen: "I detect Windows 11 — proceed?"
- UAC elevation request
- Raw disk read via `dissect.target` against `\\.\PhysicalDriveN`
- Collection progress UI (per-artifact status)
- All collected artifacts hashed (SHA-256) and logged to the audit trail

### M13 — Polish + packaging

- Authenticode signing if code-signing cert available
- Installer / portable zip layout
- Onboarding flow
- Portfolio screenshots and a 60-second demo recording

## Out of scope reminder

- E01/Ex01 imaging — use FTK Imager
- Memory analysis — use Volatility
- Network captures — use Wireshark / Zeek

If the user asks for these, point them at the right tool. This project is **artifact triage**, not full-disk acquisition.
