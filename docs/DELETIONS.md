# Deleted-file detection and attribution

Goal: answer **who deleted what, and when** from a Windows image or live host,
without carving, with an honest confidence label on every attribution.

Three evidence sources feed one view:

| Source | What it proves | Deletion time | Actor evidence |
|---|---|---|---|
| Recycle Bin `$I` records | file sent to the bin | exact | the `$Recycle.Bin\<SID>` folder owner = the deleter (**direct**) |
| USN change journal (`$Extend\$UsnJrnl:$J`) | every create/rename/delete on the volume, including Shift+Delete and programmatic deletes | exact | `SecurityId` → owner SID via `$Secure`; logon session overlap (**inferred**) |
| `$MFT` unallocated records | a file existed and its record is now free | bounded by the last `$STANDARD_INFORMATION` change time | owner SID via `$Secure`; logon session overlap (**inferred**) |

Everything is rule-based and explainable: the attribution engine records *why*
it named a user, and the UI shows that reason next to the name.

## Event contract (parsers emit, core consumes)

All three sources emit `file_delete` events (schema in EVENT_SCHEMA.md).
USN also emits `file_create` and `file_rename`. Evidence keys below are the
contract between parsers and `core/deletions.py`; keep them exact.

Common `evidence` keys for `file_delete`:

| key | type | notes |
|---|---|---|
| `original_path` | str | full path as it existed, Windows form (`C:\Users\...`) when a drive letter is known, else `\<volume>\...` |
| `deleted_name` | str | basename |
| `deleted_size` | int or null | bytes |
| `deletion_method` | str | `recycle_bin` \| `usn_journal` \| `mft_unallocated` |
| `owner_sid` | str or null | from `$Secure` (USN/MFT) or the bin folder (Recycle Bin: this is the *deleter*, also copied to `actor_sid`) |
| `actor_sid` | str or null | only when the artifact itself names the deleter (Recycle Bin) |
| `security_id` | int or null | raw NTFS security id (USN/MFT) |
| `mft_segment` | int or null | MFT record number |
| `is_directory` | bool | |
| `recoverable_hint` | str | `recycle_bin_blob` (an `$R` sibling exists) \| `data_runs_present` (MFT record still lists clusters) \| `resident` (data was inside the MFT record) \| `unknown` |
| `usn` | int or null | USN journal only |
| `usn_reason` | list[str] or null | USN only, decoded reason flags e.g. `["FILE_DELETE","CLOSE"]` |
| `last_known_modified` / `last_known_created` | ISO Z or null | MFT only; from `$STANDARD_INFORMATION` |

`timestamp_source`: `direct` for Recycle Bin and USN; `inferred` for MFT (the
`$SI` last-change time is an upper bound on when the file last existed, not
the deletion time; say so in the summary).

`file_rename` evidence: `original_path`, `new_path` (when resolvable from the
paired USN records; else null), `usn`, `usn_reason`.
`file_create` evidence: `original_path`, `usn`, `usn_reason`.

Existing Recycle Bin parser must be updated to add `deletion_method`,
`actor_sid` (= its `sid`), `owner_sid` (= same), `is_directory` (false) and
`recoverable_hint`. Keep its existing keys.

## Parser signatures (parsers/, owned by the parser builder)

```python
# parsers/usnjrnl.py
def parse_usnjrnl(
    j_path: str,                     # extracted $J stream, raw bytes
    *,
    collection_id: str,
    host_id_hint: str,
    mft_path: str | None = None,     # extracted $MFT for path resolution
    sds_path: str | None = None,     # extracted $Secure:$SDS for owner SIDs
    drive_letter: str = "C:",
    include_creates: bool = False,   # file_create is noisy; default off
    include_renames: bool = True,
) -> list[Event]

# parsers/mft.py
def parse_mft_deleted(
    mft_path: str,
    *,
    collection_id: str,
    host_id_hint: str,
    sds_path: str | None = None,
    drive_letter: str = "C:",
) -> list[Event]       # one file_delete per unallocated record that still has a $FILE_NAME

# both modules also expose a target-based variant used by live collection:
def parse_usnjrnl_from_target(target, fs_index: int, **same_kwargs) -> list[Event]
def parse_mft_deleted_from_target(target, fs_index: int, **same_kwargs) -> list[Event]
```

Use `dissect.ntfs` (`UsnJrnl`, `Mft`, `MftRecord`, `Secure`) directly; the
`dissect.target` `usnjrnl`/`mft` plugins and
`dissect.target.plugins.filesystem.ntfs.utils.get_owner_and_group` show how
owner SIDs are resolved. When `mft_path` is absent, USN paths fall back to the
record's own filename with parent `<unresolved>`; never crash.

## Collectors (collectors/windows/, owned by the parser builder)

```python
# collectors/windows/ntfs_meta.py
@dataclass
class NtfsMetaArtifacts:
    mft_path: str | None
    usnjrnl_path: str | None
    sds_path: str | None
    drive_letter: str
    errors: list[str]

def collect_ntfs_meta(target, dest_dir: Path, *, audit, fs_index: int | None = None) -> NtfsMetaArtifacts
```

Copies `$MFT`, `$Extend/$UsnJrnl:$J` and `$Secure:$SDS` from the Windows
volume of an open dissect target into `dest_dir/ntfs/` with SHA-256 audit
records (same `audit.ok(...)` pattern as `live_disk.py`). `live_disk.collect_live`
calls it after the existing artifact loop and reports the three files in its
result under `ntfs_meta`. The directory-triage classifier
(`user_hives._classify`) must recognise basenames `$MFT`, `$J`, `$UsnJrnl$J`,
`$UsnJrnl_$J`, `$SDS`, `$Secure_$SDS` as kinds `mft`, `usnjrnl`, `sds`.

## Core (core/, rules/, docs/, owned by the core builder)

### Store

New table `deletions` (rebuilt by `build_deletions`, never hand-edited):

```
deletion_id TEXT PK, collection_id, event_id (FK to the file_delete event),
deleted_at TEXT (ISO Z or null), time_basis TEXT ('exact'|'upper_bound'),
path TEXT, name TEXT, size INTEGER, is_directory INTEGER,
method TEXT ('recycle_bin'|'usn_journal'|'mft_unallocated'),
owner_sid TEXT, owner_user TEXT,
actor_user TEXT, actor_sid TEXT,
actor_confidence TEXT ('direct'|'likely'|'ambiguous'|'unknown'),
actor_reason TEXT (human sentence),
recoverable_hint TEXT, source_path TEXT
```

Indexes on (collection_id, deleted_at), (collection_id, actor_user), (collection_id, method).

### Attribution engine: `core/deletions.py`

```python
def build_deletions(store, collection_id: str) -> DeletionsSummary
```

1. Load all `file_delete` events for the collection.
2. **Dedup across sources**: a Recycle Bin record and a USN `FILE_DELETE` for
   the same `$R...` blob, or USN and MFT entries for the same `mft_segment`,
   collapse into one row; keep the most precise `deleted_at` and the strongest
   actor evidence; list the other methods in `actor_reason`.
3. **SID → user**: build a map from `account_change`/`system_config_change`
   events whose evidence has `sid` + `username` (SAM parser) or `sid` +
   `profile_path` (ProfileList parser, derive the username from the last path
   segment). Well-known SIDs (S-1-5-18 SYSTEM, S-1-5-19, S-1-5-20, S-1-5-32-544
   Administrators) map to their names.
4. **Actor**:
   - Recycle Bin: `actor_sid` given → `direct`, reason "file was in this user's Recycle Bin folder".
   - Otherwise find interactive logon sessions from `logon`/`logoff` events
     (Security 4624 types 2, 7, 10, 11 open a session for `TargetUserName`;
     4634/4647 for the same user close it; an unclosed session stays open to
     the end of the data). Sessions overlapping `deleted_at` ± 0 s:
     exactly one user → `likely`, reason names the session and the logon time;
     several → `ambiguous`, reason lists them; none → `unknown`.
   - If `owner_sid` resolves to a user, include "file owner: X" in the reason;
     when the owner equals the single session user, keep `likely`.
   - MFT rows (time is an upper bound) are never better than `ambiguous`
     unless the owner is a single interactive user, then `likely` with the bound stated.
5. **Bursts**: within one collection, ≥ 20 deletions by the same method inside
   any 120-second window emit one synthetic `file_delete_burst` event
   (`evidence`: `count`, `window_start`, `window_end`, `method`, `actor_user`,
   `sample_paths` (up to 10)) so a YAML rule can flag it.
6. Returns counts: total, by_method, by_actor_confidence, by_actor_user, bursts.

Run automatically at the end of `run_triage_directory`, `run_triage_hive` (when
a bin/USN/MFT artifact was ingested) and the live-collection worker, before
`evaluate_rules`.

### Ghost references: `core/ghosts.py`

```python
def annotate_missing_references(store, collection_id: str, root) -> int
```

`root` is a path-exists callable (`lambda win_path: bool`) built by the caller
from either the image browser root (dissect fs) or the triage directory. For
events of type `file_access` (LNK, JumpList, RecentDocs), `program_execution`
(Prefetch, ShimCache, AmCache, UserAssist) with a resolvable Windows path in
`evidence.target_path` / `evidence.program_path`, check existence on the
volume and set `evidence.referenced_path_exists` to true/false (update the
stored event). Skip paths on removable or network drives (not `C:`-like or
UNC), and skip when no root is available. Returns the number annotated.

### Rules (YAML + fixtures under tests/rules/)

- `defense_evasion/anti-forensic-tool-executed.yml` — `program_execution`
  whose program name matches sdelete, sdelete64, eraser, eraserl, ccleaner,
  ccleaner64, bleachbit, bleachbit_console, cipher (medium), privazer, wipefile,
  shred. Techniques T1070.004, T1485. Severity high (cipher: keep in list, note in description).
- `defense_evasion/referenced-file-missing.yml` — `evidence.referenced_path_exists == false`
  on `program_execution`/`file_access`. T1070.004. Severity medium.
- `impact/bulk-deletion.yml` — `event_type: file_delete_burst`. T1485. Severity high.
- `defense_evasion/usn-journal-deleted.yml` — `file_delete` whose
  `original_path` ends with `$UsnJrnl` or `$J` or program execution of
  `fsutil` (fsutil usn deletejournal). T1070.004. Severity high.

### Sidecar ops (register in `core/__main__.py`)

```
query_deletions
  request:  {collection_id, limit=500, offset=0, method?, actor_user?, actor_confidence?,
             path_contains?, sort_by='deleted_at'|'path'|'actor_user', sort_dir='desc'}
  response: {ok, deletions: [row...], total, by_method: {method: n},
             by_actor: [{actor_user, actor_confidence, count}], bursts: n}

build_deletions
  request:  {collection_id}
  response: {ok, total, by_method, by_actor_confidence, bursts}
```

Row = the `deletions` table columns, plus `event_id` so the UI can open the
underlying event in the detail pane. `is_directory` comes back as a JSON
boolean.

Implementation notes (core builder):

- `total` honours the request's filters (so paging works); `by_method`,
  `by_actor` and `bursts` always describe the whole collection, and the
  response also carries `total_unfiltered` for the tab badge.
- `query_deletions` also accepts `time_basis` (`exact` | `upper_bound`).
- `by_actor` is ordered by count desc, attributed users before the
  `actor_user = null` bucket.
- `build_deletions` returns `{ok, collection_id, total, by_method,
  by_actor_confidence, by_actor_user, bursts}`.
- The SID map also uses Security 4624 `TargetUserSid`/`TargetUserName`.
- Bursts are computed from exact-time rows only; MFT upper bounds cluster
  on last write, not on deletion, and would fabricate bursts.
- `file_delete_burst` events and `deletion_id`s are uuid5-stable across
  rebuilds so examiner statuses on burst findings survive re-evaluation.
- `run_triage_hive` also accepts a lone `$MFT` or `$J` (basenames `$MFT`,
  `$J`, `$UsnJrnl$J`, `$UsnJrnl_$J`); without siblings USN paths fall back
  to `<unresolved>` and owners stay null.
- Directory triage reports `deletions` (the summary above) and
  `ghost_annotated` in its result.
- Ghost pass in directory mode only runs when the folder is a *full* mirror
  of the volume (probe: `Windows\explorer.exe` or `Windows\System32\cmd.exe`
  present); inside it, a path whose parent folder is absent is left
  unannotated. The live worker checks the real volume (dissect root), not
  its sparse artifact mirror. Only `C:` paths are checked.

### Report

New section "Deleted files" after Findings: headline numbers (total, exact
vs upper-bound, by method), a "by user" table with confidence, a table of the
50 most recent deletions (time, path, method, user, confidence, recoverable
hint), and any bursts. Explain the confidence levels in one paragraph.

### Docs

Update `docs/EVENT_SCHEMA.md` (new evidence keys, `file_delete_burst`),
`docs/DETECTIONS.md` (new rules), `docs/PHASE1_WINDOWS.md` and `README.md`
(feature + honest limits: no carving, USN retention window, MFT time is a bound).

## UI (ui/, owned by the UI builder)

- `lib/dft.ts`: `Deletion` type (= row), `queryDeletions(args)` and
  `buildDeletions(args)` wrappers matching the op shapes above.
- New view `"deleted"` in `App.tsx` ViewMode and tab bar, labelled
  "Deleted files", with a count badge from `total`.
- `components/DeletedFiles.tsx`: TanStack table sorted by `deleted_at` desc;
  columns: time (with a small "≤" prefix when `time_basis` is `upper_bound`),
  path (monospace, truncated with full path in title), method chip, user with a
  confidence chip (direct = solid, likely = outlined, ambiguous = dashed,
  unknown = grey "—"), owner, size, recoverable hint. Filters: method,
  confidence, user, path contains. Clicking a row opens the underlying event
  in the existing DetailPane (fetch via the existing event query by id, or
  pass the event_id to the pane's loader).
- Summary strip above the table: total, by method, top three users.
- `DetailPane.tsx`: renderer for `file_delete` showing every evidence key in
  plain language, and for `file_delete_burst`.
- Welcome screen: one line mentioning deleted-file attribution.
- Keep `npx tsc -b` and `npx eslint .` clean.

## Honest limits (must appear in README and the report)

- No carving: content of files whose clusters were reused is not recovered.
- USN journal retention is finite (commonly days to weeks); older deletions
  only survive as MFT bounds or not at all.
- `$MFT` unallocated records give a *last existed by* time, not a deletion time.
- "Who" for USN/MFT deletions is inferred from who was logged on; a service or
  scheduled task running as another account can delete files during a user's
  session. The confidence label and reason say exactly what the inference rests on.
