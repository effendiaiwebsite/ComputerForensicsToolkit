# Event Schema

The normalized `Event` is the universal glue between collectors, parsers, the store, the rule engine, and the UI. **Every parsed artifact emits events conforming to this schema.** This is what makes the architecture OS-pluggable.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `event_id` | string (UUID) | yes | Internal unique identifier |
| `timestamp` | ISO 8601 UTC | nullable | Best-effort event time. `null` for events with no inherent time. |
| `timestamp_source` | enum | yes | `direct` (timestamp in artifact), `inferred` (derived from context), `none` |
| `host_os` | enum | yes | `windows`, `macos`, `linux` |
| `host_id` | string | yes | Identifier for the host (computer name, UUID, MAC) |
| `user` | string \| null | no | Associated user account, if applicable |
| `source_artifact` | string | yes | E.g. `registry.system`, `registry.ntuser`, `evtx.security`, `prefetch`, `amcache`, `lnk`, `chrome.history` |
| `source_path` | string | yes | Path on disk where the artifact was read from |
| `event_type` | string | yes | Normalized event type (see vocabulary below) |
| `summary` | string | yes | Human-readable one-liner for table display |
| `evidence` | object | yes | Structured artifact-specific fields the rule engine queries |
| `raw` | object | no | Decoded artifact-native fields, for the detail pane |
| `collection_id` | string | yes | Which `CollectionBundle` this event came from |
| `parser_version` | string | yes | Parser semver, for reproducibility |

## `event_type` vocabulary

Open vocabulary, extended as new artifacts are added. Initial set:

- `program_execution`
- `program_install`
- `usb_connection`
- `persistence_entry`
- `logon` / `logoff`
- `account_change`
- `file_access`
- `file_create` / `file_delete` / `file_rename`
- `network_connection`
- `registry_modification`
- `service_install`
- `scheduled_task`
- `browser_visit` / `browser_download` / `browser_search`
- `shell_command`
- `system_config_change`
- `security_event` (generic catch-all from event logs)

## Examples

### Program execution (from AmCache)

```json
{
  "event_id": "f3e2c4a8-9b1d-4e7f-b2c5-1a2b3c4d5e6f",
  "timestamp": "2026-06-08T14:23:11Z",
  "timestamp_source": "direct",
  "host_os": "windows",
  "host_id": "DESKTOP-ABC123",
  "user": "alice",
  "source_artifact": "registry.amcache",
  "source_path": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
  "event_type": "program_execution",
  "summary": "powershell.exe executed from %TEMP%",
  "evidence": {
    "program_path": "C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe",
    "sha1": "abc123def4567890...",
    "size_bytes": 451584,
    "product_name": "Microsoft Windows",
    "publisher": "Microsoft Corporation",
    "signed": false
  },
  "raw": { "...full AmCache record..." : "..." },
  "collection_id": "col-2026-06-08-001",
  "parser_version": "amcache/0.1.0"
}
```

### USB device connection (from SYSTEM hive)

```json
{
  "event_id": "...",
  "timestamp": "2026-06-07T19:42:30Z",
  "timestamp_source": "direct",
  "host_os": "windows",
  "host_id": "DESKTOP-ABC123",
  "user": null,
  "source_artifact": "registry.system",
  "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
  "event_type": "usb_connection",
  "summary": "USB mass storage connected: SanDisk Cruzer (SN 4C530001...)",
  "evidence": {
    "vendor": "SanDisk",
    "product": "Cruzer",
    "serial": "4C530001A6F4F1B5",
    "first_install": "2026-06-07T19:42:30Z",
    "last_connect": "2026-06-08T08:11:02Z",
    "drive_letter_hint": "E:"
  },
  "raw": { "...": "..." },
  "collection_id": "col-2026-06-08-001",
  "parser_version": "system_hive/0.1.0"
}
```

### Persistence entry (Run key)

```json
{
  "event_id": "...",
  "timestamp": null,
  "timestamp_source": "none",
  "host_os": "windows",
  "host_id": "DESKTOP-ABC123",
  "user": "alice",
  "source_artifact": "registry.ntuser",
  "source_path": "C:\\Users\\alice\\NTUSER.DAT",
  "event_type": "persistence_entry",
  "summary": "Run key: 'updater' = %APPDATA%\\Roaming\\svchost.exe",
  "evidence": {
    "key_name": "Run",
    "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "updater",
    "value_data": "C:\\Users\\alice\\AppData\\Roaming\\svchost.exe",
    "value_path": "C:\\Users\\alice\\AppData\\Roaming\\svchost.exe"
  },
  "raw": { "...": "..." },
  "collection_id": "col-2026-06-08-001",
  "parser_version": "ntuser_hive/0.1.0"
}
```

## Findings schema

The rule engine emits `Finding` records when rules match events:

```json
{
  "finding_id": "uuid",
  "rule_id": "persistence-run-key-appdata-001",
  "rule_title": "Run key entry pointing to user-writable location",
  "severity": "high",
  "mitre_techniques": ["T1547.001"],
  "mitre_tactics": ["persistence"],
  "evidence_event_ids": ["event-uuid-1", "event-uuid-2"],
  "created_at": "ISO 8601 UTC",
  "summary": "Run key 'updater' points to %APPDATA%\\Roaming\\svchost.exe",
  "examiner_status": "new" // new | reviewed | suppressed | confirmed_malicious | confirmed_benign
}
```

## Schema evolution

The `Event` schema is versioned. Each parser declares the schema version it targets. When the schema changes:

1. Bump the schema version constant
2. Provide a migration in `core/store.py` for stored events
3. Update parsers to emit the new version

For Phase 1 we lock to schema version `1`.
