# Roadmap

Three phases. Ship each one fully before starting the next.

## Phase 1 — Windows (current)

Goal: a polished, demo-ready Windows artifact triage tool.

**Artifacts in scope:**
- Registry hives: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat
- Windows Event Logs (Security, System, Application, key sub-channels)
- Prefetch (`.pf` files)
- AmCache (`Amcache.hve`)
- ShimCache (embedded in SYSTEM)
- LNK files and JumpLists
- USB device history (registry + `setupapi.dev.log`)
- Browser artifacts: Chrome and Edge History DB

**Out of scope for Phase 1** (move to Phase 1.5 if time permits):
- `$MFT`, USN journal, `$LogFile` (huge, complex — but `dissect.target` makes them feasible)
- SRUM (System Resource Usage Monitor)
- Memory artifacts

**Milestones** — see [PHASE1_WINDOWS.md](PHASE1_WINDOWS.md) for detail.

## Phase 2 — macOS

Goal: equivalent triage for macOS hosts.

**Artifacts in scope:**
- Unified logs (`.tracev3` files / `logarchive`)
- LaunchAgents / LaunchDaemons plists (system + per-user)
- KnowledgeC.db
- Spotlight metadata
- FSEvents
- Quarantine database (`QuarantineEventsV2`)
- TCC.db (privacy permissions — reveals what apps were granted what)
- Shell histories (bash, zsh)
- Browser artifacts (Safari, Chrome)
- Recent items plists, `sfl` / `sfl2` files
- Persistence equivalents: LaunchAgents, LaunchDaemons, login items, cron, periodic scripts

**Why this is the portfolio differentiator**: macOS DFIR has fewer experts and weaker commercial tooling than Windows. A working macOS module is the moment this project becomes a *story* in interviews.

**Distribution**: signed + notarized `.dmg` (Developer ID), NOT via Mac App Store — sandbox forbids Full Disk Access.

## Phase 3 — Linux

Goal: equivalent triage for Linux hosts.

**Artifacts in scope:**
- journald binary logs
- `/var/log`: `auth.log`, `syslog`, `wtmp`, `btmp`, `lastlog`, `secure`
- Shell histories (bash, zsh, fish)
- systemd unit files (persistence equivalent)
- Crontabs (`/var/spool/cron`, `/etc/cron.*`)
- `/etc`: `passwd`, `shadow`, `sudoers`, `group`
- `recently-used.xbel`
- Browser artifacts
- Audit logs (if `auditd` configured)

## Cross-cutting work (any phase)

- OS auto-detect + confirmation screen on boot
- Per-OS elevation prompt
- Report generator (HTML + PDF)
- Audit log of all collection and analysis operations
- Hashing every collected artifact
- Tagging, bookmarking, examiner notes
- Case file save/load
- Portfolio-ready screenshots and demo recordings
