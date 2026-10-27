# DFT UI

Desktop front end for the Digital Forensics Triage Toolkit: a Tauri 2 (Rust) shell hosting a Vite + React 19 + TypeScript app (Tailwind 4, shadcn-style components, TanStack Table, Apache ECharts).

## Commands

```bash
npm install
npm run tauri dev     # dev build: Vite on :5173 inside the Tauri window
npm run build         # tsc -b && vite build
npx eslint .          # lint
cd src-tauri && cargo check --quiet
```

The portable, no-install build is produced by `tools/build-portable.ps1` at the repo root (`bundle.active` is off; the build only yields `app.exe`).

## Sidecar

All parsing runs in the Python sidecar (`core/`). `src-tauri/src/sidecar.rs` spawns it once (`dft-sidecar/dft-sidecar.exe` next to the app, or `.venv` Python with `-m core` from the source tree; override with `DFT_SIDECAR_PYTHON` / `DFT_SIDECAR_CWD`) and talks JSON lines over stdio: one request per line with a `request_id`, one response per line echoing it. Replies with a foreign or missing `request_id` are skipped; a dead or unresponsive sidecar (`DFT_SIDECAR_TIMEOUT_SECS`, default 600) is killed and respawned on the next call. Release builds write the sidecar's stderr to `dft-sidecar.log` next to the exe. Each Tauri command in `src-tauri/src/lib.rs` wraps one sidecar op; `src/lib/dft.ts` is the typed client.

## Layout

- `src/App.tsx` — state, view switching, modals (live collection, report)
- `src/components/` — `DetailPane`, `FilesBrowser`, `Timeline`, `BusyDayStrip`, `Welcome`, `ui/` (shadcn primitives)
- `src/lib/dft.ts` — sidecar op wrappers and result types
- `src-tauri/` — Rust shell: `lib.rs` (commands), `sidecar.rs` (process + protocol), `elevation.rs`, `tauri.conf.json` (CSP, window)
