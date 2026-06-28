# DFT portable build script (Windows).
#
# Produces a USB-ready folder at dist/portable/ containing everything needed
# to run DFT on a fresh Windows machine - no Python install, no Tauri SDK.
#
#   dist/portable/
#     app.exe                  Tauri shell (launches the sidecar, hosts UI)
#     dft-sidecar/             PyInstaller one-folder bundle
#       dft-sidecar.exe        Python interpreter + parsers + rules
#       _internal/             runtime + DLLs + rules/
#       ...
#     README.txt               quickstart for the recipient
#
# Drop the whole portable/ folder onto a USB drive, double-click app.exe.
# Live disk collection still needs administrator on the target machine.
#
# Usage:  pwsh -File tools/build-portable.ps1

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
Set-Location $repoRoot

$python = "$repoRoot/.venv/Scripts/python.exe"
if (-not (Test-Path $python)) {
    throw "Expected .venv at $python - run 'python -m venv .venv; .venv/Scripts/pip install -e .[dev]' first."
}

Write-Host "==> Building PyInstaller sidecar bundle..." -ForegroundColor Cyan
& $python -m PyInstaller build/dft-sidecar.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)" }

$sidecarExe = "$repoRoot/dist/dft-sidecar/dft-sidecar.exe"
if (-not (Test-Path $sidecarExe)) { throw "PyInstaller did not produce $sidecarExe" }

Write-Host "==> Smoke-testing sidecar (ping over stdio)..." -ForegroundColor Cyan
$pingJson = '{"op":"ping"}'
$resp = $pingJson | & $sidecarExe
if ($LASTEXITCODE -ne 0 -or -not $resp) { throw "Sidecar smoke test failed - no response to ping" }
Write-Host "    sidecar ok: $resp"

Write-Host "==> Building Tauri release..." -ForegroundColor Cyan
Push-Location "$repoRoot/ui"
try {
    & npm run tauri build
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$appExe = "$repoRoot/ui/src-tauri/target/release/app.exe"
if (-not (Test-Path $appExe)) { throw "tauri build did not produce $appExe" }

$portable = "$repoRoot/dist/portable"
Write-Host "==> Assembling portable folder at $portable" -ForegroundColor Cyan
if (Test-Path $portable) { Remove-Item -Recurse -Force $portable }
New-Item -ItemType Directory -Force -Path $portable | Out-Null

Copy-Item $appExe "$portable/app.exe" -Force
Copy-Item "$repoRoot/dist/dft-sidecar" "$portable/dft-sidecar" -Recurse -Force

$readme = @'
Digital Forensics Triage Toolkit - portable build
=================================================

Double-click app.exe to launch.

Workflows:
  - Open hive...      parse one registry hive file (no admin required)
  - Open directory... triage a folder of mirrored Windows artifacts
  - Collect live...   read straight off the running system's volumes
                      (requires running as Administrator)

After any of the above, the Events / Findings / Browser / Timeline /
Devices tabs populate. Detection rules are MITRE ATT&CK-mapped and run
automatically. Use "Generate report..." to produce a self-contained
HTML report you can email or print to PDF.

If Windows SmartScreen blocks the unsigned binary on first launch:
  More info -> Run anyway
'@
$readme | Set-Content "$portable/README.txt" -Encoding utf8

Write-Host "`n==> Portable build complete." -ForegroundColor Green
Write-Host "    $portable"
$bytes = (Get-ChildItem -Recurse $portable | Measure-Object -Property Length -Sum).Sum
Write-Host ("    {0:N0} bytes ({1:N1} MB)" -f $bytes, ($bytes / 1MB))
