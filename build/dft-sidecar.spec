# PyInstaller spec for the DFT sidecar.
#
# One-folder build by design: faster cold-start than one-file (no
# extract-to-%TEMP% on every launch) and friendlier to AV heuristics
# that flag packed single-EXE binaries. The whole folder ships next to
# app.exe on the pendrive.
#
# Build from the project root:
#   .venv/Scripts/python.exe -m PyInstaller build/dft-sidecar.spec --noconfirm
#
# Output: dist/dft-sidecar/dft-sidecar.exe  (plus its DLLs + rules/ + _internal/)

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

PROJECT_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 — SPECPATH injected by PyInstaller

# Bundle the rules directory verbatim — the sidecar reads it at runtime.
datas = [(str(PROJECT_ROOT / "rules"), "rules")]

# Hidden imports: PyInstaller's static analysis misses anything imported
# lazily inside our op handlers (we import dissect/regipy/pyscca/yaml on
# demand). Force-include them so the bundled sidecar doesn't crash the
# first time a user runs a live collection.
hiddenimports: list[str] = []
binaries: list[tuple[str, str]] = []

for pkg in (
    "dissect.target",
    "dissect.target.loaders",
    "dissect.target.loaders.local",
    "dissect.target.filesystems",
    "dissect.target.filesystems.ntfs",
    "dissect.target.plugins.os.windows",
    "dissect.ntfs",
    "dissect.regf",
    "dissect.volume",
    "dissect.evidence",
    "dissect.eventlog",
    "dissect.util",
    "dissect.cstruct",
    "dissect.hypervisor",
    "regipy",
    "regipy.plugins",
    "pyscca",
    "pyevtx",
    "Evtx",
    "LnkParse3",
    "yaml",
    "structlog",
    "msgpack",
    "defusedxml",
    "flow.record",
):
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(pkg)
    except Exception:  # noqa: BLE001 — collect_all can throw on missing packages
        continue
    datas.extend(pkg_datas)
    binaries.extend(pkg_binaries)
    hiddenimports.extend(pkg_hidden)

# regipy and dissect.target plugin trees use dynamic discovery — pull in every submodule.
for pkg in ("regipy.plugins", "dissect.target.plugins"):
    try:
        hiddenimports.extend(collect_submodules(pkg))
    except Exception:  # noqa: BLE001
        continue

a = Analysis(  # noqa: F821 — Analysis injected by PyInstaller
    [str(PROJECT_ROOT / "core" / "__main__.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PySide6", "PyQt6", "test", "tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="dft-sidecar",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # JSON-lines IPC over stdio — must be console.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="dft-sidecar",
)
