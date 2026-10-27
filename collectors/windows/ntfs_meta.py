"""Copy the NTFS metadata streams that back deleted-file detection.

Three streams from the Windows volume of an open ``dissect.target.Target``:

* ``$MFT`` → ``dest_dir/ntfs/$MFT``
* ``$Extend/$UsnJrnl:$J`` → ``dest_dir/ntfs/$J`` (the change journal ADS)
* ``$Secure:$SDS`` → ``dest_dir/ntfs/$SDS`` (security descriptors → owner SIDs)

Same chain-of-custody rules as ``live_disk``: streamed in chunks under a
running SHA-256, one ``audit.ok`` per copied stream, ``audit.skipped`` for
"not there", ``audit.error`` for failures. Nothing raises; the result says
which files landed and ``errors`` lists what went wrong.

``$J`` is sparse: NTFS keeps a huge all-zero prefix (the journal's
already-purged range) followed by the live data. The leading sparse runs are
not copied; the audit record notes ``sparse_prefix_bytes`` so the examiner
knows the on-disk offsets differ from the extracted file.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.audit import AuditLog

logger = logging.getLogger(__name__)

_READ_CHUNK = 1024 * 1024
_CATEGORY = "ntfs_meta"
_DRIVE_RE = re.compile(r"^[a-zA-Z]:$")


@dataclass
class NtfsMetaArtifacts:
    mft_path: str | None
    usnjrnl_path: str | None
    sds_path: str | None
    drive_letter: str
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Stream:
    label: str
    dest_name: str
    fs_path: str  # how the stream is addressed through fs.path(...)
    raw_attr: str  # fallback: attribute path under fs.ntfs holding the raw stream


_STREAMS: tuple[_Stream, ...] = (
    _Stream("$MFT", "$MFT", "$MFT", "mft.fh"),
    _Stream("$UsnJrnl:$J", "$J", "$Extend/$UsnJrnl:$J", "usnjrnl.fh"),
    _Stream("$Secure:$SDS", "$SDS", "$Secure:$SDS", "secure.sds"),
)


def collect_ntfs_meta(
    target: Any,
    dest_dir: Path,
    *,
    audit: AuditLog,
    fs_index: int | None = None,
) -> NtfsMetaArtifacts:
    """Copy ``$MFT``, ``$J`` and ``$SDS`` from the Windows NTFS volume into ``dest_dir/ntfs/``."""
    dest_root = Path(dest_dir).resolve()
    out_dir = dest_root / "ntfs"
    result = NtfsMetaArtifacts(None, None, None, "C:")

    fs, label = _pick_filesystem(target, fs_index)
    if fs is None:
        audit.skipped(
            "copy", "ntfs:$MFT,$J,$SDS", "no NTFS filesystem exposed by target",
            category=_CATEGORY, label="ntfs_meta",
        )
        return result
    result.drive_letter = _drive_letter_of(target, fs) or "C:"

    for stream in _STREAMS:
        dest = out_dir / stream.dest_name
        source = f"{label}:{stream.fs_path}"
        try:
            fh, sparse_prefix = _open_stream(fs, stream)
        except Exception as exc:
            logger.exception("could not open %s", source)
            audit.error("copy", source, exc, category=_CATEGORY, label=stream.label)
            result.errors.append(f"{stream.label}: {type(exc).__name__}: {exc}")
            continue
        if fh is None:
            audit.skipped("copy", source, "not present", category=_CATEGORY, label=stream.label)
            continue
        try:
            sha, size = _stream_copy(fh, dest)
        except Exception as exc:
            logger.exception("copy failed for %s", source)
            audit.error("copy", source, exc, category=_CATEGORY, label=stream.label)
            result.errors.append(f"{stream.label}: {type(exc).__name__}: {exc}")
            _remove_partial(dest)
            continue
        finally:
            _close_quietly(fh)
        audit.ok(
            action="copy",
            source_path=source,
            dest_path=str(dest.relative_to(dest_root)),
            sha256=sha,
            size_bytes=size,
            category=_CATEGORY,
            label=stream.label,
            sparse_prefix_bytes=sparse_prefix,
        )
        if stream.dest_name == "$MFT":
            result.mft_path = str(dest)
        elif stream.dest_name == "$J":
            result.usnjrnl_path = str(dest)
        else:
            result.sds_path = str(dest)
    return result


# ---------- filesystem selection --------------------------------------------


def _pick_filesystem(target: Any, fs_index: int | None) -> tuple[Any | None, str]:
    """The NTFS filesystem to read from and a label for the audit trail."""
    if fs_index is not None:
        try:
            fs = target.filesystems[fs_index]
        except Exception:
            return None, f"filesystems[{fs_index}]"
        return (fs, f"filesystems[{fs_index}]") if getattr(fs, "ntfs", None) else (None, "")

    candidates: list[tuple[Any, str]] = []
    try:
        mounts = getattr(getattr(target, "fs", None), "mounts", None) or {}
        # sysvol / c: first: that is where dissect's Windows plugin mounts the system volume.
        for key in sorted(mounts, key=lambda k: (k.lower() not in ("sysvol", "c:"), k.lower())):
            fs = mounts[key]
            if getattr(fs, "ntfs", None):
                candidates.append((fs, f"mount:{key}"))
    except Exception:
        pass
    try:
        for i, fs in enumerate(getattr(target, "filesystems", []) or []):
            if getattr(fs, "ntfs", None):
                candidates.append((fs, f"filesystems[{i}]"))
    except Exception:
        pass

    seen: set[int] = set()
    unique = []
    for fs, label in candidates:
        if id(fs.ntfs) in seen:
            continue
        seen.add(id(fs.ntfs))
        unique.append((fs, label))
    for fs, label in unique:
        try:
            p = fs.path("/Windows")
            if p.exists() and p.is_dir():
                return fs, label
        except Exception:
            continue
    return unique[0] if unique else (None, "")


def _drive_letter_of(target: Any, fs: Any) -> str | None:
    try:
        mounts = getattr(getattr(target, "fs", None), "mounts", None) or {}
        for key, mounted in mounts.items():
            if _DRIVE_RE.match(str(key)) and getattr(mounted, "ntfs", None) is fs.ntfs:
                return str(key).upper()
    except Exception:
        pass
    return None


# ---------- stream access ----------------------------------------------------


def _open_stream(fs: Any, stream: _Stream) -> tuple[Any | None, int]:
    """Open one metadata stream as ``(fh, sparse_prefix_bytes)``; ``(None, 0)`` if absent."""
    fh = None
    try:
        p = fs.path(stream.fs_path)
        if p.exists():
            fh = p.open("rb")
    except Exception as exc:
        logger.debug("fs.path(%s) failed (%s); trying raw stream", stream.fs_path, exc)
    if fh is None:
        fh = _raw_stream(fs.ntfs, stream.raw_attr)
    if fh is None:
        return None, 0
    sparse = _leading_sparse_bytes(fh) if stream.dest_name == "$J" else 0
    fh.seek(sparse)
    return fh, sparse


def _raw_stream(ntfs: Any, dotted: str) -> Any | None:
    obj = ntfs
    for part in dotted.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def _leading_sparse_bytes(fh: Any) -> int:
    runlist = getattr(fh, "runlist", None)
    block_size = getattr(fh, "block_size", None)
    if not runlist or not block_size:
        return 0
    skipped = 0
    for run_offset, run_size in runlist:
        if run_offset is not None:
            break
        skipped += run_size * block_size
    return skipped


def _stream_copy(src_fh: Any, dest_path: Path) -> tuple[str, int]:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    size = 0
    with dest_path.open("wb") as dst:
        while True:
            chunk = src_fh.read(_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            dst.write(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _remove_partial(dest: Path) -> None:
    with contextlib.suppress(OSError):
        dest.unlink(missing_ok=True)


def _close_quietly(fh: Any) -> None:
    close = getattr(fh, "close", None)
    if close is None:
        return
    with contextlib.suppress(Exception):
        close()


__all__ = ["NtfsMetaArtifacts", "collect_ntfs_meta"]
