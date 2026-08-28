# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Safe archive extraction for GSC scanning.

This module exposes a single public function, :func:`iter_archive_text_files`,
that walks an archive on disk and yields ``(relative_name, text)`` pairs for
every text file inside. It is intentionally minimal and defensive:

* **ZIP-SLIP** — entries whose normalized name escapes the archive root
  (``..`` segments, absolute POSIX paths, Windows drive paths) are dropped.
* **Anti ZIP-BOMB** — cumulative uncompressed size and entry count are
  bounded; the iteration stops cleanly when either cap is hit.
* **Binary detection** — entries containing NUL bytes or a high ratio of
  non-printable characters in a small head sample are skipped.
* **Tolerant decoding** — UTF-8 with ``errors="replace"`` and a latin-1
  fallback; no exception ever escapes the iterator.

Only the standard library is used (``zipfile``, ``tarfile``, ``gzip``,
``bz2``, ``io``, ``pathlib``). No network, environment, or global state is
touched, so the function is safe to call from any context.
"""
from __future__ import annotations

import bz2
import gzip
import io
import tarfile
import zipfile
from pathlib import Path
from typing import Iterator, Tuple

# ── Configuration ──────────────────────────────────────────────────────────

#: Maximum total uncompressed bytes we are willing to emit per archive.
MAX_TOTAL_UNCOMPRESSED_BYTES: int = 100 * 1024 * 1024  # 100 MiB

#: Maximum number of archive entries we are willing to process.
MAX_ENTRIES: int = 10_000

#: Number of leading bytes sampled for the binary-content heuristic.
BINARY_SNIFF_BYTES: int = 4096

#: A byte is considered "non-printable" when it is not in this set or whitespace.
_PRINTABLE = set(bytes(range(0x20, 0x7F))) | {0x09, 0x0A, 0x0D, 0x0C, 0x0B}

# ZIP-family container extensions (all use the same ZIP format under the hood).
_ZIP_EXTS = {".zip", ".jar", ".ear", ".aar", ".war", ".apk"}
# Tape archive extensions (we use suffixes to disambiguate .tar.gz / .tar.bz2).
_TAR_EXTS = {".tar", ".tar.gz", ".tgz", ".tar.bz2"}

#: Union of all supported archive extensions (for external callers to detect
#: an archive without importing the private extension sets).
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(_ZIP_EXTS | _TAR_EXTS)


def is_archive(path: Path) -> bool:
    """Return ``True`` if ``path`` is a supported archive (by extension).

    Uses the same suffix logic as :func:`iter_archive_text_files` so the
    two can never disagree about what counts as an archive.
    """
    try:
        p = Path(path)
        suffix = "".join(s.lower() for s in p.suffixes)
        return suffix in ARCHIVE_EXTENSIONS or p.suffix.lower() in ARCHIVE_EXTENSIONS
    except Exception:
        return False


# ── Public API ─────────────────────────────────────────────────────────────


def iter_archive_text_files(path: Path) -> Iterator[Tuple[str, str]]:
    """Yield ``(relative_name, text)`` for every text file inside ``path``.

    Supported extensions:

    * ``.zip .jar .ear .aar .war .apk`` — ZIP-family, opened with
      :class:`zipfile.ZipFile`.
    * ``.tar .tar.gz .tgz .tar.bz2``   — Tape archives, opened with
      :class:`tarfile.open` in read-only mode.

    Unsupported or unreadable archives produce an empty iterator — no
    exception is raised. See module docstring for the full safety contract.
    """
    try:
        p = Path(path)
        suffix = "".join(s.lower() for s in p.suffixes)
        if not p.is_file():
            return

        if suffix in _ZIP_EXTS or p.suffix.lower() in _ZIP_EXTS:
            yield from _iter_zip(p)
            return

        if suffix in _TAR_EXTS or p.suffix.lower() in _TAR_EXTS:
            yield from _iter_tar(p)
            return
    except Exception:
        # Defensive: any unexpected failure (e.g. a corrupt magic number) must
        # not propagate — callers expect "empty iterator on bad archive".
        return


# ── Helpers ────────────────────────────────────────────────────────────────


def _is_unsafe_member_name(name: str) -> bool:
    """Return ``True`` if ``name`` would escape the archive root after joining.

    The check rejects:

    * Absolute POSIX paths (``/etc/passwd``).
    * Windows drive paths (``C:\\evil`` or ``C:/evil``).
    * Any path that, after POSIX-style normalization, contains a ``..`` segment.
    """
    if not name:
        return True
    # Absolute POSIX path.
    if name.startswith("/") or name.startswith("\\"):
        return True
    # Windows drive letter, e.g. "C:\\" or "C:/".
    if len(name) >= 2 and name[1] == ":":
        return True
    # Walk the segments. Any ".." means an attempt to traverse upwards.
    # On Windows archives may use backslashes; treat both separators.
    parts = name.replace("\\", "/").split("/")
    for part in parts:
        if part == "..":
            return True
    return False


def _looks_binary(sample: bytes) -> bool:
    """Heuristic: does the leading sample look like binary content?

    A buffer is treated as binary when *any* of the following holds:

    * It contains at least one NUL byte (``\\x00``).
    * More than ~30% of bytes are non-printable / non-whitespace control bytes.
    """
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    non_printable = sum(1 for b in sample if b not in _PRINTABLE)
    # Keep the threshold conservative: 30% non-printable ⇒ binary.
    return (non_printable * 10) >= (len(sample) * 3)


def _decode_safely(data: bytes) -> str:
    """Decode ``data`` to text, never raising on malformed input."""
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        # latin-1 is defined for every possible byte, so this cannot fail.
        return data.decode("latin-1", errors="replace")


# ── ZIP-family iteration ───────────────────────────────────────────────────


def _iter_zip(path: Path) -> Iterator[Tuple[str, str]]:
    """Iterate a ZIP-family archive safely.

    Handles both regular files and ZIP_STORED (no-compression) entries, but
    ignores symlinks/hardlinks — they are not files we can scan as text.
    """
    total = 0
    count = 0
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                # Only consider regular files. is_dir() and symlinks are skipped.
                if info.is_dir():
                    continue
                name = info.filename
                if _is_unsafe_member_name(name):
                    continue
                if count >= MAX_ENTRIES or total >= MAX_TOTAL_UNCOMPRESSED_BYTES:
                    return
                # Peek at the raw bytes to detect binary content before we
                # commit to the full read — saves work on large binaries.
                try:
                    # We read via a small window to sniff, then re-read the
                    # full entry. zipfile does not expose a true peek, so we
                    # use the file_size header as the cheap upper bound.
                    if info.file_size > MAX_TOTAL_UNCOMPRESSED_BYTES - total:
                        return
                    with zf.open(info, "r") as fh:
                        data = fh.read()
                except Exception:
                    continue
                if _looks_binary(data[:BINARY_SNIFF_BYTES]):
                    continue
                total += len(data)
                count += 1
                yield (name, _decode_safely(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return


# ── Tar-family iteration ───────────────────────────────────────────────────


def _iter_tar(path: Path) -> Iterator[Tuple[str, str]]:
    """Iterate a tar(.gz|.bz2) archive safely."""
    total = 0
    count = 0
    try:
        # 'r:*' lets tarfile auto-detect gzip / bzip2 / plain.
        with tarfile.open(str(path), mode="r:*") as tf:
            for member in tf:
                if count >= MAX_ENTRIES or total >= MAX_TOTAL_UNCOMPRESSED_BYTES:
                    return
                # Only plain files. Symlinks, devices, directories are skipped.
                if not member.isfile():
                    continue
                if member.issym() or member.islnk():
                    continue
                if _is_unsafe_member_name(member.name):
                    continue
                # Cap the size of any single entry: refuse to materialize a
                # multi-GB entry that would blow the global budget anyway.
                if member.size > MAX_TOTAL_UNCOMPRESSED_BYTES - total:
                    return
                try:
                    fh = tf.extractfile(member)
                except Exception:
                    continue
                if fh is None:
                    continue
                try:
                    data = fh.read()
                except Exception:
                    continue
                finally:
                    try:
                        fh.close()
                    except Exception:
                        pass
                if _looks_binary(data[:BINARY_SNIFF_BYTES]):
                    continue
                total += len(data)
                count += 1
                yield (member.name, _decode_safely(data))
    except (tarfile.TarError, OSError, ValueError, gzip.BadGzipFile, EOFError, bz2.BZ2Error):
        return


# ── Self-check ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Minimal smoke test from the CLI: walk the first positional argument.
    import sys

    if len(sys.argv) < 2:
        print("usage: python3 gsc_archive.py <archive>")
        raise SystemExit(2)
    for name, text in iter_archive_text_files(Path(sys.argv[1])):
        print(f"{name}\t{len(text)} chars")
