#!/usr/bin/env python3
"""Tests for gsc_core.gsc_archive — safe archive iteration.

These tests exercise the public contract of :func:`iter_archive_text_files`:
text extraction, ZIP-SLIP rejection, ZIP-BOMB caps, binary detection, and
the unsupported-extension fallback. Every test builds the fixture archive
in a temp dir so the suite is self-contained and hermetic.
"""
from __future__ import annotations

import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

# Ensure the repo root is importable even when pytest is invoked from elsewhere.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gsc_core.gsc_archive import iter_archive_text_files  # noqa: E402


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def workdir(tmp_path) -> Path:
    """A scratch directory for building test archives."""
    return tmp_path


# ── Tests ──────────────────────────────────────────────────────────────────


def test_zip_text_file_is_extracted(workdir: Path) -> None:
    """A plain zip with a single text file round-trips through the iterator."""
    archive = workdir / "sample.zip"
    payload = "hello, world\nthis is a config\n"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config/app.cfg", payload)

    results = list(iter_archive_text_files(archive))

    assert len(results) == 1, f"expected 1 file, got {len(results)}: {results}"
    name, text = results[0]
    assert name == "config/app.cfg"
    assert text == payload


def test_zip_slip_is_dropped(workdir: Path) -> None:
    """An entry that escapes the archive root must NOT be returned."""
    archive = workdir / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("safe.txt", "ok")
        zf.writestr("../evil.txt", "should never escape")
        zf.writestr("/abs.txt", "absolute also blocked")

    results = list(iter_archive_text_files(archive))
    names = [n for n, _ in results]

    assert "safe.txt" in names, f"safe entry missing: {names}"
    assert not any("evil" in n for n in names), f"slip entry leaked: {names}"
    assert not any(n.startswith("/") for n in names), f"absolute entry leaked: {names}"


def test_tar_gz_text_file_is_extracted(workdir: Path) -> None:
    """A gzipped tar with a text file is iterated correctly."""
    archive = workdir / "sample.tar.gz"
    payload = "tar line one\ntar line two\n"
    data = payload.encode("utf-8")
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo(name="notes/readme.txt")
        info.size = len(data)
        tf.addfile(info, BytesIO(data))

    results = list(iter_archive_text_files(archive))

    assert len(results) == 1, f"expected 1 entry, got {len(results)}"
    name, text = results[0]
    assert name == "notes/readme.txt"
    assert text == payload


def test_jar_extension_is_zip_family(workdir: Path) -> None:
    """``.jar`` is just a renamed zip — it must be opened transparently."""
    archive = workdir / "library.jar"
    payload = "Manifest-Version: 1.0\n"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", payload)

    results = list(iter_archive_text_files(archive))

    assert len(results) == 1
    name, text = results[0]
    assert name.endswith("MANIFEST.MF")
    assert "Manifest-Version" in text


def test_binary_file_with_nulls_is_skipped(workdir: Path) -> None:
    """An entry whose head contains NUL bytes must be classified as binary."""
    archive = workdir / "mixed.zip"
    binary = b"\x00\x01\x02\x03" * 64  # 256 bytes of opaque binary
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("real.txt", "this is real text")
        zf.writestr("blob.bin", binary)

    results = list(iter_archive_text_files(archive))
    names = [n for n, _ in results]

    assert "real.txt" in names
    assert "blob.bin" not in names, "binary entry was not filtered"


def test_size_limit_stops_iteration(workdir: Path) -> None:
    """Once the global uncompressed budget is hit, iteration stops cleanly."""
    import gsc_core.gsc_archive as mod

    saved = mod.MAX_TOTAL_UNCOMPRESSED_BYTES
    mod.MAX_TOTAL_UNCOMPRESSED_BYTES = 64  # tiny cap, in bytes
    try:
        archive = workdir / "many.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("a.txt", "x" * 32)
            zf.writestr("b.txt", "y" * 32)
            zf.writestr("c.txt", "z" * 32)  # should NOT be yielded
        # _iter_zip reads the module attribute fresh on every call.
        results = list(mod._iter_zip(archive))
        assert len(results) <= 2, (
            f"expected <=2 entries, got {len(results)}: {[n for n, _ in results]}"
        )
        assert len(results) >= 1
        names = [n for n, _ in results]
        assert "c.txt" not in names
    finally:
        mod.MAX_TOTAL_UNCOMPRESSED_BYTES = saved


def test_entry_count_limit_stops_iteration(workdir: Path) -> None:
    """The MAX_ENTRIES cap is enforced — we do not scan past it."""
    import gsc_core.gsc_archive as mod

    saved = mod.MAX_ENTRIES
    mod.MAX_ENTRIES = 3
    try:
        archive = workdir / "counted.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            for i in range(10):
                zf.writestr(f"f{i}.txt", f"content {i}")
        results = list(mod._iter_zip(archive))
        assert len(results) == 3, f"expected exactly 3 entries, got {len(results)}"
    finally:
        mod.MAX_ENTRIES = saved


def test_unsupported_extension_returns_empty(workdir: Path) -> None:
    """An unknown extension must yield nothing — no exception."""
    bogus = workdir / "thing.bin"
    bogus.write_bytes(b"not really an archive")

    # Must not raise.
    results = list(iter_archive_text_files(bogus))
    assert results == []


def test_nonexistent_path_returns_empty(workdir: Path) -> None:
    """A missing file is treated as an empty archive."""
    results = list(iter_archive_text_files(workdir / "does-not-exist.zip"))
    assert results == []


def test_corrupt_zip_returns_empty(workdir: Path) -> None:
    """Random bytes with a .zip suffix must not crash the iterator."""
    junk = workdir / "corrupt.zip"
    junk.write_bytes(b"this is definitely not a zip file" * 100)

    # Must not raise.
    results = list(iter_archive_text_files(junk))
    assert results == []
