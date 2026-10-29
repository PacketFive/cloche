# SPDX-License-Identifier: GPL-2.0
"""Writing and strictly reading cpio newc archives."""

import io
import os
import resource
import stat
from pathlib import Path

import pytest

from cloche.newc import MAGIC, TRAILER, Entry, archive, extract

FILE = stat.S_IFREG
DIR = stat.S_IFDIR
LINK = stat.S_IFLNK


def unpack(entries: list[Entry], out: Path, outputs: tuple[str, ...] = ("out",)) -> set[str]:
    return extract(io.BytesIO(archive(entries)), str(out), outputs)


def test_round_trip(tmp_path: Path) -> None:
    entries = [
        Entry("out", DIR | 0o755),
        Entry("out/file", FILE | 0o644, b"data\n"),
        Entry("out/run", FILE | 0o4755, b"#!/bin/sh\n"),
        Entry("out/sub", DIR | 0o500),
        Entry("out/sub/empty", FILE | 0o600),
        Entry("out/link", LINK | 0o777, b"file"),
        Entry("log", FILE | 0o644, b"x" * 5),
    ]
    assert unpack(entries, tmp_path, ("out", "log")) == {"out", "log"}
    assert (tmp_path / "out/file").read_bytes() == b"data\n"
    assert stat.S_IMODE((tmp_path / "out/run").stat().st_mode) == 0o755
    assert stat.S_IMODE((tmp_path / "out/sub").stat().st_mode) == 0o500
    assert (tmp_path / "out/sub/empty").read_bytes() == b""
    assert os.readlink(tmp_path / "out/link") == "file"
    assert (tmp_path / "log").read_bytes() == b"xxxxx"
    (tmp_path / "out/sub").chmod(0o700)


def test_archive_layout() -> None:
    data = archive([Entry("dev/console", stat.S_IFCHR | 0o600, rdev=(5, 1))])
    assert data.startswith(MAGIC)
    assert len(data) % 4 == 0
    assert TRAILER.encode() in data
    assert b"%08X%08X" % (5, 1) in data


def test_missing_output_is_not_found(tmp_path: Path) -> None:
    assert unpack([], tmp_path) == set()


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([Entry("etc/passwd", FILE | 0o644)], "unexpected name 'etc/passwd'"),
        ([Entry("out", DIR | 0o755), Entry("out/../x", FILE)], "unexpected name"),
        ([Entry("out", DIR | 0o755), Entry("out//x", FILE)], "unexpected name"),
        ([Entry("out", DIR | 0o755), Entry("out/./x", FILE)], "unexpected name"),
        ([Entry("out", FILE), Entry("out", FILE)], "holds 'out' twice"),
        ([Entry("out/x", FILE)], "apart from its directory"),
        ([Entry("out", FILE), Entry("out/x", FILE)], "apart from its directory"),
        (
            [
                Entry("out", DIR | 0o755),
                Entry("out/a", DIR | 0o755),
                Entry("out/b", FILE),
                Entry("out/a/x", FILE),
            ],
            "apart from its directory",
        ),
        ([Entry("out", stat.S_IFIFO | 0o644)], "not a regular file"),
        ([Entry("out", stat.S_IFCHR | 0o644, rdev=(1, 3))], "not a regular file"),
        ([Entry("out", LINK | 0o777)], "bad length"),
        ([Entry("out", LINK | 0o777, b"a\0b")], "NUL byte"),
        ([Entry("out", DIR | 0o755, b"x")], "has contents"),
    ],
)
def test_rejects(entries: list[Entry], message: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=message):
        unpack(entries, tmp_path)


def test_open_directories_follow_depth(tmp_path: Path) -> None:
    entries = [Entry("out", DIR | 0o755)]
    for i in range(300):
        entries += [Entry(f"out/d{i}", DIR | 0o555), Entry(f"out/d{i}/f", FILE | 0o444, b"x")]
    before = len(os.listdir("/proc/self/fd"))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (before + 16, hard))
    try:
        assert unpack(entries, tmp_path) == {"out"}
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    assert stat.S_IMODE((tmp_path / "out" / "d299").stat().st_mode) == 0o555
    assert (tmp_path / "out" / "d0" / "f").read_bytes() == b"x"
    for i in range(300):
        (tmp_path / "out" / f"d{i}").chmod(0o755)


def test_rejects_truncation(tmp_path: Path) -> None:
    data = archive([Entry("out", FILE | 0o644, b"data")])
    with pytest.raises(ValueError, match="truncated"):
        extract(io.BytesIO(data[:120]), str(tmp_path), ["out"])


def test_rejects_an_empty_device(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="truncated"):
        extract(io.BytesIO(b"\0" * 64), str(tmp_path), ["out"])


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: b"\0" * 6 + d[6:], "bad header"),
        (lambda d: d[:6] + b"ZZZZZZZZ" + d[14:], "bad header"),
        (lambda d: d[:94] + b"%08X" % 1 + d[102:], "bad name length"),
        (lambda d: d[:94] + b"%08X" % 100000 + d[102:], "bad name length"),
        (lambda d: d[:110] + b"o\0t\0" + d[114:], "bad name"),
    ],
)
def test_rejects_bad_headers(change, message: str, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    data = archive([Entry("out", FILE | 0o644, b"data")])
    with pytest.raises(ValueError, match=message):
        extract(io.BytesIO(change(data)), str(tmp_path), ["out"])


def test_does_not_follow_a_planted_link(tmp_path: Path) -> None:
    (tmp_path / "out").symlink_to("/etc")
    with pytest.raises(FileExistsError):
        unpack([Entry("out", FILE | 0o644, b"x")], tmp_path)
