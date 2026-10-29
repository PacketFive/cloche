# SPDX-License-Identifier: GPL-2.0
"""The cpio newc format, as the microVM backend uses it.

The host writes the guest's initramfs with ``archive``, and reads the
outputs the guest init wrote to its output device with ``extract``. The
second archive is written by a guest that runs the build, so ``extract``
trusts nothing in it: every name must lie under an expected output, every
parent must be a directory the archive created earlier, entries must come
in pre-order, with each directory's contents straight after it, and only
regular files, directories and symbolic links are accepted. Set-user-ID and
set-group-ID bits are dropped, as copy_out drops them.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from typing import BinaryIO

MAGIC = b"070701"
HEADER_SIZE = 110
TRAILER = "TRAILER!!!"
MAX_NAME = 8192
_CHUNK = 1 << 20


class Entry:
    """One member of an archive the host writes."""

    def __init__(self, name: str, mode: int, data: bytes = b"", rdev: tuple[int, int] = (0, 0)):
        """Store the member: its path, mode with file type, contents and device."""
        self.name = name
        self.mode = mode
        self.data = data
        self.rdev = rdev


def _pad(length: int) -> bytes:
    return b"\0" * (-length % 4)


def _header(inode: int, mode: int, size: int, rdev: tuple[int, int], name: bytes) -> bytes:
    fields = (inode, mode, 0, 0, 1, 0, size, 0, 0, rdev[0], rdev[1], len(name) + 1, 0)
    return MAGIC + b"".join(b"%08X" % field for field in fields)


def archive(entries: Iterable[Entry]) -> bytes:
    """Return ``entries`` as a newc archive, owned by root, with time 0."""
    parts: list[bytes] = []
    inode = 0
    for entry in [*entries, Entry(TRAILER, 0)]:
        inode += 1
        name = entry.name.encode()
        head = _header(inode, entry.mode, len(entry.data), entry.rdev, name) + name + b"\0"
        parts += [head, _pad(len(head)), entry.data, _pad(len(entry.data))]
    return b"".join(parts)


class _Reader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.offset = 0

    def read(self, size: int) -> bytes:
        data = self.stream.read(size)
        if len(data) != size:
            raise ValueError("the output archive is truncated")
        self.offset += size
        return data

    def align(self) -> None:
        self.read(-self.offset % 4)


def _check_name(name: str, outputs: Iterable[str]) -> tuple[str, list[str]]:
    parts = name.split("/")
    if parts[0] not in outputs or any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"the output archive holds an unexpected name {name!r}")
    return parts[0], parts


def _write_file(reader: _Reader, size: int, parent: int, name: str, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    target = os.open(name, flags, 0o600, dir_fd=parent)
    try:
        left = size
        while left:
            chunk = reader.read(min(left, _CHUNK))
            os.write(target, chunk)
            left -= len(chunk)
        os.fchmod(target, mode)
    finally:
        os.close(target)


def extract(stream: BinaryIO, out_dir: str, outputs: Iterable[str]) -> set[str]:
    """Write the outputs in the newc archive ``stream`` into ``out_dir``.

    Each output named in ``outputs`` becomes ``out_dir/<name>``. Returns
    the names found. Raises ValueError if the archive breaks a rule of
    this module.
    """
    expected = set(outputs)
    reader = _Reader(stream)
    found: set[str] = set()
    seen: set[str] = set()
    # The directories on the path to the current entry, open, with their
    # modes. The guest writes the archive in pre-order, so a directory is
    # finished, and gets its mode, once an entry outside it arrives. Open
    # descriptors grow with the depth of the tree, not its size.
    stack: list[tuple[str, int, int]] = []
    top = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while True:
            head = reader.read(HEADER_SIZE)
            if head[:6] != MAGIC:
                raise ValueError("the output archive has a bad header")
            try:
                fields = [int(head[6 + 8 * i : 14 + 8 * i], 16) for i in range(13)]
            except ValueError:
                raise ValueError("the output archive has a bad header") from None
            mode, size, name_size = fields[1], fields[6], fields[11]
            if not 1 < name_size <= MAX_NAME:
                raise ValueError("the output archive has a bad name length")
            raw = reader.read(name_size)
            reader.align()
            if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
                raise ValueError("the output archive has a bad name")
            name = raw[:-1].decode("utf-8", errors="surrogateescape")
            if name == TRAILER:
                break
            output, parts = _check_name(name, expected)
            if name in seen:
                raise ValueError(f"the output archive holds {name!r} twice")
            seen.add(name)
            within = "/".join(parts[:-1])
            while stack and stack[-1][0] != within:
                _finish(stack.pop())
            if within and not stack:
                raise ValueError(f"the output archive holds {name!r} apart from its directory")
            parent = stack[-1][1] if stack else top
            leaf = parts[-1]
            permissions = stat.S_IMODE(mode) & 0o777
            if stat.S_ISREG(mode):
                _write_file(reader, size, parent, leaf, permissions)
            elif stat.S_ISLNK(mode):
                if not 0 < size <= 4096:
                    raise ValueError(f"symbolic link {name!r} has a bad length")
                target = reader.read(size)
                if b"\0" in target:
                    raise ValueError(f"symbolic link {name!r} holds a NUL byte")
                os.symlink(os.fsdecode(target), leaf, dir_fd=parent)
            elif stat.S_ISDIR(mode):
                if size:
                    raise ValueError(f"directory {name!r} has contents")
                os.mkdir(leaf, 0o700, dir_fd=parent)
                handle = os.open(
                    leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
                )
                stack.append((name, handle, permissions))
            else:
                raise ValueError(f"{name} is not a regular file, directory or symbolic link")
            reader.align()
            if len(parts) == 1:
                found.add(output)
    finally:
        while stack:
            _finish(stack.pop())
        os.close(top)
    return found


def _finish(directory: tuple[str, int, int]) -> None:
    _, handle, permissions = directory
    try:
        os.fchmod(handle, permissions)
    finally:
        os.close(handle)


__all__ = ["MAGIC", "TRAILER", "Entry", "archive", "extract"]
