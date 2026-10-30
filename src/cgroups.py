# SPDX-License-Identifier: GPL-2.0
"""Resource limits through a delegated cgroup version 2 subtree.

A service manager delegates a cgroup to a service when the service may
manage the cgroups below it; systemd does so for a unit with
``Delegate=yes`` and marks the cgroup with the extended attribute
``trusted.delegate`` or ``user.delegate``. When the process runs in such
a cgroup, each run gets a child cgroup whose ``memory.max``, ``cpu.max``
and ``pids.max`` come from Limits, and removing the child ends every
process left in it. Without a delegated cgroup the limits are not
applied, and status says why.

A cgroup with processes cannot pass controllers to its children, so the
first run moves the processes of the delegated cgroup into its child
``supervisor`` and enables the controllers. The runs are siblings of
``supervisor``.
"""

from __future__ import annotations

import errno
import os
import threading
import time
import uuid

from .errors import SandboxUnavailable
from .models import Limits, Model

ROOT = "/sys/fs/cgroup"
SELF = "/proc/self/cgroup"
SUPERVISOR = "supervisor"
PREFIX = "cloche-"
CONTROLLERS = ("cpu", "memory", "pids")
DELEGATE_ATTRIBUTES = ("trusted.delegate", "user.delegate")
CPU_PERIOD = 100_000
REMOVE_SECONDS = 10.0

_lock = threading.Lock()


class CgroupStatus(Model):
    """Whether runs get their own cgroup, and the delegated cgroup or the reason not."""

    available: bool
    path: str = ""
    reason: str = ""


def wanted(limits: Limits) -> bool:
    """Whether ``limits`` set anything only a cgroup can enforce."""
    return any(v is not None for v in (limits.max_memory, limits.max_cpu, limits.max_processes))


def _read(path: str) -> str:
    with open(path, encoding="ascii") as file:
        return file.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="ascii") as file:
        file.write(text)


def _own(root: str, self_file: str) -> str | None:
    """Return the cgroup version 2 directory of this process, or None."""
    try:
        lines = _read(self_file).splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("0::/"):
            return os.path.normpath(os.path.join(root, line[4:]))
    return None


def _delegated(path: str) -> bool:
    for name in DELEGATE_ATTRIBUTES:
        try:
            if os.getxattr(path, name) == b"1":
                return True
        except OSError:
            continue
    return False


def status(root: str | None = None, self_file: str | None = None) -> CgroupStatus:
    """Return whether runs started from this process can have their own cgroup."""
    own = _own(root or ROOT, self_file or SELF)
    if own is None:
        return CgroupStatus(available=False, reason="cgroup version 2 is not in use")
    base = os.path.dirname(own) if os.path.basename(own) == SUPERVISOR else own
    if not _delegated(base):
        return CgroupStatus(
            available=False,
            reason=f"{base} is not delegated; run under a service with Delegate=yes",
        )
    try:
        controllers = _read(os.path.join(base, "cgroup.controllers")).split()
    except OSError as error:
        return CgroupStatus(available=False, reason=f"{base}: {error.strerror}")
    missing = [c for c in CONTROLLERS if c not in controllers]
    if missing:
        return CgroupStatus(
            available=False, reason=f"{base} lacks the controllers {', '.join(missing)}"
        )
    return CgroupStatus(available=True, path=base)


def _prepare(base: str) -> None:
    """Move the processes of ``base`` into ``supervisor`` and enable the controllers."""
    enabled = _read(os.path.join(base, "cgroup.subtree_control")).split()
    if all(c in enabled for c in CONTROLLERS):
        return
    supervisor = os.path.join(base, SUPERVISOR)
    os.makedirs(supervisor, exist_ok=True)
    for _ in range(10):
        pids = _read(os.path.join(base, "cgroup.procs")).split()
        if not pids:
            break
        for pid in pids:
            try:
                _write(os.path.join(supervisor, "cgroup.procs"), pid)
            except ProcessLookupError:
                continue
    _write(
        os.path.join(base, "cgroup.subtree_control"),
        " ".join(f"+{c}" for c in CONTROLLERS if c not in enabled),
    )


def create(limits: Limits, root: str | None = None, self_file: str | None = None) -> str | None:
    """Create the cgroup of one run with ``limits`` and return its path.

    Returns None when ``limits`` need no cgroup or none is delegated, so
    the run goes ahead without these limits. Raises SandboxUnavailable if
    the delegated cgroup cannot be set up.
    """
    if not wanted(limits):
        return None
    found = status(root, self_file)
    if not found.available:
        return None
    path = os.path.join(found.path, f"{PREFIX}{uuid.uuid4().hex}")
    try:
        with _lock:
            _prepare(found.path)
        os.mkdir(path, 0o755)
        if limits.max_memory is not None:
            _write(os.path.join(path, "memory.max"), str(limits.max_memory))
            if os.path.exists(os.path.join(path, "memory.swap.max")):
                _write(os.path.join(path, "memory.swap.max"), "0")
        if limits.max_cpu is not None:
            quota = max(int(limits.max_cpu * CPU_PERIOD), 1000)
            _write(os.path.join(path, "cpu.max"), f"{quota} {CPU_PERIOD}")
        if limits.max_processes is not None:
            _write(os.path.join(path, "pids.max"), str(limits.max_processes))
    except OSError as error:
        if os.path.isdir(path):
            remove(path)
        raise SandboxUnavailable(
            f"cannot set up the cgroup of the run under {found.path}: {error.strerror or error}"
        ) from None
    return path


def join(path: str) -> None:
    """Move the calling process into the cgroup at ``path``."""
    _write(os.path.join(path, "cgroup.procs"), "0")


def _remove_directory(path: str) -> None:
    os.rmdir(path)


def remove(path: str) -> None:
    """End every process in the cgroup at ``path`` and remove it.

    Waits up to REMOVE_SECONDS for the processes to exit, and leaves a
    cgroup that is still busy after that in place.
    """
    if not os.path.isdir(path):
        return
    kill = os.path.join(path, "cgroup.kill")
    if os.path.exists(kill):
        _write(kill, "1")
    else:
        try:
            pids = _read(os.path.join(path, "cgroup.procs")).split()
        except OSError:
            pids = []
        for pid in pids:
            try:
                os.kill(int(pid), 9)
            except ProcessLookupError:
                continue
    deadline = time.monotonic() + REMOVE_SECONDS
    while True:
        try:
            _remove_directory(path)
            return
        except FileNotFoundError:
            return
        except OSError as error:
            if error.errno != errno.EBUSY or time.monotonic() >= deadline:
                return
            time.sleep(0.05)


__all__ = ["CgroupStatus", "create", "join", "remove", "status", "wanted"]
