# SPDX-License-Identifier: GPL-2.0
"""Reports which sandbox backends can run on this machine.

The namespace backend is tested by doing what a run does first: a fresh
process creates the namespaces, maps its ids and mounts a tmpfs. Some
kernels let a process create a user namespace but deny it the
capabilities inside, so creating the namespace alone proves nothing.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from . import libc
from .models import Model

BACKENDS: tuple[str, ...] = ("namespaces", "oci", "microvm")
"""Every backend, in order of preference. Only namespaces works in this release."""

_PROBE = """
import os, sys
from cloche import libc
uid, gid = os.getuid(), os.getgid()
os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWNET
           | os.CLONE_NEWUTS | os.CLONE_NEWIPC | os.CLONE_NEWPID)
for name, text in (("setgroups", "deny"), ("uid_map", f"0 {uid} 1"), ("gid_map", f"0 {gid} 1")):
    with open(f"/proc/self/{name}", "w") as file:
        file.write(text)
libc.mount(None, "/", None, libc.MS_REC | libc.MS_PRIVATE)
libc.mount("tmpfs", sys.argv[1], "tmpfs", libc.MS_NOSUID | libc.MS_NODEV)
"""

# Files that explain why unprivileged user namespaces fail, with the value
# that disables them.
_SYSCTLS: tuple[tuple[str, str, str], ...] = (
    ("/proc/sys/kernel/unprivileged_userns_clone", "0", "kernel.unprivileged_userns_clone is 0"),
    ("/proc/sys/user/max_user_namespaces", "0", "user.max_user_namespaces is 0"),
    (
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        "1",
        "kernel.apparmor_restrict_unprivileged_userns is 1, so AppArmor denies"
        " capabilities inside a new user namespace",
    ),
)


class BackendStatus(Model):
    """Whether one sandbox backend can run here, and why not when it cannot."""

    name: str
    available: bool
    reason: str = ""


def _explain() -> str:
    for path, value, reason in _SYSCTLS:
        try:
            if Path(path).read_text(encoding="ascii").strip() == value:
                return reason
        except OSError:
            continue
    return ""


def namespaces_status() -> BackendStatus:
    """Test the namespace backend."""
    name = "namespaces"
    machine = libc.machine()
    if machine not in libc.MACHINES:
        return BackendStatus(name=name, available=False, reason=f"{machine} is not supported")
    with tempfile.TemporaryDirectory(prefix="cloche-probe-") as directory:
        try:
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-I", "-c", _PROBE, directory],
                env={},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return BackendStatus(name=name, available=False, reason=str(error))
    if result.returncode == 0:
        return BackendStatus(name=name, available=True)
    lines = result.stderr.strip().splitlines()
    detail = lines[-1] if lines else f"exit status {result.returncode}"
    cause = _explain()
    reason = f"unprivileged user namespaces do not work: {detail}"
    return BackendStatus(
        name=name, available=False, reason=f"{reason} ({cause})" if cause else reason
    )


def backend_status() -> tuple[BackendStatus, ...]:
    """Report every backend in BACKENDS, in that order."""
    return tuple(
        namespaces_status()
        if name == "namespaces"
        else BackendStatus(name=name, available=False, reason="not available in this release")
        for name in BACKENDS
    )
