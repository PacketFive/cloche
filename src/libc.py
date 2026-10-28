# SPDX-License-Identifier: GPL-2.0
"""System calls the namespace backend needs and the os module lacks.

Each wrapper calls libc through ctypes and raises OSError with the errno
on failure. Only Linux on x86-64 and AArch64 is supported, the two
architectures the seccomp filter is defined for.
"""

from __future__ import annotations

import ctypes
import os
import platform

MS_RDONLY = 0x1
MS_NOSUID = 0x2
MS_NODEV = 0x4
MS_NOEXEC = 0x8
MS_REMOUNT = 0x20
MS_NOATIME = 0x400
MS_NODIRATIME = 0x800
MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 0x40000
MS_RELATIME = 0x200000
MNT_DETACH = 0x2

PR_SET_PDEATHSIG = 1
PR_SET_SECCOMP = 22
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
SECCOMP_MODE_FILTER = 2

MACHINES: tuple[str, ...] = ("x86_64", "aarch64")

# System call numbers that glibc has no wrapper for.
_SYSCALLS: dict[str, dict[str, int]] = {
    "x86_64": {
        "pivot_root": 155,
        "capset": 126,
    },
    "aarch64": {
        "pivot_root": 41,
        "capset": 91,
    },
}

_LINUX_CAPABILITY_VERSION_3 = 0x20080522

_libc = ctypes.CDLL(None, use_errno=True)
_libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_char_p,
]
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_libc.setdomainname.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
_libc.syscall.restype = ctypes.c_long


def machine() -> str:
    """Return the machine name as the kernel reports it, for example ``x86_64``."""
    return platform.machine()


def _check(result: int, what: str, path: str | None = None) -> None:
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"{what}: {os.strerror(error)}", path)


def _encode(value: str | None) -> bytes | None:
    return None if value is None else os.fsencode(value)


def _syscall(name: str, *args: object) -> int:
    number = _SYSCALLS[machine()][name]
    return _libc.syscall(ctypes.c_long(number), *args)


def mount(
    source: str | None,
    target: str,
    fstype: str | None,
    flags: int = 0,
    data: str | None = None,
) -> None:
    """Mount a filesystem with the mount system call."""
    result = _libc.mount(_encode(source), _encode(target), _encode(fstype), flags, _encode(data))
    _check(result, "mount", target)


def umount2(target: str, flags: int = 0) -> None:
    """Unmount a filesystem with the umount2 system call."""
    _check(_libc.umount2(_encode(target), flags), "umount2", target)


def pivot_root(new_root: str, put_old: str) -> None:
    """Change the root mount with the pivot_root system call."""
    result = _syscall(
        "pivot_root", ctypes.c_char_p(_encode(new_root)), ctypes.c_char_p(_encode(put_old))
    )
    _check(result, "pivot_root", new_root)


def prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> None:
    """Set a process attribute with the prctl system call."""
    _check(_libc.prctl(option, arg2, arg3, arg4, arg5), "prctl")


def setdomainname(name: str) -> None:
    """Set the NIS domain name with the setdomainname system call."""
    data = name.encode()
    _check(_libc.setdomainname(data, len(data)), "setdomainname")


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def drop_capabilities() -> None:
    """Empty the bounding, ambient, effective, permitted and inheritable sets.

    With the bounding set empty, a process running as root in its user
    namespace gains no capabilities on execve either.
    """
    with open("/proc/sys/kernel/cap_last_cap", encoding="ascii") as file:
        last = int(file.read())
    for capability in range(last + 1):
        prctl(PR_CAPBSET_DROP, capability)
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    _check(_syscall("capset", ctypes.byref(header), ctypes.byref(data)), "capset")
