# SPDX-License-Identifier: GPL-2.0
"""The seccomp filter of the sandbox.

RULES lists the denied system calls once. filter_program turns them into a
classic BPF program for the namespace backend, installed with prctl, and
oci_syscalls into the ``linux.seccomp.syscalls`` entries of the OCI
configuration, so both backends deny the same calls.

The program first checks the architecture of each call. A call made
through any other system call ABI, such as 32-bit x86 or x32 on an x86-64
host, kills the process, since the rules give no numbers for it. A denied
call fails with EPERM and does not end the program.
"""

from __future__ import annotations

import ctypes
import errno
import stat
import struct

from . import libc
from .models import Model

AUDIT_ARCH: dict[str, int] = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7, "riscv64": 0xC00000F3}
OCI_ARCH: dict[str, str] = {
    "x86_64": "SCMP_ARCH_X86_64",
    "aarch64": "SCMP_ARCH_AARCH64",
    "riscv64": "SCMP_ARCH_RISCV64",
}

# x86-64 marks x32 calls by setting this bit in the call number.
X32_SYSCALL_BIT = 0x40000000

SETID_BITS = stat.S_ISUID | stat.S_ISGID

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

_BPF_LD_W_ABS = 0x20
_BPF_JEQ_K = 0x15
_BPF_JGE_K = 0x35
_BPF_JSET_K = 0x45
_BPF_RET_K = 0x06

# Offsets in struct seccomp_data. Both architectures are little endian,
# so the low 32 bits of argument i are at 16 + 8 * i.
_NR_OFFSET = 0
_ARCH_OFFSET = 4


def _arg_offset(index: int) -> int:
    return 16 + 8 * index


class SeccompRule(Model):
    """One denied system call.

    Without ``arg`` the call is always denied. With ``arg`` it is denied
    when the argument at that index has any of the bits in ``mask`` set.
    """

    name: str
    arg: int | None = None
    mask: int = 0


RULES: tuple[SeccompRule, ...] = (
    SeccompRule(name="chmod", arg=1, mask=SETID_BITS),
    SeccompRule(name="fchmod", arg=1, mask=SETID_BITS),
    SeccompRule(name="fchmodat", arg=2, mask=SETID_BITS),
    SeccompRule(name="fchmodat2", arg=2, mask=SETID_BITS),
    SeccompRule(name="setxattr"),
    SeccompRule(name="lsetxattr"),
    SeccompRule(name="fsetxattr"),
    SeccompRule(name="setxattrat"),
    SeccompRule(name="add_key"),
    SeccompRule(name="keyctl"),
    SeccompRule(name="request_key"),
    # io_uring runs file operations, including setting extended
    # attributes, without passing through this filter.
    SeccompRule(name="io_uring_setup"),
    SeccompRule(name="io_uring_enter"),
    SeccompRule(name="io_uring_register"),
)

# AArch64 and RISC-V 64 have no chmod; their other numbers come from
# the generic table of the kernel, so they are the same.
SYSCALL_NUMBERS: dict[str, dict[str, int]] = {
    "x86_64": {
        "chmod": 90,
        "fchmod": 91,
        "fchmodat": 268,
        "fchmodat2": 452,
        "setxattr": 188,
        "lsetxattr": 189,
        "fsetxattr": 190,
        "setxattrat": 463,
        "add_key": 248,
        "request_key": 249,
        "keyctl": 250,
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
    },
    "aarch64": {
        "fchmod": 52,
        "fchmodat": 53,
        "fchmodat2": 452,
        "setxattr": 5,
        "lsetxattr": 6,
        "fsetxattr": 7,
        "setxattrat": 463,
        "add_key": 217,
        "request_key": 218,
        "keyctl": 219,
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
    },
}
SYSCALL_NUMBERS["riscv64"] = dict(SYSCALL_NUMBERS["aarch64"])

Instruction = tuple[int, int, int, int]


def instructions(machine: str) -> list[Instruction]:
    """Return the filter for ``machine`` as (code, jt, jf, k) tuples.

    Raises ValueError for a machine the filter is not defined for.
    """
    if machine not in AUDIT_ARCH:
        raise ValueError(f"no seccomp filter is defined for {machine}")
    numbers = SYSCALL_NUMBERS[machine]
    # Each entry is (code, true label, false label, k); a label is an int
    # offset or the name of one of the three return instructions.
    program: list[tuple[int, int | str, int | str, int]] = [
        (_BPF_LD_W_ABS, 0, 0, _ARCH_OFFSET),
        (_BPF_JEQ_K, 0, "kill", AUDIT_ARCH[machine]),
        (_BPF_LD_W_ABS, 0, 0, _NR_OFFSET),
    ]
    if machine == "x86_64":
        program.append((_BPF_JGE_K, "kill", 0, X32_SYSCALL_BIT))
    for rule in RULES:
        if rule.name not in numbers:
            continue
        if rule.arg is None:
            program.append((_BPF_JEQ_K, "deny", 0, numbers[rule.name]))
        else:
            program.append((_BPF_JEQ_K, 0, 2, numbers[rule.name]))
            program.append((_BPF_LD_W_ABS, 0, 0, _arg_offset(rule.arg)))
            program.append((_BPF_JSET_K, "deny", "allow", rule.mask))
    labels = {"allow": len(program), "deny": len(program) + 1, "kill": len(program) + 2}
    program.append((_BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    program.append((_BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM))
    program.append((_BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS))

    def resolve(index: int, target: int | str) -> int:
        if isinstance(target, int):
            return target
        offset = labels[target] - index - 1
        if not 0 <= offset <= 255:
            raise ValueError("seccomp filter jump out of range")
        return offset

    return [
        (code, resolve(i, jt), resolve(i, jf), k) for i, (code, jt, jf, k) in enumerate(program)
    ]


def filter_program(machine: str) -> bytes:
    """Return the filter for ``machine`` as an array of struct sock_filter."""
    return b"".join(struct.pack("=HBBI", *ins) for ins in instructions(machine))


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install(machine: str) -> None:
    """Install the filter in the calling process.

    PR_SET_NO_NEW_PRIVS must be set first, as the kernel requires for a
    process without CAP_SYS_ADMIN in the initial user namespace.
    """
    program = filter_program(machine)
    buffer = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // 8, ctypes.addressof(buffer))
    libc.prctl(libc.PR_SET_SECCOMP, libc.SECCOMP_MODE_FILTER, ctypes.addressof(fprog))


def oci_syscalls(machine: str) -> list[dict[str, object]]:
    """Return the rules as OCI ``linux.seccomp.syscalls`` entries for ``machine``.

    OCI conditions are ANDed, so a rule with a mask becomes one entry per
    bit, each denying the call when that bit is set.
    """
    numbers = SYSCALL_NUMBERS[machine]
    entries: list[dict[str, object]] = []
    for rule in RULES:
        if rule.name not in numbers:
            continue
        deny: dict[str, object] = {
            "names": (rule.name,),
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": errno.EPERM,
        }
        if rule.arg is None:
            entries.append(deny)
            continue
        for bit in (b for b in (stat.S_ISUID, stat.S_ISGID) if rule.mask & b):
            condition = {
                "index": rule.arg,
                "value": bit,
                "valueTwo": bit,
                "op": "SCMP_CMP_MASKED_EQ",
            }
            entries.append(deny | {"args": (condition,)})
    return entries
