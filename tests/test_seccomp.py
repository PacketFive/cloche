# SPDX-License-Identifier: GPL-2.0
"""Seccomp filter tests.

The packed program is run by a small classic BPF interpreter, so every
rule is checked on both architectures without installing the filter.
"""

import errno
import stat
import struct

import pytest

from cloche import seccomp

ALLOW = seccomp.SECCOMP_RET_ALLOW
DENY = seccomp.SECCOMP_RET_ERRNO | errno.EPERM
KILL = seccomp.SECCOMP_RET_KILL_PROCESS
I386 = 0x40000003


def run(program: bytes, nr: int, arch: int, *args: int) -> int:
    data = struct.pack("<iIQ6Q", nr, arch, 0, *args, *(0,) * (6 - len(args)))
    code = [struct.unpack("=HBBI", program[i : i + 8]) for i in range(0, len(program), 8)]
    accumulator, pc = 0, 0
    while True:
        op, jt, jf, k = code[pc]
        pc += 1
        if op == 0x20:
            (accumulator,) = struct.unpack_from("<I", data, k)
        elif op == 0x06:
            return k
        else:
            taken = {
                0x15: accumulator == k,
                0x35: accumulator >= k,
                0x45: bool(accumulator & k),
            }[op]
            pc += jt if taken else jf


def call(machine: str, name: str, *args: int) -> int:
    program = seccomp.filter_program(machine)
    number = seccomp.SYSCALL_NUMBERS[machine][name]
    return run(program, number, seccomp.AUDIT_ARCH[machine], *args)


@pytest.mark.parametrize("machine", ["x86_64", "aarch64", "riscv64"])
def test_unconditional_denials(machine: str) -> None:
    for rule in seccomp.RULES:
        if rule.arg is None and rule.name in seccomp.SYSCALL_NUMBERS[machine]:
            assert call(machine, rule.name) == DENY, rule.name


@pytest.mark.parametrize("machine", ["x86_64", "aarch64", "riscv64"])
@pytest.mark.parametrize("name", ["chmod", "fchmod", "fchmodat", "fchmodat2"])
def test_chmod_denies_only_setid_bits(machine: str, name: str) -> None:
    if name not in seccomp.SYSCALL_NUMBERS[machine]:
        pytest.skip(f"{machine} has no {name}")
    index = next(r.arg for r in seccomp.RULES if r.name == name)
    assert index is not None

    def mode(value: int) -> list[int]:
        args = [0] * 6
        args[index] = value
        return args

    assert call(machine, name, *mode(0o755)) == ALLOW
    assert call(machine, name, *mode(0o1777)) == ALLOW
    assert call(machine, name, *mode(stat.S_ISUID | 0o755)) == DENY
    assert call(machine, name, *mode(stat.S_ISGID | 0o755)) == DENY


@pytest.mark.parametrize("machine", ["x86_64", "aarch64", "riscv64"])
def test_other_calls_are_allowed(machine: str) -> None:
    program = seccomp.filter_program(machine)
    for number in (0, 1, 59, 221, 500):
        if number not in seccomp.SYSCALL_NUMBERS[machine].values():
            assert run(program, number, seccomp.AUDIT_ARCH[machine]) == ALLOW


def test_other_architectures_are_killed() -> None:
    program = seccomp.filter_program("x86_64")
    assert run(program, 15, I386, 0) == KILL
    assert run(program, 90, seccomp.AUDIT_ARCH["aarch64"]) == KILL


def test_x32_calls_are_killed() -> None:
    program = seccomp.filter_program("x86_64")
    arch = seccomp.AUDIT_ARCH["x86_64"]
    assert run(program, seccomp.X32_SYSCALL_BIT | 1, arch) == KILL
    assert run(program, seccomp.X32_SYSCALL_BIT | 90, arch, 0, 0o4755) == KILL


def test_unknown_machine() -> None:
    with pytest.raises(ValueError, match="ppc64le"):
        seccomp.instructions("ppc64le")


def test_every_rule_has_numbers() -> None:
    for rule in seccomp.RULES:
        known = [m for m, numbers in seccomp.SYSCALL_NUMBERS.items() if rule.name in numbers]
        assert known, rule.name
    assert "chmod" not in seccomp.SYSCALL_NUMBERS["aarch64"]
    assert "chmod" not in seccomp.SYSCALL_NUMBERS["riscv64"]


def test_riscv64_filter() -> None:
    program = seccomp.filter_program("riscv64")
    arch = seccomp.AUDIT_ARCH["riscv64"]
    assert arch == 0xC00000F3
    assert run(program, 219, arch) == DENY
    assert run(program, 219, seccomp.AUDIT_ARCH["aarch64"]) == KILL
    assert seccomp.OCI_ARCH["riscv64"] == "SCMP_ARCH_RISCV64"


def test_oci_entries() -> None:
    entries = seccomp.oci_syscalls("x86_64")
    chmod = [e for e in entries if e["names"] == ("chmod",)]
    assert [e["args"] for e in chmod] == [
        ({"index": 1, "value": 2048, "valueTwo": 2048, "op": "SCMP_CMP_MASKED_EQ"},),
        ({"index": 1, "value": 1024, "valueTwo": 1024, "op": "SCMP_CMP_MASKED_EQ"},),
    ]
    assert {"names": ("keyctl",), "action": "SCMP_ACT_ERRNO", "errnoRet": 1} in entries
    names = {name for e in seccomp.oci_syscalls("aarch64") for name in e["names"]}  # type: ignore[attr-defined]
    assert "chmod" not in names
    assert "io_uring_setup" in names
