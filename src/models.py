# SPDX-License-Identifier: GPL-2.0
"""The data models of Cloche.

A Command says what to run and what the program may see: the host paths
bound read-only into the sandbox, the empty writable directories, and the
outputs to copy out when it succeeds. Limits says how long it may run.
Both are validated by Espalier when they are made, so a Command that
exists is well formed; make_spec (spec.py) then checks the rules that
relate its fields to each other.

Models are immutable and reject unknown fields. Validation is strict, so a
string is never silently turned into a number.
"""

from __future__ import annotations

import posixpath
import re
from typing import Annotated

from espalier import AfterValidator, BaseModel, ConfigDict, Field, field_validator

BUILD_DIR = "/build"
"""The working directory of the program, an empty tmpfs."""

RESERVED: tuple[str, ...] = ("/proc", "/dev", BUILD_DIR)
"""Paths the sandbox mounts itself. Nothing may be bound or created at or below them."""

_OUTPUT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")


class Model(BaseModel):
    """Base class of every Cloche data model."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def _absolute(path: str) -> str:
    if not path.startswith("/") or posixpath.normpath(path) != path or "\0" in path:
        raise ValueError(f"{path!r} is not a normalised absolute path")
    return path


def is_below(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def _placeable(path: str) -> str:
    _absolute(path)
    if path == "/" or any(is_below(path, reserved) for reserved in RESERVED):
        raise ValueError(f"{path!r} is the root or a path the sandbox mounts itself")
    return path


AbsolutePath = Annotated[str, AfterValidator(_absolute)]
"""A normalised absolute path, such as ``/usr/bin/env``."""

SandboxPath = Annotated[str, AfterValidator(_placeable)]
"""An absolute path inside the sandbox that Cloche does not mount itself."""


class Bind(Model):
    """A host path bound read-only at ``destination`` inside the sandbox.

    The host path is opened without following a final symbolic link. If it
    is one, the sandbox gets a symbolic link with the same target instead
    of the file it names.
    """

    source: AbsolutePath
    destination: SandboxPath


class Limits(Model):
    """Limits applied to every run.

    ``timeout`` ends a run that takes longer than that many seconds, and
    ``max_silent_time`` one that writes nothing to its log for that many
    seconds. None means no limit. ``max_open_files`` is the program's
    ``RLIMIT_NOFILE``.

    ``max_memory`` in bytes, ``max_cpu`` in CPUs and ``max_processes``
    become ``memory.max``, ``cpu.max`` and ``pids.max`` of the run's own
    cgroup. They apply only when the process runs in a delegated cgroup
    version 2 subtree (cgroups.py); otherwise the run goes ahead without
    them.
    """

    timeout: int | None = Field(default=None, gt=0)
    max_silent_time: int | None = Field(default=None, gt=0)
    max_open_files: int = Field(default=1024, ge=64, le=1048576)
    max_memory: int | None = Field(default=None, ge=1 << 20)
    max_cpu: float | None = Field(default=None, ge=0.01)
    max_processes: int | None = Field(default=None, ge=8)


class Command(Model):
    """One program to run in the sandbox.

    ``name`` labels log lines and errors. ``program`` is run with ``args``
    and must lie inside one of the ``binds``, since nothing else exists in
    the sandbox. ``env`` is added to the fixed variables of
    environment.py. Each of ``directories`` is an empty writable tmpfs.
    ``outputs`` maps a name to a path the program creates below
    ``/build`` or one of ``directories``; each is copied out, under its
    name, when the program succeeds.
    """

    name: str = Field(min_length=1)
    program: AbsolutePath
    args: tuple[str, ...] = ()
    env: dict[str, str] = {}
    binds: tuple[Bind, ...] = ()
    directories: tuple[SandboxPath, ...] = ()
    outputs: dict[str, AbsolutePath] = {}

    @field_validator("outputs")
    @classmethod
    def _output_names(cls, outputs: dict[str, str]) -> dict[str, str]:
        for name in outputs:
            if not _OUTPUT_NAME.fullmatch(name):
                raise ValueError(f"output name {name!r} is not a plain file name")
        return outputs


__all__ = [
    "BUILD_DIR",
    "RESERVED",
    "AbsolutePath",
    "Bind",
    "Command",
    "Limits",
    "Model",
    "SandboxPath",
]
