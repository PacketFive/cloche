# SPDX-License-Identifier: GPL-2.0
"""Cloche runs a program in an unprivileged Linux sandbox.

The program sees only the host paths bound into the sandbox, read-only,
and empty writable directories. It has no network, no capabilities and
no way to gain privileges, runs under a seccomp filter with a fixed
environment and fixed limits, and ends with its sandbox. When it
succeeds, its declared outputs are copied out.

Cloche needs no root and no daemon. It is a library first:

    from cloche import Bind, Command, run

    command = Command(
        name="hello",
        program="/usr/bin/sh",
        args=("-c", "echo hello > /build/greeting"),
        binds=tuple(Bind(source=p, destination=p) for p in ("/usr", "/lib", "/lib64")),
        outputs={"greeting": "/build/greeting"},
    )
    outcome = run(command, "/tmp/work")  # an empty directory
    print(outcome.outputs["greeting"])  # /tmp/work/out/greeting

models.py holds the data models, spec.py turns a Command into a
SandboxSpec and an OCI runtime configuration, environment.py fixes the
environment, seccomp.py the denied system calls, namespaces.py is the
backend that applies a spec, runner.py supervises a run, probe.py reports
which backends work here and cli.py is the ``cloche`` command.

Names in ``__all__`` follow semantic versioning from release 1.0. A name
is removed only after one minor release in which using it raises a
DeprecationWarning. Modules and names not listed here are internal.
"""

from __future__ import annotations

from .backends import Backend, select_backend
from .environment import FIXED_VARIABLES
from .errors import ClocheError, InvalidCommand, RunFailed, SandboxUnavailable
from .models import BUILD_DIR, Bind, Command, Limits
from .probe import BACKENDS, BackendStatus, backend_status
from .runner import Outcome, run
from .spec import OciConfig, SandboxJob, SandboxSpec, make_spec, oci_config

__version__ = "0.0.0"

__all__ = [
    "BACKENDS",
    "BUILD_DIR",
    "FIXED_VARIABLES",
    "Backend",
    "BackendStatus",
    "Bind",
    "ClocheError",
    "Command",
    "InvalidCommand",
    "Limits",
    "OciConfig",
    "Outcome",
    "RunFailed",
    "SandboxJob",
    "SandboxSpec",
    "SandboxUnavailable",
    "__version__",
    "backend_status",
    "make_spec",
    "oci_config",
    "run",
    "select_backend",
]
