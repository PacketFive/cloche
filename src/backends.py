# SPDX-License-Identifier: GPL-2.0
"""The interface every backend implements, and the choice of one.

A backend takes a SandboxJob and starts a process that sets up the
sandbox, runs the program and writes HelperReport lines on a status pipe.
There are three: namespaces.py runs the program in Linux namespaces,
oci.py with a rootless OCI runtime and microvm.py in a virtual machine.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Protocol

from .errors import SandboxUnavailable
from .probe import BACKENDS, BackendStatus
from .spec import SandboxJob

if TYPE_CHECKING:
    from .microvm import MicroVMConfig


class Backend(Protocol):
    """A way to run a SandboxSpec."""

    name: str

    def status(self) -> BackendStatus:
        """Test whether this machine can run the backend."""
        ...

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        """Start ``job``, reporting on ``status_fd`` and logging to ``log_fd``."""
        ...


def select_backend(
    name: str = "namespaces",
    *,
    runtime: str | None = None,
    microvm: MicroVMConfig | None = None,
) -> Backend:
    """Return the backend called ``name``.

    ``runtime`` is the OCI runtime, a name or a path, and ``microvm`` the
    configuration of the microVM backend; each is ignored by the other
    backends. Raises SandboxUnavailable when the backend is unknown or
    cannot run here. Cloche never falls back to another backend.
    """
    if name not in BACKENDS:
        raise SandboxUnavailable(f"there is no sandbox backend called {name}")
    backend: Backend
    if name == "oci":
        from .oci import OciBackend

        backend = OciBackend(runtime)
    elif name == "microvm":
        from .microvm import MicroVMBackend

        backend = MicroVMBackend(microvm)
    else:
        from .namespaces import NamespaceBackend

        backend = NamespaceBackend()
    status = backend.status()
    if not status.available:
        raise SandboxUnavailable(f"the {name} sandbox backend cannot run here: {status.reason}")
    return backend
