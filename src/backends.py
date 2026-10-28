# SPDX-License-Identifier: GPL-2.0
"""The interface every backend implements, and the choice of one.

A backend takes a SandboxJob and starts a process that sets up the
sandbox, runs the program and writes HelperReport lines on a status pipe.
The namespace backend (namespaces.py) is the only one in this release.
"""

from __future__ import annotations

import subprocess
from typing import Protocol

from .errors import SandboxUnavailable
from .probe import BACKENDS, BackendStatus
from .spec import SandboxJob


class Backend(Protocol):
    """A way to run a SandboxSpec."""

    name: str

    def status(self) -> BackendStatus:
        """Test whether this machine can run the backend."""
        ...

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        """Start ``job``, reporting on ``status_fd`` and logging to ``log_fd``."""
        ...


def select_backend(name: str = "namespaces") -> Backend:
    """Return the backend called ``name``.

    Raises SandboxUnavailable when it is unknown or cannot run here. Cloche
    never falls back to a weaker backend.
    """
    if name not in BACKENDS:
        raise SandboxUnavailable(f"there is no sandbox backend called {name}")
    if name != "namespaces":
        raise SandboxUnavailable(f"the {name} sandbox backend is not available in this release")
    from .namespaces import NamespaceBackend

    backend = NamespaceBackend()
    status = backend.status()
    if not status.available:
        raise SandboxUnavailable(f"the {name} sandbox backend cannot run here: {status.reason}")
    return backend
