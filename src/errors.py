# SPDX-License-Identifier: GPL-2.0
"""The errors Cloche raises on purpose.

Every one is a ClocheError, so a caller can catch them all at once and
let a bug in Cloche or in the caller surface as itself.
"""

from __future__ import annotations


class ClocheError(Exception):
    """Base class for every error Cloche raises on purpose."""


class InvalidCommand(ClocheError):
    """A Command breaks a rule of the sandbox, so it is never started."""


class SandboxUnavailable(ClocheError):
    """The chosen backend cannot run on this machine.

    Cloche never falls back to a weaker backend.
    """


class RunFailed(ClocheError):
    """The program ran but failed, ran out of time or left an output missing."""


__all__ = ["ClocheError", "InvalidCommand", "RunFailed", "SandboxUnavailable"]
