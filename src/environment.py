# SPDX-License-Identifier: GPL-2.0
"""The program's environment.

The program sees the Command's ``env`` and FIXED_VARIABLES, and nothing
from the environment of the process that started it. The fixed variables
give every run the same time zone, locale, home and clock for archive
timestamps, which reproducible builds need. A Command that sets one of
them is refused, so a reader of the Command sees exactly what the program
sees.
"""

from __future__ import annotations

from types import MappingProxyType

from .errors import InvalidCommand
from .models import BUILD_DIR, Command

FIXED_VARIABLES = MappingProxyType(
    {
        "SOURCE_DATE_EPOCH": "315532800",
        "TZ": "UTC",
        "LANG": "C.UTF-8",
        "HOME": "/homeless",
        "TMPDIR": BUILD_DIR,
        "PATH": "/path-not-set",
    }
)


def program_environment(command: Command) -> dict[str, str]:
    """Return the environment of ``command``'s program, sorted by name.

    Raises InvalidCommand if ``env`` sets a fixed variable or holds a name
    or value that execve cannot pass.
    """
    result: dict[str, str] = {}
    for name, value in command.env.items():
        if name in FIXED_VARIABLES:
            raise InvalidCommand(f"{command.name}: env sets {name}, which the sandbox fixes")
        if not name or "=" in name or "\0" in name or "\0" in value:
            raise InvalidCommand(
                f"{command.name}: env variable {name!r} cannot be passed to a program"
            )
        result[name] = value
    result.update(FIXED_VARIABLES)
    return dict(sorted(result.items()))
