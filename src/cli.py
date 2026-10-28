# SPDX-License-Identifier: GPL-2.0
"""The ``cloche`` command.

Usage::

    cloche run [OPTIONS] PROGRAM [ARG ...]
    cloche oci-config [OPTIONS] PROGRAM [ARG ...]
    cloche status

``run`` runs PROGRAM in the sandbox, streams its log to stderr and, when
it succeeds, prints one line per output: its name and the host path it
was copied to. ``oci-config`` prints the OCI runtime configuration of the
same sandbox instead of running it. ``status`` prints whether each
backend can run here, and exits with 1 if none can.

OPTIONS build the Command and Limits of models.py:

    --bind SOURCE[:DESTINATION]   bind a host path read-only (repeatable)
    --dir PATH                    add an empty writable directory (repeatable)
    --output NAME=PATH            copy PATH out as NAME on success (repeatable)
    --env NAME=VALUE              set a variable (repeatable)
    --name NAME                   label for the log and errors
    --work DIR                    empty directory for the run, created if missing;
                                  a new temporary one by default
    --timeout SECONDS, --max-silent-time SECONDS, --max-open-files N

Every option maps to a field of a model, so the command and the library
always behave the same way.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence

from pydantic import ValidationError

from . import libc
from .backends import select_backend
from .errors import ClocheError
from .models import Bind, Command, Limits
from .probe import backend_status
from .runner import run
from .spec import make_spec, oci_config


class UsageError(Exception):
    """A command-line value that cannot be turned into a model field."""


def _pair(value: str, form: str) -> tuple[str, str]:
    key, found, rest = value.partition("=")
    if not found or not key:
        raise UsageError(f"{value!r} must be written {form}")
    return key, rest


def _bind(value: str) -> Bind:
    source, found, destination = value.partition(":")
    return Bind(source=source, destination=destination if found else source)


def _command(args: argparse.Namespace) -> Command:
    return Command(
        name=args.name or os.path.basename(args.program) or "program",
        program=args.program,
        args=tuple(args.args),
        env=dict(_pair(item, "NAME=VALUE") for item in args.env),
        binds=tuple(_bind(item) for item in args.bind),
        directories=tuple(args.dir),
        outputs=dict(_pair(item, "NAME=PATH") for item in args.output),
    )


def _limits(args: argparse.Namespace) -> Limits:
    return Limits(
        timeout=args.timeout,
        max_silent_time=args.max_silent_time,
        max_open_files=args.max_open_files,
    )


def _command_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bind", action="append", default=[], metavar="SOURCE[:DESTINATION]")
    parser.add_argument("--dir", action="append", default=[], metavar="PATH")
    parser.add_argument("--output", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--name", help="label for the log and errors")
    parser.add_argument("--timeout", type=int, metavar="SECONDS")
    parser.add_argument("--max-silent-time", type=int, metavar="SECONDS")
    parser.add_argument("--max-open-files", type=int, default=1024, metavar="N")
    parser.add_argument("program", help="absolute path of the program inside the sandbox")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments of the program")


def build_parser() -> argparse.ArgumentParser:
    """Return the parser of the ``cloche`` command."""
    parser = argparse.ArgumentParser(prog="cloche", description="Run a program in a sandbox.")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="run a program in the sandbox")
    run_parser.add_argument(
        "--work", metavar="DIR", help="empty directory for the run, created if missing"
    )
    run_parser.add_argument("--backend", default="namespaces", help="sandbox backend")
    _command_arguments(run_parser)
    run_parser.set_defaults(handler=cmd_run)
    config = commands.add_parser("oci-config", help="print the OCI configuration of a sandbox")
    _command_arguments(config)
    config.set_defaults(handler=cmd_oci_config)
    status = commands.add_parser("status", help="show which backends can run here")
    status.set_defaults(handler=cmd_status)
    return parser


def cmd_run(args: argparse.Namespace) -> int:
    """Run the program and print ``NAME PATH`` for each output. Return 0."""
    command, limits = _command(args), _limits(args)
    backend = select_backend(args.backend)
    if args.work is None:
        work = tempfile.mkdtemp(prefix="cloche-")
    else:
        work = args.work
        os.makedirs(work, mode=0o700, exist_ok=True)
    outcome = run(command, work, limits, backend=backend, on_log=sys.stderr.write)
    for name, path in outcome.outputs.items():
        print(name, path)
    return 0


def cmd_oci_config(args: argparse.Namespace) -> int:
    """Print the OCI runtime configuration of the sandbox as JSON. Return 0."""
    spec = make_spec(
        _command(args),
        _limits(args),
        uid=os.getuid(),
        gid=os.getgid(),
        machine=libc.machine(),
    )
    print(oci_config(spec).model_dump_json(indent=2))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Print one line per backend. Return 1 if no backend can run."""
    statuses = backend_status()
    for status in statuses:
        print(f"{status.name}: {'available' if status.available else status.reason}")
    return 0 if any(status.available for status in statuses) else 1


def _validation_message(error: ValidationError) -> str:
    first = error.errors()[0]
    where = ".".join(str(part) for part in first["loc"])
    return f"{where}: {first['msg']}" if where else first["msg"]


def main(argv: Sequence[str] | None = None) -> int:
    """Parse ``argv``, run the selected subcommand and return its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except UsageError as error:
        parser.error(str(error))
    except ValidationError as error:
        print(f"cloche: {_validation_message(error)}", file=sys.stderr)
        return 1
    except ClocheError as error:
        print(f"cloche: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        reason = error.strerror or str(error)
        where = error.filename
        print(f"cloche: {where}: {reason}" if where else f"cloche: {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
