# SPDX-License-Identifier: GPL-2.0
"""The ``cloche`` command.

Usage::

    cloche run [--backend NAME] [BACKEND OPTIONS] [OPTIONS] PROGRAM [ARG ...]
    cloche oci-config [OPTIONS] PROGRAM [ARG ...]
    cloche status [BACKEND OPTIONS]
    cloche guest-init OUTPUT

``run`` runs PROGRAM in the sandbox, streams its log to stderr and, when
it succeeds, prints one line per output: its name and the host path it
was copied to. ``oci-config`` prints the OCI runtime configuration of the
same sandbox instead of running it. ``status`` prints whether each
backend can run here, and whether runs get their own cgroup, and exits
with 1 if no backend can run. ``guest-init``
compiles the guest init of the microVM backend, statically, to OUTPUT.

``--backend`` is namespaces (the default), oci or microvm. BACKEND
OPTIONS configure the last two:

    --runtime NAME|PATH           OCI runtime; the first of crun, runc, youki by default
    --vmm NAME                    firecracker (default), cloud-hypervisor or openvmm
    --vmm-path PATH               the monitor's executable, if not in PATH
    --kernel PATH, --init PATH    guest kernel (vmlinux) and guest init
    --memory MIB, --cpus N        size of the virtual machine

OPTIONS build the Command and Limits of models.py:

    --bind SOURCE[:DESTINATION]   bind a host path read-only (repeatable)
    --dir PATH                    add an empty writable directory (repeatable)
    --output NAME=PATH            copy PATH out as NAME on success (repeatable)
    --env NAME=VALUE              set a variable (repeatable)
    --name NAME                   label for the log and errors
    --work DIR                    empty directory for the run, created if missing;
                                  a new temporary one by default
    --timeout SECONDS, --max-silent-time SECONDS, --max-open-files N
    --max-memory MIB, --max-cpu N, --max-processes N
                                  cgroup limits, applied in a delegated cgroup

Every option maps to a field of a model, so the command and the library
always behave the same way.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence

from pydantic import ValidationError

from . import libc
from .backends import select_backend
from .cgroups import status as cgroup_status
from .errors import ClocheError
from .microvm import MicroVMConfig, build_guest_init
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
        max_memory=args.max_memory * 1024 * 1024 if args.max_memory is not None else None,
        max_cpu=args.max_cpu,
        max_processes=args.max_processes,
    )


def _microvm(args: argparse.Namespace) -> MicroVMConfig:
    fields = {
        "vmm": args.vmm,
        "vmm_path": args.vmm_path,
        "kernel": args.kernel,
        "init": args.init,
        "memory_mib": args.memory,
        "cpus": args.cpus,
    }
    return MicroVMConfig.model_validate({k: v for k, v in fields.items() if v is not None})


def _backend_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime", metavar="NAME|PATH", help="OCI runtime")
    parser.add_argument("--vmm", help="firecracker, cloud-hypervisor or openvmm")
    parser.add_argument("--vmm-path", metavar="PATH", help="the monitor's executable")
    parser.add_argument("--kernel", metavar="PATH", help="guest kernel (vmlinux)")
    parser.add_argument("--init", metavar="PATH", help="guest init, see guest-init")
    parser.add_argument("--memory", type=int, metavar="MIB", help="guest memory in MiB")
    parser.add_argument("--cpus", type=int, metavar="N", help="guest processors")


def _command_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bind", action="append", default=[], metavar="SOURCE[:DESTINATION]")
    parser.add_argument("--dir", action="append", default=[], metavar="PATH")
    parser.add_argument("--output", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--name", help="label for the log and errors")
    parser.add_argument("--timeout", type=int, metavar="SECONDS")
    parser.add_argument("--max-silent-time", type=int, metavar="SECONDS")
    parser.add_argument("--max-open-files", type=int, default=1024, metavar="N")
    parser.add_argument("--max-memory", type=int, metavar="MIB")
    parser.add_argument("--max-cpu", type=float, metavar="N")
    parser.add_argument("--max-processes", type=int, metavar="N")
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
    run_parser.add_argument(
        "--backend", default="namespaces", help="namespaces (default), oci or microvm"
    )
    _backend_arguments(run_parser)
    _command_arguments(run_parser)
    run_parser.set_defaults(handler=cmd_run)
    config = commands.add_parser("oci-config", help="print the OCI configuration of a sandbox")
    _command_arguments(config)
    config.set_defaults(handler=cmd_oci_config)
    status = commands.add_parser("status", help="show which backends can run here")
    _backend_arguments(status)
    status.set_defaults(handler=cmd_status)
    guest = commands.add_parser("guest-init", help="compile the microVM guest init")
    guest.add_argument("output", help="path of the static executable to write")
    guest.set_defaults(handler=cmd_guest_init)
    return parser


def cmd_run(args: argparse.Namespace) -> int:
    """Run the program and print ``NAME PATH`` for each output. Return 0."""
    command, limits = _command(args), _limits(args)
    backend = select_backend(args.backend, runtime=args.runtime, microvm=_microvm(args))
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
    statuses = backend_status(runtime=args.runtime, microvm=_microvm(args))
    for status in statuses:
        print(f"{status.name}: {'available' if status.available else status.reason}")
    cgroup = cgroup_status()
    print(f"cgroups: {f'available in {cgroup.path}' if cgroup.available else cgroup.reason}")
    return 0 if any(status.available for status in statuses) else 1


def cmd_guest_init(args: argparse.Namespace) -> int:
    """Compile the guest init to ``args.output``. Return 0, or 1 if compiling fails."""
    try:
        build_guest_init(args.output)
    except subprocess.CalledProcessError as error:
        print(f"cloche: cannot compile the guest init:\n{error.stderr}", file=sys.stderr)
        return 1
    print(args.output)
    return 0


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
