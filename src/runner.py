# SPDX-License-Identifier: GPL-2.0
"""Runs one Command in the sandbox and supervises it.

run describes the sandbox, starts the backend and then waits. It writes
everything the program prints to ``<work_dir>/run.log``, passes each chunk
to ``on_log``, and kills the program when the wall-clock limit or the
silence limit runs out. When the program succeeds each output has been
copied to ``<work_dir>/out/<name>``.

When Limits set memory, CPU or process limits and the process runs in a
delegated cgroup, the run gets its own cgroup (cgroups.py). The
namespace helper joins it as it starts; the process of any other backend
is moved into it as soon as it starts. Removing the cgroup after the run
ends whatever the program left behind.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from . import cgroups, libc
from .errors import RunFailed
from .models import Command, Limits, Model
from .spec import HelperReport, SandboxJob, make_spec

if TYPE_CHECKING:
    from .backends import Backend

LOG_TAIL_LINES = 25


class Outcome(Model):
    """A finished run: the host path of each output, the log and the time taken.

    ``boot_seconds`` is the part of ``seconds`` a backend spent booting a
    machine, and None for a backend that boots nothing.
    """

    outputs: dict[str, str]
    log: str
    seconds: float
    boot_seconds: float | None = None


def _tail(log: Path) -> str:
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-LOG_TAIL_LINES:])


def _supervise(
    process: subprocess.Popen[bytes],
    readers: set[int],
    log_read: int,
    log: Path,
    limits: Limits,
    on_log: Callable[[str], object] | None,
    started: float,
) -> tuple[list[HelperReport], str | None]:
    """Copy the log and read reports until the helper closes both pipes.

    Closes each pipe in ``readers`` at its end of file and removes it.
    Returns the reports and, if a time limit ended the run, the reason.
    """
    reports: list[HelperReport] = []
    timed_out: str | None = None
    status_buffer = b""
    last_output = started
    with selectors.DefaultSelector() as selector, log.open("wb") as log_file:
        for fd in readers:
            selector.register(fd, selectors.EVENT_READ)
        while selector.get_map():
            now = time.monotonic()
            deadlines = []
            if timed_out is None and limits.timeout is not None:
                deadlines.append((started + limits.timeout, f"timed out after {limits.timeout} s"))
            if timed_out is None and limits.max_silent_time is not None:
                deadlines.append(
                    (
                        last_output + limits.max_silent_time,
                        f"printed nothing for {limits.max_silent_time} s",
                    )
                )
            expired = [reason for deadline, reason in deadlines if deadline <= now]
            if expired:
                # The program is PID 1 of its namespace and dies with the
                # helper, so killing the helper ends the whole run.
                timed_out = expired[0]
                process.kill()
                continue
            wait = min((deadline for deadline, _ in deadlines), default=None)
            for key, _ in selector.select(None if wait is None else max(wait - now, 0)):
                fd = int(key.fd)
                chunk = os.read(fd, 65536)
                if not chunk:
                    selector.unregister(fd)
                    readers.discard(fd)
                    os.close(fd)
                elif fd == log_read:
                    last_output = time.monotonic()
                    log_file.write(chunk)
                    log_file.flush()
                    if on_log is not None:
                        on_log(chunk.decode("utf-8", errors="replace"))
                else:
                    status_buffer += chunk
                    *lines, status_buffer = status_buffer.split(b"\n")
                    for line in lines:
                        try:
                            reports.append(HelperReport.model_validate_json(line))
                        except ValidationError:
                            continue
    return reports, timed_out


def _move(process: subprocess.Popen[bytes], cgroup: str) -> None:
    """Move the backend's process into ``cgroup`` unless it has exited."""
    try:
        with open(os.path.join(cgroup, "cgroup.procs"), "w", encoding="ascii") as file:
            file.write(str(process.pid))
    except ProcessLookupError:
        pass


def run(
    command: Command,
    work_dir: str,
    limits: Limits | None = None,
    *,
    backend: Backend | None = None,
    on_log: Callable[[str], object] | None = None,
) -> Outcome:
    """Run ``command`` in the sandbox.

    ``work_dir`` is an empty directory that receives the sandbox root, the
    copied outputs and ``run.log``. The namespace backend is used unless
    ``backend`` is given.

    Raises InvalidCommand before anything starts if the command breaks a
    rule, RunFailed, with the end of the log, when the program fails or
    runs out of time, and SandboxUnavailable when the backend cannot run
    here. If anything else raises, the program is stopped first.
    """
    limits = limits if limits is not None else Limits()
    if backend is None:
        from .namespaces import NamespaceBackend

        backend = NamespaceBackend()
    spec = make_spec(command, limits, uid=os.getuid(), gid=os.getgid(), machine=libc.machine())
    work = Path(work_dir)
    root, out_dir, log = work / "root", work / "out", work / "run.log"
    root.mkdir(mode=0o700)
    out_dir.mkdir(mode=0o700)
    cgroup = cgroups.create(limits)
    job = SandboxJob(
        spec=spec, root=str(root), out_dir=str(out_dir), parent_pid=os.getpid(), cgroup=cgroup
    )
    started = time.monotonic()
    log_read, log_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    readers = {log_read, status_read}
    process: subprocess.Popen[bytes] | None = None
    try:
        try:
            process = backend.start(job, status_fd=status_write, log_fd=log_write)
            if cgroup is not None:
                _move(process, cgroup)
        finally:
            os.close(log_write)
            os.close(status_write)
        reports, timed_out = _supervise(process, readers, log_read, log, limits, on_log, started)
        exit_status = process.wait()
    finally:
        for fd in readers:
            os.close(fd)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if cgroup is not None:
            cgroups.remove(cgroup)
    seconds = time.monotonic() - started
    final = reports[-1] if reports and reports[-1].kind != "started" else None
    if timed_out is not None:
        reason = timed_out
    elif final is None:
        reason = f"the sandbox helper exited with status {exit_status} and no report"
    elif final.kind == "failed":
        reason = final.error or "the program failed"
    else:
        outputs = {name: str(out_dir / name) for name in spec.outputs}
        return Outcome(
            outputs=outputs, log=str(log), seconds=seconds, boot_seconds=final.boot_seconds
        )
    tail = _tail(log)
    raise RunFailed(
        f"{command.name}: {reason}" + (f"\nlast lines of the log:\n{tail}" if tail else "")
    )
