# SPDX-License-Identifier: GPL-2.0
"""The OCI backend.

OciBackend.start runs this module in a fresh interpreter, the helper,
with an OciRun as JSON on stdin. The helper gives the configuration of
spec.oci_config to a rootless OCI runtime, crun, runc or youki, with no
daemon and no image:

1. The bundle is a directory beside ``job.root``, and ``job.root`` is
   the container's root. A tmpfs that holds an output becomes a bind of
   a directory of that root onto itself, with the same options, so the
   outputs are still on the host when the container is gone.
2. The helper becomes a child subreaper and runs ``create``, so the
   container's PID 1 becomes its child when the runtime exits. It then
   runs ``start`` and waits for that PID 1.
3. A watchdog, started before ``create``, waits on a pipe and runs
   ``delete --force`` when the pipe closes. The runner stops a run by
   killing the helper, which closes the pipe, so the container never
   outlives its helper.
4. On success, each output is copied out with namespaces.copy_out.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING, BinaryIO

from . import libc
from .models import Model, is_below
from .namespaces import copy_out
from .spec import HelperReport, Mount, SandboxJob, SandboxSpec, oci_config

if TYPE_CHECKING:
    from .probe import BackendStatus

RUNTIMES: tuple[str, ...] = ("crun", "runc", "youki")
"""The runtimes searched for in PATH, in order."""

PR_SET_CHILD_SUBREAPER = 36


class OciRun(Model):
    """What OciBackend.start passes to the helper."""

    job: SandboxJob
    runtime: str


def find_runtime(runtime: str | None = None) -> str | None:
    """Return the path of ``runtime``, or of the first of RUNTIMES in PATH."""
    if runtime is not None:
        if os.sep in runtime:
            return runtime if os.access(runtime, os.X_OK) else None
        return shutil.which(runtime)
    for name in RUNTIMES:
        found = shutil.which(name)
        if found is not None:
            return found
    return None


def oci_status(runtime: str | None = None) -> BackendStatus:
    """Test whether the OCI backend can run with ``runtime``.

    A rootless runtime needs what the namespace backend needs, so that is
    tested first, then that the runtime starts.
    """
    from .probe import BackendStatus, namespaces_status

    name = "oci"
    path = find_runtime(runtime)
    if path is None:
        wanted = runtime or " or ".join(RUNTIMES)
        return BackendStatus(name=name, available=False, reason=f"{wanted} is not installed")
    userns = namespaces_status()
    if not userns.available:
        return BackendStatus(name=name, available=False, reason=userns.reason)
    try:
        subprocess.run(  # noqa: S603
            [path, "--version"], capture_output=True, check=True, timeout=30, env={}
        )
    except (OSError, subprocess.SubprocessError) as error:
        return BackendStatus(name=name, available=False, reason=f"{path} does not run: {error}")
    return BackendStatus(name=name, available=True)


def container_spec(job: SandboxJob) -> SandboxSpec:
    """Return ``job.spec`` adjusted for an OCI runtime.

    Each tmpfs that holds an output becomes a bind of a directory created
    under ``job.root``, so the outputs stay on the host. A bind whose
    source is a symbolic link becomes the same link in ``job.root``, as in
    the namespace backend, since a runtime would follow it.
    """
    spec = job.spec
    mounts: list[Mount] = []
    for mount in spec.mounts:
        if mount.kind == "bind" and mount.source is not None and os.path.islink(mount.source):
            target = job.root + mount.destination
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            os.symlink(os.readlink(mount.source), target)
            continue
        holds_output = any(is_below(path, mount.destination) for path in spec.outputs.values())
        if mount.kind != "tmpfs" or not holds_output:
            mounts.append(mount)
            continue
        source = job.root + mount.destination
        os.makedirs(source, mode=0o755, exist_ok=True)
        os.chmod(source, 0o755)  # noqa: S103
        options = tuple(option for option in mount.options if "=" not in option)
        mounts.append(
            Mount(destination=mount.destination, kind="bind", source=source, options=options)
        )
    return spec.model_copy(update={"mounts": tuple(mounts)})


def bundle_config(job: SandboxJob) -> str:
    """Return the ``config.json`` of the container that runs ``job``."""
    config = oci_config(container_spec(job))
    config = config.model_copy(update={"root": config.root.model_copy(update={"path": job.root})})
    return config.model_dump_json(indent=2)


class OciBackend:
    """Runs programs with a rootless OCI runtime."""

    name = "oci"

    def __init__(self, runtime: str | None = None):
        """Use ``runtime``, a name or path, or the first of RUNTIMES found."""
        self.runtime = runtime

    def status(self) -> BackendStatus:
        """Test whether this machine can run the backend."""
        return oci_status(self.runtime)

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        """Start the helper for ``job``, as NamespaceBackend.start does."""
        runtime = find_runtime(self.runtime) or self.runtime or RUNTIMES[0]
        payload = OciRun(job=job, runtime=runtime)
        process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-I", "-c", _HELPER, str(status_fd)],
            stdin=subprocess.PIPE,
            stdout=log_fd,
            stderr=log_fd,
            env={},
            pass_fds=(status_fd,),
            start_new_session=True,
        )
        assert process.stdin is not None  # noqa: S101
        try:
            process.stdin.write(payload.model_dump_json().encode())
            process.stdin.close()
        except BrokenPipeError:
            pass
        return process


def _report(stream: BinaryIO, report: HelperReport) -> None:
    stream.write(report.model_dump_json().encode() + b"\n")
    stream.flush()


def _describe(status: int) -> str:
    if os.WIFSIGNALED(status):
        return f"the program was killed by signal {os.WTERMSIG(status)}"
    return f"the program exited with status {os.waitstatus_to_exitcode(status)}"


def _runtime(run: OciRun, state: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [run.runtime, "--root", state, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )


def _failure(result: subprocess.CompletedProcess[str], what: str) -> HelperReport:
    lines = result.stderr.strip().splitlines()
    detail = lines[-1] if lines else f"exit status {result.returncode}"
    return HelperReport(kind="failed", error=f"sandbox setup failed: {what}: {detail}")


def _wait(pid: int) -> int:
    """Wait for the container's PID 1, a child once the runtime exits."""
    return os.waitpid(pid, 0)[1]


def _contain(run: OciRun, report: BinaryIO, bundle: str, state: str, name: str) -> HelperReport:
    job = run.job
    pid_file, log = os.path.join(bundle, "pid"), os.path.join(bundle, "runtime.log")
    # The container takes the runtime's stdout and stderr, which are the
    # log, so the runtime's own messages go to a file of their own.
    created = subprocess.run(  # noqa: S603
        [run.runtime, "--root", state, "--log", log, "create"]
        + ["--bundle", bundle, "--pid-file", pid_file, name],
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if created.returncode != 0:
        try:
            with open(log, encoding="utf-8", errors="replace") as file:
                detail = file.read()
        except FileNotFoundError:
            detail = ""
        result = subprocess.CompletedProcess(created.args, created.returncode, "", detail)
        return _failure(result, "the runtime cannot create the container")
    with open(pid_file, encoding="ascii") as file:
        pid = int(file.read().strip())
    _report(report, HelperReport(kind="started", pid=pid))
    started = _runtime(run, state, "start", name)
    if started.returncode != 0:
        return _failure(started, "the runtime cannot start the container")
    status = _wait(pid)
    if status != 0:
        return HelperReport(kind="failed", error=_describe(status))
    for output, path in job.spec.outputs.items():
        destination = os.path.join(job.out_dir, output)
        try:
            copy_out(job.root, path, destination)
        except FileNotFoundError:
            return HelperReport(
                kind="failed", error=f"the program did not create output {output} ({path})"
            )
        except (OSError, ValueError) as error:
            return HelperReport(kind="failed", error=f"cannot copy output {output}: {error}")
    return HelperReport(kind="finished")


def _run(run: OciRun, report: BinaryIO) -> HelperReport:
    libc.prctl(libc.PR_SET_PDEATHSIG, 9)
    if os.getppid() != run.job.parent_pid:
        return HelperReport(kind="failed", error="the supervisor exited")
    libc.prctl(PR_SET_CHILD_SUBREAPER, 1)
    work = os.path.dirname(run.job.root)
    bundle, state = os.path.join(work, "bundle"), os.path.join(work, "state")
    os.mkdir(bundle, 0o700)
    os.mkdir(state, 0o700)
    with open(os.path.join(bundle, "config.json"), "w", encoding="utf-8") as file:
        file.write(bundle_config(run.job))
    name = f"cloche-{os.getpid()}-{secrets.token_hex(4)}"
    alive_read, alive_write = os.pipe2(os.O_CLOEXEC)
    watchdog = subprocess.Popen(  # noqa: S603
        [
            "/bin/sh",
            "-c",
            'read _ ; exec "$0" --root "$1" delete --force "$2"',
            run.runtime,
            state,
            name,
        ],
        stdin=alive_read,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    os.close(alive_read)
    try:
        return _contain(run, report, bundle, state, name)
    finally:
        os.close(alive_write)
        watchdog.wait()


_HELPER = f"import sys; from {__name__} import main; sys.exit(main(sys.argv))"
"""The helper's program. ``-m`` would warn, since the package imports this module."""


def main(argv: list[str]) -> int:
    """Run one program in a container. ``argv[1]`` is the status pipe."""
    with os.fdopen(int(argv[1]), "wb") as report:
        try:
            run = OciRun.model_validate_json(sys.stdin.buffer.read())
            result = _run(run, report)
        except OSError as error:
            text = f"sandbox setup failed: {error.strerror or error}"
            if error.filename:
                text += f" ({error.filename})"
            result = HelperReport(kind="failed", error=text)
        except Exception as error:
            result = HelperReport(kind="failed", error=f"sandbox setup failed: {error}")
        _report(report, result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))


__all__ = ["RUNTIMES", "OciBackend", "OciRun", "bundle_config", "find_runtime", "oci_status"]
