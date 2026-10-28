# SPDX-License-Identifier: GPL-2.0
"""Supervising a run with a stand-in backend.

FakeBackend runs a small Python program instead of the sandbox helper,
so log capture, reports and time limits are tested on any machine.
"""

import os
import resource
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from cloche import Bind, Command, Limits, RunFailed, SandboxJob, run
from cloche.namespaces import copy_out

SCRIPT = """
import json, os, sys, time
fd, mode = int(sys.argv[1]), sys.argv[2]
def report(**fields):
    os.write(fd, (json.dumps(fields) + "\\n").encode())
report(kind="started", pid=os.getpid())
os.write(fd, b"not json\\n")
print("running", flush=True)
if mode == "finished":
    report(kind="finished")
elif mode == "failed":
    report(kind="failed", error="the program exited with status 2")
elif mode == "silent":
    time.sleep(30)
elif mode == "chatty":
    while True:
        print("tick", flush=True)
        time.sleep(0.05)
else:
    sys.exit(3)
"""

COMMAND = Command(
    name="hello",
    program="/tools/bin/sh",
    binds=(Bind(source="/usr", destination="/tools"),),
    outputs={"out": "/build/out"},
)


class FakeBackend:
    name = "fake"

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.job: SandboxJob | None = None

    def status(self) -> object:
        raise AssertionError("not called")

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        self.job = job
        return subprocess.Popen(
            [sys.executable, "-c", SCRIPT, str(status_fd), self.mode],
            stdout=log_fd,
            stderr=log_fd,
            pass_fds=(status_fd,),
        )


def start(tmp_path: Path, mode: str, **limits: int) -> tuple[FakeBackend, object]:
    backend = FakeBackend(mode)
    seen: list[str] = []
    try:
        outcome: object = run(
            COMMAND,
            str(tmp_path),
            Limits.model_validate(limits),
            backend=backend,  # type: ignore[arg-type]
            on_log=seen.append,
        )
    except RunFailed as error:
        outcome = error
    assert "".join(seen).startswith("running\n")
    return backend, outcome


def test_exception_stops_the_run(tmp_path: Path) -> None:
    backend = FakeBackend("chatty")

    def on_log(text: str) -> None:
        raise RuntimeError("client went away")

    processes: list[subprocess.Popen[bytes]] = []
    start = backend.start

    def recording_start(job: SandboxJob, **fds: int) -> subprocess.Popen[bytes]:
        processes.append(start(job, **fds))
        return processes[-1]

    backend.start = recording_start  # type: ignore[method-assign]
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(RuntimeError, match="client went away"):
        run(COMMAND, str(tmp_path), backend=backend, on_log=on_log)  # type: ignore[arg-type]
    assert processes[0].poll() is not None
    assert set(os.listdir("/proc/self/fd")) == before


def test_finished(tmp_path: Path) -> None:
    backend, outcome = start(tmp_path, "finished")
    assert not isinstance(outcome, RunFailed)
    assert outcome.outputs == {"out": str(tmp_path / "out" / "out")}  # type: ignore[attr-defined]
    assert Path(outcome.log) == tmp_path / "run.log"  # type: ignore[attr-defined]
    assert Path(outcome.log).read_text(encoding="utf-8") == "running\n"  # type: ignore[attr-defined]
    assert backend.job is not None
    assert backend.job.root == str(tmp_path / "root")
    assert backend.job.spec.mounts[-1].destination == "/dev/shm"  # noqa: S108


def test_failed_report(tmp_path: Path) -> None:
    _, outcome = start(tmp_path, "failed")
    assert isinstance(outcome, RunFailed)
    assert str(outcome) == (
        "hello: the program exited with status 2\nlast lines of the log:\nrunning"
    )


def test_no_report(tmp_path: Path) -> None:
    _, outcome = start(tmp_path, "crash")
    assert "exited with status 3 and no report" in str(outcome)


def test_timeout(tmp_path: Path) -> None:
    _, outcome = start(tmp_path, "chatty", timeout=1)
    assert "timed out after 1 s" in str(outcome)


def test_silence(tmp_path: Path) -> None:
    _, outcome = start(tmp_path, "silent", max_silent_time=1, timeout=60)
    assert "printed nothing for 1 s" in str(outcome)


def test_work_dir_must_be_empty(tmp_path: Path) -> None:
    (tmp_path / "root").mkdir()
    with pytest.raises(FileExistsError):
        run(COMMAND, str(tmp_path), backend=FakeBackend("finished"))  # type: ignore[arg-type]


def test_copy_out_holds_few_descriptors(tmp_path: Path) -> None:
    output = tmp_path / "root/store/abc-many"
    for index in range(300):
        leaf = output / f"d{index}" / "sub"
        leaf.mkdir(parents=True)
        (leaf / "file").write_text(str(index), encoding="utf-8")
    deep = output / "deep"
    for _ in range(20):
        deep /= "x"
    deep.mkdir(parents=True)
    (output / "d0").chmod(0o555)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (len(os.listdir("/proc/self/fd")) + 64, hard))
    try:
        copy_out(str(tmp_path / "root"), "/store/abc-many", str(tmp_path / "copy"))
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    copy = tmp_path / "copy"
    assert (copy / "d299/sub/file").read_text(encoding="utf-8") == "299"
    assert (copy / "deep").joinpath(*["x"] * 20).is_dir()
    assert stat.S_IMODE((copy / "d0").stat().st_mode) == 0o555
