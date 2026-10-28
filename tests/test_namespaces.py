# SPDX-License-Identifier: GPL-2.0
"""The parts of the namespace helper that run without a sandbox.

The helper itself runs in a child process during test_run.py, where
coverage does not follow it, so its reporting and error paths are
called directly here.
"""

import errno
import io
import os
import signal
from pathlib import Path

import pytest

from cloche import Bind, Command, SandboxJob, make_spec
from cloche import namespaces as helper
from cloche.spec import HelperReport

COMMAND = Command(
    name="t",
    program="/tools/bin/t",
    binds=(Bind(source="/usr", destination="/tools"),),
    outputs={"out": "/build/out"},
)


def job(tmp_path: Path, parent_pid: int) -> SandboxJob:
    spec = make_spec(COMMAND, uid=1000, gid=100, machine="x86_64")
    return SandboxJob(
        spec=spec, root=str(tmp_path / "root"), out_dir=str(tmp_path / "out"), parent_pid=parent_pid
    )


class Pipe(io.BytesIO):
    """A status pipe that keeps its contents after close."""

    def close(self) -> None:
        self.text = self.getvalue().decode()
        super().close()


def run_main(monkeypatch: pytest.MonkeyPatch, stdin: bytes) -> list[HelperReport]:
    pipe = Pipe()
    monkeypatch.setattr("cloche.namespaces.os.fdopen", lambda fd, mode: pipe)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin)))
    assert helper.main(["helper", "9"]) == 0
    return [HelperReport.model_validate_json(line) for line in pipe.text.splitlines()]


def test_describe() -> None:
    assert helper._describe(2 << 8) == "the program exited with status 2"
    assert helper._describe(signal.SIGKILL) == "the program was killed by signal 9"


def test_split_options() -> None:
    flags, data = helper._split_options(("nosuid", "nodev", "mode=755", "size=1m"))
    assert flags != 0
    assert data == "mode=755,size=1m"
    assert helper._split_options(()) == (0, None)


def test_main_rejects_a_bad_job(monkeypatch: pytest.MonkeyPatch) -> None:
    (report,) = run_main(monkeypatch, b"{}")
    assert report.kind == "failed"
    assert report.error is not None
    assert report.error.startswith("sandbox setup failed: ")


def test_main_reports_a_lost_supervisor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cloche.namespaces.libc.prctl", lambda *args: 0)
    data = job(tmp_path, parent_pid=os.getppid() + 1).model_dump_json().encode()
    (report,) = run_main(monkeypatch, data)
    assert report == HelperReport(kind="failed", error="the supervisor exited")


@pytest.mark.parametrize(
    ("error", "text"),
    [
        (OSError(errno.EPERM, "Operation not permitted", "/proc"), "(/proc); see cloche status"),
        (OSError(errno.ENOENT, "No such file or directory"), "No such file or directory"),
    ],
)
def test_main_explains_os_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: OSError, text: str
) -> None:
    def failing(*args: object) -> HelperReport:
        raise error

    monkeypatch.setattr("cloche.namespaces._run", failing)
    (report,) = run_main(monkeypatch, job(tmp_path, os.getppid()).model_dump_json().encode())
    assert report.error is not None
    assert report.error.startswith("sandbox setup failed: ")
    assert report.error.endswith(text)
