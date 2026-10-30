# SPDX-License-Identifier: GPL-2.0
"""Cgroup limits of a run, on a directory tree that stands in for cgroupfs.

A real delegated cgroup needs a service manager; the kernel side was
checked by hand in a scope with Delegate=yes.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cloche import Bind, Command, Limits, SandboxJob, SandboxUnavailable, cgroups, cli, run


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A delegated cgroup ``service`` holding two processes, as cgroupfs files."""
    base = tmp_path / "cg" / "system.slice" / "lattice.service"
    base.mkdir(parents=True)
    (base / "cgroup.controllers").write_text("cpu io memory pids\n")
    (base / "cgroup.subtree_control").write_text("\n")
    (base / "cgroup.procs").write_text("11\n12\n")
    self_file = tmp_path / "self"
    self_file.write_text("0::/system.slice/lattice.service\n")
    monkeypatch.setattr(cgroups, "ROOT", str(tmp_path / "cg"))
    monkeypatch.setattr(cgroups, "SELF", str(self_file))
    monkeypatch.setattr(cgroups, "_delegated", lambda path: path == str(base))
    monkeypatch.setattr(cgroups, "_remove_directory", shutil.rmtree)
    return base


class FakeCgroupfs:
    """Makes writes to cgroup.procs move pids and mkdir create interface files."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.real_mkdir = os.mkdir

    def mkdir(self, path: str, mode: int = 0o777) -> None:
        self.real_mkdir(path, mode)
        for name in ("cgroup.procs", "memory.max", "memory.swap.max", "cpu.max", "pids.max"):
            Path(path, name).write_text("")


def test_limits_validate() -> None:
    assert not cgroups.wanted(Limits())
    assert cgroups.wanted(Limits(max_cpu=1.5))
    with pytest.raises(ValueError, match="greater than or equal"):
        Limits(max_memory=1024)
    with pytest.raises(ValueError, match="greater than or equal"):
        Limits(max_processes=1)


def test_status(tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert cgroups.status() == cgroups.CgroupStatus(available=True, path=str(tree))
    (tmp_path / "self").write_text("0::/system.slice/lattice.service/supervisor\n")
    assert cgroups.status().path == str(tree)
    (tree / "cgroup.controllers").write_text("cpu io\n")
    assert cgroups.status().reason.endswith("lacks the controllers memory, pids")
    (tree / "cgroup.controllers").unlink()
    assert "No such file" in cgroups.status().reason
    (tmp_path / "self").write_text("0::/user.slice\n")
    assert "is not delegated; run under a service with Delegate=yes" in cgroups.status().reason
    (tmp_path / "self").write_text("1:name=systemd:/\n")
    assert cgroups.status().reason == "cgroup version 2 is not in use"
    monkeypatch.setattr(cgroups, "SELF", str(tmp_path / "none"))
    assert not cgroups.status().available


def test_delegate_attribute(tmp_path: Path) -> None:
    assert not cgroups._delegated(str(tmp_path))
    try:
        os.setxattr(tmp_path, "user.delegate", b"1")
    except OSError:
        pytest.skip("the file system has no user extended attributes")
    assert cgroups._delegated(str(tmp_path))


def test_create_and_remove(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "mkdir", FakeCgroupfs(tree).mkdir)
    assert cgroups.create(Limits()) is None
    path = cgroups.create(Limits(max_memory=64 << 20, max_cpu=1.5, max_processes=32))
    assert path is not None
    assert Path(path).parent == tree
    assert Path(path).name.startswith("cloche-")
    assert (tree / "supervisor" / "cgroup.procs").read_text() == "12"
    assert (tree / "cgroup.subtree_control").read_text() == "+cpu +memory +pids"
    assert Path(path, "memory.max").read_text() == str(64 << 20)
    assert Path(path, "memory.swap.max").read_text() == "0"
    assert Path(path, "cpu.max").read_text() == "150000 100000"
    assert Path(path, "pids.max").read_text() == "32"
    cgroups.join(path)
    assert Path(path, "cgroup.procs").read_text() == "0"
    (tree / "cgroup.subtree_control").write_text("cpu memory pids\n")
    second = cgroups.create(Limits(max_cpu=0.01))
    assert second is not None
    assert Path(second, "cpu.max").read_text() == "1000 100000"
    assert Path(second, "memory.max").read_text() == ""
    Path(path, "cgroup.kill").write_text("")
    cgroups.remove(path)
    assert not os.path.exists(path)
    cgroups.remove(path)


def test_remove_kills_without_cgroup_kill(
    tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    path = tree / "cloche-x"
    path.mkdir()
    (path / "cgroup.procs").write_text(f"{child.pid}\n999999999\n")
    busy = [OSError(16, "busy"), None]

    def remove_directory(target: str) -> None:
        error = busy.pop(0)
        if error is not None:
            raise error
        shutil.rmtree(target)

    monkeypatch.setattr(cgroups, "_remove_directory", remove_directory)
    cgroups.remove(str(path))
    assert child.wait(5) == -9
    assert not path.exists()


def test_remove_gives_up(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tree / "cloche-y"
    path.mkdir()
    (path / "cgroup.kill").write_text("")

    def busy(target: str) -> None:
        raise OSError(16, "busy")

    monkeypatch.setattr(cgroups, "_remove_directory", busy)
    monkeypatch.setattr(cgroups, "REMOVE_SECONDS", 0.1)
    cgroups.remove(str(path))
    assert path.exists()
    assert (path / "cgroup.kill").read_text() == "1"


def test_create_failure(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_mkdir = os.mkdir

    def no_space(path: str, mode: int = 0o777) -> None:
        real_mkdir(path, mode)
        if os.path.basename(path).startswith("cloche-"):
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "mkdir", no_space)
    with pytest.raises(SandboxUnavailable, match="cannot set up the cgroup of the run"):
        cgroups.create(Limits(max_processes=8))
    assert [p.name for p in tree.iterdir() if p.name.startswith("cloche-")] == []


def test_no_delegation_means_no_cgroup(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cgroups, "_delegated", lambda path: False)
    assert cgroups.create(Limits(max_processes=8)) is None


class RecordingBackend:
    name = "recording"

    def __init__(self) -> None:
        self.job: SandboxJob | None = None

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        self.job = job
        script = (
            "import json, os, sys\n"
            "fd = int(sys.argv[1])\n"
            "os.write(fd, (json.dumps({'kind': 'started', 'pid': os.getpid()}) + '\\n').encode())\n"
            'os.write(fd, b\'{"kind": "finished"}\\n\')\n'
        )
        return subprocess.Popen(
            [sys.executable, "-c", script, str(status_fd)], pass_fds=(status_fd,)
        )


def test_run_uses_the_cgroup(tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "mkdir", FakeCgroupfs(tree).mkdir)
    removed: list[str] = []
    monkeypatch.setattr("cloche.runner.cgroups.remove", removed.append)
    backend = RecordingBackend()
    command = Command(
        name="c", program="/tools/x", binds=(Bind(source="/usr", destination="/tools"),)
    )
    run(command, str(tmp_path), Limits(max_processes=8), backend=backend)  # type: ignore[arg-type]
    assert backend.job is not None and backend.job.cgroup is not None
    assert removed == [backend.job.cgroup]
    assert Path(backend.job.cgroup, "cgroup.procs").read_text().isdigit()


def test_cli_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Limits] = []

    def fake_run(command: Command, work: str, limits: Limits, **kwargs: object) -> object:
        seen.append(limits)
        raise SandboxUnavailable("stop")

    monkeypatch.setattr(cli, "run", fake_run)
    argv = ["run", "--max-memory", "64", "--max-cpu", "0.5", "--max-processes", "9"]
    cli.main([*argv, "--bind", "/usr", "/usr/bin/true"])
    assert (seen[0].max_memory, seen[0].max_cpu, seen[0].max_processes) == (64 << 20, 0.5, 9)
