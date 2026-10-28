# SPDX-License-Identifier: GPL-2.0
"""The cloche command, with the sandbox replaced where it would run."""

import json
import subprocess
from pathlib import Path

import pytest

from cloche import Command, Limits, Outcome, RunFailed, cli

CONFIG = ["oci-config", "--bind", "/usr:/tools", "--dir", "/out", "--output", "out=/out/x"]


@pytest.fixture(autouse=True)
def x86_64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cloche.cli.libc.machine", lambda: "x86_64")


def test_oci_config(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(
        [*CONFIG, "--env", "A=1=2", "--max-open-files", "64", "/tools/bin/sh", "-c", "x"]
    )
    assert code == 0
    config = json.loads(capsys.readouterr().out)
    assert config["process"]["args"] == ["/tools/bin/sh", "-c", "x"]
    assert "A=1=2" in config["process"]["env"]
    assert {"type": "RLIMIT_NOFILE", "hard": 64, "soft": 64} in config["process"]["rlimits"]
    tools = next(m for m in config["mounts"] if m["destination"] == "/tools")
    assert tools["source"] == "/usr"


def test_bind_without_destination(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["oci-config", "--bind", "/usr", "/usr/bin/true"]) == 0
    mounts = json.loads(capsys.readouterr().out)["mounts"]
    assert {"/usr"} == {m["source"] for m in mounts if m["destination"] == "/usr"}


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["/bin/sh"], "cloche: sh: program /bin/sh is not inside any bind"),
        (["--bind", "usr", "/usr/bin/sh"], "cloche: source: Value error, 'usr' is not"),
        (["--bind", "/usr", "--output", "o=/elsewhere", "/usr/bin/sh"], "below /build"),
        (["--bind", "/usr", "--timeout", "0", "/usr/bin/sh"], "cloche: timeout: "),
    ],
)
def test_invalid_command(argv: list[str], message: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["oci-config", *argv]) == 1
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("option", ["--env", "--output"])
def test_usage_error(option: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["oci-config", option, "novalue", "/bin/sh"])
    assert info.value.code == 2
    assert "must be written NAME=" in capsys.readouterr().err


def test_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_run(
        command: Command, work: str, limits: Limits, *, backend: object, on_log: object
    ) -> Outcome:
        seen.update(command=command, work=work, limits=limits, backend=backend)
        return Outcome(outputs={"out": f"{work}/out/out"}, log=f"{work}/run.log", seconds=0.1)

    monkeypatch.setattr("cloche.cli.select_backend", lambda name: f"backend {name}")
    monkeypatch.setattr("cloche.cli.run", fake_run)
    argv = ["run", "--work", str(tmp_path), "--name", "greet", "--timeout", "5"]
    assert (
        cli.main(
            [*argv, "--bind", "/usr", "--dir", "/out", "--output", "out=/out/x", "/usr/bin/true"]
        )
        == 0
    )
    assert capsys.readouterr().out == f"out {tmp_path}/out/out\n"
    command = seen["command"]
    assert isinstance(command, Command)
    assert (command.name, command.program, command.args) == ("greet", "/usr/bin/true", ())
    assert seen["work"] == str(tmp_path)
    assert seen["limits"] == Limits(timeout=5)
    assert seen["backend"] == "backend namespaces"


def test_run_creates_the_named_work_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("cloche.cli.select_backend", lambda name: None)
    monkeypatch.setattr(
        "cloche.cli.run", lambda *args, **kwargs: Outcome(outputs={}, log="", seconds=0)
    )
    work = tmp_path / "a/b"
    assert cli.main(["run", "--work", str(work), "--bind", "/usr", "/usr/bin/true"]) == 0
    assert work.is_dir()


def test_run_makes_a_work_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    works: list[str] = []

    def fake_run(command: Command, work: str, *args: object, **kwargs: object) -> Outcome:
        works.append(work)
        return Outcome(outputs={}, log=f"{work}/run.log", seconds=0)

    monkeypatch.setattr("cloche.cli.select_backend", lambda name: None)
    monkeypatch.setattr("cloche.cli.run", fake_run)
    assert cli.main(["run", "--bind", "/usr", "/usr/bin/true"]) == 0
    work = Path(works[0])
    assert work.name.startswith("cloche-")
    assert work.is_dir()
    work.rmdir()


def test_run_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*args: object, **kwargs: object) -> Outcome:
        raise RunFailed("true: the program exited with status 1")

    monkeypatch.setattr("cloche.cli.select_backend", lambda name: None)
    monkeypatch.setattr("cloche.cli.run", failing)
    assert cli.main(["run", "--work", str(tmp_path), "--bind", "/usr", "/usr/bin/true"]) == 1
    assert capsys.readouterr().err == "cloche: true: the program exited with status 1\n"


def test_run_os_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*args: object, **kwargs: object) -> Outcome:
        raise FileExistsError(17, "File exists", str(tmp_path))

    monkeypatch.setattr("cloche.cli.select_backend", lambda name: None)
    monkeypatch.setattr("cloche.cli.run", failing)
    assert cli.main(["run", "--work", str(tmp_path), "--bind", "/usr", "/usr/bin/true"]) == 1
    assert capsys.readouterr().err == f"cloche: {tmp_path}: File exists\n"


def test_run_unknown_backend(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run", "--backend", "chroot", "--bind", "/usr", "/usr/bin/true"]) == 1
    assert "no sandbox backend called chroot" in capsys.readouterr().err


def test_status(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def failed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, "", "PermissionError: denied\n")

    monkeypatch.setattr(subprocess, "run", failed)
    assert cli.main(["status"]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("namespaces: unprivileged user namespaces do not work")
    assert lines[1:] == [
        "oci: not available in this release",
        "microvm: not available in this release",
    ]
