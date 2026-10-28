# SPDX-License-Identifier: GPL-2.0
"""Runs in the namespace backend.

The program is sandbox_probe.c, linked statically so it needs nothing
from the sandbox. The tests are skipped where unprivileged user
namespaces or static linking are not available.
"""

import errno
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from cloche import FIXED_VARIABLES, Bind, Command, Limits, Outcome, RunFailed, run
from cloche.probe import namespaces_status

pytestmark = pytest.mark.requires_userns

TOOLS = "/tools"
PROBE = f"{TOOLS}/bin/probe"
OUT = "/out/result"


@pytest.fixture(scope="module")
def tools(tmp_path_factory: pytest.TempPathFactory) -> Path:
    status = namespaces_status()
    if not status.available:
        pytest.skip(status.reason)
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        pytest.skip("no C compiler")
    root = tmp_path_factory.mktemp("tools")
    target = root / "bin/probe"
    target.parent.mkdir(parents=True)
    source = Path(__file__).with_name("sandbox_probe.c")
    result = subprocess.run(
        [compiler, "-static", "-O2", "-o", str(target), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"cannot link statically: {result.stderr.strip()[-200:]}")
    return root


def command(tools: Path, *args: str, binds: tuple[Bind, ...] = ()) -> Command:
    return Command(
        name="probe-run",
        program=PROBE,
        args=args,
        env={"greeting": "hi", "out": OUT},
        binds=(Bind(source=str(tools), destination=TOOLS), *binds),
        directories=("/out",),
        outputs={"out": OUT},
    )


def start(
    tools: Path, work: Path, *args: str, binds: tuple[Bind, ...] = (), **limits: int
) -> Outcome:
    return run(command(tools, *args, binds=binds), str(work), Limits.model_validate(limits))


def report(outcome: Outcome) -> dict[str, str]:
    lines = Path(outcome.log).read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line and ":" not in line[:4])


def test_environment(tools: Path, tmp_path: Path) -> None:
    outcome = start(tools, tmp_path, "env", "a b")
    lines = Path(outcome.log).read_text(encoding="utf-8").splitlines()
    env = dict(line[4:].split("=", 1) for line in lines if line.startswith("env:"))
    assert env == {**FIXED_VARIABLES, "greeting": "hi", "out": OUT}
    values = report(outcome)
    assert values["hostname"] == "localhost"
    assert (values["pid"], values["uid"]) == ("1", "0")
    assert values["cwd"] == "/build"
    assert values["umask"] == "22"
    assert "arg=a b" in lines
    output = Path(outcome.outputs["out"])
    assert (output / "file").read_text(encoding="utf-8") == "data\n"
    assert stat.S_IMODE((output / "file").stat().st_mode) == 0o644


def test_isolation(tools: Path, tmp_path: Path) -> None:
    values = report(start(tools, tmp_path, "isolation", TOOLS))
    assert values["etc"] == str(errno.ENOENT)
    assert values["route"] == str(errno.ENETUNREACH)
    assert values["loopback"] == "0"
    assert values["write_input"] == str(errno.EROFS)
    assert values["umount_input"] == str(errno.EPERM)
    assert values["remount_input"] == str(errno.EPERM)
    assert values["mount"] == str(errno.EPERM)
    assert values["null"] == "0"
    assert values["shm"] == "0"


def test_hardening(tools: Path, tmp_path: Path) -> None:
    outcome = start(tools, tmp_path, "harden")
    values = report(outcome)
    for name in ("chmod_setuid", "chmod_setgid", "setxattr", "keyctl", "io_uring"):
        assert values[name] == str(errno.EPERM), name
    assert values["chmod_plain"] == "0"
    assert values["create_setuid"] == "0"
    output = Path(outcome.outputs["out"])
    assert stat.S_IMODE((output / "suid").stat().st_mode) == 0o755
    assert stat.S_IMODE((output / "file").stat().st_mode) == 0o700


def test_failing_program(tools: Path, tmp_path: Path) -> None:
    with pytest.raises(RunFailed, match="exited with status 2") as info:
        start(tools, tmp_path, "fail")
    assert "failing on purpose" in str(info.value)


def test_missing_output(tools: Path, tmp_path: Path) -> None:
    with pytest.raises(RunFailed, match="did not create output out"):
        start(tools, tmp_path, "nothing")


def test_symlink_output_is_not_followed(tools: Path, tmp_path: Path) -> None:
    output = Path(start(tools, tmp_path, "escape").outputs["out"])
    assert output.is_symlink()
    assert os.readlink(output) == "/etc/passwd"


def test_symlink_bind_is_not_followed(tools: Path, tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "key").write_text("private\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(secret)
    (tmp_path / "work").mkdir()
    outcome = start(
        tools,
        tmp_path / "work",
        "open",
        "/linked/key",
        binds=(Bind(source=str(link), destination="/linked"),),
    )
    assert report(outcome)["open"] == str(errno.ENOENT)


def test_special_file_fails(tools: Path, tmp_path: Path) -> None:
    with pytest.raises(RunFailed, match="pipe is not a regular file"):
        start(tools, tmp_path, "fifo")


def test_timeout_kills_the_program(tools: Path, tmp_path: Path) -> None:
    with pytest.raises(RunFailed, match="timed out after 1 s") as info:
        start(tools, tmp_path, "sleep", timeout=1)
    assert "sleeping" in str(info.value)


def test_missing_bind_fails_setup(tools: Path, tmp_path: Path) -> None:
    with pytest.raises(RunFailed, match="sandbox setup failed"):
        start(tmp_path / "none", tmp_path, "env")
