# SPDX-License-Identifier: GPL-2.0
"""Models, the environment, the sandbox description, copying out and the probe."""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from cloche import (
    BACKENDS,
    FIXED_VARIABLES,
    Bind,
    Command,
    InvalidCommand,
    Limits,
    SandboxSpec,
    SandboxUnavailable,
    backend_status,
    make_spec,
    oci_config,
    probe,
    select_backend,
)
from cloche.environment import program_environment
from cloche.namespaces import copy_out

TOOLS = "/opt/tools"
STORE = "/store"


def command(**fields: object) -> Command:
    values: dict[str, object] = {
        "name": "hello",
        "program": f"{TOOLS}/bin/sh",
        "binds": (Bind(source="/host/tools", destination=TOOLS),),
        "directories": (STORE,),
        "outputs": {"out": f"{STORE}/hello"},
    }
    values.update(fields)
    return Command.model_validate(values)


def spec_of(cmd: Command, machine: str = "x86_64") -> SandboxSpec:
    return make_spec(cmd, uid=1000, gid=100, machine=machine)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"program": "bin/sh"}, "not a normalised absolute path"),
        ({"program": "/opt/tools/../sh"}, "not a normalised absolute path"),
        ({"directories": ("/",)}, "mounts itself"),
        ({"directories": ("/build/x",)}, "mounts itself"),
        ({"directories": ("/devices",)}, None),
        ({"outputs": {"../x": "/build/x"}}, "plain file name"),
        ({"name": ""}, "at least 1 character"),
        ({"args": ["a"]}, "valid tuple"),
    ],
)
def test_command_fields(fields: dict[str, object], message: str | None) -> None:
    if message is None:
        assert command(**fields).directories == ("/devices",)
        return
    with pytest.raises(ValidationError, match=message):
        command(**fields)


def test_bind_paths() -> None:
    with pytest.raises(ValidationError, match="normalised absolute"):
        Bind(source="relative", destination="/x")
    with pytest.raises(ValidationError, match="mounts itself"):
        Bind(source="/dev", destination="/dev")


def test_limits() -> None:
    assert Limits().max_open_files == 1024
    for bad in ({"timeout": 0}, {"max_silent_time": -1}, {"max_open_files": 10}):
        with pytest.raises(ValidationError):
            Limits.model_validate(bad)


def test_environment() -> None:
    env = program_environment(command(env={"greeting": "hi"}))
    assert list(env) == sorted(env)
    assert env == {"greeting": "hi", **FIXED_VARIABLES}


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"PATH": "/bin"}, "sandbox fixes"),
        ({"a=b": "x"}, "cannot be passed"),
        ({"": "x"}, "cannot be passed"),
        ({"a": "x\0y"}, "cannot be passed"),
    ],
)
def test_environment_rejects(env: dict[str, str], message: str) -> None:
    with pytest.raises(InvalidCommand, match=message):
        spec_of(command(env=env))


def test_spec() -> None:
    spec = spec_of(command(binds=(Bind(source="/host/tools", destination=TOOLS),)))
    assert spec.program == f"{TOOLS}/bin/sh"
    assert spec.outputs == {"out": f"{STORE}/hello"}
    assert spec.cwd == "/build"
    assert spec.hostname == "localhost"
    assert (spec.uid_map.outside, spec.gid_map.outside) == (1000, 100)
    mounts = {m.destination: m for m in spec.mounts}
    assert (mounts[STORE].kind, mounts[STORE].read_only) == ("tmpfs", False)
    assert (mounts[TOOLS].kind, mounts[TOOLS].source, mounts[TOOLS].read_only) == (
        "bind",
        "/host/tools",
        True,
    )
    assert mounts["/proc"].kind == "proc"
    assert mounts["/dev/null"].kind == "bind"
    assert "/etc" not in mounts
    destinations = [m.destination for m in spec.mounts]
    assert destinations.index("/build") < destinations.index(STORE) < destinations.index(TOOLS)
    assert destinations.index("/dev") < destinations.index("/dev/shm")  # noqa: S108


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"program": "/bin/sh"}, "not inside any bind"),
        ({"program": f"{TOOLS}x/bin/sh"}, "not inside any bind"),
        ({"directories": (TOOLS,)}, "share a path"),
        ({"directories": (f"{TOOLS}/var",)}, "inside the bind"),
        (
            {
                "binds": (
                    Bind(source="/host/tools", destination=TOOLS),
                    Bind(source="/host/b", destination=f"{TOOLS}/lib"),
                )
            },
            f"bind {TOOLS}/lib is inside the bind at {TOOLS}",
        ),
        ({"outputs": {"out": "/elsewhere/x"}}, "must be below /build or a directory"),
        ({"outputs": {"out": STORE}}, "must be below /build or a directory"),
        ({"outputs": {"out": "/build"}}, "must be below /build or a directory"),
        (
            {
                "binds": (
                    Bind(source="/host/tools", destination=TOOLS),
                    Bind(source="/host/x", destination=f"{STORE}/x"),
                ),
                "outputs": {"out": f"{STORE}/x/y"},
            },
            "inside a bind",
        ),
    ],
)
def test_spec_rejects(fields: dict[str, object], message: str) -> None:
    with pytest.raises(InvalidCommand, match=message):
        spec_of(command(**fields))


def test_output_below_build() -> None:
    assert spec_of(command(outputs={"log": "/build/log"})).outputs == {"log": "/build/log"}


def test_spec_rejects_unknown_machine() -> None:
    with pytest.raises(SandboxUnavailable, match="riscv64"):
        spec_of(command(), machine="riscv64")


def test_oci_config() -> None:
    cmd = command(args=("-c", "true"))
    spec = make_spec(cmd, Limits(max_open_files=64), uid=1000, gid=100, machine="aarch64")
    value = json.loads(oci_config(spec).model_dump_json())
    assert value["ociVersion"] == "1.0.2"
    assert value["root"] == {"path": "rootfs", "readonly": False}
    process = value["process"]
    assert process["args"] == [cmd.program, "-c", "true"]
    assert process["noNewPrivileges"] is True
    assert process["user"] == {"uid": 0, "gid": 0}
    assert all(v == [] for v in process["capabilities"].values())
    assert "TZ=UTC" in process["env"]
    assert {"type": "RLIMIT_CORE", "hard": 0, "soft": 0} in process["rlimits"]
    assert {"type": "RLIMIT_NOFILE", "hard": 64, "soft": 64} in process["rlimits"]
    linux = value["linux"]
    assert [n["type"] for n in linux["namespaces"]] == [
        "user",
        "mount",
        "network",
        "pid",
        "uts",
        "ipc",
    ]
    assert linux["uidMappings"] == [{"containerID": 0, "hostID": 1000, "size": 1}]
    assert linux["seccomp"]["architectures"] == ["SCMP_ARCH_AARCH64"]
    tools = next(m for m in value["mounts"] if m["destination"] == TOOLS)
    assert tools == {
        "destination": TOOLS,
        "type": "bind",
        "source": "/host/tools",
        "options": ["rbind", "nosuid", "nodev", "ro"],
    }


def test_copy_out(tmp_path: Path) -> None:
    root = tmp_path / "root"
    made = root / "store/abc-x"
    (made / "bin").mkdir(parents=True)
    (made / "bin/tool").write_text("tool", encoding="utf-8")
    (made / "bin/tool").chmod(0o4755)
    (made / "link").symlink_to("/etc/passwd")
    (made / "share").mkdir(mode=0o555)
    destination = tmp_path / "out/x"
    destination.parent.mkdir()
    copy_out(str(root), "/store/abc-x", str(destination))
    assert (destination / "bin/tool").read_text(encoding="utf-8") == "tool"
    assert stat.S_IMODE((destination / "bin/tool").stat().st_mode) == 0o755
    assert os.readlink(destination / "link") == "/etc/passwd"
    assert stat.S_IMODE((destination / "share").stat().st_mode) == 0o555
    (destination / "share").chmod(0o755)


def test_copy_out_does_not_follow_links(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    secret = tmp_path / "secret"
    secret.mkdir()
    (root / "store").symlink_to(secret)
    (secret / "abc-x").write_text("host file", encoding="utf-8")
    with pytest.raises(OSError):
        copy_out(str(root), "/store/abc-x", str(tmp_path / "copy"))
    assert not (tmp_path / "copy").exists()


def test_copy_out_rejects_special_files(tmp_path: Path) -> None:
    store = tmp_path / "root/store"
    (store / "abc-x").mkdir(parents=True)
    os.mkfifo(store / "abc-x/pipe")
    (tmp_path / "out").mkdir()
    with pytest.raises(ValueError, match="pipe is not a regular file"):
        copy_out(str(tmp_path / "root"), "/store/abc-x", str(tmp_path / "out/x"))


def test_copy_out_missing(tmp_path: Path) -> None:
    (tmp_path / "root/store").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        copy_out(str(tmp_path / "root"), "/store/abc-x", str(tmp_path / "x"))


def failed_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 1, "", "Traceback\nPermissionError: denied\n")


def test_probe_explains_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sysctl = tmp_path / "restrict"
    sysctl.write_text("1\n", encoding="ascii")
    monkeypatch.setattr(subprocess, "run", failed_run)
    monkeypatch.setattr(
        probe, "_SYSCTLS", ((str(tmp_path / "none"), "0", "no"), (str(sysctl), "1", "restricted"))
    )
    status = probe.namespaces_status()
    assert not status.available
    assert (
        status.reason
        == "unprivileged user namespaces do not work: PermissionError: denied (restricted)"
    )


def test_probe_explains_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def empty(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 2, "", "")

    monkeypatch.setattr(subprocess, "run", empty)
    monkeypatch.setattr(probe, "_SYSCTLS", ((str(tmp_path / "none"), "0", "no"),))
    assert probe.namespaces_status().reason.endswith("do not work: exit status 2")


def test_probe_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("python", 30)

    monkeypatch.setattr(subprocess, "run", slow)
    assert "timed out" in probe.namespaces_status().reason


def test_probe_unsupported_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe.libc, "machine", lambda: "riscv64")
    assert probe.namespaces_status().reason == "riscv64 is not supported"


def test_backend_status_lists_every_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", failed_run)
    monkeypatch.setattr("cloche.oci.find_runtime", lambda runtime: "/usr/bin/runc")
    statuses = backend_status()
    assert tuple(s.name for s in statuses) == BACKENDS == ("namespaces", "oci", "microvm")
    assert statuses[1].reason == statuses[0].reason
    assert statuses[2].reason == "no guest kernel and init are configured"


def test_select_backend_never_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SandboxUnavailable, match="no sandbox backend called chroot"):
        select_backend("chroot")
    with pytest.raises(SandboxUnavailable, match="/nowhere/runc is not installed"):
        select_backend("oci", runtime="/nowhere/runc")
    with pytest.raises(SandboxUnavailable, match="no guest kernel"):
        select_backend("microvm")
    monkeypatch.setattr(subprocess, "run", failed_run)
    with pytest.raises(SandboxUnavailable, match="cannot run here"):
        select_backend("namespaces")
