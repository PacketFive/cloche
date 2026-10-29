# SPDX-License-Identifier: GPL-2.0
"""The parts of the OCI backend that run without a container.

The helper runs in a child process during test_run.py, where coverage
does not follow it, so a stand-in runtime, a shell script, drives its
paths here.
"""

import io
import json
import os
import subprocess
from pathlib import Path

import pytest

from cloche import BackendStatus, Bind, Command, SandboxJob, make_spec, oci
from cloche.oci import OciBackend, OciRun, bundle_config, container_spec, find_runtime, oci_status
from cloche.spec import HelperReport

COMMAND = Command(
    name="t",
    program="/tools/bin/t",
    binds=(Bind(source="/usr", destination="/tools"),),
    directories=("/out", "/cache"),
    outputs={"out": "/out/x"},
)

# The stand-in runtime logs its arguments. ``create`` writes the pid file,
# or fails where the bundle holds a file named after the step.
RUNTIME = """#!/bin/sh
echo "$@" >> "$LOG"
case "$3" in --log) step=$5 ;; *) step=$3 ;; esac
bundle=$(dirname "$LOG")
if [ -e "$bundle/fail-$step" ]; then
    echo "$step went wrong" >&2
    [ "$step" = create ] && echo "cannot create" > "$4"
    exit 1
fi
[ "$step" = create ] && echo 4242 > "$9"
exit 0
"""


def job(tmp_path: Path, parent_pid: int = 1) -> SandboxJob:
    spec = make_spec(COMMAND, uid=1000, gid=100, machine="x86_64")
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    return SandboxJob(
        spec=spec, root=str(root), out_dir=str(tmp_path / "out"), parent_pid=parent_pid
    )


def test_find_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "youki"
    runtime.write_text("#!/bin/sh\n", encoding="utf-8")
    runtime.chmod(0o755)
    assert find_runtime(str(runtime)) == str(runtime)
    assert find_runtime(str(tmp_path / "none")) is None
    monkeypatch.setenv("PATH", str(tmp_path))
    assert find_runtime() == str(runtime)
    assert find_runtime("youki") == str(runtime)
    assert find_runtime("crun") is None
    monkeypatch.setenv("PATH", "/nonexistent")
    assert find_runtime() is None


def test_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    assert oci_status().reason == "crun or runc or youki is not installed"
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    bad.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    good.chmod(0o755)
    bad.chmod(0o755)
    monkeypatch.setattr(
        "cloche.probe.namespaces_status",
        lambda: BackendStatus(name="namespaces", available=True),
    )
    assert OciBackend(str(good)).status().available
    assert f"{bad} does not run" in oci_status(str(bad)).reason


def test_status_needs_user_namespaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "cloche.probe.namespaces_status",
        lambda: BackendStatus(name="namespaces", available=False, reason="no userns"),
    )
    assert oci_status("/bin/sh").reason == "no userns"


def test_container_spec_keeps_outputs_on_the_host(tmp_path: Path) -> None:
    run = job(tmp_path)
    spec = container_spec(run)
    out = next(m for m in spec.mounts if m.destination == "/out")
    assert (out.kind, out.source) == ("bind", f"{run.root}/out")
    assert "mode=0755" not in out.options
    assert (tmp_path / "root/out").is_dir()
    cache = next(m for m in spec.mounts if m.destination == "/cache")
    assert cache.kind == "tmpfs"


def test_container_spec_recreates_a_linked_bind(tmp_path: Path) -> None:
    (tmp_path / "link").symlink_to("/etc")
    command = COMMAND.model_copy(
        update={"binds": (Bind(source=str(tmp_path / "link"), destination="/tools"),)}
    )
    spec = make_spec(command, uid=1000, gid=100, machine="x86_64")
    (tmp_path / "root").mkdir()
    run = SandboxJob(spec=spec, root=str(tmp_path / "root"), out_dir="/o", parent_pid=1)
    result = container_spec(run)
    assert not [m for m in result.mounts if m.destination == "/tools"]
    assert os.readlink(tmp_path / "root/tools") == "/etc"


def test_bundle_config(tmp_path: Path) -> None:
    run = job(tmp_path)
    config = json.loads(bundle_config(run))
    assert config["root"]["path"] == run.root
    assert config["process"]["args"] == ["/tools/bin/t"]
    assert "network" in [n["type"] for n in config["linux"]["namespaces"]]


@pytest.fixture
def runtime(tmp_path: Path) -> Path:
    path = tmp_path / "runtime"
    path.write_text(RUNTIME, encoding="utf-8")
    path.chmod(0o755)
    return path


def contain(
    tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch, status: int = 0
) -> tuple[HelperReport, io.BytesIO]:
    run = OciRun(job=job(tmp_path), runtime=str(runtime))
    bundle, state = tmp_path / "bundle", tmp_path / "state"
    bundle.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)
    monkeypatch.setenv("LOG", str(bundle / "calls"))
    monkeypatch.setattr("cloche.oci._wait", lambda pid: status)
    Path(run.job.out_dir).mkdir(exist_ok=True)
    pipe = io.BytesIO()
    return oci._contain(run, pipe, str(bundle), str(state), "c1"), pipe


def test_contain(tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "root/out").mkdir(parents=True)
    (tmp_path / "root/out/x").write_text("made\n", encoding="utf-8")
    report, pipe = contain(tmp_path, runtime, monkeypatch)
    assert report == HelperReport(kind="finished")
    assert HelperReport.model_validate_json(pipe.getvalue()) == HelperReport(
        kind="started", pid=4242
    )
    assert (tmp_path / "out/out").read_text(encoding="utf-8") == "made\n"
    calls = (tmp_path / "bundle/calls").read_text(encoding="utf-8").splitlines()
    bundle = str(tmp_path / "bundle")
    assert calls[0].split()[4:] == [
        "create",
        "--bundle",
        bundle,
        "--pid-file",
        f"{bundle}/pid",
        "c1",
    ]
    assert calls[1].split()[2:] == ["start", "c1"]


def test_contain_missing_output(
    tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, _ = contain(tmp_path, runtime, monkeypatch)
    assert report.error == "the program did not create output out (/out/x)"


def test_contain_bad_output(tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "root/out").mkdir(parents=True)
    os.mkfifo(tmp_path / "root/out/x")
    report, _ = contain(tmp_path, runtime, monkeypatch)
    assert report.error is not None
    assert report.error.startswith("cannot copy output out: ")


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (2 << 8, "the program exited with status 2"),
        (9, "the program was killed by signal 9"),
    ],
)
def test_contain_program_fails(
    status: int, error: str, tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, _ = contain(tmp_path, runtime, monkeypatch, status)
    assert report.error == error


@pytest.mark.parametrize(
    ("step", "error"),
    [
        ("create", "sandbox setup failed: the runtime cannot create the container: cannot create"),
        ("start", "sandbox setup failed: the runtime cannot start the container: start went wrong"),
    ],
)
def test_contain_runtime_fails(
    step: str, error: str, tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bundle").mkdir()
    (tmp_path / "bundle" / f"fail-{step}").write_bytes(b"")
    report, _ = contain(tmp_path, runtime, monkeypatch)
    assert report == HelperReport(kind="failed", error=error)


def test_failure_without_a_message() -> None:
    result = subprocess.CompletedProcess(["x"], 3, "", "")
    assert oci._failure(result, "what").error == "sandbox setup failed: what: exit status 3"


def test_run_deletes_the_container(
    tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = tmp_path / "calls"
    monkeypatch.setenv("LOG", str(calls))
    monkeypatch.setattr("cloche.oci.libc.prctl", lambda *args: 0)
    monkeypatch.setattr(
        "cloche.oci._contain", lambda *args: HelperReport(kind="failed", error="stand-in")
    )
    run = OciRun(job=job(tmp_path, os.getppid()), runtime=str(runtime))
    assert oci._run(run, io.BytesIO()) == HelperReport(kind="failed", error="stand-in")
    config = json.loads((tmp_path / "bundle/config.json").read_text(encoding="utf-8"))
    assert config["root"]["path"] == run.job.root
    (line,) = calls.read_text(encoding="utf-8").splitlines()
    words = line.split()
    assert words[:2] == ["--root", str(tmp_path / "state")]
    assert words[2:4] == ["delete", "--force"]
    assert words[4].startswith(f"cloche-{os.getpid()}-")


class Pipe(io.BytesIO):
    """A status pipe that keeps its contents after close."""

    def close(self) -> None:
        self.text = self.getvalue().decode()
        super().close()


def run_main(monkeypatch: pytest.MonkeyPatch, stdin: bytes) -> list[HelperReport]:
    pipe = Pipe()
    monkeypatch.setattr("cloche.oci.os.fdopen", lambda fd, mode: pipe)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin)))
    assert oci.main(["helper", "9"]) == 0
    return [HelperReport.model_validate_json(line) for line in pipe.text.splitlines()]


def test_main_rejects_a_bad_run(monkeypatch: pytest.MonkeyPatch) -> None:
    (report,) = run_main(monkeypatch, b"{}")
    assert report.error is not None
    assert report.error.startswith("sandbox setup failed: ")


def test_main_reports_a_lost_supervisor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cloche.oci.libc.prctl", lambda *args: 0)
    data = OciRun(job=job(tmp_path, os.getppid() + 1), runtime="runc").model_dump_json()
    (report,) = run_main(monkeypatch, data.encode())
    assert report == HelperReport(kind="failed", error="the supervisor exited")


def test_main_reports_os_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def failing(run: OciRun, report: object) -> HelperReport:
        raise FileExistsError(17, "File exists", "/w/bundle")

    monkeypatch.setattr("cloche.oci._run", failing)
    data = OciRun(job=job(tmp_path), runtime="runc").model_dump_json()
    (report,) = run_main(monkeypatch, data.encode())
    assert report.error == "sandbox setup failed: File exists (/w/bundle)"
