# SPDX-License-Identifier: GPL-2.0
"""The parts of the microVM backend that run without a virtual machine.

The helper runs in a child process during test_run.py, where coverage
does not follow it, so its pieces and error paths are called directly
here.
"""

import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from cloche import Bind, Command, SandboxJob, make_spec, microvm, newc
from cloche.libc import MS_NODEV, MS_NOSUID, MS_RDONLY
from cloche.microvm import (
    INPUTS,
    KERNEL_ARGS,
    PORT,
    MicroVMBackend,
    MicroVMConfig,
    MicroVMRun,
    VMFiles,
    firecracker_config,
    guest_mounts,
    guest_spec,
    microvm_status,
    mount_flags,
    vmm_command,
)
from cloche.probe import namespaces_status
from cloche.spec import HelperReport, Mount

COMMAND = Command(
    name="t",
    program="/tools/bin/t",
    args=("a b",),
    env={"k": "v"},
    binds=(Bind(source="/usr", destination="/tools"),),
    directories=("/out",),
    outputs={"out": "/out/x"},
)
FILES = VMFiles(
    kernel="/k/vmlinux",
    initramfs="/w/initramfs.cpio",
    inputs="/w/inputs.ext4",
    outputs="/w/outputs.img",
    vsock="/s/v",
    config="/w/vm.json",
)


def job(tmp_path: Path, parent_pid: int = 1, command: Command = COMMAND) -> SandboxJob:
    spec = make_spec(command, uid=1000, gid=100, machine="x86_64")
    return SandboxJob(
        spec=spec, root=str(tmp_path / "root"), out_dir=str(tmp_path / "out"), parent_pid=parent_pid
    )


def config(**fields: object) -> MicroVMConfig:
    return MicroVMConfig.model_validate(fields)


def test_mount_flags() -> None:
    mount = Mount(destination="/x", kind="tmpfs", options=("nosuid", "nodev", "mode=0755"))
    assert mount_flags(mount) == (MS_NOSUID | MS_NODEV, "mode=0755")
    bind = Mount(destination="/y", kind="bind", source="/usr", read_only=True)
    assert mount_flags(bind) == (MS_RDONLY, "")


def test_guest_mounts_number_the_binds(tmp_path: Path) -> None:
    spec = job(tmp_path).spec
    mounts, sources = guest_mounts(spec)
    assert sources == ["/usr"]
    tools = next(m for m in mounts if m.destination == "/tools")
    assert tools.source == f"{INPUTS}/0"
    null = next(m for m in mounts if m.destination == "/dev/null")
    assert null.source == "/dev/null"
    assert len(mounts) == len(spec.mounts)


def test_guest_spec(tmp_path: Path) -> None:
    spec = job(tmp_path).spec
    mounts, _ = guest_mounts(spec)
    words = guest_spec(spec, mounts).split(b"\0")
    assert words[:4] == [b"program", b"/tools/bin/t", b"arg", b"a b"]
    assert words[-2:] == [b"end", b""]
    assert b"k=v" in words
    index = words.index(b"port")
    assert words[index + 1] == str(PORT).encode()
    index = words.index(b"id")
    assert words[index + 1 : index + 3] == [b"0", b"0"]
    index = words.index(b"output")
    assert words[index + 1 : index + 3] == [b"out", b"/out/x"]
    assert words.count(b"mount") == len(mounts)
    assert words.count(b"rlimit") == 2


def test_guest_spec_rejects_nul(tmp_path: Path) -> None:
    spec = job(tmp_path).spec.model_copy(update={"args": ("a\0b",)})
    with pytest.raises(ValueError, match="NUL"):
        guest_spec(spec, [])


def test_initramfs_holds_the_run(tmp_path: Path) -> None:
    data = microvm.initramfs(b"\x7fELF", b"program\0", "x86_64")
    for name in (b"dev/console", b"cloche/spec", b"cloche/seccomp.bpf", b"init\0"):
        assert name in data
    assert data.startswith(newc.MAGIC)


def test_firecracker_config_has_no_network() -> None:
    document = firecracker_config(config(cpus=3, memory_mib=256), FILES)
    assert document["network-interfaces"] == []
    assert document["machine-config"] == {"vcpu_count": 3, "mem_size_mib": 256}
    drives = document["drives"]
    assert isinstance(drives, list)
    assert [d["is_read_only"] for d in drives] == [True, False]
    boot = document["boot-source"]
    assert isinstance(boot, dict)
    assert boot["boot_args"].split() == [*KERNEL_ARGS, "pci=off"]
    json.dumps(document)


@pytest.mark.parametrize("vmm", ["firecracker", "cloud-hypervisor", "openvmm"])
def test_vmm_command(vmm: str) -> None:
    command = vmm_command(config(vmm=vmm, cpus=2, memory_mib=512), "/bin/vmm", FILES)
    assert command[0] == "/bin/vmm"
    text = " ".join(command)
    assert not [word for word in command if word.startswith(("--net", "--nic", "tap"))]
    if vmm == "firecracker":
        assert command[1:] == ["--no-api", "--config-file", FILES.config, "--level", "Error"]
    else:
        assert FILES.inputs in text
        assert FILES.outputs in text
        assert FILES.vsock in text
        assert " ".join(KERNEL_ARGS) in command


def test_cloud_hypervisor_command() -> None:
    command = vmm_command(config(vmm="cloud-hypervisor", cpus=2, memory_mib=512), "ch", FILES)
    assert "boot=2" in command
    assert "size=512M" in command
    assert f"path={FILES.inputs},readonly=on,image_type=raw,sparse=off" in command


def test_openvmm_command() -> None:
    command = vmm_command(config(vmm="openvmm", cpus=2, memory_mib=512), "openvmm", FILES)
    assert command[command.index("--memory") + 1] == "512MB"
    assert f"file:{FILES.inputs},ro" in command


def test_status_unsupported_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cloche.microvm.libc.machine", lambda: "riscv64")
    assert microvm_status(config()).reason == "riscv64 is not supported"


def test_status_needs_kernel_and_init(tmp_path: Path) -> None:
    assert microvm_status(None).reason == "no guest kernel and init are configured"
    assert microvm_status(config(kernel="/k")).reason == "no guest kernel and init are configured"
    missing = microvm_status(config(kernel=str(tmp_path / "k"), init=str(tmp_path / "i")))
    assert missing.reason == f"the guest kernel {tmp_path}/k does not exist"


@pytest.fixture
def guest(tmp_path: Path) -> dict[str, str]:
    for name in ("vmlinux", "init"):
        (tmp_path / name).write_bytes(b"")
    vmm = tmp_path / "vmm"
    vmm.write_text("#!/bin/sh\n", encoding="utf-8")
    vmm.chmod(0o755)
    return {"kernel": str(tmp_path / "vmlinux"), "init": str(tmp_path / "init"), "vmm": str(vmm)}


def test_status_needs_the_monitor(guest: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    status = microvm_status(config(kernel=guest["kernel"], init=guest["init"], vmm_path="/no/vmm"))
    assert status.reason == "/no/vmm is not installed"
    monkeypatch.setenv("PATH", "/nonexistent")
    status = microvm_status(config(kernel=guest["kernel"], init=guest["init"], vmm="openvmm"))
    assert status.reason == "openvmm is not installed"


def test_status_needs_mkfs(guest: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cloche.microvm.find_mkfs", lambda: None)
    status = microvm_status(
        config(kernel=guest["kernel"], init=guest["init"], vmm_path=guest["vmm"])
    )
    assert status.reason == "mkfs.ext4 is not installed"


def test_status_needs_kvm(guest: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(path: str, flags: int) -> int:
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr("cloche.microvm.find_mkfs", lambda: "/sbin/mkfs.ext4")
    monkeypatch.setattr("cloche.microvm.os.open", denied)
    status = microvm_status(
        config(kernel=guest["kernel"], init=guest["init"], vmm_path=guest["vmm"])
    )
    assert status.reason == "cannot open /dev/kvm: Permission denied"


def test_status_available(guest: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cloche.microvm.find_mkfs", lambda: "/sbin/mkfs.ext4")
    monkeypatch.setattr("cloche.microvm.os.open", lambda path, flags: os.dup(0))
    backend = MicroVMBackend(
        config(kernel=guest["kernel"], init=guest["init"], vmm_path=guest["vmm"])
    )
    assert backend.status().available


def test_build_guest_init(tmp_path: Path) -> None:
    script = tmp_path / "cc"
    script.write_text('#!/bin/sh\necho "$@" > "$4.args"\n', encoding="utf-8")
    script.chmod(0o755)
    target = tmp_path / "init"
    microvm.build_guest_init(str(target), str(script))
    words = (tmp_path / "init.args").read_text(encoding="utf-8").split()
    assert words == ["-static", "-O2", "-o", str(target), str(microvm.GUEST_INIT_SOURCE)]
    assert microvm.GUEST_INIT_SOURCE.is_file()


def test_build_guest_init_needs_a_compiler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cloche.microvm.shutil.which", lambda name: None)
    with pytest.raises(OSError, match="no C compiler"):
        microvm.build_guest_init("/tmp/init")  # noqa: S108


def test_stage(tmp_path: Path) -> None:
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "file").write_bytes(b"12345")
    (source / "sub/more").write_bytes(b"678")
    (source / "link").symlink_to("file")
    (source / "sub").chmod(0o500)
    try:
        assert microvm.stage(str(source), str(tmp_path / "copy")) == (8, 5)
    finally:
        (source / "sub").chmod(0o755)
    assert (tmp_path / "copy/file").read_bytes() == b"12345"
    assert os.readlink(tmp_path / "copy/link") == "file"


def test_remove_tree_with_read_only_directories(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "file").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o555)
    (tree / "link").symlink_to(outside)
    (tree / "sub").chmod(0o555)
    tree.chmod(0o555)
    microvm.remove_tree(str(tree))
    assert not tree.exists()
    assert stat.S_IMODE(outside.stat().st_mode) == 0o555
    microvm.remove_tree(str(tree))


def test_stage_rejects_special_files(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ValueError, match="not a regular file"):
        microvm.stage(str(tmp_path / "pipe"), str(tmp_path / "copy"))


def test_stage_copies_across_file_systems(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def cross(*args: object, **kwargs: object) -> None:
        raise OSError(18, "Invalid cross-device link")

    (tmp_path / "file").write_bytes(b"x")
    (tmp_path / "file").chmod(0o640)
    monkeypatch.setattr("cloche.microvm.os.link", cross)
    microvm.stage(str(tmp_path / "file"), str(tmp_path / "copy"))
    assert (tmp_path / "copy").read_bytes() == b"x"
    assert stat.S_IMODE((tmp_path / "copy").stat().st_mode) == 0o640


def test_restore_modes(tmp_path: Path) -> None:
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "sub").chmod(0o750)
    (source / "away").symlink_to(tmp_path)
    link = tmp_path / "linked"
    link.symlink_to(source)
    stage_dir = tmp_path / "stage"
    stage_dir.mkdir()
    microvm.stage(str(source), str(stage_dir / "0"))
    microvm.stage(str(link), str(stage_dir / "1"))
    microvm._restore_modes([str(source), str(link)], str(stage_dir))
    assert stat.S_IMODE((stage_dir / "0/sub").stat().st_mode) == 0o750
    assert (stage_dir / "1").is_symlink()


def ext4_owner(image: Path, path: str) -> str:
    debugfs = shutil.which("debugfs") or shutil.which("debugfs", path="/usr/sbin:/sbin")
    if debugfs is None:
        pytest.skip("debugfs is not installed")
    result = subprocess.run(
        [debugfs, "-R", f"stat {path}", str(image)], capture_output=True, text=True, check=True
    )
    return result.stdout.split("User:")[1].split()[0]


@pytest.fixture
def mkfs() -> str:
    found = microvm.find_mkfs()
    if found is None:
        pytest.skip("mkfs.ext4 is not installed")
    return found


def test_input_image_belongs_to_root(tmp_path: Path, mkfs: str) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/file").write_bytes(b"data")
    image = tmp_path / "in.ext4"
    microvm.make_input_image([str(tmp_path / "src")], str(tmp_path / "stage"), str(image), mkfs)
    assert image.stat().st_size % (1 << 20) == 0
    if not namespaces_status().available:
        pytest.skip("user namespaces do not work here")
    assert ext4_owner(image, "/0/file") == "0"


def test_input_image_without_user_namespaces(
    tmp_path: Path, mkfs: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(uid: int, gid: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("cloche.microvm._map_to_root", refused)
    (tmp_path / "src").mkdir()
    image = tmp_path / "in.ext4"
    microvm.make_input_image([str(tmp_path / "src")], str(tmp_path / "stage"), str(image), mkfs)
    assert image.is_file()


def test_input_image_mkfs_fails(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    with pytest.raises(subprocess.CalledProcessError):
        microvm.make_input_image(
            [str(tmp_path / "src")], str(tmp_path / "stage"), str(tmp_path / "i"), "/bin/false"
        )


def test_output_image_is_sparse(tmp_path: Path) -> None:
    microvm.make_output_image(str(tmp_path / "out"), 3)
    info = (tmp_path / "out").stat()
    assert info.st_size == 3 << 20
    assert info.st_blocks == 0


@pytest.mark.parametrize(
    ("final", "reason"),
    [
        ("exited 0", None),
        ("exited 2", "the program exited with status 2"),
        ("killed 9", "the program was killed by signal 9"),
        ("error sandbox setup failed: x", "sandbox setup failed: x"),
        ("error cannot write", "sandbox setup failed: cannot write"),
        ("hello", "the guest init sent an unknown line: hello"),
    ],
)
def test_verdict(final: str, reason: str | None) -> None:
    assert microvm._verdict(final) == reason


def test_lines_stop_after_the_result() -> None:
    host, guest = socket.socketpair()
    with host, guest:
        guest.sendall(b"ready\nexited 0\nignored")
        assert microvm._lines(host) == ["ready", "exited 0", "ignored"]
    host, guest = socket.socketpair()
    with host, guest:
        guest.sendall(b"ready\n")
        guest.close()
        assert microvm._lines(host) == ["ready"]


class Stopped:
    """A monitor process that has already exited."""

    def __init__(self, status: int | None):
        self.status = status

    def poll(self) -> int | None:
        return self.status


def test_accept_notices_a_stopped_monitor(tmp_path: Path) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(tmp_path / "s"))
        listener.listen(1)
        with pytest.raises(RuntimeError, match="stopped before its init connected"):
            microvm._accept(listener, Stopped(1), 5)  # type: ignore[arg-type]
        with pytest.raises(RuntimeError, match="did not connect within 0.05 s"):
            microvm._accept(listener, Stopped(None), 0.05)  # type: ignore[arg-type]
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(tmp_path / "s"))
            microvm._accept(listener, Stopped(None), 5).close()  # type: ignore[arg-type]


def test_collect(tmp_path: Path) -> None:
    run = job(tmp_path)
    Path(run.out_dir).mkdir()
    image = tmp_path / "outputs.img"
    image.write_bytes(newc.archive([newc.Entry("out", stat.S_IFREG | 0o644, b"x")]))
    assert microvm._collect(run, str(image)) is None
    assert (Path(run.out_dir) / "out").read_bytes() == b"x"


def test_collect_failures(tmp_path: Path) -> None:
    run = job(tmp_path)
    Path(run.out_dir).mkdir()
    image = tmp_path / "outputs.img"
    image.write_bytes(newc.archive([]))
    assert microvm._collect(run, str(image)) == HelperReport(
        kind="failed", error="the program did not create output out (/out/x)"
    )
    image.write_bytes(b"\0" * 512)
    failure = microvm._collect(run, str(image))
    assert failure is not None
    assert failure.error == "cannot copy the outputs: the output archive has a bad header"


class Pipe(io.BytesIO):
    """A status pipe that keeps its contents after close."""

    def close(self) -> None:
        self.text = self.getvalue().decode()
        super().close()


def run_main(monkeypatch: pytest.MonkeyPatch, stdin: bytes) -> list[HelperReport]:
    pipe = Pipe()
    monkeypatch.setattr("cloche.microvm.os.fdopen", lambda fd, mode: pipe)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin)))
    assert microvm.main(["helper", "9"]) == 0
    return [HelperReport.model_validate_json(line) for line in pipe.text.splitlines()]


def payload(tmp_path: Path, parent_pid: int = 1) -> bytes:
    run = MicroVMRun(
        job=job(tmp_path, parent_pid), config=config(kernel="/k", init="/i"), vmm="/bin/vmm"
    )
    return run.model_dump_json().encode()


def test_main_rejects_a_bad_run(monkeypatch: pytest.MonkeyPatch) -> None:
    (report,) = run_main(monkeypatch, b"{}")
    assert report.kind == "failed"
    assert report.error is not None
    assert report.error.startswith("sandbox setup failed: ")


def test_main_reports_a_lost_supervisor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cloche.microvm.libc.prctl", lambda *args: 0)
    (report,) = run_main(monkeypatch, payload(tmp_path, os.getppid() + 1))
    assert report == HelperReport(kind="failed", error="the supervisor exited")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            subprocess.CalledProcessError(1, ["mkfs"], "", "first\nmkfs.ext4: no space\n"),
            "sandbox setup failed: mkfs.ext4: no space",
        ),
        (subprocess.CalledProcessError(3, ["mkfs"], "", ""), "sandbox setup failed: exit status 3"),
        (FileNotFoundError(2, "No such file", "/k"), "sandbox setup failed: No such file (/k)"),
        (ValueError("/x is not a regular file"), "sandbox setup failed: /x is not a regular file"),
    ],
)
def test_main_reports_setup_errors(
    error: Exception, message: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def failing(run: MicroVMRun, report: object) -> HelperReport:
        raise error

    monkeypatch.setattr("cloche.microvm._run", failing)
    (report,) = run_main(monkeypatch, payload(tmp_path))
    assert report == HelperReport(kind="failed", error=message)


def test_run_cleans_up(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[str] = []

    def boot(run: MicroVMRun, work: str, report: object) -> HelperReport:
        seen.append(work)
        return HelperReport(kind="finished")

    monkeypatch.setattr("cloche.microvm.libc.prctl", lambda *args: 0)
    monkeypatch.setattr("cloche.microvm._boot", boot)
    run = MicroVMRun.model_validate_json(payload(tmp_path, os.getppid()))
    assert microvm._run(run, io.BytesIO()) == HelperReport(kind="finished")
    assert seen[0] == str(tmp_path / "vm")
    assert not any(os.path.exists(path) for path in seen)


def test_boot_needs_mkfs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cloche.microvm.find_mkfs", lambda: None)
    run = MicroVMRun.model_validate_json(payload(tmp_path))
    report = microvm._boot(run, str(tmp_path), io.BytesIO())
    assert report.error == "sandbox setup failed: mkfs.ext4 is not installed"


FAKE_VMM = """\
import json, socket, sys
from cloche import newc
config = json.load(open(sys.argv[3]))
mode = config["boot-source"]["kernel_image_path"].rsplit("/", 1)[1]
if mode == "crash":
    sys.exit(4)
with open(config["drives"][1]["path_on_host"], "r+b") as device:
    device.write(newc.archive([newc.Entry("out", 0o100644, b"made")] if mode != "none" else []))
connection = socket.socket(socket.AF_UNIX)
connection.connect(config["vsock"]["uds_path"] + "_1024")
lines = {"ok": "ready\\nexited 0\\n", "none": "ready\\nexited 0\\n", "fail": "ready\\nexited 3\\n",
         "mute": "ready\\n", "rude": "hello\\n"}[mode]
connection.sendall(lines.encode())
connection.close()
import time; time.sleep(30)
"""


@pytest.mark.parametrize(
    ("mode", "kind", "error"),
    [
        ("ok", "finished", None),
        ("none", "failed", "the program did not create output out (/out/x)"),
        ("fail", "failed", "the program exited with status 3"),
        ("mute", "failed", "the virtual machine stopped without a result"),
        ("rude", "failed", "the guest init did not say ready"),
        ("crash", "failed", "the virtual machine stopped before its init connected (status 4)"),
    ],
)
def test_boot_with_a_fake_monitor(
    mode: str, kind: str, error: str | None, mkfs: str, tmp_path: Path
) -> None:
    vmm = tmp_path / "vmm"
    vmm.write_text(f"#!{sys.executable}\n" + FAKE_VMM, encoding="utf-8")
    vmm.chmod(0o755)
    (tmp_path / mode).write_bytes(b"")
    (tmp_path / "init").write_bytes(b"")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools/t").write_bytes(b"")
    small = COMMAND.model_copy(
        update={"binds": (Bind(source=str(tmp_path / "tools"), destination="/tools"),)}
    )
    run = MicroVMRun(
        job=job(tmp_path, os.getpid(), small),
        config=config(kernel=str(tmp_path / mode), init=str(tmp_path / "init"), output_mib=1),
        vmm=str(vmm),
    )
    Path(run.job.out_dir).mkdir()
    work = tmp_path / "vm"
    work.mkdir()
    pipe = io.BytesIO()
    report = microvm._boot(run, str(work), pipe)
    assert (report.kind, report.error) == (kind, error)
    started = HelperReport.model_validate_json(pipe.getvalue().splitlines()[0])
    assert started.kind == "started"
    if mode == "ok":
        assert (Path(run.job.out_dir) / "out").read_bytes() == b"made"
        assert report.boot_seconds is not None
