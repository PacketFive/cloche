# SPDX-License-Identifier: GPL-2.0
"""The microVM backend.

MicroVMBackend.start runs this module in a fresh interpreter, the helper,
with a MicroVMRun as JSON on stdin. The helper runs the program in a
virtual machine with no network device, under one of the virtual machine
monitors in VMMS:

1. Every bind of the spec, other than the devices of /dev, is copied
   into a staging tree, hard-linked where it can be, and the tree becomes
   an ext4 image labelled cloche-in, made with ``mkfs.ext4 -d``. No root
   and no loop device are needed. The guest mounts it read-only.
2. An empty sparse file of ``output_mib`` MiB becomes the output device.
3. An initramfs is written for the run: the guest init, the spec as
   guest_init.c reads it, and the seccomp filter of seccomp.py.
4. The monitor boots the guest kernel with that initramfs and the two
   devices, and its serial console is the log.
5. The guest init connects back over vsock, port PORT, and says "ready",
   which marks the end of the boot. It builds the sandbox, runs the
   program, writes the outputs to the output device as a newc archive
   and sends one last line: "exited N", "killed N" or "error MESSAGE".
6. The helper stops the monitor and reads the outputs with newc.extract.

All three monitors use the same hybrid vsock: a connection the guest
opens to the host on port P arrives on the Unix socket ``<base>_P``.

The guest kernel and init are files the caller names in MicroVMConfig;
``build_guest_init`` compiles the init from guest_init.c.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from pydantic import Field

from . import libc, newc, seccomp
from .models import Model
from .spec import DEVICES, HelperReport, Mount, SandboxJob, SandboxSpec

if TYPE_CHECKING:
    from .probe import BackendStatus

VMMS: tuple[str, ...] = ("firecracker", "cloud-hypervisor", "openvmm")
"""The virtual machine monitors the backend can drive."""

PORT = 1024
GUEST_CID = 3
INPUT_LABEL = "cloche-in"
INPUTS = "/inputs"
KERNEL_ARGS: tuple[str, ...] = (
    "console=ttyS0",
    "reboot=k",
    "panic=-1",
    "quiet",
    "loglevel=0",
    "rdinit=/init",
)
GUEST_INIT_SOURCE = Path(__file__).with_name("guest_init.c")

_MOUNT_FLAGS: dict[str, int] = {
    "ro": libc.MS_RDONLY,
    "nosuid": libc.MS_NOSUID,
    "nodev": libc.MS_NODEV,
    "noexec": libc.MS_NOEXEC,
}
_RLIMITS: dict[str, int] = {
    "RLIMIT_CORE": resource.RLIMIT_CORE,
    "RLIMIT_NOFILE": resource.RLIMIT_NOFILE,
}
_DEVICE_SOURCES = frozenset(f"/dev/{name}" for name in DEVICES)
_MIB = 1 << 20
_IMAGE_SLACK = 32 * _MIB
_ENTRY_COST = 4096


class MicroVMConfig(Model):
    """How the microVM backend boots its virtual machines.

    ``kernel`` is an uncompressed guest kernel (vmlinux) with virtio
    block, virtio vsock, ext4, tmpfs and devtmpfs built in, and ``init``
    a statically linked build of guest_init.c. ``vmm_path`` overrides the
    search for ``vmm`` in PATH. ``output_mib`` is the size of the sparse
    output device, which caps the size of the outputs.
    """

    vmm: Literal["firecracker", "cloud-hypervisor", "openvmm"] = "firecracker"
    vmm_path: str | None = None
    kernel: str | None = None
    init: str | None = None
    memory_mib: int = Field(default=2048, ge=128)
    cpus: int = Field(default=2, ge=1, le=64)
    output_mib: int = Field(default=4096, ge=1)
    boot_timeout: float = Field(default=60.0, gt=0)


class MicroVMRun(Model):
    """What MicroVMBackend.start passes to the helper."""

    job: SandboxJob
    config: MicroVMConfig
    vmm: str


class VMFiles(Model):
    """The files of one virtual machine, all on the host.

    ``vsock`` is relative to the run's directory, which is the monitor's
    working directory, so the socket paths stay short.
    """

    kernel: str
    initramfs: str
    inputs: str
    outputs: str
    vsock: str
    config: str


def find_vmm(config: MicroVMConfig) -> str | None:
    """Return the absolute path of the configured monitor, or None if it is missing."""
    found = config.vmm_path if config.vmm_path is not None else shutil.which(config.vmm)
    if found is None or not os.access(found, os.X_OK):
        return None
    return os.path.abspath(found)


def find_mkfs() -> str | None:
    """Return the path of mkfs.ext4, which is often outside a user's PATH."""
    return shutil.which("mkfs.ext4") or shutil.which("mkfs.ext4", path="/usr/sbin:/sbin")


def microvm_status(config: MicroVMConfig | None) -> BackendStatus:
    """Test whether the microVM backend can run with ``config``."""
    from .probe import BackendStatus

    name = "microvm"

    def unavailable(reason: str) -> BackendStatus:
        return BackendStatus(name=name, available=False, reason=reason)

    if libc.machine() not in seccomp.AUDIT_ARCH:
        return unavailable(f"{libc.machine()} is not supported")
    if config is None or config.kernel is None or config.init is None:
        return unavailable("no guest kernel and init are configured")
    for what, path in (("guest kernel", config.kernel), ("guest init", config.init)):
        if not os.path.isfile(path):
            return unavailable(f"the {what} {path} does not exist")
    if find_vmm(config) is None:
        return unavailable(f"{config.vmm_path or config.vmm} is not installed")
    if find_mkfs() is None:
        return unavailable("mkfs.ext4 is not installed")
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC))
    except OSError as error:
        return unavailable(f"cannot open /dev/kvm: {error.strerror}")
    return BackendStatus(name=name, available=True)


def build_guest_init(output: str, compiler: str | None = None) -> None:
    """Compile guest_init.c to ``output`` as a static executable.

    Raises OSError if no C compiler is found and CalledProcessError if
    the compiler fails.
    """
    compiler = compiler or shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise OSError(errno.ENOENT, "no C compiler found", "cc")
    subprocess.run(  # noqa: S603
        [compiler, "-static", "-O2", "-o", output, str(GUEST_INIT_SOURCE)],
        check=True,
        capture_output=True,
        text=True,
    )


def mount_flags(mount: Mount) -> tuple[int, str]:
    """Return the flags and the data of ``mount`` as mount(2) takes them."""
    flags = libc.MS_RDONLY if mount.read_only else 0
    data: list[str] = []
    for option in mount.options:
        if option in _MOUNT_FLAGS:
            flags |= _MOUNT_FLAGS[option]
        else:
            data.append(option)
    return flags, ",".join(data)


def guest_mounts(spec: SandboxSpec) -> tuple[list[Mount], list[str]]:
    """Point the binds of ``spec`` at the input image.

    Returns the mounts the guest applies and the host source of each
    numbered entry of the image: bind ``i`` comes from ``INPUTS/i``. The
    devices of /dev stay as they are, since the guest has its own.
    """
    mounts: list[Mount] = []
    sources: list[str] = []
    for mount in spec.mounts:
        if mount.kind == "bind" and mount.source not in _DEVICE_SOURCES:
            assert mount.source is not None  # noqa: S101
            mounts.append(mount.model_copy(update={"source": f"{INPUTS}/{len(sources)}"}))
            sources.append(mount.source)
        else:
            mounts.append(mount)
    return mounts, sources


def guest_spec(spec: SandboxSpec, mounts: list[Mount]) -> bytes:
    """Write ``spec`` with ``mounts`` in the form guest_init.c reads."""
    words: list[str] = ["program", spec.program]
    for arg in spec.args:
        words += ["arg", arg]
    for key, value in spec.env.items():
        words += ["env", f"{key}={value}"]
    words += ["cwd", spec.cwd, "hostname", spec.hostname, "port", str(PORT)]
    words += ["id", str(spec.uid_map.inside), str(spec.gid_map.inside)]
    for limit in spec.rlimits:
        words += ["rlimit", str(_RLIMITS[limit.name]), str(limit.soft), str(limit.hard)]
    for mount in mounts:
        flags, data = mount_flags(mount)
        words += ["mount", mount.kind, mount.destination, mount.source or "", str(flags), data]
    for name, path in spec.outputs.items():
        words += ["output", name, path]
    words.append("end")
    encoded = [word.encode() for word in words]
    for word in encoded:
        if b"\0" in word:
            raise ValueError("the sandbox spec holds a NUL byte")
    return b"".join(word + b"\0" for word in encoded)


def initramfs(init: bytes, spec: bytes, machine: str) -> bytes:
    """Return the initramfs of one run."""
    directory = stat.S_IFDIR | 0o755
    return newc.archive(
        [
            newc.Entry("dev", directory),
            newc.Entry("dev/console", stat.S_IFCHR | 0o600, rdev=(5, 1)),
            newc.Entry("proc", directory),
            newc.Entry("inputs", directory),
            newc.Entry("sandbox", directory),
            newc.Entry("cloche", directory),
            newc.Entry("cloche/spec", stat.S_IFREG | 0o444, spec),
            newc.Entry("cloche/seccomp.bpf", stat.S_IFREG | 0o444, seccomp.filter_program(machine)),
            newc.Entry("init", stat.S_IFREG | 0o755, init),
        ]
    )


def _copy_file(source: str, target: str) -> None:
    try:
        os.link(source, target, follow_symlinks=False)
    except OSError:
        shutil.copyfile(source, target, follow_symlinks=False)
        shutil.copymode(source, target, follow_symlinks=False)


def stage(source: str, target: str) -> tuple[int, int]:
    """Copy ``source`` to ``target`` for the input image.

    Files are hard-linked where the file system allows it. Symbolic links
    are copied as links. Returns the bytes of file data and the number of
    entries. Raises ValueError for any other kind of file.
    """
    size = entries = 0
    pending = [(source, target)]
    while pending:
        here, there = pending.pop()
        info = os.lstat(here)
        entries += 1
        if stat.S_ISLNK(info.st_mode):
            os.symlink(os.readlink(here), there)
        elif stat.S_ISREG(info.st_mode):
            _copy_file(here, there)
            size += info.st_size
        elif stat.S_ISDIR(info.st_mode):
            os.mkdir(there, 0o700)
            # The final mode is set below, before the image is made, so a
            # read-only directory can still be filled.
            pending += [
                (os.path.join(here, name), os.path.join(there, name)) for name in os.listdir(here)
            ]
        else:
            raise ValueError(f"{here} is not a regular file, directory or symbolic link")
    return size, entries


def _restore_modes(sources: list[str], stage_dir: str) -> None:
    for index, source in enumerate(sources):
        if os.path.islink(source):
            continue
        for here, dirs, _ in os.walk(source):
            relative = os.path.relpath(here, source)
            there = os.path.normpath(os.path.join(stage_dir, str(index), relative))
            os.chmod(there, stat.S_IMODE(os.lstat(here).st_mode))
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(here, d))]


def remove_tree(path: str) -> None:
    """Remove ``path``, a staging tree that may hold read-only directories.

    Nothing is reported if it is missing or cannot be removed.
    """
    for here, _, _ in os.walk(path):
        with contextlib.suppress(OSError):
            os.chmod(here, 0o700)
    shutil.rmtree(path, ignore_errors=True)


def _map_to_root(uid: int, gid: int) -> None:
    os.unshare(os.CLONE_NEWUSER)
    for name, text in (("setgroups", "deny"), ("uid_map", f"0 {uid} 1"), ("gid_map", f"0 {gid} 1")):
        with open(f"/proc/self/{name}", "w", encoding="ascii") as file:
            file.write(text)


def make_input_image(sources: list[str], stage_dir: str, image: str, mkfs: str) -> None:
    """Make the ext4 image whose entry ``i`` is a copy of ``sources[i]``.

    mkfs runs in a user namespace that maps the caller to root, so files
    the caller owns belong to root in the image and all others to nobody,
    as the namespace backend shows them. Where user namespaces are not
    allowed, files keep their owners.
    """
    os.mkdir(stage_dir, 0o755)
    size = entries = 0
    for index, source in enumerate(sources):
        more, count = stage(source, os.path.join(stage_dir, str(index)))
        size += more
        entries += count
    _restore_modes(sources, stage_dir)
    total = size + size // 10 + entries * _ENTRY_COST + _IMAGE_SLACK
    total = -(-total // _MIB) * _MIB
    with open(image, "wb") as file:
        file.truncate(total)
    command = [
        mkfs,
        "-q",
        "-F",
        "-L",
        INPUT_LABEL,
        "-O",
        "^has_journal",
        "-m",
        "0",
        "-N",
        str(entries + 1024),
        "-E",
        "root_owner=0:0",
        "-d",
        stage_dir,
        image,
    ]
    ids = (os.getuid(), os.getgid())
    try:
        subprocess.run(  # noqa: S603
            command,
            check=True,
            capture_output=True,
            text=True,
            preexec_fn=lambda: _map_to_root(*ids),
        )
    except subprocess.SubprocessError as error:
        if isinstance(error, subprocess.CalledProcessError):
            raise
        subprocess.run(command, check=True, capture_output=True, text=True)  # noqa: S603


def make_output_image(image: str, mib: int) -> None:
    """Make the sparse output device of ``mib`` MiB."""
    with open(image, "wb") as file:
        file.truncate(mib << 20)


def firecracker_config(config: MicroVMConfig, files: VMFiles) -> dict[str, object]:
    """Return the Firecracker configuration of one virtual machine."""
    return {
        "boot-source": {
            "kernel_image_path": files.kernel,
            "initrd_path": files.initramfs,
            "boot_args": " ".join((*KERNEL_ARGS, "pci=off")),
        },
        "drives": [
            {
                "drive_id": "inputs",
                "path_on_host": files.inputs,
                "is_root_device": False,
                "is_read_only": True,
            },
            {
                "drive_id": "outputs",
                "path_on_host": files.outputs,
                "is_root_device": False,
                "is_read_only": False,
            },
        ],
        "machine-config": {"vcpu_count": config.cpus, "mem_size_mib": config.memory_mib},
        "vsock": {"guest_cid": GUEST_CID, "uds_path": files.vsock},
        "network-interfaces": [],
    }


def vmm_command(config: MicroVMConfig, vmm: str, files: VMFiles) -> list[str]:
    """Return the command that boots one virtual machine with ``vmm``.

    Firecracker reads its configuration from ``files.config``, which the
    caller writes with firecracker_config. No command adds a network
    device.
    """
    cmdline = " ".join(KERNEL_ARGS)
    if config.vmm == "firecracker":
        return [vmm, "--no-api", "--config-file", files.config, "--level", "Error"]
    if config.vmm == "cloud-hypervisor":
        return [
            vmm,
            "--kernel",
            files.kernel,
            "--initramfs",
            files.initramfs,
            "--cmdline",
            cmdline,
            "--cpus",
            f"boot={config.cpus}",
            "--memory",
            f"size={config.memory_mib}M",
            "--disk",
            f"path={files.inputs},readonly=on,image_type=raw,sparse=off",
            f"path={files.outputs},image_type=raw,sparse=off",
            "--vsock",
            f"cid={GUEST_CID},socket={files.vsock}",
            "--serial",
            "tty",
            "--console",
            "off",
        ]
    return [
        vmm,
        "--kernel",
        files.kernel,
        "--initrd",
        files.initramfs,
        "--cmdline",
        cmdline,
        "--processors",
        str(config.cpus),
        "--memory",
        f"{config.memory_mib}MB",
        "--virtio-blk",
        f"file:{files.inputs},ro",
        "--virtio-blk",
        f"file:{files.outputs}",
        "--virtio-vsock-path",
        files.vsock,
        "--com1",
        "console",
    ]


class MicroVMBackend:
    """Runs programs in a virtual machine with no network device."""

    name = "microvm"

    def __init__(self, config: MicroVMConfig | None = None):
        """Use ``config``; the backend is unavailable without a kernel and init."""
        self.config = config if config is not None else MicroVMConfig()

    def status(self) -> BackendStatus:
        """Test whether this machine can run the backend."""
        return microvm_status(self.config)

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        """Start the helper for ``job``, as NamespaceBackend.start does."""
        vmm = find_vmm(self.config) or self.config.vmm
        payload = MicroVMRun(job=job, config=self.config, vmm=vmm)
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


def _die_with_parent() -> None:
    libc.prctl(libc.PR_SET_PDEATHSIG, signal.SIGKILL)


def _accept(
    listener: socket.socket, process: subprocess.Popen[bytes], timeout: float
) -> socket.socket:
    deadline = time.monotonic() + timeout
    listener.settimeout(0.1)
    while True:
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            status = process.poll()
            if status is not None:
                raise RuntimeError(
                    f"the virtual machine stopped before its init connected (status {status})"
                ) from None
            if time.monotonic() > deadline:
                raise RuntimeError(f"the guest init did not connect within {timeout} s") from None
            continue
        connection.settimeout(None)
        return connection


def _lines(connection: socket.socket) -> list[str]:
    """Read lines up to the one after "ready", which ends the run, or to the end."""
    data = b""
    while chunk := connection.recv(4096):
        data += chunk
        lines = data.split(b"\n")
        if len(lines) > 2 or len(data) > 1 << 16:
            break
    return [line.decode("utf-8", errors="replace") for line in data.split(b"\n") if line]


def _stop(process: subprocess.Popen[bytes]) -> None:
    # The guest flushed the output device before its last line, so the
    # monitor holds nothing left to write. Not every monitor exits when
    # the guest powers off, so it is stopped here.
    process.kill()
    process.wait()


def _verdict(final: str) -> str | None:
    """Return the reason a run failed, from the last line of the guest, or None."""
    kind, _, value = final.partition(" ")
    if kind == "exited":
        return None if value == "0" else f"the program exited with status {value}"
    if kind == "killed":
        return f"the program was killed by signal {value}"
    if kind == "error":
        prefix = "sandbox setup failed: "
        return value if value.startswith(prefix) else prefix + value
    return f"the guest init sent an unknown line: {final[:200]}"


def _collect(job: SandboxJob, outputs_image: str) -> HelperReport | None:
    spec = job.spec
    try:
        with open(outputs_image, "rb") as stream:
            found = newc.extract(stream, job.out_dir, spec.outputs)
    except (OSError, ValueError) as error:
        return HelperReport(kind="failed", error=f"cannot copy the outputs: {error}")
    for output, path in spec.outputs.items():
        if output not in found:
            return HelperReport(
                kind="failed", error=f"the program did not create output {output} ({path})"
            )
    return None


def _boot(run: MicroVMRun, work: str, report: BinaryIO) -> HelperReport:
    job, config = run.job, run.config
    assert config.kernel is not None and config.init is not None  # noqa: S101
    mkfs = find_mkfs()
    if mkfs is None:
        return HelperReport(kind="failed", error="sandbox setup failed: mkfs.ext4 is not installed")
    files = VMFiles(
        kernel=os.path.abspath(config.kernel),
        initramfs=os.path.join(work, "initramfs.cpio"),
        inputs=os.path.join(work, "inputs.ext4"),
        outputs=os.path.join(work, "outputs.img"),
        vsock="v",
        config=os.path.join(work, "vm.json"),
    )
    mounts, sources = guest_mounts(job.spec)
    make_input_image(sources, os.path.join(work, "inputs"), files.inputs, mkfs)
    remove_tree(os.path.join(work, "inputs"))
    make_output_image(files.outputs, config.output_mib)
    init = Path(config.init).read_bytes()
    Path(files.initramfs).write_bytes(
        initramfs(init, guest_spec(job.spec, mounts), job.spec.machine)
    )
    Path(files.config).write_text(json.dumps(firecracker_config(config, files)), encoding="utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            listener.bind(f"/proc/self/fd/{directory}/{files.vsock}_{PORT}")
        finally:
            os.close(directory)
        listener.listen(1)
        started = time.monotonic()
        process = subprocess.Popen(  # noqa: S603
            vmm_command(config, run.vmm, files),
            stdin=subprocess.DEVNULL,
            cwd=work,
            env={},
            preexec_fn=_die_with_parent,
        )
        try:
            _report(report, HelperReport(kind="started", pid=process.pid))
            connection = _accept(listener, process, config.boot_timeout)
            boot = time.monotonic() - started
            with connection:
                lines = _lines(connection)
        except RuntimeError as error:
            process.kill()
            process.wait()
            return HelperReport(kind="failed", error=str(error))
        _stop(process)
    if not lines or lines[0] != "ready":
        return HelperReport(kind="failed", error="the guest init did not say ready")
    if len(lines) < 2:
        return HelperReport(kind="failed", error="the virtual machine stopped without a result")
    reason = _verdict(lines[-1])
    if reason is not None:
        return HelperReport(kind="failed", error=reason, boot_seconds=boot)
    failure = _collect(job, files.outputs)
    if failure is not None:
        return failure.model_copy(update={"boot_seconds": boot})
    return HelperReport(kind="finished", boot_seconds=boot)


def _run(run: MicroVMRun, report: BinaryIO) -> HelperReport:
    _die_with_parent()
    if os.getppid() != run.job.parent_pid:
        return HelperReport(kind="failed", error="the supervisor exited")
    # Everything of the run, the sockets too, is in the caller's work
    # directory, so a run killed by its time limit leaves nothing elsewhere.
    work = os.path.abspath(os.path.join(os.path.dirname(run.job.root), "vm"))
    os.mkdir(work, 0o700)
    try:
        return _boot(run, work, report)
    finally:
        remove_tree(work)


_HELPER = f"import sys; from {__name__} import main; sys.exit(main(sys.argv))"
"""The helper's program. ``-m`` would warn, since the package imports this module."""


def main(argv: list[str]) -> int:
    """Run one program in a virtual machine. ``argv[1]`` is the status pipe."""
    with os.fdopen(int(argv[1]), "wb") as report:
        try:
            run = MicroVMRun.model_validate_json(sys.stdin.buffer.read())
            result = _run(run, report)
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or "").strip().splitlines()
            text = detail[-1] if detail else f"exit status {error.returncode}"
            result = HelperReport(kind="failed", error=f"sandbox setup failed: {text}")
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


__all__ = [
    "GUEST_INIT_SOURCE",
    "PORT",
    "VMMS",
    "MicroVMBackend",
    "MicroVMConfig",
    "build_guest_init",
    "find_vmm",
    "guest_spec",
    "microvm_status",
    "vmm_command",
]
