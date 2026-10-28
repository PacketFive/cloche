# SPDX-License-Identifier: GPL-2.0
"""The namespace backend.

NamespaceBackend.start runs this module in a fresh interpreter, the
helper, with the SandboxJob as JSON on stdin. A fresh process is used
because the kernel refuses to move a process with several threads into a
new user namespace, and forking a daemon that runs threads is unsafe.

The helper creates the user, mount, network, UTS, IPC and PID
namespaces, maps its own uid and gid to root inside them and builds the
sandbox filesystem on a tmpfs at ``job.root``. It then forks the
program's PID 1, which mounts /proc, sets the host name, brings up the
loopback interface, makes the tmpfs its root, sets the umask to 022,
drops every capability, applies the resource limits and the seccomp
filter and runs the program.
When the program exits, the whole PID namespace ends with it, and the
helper copies the outputs out of the tmpfs into ``job.out_dir``.

The helper reports on the status pipe with one HelperReport per line.
Its stdout and stderr, which the program inherits, are the log.
"""

from __future__ import annotations

import errno
import fcntl
import os
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
from typing import TYPE_CHECKING, BinaryIO

from . import libc, seccomp
from .spec import HelperReport, Mount, SandboxJob, SandboxSpec

if TYPE_CHECKING:
    from .probe import BackendStatus

NAMESPACES = (
    os.CLONE_NEWUSER
    | os.CLONE_NEWNS
    | os.CLONE_NEWNET
    | os.CLONE_NEWUTS
    | os.CLONE_NEWIPC
    | os.CLONE_NEWPID
)

_FLAGS: dict[str, int] = {
    "ro": libc.MS_RDONLY,
    "nosuid": libc.MS_NOSUID,
    "nodev": libc.MS_NODEV,
    "noexec": libc.MS_NOEXEC,
}

# Flags of a mount that a user namespace may not clear, as statvfs reports
# them, with the mount flag that keeps each one on a remount.
_LOCKED: tuple[tuple[int, int], ...] = (
    (os.ST_RDONLY, libc.MS_RDONLY),
    (os.ST_NOSUID, libc.MS_NOSUID),
    (os.ST_NODEV, libc.MS_NODEV),
    (os.ST_NOEXEC, libc.MS_NOEXEC),
    (os.ST_NOATIME, libc.MS_NOATIME),
    (os.ST_NODIRATIME, libc.MS_NODIRATIME),
    (os.ST_RELATIME, libc.MS_RELATIME),
)

UMASK = 0o022

_SIOCGIFFLAGS = 0x8913
_SIOCSIFFLAGS = 0x8914
_IFF_UP = 0x1
_IFREQ = "16sh22x"

_DEV_LINKS: tuple[tuple[str, str], ...] = (
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
)

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CHUNK = 1 << 20


class NamespaceBackend:
    """Runs programs in unprivileged Linux namespaces."""

    name = "namespaces"

    def status(self) -> BackendStatus:
        """Test whether this machine can run the backend."""
        from .probe import namespaces_status

        return namespaces_status()

    def start(self, job: SandboxJob, *, status_fd: int, log_fd: int) -> subprocess.Popen[bytes]:
        """Start the helper for ``job``.

        The helper writes its reports on ``status_fd`` and the log on
        ``log_fd``. The caller keeps both read ends and closes these.
        """
        process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-I", "-m", __name__, str(status_fd)],
            stdin=subprocess.PIPE,
            stdout=log_fd,
            stderr=log_fd,
            env={},
            pass_fds=(status_fd,),
            start_new_session=True,
        )
        assert process.stdin is not None  # noqa: S101
        try:
            process.stdin.write(job.model_dump_json().encode())
            process.stdin.close()
        except BrokenPipeError:
            pass
        return process


def _report(stream: BinaryIO, report: HelperReport) -> None:
    stream.write(report.model_dump_json().encode() + b"\n")
    stream.flush()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="ascii") as file:
        file.write(text)


def _split_options(options: tuple[str, ...]) -> tuple[int, str | None]:
    flags = 0
    data: list[str] = []
    for option in options:
        if option in _FLAGS:
            flags |= _FLAGS[option]
        else:
            data.append(option)
    return flags, ",".join(data) or None


def _apply_mount(job: SandboxJob, mount: Mount) -> None:
    target = job.root + mount.destination
    flags, data = _split_options(mount.options)
    if mount.read_only:
        flags |= libc.MS_RDONLY
    if mount.kind == "tmpfs":
        os.makedirs(target, mode=0o755, exist_ok=True)
        libc.mount("tmpfs", target, "tmpfs", flags, data)
        return
    if mount.kind != "bind" or mount.source is None:
        raise ValueError(f"cannot apply a {mount.kind} mount at {mount.destination}")
    source = mount.source
    # A bound path may itself be a symbolic link. Recreate it as a link
    # rather than bind-mounting it, which would expose the host path it
    # names, and bind through an O_PATH descriptor so nothing is followed.
    handle = os.open(source, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(handle)
        if stat.S_ISLNK(info.st_mode):
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            os.symlink(os.readlink(source), target)
            return
        if stat.S_ISDIR(info.st_mode):
            os.makedirs(target, mode=0o755, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o644))
        libc.mount(f"/proc/self/fd/{handle}", target, None, libc.MS_BIND | libc.MS_REC)
    finally:
        os.close(handle)
    locked = os.statvfs(target).f_flag
    for statvfs_flag, mount_flag in _LOCKED:
        if locked & statvfs_flag:
            flags |= mount_flag
    libc.mount(None, target, None, libc.MS_REMOUNT | libc.MS_BIND | flags)


def _setup(job: SandboxJob) -> None:
    spec = job.spec
    os.unshare(NAMESPACES)
    _write("/proc/self/setgroups", "deny")
    _write(
        "/proc/self/uid_map", f"{spec.uid_map.inside} {spec.uid_map.outside} {spec.uid_map.size}"
    )
    _write(
        "/proc/self/gid_map", f"{spec.gid_map.inside} {spec.gid_map.outside} {spec.gid_map.size}"
    )
    libc.mount(None, "/", None, libc.MS_REC | libc.MS_PRIVATE)
    libc.mount("tmpfs", job.root, "tmpfs", libc.MS_NOSUID | libc.MS_NODEV, "mode=0755")
    for mount in spec.mounts:
        if mount.kind != "proc":
            _apply_mount(job, mount)
    for name, target in _DEV_LINKS:
        os.symlink(target, f"{job.root}/dev/{name}")


def _loopback_up() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = struct.pack(_IFREQ, b"lo", 0)
        name, flags = struct.unpack(_IFREQ, fcntl.ioctl(sock, _SIOCGIFFLAGS, request))
        fcntl.ioctl(sock, _SIOCSIFFLAGS, struct.pack(_IFREQ, name, flags | _IFF_UP))


def _program(job: SandboxJob, alive_fd: int, error_fd: int) -> None:
    """Become the program. Runs as PID 1 of the new PID namespace."""
    spec = job.spec
    libc.prctl(libc.PR_SET_PDEATHSIG, signal.SIGKILL)
    poller = select.poll()
    poller.register(alive_fd, select.POLLIN)
    if poller.poll(0):
        raise RuntimeError("the sandbox helper exited")
    os.unshare(os.CLONE_NEWNS)
    for mount in spec.mounts:
        if mount.kind == "proc":
            flags, data = _split_options(mount.options)
            target = job.root + mount.destination
            os.makedirs(target, mode=0o755, exist_ok=True)
            libc.mount("proc", target, "proc", flags, data)
    socket.sethostname(spec.hostname)
    libc.setdomainname("(none)")
    _loopback_up()
    os.chdir(job.root)
    libc.pivot_root(".", ".")
    libc.umount2(".", libc.MNT_DETACH)
    os.chdir(spec.cwd)
    os.umask(UMASK)
    null = os.open("/dev/null", os.O_RDONLY)
    os.dup2(null, 0)
    os.closerange(3, error_fd)
    os.closerange(error_fd + 1, os.sysconf("SC_OPEN_MAX"))
    for limit in spec.rlimits:
        resource.setrlimit(getattr(resource, limit.name), (limit.soft, limit.hard))
    libc.drop_capabilities()
    libc.prctl(libc.PR_SET_NO_NEW_PRIVS, 1)
    seccomp.install(spec.machine)
    os.execve(spec.program, [spec.program, *spec.args], spec.env)  # noqa: S606


_Frame = tuple[int, int, list[str], int]
"""A directory being copied: source fd, target fd, names left, mode."""


def _copy_entry(src_dir: int, name: str, dst_dir: int, dst_name: str) -> _Frame | None:
    info = os.stat(name, dir_fd=src_dir, follow_symlinks=False)
    mode = stat.S_IMODE(info.st_mode) & 0o777
    if stat.S_ISLNK(info.st_mode):
        os.symlink(os.readlink(name, dir_fd=src_dir), dst_name, dir_fd=dst_dir)
    elif stat.S_ISREG(info.st_mode):
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src_dir)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            target = os.open(dst_name, flags, 0o600, dir_fd=dst_dir)
            try:
                while chunk := os.read(source, _CHUNK):
                    os.write(target, chunk)
                os.fchmod(target, mode)
            finally:
                os.close(target)
        finally:
            os.close(source)
    elif stat.S_ISDIR(info.st_mode):
        os.mkdir(dst_name, 0o700, dir_fd=dst_dir)
        source = os.open(name, _DIRECTORY, dir_fd=src_dir)
        try:
            target = os.open(dst_name, _DIRECTORY, dir_fd=dst_dir)
        except BaseException:
            os.close(source)
            raise
        try:
            with os.scandir(source) as entries:
                names = sorted((entry.name for entry in entries), reverse=True)
        except BaseException:
            os.close(source)
            os.close(target)
            raise
        return source, target, names, mode
    else:
        raise ValueError(f"{name} is not a regular file, directory or symbolic link")
    return None


def copy_out(root: str, path: str, destination: str) -> None:
    """Copy ``path`` under ``root`` to ``destination``.

    Symbolic links are copied as links and never followed, so a link the
    program made cannot point the copy at a host file. Set-user-ID and
    set-group-ID bits are dropped. Any other kind of file is an error.
    """
    parts = path.strip("/").split("/")
    current = os.open(root, _DIRECTORY)
    try:
        for part in parts[:-1]:
            following = os.open(part, _DIRECTORY, dir_fd=current)
            os.close(current)
            current = following
        target_dir = os.open(os.path.dirname(destination), _DIRECTORY)
        # Depth first, so open descriptors grow with the depth of the
        # tree, not its size. A directory gets its mode once it is full.
        stack: list[_Frame] = []
        try:
            frame = _copy_entry(current, parts[-1], target_dir, os.path.basename(destination))
            if frame is not None:
                stack.append(frame)
            while stack:
                source, target, names, mode = stack[-1]
                if names:
                    name = names.pop()
                    frame = _copy_entry(source, name, target, name)
                    if frame is not None:
                        stack.append(frame)
                    continue
                stack.pop()
                os.close(source)
                try:
                    os.fchmod(target, mode)
                finally:
                    os.close(target)
        finally:
            for source, target, _, _ in stack:
                os.close(source)
                os.close(target)
            os.close(target_dir)
    finally:
        os.close(current)


def _describe(status: int) -> str:
    if os.WIFSIGNALED(status):
        return f"the program was killed by signal {os.WTERMSIG(status)}"
    return f"the program exited with status {os.waitstatus_to_exitcode(status)}"


def _run(job: SandboxJob, report: BinaryIO) -> HelperReport:
    libc.prctl(libc.PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != job.parent_pid:
        return HelperReport(kind="failed", error="the supervisor exited")
    spec: SandboxSpec = job.spec
    _setup(job)
    alive_read, alive_write = os.pipe2(os.O_CLOEXEC)
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(alive_write)
            os.close(error_read)
            _program(job, alive_read, error_write)
        except BaseException as error:
            os.write(error_write, f"{type(error).__name__}: {error}".encode()[:4096])
        finally:
            os._exit(127)
    os.close(alive_read)
    os.close(error_write)
    _report(report, HelperReport(kind="started", pid=pid))
    message = b""
    while chunk := os.read(error_read, 4096):
        message += chunk
    os.close(error_read)
    _, status = os.waitpid(pid, 0)
    os.close(alive_write)
    if message:
        return HelperReport(
            kind="failed", error=f"sandbox setup failed: {message.decode(errors='replace')}"
        )
    if status != 0:
        return HelperReport(kind="failed", error=_describe(status))
    for output, path in spec.outputs.items():
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


def main(argv: list[str]) -> int:
    """Run one program as the sandbox helper. ``argv[1]`` is the status pipe."""
    with os.fdopen(int(argv[1]), "wb") as report:
        try:
            job = SandboxJob.model_validate_json(sys.stdin.buffer.read())
            result = _run(job, report)
        except OSError as error:
            text = f"sandbox setup failed: {error.strerror or error}"
            if error.filename:
                text += f" ({error.filename})"
            if error.errno in (errno.EPERM, errno.EACCES, errno.ENOSPC):
                text += "; see cloche status"
            result = HelperReport(kind="failed", error=text)
        except Exception as error:
            result = HelperReport(kind="failed", error=f"sandbox setup failed: {error}")
        _report(report, result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
