# SPDX-License-Identifier: GPL-2.0
"""The sandbox description every backend consumes.

make_spec turns a Command and Limits into a SandboxSpec: the program to
run, its environment, the mounts that make up the filesystem, the id
mappings and the resource limits. The namespace backend applies it
directly, and oci_config writes the same description as an OCI runtime
configuration, so an OCI runtime such as crun can run it too.
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from . import seccomp
from .environment import program_environment
from .errors import InvalidCommand, SandboxUnavailable
from .models import BUILD_DIR, Command, Limits, Model, is_below

HOSTNAME = "localhost"
DEVICES: tuple[str, ...] = ("null", "zero", "full", "random", "urandom")
TMPFS_OPTIONS: tuple[str, ...] = ("nosuid", "nodev", "mode=0755")


class Mount(Model):
    """One mount of the sandbox filesystem, applied in the order listed.

    ``source`` is set for a bind mount only, and is a host path. ``options``
    are the flags and data of the mount, such as ``nosuid`` or
    ``mode=0755``.
    """

    destination: str
    kind: Literal["tmpfs", "bind", "proc"]
    source: str | None = None
    read_only: bool = False
    options: tuple[str, ...] = ()


class IdMapping(Model):
    """Maps ``size`` ids from ``inside`` the user namespace to ``outside`` it."""

    inside: int
    outside: int
    size: int = 1


class Rlimit(Model):
    """A resource limit set before the program starts."""

    name: Literal["RLIMIT_CORE", "RLIMIT_NOFILE"]
    soft: int
    hard: int


class SandboxSpec(Model):
    """Everything a backend needs to run one program.

    ``outputs`` maps each output name to the path inside the sandbox that
    the program creates.
    """

    name: str
    machine: str
    program: str
    args: tuple[str, ...]
    env: dict[str, str]
    cwd: str = BUILD_DIR
    hostname: str = HOSTNAME
    outputs: dict[str, str]
    mounts: tuple[Mount, ...]
    uid_map: IdMapping
    gid_map: IdMapping
    rlimits: tuple[Rlimit, ...]


class SandboxJob(Model):
    """A SandboxSpec with the host paths of one run.

    ``root`` is an empty host directory the sandbox root is mounted on,
    and each output is copied into ``out_dir`` under its name.
    ``parent_pid`` is the process that supervises the run.
    """

    spec: SandboxSpec
    root: str
    out_dir: str
    parent_pid: int


def _check(command: Command) -> None:
    """Raise InvalidCommand if the fields of ``command`` do not fit together."""
    name = command.name
    destinations = [bind.destination for bind in command.binds]
    places = [*command.directories, *destinations]
    if len(set(places)) != len(places):
        raise InvalidCommand(f"{name}: two binds or directories share a path")
    for bind in command.binds:
        for other in destinations:
            # A nested target would be created and mounted through the
            # outer bind's tree on the host, before the root is pivoted, so
            # a symbolic link there could place it outside the sandbox.
            if other != bind.destination and is_below(other, bind.destination):
                raise InvalidCommand(
                    f"{name}: bind {other} is inside the bind at {bind.destination}"
                )
        for directory in command.directories:
            if is_below(directory, bind.destination):
                raise InvalidCommand(
                    f"{name}: directory {directory} is inside the bind at {bind.destination}"
                )
    program = command.program
    if not any(is_below(program, destination) for destination in destinations):
        raise InvalidCommand(f"{name}: program {program} is not inside any bind")
    writable = (BUILD_DIR, *command.directories)
    for output, path in command.outputs.items():
        if path in writable or not any(is_below(path, place) for place in writable):
            raise InvalidCommand(
                f"{name}: output {output} ({path}) must be below {BUILD_DIR} or a directory"
            )
        if any(is_below(path, destination) for destination in destinations):
            raise InvalidCommand(f"{name}: output {output} ({path}) is inside a bind")


def make_spec(
    command: Command,
    limits: Limits | None = None,
    *,
    uid: int,
    gid: int,
    machine: str,
) -> SandboxSpec:
    """Describe the sandbox that runs ``command``.

    The program runs as root in a user namespace, mapped to ``uid`` and
    ``gid`` outside it. Directories are mounted before binds, and binds in
    order of their destination, so a bind is never hidden by a later mount.

    Raises InvalidCommand if the command breaks a rule of models.py or
    environment.py, and SandboxUnavailable if no seccomp filter exists for
    ``machine``.
    """
    if machine not in seccomp.AUDIT_ARCH:
        raise SandboxUnavailable(f"the sandbox does not support {machine}")
    limits = limits if limits is not None else Limits()
    _check(command)
    env = program_environment(command)
    mounts = [
        Mount(destination=BUILD_DIR, kind="tmpfs", options=TMPFS_OPTIONS),
        *(
            Mount(destination=path, kind="tmpfs", options=TMPFS_OPTIONS)
            for path in sorted(command.directories)
        ),
        *(
            Mount(
                destination=bind.destination,
                kind="bind",
                source=bind.source,
                read_only=True,
                options=("nosuid", "nodev"),
            )
            for bind in sorted(command.binds, key=lambda bind: bind.destination)
        ),
        Mount(destination="/proc", kind="proc", options=("nosuid", "nodev", "noexec")),
        Mount(destination="/dev", kind="tmpfs", options=("nosuid", "noexec", "mode=0755")),
        *(
            Mount(
                destination=f"/dev/{name}",
                kind="bind",
                source=f"/dev/{name}",
                options=("nosuid", "noexec"),
            )
            for name in DEVICES
        ),
        Mount(
            destination="/dev/shm",  # noqa: S108
            kind="tmpfs",
            options=("nosuid", "nodev", "noexec", "mode=1777"),
        ),
    ]
    return SandboxSpec(
        name=command.name,
        machine=machine,
        program=command.program,
        args=command.args,
        env=env,
        outputs=dict(command.outputs),
        mounts=tuple(mounts),
        uid_map=IdMapping(inside=0, outside=uid),
        gid_map=IdMapping(inside=0, outside=gid),
        rlimits=(
            Rlimit(name="RLIMIT_CORE", soft=0, hard=0),
            Rlimit(name="RLIMIT_NOFILE", soft=limits.max_open_files, hard=limits.max_open_files),
        ),
    )


class _Oci(Model):
    model_config = ConfigDict(
        alias_generator=to_camel,
        validate_by_name=True,
        validate_by_alias=True,
        serialize_by_alias=True,
    )


class OciUser(_Oci):
    """``process.user``."""

    uid: int = 0
    gid: int = 0


class OciRlimit(_Oci):
    """One entry of ``process.rlimits``."""

    type: str
    hard: int
    soft: int


class OciCapabilities(_Oci):
    """``process.capabilities``: every set is empty in the sandbox."""

    bounding: tuple[str, ...] = ()
    effective: tuple[str, ...] = ()
    permitted: tuple[str, ...] = ()
    inheritable: tuple[str, ...] = ()
    ambient: tuple[str, ...] = ()


class OciProcess(_Oci):
    """``process``."""

    terminal: bool = False
    user: OciUser = OciUser()
    args: tuple[str, ...]
    env: tuple[str, ...]
    cwd: str
    no_new_privileges: bool = True
    capabilities: OciCapabilities = OciCapabilities()
    rlimits: tuple[OciRlimit, ...]


class OciRoot(_Oci):
    """``root``: an empty directory the runtime provides."""

    path: str = "rootfs"
    readonly: bool = False


class OciMount(_Oci):
    """One entry of ``mounts``."""

    destination: str
    type: str
    source: str
    options: tuple[str, ...]


class OciNamespace(_Oci):
    """One entry of ``linux.namespaces``."""

    type: str


class OciIdMapping(_Oci):
    """One entry of ``linux.uidMappings`` or ``linux.gidMappings``."""

    container_id: int = Field(alias="containerID")
    host_id: int = Field(alias="hostID")
    size: int


class OciSeccompArg(_Oci):
    """One condition of a seccomp rule."""

    index: int
    value: int
    value_two: int
    op: str


class OciSyscall(_Oci):
    """One entry of ``linux.seccomp.syscalls``."""

    names: tuple[str, ...]
    action: str
    errno_ret: int
    args: tuple[OciSeccompArg, ...] = ()


class OciSeccomp(_Oci):
    """``linux.seccomp``."""

    default_action: str = "SCMP_ACT_ALLOW"
    architectures: tuple[str, ...]
    syscalls: tuple[OciSyscall, ...]


class OciLinux(_Oci):
    """``linux``."""

    namespaces: tuple[OciNamespace, ...]
    uid_mappings: tuple[OciIdMapping, ...]
    gid_mappings: tuple[OciIdMapping, ...]
    seccomp: OciSeccomp


class OciConfig(_Oci):
    """An OCI runtime configuration, ``config.json``."""

    oci_version: str = "1.2.0"
    process: OciProcess
    root: OciRoot = OciRoot()
    hostname: str
    mounts: tuple[OciMount, ...]
    linux: OciLinux


NAMESPACES: tuple[str, ...] = ("user", "mount", "network", "pid", "uts", "ipc")


def _oci_mount(mount: Mount) -> OciMount:
    options = list(mount.options)
    if mount.kind == "bind":
        options = ["rbind", *options]
    if mount.read_only:
        options.append("ro")
    source = mount.source if mount.source is not None else mount.kind
    return OciMount(
        destination=mount.destination, type=mount.kind, source=source, options=tuple(options)
    )


def _oci_mapping(mapping: IdMapping) -> OciIdMapping:
    return OciIdMapping(containerID=mapping.inside, hostID=mapping.outside, size=mapping.size)


def oci_config(spec: SandboxSpec) -> OciConfig:
    """Write ``spec`` as an OCI runtime configuration."""
    return OciConfig(
        process=OciProcess(
            args=(spec.program, *spec.args),
            env=tuple(f"{k}={v}" for k, v in spec.env.items()),
            cwd=spec.cwd,
            rlimits=tuple(OciRlimit(type=r.name, hard=r.hard, soft=r.soft) for r in spec.rlimits),
        ),
        hostname=spec.hostname,
        mounts=tuple(_oci_mount(m) for m in spec.mounts),
        linux=OciLinux(
            namespaces=tuple(OciNamespace(type=n) for n in NAMESPACES),
            uid_mappings=(_oci_mapping(spec.uid_map),),
            gid_mappings=(_oci_mapping(spec.gid_map),),
            seccomp=OciSeccomp(
                architectures=(seccomp.OCI_ARCH[spec.machine],),
                syscalls=tuple(
                    OciSyscall.model_validate(entry) for entry in seccomp.oci_syscalls(spec.machine)
                ),
            ),
        ),
    )


class HelperReport(Model):
    """One line the sandbox helper writes on its status pipe.

    ``started`` carries the host pid of the program's PID 1, so the runner
    can kill the run. ``finished`` or ``failed`` ends the run; ``failed``
    carries the reason.
    """

    kind: Literal["started", "finished", "failed"]
    pid: int | None = None
    error: str | None = None
