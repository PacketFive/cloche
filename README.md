# Cloche

Cloche runs a program in an unprivileged Linux sandbox. It is a Python
library first, with a small command on top. It needs no root, no daemon
and no container image: the program sees only the host paths you bind
into the sandbox, read-only, and a few empty writable directories. When
the program succeeds, the outputs you declared are copied out.
The same sandbox can also run under a rootless OCI runtime, or in a
small virtual machine with its own kernel for a stronger boundary.

Cloche began as the build sandbox of
[PyrixOS](https://github.com/PacketFive/PyrixOS) and its package manager
Lattice, and is published on its own so any project can use it: build
tools, test runners, graders for submitted code, or anything else that
must run a program it does not trust with nothing but the inputs it was
given.

Inside the sandbox the program:

* runs as root of a new user namespace, mapped to the calling user, with
  no capabilities and `no_new_privs` set;
* has its own mount, PID, network, UTS and IPC namespaces, with only a
  loopback interface and the host name `localhost`;
* sees a new root that holds only the binds, the writable directories,
  `/build` (its working directory), `/proc`, a minimal `/dev` and
  `/dev/shm`;
* cannot remount, unmount or write to a bind;
* runs under a seccomp filter that denies setting setuid and setgid bits,
  extended attributes, keyrings and `io_uring`, and kills the program on
  any other system call ABI, such as x32;
* gets a fixed environment: `SOURCE_DATE_EPOCH=315532800`, `TZ=UTC`,
  `LANG=C.UTF-8`, `HOME=/homeless`, `TMPDIR=/build` and
  `PATH=/path-not-set`, plus the variables you set;
* has its core dumps disabled, a limit on open files, and optional
  wall-clock and silence time limits;
* ends with its sandbox: every process left behind is killed.

Outputs are copied out without following symbolic links, and setuid and
setgid bits are dropped. A special file in an output fails the run.

## Status

Stable since 1.0.0. Three backends run the same sandbox:

| Backend | Runs the program in | Needs |
| --- | --- | --- |
| `namespaces` (default) | Linux namespaces Cloche creates itself | Unprivileged user namespaces |
| `oci` | A rootless OCI runtime: crun, runc or youki | The runtime, and unprivileged user namespaces |
| `microvm` | A virtual machine with its own kernel, under Firecracker, Cloud Hypervisor or OpenVMM | KVM, the monitor, `mkfs.ext4`, a guest kernel and the guest init |

The namespace backend works on x86_64 and aarch64 Linux. The OCI backend
is tested with runc and crun, and the microVM backend on x86_64 with
Firecracker and Cloud Hypervisor. OpenVMM support follows its documented
command line and is untested. The coverage floor is 80%.

## Install

To use Cloche in another project:

```sh
pip install cloche
```

or add `cloche>=1.0,<2` to the project's dependencies. Version 1 keeps the
names in `cloche.__all__`, the fields of its models and the guarantees
above stable for every 1.x release.

To work on Cloche itself:

```sh
python -m pip install --upgrade "pip>=25.1"
pip install --group dev
pip install --config-settings editable_mode=strict -e .
pybootstrap check
```

Python 3.12 or later is required. The only runtime dependency is
Pydantic 2. The `dev` dependency group installs
[pybootstrap](https://github.com/packetfive/pybootstrap) and the tools its
gates drive: ruff, pyright, and pytest with coverage. The tests in
`tests/test_run.py` run real sandboxes on every backend; they need
unprivileged user namespaces and a C compiler that links statically, and
are skipped otherwise. The OCI cases also need a runtime, and the microVM
cases run only when `CLOCHE_TEST_KERNEL` names a guest kernel and the
monitor is in `PATH`.

Run `cloche status` to see whether the sandbox can run on a machine and,
if not, why. On Ubuntu 23.10 and later, AppArmor may restrict
unprivileged user namespaces; the reason then names the sysctl involved.

Releases are made by pushing a tag `vX.Y.Z` that matches `__version__`
and has a section in `CHANGELOG.md`. The release workflow runs the gates,
builds the package, publishes it to PyPI through trusted publishing with
attestations, and creates the GitHub release.

## Use

```python
import tempfile

from cloche import Bind, Command, Limits, run

command = Command(
    name="hello",
    program="/usr/bin/sh",
    args=("-c", "echo hello > /build/greeting"),
    binds=tuple(Bind(source=p, destination=p) for p in ("/usr", "/lib", "/lib64")),
    outputs={"greeting": "/build/greeting"},
)
outcome = run(command, tempfile.mkdtemp(), Limits(timeout=60))
print(open(outcome.outputs["greeting"]).read())  # hello
```

`run` takes a `Command`, an empty work directory and optional `Limits`. It
returns an `Outcome` with the host path of each output, the path of the
log, and the run time. The log holds everything the program wrote to its
standard output and error; pass `on_log` to receive it as it arrives.

Every field is checked by Pydantic when the model is created, and
`make_spec` checks how the fields fit together before anything starts:

| Field | Meaning |
| --- | --- |
| `name` | Label used in the log and in errors |
| `program` | Absolute path of the program inside the sandbox; must be inside a bind |
| `args` | Arguments after the program |
| `env` | Variables to set; the fixed ones above cannot be changed |
| `binds` | Host paths mounted read-only, each at its own destination |
| `directories` | Empty writable directories, in addition to `/build` |
| `outputs` | Name to path; each path must be below `/build` or a directory |

A bind whose source is a symbolic link appears as that link, not as the
path it names. Two mounts cannot share a path, a bind or directory
cannot sit inside a bind, and `/proc`, `/dev` and `/build` are reserved.

Errors derive from `ClocheError`:

| Error | Raised when |
| --- | --- |
| `InvalidCommand` | The command breaks a rule; nothing was started |
| `RunFailed` | The program failed, timed out or left an output missing; the message ends with the last lines of the log |
| `SandboxUnavailable` | The chosen backend cannot run on this machine |

Lower down, `make_spec` turns a `Command` into a `SandboxSpec`, the exact
list of mounts, ID maps, limits and seccomp rules a backend applies, and
`oci_config` turns a spec into an OCI runtime configuration.
`backend_status` reports which backends can run here, and
`select_backend` returns one or raises; Cloche never falls back to a
weaker backend.

### Resource limits

`Limits` also takes `max_memory` (bytes), `max_cpu` (CPUs, such as `0.5`)
and `max_processes`. Only a cgroup can enforce these, so they apply when
the calling process runs in a delegated cgroup version 2 subtree, for
example a systemd service with `Delegate=yes`. Each run then gets its own
child cgroup with `memory.max`, `cpu.max` and `pids.max` set, swap turned
off, and every process left in it is killed when the run ends. The first
run moves the processes of the delegated cgroup into a child named
`supervisor`, since a cgroup with processes cannot pass controllers on.
Without a delegated cgroup these three limits are not applied and the run
goes ahead; `cgroup_status()` and `cloche status` say why.

### Other backends

`run` uses the namespace backend unless `backend` names another:

```python
from cloche import MicroVMConfig, run, select_backend

oci = select_backend("oci", runtime="crun")
vm = select_backend(
    "microvm",
    microvm=MicroVMConfig(vmm="firecracker", kernel="/srv/vm/vmlinux", init="/srv/vm/init"),
)
outcome = run(command, tempfile.mkdtemp(), Limits(timeout=60), backend=vm)
```

The OCI backend writes the configuration `oci_config` returns into a
bundle and runs the runtime's `create`, `start` and `delete` as the
calling user. No daemon and no image are involved.

The microVM backend boots a virtual machine with no network device. The
guest kernel is an uncompressed `vmlinux` with virtio block, virtio vsock,
ext4, tmpfs and devtmpfs built in, such as the guest kernels Firecracker
publishes. The guest init is a small static C program shipped with
Cloche; `cloche guest-init OUTPUT` or `build_guest_init(OUTPUT)` compiles
it. The binds are copied, hard-linked where possible, into a read-only
ext4 image, so every file in them must be readable by the caller. The
program runs as root of the guest with the same mounts, seccomp filter,
limits and environment as on the other backends, without capabilities
and with `/proc/sys`, `/proc/sysrq-trigger`, `/proc/bus`, `/proc/fs` and
`/proc/irq` mounted read-only. Its outputs come back
as a `newc` archive on a sparse output device of `output_mib` MiB and
are extracted with the same rules as the other backends; a single file
cannot exceed 4 GiB. `Outcome.boot_seconds` is the time from starting
the monitor to the guest init connecting back over vsock.

### The command

```sh
cloche run --bind /usr --bind /lib --bind /lib64 --output greeting=/build/greeting \
    /usr/bin/sh -c 'echo hello > /build/greeting'
cloche oci-config --bind /usr /usr/bin/true
cloche status
cloche guest-init init
cloche run --backend microvm --kernel vmlinux --init init --bind /usr ... /usr/bin/true
```

`cloche run` streams the log to standard error and prints one line per
output: its name and the host path it was copied to. `--bind SOURCE` binds
a path at the same place; `--bind SOURCE:DESTINATION` moves it. `--dir`,
`--env NAME=VALUE`, `--name`, `--timeout`, `--max-silent-time`,
`--max-open-files`, `--max-memory MIB`, `--max-cpu N`, `--max-processes N`
and `--work DIR` map to the fields above. Everything
after the program is passed to it. Since `PATH` is fixed, name programs by
their full path, or run `/usr/bin/env PATH=/usr/bin ...`. `--backend`
chooses `namespaces`, `oci` or `microvm`; `--runtime` names the OCI
runtime, and `--vmm`, `--vmm-path`, `--kernel`, `--init`, `--memory` and
`--cpus` configure the virtual machine. `cloche status` accepts the same
backend options and ends with a line on cgroup limits.

## Layout

| Module | Role |
| --- | --- |
| `models.py` | `Command`, `Bind` and `Limits`, the Pydantic models a caller fills in |
| `spec.py` | `make_spec`, the `SandboxSpec` model and the OCI runtime configuration |
| `environment.py` | The fixed environment |
| `seccomp.py` | The seccomp filter, as rules and as a packed BPF program |
| `namespaces.py` | The namespace backend: the helper that builds the sandbox and copies outputs out |
| `oci.py` | The OCI backend: the bundle and the helper that drives the runtime |
| `microvm.py` | The microVM backend: the input image, the initramfs, the monitor and the output archive |
| `guest_init.c` | The guest init of the microVM backend |
| `newc.py` | Writing and strictly reading `newc` cpio archives |
| `runner.py` | `run`: supervises the helper, captures the log and enforces time limits |
| `cgroups.py` | The cgroup of each run under a delegated subtree, and `cgroup_status` |
| `backends.py` | The `Backend` protocol and `select_backend` |
| `probe.py` | `backend_status` and the user namespace probe |
| `libc.py` | The few system calls Python does not expose |
| `errors.py` | `ClocheError` and its subclasses |
| `cli.py` | The `cloche` command |

## License

GPL-2.0-only. See [LICENSE](LICENSE).
