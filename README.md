# Cloche

Cloche runs a program in an unprivileged Linux sandbox. It is a Python
library first, with a small command on top. It needs no root, no daemon
and no container image: the program sees only the host paths you bind
into the sandbox, read-only, and a few empty writable directories. When
the program succeeds, the outputs you declared are copied out.

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

Alpha. The namespace backend works on x86_64 and aarch64 Linux with
unprivileged user namespaces enabled. `oci` and `microvm` backends are
planned; `cloche oci-config` already prints the OCI runtime configuration
of a sandbox, for use with runc or crun. The coverage floor is 80%.

## Install

Cloche is not on PyPI yet. To use it in another project, install it from
its repository:

```sh
pip install git+https://github.com/PacketFive/cloche.git
```

To work on Cloche itself:

```sh
pip install --config-settings editable_mode=strict -e '.[dev]'
pybootstrap check
```

Python 3.12 or later is required. The only runtime dependency is
Pydantic 2. The `dev` extra installs
[pybootstrap](https://github.com/packetfive/pybootstrap) and the tools its
gates drive: ruff, pyright, and pytest with coverage. The tests in
`tests/test_run.py` run real sandboxes; they need unprivileged user
namespaces and a C compiler that links statically, and are skipped
otherwise.

Run `cloche status` to see whether the sandbox can run on a machine and,
if not, why. On Ubuntu 23.10 and later, AppArmor may restrict
unprivileged user namespaces; the reason then names the sysctl involved.

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

### The command

```sh
cloche run --bind /usr --bind /lib --bind /lib64 --output greeting=/build/greeting \
    /usr/bin/sh -c 'echo hello > /build/greeting'
cloche oci-config --bind /usr /usr/bin/true
cloche status
```

`cloche run` streams the log to standard error and prints one line per
output: its name and the host path it was copied to. `--bind SOURCE` binds
a path at the same place; `--bind SOURCE:DESTINATION` moves it. `--dir`,
`--env NAME=VALUE`, `--name`, `--timeout`, `--max-silent-time`,
`--max-open-files` and `--work DIR` map to the fields above. Everything
after the program is passed to it. Since `PATH` is fixed, name programs by
their full path, or run `/usr/bin/env PATH=/usr/bin ...`.

## Layout

| Module | Role |
| --- | --- |
| `models.py` | `Command`, `Bind` and `Limits`, the Pydantic models a caller fills in |
| `spec.py` | `make_spec`, the `SandboxSpec` model and the OCI runtime configuration |
| `environment.py` | The fixed environment |
| `seccomp.py` | The seccomp filter, as rules and as a packed BPF program |
| `namespaces.py` | The namespace backend: the helper that builds the sandbox and copies outputs out |
| `runner.py` | `run`: supervises the helper, captures the log and enforces time limits |
| `backends.py` | The `Backend` protocol and `select_backend` |
| `probe.py` | `backend_status` and the user namespace probe |
| `libc.py` | The few system calls Python does not expose |
| `errors.py` | `ClocheError` and its subclasses |
| `cli.py` | The `cloche` command |

## License

GPL-2.0-only.
