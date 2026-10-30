# Changelog

All notable changes to Cloche are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-30

### Added

- `Limits.max_memory`, `Limits.max_cpu` and `Limits.max_processes`,
  enforced through a child cgroup per run when the caller runs in a
  delegated cgroup version 2 subtree. The cgroup is removed after the
  run, which ends every process left in it.
- `cgroup_status` and `CgroupStatus`, and a `cgroups:` line in
  `cloche status`.
- The `--max-memory`, `--max-cpu` and `--max-processes` options of
  `cloche run`.

## [1.0.0] - 2026-10-29

First release, published on PyPI.

### Added

- `run`, `Command`, `Bind`, `Limits` and `Outcome`: run a program in an
  unprivileged sandbox and copy its declared outputs out.
- The `namespaces` backend: user, mount, PID, network, UTS and IPC
  namespaces, no capabilities, `no_new_privs`, a seccomp filter, a fixed
  environment, read-only binds and a minimal `/dev`.
- The `oci` backend, for rootless crun, runc or youki.
- The `microvm` backend, for Firecracker, Cloud Hypervisor or OpenVMM,
  with its own guest kernel and the bundled guest init.
- Wall-clock and silence time limits, and a limit on open files.
- The `cloche` command, with `cloche status` to report which backends a
  machine can run and why the others cannot.

### Stability

The names in `cloche.__all__`, the fields of the Pydantic models and the
guarantees listed in the README are the public interface. Weakening a
guarantee needs a new major version. OpenVMM support follows its
documented command line and is not yet tested.
