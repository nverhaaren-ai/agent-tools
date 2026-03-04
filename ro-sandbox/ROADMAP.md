# ro-sandbox — Roadmap

---

## Priorities

### 1. Minimal-exposure filesystem mode

**Current behaviour**: `--ro-bind / /` exposes the entire host filesystem read-only,
including `~/.ssh`, `~/.aws/credentials`, `/etc/shadow`, and any other secrets
accessible to the calling user.

**Goal**: Make the default bind a small, predictable set of paths rather than
everything:

- The **current working directory** (read-only).
- A set of **safe system paths** needed for programs to run: system binaries
  (`/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`), libraries (`/lib`, `/lib64`,
  `/usr/lib`, `/usr/lib64`), linker config (`/etc/ld.so.cache`,
  `/etc/ld.so.conf.d`), locale/timezone data (`/usr/share/locale`,
  `/etc/localtime`), and a small set of `/etc` files commonly needed at startup
  (`nsswitch.conf`, `hosts`, `os-release`). The exact list needs to be derived
  from what a typical `ldd` dependency chain and libc startup require, and will
  vary somewhat across distros.
- `/proc`, `/dev`, `/sys`, `/tmp`, `/var/tmp`, `/run` — already handled as fresh
  mounts.

**Home directory exposure** requires an explicit opt-in. The rule: if cwd is
anywhere under `$HOME`, ro-sandbox refuses to run without a flag. The reason is
simple: even if cwd is `/home/user/project` (no secrets directly present),
`$HOME/.ssh` is adjacent and would be exposed by any bind of `$HOME`.

Proposed flags:
- `--expose PATH` — bind an additional path read-only (repeatable). Needed for
  home-relative tooling: `--expose ~/.cargo --expose ~/.rustup`.
- `--expose-home` — shorthand for `--expose $HOME`. Convenience for users who
  want the current whole-home behaviour.

This composes naturally with the planned `--output-dir` flag (writable bind of a
specific path).

---

## General ideas

### Interactive mode / TTY support

`--new-session` calls `setsid()`, which detaches the sandbox from the calling
process's controlling terminal. This closes the TIOCSTI terminal injection attack
but breaks programs that need a TTY (readline, `vim`, `sudo`, job control, etc.).

A safe interactive mode would need to allocate a fresh pseudoterminal pair
(`posix_openpt` / `openpty`), proxy it between the caller's terminal and the
sandboxed process, and filter or drop dangerous ioctl requests (particularly
`TIOCSTI` and `TIOCLINUX`) in the proxy layer rather than relying on session
separation. The proxy sits outside the sandbox, so it can enforce these
constraints without limiting what programs run inside.

### Cgroup isolation

The sandbox currently sets no resource limits. An untrusted or runaway process
can exhaust CPU, memory, or file descriptors and affect the host.

bwrap exposes `--cgroup-*` flags for attaching the sandbox to a cgroup v2
hierarchy. Wrapping that would allow configurable CPU and memory limits.
Alternatively, `systemd-run --scope` or a dedicated cgroup manager could set up
the cgroup before invoking ro-sandbox.

---

## Further reading

- [bubblewrap README](https://github.com/containers/bubblewrap/blob/main/README.md) —
  overview of what bwrap does and does not do
- [`seccompiler` crate docs](https://docs.rs/seccompiler) — the BPF compilation
  library used here
- [Chromium sandbox design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/sandboxing.md) —
  comprehensive write-up on layered Linux sandboxing
- [`namespaces(7)` man page](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [`seccomp(2)` man page](https://man7.org/linux/man-pages/man2/seccomp.2.html)
