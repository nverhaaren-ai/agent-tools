# ro-sandbox — Roadmap

Future areas to explore. Not prioritised; ideas will accumulate here over time.

---

## Interactive mode / TTY support

`--new-session` calls `setsid()`, which detaches the sandbox from the calling
process's controlling terminal. This closes the TIOCSTI terminal injection attack but
breaks programs that need a TTY (readline, `vim`, `sudo`, job control, etc.).

A safe interactive mode would need to allocate a fresh pseudoterminal pair (`posix_openpt`
/ `openpty`), proxy it between the caller's terminal and the sandboxed process, and
filter or drop dangerous ioctl requests (particularly `TIOCSTI` and `TIOCLINUX`) in the
proxy layer rather than relying on session separation. The proxy sits outside the sandbox,
so it can enforce these constraints without limiting what programs run inside.

---

## Cgroup isolation

The sandbox currently sets no resource limits. An untrusted or runaway process can
exhaust CPU, memory, or file descriptors and affect the host.

bwrap exposes `--cgroup-*` flags for attaching the sandbox to a cgroup v2 hierarchy.
Wrapping that would allow configurable CPU and memory limits. Alternatively, `systemd-run
--scope` or a dedicated cgroup manager could be used to set up the cgroup before
invoking ro-sandbox.

---

## Further reading

- [bubblewrap README](https://github.com/containers/bubblewrap/blob/main/README.md) —
  overview of what bwrap does and does not do
- [`seccompiler` crate docs](https://docs.rs/seccompiler) — the BPF compilation library
  used here
- [Chromium sandbox design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/sandboxing.md) —
  comprehensive write-up on layered Linux sandboxing
- [Linux namespaces man page](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [`seccomp(2)` man page](https://man7.org/linux/man-pages/man2/seccomp.2.html)
