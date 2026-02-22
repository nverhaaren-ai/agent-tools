# ro-sandbox

A small Rust binary that runs an arbitrary command in a read-everything, write-nothing,
no-network sandbox using [bubblewrap](https://github.com/containers/bubblewrap) and a
seccomp-BPF filter.

## Usage

```
ro-sandbox [--] command [args...]
```

Examples:

```bash
ro-sandbox grep -r "pattern" /etc
ro-sandbox -- python3 script.py
ro-sandbox make
```

## What it does

The sandboxed command runs with:

- **Read-only filesystem** — the entire host filesystem is visible but no file can be
  written. Attempts to write return `EROFS`.
- **No network** — an empty network namespace means no interfaces, no routing, no sockets.
  Any attempt to connect or listen fails immediately.
- **Process isolation** — the command cannot see or signal host processes.
- **No privilege escalation** — capabilities are dropped; `PR_SET_NO_NEW_PRIVS` is sticky
  and inherited by all subprocesses.
- **seccomp-BPF filter** — high-risk syscalls (`ptrace`, `mount`, `kexec_*`, etc.) are
  blocked before execution.
- `/tmp` and `/var/tmp` are writable (ephemeral `tmpfs`, not visible on the host).
- `stdin`, `stdout`, and `stderr` pass through normally.

See [the implementation plan](https://github.com/nverhaaren-ai/agent-notes/blob/main/projects/readbox/ro-sandbox-plan.md) for
a detailed explanation of each security layer and its rationale.

## Prerequisites

```bash
# Debian/Ubuntu
sudo apt install bubblewrap

# Fedora/RHEL
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

Kernel requirements: Linux ≥ 4.8, unprivileged user namespaces enabled.

## Building

```bash
# Development build
cargo build

# Release build (optimised, stripped)
cargo build --release

# Fully static binary (no libc dependency)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Testing

```bash
# Unit tests (no bwrap needed)
cargo test --lib

# All tests — integration tests require bwrap and are skipped automatically
# if user namespaces are unavailable (e.g. some Docker environments)
cargo test
```

## Limitations

- `--new-session` calls `setsid()`, detaching from the controlling terminal. Programs
  that rely on a controlling terminal for readline, password prompts, or job control may
  behave unexpectedly. Non-interactive use (piped input/output) is unaffected.
- `clone3` (Linux 5.3+) cannot be conditionally filtered by seccomp-BPF because its
  flags are in a struct pointer rather than an inline register. User namespace creation
  via `clone3` is blocked by `bwrap --disable-userns` instead. See the Security
  Considerations section in the implementation plan for details.
- The entire host filesystem (including `~/.ssh`, `~/.aws`, etc.) is readable. For
  untrusted workloads, consider restricting the set of paths exposed.
- No CPU or memory limits; add `--cgroup-*` flags via bwrap if needed.
