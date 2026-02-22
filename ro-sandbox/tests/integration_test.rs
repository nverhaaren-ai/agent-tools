/// Integration tests for ro-sandbox.
///
/// These tests require both `ro-sandbox` (built by cargo) and `bwrap` to be installed.
/// If either is missing the tests are skipped rather than failing.
use std::process::Command;

/// Path to the compiled ro-sandbox binary provided by cargo's test environment.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ro-sandbox")
}

/// Returns true if bwrap can create user namespaces on this kernel.
/// Tests the minimal bwrap invocation to detect environments where user
/// namespaces are disabled (e.g. Docker containers without --privileged).
fn sandbox_functional() -> bool {
    Command::new("bwrap")
        .args(["--ro-bind", "/", "/", "--unshare-user", "--", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Skip the test (by returning) if bwrap cannot create user namespaces.
macro_rules! require_sandbox {
    () => {
        if !sandbox_functional() {
            eprintln!(
                "SKIP: bwrap cannot create user namespaces (missing or kernel \
                 restriction) — skipping integration test"
            );
            return;
        }
    };
}

// ── Filesystem isolation ──────────────────────────────────────────────────────

#[test]
fn test_read_allowed() {
    require_sandbox!();
    // Reads should succeed anywhere on the host filesystem.
    let output = Command::new(bin())
        .args(["cat", "/etc/os-release"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "reading /etc/os-release should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "/etc/os-release should be non-empty"
    );
}

#[test]
fn test_write_to_readonly_path_fails() {
    require_sandbox!();
    // The host filesystem is bind-mounted read-only. Writes should fail with EROFS.
    let status = Command::new(bin())
        .args(["sh", "-c", "echo x > /etc/ro-sandbox-test-file"])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "write to /etc (read-only bind mount) should fail"
    );
}

#[test]
fn test_tmp_writable_inside_sandbox() {
    require_sandbox!();
    // /tmp is a fresh tmpfs inside the sandbox — writes should succeed.
    let status = Command::new(bin())
        .args([
            "sh",
            "-c",
            "echo hello > /tmp/ro-sandbox-test && cat /tmp/ro-sandbox-test",
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "/tmp should be a writable tmpfs inside the sandbox"
    );
}

#[test]
fn test_tmp_not_visible_on_host() {
    require_sandbox!();
    // Files written to sandbox /tmp should not appear on the host.
    // Run sandbox to create a file, then check host /tmp for it.
    Command::new(bin())
        .args([
            "sh",
            "-c",
            "echo sandboxed > /tmp/ro-sandbox-isolation-check",
        ])
        .status()
        .unwrap();
    assert!(
        !std::path::Path::new("/tmp/ro-sandbox-isolation-check").exists(),
        "sandbox /tmp write should not be visible on the host"
    );
}

// ── Network isolation ─────────────────────────────────────────────────────────

#[test]
fn test_no_network_connection() {
    require_sandbox!();
    // In an empty network namespace, connections fail immediately.
    // We attempt to connect to localhost — in the empty netns there is no
    // loopback interface, so the kernel returns ENETUNREACH or ENONET.
    let output = Command::new(bin())
        .args([
            "python3",
            "-c",
            "import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('127.0.0.1', 1))
    sys.exit(1)  # should not reach here
except OSError:
    sys.exit(0)  # expected: no route to host / network unreachable
",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "network connection in empty netns should raise OSError; \
         stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── Process isolation ─────────────────────────────────────────────────────────

#[test]
fn test_pid_namespace_isolated() {
    require_sandbox!();
    // Inside the PID namespace, the command's process is at a low PID.
    // The host's PID 1 (systemd/init) should not be visible.
    let output = Command::new(bin())
        .args(["sh", "-c", "cat /proc/1/cmdline"])
        .output()
        .unwrap();
    let cmdline = String::from_utf8_lossy(&output.stdout);
    assert!(
        !cmdline.contains("systemd"),
        "host PID 1 (systemd) should not be visible inside sandbox; got: {cmdline:?}"
    );
}

// ── Exit code propagation ─────────────────────────────────────────────────────

#[test]
fn test_exit_code_propagates() {
    require_sandbox!();
    let status = Command::new(bin())
        .args(["sh", "-c", "exit 42"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(42),
        "exit code should propagate through bwrap to the caller"
    );
}

#[test]
fn test_exit_code_zero_on_success() {
    require_sandbox!();
    let status = Command::new(bin()).args(["true"]).status().unwrap();
    assert_eq!(status.code(), Some(0));
}

// ── Seccomp filter — blocked syscalls ────────────────────────────────────────

#[test]
fn test_ptrace_blocked() {
    require_sandbox!();
    // ptrace(PTRACE_TRACEME) should be blocked by the seccomp filter (EPERM).
    // The Python script exits 0 if ptrace returned -1, else exits 1.
    let status = Command::new(bin())
        .args([
            "python3",
            "-c",
            "import ctypes, sys
# PTRACE_TRACEME = 0, syscall nr 101 (ptrace) on x86_64
ret = ctypes.CDLL(None).syscall(101, 0, 0, 0, 0)
sys.exit(0 if ret == -1 else 1)",
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "ptrace should have been blocked by the seccomp filter (returned -1 / EPERM)"
    );
}

// ── Argument handling ─────────────────────────────────────────────────────────

#[test]
fn test_dashdash_separator_stripped() {
    require_sandbox!();
    // ro-sandbox -- cmd arg should work the same as ro-sandbox cmd arg.
    let with_sep = Command::new(bin())
        .args(["--", "echo", "hello"])
        .output()
        .unwrap();
    let without_sep = Command::new(bin())
        .args(["echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        with_sep.stdout, without_sep.stdout,
        "-- separator should be stripped transparently"
    );
}
