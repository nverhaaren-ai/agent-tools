// ro-sandbox is x86_64-only: TargetArch::x86_64 is hardcoded in build_seccomp_filter
// and libc::SYS_* constants are arch-specific. On any other arch the filter would
// silently use the wrong syscall numbers, degrading security without any error.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("ro-sandbox is currently only supported on x86_64");

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::CString;
use std::os::unix::io::IntoRawFd;

use libc::{self};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command_args = strip_separator(args);

    if command_args.is_empty() {
        eprintln!("Usage: ro-sandbox [--] command [args...]");
        std::process::exit(1);
    }

    let seccomp_fd = build_and_load_seccomp_filter();
    exec_bwrap(command_args, seccomp_fd);
}

fn strip_separator(mut args: Vec<String>) -> Vec<String> {
    if args.first().map(|s| s == "--").unwrap_or(false) {
        args.remove(0);
    }
    args
}

// ── Section 2: Seccomp filter construction ────────────────────────────────────

fn build_seccomp_filter() -> BpfProgram {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Unconditional blocks — empty Vec means block regardless of arguments.
    let blocked: &[i64] = &[
        // ptrace family: can read/modify other processes' memory and syscall args
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_perf_event_open,
        // filesystem reconfiguration
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        // privilege escalation (unconditional; prctl is handled conditionally below)
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_capset,
        // kernel modification
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        // misc high-risk
        libc::SYS_acct,
        libc::SYS_syslog,
        libc::SYS_nfsservctl,
    ];

    for &syscall_nr in blocked {
        rules.insert(syscall_nr, vec![]);
    }

    // Conditional blocks.
    //
    // CLONE_NEWUSER flag for unshare and clone. The flags argument is a 32-bit
    // int in the first syscall register (arg_index 0). SeccompCmpArgLen::Dword
    // compares only the low 32 bits, which is correct here.
    let clone_newuser_flag: u64 = libc::CLONE_NEWUSER as u64;

    // Block unshare(flags) when CLONE_NEWUSER is set.
    rules.insert(
        libc::SYS_unshare,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(clone_newuser_flag),
            clone_newuser_flag,
        )
        .unwrap()])
        .unwrap()],
    );

    // Block clone(flags, ...) when CLONE_NEWUSER is set.
    // clone3 cannot be conditionally filtered (flags are in a struct pointer,
    // not a register); it is left to bwrap's --disable-userns to handle.
    rules.insert(
        libc::SYS_clone,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(clone_newuser_flag),
            clone_newuser_flag,
        )
        .unwrap()])
        .unwrap()],
    );

    // Block prctl(PR_SET_SECCOMP, ...) to prevent a sandboxed process from
    // replacing or augmenting the seccomp filter. All other prctl operations
    // are allowed.
    rules.insert(
        libc::SYS_prctl,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_SECCOMP as u64,
        )
        .unwrap()])
        .unwrap()],
    );

    // Build the filter with default ALLOW (mismatch_action).
    // Syscalls matching a rule are blocked with ERRNO(EPERM) (match_action).
    //   mismatch_action — applied when a syscall does NOT match any rule (default)
    //   match_action    — applied when a syscall DOES match a rule (blocked case)
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // mismatch_action: permit all others
        SeccompAction::Errno(libc::EPERM as u32), // match_action: block matched syscalls
        TargetArch::x86_64,
    )
    .unwrap();

    filter.try_into().unwrap()
}

// ── Section 3: Write filter to a memfd ───────────────────────────────────────

fn build_and_load_seccomp_filter() -> i32 {
    let bpf: BpfProgram = build_seccomp_filter();

    // Serialize BpfProgram (Vec<sock_filter>) to raw bytes.
    // Each sock_filter is 8 bytes: { u16 code, u8 jt, u8 jf, u32 k }
    let raw_bytes: Vec<u8> = bpf
        .iter()
        .flat_map(|insn| {
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&insn.code.to_ne_bytes());
            b[2] = insn.jt;
            b[3] = insn.jf;
            b[4..8].copy_from_slice(&insn.k.to_ne_bytes());
            b
        })
        .collect();

    // Create a memfd. MFD_CLOEXEC is intentionally NOT set —
    // the fd must survive across execvp into bwrap.
    let name = CString::new("seccomp-filter").unwrap();
    let fd = memfd_create(&name, MemFdCreateFlag::empty())
        .expect("memfd_create failed — kernel too old? (need 3.17+)");

    let raw_fd = fd.into_raw_fd();

    // Write BPF bytes into the memfd.
    // Using libc::write directly rather than nix::unistd::write because nix 0.29
    // changed write() to take AsFd rather than RawFd, which is incompatible with
    // the RawFd we hold after calling into_raw_fd().
    let written = unsafe {
        libc::write(
            raw_fd,
            raw_bytes.as_ptr() as *const libc::c_void,
            raw_bytes.len(),
        )
    };
    assert!(
        written == raw_bytes.len() as isize,
        "write to memfd failed: wrote {written} of {} bytes",
        raw_bytes.len()
    );

    // Seek back to start so bwrap can read it.
    let seek_ret = unsafe { libc::lseek(raw_fd, 0, libc::SEEK_SET) };
    assert_eq!(seek_ret, 0, "lseek on memfd failed");

    raw_fd
}

// ── Section 4: Build bwrap argv and exec ─────────────────────────────────────

fn exec_bwrap(command: Vec<String>, seccomp_fd: i32) -> ! {
    // Verify bwrap is available before building argv.
    which_bwrap();

    let mut argv: Vec<CString> = Vec::new();
    let cs = |s: &str| CString::new(s).expect("arg contains null byte");

    argv.push(cs("bwrap"));

    // === Filesystem ===
    // Bind the entire host filesystem read-only.
    argv.push(cs("--ro-bind"));
    argv.push(cs("/"));
    argv.push(cs("/"));
    // Fresh devtmpfs — programs need /dev/urandom, /dev/null, etc.
    argv.push(cs("--dev"));
    argv.push(cs("/dev"));
    // Namespace-scoped procfs — many programs require /proc to start.
    argv.push(cs("--proc"));
    argv.push(cs("/proc"));
    // Writable tmpfs — compilers, Python, etc. need temp file space.
    argv.push(cs("--tmpfs"));
    argv.push(cs("/tmp"));
    argv.push(cs("--tmpfs"));
    argv.push(cs("/var/tmp"));
    // Writable tmpfs for /run — prevents access to host D-Bus and systemd sockets.
    argv.push(cs("--tmpfs"));
    argv.push(cs("/run"));

    // === Network ===
    // Empty network namespace — no interfaces, no routing, no sockets.
    argv.push(cs("--unshare-net"));

    // === Process isolation ===
    argv.push(cs("--unshare-pid"));
    argv.push(cs("--unshare-ipc"));
    argv.push(cs("--unshare-uts"));

    // === User/capability isolation ===
    argv.push(cs("--unshare-user"));
    // Prevent nested user namespace creation (covers clone3 which seccomp cannot
    // conditionally filter — see Security Considerations in the plan).
    argv.push(cs("--disable-userns"));

    // === Anti-escape hardening ===
    // setsid() blocks TIOCSTI terminal injection attacks.
    // Note: detaches from controlling terminal; affects programs using readline,
    // password prompts, or job control (see limitations).
    argv.push(cs("--new-session"));
    // sandbox dies if the ro-sandbox process dies.
    argv.push(cs("--die-with-parent"));

    // === Seccomp filter ===
    argv.push(cs("--seccomp"));
    argv.push(cs(&seccomp_fd.to_string()));

    // === Command ===
    argv.push(cs("--"));
    for arg in command {
        argv.push(CString::new(arg).expect("command arg contains null byte"));
    }

    // execvp replaces this process image with bwrap — no wrapper process remains.
    // Signals go directly to bwrap; exit codes propagate naturally.
    let argv_refs: Vec<&std::ffi::CStr> = argv.iter().map(|s| s.as_c_str()).collect();
    nix::unistd::execvp(argv[0].as_c_str(), &argv_refs)
        .expect("execvp(bwrap) failed — is bwrap installed?");

    unreachable!()
}

fn which_bwrap() {
    let path = std::env::var("PATH").unwrap_or_default();
    let found = path
        .split(':')
        .any(|dir| std::path::Path::new(dir).join("bwrap").exists());
    if !found {
        eprintln!("ro-sandbox: 'bwrap' not found in PATH.");
        eprintln!("Install it with: apt install bubblewrap  # or dnf, pacman, etc.");
        std::process::exit(127);
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_compiles() {
        // Exercises the entire build_seccomp_filter() path.
        // Any .unwrap() panic inside the function would surface here.
        let _bpf = build_seccomp_filter();
    }

    #[test]
    fn test_filter_is_nonempty() {
        let bpf = build_seccomp_filter();
        assert!(
            !bpf.is_empty(),
            "BPF program should contain at least one instruction"
        );
    }

    #[test]
    fn test_strip_separator_removes_dashdash() {
        let args = vec!["--".to_string(), "cmd".to_string(), "arg".to_string()];
        assert_eq!(strip_separator(args), vec!["cmd", "arg"]);
    }

    #[test]
    fn test_strip_separator_noop_without_dashdash() {
        let args = vec!["cmd".to_string(), "arg".to_string()];
        assert_eq!(strip_separator(args), vec!["cmd", "arg"]);
    }

    #[test]
    fn test_strip_separator_empty() {
        assert!(strip_separator(vec![]).is_empty());
    }
}
