//! Behaviour that needs a real Linux kernel: signals here, and from Task 5
//! the sandbox, applied in child processes.

#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};

use mdns_alias::signals::Signals;
use mdns_alias::{netlink, sandbox, sys};

#[test]
fn signalfd_reports_a_blocked_sigterm_once() {
    let signals = Signals::new().unwrap();
    assert!(!signals.pending());
    // raise() targets this thread, which Signals::new has just blocked
    // SIGTERM for, so it queues on the signalfd instead of killing us.
    unsafe { libc::raise(libc::SIGTERM) };
    assert!(signals.pending());
    assert!(!signals.pending());
}

const CHILD: &str = "MDNS_ALIAS_TEST_CHILD";

/// Runs `test` again, alone, in a child process, and returns how it ended.
/// Inside that child it returns `None` instead: the test body then does the
/// sandboxed part and ends with `sys::exit_now`, since once sandboxed the
/// test harness could not report anything itself.
fn in_child_with(test: &str, configure: impl FnOnce(&mut Command)) -> Option<ExitStatus> {
    if std::env::var_os(CHILD).is_some() {
        return None;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            test,
            "--exact",
            "--test-threads=1",
            "--nocapture",
            "--quiet",
        ])
        .env(CHILD, "1")
        .stdout(Stdio::null());
    configure(&mut command);
    Some(command.status().unwrap())
}

fn in_child(test: &str) -> Option<ExitStatus> {
    in_child_with(test, |_| {})
}

fn seccomp() {
    sys::set_no_new_privs().unwrap();
    let (arch, x32) = sandbox::arch().expect("tests run on x86_64 or aarch64");
    sys::install_seccomp(&sandbox::compile(arch, x32, &sandbox::allowlist())).unwrap();
}

fn assert_killed(status: ExitStatus) {
    assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
}

#[test]
fn seccomp_allows_the_steady_state() {
    let Some(status) = in_child("seccomp_allows_the_steady_state") else {
        seccomp();
        let started = std::time::Instant::now();
        let buffer = vec![1u8; 1 << 20];
        std::hint::black_box(&buffer);
        drop(buffer);
        let rescanned = netlink::dump().is_ok();
        eprintln!("sandboxed child alive after {:?}", started.elapsed());
        sys::exit_now(if rescanned { 0 } else { 3 });
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn seccomp_allows_a_normal_exit() {
    let Some(status) = in_child("seccomp_allows_a_normal_exit") else {
        seccomp();
        // Not exit_now: std's exit runs the runtime's cleanup, as returning
        // from main does, which takes down the stack-overflow guard stack.
        std::process::exit(0);
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn seccomp_kills_file_access() {
    let Some(status) = in_child("seccomp_kills_file_access") else {
        seccomp();
        let _ = std::fs::File::open("/proc/self/status");
        sys::exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_new_ip_sockets() {
    let Some(status) = in_child("seccomp_kills_new_ip_sockets") else {
        seccomp();
        let _ = std::net::UdpSocket::bind(("127.0.0.1", 0));
        sys::exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_new_processes() {
    let Some(status) = in_child("seccomp_kills_new_processes") else {
        seccomp();
        let _ = Command::new("/bin/true").status();
        sys::exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_executable_memory() {
    let Some(status) = in_child("seccomp_kills_executable_memory") else {
        seccomp();
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        // SAFETY: a fresh anonymous mapping that is never used; the call is
        // expected to kill the process before it returns.
        unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                flags,
                -1,
                0,
            )
        };
        sys::exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_writes_to_stdout() {
    let Some(status) = in_child("seccomp_kills_writes_to_stdout") else {
        seccomp();
        use std::io::Write;
        let _ = std::io::stdout().write_all(b"x\n");
        let _ = std::io::stdout().flush();
        sys::exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn landlock_denies_files_and_tcp() {
    let Some(status) = in_child("landlock_denies_files_and_tcp") else {
        let exe = std::env::current_exe().unwrap();
        let Ok(abi) = sys::landlock_abi() else {
            sys::exit_now(77)
        };
        sys::set_no_new_privs().unwrap();
        sys::landlock_restrict(&sandbox::landlock_ruleset(abi)).unwrap();
        let denied = |e: std::io::Error| e.kind() == std::io::ErrorKind::PermissionDenied;
        let file = std::fs::File::open(&exe).is_err_and(denied);
        let tcp = abi < 4 || std::net::TcpStream::connect(("127.0.0.1", 9)).is_err_and(denied);
        sys::exit_now(match (file, tcp) {
            (true, true) => 0,
            (false, _) => 2,
            (_, false) => 3,
        });
    };
    match status.code() {
        Some(0) => {}
        Some(77) => eprintln!("Landlock is not available on this kernel; skipped"),
        _ => panic!("{status:?}"),
    }
}

#[test]
fn logging_to_a_file_survives_the_full_lockdown() {
    let log = std::env::temp_dir().join(format!("mdns-alias-test-{}.log", std::process::id()));
    let Some(status) = in_child_with("logging_to_a_file_survives_the_full_lockdown", |c| {
        c.stderr(std::fs::File::create(&log).unwrap());
    }) else {
        let report = sandbox::lock(2);
        for line in report.lines() {
            eprintln!("{line}");
        }
        sys::exit_now(0);
    };
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(&log).unwrap();
    assert!(status.success(), "{status:?}");
    // Every layer applied, seccomp last; only Landlock may be missing, on
    // kernels without it. A "seccomp unavailable" line must not pass.
    let lines: Vec<&str> = text.lines().collect();
    let first = "sandbox: rlimits, address-space limit, non-dumpable, no-new-privs, ";
    assert!(lines[0].starts_with(first), "{text}");
    assert!(lines[0].ends_with(", seccomp"), "{text}");
    assert!(
        lines[1..]
            .iter()
            .all(|l| l.starts_with("sandbox: landlock unavailable")),
        "{text}"
    );
}

#[test]
fn without_proc_only_the_address_space_limit_is_lost() {
    let Some(status) = in_child("without_proc_only_the_address_space_limit_is_lost") else {
        let report = sandbox::lock_with(2, Err(std::io::ErrorKind::NotFound.into()));
        let rlimits = report.applied.iter().any(|a| a == "rlimits");
        let missing = report
            .missing
            .iter()
            .any(|m| m.starts_with("address-space limit unavailable"));
        sys::exit_now(if rlimits && missing { 0 } else { 4 });
    };
    assert!(status.success(), "{status:?}");
}
