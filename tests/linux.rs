//! Behaviour that needs a real Linux kernel: signals, and the sandbox
//! applied in child processes.

#![cfg(target_os = "linux")]

use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use mdns_alias::testing::responder::Conflict;
use mdns_alias::testing::sandbox::Layer;
use mdns_alias::testing::signals::Signals;
use mdns_alias::testing::wire::Name;
use mdns_alias::testing::{netlink, sandbox, sys};
use socket_pktinfo::PktInfoUdpSocket;
use socket2::{Domain, SockAddr};

#[test]
fn signalfd_reports_a_blocked_sigterm_once() {
    let signals = Signals::new().unwrap();
    assert!(!signals.pending());
    // SAFETY: raise() takes an integer and touches no memory. It targets
    // this thread, which Signals::new has just blocked SIGTERM for, so it
    // queues on the signalfd instead of killing us.
    unsafe { libc::raise(libc::SIGTERM) };
    assert!(signals.pending());
    assert!(!signals.pending());
}

const CHILD: &str = "MDNS_ALIAS_TEST_CHILD";

/// Exits at once with `code`, running nothing else: for sandboxed test
/// children, which could not flush or report anyway.
fn exit_now(code: i32) -> ! {
    // SAFETY: _exit takes an integer and never returns.
    unsafe { libc::_exit(code) }
}

/// Runs `test` again, alone, in a child process, and returns how it ended.
/// Inside that child it returns `None` instead: the test body then does the
/// sandboxed part and ends with `exit_now`, since once sandboxed the
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
    sys::install_seccomp(&sandbox::program(sys::thread_id()).unwrap()).unwrap();
}

fn assert_killed(status: ExitStatus) {
    assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
}

#[test]
fn seccomp_allows_the_steady_state() {
    let Some(status) = in_child("seccomp_allows_the_steady_state") else {
        // Sockets exist before lockdown, as in the real program.
        let signals = Signals::new().unwrap();
        let receiver = PktInfoUdpSocket::new(Domain::IPV4).unwrap();
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        receiver.bind(&SockAddr::from(local)).unwrap();
        let to = receiver.try_clone_std().unwrap().local_addr().unwrap();
        let sender = UdpSocket::bind(local).unwrap();
        let v6 = PktInfoUdpSocket::new(Domain::IPV6).ok();
        let events = netlink::subscribe().unwrap();
        let mut dumper = netlink::Dumper::open().unwrap();
        receiver.set_nonblocking(true).unwrap();
        // As the main loop fills them: IPv4, IPv6 (-1 without), the
        // notification socket, the signalfd.
        let entries = [
            receiver.as_raw_fd(),
            v6.as_ref().map_or(-1, |v6| v6.as_raw_fd()),
            events.as_raw_fd(),
            signals.fd().unwrap(),
        ];
        seccomp();
        // A rescan: the netlink dump over the socket opened before
        // lockdown (twice, as every rescan reuses it), then joining and
        // leaving groups. On loopback the joins may fail; the calls just
        // must not be killed. The filter allows no socket(), so a dump that
        // opened one would kill the child here.
        let rescanned =
            dumper.dump().is_ok_and(|(links, _)| !links.is_empty()) && dumper.dump().is_ok();
        let group = Ipv4Addr::new(224, 0, 0, 251);
        let _ = receiver.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST);
        let _ = receiver.leave_multicast_v4(&group, &Ipv4Addr::LOCALHOST);
        let _ = receiver.set_multicast_if_v4(&Ipv4Addr::LOCALHOST);
        if let Some(v6) = &v6 {
            let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
            let _ = v6.join_multicast_v6(&group, 1);
            let _ = v6.leave_multicast_v6(&group, 1);
            let _ = v6.set_multicast_if_v6(1);
        }
        // A packet out and back in, as replies and queries travel, and a
        // send that fails, as to an unreachable querier.
        // The main loop's wait: the packet makes the socket ready, then
        // reading until the socket has nothing more, then a wait that times
        // out, as an idle loop's does.
        sender.send_to(b"ping", to).unwrap();
        let mut fds = entries.map(sys::poll_entry);
        let woke = sys::poll(&mut fds, Duration::from_secs(5)).unwrap_or(0) >= 1
            && fds[0].revents & libc::POLLIN != 0;
        let mut buf = [0u8; 16];
        let got = receiver.recv(&mut buf).map_or(0, |(n, _)| n);
        let drained = receiver
            .recv(&mut buf)
            .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock);
        let mut fds = entries.map(sys::poll_entry);
        let timed_out = sys::poll(&mut fds, Duration::from_millis(5)).ok() == Some(0);
        let _ = sender.send_to(b"x", (Ipv4Addr::BROADCAST, 9));
        let quiet = !signals.pending();
        let buffer = vec![1u8; 1 << 20];
        std::hint::black_box(&buffer);
        drop(buffer);
        // Growing past the allocator's mmap threshold reallocates through
        // mremap, and freeing returns pages through madvise or munmap.
        let mut grow: Vec<u8> = Vec::new();
        while grow.len() < 8 << 20 {
            grow.extend_from_slice(&[7u8; 64 << 10]);
        }
        std::hint::black_box(&grow);
        drop(grow);
        eprintln!(
            "sandboxed child: rescanned {rescanned}, woke {woke}, received {got}, \
             drained {drained}, timed out {timed_out}"
        );
        let waited = woke && drained && timed_out;
        exit_now(if rescanned && got == 4 && waited && quiet {
            0
        } else {
            3
        });
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn a_signal_wakes_the_wait_under_seccomp() {
    let Some(status) = in_child("a_signal_wakes_the_wait_under_seccomp") else {
        let signals = Signals::new().unwrap();
        // SAFETY: raise() takes an integer and touches no memory. SIGTERM
        // is blocked, so it queues on the signalfd. Before lockdown: the
        // filter lets this thread signal itself with SIGABRT only.
        unsafe { libc::raise(libc::SIGTERM) };
        seccomp();
        let mut fds = [-1, -1, -1, signals.fd().unwrap()].map(sys::poll_entry);
        let start = std::time::Instant::now();
        let ready = sys::poll(&mut fds, Duration::from_secs(10)).unwrap_or(0);
        let prompt = start.elapsed() < Duration::from_secs(1);
        let woke = ready == 1 && fds[3].revents & libc::POLLIN != 0;
        exit_now(if prompt && woke && signals.pending() {
            0
        } else {
            3
        });
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn seccomp_allows_an_error_exit() {
    let Some(status) = in_child("seccomp_allows_an_error_exit") else {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        seccomp();
        // Log a conflict as the loop does, then fail as main does on a fatal
        // error: format and log the error, drop it and the sockets, and exit
        // with status 1 through std's cleanup.
        let conflict = Conflict {
            alias: Name::parse("app.myhost.local").unwrap(),
            source: "192.0.2.30".parse().unwrap(),
        };
        eprintln!("mdns-alias: {conflict}; probing again");
        let error: Box<dyn std::error::Error> =
            format!("cannot wait for packets after {conflict}").into();
        eprintln!("mdns-alias: {error}");
        drop(error);
        drop(socket);
        std::process::exit(1);
    };
    assert_eq!(status.code(), Some(1), "{status:?}");
}

/// The highest open descriptor, read before lockdown as the real program
/// knows its own.
fn highest_fd() -> i32 {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .max()
        .unwrap()
}

#[test]
fn full_lockdown_still_rescans() {
    let Some(status) = in_child("full_lockdown_still_rescans") else {
        let mut dumper = netlink::Dumper::open().unwrap();
        let report = sandbox::lock([highest_fd()]);
        let sealed = report.applied(Layer::Seccomp);
        // Twice: every rescan reuses the socket opened before lockdown,
        // which opens nothing new under the descriptor cap.
        let rescans = dumper.dump().is_ok() && dumper.dump().is_ok();
        exit_now(if sealed && rescans { 0 } else { 3 });
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
fn seccomp_lets_a_panic_report_itself() {
    let log = std::env::temp_dir().join(format!("mdns-alias-panic-{}.log", std::process::id()));
    let Some(status) = in_child_with("seccomp_lets_a_panic_report_itself", |c| {
        c.stderr(std::fs::File::create(&log).unwrap());
    }) else {
        // For the parent: the id the hook must print without a gettid call.
        eprintln!("tid {}", sys::thread_id());
        seccomp();
        // What panic = "abort" (the release profile) does: run the default
        // hook, then abort. Tests build with unwinding, so the harness would
        // otherwise catch the panic and exit normally.
        let _ = std::panic::catch_unwind(|| panic!("sandboxed boom"));
        std::process::abort();
    };
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(&log).unwrap();
    // The hook prints the thread id and the message, then abort() raises
    // SIGABRT: neither step may be killed by the filter first.
    let tid = text
        .lines()
        .find_map(|l| l.strip_prefix("tid "))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        text.contains(&format!("({tid}) panicked at")) && text.contains("sandboxed boom"),
        "{text}"
    );
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{status:?}");
}

#[test]
fn seccomp_kills_file_access() {
    let Some(status) = in_child("seccomp_kills_file_access") else {
        seccomp();
        let _ = std::fs::File::open("/proc/self/status");
        exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_new_ip_sockets() {
    let Some(status) = in_child("seccomp_kills_new_ip_sockets") else {
        seccomp();
        let _ = std::net::UdpSocket::bind(("127.0.0.1", 0));
        exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_new_netlink_sockets() {
    let Some(status) = in_child("seccomp_kills_new_netlink_sockets") else {
        seccomp();
        // socket() alone: Dumper::open would bind next, which the filter
        // kills too, so it could not tell whether socket() was allowed.
        // SAFETY: socket takes integers and touches no memory; the call is
        // expected to kill the process.
        unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_fork() {
    let Some(status) = in_child("seccomp_kills_fork") else {
        seccomp();
        // SAFETY: the call is expected to kill the process; if it returned,
        // the child would exit at once without touching shared state.
        unsafe { libc::fork() };
        exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn seccomp_kills_execve() {
    let Some(status) = in_child("seccomp_kills_execve") else {
        // A path that does not exist: if execve were allowed it would just
        // fail with ENOENT and the child would exit normally. A real program
        // would die under the inherited filter instead, for the wrong reason.
        let path = c"/nonexistent/mdns-alias-test";
        let argv = [path.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        seccomp();
        // SAFETY: valid NUL-terminated path, argv and envp arrays; the call
        // is expected to kill the process.
        unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        exit_now(0);
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
        exit_now(0);
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
        exit_now(0);
    };
    assert_killed(status);
}

#[test]
fn landlock_denies_files_and_tcp() {
    let Some(status) = in_child("landlock_denies_files_and_tcp") else {
        let exe = std::env::current_exe().unwrap();
        let Ok(abi) = sys::landlock_abi() else {
            exit_now(77)
        };
        sys::set_no_new_privs().unwrap();
        sys::landlock_restrict(&sandbox::landlock_ruleset(abi)).unwrap();
        let denied = |e: std::io::Error| e.kind() == std::io::ErrorKind::PermissionDenied;
        let file = std::fs::File::open(&exe).is_err_and(denied);
        let tcp = abi < 4 || std::net::TcpStream::connect(("127.0.0.1", 9)).is_err_and(denied);
        exit_now(match (file, tcp) {
            (true, true) => 0,
            (false, _) => 2,
            (_, false) => 3,
        });
    };
    match status.code() {
        Some(0) => {}
        // CI runners have Landlock; skipping there would hide a regression.
        Some(77) if std::env::var_os("CI").is_some() => panic!("Landlock unavailable in CI"),
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
        let report = sandbox::lock([]);
        for line in report.lines() {
            eprintln!("{line}");
        }
        exit_now(0);
    };
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(&log).unwrap();
    assert!(status.success(), "{status:?}");
    // Every layer applied, seccomp last; only Landlock may be missing, on
    // kernels without it. A "seccomp unavailable" line must not pass.
    let lines: Vec<&str> = text.lines().collect();
    let first = "sandbox: rlimits, address-space limit, capability drop, non-dumpable, \
                 no-new-privs, ";
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
        let report = sandbox::lock_with([], Err(std::io::ErrorKind::NotFound.into()));
        let lost = report
            .missing(Layer::AddressSpace)
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
        // Every other layer applied; Landlock may be missing instead, on
        // kernels without it.
        let others = Layer::ALL.into_iter().all(|layer| match layer {
            Layer::AddressSpace => !report.applied(layer),
            Layer::Landlock => report.applied(layer) != report.missing(layer).is_some(),
            _ => report.applied(layer),
        });
        exit_now(if lost && others { 0 } else { 4 });
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn draining_notifications_is_allowed_under_seccomp() {
    let Some(status) = in_child("draining_notifications_is_allowed_under_seccomp") else {
        let sock = netlink::subscribe().unwrap();
        let mut buf = vec![0u8; 8192];
        seccomp();
        let _ = netlink::drain(&sock, &mut buf);
        exit_now(0);
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn address_changes_arrive_as_notifications() {
    // Needs CAP_NET_ADMIN (the deployment host's test container has it; CI
    // runners do not). Only ever touches loopback in the test's own network
    // namespace.
    let sock = netlink::subscribe().unwrap();
    let ip = |verb: &str| {
        Command::new("ip")
            .args(["addr", verb, "127.0.0.2/8", "dev", "lo"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !ip("add") {
        eprintln!("cannot add an address here (needs CAP_NET_ADMIN); skipped");
        return;
    }
    let mut buf = vec![0u8; 8192];
    let mut changed = false;
    for _ in 0..50 {
        if netlink::drain(&sock, &mut buf).changed {
            changed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    ip("del");
    assert!(changed, "no notification for the new address");
}

/// The local address of netlink socket `fd` as `(port id, group mask)`, from
/// getsockname: an unbound socket reports port 0.
fn netlink_local_address(fd: BorrowedFd<'_>) -> io::Result<(u32, u32)> {
    // SAFETY: an all-zero sockaddr_nl is valid.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: getsockname writes at most `len` bytes into a live local of
    // exactly that size, and updates `len`.
    let ret = unsafe { libc::getsockname(fd.as_raw_fd(), (&raw mut addr).cast(), &raw mut len) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((addr.nl_pid, addr.nl_groups))
}

#[test]
fn the_notification_socket_is_bound_and_subscribed() {
    // Unprivileged, so CI runs it: an unbound socket has port 0 and, since
    // Bind replaces the group mask, a bind after subscribing would clear it.
    let sock = netlink::subscribe().unwrap();
    let (pid, groups) = netlink_local_address(sock.as_fd()).unwrap();
    let bit = |group: u32| 1u32 << (group - 1);
    let want = bit(netlink::RTNLGRP_LINK)
        | bit(netlink::RTNLGRP_IPV4_IFADDR)
        | bit(netlink::RTNLGRP_IPV6_IFADDR);
    assert_ne!(pid, 0, "socket is not bound");
    assert_eq!(groups, want, "group mask {groups:#x}");
}

/// The capability sets in a /proc/<pid>/status, by name (`CapEff`, ...), as
/// masks.
fn capability_sets(status: &str) -> Vec<(String, u64)> {
    status
        .lines()
        .filter_map(|line| {
            let (name, mask) = line.split_once(":\t")?;
            let name = name.strip_prefix("Cap")?;
            Some((name.to_string(), u64::from_str_radix(mask.trim(), 16).ok()?))
        })
        .collect()
}

/// Every capability set is empty once the full lockdown is in place, read
/// from outside: the locked-down child can open no file, so the parent
/// reads the locked thread's /proc/<pid>/task/<tid>/status while it waits.
/// Capabilities are per thread, and the test harness runs the test on a
/// thread of its own. As root (a test container run as root with
/// CAP_NET_ADMIN) the child starts with capabilities, CAP_SETPCAP among
/// them, and must end with none, bounding set included. Unprivileged, it
/// starts with empty sets and an unreachable bounding set, which the
/// lockdown must leave as harmless, not report as a failure.
#[test]
fn lockdown_empties_every_capability_set() {
    const NAME: &str = "lockdown_empties_every_capability_set";
    if std::env::var_os(CHILD).is_some() {
        let before = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let before: Vec<String> = capability_sets(&before)
            .into_iter()
            .map(|(name, mask)| format!("Cap{name}={mask:x}"))
            .collect();
        eprintln!("before {}", before.join(" "));
        let report = sandbox::lock([highest_fd()]);
        let dropped = report.applied(Layer::Capabilities);
        let sealed = report.applied(Layer::Seccomp);
        // Capabilities are per thread, and this is not the main one: the
        // parent reads this thread's status, not the process's.
        eprintln!("locked {dropped} {sealed} {}", sys::thread_id());
        // Wait for the parent to close stdin, which wakes the wait.
        let mut fds = [0, -1, -1, -1].map(sys::poll_entry);
        let _ = sys::poll(&mut fds, Duration::from_secs(30));
        exit_now(0);
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            NAME,
            "--exact",
            "--test-threads=1",
            "--nocapture",
            "--quiet",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut next = |prefix: &str| {
        lines
            .by_ref()
            .map(Result::unwrap)
            .find_map(|l| l.strip_prefix(prefix).map(str::to_string))
            .unwrap_or_else(|| panic!("child never said {prefix:?}"))
    };
    let before = next("before ");
    let locked = next("locked ");
    let (locked, tid) = locked.rsplit_once(' ').unwrap();
    let path = format!("/proc/{}/task/{tid}/status", child.id());
    let after = std::fs::read_to_string(path).unwrap();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    eprintln!("capabilities before lockdown: {before}");
    assert!(status.success(), "{status:?}");
    assert_eq!(locked, "true true", "capability drop and seccomp applied");
    let after = capability_sets(&after);
    eprintln!("capabilities after lockdown: {after:x?}");
    // Every set but the bounding one: inheritable, permitted, effective and
    // ambient, all four of which the kernel reports.
    let sets: Vec<_> = after.iter().filter(|(name, _)| name != "Bnd").collect();
    assert_eq!(sets.len(), 4, "{after:?}");
    for (name, mask) in sets {
        assert_eq!(*mask, 0, "Cap{name} after lockdown");
    }
    // With CAP_SETPCAP to drop it, the bounding set empties too.
    let had_setpcap = before
        .split(' ')
        .find_map(|set| set.strip_prefix("CapEff="))
        .and_then(|mask| u64::from_str_radix(mask, 16).ok())
        .is_some_and(|mask| mask & 1 << sys::CAP_SETPCAP != 0);
    if had_setpcap {
        let bounding = after.iter().find(|(n, _)| n == "Bnd").map(|&(_, m)| m);
        assert_eq!(bounding, Some(0), "CapBnd after lockdown");
    }
    // Root always starts with capabilities, so as root this proves a drop.
    // SAFETY: geteuid cannot fail and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        assert!(had_setpcap, "root without CAP_SETPCAP: {before}");
    }
}
