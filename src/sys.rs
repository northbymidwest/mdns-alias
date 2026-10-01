//! Every raw system call the program makes for itself, each in a thin
//! wrapper. This is the only module allowed `unsafe`, and every block says
//! why it is sound. Linux only.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// prctl reads its optional arguments as `unsigned long`; passing `int`s
/// leaves their upper halves unspecified, and the kernel rejects
/// PR_SET_NO_NEW_PRIVS unless they are exactly 1, 0, 0, 0.
const ONE: libc::c_ulong = 1;
const ZERO: libc::c_ulong = 0;

/// musl's syscall() reads six `long` arguments whatever the call; passing
/// fewer, or narrower ones, leaves the rest unspecified. Every raw syscall
/// goes through here with all six.
///
/// # Safety
///
/// The arguments must be valid for syscall `nr`, as for libc::syscall.
unsafe fn raw_syscall(nr: libc::c_long, args: [libc::c_long; 6]) -> libc::c_long {
    let [a, b, c, d, e, f] = args;
    // SAFETY: the caller vouches for the arguments.
    unsafe { libc::syscall(nr, a, b, c, d, e, f) }
}

/// A pointer as a syscall argument word.
fn word<T>(p: *const T) -> libc::c_long {
    p.expose_provenance() as libc::c_long
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Whether the process runs as root, by real or effective uid.
pub fn is_root() -> bool {
    // SAFETY: getuid and geteuid cannot fail and touch no memory.
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}

/// Blocks SIGINT and SIGTERM and returns a non-blocking signalfd that
/// reports them instead, so no handler and no second thread are needed.
pub fn signalfd() -> io::Result<OwnedFd> {
    // SAFETY: sigset_t is plain data, initialised by sigemptyset before any
    // other use; every pointer is to a live local. signalfd returns a new
    // descriptor that nothing else owns.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        check(libc::sigprocmask(
            libc::SIG_BLOCK,
            &set,
            std::ptr::null_mut(),
        ))?;
        let fd = check(libc::signalfd(
            -1,
            &set,
            libc::SFD_NONBLOCK | libc::SFD_CLOEXEC,
        ))?;
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Whether a SIGINT or SIGTERM is waiting on `fd`. Consumes one; never
/// blocks.
pub fn signal_pending(fd: &OwnedFd) -> bool {
    // SAFETY: reads at most size_of::<signalfd_siginfo>() bytes into a local
    // of exactly that size.
    unsafe {
        let mut info: libc::signalfd_siginfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::signalfd_siginfo>();
        libc::read(fd.as_raw_fd(), (&raw mut info).cast(), size) == size as isize
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Limit {
    Processes,
    CoreSize,
    OpenFiles,
    AddressSpace,
}

/// Sets both the soft and hard limit, so it cannot be raised again.
pub fn set_limit(limit: Limit, value: u64) -> io::Result<()> {
    let resource = match limit {
        Limit::Processes => libc::RLIMIT_NPROC,
        Limit::CoreSize => libc::RLIMIT_CORE,
        Limit::OpenFiles => libc::RLIMIT_NOFILE,
        Limit::AddressSpace => libc::RLIMIT_AS,
    };
    let rlim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: setrlimit reads one live rlimit struct.
    check(unsafe { libc::setrlimit(resource, &rlim) }).map(drop)
}

/// No exec can ever grant privileges again; also what lets an unprivileged
/// process install a seccomp filter or a Landlock ruleset.
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: prctl with integer arguments only.
    check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, ONE, ZERO, ZERO, ZERO) }).map(drop)
}

/// No core dumps, and other processes of the same user cannot ptrace this
/// one or read its memory through /proc.
pub fn set_not_dumpable() -> io::Result<()> {
    // SAFETY: prctl with integer arguments only.
    check(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, ZERO, ZERO, ZERO, ZERO) }).map(drop)
}

/// This thread's kernel id: abort() raises SIGABRT at it, so the seccomp
/// filter allows tkill for this id alone.
pub fn thread_id() -> u64 {
    // SAFETY: gettid ignores its arguments and cannot fail.
    unsafe { raw_syscall(libc::SYS_gettid, [0; 6]) as u64 }
}

pub fn page_size() -> u64 {
    // SAFETY: sysconf takes an integer and touches no memory.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// Installs `program` as this thread's seccomp filter. No-new-privs must be
/// set first.
pub fn install_seccomp(program: &[crate::sandbox::Insn]) -> io::Result<()> {
    let mut filter: Vec<libc::sock_filter> = program
        .iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect();
    let len =
        u16::try_from(filter.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let prog = libc::sock_fprog {
        len,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: prog points at `filter`, which outlives the call; the kernel
    // copies the program before returning.
    check(unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
            word(&raw const prog) as libc::c_ulong,
            ZERO,
            ZERO,
        )
    })
    .map(drop)
}

/// `struct landlock_ruleset_attr`.
#[repr(C)]
struct LandlockAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_long = 1;

/// The kernel's Landlock ABI version; an error if Landlock is unavailable.
pub fn landlock_abi() -> io::Result<u32> {
    // SAFETY: the version query passes no attribute pointer.
    let abi = unsafe {
        raw_syscall(
            libc::SYS_landlock_create_ruleset,
            [0, 0, LANDLOCK_CREATE_RULESET_VERSION, 0, 0, 0],
        )
    };
    if abi < 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(abi).map_err(|_| io::ErrorKind::InvalidData.into())
}

/// Restricts this thread, and anything it starts, by a ruleset with no
/// rules: every right `ruleset` handles is denied. No-new-privs must be set
/// first.
pub fn landlock_restrict(ruleset: &crate::sandbox::Landlock) -> io::Result<()> {
    let attr = LandlockAttr {
        handled_access_fs: ruleset.fs,
        handled_access_net: ruleset.net,
        scoped: ruleset.scoped,
    };
    debug_assert!(ruleset.size <= std::mem::size_of::<LandlockAttr>());
    // SAFETY: attr is live and at least `size` bytes; the new descriptor is
    // owned by `fd` and closed when it drops.
    unsafe {
        let size = ruleset.size as libc::c_long;
        let fd = raw_syscall(
            libc::SYS_landlock_create_ruleset,
            [word(&raw const attr), size, 0, 0, 0, 0],
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd as libc::c_int);
        let fd_word = libc::c_long::from(fd.as_raw_fd());
        if raw_syscall(libc::SYS_landlock_restrict_self, [fd_word, 0, 0, 0, 0, 0]) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Exits at once with `code`, running nothing else: for sandboxed test
/// children, which could not flush or report anyway.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit takes an integer and never returns.
    unsafe { libc::_exit(code) }
}

/// Binds netlink socket `fd` to an automatically chosen port and no groups.
/// The kernel delivers multicast notifications only to bound sockets (an
/// unbound one has port 0, the kernel's own sender port, and is skipped).
/// Bind replaces the socket's whole group mask, so this must come before
/// `netlink_subscribe`, never after. Only before lockdown: the seccomp
/// filter allows no bind.
pub fn netlink_bind(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: an all-zero sockaddr_nl is valid (port 0 picks one, no groups).
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: bind reads size_of::<sockaddr_nl>() bytes from a live local.
    check(unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    })
    .map(drop)
}

/// Subscribes netlink socket `fd` to notification group `group` (an
/// RTNLGRP_* number). Only before lockdown: the seccomp filter allows no
/// netlink socket options.
pub fn netlink_subscribe(fd: std::os::fd::RawFd, group: u32) -> io::Result<()> {
    // SAFETY: setsockopt reads size_of::<u32>() bytes from a live local.
    check(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_NETLINK,
            libc::NETLINK_ADD_MEMBERSHIP,
            (&raw const group).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    })
    .map(drop)
}

/// The local address of netlink socket `fd` as `(port id, group mask)`, from
/// getsockname. For tests and diagnostics: an unbound socket reports port 0.
pub fn netlink_local_address(fd: std::os::fd::RawFd) -> io::Result<(u32, u32)> {
    // SAFETY: an all-zero sockaddr_nl is valid.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: getsockname writes at most `len` bytes into a live local of
    // exactly that size, and updates `len`.
    check(unsafe { libc::getsockname(fd, (&raw mut addr).cast(), &raw mut len) })?;
    Ok((addr.nl_pid, addr.nl_groups))
}
