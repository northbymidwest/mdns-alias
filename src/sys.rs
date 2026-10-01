//! Every raw system call the program makes for itself, each in a thin
//! wrapper. This is the only module allowed `unsafe`, and every block says
//! why it is sound. Linux only.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// prctl reads its optional arguments as `unsigned long`; passing `int`s
/// leaves their upper halves unspecified, and the kernel rejects
/// PR_SET_NO_NEW_PRIVS unless they are exactly 1, 0, 0, 0.
const ONE: libc::c_ulong = 1;
const ZERO: libc::c_ulong = 0;

/// musl's syscall() reads six `long` arguments whatever the call; passing
/// fewer, or narrower ones, leaves the rest unspecified. Every raw syscall
/// goes through here with all six. Only for calls libc has no wrapper for:
/// neither musl nor the libc crate wraps the Landlock calls.
///
/// # Safety
///
/// The arguments must be valid for syscall `nr`, as for libc::syscall.
unsafe fn raw_syscall(nr: libc::c_long, args: [libc::c_long; 6]) -> libc::c_long {
    let [a, b, c, d, e, f] = args;
    // SAFETY: the caller vouches for the arguments.
    unsafe { libc::syscall(nr, a, b, c, d, e, f) }
}

/// A pointer as a syscall argument word. `long` is pointer-sized on every
/// Linux ABI, so this `as` only reinterprets the address's bits as signed,
/// losing none; no `From` or `TryFrom` expresses that.
fn word<T>(p: *const T) -> libc::c_long {
    p.expose_provenance() as libc::c_long
}

/// The size of `T` as the socket calls take it.
fn socklen<T>() -> io::Result<libc::socklen_t> {
    libc::socklen_t::try_from(std::mem::size_of::<T>())
        .map_err(|_| io::ErrorKind::InvalidInput.into())
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
    // SAFETY: sigset_t is plain data, all-zero is a valid value, and
    // sigemptyset initialises it before any other use; every pointer is to a
    // live local. signalfd returns a new descriptor that nothing else owns.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        check(libc::sigemptyset(&raw mut set))?;
        check(libc::sigaddset(&raw mut set, libc::SIGINT))?;
        check(libc::sigaddset(&raw mut set, libc::SIGTERM))?;
        check(libc::sigprocmask(
            libc::SIG_BLOCK,
            &raw const set,
            std::ptr::null_mut(),
        ))?;
        let fd = check(libc::signalfd(
            -1,
            &raw const set,
            libc::SFD_NONBLOCK | libc::SFD_CLOEXEC,
        ))?;
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Whether a SIGINT or SIGTERM is waiting on `fd`. Consumes one; never
/// blocks.
pub fn signal_pending(fd: BorrowedFd<'_>) -> bool {
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: signalfd_siginfo is plain data, valid all-zero; read writes at
    // most `size` bytes into a live local of exactly that size.
    let read = unsafe {
        let mut info: libc::signalfd_siginfo = std::mem::zeroed();
        libc::read(fd.as_raw_fd(), (&raw mut info).cast(), size)
    };
    // read returns -1 on error, which no usize matches.
    usize::try_from(read) == Ok(size)
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
    check(unsafe { libc::setrlimit(resource, &raw const rlim) }).map(drop)
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
/// filter allows tkill for this id alone. musl's gettid makes no system
/// call: it returns the id cached in the thread's descriptor, the same value
/// its abort() passes to tkill. Referencing it here also links it in, so
/// std's panic hook, which binds gettid weakly and makes the syscall only
/// without it, gets the id without one: the filter allows no gettid.
pub fn thread_id() -> libc::pid_t {
    // SAFETY: gettid takes no arguments, reads only this thread's
    // descriptor and cannot fail.
    unsafe { libc::gettid() }
}

/// The size of a memory page, in bytes. An error if sysconf reports none:
/// -1, which it returns on failure (not always setting errno), or 0.
pub fn page_size() -> io::Result<u64> {
    // SAFETY: sysconf takes an integer and touches no memory.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size)
        .ok()
        .filter(|&size| size > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no page size"))
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
    // SAFETY: the third argument points at `prog`, which points at `filter`;
    // both outlive the call, and the kernel copies the program before
    // returning. prctl is variadic and reads it as an unsigned long, which
    // is pointer-sized on Linux.
    check(unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
            &raw const prog,
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
    // The kernel reads `size` bytes of attr: never more than it has.
    if ruleset.size > std::mem::size_of::<LandlockAttr>() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let size = libc::c_long::try_from(ruleset.size)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: attr is live and at least `size` bytes, checked above.
    let fd = unsafe {
        raw_syscall(
            libc::SYS_landlock_create_ruleset,
            [word(&raw const attr), size, 0, 0, 0, 0],
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(fd).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: the kernel just returned this descriptor, and nothing else
    // owns it; `fd` closes it when it drops.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd_word = libc::c_long::from(fd.as_raw_fd());
    // SAFETY: landlock_restrict_self takes a descriptor and flags 0, and
    // touches no memory of ours.
    if unsafe { raw_syscall(libc::SYS_landlock_restrict_self, [fd_word, 0, 0, 0, 0, 0]) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Binds netlink socket `fd` to an automatically chosen port and no groups.
/// The kernel delivers multicast notifications only to bound sockets (an
/// unbound one has port 0, the kernel's own sender port, and is skipped).
/// Bind replaces the socket's whole group mask, so this must come before
/// `netlink_subscribe`, never after. Only before lockdown: the seccomp
/// filter allows no bind.
pub fn netlink_bind(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: an all-zero sockaddr_nl is valid (port 0 picks one, no groups).
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::sa_family_t::try_from(libc::AF_NETLINK)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let len = socklen::<libc::sockaddr_nl>()?;
    // SAFETY: bind reads `len`, size_of::<sockaddr_nl>(), bytes from a live
    // local.
    check(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) }).map(drop)
}

/// Subscribes netlink socket `fd` to notification group `group` (an
/// RTNLGRP_* number). Only before lockdown: the seccomp filter allows no
/// netlink socket options.
pub fn netlink_subscribe(fd: BorrowedFd<'_>, group: u32) -> io::Result<()> {
    let len = socklen::<u32>()?;
    // SAFETY: setsockopt reads `len`, size_of::<u32>(), bytes from a live
    // local.
    check(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_NETLINK,
            libc::NETLINK_ADD_MEMBERSHIP,
            (&raw const group).cast(),
            len,
        )
    })
    .map(drop)
}
