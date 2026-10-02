//! Every raw system call the program makes for itself, each in a thin
//! wrapper. This is the only module allowed `unsafe`, and every block says
//! why it is sound. Linux only.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// prctl reads its optional arguments as `unsigned long`; passing `int`s
/// leaves their upper halves unspecified, and the kernel rejects
/// PR_SET_NO_NEW_PRIVS unless they are exactly 1, 0, 0, 0.
const ONE: libc::c_ulong = 1;
const ZERO: libc::c_ulong = 0;

/// musl's syscall() reads six `long` arguments whatever the call; passing
/// fewer, or narrower ones, leaves the rest unspecified. Every raw syscall
/// goes through here with all six. Only for calls libc has no wrapper for
/// (neither musl nor the libc crate wraps the Landlock calls), or whose
/// wrapper passes arguments the seccomp filter would rather pin (`poll`).
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

/// How many entries `poll` takes: both mDNS sockets, the notification
/// socket and the signalfd. An unused entry holds descriptor -1, which the
/// kernel skips, so the count never varies and the seccomp filter pins it.
pub const POLL_FDS: usize = 4;

/// An entry for `poll` that waits for `fd` to be readable (or to report an
/// error, which the kernel always reports); -1 for an unused entry.
pub const fn poll_entry(fd: libc::c_int) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Waits until an entry of `fds` is ready or `timeout` passes, filling in
/// each entry's `revents`, and returns how many are ready: 0 on a timeout.
/// A signal that interrupts the wait is `ErrorKind::Interrupted`.
///
/// The ppoll system call itself, not musl's wrapper: there is no signal mask
/// to set, so this passes a null mask and a mask size of 0, which the
/// seccomp filter pins, where musl passes its signal-set size whatever the
/// mask. ppoll rather than poll, because aarch64 has no poll system call.
pub fn poll(fds: &mut [libc::pollfd; POLL_FDS], timeout: Duration) -> io::Result<usize> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    let mut ts = libc::timespec {
        // time_t, 64-bit on every target the filter is built for.
        tv_sec: i64::try_from(timeout.as_secs()).map_err(|_| invalid())?,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
    };
    let nfds = libc::c_long::try_from(fds.len()).map_err(|_| invalid())?;
    // SAFETY: `fds` points at `nfds` live pollfd entries, which the kernel
    // reads and whose `revents` it writes; `ts` is a live timespec, into
    // which the kernel may write the time left. Both outlive the call. The
    // signal mask is null, so its size, 0, is never used.
    let ready = unsafe {
        raw_syscall(
            libc::SYS_ppoll,
            [word(fds.as_mut_ptr()), nfds, word(&raw mut ts), 0, 0, 0],
        )
    };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(ready).map_err(|_| io::ErrorKind::InvalidData.into())
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

/// This machine's host name: the kernel's nodename, from uname. An error
/// if uname fails or the name is not UTF-8. Only before lockdown: the
/// seccomp filter does not allow uname.
pub fn host_name() -> io::Result<String> {
    // SAFETY: utsname holds only byte arrays, for which all zeros is a
    // valid value.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: uname writes only into the utsname it is given, which is
    // valid and writable for its whole size.
    check(unsafe { libc::uname(&mut uts) })?;
    // nodename is NUL-terminated within the array; c_char is i8 or u8 by
    // architecture, and either way its byte is taken as is.
    let bytes: Vec<u8> = uts
        .nodename
        .iter()
        .map(|c| c.to_ne_bytes()[0])
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into())
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

/// The port id netlink socket `fd` is bound to, from getsockname: the
/// `nlmsg_pid` the kernel puts on its replies to this socket. 0 if the
/// socket is unbound.
pub fn netlink_port(fd: BorrowedFd<'_>) -> io::Result<u32> {
    // SAFETY: an all-zero sockaddr_nl is valid.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut len = socklen::<libc::sockaddr_nl>()?;
    // SAFETY: getsockname writes at most `len`, size_of::<sockaddr_nl>(),
    // bytes into a live local of exactly that size, and updates `len`, also
    // a live local.
    check(unsafe { libc::getsockname(fd.as_raw_fd(), (&raw mut addr).cast(), &raw mut len) })?;
    Ok(addr.nl_pid)
}

/// One receive on socket `fd` into `buf` that never blocks, whatever the
/// socket's mode or receive timeout: WouldBlock if nothing is waiting.
/// Returns how many bytes it put in `buf`. musl's recv is the recvfrom
/// system call, which the seccomp filter allows.
pub fn recv_nowait(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: recv writes at most `buf.len()` bytes into `buf`, which is
    // live and exclusively borrowed for the call.
    let n = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    // recv returns -1 on error, which no usize matches.
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

/// CAP_SETPCAP, which dropping from the bounding set needs.
pub const CAP_SETPCAP: u32 = 8;

/// `_LINUX_CAPABILITY_VERSION_3`: 64-bit sets, as two 32-bit halves.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

/// `struct __user_cap_data_struct`: one 32-bit half of each set.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The two halves of one capability set as a 64-bit mask.
fn joined(low: u32, high: u32) -> u64 {
    u64::from(high) << 32 | u64::from(low)
}

/// This thread's effective capability set, as a mask with bit `n` for
/// capability `n`.
pub fn effective_capabilities() -> io::Result<u64> {
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget reads the live header and, for version 3, writes
    // exactly two CapData entries, which `data` holds. The kernel writes
    // the header back only to report its own version when given one it
    // does not support; version 3 is supported (Linux 2.6.26 on), so the
    // header behind the const pointer is only read.
    let ret = unsafe {
        raw_syscall(
            libc::SYS_capget,
            [word(&raw const header), word(data.as_mut_ptr()), 0, 0, 0, 0],
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(joined(data[0].effective, data[1].effective))
}

/// Empties this thread's effective, permitted and inheritable capability
/// sets. Lowering them needs no capability, so this does not fail for want
/// of one, though a security module may still deny capset, which the
/// sandbox reports as a missing layer. Nothing short of an exec of a
/// privileged file could raise them again, which no-new-privs and seccomp
/// both rule out.
pub fn clear_capabilities() -> io::Result<()> {
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    // Both 32-bit halves of every set: zero.
    let data = [CapData::default(); 2];
    // SAFETY: capset reads the live header and, for version 3, exactly two
    // CapData entries, which `data` holds. As with capget, the header is
    // written back only for an unsupported version, which version 3 is
    // not, so it is only read through the const pointer.
    let ret = unsafe {
        raw_syscall(
            libc::SYS_capset,
            [word(&raw const header), word(data.as_ptr()), 0, 0, 0, 0],
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Empties the ambient capability set. Needs no capability.
pub fn clear_ambient_capabilities() -> io::Result<()> {
    let clear_all = libc::c_ulong::from(libc::PR_CAP_AMBIENT_CLEAR_ALL.unsigned_abs());
    // SAFETY: prctl with integer arguments only.
    check(unsafe { libc::prctl(libc::PR_CAP_AMBIENT, clear_all, ZERO, ZERO, ZERO) }).map(drop)
}

/// Whether capability `cap` is in the bounding set. `InvalidInput` (EINVAL)
/// past the kernel's last capability.
pub fn in_bounding_set(cap: u32) -> io::Result<bool> {
    // SAFETY: prctl with integer arguments only.
    check(unsafe {
        libc::prctl(
            libc::PR_CAPBSET_READ,
            libc::c_ulong::from(cap),
            ZERO,
            ZERO,
            ZERO,
        )
    })
    .map(|held| held == 1)
}

/// Removes capability `cap` from the bounding set. Needs CAP_SETPCAP in the
/// effective set; EPERM without it.
pub fn drop_from_bounding_set(cap: u32) -> io::Result<()> {
    // SAFETY: prctl with integer arguments only.
    check(unsafe {
        libc::prctl(
            libc::PR_CAPBSET_DROP,
            libc::c_ulong::from(cap),
            ZERO,
            ZERO,
            ZERO,
        )
    })
    .map(drop)
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_name_reads_the_kernels_name() {
        let name = super::host_name().unwrap();
        assert!(!name.is_empty() && !name.contains('\0'), "{name:?}");
    }
}
