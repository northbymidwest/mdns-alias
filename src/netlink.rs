//! Interfaces and their addresses from the kernel, over rtnetlink: one link
//! dump and one address dump per rescan. On Linux this replaces
//! getifaddrs, whose musl version also opens a Unix socket and issues an
//! ioctl for every address; the sandbox allows neither. Parsing is pure and
//! tested everywhere; only the socket is Linux-specific, and elsewhere only
//! tests use what the socket code needs.

#![cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only the Linux code uses these outside tests; Linux CI lints this module in full"
    )
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::net::IfIndex;

/// Message types: the dump requests `request` builds, and the replies.
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
/// Set by the kernel on the messages of a dump that a change interrupted:
/// the listing may show some things twice and others not at all.
const NLM_F_DUMP_INTR: u16 = 0x10;
/// `struct nlmsghdr`.
const HEADER: usize = 16;
/// `struct ifinfomsg`, before a link's attributes.
const IFINFOMSG: usize = 16;
/// `struct ifaddrmsg`, before an address's attributes.
const IFADDRMSG: usize = 8;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
/// IPv6 address states that make an address unfit to publish.
const IFA_F_TEMPORARY: u32 = 0x01;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
/// Notification groups: links, IPv4 addresses, IPv6 addresses.
pub const RTNLGRP_LINK: u32 = 1;
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

pub const IFF_UP: u32 = 0x1;
pub const IFF_LOOPBACK: u32 = 0x8;
#[cfg(target_os = "linux")]
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub index: IfIndex,
    pub flags: u32,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    pub index: IfIndex,
    pub addr: IpAddr,
    pub prefix: u8,
    flags: u32,
}

impl AddrInfo {
    /// Whether the address is settled and lasting enough to publish: every
    /// IPv4 address, and IPv6 addresses that are not tentative, failed
    /// duplicate detection, deprecated or temporary.
    pub fn stable(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => true,
            IpAddr::V6(_) => {
                self.flags
                    & (IFA_F_TENTATIVE | IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TEMPORARY)
                    == 0
            }
        }
    }
}

/// A reply the kernel should never send: lengths that do not fit, or an
/// error message.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

/// What a dump request asks for.
#[derive(Clone, Copy, Debug)]
enum Dump {
    Links,
    Addresses,
}

/// A dump request for every link or every address, across every address
/// family.
fn request(dump: Dump, seq: u32) -> Vec<u8> {
    let (rtype, body) = match dump {
        Dump::Links => (RTM_GETLINK, IFINFOMSG),
        Dump::Addresses => (RTM_GETADDR, IFADDRMSG),
    };
    let len = HEADER + body;
    let mut out = vec![0u8; len];
    out[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    out[4..6].copy_from_slice(&rtype.to_ne_bytes());
    out[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    out[8..12].copy_from_slice(&seq.to_ne_bytes());
    out
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        b.get(i..i.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        b.get(i..i.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Netlink pads every message and attribute to 4 bytes.
fn align(n: usize) -> usize {
    n.saturating_add(3) & !3
}

/// What walking one received datagram found besides its messages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Walk {
    /// NLMSG_DONE was seen: the dump is finished.
    pub done: bool,
    /// A message carried NLM_F_DUMP_INTR: a change interrupted the dump, so
    /// what it listed may be inconsistent.
    pub interrupted: bool,
    /// The kernel refused the request with this error number: an
    /// NLMSG_ERROR answering it. The walk stops there.
    pub error: Option<i32>,
}

/// Calls `each(type, payload)` for every message in one received datagram,
/// and returns whether the dump is finished (NLMSG_DONE seen).
pub fn messages(buf: &[u8], each: &mut dyn FnMut(u16, &[u8])) -> Result<bool, Malformed> {
    walk(buf, None, each).map(|walk| walk.done)
}

/// Which messages are the answer to a request: those carrying its sequence
/// number and the requesting socket's port id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub seq: u32,
    pub port: u32,
}

/// `messages`, for the messages answering `reply` alone: any other, such
/// as one left over from an earlier request, is skipped whole, its
/// NLMSG_DONE and NLMSG_ERROR included. An NLMSG_ERROR answering `reply`
/// is not malformed but the kernel's refusal, with its error number.
pub fn replies(
    buf: &[u8],
    reply: Reply,
    each: &mut dyn FnMut(u16, &[u8]),
) -> Result<Walk, Malformed> {
    walk(buf, Some(reply), each)
}

/// `messages`, or `replies` given a `reply`, also saying whether any message
/// taken, the last included, was flagged as interrupted, and with a
/// `reply`, the error number of an NLMSG_ERROR answering it.
fn walk(
    buf: &[u8],
    reply: Option<Reply>,
    each: &mut dyn FnMut(u16, &[u8]),
) -> Result<Walk, Malformed> {
    let mut walk = Walk::default();
    let mut at = 0;
    while at < buf.len() {
        let len = u32_at(buf, at).ok_or(Malformed)? as usize;
        let kind = u16_at(buf, at + 4).ok_or(Malformed)?;
        let flags = u16_at(buf, at + 6).ok_or(Malformed)?;
        if len < HEADER || len > buf.len() - at {
            return Err(Malformed);
        }
        let seq = u32_at(buf, at + 8).ok_or(Malformed)?;
        let port = u32_at(buf, at + 12).ok_or(Malformed)?;
        if reply.is_some_and(|reply| reply != Reply { seq, port }) {
            at += align(len);
            continue;
        }
        walk.interrupted |= flags & NLM_F_DUMP_INTR != 0;
        match kind {
            NLMSG_DONE => {
                walk.done = true;
                return Ok(walk);
            }
            NLMSG_ERROR => {
                if reply.is_none() {
                    return Err(Malformed);
                }
                walk.error = Some(error_number(&buf[at + HEADER..at + len]).ok_or(Malformed)?);
                return Ok(walk);
            }
            _ => each(kind, &buf[at + HEADER..at + len]),
        }
        at += align(len);
    }
    Ok(walk)
}

/// The error number an NLMSG_ERROR payload carries: its first four bytes,
/// `-errno`. `None` if too short, or not negative: 0 is an acknowledgement,
/// which no dump request asks for.
fn error_number(payload: &[u8]) -> Option<i32> {
    let code = i32::from_ne_bytes(payload.get(..4)?.try_into().ok()?);
    code.checked_neg().filter(|&errno| errno > 0)
}

/// A link listing and an address listing, from one dump.
type Listing = (Vec<LinkInfo>, Vec<AddrInfo>);

/// `EBUSY` on Linux: the kernel refuses a dump request while an earlier
/// dump on the socket is still running.
const EBUSY: i32 = 16;

/// Whether a failed listing is worth trying again soon rather than at the
/// next scheduled rescan: one a change interrupted, one whose reply did
/// not come in time, or one the kernel refused as busy.
pub fn retry_soon(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::TimedOut)
        || e.raw_os_error() == Some(EBUSY)
}

/// Reads the replies to request `reply` through `read`, which fills a
/// buffer and returns how many bytes it put there (WouldBlock once the
/// receive timeout passes), into `links` and `addrs`, until NLMSG_DONE.
/// Returns whether the kernel flagged the dump as interrupted. An error
/// the kernel answers with comes back as that error number.
fn read_replies(
    buf: &mut [u8],
    reply: Reply,
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
    links: &mut Vec<LinkInfo>,
    addrs: &mut Vec<AddrInfo>,
) -> std::io::Result<bool> {
    use std::io::{self, ErrorKind};

    let mut interrupted = false;
    loop {
        let n = match read(buf) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "no reply from the kernel",
                ));
            }
            Err(e) => return Err(e),
        };
        let walk = walk(&buf[..n], Some(reply), &mut |kind, payload| match kind {
            RTM_NEWLINK => links.extend(parse_link(payload)),
            RTM_NEWADDR => addrs.extend(parse_addr(payload)),
            _ => {}
        })
        .map_err(|Malformed| io::Error::new(ErrorKind::InvalidData, "malformed netlink reply"))?;
        if let Some(errno) = walk.error {
            return Err(io::Error::from_raw_os_error(errno));
        }
        interrupted |= walk.interrupted;
        if walk.done {
            return Ok(interrupted);
        }
    }
}

/// `Dumper::dump`'s retries over `attempt`, one whole dump that returns
/// `None` if the kernel flagged it as interrupted. An interrupted dump is
/// tried once more, and if that one is interrupted too the error is
/// `ErrorKind::Interrupted`. A dump the kernel refuses as busy is tried
/// once more: reading that refusal let the earlier dump, which was still
/// running, go on, and each attempt starts by reading such a dump to its
/// end.
fn dump_with(
    mut attempt: impl FnMut() -> std::io::Result<Option<Listing>>,
) -> std::io::Result<Listing> {
    let (mut interrupted, mut busy) = (false, false);
    loop {
        match attempt() {
            Ok(Some(listing)) => return Ok(listing),
            Ok(None) if !interrupted => interrupted = true,
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "the kernel's listing was interrupted by a change, twice",
                ));
            }
            Err(e) if e.raw_os_error() == Some(EBUSY) && !busy => busy = true,
            Err(e) => return Err(e),
        }
    }
}

/// Calls `each(type, value)` for each route attribute in `b`, stopping at
/// the first whose length does not fit.
fn attributes(mut b: &[u8], mut each: impl FnMut(u16, &[u8])) {
    while let (Some(len), Some(kind)) = (u16_at(b, 0), u16_at(b, 2)) {
        let len = usize::from(len);
        if len < 4 || len > b.len() {
            return;
        }
        // The top two bits of the type are flags (nested, byte order).
        each(kind & 0x3fff, &b[4..len]);
        b = &b[align(len).min(b.len())..];
    }
}

/// An RTM_NEWLINK payload. `None` if it is too short, has no name, or
/// has index 0.
pub fn parse_link(payload: &[u8]) -> Option<LinkInfo> {
    let index = IfIndex::new(u32_at(payload, 4)?)?;
    let flags = u32_at(payload, 8)?;
    let mut name = None;
    attributes(payload.get(IFINFOMSG..)?, |kind, value| {
        if kind == IFLA_IFNAME {
            let bytes = value.split(|&b| b == 0).next().unwrap_or_default();
            name = Some(String::from_utf8_lossy(bytes).into_owned());
        }
    });
    Some(LinkInfo {
        index,
        flags,
        name: name?,
    })
}

/// An RTM_NEWADDR payload. IPv4 prefers IFA_LOCAL: on point-to-point links
/// IFA_ADDRESS is the peer's address. `None` without an address, or for
/// index 0.
pub fn parse_addr(payload: &[u8]) -> Option<AddrInfo> {
    let family = *payload.first()?;
    let prefix = *payload.get(1)?;
    let index = IfIndex::new(u32_at(payload, 4)?)?;
    let mut flags = u32::from(*payload.get(2)?);
    let (mut address, mut local) = (None, None);
    attributes(payload.get(IFADDRMSG..)?, |kind, value| {
        if kind == IFA_FLAGS {
            if let Ok(bytes) = <[u8; 4]>::try_from(value) {
                flags = u32::from_ne_bytes(bytes);
            }
            return;
        }
        let ip = match (family, value.len()) {
            (AF_INET, 4) => IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
            (AF_INET6, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(value);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return,
        };
        match kind {
            IFA_ADDRESS => address = Some(ip),
            IFA_LOCAL => local = Some(ip),
            _ => {}
        }
    });
    Some(AddrInfo {
        index,
        addr: local.or(address)?,
        prefix,
        flags,
    })
}

/// Whether a notification of `kind` may have changed links or addresses.
fn is_change(kind: u16) -> bool {
    matches!(kind, RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR)
}

/// What draining the notification socket found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// A link or address changed: rescan once things settle.
    pub changed: bool,
    /// The kernel dropped notifications: rescan now.
    pub overflow: bool,
    /// A read failed, or found nothing where a message should be: rest the
    /// socket, so one that stays readable cannot end every wait at once.
    pub failed: bool,
}

/// `ENOBUFS` on Linux: the socket's buffer overflowed and notifications
/// were lost.
const ENOBUFS: i32 = 105;

/// Adds one read of the notification socket, `read` (the bytes read, or the
/// error), to `drained`; whether to read again. Anything unreadable counts
/// as a change: a needless rescan is cheap, a missed change is not.
fn absorb(drained: &mut Drained, read: std::io::Result<&[u8]>) -> bool {
    use std::io::ErrorKind;

    match read {
        Ok([]) => {
            drained.changed = true;
            drained.failed = true;
            false
        }
        Ok(bytes) => {
            if messages(bytes, &mut |kind, _| drained.changed |= is_change(kind)).is_err() {
                drained.changed = true;
            }
            true
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => false,
        Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
            drained.overflow = true;
            true
        }
        Err(e) if e.kind() == ErrorKind::Interrupted => true,
        Err(_) => {
            drained.changed = true;
            drained.failed = true;
            false
        }
    }
}

/// A non-blocking socket subscribed to link and address notifications.
/// Subscribing is only possible before lockdown.
#[cfg(target_os = "linux")]
pub fn subscribe() -> std::io::Result<socket2::Socket> {
    use std::os::fd::AsFd;

    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::RAW,
        Some(Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    crate::sys::netlink_bind(sock.as_fd())?;
    for group in [RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR] {
        crate::sys::netlink_subscribe(sock.as_fd(), group)?;
    }
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Most reads one `drain` makes. A flood of notifications cannot hold the
/// loop here: past the cap the rest waits for the next pass, and a rescan
/// is due, since what was read is not all there is.
const MAX_DRAIN_READS: usize = 64;

/// Reads pending notifications from `sock` without blocking, at most
/// `MAX_DRAIN_READS` times; see `absorb` for what each read adds.
#[cfg(target_os = "linux")]
pub fn drain(sock: &socket2::Socket, buf: &mut [u8]) -> Drained {
    use std::io::Read;

    const _: () = assert!(ENOBUFS == libc::ENOBUFS);
    let mut reader = sock;
    drain_with(buf, |buf| reader.read(buf))
}

/// `drain` over any `read`, which returns how many bytes it put in the
/// buffer. Stops at the first read that says to, or at the cap, which
/// counts as a change. Reaching the cap exactly as the queue empties still
/// reports one: a harmless extra rescan.
fn drain_with(
    buf: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
) -> Drained {
    let mut drained = Drained::default();
    for _ in 0..MAX_DRAIN_READS {
        let result = read(buf);
        let again = absorb(&mut drained, result.map(|n| &buf[..n]));
        if !again {
            return drained;
        }
    }
    drained.changed = true;
    drained
}

/// Longest a dump waits for each reply from the kernel. The kernel answers
/// at once, so this only bounds a reply that never comes: the rescan then
/// fails and keeps the previous state, instead of holding the loop.
#[cfg(target_os = "linux")]
const REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Most reads `Dumper::discard_stale` makes before giving up on a socket
/// that will not empty.
#[cfg(target_os = "linux")]
const MAX_STALE_READS: usize = 1024;

/// The socket every dump goes over, link and address listings alike, for
/// the life of the process: opened and bound before lockdown, so the
/// sandboxed steady state never opens a socket. It joins no notification
/// group, so it receives only replies to its own requests; each request
/// has a sequence number of its own, and replies to any other are skipped.
#[cfg(target_os = "linux")]
pub struct Dumper {
    sock: socket2::Socket,
    /// The port id the socket is bound to, which the kernel puts on every
    /// reply to it.
    port: u32,
    /// The last request's sequence number.
    seq: u32,
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl Dumper {
    /// Opens and binds the dump socket, with a receive timeout of
    /// `REPLY_TIMEOUT`. Only before lockdown: the seccomp filter allows no
    /// socket, bind or socket option on it.
    pub fn open() -> std::io::Result<Dumper> {
        use std::os::fd::AsFd;

        use socket2::{Domain, Protocol, Socket, Type};

        let sock = Socket::new(
            Domain::from(libc::AF_NETLINK),
            Type::RAW,
            Some(Protocol::from(libc::NETLINK_ROUTE)),
        )?;
        // Bound now, rather than on the first request: autobinding then
        // would be a system call the steady state has no need for.
        crate::sys::netlink_bind(sock.as_fd())?;
        let port = crate::sys::netlink_port(sock.as_fd())?;
        sock.set_read_timeout(Some(REPLY_TIMEOUT))?;
        Ok(Dumper {
            sock,
            port,
            seq: 0,
            // The kernel sizes dump datagrams to the reader's buffer, up to
            // 32 KiB.
            buf: vec![0; 32 * 1024],
        })
    }

    /// The socket's descriptor, for the sandbox's descriptor cap.
    pub fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;

        self.sock.as_raw_fd()
    }

    /// Every link and every address, straight from the kernel.
    ///
    /// A dump the kernel flags as interrupted by a change (NLM_F_DUMP_INTR)
    /// is not used, and one it refuses as busy is not given up on at once:
    /// see `dump_with`. Whatever the error, the caller keeps its previous
    /// state; `retry_soon` says whether to try again soon.
    pub fn dump(&mut self) -> std::io::Result<Listing> {
        const _: () = assert!(EBUSY == libc::EBUSY);
        dump_with(|| self.dump_once())
    }

    /// One attempt at `dump`: `None` if the kernel flagged it as
    /// interrupted.
    fn dump_once(&mut self) -> std::io::Result<Option<Listing>> {
        use std::io::Read;

        // A dump abandoned part way (a read that failed or timed out, a
        // malformed reply) may have left replies queued, or still running
        // in the kernel, which would refuse a new one. Read it to its end.
        self.discard_stale()?;
        let (mut links, mut addrs) = (Vec::new(), Vec::new());
        let mut interrupted = false;
        for dump in [Dump::Links, Dump::Addresses] {
            self.seq = self.seq.wrapping_add(1);
            let reply = Reply {
                seq: self.seq,
                port: self.port,
            };
            self.sock.send(&request(dump, reply.seq))?;
            let mut sock = &self.sock;
            interrupted |= read_replies(
                &mut self.buf,
                reply,
                |buf| sock.read(buf),
                &mut links,
                &mut addrs,
            )?;
        }
        Ok((!interrupted).then_some((links, addrs)))
    }

    /// Reads, without waiting, whatever is queued on the socket and drops
    /// it. Each read lets a dump still running in the kernel queue its next
    /// datagram, so this reads such a dump to its end. An error if the
    /// socket does not empty within `MAX_STALE_READS` reads.
    fn discard_stale(&mut self) -> std::io::Result<()> {
        use std::io::ErrorKind;
        use std::os::fd::AsFd;

        for _ in 0..MAX_STALE_READS {
            match crate::sys::recv_nowait(self.sock.as_fd(), &mut self.buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                // Replies lost to a full buffer: read on. Interrupted cannot
                // happen with the signalfd; harmless.
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("stale netlink replies without end"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draining_stops_and_flags_a_failure_on_errors_and_empty_reads() {
        use std::io::{Error, ErrorKind};

        let mut d = Drained::default();
        assert!(!absorb(&mut d, Err(ErrorKind::WouldBlock.into())));
        assert_eq!(d, Drained::default());
        assert!(absorb(&mut d, Err(ErrorKind::Interrupted.into())));
        assert_eq!(d, Drained::default());
        // Lost notifications: rescan at once, but the socket is fine.
        assert!(absorb(&mut d, Err(Error::from_raw_os_error(ENOBUFS))));
        assert!(d.overflow && !d.failed && !d.changed);

        for read in [Ok(&[][..]), Err(ErrorKind::ConnectionReset.into())] {
            let mut d = Drained::default();
            assert!(!absorb(&mut d, read));
            assert!(d.failed && d.changed && !d.overflow, "{d:?}");
        }
    }

    #[test]
    fn draining_stops_at_the_cap_and_asks_for_a_rescan() {
        // Notifications that change nothing, without end.
        let quiet = message(99, &[0; 4]);
        let mut buf = [0u8; 64];
        let mut reads = 0;
        let d = drain_with(&mut buf, |buf| {
            reads += 1;
            buf[..quiet.len()].copy_from_slice(&quiet);
            Ok(quiet.len())
        });
        assert_eq!(reads, MAX_DRAIN_READS);
        assert!(d.changed && !d.failed && !d.overflow, "{d:?}");

        // Fewer reads than the cap, then nothing more: no change implied.
        let mut left = MAX_DRAIN_READS - 1;
        let d = drain_with(&mut buf, |buf| {
            if left == 0 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            left -= 1;
            buf[..quiet.len()].copy_from_slice(&quiet);
            Ok(quiet.len())
        });
        assert_eq!(d, Drained::default());
    }

    /// One message: header, then payload, padded to 4 bytes.
    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = HEADER + payload.len();
        let mut out = Vec::new();
        out.extend((len as u32).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend([0u8; 10]);
        out.extend(payload);
        out.resize(align(out.len()), 0);
        out
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(((4 + value.len()) as u16).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend(value);
        out.resize(align(out.len()), 0);
        out
    }

    fn link(index: u32, flags: u32, extra: &[u8], name: &str) -> Vec<u8> {
        let mut payload = vec![0u8; IFINFOMSG];
        payload[4..8].copy_from_slice(&index.to_ne_bytes());
        payload[8..12].copy_from_slice(&flags.to_ne_bytes());
        payload.extend(extra);
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        payload.extend(attribute(IFLA_IFNAME, &name));
        message(RTM_NEWLINK, &payload)
    }

    fn addr(family: u8, prefix: u8, index: u32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut payload = vec![family, prefix, 0, 0];
        payload.extend(index.to_ne_bytes());
        for (kind, value) in attrs {
            payload.extend(attribute(*kind, value));
        }
        message(RTM_NEWADDR, &payload)
    }

    fn collect(buf: &[u8]) -> (Result<bool, Malformed>, Vec<LinkInfo>, Vec<AddrInfo>) {
        let (mut links, mut addrs) = (Vec::new(), Vec::new());
        let done = messages(buf, &mut |kind, payload| match kind {
            RTM_NEWLINK => links.extend(parse_link(payload)),
            RTM_NEWADDR => addrs.extend(parse_addr(payload)),
            _ => {}
        });
        (done, links, addrs)
    }

    const UP: u32 = IFF_UP | IFF_RUNNING | IFF_MULTICAST;

    #[test]
    fn requests_dump_every_family() {
        let link = request(Dump::Links, 7);
        assert_eq!(link.len(), HEADER + IFINFOMSG);
        assert_eq!(u32::from_ne_bytes(link[0..4].try_into().unwrap()), 32);
        assert_eq!(
            u16::from_ne_bytes(link[4..6].try_into().unwrap()),
            RTM_GETLINK
        );
        assert_eq!(u16::from_ne_bytes(link[6..8].try_into().unwrap()), 0x301);
        assert_eq!(u32::from_ne_bytes(link[8..12].try_into().unwrap()), 7);
        assert!(link[12..].iter().all(|&b| b == 0));
        let addr = request(Dump::Addresses, 8);
        assert_eq!(addr.len(), HEADER + IFADDRMSG);
        assert_eq!(
            u16::from_ne_bytes(addr[4..6].try_into().unwrap()),
            RTM_GETADDR
        );
    }

    #[test]
    fn parses_links_and_addresses_across_datagrams() {
        let first = [
            link(2, UP, &[], "enp1s0"),
            link(1, IFF_UP | IFF_LOOPBACK, &[], "lo"),
        ]
        .concat();
        let (done, links, _) = collect(&first);
        assert_eq!(done, Ok(false));
        assert_eq!(
            links,
            [
                LinkInfo {
                    index: IfIndex::of(2),
                    flags: UP,
                    name: "enp1s0".into()
                },
                LinkInfo {
                    index: IfIndex::of(1),
                    flags: IFF_UP | IFF_LOOPBACK,
                    name: "lo".into()
                },
            ]
        );
        let second = [
            addr(
                AF_INET,
                24,
                2,
                &[
                    (IFA_ADDRESS, &[192, 0, 2, 10]),
                    (IFA_LOCAL, &[192, 0, 2, 10]),
                ],
            ),
            message(NLMSG_DONE, &[0; 4]),
        ]
        .concat();
        let (done, _, addrs) = collect(&second);
        assert_eq!(done, Ok(true));
        assert_eq!(
            addrs,
            [AddrInfo {
                index: IfIndex::of(2),
                addr: "192.0.2.10".parse().unwrap(),
                prefix: 24,
                flags: 0,
            }]
        );
    }

    #[test]
    fn prefers_the_local_address_on_point_to_point_links() {
        let buf = addr(
            AF_INET,
            32,
            3,
            &[
                (IFA_ADDRESS, &[192, 0, 2, 99]),
                (IFA_LOCAL, &[192, 0, 2, 10]),
            ],
        );
        assert_eq!(
            collect(&buf).2[0].addr,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn parses_ipv6_addresses() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let buf = addr(AF_INET6, 64, 2, &[(IFA_ADDRESS, &ip.octets())]);
        assert_eq!(
            collect(&buf).2,
            [AddrInfo {
                index: IfIndex::of(2),
                addr: IpAddr::V6(ip),
                prefix: 64,
                flags: 0,
            }]
        );
    }

    #[test]
    fn skips_unknown_attributes_and_messages() {
        let buf = [
            link(4, UP, &attribute(99, &[1, 2, 3]), "wlo1"),
            message(99, &[0; 8]),
        ]
        .concat();
        let (done, links, addrs) = collect(&buf);
        assert_eq!(done, Ok(false));
        assert_eq!(links[0].name, "wlo1");
        assert!(addrs.is_empty());
    }

    #[test]
    fn rejects_lengths_that_overrun_or_underrun() {
        let mut long = message(RTM_NEWLINK, &[0; 16]);
        long[0..4].copy_from_slice(&64u32.to_ne_bytes());
        assert_eq!(collect(&long).0, Err(Malformed));
        let mut short = message(RTM_NEWLINK, &[0; 16]);
        short[0..4].copy_from_slice(&8u32.to_ne_bytes());
        assert_eq!(collect(&short).0, Err(Malformed));
        assert_eq!(collect(&[1, 2, 3]).0, Err(Malformed));
    }

    #[test]
    fn errors_end_the_dump() {
        assert_eq!(collect(&message(NLMSG_ERROR, &[0xff; 4])).0, Err(Malformed));
    }

    /// `message` with `flags` in the header.
    fn flagged(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = message(kind, payload);
        out[6..8].copy_from_slice(&flags.to_ne_bytes());
        out
    }

    #[test]
    fn a_flagged_message_marks_the_dump_interrupted() {
        let plain = |buf: &[u8]| walk(buf, None, &mut |_, _| {}).unwrap();
        let mut one = link(2, UP, &[], "enp1s0");
        assert_eq!(plain(&one), Walk::default());
        // Any message in the datagram counts, not just the first.
        one.extend(flagged(RTM_NEWLINK, NLM_F_DUMP_INTR | 0x2, &[0; 4]));
        assert_eq!(
            plain(&one),
            Walk {
                done: false,
                interrupted: true,
                error: None,
            }
        );
        // The kernel may set it on the closing message alone.
        let mut ended = link(2, UP, &[], "enp1s0");
        ended.extend(flagged(NLMSG_DONE, NLM_F_DUMP_INTR, &[0; 4]));
        assert_eq!(
            plain(&ended),
            Walk {
                done: true,
                interrupted: true,
                error: None,
            }
        );
        // `messages` is unchanged by it.
        assert_eq!(messages(&ended, &mut |_, _| {}), Ok(true));
    }

    #[test]
    fn short_or_nameless_payloads_yield_nothing() {
        assert_eq!(parse_link(&[0; 8]), None);
        let mut nameless = vec![0u8; IFINFOMSG];
        nameless[4..8].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(parse_link(&nameless), None);
        assert_eq!(parse_addr(&[AF_INET, 24]), None);
        let mut overrun = nameless;
        overrun.extend(200u16.to_ne_bytes());
        overrun.extend(IFLA_IFNAME.to_ne_bytes());
        overrun.extend(b"lo\0\0");
        assert_eq!(parse_link(&overrun), None);
    }

    #[test]
    fn index_zero_is_no_interface() {
        assert_eq!(collect(&link(0, UP, &[], "enp1s0")).1, []);
        assert_eq!(
            collect(&addr(AF_INET, 24, 0, &[(IFA_LOCAL, &[192, 0, 2, 10])])).2,
            []
        );
    }

    fn addr_with_flags(family: u8, flags_byte: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut payload = vec![family, 64, flags_byte, 0];
        payload.extend(2u32.to_ne_bytes());
        for (kind, value) in attrs {
            payload.extend(attribute(*kind, value));
        }
        message(RTM_NEWADDR, &payload)
    }

    fn only_addr(buf: &[u8]) -> AddrInfo {
        let (_, _, addrs) = collect(buf);
        addrs.into_iter().next().expect("one address")
    }

    #[test]
    fn address_flags_come_from_the_attribute_or_the_byte() {
        let ip = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let from_byte = addr_with_flags(AF_INET6, IFA_F_DEPRECATED as u8, &[(IFA_ADDRESS, &ip)]);
        assert_eq!(only_addr(&from_byte).flags, IFA_F_DEPRECATED);
        let wide = IFA_F_TEMPORARY.to_ne_bytes();
        let from_attr = addr_with_flags(AF_INET6, 0, &[(IFA_ADDRESS, &ip), (IFA_FLAGS, &wide)]);
        assert_eq!(only_addr(&from_attr).flags, IFA_F_TEMPORARY);
    }

    #[test]
    fn only_settled_lasting_ipv6_addresses_are_stable() {
        let ip = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        for (flags, stable) in [
            (0, true),
            (IFA_F_TENTATIVE, false),
            (IFA_F_DADFAILED, false),
            (IFA_F_DEPRECATED, false),
            (IFA_F_TEMPORARY, false),
        ] {
            let buf = addr_with_flags(
                AF_INET6,
                0,
                &[(IFA_ADDRESS, &ip), (IFA_FLAGS, &flags.to_ne_bytes())],
            );
            assert_eq!(only_addr(&buf).stable(), stable, "flags {flags:#x}");
        }
        let v4 = addr_with_flags(
            AF_INET,
            0,
            &[
                (IFA_ADDRESS, &[192, 0, 2, 10]),
                (IFA_FLAGS, &IFA_F_TEMPORARY.to_ne_bytes()),
            ],
        );
        assert!(only_addr(&v4).stable());
    }

    #[test]
    fn link_and_address_notifications_are_changes() {
        for kind in [RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR, RTM_DELADDR] {
            assert!(is_change(kind), "{kind}");
        }
        for kind in [RTM_GETLINK, RTM_GETADDR, 24, NLMSG_DONE] {
            assert!(!is_change(kind), "{kind}");
        }
    }

    /// `message`, answering request `seq` to port `port`.
    fn answer(kind: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = message(kind, payload);
        out[8..12].copy_from_slice(&seq.to_ne_bytes());
        out[12..16].copy_from_slice(&port.to_ne_bytes());
        out
    }

    #[test]
    fn only_replies_to_the_request_are_taken() {
        let reply = Reply { seq: 7, port: 4242 };
        let mut stale = answer(NLMSG_DONE, 6, 4242, &[0; 4]);
        stale[6..8].copy_from_slice(&NLM_F_DUMP_INTR.to_ne_bytes());
        let buf = [
            // A link and the end of an earlier request's dump, an error for
            // it, and a reply to another port: all skipped.
            answer(RTM_NEWLINK, 6, 4242, &link(3, UP, &[], "old0")[HEADER..]),
            stale,
            answer(NLMSG_ERROR, 6, 4242, &[0xff; 4]),
            answer(RTM_NEWLINK, 7, 99, &link(4, UP, &[], "other0")[HEADER..]),
            answer(RTM_NEWLINK, 7, 4242, &link(2, UP, &[], "enp1s0")[HEADER..]),
        ]
        .concat();
        let mut names = Vec::new();
        let mut each = |kind, payload: &[u8]| {
            if kind == RTM_NEWLINK {
                names.extend(parse_link(payload).map(|l| l.name));
            }
        };
        assert_eq!(walk(&buf, Some(reply), &mut each), Ok(Walk::default()));
        assert_eq!(names, ["enp1s0"]);
        // Its own end and its own error still count.
        let done = answer(NLMSG_DONE, 7, 4242, &[0; 4]);
        let ended = replies(&done, reply, &mut |_, _| {}).unwrap();
        assert!(ended.done && ended.error.is_none());
        let error = answer(NLMSG_ERROR, 7, 4242, &(-EBUSY).to_ne_bytes());
        let refused = replies(&error, reply, &mut |_, _| {}).unwrap();
        assert_eq!(refused.error, Some(EBUSY));
        // Without a reply to match, as for notifications, nothing is skipped.
        assert_eq!(messages(&buf, &mut |_, _| {}), Ok(true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_dump_socket_is_bound_and_survives_an_abandoned_dump() {
        let mut dumper = Dumper::open().unwrap();
        assert_ne!(dumper.port, 0, "socket is not bound");
        let (links, _) = dumper.dump().unwrap();
        assert!(!links.is_empty());
        // A request whose replies nobody reads, as a dump that failed part
        // way leaves behind, with the sequence number the next request
        // would otherwise expect to be its own.
        let next = dumper.seq.wrapping_add(1);
        dumper.sock.send(&request(Dump::Addresses, next)).unwrap();
        let (again, _) = dumper.dump().unwrap();
        assert_eq!(again, links);
        // And one read part way: the first datagram only.
        dumper.sock.send(&request(Dump::Links, 1)).unwrap();
        let mut first = vec![0u8; 512];
        let _ = std::io::Read::read(&mut &dumper.sock, &mut first).unwrap();
        assert_eq!(dumper.dump().unwrap().0, links);
    }

    #[test]
    fn the_error_number_is_the_negated_code() {
        let code = |c: i32| error_number(&[&c.to_ne_bytes()[..], &[0; 16]].concat());
        assert_eq!(code(-EBUSY), Some(EBUSY));
        assert_eq!(code(-ENOBUFS), Some(ENOBUFS));
        // An acknowledgement, a positive code, one with no negation, or too
        // few bytes: none of them is a refusal.
        for c in [0, 5, i32::MIN] {
            assert_eq!(code(c), None, "{c}");
        }
        assert_eq!(error_number(&[0xf0, 0xff, 0xff]), None);
        // As a walk sees it: malformed only without a request to match.
        let short = answer(NLMSG_ERROR, 7, 4242, &[0xf0, 0xff]);
        let reply = Reply { seq: 7, port: 4242 };
        assert_eq!(replies(&short, reply, &mut |_, _| {}), Err(Malformed));
        let busy = answer(NLMSG_ERROR, 7, 4242, &(-EBUSY).to_ne_bytes());
        assert_eq!(messages(&busy, &mut |_, _| {}), Err(Malformed));
    }

    #[test]
    fn a_refusal_comes_back_as_its_error_number() {
        use std::io::ErrorKind;

        let reply = Reply { seq: 7, port: 4242 };
        let (mut links, mut addrs) = (Vec::new(), Vec::new());
        let mut buf = [0u8; 256];
        // The stale end of an earlier dump, then the refusal of this one.
        let datagrams = [
            answer(NLMSG_DONE, 6, 4242, &[0; 4]),
            answer(NLMSG_ERROR, 7, 4242, &(-EBUSY).to_ne_bytes()),
        ];
        let mut queue = datagrams.iter();
        let read = |buf: &mut [u8]| {
            let next = queue.next().ok_or(ErrorKind::WouldBlock)?;
            buf[..next.len()].copy_from_slice(next);
            Ok(next.len())
        };
        let e = read_replies(&mut buf, reply, read, &mut links, &mut addrs).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(EBUSY));
        assert!(retry_soon(&e));
        // A reply that never comes times out, also worth a retry soon.
        let never = |_: &mut [u8]| Err(ErrorKind::WouldBlock.into());
        let e = read_replies(&mut buf, reply, never, &mut links, &mut addrs).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert!(retry_soon(&e));
        // A whole reply is read to its end.
        let whole = [
            answer(RTM_NEWLINK, 7, 4242, &link(2, UP, &[], "enp1s0")[HEADER..]),
            answer(NLMSG_DONE, 7, 4242, &[0; 4]),
        ]
        .concat();
        let mut once = Some(whole);
        let read = |buf: &mut [u8]| {
            let next = once.take().ok_or(ErrorKind::WouldBlock)?;
            buf[..next.len()].copy_from_slice(&next);
            Ok(next.len())
        };
        assert_eq!(
            read_replies(&mut buf, reply, read, &mut links, &mut addrs).ok(),
            Some(false)
        );
        assert_eq!(links.len(), 1);
        // Malformed replies and other errors wait for the usual rescan.
        assert!(!retry_soon(&ErrorKind::InvalidData.into()));
        assert!(!retry_soon(&std::io::Error::from_raw_os_error(ENOBUFS)));
    }

    #[test]
    fn a_busy_dump_is_tried_once_more() {
        let busy = || std::io::Error::from_raw_os_error(EBUSY);
        let listing = || (Vec::new(), vec![]);
        // Busy, then answered.
        let mut attempts = 0;
        let got = dump_with(|| {
            attempts += 1;
            if attempts == 1 {
                Err(busy())
            } else {
                Ok(Some(listing()))
            }
        });
        assert!(got.is_ok() && attempts == 2);
        // Busy twice: the second refusal is the error, worth a retry soon.
        let mut attempts = 0;
        let e = dump_with(|| {
            attempts += 1;
            Err(busy())
        })
        .unwrap_err();
        assert_eq!((attempts, e.raw_os_error()), (2, Some(EBUSY)));
        assert!(retry_soon(&e));
        // Interrupted twice, with a busy refusal between: three attempts.
        let mut results = vec![Ok(None), Err(busy()), Ok(None)].into_iter();
        let e = dump_with(|| results.next().unwrap()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Interrupted);
        assert!(results.next().is_none());
        // Other errors are not retried.
        let mut attempts = 0;
        let e = dump_with(|| {
            attempts += 1;
            Err(std::io::ErrorKind::InvalidData.into())
        })
        .unwrap_err();
        assert_eq!((attempts, e.kind()), (1, std::io::ErrorKind::InvalidData));
    }
}
