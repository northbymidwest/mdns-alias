//! Sockets and interfaces: one socket per address family, sharing UDP 5353
//! with the host's own responder, joined to the mDNS group on each interface
//! served.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use socket_pktinfo::PktInfoUdpSocket;
use socket2::{Domain, SockAddr, SockRef};

use crate::responder::{Dest, Family, Link, MDNS_PORT, Outgoing};

/// An interface index as the kernel numbers interfaces: never 0, and its
/// own type so it cannot be mixed up with the flag words beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IfIndex(NonZeroU32);

impl IfIndex {
    /// `None` for 0, which is no interface.
    pub const fn new(index: u32) -> Option<IfIndex> {
        match NonZeroU32::new(index) {
            Some(index) => Some(IfIndex(index)),
            None => None,
        }
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Index `index`, which must not be 0.
    #[cfg(test)]
    pub const fn of(index: u32) -> IfIndex {
        IfIndex::new(index).expect("interface index 0")
    }
}

const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// Milliseconds a socket is left out of the wait after a receive on it
/// fails, so a socket that keeps failing cannot spin the loop.
pub const FAILURE_BACKOFF: u64 = 100;
/// Longest wait without a way to wait on the sockets (macOS, a development
/// platform): the loop then looks at every socket this often.
#[cfg(not(target_os = "linux"))]
const DEV_WAIT: Duration = Duration::from_millis(50);
/// Container bridges and veths, skipped unless named with `--interface`:
/// nothing on them resolves the host's LAN names.
const SKIPPED_PREFIXES: [&str; 3] = ["docker", "br-", "veth"];

pub struct Net {
    /// Either may be missing, for a host with that family disabled.
    v4: Option<PktInfoUdpSocket>,
    v6: Option<PktInfoUdpSocket>,
    /// `--interface` names; empty means the default set.
    only: Vec<String>,
    /// The links served: joined to the group, and the only ones whose
    /// packets reach the responder.
    joined: BTreeMap<Link, Joined>,
    /// Named interfaces last reported as unserved, so each absence is logged
    /// once rather than on every rescan.
    unserved: Vec<String>,
    /// Each served interface's stable addresses as of the last rescan.
    addrs: Vec<(IfIndex, Vec<IpAddr>)>,
    /// Link and address change notifications, if the host allows them.
    #[cfg(target_os = "linux")]
    events: Option<socket2::Socket>,
    #[cfg(target_os = "linux")]
    event_buf: Vec<u8>,
    drops: DropLog,
    /// The notification socket's rest after a failed drain.
    events_rest: Backoff,
    /// Packets dropped for a full send buffer, per family, IPv4 first: the
    /// first is logged, then at most one line a minute.
    full: [FailureLog; 2],
    /// Lines to log, from opening, rescans and receives; collected by
    /// `take_log`.
    log: Vec<String>,
}

#[derive(Clone, Debug)]
struct Joined {
    name: String,
    membership: Membership,
    /// The link's addresses and prefix lengths, for the source check.
    /// Updated on every successful rescan; a change here alone is not a
    /// reason to join again.
    subnets: Vec<(IpAddr, u8)>,
}

impl Joined {
    /// Whether `other` is the same group membership on the same interface,
    /// whatever the subnets: if so, the link stays joined as it is.
    fn same_membership(&self, other: &Joined) -> bool {
        self.name == other.name && self.membership == other.membership
    }
}

/// What a link's group membership is keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Membership {
    /// IPv4 membership is keyed by an interface address, so a change of
    /// address means leaving and joining again.
    V4(Ipv4Addr),
    /// IPv6 membership is keyed by the interface index alone.
    V6,
}

#[derive(Debug, Default)]
pub struct Rescan {
    /// Links that are new: probe and announce on them.
    pub added: Vec<Link>,
    /// Links that are gone: forget them.
    pub removed: Vec<Link>,
    /// Interfaces whose stable addresses changed, with the new sets; empty for interfaces no longer served.
    pub addresses: Vec<(IfIndex, Vec<IpAddr>)>,
}

pub struct Received {
    pub len: usize,
    pub link: Link,
    pub source: SocketAddr,
}

/// What one read of a non-blocking socket found.
pub enum Receive {
    /// A packet for the responder.
    Packet(Received),
    /// A packet the responder must not see: on a link not served, or from
    /// off-link. There may be more behind it.
    Ignored,
    /// Nothing waiting, or no socket for the family.
    Empty,
}

/// What a wait found on one family's socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Readiness {
    /// Not waited on: resting after a failure, no socket for the family, or
    /// the wait was interrupted.
    #[default]
    Unwatched,
    /// Waited on, and nothing to read: the socket is healthy.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "only the Linux wait tells an idle socket from a readable one"
        )
    )]
    Idle,
    /// Something to read.
    Readable,
    /// The kernel reports an error condition on the socket (POLLERR,
    /// POLLHUP or POLLNVAL). A read may still find packets, or the error.
    Faulty,
}

/// One address on one interface, whichever way the platform lists them.
#[derive(Clone, Debug)]
struct Interface {
    name: String,
    index: IfIndex,
    /// Administratively up and with a carrier.
    up: bool,
    loopback: bool,
    point_to_point: bool,
    multicast: bool,
    addr: IpAddr,
    prefix: u8,
    /// Settled and lasting enough to publish (see netlink::AddrInfo::stable).
    stable: bool,
}

impl Net {
    /// Opens a socket per family. One family failing, as IPv6 does on a
    /// host that disables it, leaves the other serving, with a line for
    /// `take_log` saying so; both failing is an error.
    pub fn open(only: Vec<String>) -> io::Result<Net> {
        let mut log = Vec::new();
        let (v4, v6) = match (socket(Family::V4), socket(Family::V6)) {
            (Err(e), Err(_)) => return Err(e),
            (v4, v6) => {
                for (family, result) in [(Family::V4, &v4), (Family::V6, &v6)] {
                    if let Err(e) = result {
                        log.push(format!("{family} unavailable, serving without it: {e}"));
                    }
                }
                (v4.ok(), v6.ok())
            }
        };
        #[cfg(target_os = "linux")]
        let events = match crate::netlink::subscribe() {
            Ok(sock) => Some(sock),
            Err(e) => {
                log.push(format!(
                    "address events unavailable ({e}); rescanning every 30s"
                ));
                None
            }
        };
        Ok(Net {
            v4,
            v6,
            only,
            joined: BTreeMap::new(),
            unserved: Vec::new(),
            addrs: Vec::new(),
            #[cfg(target_os = "linux")]
            events,
            #[cfg(target_os = "linux")]
            event_buf: vec![0; 8192],
            drops: DropLog::default(),
            events_rest: Backoff::default(),
            full: Default::default(),
            log,
        })
    }

    /// Brings group membership in line with the interfaces present now,
    /// with what it did for `take_log`.
    pub fn rescan(&mut self) -> Rescan {
        match list_interfaces() {
            Ok(ifs) => self.reconcile(&ifs, &self.families()),
            Err(e) => {
                self.log.push(format!("cannot list interfaces: {e}"));
                Rescan::default()
            }
        }
    }

    /// `rescan` for these interfaces, serving these families.
    fn reconcile(&mut self, ifs: &[Interface], families: &[Family]) -> Rescan {
        let mut scan = Rescan::default();
        let want = wanted(ifs, &self.only, families);
        let stable = stable_addresses(ifs, &want);
        scan.addresses = address_changes(&self.addrs, &stable);
        self.addrs = stable;
        self.drops.reset();
        while let Some(&link) = self.joined.keys().find(|link| !want.contains_key(link)) {
            self.log.push(format!("left {}", self.describe(link)));
            self.leave(link);
            scan.removed.push(link);
        }
        let unserved = unserved(&self.only, &want);
        for name in unserved.iter().filter(|n| !self.unserved.contains(n)) {
            self.log.push(format!(
                "interface {name} is missing or not usable, will use it when it appears"
            ));
        }
        self.unserved = unserved;
        for (link, joined) in want {
            // An address change keeps the link, and its records, as they
            // are; only the subnets for the source check move on.
            let changed = match self.joined.get_mut(&link) {
                Some(current) if current.same_membership(&joined) => {
                    current.subnets = joined.subnets;
                    continue;
                }
                current => current.is_some(),
            };
            if changed {
                self.leave(link);
            }
            match self.join(link, &joined) {
                Ok(()) => {
                    self.joined.insert(link, joined);
                    if !changed {
                        self.log.push(format!("joined {}", self.describe(link)));
                        scan.added.push(link);
                    }
                }
                Err(e) => {
                    self.log.push(format!(
                        "cannot join {} ({}): {e}",
                        joined.name, link.family
                    ));
                    if changed {
                        scan.removed.push(link);
                    }
                }
            }
        }
        scan
    }

    /// Reads one packet from one family's socket, without waiting.
    pub fn recv(&mut self, family: Family, buf: &mut [u8]) -> io::Result<Receive> {
        let Ok(sock) = self.socket(family) else {
            return Ok(Receive::Empty);
        };
        match sock.recv(buf) {
            Ok((len, info)) => {
                // Index 0, or one out of range, is no interface we serve.
                let Some(index) = u32::try_from(info.if_index).ok().and_then(IfIndex::new) else {
                    return Ok(Receive::Ignored);
                };
                let link = Link { index, family };
                // Off-link senders (RFC 6762 section 11), and anything on a
                // link we do not serve, never reach the responder. Off-link
                // drops on a served link are logged once per rescan: a
                // netmask that does not cover the LAN should not fail
                // silently.
                match verdict(&self.joined, link, info.addr_src.ip()) {
                    Verdict::Accept => {}
                    Verdict::Unserved => return Ok(Receive::Ignored),
                    Verdict::OffLink => {
                        if self.drops.first(link) {
                            self.log.push(format!(
                                "ignoring {} on {}: not on its subnets; further ones are \
                                 ignored silently until the next rescan",
                                info.addr_src.ip(),
                                self.describe(link)
                            ));
                        }
                        return Ok(Receive::Ignored);
                    }
                }
                Ok(Receive::Packet(Received {
                    len,
                    link,
                    source: info.addr_src,
                }))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Receive::Empty)
            }
            Err(e) => Err(e),
        }
    }

    /// A packet for `family` was dropped at `now` for a full send buffer.
    /// `Some(n)` means log it, noting the `n` drops skipped since the last
    /// line: the first is logged, then at most one line a minute.
    pub fn send_dropped(&mut self, family: Family, now: u64) -> Option<u64> {
        self.full[slot(family)].failed(now)
    }

    /// Waits until a socket of a family in `watch` has something to read or
    /// reports an error, the notification socket (unless resting at `now`)
    /// or `wake` (the signalfd) is readable, or `timeout` passes; then says
    /// what it found on each family's socket, IPv4 first.
    ///
    /// A failure other than an interruption should be unreachable: the
    /// entry count is fixed at 4, which the descriptor cap always allows,
    /// the timeout is a valid timespec, and every pointer is to a live
    /// local. So it is fatal; do not add retries, which could only spin.
    #[cfg(target_os = "linux")]
    pub fn wait(
        &self,
        wake: Option<RawFd>,
        watch: [bool; 2],
        now: u64,
        timeout: Duration,
    ) -> io::Result<[Readiness; 2]> {
        use crate::sys::{self, poll_entry};

        let watched = |slot: usize, sock: &Option<PktInfoUdpSocket>| match sock {
            Some(sock) if watch[slot] => sock.as_raw_fd(),
            _ => -1,
        };
        let events = match &self.events {
            Some(sock) if self.events_rest.until(now).is_none() => sock.as_raw_fd(),
            _ => -1,
        };
        let mut fds = [
            watched(0, &self.v4),
            watched(1, &self.v6),
            events,
            wake.unwrap_or(-1),
        ]
        .map(poll_entry);
        match sys::poll(&mut fds, timeout) {
            Ok(_) => Ok([0, 1].map(|slot| readiness(fds[slot].fd, fds[slot].revents))),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok([Readiness::Unwatched; 2]),
            Err(e) => Err(e),
        }
    }

    /// `wait` without a way to wait on the sockets: sleeps for `timeout`,
    /// but no more than `DEV_WAIT`, then has every watched socket read.
    /// Development platforms only.
    #[cfg(not(target_os = "linux"))]
    pub fn wait(
        &self,
        _wake: Option<RawFd>,
        watch: [bool; 2],
        _now: u64,
        timeout: Duration,
    ) -> io::Result<[Readiness; 2]> {
        std::thread::sleep(timeout.min(DEV_WAIT));
        let mut ready = [Readiness::Unwatched; 2];
        for (slot, family) in [Family::V4, Family::V6].into_iter().enumerate() {
            if watch[slot] && self.socket(family).is_ok() {
                ready[slot] = Readiness::Readable;
            }
        }
        Ok(ready)
    }

    /// Sends on the packet's link: multicast to the group there, or unicast.
    pub fn send(&self, out: &Outgoing) -> io::Result<()> {
        let dest = match (out.link.family, out.dest) {
            (_, Dest::Unicast(addr)) => addr,
            (Family::V4, Dest::Multicast) => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
            (Family::V6, Dest::Multicast) => SocketAddr::V6(SocketAddrV6::new(
                GROUP_V6,
                MDNS_PORT,
                0,
                out.link.index.get(),
            )),
        };
        let dest = SockAddr::from(dest);
        match out.link.family {
            Family::V4 => {
                let Some(Joined {
                    membership: Membership::V4(addr),
                    ..
                }) = self.joined.get(&out.link)
                else {
                    return Err(io::ErrorKind::NotFound.into());
                };
                let sock = self.socket(Family::V4)?;
                sock.set_multicast_if_v4(addr)?;
                sock.send_to(&out.packet, &dest)?;
            }
            Family::V6 => {
                let sock = self.socket(Family::V6)?;
                sock.set_multicast_if_v6(out.link.index.get())?;
                sock.send_to(&out.packet, &dest)?;
            }
        }
        Ok(())
    }

    /// Stops serving a link. The next rescan joins it again if it is still
    /// there, which is how a link whose sends failed gets another chance.
    pub fn leave(&mut self, link: Link) {
        let Some(joined) = self.joined.remove(&link) else {
            return;
        };
        // Leaving fails if the interface is already gone, which is fine.
        let Ok(sock) = self.socket(link.family) else {
            return;
        };
        let _ = match joined.membership {
            Membership::V4(addr) => sock.leave_multicast_v4(&GROUP_V4, &addr),
            Membership::V6 => sock.leave_multicast_v6(&GROUP_V6, link.index.get()),
        };
    }

    /// The descriptors the sockets hold, for the sandbox's descriptor cap.
    pub fn fds(&self) -> Vec<RawFd> {
        let sockets = [&self.v4, &self.v6]
            .into_iter()
            .flatten()
            .map(|sock| sock.as_raw_fd());
        #[cfg(target_os = "linux")]
        let sockets = sockets.chain(self.events.iter().map(|sock| sock.as_raw_fd()));
        sockets.collect()
    }

    /// Whether change notifications arrive, so polling can be slow.
    pub fn has_events(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.events.is_some();
        #[cfg(not(target_os = "linux"))]
        false
    }

    /// Reads every pending change notification without blocking. After a
    /// failed drain the socket rests for `FAILURE_BACKOFF` ms: left out of
    /// the wait and not read. The failure itself counts as a change.
    pub fn drain_events(&mut self, now: u64) -> crate::netlink::Drained {
        if self.events_rest.until(now).is_some() {
            return crate::netlink::Drained::default();
        }
        let drained = self.read_events();
        self.note_drain(&drained, now);
        drained
    }

    fn read_events(&mut self) -> crate::netlink::Drained {
        #[cfg(target_os = "linux")]
        if let Some(sock) = &self.events {
            return crate::netlink::drain(sock, &mut self.event_buf);
        }
        crate::netlink::Drained::default()
    }

    /// Starts the notification socket's rest if `drained` failed.
    fn note_drain(&mut self, drained: &crate::netlink::Drained, now: u64) {
        if drained.failed {
            self.events_rest.start(now);
        }
    }

    /// When the notification socket's rest under way at `now` ends, for the
    /// wait's timeout.
    pub fn events_rest_until(&self, now: u64) -> Option<u64> {
        self.events_rest.until(now)
    }

    /// The name of a served interface, for logs.
    pub fn interface_name(&self, index: IfIndex) -> Option<&str> {
        self.joined
            .iter()
            .find(|(link, _)| link.index == index)
            .map(|(_, joined)| joined.name.as_str())
    }

    /// Lines to log since the last call.
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    pub fn serves(&self, link: Link) -> bool {
        self.joined.contains_key(&link)
    }

    pub fn is_empty(&self) -> bool {
        self.joined.is_empty()
    }

    /// `enp1s0 (IPv4)`, for logs.
    pub fn describe(&self, link: Link) -> String {
        let name = self.joined.get(&link).map_or("?", |j| j.name.as_str());
        format!("{name} ({})", link.family)
    }

    fn socket(&self, family: Family) -> io::Result<&PktInfoUdpSocket> {
        let sock = match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        };
        sock.as_ref().ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    /// The families with a socket.
    fn families(&self) -> Vec<Family> {
        [Family::V4, Family::V6]
            .into_iter()
            .filter(|&family| self.socket(family).is_ok())
            .collect()
    }

    fn join(&self, link: Link, joined: &Joined) -> io::Result<()> {
        let sock = self.socket(link.family)?;
        match joined.membership {
            Membership::V4(addr) => sock.join_multicast_v4(&GROUP_V4, &addr),
            Membership::V6 => sock.join_multicast_v6(&GROUP_V6, link.index.get()),
        }
    }
}

/// A socket bound to the mDNS port for one family, shared with the host's
/// own responder through `SO_REUSEADDR` and `SO_REUSEPORT`.
fn socket(family: Family) -> io::Result<PktInfoUdpSocket> {
    let (domain, bind) = match family {
        Family::V4 => (
            Domain::IPV4,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)),
        ),
        Family::V6 => (
            Domain::IPV6,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)),
        ),
    };
    let sock = PktInfoUdpSocket::new(domain)?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    // The loop waits on every descriptor at once, then reads each until it
    // is empty.
    sock.set_nonblocking(true)?;
    match family {
        Family::V4 => {
            sock.set_multicast_loop_v4(true)?;
            sock.set_multicast_ttl_v4(255)?;
        }
        Family::V6 => {
            // A std handle on the same socket, for the option
            // PktInfoUdpSocket does not offer. Dropping it closes only the
            // duplicate descriptor.
            let handle = sock.try_clone_std()?;
            // Otherwise Linux delivers IPv4 traffic here too, as mapped
            // addresses, and every IPv4 query would be answered twice.
            SockRef::from(&handle).set_only_v6(true)?;
            sock.set_multicast_loop_v6(true)?;
            sock.set_multicast_hops_v6(255)?;
        }
    }
    sock.bind(&SockAddr::from(bind))?;
    Ok(sock)
}

/// The links to serve: one per interface and family with an address there.
/// Interfaces that are down, loopback, point-to-point or without multicast
/// never qualify.
fn wanted(ifs: &[Interface], only: &[String], families: &[Family]) -> BTreeMap<Link, Joined> {
    // Loopback is a property of the interface, but getifaddrs reports it per
    // address, and macOS gives lo0 a non-loopback fe80::1 too.
    let loopback: Vec<&str> = ifs
        .iter()
        .filter(|i| i.loopback)
        .map(|i| i.name.as_str())
        .collect();
    let mut want = BTreeMap::new();
    for i in ifs {
        if loopback.contains(&i.name.as_str()) || i.point_to_point || !i.up || !i.multicast {
            continue;
        }
        let chosen = if only.is_empty() {
            !SKIPPED_PREFIXES
                .iter()
                .any(|prefix| i.name.starts_with(prefix))
        } else {
            only.contains(&i.name)
        };
        if !chosen {
            continue;
        }
        let (family, membership) = match i.addr {
            IpAddr::V4(addr) => (Family::V4, Membership::V4(addr)),
            IpAddr::V6(_) => (Family::V6, Membership::V6),
        };
        if !families.contains(&family) {
            continue;
        }
        want.entry(Link {
            index: i.index,
            family,
        })
        .or_insert(Joined {
            name: i.name.clone(),
            membership,
            subnets: Vec::new(),
        });
    }
    // Every address on the interface in the link's family counts for the
    // source check.
    for (link, joined) in &mut want {
        joined.subnets = ifs
            .iter()
            .filter(|i| i.index == link.index && i.addr.is_ipv4() == (link.family == Family::V4))
            .map(|i| (i.addr, i.prefix))
            .collect();
    }
    want
}

/// The `--interface` names that yield no link: absent, down, or unusable.
fn unserved(only: &[String], want: &BTreeMap<Link, Joined>) -> Vec<String> {
    let mut out = Vec::new();
    for name in only {
        if !want.values().any(|j| j.name == *name) {
            out.push(name.clone());
        }
    }
    out
}

/// What to do with a packet from `source` on `link`.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    /// A link we do not serve, or whose join failed: Linux delivers group
    /// traffic joined by any socket to every one, so this is normal.
    Unserved,
    /// A served link, but the source is not on-link there.
    OffLink,
}

fn verdict(joined: &BTreeMap<Link, Joined>, link: Link, source: IpAddr) -> Verdict {
    match joined.get(&link) {
        None => Verdict::Unserved,
        Some(j) if on_link(source, &j.subnets) => Verdict::Accept,
        Some(_) => Verdict::OffLink,
    }
}

/// The links that have logged an off-link drop since the last rescan. At
/// most one entry per served link, so a list is plenty, and it costs less
/// code than another B-tree.
#[derive(Debug, Default)]
struct DropLog(Vec<Link>);

impl DropLog {
    /// Whether this is the first drop on `link` since the last reset.
    fn first(&mut self, link: Link) -> bool {
        if self.0.contains(&link) {
            return false;
        }
        self.0.push(link);
        true
    }

    fn reset(&mut self) {
        self.0.clear();
    }
}

/// A family's place in per-family arrays: IPv4 first.
const fn slot(family: Family) -> usize {
    match family {
        Family::V4 => 0,
        Family::V6 => 1,
    }
}

/// What a wait's report on descriptor `fd` means for a socket: -1 (left
/// out) is unwatched, any error bit is faulty.
#[cfg(target_os = "linux")]
fn readiness(fd: RawFd, revents: libc::c_short) -> Readiness {
    if fd < 0 {
        Readiness::Unwatched
    } else if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        Readiness::Faulty
    } else if revents & libc::POLLIN != 0 {
        Readiness::Readable
    } else {
        Readiness::Idle
    }
}

/// When a socket whose receive failed is waited on again.
#[derive(Debug, Default)]
pub struct Backoff {
    /// The end of the rest, in ms; may have passed.
    until: Option<u64>,
}

impl Backoff {
    /// A receive failed at `now`: rest for `FAILURE_BACKOFF` ms.
    pub fn start(&mut self, now: u64) {
        self.until = Some(now.saturating_add(FAILURE_BACKOFF));
    }

    /// When the rest that is under way at `now` ends; `None` if there is
    /// none, so a rest that has ended never sets a timeout in the past.
    pub fn until(&self, now: u64) -> Option<u64> {
        self.until.filter(|&until| now < until)
    }
}

/// Milliseconds between repeats of a receive error's log line while it
/// persists.
const FAILURE_REPEAT: u64 = 60_000;

/// Rate-limits the log of one socket's receive errors: the first is logged,
/// repeats only once a minute, with a count of those skipped, and recovery
/// once.
#[derive(Debug, Default)]
pub struct FailureLog {
    /// While failing: when a line was last logged, and the errors since.
    run: Option<(u64, u64)>,
}

impl FailureLog {
    /// Records a failure at `now` (ms). `Some(n)` means log it, noting the
    /// `n` repeats skipped since the last line.
    pub fn failed(&mut self, now: u64) -> Option<u64> {
        match &mut self.run {
            Some((logged, skipped)) if now.saturating_sub(*logged) < FAILURE_REPEAT => {
                *skipped += 1;
                None
            }
            run => {
                let skipped = run.map_or(0, |(_, skipped)| skipped);
                *run = Some((now, 0));
                Some(skipped)
            }
        }
    }

    /// Records a good receive. `Some(n)` if it ends a run of failures,
    /// which deserves a line noting the `n` skipped since the last one.
    pub fn recovered(&mut self) -> Option<u64> {
        self.run.take().map(|(_, skipped)| skipped)
    }
}

/// Whether `source` is on-link for an interface with these addresses:
/// inside one of its subnets, or link-local (169.254/16, fe80::/10), which
/// RFC 6762 section 11 counts as on-link wherever it arrives.
fn on_link(source: IpAddr, subnets: &[(IpAddr, u8)]) -> bool {
    let link_local = match source {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    };
    if link_local {
        return true;
    }
    subnets
        .iter()
        .any(|&(addr, prefix)| same_prefix(source, addr, prefix))
}

fn same_prefix(a: IpAddr, b: IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix.min(32)))
                .unwrap_or(0);
            (a.to_bits() ^ b.to_bits()) & mask == 0
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix.min(128)))
                .unwrap_or(0);
            (a.to_bits() ^ b.to_bits()) & mask == 0
        }
        _ => false,
    }
}

/// Each served interface's stable addresses, sorted.
fn stable_addresses(
    ifs: &[Interface],
    want: &BTreeMap<Link, Joined>,
) -> Vec<(IfIndex, Vec<IpAddr>)> {
    // `want` is ordered by link, so this comes out ordered by index.
    let mut stable: Vec<(IfIndex, Vec<IpAddr>)> = Vec::new();
    for link in want.keys() {
        if stable.last().is_none_or(|(index, _)| *index != link.index) {
            stable.push((link.index, Vec::new()));
        }
    }
    for i in ifs.iter().filter(|i| i.stable) {
        if let Some((_, list)) = stable.iter_mut().find(|(index, _)| *index == i.index) {
            list.push(i.addr);
        }
    }
    for (_, list) in &mut stable {
        crate::order::sort(list);
        list.dedup();
    }
    stable
}

/// The interfaces whose stable addresses differ between `old` and `new`,
/// with their new sets; an interface no longer served gets an empty set.
///
/// Both lists must be strictly ascending by interface index, as
/// `stable_addresses` returns them; one merge pass relies on that and
/// returns the changes in the same order.
fn address_changes(
    old: &[(IfIndex, Vec<IpAddr>)],
    new: &[(IfIndex, Vec<IpAddr>)],
) -> Vec<(IfIndex, Vec<IpAddr>)> {
    debug_assert!(old.windows(2).all(|w| w[0].0 < w[1].0));
    debug_assert!(new.windows(2).all(|w| w[0].0 < w[1].0));
    let mut changes = Vec::new();
    let (mut o, mut n) = (0, 0);
    while o < old.len() || n < new.len() {
        match (old.get(o), new.get(n)) {
            (Some(a), Some(b)) if a.0 == b.0 => {
                if a.1 != b.1 {
                    changes.push(b.clone());
                }
                o += 1;
                n += 1;
            }
            (Some(a), b) if b.is_none_or(|b| a.0 < b.0) => {
                changes.push((a.0, Vec::new()));
                o += 1;
            }
            (_, b) => {
                changes.extend(b.cloned());
                n += 1;
            }
        }
    }
    changes
}

/// Quiet time after the last change notification before rescanning.
const SETTLE_QUIET: u64 = 250;
/// Longest wait after the first notification of a burst.
const SETTLE_MAX: u64 = 2000;

/// When to rescan after change notifications: once they have been quiet for
/// `SETTLE_QUIET` ms, but no later than `SETTLE_MAX` ms after the first; at
/// once if some were lost.
#[derive(Debug, Default)]
pub enum Settle {
    /// No notification since the last rescan.
    #[default]
    Idle,
    /// Notifications arrived, the first and the last at these times (ms).
    Burst { first: u64, last: u64 },
    /// Notifications were lost; later ones change nothing.
    Overflow,
}

impl Settle {
    pub fn changed(&mut self, now: u64) {
        match self {
            Settle::Idle => {
                *self = Settle::Burst {
                    first: now,
                    last: now,
                }
            }
            Settle::Burst { last, .. } => *last = now,
            Settle::Overflow => {}
        }
    }

    /// Notifications were lost: rescan at once.
    pub fn overflowed(&mut self) {
        *self = Settle::Overflow;
    }

    pub fn due(&self, now: u64) -> bool {
        self.due_at().is_some_and(|due| now >= due)
    }

    /// When the rescan is due, in ms, for the wait's timeout; `None` while
    /// no notification is waiting for one.
    pub fn due_at(&self) -> Option<u64> {
        match *self {
            Settle::Idle => None,
            Settle::Burst { first, last } => Some((last + SETTLE_QUIET).min(first + SETTLE_MAX)),
            Settle::Overflow => Some(0),
        }
    }

    pub fn clear(&mut self) {
        *self = Settle::Idle;
    }
}

#[cfg(target_os = "linux")]
fn list_interfaces() -> io::Result<Vec<Interface>> {
    use crate::netlink::{self, IFF_LOOPBACK, IFF_MULTICAST, IFF_POINTOPOINT, IFF_RUNNING, IFF_UP};
    let (links, addrs) = netlink::dump()?;
    Ok(addrs
        .into_iter()
        .filter_map(|a| {
            let link = links.iter().find(|l| l.index == a.index)?;
            let has = |flag: u32| link.flags & flag != 0;
            Some(Interface {
                name: link.name.clone(),
                index: a.index,
                up: has(IFF_UP) && has(IFF_RUNNING),
                loopback: has(IFF_LOOPBACK),
                point_to_point: has(IFF_POINTOPOINT),
                multicast: has(IFF_MULTICAST),
                addr: a.addr,
                prefix: a.prefix,
                stable: a.stable(),
            })
        })
        .collect())
}

#[cfg(not(target_os = "linux"))]
fn list_interfaces() -> io::Result<Vec<Interface>> {
    use if_addrs::IfAddr;
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|i| {
            let prefix = match &i.addr {
                IfAddr::V4(a) => a.prefixlen,
                IfAddr::V6(a) => a.prefixlen,
            };
            Some(Interface {
                index: IfIndex::new(i.index?)?,
                up: i.is_oper_up(),
                loopback: i.is_loopback(),
                point_to_point: i.is_p2p(),
                // if-addrs does not report it; an interface without it fails
                // to join the group, which is logged.
                multicast: true,
                addr: i.ip(),
                prefix,
                // if-addrs reports no address states.
                stable: true,
                name: i.name,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, index: u32, ip: &str) -> Interface {
        let addr: IpAddr = ip.parse().unwrap();
        Interface {
            name: name.into(),
            index: IfIndex::of(index),
            up: true,
            loopback: addr.is_loopback(),
            point_to_point: false,
            multicast: true,
            stable: true,
            addr,
            prefix: if addr.is_ipv4() { 24 } else { 64 },
        }
    }

    const BOTH: [Family; 2] = [Family::V4, Family::V6];

    fn links(want: &BTreeMap<Link, Joined>) -> Vec<(String, Family)> {
        want.iter()
            .map(|(link, j)| (j.name.clone(), link.family))
            .collect()
    }

    #[test]
    fn default_set_skips_loopback_containers_down_and_p2p() {
        let mut down = iface("wlo1", 3, "192.0.2.40");
        down.up = false;
        let mut tunnel = iface("utun0", 7, "fd00::1");
        tunnel.point_to_point = true;
        let mut no_multicast = iface("can0", 8, "192.0.2.50");
        no_multicast.multicast = false;
        let ifs = [
            iface("lo", 1, "127.0.0.1"),
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "fe80::1"),
            down,
            iface("docker0", 4, "172.17.0.1"),
            iface("br-0123456789ab", 5, "172.20.0.1"),
            iface("veth1234", 6, "fe80::2"),
            tunnel,
            no_multicast,
        ];
        assert_eq!(
            links(&wanted(&ifs, &[], &BOTH)),
            [
                ("enp1s0".to_string(), Family::V4),
                ("enp1s0".to_string(), Family::V6)
            ]
        );
    }

    #[test]
    fn loopback_interfaces_are_skipped_for_all_their_addresses() {
        // macOS gives lo0 fe80::1 as well as ::1 and 127.0.0.1.
        let ifs = [
            iface("lo0", 1, "127.0.0.1"),
            iface("lo0", 1, "::1"),
            iface("lo0", 1, "fe80::1"),
            iface("en0", 2, "192.0.2.20"),
        ];
        assert_eq!(
            links(&wanted(&ifs, &[], &BOTH)),
            [("en0".to_string(), Family::V4)]
        );
    }

    #[test]
    fn first_ipv4_address_is_the_membership_address() {
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "10.0.0.5"),
        ];
        let want = wanted(&ifs, &[], &BOTH);
        assert_eq!(
            want[&Link {
                index: IfIndex::of(2),
                family: Family::V4
            }]
                .membership,
            Membership::V4(Ipv4Addr::new(192, 0, 2, 10))
        );
    }

    #[test]
    fn named_interfaces_replace_the_default_set() {
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("docker0", 4, "172.17.0.1"),
        ];
        assert_eq!(
            links(&wanted(&ifs, &["docker0".to_string()], &BOTH)),
            [("docker0".to_string(), Family::V4)]
        );
    }

    #[test]
    fn ipv4_only_without_an_ipv6_socket() {
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "fe80::1"),
        ];
        assert_eq!(
            links(&wanted(&ifs, &[], &[Family::V4])),
            [("enp1s0".to_string(), Family::V4)]
        );
    }

    #[test]
    fn named_interfaces_without_a_link_are_reported() {
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("lo", 1, "127.0.0.1"),
        ];
        let only = ["enp1s0".to_string(), "wlan0".to_string(), "lo".to_string()];
        let want = wanted(&ifs, &only, &BOTH);
        assert_eq!(unserved(&only, &want), ["wlan0", "lo"]);
    }
    fn subnet(addr: &str, prefix: u8) -> (IpAddr, u8) {
        (addr.parse().unwrap(), prefix)
    }

    #[test]
    fn on_link_sources_are_in_a_subnet_or_ipv6_link_local() {
        let subnets = [subnet("192.0.2.10", 24), subnet("2001:db8::10", 64)];
        for (source, expected) in [
            ("192.0.2.200", true),
            ("192.0.3.1", false),
            ("198.51.100.7", false),
            ("2001:db8::99", true),
            ("2001:db8:1::1", false),
            ("fe80::1234", true),
            ("169.254.10.20", true),
            ("::1", false),
        ] {
            assert_eq!(
                on_link(source.parse().unwrap(), &subnets),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn prefix_lengths_at_the_edges() {
        assert!(on_link(
            "203.0.113.1".parse().unwrap(),
            &[subnet("192.0.2.10", 0)]
        ));
        assert!(on_link(
            "192.0.2.10".parse().unwrap(),
            &[subnet("192.0.2.10", 32)]
        ));
        assert!(!on_link(
            "192.0.2.11".parse().unwrap(),
            &[subnet("192.0.2.10", 32)]
        ));
        assert!(!on_link(
            "2001:db8::11".parse().unwrap(),
            &[subnet("2001:db8::10", 128)]
        ));
        assert!(!on_link(
            "192.0.2.10".parse().unwrap(),
            &[subnet("2001:db8::10", 0)]
        ));
    }

    const ENP1S0_V4: Link = Link {
        index: IfIndex::of(2),
        family: Family::V4,
    };

    #[test]
    fn subnets_cover_only_served_links() {
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "10.0.0.5"),
            iface("docker0", 4, "172.17.0.1"),
        ];
        let want = wanted(&ifs, &[], &BOTH);
        assert_eq!(want.len(), 1);
        assert_eq!(
            want[&ENP1S0_V4].subnets,
            [subnet("192.0.2.10", 24), subnet("10.0.0.5", 24)]
        );
    }

    #[test]
    fn packets_are_accepted_only_from_on_link_senders_on_served_links() {
        let ifs = [iface("enp1s0", 2, "192.0.2.10")];
        let joined = wanted(&ifs, &[], &BOTH);
        let other = Link {
            index: IfIndex::of(4),
            family: Family::V4,
        };
        let source = "192.0.2.20".parse().unwrap();
        assert_eq!(verdict(&joined, ENP1S0_V4, source), Verdict::Accept);
        assert_eq!(verdict(&joined, other, source), Verdict::Unserved);
        let far = "198.51.100.7".parse().unwrap();
        assert_eq!(verdict(&joined, ENP1S0_V4, far), Verdict::OffLink);
    }

    /// A `Net` without sockets, so every join fails, that has already
    /// joined `joined`.
    fn unconnected(joined: BTreeMap<Link, Joined>) -> Net {
        Net {
            v4: None,
            v6: None,
            only: Vec::new(),
            joined,
            unserved: Vec::new(),
            addrs: Vec::new(),
            #[cfg(target_os = "linux")]
            events: None,
            #[cfg(target_os = "linux")]
            event_buf: Vec::new(),
            drops: DropLog::default(),
            events_rest: Backoff::default(),
            full: Default::default(),
            log: Vec::new(),
        }
    }

    #[test]
    fn a_link_whose_join_failed_does_not_pass_the_source_check() {
        let ifs = [iface("enp1s0", 2, "192.0.2.10")];
        let mut net = unconnected(BTreeMap::new());
        let scan = net.reconcile(&ifs, &[Family::V4]);
        assert!(scan.added.is_empty() && scan.removed.is_empty());
        let log = net.take_log();
        assert_eq!(log.len(), 1);
        assert!(log[0].starts_with("cannot join enp1s0 (IPv4): "), "{log:?}");
        assert!(!net.serves(ENP1S0_V4));
        let source = "192.0.2.20".parse().unwrap();
        assert_eq!(verdict(&net.joined, ENP1S0_V4, source), Verdict::Unserved);
    }

    #[test]
    fn a_rescan_logs_leaving_then_unserved_then_joining() {
        let old = [iface("enp1s0", 2, "192.0.2.10")];
        let mut net = unconnected(wanted(&old, &[], &[Family::V4]));
        net.only = vec!["enp2s0".into(), "missing0".into()];
        let now = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp2s0", 3, "198.51.100.10"),
        ];
        net.reconcile(&now, &[Family::V4]);
        let log = net.take_log();
        assert_eq!(log.len(), 3, "{log:?}");
        assert_eq!(log[0], "left enp1s0 (IPv4)");
        assert_eq!(
            log[1],
            "interface missing0 is missing or not usable, will use it when it appears"
        );
        assert!(log[2].starts_with("cannot join enp2s0 (IPv4): "), "{log:?}");
    }

    #[test]
    fn an_address_only_change_keeps_the_link_and_updates_its_subnets() {
        let before = [iface("enp1s0", 2, "192.0.2.10")];
        let mut net = unconnected(wanted(&before, &[], &[Family::V4]));
        net.reconcile(&before, &[Family::V4]);
        let new_source = "198.51.100.20".parse().unwrap();
        assert_eq!(
            verdict(&net.joined, ENP1S0_V4, new_source),
            Verdict::OffLink
        );
        // A second address, and a wider prefix on the first, which stays
        // the membership address: no rejoin, which here would fail.
        let mut wider = iface("enp1s0", 2, "192.0.2.10");
        wider.prefix = 16;
        let after = [wider, iface("enp1s0", 2, "198.51.100.10")];
        let scan = net.reconcile(&after, &[Family::V4]);
        assert!(scan.added.is_empty() && scan.removed.is_empty());
        assert_eq!(scan.addresses.len(), 1);
        assert!(net.take_log().is_empty());
        assert!(net.serves(ENP1S0_V4));
        assert_eq!(
            net.joined[&ENP1S0_V4].subnets,
            [subnet("192.0.2.10", 16), subnet("198.51.100.10", 24)]
        );
        assert_eq!(verdict(&net.joined, ENP1S0_V4, new_source), Verdict::Accept);
        // A new membership address does mean joining again, which fails
        // here and drops the link.
        let moved = [iface("enp1s0", 2, "192.0.2.11")];
        let scan = net.reconcile(&moved, &[Family::V4]);
        assert_eq!(scan.removed, [ENP1S0_V4]);
        assert!(!net.serves(ENP1S0_V4));
    }

    #[test]
    fn receive_errors_are_logged_first_then_once_a_minute() {
        let mut log = FailureLog::default();
        assert_eq!(log.failed(1_000), Some(0));
        assert_eq!(log.failed(1_100), None);
        assert_eq!(log.failed(60_999), None);
        // A minute after the line, with the two skipped repeats counted.
        assert_eq!(log.failed(61_000), Some(2));
        assert_eq!(log.failed(61_100), None);
        assert_eq!(log.failed(121_000), Some(1));
    }

    #[test]
    fn receive_recovery_is_logged_once_and_rearms_the_log() {
        let mut log = FailureLog::default();
        assert_eq!(log.recovered(), None);
        assert_eq!(log.failed(0), Some(0));
        assert_eq!(log.recovered(), Some(0));
        assert_eq!(log.recovered(), None);
        // A new failure right after is a first one again.
        assert_eq!(log.failed(10), Some(0));
        // Recovery counts the failures skipped since the last line.
        assert_eq!(log.failed(20), None);
        assert_eq!(log.failed(30), None);
        assert_eq!(log.failed(40), None);
        assert_eq!(log.recovered(), Some(3));
        assert_eq!(log.failed(50), Some(0));
        assert_eq!(log.recovered(), Some(0));
    }

    #[test]
    fn off_link_drops_are_logged_once_per_link_per_rescan() {
        let mut log = DropLog::default();
        let a = Link {
            index: IfIndex::of(2),
            family: Family::V4,
        };
        let b = Link {
            index: IfIndex::of(2),
            family: Family::V6,
        };
        assert!(log.first(a));
        assert!(!log.first(a));
        assert!(log.first(b));
        log.reset();
        assert!(log.first(a));
    }

    #[test]
    fn stable_addresses_are_kept_per_served_interface() {
        let mut temporary = iface("enp1s0", 2, "2001:db8::99");
        temporary.stable = false;
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "2001:db8::10"),
            temporary,
            iface("docker0", 4, "172.17.0.1"),
        ];
        let want = wanted(&ifs, &[], &BOTH);
        let stable = stable_addresses(&ifs, &want);
        assert_eq!(stable.len(), 1);
        assert_eq!(stable[0].0, IfIndex::of(2));
        assert_eq!(
            stable[0].1,
            [
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::10".parse().unwrap()
            ]
        );
    }

    #[test]
    fn changed_and_new_interfaces_are_reported() {
        let old = vec![(
            IfIndex::of(2),
            vec!["192.0.2.10".parse::<IpAddr>().unwrap()],
        )];
        let same = old.clone();
        assert!(address_changes(&old, &same).is_empty());
        let moved = vec![
            (
                IfIndex::of(2),
                vec!["192.0.2.11".parse::<IpAddr>().unwrap()],
            ),
            (IfIndex::of(3), vec!["198.51.100.10".parse().unwrap()]),
        ];
        assert_eq!(
            address_changes(&old, &moved),
            [
                (IfIndex::of(2), vec!["192.0.2.11".parse().unwrap()]),
                (IfIndex::of(3), vec!["198.51.100.10".parse().unwrap()])
            ]
        );
    }

    #[test]
    fn departed_interfaces_report_empty_address_sets() {
        let old = vec![(
            IfIndex::of(2),
            vec!["192.0.2.10".parse::<IpAddr>().unwrap()],
        )];
        assert_eq!(address_changes(&old, &[]), [(IfIndex::of(2), Vec::new())]);
    }

    #[test]
    fn settle_waits_for_a_quiet_spell() {
        let mut s = Settle::default();
        assert!(!s.due(0));
        s.changed(1000);
        assert!(!s.due(1100));
        s.changed(1200);
        assert!(!s.due(1449));
        assert!(s.due(1450));
        s.clear();
        assert!(!s.due(9000));
    }

    #[test]
    fn settle_says_when_it_is_due() {
        let mut s = Settle::default();
        assert_eq!(s.due_at(), None);
        s.changed(1000);
        assert_eq!(s.due_at(), Some(1250));
        s.changed(1200);
        assert_eq!(s.due_at(), Some(1450));
        // Never past the cap after the first notification.
        s.changed(2900);
        assert_eq!(s.due_at(), Some(3000));
        s.overflowed();
        assert_eq!(s.due_at(), Some(0));
        s.clear();
        assert_eq!(s.due_at(), None);
    }

    #[test]
    fn a_failed_socket_rests_then_is_waited_on_again() {
        let mut rest = Backoff::default();
        assert_eq!(rest.until(0), None);
        rest.start(1_000);
        assert_eq!(rest.until(1_000), Some(1_100));
        assert_eq!(rest.until(1_099), Some(1_100));
        // Over: no deadline left behind to wake the loop at once forever.
        assert_eq!(rest.until(1_100), None);
        assert_eq!(rest.until(5_000), None);
        // Another failure starts another rest.
        rest.start(5_000);
        assert_eq!(rest.until(5_000), Some(5_100));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wait_results_map_to_readiness() {
        assert_eq!(readiness(-1, 0), Readiness::Unwatched);
        assert_eq!(readiness(3, 0), Readiness::Idle);
        assert_eq!(readiness(3, libc::POLLIN), Readiness::Readable);
        for bit in [libc::POLLERR, libc::POLLHUP, libc::POLLNVAL] {
            assert_eq!(readiness(3, bit), Readiness::Faulty);
            assert_eq!(readiness(3, bit | libc::POLLIN), Readiness::Faulty);
        }
    }

    #[test]
    fn a_failed_drain_rests_the_notification_socket() {
        use crate::netlink::Drained;

        let mut net = unconnected(BTreeMap::new());
        net.note_drain(&Drained::default(), 1_000);
        assert_eq!(net.events_rest_until(1_000), None);
        let failed = Drained {
            changed: true,
            overflow: false,
            failed: true,
        };
        net.note_drain(&failed, 1_000);
        assert_eq!(net.events_rest_until(1_000), Some(1_100));
        // Resting: not read at all, so nothing to report.
        assert_eq!(net.drain_events(1_050), Drained::default());
        assert_eq!(net.events_rest_until(1_100), None);
        assert_eq!(net.drain_events(1_100), Drained::default());
    }

    #[test]
    fn full_buffer_drops_are_logged_per_family_then_once_a_minute() {
        let mut net = unconnected(BTreeMap::new());
        assert_eq!(net.send_dropped(Family::V4, 1_000), Some(0));
        assert_eq!(net.send_dropped(Family::V4, 1_010), None);
        assert_eq!(net.send_dropped(Family::V4, 1_020), None);
        // The other family has a log of its own.
        assert_eq!(net.send_dropped(Family::V6, 1_020), Some(0));
        assert_eq!(net.send_dropped(Family::V4, 60_999), None);
        assert_eq!(net.send_dropped(Family::V4, 61_000), Some(3));
        // Long after, a lone drop is logged with the count so far.
        assert_eq!(net.send_dropped(Family::V6, 500_000), Some(0));
    }

    #[test]
    fn settle_caps_the_wait() {
        let mut s = Settle::default();
        for t in (1000..3000).step_by(100) {
            s.changed(t);
        }
        assert!(!s.due(2999));
        assert!(s.due(3000));
    }

    #[test]
    fn an_overflow_is_due_at_once() {
        let mut s = Settle::default();
        s.overflowed();
        assert!(s.due(0));
        // Later notifications do not turn it back into a wait.
        s.changed(0);
        assert!(s.due(0));
    }

    #[test]
    fn an_overflow_during_a_burst_is_due_at_once() {
        let mut s = Settle::default();
        s.changed(1000);
        s.overflowed();
        assert!(s.due(1000));
        s.clear();
        assert!(!s.due(9000));
    }
}
