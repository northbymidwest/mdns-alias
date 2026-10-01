//! Sockets and interfaces: one socket per address family, sharing UDP 5353
//! with the host's own responder, joined to the mDNS group on each interface
//! served.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket_pktinfo::PktInfoUdpSocket;
use socket2::{Domain, SockAddr, SockRef};

use crate::responder::{Dest, Family, Link, MDNS_PORT, Outgoing};

const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// How long a receive waits before the loop moves on to the other socket
/// and to due timers. mDNS tolerates far more latency than this.
const RECV_TIMEOUT: Duration = Duration::from_millis(100);
/// Container bridges and veths, skipped unless named with `--interface`:
/// nothing on them resolves the host's LAN names.
const SKIPPED_PREFIXES: [&str; 3] = ["docker", "br-", "veth"];

pub struct Net {
    /// Either may be missing, for a host with that family disabled.
    v4: Option<PktInfoUdpSocket>,
    v6: Option<PktInfoUdpSocket>,
    /// `--interface` names; empty means the default set.
    only: Vec<String>,
    joined: BTreeMap<Link, Joined>,
    /// Named interfaces last reported as unserved, so each absence is logged
    /// once rather than on every rescan.
    unserved: Vec<String>,
    /// Each served link's addresses and prefix lengths, for the source
    /// check. Replaced on every successful rescan.
    subnets: BTreeMap<Link, Vec<(IpAddr, u8)>>,
    drops: DropLog,
    /// Lines to log, collected by `take_log`.
    log: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Joined {
    name: String,
    /// IPv4 group membership is keyed by an interface address, so a change
    /// of address means leaving and joining again. IPv6 uses the index.
    v4: Option<Ipv4Addr>,
}

#[derive(Debug, Default)]
pub struct Rescan {
    /// Links that are new: probe and announce on them.
    pub added: Vec<Link>,
    /// Links that are gone: forget them.
    pub removed: Vec<Link>,
    pub log: Vec<String>,
}

pub struct Received {
    pub len: usize,
    pub link: Link,
    pub source: SocketAddr,
}

/// One address on one interface, whichever way the platform lists them.
#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    /// Administratively up and with a carrier.
    pub up: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    /// Opens a socket per family. One family failing, as IPv6 does on a
    /// host that disables it, leaves the other serving, with a line to log
    /// saying so; both failing is an error.
    pub fn open(only: Vec<String>) -> io::Result<(Net, Vec<String>)> {
        let mut log = Vec::new();
        let (v4, v6) = match (socket(Family::V4), socket(Family::V6)) {
            (Err(e), Err(_)) => return Err(e),
            (v4, v6) => {
                for (family, result) in [(Family::V4, &v4), (Family::V6, &v6)] {
                    if let Err(e) = result {
                        let name = family_name(family);
                        log.push(format!("{name} unavailable, serving without it: {e}"));
                    }
                }
                (v4.ok(), v6.ok())
            }
        };
        let net = Net {
            v4,
            v6,
            only,
            joined: BTreeMap::new(),
            unserved: Vec::new(),
            subnets: BTreeMap::new(),
            drops: DropLog::default(),
            log: Vec::new(),
        };
        Ok((net, log))
    }

    /// Brings group membership in line with the interfaces present now.
    pub fn rescan(&mut self) -> Rescan {
        let mut scan = Rescan::default();
        let ifs = match list_interfaces() {
            Ok(ifs) => ifs,
            Err(e) => {
                scan.log.push(format!("cannot list interfaces: {e}"));
                return scan;
            }
        };
        let want = wanted(&ifs, &self.only, &self.families());
        self.subnets = subnets(&ifs, &want);
        self.drops.reset();
        let gone: Vec<Link> = self
            .joined
            .keys()
            .filter(|link| !want.contains_key(link))
            .copied()
            .collect();
        for link in gone {
            scan.log.push(format!("left {}", self.describe(link)));
            self.leave(link);
            scan.removed.push(link);
        }
        let unserved = unserved(&self.only, &want);
        for name in unserved.iter().filter(|n| !self.unserved.contains(n)) {
            scan.log.push(format!(
                "interface {name} is missing or not usable, looking again every 30s"
            ));
        }
        self.unserved = unserved;
        for (link, joined) in want {
            let current = self.joined.get(&link).cloned();
            if current.as_ref() == Some(&joined) {
                continue;
            }
            // An address change keeps the link, and its records, as they are.
            let changed = current.is_some();
            if changed {
                self.leave(link);
            }
            match self.join(link, &joined) {
                Ok(()) => {
                    self.joined.insert(link, joined);
                    if !changed {
                        scan.log.push(format!("joined {}", self.describe(link)));
                        scan.added.push(link);
                    }
                }
                Err(e) => {
                    scan.log.push(format!(
                        "cannot join {} ({}): {e}",
                        joined.name,
                        family_name(link.family)
                    ));
                    if changed {
                        scan.removed.push(link);
                    }
                }
            }
        }
        scan
    }

    /// Waits up to 100 ms for a packet on one family's socket.
    pub fn recv(&mut self, family: Family, buf: &mut [u8]) -> io::Result<Option<Received>> {
        let Ok(sock) = self.socket(family) else {
            return Ok(None);
        };
        match sock.recv(buf) {
            Ok((len, info)) => {
                // Index 0 is never a link we serve, so the packet is ignored.
                let index = u32::try_from(info.if_index).unwrap_or(0);
                let link = Link { index, family };
                // Off-link senders (RFC 6762 section 11), and anything on a
                // link we do not serve, never reach the responder. Off-link
                // drops on a served link are logged once per rescan: a
                // netmask that does not cover the LAN should not fail
                // silently.
                match verdict(&self.subnets, link, info.addr_src.ip()) {
                    Verdict::Accept => {}
                    Verdict::Unserved => return Ok(None),
                    Verdict::OffLink => {
                        if self.drops.first(link) {
                            self.log.push(format!(
                                "ignoring {} on {}: not on its subnets; further ones are \
                                 ignored silently until the next rescan",
                                info.addr_src.ip(),
                                self.describe(link)
                            ));
                        }
                        return Ok(None);
                    }
                }
                Ok(Some(Received {
                    len,
                    link,
                    source: info.addr_src,
                }))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Sends on the packet's link: multicast to the group there, or unicast.
    pub fn send(&self, out: &Outgoing) -> io::Result<()> {
        let dest = match (out.link.family, out.dest) {
            (_, Dest::Unicast(addr)) => addr,
            (Family::V4, Dest::Multicast) => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
            (Family::V6, Dest::Multicast) => {
                SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, out.link.index))
            }
        };
        let dest = SockAddr::from(dest);
        match out.link.family {
            Family::V4 => {
                let addr = self
                    .joined
                    .get(&out.link)
                    .and_then(|j| j.v4)
                    .ok_or(io::ErrorKind::NotFound)?;
                let sock = self.socket(Family::V4)?;
                sock.set_multicast_if_v4(&addr)?;
                sock.send_to(&out.packet, &dest)?;
            }
            Family::V6 => {
                let sock = self.socket(Family::V6)?;
                sock.set_multicast_if_v6(out.link.index)?;
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
        let _ = match (link.family, joined.v4) {
            (Family::V4, Some(addr)) => sock.leave_multicast_v4(&GROUP_V4, &addr),
            (Family::V6, _) => sock.leave_multicast_v6(&GROUP_V6, link.index),
            (Family::V4, None) => Ok(()),
        };
    }

    /// The highest descriptor the sockets hold, so the sandbox can cap new
    /// descriptors just above it.
    pub fn highest_fd(&self) -> i32 {
        [&self.v4, &self.v6]
            .into_iter()
            .flatten()
            .map(|sock| sock.as_raw_fd())
            .max()
            .unwrap_or(-1)
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
        format!("{name} ({})", family_name(link.family))
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
        match (link.family, joined.v4) {
            (Family::V4, Some(addr)) => sock.join_multicast_v4(&GROUP_V4, &addr),
            (Family::V6, _) => sock.join_multicast_v6(&GROUP_V6, link.index),
            (Family::V4, None) => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
}

fn family_name(family: Family) -> &'static str {
    match family {
        Family::V4 => "IPv4",
        Family::V6 => "IPv6",
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
    // A std handle on the same socket, for the options PktInfoUdpSocket does
    // not offer. Dropping it closes only the duplicate descriptor.
    let handle = sock.try_clone_std()?;
    handle.set_read_timeout(Some(RECV_TIMEOUT))?;
    match family {
        Family::V4 => {
            sock.set_multicast_loop_v4(true)?;
            sock.set_multicast_ttl_v4(255)?;
        }
        Family::V6 => {
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
        let (family, v4) = match i.addr {
            IpAddr::V4(addr) => (Family::V4, Some(addr)),
            IpAddr::V6(_) => (Family::V6, None),
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
            v4,
        });
    }
    want
}

/// The `--interface` names that yield no link: absent, down, or unusable.
fn unserved(only: &[String], want: &BTreeMap<Link, Joined>) -> Vec<String> {
    only.iter()
        .filter(|name| !want.values().any(|j| &j.name == *name))
        .cloned()
        .collect()
}

/// Each served link's addresses and prefix lengths.
fn subnets(ifs: &[Interface], want: &BTreeMap<Link, Joined>) -> BTreeMap<Link, Vec<(IpAddr, u8)>> {
    let mut out: BTreeMap<Link, Vec<(IpAddr, u8)>> = BTreeMap::new();
    for i in ifs {
        let family = if i.addr.is_ipv4() {
            Family::V4
        } else {
            Family::V6
        };
        let link = Link {
            index: i.index,
            family,
        };
        if want.contains_key(&link) {
            out.entry(link).or_default().push((i.addr, i.prefix));
        }
    }
    out
}

/// What to do with a packet from `source` on `link`.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    /// A link we do not serve: Linux delivers group traffic joined by any
    /// socket to every one, so this is normal.
    Unserved,
    /// A served link, but the source is not on-link there.
    OffLink,
}

fn verdict(subnets: &BTreeMap<Link, Vec<(IpAddr, u8)>>, link: Link, source: IpAddr) -> Verdict {
    match subnets.get(&link) {
        None => Verdict::Unserved,
        Some(s) if on_link(source, s) => Verdict::Accept,
        Some(_) => Verdict::OffLink,
    }
}

/// The links that have logged an off-link drop since the last rescan.
#[derive(Debug, Default)]
struct DropLog(BTreeSet<Link>);

impl DropLog {
    /// Whether this is the first drop on `link` since the last reset.
    fn first(&mut self, link: Link) -> bool {
        self.0.insert(link)
    }

    fn reset(&mut self) {
        self.0.clear();
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
                index: i.index?,
                up: i.is_oper_up(),
                loopback: i.is_loopback(),
                point_to_point: i.is_p2p(),
                // if-addrs does not report it; an interface without it fails
                // to join the group, which is logged.
                multicast: true,
                addr: i.ip(),
                prefix,
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
            index,
            up: true,
            loopback: addr.is_loopback(),
            point_to_point: false,
            multicast: true,
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
                index: 2,
                family: Family::V4
            }]
                .v4,
            Some(Ipv4Addr::new(192, 0, 2, 10))
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

    #[test]
    fn subnets_cover_only_served_links() {
        let ifs = [
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "10.0.0.5"),
            iface("docker0", 4, "172.17.0.1"),
        ];
        let subnets = subnets(&ifs, &wanted(&ifs, &[], &BOTH));
        assert_eq!(subnets.len(), 1);
        assert_eq!(
            subnets[&Link {
                index: 2,
                family: Family::V4
            }],
            [subnet("192.0.2.10", 24), subnet("10.0.0.5", 24)]
        );
    }

    #[test]
    fn packets_are_accepted_only_from_on_link_senders_on_served_links() {
        let ifs = [iface("enp1s0", 2, "192.0.2.10")];
        let subnets = subnets(&ifs, &wanted(&ifs, &[], &BOTH));
        let served = Link {
            index: 2,
            family: Family::V4,
        };
        let other = Link {
            index: 4,
            family: Family::V4,
        };
        let source = "192.0.2.20".parse().unwrap();
        assert_eq!(verdict(&subnets, served, source), Verdict::Accept);
        assert_eq!(verdict(&subnets, other, source), Verdict::Unserved);
        let far = "198.51.100.7".parse().unwrap();
        assert_eq!(verdict(&subnets, served, far), Verdict::OffLink);
    }

    #[test]
    fn off_link_drops_are_logged_once_per_link_per_rescan() {
        let mut log = DropLog::default();
        let a = Link {
            index: 2,
            family: Family::V4,
        };
        let b = Link {
            index: 2,
            family: Family::V6,
        };
        assert!(log.first(a));
        assert!(!log.first(a));
        assert!(log.first(b));
        log.reset();
        assert!(log.first(a));
    }
}
