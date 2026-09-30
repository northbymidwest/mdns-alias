//! Sockets and interfaces: one socket per address family, sharing UDP 5353
//! with the host's own responder, joined to the mDNS group on each interface
//! served.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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
        };
        Ok((net, log))
    }

    /// Brings group membership in line with the interfaces present now.
    pub fn rescan(&mut self) -> Rescan {
        let mut scan = Rescan::default();
        let want = match if_addrs::get_if_addrs() {
            Ok(ifs) => wanted(&ifs, &self.only, &self.families()),
            Err(e) => {
                scan.log.push(format!("cannot list interfaces: {e}"));
                return scan;
            }
        };
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
    pub fn recv(&self, family: Family, buf: &mut [u8]) -> io::Result<Option<Received>> {
        let Ok(sock) = self.socket(family) else {
            return Ok(None);
        };
        match sock.recv(buf) {
            Ok((len, info)) => {
                // Index 0 is never a link we serve, so the packet is ignored.
                let index = u32::try_from(info.if_index).unwrap_or(0);
                Ok(Some(Received {
                    len,
                    link: Link { index, family },
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
/// Interfaces that are down, loopback or point-to-point never qualify.
fn wanted(
    ifs: &[if_addrs::Interface],
    only: &[String],
    families: &[Family],
) -> BTreeMap<Link, Joined> {
    // Loopback is a property of the interface, but if-addrs reports it per
    // address, and macOS gives lo0 a non-loopback fe80::1 too.
    let loopback: Vec<&str> = ifs
        .iter()
        .filter(|i| i.is_loopback())
        .map(|i| i.name.as_str())
        .collect();
    let mut want = BTreeMap::new();
    for i in ifs {
        let Some(index) = i.index else { continue };
        if loopback.contains(&i.name.as_str()) || i.is_p2p() || !i.is_oper_up() {
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
        let (family, v4) = match i.ip() {
            IpAddr::V4(addr) => (Family::V4, Some(addr)),
            IpAddr::V6(_) => (Family::V6, None),
        };
        if !families.contains(&family) {
            continue;
        }
        want.entry(Link { index, family }).or_insert(Joined {
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

#[cfg(test)]
mod tests {
    use super::*;
    use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Ifv6Addr, Interface};

    fn iface(name: &str, index: u32, ip: &str) -> Interface {
        let addr = match ip.parse::<IpAddr>().unwrap() {
            IpAddr::V4(ip) => IfAddr::V4(Ifv4Addr {
                ip,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            IpAddr::V6(ip) => IfAddr::V6(Ifv6Addr {
                ip,
                netmask: Ipv6Addr::UNSPECIFIED,
                prefixlen: 64,
                broadcast: None,
            }),
        };
        Interface {
            name: name.into(),
            addr,
            index: Some(index),
            oper_status: IfOperStatus::Up,
            is_p2p: false,
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
        down.oper_status = IfOperStatus::Down;
        let mut tunnel = iface("utun0", 7, "fd00::1");
        tunnel.is_p2p = true;
        let ifs = [
            iface("lo", 1, "127.0.0.1"),
            iface("enp1s0", 2, "192.0.2.10"),
            iface("enp1s0", 2, "fe80::1"),
            down,
            iface("docker0", 4, "172.17.0.1"),
            iface("br-0123456789ab", 5, "172.20.0.1"),
            iface("veth1234", 6, "fe80::2"),
            tunnel,
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
}
