//! Interfaces and their addresses from the kernel, over rtnetlink: one link
//! dump and one address dump per rescan. On Linux this replaces
//! getifaddrs, whose musl version also opens a Unix socket and issues an
//! ioctl for every address; the sandbox allows neither. Parsing is pure and
//! tested everywhere; only the socket is Linux-specific.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Message types: the dump requests `request` builds, and the replies.
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
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
pub const IFA_F_TEMPORARY: u32 = 0x01;
pub const IFA_F_DADFAILED: u32 = 0x08;
pub const IFA_F_DEPRECATED: u32 = 0x20;
pub const IFA_F_TENTATIVE: u32 = 0x40;
/// Notification groups: links, IPv4 addresses, IPv6 addresses.
pub const RTNLGRP_LINK: u32 = 1;
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

pub const IFF_UP: u32 = 0x1;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub index: u32,
    pub flags: u32,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    pub index: u32,
    pub addr: IpAddr,
    pub prefix: u8,
    pub flags: u32,
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

/// A dump request for `rtype` (RTM_GETLINK or RTM_GETADDR) across every
/// address family.
pub fn request(rtype: u16, seq: u32) -> Vec<u8> {
    let body = if rtype == RTM_GETLINK {
        IFINFOMSG
    } else {
        IFADDRMSG
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

/// Calls `each(type, payload)` for every message in one received datagram,
/// and returns whether the dump is finished (NLMSG_DONE seen).
pub fn messages(buf: &[u8], each: &mut dyn FnMut(u16, &[u8])) -> Result<bool, Malformed> {
    let mut at = 0;
    while at < buf.len() {
        let len = u32_at(buf, at).ok_or(Malformed)? as usize;
        let kind = u16_at(buf, at + 4).ok_or(Malformed)?;
        if len < HEADER || len > buf.len() - at {
            return Err(Malformed);
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => return Err(Malformed),
            _ => each(kind, &buf[at + HEADER..at + len]),
        }
        at += align(len);
    }
    Ok(false)
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

/// An RTM_NEWLINK payload. `None` if it is too short or has no name.
pub fn parse_link(payload: &[u8]) -> Option<LinkInfo> {
    let index = u32_at(payload, 4)?;
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
/// IFA_ADDRESS is the peer's address.
pub fn parse_addr(payload: &[u8]) -> Option<AddrInfo> {
    let family = *payload.first()?;
    let prefix = *payload.get(1)?;
    let index = u32_at(payload, 4)?;
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
pub fn is_change(kind: u16) -> bool {
    matches!(kind, RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR)
}

/// What draining the notification socket found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// A link or address changed: rescan once things settle.
    pub changed: bool,
    /// The kernel dropped notifications: rescan now.
    pub overflow: bool,
}

/// A non-blocking socket subscribed to link and address notifications.
/// Subscribing is only possible before lockdown.
#[cfg(target_os = "linux")]
pub fn subscribe() -> std::io::Result<socket2::Socket> {
    use std::os::fd::AsRawFd;

    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::RAW,
        Some(Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    crate::sys::netlink_bind(sock.as_raw_fd())?;
    for group in [RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR] {
        crate::sys::netlink_subscribe(sock.as_raw_fd(), group)?;
    }
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Reads every pending notification from `sock` without blocking.
/// Anything unreadable counts as a change: a needless rescan is cheap, a
/// missed change is not.
#[cfg(target_os = "linux")]
pub fn drain(sock: &socket2::Socket, buf: &mut [u8]) -> Drained {
    use std::io::{ErrorKind, Read};

    let mut drained = Drained::default();
    let mut reader = sock;
    loop {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                let parsed = messages(&buf[..n], &mut |kind, _| drained.changed |= is_change(kind));
                if parsed.is_err() {
                    drained.changed = true;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => drained.overflow = true,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                drained.changed = true;
                break;
            }
        }
    }
    drained
}

/// Every link and every address, straight from the kernel. The socket is
/// the only one the sandboxed steady state may open: AF_NETLINK,
/// NETLINK_ROUTE.
#[cfg(target_os = "linux")]
pub fn dump() -> std::io::Result<(Vec<LinkInfo>, Vec<AddrInfo>)> {
    use std::io::{self, Read};

    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::RAW,
        Some(Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    // The kernel sizes dump datagrams to the reader's buffer, up to 32 KiB.
    let mut buf = vec![0u8; 32 * 1024];
    let (mut links, mut addrs) = (Vec::new(), Vec::new());
    for (seq, rtype) in [(1, RTM_GETLINK), (2, RTM_GETADDR)] {
        sock.send(&request(rtype, seq))?;
        loop {
            let n = (&sock).read(&mut buf)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let done = messages(&buf[..n], &mut |kind, payload| match kind {
                RTM_NEWLINK => links.extend(parse_link(payload)),
                RTM_NEWADDR => addrs.extend(parse_addr(payload)),
                _ => {}
            })
            .map_err(|Malformed| io::Error::from(io::ErrorKind::InvalidData))?;
            if done {
                break;
            }
        }
    }
    Ok((links, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let link = request(RTM_GETLINK, 7);
        assert_eq!(link.len(), HEADER + IFINFOMSG);
        assert_eq!(u32::from_ne_bytes(link[0..4].try_into().unwrap()), 32);
        assert_eq!(
            u16::from_ne_bytes(link[4..6].try_into().unwrap()),
            RTM_GETLINK
        );
        assert_eq!(u16::from_ne_bytes(link[6..8].try_into().unwrap()), 0x301);
        assert_eq!(u32::from_ne_bytes(link[8..12].try_into().unwrap()), 7);
        assert!(link[12..].iter().all(|&b| b == 0));
        assert_eq!(request(RTM_GETADDR, 8).len(), HEADER + IFADDRMSG);
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
                    index: 2,
                    flags: UP,
                    name: "enp1s0".into()
                },
                LinkInfo {
                    index: 1,
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
                index: 2,
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
                index: 2,
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

    #[test]
    fn short_or_nameless_payloads_yield_nothing() {
        assert_eq!(parse_link(&[0; 8]), None);
        assert_eq!(parse_link(&[0; IFINFOMSG]), None);
        assert_eq!(parse_addr(&[AF_INET, 24]), None);
        let mut overrun = vec![0u8; IFINFOMSG];
        overrun.extend(200u16.to_ne_bytes());
        overrun.extend(IFLA_IFNAME.to_ne_bytes());
        overrun.extend(b"lo\0\0");
        assert_eq!(parse_link(&overrun), None);
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
}
