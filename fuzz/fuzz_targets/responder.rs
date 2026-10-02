//! The responder answers whatever the LAN sends. Whatever packets, clock
//! steps, address changes and link changes arrive, in any order, it must
//! never panic, every packet it sends must fit one datagram and parse, a
//! multicast one must not claim to be truncated, and after a poll nothing
//! may be due already.
//!
//! The input is a header byte (bits 1-2 the number of aliases; bit 0 is
//! unused, as it once picked CNAME mode, so older inputs keep their
//! meaning) and then steps, each an opcode byte and operands:
//!
//! - 0 delivers a raw packet (link, source, port, length in 6-byte units,
//!   bytes);
//! - 1 advances the clock by up to about four seconds and polls (two bytes
//!   of milliseconds);
//! - 2 sets a link's addresses (mostly 0-3 of them, now and then 40-71,
//!   enough to make an alias too big for one packet), 3 adds a link, 4
//!   removes a link;
//! - 5 takes the goodbyes;
//! - 6 delivers a packet built from a few bytes as a message (link,
//!   source, port, then the message: flags, questions, authority and
//!   answer records about the aliases), encoded, so that the packets that
//!   matter are reached without the fuzzer spelling out a valid one. It
//!   needs no length. The port byte of 0 and 6 is 0-127 for the mDNS port,
//!   else a legacy one; its bit 6 set marks a sender a unicast reply cannot
//!   reach (off the link's subnets), which must never get one;
//! - 7 advances the clock by minutes (one byte of 2 s units, up to about
//!   8.5 minutes) and polls, so that the 5-minute retry of a lost alias is
//!   reachable.
//!
//! Every unicast reply to port 5353 the responder sends is also fed back through
//! `unicast_failed`, as if the send had failed for lack of a route, and
//! what that returns is held to the same rules and must be multicast.
//!
//! The corpus is git-ignored; seed `fuzz/corpus/responder/` with such
//! inputs, for instance a header then `00 <link> <addr> <port> <len> <a
//! query for an alias>` with `<len>` in 6-byte units, if a start is wanted.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use mdns_alias::testing::net::IfIndex;
use mdns_alias::testing::responder::{
    Dest, Family, Link, MAX_PACKET, MDNS_PORT, Outgoing, Responder, Source,
};
use mdns_alias::testing::wire::{self, Class, Message, Name, Question, RData, RType, Record};

/// Reads bytes, and yields zeros once the input is spent.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.0.split_at(n.min(self.0.len()));
        self.0 = rest;
        head
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }

    fn link(&mut self) -> Link {
        let b = self.byte();
        Link {
            index: IfIndex::new(u32::from(b & 3) + 1).unwrap(),
            family: if b & 4 == 0 { Family::V4 } else { Family::V6 },
        }
    }

    /// One of a few addresses per family, so that packets and addresses
    /// meet: a source can be one of ours.
    fn addr(&mut self) -> IpAddr {
        let b = self.byte();
        let n = b >> 1 & 7;
        if b & 1 == 0 {
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
        } else if b & 0x10 == 0 {
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n.into()))
        } else {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n.into()))
        }
    }
}

/// A name: one of the aliases, or a stranger.
fn name(b: u8) -> Name {
    let names = [
        "web.local",
        "files.local",
        "a.b.local",
        "myhost.local",
        "other.local",
    ];
    Name::parse(names[usize::from(b) % names.len()]).unwrap()
}

fn rtype(b: u8) -> RType {
    [
        RType::A,
        RType::AAAA,
        RType::ANY,
        RType::CNAME,
        RType::NSEC,
        // Some type the responder does not know, carried as opaque data.
        RType(16),
    ][usize::from(b) % 6]
}

/// A record of the name: an address (one of the few the links have), a
/// CNAME, or opaque data of some other type.
fn record(cur: &mut Cursor) -> Record {
    let name = name(cur.byte());
    let b = cur.byte();
    let rdata = match b % 4 {
        0 => match cur.addr() {
            IpAddr::V4(a) => RData::A(a),
            IpAddr::V6(a) => RData::Aaaa(a),
        },
        1 => RData::Aaaa(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            0,
            cur.byte().into(),
        )),
        2 => RData::Cname(self::name(cur.byte())),
        // Opaque (other) rdata.
        _ => RData::other(RType(16), vec![cur.byte(); 3]).unwrap(),
    };
    Record {
        name,
        class: Class::IN,
        cache_flush: b & 4 != 0,
        ttl: if b & 8 == 0 { 120 } else { 0 },
        rdata,
    }
}

/// A message built from bytes: flags, then how many questions, authority
/// and answer records follow, then each.
fn message(cur: &mut Cursor) -> Message {
    let flags = cur.byte();
    let counts = cur.byte();
    Message {
        id: 0,
        is_response: flags & 1 != 0,
        truncated: flags & 2 != 0,
        questions: (0..counts & 3)
            .map(|_| {
                let b = cur.byte();
                Question {
                    name: name(b),
                    qtype: rtype(b >> 3),
                    qclass: Class::IN,
                    unicast_response: b & 0x80 != 0,
                }
            })
            .collect(),
        authorities: (0..counts >> 2 & 3).map(|_| record(cur)).collect(),
        answers: (0..counts >> 4 & 3).map(|_| record(cur)).collect(),
        additionals: (0..counts >> 6 & 1).map(|_| record(cur)).collect(),
    }
}

fn check(sends: &[Outgoing]) {
    for out in sends {
        assert!(out.packet.len() <= MAX_PACKET, "{} bytes", out.packet.len());
        let msg = wire::parse(&out.packet).expect("sent packet parses");
        if out.dest == Dest::Multicast {
            assert!(!msg.truncated, "multicast packet with TC");
        }
    }
}

/// `check`, and then each unicast packet of `sends` as if it could not be
/// sent for lack of a route: what the responder falls back to must be
/// multicast, and as sound as anything else it sends.
fn check_with_fallback(r: &mut Responder, sends: &[Outgoing], now: u64) {
    check(sends);
    for out in sends {
        // The program falls back only for a reply to port 5353: a legacy
        // querier cannot hear multicast.
        if matches!(out.dest, Dest::Unicast(a) if a.port() == MDNS_PORT) {
            let again = r.unicast_failed(out, now);
            check(&again);
            assert!(
                again.iter().all(|o| o.dest == Dest::Multicast),
                "a fallback that is not multicast"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor(data);
    let head = cur.byte();
    let names = ["web.local", "files.local", "a.b.local"];
    let aliases = names[..usize::from(head >> 1 & 3).clamp(1, 3)]
        .iter()
        .map(|n| Name::parse(n).unwrap())
        .collect();
    let mut r = Responder::new(aliases, u64::from(head));
    let mut now = 1000u64;
    for index in 1..=2 {
        let index = IfIndex::new(index).unwrap();
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, index.get() as u8)),
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0,
                0,
                0,
                0,
                0,
                index.get() as u16,
            )),
        ];
        check(&r.set_addresses(index, addrs, now).sends);
    }
    for family in [Family::V4, Family::V6] {
        r.add_link(
            Link {
                index: IfIndex::new(1).unwrap(),
                family,
            },
            now,
        );
    }
    r.add_link(
        Link {
            index: IfIndex::new(2).unwrap(),
            family: Family::V4,
        },
        now,
    );

    let mut steps = 0;
    while !cur.done() && steps < 512 {
        steps += 1;
        match cur.byte() % 8 {
            op @ (0 | 6) => {
                let raw = op == 0;
                let link = cur.link();
                let ip = cur.addr();
                let byte = cur.byte();
                let port = match byte {
                    0..=127 => MDNS_PORT,
                    p => 1024 + u16::from(p),
                };
                let source = Source {
                    addr: SocketAddr::new(ip, port),
                    unicast: byte & 0x40 == 0,
                    direct: byte & 0x20 != 0,
                };
                let packet = if raw {
                    let len = usize::from(cur.byte()) * 6;
                    cur.take(len).to_vec()
                } else {
                    wire::encode(&message(&mut cur))
                };
                let sends = r.handle(&packet, link, source, now).sends;
                check_with_fallback(&mut r, &sends, now);
                if !source.unicast {
                    assert!(
                        sends.iter().all(|o| o.dest == Dest::Multicast),
                        "unicast to an unreachable sender"
                    );
                }
            }
            op @ (1 | 7) => {
                now += if op == 1 {
                    u64::from(cur.byte()) << 4 | u64::from(cur.byte() >> 4)
                } else {
                    u64::from(cur.byte()) * 2000
                };
                let sends = r.poll(now).sends;
                check_with_fallback(&mut r, &sends, now);
                if let Some(due) = r.next_due() {
                    assert!(due > now, "due {due} at {now} after a poll");
                }
            }
            2 => {
                let link = cur.link();
                let b = cur.byte();
                // Mostly a few addresses; sometimes so many that an alias
                // no longer fits one packet.
                let count = if b & 0x80 == 0 {
                    usize::from(b & 3)
                } else {
                    40 + usize::from(b & 0x1f)
                };
                let addrs = (0..count).map(|_| cur.addr()).collect();
                check(&r.set_addresses(link.index, addrs, now).sends);
            }
            3 => {
                let link = cur.link();
                r.add_link(link, now);
            }
            4 => {
                let link = cur.link();
                r.remove_link(link);
            }
            _ => check(&r.goodbye()),
        }
    }
});
