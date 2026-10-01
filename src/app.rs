//! The program: parse the command line, open the sockets, lock the
//! sandbox, then serve until SIGINT or SIGTERM.

use std::error::Error;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::time::Instant;

use crate::cli;
use crate::net::IfIndex;
use crate::net::{FailureLog, Net, RECV_TIMEOUT, Rescan, Settle};
use crate::responder::{Family, Mode, Notice, Responder, Step};
use crate::sandbox;
use crate::signals::Signals;

/// The kernel host name on Linux, where this is deployed. Elsewhere the
/// read fails and `--host` is required.
const HOSTNAME_FILE: &str = "/proc/sys/kernel/hostname";
/// Milliseconds between safety rescans when change notifications arrive.
const SAFETY_RESCAN: u64 = 300_000;
/// Milliseconds between rescans without notifications (macOS, or a host
/// that refused the subscription).
const POLL_RESCAN: u64 = 30_000;
/// Largest mDNS message (RFC 6762 section 17).
const MAX_MESSAGE: usize = 9000;

/// Runs the responder until SIGINT or SIGTERM. An error is fatal: bad
/// arguments, no usable socket, an unmet `--require-sandbox`, or a name
/// conflict.
pub fn run() -> Result<(), Box<dyn Error>> {
    let cli = cli::parse(std::env::args().skip(1))?;
    #[cfg(target_os = "linux")]
    if crate::sys::is_root() {
        return Err("refusing to run as root; run as an unprivileged user".into());
    }
    let hostname = std::fs::read_to_string(HOSTNAME_FILE).ok();
    let (target, aliases) = cli::resolve(&cli, hostname.as_deref())?;
    // Only for probe jitter, so a hash of the pid with a random key is plenty.
    let seed = RandomState::new().hash_one(std::process::id());
    let mode = if cli.cname {
        Mode::Cname(target.clone())
    } else {
        Mode::Addresses
    };
    let mut responder = Responder::new(aliases.clone(), mode.clone(), seed);
    let signals = Signals::new()?;
    let mut net = Net::open(cli.interfaces)?;
    log_net(&mut net);
    // Everything that needs files, new sockets or privileges is done; shed
    // the ability to do any of it again.
    let report = sandbox::lock(net.fds().into_iter().chain(signals.fd()));
    for line in report.lines() {
        eprintln!("mdns-alias: {line}");
    }
    if cli.require_sandbox && !report.complete() {
        return Err("--require-sandbox: not every sandbox layer could be applied".into());
    }
    for alias in &aliases {
        match &mode {
            Mode::Cname(host) => eprintln!("mdns-alias: publishing {alias} -> {host}"),
            Mode::Addresses => eprintln!("mdns-alias: publishing {alias}"),
        }
    }

    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let interval = if net.has_events() {
        SAFETY_RESCAN
    } else {
        POLL_RESCAN
    };
    let mut settle = Settle::default();
    let mut next_rescan = 0;
    let mut buf = vec![0; MAX_MESSAGE];
    let mut v4_failures = FailureLog::default();
    let mut v6_failures = FailureLog::default();
    while !signals.pending() {
        let drained = net.drain_events();
        if drained.overflow {
            settle.overflowed();
        } else if drained.changed {
            settle.changed(now());
        }
        if settle.due(now()) || now() >= next_rescan {
            settle.clear();
            rescan(&mut net, &mut responder, now());
            next_rescan = now() + interval;
        }
        for family in [Family::V4, Family::V6] {
            let received = net.recv(family, &mut buf);
            log_net(&mut net);
            let failures = match family {
                Family::V4 => &mut v4_failures,
                Family::V6 => &mut v6_failures,
            };
            if received.is_ok()
                && let Some(skipped) = failures.recovered()
            {
                eprintln!(
                    "mdns-alias: receiving on {family} works again{}",
                    not_logged(skipped, "failure")
                );
            }
            match received {
                Ok(Some(got)) => {
                    // A conflict ends the program: the name is someone else's.
                    let step = responder.handle(&buf[..got.len], got.link, got.source, now())?;
                    dispatch(&mut net, &mut responder, step);
                }
                Ok(None) => {}
                Err(e) => {
                    // A failed receive returns at once, so wait out the time
                    // it would have, or a dead socket spins the loop.
                    if let Some(skipped) = failures.failed(now()) {
                        eprintln!(
                            "mdns-alias: receive on {family} failed: {e}{}; \
                             retrying, and logging again at most once a minute",
                            not_logged(skipped, "")
                        );
                    }
                    std::thread::sleep(RECV_TIMEOUT);
                }
            }
        }
        let step = responder.poll(now());
        dispatch(&mut net, &mut responder, step);
    }

    // Goodbyes make clients forget the names now rather than when their
    // cached records expire.
    for out in responder.goodbye() {
        let _ = net.send(&out);
    }
    eprintln!("mdns-alias: stopped");
    Ok(())
}

/// ` (3 more failures not logged)` for `skipped` 3 and `noun` "failure",
/// ` (1 more not logged)` for 1 and no noun, nothing for 0.
fn not_logged(skipped: u64, noun: &str) -> String {
    match (skipped, noun) {
        (0, _) => String::new(),
        (_, "") => format!(" ({skipped} more not logged)"),
        (1, _) => format!(" (1 more {noun} not logged)"),
        _ => format!(" ({skipped} more {noun}s not logged)"),
    }
}

/// Logs what `net` has to say since the last call. Called right after each
/// step that can add lines (opening, a rescan, a receive), so they come
/// out in order with the lines around them.
fn log_net(net: &mut Net) {
    for line in net.take_log() {
        eprintln!("mdns-alias: {line}");
    }
}

fn rescan(net: &mut Net, responder: &mut Responder, now: u64) {
    let scan = net.rescan();
    log_net(net);
    for change in apply(scan, responder, now) {
        if let Some(name) = net.interface_name(change.index) {
            let list = if change.addrs.is_empty() {
                "none stable".to_string()
            } else {
                change
                    .addrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            eprintln!("mdns-alias: addresses on {name}: {list}");
        }
        dispatch(net, responder, change.step);
    }
    if net.is_empty() {
        eprintln!("mdns-alias: no usable interfaces yet");
    }
}

/// One interface's address change as `apply` made it: the new set as the
/// scan listed it, for the log, and what the responder sends about it.
struct Change {
    index: IfIndex,
    addrs: Vec<IpAddr>,
    step: Step,
}

/// Applies a rescan to the responder, returning each address change, in the
/// order of `scan.addresses`, for the caller to log and send.
///
/// Removed links go first, so a departed interface's empty address set finds
/// no link to say goodbye on: its sockets have already left the group.
/// Address changes come next, so an interface that stays keeps its links and
/// announces the change on them. Added links come last, so a new interface's
/// links find its addresses already set and go straight to probing with
/// them. (Added first, they would wait until the address change woke them,
/// and go through the same phases with the same packets, only with
/// different jitter draws; only removing first is load-bearing.)
///
/// Sending the steps after the links are added, rather than between address
/// changes, changes nothing: a step only sends on links that were already
/// served, and a failed send drops only such a link, never an added one.
fn apply(scan: Rescan, responder: &mut Responder, now: u64) -> Vec<Change> {
    for &link in &scan.removed {
        responder.remove_link(link);
    }
    let changes = scan
        .addresses
        .into_iter()
        .map(|(index, addrs)| Change {
            index,
            step: responder.set_addresses(index, addrs.clone(), now),
            addrs,
        })
        .collect();
    for &link in &scan.added {
        responder.add_link(link, now);
    }
    changes
}

fn dispatch(net: &mut Net, responder: &mut Responder, step: Step) {
    for notice in step.notices {
        match notice {
            Notice::Announced(link) => eprintln!("mdns-alias: announced on {}", net.describe(link)),
            Notice::TiebreakLost(link) => eprintln!(
                "mdns-alias: another host is probing for the same name on {}, probing again",
                net.describe(link)
            ),
            Notice::Oversized(link, alias) => eprintln!(
                "mdns-alias: {alias}'s records do not fit one packet on {}; not serving it there",
                net.describe(link)
            ),
        }
    }
    for out in step.sends {
        // An earlier send in this step may have failed and dropped the link.
        if !net.serves(out.link) {
            continue;
        }
        match net.send(&out) {
            Ok(()) => {}
            Err(e) if out.failure_breaks_link() => {
                eprintln!(
                    "mdns-alias: sending on {} failed, dropping it until the next rescan: {e}",
                    net.describe(out.link)
                );
                net.leave(out.link);
                responder.remove_link(out.link);
            }
            Err(e) => eprintln!(
                "mdns-alias: reply to {:?} on {} failed: {e}",
                out.dest,
                net.describe(out.link)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{apply, not_logged};
    use crate::net::IfIndex;
    use crate::net::Rescan;
    use crate::responder::{Family, Link, Mode, Outgoing, Responder};
    use crate::wire::{self, Message, Name, RData};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn skipped_counts_read_naturally() {
        assert_eq!(not_logged(0, "failure"), "");
        assert_eq!(not_logged(1, "failure"), " (1 more failure not logged)");
        assert_eq!(not_logged(3, "failure"), " (3 more failures not logged)");
        assert_eq!(not_logged(0, ""), "");
        assert_eq!(not_logged(2, ""), " (2 more not logged)");
    }

    const V4: Link = Link {
        index: IfIndex::of(2),
        family: Family::V4,
    };
    const V6: Link = Link {
        index: IfIndex::of(2),
        family: Family::V6,
    };
    /// A link on another interface, index 3.
    const OTHER: Link = Link {
        index: IfIndex::of(3),
        family: Family::V4,
    };

    fn responder() -> Responder {
        let alias = Name::parse("app.myhost.local").unwrap();
        Responder::new(vec![alias], Mode::Addresses, 7)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn scan(added: &[Link], removed: &[Link], addresses: &[(u32, &[&str])]) -> Rescan {
        Rescan {
            added: added.to_vec(),
            removed: removed.to_vec(),
            addresses: addresses
                .iter()
                .map(|(index, addrs)| (IfIndex::of(*index), addrs.iter().map(|a| ip(a)).collect()))
                .collect(),
        }
    }

    /// Polls every millisecond from `from` to `to` inclusive.
    fn run(r: &mut Responder, from: u64, to: u64) -> Vec<(u64, Outgoing)> {
        (from..=to)
            .flat_map(|now| r.poll(now).sends.into_iter().map(move |o| (now, o)))
            .collect()
    }

    fn decode(out: &Outgoing) -> Message {
        wire::parse(&out.packet).unwrap()
    }

    /// The A records in a message's answers and authorities, with their TTLs.
    fn a_records(msg: &Message) -> Vec<(Ipv4Addr, u32)> {
        msg.answers
            .iter()
            .chain(&msg.authorities)
            .filter_map(|rec| match rec.rdata {
                RData::A(addr) => Some((addr, rec.ttl)),
                _ => None,
            })
            .collect()
    }

    /// A responder that has announced `addrs` on interface 2's links and
    /// 192.0.2.99 on interface 3's, and is quiet by 3000 ms.
    fn serving(addrs: &[&str]) -> Responder {
        let mut r = responder();
        let changes = apply(
            scan(&[V4, V6, OTHER], &[], &[(2, addrs), (3, &["192.0.2.99"])]),
            &mut r,
            0,
        );
        assert!(changes.iter().all(|c| c.step.sends.is_empty()));
        run(&mut r, 0, 2999);
        assert!(run(&mut r, 3000, 6000).is_empty());
        r
    }

    #[test]
    fn a_new_interface_probes_at_once_with_its_addresses() {
        let mut r = responder();
        let changes = apply(scan(&[V4], &[], &[(2, &["192.0.2.10"])]), &mut r, 0);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].step.sends.is_empty() && changes[0].step.notices.is_empty());
        // The first probe goes out within the 0-250 ms jitter, carrying the
        // address: the link never waited for it.
        let sent = run(&mut r, 0, 250);
        assert!(!sent.is_empty());
        let probe = decode(&sent[0].1);
        assert!(!probe.is_response);
        assert_eq!(sent[0].1.link, V4);
        assert_eq!(
            a_records(&probe).iter().map(|r| r.0).collect::<Vec<_>>(),
            [Ipv4Addr::new(192, 0, 2, 10)]
        );
    }

    #[test]
    fn a_departed_interface_says_nothing_on_its_dead_links() {
        let mut r = serving(&["192.0.2.10"]);
        let changes = apply(scan(&[], &[V4, V6], &[(2, &[])]), &mut r, 7000);
        assert_eq!(changes.len(), 1);
        assert!(
            changes[0].step.sends.is_empty(),
            "{:?}",
            changes[0].step.sends
        );
        assert!(run(&mut r, 7000, 10_000).is_empty());
        // Only the interface still there says goodbye on shutdown.
        let byes = r.goodbye();
        assert!(!byes.is_empty() && byes.iter().all(|o| o.link == OTHER));

        // Had the empty address set gone first, it would have sent goodbyes
        // on links whose sockets have already left the group.
        let mut r = serving(&["192.0.2.10"]);
        let step = r.set_addresses(IfIndex::of(2), Vec::new(), 7000);
        assert!(!step.sends.is_empty());
    }

    #[test]
    fn an_address_change_keeps_the_links_and_announces_on_them() {
        let mut r = serving(&["192.0.2.10"]);
        let changes = apply(scan(&[], &[], &[(2, &["192.0.2.11"])]), &mut r, 7000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].index, IfIndex::of(2));
        assert_eq!(changes[0].addrs, [ip("192.0.2.11")]);
        let sends = &changes[0].step.sends;
        // Per link of interface 2, a goodbye for the old address and an
        // announcement of the new one; nothing on interface 3.
        for link in [V4, V6] {
            let on: Vec<Message> = sends
                .iter()
                .filter(|o| o.link == link)
                .map(decode)
                .collect();
            assert_eq!(on.len(), 2, "{link:?}: {on:?}");
            assert_eq!(a_records(&on[0]), [(Ipv4Addr::new(192, 0, 2, 10), 0)]);
            let new = a_records(&on[1]);
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].0, Ipv4Addr::new(192, 0, 2, 11));
            assert!(new[0].1 > 0);
        }
        assert_eq!(sends.len(), 4);
        // The links were kept: the second announcement follows a second
        // later, with no probing first.
        let sent = run(&mut r, 7001, 10_000);
        assert_eq!(sent.len(), 2);
        for (at, out) in &sent {
            assert_eq!(*at, 8000);
            assert!(decode(out).is_response);
        }
    }

    // `Net::rescan` never lists one link as both removed and added today;
    // the two flap tests pin `apply`'s contract should it ever do so.

    #[test]
    fn a_link_that_flaps_within_one_rescan_probes_again() {
        let mut r = serving(&["192.0.2.10"]);
        let changes = apply(scan(&[V4], &[V4], &[]), &mut r, 7000);
        assert!(changes.is_empty());
        let sent = run(&mut r, 7000, 7250);
        assert!(!sent.is_empty());
        assert_eq!(sent[0].1.link, V4);
        assert!(!decode(&sent[0].1).is_response);
    }

    #[test]
    fn a_link_that_flaps_with_an_address_change_probes_with_the_new_address() {
        let mut r = serving(&["192.0.2.10"]);
        let changes = apply(scan(&[V4], &[V4], &[(2, &["192.0.2.11"])]), &mut r, 7000);
        // Only interface 2's other link, which stayed, says goodbye and
        // announces; the flapped link was gone while the change applied.
        assert_eq!(changes.len(), 1);
        assert!(changes[0].step.sends.iter().all(|o| o.link == V6));
        assert_eq!(changes[0].step.sends.len(), 2);
        let sent: Vec<_> = run(&mut r, 7000, 7250)
            .into_iter()
            .filter(|(_, o)| o.link == V4)
            .collect();
        assert!(!sent.is_empty());
        let probe = decode(&sent[0].1);
        assert!(!probe.is_response);
        assert_eq!(a_records(&probe)[0].0, Ipv4Addr::new(192, 0, 2, 11));
    }
}
