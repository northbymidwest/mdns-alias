//! The program: parse the command line, open the sockets, lock the
//! sandbox, then serve until SIGINT or SIGTERM.

use std::error::Error;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::cli;
use crate::net::IfIndex;
use crate::net::{Backoff, FailureLog, Net, Readiness, Receive, Rescan, Settle};
use crate::responder::{Dest, Family, MDNS_PORT, Notice, Outgoing, Responder, Source, Step};
use crate::sandbox;
use crate::signals::Signals;

/// Milliseconds between safety rescans when change notifications arrive.
const SAFETY_RESCAN: u64 = 300_000;
/// Milliseconds between rescans without notifications (macOS, or a host
/// that refused the subscription).
const POLL_RESCAN: u64 = 30_000;
/// Milliseconds before rescanning again after a listing that was
/// interrupted, timed out or was refused as busy (`netlink::retry_soon`);
/// doubled for each further consecutive retry, up to the usual interval.
const RETRY_RESCAN: u64 = 2_000;
/// Largest mDNS message (RFC 6762 section 17).
const MAX_MESSAGE: usize = 9000;
/// Most packets read from one socket per pass of the loop, so a busy socket
/// cannot keep the other one, the timers or a shutdown waiting.
const READ_BURST: usize = 32;
/// The families, in the order `Net::wait` reports on them.
const FAMILIES: [Family; 2] = [Family::V4, Family::V6];
/// `ENOBUFS`: no room in the device queue or the socket's buffers for this
/// packet, which is lost, but the link is fine.
#[cfg(target_os = "linux")]
const ENOBUFS: i32 = libc::ENOBUFS;
/// `ENOBUFS` on macOS and the BSDs, the development platforms.
#[cfg(not(target_os = "linux"))]
const ENOBUFS: i32 = 55;

/// Runs the responder until SIGINT or SIGTERM. An error is fatal: bad
/// arguments, no usable socket, an unmet `--require-sandbox`, or a failed
/// wait. A name conflict is not: the responder probes the name again, and
/// stops serving it where another host holds it until a later retry.
pub fn run() -> Result<(), Box<dyn Error>> {
    let cli = cli::parse(std::env::args().skip(1))?;
    #[cfg(target_os = "linux")]
    if crate::sys::is_root() {
        return Err("refusing to run as root; run as an unprivileged user".into());
    }
    // Before lockdown, which forbids uname. Elsewhere than Linux there is
    // no wrapper for it, and the check is skipped.
    #[cfg(target_os = "linux")]
    let host_name = crate::sys::host_name()
        .inspect_err(|e| {
            eprintln!(
                "mdns-alias: cannot read the host name ({e}); not checking aliases against it"
            );
        })
        .ok();
    #[cfg(not(target_os = "linux"))]
    let host_name: Option<String> = None;
    cli::check_own_name(&cli.aliases, host_name.as_deref())?;
    // Only for probe jitter, so a hash of the pid with a random key is plenty.
    let seed = RandomState::new().hash_one(std::process::id());
    let mut responder = Responder::new(cli.aliases.clone(), seed);
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
    for alias in &cli.aliases {
        eprintln!("mdns-alias: publishing {alias}");
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
    let mut health: [Health; 2] = Default::default();
    // Nothing to read before the first wait.
    let mut ready = [Readiness::Unwatched; 2];
    let mut retries = 0u32;
    let mut relink = Relink::default();
    while !signals.pending() {
        let drained = net.drain_events(now());
        if drained.overflow {
            settle.overflowed();
        } else if drained.changed {
            settle.changed(now());
        }
        if settle.due(now()) || now() >= next_rescan {
            settle.clear();
            let retry = rescan(&mut net, &mut responder, now());
            retries = if retry { retries.saturating_add(1) } else { 0 };
            next_rescan = now() + rescan_delay(retry, retries, interval);
        }
        for ((family, health), readiness) in FAMILIES.into_iter().zip(&mut health).zip(ready) {
            match readiness {
                Readiness::Unwatched => {}
                // Waited on without an error: whatever failed is over.
                Readiness::Idle => health.recovered(family),
                Readiness::Readable | Readiness::Faulty => {
                    let faulty = readiness == Readiness::Faulty;
                    receive(
                        &mut net,
                        &mut responder,
                        family,
                        health,
                        faulty,
                        &mut buf,
                        &now,
                    );
                }
            }
        }
        let step = responder.poll(now());
        dispatch(&mut net, &mut responder, step, now());
        // A link dropped for a failed send, by any dispatch above, comes
        // back with the next rescan: soon, should the failure be brief.
        if net.take_dropped() {
            let at = now();
            next_rescan = next_rescan.min(at + relink.dropped(at, interval));
        }

        // Sleep until a descriptor wakes us or the next timer is due.
        let at = now();
        let watch = health.each_ref().map(|h| h.rest.until(at).is_none());
        let others = [
            responder.next_due(),
            settle.due_at(),
            net.events_rest_until(at),
        ]
        .into_iter()
        .chain(health.iter().map(|h| h.rest.until(at)));
        let timeout = Duration::from_millis(timeout(at, next_rescan, others));
        ready = net
            .wait(signals.fd(), watch, at, timeout)
            .map_err(|e| format!("cannot wait for packets: {e}"))?;
    }

    // Goodbyes make clients forget the names now rather than when their
    // cached records expire.
    for out in responder.goodbye() {
        let _ = net.send(&out);
    }
    eprintln!("mdns-alias: stopped");
    Ok(())
}

/// How long the loop may wait at `now`, in ms: until the next rescan at
/// `rescan`, or the earliest of `others` if sooner (the responder's next
/// send, the end of a burst of notifications, the end of a socket's rest,
/// mDNS or notification);
/// 0 if one of them is already due. Times are ms since the start.
fn timeout(now: u64, rescan: u64, others: impl IntoIterator<Item = Option<u64>>) -> u64 {
    others
        .into_iter()
        .flatten()
        .fold(rescan, u64::min)
        .saturating_sub(now)
}

/// When to rescan after a link was dropped for a failed send, so that it is
/// joined again: `RETRY_RESCAN` after the drop, doubled for each further
/// drop, up to the usual interval, so a link that keeps failing is not
/// rejoined and dropped every few seconds. The doubling starts over only
/// once a rejoined link has gone a whole interval without a drop.
#[derive(Debug, Default)]
struct Relink {
    /// While links keep failing: when the last drop was, how many have
    /// followed each other so far, and the delay that drop was given.
    run: Option<(u64, u32, u64)>,
}

impl Relink {
    /// A link was dropped at `now`: how long until the rescan that rejoins
    /// it, never more than `interval`.
    fn dropped(&mut self, now: u64, interval: u64) -> u64 {
        let count = match self.run {
            // Rejoined `delay` after the last drop at the earliest; lasting
            // an interval from then would have ended the run.
            Some((last, count, delay))
                if now.saturating_sub(last) < delay.saturating_add(interval) =>
            {
                count.saturating_add(1)
            }
            _ => 1,
        };
        let delay = rescan_delay(true, count, interval);
        self.run = Some((now, count, delay));
        delay
    }
}

/// One family's socket health: its failure log, and its rest after a
/// failure.
#[derive(Debug, Default)]
struct Health {
    failures: FailureLog,
    rest: Backoff,
}

impl Health {
    /// A receive or a wait went well: logs the end of a run of failures.
    fn recovered(&mut self, family: Family) {
        if let Some(skipped) = self.failures.recovered() {
            eprintln!(
                "mdns-alias: receiving on {family} works again{}",
                not_logged(skipped, "failure")
            );
        }
    }

    /// A receive failed at `now`: logs it, rate-limited, and rests the
    /// socket, so one that keeps failing cannot spin the loop.
    fn failed(&mut self, family: Family, e: &io::Error, now: u64) {
        if let Some(skipped) = self.failures.failed(now) {
            eprintln!(
                "mdns-alias: receive on {family} failed: {e}{}; \
                 retrying, and logging again at most once a minute",
                not_logged(skipped, "")
            );
        }
        self.rest.start(now);
    }
}

/// Reads one family's socket until it is empty, or for `READ_BURST`
/// packets, handing each to the responder. `faulty`: the wait reported an
/// error condition, so finding nothing at all is a failure too; otherwise a
/// condition the read does not clear would end every wait at once.
fn receive(
    net: &mut Net,
    responder: &mut Responder,
    family: Family,
    health: &mut Health,
    faulty: bool,
    buf: &mut [u8],
    now: &impl Fn() -> u64,
) {
    for read in 0..READ_BURST {
        let received = match net.recv(family, buf) {
            Ok(Receive::Empty) if faulty && read == 0 => {
                Err(io::Error::other("the socket reports an error"))
            }
            received => received,
        };
        log_net(net);
        match received {
            Ok(got) => {
                health.recovered(family);
                match got {
                    Receive::Packet(got) => {
                        let source = Source {
                            addr: got.source,
                            unicast: got.unicast,
                            direct: got.direct,
                        };
                        let step = responder.handle(&buf[..got.len], got.link, source, now());
                        dispatch(net, responder, step, now());
                    }
                    Receive::Ignored => {}
                    Receive::Empty => break,
                }
            }
            Err(e) => {
                health.failed(family, &e, now());
                break;
            }
        }
    }
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

/// How long until the next rescan: after a listing worth retrying soon
/// (`retries` is the number of those in a row, this one included),
/// `RETRY_RESCAN` doubled for each one before it, else `interval`; never
/// more than `interval`.
fn rescan_delay(retry_soon: bool, retries: u32, interval: u64) -> u64 {
    if retry_soon {
        let doublings = retries.saturating_sub(1).min(32);
        (RETRY_RESCAN << doublings).min(interval)
    } else {
        interval
    }
}

/// Rescans and applies the result; whether the listing was interrupted,
/// timed out or refused as busy and should be repeated soon.
fn rescan(net: &mut Net, responder: &mut Responder, now: u64) -> bool {
    let scan = net.rescan(now);
    let retry_soon = scan.retry_soon;
    log_net(net);
    for change in apply(scan, responder, now) {
        if let Some(name) = net.interface_name(change.index) {
            let list = if change.addrs.is_empty() {
                "none stable".to_string()
            } else {
                join(&change.addrs)
            };
            eprintln!("mdns-alias: addresses on {name}: {list}");
        }
        dispatch(net, responder, change.step, now);
    }
    if net.is_empty() {
        eprintln!("mdns-alias: no usable interfaces yet");
    }
    retry_soon
}

/// `ms` milliseconds as whole minutes, at least one, for a log line.
fn minutes(ms: u64) -> String {
    format!("{} min", (ms / 60_000).max(1))
}

/// `items` in order, separated by commas, for a log line.
fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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

fn dispatch(net: &mut Net, responder: &mut Responder, step: Step, now: u64) {
    for notice in step.notices {
        match notice {
            Notice::Announced(link, aliases) => eprintln!(
                "mdns-alias: announced {} on {}",
                join(&aliases),
                net.describe(link)
            ),
            Notice::TiebreakLost(link, alias) => eprintln!(
                "mdns-alias: another host is probing for {alias} on {}, probing again",
                net.describe(link)
            ),
            Notice::HeldBack(link, alias) => eprintln!(
                "mdns-alias: {alias} on {}: probing held back by other hosts' probes",
                net.describe(link)
            ),
            Notice::Conflict(conflict) => {
                eprintln!("mdns-alias: {conflict}; probing again");
            }
            Notice::Lost {
                link,
                conflict,
                retry,
            } => eprintln!(
                "mdns-alias: {conflict} on {}; giving up on it there for now, retrying in {}",
                net.describe(link),
                minutes(retry)
            ),
            Notice::Retry(link, alias) => eprintln!(
                "mdns-alias: probing for {alias} on {} again",
                net.describe(link)
            ),
            Notice::Oversized(link, alias) => eprintln!(
                "mdns-alias: {alias}'s records do not fit one packet on {}; not serving it there",
                net.describe(link)
            ),
        }
    }
    for out in step.sends {
        send(net, responder, out, now);
    }
}

/// Sends one packet, and deals with its failure: see `SendFailure`.
fn send(net: &mut Net, responder: &mut Responder, out: Outgoing, now: u64) {
    send_with(net, responder, out, now, &mut |net, out| net.send(out));
}

/// `send`, sending with `transmit`, which tests replace.
fn send_with(
    net: &mut Net,
    responder: &mut Responder,
    out: Outgoing,
    now: u64,
    transmit: &mut impl FnMut(&Net, &Outgoing) -> io::Result<()>,
) {
    // An earlier send in this step may have failed and dropped the link.
    if !net.serves(out.link) {
        return;
    }
    let Err(e) = transmit(net, &out) else {
        return;
    };
    match failure(&out, &e) {
        SendFailure::Dropped => {
            if let Some(skipped) = net.send_dropped(out.link.family, now) {
                let reason = if e.kind() == io::ErrorKind::WouldBlock {
                    "send buffer full".to_string()
                } else {
                    e.to_string()
                };
                eprintln!(
                    "mdns-alias: dropped a packet on {} ({reason}){}; \
                     logging again at most once a minute",
                    net.describe(out.link),
                    not_logged(skipped, "")
                );
            }
        }
        SendFailure::LinkBroken => {
            eprintln!(
                "mdns-alias: sending on {} failed, dropping it until a rescan rejoins it: {e}",
                net.describe(out.link)
            );
            net.drop_link(out.link);
            responder.remove_link(out.link);
        }
        SendFailure::Unreachable(addr) => {
            log_reply_failure(net, &out, addr, &e, "; answering by multicast instead", now);
            for out in responder.unicast_failed(&out, now) {
                send_with(net, responder, out, now, transmit);
            }
        }
        SendFailure::ReplyFailed(addr) => log_reply_failure(net, &out, addr, &e, "", now),
    }
}

/// Logs a failed unicast reply to `addr`, rate-limited per family: anyone
/// on the link can make replies fail, so each must not cost a line.
fn log_reply_failure(
    net: &mut Net,
    out: &Outgoing,
    addr: SocketAddr,
    e: &io::Error,
    then: &str,
    now: u64,
) {
    if let Some(skipped) = net.reply_failed(out.link.family, now) {
        eprintln!(
            "mdns-alias: reply to {addr} on {} failed: {e}{then}{}; \
             logging again at most once a minute",
            net.describe(out.link),
            not_logged(skipped, "")
        );
    }
}

/// What a failed send means.
#[derive(Debug, PartialEq, Eq)]
enum SendFailure {
    /// No room for the packet just now (the socket does not wait for it):
    /// it is lost, but the link is fine.
    Dropped,
    /// The link cannot send multicast: stop serving it until a rescan
    /// joins it again.
    LinkBroken,
    /// A unicast reply to a querier on port 5353 found no route (or no
    /// source address) for it: the responder answers by multicast instead
    /// (`Responder::unicast_failed`), which the querier hears as well as
    /// any (RFC 6762 section 11), under the multicast rate limit. A legacy
    /// querier cannot hear multicast, so never gets here.
    Unreachable(SocketAddr),
    /// Any other failed unicast reply. Its reasons may be the querier's
    /// own, which must not cost everyone else on the link their answers.
    ReplyFailed(SocketAddr),
}

/// What sending `out` failing with `e` means.
fn failure(out: &Outgoing, e: &io::Error) -> SendFailure {
    let no_room = matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
    ) || e.raw_os_error() == Some(ENOBUFS);
    let unreachable = matches!(
        e.kind(),
        io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable
    );
    match out.dest {
        _ if no_room => SendFailure::Dropped,
        Dest::Multicast => SendFailure::LinkBroken,
        // A legacy querier, on another port, cannot hear multicast.
        Dest::Unicast(addr) if unreachable && addr.port() == MDNS_PORT => {
            SendFailure::Unreachable(addr)
        }
        Dest::Unicast(addr) => SendFailure::ReplyFailed(addr),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ENOBUFS, RETRY_RESCAN, Relink, SendFailure, apply, failure, not_logged, rescan_delay,
        send_with, timeout,
    };
    use crate::net::IfIndex;
    use crate::net::Net;
    use crate::net::Rescan;
    use crate::responder::{Dest, Family, Link, Outgoing, Responder};
    use crate::wire::{self, Message, Name, RData};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn skipped_counts_read_naturally() {
        assert_eq!(not_logged(0, "failure"), "");
        assert_eq!(not_logged(1, "failure"), " (1 more failure not logged)");
        assert_eq!(not_logged(3, "failure"), " (3 more failures not logged)");
        assert_eq!(not_logged(0, ""), "");
        assert_eq!(not_logged(2, ""), " (2 more not logged)");
    }

    #[test]
    fn a_failed_listing_is_retried_soon_backing_off_but_not_later_than_usual() {
        assert_eq!(rescan_delay(false, 0, 300_000), 300_000);
        assert_eq!(rescan_delay(true, 1, 300_000), RETRY_RESCAN);
        assert_eq!(rescan_delay(true, 2, 300_000), 2 * RETRY_RESCAN);
        assert_eq!(rescan_delay(true, 4, 300_000), 8 * RETRY_RESCAN);
        assert_eq!(rescan_delay(true, 20, 300_000), 300_000);
        assert_eq!(rescan_delay(true, u32::MAX, 300_000), 300_000);
        assert_eq!(rescan_delay(true, 1, 1_000), 1_000);
    }

    #[test]
    fn a_dropped_link_is_rejoined_soon_backing_off_while_drops_continue() {
        let mut relink = Relink::default();
        let interval = 300_000;
        assert_eq!(relink.dropped(10_000, interval), RETRY_RESCAN);
        // Dropped again after each rejoin: twice as long each time.
        assert_eq!(relink.dropped(12_500, interval), 2 * RETRY_RESCAN);
        assert_eq!(relink.dropped(17_000, interval), 4 * RETRY_RESCAN);
        // Never later than the usual rescan.
        let mut at = 17_000;
        for _ in 0..40 {
            at += 1_000;
            assert!(relink.dropped(at, interval) <= interval);
        }
        // A link that fails on every rejoin stays at the interval, though
        // each drop comes over an interval after the one before.
        for _ in 0..3 {
            at += interval + 50;
            assert_eq!(relink.dropped(at, interval), interval);
        }
        // A rejoined link that lasts a whole interval starts over.
        at += 2 * interval;
        assert_eq!(relink.dropped(at, interval), RETRY_RESCAN);
        // Rejoined 2 s later, dropped just short of an interval after that:
        // still the same run.
        at += RETRY_RESCAN + interval - 1;
        assert_eq!(relink.dropped(at, interval), 2 * RETRY_RESCAN);
        at += 2 * RETRY_RESCAN + interval;
        assert_eq!(relink.dropped(at, interval), RETRY_RESCAN);
    }

    #[test]
    fn a_send_without_room_loses_the_packet_but_keeps_the_link() {
        let multicast = Outgoing {
            link: V4,
            dest: Dest::Multicast,
            packet: Vec::new(),
            probe: false,
        };
        let unicast = Outgoing {
            dest: Dest::Unicast(QUERIER),
            ..multicast.clone()
        };
        for out in [&multicast, &unicast] {
            for e in [
                io::Error::from(io::ErrorKind::WouldBlock),
                io::Error::from(io::ErrorKind::OutOfMemory),
                io::Error::from_raw_os_error(ENOBUFS),
            ] {
                assert_eq!(failure(out, &e), SendFailure::Dropped, "{e}");
            }
        }
        // Anything else breaks a link that cannot multicast, but a failed
        // reply is the querier's affair.
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(failure(&multicast, &e), SendFailure::LinkBroken);
        assert_eq!(failure(&unicast, &e), SendFailure::ReplyFailed(QUERIER));
        let e = io::Error::from(io::ErrorKind::NetworkUnreachable);
        assert_eq!(failure(&multicast, &e), SendFailure::LinkBroken);
    }

    const QUERIER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 5353);

    #[test]
    fn a_reply_with_no_route_goes_by_multicast_unless_legacy() {
        let auto = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)), 5353);
        let reply = Outgoing {
            link: V4,
            dest: Dest::Unicast(auto),
            packet: Vec::new(),
            probe: false,
        };
        for kind in [
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::AddrNotAvailable,
        ] {
            let e = io::Error::from(kind);
            assert_eq!(failure(&reply, &e), SendFailure::Unreachable(auto));
            // A legacy querier cannot hear multicast: nothing to fall back to.
            let legacy = SocketAddr::new(auto.ip(), 54928);
            let out = Outgoing {
                dest: Dest::Unicast(legacy),
                ..reply.clone()
            };
            assert_eq!(failure(&out, &e), SendFailure::ReplyFailed(legacy));
        }
        // Other failures are not about the route.
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(failure(&reply, &e), SendFailure::ReplyFailed(auto));
    }

    /// A served responder and net on V4, and the unicast reply to a QU
    /// question from `querier`, asked at 7000.
    fn failing_reply(querier: SocketAddr) -> (Responder, Net, Outgoing) {
        let mut r = serving(&["192.0.2.10"]);
        let q = Message {
            questions: vec![wire::Question {
                name: Name::parse("app.myhost.local").unwrap(),
                qtype: wire::RType::A,
                qclass: wire::Class::IN,
                unicast_response: true,
            }],
            ..Message::default()
        };
        let mut sent = r.handle(&wire::encode(&q), V4, querier, 7000).sends;
        assert_eq!(sent.len(), 1, "{sent:?}");
        let reply = sent.remove(0);
        assert_eq!(reply.dest, Dest::Unicast(querier));
        (r, Net::without_sockets(&[V4, V6, OTHER]), reply)
    }

    /// Sends `out` at `now` with every unicast failing with `unicast` and
    /// every multicast with `multicast`; the destinations tried, in order.
    fn try_send(
        r: &mut Responder,
        net: &mut Net,
        out: &Outgoing,
        now: u64,
        unicast: io::ErrorKind,
        multicast: io::ErrorKind,
    ) -> Vec<Dest> {
        let mut tried = Vec::new();
        send_with(net, r, out.clone(), now, &mut |_, out: &Outgoing| {
            tried.push(out.dest);
            Err(match out.dest {
                Dest::Unicast(_) => unicast,
                Dest::Multicast => multicast,
            }
            .into())
        });
        tried
    }

    const AUTO: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)), 5353);

    #[test]
    fn a_reply_without_a_route_falls_back_to_a_rate_limited_multicast() {
        use io::ErrorKind::{NetworkUnreachable, WouldBlock};
        let (mut r, mut net, reply) = failing_reply(AUTO);
        let tried = try_send(
            &mut r,
            &mut net,
            &reply,
            7000,
            NetworkUnreachable,
            WouldBlock,
        );
        assert_eq!(tried, [Dest::Unicast(AUTO), Dest::Multicast]);
        // The multicast found no room: the packet is lost, the link kept.
        assert!(net.serves(V4) && !net.take_dropped());
        // Both failures were logged, so the next ones within a minute are
        // not.
        assert_eq!(net.reply_failed(Family::V4, 7001), None);
        assert_eq!(net.send_dropped(Family::V4, 7001), None);
        // Failing again 1 ms later: no second multicast within the second.
        let tried = try_send(
            &mut r,
            &mut net,
            &reply,
            7001,
            NetworkUnreachable,
            WouldBlock,
        );
        assert_eq!(tried, [Dest::Unicast(AUTO)]);
        // A legacy querier cannot hear multicast: nothing to fall back to.
        let legacy = SocketAddr::new(AUTO.ip(), 54928);
        let (mut r, mut net, reply) = failing_reply(legacy);
        let tried = try_send(
            &mut r,
            &mut net,
            &reply,
            7000,
            NetworkUnreachable,
            WouldBlock,
        );
        assert_eq!(tried, [Dest::Unicast(legacy)]);
        assert!(net.serves(V4));
    }

    #[test]
    fn a_fallback_multicast_that_fails_drops_the_link() {
        use io::ErrorKind::{NetworkUnreachable, PermissionDenied};
        let (mut r, mut net, reply) = failing_reply(AUTO);
        let tried = try_send(
            &mut r,
            &mut net,
            &reply,
            7000,
            NetworkUnreachable,
            PermissionDenied,
        );
        assert_eq!(tried, [Dest::Unicast(AUTO), Dest::Multicast]);
        assert!(!net.serves(V4) && net.take_dropped());
        // The responder forgot the link too.
        assert!(r.unicast_failed(&reply, 9000).is_empty());
        // Other links carry on.
        assert!(net.serves(V6) && net.serves(OTHER));
    }

    #[test]
    fn the_wait_ends_at_the_earliest_timer() {
        // Idle: until the next rescan.
        assert_eq!(timeout(1_000, 300_000, []), 299_000);
        assert_eq!(timeout(1_000, 300_000, [None, None, None, None]), 299_000);
        // Any sooner timer wins: a send, a settled burst, a rest's end.
        assert_eq!(timeout(1_000, 300_000, [Some(1_250), None]), 250);
        assert_eq!(timeout(1_000, 300_000, [Some(5_000), Some(1_100)]), 100);
        // A later one does not.
        assert_eq!(timeout(1_000, 2_000, [Some(9_000)]), 1_000);
        // Due or overdue: no wait at all.
        assert_eq!(timeout(1_000, 300_000, [Some(1_000)]), 0);
        assert_eq!(timeout(1_000, 300_000, [Some(0)]), 0);
        assert_eq!(timeout(1_000, 500, []), 0);
    }

    /// The wait relies on this: were anything left due after a poll, the
    /// loop would never sleep.
    #[test]
    fn nothing_is_left_due_after_a_poll() {
        let mut r = responder();
        apply(scan(&[V4, V6], &[], &[(2, &["192.0.2.10"])]), &mut r, 0);
        let mut woke = 0;
        let mut at = 0;
        while let Some(due) = r.next_due() {
            assert!(due >= at, "{due} is before {at}");
            at = due;
            r.poll(at);
            assert!(r.next_due().is_none_or(|next| next > at), "{at}");
            woke += 1;
        }
        // Waking only when due: the probes and announcements on two links,
        // with no idle wakeups between them.
        assert!((2..=20).contains(&woke), "{woke}");
        assert!(run(&mut r, at, at + 10_000).is_empty());
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
        Responder::new(vec![alias], 7)
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
            retry_soon: false,
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
