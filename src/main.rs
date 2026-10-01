//! Publish extra mDNS host names for this machine, as CNAMEs of its own
//! `.local` name.
//!
//! Usage: `mdns-alias [--target <name.local>] [--interface <name>]... [--require-sandbox] <alias.local>...`

#![forbid(unsafe_code)]

use std::error::Error;
use std::hash::{BuildHasher, RandomState};
use std::process::ExitCode;
use std::time::Instant;

use mdns_alias::cli;
use mdns_alias::net::Net;
use mdns_alias::responder::{Family, Notice, Responder, Step};
use mdns_alias::sandbox;
use mdns_alias::signals::Signals;

/// The kernel host name on Linux, where this is deployed. Elsewhere the
/// read fails and `--target` is required.
const HOSTNAME_FILE: &str = "/proc/sys/kernel/hostname";
/// Milliseconds between interface rescans.
const RESCAN_INTERVAL: u64 = 30_000;
/// Largest mDNS message (RFC 6762 section 17).
const MAX_MESSAGE: usize = 9000;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mdns-alias: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = cli::parse(std::env::args().skip(1))?;
    #[cfg(target_os = "linux")]
    if mdns_alias::sys::is_root() {
        return Err("refusing to run as root; run as an unprivileged user".into());
    }
    let hostname = std::fs::read_to_string(HOSTNAME_FILE).ok();
    let target = cli::target(&cli, hostname.as_deref())?;
    // Only for probe jitter, so a hash of the pid with a random key is plenty.
    let seed = RandomState::new().hash_one(std::process::id());
    let mut responder = Responder::new(cli.aliases.clone(), target.clone(), seed)?;
    let signals = Signals::new()?;
    let (mut net, log) = Net::open(cli.interfaces)?;
    for line in log {
        eprintln!("mdns-alias: {line}");
    }
    // Everything that needs files, new sockets or privileges is done; shed
    // the ability to do any of it again.
    let report = sandbox::lock(net.highest_fd().max(signals.raw_fd()).max(2));
    for line in report.lines() {
        eprintln!("mdns-alias: {line}");
    }
    if cli.require_sandbox && !report.complete() {
        return Err("--require-sandbox: not every sandbox layer could be applied".into());
    }
    for alias in &cli.aliases {
        eprintln!("mdns-alias: publishing {alias} -> {target}");
    }

    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let mut next_rescan = 0;
    let mut buf = vec![0; MAX_MESSAGE];
    while !signals.pending() {
        if now() >= next_rescan {
            rescan(&mut net, &mut responder, now());
            next_rescan = now() + RESCAN_INTERVAL;
        }
        for family in [Family::V4, Family::V6] {
            match net.recv(family, &mut buf) {
                Ok(Some(got)) => {
                    // A conflict ends the program: the name is someone else's.
                    let step = responder.handle(&buf[..got.len], got.link, got.source, now())?;
                    dispatch(&mut net, &mut responder, step);
                }
                Ok(None) => {}
                Err(e) => eprintln!("mdns-alias: receive failed: {e}"),
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

fn rescan(net: &mut Net, responder: &mut Responder, now: u64) {
    let scan = net.rescan();
    for line in &scan.log {
        eprintln!("mdns-alias: {line}");
    }
    for &link in &scan.removed {
        responder.remove_link(link);
    }
    for &link in &scan.added {
        responder.add_link(link, now);
    }
    if net.is_empty() {
        eprintln!("mdns-alias: no usable interfaces yet, looking again in 30s");
    }
}

fn dispatch(net: &mut Net, responder: &mut Responder, step: Step) {
    for notice in step.notices {
        match notice {
            Notice::Announced(link) => eprintln!("mdns-alias: announced on {}", net.describe(link)),
            Notice::TiebreakLost(link) => eprintln!(
                "mdns-alias: another host is probing for the same name on {}, probing again",
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
