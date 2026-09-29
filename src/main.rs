//! Publish extra mDNS host names (aliases) that resolve to one address.
//!
//! Usage: `mdns-alias <address> <name.local>...`

use std::error::Error;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::mpsc;

use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};

const USAGE: &str = "usage: mdns-alias <address> <name.local>...";

// mdns-sd has no bare address records, but it answers A/AAAA queries for the
// host name of every service it registers. So each alias is a placeholder
// service whose host name is the alias.
const SERVICE_TYPE: &str = "_mdns-alias._tcp.local.";

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
    let mut args = std::env::args().skip(1);
    let addr: IpAddr = args.next().ok_or(USAGE)?.parse()?;
    let names: Vec<String> = args
        .map(|name| format!("{}.", name.trim_end_matches('.')))
        .collect();
    if names.is_empty() {
        return Err(USAGE.into());
    }

    // Only the interface that holds `addr`; not loopback or Docker bridges.
    let daemon = ServiceDaemon::new()?;
    daemon.disable_interface(IfKind::All)?;
    daemon.enable_interface(IfKind::Addr(addr))?;

    let mut services = Vec::new();
    for name in &names {
        let service = ServiceInfo::new(SERVICE_TYPE, name, name, addr, 0, None)?;
        services.push(service.get_fullname().to_owned());
        daemon.register(service)?;
        eprintln!("mdns-alias: publishing {name} -> {addr}");
    }

    let (stop, stopped) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = stop.send(());
    })?;
    stopped.recv()?;

    // Unregistering sends goodbye packets, so clients forget the names now
    // instead of when their cached records expire. Shutdown alone doesn't.
    for service in &services {
        daemon.unregister(service)?.recv()?;
    }
    daemon.shutdown()?.recv()?;
    Ok(())
}
