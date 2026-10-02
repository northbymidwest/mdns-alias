//! Publish extra mDNS host names for this machine, answered with its
//! addresses.
//!
//! Usage: `mdns-alias [--interface <name>]... [--require-sandbox] <name.local>...`

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match mdns_alias::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mdns-alias: {e}");
            ExitCode::FAILURE
        }
    }
}
