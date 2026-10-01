//! Publish extra mDNS host names for this machine, as address records by
//! default, or as CNAMEs of its own `.local` name with `--cname`.
//!
//! Usage: `mdns-alias [--host <name.local>] [--cname] [--interface <name>]... [--require-sandbox] <name>...`

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
