//! The parser reads untrusted packets from the LAN. It must never panic, and
//! anything it accepts must encode and parse back to the same message.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mdns_alias::wire;

fuzz_target!(|data: &[u8]| {
    if let Some(msg) = wire::parse(data) {
        assert_eq!(wire::parse(&wire::encode(&msg)), Some(msg));
    }
});
