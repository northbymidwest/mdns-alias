//! Netlink replies come from the kernel, but the parser must still never
//! panic or loop on anything at all.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mdns_alias::testing::netlink;

fuzz_target!(|data: &[u8]| {
    let _ = netlink::messages(data, &mut |_, payload| {
        let _ = netlink::parse_link(payload);
        let _ = netlink::parse_addr(payload);
    });
    // The dump's reply matching, for a request taken from the input's
    // first eight bytes, so some messages match and others are skipped.
    if let (Some(seq), Some(port)) = (data.get(0..4), data.get(4..8)) {
        let reply = netlink::Reply {
            seq: u32::from_ne_bytes(seq.try_into().unwrap()),
            port: u32::from_ne_bytes(port.try_into().unwrap()),
        };
        let _ = netlink::replies(data, reply, &mut |_, payload| {
            let _ = netlink::parse_link(payload);
        });
    }
    let _ = netlink::parse_link(data);
    let _ = netlink::parse_addr(data);
});
