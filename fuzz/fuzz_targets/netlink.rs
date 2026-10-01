//! Netlink replies come from the kernel, but the parser must still never
//! panic or loop on anything at all.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mdns_alias::netlink;

fuzz_target!(|data: &[u8]| {
    let _ = netlink::messages(data, &mut |_, payload| {
        let _ = netlink::parse_link(payload);
        let _ = netlink::parse_addr(payload);
    });
    let _ = netlink::parse_link(data);
    let _ = netlink::parse_addr(data);
});
