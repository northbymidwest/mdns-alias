//! Publish extra mDNS host names for this host, answered with its
//! addresses (A, AAAA, and NSEC for a missing family). The program is
//! [`run`]; the binary in `main.rs` only calls it and reports its error.
//!
//! Every module is private, so items are plain `pub` where another module
//! uses them and private otherwise, and on Linux the dead-code lint covers
//! all of them; elsewhere `netlink` and `sandbox` allow dead code, since
//! only the Linux code uses much of them outside tests.
//! [`testing`] re-exports, by hand, the few items the integration tests and
//! the fuzz targets reach for.
//!
//! No `unsafe` anywhere but `sys`, which wraps every raw system call.

#![deny(unsafe_code)]

mod app;
mod cli;
mod net;
mod netlink;
mod order;
mod responder;
mod sandbox;
mod signals;
#[cfg(target_os = "linux")]
mod sys;
mod wire;

pub use app::run;

/// What tests/linux.rs and the fuzz targets use, under the module names the
/// items live in. Not an API: hidden from the docs, and changed whenever
/// those users change.
#[doc(hidden)]
pub mod testing {
    /// The DNS codec, for the parse fuzz target and test names.
    pub mod wire {
        pub use crate::wire::{
            Class, Message, Name, Question, RData, RType, Record, encode, parse,
        };
    }

    /// The netlink parsers, for the netlink fuzz target, and on Linux the
    /// sockets, for the notification and seccomp tests.
    pub mod netlink {
        #[cfg(target_os = "linux")]
        pub use crate::netlink::{Dumper, drain, subscribe};
        pub use crate::netlink::{
            RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, RTNLGRP_LINK, Reply, messages, parse_addr,
            parse_link, replies,
        };
    }

    /// The interface index, for the responder fuzz target.
    pub mod net {
        pub use crate::net::IfIndex;
    }

    /// The conflict notice, which the seccomp tests format under the filter,
    /// and the responder with what the fuzz target feeds it.
    pub mod responder {
        pub use crate::responder::{
            Conflict, Dest, Family, Link, MAX_PACKET, MDNS_PORT, Outgoing, Responder, Source,
        };
    }

    pub mod signals {
        pub use crate::signals::Signals;
    }

    /// The lockdown and its parts, which the Linux tests apply piecemeal.
    pub mod sandbox {
        pub use crate::sandbox::{Landlock, Layer, landlock_ruleset, lock};
        #[cfg(target_os = "linux")]
        pub use crate::sandbox::{lock_with, program};
    }

    /// The raw calls the Linux tests make to apply one layer at a time, and
    /// the wait they make under the filter.
    #[cfg(target_os = "linux")]
    pub mod sys {
        pub use crate::sys::{
            CAP_SETPCAP, install_seccomp, landlock_abi, landlock_restrict, poll, poll_entry,
            set_no_new_privs, thread_id,
        };
    }
}
