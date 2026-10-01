//! Publish extra mDNS host names for this host, as address records by
//! default or as CNAMEs of its own name with `--cname`. The
//! binary in `main.rs` wires these modules to the network; the library exists
//! so tests and the fuzz target can reach them.
//!
//! No `unsafe` anywhere but `sys`, which wraps every raw system call.

#![deny(unsafe_code)]

pub mod cli;
pub mod net;
pub mod netlink;
pub mod order;
pub mod responder;
pub mod sandbox;
pub mod signals;
#[cfg(target_os = "linux")]
pub mod sys;
pub mod wire;
