//! Publish extra mDNS host names as CNAMEs of this host's own name. The
//! binary in `main.rs` wires these modules to the network; the library exists
//! so tests and the fuzz target can reach them.
//!
//! No `unsafe` anywhere but `sys`, which wraps every raw system call.

#![deny(unsafe_code)]

pub mod cli;
pub mod net;
pub mod netlink;
pub mod responder;
pub mod sandbox;
pub mod signals;
#[cfg(target_os = "linux")]
pub mod sys;
pub mod wire;
