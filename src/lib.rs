//! Publish extra mDNS host names as CNAMEs of this host's own name. The
//! binary in `main.rs` wires these modules to the network; the library exists
//! so tests and the fuzz target can reach them.

#![forbid(unsafe_code)]

pub mod cli;
pub mod net;
pub mod responder;
pub mod wire;
