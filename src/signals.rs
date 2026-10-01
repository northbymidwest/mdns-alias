//! SIGINT and SIGTERM, as something the main loop polls.
//!
//! On Linux the signals stay blocked and queue on a signalfd: no handler, no
//! second thread. That also stops PID 1 in a container cleanly, since the
//! kernel discards default-action signals sent to PID 1 but still queues
//! blocked ones.

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

    pub struct Signals(OwnedFd);

    impl Signals {
        pub fn new() -> io::Result<Signals> {
            crate::sys::signalfd().map(Signals)
        }

        /// Whether SIGINT or SIGTERM has arrived since the last call.
        pub fn pending(&self) -> bool {
            crate::sys::signal_pending(self.0.as_fd())
        }

        /// The signalfd, for the sandbox's descriptor cap.
        pub fn fd(&self) -> Option<RawFd> {
            Some(self.0.as_raw_fd())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;
    use std::os::fd::RawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub struct Signals(Arc<AtomicBool>);

    impl Signals {
        pub fn new() -> io::Result<Signals> {
            let flag = Arc::new(AtomicBool::new(false));
            let set = Arc::clone(&flag);
            ctrlc::set_handler(move || set.store(true, Ordering::Relaxed))
                .map_err(io::Error::other)?;
            Ok(Signals(flag))
        }

        pub fn pending(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }

        /// No descriptor: signals arrive through a handler here.
        pub fn fd(&self) -> Option<RawFd> {
            None
        }
    }
}

pub use imp::Signals;
