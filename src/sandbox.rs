//! The lockdown applied after startup. Building the seccomp program and the
//! Landlock ruleset is pure and tested everywhere; applying them goes
//! through `sys` and is Linux only. Elsewhere only tests use the seccomp
//! compiler.

#![cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only the Linux code uses these outside tests; Linux CI lints this module in full"
    )
)]

use std::fmt;
use std::io;
use std::os::fd::RawFd;

/// One classic BPF instruction, `struct sock_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// The value an argument must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    /// Exactly this 64-bit value.
    Is(u64),
    /// The locking thread's id, known only at run time: compiled as a
    /// placeholder in one instruction, `Program::tid_slot`, patched at
    /// lockdown.
    ThreadId,
}

/// One allowlist entry, for syscall number `nr`.
#[derive(Clone, Copy, Debug)]
enum Rule {
    /// The syscall, with any arguments.
    Any(i64),
    /// The syscall, if its arguments match one of the `alternatives`, each a
    /// list of (argument index, value).
    Args {
        nr: i64,
        alternatives: &'static [&'static [(u8, Value)]],
    },
    /// The syscall, if argument `arg` has none of the bits in `mask` set.
    Clear { nr: i64, arg: u8, mask: u64 },
}

impl Rule {
    /// The syscall number the rule is for.
    const fn nr(&self) -> i64 {
        match *self {
            Rule::Any(nr) | Rule::Args { nr, .. } | Rule::Clear { nr, .. } => nr,
        }
    }
}

/// The program buffer, in a module of its own so that only its methods write
/// its fields.
mod buffer {
    use super::{
        Insn, JEQ_K, JSET_K, LD_W_ABS, RET_ALLOW, RET_KILL_PROCESS, Value, arg_offset, ins, jump,
        ret,
    };

    /// A compiled filter in a buffer of `N` instructions, of which the first
    /// `len` are used. Only the methods here write it, which keeps `len <= N`
    /// and `tid_slot` on the JEQ that compares the thread id.
    #[derive(Clone, Copy, Debug)]
    pub(super) struct Program<const N: usize> {
        insns: [Insn; N],
        len: usize,
        /// The instruction comparing against `Value::ThreadId`, if any.
        tid_slot: Option<usize>,
    }

    impl<const N: usize> Program<N> {
        /// An empty program.
        pub(super) const fn new() -> Self {
            Program {
                insns: [ret(RET_KILL_PROCESS); N],
                len: 0,
                tid_slot: None,
            }
        }

        /// The instructions written so far.
        pub(super) const fn insns(&self) -> &[Insn] {
            self.insns.split_at(self.len).0
        }

        /// The instruction comparing against `Value::ThreadId`, if any: a JEQ
        /// whose constant is patched at lockdown.
        pub(super) const fn tid_slot(&self) -> Option<usize> {
            self.tid_slot
        }

        pub(super) const fn push(&mut self, insn: Insn) {
            if self.len == N {
                panic!("seccomp filter longer than its buffer");
            }
            self.insns[self.len] = insn;
            self.len += 1;
        }

        /// Allow if any alternative matches every one of its (argument, value)
        /// pairs, comparing both 32-bit halves; otherwise kill.
        pub(super) const fn args(&mut self, alternatives: &[&[(u8, Value)]]) {
            let mut a = 0;
            while a < alternatives.len() {
                let alternative = alternatives[a];
                // A mismatch skips to just past this alternative's return.
                let end = self.len + 4 * alternative.len() + 1;
                let mut c = 0;
                while c < alternative.len() {
                    let (arg, value) = alternative[c];
                    let (low, high) = match value {
                        Value::Is(v) => (v as u32, (v >> 32) as u32),
                        Value::ThreadId => {
                            if self.tid_slot.is_some() {
                                panic!("more than one thread-id argument");
                            }
                            // The JEQ after this load; patched at lockdown.
                            self.tid_slot = Some(self.len + 1);
                            (0, 0)
                        }
                    };
                    self.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, false)));
                    self.push(ins(JEQ_K, 0, jump(end - self.len - 1), low));
                    self.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, true)));
                    self.push(ins(JEQ_K, 0, jump(end - self.len - 1), high));
                    c += 1;
                }
                self.push(ret(RET_ALLOW));
                a += 1;
            }
            self.push(ret(RET_KILL_PROCESS));
        }

        /// Allow unless argument `arg` has any bit of `mask` set.
        pub(super) const fn clear(&mut self, arg: u8, mask: u64) {
            self.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, false)));
            self.push(ins(JSET_K, 3, 0, mask as u32));
            self.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, true)));
            self.push(ins(JSET_K, 1, 0, (mask >> 32) as u32));
            self.push(ret(RET_ALLOW));
            self.push(ret(RET_KILL_PROCESS));
        }
    }
}
use buffer::Program;

/// How many instructions a rule's body takes; every body ends in a return.
const fn body_len(rule: &Rule) -> usize {
    match *rule {
        Rule::Any(_) => 1,
        Rule::Args { alternatives, .. } => {
            let mut len = 1;
            let mut a = 0;
            while a < alternatives.len() {
                len += 4 * alternatives[a].len() + 1;
                a += 1;
            }
            len
        }
        Rule::Clear { .. } => 6,
    }
}

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
/// `struct seccomp_data`: the syscall number, then the architecture.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
/// On x86_64, syscall numbers with this bit set are the x32 ABI: a classic
/// way around a filter written for x86_64 numbers.
const X32_BIT: u32 = 0x4000_0000;

#[cfg(target_endian = "big")]
compile_error!("seccomp argument offsets below assume a little-endian target");

const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

const fn ret(k: u32) -> Insn {
    ins(RET_K, 0, 0, k)
}

/// Where the low or high 32 bits of argument `arg` sit in seccomp_data.
const fn arg_offset(arg: u8, high: bool) -> u32 {
    16 + 8 * arg as u32 + if high { 4 } else { 0 }
}

/// A BPF jump distance. The allowlist is small and fixed, so every jump
/// fits; a rule body that ever outgrows one fails the build here.
const fn jump(n: usize) -> u8 {
    if n > u8::MAX as usize {
        panic!("seccomp rule body longer than a BPF jump");
    }
    n as u8
}

/// Compiles `rules` into a filter for `arch` (an AUDIT_ARCH value): any other
/// architecture is killed, so is every syscall no rule allows, and with
/// `x32_guard`, every x32-ABI number. The rules come in `lists`, concatenated.
/// A `const fn`, so the real allowlist is
/// compiled at build time, and a rule that cannot compile fails the build.
const fn compile<const N: usize>(arch: u32, x32_guard: bool, lists: &[&[Rule]]) -> Program<N> {
    let mut program = Program::<N>::new();
    program.push(ins(LD_W_ABS, 0, 0, OFFSET_ARCH));
    program.push(ins(JEQ_K, 1, 0, arch));
    program.push(ret(RET_KILL_PROCESS));
    program.push(ins(LD_W_ABS, 0, 0, OFFSET_NR));
    if x32_guard {
        program.push(ins(JGE_K, 0, 1, X32_BIT));
        program.push(ret(RET_KILL_PROCESS));
    }
    let mut l = 0;
    let mut r = 0;
    while l < lists.len() {
        if r == lists[l].len() {
            l += 1;
            r = 0;
            continue;
        }
        let rule = &lists[l][r];
        // Every body ends in a return, so skipping it lands on the next
        // rule's test with the syscall number still loaded.
        program.push(ins(JEQ_K, 0, jump(body_len(rule)), rule.nr() as u32));
        match *rule {
            Rule::Any(_) => program.push(ret(RET_ALLOW)),
            Rule::Args { alternatives, .. } => program.args(alternatives),
            Rule::Clear { arg, mask, .. } => program.clear(arg, mask),
        }
        r += 1;
    }
    program.push(ret(RET_KILL_PROCESS));
    program
}

/// The used part of `program`, as an exact-size array.
#[cfg(target_os = "linux")]
const fn truncate<const N: usize, const M: usize>(program: &Program<N>) -> [Insn; M] {
    let insns = program.insns();
    if insns.len() != M {
        panic!("truncated to the wrong length");
    }
    let mut out = [ret(RET_KILL_PROCESS); M];
    let mut i = 0;
    while i < M {
        out[i] = insns[i];
        i += 1;
    }
    out
}

/// This build's AUDIT_ARCH value, and whether it needs the x32 guard.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ARCH: u32 = 0xC000_003E;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const X32_GUARD: bool = true;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const ARCH: u32 = 0xC000_00B7;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const X32_GUARD: bool = false;

/// Constants are small and positive, so widening keeps their value.
#[cfg(target_os = "linux")]
const fn v(x: libc::c_int) -> Value {
    Value::Is(x as u64)
}

/// Every syscall the steady state makes, and nothing else. Startup is never
/// filtered. Changes come from tracing the real binary; each line says why.
#[cfg(target_os = "linux")]
const ALLOWLIST: &[Rule] = &[
    // Receiving: mDNS (recvmsg), netlink replies (recvfrom), the signalfd
    // (read).
    Rule::Any(libc::SYS_recvmsg),
    Rule::Any(libc::SYS_recvfrom),
    Rule::Any(libc::SYS_read),
    // Sending: replies, announcements, netlink requests.
    Rule::Any(libc::SYS_sendto),
    // Choosing the send interface; joining and leaving groups on rescans.
    Rule::Args {
        nr: libc::SYS_setsockopt,
        alternatives: &[
            &[(1, v(libc::IPPROTO_IP)), (2, v(libc::IP_ADD_MEMBERSHIP))],
            &[(1, v(libc::IPPROTO_IP)), (2, v(libc::IP_DROP_MEMBERSHIP))],
            &[(1, v(libc::IPPROTO_IP)), (2, v(libc::IP_MULTICAST_IF))],
            &[
                (1, v(libc::IPPROTO_IPV6)),
                (2, v(libc::IPV6_ADD_MEMBERSHIP)),
            ],
            &[
                (1, v(libc::IPPROTO_IPV6)),
                (2, v(libc::IPV6_DROP_MEMBERSHIP)),
            ],
            &[(1, v(libc::IPPROTO_IPV6)), (2, v(libc::IPV6_MULTICAST_IF))],
        ],
    },
    // The rescan's netlink socket, and no other.
    Rule::Args {
        nr: libc::SYS_socket,
        alternatives: &[&[(0, v(libc::AF_NETLINK)), (2, v(libc::NETLINK_ROUTE))]],
    },
    Rule::Any(libc::SYS_close),
    // Logging, to stderr only.
    Rule::Args {
        nr: libc::SYS_write,
        alternatives: &[&[(0, Value::Is(2))]],
    },
    // Memory: musl's allocator maps, unmaps, grows (realloc), frees pages
    // (madvise) and moves the break. Never executable, never at a fixed
    // address over another mapping, no other advice. No mprotect at all:
    // after lockdown nothing changes a mapping's permissions.
    Rule::Clear {
        nr: libc::SYS_mmap,
        arg: 2,
        mask: libc::PROT_EXEC as u64,
    },
    Rule::Any(libc::SYS_munmap),
    Rule::Args {
        nr: libc::SYS_mremap,
        alternatives: &[&[(3, Value::Is(0))], &[(3, v(libc::MREMAP_MAYMOVE))]],
    },
    Rule::Args {
        nr: libc::SYS_madvise,
        alternatives: &[&[(2, v(libc::MADV_FREE))], &[(2, v(libc::MADV_DONTNEED))]],
    },
    Rule::Any(libc::SYS_brk),
    // Time: normally the vDSO, but libc falls back to the syscall when the
    // clock source cannot be read from user space, as on some VMs. No
    // futex: the process is single-threaded, so no lock ever waits.
    Rule::Any(libc::SYS_clock_gettime),
    // Waiting for a packet, a notification, a signal or the next timer:
    // sys::poll, always over the same number of entries and with no signal
    // mask (null, size 0). ppoll, since aarch64 has no plain poll. Nothing
    // sleeps: a socket that keeps failing is left out of the wait instead.
    Rule::Args {
        nr: libc::SYS_ppoll,
        alternatives: &[&[
            (1, Value::Is(crate::sys::POLL_FDS as u64)),
            (3, Value::Is(0)),
            (4, Value::Is(0)),
        ]],
    },
    // A panic reporting itself and aborting: abort() blocks signals and
    // raises SIGABRT at this thread only. The hook also prints the thread
    // id, but makes no gettid syscall: std binds musl's gettid weakly and
    // falls back to the syscall only when it is absent, and sys::thread_id
    // links it in, where it reads the id from the thread's descriptor.
    Rule::Any(libc::SYS_rt_sigprocmask),
    Rule::Args {
        nr: libc::SYS_tkill,
        alternatives: &[&[(0, Value::ThreadId), (1, v(libc::SIGABRT))]],
    },
    // Leaving. Returning from main runs std's cleanup, which takes down the
    // stack-overflow guard's alternate signal stack. Only exit_group: there
    // are no threads to end alone, and no handler ever returns, so no
    // rt_sigreturn either.
    Rule::Any(libc::SYS_sigaltstack),
    Rule::Any(libc::SYS_exit_group),
];

/// Allowed only in debug builds (tests): std checks that a descriptor is
/// open (fcntl F_GETFD) before closing it. Release builds never do, so the
/// image never allows it.
#[cfg(all(target_os = "linux", debug_assertions))]
const DEBUG_ALLOWLIST: &[Rule] = &[Rule::Args {
    nr: libc::SYS_fcntl,
    alternatives: &[&[(1, v(libc::F_GETFD))]],
}];
#[cfg(all(target_os = "linux", not(debug_assertions)))]
const DEBUG_ALLOWLIST: &[Rule] = &[];

/// The allowlist compiled at build time into a scratch buffer, which never
/// reaches the binary: only `FILTER`, cut to size from it, does.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const COMPILED: Program<256> = compile(ARCH, X32_GUARD, &[ALLOWLIST, DEBUG_ALLOWLIST]);
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const FILTER_LEN: usize = COMPILED.insns().len();
/// The seccomp filter, built at compile time, in read-only data.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
static FILTER: [Insn; FILTER_LEN] = truncate(&COMPILED);
/// The one instruction in `FILTER` to patch with the locking thread's id.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const TID_SLOT: usize = match COMPILED.tid_slot() {
    Some(slot) => slot,
    None => panic!("the allowlist has no thread-id argument"),
};

/// `FILTER`, with the thread `tid` as the only one abort() may signal. An
/// error if `tid` is negative, which no thread id is. The filter compares
/// both halves of tkill's 64-bit argument: a positive id's high half is 0.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn program(tid: libc::pid_t) -> io::Result<Vec<Insn>> {
    let tid = u32::try_from(tid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut program = FILTER.to_vec();
    program[TID_SLOT].k = tid;
    Ok(program)
}

/// The highest Landlock ABI whose rights this table knows. Newer kernels get
/// these rights; whatever they add stays allowed until the table learns it.
const LANDLOCK_KNOWN_ABI: u32 = 6;

/// A Landlock ruleset with no rules: everything it handles is denied.
/// `size` is how much of `struct landlock_ruleset_attr` the ABI reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Landlock {
    pub fs: u64,
    pub net: u64,
    pub scoped: u64,
    pub size: usize,
}

/// Every right of `abi`: filesystem (13 at ABI 1, then REFER at 2,
/// TRUNCATE at 3, IOCTL_DEV at 5), TCP bind and connect (4), abstract Unix
/// sockets and signals (6).
pub fn landlock_ruleset(abi: u32) -> Landlock {
    let abi = abi.min(LANDLOCK_KNOWN_ABI);
    let fs = match abi {
        0 | 1 => (1 << 13) - 1,
        2 => (1 << 14) - 1,
        3 | 4 => (1 << 15) - 1,
        _ => (1 << 16) - 1,
    };
    Landlock {
        fs,
        net: if abi >= 4 { 0b11 } else { 0 },
        scoped: if abi >= 6 { 0b11 } else { 0 },
        size: match abi {
            0..=3 => 8,
            4 | 5 => 16,
            _ => 24,
        },
    }
}

/// Defines `Layer` and `Layer::ALL` from one list, so a variant cannot exist
/// without being in `ALL`.
macro_rules! layers {
    ($($variant:ident),+ $(,)?) => {
        /// One layer of the lockdown, named as the log names it.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Layer {
            $($variant),+
        }

        impl Layer {
            /// Every layer, in the order the lockdown applies them.
            pub const ALL: [Layer; [$(Layer::$variant),+].len()] = [$(Layer::$variant),+];
        }
    };
}

layers!(
    Rlimits,
    AddressSpace,
    NonDumpable,
    NoNewPrivs,
    Landlock,
    Seccomp
);

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Layer::Rlimits => "rlimits",
            Layer::AddressSpace => "address-space limit",
            Layer::NonDumpable => "non-dumpable",
            Layer::NoNewPrivs => "no-new-privs",
            Layer::Landlock => "landlock",
            Layer::Seccomp => "seccomp",
        })
    }
}

/// A layer that applied, and for Landlock the ABI it applied at.
#[derive(Debug)]
struct Applied {
    layer: Layer,
    abi: Option<u32>,
}

impl fmt::Display for Applied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.abi {
            Some(abi) => write!(f, "{} ABI {abi}", self.layer),
            None => write!(f, "{}", self.layer),
        }
    }
}

/// What did not apply.
#[derive(Debug)]
enum Missing {
    /// One layer, and the error that stopped it.
    Layer(Layer, io::Error),
    /// The whole lockdown: this platform has none.
    #[cfg(not(target_os = "linux"))]
    Platform,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Missing::Layer(layer, e) => write!(f, "{layer} unavailable ({e})"),
            #[cfg(not(target_os = "linux"))]
            Missing::Platform => f.write_str("unavailable on this platform"),
        }
    }
}

/// What the lockdown managed to apply.
#[derive(Debug, Default)]
pub struct Report {
    applied: Vec<Applied>,
    missing: Vec<Missing>,
}

impl Report {
    /// Whether every layer applied.
    pub fn complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Whether `layer` applied.
    pub fn applied(&self, layer: Layer) -> bool {
        self.applied.iter().any(|a| a.layer == layer)
    }

    /// Why `layer` did not apply, if it was tried and failed.
    pub fn missing(&self, layer: Layer) -> Option<&io::Error> {
        self.missing.iter().find_map(|m| match m {
            Missing::Layer(l, e) if *l == layer => Some(e),
            _ => None,
        })
    }

    /// Lines to log: what applied, then one per layer that did not.
    pub fn lines(&self) -> Vec<String> {
        let applied = if self.applied.is_empty() {
            "none".to_string()
        } else {
            let names: Vec<String> = self.applied.iter().map(Applied::to_string).collect();
            names.join(", ")
        };
        std::iter::once(format!("sandbox: {applied}"))
            .chain(self.missing.iter().map(|m| format!("sandbox: {m}")))
            .collect()
    }

    /// Records whether `layer` applied, and at which Landlock `abi`.
    #[cfg(target_os = "linux")]
    fn note(&mut self, layer: Layer, result: io::Result<Option<u32>>) {
        match result {
            Ok(abi) => self.applied.push(Applied { layer, abi }),
            Err(e) => self.missing.push(Missing::Layer(layer, e)),
        }
    }
}

/// Room above the address space in use at lockdown, for everything the
/// steady state allocates: receive and netlink buffers, encoding, logging.
/// Measured on the x86_64 image (4 KiB pages): 752 kB at lockdown, 792 kB at
/// peak after 200 queries and a rescan, so 40 kB of growth; 1 MiB is 25
/// times that. At least 256 pages, because kernels with 16 or 64 KiB pages
/// round every mapping up to whole pages. `None` if that overflows.
fn address_space_headroom(page_size: u64) -> Option<u64> {
    page_size.checked_mul(256).map(|pages| pages.max(1 << 20))
}

/// The address-space cap: the size in use, from `statm` (its first field, in
/// pages), plus the headroom. `None` if `statm` does not parse, or the sum
/// overflows.
fn address_space_limit(statm: &str, page_size: u64) -> Option<u64> {
    let pages: u64 = statm.split_whitespace().next()?.parse().ok()?;
    pages
        .checked_mul(page_size)?
        .checked_add(address_space_headroom(page_size)?)
}

/// The descriptor cap (RLIMIT_NOFILE) for a process whose steady state
/// keeps the descriptors `open`: the number just above the highest of them
/// stays free, for the netlink socket each rescan opens and closes, and
/// nothing past it. The highest counts as at least 2, stderr, which logging
/// writes to and which is open whether or not `open` lists it. The one
/// place this floor is applied; negative entries are ignored.
fn open_files_limit(open: impl IntoIterator<Item = RawFd>) -> u64 {
    let highest = open
        .into_iter()
        .filter_map(|fd| u64::try_from(fd).ok())
        .fold(2, u64::max);
    // The limit is one more than the highest number allowed.
    highest + 2
}

/// Sheds everything the steady state does not need, in an order where each
/// step is still permitted by the ones before: rlimits, non-dumpable,
/// no-new-privs, Landlock, then seccomp, which forbids the Landlock calls.
/// `open` lists the descriptors the steady state keeps; see
/// `open_files_limit` for the cap it sets on new ones.
#[cfg(target_os = "linux")]
pub fn lock(open: impl IntoIterator<Item = RawFd>) -> Report {
    lock_with(open, std::fs::read_to_string("/proc/self/statm"))
}

/// `lock`, given the contents of /proc/self/statm. Only the address-space
/// limit needs them, so without /proc every other layer still applies.
#[cfg(target_os = "linux")]
pub fn lock_with(open: impl IntoIterator<Item = RawFd>, statm: io::Result<String>) -> Report {
    use crate::sys::{self, Limit};

    let mut report = Report::default();
    let open_files = open_files_limit(open);
    let limits = [
        (Limit::Processes, 0),
        (Limit::CoreSize, 0),
        (Limit::OpenFiles, open_files),
    ]
    .into_iter()
    .try_for_each(|(limit, value)| sys::set_limit(limit, value));
    report.note(Layer::Rlimits, limits.map(|()| None));
    let space = sys::page_size()
        .and_then(|page_size| {
            let statm = statm?;
            address_space_limit(&statm, page_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unparsable /proc/self/statm")
            })
        })
        .and_then(|space| sys::set_limit(Limit::AddressSpace, space));
    report.note(Layer::AddressSpace, space.map(|()| None));
    report.note(Layer::NonDumpable, sys::set_not_dumpable().map(|()| None));
    report.note(Layer::NoNewPrivs, sys::set_no_new_privs().map(|()| None));
    let landlock = sys::landlock_abi().and_then(|abi| {
        sys::landlock_restrict(&landlock_ruleset(abi))?;
        Ok(Some(abi))
    });
    report.note(Layer::Landlock, landlock);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let seccomp = program(sys::thread_id()).and_then(|program| sys::install_seccomp(&program));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let seccomp: io::Result<()> = Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no filter for this architecture",
    ));
    report.note(Layer::Seccomp, seccomp.map(|()| None));
    report
}

#[cfg(not(target_os = "linux"))]
pub fn lock(_open: impl IntoIterator<Item = RawFd>) -> Report {
    Report {
        applied: Vec::new(),
        missing: vec![Missing::Platform],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_64: u32 = 0xC000_003E;
    const AARCH64: u32 = 0xC000_00B7;

    /// Runs a filter the way the kernel does, on one syscall.
    fn run(filter: &[Insn], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
        }
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let insn = filter[pc];
            pc += 1;
            let jump = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
            match insn.code {
                LD_W_ABS => {
                    let k = insn.k as usize;
                    a = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
                }
                JEQ_K => pc += jump(a == insn.k),
                JGE_K => pc += jump(a >= insn.k),
                JSET_K => pc += jump(a & insn.k != 0),
                RET_K => return insn.k,
                code => panic!("unexpected opcode {code:#x}"),
            }
        }
    }

    const RULES: &[Rule] = &[
        Rule::Any(1),
        Rule::Args {
            nr: 41,
            alternatives: &[&[(0, Value::Is(16)), (2, Value::Is(0))]],
        },
        Rule::Args {
            nr: 54,
            alternatives: &[
                &[(1, Value::Is(0)), (2, Value::Is(35))],
                &[(1, Value::Is(41)), (2, Value::Is(20))],
            ],
        },
        Rule::Clear {
            nr: 9,
            arg: 2,
            mask: 4,
        },
    ];

    /// The used part of a filter compiled at run time, as tests need it.
    fn compiled(arch: u32, x32_guard: bool, rules: &[Rule]) -> Vec<Insn> {
        let program = compile::<256>(arch, x32_guard, &[rules]);
        program.insns().to_vec()
    }

    fn filter() -> Vec<Insn> {
        compiled(X86_64, true, RULES)
    }

    #[test]
    fn allows_listed_syscalls_with_any_arguments() {
        assert_eq!(run(&filter(), X86_64, 1, [7, 8, 9, 0, 0, 0]), RET_ALLOW);
    }

    #[test]
    fn kills_unlisted_syscalls() {
        assert_eq!(run(&filter(), X86_64, 2, [0; 6]), RET_KILL_PROCESS);
    }

    #[test]
    fn kills_other_architectures() {
        assert_eq!(run(&filter(), AARCH64, 1, [0; 6]), RET_KILL_PROCESS);
    }

    #[test]
    fn x32_guard_kills_x32_numbers_even_if_listed() {
        let listed = [Rule::Any(0x4000_0001)];
        assert_eq!(
            run(
                &compiled(X86_64, true, &listed),
                X86_64,
                0x4000_0001,
                [0; 6]
            ),
            RET_KILL_PROCESS
        );
        assert_eq!(
            run(
                &compiled(X86_64, false, &listed),
                X86_64,
                0x4000_0001,
                [0; 6]
            ),
            RET_ALLOW
        );
    }

    #[test]
    fn argument_rules_need_every_argument_to_match() {
        let f = filter();
        assert_eq!(run(&f, X86_64, 41, [16, 3, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(run(&f, X86_64, 41, [2, 3, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(run(&f, X86_64, 41, [16, 3, 9, 0, 0, 0]), RET_KILL_PROCESS);
    }

    #[test]
    fn argument_rules_compare_all_64_bits() {
        assert_eq!(
            run(&filter(), X86_64, 41, [16 | 1 << 32, 3, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
    }

    #[test]
    fn any_alternative_may_match() {
        let f = filter();
        assert_eq!(run(&f, X86_64, 54, [3, 0, 35, 0, 0, 0]), RET_ALLOW);
        assert_eq!(run(&f, X86_64, 54, [3, 41, 20, 0, 0, 0]), RET_ALLOW);
        assert_eq!(run(&f, X86_64, 54, [3, 0, 20, 0, 0, 0]), RET_KILL_PROCESS);
    }

    #[test]
    fn clear_rules_kill_when_a_masked_bit_is_set() {
        let f = filter();
        assert_eq!(run(&f, X86_64, 9, [0, 4096, 3, 0, 0, 0]), RET_ALLOW);
        assert_eq!(run(&f, X86_64, 9, [0, 4096, 7, 0, 0, 0]), RET_KILL_PROCESS);
    }

    #[test]
    fn every_jump_lands_inside_the_filter() {
        let f = filter();
        for (pc, insn) in f.iter().enumerate() {
            if matches!(insn.code, JEQ_K | JGE_K | JSET_K) {
                assert!(
                    pc + 1 + usize::from(insn.jt.max(insn.jf)) < f.len(),
                    "jump at {pc}"
                );
            }
        }
        assert_eq!(
            f.last().map(|i| (i.code, i.k)),
            Some((RET_K, RET_KILL_PROCESS))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_allowlist_allows_the_steady_state_and_kills_samples_of_the_rest() {
        const TID: libc::pid_t = 4242;
        let tid = u64::try_from(TID).unwrap();
        let f = program(TID).unwrap();
        let call = |nr: i64, args: [u64; 6]| run(&f, ARCH, nr as u32, args);
        let netlink = [
            libc::AF_NETLINK as u64,
            3,
            libc::NETLINK_ROUTE as u64,
            0,
            0,
            0,
        ];
        assert_eq!(call(libc::SYS_recvmsg, [0; 6]), RET_ALLOW);
        // No sleeping: the wait's timeout is the only timer.
        let monotonic = libc::CLOCK_MONOTONIC as u64;
        assert_eq!(
            call(libc::SYS_clock_nanosleep, [monotonic, 0, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(call(libc::SYS_nanosleep, [0; 6]), RET_KILL_PROCESS);
        // The wait: its entry count, a null signal mask and size 0 only.
        let fds = crate::sys::POLL_FDS as u64;
        let ppoll = |nfds: u64, mask: u64, size: u64| {
            call(libc::SYS_ppoll, [0x1000, nfds, 0x2000, mask, size, 0])
        };
        assert_eq!(ppoll(fds, 0, 0), RET_ALLOW);
        assert_eq!(ppoll(fds + 1, 0, 0), RET_KILL_PROCESS);
        assert_eq!(ppoll(fds, 0x3000, 8), RET_KILL_PROCESS);
        assert_eq!(ppoll(fds, 0, 8), RET_KILL_PROCESS);
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_poll, libc::SYS_select] {
            assert_eq!(call(nr, [0; 6]), RET_KILL_PROCESS, "syscall {nr}");
        }
        assert_eq!(call(libc::SYS_socket, netlink), RET_ALLOW);
        assert_eq!(
            call(libc::SYS_socket, [libc::AF_INET as u64, 2, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(call(libc::SYS_write, [2, 0, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_write, [1, 0, 0, 0, 0, 0]), RET_KILL_PROCESS);
        let exec = [0, 4096, (libc::PROT_READ | libc::PROT_EXEC) as u64, 0, 0, 0];
        assert_eq!(call(libc::SYS_mmap, exec), RET_KILL_PROCESS);
        // F_GETFD only in debug builds, where std checks descriptors.
        let getfd = if cfg!(debug_assertions) {
            RET_ALLOW
        } else {
            RET_KILL_PROCESS
        };
        assert_eq!(
            call(libc::SYS_fcntl, [3, libc::F_GETFD as u64, 0, 0, 0, 0]),
            getfd
        );
        assert_eq!(
            call(libc::SYS_fcntl, [3, libc::F_SETFL as u64, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(call(libc::SYS_sigaltstack, [0; 6]), RET_ALLOW);
        // Never needed after lockdown, so never allowed: futex (a classic
        // kernel exploit target), mprotect (no permission changes at all),
        // writev, thread exit, and rt_sigreturn (sigreturn-oriented code).
        for nr in [
            libc::SYS_futex,
            libc::SYS_mprotect,
            libc::SYS_writev,
            libc::SYS_exit,
            libc::SYS_rt_sigreturn,
        ] {
            assert_eq!(
                call(nr, [2, 0, 0, 0, 0, 0]),
                RET_KILL_PROCESS,
                "syscall {nr}"
            );
        }
        // The allocator's madvise and mremap, and only those uses.
        let advise = |advice: i32| call(libc::SYS_madvise, [0, 4096, advice as u64, 0, 0, 0]);
        assert_eq!(advise(libc::MADV_FREE), RET_ALLOW);
        assert_eq!(advise(libc::MADV_DONTNEED), RET_ALLOW);
        assert_eq!(advise(libc::MADV_WILLNEED), RET_KILL_PROCESS);
        assert_eq!(advise(libc::MADV_REMOVE), RET_KILL_PROCESS);
        let remap = |flags: i32| call(libc::SYS_mremap, [0, 4096, 8192, flags as u64, 0, 0]);
        assert_eq!(remap(0), RET_ALLOW);
        assert_eq!(remap(libc::MREMAP_MAYMOVE), RET_ALLOW);
        assert_eq!(
            remap(libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED),
            RET_KILL_PROCESS
        );
        assert_eq!(call(libc::SYS_openat, [0; 6]), RET_KILL_PROCESS);
        // A panic may report and abort itself, at this thread only.
        let abrt = libc::SIGABRT as u64;
        assert_eq!(call(libc::SYS_tkill, [tid, abrt, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(
            call(libc::SYS_tkill, [tid + 1, abrt, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(
            call(libc::SYS_tkill, [tid, libc::SIGKILL as u64, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        // No new processes or threads, and no signals to anything else.
        for nr in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_kill,
            libc::SYS_tgkill,
            libc::SYS_gettid,
        ] {
            assert_eq!(call(nr, [0; 6]), RET_KILL_PROCESS, "syscall {nr}");
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_fork, libc::SYS_vfork, libc::SYS_open] {
            assert_eq!(call(nr, [0; 6]), RET_KILL_PROCESS, "syscall {nr}");
        }
        assert_eq!(call(libc::SYS_execve, [0; 6]), RET_KILL_PROCESS);
    }

    #[test]
    fn landlock_rights_grow_with_the_abi() {
        assert_eq!(
            landlock_ruleset(1),
            Landlock {
                fs: (1 << 13) - 1,
                net: 0,
                scoped: 0,
                size: 8
            }
        );
        assert_eq!(landlock_ruleset(2).fs, (1 << 14) - 1);
        assert_eq!(landlock_ruleset(3).fs, (1 << 15) - 1);
        assert_eq!(
            landlock_ruleset(4),
            Landlock {
                fs: (1 << 15) - 1,
                net: 0b11,
                scoped: 0,
                size: 16
            }
        );
        assert_eq!(landlock_ruleset(5).fs, (1 << 16) - 1);
        assert_eq!(
            landlock_ruleset(6),
            Landlock {
                fs: (1 << 16) - 1,
                net: 0b11,
                scoped: 0b11,
                size: 24
            }
        );
    }

    #[test]
    fn landlock_newer_abis_use_the_known_rights() {
        assert_eq!(landlock_ruleset(7), landlock_ruleset(LANDLOCK_KNOWN_ABI));
        assert_eq!(landlock_ruleset(42), landlock_ruleset(LANDLOCK_KNOWN_ABI));
    }

    #[test]
    fn report_lines_name_what_applied_and_what_did_not() {
        let report = Report {
            applied: vec![
                Applied {
                    layer: Layer::Rlimits,
                    abi: None,
                },
                Applied {
                    layer: Layer::Seccomp,
                    abi: None,
                },
            ],
            missing: vec![Missing::Layer(
                Layer::Landlock,
                io::Error::new(io::ErrorKind::Unsupported, "Function not implemented"),
            )],
        };
        assert!(!report.complete());
        assert!(report.applied(Layer::Seccomp) && !report.applied(Layer::Landlock));
        assert!(report.missing(Layer::Landlock).is_some());
        assert!(report.missing(Layer::Seccomp).is_none());
        assert_eq!(
            report.lines(),
            [
                "sandbox: rlimits, seccomp",
                "sandbox: landlock unavailable (Function not implemented)"
            ]
        );
        assert_eq!(Report::default().lines(), ["sandbox: none"]);
    }

    /// The exact log text for every layer and every kind of missing entry,
    /// which operators read and may match on.
    #[test]
    fn report_lines_spell_every_layer_as_before() {
        let mut report = Report::default();
        for layer in Layer::ALL {
            let abi = (layer == Layer::Landlock).then_some(4);
            report.applied.push(Applied { layer, abi });
        }
        report.missing.push(Missing::Layer(
            Layer::AddressSpace,
            io::Error::new(io::ErrorKind::InvalidData, "unparsable /proc/self/statm"),
        ));
        assert_eq!(
            report.lines(),
            [
                "sandbox: rlimits, address-space limit, non-dumpable, no-new-privs, \
                 landlock ABI 4, seccomp",
                "sandbox: address-space limit unavailable (unparsable /proc/self/statm)",
            ]
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            lock([]).lines(),
            ["sandbox: none", "sandbox: unavailable on this platform"]
        );
    }

    #[test]
    fn the_descriptor_cap_leaves_one_free_above_the_highest() {
        assert_eq!(open_files_limit([3, 7, 5]), 9);
        // Stderr is the floor, with or without sockets below it.
        assert_eq!(open_files_limit([]), 4);
        assert_eq!(open_files_limit([0, 1]), 4);
        assert_eq!(open_files_limit([-1]), 4);
    }

    #[test]
    fn headroom_scales_with_page_size() {
        assert_eq!(address_space_headroom(4096), Some(1 << 20));
        assert_eq!(address_space_headroom(16384), Some(4 << 20));
        assert_eq!(address_space_headroom(65536), Some(16 << 20));
        assert_eq!(address_space_headroom(u64::MAX), None);
    }

    #[test]
    fn address_space_limit_is_the_size_in_use_plus_headroom() {
        let statm = "188 107 98 1 0 34 0\n";
        assert_eq!(
            address_space_limit(statm, 4096),
            Some(188 * 4096 + (1 << 20))
        );
        assert_eq!(address_space_limit("garbage", 4096), None);
        assert_eq!(address_space_limit("", 4096), None);
        assert_eq!(address_space_limit("18446744073709551615", 4096), None);
        assert_eq!(address_space_limit("1", u64::MAX / 256), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_allowlist_jumps_land_inside_the_filter() {
        let f = program(4242).unwrap();
        for (pc, insn) in f.iter().enumerate() {
            if matches!(insn.code, JEQ_K | JGE_K | JSET_K) {
                assert!(
                    pc + 1 + usize::from(insn.jt.max(insn.jf)) < f.len(),
                    "jump at {pc}"
                );
            }
        }
        assert_eq!(
            f.last().map(|i| (i.code, i.k)),
            Some((RET_K, RET_KILL_PROCESS))
        );
    }

    #[test]
    #[should_panic(expected = "longer than its buffer")]
    fn a_filter_that_does_not_fit_its_buffer_panics() {
        compile::<8>(X86_64, true, &[RULES]);
    }

    #[test]
    #[should_panic(expected = "longer than a BPF jump")]
    fn a_rule_body_past_a_bpf_jump_panics() {
        const MANY: &[(u8, Value)] = &[(0, Value::Is(1)); 64];
        compile::<512>(
            X86_64,
            true,
            &[&[Rule::Args {
                nr: 1,
                alternatives: &[MANY],
            }]],
        );
    }

    #[test]
    fn a_thread_id_argument_is_one_patchable_slot() {
        let rules = [Rule::Args {
            nr: 200,
            alternatives: &[&[(0, Value::ThreadId), (1, Value::Is(6))]],
        }];
        let program = compile::<64>(X86_64, true, &[&rules]);
        let slot = program.tid_slot().expect("one thread-id slot");
        assert_eq!(
            (program.insns()[slot].code, program.insns()[slot].k),
            (JEQ_K, 0)
        );
        let mut f = program.insns().to_vec();
        f[slot].k = 77;
        assert_eq!(run(&f, X86_64, 200, [77, 6, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(run(&f, X86_64, 200, [78, 6, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(
            run(&f, X86_64, 200, [77 | 1 << 32, 6, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
    }

    /// The compiler's exact output for every kind of rule: a refactor of the
    /// compiler or of `Rule` must not change a single instruction, and a
    /// deliberate change to the encoding shows up here as a diff.
    #[test]
    fn the_compiled_program_is_pinned() {
        let tid = [Rule::Args {
            nr: 200,
            alternatives: &[&[(0, Value::ThreadId), (1, Value::Is(6))]],
        }];
        let program = compile::<256>(X86_64, true, &[RULES, &tid]);
        let want = [
            ins(LD_W_ABS, 0, 0, 0x4),
            ins(JEQ_K, 1, 0, 0xc000003e),
            ret(RET_KILL_PROCESS),
            ins(LD_W_ABS, 0, 0, 0x0),
            ins(JGE_K, 0, 1, 0x40000000),
            ret(RET_KILL_PROCESS),
            ins(JEQ_K, 0, 1, 0x1),
            ret(RET_ALLOW),
            ins(JEQ_K, 0, 10, 0x29),
            ins(LD_W_ABS, 0, 0, 0x10),
            ins(JEQ_K, 0, 7, 0x10),
            ins(LD_W_ABS, 0, 0, 0x14),
            ins(JEQ_K, 0, 5, 0x0),
            ins(LD_W_ABS, 0, 0, 0x20),
            ins(JEQ_K, 0, 3, 0x0),
            ins(LD_W_ABS, 0, 0, 0x24),
            ins(JEQ_K, 0, 1, 0x0),
            ret(RET_ALLOW),
            ret(RET_KILL_PROCESS),
            ins(JEQ_K, 0, 19, 0x36),
            ins(LD_W_ABS, 0, 0, 0x18),
            ins(JEQ_K, 0, 7, 0x0),
            ins(LD_W_ABS, 0, 0, 0x1c),
            ins(JEQ_K, 0, 5, 0x0),
            ins(LD_W_ABS, 0, 0, 0x20),
            ins(JEQ_K, 0, 3, 0x23),
            ins(LD_W_ABS, 0, 0, 0x24),
            ins(JEQ_K, 0, 1, 0x0),
            ret(RET_ALLOW),
            ins(LD_W_ABS, 0, 0, 0x18),
            ins(JEQ_K, 0, 7, 0x29),
            ins(LD_W_ABS, 0, 0, 0x1c),
            ins(JEQ_K, 0, 5, 0x0),
            ins(LD_W_ABS, 0, 0, 0x20),
            ins(JEQ_K, 0, 3, 0x14),
            ins(LD_W_ABS, 0, 0, 0x24),
            ins(JEQ_K, 0, 1, 0x0),
            ret(RET_ALLOW),
            ret(RET_KILL_PROCESS),
            ins(JEQ_K, 0, 6, 0x9),
            ins(LD_W_ABS, 0, 0, 0x20),
            ins(JSET_K, 3, 0, 0x4),
            ins(LD_W_ABS, 0, 0, 0x24),
            ins(JSET_K, 1, 0, 0x0),
            ret(RET_ALLOW),
            ret(RET_KILL_PROCESS),
            ins(JEQ_K, 0, 10, 0xc8),
            ins(LD_W_ABS, 0, 0, 0x10),
            ins(JEQ_K, 0, 7, 0x0),
            ins(LD_W_ABS, 0, 0, 0x14),
            ins(JEQ_K, 0, 5, 0x0),
            ins(LD_W_ABS, 0, 0, 0x18),
            ins(JEQ_K, 0, 3, 0x6),
            ins(LD_W_ABS, 0, 0, 0x1c),
            ins(JEQ_K, 0, 1, 0x0),
            ret(RET_ALLOW),
            ret(RET_KILL_PROCESS),
            ret(RET_KILL_PROCESS),
        ];
        assert_eq!(program.insns(), want);
        assert_eq!(program.tid_slot(), Some(48));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_static_filter_is_exact_and_differs_only_in_the_thread_id() {
        assert_eq!(FILTER.len(), FILTER_LEN);
        assert_eq!(
            FILTER.last().map(|i| (i.code, i.k)),
            Some((RET_K, RET_KILL_PROCESS))
        );
        let patched = program(4242).unwrap();
        assert_eq!(patched.len(), FILTER.len());
        let differ: Vec<usize> = (0..FILTER.len())
            .filter(|&i| patched[i] != FILTER[i])
            .collect();
        assert_eq!(differ, [TID_SLOT]);
        assert_eq!(patched[TID_SLOT].k, 4242);
        assert!(program(-1).is_err());
    }
}
