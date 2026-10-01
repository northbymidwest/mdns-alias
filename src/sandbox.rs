//! The lockdown applied after startup. Building the seccomp program and the
//! Landlock ruleset is pure and tested everywhere; applying them goes
//! through `sys` and is Linux only.

#[cfg(target_os = "linux")]
use std::io;

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
pub enum Value {
    /// Exactly this 64-bit value.
    Is(u64),
    /// The locking thread's id, known only at run time: compiled as a
    /// placeholder in one instruction, `Program::tid_slot`, patched at
    /// lockdown.
    ThreadId,
}

/// One allowlist entry.
#[derive(Clone, Copy, Debug)]
pub enum Rule {
    /// The syscall, with any arguments.
    Any(i64),
    /// The syscall, if its arguments match one of the alternatives, each a
    /// list of (argument index, value).
    Args(i64, &'static [&'static [(u8, Value)]]),
    /// The syscall, if argument `.1` has none of the bits in `.2` set.
    Clear(i64, u8, u64),
}

/// A compiled filter in a buffer of `N` instructions, of which the first
/// `len` are used.
#[derive(Clone, Copy, Debug)]
pub struct Program<const N: usize> {
    pub insns: [Insn; N],
    pub len: usize,
    /// The instruction comparing against `Value::ThreadId`, if any.
    pub tid_slot: Option<usize>,
}

impl<const N: usize> Program<N> {
    const fn push(&mut self, insn: Insn) {
        if self.len == N {
            panic!("seccomp filter longer than its buffer");
        }
        self.insns[self.len] = insn;
        self.len += 1;
    }

    /// Allow if any alternative matches every one of its (argument, value)
    /// pairs, comparing both 32-bit halves; otherwise kill.
    const fn args(&mut self, alternatives: &[&[(u8, Value)]]) {
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
    const fn clear(&mut self, arg: u8, mask: u64) {
        self.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, false)));
        self.push(ins(JSET_K, 3, 0, mask as u32));
        self.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, true)));
        self.push(ins(JSET_K, 1, 0, (mask >> 32) as u32));
        self.push(ret(RET_ALLOW));
        self.push(ret(RET_KILL_PROCESS));
    }
}

/// How many instructions a rule's body takes; every body ends in a return.
const fn body_len(rule: &Rule) -> usize {
    match *rule {
        Rule::Any(_) => 1,
        Rule::Args(_, alternatives) => {
            let mut len = 1;
            let mut a = 0;
            while a < alternatives.len() {
                len += 4 * alternatives[a].len() + 1;
                a += 1;
            }
            len
        }
        Rule::Clear(..) => 6,
    }
}

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
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
pub const fn compile<const N: usize>(arch: u32, x32_guard: bool, lists: &[&[Rule]]) -> Program<N> {
    let mut program = Program {
        insns: [ret(RET_KILL_PROCESS); N],
        len: 0,
        tid_slot: None,
    };
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
        let nr = match *rule {
            Rule::Any(nr) | Rule::Args(nr, _) | Rule::Clear(nr, ..) => nr,
        };
        // Every body ends in a return, so skipping it lands on the next
        // rule's test with the syscall number still loaded.
        program.push(ins(JEQ_K, 0, jump(body_len(rule)), nr as u32));
        match *rule {
            Rule::Any(_) => program.push(ret(RET_ALLOW)),
            Rule::Args(_, alternatives) => program.args(alternatives),
            Rule::Clear(_, arg, mask) => program.clear(arg, mask),
        }
        r += 1;
    }
    program.push(ret(RET_KILL_PROCESS));
    program
}

/// The used part of `program`, as an exact-size array.
#[cfg(target_os = "linux")]
const fn truncate<const N: usize, const M: usize>(program: &Program<N>) -> [Insn; M] {
    if program.len != M {
        panic!("truncated to the wrong length");
    }
    let mut out = [ret(RET_KILL_PROCESS); M];
    let mut i = 0;
    while i < M {
        out[i] = program.insns[i];
        i += 1;
    }
    out
}

/// This build's AUDIT_ARCH value, and whether it needs the x32 guard.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const ARCH: u32 = 0xC000_003E;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const X32_GUARD: bool = true;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const ARCH: u32 = 0xC000_00B7;
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
pub const ALLOWLIST: &[Rule] = &[
    // Receiving: mDNS (recvmsg), netlink replies (recvfrom), the signalfd
    // (read).
    Rule::Any(libc::SYS_recvmsg),
    Rule::Any(libc::SYS_recvfrom),
    Rule::Any(libc::SYS_read),
    // Sending: replies, announcements, netlink requests.
    Rule::Any(libc::SYS_sendto),
    // Choosing the send interface; joining and leaving groups on rescans.
    Rule::Args(
        libc::SYS_setsockopt,
        &[
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
    ),
    // The rescan's netlink socket, and no other.
    Rule::Args(
        libc::SYS_socket,
        &[&[(0, v(libc::AF_NETLINK)), (2, v(libc::NETLINK_ROUTE))]],
    ),
    Rule::Any(libc::SYS_close),
    // Logging, to stderr only.
    Rule::Args(libc::SYS_write, &[&[(0, Value::Is(2))]]),
    // Memory: musl's allocator maps, unmaps, grows (realloc), frees pages
    // (madvise) and moves the break. Never executable, never at a fixed
    // address over another mapping, no other advice. No mprotect at all:
    // after lockdown nothing changes a mapping's permissions.
    Rule::Clear(libc::SYS_mmap, 2, libc::PROT_EXEC as u64),
    Rule::Any(libc::SYS_munmap),
    Rule::Args(
        libc::SYS_mremap,
        &[&[(3, Value::Is(0))], &[(3, v(libc::MREMAP_MAYMOVE))]],
    ),
    Rule::Args(
        libc::SYS_madvise,
        &[&[(2, v(libc::MADV_FREE))], &[(2, v(libc::MADV_DONTNEED))]],
    ),
    Rule::Any(libc::SYS_brk),
    // Time: normally the vDSO, but libc falls back to the syscall when the
    // clock source cannot be read from user space, as on some VMs. No
    // futex: the process is single-threaded, so no lock ever waits.
    Rule::Any(libc::SYS_clock_gettime),
    // A panic reporting itself and aborting: the hook asks for the thread
    // id, then abort() blocks signals and raises SIGABRT at this thread only.
    Rule::Any(libc::SYS_gettid),
    Rule::Any(libc::SYS_rt_sigprocmask),
    Rule::Args(
        libc::SYS_tkill,
        &[&[(0, Value::ThreadId), (1, v(libc::SIGABRT))]],
    ),
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
pub const DEBUG_ALLOWLIST: &[Rule] = &[Rule::Args(libc::SYS_fcntl, &[&[(1, v(libc::F_GETFD))]])];
#[cfg(all(target_os = "linux", not(debug_assertions)))]
pub const DEBUG_ALLOWLIST: &[Rule] = &[];

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
pub const FILTER_LEN: usize = COMPILED.len;
/// The seccomp filter, built at compile time, in read-only data.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub static FILTER: [Insn; FILTER_LEN] = truncate(&COMPILED);
/// The one instruction in `FILTER` to patch with the locking thread's id.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub const TID_SLOT: usize = match COMPILED.tid_slot {
    Some(slot) => slot,
    None => panic!("the allowlist has no thread-id argument"),
};

/// `FILTER`, with the thread `tid` as the only one abort() may signal.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn program(tid: u64) -> Vec<Insn> {
    let mut program = FILTER.to_vec();
    // Thread ids fit 32 bits (the kernel caps them far lower), so the high
    // half's comparison stays 0.
    program[TID_SLOT].k = tid as u32;
    program
}

/// The highest Landlock ABI whose rights this table knows. Newer kernels get
/// these rights; whatever they add stays allowed until the table learns it.
pub const LANDLOCK_KNOWN_ABI: u32 = 6;

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

/// What the lockdown managed to apply.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub applied: Vec<String>,
    pub missing: Vec<String>,
}

impl Report {
    /// Whether every layer applied.
    pub fn complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Lines to log: what applied, then one per layer that did not.
    pub fn lines(&self) -> Vec<String> {
        let applied = if self.applied.is_empty() {
            "none".to_string()
        } else {
            self.applied.join(", ")
        };
        std::iter::once(format!("sandbox: {applied}"))
            .chain(self.missing.iter().map(|m| format!("sandbox: {m}")))
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn note(&mut self, layer: &str, result: io::Result<String>) {
        match result {
            Ok(done) => self.applied.push(done),
            Err(e) => self.missing.push(format!("{layer} unavailable ({e})")),
        }
    }
}

/// Room above the address space in use at lockdown, for everything the
/// steady state allocates: receive and netlink buffers, encoding, logging.
/// Measured on the x86_64 image (4 KiB pages): 752 kB at lockdown, 792 kB at
/// peak after 200 queries and a rescan, so 40 kB of growth; 1 MiB is 25
/// times that. At least 256 pages, because kernels with 16 or 64 KiB pages
/// round every mapping up to whole pages.
pub fn address_space_headroom(page_size: u64) -> u64 {
    (1 << 20).max(256 * page_size)
}

/// The address-space cap: the size in use, from `statm` (its first field, in
/// pages), plus the headroom. `None` if `statm` does not parse.
pub fn address_space_limit(statm: &str, page_size: u64) -> Option<u64> {
    let pages: u64 = statm.split_whitespace().next()?.parse().ok()?;
    Some(pages * page_size + address_space_headroom(page_size))
}

/// Sheds everything the steady state does not need, in an order where each
/// step is still permitted by the ones before: rlimits, non-dumpable,
/// no-new-privs, Landlock, then seccomp, which forbids the Landlock calls.
/// `highest_fd` is the highest descriptor in use; new ones are capped just
/// above it.
#[cfg(target_os = "linux")]
pub fn lock(highest_fd: i32) -> Report {
    lock_with(highest_fd, std::fs::read_to_string("/proc/self/statm"))
}

/// `lock`, given the contents of /proc/self/statm. Only the address-space
/// limit needs them, so without /proc every other layer still applies.
#[cfg(target_os = "linux")]
pub fn lock_with(highest_fd: i32, statm: io::Result<String>) -> Report {
    use crate::sys::{self, Limit};

    let mut report = Report::default();
    let open_files = u64::try_from(highest_fd).unwrap_or(2) + 2;
    let limits = [
        (Limit::Processes, 0),
        (Limit::CoreSize, 0),
        (Limit::OpenFiles, open_files),
    ]
    .into_iter()
    .try_for_each(|(limit, value)| sys::set_limit(limit, value));
    report.note("rlimits", limits.map(|()| "rlimits".into()));
    let page_size = sys::page_size();
    let space = statm
        .and_then(|statm| {
            address_space_limit(&statm, page_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unparsable /proc/self/statm")
            })
        })
        .and_then(|space| sys::set_limit(Limit::AddressSpace, space));
    report.note(
        "address-space limit",
        space.map(|()| "address-space limit".into()),
    );
    report.note(
        "non-dumpable",
        sys::set_not_dumpable().map(|()| "non-dumpable".into()),
    );
    report.note(
        "no-new-privs",
        sys::set_no_new_privs().map(|()| "no-new-privs".into()),
    );
    let landlock = sys::landlock_abi().and_then(|abi| {
        sys::landlock_restrict(&landlock_ruleset(abi))?;
        Ok(format!("landlock ABI {abi}"))
    });
    report.note("landlock", landlock);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let seccomp = sys::install_seccomp(&program(sys::thread_id()));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let seccomp: io::Result<()> = Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no filter for this architecture",
    ));
    report.note("seccomp", seccomp.map(|()| "seccomp".into()));
    report
}

#[cfg(not(target_os = "linux"))]
pub fn lock(_highest_fd: i32) -> Report {
    Report {
        applied: Vec::new(),
        missing: vec!["unavailable on this platform".into()],
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
        Rule::Args(41, &[&[(0, Value::Is(16)), (2, Value::Is(0))]]),
        Rule::Args(
            54,
            &[
                &[(1, Value::Is(0)), (2, Value::Is(35))],
                &[(1, Value::Is(41)), (2, Value::Is(20))],
            ],
        ),
        Rule::Clear(9, 2, 4),
    ];

    /// The used part of a filter compiled at run time, as tests need it.
    fn compiled(arch: u32, x32_guard: bool, rules: &[Rule]) -> Vec<Insn> {
        let program = compile::<256>(arch, x32_guard, &[rules]);
        program.insns[..program.len].to_vec()
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
        let tid = 4242;
        let f = program(tid);
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
        assert_eq!(call(libc::SYS_gettid, [0; 6]), RET_ALLOW);
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
            applied: vec!["rlimits".into(), "seccomp".into()],
            missing: vec!["landlock unavailable (Function not implemented)".into()],
        };
        assert!(!report.complete());
        assert_eq!(
            report.lines(),
            [
                "sandbox: rlimits, seccomp",
                "sandbox: landlock unavailable (Function not implemented)"
            ]
        );
        assert_eq!(Report::default().lines(), ["sandbox: none"]);
    }

    #[test]
    fn headroom_scales_with_page_size() {
        assert_eq!(address_space_headroom(4096), 1 << 20);
        assert_eq!(address_space_headroom(16384), 4 << 20);
        assert_eq!(address_space_headroom(65536), 16 << 20);
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
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_allowlist_jumps_land_inside_the_filter() {
        let f = program(4242);
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
        compile::<512>(X86_64, true, &[&[Rule::Args(1, &[MANY])]]);
    }

    #[test]
    fn a_thread_id_argument_is_one_patchable_slot() {
        let rules = [Rule::Args(
            200,
            &[&[(0, Value::ThreadId), (1, Value::Is(6))]],
        )];
        let program = compile::<64>(X86_64, true, &[&rules]);
        let slot = program.tid_slot.expect("one thread-id slot");
        assert_eq!(
            (program.insns[slot].code, program.insns[slot].k),
            (JEQ_K, 0)
        );
        let mut f = program.insns[..program.len].to_vec();
        f[slot].k = 77;
        assert_eq!(run(&f, X86_64, 200, [77, 6, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(run(&f, X86_64, 200, [78, 6, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(
            run(&f, X86_64, 200, [77 | 1 << 32, 6, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_static_filter_is_exact_and_differs_only_in_the_thread_id() {
        assert_eq!(FILTER.len(), FILTER_LEN);
        assert_eq!(
            FILTER.last().map(|i| (i.code, i.k)),
            Some((RET_K, RET_KILL_PROCESS))
        );
        let patched = program(4242);
        assert_eq!(patched.len(), FILTER.len());
        let differ: Vec<usize> = (0..FILTER.len())
            .filter(|&i| patched[i] != FILTER[i])
            .collect();
        assert_eq!(differ, [TID_SLOT]);
        assert_eq!(patched[TID_SLOT].k, 4242);
    }
}
