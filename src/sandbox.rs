//! The lockdown applied after startup. Building the seccomp program (and,
//! from Task 5, the Landlock ruleset) is pure and tested everywhere;
//! applying it goes through `sys` and is Linux only.

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

/// One allowlist entry.
#[derive(Clone, Debug)]
pub enum Rule {
    /// The syscall, with any arguments.
    Any(i64),
    /// The syscall, if its arguments match one of the alternatives, each a
    /// list of (argument index, exact 64-bit value).
    Args(i64, Vec<Vec<(u8, u64)>>),
    /// The syscall, if argument `.1` has none of the bits in `.2` set.
    Clear(i64, u8, u64),
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

fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

fn ret(k: u32) -> Insn {
    ins(RET_K, 0, 0, k)
}

/// Where the low or high 32 bits of argument `arg` sit in seccomp_data.
fn arg_offset(arg: u8, high: bool) -> u32 {
    16 + 8 * u32::from(arg) + if high { 4 } else { 0 }
}

/// A BPF jump distance. The allowlist is small and fixed, so every jump
/// fits; a rule body that ever outgrows one fails loudly here.
fn jump(n: usize) -> u8 {
    u8::try_from(n).expect("seccomp rule body longer than a BPF jump")
}

/// Compiles `rules` into a filter for `arch` (an AUDIT_ARCH value): any other
/// architecture is killed, so is every syscall no rule allows, and with
/// `x32_guard`, every x32-ABI number.
pub fn compile(arch: u32, x32_guard: bool, rules: &[Rule]) -> Vec<Insn> {
    let mut filter = vec![
        ins(LD_W_ABS, 0, 0, OFFSET_ARCH),
        ins(JEQ_K, 1, 0, arch),
        ret(RET_KILL_PROCESS),
        ins(LD_W_ABS, 0, 0, OFFSET_NR),
    ];
    if x32_guard {
        filter.push(ins(JGE_K, 0, 1, X32_BIT));
        filter.push(ret(RET_KILL_PROCESS));
    }
    for rule in rules {
        let (nr, body) = match rule {
            Rule::Any(nr) => (*nr, vec![ret(RET_ALLOW)]),
            Rule::Args(nr, alternatives) => (*nr, args_body(alternatives)),
            Rule::Clear(nr, arg, mask) => (*nr, clear_body(*arg, *mask)),
        };
        // Every body ends in a return, so skipping it lands on the next
        // rule's test with the syscall number still loaded.
        filter.push(ins(JEQ_K, 0, jump(body.len()), nr as u32));
        filter.extend(body);
    }
    filter.push(ret(RET_KILL_PROCESS));
    filter
}

/// Allow if any alternative matches every one of its (argument, value)
/// pairs, comparing both 32-bit halves; otherwise kill.
fn args_body(alternatives: &[Vec<(u8, u64)>]) -> Vec<Insn> {
    let mut body = Vec::new();
    for alternative in alternatives {
        let mut block = Vec::new();
        for &(arg, value) in alternative {
            for (high, half) in [(false, value as u32), (true, (value >> 32) as u32)] {
                block.push(ins(LD_W_ABS, 0, 0, arg_offset(arg, high)));
                block.push(ins(JEQ_K, 0, 0, half));
            }
        }
        block.push(ret(RET_ALLOW));
        // A mismatch skips to just past this alternative's return.
        let len = block.len();
        for (i, insn) in block.iter_mut().enumerate() {
            if insn.code == JEQ_K {
                insn.jf = jump(len - i - 1);
            }
        }
        body.extend(block);
    }
    body.push(ret(RET_KILL_PROCESS));
    body
}

/// Allow unless argument `arg` has any bit of `mask` set.
fn clear_body(arg: u8, mask: u64) -> Vec<Insn> {
    vec![
        ins(LD_W_ABS, 0, 0, arg_offset(arg, false)),
        ins(JSET_K, 3, 0, mask as u32),
        ins(LD_W_ABS, 0, 0, arg_offset(arg, true)),
        ins(JSET_K, 1, 0, (mask >> 32) as u32),
        ret(RET_ALLOW),
        ret(RET_KILL_PROCESS),
    ]
}

/// This build's AUDIT_ARCH value, and whether it needs the x32 guard.
/// `None` on architectures without a filter here.
#[cfg(target_os = "linux")]
pub fn arch() -> Option<(u32, bool)> {
    if cfg!(target_arch = "x86_64") {
        Some((0xC000_003E, true))
    } else if cfg!(target_arch = "aarch64") {
        Some((0xC000_00B7, false))
    } else {
        None
    }
}

/// Every syscall the steady state makes, and nothing else. Startup is never
/// filtered. Changes come from tracing the real binary; each line says why.
#[cfg(target_os = "linux")]
pub fn allowlist() -> Vec<Rule> {
    // Constants are small and positive, so widening keeps their value.
    fn v(x: libc::c_int) -> u64 {
        x as u64
    }
    let sockopts = [
        (libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP),
        (libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP),
        (libc::IPPROTO_IP, libc::IP_MULTICAST_IF),
        (libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP),
        (libc::IPPROTO_IPV6, libc::IPV6_DROP_MEMBERSHIP),
        (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF),
    ];
    vec![
        // Receiving: mDNS (recvmsg), netlink replies (recvfrom), the
        // signalfd (read).
        Rule::Any(libc::SYS_recvmsg),
        Rule::Any(libc::SYS_recvfrom),
        Rule::Any(libc::SYS_read),
        // Sending: replies, announcements, netlink requests.
        Rule::Any(libc::SYS_sendto),
        // Choosing the send interface; joining and leaving groups on rescans.
        Rule::Args(
            libc::SYS_setsockopt,
            sockopts
                .iter()
                .map(|&(level, opt)| vec![(1, v(level)), (2, v(opt))])
                .collect(),
        ),
        // The rescan's netlink socket, and no other.
        Rule::Args(
            libc::SYS_socket,
            vec![vec![(0, v(libc::AF_NETLINK)), (2, v(libc::NETLINK_ROUTE))]],
        ),
        Rule::Any(libc::SYS_close),
        // Only reading the close-on-exec flag: debug builds of std check
        // that a descriptor is open (F_GETFD) before closing it.
        Rule::Args(libc::SYS_fcntl, vec![vec![(1, v(libc::F_GETFD))]]),
        // Logging, to stderr only.
        Rule::Args(libc::SYS_write, vec![vec![(0, 2)]]),
        Rule::Args(libc::SYS_writev, vec![vec![(0, 2)]]),
        // Memory, never executable.
        Rule::Clear(libc::SYS_mmap, 2, v(libc::PROT_EXEC)),
        Rule::Clear(libc::SYS_mprotect, 2, v(libc::PROT_EXEC)),
        Rule::Any(libc::SYS_munmap),
        Rule::Any(libc::SYS_mremap),
        Rule::Any(libc::SYS_madvise),
        Rule::Any(libc::SYS_brk),
        // Time (normally the vDSO, but libc may fall back) and locks.
        Rule::Any(libc::SYS_clock_gettime),
        Rule::Any(libc::SYS_futex),
        // Leaving. Returning from main runs std's cleanup, which takes down
        // the stack-overflow guard's alternate signal stack.
        Rule::Any(libc::SYS_sigaltstack),
        Rule::Any(libc::SYS_exit),
        Rule::Any(libc::SYS_exit_group),
        Rule::Any(libc::SYS_rt_sigreturn),
    ]
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
    let seccomp = match arch() {
        Some((arch, x32)) => sys::install_seccomp(&compile(arch, x32, &allowlist())),
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no filter for this architecture",
        )),
    };
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

    fn rules() -> Vec<Rule> {
        vec![
            Rule::Any(1),
            Rule::Args(41, vec![vec![(0, 16), (2, 0)]]),
            Rule::Args(54, vec![vec![(1, 0), (2, 35)], vec![(1, 41), (2, 20)]]),
            Rule::Clear(9, 2, 4),
        ]
    }

    fn filter() -> Vec<Insn> {
        compile(X86_64, true, &rules())
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
            run(&compile(X86_64, true, &listed), X86_64, 0x4000_0001, [0; 6]),
            RET_KILL_PROCESS
        );
        assert_eq!(
            run(
                &compile(X86_64, false, &listed),
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
    fn linux_allowlist_allows_the_steady_state_and_nothing_else() {
        let (arch, x32) = arch().expect("tests run on x86_64 or aarch64");
        let f = compile(arch, x32, &allowlist());
        let call = |nr: i64, args: [u64; 6]| run(&f, arch, nr as u32, args);
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
        assert_eq!(
            call(libc::SYS_fcntl, [3, libc::F_GETFD as u64, 0, 0, 0, 0]),
            RET_ALLOW
        );
        assert_eq!(
            call(libc::SYS_fcntl, [3, libc::F_SETFL as u64, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(call(libc::SYS_sigaltstack, [0; 6]), RET_ALLOW);
        assert_eq!(call(libc::SYS_openat, [0; 6]), RET_KILL_PROCESS);
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
}
