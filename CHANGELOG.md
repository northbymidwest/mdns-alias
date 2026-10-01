# Changelog

Notable changes per release. Dates are the publish date.

Changes land under `## Unreleased` as they are made. Releasing retitles that
heading to `## <version> - <publish date>`, so the notes are written while the
reason is still fresh rather than reconstructed from the log at release time.
`RELEASING.md` has the rest; the workflow refuses to publish a version whose
section is missing or empty, or to leave anything behind under `Unreleased`.

## Unreleased

### Added

- Queries with the TC (truncated) bit set, whose known answers continue in
  later packets, are answered after a random 400-500 ms instead of at once,
  with every known answer the querier sent in the meantime suppressing what
  it already has (RFC 6762 section 7.2). A further TC packet extends the
  wait, to at most 2 s after the first. Other queries from a querier that
  is being waited on are answered with its pending query. Probes and legacy
  unicast queries are still answered at once, and at most 32 queries wait
  per interface and family; more are answered at once, as before.

### Changed

- The main loop waits on both sockets, the signalfd and the notification
  socket at once, until the next timer is due, instead of waiting up to
  100 ms on each socket in turn. An idle process now sleeps until its next
  rescan (5 minutes, or 30 seconds without notifications) instead of waking
  5 to 10 times a second, and probes, announcements and delayed answers go
  out within a few milliseconds of when they are due instead of up to about
  200 ms late. The sockets are non-blocking: a packet that does not fit the
  send buffer is dropped instead of waiting for room, and logged per family
  as `send buffer full on <interface> (IPv4), dropped a packet; logging
  again at most once a minute`, then at most once a minute with a count of
  the drops skipped. Goodbyes at shutdown are best-effort too: any that do
  not fit the send buffer are dropped.
- A socket whose receive fails is left out of the wait for 100 ms instead of
  the loop sleeping, with the same rate-limited log lines as before. An
  error condition the kernel reports on a socket with nothing to read
  counts as a failure (`receive on IPv4 failed: the socket reports an
  error; ...`). The notification socket rests the same way after a failed
  read, which still counts as an address change and leads to a rescan.
- The seccomp allowlist now allows `ppoll`, with four entries and no signal
  mask only, and no longer allows `clock_nanosleep`: nothing sleeps any
  more.

## 0.5.1 - 2026-10-01

### Changed

- A receive that fails with anything but a timeout now waits out the 100 ms
  receive timeout before retrying, so a dead socket no longer spins the
  loop. Each family logs its first failure as `receive on IPv4 failed:
  <error>; retrying, and logging again at most once a minute`, then at most
  once a minute, with a count of the failures skipped since the last line
  (`receive on IPv4 failed: <error> (3 more not logged); ...`). Recovery is
  logged once, as `receiving on IPv4 works again`, followed by ` (1 more
  failure not logged)` or ` (N more failures not logged)` if any were
  skipped.
- The seccomp allowlist now allows `clock_nanosleep`, on the monotonic clock
  and relative only, for that wait, and no longer allows `gettid`: a panic
  still reports its thread id, read without the syscall.
- If the page size cannot be read, the address-space limit is skipped and
  logged as missing (`sandbox: address-space limit unavailable (<error>)`)
  instead of being computed from a bad value.

### Fixed

- Interfaces that go away are now forgotten. Before, each one left its
  address list behind for the life of the process.

## 0.5.0 - 2026-10-01

### Changed

- Breaking: aliases are answered with this host's addresses (A, AAAA, and
  NSEC for a missing family) on the interface each query arrives on, instead
  of CNAMEs. `--cname` restores CNAMEs.
- Breaking: `--target` is now `--host`.
- On Linux, interface and address changes are picked up from kernel
  notifications as they happen, with a full rescan every 5 minutes, instead
  of every 30 seconds. Changed addresses are re-announced and removed ones
  withdrawn.
- Probes, announcements and replies that do not fit one packet are split
  across several, so the alias count is no longer limited by packet size.

## 0.4.0 - 2026-09-30

### Changed

- Breaking: a name that does not end in `.local` is now relative to the
  target instead of an error: `mdns-alias seerr sonarr` publishes
  `seerr.<host>.local` and `sonarr.<host>.local`. Multi-label names work the
  same way (`api.seerr`), names ending in `.local` are used as given, and a
  trailing dot marks a name as absolute. The full names are logged at
  startup. Command lines that worked before mean the same thing.

## 0.3.1 - 2026-09-30

### Changed

- The seccomp allowlist is smaller: futex, mprotect, writev, thread exit
  and rt_sigreturn are no longer allowed (none is used after lockdown), so
  nothing can change a mapping's permissions; madvise is limited to the
  allocator's MADV_FREE and MADV_DONTNEED, and mremap to its plain and
  MREMAP_MAYMOVE forms. fcntl(F_GETFD), needed only by debug builds, is no
  longer in release builds.

## 0.3.0 - 2026-09-30

### Added

- A sandbox on Linux, applied once the sockets are open: rlimits, an
  address-space limit, non-dumpable, no-new-privs, a deny-all Landlock ruleset, and a seccomp
  allowlist of about twenty system calls that kills the process on anything
  else. Layers the kernel lacks are logged and skipped; `--require-sandbox`
  makes them fatal.
- mdns-alias refuses to run as root.
- A panic under the sandbox still prints its message and ends in SIGABRT,
  rather than a bare SIGSYS that would look like a sandbox violation.

### Changed

- Packets from senders that are not on-link for the arrival interface are
  ignored (RFC 6762 section 11), so off-link hosts can no longer trigger
  replies or the conflict exit. Link-local senders (169.254/16, fe80::/10)
  are always on-link. The first off-link sender on an interface is logged
  once per rescan, so a netmask that does not cover the LAN is visible.
- Interfaces without multicast support are skipped.
- On Linux, signals are read from a signalfd and interfaces are listed over
  netlink, dropping `ctrlc` and `if-addrs` from the image and its second
  thread: the binary is about 54 KB (9%) smaller.
- CI tests Linux on musl, as the image ships. glibc builds are unsupported.

## 0.2.0 - 2026-09-30

### Changed

- Breaking: the command line is now `mdns-alias [--target <name.local>]
  [--interface <name>]... <alias.local>...`. Each alias is published as a
  CNAME of the target, which defaults to this host's `.local` name, instead
  of resolving to an address given on the command line. Aliases follow the
  host's address, and there is no address to update.
- Names are no longer registered as placeholder `_mdns-alias._tcp` services,
  so service browsers stop listing them.
- Each name is probed before it is published, and mdns-alias exits with an
  error naming the other device if the name is already taken, or taken later.
- Answers over IPv6 as well as IPv4, on every suitable interface rather than
  only the one holding a given address. Interfaces are rescanned every 30
  seconds.

### Removed

- The mdns-sd dependency, and with it most of the dependency tree. The
  responder is now part of mdns-alias.

## 0.1.3 - 2026-09-29

### Added

- Releases also move a `latest` tag to the new image. The exact-version tag
  is still the one to pin.

## 0.1.2 - 2026-09-29

### Fixed

- The release SBOM named the image `ghcr.io/*******/mdns-alias`: syft
  redacted the registry username, which is also the image's owner. The SBOM
  is now generated from an anonymous pull.

## 0.1.1 - 2026-09-29

### Changed

- The binary is built with `cargo auditable`, so its exact dependency list is
  embedded and scanners can read it out of the image. CI audits the shipped
  binary with `cargo audit bin`, and each release attests an SPDX SBOM
  alongside its build provenance.
- The build image is pinned by digest, and `#![forbid(unsafe_code)]` keeps
  the crate free of `unsafe`.

## 0.1.0 - 2026-09-29

### Added

- `mdns-alias <address> <name.local>...` publishes each name as an mDNS host
  name resolving to `<address>`, alongside the host's own responder
  (systemd-resolved, Avahi, mDNSResponder), answering only on the interface
  that holds the address. Goodbye packets on SIGTERM and SIGINT withdraw the
  names immediately.
- A multi-arch image (`linux/amd64`, `linux/arm64`) at
  `ghcr.io/northbymidwest/mdns-alias`, holding only the static binary and
  running as a non-root user.
