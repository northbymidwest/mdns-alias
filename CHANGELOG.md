# Changelog

Notable changes per release. Dates are the publish date.

Changes land under `## Unreleased` as they are made. Releasing retitles that
heading to `## <version> - <publish date>`, so the notes are written while the
reason is still fresh rather than reconstructed from the log at release time.
`RELEASING.md` has the rest; the workflow refuses to publish a version whose
section is missing or empty, or to leave anything behind under `Unreleased`.

## 0.6.0 - 2026-10-02

### Changed

- Breaking: `--cname`, `--host` and relative names are removed. Every alias
  is answered with the addresses of the interface a query arrives on (A,
  AAAA, and NSEC for a missing family), and every alias is a full name
  ending in `.local`, used as given: `mdns-alias app.local media.local`.
  Only some clients followed the CNAMEs, and relative names (`app` for
  `app.<host>.local`) made names of several labels, which resolve poorly.
  A name without `.local` is refused at startup, with the fix when it is
  a single valid label (`"app" is not a .local name; write app.local`),
  and `--cname`, `--host` and the older `--target` (also as
  `--host=<name>`) are refused as removed. Names of several labels given
  in full (`api.app.local`) are still accepted, though a single label
  before `.local` resolves most reliably. An alias that is this machine's
  own name (the first label of its host name plus `.local`) is refused:
  the host's responder already publishes it, and mdns-alias's goodbyes
  would withdraw it from caches. The host name now comes from `uname()`,
  before lockdown, instead of `/proc/sys/kernel/hostname`; if it cannot be
  read the check is skipped.

- Breaking: log lines changed. Anything that matches them needs updating.
  Old -> new:
  `publishing <alias> -> <host>` -> `publishing <alias>`;
  `send buffer full on <interface>, dropped a packet` -> `dropped a packet
  on <interface> (<reason>)`, the reason being `send buffer full` or the
  error;
  `sending on <interface> failed, dropping it until the next rescan: <error>`
  -> `sending on <interface> failed, dropping it until a rescan rejoins it:
  <error>`;
  `announced on <interface>` -> `announced <alias>, ... on <interface>`;
  `another host is probing for the same name on <interface>, probing
  again` -> `another host is probing for <alias> on <interface>, probing
  again`;
  `reply to <destination> on <interface> failed: <error>` -> `reply to
  <address> on <interface> failed: <error>`, now rate-limited, with a
  `; logging again at most once a minute` suffix and a count of those not
  logged; the line a name conflict ended the program with (`<alias> is
  already in use by <address>`) is gone. The sandbox line now lists
  `capability drop` among its layers. New lines: `<alias> is claimed by
  <address>; probing again`, `<alias> is claimed by <address> on
  <interface>; giving up on it there for now, retrying in 5 min`, `probing
  for <alias> on <interface> again`, `<alias> on <interface>: probing held
  back by other hosts' probes`, `cannot read the host name (<error>); not
  checking aliases against it`, and `cannot open the netlink socket for
  listing interfaces: <error>`, which ends startup.

- Breaking: a name conflict no longer ends the program (under `restart:
  unless-stopped` that was a restart loop). When another host answers for
  a published alias with different data, the alias stops being answered
  for and is probed again on every interface where it was established
  (RFC 6762 section 9), logged as `<alias> is claimed by <address>;
  probing again`; the other aliases keep answering and defending. If the
  other host answers that probe, the alias is given up on that interface
  alone, with goodbyes for what it had published there (`<alias> is
  claimed by <address> on <interface>; giving up on it there for now,
  retrying in 5 min`), and probed again 5 minutes later (`probing for
  <alias> on <interface> again`). After 15 conflicts within 10 seconds,
  each further probe attempt waits at least 5 seconds (RFC 6762 section
  8.1), and never more than 10 seconds. If other hosts' probes keep an
  alias from probing for 10 seconds, one line says so (`<alias> on
  <interface>: probing held back by other hosts' probes`), and no more
  until it probes again. A lost tiebreak now restarts probing only for the
  alias that lost it, once per probe run of ours, and its log line names
  the alias. Goodbyes, on shutdown and on address changes, also cover an
  alias that is being probed again.

- Breaking: alias names given on the command line are checked: every label
  must be only ASCII letters, digits and hyphens, and not start or end with
  a hyphen. A name that breaks this is refused at startup with `invalid name
  "my_app.local": label "my_app" must be only ASCII letters, digits and
  hyphens, and not start or end with a hyphen`, instead of being published
  for clients that would not resolve it. Packets from the network are still
  parsed whatever their names contain.

- Multicast queries and responses from senders outside the arrival
  interface's subnets are no longer ignored (RFC 6762 section 11): a packet
  sent to 224.0.0.251 or ff02::fb is from the local link whatever its
  source address. Overlaid subnets, a device with the wrong netmask, or an
  IPv6 client on a prefix the host lacks (common with `accept_ra=0`) went
  unanswered before. Such a sender is answered by multicast, even for a QU
  question, never by unicast; a legacy query (from a port other than 5353)
  from one gets no reply, since it cannot hear multicast. The same goes for
  an IPv4 link-local (169.254/16) sender on an interface without a
  169.254/16 address, which the host has no route back to. Packets sent
  straight to this host from off-link are still ignored, and the first one
  per interface is still logged once per rescan.

- Unicast replies leave with an IP TTL (IPv6 hop limit) of 255, like the
  multicast ones (RFC 6762 section 11).

- The sandbox empties every capability set at lockdown, a new layer
  logged as `capability drop` between `address-space limit` and
  `non-dumpable` (and made fatal by `--require-sandbox` if it fails). The
  root check refused uid 0 but not an unprivileged process started with
  capabilities (systemd's `AmbientCapabilities=`, or a binary given file
  capabilities), which kept them: with CAP_NET_ADMIN, the netlink socket
  kept for rescans could have changed the host's addresses and routes.

- Reading the address change notifications stops after 64 reads per pass,
  so a flood of them cannot hold the main loop; reaching that cap counts as
  a change, so a rescan follows.

- The seccomp filter no longer allows `socket()` at all. Each rescan used
  to open a fresh netlink socket for its link and address listings, so the
  filter had to allow `socket(AF_NETLINK, ..., NETLINK_ROUTE)`; now one
  socket for them is opened and bound before lockdown and every rescan
  reuses it. Each request has its own sequence number, and replies left
  over from an earlier listing that failed part way are read off and
  dropped before the next request; a listing the kernel refuses because an
  earlier one is still running is tried once more after that. A reply that
  does not come within 1 s fails the rescan (`cannot list interfaces: no
  reply from the kernel`) instead of holding the main loop. A failed rescan
  keeps the previous state; one that timed out or was refused as busy is
  tried again after 2 s, as an interrupted one is, and an error the kernel
  answers with is logged as itself (`cannot list interfaces: Resource busy
  (os error 16)`) rather than as `invalid data`. The socket cannot be
  replaced under the sandbox, but a listing that stalls on it recovers on
  the next request. If that socket cannot be opened at startup, startup
  fails (`cannot open the netlink socket for listing interfaces: ...`).

- A listing of links and addresses that the kernel flags as interrupted by a
  change (`NLM_F_DUMP_INTR`) is no longer used as if it were complete. It is
  read once more; if that one is interrupted too, the rescan logs `cannot
  list interfaces: ...`, keeps the previous state, and tries again after 2 s
  instead of at the next rescan.

- The README is shorter, covering what it is, usage, Docker and the
  license; the technical details moved to `docs/design.md`.

- Probes no longer ask for a unicast reply (the QU bit on the first one).
  Port 5353 is shared with the host's own responder, and a unicast packet
  to it reaches only one of the two, so a unicast reply to a probe could be
  lost to the host's responder; multicast replies reach both. This departs
  from RFC 6762 section 8.1, which says the first probe SHOULD ask for one.
  `docs/design.md` now explains what sharing the port means for unicast
  traffic.

### Fixed

- The `addresses on <interface>: ...` line is logged whenever a wanted
  interface's stable addresses change, also when its first join failed
  (`cannot join ...`); it was skipped then, because the interface's name
  was looked up among the joined ones only.
- An alias whose records come close to the 1440-byte packet limit (about
  50 or more addresses on one interface) is now either fully served on a
  link or not at all. Its probe is a few bytes bigger than its
  announcement, so one just over the limit was reported as too big and left
  out of the probes but then announced anyway, without ever being probed.
  The probe's size now decides, and an alias too big for a link is left out
  of its probes, announcements, answers and goodbyes alike. An address
  change re-evaluates this: an alias that fits again is probed on that link
  as on a new one, on its own, while the link's other aliases keep
  answering (and are re-announced with the new addresses), and one that
  becomes too big is logged again (`<alias>'s records do not fit one packet
  on <interface>; not serving it there`) and gets goodbyes for what it had
  announced. The announcement line now names the aliases it covers
  (`announced <alias>, ... on <interface>`), and is not logged when every
  alias was too big and nothing went out.
- A query with the TC bit set is held for its known answers only if it asks
  about an alias answered for on that interface and family; one about
  aliases still being probed, or not served there, was held for nothing.
- A legacy unicast query (from a port other than 5353) with more than 32
  questions is no longer answered, and a legacy reply echoes only the
  questions it has answers for, still with the query's ID; nothing is sent
  if not even one answer fits within 1440 bytes (it could exceed 1440 bytes,
  or go out with no answers, before). A legacy resolver asks one question;
  echoing every question meant compressing names chosen by the sender,
  which for a few dozen long distinct names took over a second per packet,
  and a 9 KB query of short names about 90 times as long as a normal one.
  Both now cost about as much as the same query from port 5353.
- Known-answer suppression works per record set (alias and type), not per
  record: a set is left out of a reply only if the querier knows every
  record of it with at least half its TTL left, and otherwise goes out
  whole, in the answers and the additional records alike. A querier that
  knew one of two addresses used to get only the other, with the
  cache-flush bit set, which made every cache on the link drop the one it
  knew (RFC 6762 section 10.2).
- A record whose CNAME or NSEC data cannot be decoded (a malformed NSEC
  type bitmap, a bad name inside the data, bytes past the name) is now left
  out, and the rest of the message is handled as usual. It used to make the
  whole message be ignored, so a query listing such an NSEC among its known
  answers went unanswered, and a response carrying one hid any conflict in
  the same packet (RFC 6762 section 6.1). A message whose framing is broken
  (truncated, a bad owner or question name, counts past the end) is still
  ignored whole.
- An interface dropped because a multicast send on it failed is rejoined
  by a rescan 2 seconds later, doubling while drops keep coming, instead of
  at the next safety rescan up to 5 minutes later, during which its aliases
  went unanswered and undefended. `ENOBUFS` (a full device queue) and
  `ENOMEM` no longer count as such a failure: like a full send buffer, they
  lose the one packet, logged first and then at most once a minute, as
  `dropped a packet on <interface> (<reason>)`.
- A failed unicast reply is logged first and then at most once a minute per
  family, with a count of those not logged, instead of once per reply: any
  device that self-assigned a 169.254/16 address could make every reply to
  it fail on a host without a route there, one log line each. A reply to
  port 5353 that fails for want of a route (or of a source address) is
  answered by multicast instead, which the querier hears too (`reply to
  <address> on <interface> failed: <error>; answering by multicast
  instead`), within the limit of one multicast of a record a second (RFC
  6762 section 6), which it counts towards (a defence against a probe keeps
  only the 250 ms gap allowed for probe answers, as anywhere); a legacy
  querier, on another port, cannot hear multicast, so its reply is only
  logged.
- A query repeating one question many times costs about what one question
  does. Each alias was looked up again for every question, and every
  record checked against those already collected, so 1400 copies of an
  ANY question from port 5353 took about 0.4 ms with 4 addresses and 26 ms
  with 50; now each alias is looked up at most once per kind of question
  (A, AAAA, ANY, any other type), and not at all after an ANY, about 0.1
  ms either way, most of it parsing.
- Packets sent straight to this host's address on port 5353, rather than
  to the mDNS group, are told apart. A query sent so is answered by unicast
  to the querier (RFC 6762 section 5.5), not multicast to the link. A
  response sent so is ignored (section 6: unicast responses not asked for
  are silently ignored, and probes no longer ask): with the port shared, it
  was most likely meant for the host's own responder, and it no longer
  counts as a conflict.
- A multicast defence against a probe keeps at least 250 ms since its
  record set was last multicast on the link (RFC 6762 section 6), also
  when a unicast defence falls back to multicast. One the gap holds back
  is sent as soon as it has passed, once however many probes arrive
  meanwhile. Probe answers were exempt from the multicast rate limit
  altogether, so a stream of forged probes made mdns-alias multicast its
  records once per probe.
- Additional records (the other address family sent with an A or AAAA
  answer) go through the one-second multicast rate limit too (RFC 6762
  section 6): a set multicast on the link within the last second is left
  out, whole, and a set sent counts as multicast. An A query followed
  within a second by an AAAA query used to multicast the AAAA records
  twice.
- When another host sends one of our records (same name, type, class and
  data) with less than half its TTL, a goodbye (TTL 0) included, the
  record set is multicast with the full TTL (RFC 6762 sections 6.6 and
  10.1), at once or, within the one-second rate limit, as soon as that
  allows, still inside the second caches keep a record after a goodbye.
  Such records were ignored, so another host's goodbye for our data (a
  bridged copy of an old one, or a forged one) took it out of caches until
  they asked again. Packets from this host's own addresses (including one
  removed in the last 5 seconds) are its own looped back and never
  corrected.
- While an alias is being probed, any record of its name from another
  host (TXT, HINFO, SRV and the rest, not only an address, CNAME or NSEC
  that disagrees with ours) answers the probe, which asks for every type,
  and the alias is given up on that interface (RFC 6762 section 8.1).
  Responses read before the alias's first probe on a link went out are
  ignored: they answer nothing sent yet. Goodbyes, our own records and
  records of a class other than IN still do not count. Once established,
  only records that contradict ours are conflicts, as before (section 9).
  A probe after a section 9 reset waits 20-250 ms, so the copies of the
  conflicting response that the other host sent on the other interfaces
  and address family are read before it, not taken for an answer to it.

## 0.5.2 - 2026-10-01

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
