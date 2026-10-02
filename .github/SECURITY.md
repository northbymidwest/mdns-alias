# Security policy

## Supported versions

`mdns-alias` is 0.x. Fixes go into a new release cut from `main`; older
versions are not patched. Report against the latest release or against
`main`.

## What this does

`mdns-alias` is a long-running daemon that publishes extra `.local` names
for the machine it runs on, alongside the host's own mDNS responder. It
joins the mDNS group on every interface that is up (except loopback,
point-to-point and container interfaces), or on those named with
`--interface`, and reads every mDNS packet that arrives there. It parses
the packets itself (no mDNS library). For each name it was given it probes
before publishing, answers queries with the addresses of the interface the
query arrived on, and defends the name against other hosts that answer for it.

It has no configuration file, writes nothing to disk but its log on
stderr, and opens no connection. On Linux it holds two IP sockets for mDNS
(IPv4 and IPv6), two netlink sockets (one subscribed to link and address
changes, one for listing links and addresses), and a signalfd, all opened
before it locks itself down. It refuses to run as root. The lockdown
(described in [docs/design.md](../docs/design.md)) is: rlimits (no new
processes, no core dumps, descriptors capped), an address-space limit, all
capabilities dropped, non-dumpable, no-new-privs, a Landlock ruleset that
denies all filesystem access, TCP, abstract Unix sockets and signals to
other processes, and a seccomp allowlist of eighteen system calls, some
limited by argument. The published image holds only the static binary and
runs as a non-root user.

## In scope

- A system call outside the seccomp allowlist that the daemon can be made
  to reach, or an allowed one reachable with arguments the filter should
  have refused.
- A way around the other sandbox layers: Landlock, the rlimits or the
  address-space limit, or the capability drop (a capability still in the
  effective, permitted, inheritable or ambient set after lockdown, or in
  the bounding set when the daemon was started with CAP_SETPCAP; started
  without it, the bounding set stays full by design, since nothing can
  draw on it once exec and new privileges are ruled out).
- A packet that crashes the daemon, hangs it, or makes it use unbounded
  memory or CPU.
- Answers the daemon should not give: for a name it was not given, with an
  address that is not the arrival interface's own, or on an interface it
  was not asked to serve.
- A packet with a forged source address that makes the daemon send much
  more than it received, to that address or to the group, so it can be
  used to amplify or reflect traffic at a victim. (Replies by unicast go
  only to senders on the arrival interface's subnets or IPv6 link-local.)
- Anything the daemon does beyond its sockets: a file written, a
  connection opened, a privilege it needs and should not.
- The image: contents other than the binary, or a published image whose
  binary was not built from the commit its tag names.

## Not in scope

These are properties of mDNS itself. A report about one of them is welcome
as a normal issue:

- mDNS is unauthenticated. Anything on the same network can answer for the
  same names, and nothing here can stop that.
- Names published here are visible to everything on the network, as every
  mDNS name is.

## Reporting

Use GitHub's private vulnerability reporting: the **Security** tab of this
repository, then **Report a vulnerability**. That keeps the report private
until there is a release to point at.

Include what makes it reproducible: the command line the daemon was started
with, the packet or the tool that sent it if you have it, the host OS and the
other mDNS responder running there (systemd-resolved, Avahi, mDNSResponder),
and the `mdns-alias` version.

This is a personal project maintained by one person. Expect a reply in days
rather than hours, and nothing more binding than that.
