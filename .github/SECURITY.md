# Security policy

## Supported versions

`mdns-alias` is 0.x. Fixes go into a new release cut from `main`; older
versions are not patched. Report against the latest release or against
`main`.

## What this does

`mdns-alias` is a long-running daemon that joins the mDNS multicast group on
one interface, reads every mDNS packet that arrives there, and answers
address queries for the names it was given. Packet parsing is done by
[mdns-sd](https://crates.io/crates/mdns-sd). It has no configuration file,
writes nothing to disk, and opens no connection other than its mDNS socket.
The published image holds only the static binary and runs as a non-root
user.

## In scope

- A packet that crashes the daemon, hangs it, or makes it use unbounded
  memory or CPU.
- Answers the daemon was not asked to give: a name it was not given, an
  address other than the one it was given, or an answer on an interface other
  than the one that holds that address.
- Anything the daemon does beyond its mDNS socket: a file written, a
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
