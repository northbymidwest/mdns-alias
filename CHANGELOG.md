# Changelog

Notable changes per release. Dates are the publish date.

Changes land under `## Unreleased` as they are made. Releasing retitles that
heading to `## <version> - <publish date>`, so the notes are written while the
reason is still fresh rather than reconstructed from the log at release time.
`RELEASING.md` has the rest; the workflow refuses to publish a version whose
section is missing or empty, or to leave anything behind under `Unreleased`.

## Unreleased

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
