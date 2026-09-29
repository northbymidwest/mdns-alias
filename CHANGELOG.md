# Changelog

Notable changes per release. Dates are the publish date.

Changes land under `## Unreleased` as they are made. Releasing retitles that
heading to `## <version> - <publish date>`, so the notes are written while the
reason is still fresh rather than reconstructed from the log at release time.
`RELEASING.md` has the rest; the workflow refuses to publish a version whose
section is missing or empty, or to leave anything behind under `Unreleased`.

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
