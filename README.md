# mdns-alias

Publishes extra mDNS host names for a machine, answered with the machine's own
addresses, alongside whatever mDNS responder the host already runs
(systemd-resolved, Avahi, mDNSResponder). Useful for giving services on one
machine their own `.local` names, such as `app.myhost.local`, that follow the
machine's address wherever DHCP puts it.

```sh
mdns-alias [--host <name.local>] [--cname] [--interface <name>]... [--require-sandbox] <name>...
mdns-alias app media           # app.myhost.local, media.myhost.local, answered with this host's addresses
mdns-alias api.app tv.local    # api.app.myhost.local, tv.local
mdns-alias --cname app         # app.myhost.local CNAME myhost.local
```

By default each alias is answered with this host's addresses on the
interface a query arrives on: A records for its IPv4 addresses, AAAA for
its stable IPv6 addresses (not temporary, deprecated or still being
checked), and an NSEC record when one family has none, so clients do not
wait for an answer that will not come. With `--cname`, each alias is
instead a CNAME of the host's own `.local` name.

The host name, which relative names extend and CNAMEs point at, defaults to
this host's name plus `.local` (read from `/proc/sys/kernel/hostname`, so
elsewhere than Linux `--host` is required). A name ending in `.local` is
used as given; any other name is relative to the host name, as in a DNS
zone file, so `app` means `app.myhost.local`. A trailing dot marks a name as
absolute. The full names are logged at startup.

It answers on every interface that is up, except loopback, point-to-point and
container interfaces (`docker*`, `br-*`, `veth*`); `--interface`, repeatable,
names the interfaces to use instead. On Linux it follows interface and
address changes as the kernel reports them, with a full rescan every 5
minutes as a safety net; when addresses change it announces the new ones and
withdraws the old. Elsewhere it rescans every 30 seconds, and so does Linux
if the kernel's change notifications are unavailable: it logs `address events
unavailable (<reason>); rescanning every 30s` and falls back to polling.

Before publishing, it probes each name, and it exits with an error if another
device already answers for one, or starts to later. It sends goodbye packets
on SIGTERM/SIGINT so clients drop the names immediately.

Tested against macOS and iOS clients, whose resolver (mDNSResponder) follows
the addresses (or the CNAME, with `--cname`) as expected.

## Docker

Released images are at `ghcr.io/northbymidwest/mdns-alias:<version>`, for
`linux/amd64` and `linux/arm64`. The current release is `0.4.0`. `latest`
follows the newest release; pin a version (or a digest) for anything you
deploy. Each release carries build provenance and SBOM attestations:

```sh
gh attestation verify oci://ghcr.io/northbymidwest/mdns-alias:0.4.0 \
  --owner northbymidwest
```

The image contains only the static binary. It needs the host's network to
reach the LAN, and nothing else: it runs as a non-root user, and port 5353 is
unprivileged. With `network_mode: host` the container has the host's name, so
the default host name is right.

```yaml
services:
  mdns-alias:
    image: ghcr.io/northbymidwest/mdns-alias:0.4.0
    network_mode: host
    command: ["app", "media"]
    read_only: true
    cap_drop: [ALL]
    restart: unless-stopped
```

The binary sets no-new-privileges on itself once started, so the compose
`no-new-privileges` option adds nothing. Leave it out: on some Docker
installs, notably the Ubuntu snap, it stops the container from starting at
all (`exec /mdns-alias: operation not permitted`), because exec'ing the
binary needs an AppArmor profile transition that the option forbids.

## Sandbox

On Linux, once its sockets are open, mdns-alias sheds everything it no
longer needs:

- rlimits: no new processes, no core dumps, and file descriptors capped
  just above those in use.
- A netlink socket subscribed to link and address changes, opened before
  lockdown; afterwards it can only be read.
- An address-space limit just above the size in use (read from
  `/proc/self/statm`, which Docker always mounts; without `/proc` only this
  layer is skipped).
- Non-dumpable and no-new-privs: nothing can ptrace it or read its memory,
  and nothing it runs could gain privileges.
- Landlock: no filesystem access at all, no TCP, no abstract Unix sockets,
  no signals to other processes.
- seccomp: about twenty system calls, some limited by argument (only
  netlink sockets, only multicast socket options, writes only to stderr,
  never executable memory). Anything else kills the process.

It also ignores packets from senders that are not on the local network of
the interface they arrived on.

It refuses to run as root. Layers the kernel does not support are skipped
and logged at startup:

```
mdns-alias: sandbox: rlimits, address-space limit, non-dumpable, no-new-privs, landlock ABI 8, seccomp
```

`--require-sandbox` makes a missing layer fatal instead. On macOS, a
development platform here, there is no sandbox.

Build Linux binaries for musl (`x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`), as the image does. The seccomp allowlist is
tested against musl's system calls only; a glibc build is unsupported and
may be killed by its own sandbox.

## How it works

By default each alias is published with this host's addresses on the
interface the query arrives on (`alias A`, `alias AAAA`, and an NSEC record
for a family with no addresses), read from the interface rather than
configured, so none goes stale. With `--cname`, each alias is instead a
single record, `alias CNAME <host>.local`: the host's own responder already
answers for `<host>.local`, so a client gets the CNAME from mdns-alias, then
the addresses from the host. Probes, announcements and replies too large for
one packet are split across several, so the number of aliases is not limited.

mdns-alias is a small mDNS responder of its own (RFC 6762: probing,
announcing, known-answer suppression, rate limiting, legacy unicast replies),
over IPv4 and IPv6. Its sockets share port 5353 with the host's responder via
`SO_REUSEADDR` and `SO_REUSEPORT`, which systemd-resolved deliberately
allows.

## License

[BSD Zero Clause License](LICENSE)

### Why 0BSD?

The majority of this codebase was generated by AI coding agents (primarily
Claude). AI-generated code is not copyrightable and is effectively public
domain, making 0BSD, which imposes no restrictions on use, the most
appropriate license.

### Disclaimer

While AI-generated code itself is public domain, AI agents may have reproduced
or closely derived code from copyrighted sources (training data, reference
implementations, open-source projects, etc.). No audit has been conducted to
identify such instances, as this is a personal side project. Any such code
fragments remain subject to the licenses of their original creators. Use at
your own discretion.
