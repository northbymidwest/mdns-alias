# mdns-alias: how it works

The technical details behind mdns-alias. For what it is and how to set it
up, see the [README](../README.md).

## Overview

mdns-alias publishes extra mDNS host names for a machine, alongside whatever
mDNS responder the host already runs (systemd-resolved, Avahi,
mDNSResponder). It is a small mDNS responder of its own (RFC 6762: probing,
announcing, known-answer suppression, rate limiting, legacy unicast
replies), over IPv4 and IPv6. Its sockets share port 5353 with the host's
responder via `SO_REUSEADDR` and `SO_REUSEPORT`, which systemd-resolved
deliberately allows.

It answers any mDNS client.

## Records

Each alias is answered with this host's addresses on the interface a query
arrives on: A records for its IPv4 addresses, AAAA for its stable IPv6
addresses (not temporary, deprecated or still being checked), and an NSEC
record when one family has none, so clients do not wait for an answer that
will not come. The addresses are read from the interface rather than
configured, so none goes stale.

Earlier releases could publish each alias as a CNAME of the host's own name
instead (`--cname`). Only some clients followed it, so it was removed.

Probes, announcements and replies too large for one packet are split across
several, so the number of aliases is not limited.

## Names

Every alias is a full name ending in `.local`, used as given (a trailing
dot, as in DNS, is allowed and dropped). A name without `.local` is refused
at startup, with the fix when it is a single valid label (`"app" is not a
.local name; write app.local`); earlier releases took such a name as
relative to the host's own name (`app` as `app.myhost.local`), which made
names of several labels that resolve poorly, so that was removed along with
`--host`. Names of several labels given in full (`api.app.local`) are still
accepted, since they are valid mDNS names, but a single label before
`.local` resolves most reliably. The same name given twice, in any case, is
published once, and the names are logged at startup.

An alias may not be this machine's own `.local` name (the first label of
its host name, as `uname` gives it, plus `.local`): the host's responder
already publishes that, and mdns-alias's goodbyes on shutdown, sent with
the same addresses, would make caches drop the machine's real name.
Startup fails with `myhost.local is this machine's own name
(myhost.local); its responder already publishes it`. The host name is read
before the sandbox locks; if it cannot be read (which is logged), or makes
no valid name, the check is skipped, as it is on macOS. In Docker, `uname`
gives the container's host name: with `network_mode: host` that is the
host's own name and the check works, but otherwise it is the container ID
(or whatever `hostname:` sets), and the check protects nothing.

Each label must be only ASCII letters, digits and hyphens, and not start or
end with a hyphen, as for any host name; anything else is refused at
startup. Packets from the network are still parsed whatever their names
contain.

## Interfaces and change notifications

It answers on every interface that is up, except loopback, point-to-point
and container interfaces (`docker*`, `br-*`, `veth*`); `--interface`,
repeatable, names the interfaces to use instead.

On Linux it follows interface and address changes as the kernel reports
them (netlink), with a full rescan every 5 minutes as a safety net. When
addresses change it announces the new ones and withdraws the old. Reading
the notifications stops after 64 reads per pass, so a flood of them cannot
hold the main loop; reaching that cap counts as a change, so a rescan
follows.

Elsewhere it rescans every 30 seconds, and so does Linux if the kernel's
change notifications are unavailable: it logs `address events unavailable
(<reason>); rescanning every 30s` and falls back to polling.

Before publishing, it probes each name, and it sends goodbye packets on
SIGTERM/SIGINT so clients drop the names immediately.

A send that finds no room (a full send buffer, `ENOBUFS` from a full
device queue, `ENOMEM`) loses that packet and nothing else; the first such
drop is logged, then at most one line a minute per family. Any other
failure to multicast on an interface means it cannot be served as it is:
it is dropped, with its probing and announcing state, and a rescan follows
2 seconds later to join it again, as a new interface, if it is still
usable. If it keeps failing, each further rescan waits twice as long as
the one before, up to the usual interval, starting over once a rejoined
interface lasts a whole interval without a drop.

Which senders it listens to follows RFC 6762 section 11. A packet sent to
the mDNS group (224.0.0.251 or ff02::fb) is from the local link whatever
its source address, since link-scope multicast is never routed: overlaid
subnets, a device with the wrong netmask, or an IPv6 client on a prefix
this host never took up all still get answers. A packet sent straight to
this host (unicast, or a broadcast) is ignored unless its source is on one
of the arrival interface's subnets or link-local; the first such packet on
an interface is logged once per rescan, so a netmask that does not cover
the LAN is visible.

A reply goes by unicast (to a QU question, a query sent straight to this
host rather than to the group, or a legacy query from a port other than
5353) only to a sender on one of the interface's subnets, or
IPv6 link-local. Any other sender is answered by multicast instead, even
when it asked for unicast (section 11's "SHOULD elect to respond by
multicast anyway"); that includes an IPv4 link-local (169.254/16) sender on
an interface without such an address, which has no route back. A legacy
querier cannot hear multicast, so one that unicast cannot reach gets no
reply. Should a unicast reply to port 5353 still find no route (or no
source address), its answers go by multicast instead, within the limit of
one multicast of a record a second (section 6), which they count towards;
a defence against a probe keeps only the 250 ms gap section 6 allows
probe answers, and waits for it if need be, as it does anywhere.
A failed unicast reply never affects the interface, since anyone can ask
from an address there is no route to; the first is logged, then at most
one line a minute per family. Every reply, unicast included, leaves with
an IP TTL (hop limit) of 255, as section 11 asks. Received packets are not
checked for TTL 255: section 11 asks that only of senders.

## Sharing port 5353

Multicast packets to port 5353 reach every socket bound to it, so
mdns-alias and the host's responder both see every query and every
multicast response. A unicast packet to port 5353 reaches only one of them:
the two usually run as different users, so the kernel picks one socket
rather than spreading packets across a group (RFC 6762 section 15.1), and
which one it picks depends on the kernel and on which bound first. So:

- mdns-alias never asks for a unicast reply to its own probes, though RFC
  6762 section 8.1 says the first probe SHOULD set the QU bit: a unicast
  reply might go to the host's responder and be lost, while a multicast
  one always reaches mdns-alias. Probing takes as long either way; this
  only gives up a little multicast traffic saved.
- A query sent straight to this host's address on port 5353 (RFC 6762
  section 5.5, or `dig @<host> -p 5353`) reaches mdns-alias or the host's
  responder, not both. When mdns-alias gets one about an alias, it answers
  by unicast; when the host's responder gets it, the alias goes
  unanswered. Queries sent to the multicast group, the usual case, reach
  both.
- Unicast responses meant for the host's responder (to its own QU
  questions and probes) may be delivered to mdns-alias instead. Since
  mdns-alias never asks for one, it ignores every response sent straight
  to it (RFC 6762 section 6: unicast responses not asked for are silently
  ignored), so such a response neither reaches the host's responder nor
  counts as a conflict here. The host's responder then falls back to the
  multicast replies and retries it already relies on.

mdns-alias's own unicast replies (to QU questions, legacy queries and
queries sent straight to this host) are sent, not received, so they are
unaffected.

## Conflicts

A name conflict never stops the program. If another device starts answering
for a published name with different data, mdns-alias stops answering for
that name, logs `app.local is claimed by 192.0.2.30; probing again`,
and probes it again on every interface where it was published (RFC 6762
section 9); the other names keep answering throughout.

If the other device answers the probe (with any record of the name in
class IN: the probe asks for every type), the name is its own on that
interface: mdns-alias logs `... on <interface>; giving up on it there for
now, retrying in 5 min`, sends goodbyes for what it had published there,
and probes again 5 minutes later, so a name that is freed up is taken
back. Its other interfaces and names are unaffected.

After 15 conflicts within 10 seconds, each further probe waits at least 5
seconds (RFC 6762 section 8.1), so two misbehaving devices cannot flood the
network.

The configured name is kept and retried, never renamed: RFC 6762 suggests
picking a new name (`app-2.local`) after a conflict, which suits a printer
naming itself but not an alias someone configured and expects to resolve.

mDNS is unauthenticated, so any host on the LAN can keep an alias down by
sending a couple of forged packets every 5 minutes; it can no longer make
mdns-alias exit, and the other aliases keep working.

## Sandbox

On Linux, once its sockets are open, mdns-alias sheds everything it no
longer needs:

- rlimits: no new processes, no core dumps, and file descriptors capped just
  above those in use.
- Two netlink sockets opened before lockdown: one subscribed to link and
  address changes, and one that every rescan lists links and addresses over.
  Afterwards nothing can open a socket of any kind.
- An address-space limit just above the size in use (read from
  `/proc/self/statm`, which Docker always mounts; without `/proc` only this
  layer is skipped).
- No capabilities: the effective, permitted, inheritable and ambient sets
  are emptied, so a process started without root but with capabilities
  (systemd's `AmbientCapabilities=`, or a binary given file capabilities)
  keeps none, and CAP_NET_ADMIN, say, could not change addresses or routes
  through the netlink socket kept for rescans. The bounding set is emptied
  too when the process holds CAP_SETPCAP; without it the kernel refuses,
  which is harmless, since no-new-privs and the ban on exec leave nothing
  that could draw on it.
- Non-dumpable and no-new-privs: nothing can ptrace it or read its memory,
  and nothing it runs could gain privileges.
- Landlock: no filesystem access at all, no TCP, no abstract Unix sockets,
  no signals to other processes.
- seccomp: eighteen system calls, some limited by argument (only multicast
  socket options, writes only to stderr, never executable memory). No
  `socket()`: anything else, opening a socket included, kills the process.

It refuses to run as root. Layers the kernel does not support are skipped and
logged at startup:

```
mdns-alias: sandbox: rlimits, address-space limit, capability drop, non-dumpable, no-new-privs, landlock ABI 8, seccomp
```

`--require-sandbox` makes a missing layer fatal instead. On macOS, a
development platform here, there is no sandbox.

Build Linux binaries for musl (`x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`), as the image does. The seccomp allowlist is
tested against musl's system calls only; a glibc build is unsupported and
may be killed by its own sandbox.

## Docker notes

The image contains only the static binary. It needs the host's network to
reach the LAN, and nothing else: it runs as a non-root user, and port 5353 is
unprivileged.

The binary sets no-new-privileges on itself once started, so the compose
`no-new-privileges` option adds nothing. Leave it out: on some Docker
installs, notably the Ubuntu snap, it stops the container from starting at
all (`exec /mdns-alias: operation not permitted`), because exec'ing the
binary needs an AppArmor profile transition that the option forbids.

## Testing

`cargo test` covers the wire format, the responder and the sandbox against
the crate's own encoder and decoder. `scripts/interop-test.sh` checks the
result against another implementation, Avahi, on any Linux host with Docker
(CI runs it too). On a Docker bridge network of its own, in
documentation address ranges, it runs avahi-daemon and the image in one
network namespace, both on port 5353 as different users, with a second
avahi-daemon as another host on the link, and checks that:

- Avahi resolves the aliases over IPv4 and IPv6;
- avahi-daemon keeps its own name and still claims new ones beside
  mdns-alias;
- a name Avahi already holds is given up on that link with the logged
  conflict, while the other aliases keep answering, and Avahi probing for
  a name mdns-alias holds reports a collision;
- legacy unicast queries are answered in the shared namespace.

It also reports, for information only, which of the two port-5353 sockets
a query sent straight to the host's address reaches. That depends on the
kernel and on bind order; on the one kernel tried, it was mdns-alias, the
later IPv4 binder. Everything it creates is removed on exit.

## Standards and known deviations

mdns-alias is a responder only: it never queries and keeps no cache, and it
publishes no DNS-SD services (RFC 6763). Against RFC 6762 it implements
probing with simultaneous-probe tiebreaking, deferring to any record of the
name in class IN another host sends after the first probe goes out, and
ignoring any read before it (sections 8.1, 8.2; after a conflict the
re-probe waits 20-250 ms, so the copies the other host sent on our other
links and families are read first), two announcements a second apart (8.3),
re-announcement on address changes (8.4), conflict detection and re-probing
for the life of each name (9), goodbyes on shutdown (10.1), a multicast of
its own records with the full TTL when another host sends one of them with
less than half, a goodbye included (6.6, 10.1; never for a packet from one
of its own addresses, which is its own looped back), the cache-flush bit on
every unique record sent to port 5353 and never on legacy replies (10.2),
answers immediately for its unique records and 400-500 ms later for a query
with TC set (6, 7.2), NSEC negative answers in the restricted form (6.1),
the other address family as additional records (6.2), only the arrival
interface's addresses (6.2, 14), known-answer suppression (7.1), the
one-second multicast rate limit (6) on answers and additional records
alike, by record set, with the shorter 250 ms gap for answers to probes (a
defence the gap holds back goes out as soon as it has passed), QU and
direct unicast queries (5.4, 5.5), legacy unicast replies with the query's
ID and TTLs of at most 10 s (6.7), the source address check and IP TTL 255
on every reply (11), and the header rules of section 18 (AA set on
responses, ID 0 on multicast, non-zero opcode or rcode ignored, NSEC rdata
compressed). Received packets up to 9000 bytes are read (17). Not checking
the IP TTL of received packets is not a deviation: section 11 asks for TTL
255 only of senders.

### Deliberate deviations

Each is a choice, with the RFC clause, its requirement level, what
mdns-alias does instead, and why.

- **8.1, SHOULD: the first probe asks for a unicast reply (QU).** Probes
  never set the QU bit. Port 5353 is shared with the host's responder, and
  a unicast reply may be delivered to its socket rather than ours; section
  15.1 recommends exactly this for an implementation that is not the first
  to bind the port (see "Sharing port 5353").
- **9: once a name is established, a record of another type for it is not a
  conflict.** While probing, any record of an alias's name in class IN (the
  class probed for) from another host answers the probe (8.1), so the alias
  is given up there; records of other classes are ignored, then and later.
  Once it is established, section 9's definition (same name, type and
  class, different data) applies: a TXT or HINFO record another host starts
  sending under an alias name does not take the alias down, though the NSEC
  mdns-alias sends for other types is then wrong on that link. A CNAME for
  an alias is a conflict, since it says the name has no addresses of its
  own.
- **8.1 and 9, SHOULD and recommended: after losing a name, choose a new
  one (`app-2.local`); 14: a conflict on any interface means a new name on
  all.** The configured name is kept: it is given up on the link where
  another host holds it, kept on the others, and probed again there every
  5 minutes. An alias is configured by someone who expects that exact name
  to resolve, and a renamed alias would be useless to them (see
  "Conflicts").
- **8.1, MUST: after 15 conflicts in 10 s, wait at least 5 s before each
  further probe attempt.** The wait is applied per attempt: each attempt
  waits at least 5 s after it is requested, and no attempt waits more than
  10 s, so attempts requested at different times are not strictly 5 s
  apart across the host. This matches the RFC's own simple reading ("always
  wait five seconds after any failed probe attempt"), and the cap keeps a
  burst of forged conflicts from pushing every later attempt out of reach.
- **7.1, MUST NOT: answer with a record the querier lists as known with at
  least half its TTL.** Suppression is per record set (alias and type): a
  set is left out only if every record of it is known, and otherwise goes
  out whole. A partial set carries the cache-flush bit and would make every
  cache on the link drop the records left out (section 10.2).
- **7.2, SHOULD: keep extending the wait while TC packets keep coming.**
  The wait ends at most 2 s after the first packet, at most 32 queries are
  held per link (a TC query beyond that is answered at once), and at most
  32 questions and 64 known answers are kept per held query. These bound
  the state a querier can make mdns-alias keep. Past them a querier may
  get a record it already knows: some wasted traffic, where the RFC would
  rather accept the delay.
- **6.7, MUST: a legacy reply repeats the question.** Only the questions an
  answer is about are echoed, and a legacy query with more than 32
  questions is not answered at all. A legacy resolver asks one question,
  which is unaffected; the bounds keep the cost of encoding names chosen by
  the sender in check (a query with a few dozen long distinct names
  otherwise took over a second to answer). A legacy querier that a unicast
  reply cannot reach (section 11) gets no reply, since it cannot hear
  multicast.
- **6.2, MUST: include all addresses valid on the interface.** Only stable
  addresses are published: temporary (privacy) IPv6 addresses and deprecated
  ones are left out, as are tentative ones, which are not valid yet.
  Temporary addresses rotate and exist for outgoing connections; deprecated
  ones are on their way out.
- **8.4, SHOULD: omit goodbyes for unique records whose data changes.**
  When an interface's addresses change, goodbyes go out for the addresses
  withdrawn as well as announcements of the new set. The same path covers
  an alias that stops being served on the interface (no addresses left, or
  too big to fit), where nothing would replace the old records; where the
  new announcement does replace them, the goodbye is redundant but
  harmless.

### Known limitations

Deviations that are not choices, left for later; none stops an alias from
resolving.

- **5.4, SHOULD: multicast a QU answer the record has not been multicast
  within a quarter of its TTL.** A QU question from a reachable sender is
  always answered by unicast, so peers' caches are not refreshed and
  passive conflict detection does not see the answer.
- **6.3, SHOULD: delay answers to a query with several questions by 20-120
  ms.** Every answer goes out at once, or after the TC wait.
- **6.7 and 18.5: a legacy reply is a conventional DNS reply.** It is
  trimmed to 1440 bytes rather than 512 when the query carries no EDNS0
  OPT, and answers dropped to fit do not set TC. Only reachable with
  roughly 15 or more addresses on an interface.
- **7.4, SHOULD: drop a planned answer another host has just sent.** A
  query held for its TC known answers is answered even if another host
  multicast the same records meanwhile. Our own multicast of them
  meanwhile is different: the one-second rate limit then drops the
  deferred answer.
- **8.4, SHOULD NOT: update records more than ten times a minute.**
  Address changes are coalesced over at most 2 s and then announced, with
  no per-minute cap, so a flapping address can re-announce more often.
- **10.2 and 14: on bridged links, re-announce when our own records from
  another interface arrive with the cache-flush bit.** Not done: each
  interface announces its own set with the cache-flush bit, so
  peers on a bridged segment keep whichever set they heard last. Either set
  works.
- **17, MUST: a packet larger than the interface MTU holds one record.**
  Packets are built up to 1440 bytes whatever the MTU, so on a link with a
  smaller MTU than that plus the IP and UDP headers, a packet about many
  aliases or addresses can be fragmented with several records in it.

A goodbye for an alias given up after losing a name carries the cache-flush
bit, as section 10.2 requires of every unique record; a receiver that
applied the flush before the goodbye could drop the winning host's records
too. Receiver behaviour here is not verified.

### Not applicable

Section 5 (querying), 7.3 (duplicate question suppression), 10.3 to 10.5
(cache maintenance), 13 (enabling mDNS in resolvers), the querier halves of
6, 11 and 18.1, and the multipacket and cache-sharing concerns of 15.2 and
15.3 apply to queriers and caches, which mdns-alias does not have. There are
no shared records, so the 20-120 ms delay for shared answers and the
cache-flush rules for shared records (6, 10.2) do not arise; there is no
DNS-SD, so RFC 6763 and the SRV compression rule (18.14) do not either. No
record is larger than one packet, so fragmenting a single record (17) never
happens. Names are restricted to ASCII letters, digits and hyphens, a
subset of the UTF-8 that section 16 requires, and compared ignoring ASCII
case only. RFC 3927 and 4291 matter only for which senders count as on the
link (see "Interfaces and change notifications").
