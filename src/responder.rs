//! The mDNS protocol for a fixed set of aliases, published as the addresses
//! of the interface a query arrives on (A, AAAA, and NSEC for a missing
//! family): probing, announcing, answering, conflict detection, address
//! changes and goodbyes (RFC 6762).
//! Pure: packets and the time come in, packets to send go out, so tests
//! drive it with a fake clock. Times are milliseconds on any monotonic
//! clock.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::net::IfIndex;
use crate::wire::{self, Class, Message, Name, Question, RData, RType, Record};

pub const MDNS_PORT: u16 = 5353;
/// TTL for host name records (RFC 6762 section 10).
const TTL: u32 = 120;
/// Largest packet sent: a 1500-byte MTU less IPv6 and UDP headers, rounded
/// down.
pub const MAX_PACKET: usize = 1440;
/// Longest random wait before the first probe (RFC 6762 section 8.1).
const PROBE_WAIT_MAX: u64 = 250;
const PROBE_INTERVAL: u64 = 250;
const PROBES: u8 = 3;
const ANNOUNCE_INTERVAL: u64 = 1000;
/// TTL cap for replies to legacy unicast queries (RFC 6762 section 6.7).
const LEGACY_TTL: u32 = 10;
/// Minimum gap between multicasts of one record set on one link (RFC 6762
/// section 6).
const RATE_LIMIT: u64 = 1000;
/// The shorter gap a multicast answer to a probe keeps instead (RFC 6762
/// section 6): a defence goes out at once unless the set was multicast
/// that recently, in which case that multicast already answers the probe.
const PROBE_RATE_LIMIT: u64 = 250;
/// Wait before probing again after losing a tiebreak (RFC 6762 section 8.2).
const TIEBREAK_BACKOFF: u64 = 1000;
/// The probe restart rate limit (RFC 6762 section 8.1): once
/// `CONFLICT_LIMIT` conflicts fall within `CONFLICT_WINDOW`, each further
/// probe attempt waits at least `LIMITED_WAIT`, after the conflict and after
/// the attempt before it.
const CONFLICT_LIMIT: usize = 15;
const CONFLICT_WINDOW: u64 = 10_000;
const LIMITED_WAIT: u64 = 5000;
/// How long rival probes must keep an alias from probing before that is
/// reported.
const HELD_REPORT: u64 = 10_000;
/// Shortest wait before probing an alias again after another host's
/// response contradicted it (RFC 6762 section 9), within section 8.1's
/// 0-250 ms. A host that sends a response on several of our links (both
/// address families, say) sends the copies together; each copy read
/// before our first probe on its link is ignored there (section 8.1), so
/// this keeps the probe from going out before them. A LAN delivers them
/// within a millisecond or so of each other, and the event loop reads
/// every socket that has a packet before it sends anything due (`poll`),
/// so 20 ms leaves ample margin for scheduling while keeping most of the
/// usual random spread.
const RESET_PROBE_MIN: u64 = 20;
/// How long an alias that another host turned out to hold on a link waits
/// there before it is probed again: long enough that a host keeping the
/// name costs a few packets an hour, short enough that a name freed up is
/// taken back soon.
const LOST_RETRY: u64 = 300_000;
/// How long a removed address still counts as ours. Our own multicasts loop
/// back and may be read after the address is gone; that copy is not a
/// conflict.
const RETIRED_GRACE: u64 = 5000;
/// Shortest wait before answering a query with the TC bit set, which says
/// more known answers follow (RFC 6762 sections 6 and 7.2). The wait is
/// this plus up to `DEFER_SPREAD`, at random.
const DEFER_MIN: u64 = 400;
const DEFER_SPREAD: u64 = 100;
/// Longest a deferred answer waits after the first packet, however many
/// further TC packets extend the wait. This departs on purpose from RFC 6762
/// section 7.2, which says to keep extending the delay while TC packets
/// keep coming and accepts the delay that brings: the cap bounds how long a
/// querier's state lives here. A packet arriving at or after the cap starts
/// a fresh deferral rather than joining the old one.
const DEFER_CAP: u64 = 2000;
/// Deferred queries kept per link. A TC query beyond this is answered at
/// once, as one without TC is.
const MAX_DEFERRED: usize = 32;
/// Questions and known answers about our aliases kept per deferred query.
/// More are dropped: a dropped question goes unanswered until asked again,
/// and a dropped known answer only costs resending a record set the querier
/// already has.
const MAX_DEFERRED_QUESTIONS: usize = 32;
const MAX_DEFERRED_KNOWN: usize = 64;
/// Most questions a legacy unicast query may have to be answered; one with
/// more is ignored. A legacy resolver asks one question per query, so this
/// is far above real use. It bounds the work for a query that is not: the
/// reply echoes the questions about our aliases, and is encoded again for
/// every record `fit` drops.
const MAX_LEGACY_QUESTIONS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

/// `IPv4` or `IPv6`, for logs.
impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        })
    }
}

/// One interface in one address family. Each is probed, announced and
/// answered on separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Link {
    pub index: IfIndex,
    pub family: Family,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    Multicast,
    Unicast(SocketAddr),
}

/// Who sent a packet, as `Responder::handle` needs to know it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub addr: SocketAddr,
    /// Whether a reply may go to `addr` by unicast. False for a sender off
    /// the link's subnets, accepted only because it sent to the group (RFC
    /// 6762 section 11), and for one with no route back: a QU question of
    /// its is answered by multicast instead, and a legacy query (whose
    /// sender cannot hear multicast) not at all.
    pub unicast: bool,
    /// Whether the packet was sent straight to us (to this host's address,
    /// not the mDNS group). A query sent so is answered by unicast (RFC 6762
    /// section 5.5); a response sent so is ignored, as we never ask for
    /// unicast responses (section 6).
    pub direct: bool,
}

/// A sender a reply can reach by unicast, as any on the link's subnets,
/// that sent to the mDNS group.
impl From<SocketAddr> for Source {
    fn from(addr: SocketAddr) -> Source {
        Source {
            addr,
            unicast: true,
            direct: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Outgoing {
    pub link: Link,
    pub dest: Dest,
    pub packet: Vec<u8>,
    /// Whether this is a reply to a probe: a defence, held only to the
    /// shorter `PROBE_RATE_LIMIT` if it has to go by multicast instead
    /// (`Responder::unicast_failed`).
    pub probe: bool,
}

/// Something worth logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The second announcement of these aliases went out on this link; they
    /// are established here.
    Announced(Link, Vec<Name>),
    /// Another host answered for an alias established here with other data
    /// (RFC 6762 section 9). It is no longer answered for, and is probed
    /// again on every link where it was established.
    Conflict(Conflict),
    /// Another host answered for an alias while it was being probed on this
    /// link: the name is theirs here. The alias says goodbye to what it had
    /// published here and is not served here until it is probed again,
    /// `retry` ms from now. Other links and other aliases carry on.
    Lost {
        link: Link,
        conflict: Conflict,
        retry: u64,
    },
    /// An alias lost on this link is being probed again.
    Retry(Link, Name),
    /// Another host probed for this alias with other data and won the
    /// tiebreak; probing it starts over here in a second, or later while
    /// probes are rate-limited (`Pacer`).
    TiebreakLost(Link, Name),
    /// Other hosts' probes have kept this alias from probing on this link
    /// for `HELD_REPORT` ms and counting. Reported once per such episode,
    /// which ends when the alias probes again.
    HeldBack(Link, Name),
    /// The alias's records alone do not fit one packet on this link, so it
    /// is not probed, announced or answered there until an address change
    /// makes it fit, when it is probed afresh. Reported once each time it
    /// becomes too big.
    Oversized(Link, Name),
}

/// What one call produced.
#[derive(Debug, Default)]
pub struct Step {
    pub sends: Vec<Outgoing>,
    pub notices: Vec<Notice>,
}

/// Someone else claims one of our aliases with other data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub alias: Name,
    pub source: IpAddr,
}

/// `app.myhost.local is claimed by 192.0.2.30`, for logs.
impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is claimed by {}", self.alias, self.source)
    }
}

/// Where one alias stands on one link. Each alias moves through these on
/// its own, so one can be probed while the link's others stay established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Not served here: the interface has no stable addresses, or the
    /// alias is too big for one packet here (`AliasState::oversized`).
    Idle,
    /// `sent` probes are out; the next step is due at `due`. After the third
    /// probe, the next step is the first announcement.
    Probing {
        sent: u8,
        due: u64,
    },
    /// The first announcement is out; the second is due at `due`.
    Announcing {
        due: u64,
    },
    Announced,
    /// Another host answered our probe: the name is theirs here. Probed
    /// again from the start at `retry`.
    Lost {
        retry: u64,
    },
}

impl Phase {
    /// Whether probing is done, so the alias is answered for here.
    fn established(self) -> bool {
        matches!(self, Phase::Announcing { .. } | Phase::Announced)
    }

    /// Whether a conflicting response arriving now answers a probe of
    /// ours: one of this probe run has gone out. One received before then
    /// is ignored (RFC 6762 section 8.1).
    fn probe_answered(self) -> bool {
        matches!(self, Phase::Probing { sent, .. } if sent > 0)
    }

    /// When the next probe or announcement is due, if one is scheduled.
    fn due(self) -> Option<u64> {
        match self {
            Phase::Probing { due, .. } | Phase::Announcing { due } => Some(due),
            Phase::Lost { retry } => Some(retry),
            Phase::Idle | Phase::Announced => None,
        }
    }
}

/// One alias on one link.
#[derive(Clone, Copy, Debug)]
struct AliasState {
    phase: Phase,
    /// Its records are announced here, with the interface's current
    /// addresses, and not yet said goodbye to. Goodbyes go by this, not the
    /// phase: an alias being probed again may still be in caches.
    published: bool,
    /// Too big for one packet here with the interface's current addresses
    /// (`too_big`); reported once when it became so, and `Idle` until it
    /// fits again.
    oversized: bool,
    /// While rival probes keep an alias with no probe of ours out from
    /// probing (`Responder::tiebreak`): since when, and whether that has
    /// been reported.
    held: Option<Held>,
}

/// One episode of an alias being kept from probing by other hosts' probes.
#[derive(Clone, Copy, Debug)]
struct Held {
    since: u64,
    reported: bool,
}

/// One of the aliases, by its position in the list `Responder::new` was
/// given. Made only by `Records`, from that list, so it is always in range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AliasId(usize);

/// A query with the TC bit set, waiting for the rest of its querier's known
/// answers (RFC 6762 section 7.2).
#[derive(Debug)]
struct Deferred {
    /// The querier, which later packets are matched to by address. The port
    /// is always 5353: legacy queries are never deferred.
    source: Source,
    /// The questions and known answers about our aliases so far, from every
    /// packet of the querier's; nothing else.
    query: Message,
    /// When the first packet arrived, which `DEFER_CAP` counts from.
    first: u64,
    due: u64,
}

#[derive(Debug)]
struct LinkState {
    /// Each alias here, by `AliasId`.
    aliases: Vec<AliasState>,
    /// Queries waiting for more known answers, at most `MAX_DEFERRED`, at
    /// most one per querier address, in arrival order.
    deferred: Vec<Deferred>,
    /// When each record set (alias, type) was last multicast here.
    last_multicast: Vec<((AliasId, RType), u64)>,
    /// Record sets to multicast as soon as the rate limit allows, at most
    /// one entry per set: answers to probes held by the 250 ms gap (RFC
    /// 6762 section 6), and corrections of our records another host sent
    /// with too short a TTL (section 6.6).
    planned: Vec<Planned>,
}

/// A record set (alias, type) to multicast on a link once the rate limit
/// allows (`LinkState::plan`).
#[derive(Clone, Copy, Debug)]
struct Planned {
    key: (AliasId, RType),
    /// Whether it answers a probe, so keeps only `PROBE_RATE_LIMIT`. A
    /// correction planned for the same set becomes one: it goes out under
    /// the 250 ms gap, which then serves as both.
    probe: bool,
    /// When the rate limit allows it, counted from the set's last
    /// multicast as it stood when last planned.
    due: u64,
}

impl LinkState {
    /// Alias `id` here.
    fn alias(&self, id: AliasId) -> &AliasState {
        &self.aliases[id.0]
    }

    /// Whether alias `id` is answered for here.
    fn serves(&self, id: AliasId) -> bool {
        self.alias(id).phase.established()
    }

    /// Every record set of the aliases `ids` was just multicast.
    fn mark(&mut self, ids: &[AliasId], now: u64) {
        for &id in ids {
            for rtype in [RType::A, RType::AAAA, RType::NSEC] {
                self.set_last((id, rtype), now);
            }
        }
    }

    /// When record set `key` was last multicast here.
    fn last(&self, key: (AliasId, RType)) -> Option<u64> {
        let found = self.last_multicast.iter().find(|(k, _)| *k == key);
        found.map(|&(_, at)| at)
    }

    /// Plans record set `key`, held by the rate limit at `now`, to go out
    /// as soon as the limit allows: `PROBE_RATE_LIMIT` after its last
    /// multicast if it answers a `probe` (or an earlier plan did), else
    /// `RATE_LIMIT`. Planning again recomputes that from the latest
    /// multicast, so a multicast between two plans does not count as the
    /// answer to the later one, while any multicast of the set after the
    /// latest plan does, and the rate limit drops the planned one then.
    fn plan(&mut self, key: (AliasId, RType), probe: bool, now: u64) {
        let last = self.last(key).unwrap_or(now);
        let at = match self.planned.iter().position(|p| p.key == key) {
            Some(at) => at,
            None => {
                self.planned.push(Planned {
                    key,
                    probe: false,
                    due: now,
                });
                self.planned.len() - 1
            }
        };
        let entry = &mut self.planned[at];
        entry.probe |= probe;
        let gap = if entry.probe {
            PROBE_RATE_LIMIT
        } else {
            RATE_LIMIT
        };
        entry.due = last + gap;
    }

    /// Records that record set `key` was multicast here at `now`.
    fn set_last(&mut self, key: (AliasId, RType), now: u64) {
        match self.last_multicast.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = now,
            None => self.last_multicast.push((key, now)),
        }
    }
}

/// The aliases, and the records they are published with.
struct Records {
    aliases: Vec<Name>,
}

impl Records {
    /// The alias `name` is, ignoring case.
    fn alias_index(&self, name: &Name) -> Option<AliasId> {
        self.aliases
            .iter()
            .position(|alias| alias == name)
            .map(AliasId)
    }

    /// Every alias, in order, with its id.
    fn iter(&self) -> impl Iterator<Item = (AliasId, &Name)> {
        self.aliases
            .iter()
            .enumerate()
            .map(|(i, alias)| (AliasId(i), alias))
    }

    fn name(&self, id: AliasId) -> &Name {
        &self.aliases[id.0]
    }

    fn record(&self, id: AliasId, rdata: RData, ttl: u32, cache_flush: bool) -> Record {
        Record {
            name: self.name(id).clone(),
            class: Class::IN,
            cache_flush,
            ttl,
            rdata,
        }
    }

    /// Every record published for alias `id` on an interface with `addrs`
    /// (sorted): an A or AAAA record per address, and the NSEC if a family
    /// is missing. Empty when there are no addresses.
    fn set(&self, id: AliasId, addrs: &[IpAddr], ttl: u32, cache_flush: bool) -> Vec<Record> {
        let mut set: Vec<Record> = addrs
            .iter()
            .map(|addr| {
                let rdata = match *addr {
                    IpAddr::V4(v4) => RData::A(v4),
                    IpAddr::V6(v6) => RData::Aaaa(v6),
                };
                self.record(id, rdata, ttl, cache_flush)
            })
            .collect();
        let v4 = addrs.iter().any(IpAddr::is_ipv4);
        let v6 = addrs.iter().any(IpAddr::is_ipv6);
        if v4 != v6 {
            set.push(self.nsec(id, addrs, ttl, cache_flush));
        }
        set
    }

    /// The NSEC naming the address types alias `id` has here (RFC 6762
    /// section 6.1).
    fn nsec(&self, id: AliasId, addrs: &[IpAddr], ttl: u32, cache_flush: bool) -> Record {
        let mut types = Vec::new();
        if addrs.iter().any(IpAddr::is_ipv4) {
            types.push(RType::A);
        }
        if addrs.iter().any(IpAddr::is_ipv6) {
            types.push(RType::AAAA);
        }
        let types = types.into_iter().collect();
        let next = self.name(id).clone();
        self.record(id, RData::Nsec { next, types }, ttl, cache_flush)
    }

    /// The answers and additional records for a question of `qtype` about
    /// alias `id`, on an interface with `addrs`. A question for A gets the
    /// AAAA records (or NSEC) as additional records and the other way round
    /// (RFC 6762 section 6.2); a type the alias does not have gets the NSEC.
    fn reply(
        &self,
        id: AliasId,
        addrs: &[IpAddr],
        qtype: RType,
        ttl: u32,
        cache_flush: bool,
    ) -> (Vec<Record>, Vec<Record>) {
        let set = self.set(id, addrs, ttl, cache_flush);
        if set.is_empty() {
            return (Vec::new(), Vec::new());
        }
        if qtype == RType::ANY {
            return (set, Vec::new());
        }
        let (mut answers, mut additionals): (Vec<Record>, Vec<Record>) = set
            .into_iter()
            .partition(|r| r.rtype() == qtype && qtype != RType::NSEC);
        if !matches!(qtype, RType::A | RType::AAAA) {
            additionals.clear();
        }
        if answers.is_empty() {
            additionals.retain(|r| r.rtype() != RType::NSEC);
            answers.push(self.nsec(id, addrs, ttl, cache_flush));
        }
        (answers, additionals)
    }

    /// Whether `rec`, about one of our aliases and not a goodbye, answers
    /// a probe of ours for it (RFC 6762 section 8.1): our probes ask for
    /// ANY, so "any answer containing a record with that name, of any type,
    /// MUST be considered a conflicting response". Records of ours (from
    /// another of our interfaces, say) do not count: that is any record
    /// that does not `contradict` us, except one of a type we never
    /// publish, which can only be another host's. Only class IN counts:
    /// the probe asks about that class, and section 9's conflicts are
    /// records of our class too, so a record of another class is ignored
    /// whatever the phase (`check_response` asks this first).
    fn answers_probe(&self, rec: &Record, ours: &[IpAddr]) -> bool {
        rec.class == Class::IN
            && (self.contradicts(rec, ours) || matches!(rec.rdata, RData::Other(_)))
    }

    /// Whether `rec`, about one of our aliases, contradicts what we publish.
    /// `ours` holds every address this host publishes, on any interface.
    fn contradicts(&self, rec: &Record, ours: &[IpAddr]) -> bool {
        match &rec.rdata {
            RData::A(addr) => !ours.contains(&IpAddr::V4(*addr)),
            RData::Aaaa(addr) => !ours.contains(&IpAddr::V6(*addr)),
            // An NSEC naming only address types agrees with us; anything
            // else claims the name has other data.
            RData::Nsec { types, .. } => {
                types.is_empty() || types.iter().any(|t| !matches!(t, RType::A | RType::AAAA))
            }
            // A CNAME says the name has no address records of its own.
            RData::Cname(_) => true,
            RData::Other(raw) => {
                matches!(
                    raw.rtype(),
                    RType::A | RType::AAAA | RType::NSEC | RType::CNAME
                )
            }
        }
    }
}

/// The question type standing for `qtype` in `Records::reply`: every type
/// `reply` treats alike maps to one, so a query asks each alias at most
/// four different things: A, AAAA, ANY, and any other type, which gets the
/// NSEC alone.
fn asked(qtype: RType) -> RType {
    match qtype {
        RType::A | RType::AAAA | RType::ANY => qtype,
        _ => RType::NSEC,
    }
}

/// What `build` assembles for an interface.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Probes: an ANY question per alias, with the proposed records in the
    /// authority section (RFC 6762 section 8.1). Never with the QU bit,
    /// though section 8.1 says the first one SHOULD have it: the port is
    /// shared with the host's own responder, and a unicast reply to port
    /// 5353 reaches only one of the sockets bound to it, maybe not ours
    /// (section 15.1). A multicast reply reaches every one of them.
    Probe,
    /// Unsolicited responses with every record; TTL 0 makes them goodbyes.
    Announce { ttl: u32 },
}

/// The message of `kind` for alias `id` on an interface with `addrs`, or
/// `None` if it has no records there.
fn part(records: &Records, id: AliasId, addrs: &[IpAddr], kind: Kind) -> Option<Message> {
    match kind {
        Kind::Probe => {
            let authorities = records.set(id, addrs, TTL, false);
            (!authorities.is_empty()).then(|| Message {
                questions: vec![Question {
                    name: records.name(id).clone(),
                    qtype: RType::ANY,
                    qclass: Class::IN,
                    unicast_response: false,
                }],
                authorities,
                ..Message::default()
            })
        }
        Kind::Announce { ttl } => {
            let answers = records.set(id, addrs, ttl, true);
            (!answers.is_empty()).then(|| Message {
                is_response: true,
                answers,
                ..Message::default()
            })
        }
    }
}

/// The aliases whose records on an interface with `addrs` do not fit one
/// packet, so are not served there at all: not probed, announced, answered
/// or said goodbye to. Decided once, by the larger of an alias's probe and
/// announcement alone. The probe is the larger by a few bytes: it names the
/// alias in a question (4 bytes more than the name) and every record by a
/// pointer, where the announcement names it in its first record. A reply
/// for one alias holds at most the announcement's records, and goodbyes and
/// legacy replies differ only in TTL and the cache-flush bit, so whatever
/// passes this fits as any of them.
fn too_big(records: &Records, addrs: &[IpAddr]) -> Vec<AliasId> {
    let kinds = [Kind::Probe, Kind::Announce { ttl: TTL }];
    records
        .iter()
        .map(|(id, _)| id)
        .filter(|&id| {
            kinds.iter().any(|&kind| {
                part(records, id, addrs, kind).is_some_and(|m| wire::encode(&m).len() > MAX_PACKET)
            })
        })
        .collect()
}

/// The messages in `parts` (each an alias and what to send for it, all
/// probes or all announcements) on an interface with `addrs`, packed into
/// packets. The aliases must not be `too_big` there.
fn build(records: &Records, addrs: &[IpAddr], parts: &[(AliasId, Kind)]) -> Vec<Vec<u8>> {
    let is_response = matches!(parts.first(), Some((_, Kind::Announce { .. })));
    let parts = parts
        .iter()
        .filter_map(|&(id, kind)| part(records, id, addrs, kind).map(|m| (id, m)))
        .collect();
    let (packets, left) = pack(is_response, parts);
    debug_assert!(left.is_empty(), "too_big let through {left:?}");
    packets
}

/// Goodbyes for what each alias in `withdrawn` published on an interface
/// with `old` addresses and no longer does: each comes with the addresses
/// it keeps publishing there, empty if none.
fn retired(records: &Records, old: &[IpAddr], withdrawn: &[(AliasId, &[IpAddr])]) -> Vec<Vec<u8>> {
    let parts = withdrawn
        .iter()
        .filter_map(|&(id, new)| {
            // Both sets are built here from the same names, so equal data
            // (which includes the type) means the same record. NSEC data
            // compares as sets: Types are always sorted and without
            // duplicates.
            let kept: Vec<RData> = records
                .set(id, new, TTL, true)
                .into_iter()
                .map(|r| r.rdata)
                .collect();
            let answers: Vec<Record> = records
                .set(id, old, 0, true)
                .into_iter()
                .filter(|r| !kept.contains(&r.rdata))
                .collect();
            (!answers.is_empty()).then(|| {
                (
                    id,
                    Message {
                        answers,
                        ..Message::default()
                    },
                )
            })
        })
        .collect();
    pack(true, parts).0
}

/// Packs `parts` (one per alias) into as few queries or responses of at
/// most `MAX_PACKET` bytes as fit, in order, never splitting a part.
/// Returns the encoded packets and the aliases whose part alone is too big.
/// A part is moved into the open message and, if that overflows, split
/// back out by the section lengths recorded beforehand.
fn pack(is_response: bool, parts: Vec<(AliasId, Message)>) -> (Vec<Vec<u8>>, Vec<AliasId>) {
    let mut packets = Vec::new();
    let mut too_big = Vec::new();
    // The open message and its encoding.
    let mut current: Option<(Message, Vec<u8>)> = None;
    for (alias, mut part) in parts {
        if let Some((open, packet)) = &mut current {
            let at = sizes(open);
            merge(open, &mut part);
            let trial = wire::encode(open);
            if trial.len() <= MAX_PACKET {
                *packet = trial;
                continue;
            }
            // Take the part back out again, unchanged.
            part = Message {
                questions: open.questions.split_off(at[0]),
                answers: open.answers.split_off(at[1]),
                authorities: open.authorities.split_off(at[2]),
                additionals: open.additionals.split_off(at[3]),
                ..Message::default()
            };
            packets.extend(current.take().map(|(_, packet)| packet));
        }
        let mut alone = Message {
            is_response,
            ..Message::default()
        };
        merge(&mut alone, &mut part);
        let packet = wire::encode(&alone);
        if packet.len() <= MAX_PACKET {
            current = Some((alone, packet));
        } else {
            too_big.push(alias);
        }
    }
    packets.extend(current.map(|(_, packet)| packet));
    (packets, too_big)
}

/// The lengths of `msg`'s four sections, in wire order.
fn sizes(msg: &Message) -> [usize; 4] {
    [
        msg.questions.len(),
        msg.answers.len(),
        msg.authorities.len(),
        msg.additionals.len(),
    ]
}

/// Moves `part`'s questions and records to the ends of `into`'s sections.
fn merge(into: &mut Message, part: &mut Message) {
    into.questions.append(&mut part.questions);
    into.answers.append(&mut part.answers);
    into.authorities.append(&mut part.authorities);
    into.additionals.append(&mut part.additionals);
}

/// A legacy reply must be one packet: drop additional records, then
/// answers, until it fits with at least one answer left.
///
/// `legacy_reply` has already cut `msg`'s questions to those with an
/// answer. The first pass keeps the questions as they are, so the querier
/// gets its question back (RFC 6762 section 6.7) for as long as that
/// fits. The second pass also drops, with each answer it drops, the
/// questions no answer left is about, so the two passes differ only once
/// answers have had to go: the querier still gets its ID back with answers
/// to what it asked about us, and a resolver matching the reply to its own
/// question still finds it. `None` if no answer fits even then, in which
/// case nothing is sent. That is not expected to happen: an alias is
/// served only where its probe, which holds its name and every record of
/// it, fits one packet (`too_big`), and the at most `MAX_LEGACY_QUESTIONS`
/// questions about one alias are a few bytes each, its name being a
/// pointer after the first.
fn fit(msg: Message) -> Option<Vec<u8>> {
    trim(msg.clone(), false).or_else(|| trim(msg, true))
}

/// Drops `msg`'s additional records, then its answers, until it fits one
/// packet with an answer left. With `answered_only`, a question no answer
/// left is about is dropped too.
fn trim(mut msg: Message, answered_only: bool) -> Option<Vec<u8>> {
    loop {
        if answered_only {
            let answers = &msg.answers;
            msg.questions
                .retain(|q| answers.iter().any(|a| a.name == q.name));
        }
        let packet = wire::encode(&msg);
        if packet.len() <= MAX_PACKET {
            return (!msg.answers.is_empty()).then_some(packet);
        }
        if msg.additionals.pop().is_none() {
            if msg.answers.len() <= 1 {
                return None;
            }
            msg.answers.pop();
        }
    }
}

/// Records about our aliases, each with the alias it is about, which keys
/// the rate limit and the packing of a reply.
type Tagged = Vec<(AliasId, Record)>;

/// The answers and additional records for `msg`'s questions about our
/// aliases on an interface with `addrs`, each record once and none in both
/// sections, and whether every such question asked for a unicast response.
///
/// Each alias is looked up once per kind of question (`asked`),
/// and not at all after an ANY question, which already brought its whole
/// set: a query repeating one question many times costs about what one
/// question does, not that many times the set.
fn collect(
    records: &Records,
    msg: &Message,
    addrs: &[IpAddr],
    ttl: u32,
    cache_flush: bool,
) -> (Tagged, Tagged, bool) {
    let mut answers: Tagged = Vec::new();
    let mut additionals: Tagged = Vec::new();
    let mut all_unicast = true;
    let mut done: Vec<(AliasId, RType)> = Vec::new();
    for q in &msg.questions {
        if !matches!(q.qclass, Class::IN | Class::ANY) {
            continue;
        }
        let Some(id) = records.alias_index(&q.name) else {
            continue;
        };
        all_unicast &= q.unicast_response;
        let kind = asked(q.qtype);
        if done.contains(&(id, kind)) || done.contains(&(id, RType::ANY)) {
            continue;
        }
        done.push((id, kind));
        let (asked, extra) = records.reply(id, addrs, kind, ttl, cache_flush);
        for rec in asked {
            if !answers.iter().any(|(_, r)| *r == rec) {
                answers.push((id, rec));
            }
        }
        for rec in extra {
            if !additionals.iter().any(|(_, r)| *r == rec) {
                additionals.push((id, rec));
            }
        }
    }
    additionals.retain(|(_, r)| !answers.iter().any(|(_, a)| a == r));
    (answers, additionals, all_unicast)
}

/// Known-answer suppression (RFC 6762 section 7.1), by record set: drops
/// from `records` each set (alias, type) whose every record the querier
/// lists in `known` with at least half its TTL left, and keeps every other
/// set whole. Our sets are unique and carry the cache-flush bit, and a
/// reply with only part of one would make every cache on the link flush
/// the rest (section 10.2), so a set is sent entire or not at all. The
/// type is part of the data, so equal data means the same type.
fn suppress_known(records: &mut Tagged, known: &[Record]) {
    let is_known = |rec: &Record| {
        known.iter().any(|k| {
            k.name == rec.name && k.class == rec.class && k.rdata == rec.rdata && k.ttl >= TTL / 2
        })
    };
    let wanted: Vec<(AliasId, RType)> = records
        .iter()
        .filter(|(_, rec)| !is_known(rec))
        .map(|(id, rec)| (*id, rec.rtype()))
        .collect();
    records.retain(|(id, rec)| wanted.contains(&(*id, rec.rtype())));
}

/// The multicast rate limit (RFC 6762 section 6): drops answers whose
/// record set (alias, type) was multicast on this link less than
/// `RATE_LIMIT` ago, or `PROBE_RATE_LIMIT` ago if they defend against a
/// `probe`, and notes the rest as multicast at `now`. Keyed by record set,
/// so a set is dropped or kept whole.
///
/// A probe answer held by the shorter gap is not lost: the caller plans it
/// first (`plan_probe_answers`).
fn rate_limit(state: &mut LinkState, answers: &mut Tagged, probe: bool, now: u64) {
    let gap = if probe { PROBE_RATE_LIMIT } else { RATE_LIMIT };
    answers.retain(|&(id, ref r)| state.last((id, r.rtype())).is_none_or(|t| now >= t + gap));
    for (id, rec) in answers.iter() {
        state.set_last((*id, rec.rtype()), now);
    }
}

/// Section 6 lets a multicast answer to a probe be delayed only as far as
/// the 250 ms gap requires: plans each set of `answers` that `rate_limit`
/// is about to hold back for that, so it goes out once the gap has passed
/// (`Responder::poll`). A prober counts only responses sent after its
/// probe, so an earlier multicast of the set is no answer to it.
fn plan_probe_answers(state: &mut LinkState, answers: &Tagged, now: u64) {
    for (id, rec) in answers {
        let key = (*id, rec.rtype());
        if state.last(key).is_some_and(|t| now < t + PROBE_RATE_LIMIT) {
            state.plan(key, true, now);
        }
    }
}

/// The multicast rate limit for the additional records of a reply whose
/// `answers` have been through `rate_limit`: drops those of aliases with no
/// answers left (which `reply_packets` would leave out anyway), then holds
/// the rest to the one-second limit by record set, as answers are, and
/// notes them as multicast. The section 6 limit is on every record
/// multicast, not only answers; the shorter gap for probe answers does not
/// extend to records sent alongside them.
fn limit_additionals(state: &mut LinkState, answers: &Tagged, additionals: &mut Tagged, now: u64) {
    additionals.retain(|(id, _)| answers.iter().any(|(a, _)| a == id));
    rate_limit(state, additionals, false, now);
}

/// Our record set `key` (alias, type) on an interface with `addrs`, as
/// sent to port 5353, tagged for `reply_packets`. Empty if the alias has no
/// records of that type there.
fn record_set(records: &Records, key: (AliasId, RType), addrs: &[IpAddr]) -> Tagged {
    let (id, rtype) = key;
    let set = records.set(id, addrs, TTL, true).into_iter();
    set.filter(|r| r.rtype() == rtype)
        .map(|r| (id, r))
        .collect()
}

/// A legacy unicast reply (RFC 6762 section 6.7): one packet, echoing the
/// query's ID and its questions that an answer is about, as `fit` trims it;
/// `None` if nothing fits.
///
/// Only those questions are echoed: a legacy resolver asks one question,
/// which is about our alias if we answer at all, and leaving out the rest
/// keeps names we did not choose out of the encoder. Compressing many long
/// distinct names costs far more than their size suggests (a query with a
/// few dozen took over a second to answer), and a query of any size could
/// be made that way.
fn legacy_reply(msg: &Message, answers: Tagged, additionals: Tagged) -> Option<Vec<u8>> {
    let mut questions = msg.questions.clone();
    questions.retain(|q| answers.iter().any(|(_, a)| a.name == q.name));
    fit(Message {
        id: msg.id,
        is_response: true,
        questions,
        answers: answers.into_iter().map(|(_, r)| r).collect(),
        additionals: additionals.into_iter().map(|(_, r)| r).collect(),
        ..Message::default()
    })
}

/// The packets of an mDNS reply: one part per alias with answers, in alias
/// order, packed. Additional records for an alias with no answers left are
/// dropped.
fn reply_packets(records: &Records, answers: Tagged, additionals: Tagged) -> Vec<Vec<u8>> {
    let mut parts: Vec<Message> = records.iter().map(|_| Message::default()).collect();
    for (id, rec) in answers {
        parts[id.0].answers.push(rec);
    }
    for (id, rec) in additionals {
        parts[id.0].additionals.push(rec);
    }
    let parts = records
        .iter()
        .zip(parts)
        .filter(|(_, part)| !part.answers.is_empty())
        .map(|((id, _), part)| (id, part))
        .collect();
    pack(true, parts).0
}

fn multicast(link: Link, packet: Vec<u8>) -> Outgoing {
    Outgoing {
        link,
        dest: Dest::Multicast,
        packet,
        probe: false,
    }
}

fn addrs_for(addrs: &[(IfIndex, Vec<IpAddr>)], index: IfIndex) -> &[IpAddr] {
    addrs
        .iter()
        .find(|(i, _)| *i == index)
        .map_or(&[], |(_, list)| list.as_slice())
}

/// The probe restart rate limit (RFC 6762 section 8.1), for the whole host:
/// "If fifteen conflicts occur within any ten-second period, then the host
/// MUST wait at least five seconds before each successive additional probe
/// attempt." A conflict is any probe that failed or record that had to be
/// probed again: a lost tiebreak, another host answering a probe, or
/// another host answering for an established alias. The attempts it
/// spaces are the probe runs those start, and the retries of lost aliases;
/// probing a new link or an alias that fits again is not a retry, so is not
/// held back.
#[derive(Debug, Default)]
struct Pacer {
    /// When the latest conflicts happened, oldest first, at most
    /// `CONFLICT_LIMIT` of them.
    conflicts: Vec<u64>,
    /// While limited, the earliest the next probe attempt may start.
    next: u64,
}

impl Pacer {
    fn conflict(&mut self, now: u64) {
        if self.conflicts.len() == CONFLICT_LIMIT {
            self.conflicts.remove(0);
        }
        self.conflicts.push(now);
    }

    /// Whether `CONFLICT_LIMIT` conflicts happened in the `CONFLICT_WINDOW`
    /// before `now`.
    fn limited(&self, now: u64) -> bool {
        self.conflicts.len() == CONFLICT_LIMIT && now < self.conflicts[0] + CONFLICT_WINDOW
    }

    /// When a probe attempt that would start `wait` after `now` may start.
    /// Attempts started together, such as one alias on several links, are
    /// one attempt: the caller asks once and uses the answer for each.
    ///
    /// While limited, the five seconds hold per attempt: each attempt waits
    /// at least `LIMITED_WAIT` after its own request. `next` is clamped to
    /// at most two waits past `now`, so no burst of conflicts, forged or
    /// not, can push every later attempt out of reach (an attempt waits at
    /// most `2 * LIMITED_WAIT`). The cost is that attempts are not strictly
    /// five seconds apart host-wide: requests made at different times can
    /// land closer together than that.
    fn attempt(&mut self, now: u64, wait: u64) -> u64 {
        if !self.limited(now) {
            return now + wait;
        }
        let due = (now + wait.max(LIMITED_WAIT)).max(self.next);
        self.next = (due + LIMITED_WAIT).min(now + 2 * LIMITED_WAIT);
        due
    }
}

pub struct Responder {
    records: Records,
    links: BTreeMap<Link, LinkState>,
    /// Each interface's stable addresses, by index, sorted.
    addrs: Vec<(IfIndex, Vec<IpAddr>)>,
    /// Addresses no interface has any more, and when each was removed.
    retired: Vec<(IpAddr, u64)>,
    /// Notices from `add_link`, which returns none, for the next `poll`.
    pending: Vec<Notice>,
    pacer: Pacer,
    /// xorshift64 state, for probe start jitter. Never zero.
    rng: u64,
}

impl Responder {
    /// The aliases must be distinct ignoring case, as `cli::parse` makes
    /// them.
    pub fn new(aliases: Vec<Name>, seed: u64) -> Responder {
        debug_assert!(
            aliases
                .iter()
                .enumerate()
                .all(|(i, alias)| !aliases[..i].contains(alias)),
            "aliases repeat ignoring case"
        );
        Responder {
            records: Records { aliases },
            links: BTreeMap::new(),
            addrs: Vec::new(),
            retired: Vec::new(),
            pending: Vec::new(),
            pacer: Pacer::default(),
            rng: seed | 1,
        }
    }

    /// Starts probing every alias together on a newly usable link, after a
    /// random 0-250 ms wait so hosts starting together do not probe in
    /// lockstep. A link with no stable addresses waits for them instead.
    /// An alias too big for one packet here is reported (by the next
    /// `poll`) and left out.
    pub fn add_link(&mut self, link: Link, now: u64) {
        let due = now + self.random(PROBE_WAIT_MAX + 1);
        let addrs = addrs_for(&self.addrs, link.index);
        let waiting = addrs.is_empty();
        let big = too_big(&self.records, addrs);
        let mut aliases = Vec::new();
        for (id, alias) in self.records.iter() {
            let oversized = big.contains(&id);
            if oversized {
                self.pending.push(Notice::Oversized(link, alias.clone()));
            }
            let phase = if waiting || oversized {
                Phase::Idle
            } else {
                Phase::Probing { sent: 0, due }
            };
            aliases.push(AliasState {
                phase,
                published: false,
                oversized,
                held: None,
            });
        }
        let state = LinkState {
            aliases,
            deferred: Vec::new(),
            last_multicast: Vec::new(),
            planned: Vec::new(),
        };
        self.links.insert(link, state);
    }

    /// Forgets `link`, with any answers deferred there.
    pub fn remove_link(&mut self, link: Link) {
        self.links.remove(&link);
    }

    /// Interface `index` now has these stable addresses. On its links,
    /// aliases that are established say goodbye to what is gone and announce
    /// the new set twice, with no probing; aliases still probing keep
    /// probing, with the new set; waiting ones start probing; and with
    /// nothing left, every alias waits again.
    ///
    /// Which aliases are too big for one packet (`too_big`) is decided
    /// again: one that becomes so is reported and gets goodbyes for all it
    /// had; one that fits again is probed on its own, three times before it
    /// is announced, while the link's other aliases carry on.
    ///
    /// An alias that is published but no longer established here (being
    /// probed again) gets goodbyes for everything it had: what it will
    /// announce once probed is announced then.
    ///
    /// An empty set, as for an interface that is gone, drops the interface's
    /// entry: no entry and an empty one mean the same, and interface indexes
    /// are not reused, so keeping it would grow the list forever.
    pub fn set_addresses(&mut self, index: IfIndex, mut addrs: Vec<IpAddr>, now: u64) -> Step {
        crate::order::sort(&mut addrs);
        addrs.dedup();
        let at = self.addrs.iter().position(|(i, _)| *i == index);
        let old = match at {
            Some(at) if addrs.is_empty() => self.addrs.remove(at).1,
            Some(at) => std::mem::replace(&mut self.addrs[at].1, addrs.clone()),
            None if addrs.is_empty() => Vec::new(),
            None => {
                self.addrs.push((index, addrs.clone()));
                Vec::new()
            }
        };
        self.retired.retain(|&(_, at)| now < at + RETIRED_GRACE);
        for addr in old
            .iter()
            .filter(|a| !self.addrs.iter().any(|(_, v)| v.contains(a)))
        {
            match self.retired.iter_mut().find(|(a, _)| a == addr) {
                Some(entry) => entry.1 = now,
                None => self.retired.push((*addr, now)),
            }
        }
        let mut step = Step::default();
        if old == addrs {
            return step;
        }
        let due = now + self.random(PROBE_WAIT_MAX + 1);
        let now_big = too_big(&self.records, &addrs);
        let records = &self.records;
        for (&link, state) in self.links.iter_mut().filter(|(l, _)| l.index == index) {
            let mut withdrawn: Vec<(AliasId, &[IpAddr])> = Vec::new();
            let mut announce = Vec::new();
            for ((id, name), alias) in records.iter().zip(&mut state.aliases) {
                let big = now_big.contains(&id);
                if big && !alias.oversized {
                    step.notices.push(Notice::Oversized(link, name.clone()));
                }
                alias.oversized = big;
                alias.phase = match alias.phase {
                    _ if big || addrs.is_empty() => Phase::Idle,
                    // Waiting, or fits again: never probed with these
                    // records, so probed from the start, as on a new link.
                    Phase::Idle => Phase::Probing { sent: 0, due },
                    Phase::Announcing { .. } | Phase::Announced => {
                        announce.push(id);
                        Phase::Announcing {
                            due: now + ANNOUNCE_INTERVAL,
                        }
                    }
                    // Lost stays lost until its retry while the interface
                    // has addresses that fit: the other host likely holds
                    // the name whatever they are. One that loses all its
                    // addresses, or whose alias becomes too big and then
                    // fits again, is `Idle` first and so probes afresh,
                    // which is intended.
                    other @ (Phase::Probing { .. } | Phase::Lost { .. }) => other,
                };
                if alias.published {
                    let keeps = alias.phase.established();
                    withdrawn.push((id, if keeps { &addrs } else { &[] }));
                    alias.published = keeps;
                }
            }
            for packet in retired(records, &old, &withdrawn) {
                step.sends.push(multicast(link, packet));
            }
            let parts: Vec<_> = announce
                .iter()
                .map(|&id| (id, Kind::Announce { ttl: TTL }))
                .collect();
            for packet in build(records, &addrs, &parts) {
                step.sends.push(multicast(link, packet));
            }
            state.mark(&announce, now);
        }
        step
    }

    /// Sends whatever probe, announcement, deferred answer or TTL
    /// correction (`correct_ttl`) has come due, and starts probing again
    /// any lost alias whose retry has come. The aliases due together on a
    /// link share packets.
    pub fn poll(&mut self, now: u64) -> Step {
        let mut step = Step {
            notices: std::mem::take(&mut self.pending),
            ..Step::default()
        };
        let records = &self.records;
        for (&link, state) in &mut self.links {
            let mut probes = Vec::new();
            let mut announces = Vec::new();
            let mut done = Vec::new();
            for ((id, name), alias) in records.iter().zip(&mut state.aliases) {
                if !matches!(alias.phase, Phase::Probing { sent: 0, .. }) {
                    alias.held = None;
                }
                if let Phase::Lost { retry } = alias.phase
                    && now >= retry
                {
                    let wait = xorshift(&mut self.rng, PROBE_WAIT_MAX + 1);
                    // One call per link: an alias lost on two links at the
                    // same instant counts as two attempts. Rare, and it
                    // only matters while limited.
                    let due = self.pacer.attempt(now, wait);
                    alias.phase = Phase::Probing { sent: 0, due };
                    step.notices.push(Notice::Retry(link, name.clone()));
                }
                match alias.phase {
                    Phase::Probing { sent, due } if now >= due && sent < PROBES => {
                        alias.phase = Phase::Probing {
                            sent: sent + 1,
                            due: now + PROBE_INTERVAL,
                        };
                        probes.push((id, Kind::Probe));
                    }
                    Phase::Probing { due, .. } if now >= due => {
                        alias.phase = Phase::Announcing {
                            due: now + ANNOUNCE_INTERVAL,
                        };
                        alias.published = true;
                        announces.push((id, Kind::Announce { ttl: TTL }));
                    }
                    Phase::Announcing { due } if now >= due => {
                        alias.phase = Phase::Announced;
                        announces.push((id, Kind::Announce { ttl: TTL }));
                        done.push(name.clone());
                    }
                    _ => {}
                }
            }
            let ids: Vec<AliasId> = announces.iter().map(|&(id, _)| id).collect();
            state.mark(&ids, now);
            let addrs = addrs_for(&self.addrs, link.index);
            for packet in build(records, addrs, &probes)
                .into_iter()
                .chain(build(records, addrs, &announces))
            {
                step.sends.push(multicast(link, packet));
            }
            if !done.is_empty() {
                step.notices.push(Notice::Announced(link, done));
            }
        }
        for (&link, state) in &mut self.links {
            let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut state.planned)
                .into_iter()
                .partition(|p| now >= p.due);
            state.planned = waiting;
            let addrs = addrs_for(&self.addrs, link.index);
            let mut sets: Tagged = Vec::new();
            for probe in [true, false] {
                let mut part: Tagged = due
                    .iter()
                    .filter(|p| p.probe == probe && state.serves(p.key.0))
                    .flat_map(|p| record_set(records, p.key, addrs))
                    .collect();
                // A multicast of the set since it was planned already did
                // its job, and the rate limit drops it. Planned sets go
                // out alone, without additional records: a defence or a
                // correction needs only the set itself.
                rate_limit(state, &mut part, probe, now);
                sets.append(&mut part);
            }
            for packet in reply_packets(records, sets, Vec::new()) {
                step.sends.push(multicast(link, packet));
            }
        }
        let mut ready = Vec::new();
        for (&link, state) in &mut self.links {
            let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut state.deferred)
                .into_iter()
                .partition(|d| now >= d.due);
            state.deferred = waiting;
            ready.extend(due.into_iter().map(|d| (link, d)));
        }
        for (link, d) in ready {
            self.answer(&d.query, link, d.source, now, &mut step);
        }
        step
    }

    /// When `poll` next has something to do: the earliest probe,
    /// announcement, deferred answer, TTL correction or retry of a lost
    /// alias due on any link, which may already have passed. `None` while
    /// nothing is scheduled; only `handle`, `add_link` and `set_addresses`
    /// schedule more.
    pub fn next_due(&self) -> Option<u64> {
        self.links
            .values()
            .flat_map(|state| {
                let phases = state.aliases.iter().filter_map(|a| a.phase.due());
                let planned = state.planned.iter().map(|p| p.due);
                phases
                    .chain(state.deferred.iter().map(|d| d.due))
                    .chain(planned)
            })
            .min()
    }

    /// Handles one received packet. Packets on links we do not serve, and
    /// malformed ones, are ignored.
    pub fn handle(
        &mut self,
        packet: &[u8],
        link: Link,
        source: impl Into<Source>,
        now: u64,
    ) -> Step {
        let source = source.into();
        let mut step = Step::default();
        if !self.links.contains_key(&link) {
            return step;
        }
        let Some(msg) = wire::parse(packet) else {
            return step;
        };
        if msg.is_response {
            // Responses not from port 5353 MUST be ignored (RFC 6762 section
            // 6), so a stray tool's reply cannot take our names. So must
            // unicast responses not asked for, and we never ask: one sent
            // straight to us was meant for the host's responder, which
            // shares the port, or for no one.
            if source.addr.port() == MDNS_PORT && !source.direct {
                self.check_response(&msg, link, source.addr, now, &mut step);
            }
        } else {
            self.tiebreak(&msg, link, now, &mut step);
            if !self.defer(&msg, link, source, now) {
                self.answer(&msg, link, source, now, &mut step);
            }
        }
        step
    }

    /// Every address this host publishes on any interface, and those it
    /// stopped publishing less than RETIRED_GRACE ago, which may still be in
    /// flight or cached.
    fn own_addresses(&self, now: u64) -> Vec<IpAddr> {
        let mut ours: Vec<IpAddr> = Vec::new();
        let current = self.addrs.iter().flat_map(|(_, list)| list.iter());
        let recent = self
            .retired
            .iter()
            .filter(|&&(_, at)| now < at + RETIRED_GRACE)
            .map(|(addr, _)| addr);
        for addr in current.chain(recent) {
            if !ours.contains(addr) {
                ours.push(*addr);
            }
        }
        ours
    }

    /// Anyone answering for one of our aliases with data that contradicts
    /// ours is in conflict with us (RFC 6762 section 9), and while we probe
    /// for it, anyone sending a record of its name at all has answered our
    /// probe (section 8.1, `answers_probe`). Goodbyes withdraw rather than
    /// claim, and our own records, looped back or from another of our
    /// interfaces, agree with us (`contradicts`). Each alias named is
    /// handled once per packet, by where it stands on the link the packet
    /// came in on:
    ///
    /// - Established, with data that contradicts ours: it is reset to
    ///   probing at once, as section 9 requires, on every link where it is
    ///   established, since it is one name however many links it is on.
    ///   It is no longer answered for until probed; what it published
    ///   stays published, so goodbyes still cover it.
    /// - Probing, with a probe of this run out, and any record of the
    ///   name: the other host answered it, and section 8.1 has us defer. The
    ///   alias is lost on this link alone: it says goodbye to anything it
    ///   had published here and waits `LOST_RETRY` before probing again.
    ///   Its other links carry on.
    /// - Anything else (waiting, too big, lost already, about to probe with
    ///   nothing sent yet; or established, with a record of a type we do
    ///   not publish, such as TXT, which section 9 does not count): nothing
    ///   to defend here. A probe yet to go out will be answered by a host
    ///   that holds the name (section 8.1 has responses from before the
    ///   first probe ignored). That includes the copies of a response that
    ///   sent an alias back to probing which the other host sent on our
    ///   other links (its other address family, say): the re-probe waits
    ///   at least `RESET_PROBE_MIN`, so they are read before it.
    ///
    /// A conflict on a link where the alias is not established leaves its
    /// other links alone: were the links different networks, the other
    /// host's traffic on one would otherwise keep resetting the name on the
    /// others.
    ///
    /// Records that agree with ours but carry too short a TTL, from a
    /// source that is not one of our addresses, are corrected afterwards
    /// (`correct_ttl`).
    fn check_response(
        &mut self,
        msg: &Message,
        link: Link,
        source: SocketAddr,
        now: u64,
        step: &mut Step,
    ) {
        let ours = self.own_addresses(now);
        // Each alias the packet answers a probe for, and whether it also
        // contradicts us.
        let mut claimed: Vec<(AliasId, bool)> = Vec::new();
        for rec in msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
        {
            if rec.ttl == 0 {
                continue;
            }
            let Some(id) = self.records.alias_index(&rec.name) else {
                continue;
            };
            if !self.records.answers_probe(rec, &ours) {
                continue;
            }
            let contradicts = self.records.contradicts(rec, &ours);
            match claimed.iter_mut().find(|(c, _)| *c == id) {
                Some(entry) => entry.1 |= contradicts,
                None => claimed.push((id, contradicts)),
            }
        }
        for (id, contradicts) in claimed {
            let Some(state) = self.links.get_mut(&link) else {
                return;
            };
            let conflict = Conflict {
                alias: self.records.name(id).clone(),
                source: source.ip(),
            };
            let alias = &mut state.aliases[id.0];
            match alias.phase {
                phase if phase.probe_answered() => {
                    self.pacer.conflict(now);
                    alias.phase = Phase::Lost {
                        retry: now + LOST_RETRY,
                    };
                    if alias.published {
                        alias.published = false;
                        let addrs = addrs_for(&self.addrs, link.index);
                        let bye = [(id, Kind::Announce { ttl: 0 })];
                        for packet in build(&self.records, addrs, &bye) {
                            step.sends.push(multicast(link, packet));
                        }
                    }
                    step.notices.push(Notice::Lost {
                        link,
                        conflict,
                        retry: LOST_RETRY,
                    });
                }
                phase if phase.established() && contradicts => {
                    self.pacer.conflict(now);
                    let spread = PROBE_WAIT_MAX - RESET_PROBE_MIN + 1;
                    let wait = RESET_PROBE_MIN + xorshift(&mut self.rng, spread);
                    let due = self.pacer.attempt(now, wait);
                    for state in self.links.values_mut() {
                        let alias = &mut state.aliases[id.0];
                        if alias.phase.established() {
                            alias.phase = Phase::Probing { sent: 0, due };
                        }
                    }
                    step.notices.push(Notice::Conflict(conflict));
                }
                _ => {}
            }
        }
        if !ours.contains(&source.ip()) {
            self.correct_ttl(msg, link, now, step);
        }
    }

    /// Cooperating responders (RFC 6762 section 6.6): another host sent
    /// one of our records (same name, type, class and data) with less than
    /// half its TTL, so caches would drop it early, as they drop it within
    /// a second for a goodbye (TTL 0, section 10.1). Each such record set
    /// of an alias established on `link` is multicast there with the right
    /// TTL: now, if the rate limit allows, or else as soon as it does
    /// (`poll`), which for a goodbye is still within the second the caches
    /// wait. Records that disagree with ours are `check_response`'s
    /// business, and a packet from one of our own addresses is our own
    /// looped back (the caller skips those), as a goodbye of ours is.
    ///
    /// Our records only ever go out with the full TTL or 0, and a goodbye
    /// is for records we no longer have, so two instances publishing the
    /// same records correct each other's goodbyes once and stop there.
    fn correct_ttl(&mut self, msg: &Message, link: Link, now: u64, step: &mut Step) {
        let records = &self.records;
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        let addrs = addrs_for(&self.addrs, link.index);
        // Each served alias's records here, built once per packet.
        let mut sets: Vec<(AliasId, Vec<Record>)> = Vec::new();
        let mut keys: Vec<(AliasId, RType)> = Vec::new();
        for rec in msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
        {
            if rec.ttl >= TTL / 2 {
                continue;
            }
            let Some(id) = records.alias_index(&rec.name) else {
                continue;
            };
            let key = (id, rec.rtype());
            if !state.serves(id) || keys.contains(&key) {
                continue;
            }
            let at = match sets.iter().position(|(i, _)| *i == id) {
                Some(at) => at,
                None => {
                    sets.push((id, records.set(id, addrs, TTL, true)));
                    sets.len() - 1
                }
            };
            let mine = sets[at]
                .1
                .iter()
                .any(|r| r.class == rec.class && r.rdata == rec.rdata);
            if mine {
                keys.push(key);
            }
        }
        let mut now_sets = Vec::new();
        for key in keys {
            match state.last(key) {
                Some(at) if now < at + RATE_LIMIT => state.plan(key, false, now),
                _ => now_sets.extend(record_set(records, key, addrs)),
            }
        }
        rate_limit(state, &mut now_sets, false, now);
        for packet in reply_packets(records, now_sets, Vec::new()) {
            step.sends.push(multicast(link, packet));
        }
    }

    /// Simultaneous probe tiebreaking (RFC 6762 section 8.2): another host is
    /// probing for one of our aliases while we are probing it on this link.
    /// The lexicographically later record set wins; the loser waits a second
    /// and probes that alias again, by which time the winner answers and the
    /// loser sees a conflict. Each alias is tiebroken on its own.
    ///
    /// Only a loss with a probe of ours out is a real race: it is counted
    /// as a conflict, paced and reported, once per probe run of ours. A
    /// rival probe that beats an alias with nothing sent yet (already
    /// backing off, or about to start) only keeps it from probing for
    /// another `TIEBREAK_BACKOFF`, silently, so a flood of forged probes
    /// costs no log lines and cannot push the host-wide pacer out. If that
    /// goes on for `HELD_REPORT`, one `Notice::HeldBack` says so, and no
    /// more until the alias has probed again.
    ///
    /// A probe whose records for the alias are all ours is this host
    /// probing from another interface, not a rival, so it is skipped.
    fn tiebreak(&mut self, msg: &Message, link: Link, now: u64, step: &mut Step) {
        let own = self.own_addresses(now);
        let records = &self.records;
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        let addrs = addrs_for(&self.addrs, link.index);
        for ((id, alias), st) in records.iter().zip(&mut state.aliases) {
            // Only an alias being probed here is tiebroken; one too big for
            // this link is `Idle`, never probed.
            if !matches!(st.phase, Phase::Probing { .. }) {
                continue;
            }
            let mut theirs: Vec<_> = msg
                .authorities
                .iter()
                .filter(|r| r.name == *alias)
                .map(canonical)
                .collect();
            if theirs.is_empty() {
                continue;
            }
            let ours_alone = msg
                .authorities
                .iter()
                .filter(|r| r.name == *alias)
                .all(|r| !records.contradicts(r, &own));
            if ours_alone {
                continue;
            }
            crate::order::heapsort(&mut theirs);
            let mut ours: Vec<_> = records
                .set(id, addrs, TTL, false)
                .iter()
                .map(canonical)
                .collect();
            crate::order::sort(&mut ours);
            if ours >= theirs {
                continue;
            }
            match st.phase {
                Phase::Probing { sent: 0, due } => {
                    st.phase = Phase::Probing {
                        sent: 0,
                        due: due.max(now + TIEBREAK_BACKOFF),
                    };
                    let held = st.held.get_or_insert(Held {
                        since: now,
                        reported: false,
                    });
                    if !held.reported && now.saturating_sub(held.since) >= HELD_REPORT {
                        held.reported = true;
                        step.notices.push(Notice::HeldBack(link, alias.clone()));
                    }
                }
                _ => {
                    st.held = None;
                    self.pacer.conflict(now);
                    let due = self.pacer.attempt(now, TIEBREAK_BACKOFF);
                    st.phase = Phase::Probing { sent: 0, due };
                    step.notices.push(Notice::TiebreakLost(link, alias.clone()));
                }
            }
        }
    }

    /// Multipacket known-answer suppression (RFC 6762 section 7.2): a query
    /// with TC set is held for a random 400-500 ms, gathering the known
    /// answers that follow from the same querier, and `poll` answers it
    /// then. Returns whether `msg` was taken in here; if not, it is to be
    /// answered now.
    ///
    /// A new deferral needs TC and a question about an alias served on the
    /// link, and room on the link. Once a querier has one, every later query
    /// of its on the link joins it: its known answers count against all the
    /// questions, its questions are answered with the rest, and with TC
    /// again the wait is extended to 400-500 ms past it, but never past
    /// `DEFER_CAP` after the first packet; from then on, the querier's
    /// packets are treated as if it had none. Probes are answered at once,
    /// and legacy queriers (RFC 6762 section 6.7) send no continuations, so
    /// neither is deferred or joins. The jitter is drawn only for a TC
    /// packet that is taken in.
    fn defer(&mut self, msg: &Message, link: Link, source: Source, now: u64) -> bool {
        // A probe is a query with authority records. One whose authority
        // records were all left out as undecodable (`wire::parse`) is
        // treated as a plain query, here and in `answer`.
        if !msg.authorities.is_empty() || source.addr.port() != MDNS_PORT {
            return false;
        }
        let records = &self.records;
        let Some(state) = self.links.get_mut(&link) else {
            return false;
        };
        let joined = state
            .deferred
            .iter()
            .position(|d| d.source.addr.ip() == source.addr.ip() && now < d.first + DEFER_CAP);
        let at = match joined {
            Some(at) => at,
            None => {
                // A query about nothing served here would be answered with
                // nothing, so is not worth holding.
                let ours = msg.questions.iter().any(|q| {
                    records
                        .alias_index(&q.name)
                        .is_some_and(|id| state.serves(id))
                });
                if !msg.truncated || !ours || state.deferred.len() >= MAX_DEFERRED {
                    return false;
                }
                state.deferred.push(Deferred {
                    source,
                    query: Message::default(),
                    first: now,
                    due: now,
                });
                state.deferred.len() - 1
            }
        };
        let entry = &mut state.deferred[at];
        if msg.truncated {
            let wait = DEFER_MIN + xorshift(&mut self.rng, DEFER_SPREAD + 1);
            let due = (now + wait).min(entry.first + DEFER_CAP);
            entry.due = entry.due.max(due);
        }
        let query = &mut entry.query;
        for q in &msg.questions {
            if records.alias_index(&q.name).is_some()
                && query.questions.len() < MAX_DEFERRED_QUESTIONS
                && !query.questions.contains(q)
            {
                query.questions.push(q.clone());
            }
        }
        for known in &msg.answers {
            if records.alias_index(&known.name).is_some()
                && query.answers.len() < MAX_DEFERRED_KNOWN
                && !query.answers.contains(known)
            {
                query.answers.push(known.clone());
            }
        }
        true
    }

    /// Answers a query about our aliases: collect the records, drop those
    /// the querier knows, rate-limit multicasts (answers, then additional
    /// records), and pack what is left. Only
    /// aliases established on the link are answered for: one still being
    /// probed is not ours to answer for yet, and one too big or waiting for
    /// addresses is not served there at all. A legacy query with more than
    /// `MAX_LEGACY_QUESTIONS` questions is not answered, nor is one from a
    /// sender a unicast reply cannot reach. A QU question from such a
    /// sender is answered by multicast, rate-limited as any multicast.
    fn answer(&mut self, msg: &Message, link: Link, source: Source, now: u64, step: &mut Step) {
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        let legacy = source.addr.port() != MDNS_PORT;
        if legacy && (!source.unicast || msg.questions.len() > MAX_LEGACY_QUESTIONS) {
            return;
        }
        let addrs = addrs_for(&self.addrs, link.index);
        // Legacy replies get short TTLs and no cache-flush bit (RFC 6762
        // section 6.7).
        let (ttl, cache_flush) = if legacy {
            (LEGACY_TTL, false)
        } else {
            (TTL, true)
        };
        let (mut answers, mut additionals, all_unicast) =
            collect(&self.records, msg, addrs, ttl, cache_flush);
        // A query sent straight to us is answered straight back (RFC 6762
        // section 5.5), as one with only QU questions is.
        let unicast = (all_unicast || source.direct) && source.unicast;
        answers.retain(|&(id, _)| state.serves(id));
        additionals.retain(|&(id, _)| state.serves(id));
        suppress_known(&mut answers, &msg.answers);
        suppress_known(&mut additionals, &msg.answers);
        if answers.is_empty() {
            return;
        }
        // A probe must be answered at once, so it is held only to the
        // shorter probe rate limit, here and if a unicast defence falls
        // back to multicast.
        let probe = !msg.authorities.is_empty();
        if !legacy && !unicast {
            if probe {
                plan_probe_answers(state, &answers, now);
            }
            rate_limit(state, &mut answers, probe, now);
            if answers.is_empty() {
                return;
            }
            limit_additionals(state, &answers, &mut additionals, now);
        }
        let (dest, packets) = if legacy {
            let packet = legacy_reply(msg, answers, additionals);
            (Dest::Unicast(source.addr), packet.into_iter().collect())
        } else {
            let dest = if unicast {
                Dest::Unicast(source.addr)
            } else {
                Dest::Multicast
            };
            (dest, reply_packets(&self.records, answers, additionals))
        };
        for packet in packets {
            step.sends.push(Outgoing {
                link,
                dest,
                packet,
                probe,
            });
        }
    }

    /// A unicast reply, `out`, could not be sent for want of a route: what
    /// to multicast in its place, which the querier hears too (RFC 6762
    /// section 11). Its records go through the multicast rate limit, as any
    /// multicast reply's do (section 6), and count as multicast for it;
    /// nothing if every one went out by multicast within the last second,
    /// or if `out` is not an mDNS reply of ours on a served link. A probe
    /// defence is held only to the 250 ms probe limit, and planned for when
    /// that has passed if it holds the defence back, as in `answer`: a
    /// prober with no route back to us counts only responses sent after its
    /// probe, so a defence dropped could let it claim our name.
    pub fn unicast_failed(&mut self, out: &Outgoing, now: u64) -> Vec<Outgoing> {
        let Some(state) = self.links.get_mut(&out.link) else {
            return Vec::new();
        };
        let Some(msg) = wire::parse(&out.packet) else {
            return Vec::new();
        };
        let tag = |records: Vec<Record>| -> Tagged {
            records
                .into_iter()
                .filter_map(|rec| Some((self.records.alias_index(&rec.name)?, rec)))
                .filter(|&(id, _)| state.serves(id))
                .collect()
        };
        let mut answers = tag(msg.answers);
        let mut additionals = tag(msg.additionals);
        if out.probe {
            plan_probe_answers(state, &answers, now);
        }
        rate_limit(state, &mut answers, out.probe, now);
        limit_additionals(state, &answers, &mut additionals, now);
        reply_packets(&self.records, answers, additionals)
            .into_iter()
            .map(|packet| multicast(out.link, packet))
            .collect()
    }

    /// Goodbyes (TTL 0) for every alias published on every link, so clients
    /// drop the names now instead of when their caches expire. That includes
    /// an alias being probed again after a conflict: it is still cached.
    pub fn goodbye(&self) -> Vec<Outgoing> {
        let mut sends = Vec::new();
        for (&link, state) in &self.links {
            let parts: Vec<_> = self
                .records
                .iter()
                .filter(|&(id, _)| state.alias(id).published)
                .map(|(id, _)| (id, Kind::Announce { ttl: 0 }))
                .collect();
            let addrs = addrs_for(&self.addrs, link.index);
            for packet in build(&self.records, addrs, &parts) {
                sends.push(multicast(link, packet));
            }
        }
        sends
    }

    /// A number below `bound`. Jitter only: a little modulo bias is fine.
    fn random(&mut self, bound: u64) -> u64 {
        xorshift(&mut self.rng, bound)
    }
}

/// Steps the xorshift64 state `rng` and returns a number below `bound`. A
/// function of the state alone, so it can run while other fields of the
/// `Responder` are borrowed.
fn xorshift(rng: &mut u64, bound: u64) -> u64 {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    *rng % bound
}

/// A record as RFC 6762 section 8.2 compares them: class, then type, then
/// rdata as uncompressed bytes.
fn canonical(rec: &Record) -> (Class, RType, Vec<u8>) {
    (rec.class, rec.rtype(), rec.rdata_wire())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    const V4: Link = Link {
        index: IfIndex::of(2),
        family: Family::V4,
    };
    const ALIAS: &str = "app.myhost.local";
    /// Interface 2's one address in `responder`.
    const MINE: &str = "192.0.2.10";

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    /// A responder for ALIAS, with interface 2 at MINE.
    fn responder() -> Responder {
        seeded(7)
    }

    /// `responder`, with its jitter drawn from `seed`.
    fn seeded(seed: u64) -> Responder {
        let mut r = Responder::new(vec![name(ALIAS)], seed);
        r.set_addresses(IfIndex::of(2), vec![ip(MINE)], 0);
        r
    }

    /// ALIAS's records in `responder`: the A record, and the NSEC for the
    /// missing IPv6 family.
    fn ours(ttl: u32, cache_flush: bool) -> Vec<Record> {
        vec![
            a(MINE, ttl, cache_flush),
            nsec(&[RType::A], ttl, cache_flush),
        ]
    }

    fn decode(out: &Outgoing) -> Message {
        wire::parse(&out.packet).unwrap()
    }

    /// The first packet of `kind` for every alias that fits on `link`.
    fn every(r: &Responder, link: Link, kind: Kind) -> Message {
        let addrs = addrs_for(&r.addrs, link.index);
        let big = too_big(&r.records, addrs);
        let parts: Vec<_> = r
            .records
            .iter()
            .filter(|(id, _)| !big.contains(id))
            .map(|(id, _)| (id, kind))
            .collect();
        wire::parse(&build(&r.records, addrs, &parts)[0]).unwrap()
    }

    fn announcement(r: &Responder, link: Link) -> Message {
        every(r, link, Kind::Announce { ttl: TTL })
    }

    fn probe(r: &Responder, link: Link) -> Message {
        every(r, link, Kind::Probe)
    }

    /// Polls every millisecond from `from` to `to` inclusive.
    fn run(r: &mut Responder, from: u64, to: u64) -> (Vec<(u64, Outgoing)>, Vec<Notice>) {
        let (mut sent, mut notices) = (Vec::new(), Vec::new());
        for now in from..=to {
            let step = r.poll(now);
            sent.extend(step.sends.into_iter().map(|o| (now, o)));
            notices.extend(step.notices);
        }
        (sent, notices)
    }

    /// Adds `link` at time 0 and runs it through probing and announcing,
    /// which is over by 2000 ms.
    fn announced(r: &mut Responder, link: Link) {
        r.add_link(link, 0);
        run(r, 0, 2000);
    }

    #[test]
    fn probes_three_times_then_announces_twice() {
        let mut r = responder();
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 5000);
        let times: Vec<u64> = sent.iter().map(|(t, _)| *t).collect();
        let first = times[0];
        assert!(first <= 250);
        assert_eq!(
            times,
            [first, first + 250, first + 500, first + 750, first + 1750]
        );
        for (i, (_, out)) in sent.iter().enumerate() {
            assert_eq!((out.link, out.dest), (V4, Dest::Multicast));
            let msg = decode(out);
            if i < 3 {
                assert!(!msg.is_response);
                assert_eq!(
                    msg.questions,
                    [Question {
                        name: name(ALIAS),
                        qtype: RType::ANY,
                        qclass: Class::IN,
                        unicast_response: false
                    }]
                );
                assert_eq!(msg.authorities, ours(TTL, false));
            } else {
                assert!(msg.is_response);
                assert_eq!(msg.answers, ours(TTL, true));
            }
        }
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
    }

    #[test]
    fn first_probe_waits_a_random_0_to_250_ms() {
        let mut firsts = BTreeSet::new();
        for seed in 0..50 {
            let mut r = seeded(seed);
            r.add_link(V4, 0);
            let (sent, _) = run(&mut r, 0, 250);
            firsts.insert(sent[0].0);
        }
        assert!(firsts.iter().all(|&t| t <= 250));
        assert!(firsts.len() > 10, "waits are not spread out: {firsts:?}");
    }

    #[test]
    fn links_progress_independently() {
        let v6 = Link {
            index: IfIndex::of(2),
            family: Family::V6,
        };
        let mut r = responder();
        announced(&mut r, V4);
        r.add_link(v6, 5000);
        let (sent, _) = run(&mut r, 5000, 8000);
        assert_eq!(sent.len(), 5);
        assert!(sent.iter().all(|(_, o)| o.link == v6));
    }

    #[test]
    fn goodbye_covers_links_that_announced() {
        let mut r = responder();
        r.add_link(V4, 0);
        assert!(r.goodbye().is_empty());
        run(&mut r, 0, 2000);
        let byes = r.goodbye();
        assert_eq!(byes.len(), 1);
        assert_eq!((byes[0].link, byes[0].dest), (V4, Dest::Multicast));
        assert_eq!(decode(&byes[0]).answers, ours(0, true));
    }

    #[test]
    fn removed_links_go_quiet() {
        let mut r = responder();
        announced(&mut r, V4);
        r.remove_link(V4);
        assert!(run(&mut r, 2000, 5000).0.is_empty());
        assert!(r.goodbye().is_empty());
    }

    const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 5353);
    const LEGACY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 54928);

    fn query(questions: &[(&str, RType, bool)]) -> Message {
        Message {
            id: 0x4242,
            questions: questions
                .iter()
                .map(|&(n, qtype, qu)| Question {
                    name: name(n),
                    qtype,
                    qclass: Class::IN,
                    unicast_response: qu,
                })
                .collect(),
            ..Message::default()
        }
    }

    fn ask(r: &mut Responder, msg: &Message, source: impl Into<Source>, now: u64) -> Vec<Outgoing> {
        r.handle(&wire::encode(msg), V4, source, now).sends
    }

    fn announced_responder() -> Responder {
        let mut r = responder();
        announced(&mut r, V4);
        r
    }

    #[test]
    fn ignores_other_names() {
        let mut r = announced_responder();
        assert!(
            ask(
                &mut r,
                &query(&[("other.local", RType::A, false)]),
                CLIENT,
                10_000
            )
            .is_empty()
        );
        let host = query(&[("myhost.local", RType::A, false)]);
        assert!(ask(&mut r, &host, CLIENT, 10_000).is_empty());
    }

    #[test]
    fn matches_names_ignoring_case() {
        let mut r = announced_responder();
        let sent = ask(
            &mut r,
            &query(&[("APP.MYHOST.LOCAL", RType::A, false)]),
            CLIENT,
            10_000,
        );
        assert_eq!(sent.len(), 1);
    }

    #[test]
    fn stays_silent_while_probing() {
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 600);
        assert!(ask(&mut r, &query(&[(ALIAS, RType::A, false)]), CLIENT, 600).is_empty());
    }

    #[test]
    fn ignores_links_it_does_not_serve() {
        let mut r = announced_responder();
        let other = Link {
            index: IfIndex::of(9),
            family: Family::V4,
        };
        let step = r.handle(
            &wire::encode(&query(&[(ALIAS, RType::A, false)])),
            other,
            CLIENT,
            10_000,
        );
        assert!(step.sends.is_empty());
    }

    #[test]
    fn ignores_malformed_packets() {
        let mut r = announced_responder();
        assert!(r.handle(b"\x00\x01", V4, CLIENT, 10_000).sends.is_empty());
    }

    #[test]
    fn a_query_with_an_undecodable_nsec_known_answer_is_still_answered() {
        // RFC 6762 section 6.1: an NSEC record that cannot be parsed must
        // not make the whole message be ignored.
        let mut r = announced_responder();
        let mut packet = wire::encode(&query(&[(ALIAS, RType::ANY, false)]));
        packet[7] = 1;
        // Owner: a pointer to the question's name. A bitmap window of
        // length 0, which RFC 4034 forbids.
        packet.extend_from_slice(&[0xC0, 12, 0, 47, 0, 1, 0, 0, 0, 120, 0, 4, 0xC0, 12, 0, 0]);
        let sent = r.handle(&packet, V4, CLIENT, 10_000).sends;
        assert_eq!(one(sent).answers, ours(TTL, true));
    }

    /// An A and an AAAA question: the A record answers one, the NSEC the
    /// other, and neither is left as an additional record.
    #[test]
    fn answers_several_questions_in_one_response() {
        let mut r = announced_responder();
        let sent = ask(
            &mut r,
            &query(&[(ALIAS, RType::A, false), (ALIAS, RType::AAAA, false)]),
            CLIENT,
            10_000,
        );
        assert_eq!(sent.len(), 1);
        let msg = decode(&sent[0]);
        assert_eq!(msg.answers, ours(TTL, true));
        assert!(msg.additionals.is_empty());
    }

    #[test]
    fn unicast_response_questions_get_a_unicast_reply() {
        let mut r = announced_responder();
        let sent = ask(&mut r, &query(&[(ALIAS, RType::A, true)]), CLIENT, 10_000);
        assert_eq!(sent[0].dest, Dest::Unicast(CLIENT));
        let mixed = query(&[(ALIAS, RType::A, true), (ALIAS, RType::AAAA, false)]);
        assert_eq!(ask(&mut r, &mixed, CLIENT, 20_000)[0].dest, Dest::Multicast);
    }

    #[test]
    fn legacy_queries_get_a_short_lived_unicast_echo() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, RType::A, false)]);
        let sent = ask(&mut r, &q, LEGACY, 10_000);
        assert_eq!(sent[0].dest, Dest::Unicast(LEGACY));
        let msg = decode(&sent[0]);
        assert_eq!(msg.id, 0x4242);
        assert_eq!(msg.questions, q.questions);
        assert_eq!(msg.answers, [a(MINE, 10, false)]);
    }

    #[test]
    fn suppresses_answers_the_querier_already_knows() {
        let mut r = announced_responder();
        let mut q = query(&[(ALIAS, RType::A, false)]);
        q.answers = vec![a(MINE, TTL, false)];
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        q.answers = vec![a(MINE, TTL / 2 - 1, false)];
        assert_eq!(ask(&mut r, &q, CLIENT, 10_000).len(), 1);
    }

    #[test]
    fn multicasts_each_record_at_most_once_a_second() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, RType::A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 3000).len(), 1);
        assert!(ask(&mut r, &q, CLIENT, 3500).is_empty());
        assert_eq!(ask(&mut r, &q, CLIENT, 4000).len(), 1);
    }

    #[test]
    fn defends_against_probes_despite_the_rate_limit() {
        let mut r = announced_responder();
        assert_eq!(
            ask(&mut r, &query(&[(ALIAS, RType::A, false)]), CLIENT, 3000).len(),
            1
        );
        assert_eq!(ask(&mut r, &rival_probe(false), CLIENT, 3250).len(), 1);
    }

    /// A probe for `ALIAS` with another host's address, QU if `unicast`.
    fn rival_probe(unicast: bool) -> Message {
        let mut probe = query(&[(ALIAS, RType::ANY, unicast)]);
        probe.authorities = vec![a("192.0.2.99", TTL, false)];
        probe
    }

    /// RFC 6762 section 6: a multicast probe answer keeps 250 ms since
    /// the set was last multicast, and is delayed until then rather than
    /// dropped. Probes arriving while one is planned share it: it goes out
    /// after them, so it answers each.
    #[test]
    fn probe_defences_wait_for_the_250_ms_gap() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, RType::A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 3000).len(), 1);
        let probe = rival_probe(false);
        assert!(ask(&mut r, &probe, CLIENT, 3100).is_empty());
        assert!(ask(&mut r, &probe, CLIENT, 3240).is_empty());
        assert_eq!(r.next_due(), Some(3250));
        assert!(r.poll(3249).sends.is_empty());
        // Both sets were held: the NSEC went out at 3000 as an additional
        // record.
        let sent = r.poll(3250).sends;
        assert_eq!(one(sent.clone()).answers, ours(TTL, true));
        assert!(sent.iter().all(|o| o.dest == Dest::Multicast));
        assert_eq!(r.next_due(), None);
        // The next probe waits for 250 ms after that defence.
        assert!(ask(&mut r, &probe, CLIENT, 3300).is_empty());
        assert_eq!(r.next_due(), Some(3500));
        let msg = one(r.poll(3500).sends);
        assert_eq!(msg.answers, ours(TTL, true));
        // Past the gap, a defence goes out at once.
        assert_eq!(ask(&mut r, &probe, CLIENT, 3750).len(), 1);
        assert_eq!(r.next_due(), None);
    }

    /// A planned defence is not sent twice: a multicast of the set after
    /// it was planned answers the probe in its place.
    #[test]
    fn a_planned_defence_is_dropped_after_a_newer_multicast() {
        let mut r = announced_responder();
        let probe = rival_probe(false);
        assert_eq!(ask(&mut r, &probe, CLIENT, 3000).len(), 1);
        assert!(ask(&mut r, &probe, CLIENT, 3100).is_empty());
        // The address changes: the announcement multicasts every set.
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 3200);
        assert!(!step.sends.is_empty());
        assert!(r.poll(3250).sends.is_empty());
    }

    /// The gap holds for a unicast defence that falls back to multicast
    /// too, by the same bookkeeping, and is planned the same way.
    #[test]
    fn a_unicast_defence_falling_back_to_multicast_waits_250_ms_too() {
        let mut r = announced_responder();
        let probe = rival_probe(true);
        let fallback = |r: &mut Responder, now| {
            let reply = ask(r, &probe, CLIENT, now);
            assert_eq!(reply[0].dest, Dest::Unicast(CLIENT));
            assert!(reply[0].probe);
            r.unicast_failed(&reply[0], now).len()
        };
        assert_eq!(fallback(&mut r, 3000), 1);
        assert_eq!(fallback(&mut r, 3100), 0);
        assert_eq!(r.next_due(), Some(3250));
        let msg = one(r.poll(3250).sends);
        assert_eq!(msg.answers, ours(TTL, true));
    }

    /// A QU probe from a sender with no route back to us (say a
    /// self-assigned 169.254 address) is defended by multicast even within
    /// a second of our last multicast: the prober only counts responses
    /// sent after its probing began.
    #[test]
    fn defends_a_qu_probe_without_a_route_despite_the_rate_limit() {
        let mut r = announced_responder();
        assert_eq!(
            ask(&mut r, &query(&[(ALIAS, RType::A, false)]), CLIENT, 3000).len(),
            1
        );
        let reply = ask(&mut r, &rival_probe(true), CLIENT, 3250);
        assert_eq!(reply.len(), 1);
        assert_eq!(reply[0].dest, Dest::Unicast(CLIENT));
        assert!(reply[0].probe);
        let sent = r.unicast_failed(&reply[0], 3250);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].dest, Dest::Multicast);
        assert_eq!(decode(&sent[0]).answers, decode(&reply[0]).answers);
        // An ordinary QU reply failing just after is still rate-limited.
        let qu = ask(&mut r, &query(&[(ALIAS, RType::ANY, true)]), CLIENT, 3600);
        assert!(!qu[0].probe);
        assert!(r.unicast_failed(&qu[0], 3600).is_empty());
    }

    const OTHER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)), 5353);

    fn a_record(owner: &str, ttl: u32) -> Record {
        Record {
            name: name(owner),
            class: Class::IN,
            cache_flush: true,
            ttl,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    fn response(answers: Vec<Record>) -> Message {
        Message {
            is_response: true,
            answers,
            ..Message::default()
        }
    }

    fn hear(r: &mut Responder, msg: &Message, now: u64) -> Step {
        r.handle(&wire::encode(msg), V4, OTHER, now)
    }

    /// Whether `step` saw another host claim one of our aliases.
    fn claimed(step: &Step) -> bool {
        step.notices
            .iter()
            .any(|n| matches!(n, Notice::Conflict(_) | Notice::Lost { .. }))
    }

    /// Another host's probe for ALIAS, proposing `addr`. Against MINE, a
    /// higher address wins the tiebreak, a lower one loses it.
    fn their_probe(addr: &str) -> Message {
        let mut probe = query(&[(ALIAS, RType::ANY, true)]);
        probe.authorities = vec![a(addr, TTL, false)];
        probe
    }

    #[test]
    fn other_data_for_an_alias_is_a_conflict() {
        let expected = Conflict {
            alias: name(ALIAS),
            source: OTHER.ip(),
        };
        let mut r = announced_responder();
        assert_eq!(
            hear(&mut r, &response(vec![a_record(ALIAS, 120)]), 5000).notices,
            [Notice::Conflict(expected)]
        );
        let mut r = announced_responder();
        // A CNAME says the name has no addresses of its own.
        let elsewhere = Record {
            rdata: RData::Cname(name("media.local")),
            ..a(MINE, TTL, true)
        };
        assert!(claimed(&hear(&mut r, &response(vec![elsewhere]), 5000)));
    }

    #[test]
    fn conflicts_count_while_probing_too() {
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 260);
        let step = hear(&mut r, &response(vec![a_record(ALIAS, 120)]), 300);
        assert!(matches!(step.notices[..], [Notice::Lost { .. }]));
    }

    #[test]
    fn conflict_message_names_the_alias_and_source() {
        let c = Conflict {
            alias: name(ALIAS),
            source: OTHER.ip(),
        };
        assert_eq!(c.to_string(), "app.myhost.local is claimed by 192.0.2.30");
    }

    #[test]
    fn same_data_in_another_case_is_not_a_conflict() {
        let mut r = announced_responder();
        let echoed = Record {
            name: name("App.MyHost.local"),
            ..a(MINE, TTL, true)
        };
        assert!(!claimed(&hear(&mut r, &response(vec![echoed]), 5000)));
    }

    #[test]
    fn own_announcement_is_not_a_conflict() {
        let mut r = announced_responder();
        let own = announcement(&r, V4);
        assert!(!claimed(&hear(&mut r, &own, 5000)));
    }

    #[test]
    fn responses_from_other_ports_are_ignored() {
        let mut r = announced_responder();
        let packet = wire::encode(&response(vec![a_record(ALIAS, 120)]));
        let source = SocketAddr::new(OTHER.ip(), 54000);
        assert!(!claimed(&r.handle(&packet, V4, source, 5000)));
    }

    #[test]
    fn unicast_responses_are_ignored() {
        // We never ask for a unicast response (RFC 6762 section 6), so one
        // sent straight to us is not ours to act on.
        let mut r = announced_responder();
        let packet = wire::encode(&response(vec![a_record(ALIAS, 120)]));
        let direct = Source {
            addr: OTHER,
            unicast: true,
            direct: true,
        };
        assert!(!claimed(&r.handle(&packet, V4, direct, 5000)));
        // The same response to the group is a conflict.
        assert!(claimed(&r.handle(&packet, V4, OTHER, 5000)));
    }

    #[test]
    fn a_query_sent_straight_to_us_is_answered_by_unicast() {
        // RFC 6762 section 5.5, from port 5353 and without the QU bit.
        let mut r = announced_responder();
        let direct = Source {
            addr: CLIENT,
            unicast: true,
            direct: true,
        };
        let q = query(&[(ALIAS, RType::A, false)]);
        for now in [10_000, 10_001] {
            let sent = ask(&mut r, &q, direct, now);
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].dest, Dest::Unicast(CLIENT));
            let msg = decode(&sent[0]);
            assert_eq!(msg.answers, [a(MINE, TTL, true)]);
        }
        // Unless a unicast reply cannot reach the sender: then by multicast.
        let far = Source {
            unicast: false,
            ..direct
        };
        let sent = ask(&mut r, &q, far, 20_000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].dest, Dest::Multicast);
    }

    #[test]
    fn goodbyes_are_not_conflicts() {
        let mut r = announced_responder();
        assert!(!claimed(&hear(
            &mut r,
            &response(vec![a_record(ALIAS, 0)]),
            5000
        )));
    }

    /// RFC 6762 sections 6.6 and 10.1: another host's response carrying
    /// one of our records with less than half its TTL, a goodbye included,
    /// gets ours multicast with the right TTL.
    #[test]
    fn our_record_sent_by_another_host_with_a_short_ttl_is_corrected() {
        for ttl in [0, 1, TTL / 2 - 1] {
            let mut r = announced_responder();
            let step = hear(&mut r, &response(vec![a(MINE, ttl, true)]), 5000);
            assert!(!claimed(&step));
            let msg = one(step.sends);
            assert!(msg.is_response);
            assert_eq!(msg.answers, [a(MINE, TTL, true)], "ttl {ttl}");
        }
        // Each record set is corrected on its own: a goodbye for the NSEC
        // brings back the NSEC alone.
        let mut r = announced_responder();
        let bye = response(vec![nsec(&[RType::A], 0, true)]);
        let msg = one(hear(&mut r, &bye, 5000).sends);
        assert_eq!(msg.answers, [nsec(&[RType::A], TTL, true)]);
        // At least half the TTL needs nothing.
        let mut r = announced_responder();
        let step = hear(&mut r, &response(vec![a(MINE, TTL / 2, true)]), 5000);
        assert!(step.sends.is_empty());
        assert_eq!(r.next_due(), None);
    }

    /// Only records equal to ours count: another address, or a short TTL
    /// in a probe rather than a response, is not ours to correct.
    #[test]
    fn short_ttls_on_other_data_are_left_alone() {
        let mut r = announced_responder();
        let theirs = a("192.0.2.99", 0, true);
        assert!(hear(&mut r, &response(vec![theirs]), 5000).sends.is_empty());
        let mut probe = their_probe(MINE);
        probe.authorities = vec![a(MINE, 0, false)];
        let sent = hear(&mut r, &probe, 6000).sends;
        assert!(sent.iter().all(|o| o.probe), "{sent:?}");
        // Nor is anything held for later.
        assert_eq!(r.next_due(), None);
    }

    /// The correction keeps to the multicast rate limit: one within a
    /// second of our last multicast waits for the second to pass, still
    /// inside the second a cache keeps a record after a goodbye.
    #[test]
    fn a_ttl_correction_waits_for_the_rate_limit() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, RType::A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 5000).len(), 1);
        let bye = response(vec![a(MINE, 0, true)]);
        assert!(hear(&mut r, &bye, 5300).sends.is_empty());
        // A second goodbye does not plan a second correction.
        assert!(hear(&mut r, &bye, 5400).sends.is_empty());
        assert_eq!(r.next_due(), Some(6000));
        assert!(r.poll(5999).sends.is_empty());
        let msg = one(r.poll(6000).sends);
        assert_eq!(msg.answers, [a(MINE, TTL, true)]);
        assert_eq!(r.next_due(), None);
        // Another goodbye right after it waits again; an answer multicast
        // meanwhile corrects it instead.
        assert!(hear(&mut r, &bye, 6100).sends.is_empty());
        assert_eq!(one(ask(&mut r, &q, CLIENT, 7000)).answers.len(), 1);
        assert!(r.poll(7000).sends.is_empty());
        assert_eq!(r.next_due(), None);
    }

    /// A multicast of the set between two goodbyes answers only the first:
    /// the second is corrected a second after that multicast.
    #[test]
    fn a_goodbye_after_a_multicast_is_corrected_too() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, RType::A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 5000).len(), 1);
        let bye = response(vec![a(MINE, 0, true)]);
        assert!(hear(&mut r, &bye, 5300).sends.is_empty());
        assert_eq!(r.next_due(), Some(6000));
        // A probe defence multicasts the set at 5800 ...
        let defence = ask(&mut r, &rival_probe(false), CLIENT, 5800);
        assert_eq!(one(defence).answers, ours(TTL, true));
        // ... before the second goodbye, which it does not answer.
        assert!(hear(&mut r, &bye, 5900).sends.is_empty());
        assert_eq!(r.next_due(), Some(6800));
        let (sent, _) = run(&mut r, 6000, 7000);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, 6800);
        assert_eq!(decode(&sent[0].1).answers, [a(MINE, TTL, true)]);
        assert_eq!(r.next_due(), None);
    }

    /// Our own goodbyes and records, looped back from one of our addresses
    /// (or one removed in the last few seconds), are never corrected.
    #[test]
    fn our_own_short_ttls_are_not_corrected() {
        let mut r = announced_with(&["192.0.2.10", "192.0.2.11"]);
        let bye = response(vec![a("192.0.2.10", 0, true)]);
        let from = |addr: &str| SocketAddr::new(ip(addr), MDNS_PORT);
        let step = r.handle(&wire::encode(&bye), V4, from("192.0.2.10"), 5000);
        assert!(step.sends.is_empty());
        // .11 goes; for a while packets from it are still ours.
        r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.10")], 6000);
        r.poll(6000);
        let step = r.handle(&wire::encode(&bye), V4, from("192.0.2.11"), 8000);
        assert!(step.sends.is_empty());
        assert_eq!(r.next_due(), Some(7000), "only the second announcement");
        run(&mut r, 7000, 7000);
        assert_eq!(r.next_due(), None);
        // Once that has passed, it is another host's.
        let step = r.handle(&wire::encode(&bye), V4, from("192.0.2.11"), 12_000);
        assert_eq!(one(step.sends).answers, [a("192.0.2.10", TTL, true)]);
    }

    /// Only aliases established on the link are corrected; one still being
    /// probed has nothing out yet.
    #[test]
    fn short_ttls_while_probing_are_not_corrected() {
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 300);
        let step = hear(&mut r, &response(vec![a(MINE, 0, true)]), 300);
        assert!(step.sends.is_empty());
        assert!(!claimed(&step));
    }

    /// Two instances publishing the same records: one's goodbyes get one
    /// correction from the other, which the first ignores (its TTL is
    /// full), and each one's announcements and answers move the other to
    /// nothing. No exchange keeps going.
    #[test]
    fn two_instances_do_not_answer_each_other_forever() {
        let mut a = announced_responder();
        let mut b = announced_responder();
        let a_addr = SocketAddr::new(ip("192.0.2.40"), MDNS_PORT);
        let b_addr = SocketAddr::new(ip("192.0.2.41"), MDNS_PORT);
        let q = query(&[(ALIAS, RType::A, false)]);
        let mut in_flight: Vec<(bool, Outgoing)> = Vec::new();
        in_flight.extend(ask(&mut a, &q, CLIENT, 5000).into_iter().map(|o| (true, o)));
        in_flight.extend(a.goodbye().into_iter().map(|o| (true, o)));
        let mut now = 5000;
        let mut total = 0;
        while !in_flight.is_empty() {
            total += in_flight.len();
            assert!(total < 10, "storm");
            now += 10;
            let mut next = Vec::new();
            for (from_a, out) in in_flight {
                let (to, src) = if from_a {
                    (&mut b, a_addr)
                } else {
                    (&mut a, b_addr)
                };
                let step = to.handle(&out.packet, V4, src, now);
                assert!(!claimed(&step));
                next.extend(step.sends.into_iter().map(|o| (!from_a, o)));
            }
            in_flight = next;
        }
        // The answer and the goodbye, then b's one correction.
        assert_eq!(total, 3);
    }

    #[test]
    fn responses_about_other_names_are_not_conflicts() {
        let mut r = announced_responder();
        assert!(!claimed(&hear(
            &mut r,
            &response(vec![a_record("myhost.local", 120)]),
            5000
        )));
    }

    #[test]
    fn ignores_responses_on_links_it_does_not_serve() {
        let mut r = announced_responder();
        let other = Link {
            index: IfIndex::of(9),
            family: Family::V4,
        };
        let packet = wire::encode(&response(vec![a_record(ALIAS, 120)]));
        assert!(!claimed(&r.handle(&packet, other, OTHER, 5000)));
    }

    #[test]
    fn losing_a_tiebreak_restarts_probing_a_second_later() {
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        // Their address sorts after ours, so they win.
        let step = hear(&mut r, &their_probe("192.0.2.200"), 251);
        assert_eq!(step.notices, [Notice::TiebreakLost(V4, name(ALIAS))]);
        let (sent, _) = run(&mut r, 252, 1251);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 1251);
        assert!(!decode(&sent[0].1).is_response);
        // A whole new run of three probes: two more follow.
        let (sent, _) = run(&mut r, 1252, 1751);
        let times: Vec<u64> = sent.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [1501, 1751]);
        assert!(sent.iter().all(|(_, o)| !decode(o).is_response));
    }

    #[test]
    fn winning_a_tiebreak_keeps_probing() {
        let mut r = responder();
        r.add_link(V4, 0);
        let (before, _) = run(&mut r, 0, 250);
        // Their address sorts before ours: we win.
        let step = hear(&mut r, &their_probe("192.0.2.1"), 251);
        assert!(step.notices.is_empty());
        let (after, _) = run(&mut r, 252, 3000);
        assert_eq!(before.len() + after.len(), 5);
    }

    #[test]
    fn own_probe_does_not_restart_probing() {
        let mut r = responder();
        r.add_link(V4, 0);
        let (before, _) = run(&mut r, 0, 250);
        let own = probe(&r, V4);
        assert!(hear(&mut r, &own, 251).notices.is_empty());
        let (after, _) = run(&mut r, 252, 3000);
        assert_eq!(before.len() + after.len(), 5);
    }

    const V4B: Link = Link {
        index: IfIndex::of(3),
        family: Family::V4,
    };

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn a(addr: &str, ttl: u32, cache_flush: bool) -> Record {
        let IpAddr::V4(v4) = ip(addr) else {
            panic!("not IPv4")
        };
        Record {
            name: name(ALIAS),
            class: Class::IN,
            cache_flush,
            ttl,
            rdata: RData::A(v4),
        }
    }

    fn aaaa(addr: &str, ttl: u32, cache_flush: bool) -> Record {
        let IpAddr::V6(v6) = ip(addr) else {
            panic!("not IPv6")
        };
        Record {
            name: name(ALIAS),
            class: Class::IN,
            cache_flush,
            ttl,
            rdata: RData::Aaaa(v6),
        }
    }

    fn nsec(types: &[RType], ttl: u32, cache_flush: bool) -> Record {
        Record {
            name: name(ALIAS),
            class: Class::IN,
            cache_flush,
            ttl,
            rdata: RData::Nsec {
                next: name(ALIAS),
                types: types.iter().copied().collect(),
            },
        }
    }

    /// A responder whose interface 2 has `addrs`.
    fn with_addresses(addrs: &[&str]) -> Responder {
        let mut r = Responder::new(vec![name(ALIAS)], 7);
        r.set_addresses(IfIndex::of(2), addrs.iter().map(|a| ip(a)).collect(), 0);
        r
    }

    fn announced_with(addrs: &[&str]) -> Responder {
        let mut r = with_addresses(addrs);
        announced(&mut r, V4);
        r
    }

    fn one(sent: Vec<Outgoing>) -> Message {
        assert_eq!(sent.len(), 1, "{sent:?}");
        decode(&sent[0])
    }

    #[test]
    fn waits_for_addresses_before_probing() {
        let mut r = Responder::new(vec![name(ALIAS)], 7);
        r.add_link(V4, 0);
        assert!(run(&mut r, 0, 3000).0.is_empty());
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.10")], 3000);
        assert!(step.sends.is_empty());
        assert_eq!(run(&mut r, 3000, 6000).0.len(), 5);
    }

    #[test]
    fn probes_and_announces_the_interfaces_addresses() {
        let mut r = with_addresses(&["fe80::1", "192.0.2.10"]);
        r.add_link(V4, 0);
        let (sent, _) = run(&mut r, 0, 3000);
        let probe = decode(&sent[0].1);
        assert_eq!(
            probe.authorities,
            [a("192.0.2.10", TTL, false), aaaa("fe80::1", TTL, false)]
        );
        let announcement = decode(&sent[3].1);
        assert_eq!(
            announcement.answers,
            [a("192.0.2.10", TTL, true), aaaa("fe80::1", TTL, true)]
        );
    }

    #[test]
    fn a_missing_family_is_announced_with_nsec() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        let (sent, _) = run(&mut r, 0, 3000);
        assert_eq!(
            decode(&sent[3].1).answers,
            [a("192.0.2.10", TTL, true), nsec(&[RType::A], TTL, true)]
        );
    }

    #[test]
    fn answers_a_with_aaaa_as_additional() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, RType::A, false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
    }

    #[test]
    fn a_question_repeated_many_times_gets_the_reply_to_one() {
        let addrs = ["192.0.2.10", "2001:db8::10", "2001:db8::11", "fd00::10"];
        for qtype in [RType::ANY, RType::A, RType::AAAA, RType(16)] {
            let mut r = announced_with(&addrs);
            let once = one(ask(
                &mut r,
                &query(&[(ALIAS, qtype, false)]),
                CLIENT,
                10_000,
            ));
            let mut r = announced_with(&addrs);
            let many = query(&vec![(ALIAS, qtype, false); 1400]);
            assert_eq!(one(ask(&mut r, &many, CLIENT, 10_000)), once, "{qtype:?}");
        }
        // Next to an ANY question, other questions about the alias add
        // nothing to the reply.
        let mut r = announced_with(&addrs);
        let any = one(ask(
            &mut r,
            &query(&[(ALIAS, RType::ANY, false)]),
            CLIENT,
            10_000,
        ));
        let mut mixed = vec![(ALIAS, RType::ANY, false)];
        for qtype in [RType::A, RType::AAAA, RType(16), RType::NSEC] {
            mixed.extend(vec![(ALIAS, qtype, false); 300]);
        }
        let mut r = announced_with(&addrs);
        assert_eq!(one(ask(&mut r, &query(&mixed), CLIENT, 10_000)), any);
    }

    #[test]
    fn a_question_asked_twice_gets_its_additional_record_once() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let twice = query(&[(ALIAS, RType::A, false), (ALIAS, RType::A, false)]);
        let msg = one(ask(&mut r, &twice, CLIENT, 10_000));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
    }

    #[test]
    fn several_aliases_are_rate_limited_and_packed_each_on_its_own() {
        const WEB: &str = "web.myhost.local";
        let mut r = Responder::new(vec![name(ALIAS), name(WEB)], 7);
        r.set_addresses(
            IfIndex::of(2),
            ["192.0.2.10", "2001:db8::10"].map(ip).to_vec(),
            0,
        );
        announced(&mut r, V4);
        let web = |rec: Record| Record {
            name: name(WEB),
            ..rec
        };
        let both = query(&[(WEB, RType::A, false), (ALIAS, RType::A, false)]);
        // Answers and their additional records come in alias order, whatever
        // the order of the questions.
        let msg = one(ask(&mut r, &both, CLIENT, 3000));
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), web(a("192.0.2.10", TTL, true))]
        );
        assert_eq!(
            msg.additionals,
            [
                aaaa("2001:db8::10", TTL, true),
                web(aaaa("2001:db8::10", TTL, true))
            ]
        );
        // The rate limit is per alias: answering one leaves the other free.
        let msg = one(ask(&mut r, &query(&[(WEB, RType::A, false)]), CLIENT, 4000));
        assert_eq!(msg.answers, [web(a("192.0.2.10", TTL, true))]);
        let msg = one(ask(&mut r, &both, CLIENT, 4500));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
        // An alias whose answers the querier already knows sends no
        // additional records either.
        let mut known = both.clone();
        known.answers = vec![web(a("192.0.2.10", TTL, false))];
        let msg = one(ask(&mut r, &known, CLIENT, 6000));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
    }

    #[test]
    fn a_missing_type_is_answered_with_nsec() {
        let mut r = announced_with(&["192.0.2.10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, RType::AAAA, false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(msg.answers, [nsec(&[RType::A], TTL, true)]);
        assert_eq!(msg.additionals, [a("192.0.2.10", TTL, true)]);
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, RType(16), false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(msg.answers, [nsec(&[RType::A, RType::AAAA], TTL, true)]);
        assert!(msg.additionals.is_empty());
    }

    #[test]
    fn answers_any_with_everything() {
        let mut r = announced_with(&["192.0.2.10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, RType::ANY, false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), nsec(&[RType::A], TTL, true)]
        );
    }

    #[test]
    fn answers_with_the_arrival_interfaces_addresses() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 0);
        announced(&mut r, V4);
        r.add_link(V4B, 2000);
        run(&mut r, 2000, 5000);
        let sent = r
            .handle(
                &wire::encode(&query(&[(ALIAS, RType::A, false)])),
                V4B,
                CLIENT,
                10_000,
            )
            .sends;
        assert_eq!(one(sent).answers, [a("198.51.100.10", TTL, true)]);
    }

    #[test]
    fn an_address_change_says_goodbye_and_announces_twice() {
        let mut r = announced_with(&["192.0.2.10"]);
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 5000);
        assert_eq!(step.sends.len(), 2);
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets[0].answers, [a("192.0.2.10", 0, true)]);
        assert_eq!(
            packets[1].answers,
            [a("192.0.2.11", TTL, true), nsec(&[RType::A], TTL, true)]
        );
        let (sent, notices) = run(&mut r, 5001, 7000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 6000);
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
    }

    #[test]
    fn a_family_appearing_withdraws_the_nsec() {
        let mut r = announced_with(&["192.0.2.10"]);
        let step = r.set_addresses(
            IfIndex::of(2),
            vec![ip("192.0.2.10"), ip("2001:db8::10")],
            5000,
        );
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].answers, [nsec(&[RType::A], 0, true)]);
        assert_eq!(
            packets[1].answers,
            [a("192.0.2.10", TTL, true), aaaa("2001:db8::10", TTL, true)]
        );
    }

    #[test]
    fn an_address_change_while_probing_keeps_probing() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        // Exactly one probe is out by now.
        let (sent, _) = run(&mut r, 0, 100);
        assert_eq!(sent.len(), 1);
        assert_eq!(
            decode(&sent[0].1).authorities[0],
            a("192.0.2.10", TTL, false)
        );
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 150);
        assert!(step.sends.is_empty(), "no goodbye while probing");
        let (sent, notices) = run(&mut r, 151, 5000);
        let packets: Vec<Message> = sent.iter().map(|(_, o)| decode(o)).collect();
        // Two more probes, then two announcements, all with the new address.
        assert_eq!(packets.len(), 4, "{packets:?}");
        let probes: Vec<&Message> = packets.iter().filter(|m| !m.is_response).collect();
        assert_eq!(probes.len(), 2);
        for probe in probes {
            assert_eq!(probe.authorities[0], a("192.0.2.11", TTL, false));
        }
        let announcements: Vec<&Message> = packets.iter().filter(|m| m.is_response).collect();
        assert_eq!(announcements.len(), 2);
        for msg in announcements {
            assert_eq!(
                msg.answers,
                [a("192.0.2.11", TTL, true), nsec(&[RType::A], TTL, true)]
            );
        }
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
    }

    #[test]
    fn losing_every_address_says_goodbye_and_waits() {
        let mut r = announced_with(&["192.0.2.10"]);
        let step = r.set_addresses(IfIndex::of(2), Vec::new(), 5000);
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0].answers,
            [a("192.0.2.10", 0, true), nsec(&[RType::A], 0, true)]
        );
        assert!(ask(&mut r, &query(&[(ALIAS, RType::A, false)]), CLIENT, 10_000).is_empty());
        assert!(run(&mut r, 5001, 9000).0.is_empty());
    }

    #[test]
    fn losing_every_address_while_probing_waits() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        run(&mut r, 0, 260);
        r.set_addresses(IfIndex::of(2), Vec::new(), 300);
        assert!(run(&mut r, 301, 5000).0.is_empty());
    }

    #[test]
    fn our_own_addresses_on_any_interface_are_not_conflicts() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 0);
        announced(&mut r, V4);
        let other_interface = response(vec![a("198.51.100.10", TTL, true)]);
        assert!(!claimed(&hear(&mut r, &other_interface, 5000)));
    }

    #[test]
    fn foreign_addresses_cnames_and_odd_nsecs_conflict() {
        for rec in [
            a("192.0.2.99", TTL, true),
            Record {
                rdata: RData::Cname(name("elsewhere.local")),
                ..a("192.0.2.10", TTL, true)
            },
            nsec(&[RType(16)], TTL, true),
        ] {
            let mut r = announced_with(&["192.0.2.10"]);
            assert!(
                claimed(&hear(&mut r, &response(vec![rec.clone()]), 5000)),
                "{rec:?}"
            );
        }
    }

    #[test]
    fn a_just_removed_address_is_not_a_conflict_for_a_while() {
        let looped = response(vec![a("192.0.2.10", TTL, true)]);
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 5000);
        assert!(!claimed(&hear(&mut r, &looped, 5100)));
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 5000);
        assert!(claimed(&hear(&mut r, &looped, 5000 + RETIRED_GRACE + 1)));
    }

    #[test]
    fn an_interface_left_with_no_addresses_is_forgotten() {
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 0);
        r.add_link(V4B, 0);
        run(&mut r, 0, 2000);
        r.set_addresses(IfIndex::of(2), Vec::new(), 5000);
        assert_eq!(r.addrs, [(IfIndex::of(3), vec![ip("198.51.100.10")])]);
        // Departed interfaces leave nothing behind, however many come and go.
        for index in (10..20).map(IfIndex::of) {
            r.set_addresses(index, vec![ip("203.0.113.10")], 5000);
            r.set_addresses(index, Vec::new(), 5000);
        }
        r.set_addresses(IfIndex::of(30), Vec::new(), 5000);
        assert_eq!(r.addrs.len(), 1);
        // Its addresses still count as ours for the retired window, heard
        // on interface 3, where the alias is still served.
        let looped = wire::encode(&response(vec![a("192.0.2.10", TTL, true)]));
        assert!(!claimed(&r.handle(&looped, V4B, OTHER, 5100)));
        assert!(claimed(&r.handle(
            &looped,
            V4B,
            OTHER,
            5000 + RETIRED_GRACE + 1
        )));
    }

    #[test]
    fn own_nsec_is_not_a_conflict() {
        let mut r = announced_with(&["192.0.2.10"]);
        assert!(!claimed(&hear(
            &mut r,
            &response(vec![nsec(&[RType::A], TTL, true)]),
            5000
        )));
        let own = announcement(&r, V4);
        assert!(!claimed(&hear(&mut r, &own, 5000)));
    }

    fn txt(ttl: u32) -> Record {
        Record {
            rdata: RData::other(RType(16), vec![1, b'x']).unwrap(),
            ..a("192.0.2.10", ttl, true)
        }
    }

    /// RFC 6762 section 8.1: our probes ask for ANY, so while probing, a
    /// record of the alias's name of any type answers them.
    #[test]
    fn any_record_of_the_name_answers_our_probe() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        // Before our first probe: ignored (RFC 6762 section 8.1).
        assert!(!claimed(&hear(&mut r, &response(vec![txt(TTL)]), 0)));
        run(&mut r, 0, 260);
        // A goodbye withdraws rather than answers.
        assert!(!claimed(&hear(&mut r, &response(vec![txt(0)]), 300)));
        // Our own records, from another interface, do not answer it.
        let own = response(vec![
            a("192.0.2.10", TTL, true),
            nsec(&[RType::A], TTL, true),
        ]);
        assert!(!claimed(&hear(&mut r, &own, 300)));
        let step = hear(&mut r, &response(vec![txt(TTL)]), 300);
        assert!(matches!(step.notices[..], [Notice::Lost { .. }]));
    }

    /// A record of another class answers neither our probe (which asks
    /// about class IN) nor conflicts once established.
    #[test]
    fn records_of_another_class_are_ignored() {
        let mut theirs = a("192.0.2.99", TTL, true);
        theirs.class = Class(3);
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 260);
        assert!(!claimed(&hear(
            &mut r,
            &response(vec![theirs.clone()]),
            300
        )));
        let mut r = announced_responder();
        assert!(!claimed(&hear(&mut r, &response(vec![theirs]), 5000)));
    }

    /// Once established, section 9 applies: only a record of a type we
    /// publish, with other data, conflicts.
    #[test]
    fn other_types_for_an_alias_are_not_conflicts() {
        let mut r = announced_with(&["192.0.2.10"]);
        let step = hear(&mut r, &response(vec![txt(TTL)]), 5000);
        assert!(!claimed(&step));
        assert!(step.sends.is_empty());
        // Still answered for.
        let q = query(&[(ALIAS, RType::A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 5000).len(), 1);
    }

    #[test]
    fn an_address_record_of_the_wrong_length_is_a_conflict() {
        let mut r = announced_with(&["192.0.2.10"]);
        let short = Record {
            rdata: RData::other(RType::A, vec![192, 0, 2]).unwrap(),
            ..a("192.0.2.10", TTL, true)
        };
        let msg = response(vec![short]);
        let parsed = wire::parse(&wire::encode(&msg)).unwrap();
        assert!(matches!(
            parsed.answers[0].rdata,
            RData::Other(ref raw) if raw.rtype() == RType::A
        ));
        assert!(claimed(&hear(&mut r, &msg, 5000)));
    }

    #[test]
    fn canonical_orders_by_class_then_type_then_rdata() {
        // A lower class wins over a lower type, and a lower type over
        // lower rdata bytes.
        let aaaa_in = aaaa("2001:db8::1", TTL, false);
        let a_chaos = Record {
            class: Class(3),
            ..a("192.0.2.1", TTL, false)
        };
        assert!(canonical(&aaaa_in) < canonical(&a_chaos));
        let a_high = a("192.0.2.200", TTL, false);
        let aaaa_low = aaaa("::1", TTL, false);
        assert!(canonical(&a_high) < canonical(&aaaa_low));
        assert!(canonical(&a("192.0.2.1", TTL, false)) < canonical(&a_high));
    }

    #[test]
    fn tiebreaks_compare_address_sets() {
        let probe_from = |addr: &str| {
            let mut p = query(&[(ALIAS, RType::ANY, true)]);
            p.authorities = vec![a(addr, TTL, false)];
            p
        };
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        // Ours is [A 192.0.2.10, NSEC]; theirs [A 192.0.2.200]. The first
        // records differ and ours is lower, so we lose.
        assert_eq!(
            hear(&mut r, &probe_from("192.0.2.200"), 251).notices,
            [Notice::TiebreakLost(V4, name(ALIAS))]
        );
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        assert!(
            hear(&mut r, &probe_from("192.0.2.1"), 251)
                .notices
                .is_empty()
        );
    }

    #[test]
    fn this_hosts_own_probes_on_another_interface_do_not_tiebreak() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 0);
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        let mut p = query(&[(ALIAS, RType::ANY, true)]);
        p.authorities = vec![
            a("198.51.100.10", TTL, false),
            nsec(&[RType::A], TTL, false),
        ];
        let step = hear(&mut r, &p, 251);
        assert!(step.notices.is_empty(), "{:?}", step.notices);
        // A foreign address among the records still counts as a rival.
        p.authorities.push(a("203.0.113.200", TTL, false));
        assert_eq!(
            hear(&mut r, &p, 252).notices,
            [Notice::TiebreakLost(V4, name(ALIAS))]
        );
    }

    #[test]
    fn announcements_are_packed_within_packet_limits() {
        let aliases: Vec<Name> = (0..40)
            .map(|i| name(&format!("service{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), 7);
        let addrs = ["192.0.2.10", "2001:db8::10", "fd00::10", "fe80::10"]
            .map(ip)
            .to_vec();
        r.set_addresses(IfIndex::of(2), addrs, 0);
        r.add_link(V4, 0);
        let (sent, _) = run(&mut r, 0, 3000);
        let announcements: Vec<&Outgoing> = sent
            .iter()
            .filter(|(_, o)| decode(o).is_response)
            .map(|(_, o)| o)
            .collect();
        assert!(
            announcements.len() > 2,
            "40 aliases need more than one packet per announcement"
        );
        let mut seen = std::collections::BTreeMap::new();
        for out in &announcements {
            assert!(out.packet.len() <= MAX_PACKET);
            for rec in decode(out).answers {
                *seen.entry(rec.name.to_string()).or_insert(0) += 1;
            }
        }
        // Two announcements, four records each, every alias.
        assert_eq!(seen.len(), 40);
        assert!(seen.values().all(|&n| n == 8), "{seen:?}");
        for out in &announcements {
            let names: std::collections::BTreeSet<String> = decode(out)
                .answers
                .iter()
                .map(|r| r.name.to_string())
                .collect();
            for alias in &names {
                assert_eq!(
                    decode(out)
                        .answers
                        .iter()
                        .filter(|r| r.name.to_string() == *alias)
                        .count(),
                    4,
                    "records of {alias} split"
                );
            }
        }
    }

    #[test]
    fn pack_starts_a_new_packet_for_a_part_that_overflows_the_open_one() {
        let part = |tag: &str| {
            response(
                (0..40)
                    .map(|i| a_record(&format!("{tag}{i}.myhost.local"), 120))
                    .collect(),
            )
        };
        let (first, second) = (part("a"), part("b"));
        // Each fits alone, the two together do not.
        assert!(wire::encode(&first).len() <= MAX_PACKET);
        assert!(wire::encode(&second).len() <= MAX_PACKET);
        let mut both = first.clone();
        both.answers.extend(second.answers.clone());
        assert!(wire::encode(&both).len() > MAX_PACKET);
        let (packets, too_big) = pack(
            true,
            vec![(AliasId(0), first.clone()), (AliasId(1), second.clone())],
        );
        assert!(too_big.is_empty());
        assert_eq!(packets.len(), 2);
        assert_eq!(wire::parse(&packets[0]).unwrap().answers, first.answers);
        assert_eq!(wire::parse(&packets[1]).unwrap().answers, second.answers);
    }

    #[test]
    fn answers_are_packed_per_alias_within_packet_limits() {
        let aliases: Vec<Name> = (0..40)
            .map(|i| name(&format!("service{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), 7);
        r.set_addresses(
            IfIndex::of(2),
            ["192.0.2.10", "2001:db8::10", "fd00::10"].map(ip).to_vec(),
            0,
        );
        announced(&mut r, V4);
        let mut q = Message {
            id: 0,
            ..Message::default()
        };
        for alias in &aliases {
            for qtype in [RType::A, RType::AAAA] {
                q.questions.push(Question {
                    name: alias.clone(),
                    qtype,
                    qclass: Class::IN,
                    unicast_response: false,
                });
            }
        }
        let sent = r.handle(&wire::encode(&q), V4, CLIENT, 10_000).sends;
        assert!(sent.len() > 1);
        assert!(sent.iter().all(|o| o.packet.len() <= MAX_PACKET));
        let answered: std::collections::BTreeSet<String> = sent
            .iter()
            .flat_map(|o| decode(o).answers)
            .map(|r| r.name.to_string())
            .collect();
        assert_eq!(answered.len(), 40);
    }

    #[test]
    fn a_legacy_reply_is_one_packet_within_the_limit() {
        let aliases: Vec<Name> = (0..MAX_LEGACY_QUESTIONS)
            .map(|i| name(&format!("service{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), 7);
        r.set_addresses(
            IfIndex::of(2),
            ["192.0.2.10", "2001:db8::10", "fd00::10"].map(ip).to_vec(),
            0,
        );
        announced(&mut r, V4);
        let mut q = Message {
            id: 9,
            ..Message::default()
        };
        for alias in &aliases {
            q.questions.push(Question {
                name: alias.clone(),
                qtype: RType::ANY,
                qclass: Class::IN,
                unicast_response: false,
            });
        }
        let sent = r.handle(&wire::encode(&q), V4, LEGACY, 10_000).sends;
        assert_eq!(sent.len(), 1);
        assert!(sent[0].packet.len() <= MAX_PACKET);
        let msg = decode(&sent[0]);
        assert_eq!(msg.id, 9);
        assert!(
            !msg.answers.is_empty() && msg.answers.iter().all(|r| r.ttl == 10 && !r.cache_flush)
        );
    }

    #[test]
    fn an_alias_too_big_for_any_packet_is_reported_once_and_skipped() {
        let mut r = Responder::new(vec![name(ALIAS)], 7);
        let many: Vec<IpAddr> = (1..=60u16)
            .map(|i| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
            .collect();
        r.set_addresses(IfIndex::of(2), many, 0);
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 3000);
        assert!(sent.is_empty());
        let oversized: Vec<&Notice> = notices
            .iter()
            .filter(|n| matches!(n, Notice::Oversized(..)))
            .collect();
        assert_eq!(oversized, [&Notice::Oversized(V4, name(ALIAS))]);
    }

    /// `n` IPv6 addresses from the documentation range.
    fn v6(n: u16) -> Vec<IpAddr> {
        (1..=n)
            .map(|i| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
            .collect()
    }

    /// A responder for ALIAS, with interface 2 at `addrs`.
    fn single(addrs: Vec<IpAddr>) -> Responder {
        let mut r = Responder::new(vec![name(ALIAS)], 7);
        r.set_addresses(IfIndex::of(2), addrs, 0);
        r
    }

    #[test]
    fn an_alias_whose_announcement_fits_but_probe_does_not_is_never_served() {
        let probe = Kind::Probe;
        let announce = Kind::Announce { ttl: TTL };
        // Each AAAA record takes 28 bytes and the window is a few bytes
        // wide, so the alias's length is varied as well to land in it.
        let in_window = |(label, count): (usize, u16)| {
            let alias = name(&format!("{}.myhost.local", "a".repeat(label)));
            let records = Records {
                aliases: vec![alias.clone()],
            };
            let addrs = v6(count);
            let size =
                |kind| wire::encode(&part(&records, AliasId(0), &addrs, kind).unwrap()).len();
            (size(announce) <= MAX_PACKET && size(probe) > MAX_PACKET).then_some((alias, addrs))
        };
        let (alias, addrs) = (1..=28)
            .flat_map(|label| (40..60).map(move |count| (label, count)))
            .find_map(in_window)
            .expect("nothing puts the probe and announcement either side of the limit");
        let mut r = Responder::new(vec![alias.clone()], 7);
        r.set_addresses(IfIndex::of(2), addrs, 0);
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 5000);
        assert!(sent.is_empty(), "{sent:?}");
        assert_eq!(notices, [Notice::Oversized(V4, alias.clone())]);
        for source in [CLIENT, LEGACY] {
            let any = Message {
                questions: vec![Question {
                    name: alias.clone(),
                    qtype: RType::ANY,
                    qclass: Class::IN,
                    unicast_response: false,
                }],
                ..Message::default()
            };
            assert!(ask(&mut r, &any, source, 10_000).is_empty());
        }
        assert!(r.goodbye().is_empty());
    }

    #[test]
    fn an_alias_crossing_the_limit_is_reported_each_time_and_probed_when_it_fits() {
        let (fits, big) = (v6(10), v6(60));
        let ask_any = |r: &mut Responder, now| {
            let any = query(&[(ALIAS, RType::ANY, false)]);
            ask(r, &any, CLIENT, now)
        };
        let mut r = single(fits.clone());
        announced(&mut r, V4);
        // Too big: goodbyes for everything it had, and silence.
        let step = r.set_addresses(IfIndex::of(2), big.clone(), 5000);
        assert_eq!(step.notices, [Notice::Oversized(V4, name(ALIAS))]);
        let goodbye = one(step.sends);
        assert_eq!(goodbye.answers.len(), 11);
        assert!(goodbye.answers.iter().all(|r| r.ttl == 0));
        assert!(ask_any(&mut r, 6000).is_empty());
        let (sent, notices) = run(&mut r, 5001, 8000);
        assert!(
            sent.is_empty() && notices.is_empty(),
            "{sent:?} {notices:?}"
        );
        // Fits again: nothing to say goodbye to, then probed as on a new link.
        let step = r.set_addresses(IfIndex::of(2), fits.clone(), 9000);
        assert!(step.sends.is_empty() && step.notices.is_empty(), "{step:?}");
        assert!(ask_any(&mut r, 9100).is_empty(), "answered before probing");
        let (sent, notices) = run(&mut r, 9000, 12_000);
        let kinds: Vec<bool> = sent.iter().map(|(_, o)| decode(o).is_response).collect();
        assert_eq!(kinds, [false, false, false, true, true]);
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
        assert_eq!(ask_any(&mut r, 13_000).len(), 1);
        // Too big again: reported again.
        let step = r.set_addresses(IfIndex::of(2), big.clone(), 14_000);
        assert_eq!(step.notices, [Notice::Oversized(V4, name(ALIAS))]);

        // While probing, an alias that comes to fit gets all three probes.
        let mut r = single(big);
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 1000);
        assert!(sent.is_empty());
        assert_eq!(notices, [Notice::Oversized(V4, name(ALIAS))]);
        assert!(r.set_addresses(IfIndex::of(2), fits, 1000).sends.is_empty());
        let (sent, notices) = run(&mut r, 1000, 4000);
        let kinds: Vec<bool> = sent.iter().map(|(_, o)| decode(o).is_response).collect();
        assert_eq!(kinds, [false, false, false, true, true]);
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
    }

    #[test]
    fn nothing_announced_is_not_reported_as_announced() {
        let mut r = single(v6(60));
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 5000);
        assert!(sent.is_empty());
        assert!(
            !notices.contains(&Notice::Announced(V4, vec![name(ALIAS)])),
            "{notices:?}"
        );
        // A change that leaves it too big re-announces nothing either.
        let step = r.set_addresses(IfIndex::of(2), v6(61), 6000);
        assert!(step.sends.is_empty() && step.notices.is_empty(), "{step:?}");
        let (sent, notices) = run(&mut r, 6000, 9000);
        assert!(
            sent.is_empty() && notices.is_empty(),
            "{sent:?} {notices:?}"
        );
    }

    #[test]
    fn a_legacy_reply_echoes_only_the_questions_it_answers() {
        let mut r = announced_with(&["192.0.2.10"]);
        let q = query(&[
            ("other.myhost.local", RType::A, false),
            (ALIAS, RType::A, false),
            ("more.myhost.local", RType::A, false),
        ]);
        let reply = one(ask(&mut r, &q, LEGACY, 10_000));
        assert_eq!(reply.id, q.id);
        assert_eq!(
            reply.questions,
            query(&[(ALIAS, RType::A, false)]).questions
        );
        assert_eq!(reply.answers, [a("192.0.2.10", LEGACY_TTL, false)]);
        // The echo keeps the querier's case.
        let q = query(&[("APP.MyHost.local", RType::A, false)]);
        assert_eq!(one(ask(&mut r, &q, LEGACY, 11_000)).questions, q.questions);
    }

    #[test]
    fn a_legacy_reply_keeps_only_answered_questions_when_they_leave_no_room() {
        // Aliases with long distinct first labels: their questions alone
        // take more than a packet, so the first pass of `fit` cannot help.
        let aliases: Vec<Name> = (0..MAX_LEGACY_QUESTIONS)
            .map(|i| name(&format!("{}{i:02}.myhost.local", "a".repeat(60))))
            .collect();
        let mut r = Responder::new(aliases.clone(), 7);
        r.set_addresses(IfIndex::of(2), vec![ip(MINE)], 0);
        announced(&mut r, V4);
        let mut q = Message {
            id: 7,
            ..Message::default()
        };
        for alias in &aliases {
            q.questions.push(Question {
                name: alias.clone(),
                qtype: RType::ANY,
                qclass: Class::IN,
                unicast_response: false,
            });
        }
        assert!(wire::encode(&q).len() > MAX_PACKET);
        let sent = ask(&mut r, &q, LEGACY, 10_000);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].packet.len() <= MAX_PACKET);
        let reply = decode(&sent[0]);
        assert_eq!(reply.id, 7);
        // Some answers, each with its question, and no question without one.
        let asked: Vec<Name> = reply.questions.iter().map(|q| q.name.clone()).collect();
        let mut answered: Vec<Name> = reply.answers.iter().map(|a| a.name.clone()).collect();
        answered.dedup();
        let n = answered.len();
        assert!(0 < n && n < aliases.len(), "{n}");
        assert_eq!(asked, answered);
        assert_eq!(asked, aliases[..n]);
    }

    #[test]
    fn a_legacy_query_with_too_many_questions_is_not_answered() {
        let mut r = announced_with(&["192.0.2.10"]);
        let others: Vec<String> = (0..MAX_LEGACY_QUESTIONS)
            .map(|i| format!("other{i}.myhost.local"))
            .collect();
        let mut questions = vec![(ALIAS, RType::A, false)];
        questions.extend(others.iter().map(|n| (n.as_str(), RType::A, false)));
        let q = query(&questions);
        assert!(ask(&mut r, &q, LEGACY, 10_000).is_empty());
        // One fewer is answered, at once, with just the alias echoed.
        let q = query(&questions[..MAX_LEGACY_QUESTIONS]);
        let reply = one(ask(&mut r, &q, LEGACY, 11_000));
        assert_eq!(
            reply.questions,
            query(&[(ALIAS, RType::A, false)]).questions
        );
        assert_eq!(reply.answers, [a("192.0.2.10", LEGACY_TTL, false)]);
        // A query from port 5353 is not a legacy one: no cap.
        let q = query(&questions);
        assert_eq!(ask(&mut r, &q, CLIENT, 12_000).len(), 1);
    }

    const WEB: &str = "web.myhost.local";

    fn web(rec: Record) -> Record {
        Record {
            name: name(WEB),
            ..rec
        }
    }

    fn two_aliases() -> Records {
        Records {
            aliases: vec![name(ALIAS), name(WEB)],
        }
    }

    #[test]
    fn collect_lists_each_record_once_and_none_in_both_sections() {
        let records = two_aliases();
        let addrs = ["192.0.2.10", "2001:db8::10"].map(ip);
        // A and AAAA asked together: each is the other's additional record,
        // but both are answers, so there are none.
        let q = query(&[
            (ALIAS, RType::A, true),
            (ALIAS, RType::AAAA, true),
            (ALIAS, RType::A, true),
        ]);
        let (answers, additionals, all_unicast) = collect(&records, &q, &addrs, TTL, true);
        assert_eq!(
            answers,
            [
                (AliasId(0), a("192.0.2.10", TTL, true)),
                (AliasId(0), aaaa("2001:db8::10", TTL, true))
            ]
        );
        assert!(additionals.is_empty());
        assert!(all_unicast);
        // Only questions about our aliases count towards all_unicast.
        let q = query(&[("other.local", RType::A, false), (WEB, RType::A, true)]);
        let (answers, additionals, all_unicast) = collect(&records, &q, &addrs, TTL, true);
        assert_eq!(answers, [(AliasId(1), web(a("192.0.2.10", TTL, true)))]);
        assert_eq!(
            additionals,
            [(AliasId(1), web(aaaa("2001:db8::10", TTL, true)))]
        );
        assert!(all_unicast);
        let q = query(&[(WEB, RType::A, true), (ALIAS, RType::A, false)]);
        assert!(!collect(&records, &q, &addrs, TTL, true).2);
    }

    #[test]
    fn a_known_answer_with_half_its_ttl_left_suppresses_just_that_record_set() {
        let ours = || {
            vec![
                (AliasId(0), a("192.0.2.10", TTL, true)),
                (AliasId(0), aaaa("2001:db8::10", TTL, true)),
                (AliasId(1), web(a("192.0.2.10", TTL, true))),
            ]
        };
        let mut records = ours();
        suppress_known(&mut records, &[a("192.0.2.10", TTL / 2, false)]);
        assert_eq!(records, ours()[1..]);
        // Below half its TTL, the querier is due a fresh copy.
        let mut records = ours();
        suppress_known(&mut records, &[a("192.0.2.10", TTL / 2 - 1, false)]);
        assert_eq!(records, ours());
        // Another alias's record, or another type with the same bytes,
        // suppresses nothing.
        let mut records = ours();
        let other_type = Record {
            rdata: RData::other(RType(16), vec![192, 0, 2, 10]).unwrap(),
            ..a("192.0.2.10", TTL, false)
        };
        let other_alias = Record {
            name: name("other.myhost.local"),
            ..a("192.0.2.10", TTL, false)
        };
        suppress_known(&mut records, &[other_type, other_alias]);
        assert_eq!(records, ours());
    }

    #[test]
    fn a_record_set_is_suppressed_only_when_every_record_of_it_is_known() {
        let ours = || {
            vec![
                (AliasId(0), a("192.0.2.10", TTL, true)),
                (AliasId(0), a("192.0.2.11", TTL, true)),
                (AliasId(0), aaaa("2001:db8::10", TTL, true)),
            ]
        };
        // One of two A records known: the whole A set stays (RFC 6762
        // section 10.2).
        let mut records = ours();
        suppress_known(&mut records, &[a("192.0.2.10", TTL, false)]);
        assert_eq!(records, ours());
        // Both known, but one below half its TTL: still the whole set.
        let mut records = ours();
        let known = [
            a("192.0.2.10", TTL, false),
            a("192.0.2.11", TTL / 2 - 1, false),
        ];
        suppress_known(&mut records, &known);
        assert_eq!(records, ours());
        // Both known with half their TTL: the set goes, the AAAA set stays.
        let mut records = ours();
        let known = [a("192.0.2.10", TTL, false), a("192.0.2.11", TTL / 2, false)];
        suppress_known(&mut records, &known);
        assert_eq!(records, ours()[2..]);
    }

    #[test]
    fn a_reply_never_carries_part_of_a_record_set() {
        // The review's case: two A records, one known with its full TTL.
        // Sending only the other, with cache-flush set, would make every
        // cache on the link drop the known one.
        let mut r = announced_with(&["192.0.2.10", "192.0.2.11"]);
        let mut q = query(&[(ALIAS, RType::A, false)]);
        q.answers = vec![a("192.0.2.10", TTL, false)];
        let msg = one(ask(&mut r, &q, CLIENT, 10_000));
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), a("192.0.2.11", TTL, true)]
        );
        // Both known: nothing to send.
        q.answers.push(a("192.0.2.11", TTL, false));
        assert!(ask(&mut r, &q, CLIENT, 20_000).is_empty());
        // The same for additional records: an AAAA query with one of two
        // A records known still carries the whole A set.
        let mut r = announced_with(&["192.0.2.10", "192.0.2.11", "2001:db8::10"]);
        let mut q = query(&[(ALIAS, RType::AAAA, false)]);
        q.answers = vec![a("192.0.2.11", TTL, false)];
        let msg = one(ask(&mut r, &q, CLIENT, 10_000));
        assert_eq!(msg.answers, [aaaa("2001:db8::10", TTL, true)]);
        assert_eq!(
            msg.additionals,
            [a("192.0.2.10", TTL, true), a("192.0.2.11", TTL, true)]
        );
    }

    #[test]
    fn a_known_answer_of_another_class_suppresses_nothing() {
        let ours = vec![(AliasId(0), a("192.0.2.10", TTL, true))];
        let mut records = ours.clone();
        let chaos = Record {
            class: Class(3),
            ..a("192.0.2.10", TTL, false)
        };
        suppress_known(&mut records, &[chaos]);
        assert_eq!(records, ours);
    }

    #[test]
    fn a_known_answer_leaves_the_rest_of_the_reply() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let mut q = query(&[(ALIAS, RType::ANY, false)]);
        q.answers = vec![a("192.0.2.10", TTL, false)];
        let msg = one(ask(&mut r, &q, CLIENT, 10_000));
        assert_eq!(msg.answers, [aaaa("2001:db8::10", TTL, true)]);
    }

    #[test]
    fn the_rate_limit_is_per_alias_and_type() {
        let mut state = LinkState {
            aliases: Vec::new(),
            deferred: Vec::new(),
            last_multicast: Vec::new(),
            planned: Vec::new(),
        };
        state.set_last((AliasId(0), RType::AAAA), 1000);
        let mut answers = vec![
            (AliasId(0), a("192.0.2.10", TTL, true)),
            (AliasId(0), aaaa("2001:db8::10", TTL, true)),
            (AliasId(1), web(aaaa("2001:db8::10", TTL, true))),
        ];
        rate_limit(&mut state, &mut answers, false, 1500);
        assert_eq!(
            answers,
            [
                (AliasId(0), a("192.0.2.10", TTL, true)),
                (AliasId(1), web(aaaa("2001:db8::10", TTL, true)))
            ]
        );
        assert_eq!(state.last((AliasId(0), RType::A)), Some(1500));
        assert_eq!(state.last((AliasId(0), RType::AAAA)), Some(1000));
        assert_eq!(state.last((AliasId(1), RType::AAAA)), Some(1500));
        // A record set is free again RATE_LIMIT after it went out.
        let mut again = vec![(AliasId(0), aaaa("2001:db8::10", TTL, true))];
        rate_limit(&mut state, &mut again, false, 1000 + RATE_LIMIT);
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn probe_answers_keep_only_the_shorter_rate_limit() {
        let mut state = LinkState {
            aliases: Vec::new(),
            deferred: Vec::new(),
            last_multicast: Vec::new(),
            planned: Vec::new(),
        };
        state.set_last((AliasId(0), RType::A), 1000);
        let mut answers = vec![(AliasId(0), a("192.0.2.10", TTL, true))];
        rate_limit(&mut state, &mut answers, true, 1000 + PROBE_RATE_LIMIT - 1);
        assert!(answers.is_empty());
        assert_eq!(state.last((AliasId(0), RType::A)), Some(1000));
        let mut answers = vec![(AliasId(0), a("192.0.2.10", TTL, true))];
        rate_limit(&mut state, &mut answers, true, 1000 + PROBE_RATE_LIMIT);
        assert_eq!(answers.len(), 1);
        assert_eq!(
            state.last((AliasId(0), RType::A)),
            Some(1000 + PROBE_RATE_LIMIT)
        );
    }

    #[test]
    fn an_a_query_right_after_an_aaaa_multicast_is_answered() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let mut aaaa_q = query(&[(ALIAS, RType::AAAA, false)]);
        // Knowing the A record keeps it out of the additional records.
        aaaa_q.answers = vec![a("192.0.2.10", TTL, false)];
        let a_q = query(&[(ALIAS, RType::A, false)]);
        let msg = one(ask(&mut r, &aaaa_q, CLIENT, 3000));
        assert_eq!(msg.answers, [aaaa("2001:db8::10", TTL, true)]);
        assert!(msg.additionals.is_empty());
        let msg = one(ask(&mut r, &a_q, CLIENT, 3100));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert!(ask(&mut r, &a_q, CLIENT, 3200).is_empty());
        assert!(ask(&mut r, &aaaa_q, CLIENT, 3200).is_empty());
    }

    /// RFC 6762 section 6: additional records are multicast records too,
    /// so they count towards the one-second limit and are held to it, by
    /// record set.
    #[test]
    fn additional_records_are_rate_limited_and_counted() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10", "2001:db8::11"]);
        let aaaa_set = [
            aaaa("2001:db8::10", TTL, true),
            aaaa("2001:db8::11", TTL, true),
        ];
        let a_q = query(&[(ALIAS, RType::A, false)]);
        let aaaa_q = query(&[(ALIAS, RType::AAAA, false)]);
        // An A answer brings the AAAA set as additional records ...
        let msg = one(ask(&mut r, &a_q, CLIENT, 3000));
        assert_eq!(msg.additionals, aaaa_set);
        // ... which counts as multicasting it.
        assert!(ask(&mut r, &aaaa_q, CLIENT, 3500).is_empty());
        let mut a_known = aaaa_q.clone();
        a_known.answers = vec![a("192.0.2.10", TTL, false)];
        let msg = one(ask(&mut r, &a_known, CLIENT, 4000));
        assert_eq!(msg.answers, aaaa_set);
        // An answer goes out without an additional set multicast within
        // the second, which is left out whole.
        let msg = one(ask(&mut r, &a_q, CLIENT, 4500));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert!(msg.additionals.is_empty());
        // Once the second has passed it rides along again.
        let msg = one(ask(&mut r, &a_q, CLIENT, 5500));
        assert_eq!(msg.additionals, aaaa_set);
    }

    /// On a single-family interface the NSEC rides along as the additional
    /// record of an A answer, and counts as multicast like any other: an
    /// AAAA question (answered by the NSEC) within the second gets nothing.
    #[test]
    fn an_nsec_sent_as_an_additional_record_is_rate_limited() {
        let mut r = announced_with(&[MINE]);
        let a_q = query(&[(ALIAS, RType::A, false)]);
        let aaaa_q = query(&[(ALIAS, RType::AAAA, false)]);
        let msg = one(ask(&mut r, &a_q, CLIENT, 3000));
        assert_eq!(msg.answers, [a(MINE, TTL, true)]);
        assert_eq!(msg.additionals, [nsec(&[RType::A], TTL, true)]);
        assert!(ask(&mut r, &aaaa_q, CLIENT, 3999).is_empty());
        let msg = one(ask(&mut r, &aaaa_q, CLIENT, 4000));
        assert_eq!(msg.answers, [nsec(&[RType::A], TTL, true)]);
        assert_eq!(msg.additionals, [a(MINE, TTL, true)]);
    }

    /// Additional records of an alias whose answers the rate limit dropped
    /// are not sent, so not counted either, while another alias in the
    /// same reply goes out.
    #[test]
    fn dropped_answers_leave_their_additional_records_uncounted() {
        let mut r = Responder::new(vec![name(ALIAS), name(WEB)], 7);
        r.set_addresses(
            IfIndex::of(2),
            ["192.0.2.10", "2001:db8::10"].map(ip).to_vec(),
            0,
        );
        announced(&mut r, V4);
        let mut web_a = query(&[(WEB, RType::A, false)]);
        web_a.answers = vec![web(aaaa("2001:db8::10", TTL, false))];
        assert_eq!(one(ask(&mut r, &web_a, CLIENT, 3000)).additionals, []);
        let both = query(&[(WEB, RType::A, false), (ALIAS, RType::A, false)]);
        let msg = one(ask(&mut r, &both, CLIENT, 3500));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
        let web_aaaa = query(&[(WEB, RType::AAAA, false)]);
        let msg = one(ask(&mut r, &web_aaaa, CLIENT, 3600));
        assert_eq!(msg.answers, [web(aaaa("2001:db8::10", TTL, true))]);
    }

    /// A unicast reply falling back to multicast holds its additional
    /// records to the limit too.
    #[test]
    fn a_unicast_fallback_rate_limits_its_additional_records() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let aaaa_q = query(&[(ALIAS, RType::AAAA, false)]);
        assert_eq!(one(ask(&mut r, &aaaa_q, CLIENT, 3000)).answers.len(), 1);
        let reply = ask(&mut r, &query(&[(ALIAS, RType::A, true)]), CLIENT, 3500);
        assert_eq!(decode(&reply[0]).additionals.len(), 1);
        let sent = r.unicast_failed(&reply[0], 3500);
        assert!(sent.is_empty(), "A was multicast as additional at 3000");
        let reply = ask(&mut r, &query(&[(ALIAS, RType::A, true)]), CLIENT, 4000);
        let msg = one(r.unicast_failed(&reply[0], 4000));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
    }

    /// A unicast reply that found no route goes by multicast, under the
    /// one-a-second limit (RFC 6762 section 6), and counts towards it.
    #[test]
    fn a_unicast_reply_without_a_route_is_multicast_within_the_rate_limit() {
        let mut r = announced_with(&["192.0.2.10"]);
        let qu = query(&[(ALIAS, RType::A, true)]);
        let reply = ask(&mut r, &qu, CLIENT, 3000);
        assert_eq!(reply.len(), 1);
        assert_eq!(reply[0].dest, Dest::Unicast(CLIENT));
        let sent = r.unicast_failed(&reply[0], 3000);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].link, V4);
        assert_eq!(sent[0].dest, Dest::Multicast);
        assert_eq!(decode(&sent[0]).answers, decode(&reply[0]).answers);
        // A second failure 1 ms later sends nothing.
        let again = ask(&mut r, &qu, CLIENT, 3001);
        assert_eq!(again[0].dest, Dest::Unicast(CLIENT));
        assert!(r.unicast_failed(&again[0], 3001).is_empty());
        // Nor does the responder's own next multicast of it within 1 s.
        let qm = query(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &qm, CLIENT, 3999).is_empty());
        assert_eq!(ask(&mut r, &qm, CLIENT, 4000).len(), 1);
        // A reply on a link no longer served has nothing to fall back to.
        r.remove_link(V4);
        assert!(r.unicast_failed(&reply[0], 6000).is_empty());
    }

    #[test]
    fn unicast_and_legacy_replies_are_not_rate_limited() {
        let mut r = announced_with(&["192.0.2.10"]);
        let qu = query(&[(ALIAS, RType::A, true)]);
        let qm = query(&[(ALIAS, RType::A, false)]);
        // Where the one reply went; anything but one reply fails.
        let dest = |sent: Vec<Outgoing>| {
            assert_eq!(sent.len(), 1, "{sent:?}");
            sent[0].dest
        };
        for now in [3000, 3001] {
            assert_eq!(dest(ask(&mut r, &qu, CLIENT, now)), Dest::Unicast(CLIENT));
            assert_eq!(dest(ask(&mut r, &qm, LEGACY, now)), Dest::Unicast(LEGACY));
        }
        // Nor do they count as multicasts for the rate limit.
        assert_eq!(dest(ask(&mut r, &qm, CLIENT, 3002)), Dest::Multicast);
    }

    /// RFC 6762 section 11: a sender off our subnets, accepted because it
    /// asked the group, or one with no route back, is answered by multicast
    /// even when it asks for unicast, and never by unicast.
    #[test]
    fn a_sender_unicast_cannot_reach_is_answered_by_multicast_or_not_at_all() {
        let mut r = announced_with(&["192.0.2.10"]);
        let far = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let querier = Source {
            addr: SocketAddr::new(far, 5353),
            unicast: false,
            direct: false,
        };
        let qu = query(&[(ALIAS, RType::A, true)]);
        let sent = ask(&mut r, &qu, querier, 3000);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].dest, Dest::Multicast);
        assert_eq!(decode(&sent[0]).answers.len(), 1);
        // A multicast like any other: rate-limited.
        assert!(ask(&mut r, &qu, querier, 3001).is_empty());
        // A legacy querier cannot hear multicast: no reply at all.
        let legacy = Source {
            addr: SocketAddr::new(far, 54928),
            unicast: false,
            direct: false,
        };
        let qm = query(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &qm, legacy, 5000).is_empty());
        // A deferred question goes the same way once its wait is over.
        assert!(
            ask(
                &mut r,
                &truncated(&[(ALIAS, RType::A, true)]),
                querier,
                10_000
            )
            .is_empty()
        );
        let (sent, _) = run(&mut r, 10_000, 11_000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.dest, Dest::Multicast);
    }

    /// `query` with the TC bit set: more known answers follow.
    fn truncated(questions: &[(&str, RType, bool)]) -> Message {
        Message {
            truncated: true,
            ..query(questions)
        }
    }

    /// A continuation packet: known answers only, with TC if `more` follow.
    fn continuation(known: Vec<Record>, more: bool) -> Message {
        Message {
            truncated: more,
            answers: known,
            ..Message::default()
        }
    }

    fn querier(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), MDNS_PORT)
    }

    #[test]
    fn a_truncated_query_is_answered_400_to_500_ms_later() {
        let mut times = BTreeSet::new();
        for seed in 0..50 {
            let mut r = seeded(seed);
            announced(&mut r, V4);
            let q = truncated(&[(ALIAS, RType::A, false)]);
            assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
            let (sent, _) = run(&mut r, 10_000, 11_000);
            assert_eq!(sent.len(), 1);
            let (at, out) = &sent[0];
            assert!((10_400..=10_500).contains(at), "answered at {at}");
            assert_eq!(out.dest, Dest::Multicast);
            assert_eq!(decode(out).answers, [a(MINE, TTL, true)]);
            times.insert(*at);
        }
        assert!(times.len() > 10, "waits are not spread out: {times:?}");
    }

    #[test]
    fn a_deferred_unicast_question_is_answered_to_the_querier() {
        let mut r = announced_responder();
        assert!(
            ask(
                &mut r,
                &truncated(&[(ALIAS, RType::A, true)]),
                CLIENT,
                10_000
            )
            .is_empty()
        );
        let (sent, _) = run(&mut r, 10_000, 11_000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.dest, Dest::Unicast(CLIENT));
    }

    #[test]
    fn known_answers_that_follow_from_the_querier_suppress_record_sets() {
        let mut r = announced_with(&["192.0.2.10", "192.0.2.11"]);
        let mut q = truncated(&[(ALIAS, RType::A, false)]);
        q.answers = vec![a("192.0.2.10", TTL, false)];
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        assert!(run(&mut r, 10_000, 10_099).0.is_empty());
        let more = continuation(vec![a("192.0.2.11", TTL, false)], false);
        assert!(ask(&mut r, &more, CLIENT, 10_100).is_empty());
        // Both addresses are known between the two packets: nothing to say.
        assert!(run(&mut r, 10_100, 11_000).0.is_empty());
        assert_eq!(r.next_due(), None);

        let mut r = announced_with(&["192.0.2.10", "192.0.2.11"]);
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        assert!(run(&mut r, 10_000, 10_099).0.is_empty());
        let more = continuation(vec![a("192.0.2.11", TTL, false)], false);
        assert!(ask(&mut r, &more, CLIENT, 10_100).is_empty());
        // Only one of the two is known: the whole set goes out, never part
        // of it (RFC 6762 section 10.2).
        let (sent, _) = run(&mut r, 10_100, 11_000);
        let msg = one(sent.into_iter().map(|(_, o)| o).collect());
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), a("192.0.2.11", TTL, true)]
        );
    }

    #[test]
    fn known_answers_from_another_querier_suppress_nothing() {
        let mut r = announced_with(&["192.0.2.10", "192.0.2.11"]);
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        let more = continuation(vec![a("192.0.2.11", TTL, false)], false);
        assert!(ask(&mut r, &more, OTHER, 10_100).is_empty());
        let (sent, _) = run(&mut r, 10_000, 11_000);
        let msg = one(sent.into_iter().map(|(_, o)| o).collect());
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), a("192.0.2.11", TTL, true)]
        );
    }

    #[test]
    fn another_truncated_packet_extends_the_wait() {
        let mut r = announced_responder();
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        assert!(run(&mut r, 10_000, 10_399).0.is_empty());
        let more = continuation(Vec::new(), true);
        assert!(ask(&mut r, &more, CLIENT, 10_399).is_empty());
        assert!(run(&mut r, 10_399, 10_798).0.is_empty());
        let (sent, _) = run(&mut r, 10_799, 11_500);
        assert_eq!(sent.len(), 1);
        assert!((10_799..=10_899).contains(&sent[0].0), "{}", sent[0].0);
    }

    #[test]
    fn a_stream_of_truncated_packets_delays_the_answer_two_seconds_at_most() {
        let mut r = announced_responder();
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        let mut sent = Vec::new();
        for t in (10_300..=13_000).step_by(300) {
            sent.extend(run(&mut r, t - 300, t - 1).0);
            let more = continuation(Vec::new(), true);
            assert!(ask(&mut r, &more, CLIENT, t).is_empty());
        }
        let times: Vec<u64> = sent.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [10_000 + DEFER_CAP]);
    }

    #[test]
    fn a_query_without_tc_is_answered_at_once_and_nothing_waits() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, RType::A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 10_000).len(), 1);
        assert_eq!(r.next_due(), None);
    }

    #[test]
    fn a_truncated_probe_is_answered_and_tiebroken_at_once() {
        let mut r = announced_responder();
        let mut probe = their_probe("192.0.2.99");
        probe.truncated = true;
        assert_eq!(ask(&mut r, &probe, CLIENT, 10_000).len(), 1);
        assert_eq!(r.next_due(), None);

        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        let mut probe = their_probe("192.0.2.200");
        probe.truncated = true;
        let step = hear(&mut r, &probe, 251);
        assert_eq!(step.notices, [Notice::TiebreakLost(V4, name(ALIAS))]);
        assert!(r.links[&V4].deferred.is_empty());
    }

    #[test]
    fn a_truncated_legacy_query_is_answered_at_once() {
        let mut r = announced_responder();
        let q = truncated(&[(ALIAS, RType::A, false)]);
        let sent = ask(&mut r, &q, LEGACY, 10_000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].dest, Dest::Unicast(LEGACY));
        assert_eq!(r.next_due(), None);
    }

    #[test]
    fn a_truncated_query_about_other_names_is_not_held() {
        let mut r = announced_responder();
        let q = truncated(&[("other.local", RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        assert_eq!(r.next_due(), None);
    }

    #[test]
    fn deferred_queries_are_bounded_per_link() {
        let mut r = announced_responder();
        let q = truncated(&[(ALIAS, RType::A, false)]);
        for i in 0..MAX_DEFERRED {
            let source = querier(100 + i as u8);
            assert!(ask(&mut r, &q, source, 10_000).is_empty());
        }
        assert_eq!(r.links[&V4].deferred.len(), MAX_DEFERRED);
        // One more is answered at once, as without TC.
        assert_eq!(ask(&mut r, &q, OTHER, 10_000).len(), 1);
        assert_eq!(r.links[&V4].deferred.len(), MAX_DEFERRED);
        // A querier already waiting still adds to its own entry.
        let more = continuation(vec![a(MINE, TTL, false)], false);
        assert!(ask(&mut r, &more, querier(100), 10_100).is_empty());
        assert_eq!(
            r.links[&V4].deferred[0].query.answers,
            [a(MINE, TTL, false)]
        );
    }

    #[test]
    fn questions_and_known_answers_kept_per_deferred_query_are_bounded() {
        // Below the caps, a packet sent twice is kept once.
        let mut r = announced_responder();
        let mut small = truncated(&[(ALIAS, RType::A, false), (ALIAS, RType::AAAA, false)]);
        small.answers = vec![a(MINE, TTL, false), a_record(ALIAS, TTL)];
        assert!(ask(&mut r, &small, CLIENT, 10_000).is_empty());
        assert!(ask(&mut r, &small, CLIENT, 10_100).is_empty());
        let kept = &r.links[&V4].deferred[0].query;
        assert_eq!(kept.questions, small.questions);
        assert_eq!(kept.answers, small.answers);

        let mut r = announced_responder();
        let mut q = truncated(&[("other.local", RType::A, false)]);
        q.questions
            .extend((0..=MAX_DEFERRED_QUESTIONS).map(|i| Question {
                name: name(ALIAS),
                qtype: RType(1000 + i as u16),
                qclass: Class::IN,
                unicast_response: false,
            }));
        q.answers = (0..=MAX_DEFERRED_KNOWN)
            .map(|i| a(&format!("192.0.2.{i}"), TTL, false))
            .collect();
        q.answers.insert(0, a_record("other.local", TTL));
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        // The same packet again adds nothing new.
        assert!(ask(&mut r, &q, CLIENT, 10_100).is_empty());
        let kept = &r.links[&V4].deferred[0].query;
        assert_eq!(kept.questions.len(), MAX_DEFERRED_QUESTIONS);
        assert!(kept.questions.iter().all(|q| q.name == name(ALIAS)));
        assert_eq!(kept.answers.len(), MAX_DEFERRED_KNOWN);
        assert!(kept.answers.iter().all(|k| k.name == name(ALIAS)));
    }

    #[test]
    fn another_query_from_a_waiting_querier_is_answered_with_it() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        let due = r.links[&V4].deferred[0].due;
        assert!(run(&mut r, 10_000, 10_049).0.is_empty());
        let other = query(&[(ALIAS, RType::AAAA, false)]);
        assert!(ask(&mut r, &other, CLIENT, 10_050).is_empty());
        assert_eq!(r.links[&V4].deferred[0].due, due);
        let (sent, _) = run(&mut r, 10_050, 11_000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, due);
        let msg = decode(&sent[0].1);
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), aaaa("2001:db8::10", TTL, true)]
        );
        assert!(msg.additionals.is_empty());
    }

    #[test]
    fn a_packet_at_the_cap_starts_afresh_instead_of_joining() {
        let mut r = announced_responder();
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        // No poll since: the first entry is past due but still held. A
        // packet at the cap knows the answer, yet must not suppress it.
        let mut knows = truncated(&[(ALIAS, RType::A, false)]);
        knows.answers = vec![a(MINE, TTL, false)];
        let at_cap = 10_000 + DEFER_CAP;
        assert!(ask(&mut r, &knows, CLIENT, at_cap).is_empty());
        let deferred = &r.links[&V4].deferred;
        assert_eq!(deferred.len(), 2);
        assert!(deferred[0].query.answers.is_empty());
        assert_eq!(deferred[1].first, at_cap);
        assert_eq!(deferred[1].query.answers, [a(MINE, TTL, false)]);
        let (sent, _) = run(&mut r, at_cap, at_cap + 1000);
        let times: Vec<u64> = sent.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [at_cap]);
        assert_eq!(decode(&sent[0].1).answers, [a(MINE, TTL, true)]);
        assert_eq!(r.next_due(), None);
    }

    #[test]
    fn a_truncated_query_about_other_names_draws_no_jitter() {
        let mut r = announced_responder();
        let before = r.rng;
        let q = truncated(&[("other.local", RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        assert_eq!(r.rng, before);
    }

    #[test]
    fn removing_a_link_drops_its_deferred_answers() {
        let mut r = announced_responder();
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        assert!(r.next_due().is_some());
        r.remove_link(V4);
        assert_eq!(r.next_due(), None);
        r.add_link(V4, 10_100);
        assert!(r.links[&V4].deferred.is_empty());
        // Past when the deferred answer was due, and before the first
        // announcement can be.
        let (sent, _) = run(&mut r, 10_100, 10_100 + 3 * PROBE_INTERVAL - 1);
        assert!(!sent.is_empty());
        assert!(sent.iter().all(|(_, o)| !decode(o).is_response));
    }

    #[test]
    fn next_due_covers_probes_announcements_and_deferred_answers() {
        let mut r = responder();
        assert_eq!(r.next_due(), None);
        r.add_link(V4, 0);
        // Polling only when next_due says sends every probe and
        // announcement on time.
        let first = r.next_due().unwrap();
        assert!(first <= PROBE_WAIT_MAX);
        let mut times = Vec::new();
        let mut now = first;
        loop {
            assert!(!r.poll(now).sends.is_empty(), "nothing sent at {now}");
            times.push(now);
            let Some(next) = r.next_due() else { break };
            assert!(next > now);
            now = next;
        }
        assert_eq!(
            times,
            [first, first + 250, first + 500, first + 750, first + 1750]
        );

        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        let deferred = r.next_due().unwrap();
        assert!((10_400..=10_500).contains(&deferred));
        // A probe due sooner on another link comes first.
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 10_000);
        r.add_link(V4B, 10_000);
        assert!(r.next_due().unwrap() <= 10_000 + PROBE_WAIT_MAX);
        r.remove_link(V4B);
        assert_eq!(r.next_due(), Some(deferred));
        assert!(r.poll(deferred - 1).sends.is_empty());
        assert_eq!(r.poll(deferred).sends.len(), 1);
        assert_eq!(r.next_due(), None);
    }

    #[test]
    fn a_truncated_query_about_an_alias_not_served_here_is_not_held() {
        // Still probing: nothing is served yet.
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 300);
        let q = truncated(&[(ALIAS, RType::A, false)]);
        assert!(ask(&mut r, &q, CLIENT, 400).is_empty());
        assert!(r.links[&V4].deferred.is_empty());
        // Two aliases, one too big here: a query only about that one is not
        // held, one that also asks about the served alias is.
        let (mut r, long, _) = mixed();
        announced(&mut r, V4);
        let q = truncated(&[(long.to_string().as_str(), RType::AAAA, false)]);
        assert!(ask(&mut r, &q, CLIENT, 3000).is_empty());
        assert!(r.links[&V4].deferred.is_empty());
        let both = truncated(&[
            (long.to_string().as_str(), RType::AAAA, false),
            (ALIAS, RType::AAAA, false),
        ]);
        assert!(ask(&mut r, &both, CLIENT, 3000).is_empty());
        assert_eq!(r.links[&V4].deferred.len(), 1);
    }

    /// The names of the aliases a message is about, in order, each once.
    fn names(msg: &Message) -> Vec<Name> {
        let mut seen: Vec<Name> = Vec::new();
        let named = msg.questions.iter().map(|q| &q.name);
        let records = msg.answers.iter().chain(&msg.authorities);
        for n in named.chain(records.map(|r| &r.name)) {
            if !seen.contains(n) {
                seen.push(n.clone());
            }
        }
        seen
    }

    /// A responder for ALIAS and a 63-letter alias, with interface 2 at
    /// addresses that make the long alias too big for one packet but leave
    /// ALIAS fitting; the long alias and the number of addresses.
    fn mixed() -> (Responder, Name, u16) {
        let long = name(&format!("{}.myhost.local", "a".repeat(63)));
        let records = Records {
            aliases: vec![name(ALIAS), long.clone()],
        };
        let count = (30..80)
            .find(|&n| too_big(&records, &v6(n)) == [AliasId(1)])
            .expect("no address count splits the two aliases");
        let mut r = Responder::new(vec![name(ALIAS), long.clone()], 7);
        r.set_addresses(IfIndex::of(2), v6(count), 0);
        (r, long, count)
    }

    #[test]
    fn an_oversized_alias_and_a_served_one_share_a_link() {
        let (mut r, long, count) = mixed();
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 3000);
        assert_eq!(
            notices,
            [
                Notice::Oversized(V4, long.clone()),
                Notice::Announced(V4, vec![name(ALIAS)])
            ]
        );
        assert_eq!(sent.len(), 5);
        for (_, out) in &sent {
            assert_eq!(names(&decode(out)), [name(ALIAS)]);
        }
        // Answers: the short alias only.
        let any = |n: &Name| Message {
            questions: vec![Question {
                name: n.clone(),
                qtype: RType::ANY,
                qclass: Class::IN,
                unicast_response: false,
            }],
            ..Message::default()
        };
        let msg = one(ask(&mut r, &any(&name(ALIAS)), CLIENT, 4000));
        assert_eq!(msg.answers.len(), usize::from(count) + 1);
        assert!(ask(&mut r, &any(&long), CLIENT, 4000).is_empty());
        // A legacy query about both: one reply, answers for ALIAS only.
        let mut both = any(&long);
        both.questions.extend(any(&name(ALIAS)).questions);
        let msg = one(ask(&mut r, &both, LEGACY, 4100));
        assert!(!msg.answers.is_empty());
        assert!(msg.answers.iter().all(|a| a.name == name(ALIAS)));
        // Goodbyes: ALIAS only, all of it.
        let byes: Vec<Message> = r.goodbye().iter().map(decode).collect();
        assert_eq!(byes.len(), 1);
        assert_eq!(byes[0].answers.len(), usize::from(count) + 1);
        assert!(
            byes[0]
                .answers
                .iter()
                .all(|a| a.name == name(ALIAS) && a.ttl == 0)
        );

        // Refit: fewer addresses make the long alias fit. ALIAS says goodbye
        // to the addresses it lost and announces the new set, with no
        // probing; the long alias alone is probed.
        let step = r.set_addresses(IfIndex::of(2), v6(10), 10_000);
        assert!(step.notices.is_empty(), "{:?}", step.notices);
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets.len(), 2, "{packets:?}");
        assert!(packets[0].answers.iter().all(|a| a.ttl == 0));
        assert_eq!(packets[0].answers.len(), usize::from(count) - 10);
        assert_eq!(names(&packets[1]), [name(ALIAS)]);
        assert!(packets[1].answers.iter().all(|a| a.ttl == TTL));
        // While the long alias probes, ALIAS keeps answering and defending
        // against a rival's probe; the long alias is not answered yet.
        let (sent, _) = run(&mut r, 10_000, 10_100);
        assert!(
            sent.iter()
                .all(|(_, o)| names(&decode(o)) == [long.clone()])
        );
        // (Asked for a unicast reply: the multicast was just announced.)
        let mut qu = any(&name(ALIAS));
        qu.questions[0].unicast_response = true;
        assert_eq!(one(ask(&mut r, &qu, CLIENT, 10_150)).answers.len(), 11);
        assert!(ask(&mut r, &any(&long), CLIENT, 10_150).is_empty());
        let mut rival = query(&[(ALIAS, RType::ANY, true)]);
        rival.authorities = vec![aaaa("2001:db8::99", TTL, false)];
        let defence = one(ask(&mut r, &rival, OTHER, 10_200));
        assert!(defence.is_response && !defence.answers.is_empty());
        let (sent, notices) = run(&mut r, 10_101, 14_000);
        let probes: Vec<Message> = sent
            .iter()
            .map(|(_, o)| decode(o))
            .filter(|m| !m.is_response)
            .collect();
        assert!(!probes.is_empty());
        for probe in &probes {
            assert_eq!(names(probe), std::slice::from_ref(&long));
        }
        assert_eq!(
            notices,
            [
                Notice::Announced(V4, vec![name(ALIAS)]),
                Notice::Announced(V4, vec![long.clone()])
            ]
        );
        assert_eq!(
            one(ask(&mut r, &any(&long), CLIENT, 15_000)).answers.len(),
            11
        );
    }

    #[test]
    fn a_refit_probes_only_the_alias_that_fits_again() {
        let (mut r, long, count) = mixed();
        announced(&mut r, V4);
        r.set_addresses(IfIndex::of(2), v6(count + 1), 5000);
        // Still too big: nothing is probed.
        let step = r.set_addresses(IfIndex::of(2), v6(count), 6000);
        assert!(step.notices.is_empty());
        let (sent, _) = run(&mut r, 6000, 9000);
        assert!(sent.iter().all(|(_, o)| decode(o).is_response));
        r.set_addresses(IfIndex::of(2), v6(5), 10_000);
        let (sent, _) = run(&mut r, 10_000, 13_000);
        let probes: Vec<Message> = sent
            .iter()
            .map(|(_, o)| decode(o))
            .filter(|m| !m.is_response)
            .collect();
        assert_eq!(probes.len(), 3);
        for probe in probes {
            assert_eq!(probe.questions.len(), 1);
            assert_eq!(probe.questions[0].name, long);
        }
    }

    /// A responder for ALIAS and WEB, with interface 2 at MINE.
    fn two() -> Responder {
        let mut r = Responder::new(vec![name(ALIAS), name(WEB)], 7);
        r.set_addresses(IfIndex::of(2), vec![ip(MINE)], 0);
        r
    }

    /// Another host's answer for ALIAS, with an address that is not ours.
    fn rival() -> Message {
        response(vec![a_record(ALIAS, 120)])
    }

    fn claim() -> Conflict {
        Conflict {
            alias: name(ALIAS),
            source: OTHER.ip(),
        }
    }

    /// Whether `alias` is answered on `link`, asked for a unicast reply so
    /// the multicast rate limit does not get in the way.
    fn answers_on(r: &mut Responder, link: Link, alias: &str, now: u64) -> bool {
        let q = wire::encode(&query(&[(alias, RType::ANY, true)]));
        !r.handle(&q, link, CLIENT, now).sends.is_empty()
    }

    fn answers(r: &mut Responder, alias: &str, now: u64) -> bool {
        answers_on(r, V4, alias, now)
    }

    /// The probes and the announcements among `sent`, each as the names it
    /// is about.
    fn split(sent: &[(u64, Outgoing)]) -> (Vec<Vec<Name>>, Vec<Vec<Name>>) {
        let (mut probes, mut announcements) = (Vec::new(), Vec::new());
        for (_, out) in sent {
            let msg = decode(out);
            if msg.is_response {
                announcements.push(names(&msg));
            } else {
                probes.push(names(&msg));
            }
        }
        (probes, announcements)
    }

    #[test]
    fn a_conflict_probes_that_alias_again_while_the_others_keep_answering() {
        let mut r = two();
        announced(&mut r, V4);
        let step = hear(&mut r, &rival(), 5000);
        assert_eq!(step.notices, [Notice::Conflict(claim())]);
        assert!(step.sends.is_empty());
        // Not ours to answer for until probed; WEB is untouched, and still
        // defends itself against a rival's probe.
        assert!(!answers(&mut r, ALIAS, 5001));
        assert!(answers(&mut r, WEB, 5001));
        let mut probe = query(&[(WEB, RType::ANY, true)]);
        probe.authorities = vec![web(a("192.0.2.99", TTL, false))];
        assert_eq!(ask(&mut r, &probe, OTHER, 5002).len(), 1);
        // Nobody answers the probes: ALIAS is established again.
        let (sent, notices) = run(&mut r, 5000, 8000);
        let (probes, announcements) = split(&sent);
        assert_eq!(probes, vec![vec![name(ALIAS)]; 3]);
        assert_eq!(announcements, vec![vec![name(ALIAS)]; 2]);
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
        assert!(answers(&mut r, ALIAS, 8000));
    }

    #[test]
    fn an_answer_to_our_probe_gives_the_alias_up_there_until_a_retry() {
        let mut r = two();
        announced(&mut r, V4);
        hear(&mut r, &rival(), 5000);
        let (sent, _) = run(&mut r, 5000, 5260);
        assert_eq!(sent.len(), 1, "the first probe is out");
        let step = hear(&mut r, &rival(), 5300);
        assert_eq!(
            step.notices,
            [Notice::Lost {
                link: V4,
                conflict: claim(),
                retry: LOST_RETRY
            }]
        );
        // Goodbye to what it had published; WEB carries on.
        assert_eq!(one(step.sends).answers, ours(0, true));
        assert!(!answers(&mut r, ALIAS, 5400));
        assert!(answers(&mut r, WEB, 5400));
        let byes: Vec<Message> = r.goodbye().iter().map(decode).collect();
        assert_eq!(byes.iter().map(names).collect::<Vec<_>>(), [[name(WEB)]]);
        // The other host's traffic changes nothing now.
        let step = hear(&mut r, &rival(), 6000);
        assert!(step.notices.is_empty() && step.sends.is_empty());
        let retry = 5300 + LOST_RETRY;
        assert_eq!(r.next_due(), Some(retry));
        let (sent, notices) = run(&mut r, 5301, retry - 1);
        assert!(sent.is_empty() && notices.is_empty());
        // The retry: probed again from the start, and this time nobody
        // answers.
        let (sent, notices) = run(&mut r, retry, retry + 3000);
        assert_eq!(
            notices,
            [
                Notice::Retry(V4, name(ALIAS)),
                Notice::Announced(V4, vec![name(ALIAS)])
            ]
        );
        let (probes, announcements) = split(&sent);
        assert_eq!((probes.len(), announcements.len()), (3, 2));
        assert!(answers(&mut r, ALIAS, retry + 3000));
    }

    #[test]
    fn fifteen_conflicts_in_ten_seconds_hold_each_probe_attempt_five_seconds() {
        // Sixteen aliases, all with a probe out, all beaten by one rival
        // probe: sixteen real tiebreak losses at once.
        let aliases: Vec<Name> = (0..16)
            .map(|i| name(&format!("s{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), 7);
        r.set_addresses(IfIndex::of(2), vec![ip(MINE)], 0);
        r.add_link(V4, 0);
        let lost = first_probe(&mut r) + 1;
        let mut rival = Message::default();
        for alias in &aliases {
            rival.questions.push(Question {
                name: alias.clone(),
                qtype: RType::ANY,
                qclass: Class::IN,
                unicast_response: false,
            });
            rival.authorities.push(Record {
                name: alias.clone(),
                ..a("192.0.2.200", TTL, false)
            });
        }
        let step = hear(&mut r, &rival, lost);
        assert_eq!(step.notices.len(), 16);
        // The probe attempts that follow: the first fourteen a second
        // later, together; the fifteenth five seconds after the conflict,
        // the sixteenth five seconds after that.
        let (sent, _) = run(&mut r, lost + 1, lost + 11_000);
        // The first probe of each attempt: the earliest naming each alias.
        let mut first: Vec<(u64, Vec<Name>)> = Vec::new();
        let mut seen: Vec<Name> = Vec::new();
        for (t, msg) in sent.iter().map(|(t, o)| (*t, decode(o))) {
            if msg.is_response {
                continue;
            }
            let new: Vec<Name> = names(&msg)
                .into_iter()
                .filter(|n| !seen.contains(n))
                .collect();
            if !new.is_empty() {
                seen.extend(new.iter().cloned());
                first.push((t, new));
            }
        }
        assert_eq!(
            first,
            [
                (lost + TIEBREAK_BACKOFF, aliases[..14].to_vec()),
                (lost + LIMITED_WAIT, aliases[14..15].to_vec()),
                (lost + 2 * LIMITED_WAIT, aliases[15..].to_vec()),
            ]
        );
    }

    /// Polls from 0 until the first probe goes out; when it did.
    fn first_probe(r: &mut Responder) -> u64 {
        (0..).find(|&now| !r.poll(now).sends.is_empty()).unwrap()
    }

    #[test]
    fn long_suppression_by_rival_probes_is_reported_once_per_episode() {
        let mut r = responder();
        r.add_link(V4, 0);
        let rival = wire::encode(&their_probe("192.0.2.200"));
        let held = Notice::HeldBack(V4, name(ALIAS));
        let lost = Notice::TiebreakLost(V4, name(ALIAS));
        // Rival probes every half second from `from` to `to`; when each
        // notice came.
        let flood = |r: &mut Responder, from: u64, to: u64| {
            let mut seen = Vec::new();
            for now in (from..=to).step_by(500) {
                let mut step = r.handle(&rival, V4, OTHER, now);
                let polled = r.poll(now);
                assert!(polled.sends.is_empty());
                step.notices.extend(polled.notices);
                seen.extend(step.notices.into_iter().map(|n| (now, n)));
            }
            seen
        };
        // The first rival probe beats a probe of ours that is out: a real
        // loss. The ones after only hold the alias back; the line comes
        // ten seconds into that, once.
        let start = first_probe(&mut r) + 1;
        assert_eq!(
            flood(&mut r, start, start + 30_000),
            [
                (start, lost.clone()),
                (start + 500 + HELD_REPORT, held.clone())
            ]
        );
        // It probes once the flood stops, which ends the episode; a short
        // hold-back after that is not reported.
        let probed = |r: &mut Responder, from: u64| {
            (from..).find(|&now| !r.poll(now).sends.is_empty()).unwrap()
        };
        let next = probed(&mut r, start + 30_001) + 1;
        assert_eq!(
            flood(&mut r, next, next + HELD_REPORT - 500),
            [(next, lost.clone())]
        );
        // A second long episode is reported again.
        let later = probed(&mut r, next + HELD_REPORT) + 1;
        let seen = flood(&mut r, later, later + 20_000);
        assert_eq!(seen, [(later, lost), (later + 500 + HELD_REPORT, held)]);
    }

    #[test]
    fn a_flood_of_forged_winning_probes_stays_bounded_and_quiet() {
        let mut r = responder();
        r.add_link(V4, 0);
        let start = first_probe(&mut r) + 1;
        let rival = wire::encode(&their_probe("192.0.2.200"));
        let mut notices = Vec::new();
        let mut sends = 0;
        for i in 0..1000 {
            let now = start + i;
            notices.extend(r.handle(&rival, V4, OTHER, now).notices);
            let step = r.poll(now);
            sends += step.sends.len();
            notices.extend(step.notices);
        }
        // One loss for our one probe run; the rest only hold it back.
        assert_eq!(notices, [Notice::TiebreakLost(V4, name(ALIAS))]);
        assert_eq!(sends, 0);
        let end = start + 999;
        assert!(r.next_due().unwrap() <= end + 2 * LIMITED_WAIT);
        // When the flood stops, probing resumes a second later.
        let (sent, _) = run(&mut r, end + 1, end + TIEBREAK_BACKOFF);
        assert_eq!(sent.len(), 1);
        // The pacer is bounded on its own too, however many attempts.
        let mut p = Pacer::default();
        for _ in 0..CONFLICT_LIMIT {
            p.conflict(1000);
        }
        for _ in 0..1000 {
            assert!(p.attempt(1000, TIEBREAK_BACKOFF) <= 1000 + 2 * LIMITED_WAIT);
        }
    }

    /// A defence arriving 1 ms after our first probe, then silence (a
    /// responder that will not repeat itself within the probe window):
    /// the alias is given up, never announced.
    #[test]
    fn a_defence_right_after_our_first_probe_is_an_answer() {
        let mut r = with_addresses(&[MINE]);
        r.add_link(V4, 0);
        let (sent, _) = run(&mut r, 0, 250);
        assert_eq!(sent.len(), 1);
        let first = sent[0].0;
        let defence = response(vec![a("192.0.2.99", TTL, true)]);
        let step = hear(&mut r, &defence, first + 1);
        assert!(matches!(step.notices[..], [Notice::Lost { .. }]));
        let (sent, _) = run(&mut r, first + 1, first + 3000);
        assert!(sent.is_empty(), "{sent:?}");
    }

    /// A responder for ALIAS that has lost it on V4 by 5300,
    /// with interface 2 at 192.0.2.10.
    fn lost_with_addresses() -> Responder {
        let mut r = announced_with(&["192.0.2.10"]);
        let foreign = response(vec![a("192.0.2.99", TTL, true)]);
        assert_eq!(hear(&mut r, &foreign, 5000).notices.len(), 1);
        run(&mut r, 5000, 5260);
        let step = hear(&mut r, &foreign, 5300);
        assert!(matches!(step.notices[..], [Notice::Lost { .. }]));
        r
    }

    #[test]
    fn a_lost_alias_stays_lost_across_an_address_change() {
        let mut r = lost_with_addresses();
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 6000);
        assert!(step.sends.is_empty() && step.notices.is_empty(), "{step:?}");
        assert!(run(&mut r, 6000, 9000).0.is_empty());
        assert_eq!(r.next_due(), Some(5300 + LOST_RETRY));
        // Losing every address and getting some back probes it afresh, as on
        // a new link.
        r.set_addresses(IfIndex::of(2), Vec::new(), 10_000);
        assert_eq!(r.next_due(), None);
        r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.12")], 11_000);
        let (sent, notices) = run(&mut r, 11_000, 14_000);
        let kinds: Vec<bool> = sent.iter().map(|(_, o)| decode(o).is_response).collect();
        assert_eq!(kinds, [false, false, false, true, true]);
        assert_eq!(notices, [Notice::Announced(V4, vec![name(ALIAS)])]);
    }

    #[test]
    fn a_retry_waits_out_the_rate_limit() {
        let mut r = lost_with_addresses();
        let retry = 5300 + LOST_RETRY;
        for _ in 0..CONFLICT_LIMIT {
            r.pacer.conflict(retry - 1);
        }
        let (sent, notices) = run(&mut r, retry, retry + LIMITED_WAIT - 1);
        assert!(sent.is_empty());
        assert_eq!(notices, [Notice::Retry(V4, name(ALIAS))]);
        let (sent, _) = run(&mut r, retry + LIMITED_WAIT, retry + LIMITED_WAIT);
        assert_eq!(sent.len(), 1);
        assert!(!decode(&sent[0].1).is_response);
    }

    #[test]
    fn a_conflict_on_one_link_probes_the_alias_again_on_all_its_links() {
        let mut r = two();
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 0);
        r.add_link(V4, 0);
        r.add_link(V4B, 0);
        run(&mut r, 0, 2000);
        assert_eq!(hear(&mut r, &rival(), 5000).notices.len(), 1);
        for link in [V4, V4B] {
            assert!(!answers_on(&mut r, link, ALIAS, 5001));
            assert!(answers_on(&mut r, link, WEB, 5001));
        }
        let (sent, notices) = run(&mut r, 5000, 8000);
        for link in [V4, V4B] {
            let on: Vec<_> = sent
                .iter()
                .filter(|(_, o)| o.link == link)
                .cloned()
                .collect();
            let (probes, announcements) = split(&on);
            assert_eq!(probes, vec![vec![name(ALIAS)]; 3]);
            assert_eq!(announcements.len(), 2);
            assert!(notices.contains(&Notice::Announced(link, vec![name(ALIAS)])));
        }
    }

    /// After a reset the re-probe waits at least `RESET_PROBE_MIN`, so the
    /// copy of the response on another link, read in that time, is from
    /// before our probe and ignored (RFC 6762 section 8.1).
    #[test]
    fn a_copy_of_the_conflict_on_another_link_is_not_an_answer_to_a_probe() {
        let v6 = Link {
            index: IfIndex::of(2),
            family: Family::V6,
        };
        let mut r = two();
        r.add_link(V4, 0);
        r.add_link(v6, 0);
        run(&mut r, 0, 2000);
        let packet = wire::encode(&rival());
        assert_eq!(r.handle(&packet, V4, OTHER, 5000).notices.len(), 1);
        assert!(r.next_due().unwrap() >= 5020);
        let (sent, _) = run(&mut r, 5000, 5019);
        assert!(sent.is_empty());
        // The same response, read from the IPv6 socket before any probe of
        // ours is out: the alias is not given up.
        let v6_source = SocketAddr::new(ip("2001:db8::99"), MDNS_PORT);
        let step = r.handle(&packet, v6, v6_source, 5019);
        assert!(step.notices.is_empty(), "{:?}", step.notices);
        run(&mut r, 5000, 8000);
        assert!(answers_on(&mut r, V4, ALIAS, 8000));
        assert!(answers_on(&mut r, v6, ALIAS, 8000));
    }

    /// A re-probe after a reset starts 20-250 ms later, whatever the
    /// jitter drawn.
    #[test]
    fn a_reprobe_after_a_conflict_waits_20_to_250_ms() {
        let mut waits = BTreeSet::new();
        for seed in 0..200 {
            let mut r = seeded(seed);
            announced(&mut r, V4);
            assert_eq!(hear(&mut r, &rival(), 5000).notices.len(), 1);
            waits.insert(r.next_due().unwrap() - 5000);
        }
        assert!(waits.iter().all(|w| (20..=250).contains(w)), "{waits:?}");
        assert!(waits.len() > 50, "{waits:?}");
    }

    /// The same records answering our first probe on the other family,
    /// 1 ms after it went out, are a defence (Avahi answers an address
    /// probe with the same A record on both families): the alias is given
    /// up there, not announced.
    #[test]
    fn the_same_records_after_our_probe_on_the_other_family_are_an_answer() {
        let v6 = Link {
            index: IfIndex::of(2),
            family: Family::V6,
        };
        let mut r = two();
        r.add_link(V4, 0);
        r.add_link(v6, 0);
        run(&mut r, 0, 2000);
        let packet = wire::encode(&rival());
        assert_eq!(r.handle(&packet, V4, OTHER, 5000).notices.len(), 1);
        let (sent, _) = run(&mut r, 5000, 5260);
        let out = sent.iter().find(|(_, o)| o.link == v6).unwrap().0;
        let v6_source = SocketAddr::new(ip("2001:db8::99"), MDNS_PORT);
        let step = r.handle(&packet, v6, v6_source, out + 1);
        assert!(matches!(step.notices[..], [Notice::Lost { link, .. }] if link == v6));
        let (_, notices) = run(&mut r, out + 1, out + 3000);
        assert!(
            !notices
                .iter()
                .any(|n| matches!(n, Notice::Announced(l, _) if *l == v6)),
            "{notices:?}"
        );
    }

    #[test]
    fn goodbyes_cover_an_alias_being_probed_again() {
        let mut r = two();
        announced(&mut r, V4);
        hear(&mut r, &rival(), 5000);
        let byes: Vec<Message> = r.goodbye().iter().map(decode).collect();
        assert_eq!(byes.len(), 1);
        assert_eq!(byes[0].answers.len(), 4);
        assert!(byes[0].answers.iter().all(|a| a.ttl == 0));

        // An address change in the window says goodbye to everything the
        // alias had, and announces nothing until it is probed.
        let mut r = announced_with(&["192.0.2.10"]);
        let foreign = response(vec![a("192.0.2.99", TTL, true)]);
        assert_eq!(hear(&mut r, &foreign, 5000).notices.len(), 1);
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 5100);
        assert_eq!(
            one(step.sends).answers,
            [a("192.0.2.10", 0, true), nsec(&[RType::A], 0, true)]
        );
        assert!(r.goodbye().is_empty());
        let (sent, _) = run(&mut r, 5100, 8000);
        let last = decode(&sent.last().unwrap().1);
        assert_eq!(
            last.answers,
            [a("192.0.2.11", TTL, true), nsec(&[RType::A], TTL, true)]
        );
        assert_eq!(one(r.goodbye()).answers.len(), 2);
    }

    #[test]
    fn the_pacer_spaces_attempts_while_limited_and_lifts_after_the_window() {
        let mut p = Pacer::default();
        for now in 0..15 {
            p.conflict(now);
        }
        assert!(p.limited(14));
        assert_eq!(p.attempt(14, 100), 14 + LIMITED_WAIT);
        assert_eq!(p.attempt(20, 100), 14 + 2 * LIMITED_WAIT);
        // Never more than two waits out, however many attempts pile up.
        assert_eq!(p.attempt(20, 100), 20 + 2 * LIMITED_WAIT);
        assert_eq!(p.attempt(20, 100), 20 + 2 * LIMITED_WAIT);
        assert!(!p.limited(CONFLICT_WINDOW));
        assert_eq!(p.attempt(CONFLICT_WINDOW, 100), CONFLICT_WINDOW + 100);
    }
}
