//! The mDNS protocol for a fixed set of aliases, published either as the
//! addresses of the interface a query arrives on (A, AAAA, and NSEC for a
//! missing family) or as CNAMEs of the host's name: probing, announcing,
//! answering, conflict detection, address changes and goodbyes (RFC 6762).
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
const MAX_PACKET: usize = 1440;
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
/// Wait before probing again after losing a tiebreak (RFC 6762 section 8.2).
const TIEBREAK_BACKOFF: u64 = 1000;
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
/// and a dropped known answer only costs a record the querier already has.
const MAX_DEFERRED_QUESTIONS: usize = 32;
const MAX_DEFERRED_KNOWN: usize = 64;

/// How the aliases are published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A and AAAA records with the stable addresses of the interface a
    /// query arrives on, and NSEC when a family has none.
    Addresses,
    /// A CNAME of this name, the host's own `.local` name.
    Cname(Name),
}

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

#[derive(Clone, Debug, PartialEq)]
pub struct Outgoing {
    pub link: Link,
    pub dest: Dest,
    pub packet: Vec<u8>,
}

impl Outgoing {
    /// Whether failing to send this means the link itself is unusable. A
    /// unicast reply can fail for reasons of the querier's own, such as a
    /// self-assigned address the host has no route to, and must not cost
    /// everyone else on the link their answers.
    pub fn failure_breaks_link(&self) -> bool {
        self.dest == Dest::Multicast
    }
}

/// Something worth logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The second announcement went out; the aliases are established here.
    Announced(Link),
    /// Another host probed for an alias with other data and won the tiebreak;
    /// probing starts over here in a second.
    TiebreakLost(Link),
    /// The alias's records alone do not fit one packet on this link, so it
    /// is not probed or announced there.
    Oversized(Link, Name),
}

/// What one call produced.
#[derive(Debug, Default)]
pub struct Step {
    pub sends: Vec<Outgoing>,
    pub notices: Vec<Notice>,
}

/// Someone else claims one of our aliases with other data.
#[derive(Debug, PartialEq, Eq)]
pub struct Conflict {
    pub alias: Name,
    pub source: IpAddr,
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is already in use by {}", self.alias, self.source)
    }
}

impl std::error::Error for Conflict {}

#[derive(Debug)]
enum Phase {
    /// Address mode, and the interface has no stable addresses yet.
    Waiting,
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
    source: SocketAddr,
    /// The questions and known answers about our aliases so far, from every
    /// packet of the querier's; nothing else.
    query: Message,
    /// When the first packet arrived, which `DEFER_CAP` counts from.
    first: u64,
    due: u64,
}

#[derive(Debug)]
struct LinkState {
    phase: Phase,
    /// Queries waiting for more known answers, at most `MAX_DEFERRED`, at
    /// most one per querier address, in arrival order.
    deferred: Vec<Deferred>,
    /// When each record set (alias, type) was last multicast here.
    last_multicast: Vec<((AliasId, RType), u64)>,
    /// Aliases already reported as too big for one packet here.
    oversized: Vec<AliasId>,
}

impl LinkState {
    fn new(phase: Phase) -> LinkState {
        LinkState {
            phase,
            deferred: Vec::new(),
            last_multicast: Vec::new(),
            oversized: Vec::new(),
        }
    }

    /// Every record set of every alias in `records` was just multicast.
    fn mark_all(&mut self, records: &Records, now: u64) {
        for (id, _) in records.iter() {
            for rtype in [RType::A, RType::AAAA, RType::CNAME, RType::NSEC] {
                self.set_last((id, rtype), now);
            }
        }
    }

    /// When record set `key` was last multicast here.
    fn last(&self, key: (AliasId, RType)) -> Option<u64> {
        let found = self.last_multicast.iter().find(|(k, _)| *k == key);
        found.map(|&(_, at)| at)
    }

    /// Records that record set `key` was multicast here at `now`.
    fn set_last(&mut self, key: (AliasId, RType), now: u64) {
        match self.last_multicast.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = now,
            None => self.last_multicast.push((key, now)),
        }
    }
}

/// The aliases, how they are published, and the records that makes.
struct Records {
    aliases: Vec<Name>,
    mode: Mode,
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
    /// (sorted). Empty in address mode when there are no addresses.
    fn set(&self, id: AliasId, addrs: &[IpAddr], ttl: u32, cache_flush: bool) -> Vec<Record> {
        match &self.mode {
            Mode::Cname(host) => {
                vec![self.record(id, RData::Cname(host.clone()), ttl, cache_flush)]
            }
            Mode::Addresses => {
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
        }
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
        match &self.mode {
            Mode::Cname(_) => {
                if matches!(qtype, RType::A | RType::AAAA | RType::CNAME | RType::ANY) {
                    (self.set(id, addrs, ttl, cache_flush), Vec::new())
                } else {
                    (Vec::new(), Vec::new())
                }
            }
            Mode::Addresses => {
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
        }
    }

    /// Whether `rec`, about one of our aliases, contradicts what we publish.
    /// `ours` holds every address this host publishes, on any interface.
    fn contradicts(&self, rec: &Record, ours: &[IpAddr]) -> bool {
        match &self.mode {
            Mode::Cname(host) => {
                !(rec.class == Class::IN
                    && matches!(&rec.rdata, RData::Cname(target) if target == host))
            }
            Mode::Addresses => match &rec.rdata {
                RData::A(addr) => !ours.contains(&IpAddr::V4(*addr)),
                RData::Aaaa(addr) => !ours.contains(&IpAddr::V6(*addr)),
                // An NSEC naming only address types agrees with us; anything
                // else claims the name has other data.
                RData::Nsec { types, .. } => {
                    types.is_empty() || types.iter().any(|t| !matches!(t, RType::A | RType::AAAA))
                }
                RData::Cname(_) => true,
                RData::Other(raw) => {
                    matches!(
                        raw.rtype(),
                        RType::A | RType::AAAA | RType::NSEC | RType::CNAME
                    )
                }
            },
        }
    }
}

/// What `build` assembles for an interface.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Probes: an ANY question per alias, with the proposed records in the
    /// authority section (RFC 6762 section 8.1).
    Probe { unicast_response: bool },
    /// Unsolicited responses with every record; TTL 0 makes them goodbyes.
    Announce { ttl: u32 },
}

/// Messages of `kind` for every alias on an interface with `addrs`, packed
/// into packets, and the aliases too big for any packet.
fn build(records: &Records, addrs: &[IpAddr], kind: Kind) -> (Vec<Vec<u8>>, Vec<AliasId>) {
    let parts = records
        .iter()
        .filter_map(|(id, alias)| {
            let part = match kind {
                Kind::Probe { unicast_response } => {
                    let authorities = records.set(id, addrs, TTL, false);
                    if authorities.is_empty() {
                        return None;
                    }
                    Message {
                        questions: vec![Question {
                            name: alias.clone(),
                            qtype: RType::ANY,
                            qclass: Class::IN,
                            unicast_response,
                        }],
                        authorities,
                        ..Message::default()
                    }
                }
                Kind::Announce { ttl } => {
                    let answers = records.set(id, addrs, ttl, true);
                    if answers.is_empty() {
                        return None;
                    }
                    Message {
                        answers,
                        ..Message::default()
                    }
                }
            };
            Some((id, part))
        })
        .collect();
    pack(matches!(kind, Kind::Announce { .. }), parts)
}

/// Goodbyes for what an interface published with `old` addresses and no
/// longer does with `new`.
fn retired(records: &Records, old: &[IpAddr], new: &[IpAddr]) -> Vec<Vec<u8>> {
    let parts = records
        .iter()
        .filter_map(|(id, _)| {
            // Both sets are built here from the same names, so equal data
            // (which includes the type) means the same record. Only address
            // mode gets here (set_addresses returns before reaching here in
            // CNAME mode), so no CNAME targets are compared, and NSEC data
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
/// answers, until it fits.
fn fit(mut msg: Message) -> Vec<u8> {
    loop {
        let packet = wire::encode(&msg);
        if packet.len() <= MAX_PACKET
            || msg.additionals.pop().is_none() && msg.answers.pop().is_none()
        {
            return packet;
        }
    }
}

/// Records about our aliases, each with the alias it is about, which keys
/// the rate limit and the packing of a reply.
type Tagged = Vec<(AliasId, Record)>;

/// The answers and additional records for `msg`'s questions about our
/// aliases on an interface with `addrs`, each record once and none in both
/// sections, and whether every such question asked for a unicast response.
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
    for q in &msg.questions {
        if !matches!(q.qclass, Class::IN | Class::ANY) {
            continue;
        }
        let Some(id) = records.alias_index(&q.name) else {
            continue;
        };
        all_unicast &= q.unicast_response;
        let (asked, extra) = records.reply(id, addrs, q.qtype, ttl, cache_flush);
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

/// Known-answer suppression (RFC 6762 section 7.1): drops from `records`
/// what the querier lists in `known` with at least half its TTL left. The
/// type is part of the data, so equal data means the same type.
fn suppress_known(records: &mut Tagged, known: &[Record]) {
    records.retain(|(_, rec)| {
        !known.iter().any(|k| {
            k.name == rec.name && k.class == rec.class && k.rdata == rec.rdata && k.ttl >= TTL / 2
        })
    });
}

/// The multicast rate limit (RFC 6762 section 6): drops answers whose
/// record set (alias, type) was multicast on this link less than
/// `RATE_LIMIT` ago, unless they defend against a `probe`, and notes the
/// rest as multicast at `now`.
fn rate_limit(state: &mut LinkState, answers: &mut Tagged, probe: bool, now: u64) {
    answers.retain(|&(id, ref r)| {
        probe
            || state
                .last((id, r.rtype()))
                .is_none_or(|t| now >= t + RATE_LIMIT)
    });
    for (id, rec) in answers.iter() {
        state.set_last((*id, rec.rtype()), now);
    }
}

/// A legacy unicast reply (RFC 6762 section 6.7): one packet, echoing the
/// query's ID and questions.
fn legacy_reply(msg: &Message, answers: Tagged, additionals: Tagged) -> Vec<u8> {
    fit(Message {
        id: msg.id,
        is_response: true,
        questions: msg.questions.clone(),
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
    }
}

fn addrs_for(addrs: &[(IfIndex, Vec<IpAddr>)], index: IfIndex) -> &[IpAddr] {
    addrs
        .iter()
        .find(|(i, _)| *i == index)
        .map_or(&[], |(_, list)| list.as_slice())
}

pub struct Responder {
    records: Records,
    links: BTreeMap<Link, LinkState>,
    /// Each interface's stable addresses, by index, sorted.
    addrs: Vec<(IfIndex, Vec<IpAddr>)>,
    /// Addresses no interface has any more, and when each was removed.
    retired: Vec<(IpAddr, u64)>,
    /// xorshift64 state, for probe start jitter. Never zero.
    rng: u64,
}

impl Responder {
    /// The aliases must be distinct ignoring case, as `cli::resolve` makes
    /// them.
    pub fn new(aliases: Vec<Name>, mode: Mode, seed: u64) -> Responder {
        debug_assert!(
            aliases
                .iter()
                .enumerate()
                .all(|(i, alias)| !aliases[..i].contains(alias)),
            "aliases repeat ignoring case"
        );
        Responder {
            records: Records { aliases, mode },
            links: BTreeMap::new(),
            addrs: Vec::new(),
            retired: Vec::new(),
            rng: seed | 1,
        }
    }

    /// Starts probing on a newly usable link, after a random 0-250 ms wait so
    /// hosts starting together do not probe in lockstep. In address mode a
    /// link with no stable addresses waits for them instead.
    pub fn add_link(&mut self, link: Link, now: u64) {
        let due = now + self.random(PROBE_WAIT_MAX + 1);
        let waiting =
            self.records.mode == Mode::Addresses && addrs_for(&self.addrs, link.index).is_empty();
        let phase = if waiting {
            Phase::Waiting
        } else {
            Phase::Probing { sent: 0, due }
        };
        self.links.insert(link, LinkState::new(phase));
    }

    /// Forgets `link`, with any answers deferred there.
    pub fn remove_link(&mut self, link: Link) {
        self.links.remove(&link);
    }

    /// Interface `index` now has these stable addresses. Announced links say
    /// goodbye to what is gone and announce the new set twice; waiting links
    /// start probing; a link left with nothing waits again.
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
        if old == addrs || self.records.mode != Mode::Addresses {
            return step;
        }
        let due = now + self.random(PROBE_WAIT_MAX + 1);
        for (&link, state) in self.links.iter_mut().filter(|(l, _)| l.index == index) {
            match state.phase {
                Phase::Waiting if !addrs.is_empty() => {
                    state.phase = Phase::Probing { sent: 0, due };
                }
                Phase::Probing { .. } if addrs.is_empty() => state.phase = Phase::Waiting,
                Phase::Announcing { .. } | Phase::Announced => {
                    for packet in retired(&self.records, &old, &addrs) {
                        step.sends.push(multicast(link, packet));
                    }
                    if addrs.is_empty() {
                        state.phase = Phase::Waiting;
                        continue;
                    }
                    let (msgs, _) = build(&self.records, &addrs, Kind::Announce { ttl: TTL });
                    step.sends
                        .extend(msgs.into_iter().map(|p| multicast(link, p)));
                    state.mark_all(&self.records, now);
                    state.phase = Phase::Announcing {
                        due: now + ANNOUNCE_INTERVAL,
                    };
                }
                _ => {}
            }
        }
        step
    }

    /// Sends whatever probe, announcement or deferred answer has come due.
    pub fn poll(&mut self, now: u64) -> Step {
        let mut step = Step::default();
        for (&link, state) in &mut self.links {
            let kind = match state.phase {
                Phase::Probing { sent, due } if now >= due && sent < PROBES => {
                    state.phase = Phase::Probing {
                        sent: sent + 1,
                        due: now + PROBE_INTERVAL,
                    };
                    Kind::Probe {
                        unicast_response: sent == 0,
                    }
                }
                Phase::Probing { due, .. } if now >= due => {
                    state.phase = Phase::Announcing {
                        due: now + ANNOUNCE_INTERVAL,
                    };
                    state.mark_all(&self.records, now);
                    Kind::Announce { ttl: TTL }
                }
                Phase::Announcing { due } if now >= due => {
                    state.phase = Phase::Announced;
                    state.mark_all(&self.records, now);
                    step.notices.push(Notice::Announced(link));
                    Kind::Announce { ttl: TTL }
                }
                _ => continue,
            };
            let (msgs, too_big) = build(&self.records, addrs_for(&self.addrs, link.index), kind);
            for id in too_big {
                if !state.oversized.contains(&id) {
                    state.oversized.push(id);
                    let alias = self.records.name(id).clone();
                    step.notices.push(Notice::Oversized(link, alias));
                }
            }
            step.sends
                .extend(msgs.into_iter().map(|p| multicast(link, p)));
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

    /// When `poll` next has something to send: the earliest probe,
    /// announcement or deferred answer due on any link, which may already
    /// have passed. `None` while nothing is scheduled; only `handle`,
    /// `add_link` and `set_addresses` schedule more.
    pub fn next_due(&self) -> Option<u64> {
        self.links
            .values()
            .flat_map(|state| {
                let phase = match state.phase {
                    Phase::Probing { due, .. } | Phase::Announcing { due } => Some(due),
                    Phase::Waiting | Phase::Announced => None,
                };
                phase
                    .into_iter()
                    .chain(state.deferred.iter().map(|d| d.due))
            })
            .min()
    }

    /// Handles one received packet. Packets on links we do not serve, and
    /// malformed ones, are ignored.
    pub fn handle(
        &mut self,
        packet: &[u8],
        link: Link,
        source: SocketAddr,
        now: u64,
    ) -> Result<Step, Conflict> {
        let mut step = Step::default();
        if !self.links.contains_key(&link) {
            return Ok(step);
        }
        let Some(msg) = wire::parse(packet) else {
            return Ok(step);
        };
        if msg.is_response {
            // Responses not from port 5353 MUST be ignored (RFC 6762 section
            // 6), so a stray tool's reply cannot make us exit.
            if source.port() == MDNS_PORT {
                self.check_response(&msg, source, now)?;
            }
        } else {
            self.tiebreak(&msg, link, now, &mut step);
            if !self.defer(&msg, link, source, now) {
                self.answer(&msg, link, source, now, &mut step);
            }
        }
        Ok(step)
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
    /// ours is a conflict (RFC 6762 section 9), whether we are still probing
    /// or long announced. Goodbyes withdraw rather than claim.
    fn check_response(&self, msg: &Message, source: SocketAddr, now: u64) -> Result<(), Conflict> {
        let ours = self.own_addresses(now);
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
            if self.records.contradicts(rec, &ours) {
                return Err(Conflict {
                    alias: self.records.name(id).clone(),
                    source: source.ip(),
                });
            }
        }
        Ok(())
    }

    /// Simultaneous probe tiebreaking (RFC 6762 section 8.2): another host is
    /// probing for one of our aliases while we are. The lexicographically
    /// later record set wins; the loser waits a second and probes again, by
    /// which time the winner answers and the loser sees a conflict.
    ///
    /// In address mode a probe whose records for the alias are all ours is
    /// this host probing from another interface, not a rival, so it is
    /// skipped.
    fn tiebreak(&mut self, msg: &Message, link: Link, now: u64, step: &mut Step) {
        let own = self.own_addresses(now);
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        if !matches!(state.phase, Phase::Probing { .. }) {
            return;
        }
        let addrs = addrs_for(&self.addrs, link.index);
        for (id, alias) in self.records.iter() {
            let mut theirs: Vec<_> = msg
                .authorities
                .iter()
                .filter(|r| r.name == *alias)
                .map(canonical)
                .collect();
            if theirs.is_empty() {
                continue;
            }
            let ours_alone = self.records.mode == Mode::Addresses
                && msg
                    .authorities
                    .iter()
                    .filter(|r| r.name == *alias)
                    .all(|r| !self.records.contradicts(r, &own));
            if ours_alone {
                continue;
            }
            crate::order::heapsort(&mut theirs);
            let mut ours: Vec<_> = self
                .records
                .set(id, addrs, TTL, false)
                .iter()
                .map(canonical)
                .collect();
            crate::order::sort(&mut ours);
            if ours < theirs {
                state.phase = Phase::Probing {
                    sent: 0,
                    due: now + TIEBREAK_BACKOFF,
                };
                step.notices.push(Notice::TiebreakLost(link));
                return;
            }
        }
    }

    /// Multipacket known-answer suppression (RFC 6762 section 7.2): a query
    /// with TC set is held for a random 400-500 ms, gathering the known
    /// answers that follow from the same querier, and `poll` answers it
    /// then. Returns whether `msg` was taken in here; if not, it is to be
    /// answered now.
    ///
    /// A new deferral needs TC and a question about one of our aliases, and
    /// room on the link. Once a querier has one, every later query of its on
    /// the link joins it: its known answers count against all the
    /// questions, its questions are answered with the rest, and with TC
    /// again the wait is extended to 400-500 ms past it, but never past
    /// `DEFER_CAP` after the first packet; from then on, the querier's
    /// packets are treated as if it had none. Probes are answered at once,
    /// and legacy queriers (RFC 6762 section 6.7) send no continuations, so
    /// neither is deferred or joins. The jitter is drawn only for a TC
    /// packet that is taken in.
    fn defer(&mut self, msg: &Message, link: Link, source: SocketAddr, now: u64) -> bool {
        if !msg.authorities.is_empty() || source.port() != MDNS_PORT {
            return false;
        }
        let records = &self.records;
        let Some(state) = self.links.get_mut(&link) else {
            return false;
        };
        let joined = state
            .deferred
            .iter()
            .position(|d| d.source.ip() == source.ip() && now < d.first + DEFER_CAP);
        let at = match joined {
            Some(at) => at,
            None => {
                let ours = msg
                    .questions
                    .iter()
                    .any(|q| records.alias_index(&q.name).is_some());
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
    /// the querier knows, rate-limit multicasts, and pack what is left.
    fn answer(&mut self, msg: &Message, link: Link, source: SocketAddr, now: u64, step: &mut Step) {
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        // The names are not ours to answer for until probing is done.
        if !matches!(state.phase, Phase::Announcing { .. } | Phase::Announced) {
            return;
        }
        let addrs = addrs_for(&self.addrs, link.index);
        let legacy = source.port() != MDNS_PORT;
        // Legacy replies get short TTLs and no cache-flush bit (RFC 6762
        // section 6.7).
        let (ttl, cache_flush) = if legacy {
            (LEGACY_TTL, false)
        } else {
            (TTL, true)
        };
        let (mut answers, mut additionals, all_unicast) =
            collect(&self.records, msg, addrs, ttl, cache_flush);
        suppress_known(&mut answers, &msg.answers);
        suppress_known(&mut additionals, &msg.answers);
        if answers.is_empty() {
            return;
        }
        if !legacy && !all_unicast {
            // A probe must be answered at once, so it is exempt.
            let probe = !msg.authorities.is_empty();
            rate_limit(state, &mut answers, probe, now);
            if answers.is_empty() {
                return;
            }
        }
        let (dest, packets) = if legacy {
            let packet = legacy_reply(msg, answers, additionals);
            (Dest::Unicast(source), vec![packet])
        } else {
            let dest = if all_unicast {
                Dest::Unicast(source)
            } else {
                Dest::Multicast
            };
            (dest, reply_packets(&self.records, answers, additionals))
        };
        for packet in packets {
            step.sends.push(Outgoing { link, dest, packet });
        }
    }

    /// Goodbyes (TTL 0) for every link that has announced, so clients drop
    /// the names now instead of when their caches expire.
    pub fn goodbye(&self) -> Vec<Outgoing> {
        self.links
            .iter()
            .filter(|(_, state)| matches!(state.phase, Phase::Announcing { .. } | Phase::Announced))
            .flat_map(|(&link, _)| {
                let addrs = addrs_for(&self.addrs, link.index);
                build(&self.records, addrs, Kind::Announce { ttl: 0 })
                    .0
                    .into_iter()
                    .map(move |p| multicast(link, p))
            })
            .collect()
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
    const TARGET: &str = "myhost.local";

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    fn responder() -> Responder {
        Responder::new(vec![name(ALIAS)], Mode::Cname(name(TARGET)), 7)
    }

    fn decode(out: &Outgoing) -> Message {
        wire::parse(&out.packet).unwrap()
    }

    fn cname(ttl: u32, cache_flush: bool) -> Record {
        Record {
            name: name(ALIAS),
            class: Class::IN,
            cache_flush,
            ttl,
            rdata: RData::Cname(name(TARGET)),
        }
    }

    fn announcement(r: &Responder, link: Link) -> Message {
        let packet = build(
            &r.records,
            addrs_for(&r.addrs, link.index),
            Kind::Announce { ttl: TTL },
        )
        .0
        .remove(0);
        wire::parse(&packet).unwrap()
    }

    fn probe(r: &Responder, link: Link) -> Message {
        let packet = build(
            &r.records,
            addrs_for(&r.addrs, link.index),
            Kind::Probe {
                unicast_response: false,
            },
        )
        .0
        .remove(0);
        wire::parse(&packet).unwrap()
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
                        unicast_response: i == 0
                    }]
                );
                assert_eq!(msg.authorities, [cname(TTL, false)]);
            } else {
                assert!(msg.is_response);
                assert_eq!(msg.answers, [cname(TTL, true)]);
            }
        }
        assert_eq!(notices, [Notice::Announced(V4)]);
    }

    #[test]
    fn first_probe_waits_a_random_0_to_250_ms() {
        let mut firsts = BTreeSet::new();
        for seed in 0..50 {
            let mut r = Responder::new(vec![name(ALIAS)], Mode::Cname(name(TARGET)), seed);
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
        assert_eq!(decode(&byes[0]).answers, [cname(0, true)]);
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

    fn ask(r: &mut Responder, msg: &Message, source: SocketAddr, now: u64) -> Vec<Outgoing> {
        r.handle(&wire::encode(msg), V4, source, now).unwrap().sends
    }

    fn announced_responder() -> Responder {
        let mut r = responder();
        announced(&mut r, V4);
        r
    }

    #[test]
    fn answers_address_cname_and_any_questions_with_the_cname() {
        for qtype in [RType::A, RType::AAAA, RType::CNAME, RType::ANY] {
            let mut r = announced_responder();
            let sent = ask(&mut r, &query(&[(ALIAS, qtype, false)]), CLIENT, 10_000);
            assert_eq!(sent.len(), 1, "qtype {qtype:?}");
            assert_eq!((sent[0].link, sent[0].dest), (V4, Dest::Multicast));
            let msg = decode(&sent[0]);
            assert!(msg.is_response);
            assert_eq!(msg.id, 0);
            assert!(msg.questions.is_empty());
            assert_eq!(msg.answers, [cname(TTL, true)]);
        }
    }

    #[test]
    fn ignores_other_types_and_names() {
        let mut r = announced_responder();
        assert!(ask(&mut r, &query(&[(ALIAS, RType(16), false)]), CLIENT, 10_000).is_empty());
        assert!(
            ask(
                &mut r,
                &query(&[("other.local", RType::A, false)]),
                CLIENT,
                10_000
            )
            .is_empty()
        );
        assert!(ask(&mut r, &query(&[(TARGET, RType::A, false)]), CLIENT, 10_000).is_empty());
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
        assert!(step.unwrap().sends.is_empty());
    }

    #[test]
    fn ignores_malformed_packets() {
        let mut r = announced_responder();
        assert!(
            r.handle(b"\x00\x01", V4, CLIENT, 10_000)
                .unwrap()
                .sends
                .is_empty()
        );
    }

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
        assert_eq!(decode(&sent[0]).answers, [cname(TTL, true)]);
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
        assert_eq!(msg.answers, [cname(10, false)]);
    }

    #[test]
    fn suppresses_answers_the_querier_already_knows() {
        let mut r = announced_responder();
        let mut q = query(&[(ALIAS, RType::A, false)]);
        q.answers = vec![cname(TTL, false)];
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        q.answers = vec![cname(TTL / 2 - 1, false)];
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
        let mut probe = query(&[(ALIAS, RType::ANY, false)]);
        let mut theirs = cname(TTL, false);
        theirs.rdata = RData::Cname(name("elsewhere.local"));
        probe.authorities = vec![theirs];
        assert_eq!(ask(&mut r, &probe, CLIENT, 3100).len(), 1);
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

    fn hear(r: &mut Responder, msg: &Message, now: u64) -> Result<Step, Conflict> {
        r.handle(&wire::encode(msg), V4, OTHER, now)
    }

    fn their_probe(target: &str) -> Message {
        let mut probe = query(&[(ALIAS, RType::ANY, true)]);
        probe.authorities = vec![Record {
            rdata: RData::Cname(name(target)),
            ..cname(TTL, false)
        }];
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
            hear(&mut r, &response(vec![a_record(ALIAS, 120)]), 5000).err(),
            Some(expected)
        );
        let mut r = announced_responder();
        let elsewhere = Record {
            rdata: RData::Cname(name("nas.local")),
            ..cname(TTL, true)
        };
        assert!(hear(&mut r, &response(vec![elsewhere]), 5000).is_err());
    }

    #[test]
    fn conflicts_count_while_probing_too() {
        let mut r = responder();
        r.add_link(V4, 0);
        assert!(hear(&mut r, &response(vec![a_record(ALIAS, 120)]), 100).is_err());
    }

    #[test]
    fn conflict_message_names_the_alias_and_source() {
        let c = Conflict {
            alias: name(ALIAS),
            source: OTHER.ip(),
        };
        assert_eq!(
            c.to_string(),
            "app.myhost.local is already in use by 192.0.2.30"
        );
    }

    #[test]
    fn same_data_in_another_case_is_not_a_conflict() {
        let mut r = announced_responder();
        let echoed = Record {
            name: name("App.MyHost.local"),
            rdata: RData::Cname(name("MYHOST.local")),
            ..cname(TTL, true)
        };
        assert!(hear(&mut r, &response(vec![echoed]), 5000).is_ok());
    }

    #[test]
    fn own_announcement_is_not_a_conflict() {
        let mut r = announced_responder();
        let own = announcement(&r, V4);
        assert!(hear(&mut r, &own, 5000).is_ok());
    }

    #[test]
    fn only_failed_multicasts_say_the_link_is_broken() {
        let multicast = Outgoing {
            link: V4,
            dest: Dest::Multicast,
            packet: Vec::new(),
        };
        let unicast = Outgoing {
            dest: Dest::Unicast(OTHER),
            ..multicast.clone()
        };
        assert!(multicast.failure_breaks_link());
        assert!(!unicast.failure_breaks_link());
    }

    #[test]
    fn responses_from_other_ports_are_ignored() {
        let mut r = announced_responder();
        let packet = wire::encode(&response(vec![a_record(ALIAS, 120)]));
        let source = SocketAddr::new(OTHER.ip(), 54000);
        assert!(r.handle(&packet, V4, source, 5000).is_ok());
    }

    #[test]
    fn goodbyes_are_not_conflicts() {
        let mut r = announced_responder();
        assert!(hear(&mut r, &response(vec![a_record(ALIAS, 0)]), 5000).is_ok());
    }

    #[test]
    fn responses_about_other_names_are_not_conflicts() {
        let mut r = announced_responder();
        assert!(hear(&mut r, &response(vec![a_record(TARGET, 120)]), 5000).is_ok());
    }

    #[test]
    fn ignores_responses_on_links_it_does_not_serve() {
        let mut r = announced_responder();
        let other = Link {
            index: IfIndex::of(9),
            family: Family::V4,
        };
        let packet = wire::encode(&response(vec![a_record(ALIAS, 120)]));
        assert!(r.handle(&packet, other, OTHER, 5000).is_ok());
    }

    #[test]
    fn losing_a_tiebreak_restarts_probing_a_second_later() {
        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        // "some-longer-host" starts with a larger length byte than "myhost",
        // so their rdata sorts later and they win.
        let step = hear(&mut r, &their_probe("some-longer-host.local"), 251).unwrap();
        assert_eq!(step.notices, [Notice::TiebreakLost(V4)]);
        let (sent, _) = run(&mut r, 252, 1251);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 1251);
        assert!(decode(&sent[0].1).questions[0].unicast_response);
    }

    #[test]
    fn winning_a_tiebreak_keeps_probing() {
        let mut r = responder();
        r.add_link(V4, 0);
        let (before, _) = run(&mut r, 0, 250);
        // "a" sorts before "myhost": we win.
        let step = hear(&mut r, &their_probe("a.local"), 251).unwrap();
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
        assert!(hear(&mut r, &own, 251).unwrap().notices.is_empty());
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

    /// An address-mode responder whose interface 2 has `addrs`.
    fn with_addresses(addrs: &[&str]) -> Responder {
        let mut r = Responder::new(vec![name(ALIAS)], Mode::Addresses, 7);
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
        let mut r = Responder::new(vec![name(ALIAS)], Mode::Addresses, 7);
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
        let mut r = Responder::new(vec![name(ALIAS), name(WEB)], Mode::Addresses, 7);
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
            .unwrap()
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
        assert_eq!(notices, [Notice::Announced(V4)]);
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
        assert_eq!(notices, [Notice::Announced(V4)]);
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
        assert!(hear(&mut r, &other_interface, 5000).is_ok());
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
                hear(&mut r, &response(vec![rec.clone()]), 5000).is_err(),
                "{rec:?}"
            );
        }
    }

    #[test]
    fn a_just_removed_address_is_not_a_conflict_for_a_while() {
        let looped = response(vec![a("192.0.2.10", TTL, true)]);
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 5000);
        assert!(hear(&mut r, &looped, 5100).is_ok());
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.11")], 5000);
        assert!(hear(&mut r, &looped, 5000 + RETIRED_GRACE + 1).is_err());
    }

    #[test]
    fn an_interface_left_with_no_addresses_is_forgotten() {
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 0);
        r.set_addresses(IfIndex::of(2), Vec::new(), 5000);
        assert_eq!(r.addrs, [(IfIndex::of(3), vec![ip("198.51.100.10")])]);
        // Departed interfaces leave nothing behind, however many come and go.
        for index in (10..20).map(IfIndex::of) {
            r.set_addresses(index, vec![ip("203.0.113.10")], 5000);
            r.set_addresses(index, Vec::new(), 5000);
        }
        r.set_addresses(IfIndex::of(30), Vec::new(), 5000);
        assert_eq!(r.addrs.len(), 1);
        // Its addresses still count as ours for the retired window.
        let looped = response(vec![a("192.0.2.10", TTL, true)]);
        assert!(hear(&mut r, &looped, 5100).is_ok());
        assert!(hear(&mut r, &looped, 5000 + RETIRED_GRACE + 1).is_err());
    }

    #[test]
    fn own_nsec_is_not_a_conflict() {
        let mut r = announced_with(&["192.0.2.10"]);
        assert!(hear(&mut r, &response(vec![nsec(&[RType::A], TTL, true)]), 5000).is_ok());
        let own = announcement(&r, V4);
        assert!(hear(&mut r, &own, 5000).is_ok());
    }

    #[test]
    fn other_types_for_an_alias_are_not_conflicts() {
        let mut r = announced_with(&["192.0.2.10"]);
        let txt = Record {
            rdata: RData::other(RType(16), vec![1, b'x']).unwrap(),
            ..a("192.0.2.10", TTL, true)
        };
        assert!(hear(&mut r, &response(vec![txt]), 5000).is_ok());
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
        assert!(hear(&mut r, &msg, 5000).is_err());
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
            hear(&mut r, &probe_from("192.0.2.200"), 251)
                .unwrap()
                .notices,
            [Notice::TiebreakLost(V4)]
        );
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        assert!(
            hear(&mut r, &probe_from("192.0.2.1"), 251)
                .unwrap()
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
        let step = hear(&mut r, &p, 251).unwrap();
        assert!(step.notices.is_empty(), "{:?}", step.notices);
        // A foreign address among the records still counts as a rival.
        p.authorities.push(a("203.0.113.200", TTL, false));
        assert_eq!(
            hear(&mut r, &p, 252).unwrap().notices,
            [Notice::TiebreakLost(V4)]
        );
    }

    #[test]
    fn announcements_are_packed_within_packet_limits() {
        let aliases: Vec<Name> = (0..40)
            .map(|i| name(&format!("service{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), Mode::Addresses, 7);
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
    fn answers_are_packed_per_alias_within_packet_limits() {
        let aliases: Vec<Name> = (0..40)
            .map(|i| name(&format!("service{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), Mode::Addresses, 7);
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
        let sent = r
            .handle(&wire::encode(&q), V4, CLIENT, 10_000)
            .unwrap()
            .sends;
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
        let aliases: Vec<Name> = (0..40)
            .map(|i| name(&format!("service{i}.myhost.local")))
            .collect();
        let mut r = Responder::new(aliases.clone(), Mode::Addresses, 7);
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
        let sent = r
            .handle(&wire::encode(&q), V4, LEGACY, 10_000)
            .unwrap()
            .sends;
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
        let mut r = Responder::new(vec![name(ALIAS)], Mode::Addresses, 7);
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
            mode: Mode::Addresses,
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
    fn a_known_answer_with_half_its_ttl_left_suppresses_just_that_record() {
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
        let mut state = LinkState::new(Phase::Announced);
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
    fn probes_are_exempt_from_the_rate_limit() {
        let mut state = LinkState::new(Phase::Announced);
        state.set_last((AliasId(0), RType::A), 1000);
        let mut answers = vec![(AliasId(0), a("192.0.2.10", TTL, true))];
        rate_limit(&mut state, &mut answers, true, 1100);
        assert_eq!(answers.len(), 1);
        assert_eq!(state.last((AliasId(0), RType::A)), Some(1100));
    }

    #[test]
    fn an_a_query_right_after_an_aaaa_multicast_is_answered() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let aaaa_q = query(&[(ALIAS, RType::AAAA, false)]);
        let a_q = query(&[(ALIAS, RType::A, false)]);
        let msg = one(ask(&mut r, &aaaa_q, CLIENT, 3000));
        assert_eq!(msg.answers, [aaaa("2001:db8::10", TTL, true)]);
        let msg = one(ask(&mut r, &a_q, CLIENT, 3100));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert!(ask(&mut r, &a_q, CLIENT, 3200).is_empty());
        assert!(ask(&mut r, &aaaa_q, CLIENT, 3200).is_empty());
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

    #[test]
    fn setting_addresses_in_cname_mode_changes_nothing() {
        let mut r = announced_responder();
        r.add_link(V4B, 5000);
        let step = r.set_addresses(IfIndex::of(2), vec![ip("192.0.2.10")], 5000);
        assert!(step.sends.is_empty());
        assert!(step.notices.is_empty());
        let step = r.set_addresses(IfIndex::of(3), vec![ip("198.51.100.10")], 5000);
        assert!(step.sends.is_empty());
        assert!(step.notices.is_empty());
        assert!(matches!(r.links[&V4].phase, Phase::Announced));
        assert!(matches!(
            r.links[&V4B].phase,
            Phase::Probing { sent: 0, .. }
        ));
        let step = r.set_addresses(IfIndex::of(2), Vec::new(), 6000);
        assert!(step.sends.is_empty());
        assert!(matches!(r.links[&V4].phase, Phase::Announced));
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
            let mut r = Responder::new(vec![name(ALIAS)], Mode::Cname(name(TARGET)), seed);
            announced(&mut r, V4);
            let q = truncated(&[(ALIAS, RType::A, false)]);
            assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
            let (sent, _) = run(&mut r, 10_000, 11_000);
            assert_eq!(sent.len(), 1);
            let (at, out) = &sent[0];
            assert!((10_400..=10_500).contains(at), "answered at {at}");
            assert_eq!(out.dest, Dest::Multicast);
            assert_eq!(decode(out).answers, [cname(TTL, true)]);
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
    fn known_answers_that_follow_from_the_querier_suppress_records() {
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
        let (sent, _) = run(&mut r, 10_100, 11_000);
        let msg = one(sent.into_iter().map(|(_, o)| o).collect());
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
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
        let mut probe = their_probe("elsewhere.local");
        probe.truncated = true;
        assert_eq!(ask(&mut r, &probe, CLIENT, 10_000).len(), 1);
        assert_eq!(r.next_due(), None);

        let mut r = responder();
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        let mut probe = their_probe("some-longer-host.local");
        probe.truncated = true;
        let step = hear(&mut r, &probe, 251).unwrap();
        assert_eq!(step.notices, [Notice::TiebreakLost(V4)]);
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
        let more = continuation(vec![cname(TTL, false)], false);
        assert!(ask(&mut r, &more, querier(100), 10_100).is_empty());
        assert_eq!(r.links[&V4].deferred[0].query.answers, [cname(TTL, false)]);
    }

    #[test]
    fn questions_and_known_answers_kept_per_deferred_query_are_bounded() {
        // Below the caps, a packet sent twice is kept once.
        let mut r = announced_responder();
        let mut small = truncated(&[(ALIAS, RType::A, false), (ALIAS, RType::AAAA, false)]);
        small.answers = vec![cname(TTL, false), a_record(ALIAS, TTL)];
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
            .map(|i| Record {
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, i as u8)),
                ..cname(TTL, false)
            })
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
        knows.answers = vec![cname(TTL, false)];
        let at_cap = 10_000 + DEFER_CAP;
        assert!(ask(&mut r, &knows, CLIENT, at_cap).is_empty());
        let deferred = &r.links[&V4].deferred;
        assert_eq!(deferred.len(), 2);
        assert!(deferred[0].query.answers.is_empty());
        assert_eq!(deferred[1].first, at_cap);
        assert_eq!(deferred[1].query.answers, [cname(TTL, false)]);
        let (sent, _) = run(&mut r, at_cap, at_cap + 1000);
        let times: Vec<u64> = sent.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [at_cap]);
        assert_eq!(decode(&sent[0].1).answers, [cname(TTL, true)]);
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
        let (sent, _) = run(&mut r, 10_100, 11_000);
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
        r.add_link(V4B, 10_000);
        assert!(r.next_due().unwrap() <= 10_000 + PROBE_WAIT_MAX);
        r.remove_link(V4B);
        assert_eq!(r.next_due(), Some(deferred));
        assert!(r.poll(deferred - 1).sends.is_empty());
        assert_eq!(r.poll(deferred).sends.len(), 1);
        assert_eq!(r.next_due(), None);
    }
}
