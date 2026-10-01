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

use crate::wire::{
    self, CLASS_ANY, CLASS_IN, Message, Name, Question, RData, Record, TYPE_A, TYPE_AAAA, TYPE_ANY,
    TYPE_CNAME, TYPE_NSEC,
};

pub const MDNS_PORT: u16 = 5353;
/// TTL for host name records (RFC 6762 section 10).
pub const TTL: u32 = 120;
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
/// Wait before probing again after losing a tiebreak (RFC 6762 section 8.2).
const TIEBREAK_BACKOFF: u64 = 1000;
/// How long a removed address still counts as ours. Our own multicasts loop
/// back and may be read after the address is gone; that copy is not a
/// conflict.
const RETIRED_GRACE: u64 = 5000;

/// How the aliases are published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A and AAAA records with the stable addresses of the interface a
    /// query arrives on, and NSEC when a family has none.
    Addresses,
    /// A CNAME of this name, the host's own `.local` name.
    Cname(Name),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    V4,
    V6,
}

/// One interface in one address family. Each is probed, announced and
/// answered on separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link {
    pub index: u32,
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

#[derive(Debug)]
struct LinkState {
    phase: Phase,
    /// When each record set (alias index, type) was last multicast here.
    last_multicast: Vec<((usize, u16), u64)>,
    /// Aliases already reported as too big for one packet here.
    oversized: Vec<usize>,
}

impl LinkState {
    fn new(phase: Phase) -> LinkState {
        LinkState {
            phase,
            last_multicast: Vec::new(),
            oversized: Vec::new(),
        }
    }

    /// Every record set of `aliases` aliases was just multicast.
    fn mark_all(&mut self, aliases: usize, now: u64) {
        for i in 0..aliases {
            for rtype in [TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_NSEC] {
                self.set_last((i, rtype), now);
            }
        }
    }

    /// When record set `key` was last multicast here.
    fn last(&self, key: (usize, u16)) -> Option<u64> {
        let found = self.last_multicast.iter().find(|(k, _)| *k == key);
        found.map(|&(_, at)| at)
    }

    /// Records that record set `key` was multicast here at `now`.
    fn set_last(&mut self, key: (usize, u16), now: u64) {
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
    fn alias_index(&self, name: &Name) -> Option<usize> {
        self.aliases.iter().position(|alias| alias == name)
    }

    fn record(&self, i: usize, rtype: u16, rdata: RData, ttl: u32, cache_flush: bool) -> Record {
        Record {
            name: self.aliases[i].clone(),
            rtype,
            class: CLASS_IN,
            cache_flush,
            ttl,
            rdata,
        }
    }

    /// Every record published for alias `i` on an interface with `addrs`
    /// (sorted). Empty in address mode when there are no addresses.
    fn set(&self, i: usize, addrs: &[IpAddr], ttl: u32, cache_flush: bool) -> Vec<Record> {
        match &self.mode {
            Mode::Cname(host) => {
                vec![self.record(i, TYPE_CNAME, RData::Cname(host.clone()), ttl, cache_flush)]
            }
            Mode::Addresses => {
                let mut set: Vec<Record> = addrs
                    .iter()
                    .map(|addr| match *addr {
                        IpAddr::V4(v4) => self.record(i, TYPE_A, RData::A(v4), ttl, cache_flush),
                        IpAddr::V6(v6) => {
                            self.record(i, TYPE_AAAA, RData::Aaaa(v6), ttl, cache_flush)
                        }
                    })
                    .collect();
                let v4 = addrs.iter().any(IpAddr::is_ipv4);
                let v6 = addrs.iter().any(IpAddr::is_ipv6);
                if v4 != v6 {
                    set.push(self.nsec(i, addrs, ttl, cache_flush));
                }
                set
            }
        }
    }

    /// The NSEC naming the address types alias `i` has here (RFC 6762
    /// section 6.1).
    fn nsec(&self, i: usize, addrs: &[IpAddr], ttl: u32, cache_flush: bool) -> Record {
        let mut types = Vec::new();
        if addrs.iter().any(IpAddr::is_ipv4) {
            types.push(TYPE_A);
        }
        if addrs.iter().any(IpAddr::is_ipv6) {
            types.push(TYPE_AAAA);
        }
        let next = self.aliases[i].clone();
        self.record(i, TYPE_NSEC, RData::Nsec { next, types }, ttl, cache_flush)
    }

    /// The answers and additional records for a question of `qtype` about
    /// alias `i`, on an interface with `addrs`. A question for A gets the
    /// AAAA records (or NSEC) as additional records and the other way round
    /// (RFC 6762 section 6.2); a type the alias does not have gets the NSEC.
    fn reply(
        &self,
        i: usize,
        addrs: &[IpAddr],
        qtype: u16,
        ttl: u32,
        cache_flush: bool,
    ) -> (Vec<Record>, Vec<Record>) {
        match &self.mode {
            Mode::Cname(_) => {
                if matches!(qtype, TYPE_A | TYPE_AAAA | TYPE_CNAME | TYPE_ANY) {
                    (self.set(i, addrs, ttl, cache_flush), Vec::new())
                } else {
                    (Vec::new(), Vec::new())
                }
            }
            Mode::Addresses => {
                let set = self.set(i, addrs, ttl, cache_flush);
                if set.is_empty() {
                    return (Vec::new(), Vec::new());
                }
                if qtype == TYPE_ANY {
                    return (set, Vec::new());
                }
                let (mut answers, mut additionals): (Vec<Record>, Vec<Record>) = set
                    .into_iter()
                    .partition(|r| r.rtype == qtype && qtype != TYPE_NSEC);
                if !matches!(qtype, TYPE_A | TYPE_AAAA) {
                    additionals.clear();
                }
                if answers.is_empty() {
                    additionals.retain(|r| r.rtype != TYPE_NSEC);
                    answers.push(self.nsec(i, addrs, ttl, cache_flush));
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
                !(rec.rtype == TYPE_CNAME
                    && rec.class == CLASS_IN
                    && rec.rdata == RData::Cname(host.clone()))
            }
            Mode::Addresses => match &rec.rdata {
                RData::A(addr) => !ours.contains(&IpAddr::V4(*addr)),
                RData::Aaaa(addr) => !ours.contains(&IpAddr::V6(*addr)),
                // An NSEC naming only address types agrees with us; anything
                // else claims the name has other data.
                RData::Nsec { types, .. } => {
                    types.is_empty() || types.iter().any(|t| !matches!(*t, TYPE_A | TYPE_AAAA))
                }
                RData::Cname(_) => true,
                RData::Other(_) => matches!(rec.rtype, TYPE_A | TYPE_AAAA | TYPE_NSEC | TYPE_CNAME),
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
fn build(records: &Records, addrs: &[IpAddr], kind: Kind) -> (Vec<Vec<u8>>, Vec<usize>) {
    let parts = (0..records.aliases.len())
        .filter_map(|i| {
            let part = match kind {
                Kind::Probe { unicast_response } => {
                    let authorities = records.set(i, addrs, TTL, false);
                    if authorities.is_empty() {
                        return None;
                    }
                    Message {
                        questions: vec![Question {
                            name: records.aliases[i].clone(),
                            qtype: TYPE_ANY,
                            qclass: CLASS_IN,
                            unicast_response,
                        }],
                        authorities,
                        ..Message::default()
                    }
                }
                Kind::Announce { ttl } => {
                    let answers = records.set(i, addrs, ttl, true);
                    if answers.is_empty() {
                        return None;
                    }
                    Message {
                        answers,
                        ..Message::default()
                    }
                }
            };
            Some((i, part))
        })
        .collect();
    pack(matches!(kind, Kind::Announce { .. }), parts)
}

/// Goodbyes for what an interface published with `old` addresses and no
/// longer does with `new`.
fn retired(records: &Records, old: &[IpAddr], new: &[IpAddr]) -> Vec<Vec<u8>> {
    let parts = (0..records.aliases.len())
        .filter_map(|i| {
            let kept: Vec<(u16, Vec<u8>)> = records
                .set(i, new, TTL, true)
                .iter()
                .map(|r| (r.rtype, r.rdata_wire()))
                .collect();
            let answers: Vec<Record> = records
                .set(i, old, 0, true)
                .into_iter()
                .filter(|r| !kept.contains(&(r.rtype, r.rdata_wire())))
                .collect();
            (!answers.is_empty()).then(|| {
                (
                    i,
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
fn pack(is_response: bool, parts: Vec<(usize, Message)>) -> (Vec<Vec<u8>>, Vec<usize>) {
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

fn multicast(link: Link, packet: Vec<u8>) -> Outgoing {
    Outgoing {
        link,
        dest: Dest::Multicast,
        packet,
    }
}

fn addrs_for(addrs: &[(u32, Vec<IpAddr>)], index: u32) -> &[IpAddr] {
    addrs
        .iter()
        .find(|(i, _)| *i == index)
        .map_or(&[], |(_, list)| list.as_slice())
}

pub struct Responder {
    records: Records,
    links: BTreeMap<Link, LinkState>,
    /// Each interface's stable addresses, by index, sorted.
    addrs: Vec<(u32, Vec<IpAddr>)>,
    /// Addresses no interface has any more, and when each was removed.
    retired: Vec<(IpAddr, u64)>,
    /// xorshift64 state, for probe start jitter. Never zero.
    rng: u64,
}

impl Responder {
    pub fn new(aliases: Vec<Name>, mode: Mode, seed: u64) -> Responder {
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

    pub fn remove_link(&mut self, link: Link) {
        self.links.remove(&link);
    }

    /// Interface `index` now has these stable addresses. Announced links say
    /// goodbye to what is gone and announce the new set twice; waiting links
    /// start probing; a link left with nothing waits again.
    pub fn set_addresses(&mut self, index: u32, mut addrs: Vec<IpAddr>, now: u64) -> Step {
        crate::order::sort(&mut addrs);
        addrs.dedup();
        let old = match self.addrs.iter_mut().find(|(i, _)| *i == index) {
            Some((_, list)) => std::mem::replace(list, addrs.clone()),
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
        let aliases = self.records.aliases.len();
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
                    state.mark_all(aliases, now);
                    state.phase = Phase::Announcing {
                        due: now + ANNOUNCE_INTERVAL,
                    };
                }
                _ => {}
            }
        }
        step
    }

    /// Sends whatever probe or announcement has come due.
    pub fn poll(&mut self, now: u64) -> Step {
        let mut step = Step::default();
        let aliases = self.records.aliases.len();
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
                    state.mark_all(aliases, now);
                    Kind::Announce { ttl: TTL }
                }
                Phase::Announcing { due } if now >= due => {
                    state.phase = Phase::Announced;
                    state.mark_all(aliases, now);
                    step.notices.push(Notice::Announced(link));
                    Kind::Announce { ttl: TTL }
                }
                _ => continue,
            };
            let (msgs, too_big) = build(&self.records, addrs_for(&self.addrs, link.index), kind);
            for i in too_big {
                if !state.oversized.contains(&i) {
                    state.oversized.push(i);
                    let alias = self.records.aliases[i].clone();
                    step.notices.push(Notice::Oversized(link, alias));
                }
            }
            step.sends
                .extend(msgs.into_iter().map(|p| multicast(link, p)));
        }
        step
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
            self.answer(&msg, link, source, now, &mut step);
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
            let Some(i) = self.records.alias_index(&rec.name) else {
                continue;
            };
            if self.records.contradicts(rec, &ours) {
                return Err(Conflict {
                    alias: self.records.aliases[i].clone(),
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
        for (i, alias) in self.records.aliases.iter().enumerate() {
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
                .set(i, addrs, TTL, false)
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

    fn answer(&mut self, msg: &Message, link: Link, source: SocketAddr, now: u64, step: &mut Step) {
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        // The names are not ours to answer for until probing is done.
        if !matches!(state.phase, Phase::Announcing { .. } | Phase::Announced) {
            return;
        }
        let records = &self.records;
        let addrs = addrs_for(&self.addrs, link.index);
        let legacy = source.port() != MDNS_PORT;
        let (ttl, cache_flush) = if legacy {
            (LEGACY_TTL, false)
        } else {
            (TTL, true)
        };
        let mut answers: Vec<Record> = Vec::new();
        let mut additionals: Vec<Record> = Vec::new();
        let mut all_unicast = true;
        for q in &msg.questions {
            if !matches!(q.qclass, CLASS_IN | CLASS_ANY) {
                continue;
            }
            let Some(i) = records.alias_index(&q.name) else {
                continue;
            };
            all_unicast &= q.unicast_response;
            let (asked, extra) = records.reply(i, addrs, q.qtype, ttl, cache_flush);
            for rec in asked {
                if !answers.contains(&rec) {
                    answers.push(rec);
                }
            }
            for rec in extra {
                if !additionals.contains(&rec) {
                    additionals.push(rec);
                }
            }
        }
        additionals.retain(|r| !answers.contains(r));
        // Known-answer suppression (RFC 6762 section 7.1): skip what the
        // querier holds with at least half its TTL left.
        let known = |rec: &Record| {
            msg.answers.iter().any(|k| {
                k.name == rec.name
                    && k.rtype == rec.rtype
                    && k.class == rec.class
                    && k.rdata == rec.rdata
                    && k.ttl >= TTL / 2
            })
        };
        answers.retain(|r| !known(r));
        additionals.retain(|r| !known(r));
        if answers.is_empty() {
            return;
        }
        let key = |rec: &Record| {
            (
                records.alias_index(&rec.name).unwrap_or(usize::MAX),
                rec.rtype,
            )
        };
        if !legacy && !all_unicast {
            // A probe must be answered at once, so it is exempt.
            let probe = !msg.authorities.is_empty();
            answers.retain(|r| probe || state.last(key(r)).is_none_or(|t| now >= t + RATE_LIMIT));
            if answers.is_empty() {
                return;
            }
            for rec in &answers {
                state.set_last(key(rec), now);
            }
        }
        let dest = if legacy || all_unicast {
            Dest::Unicast(source)
        } else {
            Dest::Multicast
        };
        let packets = if legacy {
            // Legacy unicast (RFC 6762 section 6.7): one packet, echoing the
            // ID and questions, short TTLs and no cache-flush bit.
            vec![fit(Message {
                id: msg.id,
                is_response: true,
                questions: msg.questions.clone(),
                answers,
                additionals,
                ..Message::default()
            })]
        } else {
            let parts = records
                .aliases
                .iter()
                .enumerate()
                .filter_map(|(i, alias)| {
                    let part = Message {
                        answers: answers
                            .iter()
                            .filter(|r| r.name == *alias)
                            .cloned()
                            .collect(),
                        additionals: additionals
                            .iter()
                            .filter(|r| r.name == *alias)
                            .cloned()
                            .collect(),
                        ..Message::default()
                    };
                    (!part.answers.is_empty()).then_some((i, part))
                })
                .collect();
            pack(true, parts).0
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
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng % bound
    }
}

/// A record as RFC 6762 section 8.2 compares them: class, then type, then
/// rdata as uncompressed bytes.
fn canonical(rec: &Record) -> (u16, u16, Vec<u8>) {
    (rec.class, rec.rtype, rec.rdata_wire())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    const V4: Link = Link {
        index: 2,
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
            rtype: TYPE_CNAME,
            class: CLASS_IN,
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
                        qtype: TYPE_ANY,
                        qclass: CLASS_IN,
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
            index: 2,
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

    fn query(questions: &[(&str, u16, bool)]) -> Message {
        Message {
            id: 0x4242,
            questions: questions
                .iter()
                .map(|&(n, qtype, qu)| Question {
                    name: name(n),
                    qtype,
                    qclass: CLASS_IN,
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
        for qtype in [TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_ANY] {
            let mut r = announced_responder();
            let sent = ask(&mut r, &query(&[(ALIAS, qtype, false)]), CLIENT, 10_000);
            assert_eq!(sent.len(), 1, "qtype {qtype}");
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
        assert!(ask(&mut r, &query(&[(ALIAS, 16, false)]), CLIENT, 10_000).is_empty());
        assert!(
            ask(
                &mut r,
                &query(&[("other.local", TYPE_A, false)]),
                CLIENT,
                10_000
            )
            .is_empty()
        );
        assert!(ask(&mut r, &query(&[(TARGET, TYPE_A, false)]), CLIENT, 10_000).is_empty());
    }

    #[test]
    fn matches_names_ignoring_case() {
        let mut r = announced_responder();
        let sent = ask(
            &mut r,
            &query(&[("APP.MYHOST.LOCAL", TYPE_A, false)]),
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
        assert!(ask(&mut r, &query(&[(ALIAS, TYPE_A, false)]), CLIENT, 600).is_empty());
    }

    #[test]
    fn ignores_links_it_does_not_serve() {
        let mut r = announced_responder();
        let other = Link {
            index: 9,
            family: Family::V4,
        };
        let step = r.handle(
            &wire::encode(&query(&[(ALIAS, TYPE_A, false)])),
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
            &query(&[(ALIAS, TYPE_A, false), (ALIAS, TYPE_AAAA, false)]),
            CLIENT,
            10_000,
        );
        assert_eq!(sent.len(), 1);
        assert_eq!(decode(&sent[0]).answers, [cname(TTL, true)]);
    }

    #[test]
    fn unicast_response_questions_get_a_unicast_reply() {
        let mut r = announced_responder();
        let sent = ask(&mut r, &query(&[(ALIAS, TYPE_A, true)]), CLIENT, 10_000);
        assert_eq!(sent[0].dest, Dest::Unicast(CLIENT));
        let mixed = query(&[(ALIAS, TYPE_A, true), (ALIAS, TYPE_AAAA, false)]);
        assert_eq!(ask(&mut r, &mixed, CLIENT, 20_000)[0].dest, Dest::Multicast);
    }

    #[test]
    fn legacy_queries_get_a_short_lived_unicast_echo() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, TYPE_A, false)]);
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
        let mut q = query(&[(ALIAS, TYPE_A, false)]);
        q.answers = vec![cname(TTL, false)];
        assert!(ask(&mut r, &q, CLIENT, 10_000).is_empty());
        q.answers = vec![cname(TTL / 2 - 1, false)];
        assert_eq!(ask(&mut r, &q, CLIENT, 10_000).len(), 1);
    }

    #[test]
    fn multicasts_each_record_at_most_once_a_second() {
        let mut r = announced_responder();
        let q = query(&[(ALIAS, TYPE_A, false)]);
        assert_eq!(ask(&mut r, &q, CLIENT, 3000).len(), 1);
        assert!(ask(&mut r, &q, CLIENT, 3500).is_empty());
        assert_eq!(ask(&mut r, &q, CLIENT, 4000).len(), 1);
    }

    #[test]
    fn defends_against_probes_despite_the_rate_limit() {
        let mut r = announced_responder();
        assert_eq!(
            ask(&mut r, &query(&[(ALIAS, TYPE_A, false)]), CLIENT, 3000).len(),
            1
        );
        let mut probe = query(&[(ALIAS, TYPE_ANY, false)]);
        let mut theirs = cname(TTL, false);
        theirs.rdata = RData::Cname(name("elsewhere.local"));
        probe.authorities = vec![theirs];
        assert_eq!(ask(&mut r, &probe, CLIENT, 3100).len(), 1);
    }

    const OTHER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)), 5353);

    fn a_record(owner: &str, ttl: u32) -> Record {
        Record {
            name: name(owner),
            rtype: TYPE_A,
            class: CLASS_IN,
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
        let mut probe = query(&[(ALIAS, TYPE_ANY, true)]);
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
            index: 9,
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
        index: 3,
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
            rtype: TYPE_A,
            class: CLASS_IN,
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
            rtype: TYPE_AAAA,
            class: CLASS_IN,
            cache_flush,
            ttl,
            rdata: RData::Aaaa(v6),
        }
    }

    fn nsec(types: &[u16], ttl: u32, cache_flush: bool) -> Record {
        Record {
            name: name(ALIAS),
            rtype: TYPE_NSEC,
            class: CLASS_IN,
            cache_flush,
            ttl,
            rdata: RData::Nsec {
                next: name(ALIAS),
                types: types.to_vec(),
            },
        }
    }

    /// An address-mode responder whose interface 2 has `addrs`.
    fn with_addresses(addrs: &[&str]) -> Responder {
        let mut r = Responder::new(vec![name(ALIAS)], Mode::Addresses, 7);
        r.set_addresses(2, addrs.iter().map(|a| ip(a)).collect(), 0);
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
        let step = r.set_addresses(2, vec![ip("192.0.2.10")], 3000);
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
            [a("192.0.2.10", TTL, true), nsec(&[TYPE_A], TTL, true)]
        );
    }

    #[test]
    fn answers_a_with_aaaa_as_additional() {
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, TYPE_A, false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(msg.answers, [a("192.0.2.10", TTL, true)]);
        assert_eq!(msg.additionals, [aaaa("2001:db8::10", TTL, true)]);
    }

    #[test]
    fn a_missing_type_is_answered_with_nsec() {
        let mut r = announced_with(&["192.0.2.10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, TYPE_AAAA, false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(msg.answers, [nsec(&[TYPE_A], TTL, true)]);
        assert_eq!(msg.additionals, [a("192.0.2.10", TTL, true)]);
        let mut r = announced_with(&["192.0.2.10", "2001:db8::10"]);
        let msg = one(ask(&mut r, &query(&[(ALIAS, 16, false)]), CLIENT, 10_000));
        assert_eq!(msg.answers, [nsec(&[TYPE_A, TYPE_AAAA], TTL, true)]);
        assert!(msg.additionals.is_empty());
    }

    #[test]
    fn answers_any_with_everything() {
        let mut r = announced_with(&["192.0.2.10"]);
        let msg = one(ask(
            &mut r,
            &query(&[(ALIAS, TYPE_ANY, false)]),
            CLIENT,
            10_000,
        ));
        assert_eq!(
            msg.answers,
            [a("192.0.2.10", TTL, true), nsec(&[TYPE_A], TTL, true)]
        );
    }

    #[test]
    fn answers_with_the_arrival_interfaces_addresses() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.set_addresses(3, vec![ip("198.51.100.10")], 0);
        announced(&mut r, V4);
        r.add_link(V4B, 2000);
        run(&mut r, 2000, 5000);
        let sent = r
            .handle(
                &wire::encode(&query(&[(ALIAS, TYPE_A, false)])),
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
        let step = r.set_addresses(2, vec![ip("192.0.2.11")], 5000);
        assert_eq!(step.sends.len(), 2);
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets[0].answers, [a("192.0.2.10", 0, true)]);
        assert_eq!(
            packets[1].answers,
            [a("192.0.2.11", TTL, true), nsec(&[TYPE_A], TTL, true)]
        );
        let (sent, notices) = run(&mut r, 5001, 7000);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 6000);
        assert_eq!(notices, [Notice::Announced(V4)]);
    }

    #[test]
    fn a_family_appearing_withdraws_the_nsec() {
        let mut r = announced_with(&["192.0.2.10"]);
        let step = r.set_addresses(2, vec![ip("192.0.2.10"), ip("2001:db8::10")], 5000);
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].answers, [nsec(&[TYPE_A], 0, true)]);
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
        let step = r.set_addresses(2, vec![ip("192.0.2.11")], 150);
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
                [a("192.0.2.11", TTL, true), nsec(&[TYPE_A], TTL, true)]
            );
        }
        assert_eq!(notices, [Notice::Announced(V4)]);
    }

    #[test]
    fn losing_every_address_says_goodbye_and_waits() {
        let mut r = announced_with(&["192.0.2.10"]);
        let step = r.set_addresses(2, Vec::new(), 5000);
        let packets: Vec<Message> = step.sends.iter().map(decode).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0].answers,
            [a("192.0.2.10", 0, true), nsec(&[TYPE_A], 0, true)]
        );
        assert!(ask(&mut r, &query(&[(ALIAS, TYPE_A, false)]), CLIENT, 10_000).is_empty());
        assert!(run(&mut r, 5001, 9000).0.is_empty());
    }

    #[test]
    fn losing_every_address_while_probing_waits() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.add_link(V4, 0);
        run(&mut r, 0, 260);
        r.set_addresses(2, Vec::new(), 300);
        assert!(run(&mut r, 301, 5000).0.is_empty());
    }

    #[test]
    fn our_own_addresses_on_any_interface_are_not_conflicts() {
        let mut r = with_addresses(&["192.0.2.10"]);
        r.set_addresses(3, vec![ip("198.51.100.10")], 0);
        announced(&mut r, V4);
        let other_interface = response(vec![a("198.51.100.10", TTL, true)]);
        assert!(hear(&mut r, &other_interface, 5000).is_ok());
    }

    #[test]
    fn foreign_addresses_cnames_and_odd_nsecs_conflict() {
        for rec in [
            a("192.0.2.99", TTL, true),
            Record {
                rtype: TYPE_CNAME,
                rdata: RData::Cname(name("elsewhere.local")),
                ..a("192.0.2.10", TTL, true)
            },
            nsec(&[16], TTL, true),
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
        r.set_addresses(2, vec![ip("192.0.2.11")], 5000);
        assert!(hear(&mut r, &looped, 5100).is_ok());
        let mut r = announced_with(&["192.0.2.10"]);
        r.set_addresses(2, vec![ip("192.0.2.11")], 5000);
        assert!(hear(&mut r, &looped, 5000 + RETIRED_GRACE + 1).is_err());
    }

    #[test]
    fn own_nsec_is_not_a_conflict() {
        let mut r = announced_with(&["192.0.2.10"]);
        assert!(hear(&mut r, &response(vec![nsec(&[TYPE_A], TTL, true)]), 5000).is_ok());
        let own = announcement(&r, V4);
        assert!(hear(&mut r, &own, 5000).is_ok());
    }

    #[test]
    fn other_types_for_an_alias_are_not_conflicts() {
        let mut r = announced_with(&["192.0.2.10"]);
        let txt = Record {
            rtype: 16,
            rdata: RData::Other(vec![1, b'x']),
            ..a("192.0.2.10", TTL, true)
        };
        assert!(hear(&mut r, &response(vec![txt]), 5000).is_ok());
    }

    #[test]
    fn tiebreaks_compare_address_sets() {
        let probe_from = |addr: &str| {
            let mut p = query(&[(ALIAS, TYPE_ANY, true)]);
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
        r.set_addresses(3, vec![ip("198.51.100.10")], 0);
        r.add_link(V4, 0);
        run(&mut r, 0, 250);
        let mut p = query(&[(ALIAS, TYPE_ANY, true)]);
        p.authorities = vec![a("198.51.100.10", TTL, false), nsec(&[TYPE_A], TTL, false)];
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
        r.set_addresses(2, addrs, 0);
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
            2,
            ["192.0.2.10", "2001:db8::10", "fd00::10"].map(ip).to_vec(),
            0,
        );
        announced(&mut r, V4);
        let mut q = Message {
            id: 0,
            ..Message::default()
        };
        for alias in &aliases {
            for qtype in [TYPE_A, TYPE_AAAA] {
                q.questions.push(Question {
                    name: alias.clone(),
                    qtype,
                    qclass: CLASS_IN,
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
            2,
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
                qtype: TYPE_ANY,
                qclass: CLASS_IN,
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
        r.set_addresses(2, many, 0);
        r.add_link(V4, 0);
        let (sent, notices) = run(&mut r, 0, 3000);
        assert!(sent.is_empty());
        let oversized: Vec<&Notice> = notices
            .iter()
            .filter(|n| matches!(n, Notice::Oversized(..)))
            .collect();
        assert_eq!(oversized, [&Notice::Oversized(V4, name(ALIAS))]);
    }
}
