//! The mDNS protocol for a fixed set of `alias CNAME target` records:
//! probing, announcing, answering, conflict detection and goodbyes (RFC
//! 6762). Pure: packets and the time come in, packets to send go out, so
//! tests drive it with a fake clock. Times are milliseconds on any monotonic
//! clock.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::wire::{
    self, CLASS_ANY, CLASS_IN, Message, Name, Question, RData, Record, TYPE_A, TYPE_AAAA, TYPE_ANY,
    TYPE_CNAME,
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
/// Minimum gap between multicasts of one record on one link (RFC 6762
/// section 6).
const RATE_LIMIT: u64 = 1000;
/// Wait before probing again after losing a tiebreak (RFC 6762 section 8.2).
const TIEBREAK_BACKOFF: u64 = 1000;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The second announcement went out; the aliases are established here.
    Announced(Link),
    /// Another host probed for an alias with other data and won the tiebreak;
    /// probing starts over here in a second.
    TiebreakLost(Link),
}

/// What one call produced.
#[derive(Debug, Default)]
pub struct Step {
    pub sends: Vec<Outgoing>,
    pub notices: Vec<Notice>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TooManyAliases {
    pub bytes: usize,
}

impl fmt::Display for TooManyAliases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "too many aliases: a probe would be {} bytes, over the {MAX_PACKET}-byte limit",
            self.bytes
        )
    }
}

impl std::error::Error for TooManyAliases {}

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
    /// When each alias was last multicast here, by alias index.
    last_multicast: Vec<Option<u64>>,
}

/// The records published, and the messages built from them.
struct Records {
    aliases: Vec<Name>,
    target: Name,
}

impl Records {
    fn cname(&self, alias: usize, ttl: u32, cache_flush: bool) -> Record {
        Record {
            name: self.aliases[alias].clone(),
            rtype: TYPE_CNAME,
            class: CLASS_IN,
            cache_flush,
            ttl,
            rdata: RData::Cname(self.target.clone()),
        }
    }

    /// A probe: an ANY question per alias, with the records we propose in
    /// the authority section (RFC 6762 section 8.1).
    fn probe(&self, unicast_response: bool) -> Message {
        Message {
            questions: self
                .aliases
                .iter()
                .map(|alias| Question {
                    name: alias.clone(),
                    qtype: TYPE_ANY,
                    qclass: CLASS_IN,
                    unicast_response,
                })
                .collect(),
            authorities: (0..self.aliases.len())
                .map(|i| self.cname(i, TTL, false))
                .collect(),
            ..Message::default()
        }
    }

    /// Every record, as an unsolicited response. TTL 0 makes it a goodbye.
    fn announcement(&self, ttl: u32) -> Message {
        Message {
            is_response: true,
            answers: (0..self.aliases.len())
                .map(|i| self.cname(i, ttl, true))
                .collect(),
            ..Message::default()
        }
    }

    fn alias_index(&self, name: &Name) -> Option<usize> {
        self.aliases.iter().position(|alias| alias == name)
    }

    /// Whether `rec` is exactly the record we publish for its name.
    fn is_ours(&self, rec: &Record) -> bool {
        rec.rtype == TYPE_CNAME
            && rec.class == CLASS_IN
            && rec.rdata == RData::Cname(self.target.clone())
    }
}

pub struct Responder {
    records: Records,
    links: BTreeMap<Link, LinkState>,
    /// xorshift64 state, for probe start jitter. Never zero.
    rng: u64,
}

impl Responder {
    /// Fails if a probe for every alias would not fit one packet: probes
    /// are the largest message sent.
    pub fn new(aliases: Vec<Name>, target: Name, seed: u64) -> Result<Responder, TooManyAliases> {
        let records = Records { aliases, target };
        let bytes = wire::encode(&records.probe(true)).len();
        if bytes > MAX_PACKET {
            return Err(TooManyAliases { bytes });
        }
        Ok(Responder {
            records,
            links: BTreeMap::new(),
            rng: seed | 1,
        })
    }

    /// Starts probing on a newly usable link, after a random 0-250 ms wait so
    /// hosts starting together do not probe in lockstep.
    pub fn add_link(&mut self, link: Link, now: u64) {
        let due = now + self.random(PROBE_WAIT_MAX + 1);
        let last_multicast = vec![None; self.records.aliases.len()];
        self.links.insert(
            link,
            LinkState {
                phase: Phase::Probing { sent: 0, due },
                last_multicast,
            },
        );
    }

    pub fn remove_link(&mut self, link: Link) {
        self.links.remove(&link);
    }

    /// Sends whatever probe or announcement has come due.
    pub fn poll(&mut self, now: u64) -> Step {
        let mut step = Step::default();
        for (&link, state) in &mut self.links {
            let msg = match state.phase {
                Phase::Probing { sent, due } if now >= due && sent < PROBES => {
                    state.phase = Phase::Probing {
                        sent: sent + 1,
                        due: now + PROBE_INTERVAL,
                    };
                    self.records.probe(sent == 0)
                }
                Phase::Probing { due, .. } if now >= due => {
                    state.phase = Phase::Announcing {
                        due: now + ANNOUNCE_INTERVAL,
                    };
                    state.last_multicast.fill(Some(now));
                    self.records.announcement(TTL)
                }
                Phase::Announcing { due } if now >= due => {
                    state.phase = Phase::Announced;
                    state.last_multicast.fill(Some(now));
                    step.notices.push(Notice::Announced(link));
                    self.records.announcement(TTL)
                }
                _ => continue,
            };
            step.sends.push(Outgoing {
                link,
                dest: Dest::Multicast,
                packet: wire::encode(&msg),
            });
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
                self.check_response(&msg, source)?;
            }
        } else {
            self.tiebreak(&msg, link, now, &mut step);
            self.answer(&msg, link, source, now, &mut step);
        }
        Ok(step)
    }

    /// Anyone answering for one of our aliases with other data is a conflict
    /// (RFC 6762 section 9), whether we are still probing or long announced.
    /// Goodbyes withdraw rather than claim, and our own records looping
    /// back, or another instance publishing the same, agree with us.
    fn check_response(&self, msg: &Message, source: SocketAddr) -> Result<(), Conflict> {
        for rec in msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
        {
            if rec.ttl == 0 || self.records.is_ours(rec) {
                continue;
            }
            if let Some(i) = self.records.alias_index(&rec.name) {
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
    fn tiebreak(&mut self, msg: &Message, link: Link, now: u64, step: &mut Step) {
        let Some(state) = self.links.get_mut(&link) else {
            return;
        };
        if !matches!(state.phase, Phase::Probing { .. }) {
            return;
        }
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
            theirs.sort();
            let ours = vec![canonical(&self.records.cname(i, TTL, false))];
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
        if matches!(state.phase, Phase::Probing { .. }) {
            return;
        }
        let mut hits: Vec<usize> = Vec::new();
        let mut all_unicast = true;
        for q in &msg.questions {
            if !matches!(q.qclass, CLASS_IN | CLASS_ANY)
                || !matches!(q.qtype, TYPE_A | TYPE_AAAA | TYPE_CNAME | TYPE_ANY)
            {
                continue;
            }
            let Some(i) = self.records.alias_index(&q.name) else {
                continue;
            };
            all_unicast &= q.unicast_response;
            if !hits.contains(&i) {
                hits.push(i);
            }
        }
        // Known-answer suppression (RFC 6762 section 7.1): skip what the
        // querier holds with at least half its TTL left.
        let records = &self.records;
        hits.retain(|&i| {
            !msg.answers.iter().any(|known| {
                known.name == records.aliases[i] && records.is_ours(known) && known.ttl >= TTL / 2
            })
        });
        if hits.is_empty() {
            return;
        }

        let legacy = source.port() != MDNS_PORT;
        let reply = if legacy {
            // Legacy unicast (RFC 6762 section 6.7): echo the ID and
            // questions, keep the TTL short, and leave out the cache-flush
            // bit, which such resolvers do not understand.
            Message {
                id: msg.id,
                is_response: true,
                questions: msg.questions.clone(),
                answers: hits
                    .iter()
                    .map(|&i| records.cname(i, LEGACY_TTL, false))
                    .collect(),
                ..Message::default()
            }
        } else {
            if !all_unicast {
                // A probe must be answered at once, so it is exempt.
                let probe = !msg.authorities.is_empty();
                hits.retain(|&i| {
                    probe || state.last_multicast[i].is_none_or(|t| now >= t + RATE_LIMIT)
                });
                if hits.is_empty() {
                    return;
                }
                for &i in &hits {
                    state.last_multicast[i] = Some(now);
                }
            }
            Message {
                is_response: true,
                answers: hits.iter().map(|&i| records.cname(i, TTL, true)).collect(),
                ..Message::default()
            }
        };
        let dest = if legacy || all_unicast {
            Dest::Unicast(source)
        } else {
            Dest::Multicast
        };
        step.sends.push(Outgoing {
            link,
            dest,
            packet: wire::encode(&reply),
        });
    }

    /// Goodbyes (TTL 0) for every link that has announced, so clients drop
    /// the names now instead of when their caches expire.
    pub fn goodbye(&self) -> Vec<Outgoing> {
        let packet = wire::encode(&self.records.announcement(0));
        self.links
            .iter()
            .filter(|(_, state)| matches!(state.phase, Phase::Announcing { .. } | Phase::Announced))
            .map(|(&link, _)| Outgoing {
                link,
                dest: Dest::Multicast,
                packet: packet.clone(),
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
        Responder::new(vec![name(ALIAS)], name(TARGET), 7).unwrap()
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
            let mut r = Responder::new(vec![name(ALIAS)], name(TARGET), seed).unwrap();
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

    #[test]
    fn rejects_aliases_that_do_not_fit_one_probe() {
        let many: Vec<Name> = (0..30)
            .map(|i| name(&format!("{}{i}.myhost.local", "a".repeat(50))))
            .collect();
        let err = Responder::new(many, name(TARGET), 7).err().unwrap();
        assert!(err.bytes > MAX_PACKET);
        assert!(
            err.to_string()
                .starts_with("too many aliases: a probe would be ")
        );
        let few: Vec<Name> = (0..10)
            .map(|i| name(&format!("app{i}.myhost.local")))
            .collect();
        assert!(Responder::new(few, name(TARGET), 7).is_ok());
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
            rdata: RData::Other(vec![192, 0, 2, 1]),
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
        let own = r.records.announcement(TTL);
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
        let own = r.records.probe(false);
        assert!(hear(&mut r, &own, 251).unwrap().notices.is_empty());
        let (after, _) = run(&mut r, 252, 3000);
        assert_eq!(before.len() + after.len(), 5);
    }
}
