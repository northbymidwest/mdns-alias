//! DNS wire format, as far as mDNS needs it here: parse any message, and
//! encode messages holding questions and records (RFC 1035 section 4, RFC
//! 6762 section 18). Pure: no I/O.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A record or question type (RFC 1035 section 3.2.2). The wire allows any
/// value, so this is a number with names for the ones used here rather than
/// an enum; the names work as `match` patterns.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RType(pub u16);

impl RType {
    pub const A: RType = RType(1);
    pub const CNAME: RType = RType(5);
    pub const AAAA: RType = RType(28);
    pub const NSEC: RType = RType(47);
    /// Questions only: every type the name has.
    pub const ANY: RType = RType(255);
}

/// The name, or `TYPE` and the number for others (RFC 3597 section 5).
impl fmt::Debug for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RType::A => f.write_str("A"),
            RType::CNAME => f.write_str("CNAME"),
            RType::AAAA => f.write_str("AAAA"),
            RType::NSEC => f.write_str("NSEC"),
            RType::ANY => f.write_str("ANY"),
            RType(n) => write!(f, "TYPE{n}"),
        }
    }
}

/// A record or question class, without the top bit mDNS gives its own
/// meaning. Open on the wire like `RType`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Class(pub u16);

impl Class {
    pub const IN: Class = Class(1);
    /// Questions only: any class.
    pub const ANY: Class = Class(255);
}

/// The name, or `CLASS` and the number for others (RFC 3597 section 5).
impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Class::IN => f.write_str("IN"),
            Class::ANY => f.write_str("ANY"),
            Class(n) => write!(f, "CLASS{n}"),
        }
    }
}

/// Top bit of a question's class: the querier asks for a unicast reply.
const QU_BIT: u16 = 0x8000;
/// Top bit of a record's class: this record replaces any cached ones of the
/// same name and type.
const CACHE_FLUSH_BIT: u16 = 0x8000;
const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000F;
const MAX_LABEL: usize = 63;
/// Encoded length limit of a name, length bytes and root label included.
const MAX_NAME: usize = 255;

/// A domain name, kept as its uncompressed wire form in one buffer: each
/// label as a length byte (1-63) and that many bytes, then the zero-length
/// root label, 255 bytes at most in all. A clone is one allocation however
/// many labels there are, and `wire` is a borrow.
///
/// Labels keep the case they came with, for display and for record
/// comparison; equality ignores ASCII case, as DNS does. Folding
/// the whole buffer is exact: length bytes are at most 63, below `A`, so
/// folding never changes them, and comparing them keeps label boundaries.
#[derive(Clone)]
pub struct Name(Box<[u8]>);

#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    EmptyLabel,
    LabelTooLong,
    TooLong,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameError::Empty => "empty name",
            NameError::EmptyLabel => "empty label",
            NameError::LabelTooLong => "label longer than 63 bytes",
            NameError::TooLong => "name longer than 255 bytes",
        })
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// Parses dotted text: `app.myhost.local`, with or without the final dot.
    /// The first empty or overlong label is the error, before the length.
    pub fn parse(text: &str) -> Result<Name, NameError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        // Each dot becomes a length byte, plus one for the first label and
        // one for the root: exactly the wire length.
        let mut wire = Vec::with_capacity(text.len() + 2);
        for label in text.split('.') {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL {
                return Err(NameError::LabelTooLong);
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        if wire.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        Ok(Name(wire.into_boxed_slice()))
    }

    /// The labels, in order, without length bytes or the root.
    fn labels(&self) -> impl Iterator<Item = &[u8]> {
        let mut rest = &self.0[..];
        std::iter::from_fn(move || {
            let (&len, tail) = rest.split_first()?;
            let label = tail.get(..usize::from(len)).filter(|l| !l.is_empty())?;
            rest = &tail[label.len()..];
            Some(label)
        })
    }

    /// Whether this is a name under `.local`: at least one label, then
    /// `local` in any case.
    pub fn is_local(&self) -> bool {
        let (count, last) = self
            .labels()
            .fold((0, None), |(count, _), label| (count + 1, Some(label)));
        count >= 2 && last.is_some_and(|l| l.eq_ignore_ascii_case(b"local"))
    }

    /// This name with `base` appended: `seerr` under `myhost.local` is
    /// `seerr.myhost.local`. Fails if the result is too long.
    pub fn under(&self, base: &Name) -> Result<Name, NameError> {
        // Both are valid names, so only the length can be wrong.
        let labels = &self.0[..self.0.len() - 1];
        let len = labels.len() + base.0.len();
        if len > MAX_NAME {
            return Err(NameError::TooLong);
        }
        let mut wire = Vec::with_capacity(len);
        wire.extend_from_slice(labels);
        wire.extend_from_slice(&base.0);
        Ok(Name(wire.into_boxed_slice()))
    }

    /// Uncompressed wire form, which record comparison (RFC 6762 section
    /// 8.2) is defined on.
    fn wire(&self) -> &[u8] {
        &self.0
    }

    /// `wire`, owned: one copy.
    fn to_wire(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for Name {}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut labels = self.labels();
        let Some(first) = labels.next() else {
            return f.write_str(".");
        };
        f.write_str(&String::from_utf8_lossy(first))?;
        for label in labels {
            f.write_str(".")?;
            f.write_str(&String::from_utf8_lossy(label))?;
        }
        Ok(())
    }
}

/// `Name([label bytes, ...])`, as when names were lists of labels.
impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Labels<'a>(&'a Name);
        impl fmt::Debug for Labels<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.labels()).finish()
            }
        }
        f.debug_tuple("Name").field(&Labels(self)).finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub name: Name,
    pub qtype: RType,
    /// Class without the unicast-response bit.
    pub qclass: Class,
    pub unicast_response: bool,
}

/// The types an NSEC record names: sorted and without duplicates, which
/// every way of making one ensures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Types(Vec<RType>);

impl Types {
    /// The types, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = RType> + '_ {
        self.0.iter().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Sorts and removes duplicates, with `order::sort`: only for short lists
/// of our own, never for types from the network (the parser needs no sort).
impl FromIterator<RType> for Types {
    fn from_iter<I: IntoIterator<Item = RType>>(iter: I) -> Types {
        let mut types: Vec<RType> = iter.into_iter().collect();
        crate::order::sort(&mut types);
        types.dedup();
        Types(types)
    }
}

/// A record's data, which also determines its type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    /// NSEC (RFC 4034 section 4): in mDNS the next name is the owner itself,
    /// and the types are those the owner has.
    Nsec {
        next: Name,
        types: Types,
    },
    /// Any other type, or an address record of the wrong length, as raw
    /// bytes. Parsing never yields this for CNAME or NSEC, nor for A or AAAA
    /// of the right length; records built here must not either, or they
    /// would not compare equal to the same record parsed.
    Other {
        rtype: RType,
        bytes: Vec<u8>,
    },
}

impl RData {
    fn rtype(&self) -> RType {
        match self {
            RData::A(_) => RType::A,
            RData::Aaaa(_) => RType::AAAA,
            RData::Cname(_) => RType::CNAME,
            RData::Nsec { .. } => RType::NSEC,
            RData::Other { rtype, .. } => *rtype,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: Name,
    /// Class without the cache-flush bit.
    pub class: Class,
    pub cache_flush: bool,
    pub ttl: u32,
    pub rdata: RData,
}

impl Record {
    pub fn rtype(&self) -> RType {
        self.rdata.rtype()
    }

    /// Uncompressed rdata, which record comparison (RFC 6762 section 8.2) is
    /// defined on.
    pub fn rdata_wire(&self) -> Vec<u8> {
        match &self.rdata {
            RData::A(addr) => addr.octets().to_vec(),
            RData::Aaaa(addr) => addr.octets().to_vec(),
            RData::Cname(name) => name.to_wire(),
            RData::Nsec { next, types } => {
                let mut out = next.to_wire();
                out.extend(type_bitmap(types));
                out
            }
            RData::Other { bytes, .. } => bytes.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

/// Parses a whole message. `None` for anything malformed, and for messages
/// with a non-zero opcode or rcode, which RFC 6762 section 18 says to ignore.
/// Bytes after the last record are ignored.
pub fn parse(packet: &[u8]) -> Option<Message> {
    let mut r = Reader { packet, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    if flags & (OPCODE_MASK | RCODE_MASK) != 0 {
        return None;
    }
    let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
    let mut msg = Message {
        id,
        is_response: flags & FLAG_QR != 0,
        ..Message::default()
    };
    for _ in 0..counts[0] {
        let name = r.name()?;
        let qtype = RType(r.u16()?);
        let class = r.u16()?;
        msg.questions.push(Question {
            name,
            qtype,
            qclass: Class(class & !QU_BIT),
            unicast_response: class & QU_BIT != 0,
        });
    }
    let sections = [&mut msg.answers, &mut msg.authorities, &mut msg.additionals];
    for (count, section) in counts[1..].iter().zip(sections) {
        for _ in 0..*count {
            section.push(r.record()?);
        }
    }
    Some(msg)
}

struct Reader<'a> {
    packet: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let bytes = self.packet.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(bytes)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Option<Name> {
        let (name, end) = read_name(self.packet, self.pos)?;
        self.pos = end;
        Some(name)
    }

    fn record(&mut self) -> Option<Record> {
        let name = self.name()?;
        let rtype = RType(self.u16()?);
        let class = self.u16()?;
        let ttl = self.u32()?;
        let len = usize::from(self.u16()?);
        let start = self.pos;
        let raw = self.bytes(len)?.to_vec();
        let rdata = match rtype {
            RType::CNAME => {
                // The target may use compression, so it is read from the
                // whole packet, and must fill the rdata exactly.
                let (target, end) = read_name(self.packet, start)?;
                if end != start + len {
                    return None;
                }
                RData::Cname(target)
            }
            RType::A if len == 4 => RData::A(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
            RType::AAAA if len == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            RType::NSEC => {
                // The next name may be compressed (RFC 6762 section 18.14);
                // the type bitmap fills the rest of the rdata.
                let (next, end) = read_name(self.packet, start)?;
                let types = bitmap_types(self.packet.get(end..start + len)?)?;
                RData::Nsec { next, types }
            }
            _ => RData::Other { rtype, bytes: raw },
        };
        Some(Record {
            name,
            class: Class(class & !CACHE_FLUSH_BIT),
            cache_flush: class & CACHE_FLUSH_BIT != 0,
            ttl,
            rdata,
        })
    }
}

/// Reads the name at `pos`, returning it and the offset just past it.
///
/// Every compression pointer must point before itself, so a chain of bare
/// pointers always ends; a cycle through labels grows the name, which the
/// 255-byte limit ends. Either way, every read terminates.
fn read_name(packet: &[u8], mut pos: usize) -> Option<(Name, usize)> {
    // The wire form is built here, then copied out in one allocation of
    // exactly its length.
    let mut wire = [0u8; MAX_NAME];
    let mut len = 0;
    let mut end = None;
    loop {
        let byte = usize::from(*packet.get(pos)?);
        match byte & 0xC0 {
            0x00 if byte == 0 => break,
            0x00 => {
                // The label with its length byte, which must leave room for
                // the root label.
                let label = packet.get(pos..pos + 1 + byte)?;
                if len + label.len() >= MAX_NAME {
                    return None;
                }
                wire[len..len + label.len()].copy_from_slice(label);
                len += label.len();
                pos += label.len();
            }
            0xC0 => {
                let low = usize::from(*packet.get(pos + 1)?);
                let target = ((byte & 0x3F) << 8) | low;
                if target >= pos {
                    return None;
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            // 0x40 and 0x80 label types were never deployed.
            _ => return None,
        }
    }
    // `wire[len]` is still zero: the root label.
    Some((Name(Box::from(&wire[..=len])), end.unwrap_or(pos + 1)))
}

/// The types in an NSEC type bitmap (RFC 4034 section 4.1.2): windows of a
/// block number, a length of 1-32 and that many bitmap octets. The windows
/// must be in strictly increasing order, so the types come out sorted and
/// unique without a sort, as `Types` requires. `None` if malformed.
fn bitmap_types(mut b: &[u8]) -> Option<Types> {
    let mut types = Vec::new();
    let mut last = None;
    while !b.is_empty() {
        let window = u16::from(*b.first()?);
        if last.is_some_and(|prev| window <= prev) {
            return None;
        }
        last = Some(window);
        let len = usize::from(*b.get(1)?);
        if len == 0 || len > 32 {
            return None;
        }
        let octets = b.get(2..2 + len)?;
        for (octet, &bits) in octets.iter().enumerate() {
            for bit in 0..8 {
                if bits & (0x80 >> bit) != 0 {
                    types.push(RType(window * 256 + (octet * 8 + bit) as u16));
                }
            }
        }
        b = &b[2 + len..];
    }
    Some(Types(types))
}

/// The NSEC type bitmap for `types`, which are already sorted and unique.
fn type_bitmap(types: &Types) -> Vec<u8> {
    let types = &types.0;
    let mut out = Vec::new();
    let mut i = 0;
    while i < types.len() {
        let window = types[i].0 >> 8;
        let mut octets = [0u8; 32];
        let mut len = 0;
        while i < types.len() && types[i].0 >> 8 == window {
            let low = usize::from(types[i].0 & 0xff);
            octets[low / 8] |= 0x80 >> (low % 8);
            len = len.max(low / 8 + 1);
            i += 1;
        }
        out.push(window as u8);
        out.push(len as u8);
        out.extend_from_slice(&octets[..len]);
    }
    out
}

/// Encodes `msg`. Responses carry QR and AA (every answer here is
/// authoritative), queries no flags. Names are compressed against earlier
/// ones in the message, which keeps a probe for many aliases under one
/// target small.
pub fn encode(msg: &Message) -> Vec<u8> {
    let mut w = Writer {
        out: Vec::with_capacity(512),
        suffixes: Vec::new(),
    };
    w.u16(msg.id);
    w.u16(if msg.is_response {
        FLAG_QR | FLAG_AA
    } else {
        0
    });
    for count in [
        msg.questions.len(),
        msg.answers.len(),
        msg.authorities.len(),
        msg.additionals.len(),
    ] {
        w.u16(count as u16);
    }
    for q in &msg.questions {
        w.name(&q.name);
        w.u16(q.qtype.0);
        w.u16(q.qclass.0 | if q.unicast_response { QU_BIT } else { 0 });
    }
    for rec in msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
    {
        w.name(&rec.name);
        w.u16(rec.rtype().0);
        w.u16(rec.class.0 | if rec.cache_flush { CACHE_FLUSH_BIT } else { 0 });
        w.u32(rec.ttl);
        let len_at = w.out.len();
        w.u16(0);
        match &rec.rdata {
            RData::A(addr) => w.out.extend_from_slice(&addr.octets()),
            RData::Aaaa(addr) => w.out.extend_from_slice(&addr.octets()),
            RData::Cname(target) => w.name(target),
            RData::Nsec { next, types } => {
                w.name(next);
                w.out.extend(type_bitmap(types));
            }
            RData::Other { bytes, .. } => w.out.extend_from_slice(bytes),
        }
        let len = (w.out.len() - len_at - 2) as u16;
        w.out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
    }
    w.out
}

struct Writer {
    out: Vec<u8>,
    /// Where in `out` each name suffix written so far as labels starts, for
    /// later names to point at. No two hold the same name ignoring case.
    suffixes: Vec<u16>,
}

impl Writer {
    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes `name`, ending in a pointer at its longest suffix already
    /// written, if any.
    fn name(&mut self, name: &Name) {
        let wire = name.wire();
        // Suffixes of this name stored below are not finished yet, and could
        // not match a shorter suffix of it anyway.
        let known = self.suffixes.len();
        let mut pos = 0;
        while wire[pos] != 0 {
            let suffix = &wire[pos..];
            let mut earlier = self.suffixes[..known].iter();
            if let Some(&offset) = earlier.find(|&&at| self.holds(at, suffix)) {
                self.u16(0xC000 | offset);
                return;
            }
            // Pointers hold 14 bits, so later offsets cannot be targets.
            if let Ok(offset) = u16::try_from(self.out.len())
                && offset <= 0x3FFF
            {
                self.suffixes.push(offset);
            }
            let next = pos + 1 + usize::from(wire[pos]);
            self.out.extend_from_slice(&wire[pos..next]);
            pos = next;
        }
        self.out.push(0);
    }

    /// Whether the finished name written at `at` is `suffix`, an
    /// uncompressed wire form, ignoring case. Pointers on the way are this
    /// writer's own, each to an earlier suffix, so the walk ends.
    fn holds(&self, at: u16, suffix: &[u8]) -> bool {
        let mut at = usize::from(at);
        let mut pos = 0;
        loop {
            let byte = self.out[at];
            if byte & 0xC0 == 0xC0 {
                at = usize::from(u16::from_be_bytes([byte & 0x3F, self.out[at + 1]]));
                continue;
            }
            // The label with its length byte, or the root label alone.
            let len = 1 + usize::from(byte);
            match suffix.get(pos..pos + len) {
                Some(theirs) if self.out[at..at + len].eq_ignore_ascii_case(theirs) => {}
                _ => return false,
            }
            if byte == 0 {
                return true;
            }
            at += len;
            pos += len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    /// A header with ID 0x1234, the given flags and section counts.
    fn header(flags: u16, counts: [u16; 4]) -> Vec<u8> {
        let mut out = vec![0x12, 0x34];
        out.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out
    }

    #[test]
    fn parses_names_with_or_without_the_root_dot() {
        assert_eq!(name("app.myhost.local").to_string(), "app.myhost.local");
        assert_eq!(name("app.myhost.local."), name("app.myhost.local"));
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(Name::parse(""), Err(NameError::Empty));
        assert_eq!(Name::parse("."), Err(NameError::Empty));
        assert_eq!(Name::parse("a..local"), Err(NameError::EmptyLabel));
        let long_label = format!("{}.local", "a".repeat(64));
        assert_eq!(Name::parse(&long_label), Err(NameError::LabelTooLong));
        // 5 labels of 60 bytes plus "local": 5 x 61 + 6 + 1 = 312 bytes.
        let long_name = format!("{}local", format!("{}.", "a".repeat(60)).repeat(5));
        assert_eq!(Name::parse(&long_name), Err(NameError::TooLong));
    }

    #[test]
    fn name_equality_ignores_case() {
        assert_eq!(name("APP.MyHost.local"), name("app.myhost.LOCAL"));
        assert_ne!(name("app.local"), name("app.myhost.local"));
    }

    #[test]
    fn local_names_need_a_label_before_local() {
        assert!(name("myhost.local").is_local());
        assert!(name("app.myhost.LOCAL").is_local());
        assert!(!name("local").is_local());
        assert!(!name("myhost.lan").is_local());
    }

    #[test]
    fn names_debug_print_as_label_lists() {
        assert_eq!(format!("{:?}", name("ab.c")), "Name([[97, 98], [99]])");
    }

    #[test]
    fn to_wire_is_uncompressed() {
        assert_eq!(name("myhost.local").to_wire(), b"\x06myhost\x05local\x00");
    }

    #[test]
    fn parses_a_query() {
        let mut p = header(0, [1, 0, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00");
        p.extend_from_slice(&[0, 1, 0x80, 1]); // type A, class IN with the QU bit
        let msg = parse(&p).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(
            msg.questions,
            vec![Question {
                name: name("app.local"),
                qtype: RType::A,
                qclass: Class::IN,
                unicast_response: true,
            }]
        );
    }

    #[test]
    fn follows_compression_pointers() {
        let mut p = header(0, [2, 0, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00\x00\x01\x00\x01");
        // "web" then a pointer to offset 16, the "local" label above.
        p.extend_from_slice(b"\x03web\xC0\x10\x00\x01\x00\x01");
        let msg = parse(&p).unwrap();
        assert_eq!(msg.questions[1].name, name("web.local"));
    }

    #[test]
    fn rejects_pointers_that_do_not_point_backward() {
        for name_bytes in [&b"\xC0\x0E"[..], b"\xC0\x0C"] {
            let mut p = header(0, [1, 0, 0, 0]);
            p.extend_from_slice(name_bytes);
            p.extend_from_slice(&[0, 0, 1, 0, 1]);
            assert_eq!(parse(&p), None);
        }
    }

    #[test]
    fn rejects_a_label_and_pointer_cycle() {
        // "a" then a pointer back to itself: valid pointers, endless name.
        let mut p = header(0, [1, 0, 0, 0]);
        p.extend_from_slice(b"\x01a\xC0\x0C\x00\x01\x00\x01");
        assert_eq!(parse(&p), None);
    }

    #[test]
    fn parses_records_and_their_class_bits() {
        let mut p = header(0x8400, [0, 2, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00");
        p.extend_from_slice(&[0, 5, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xC0, 0x10]);
        p.extend_from_slice(b"\xC0\x0C");
        p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 1]);
        let msg = parse(&p).unwrap();
        assert!(msg.is_response);
        assert_eq!(
            msg.answers,
            vec![
                Record {
                    name: name("app.local"),
                    class: Class::IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::Cname(name("local")),
                },
                Record {
                    name: name("app.local"),
                    class: Class::IN,
                    cache_flush: false,
                    ttl: 120,
                    rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                },
            ]
        );
    }

    #[test]
    fn rejects_cname_rdata_with_bytes_past_the_name() {
        let mut p = header(0x8400, [0, 1, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00");
        p.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 120, 0, 3, 0xC0, 0x10, 0]);
        assert_eq!(parse(&p), None);
    }

    #[test]
    fn ignores_nonzero_opcode_and_rcode() {
        for flags in [0x2800, 0x8403] {
            let mut p = header(flags, [1, 0, 0, 0]);
            p.extend_from_slice(b"\x03app\x05local\x00\x00\x01\x00\x01");
            assert_eq!(parse(&p), None);
        }
    }

    #[test]
    fn rejects_every_truncation() {
        let mut p = header(0x8400, [0, 1, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00");
        p.extend_from_slice(&[0, 5, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xC0, 0x10]);
        assert!(parse(&p).is_some());
        for len in 0..p.len() {
            assert_eq!(parse(&p[..len]), None, "prefix of {len} bytes");
        }
    }

    fn cname(alias: &str, target: &str) -> Record {
        Record {
            name: name(alias),
            class: Class::IN,
            cache_flush: true,
            ttl: 120,
            rdata: RData::Cname(name(target)),
        }
    }

    #[test]
    fn encode_then_parse_round_trips() {
        let msg = Message {
            id: 7,
            is_response: true,
            questions: vec![Question {
                name: name("app.myhost.local"),
                qtype: RType::ANY,
                qclass: Class::IN,
                unicast_response: true,
            }],
            answers: vec![cname("app.myhost.local", "myhost.local")],
            authorities: vec![Record {
                name: name("App.MYhost.local"),
                class: Class::IN,
                cache_flush: false,
                ttl: 0,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            }],
            additionals: vec![cname("web.local", "myhost.local")],
        };
        assert_eq!(parse(&encode(&msg)), Some(msg));
    }

    #[test]
    fn sets_response_flags_only_on_responses() {
        let query = Message::default();
        assert_eq!(encode(&query)[2..4], [0, 0]);
        let response = Message {
            is_response: true,
            ..Message::default()
        };
        assert_eq!(encode(&response)[2..4], [0x84, 0x00]);
    }

    #[test]
    fn compresses_repeated_suffixes() {
        let msg = Message {
            is_response: true,
            answers: vec![
                cname("a.myhost.local", "myhost.local"),
                cname("b.myhost.local", "myhost.local"),
            ],
            ..Message::default()
        };
        // Header 12. First record: full name (16), fixed fields (10), target
        // as a pointer (2). Second: "b" and a pointer (4), fixed (10),
        // pointer (2).
        assert_eq!(encode(&msg).len(), 12 + 28 + 16);
    }

    #[test]
    fn under_appends_the_base_and_checks_length() {
        assert_eq!(
            name("api.seerr").under(&name("myhost.local")),
            Ok(name("api.seerr.myhost.local"))
        );
        let long = name(&vec!["a".repeat(60); 4].join("."));
        assert_eq!(long.under(&name("myhost.local")), Err(NameError::TooLong));
    }

    #[test]
    fn address_and_nsec_records_round_trip() {
        let msg = Message {
            is_response: true,
            answers: vec![
                Record {
                    name: name("app.myhost.local"),
                    class: Class::IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::A("192.0.2.10".parse().unwrap()),
                },
                Record {
                    name: name("app.myhost.local"),
                    class: Class::IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::Aaaa("fe80::1".parse().unwrap()),
                },
                Record {
                    name: name("app.myhost.local"),
                    class: Class::IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::Nsec {
                        next: name("app.myhost.local"),
                        types: [RType::A, RType::AAAA].into_iter().collect(),
                    },
                },
            ],
            ..Message::default()
        };
        assert_eq!(parse(&encode(&msg)), Some(msg));
    }

    #[test]
    fn nsec_bitmap_has_the_rfc_shape() {
        let rec = Record {
            name: name("app.local"),
            class: Class::IN,
            cache_flush: false,
            ttl: 120,
            rdata: RData::Nsec {
                next: name("app.local"),
                types: [RType::AAAA, RType::A].into_iter().collect(),
            },
        };
        // RFC 4034 section 4.1.2: window 0, 4 octets, bit 1 (A) and bit 28
        // (AAAA) set, most significant bit first.
        let mut expected = name("app.local").to_wire();
        expected.extend([0, 4, 0x40, 0, 0, 0x08]);
        assert_eq!(rec.rdata_wire(), expected);
    }

    /// A response with one NSEC record for `app.local` carrying `bitmap`.
    fn nsec_packet(bitmap: &[u8]) -> Vec<u8> {
        let mut p = header(0x8400, [0, 1, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00");
        let mut rdata = b"\xC0\x0C".to_vec();
        rdata.extend_from_slice(bitmap);
        p.extend_from_slice(&[0, 47, 0, 1, 0, 0, 0, 120]);
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(&rdata);
        p
    }

    #[test]
    fn rejects_malformed_nsec_bitmaps() {
        for bitmap in [&[0u8, 0][..], &[0, 33], &[0, 2, 0x40]] {
            assert_eq!(parse(&nsec_packet(bitmap)), None, "bitmap {bitmap:?}");
        }
    }

    #[test]
    fn rejects_nsec_windows_out_of_order() {
        // Window 1 (type 257) before window 0 (type 1).
        let bitmap = [1, 1, 0x40, 0, 1, 0x40];
        assert_eq!(parse(&nsec_packet(&bitmap)), None);
    }

    #[test]
    fn rejects_a_repeated_nsec_window() {
        let bitmap = [0, 1, 0x40, 0, 1, 0x20];
        assert_eq!(parse(&nsec_packet(&bitmap)), None);
    }

    #[test]
    fn nsec_windows_in_ascending_order_round_trip() {
        let types: Types = [1, 28, 256 + 1].map(RType).into_iter().collect();
        let bitmap = type_bitmap(&types);
        // Window 0 carries types 1 and 28, window 1 carries type 257.
        assert_eq!(bitmap, [0, 4, 0x40, 0, 0, 0x08, 1, 1, 0x40]);
        let msg = parse(&nsec_packet(&bitmap)).unwrap();
        assert_eq!(
            msg.answers[0].rdata,
            RData::Nsec {
                next: name("app.local"),
                types,
            }
        );
    }

    #[test]
    fn address_records_of_the_wrong_length_stay_raw() {
        let mut p = header(0x8400, [0, 1, 0, 0]);
        p.extend_from_slice(b"\x03app\x05local\x00");
        p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 3, 192, 0, 2]);
        let msg = parse(&p).unwrap();
        assert_eq!(
            msg.answers[0].rdata,
            RData::Other {
                rtype: RType::A,
                bytes: vec![192, 0, 2]
            }
        );
    }

    #[test]
    fn types_and_classes_debug_print_by_name() {
        assert_eq!(format!("{:?}", RType::AAAA), "AAAA");
        assert_eq!(format!("{:?}", RType(65)), "TYPE65");
        assert_eq!(format!("{:?}", Class::IN), "IN");
        assert_eq!(format!("{:?}", Class(3)), "CLASS3");
    }

    #[test]
    fn nsec_types_are_sorted_and_unique_however_built() {
        let types: Types = [RType::AAAA, RType::A, RType::AAAA].into_iter().collect();
        assert_eq!(types.iter().collect::<Vec<_>>(), [RType::A, RType::AAAA]);
        assert!(!types.is_empty());
    }

    #[test]
    fn a_record_type_comes_from_its_data() {
        assert_eq!(cname("app.local", "myhost.local").rtype(), RType::CNAME);
        let other = RData::Other {
            rtype: RType(16),
            bytes: vec![1, b'x'],
        };
        assert_eq!(other.rtype(), RType(16));
    }
    /// Hex to bytes, for the test vectors below.
    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn any_question(text: &str) -> Question {
        Question {
            name: name(text),
            qtype: RType::ANY,
            qclass: Class::IN,
            unicast_response: false,
        }
    }

    fn a_record(text: &str, last: u8) -> Record {
        Record {
            name: name(text),
            class: Class::IN,
            cache_flush: true,
            ttl: 120,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, last)),
        }
    }

    fn nsec_record(text: &str, next: &str) -> Record {
        Record {
            name: name(text),
            class: Class::IN,
            cache_flush: true,
            ttl: 120,
            rdata: RData::Nsec {
                next: name(next),
                types: [RType::A, RType::AAAA].into_iter().collect(),
            },
        }
    }

    /// Encodes `msg`, checks the bytes, and checks they parse back to it.
    fn assert_encodes_to(msg: &Message, expected: &[u8]) {
        let bytes = encode(msg);
        assert_eq!(bytes, expected);
        assert_eq!(parse(&bytes).as_ref(), Some(msg));
    }

    // The vectors below were captured from the encoder that kept names as
    // label lists and compressed against lowercased copies of every suffix;
    // the encoder must keep producing exactly these bytes.

    #[test]
    fn compression_matches_the_vectors_for_aliases_under_one_host() {
        let msg = Message {
            is_response: true,
            answers: vec![
                cname("a.myhost.local", "myhost.local"),
                cname("b.myhost.local", "myhost.local"),
            ],
            ..Message::default()
        };
        assert_encodes_to(
            &msg,
            &unhex(concat!(
                "000084000000000200000000",
                "0161066d79686f7374056c6f63616c00",
                "00058001000000780002c00e",
                "0162c00e00058001000000780002c00e",
            )),
        );
    }

    #[test]
    fn compression_matches_the_vectors_across_case_and_partial_suffixes() {
        let msg = Message {
            id: 0x0102,
            questions: vec![
                any_question("App.MyHost.LOCAL"),
                any_question("web.myhost.local"),
                any_question("b.c.d.local"),
            ],
            authorities: vec![
                cname("app.myhost.local", "MYHOST.local"),
                cname("WEB.MYHOST.LOCAL", "myhost.local"),
                cname("B.C.D.LOCAL", "x.c.d.local"),
                cname("c.d.local", "d.LoCaL"),
            ],
            ..Message::default()
        };
        assert_encodes_to(
            &msg,
            &unhex(concat!(
                "010200000003000000040000",
                "03417070064d79486f7374054c4f43414c0000ff0001",
                "03776562c01000ff0001",
                "016201630164c01700ff0001",
                "c00c00058001000000780002c010",
                "c02200058001000000780002c010",
                "c02c000580010000007800040178c02e",
                "c02e00058001000000780002c030",
            )),
        );
    }

    #[test]
    fn compression_matches_the_vectors_for_mixed_records() {
        let msg = Message {
            id: 9,
            is_response: true,
            answers: vec![
                a_record("app.myhost.local", 1),
                nsec_record("App.myhost.local", "APP.myhost.local"),
            ],
            additionals: vec![
                a_record("other.example", 2),
                cname("q.other.EXAMPLE", "other.example.local"),
                nsec_record("Other.Example.Local", "local"),
            ],
            ..Message::default()
        };
        assert_encodes_to(
            &msg,
            &unhex(concat!(
                "000984000000000200000003",
                "03617070066d79686f7374056c6f63616c00",
                "00018001000000780004c0000201",
                "c00c002f8001000000780008c00c000440000008",
                "056f74686572076578616d706c6500",
                "00018001000000780004c0000202",
                "0171c04000058001000000780010",
                "056f74686572076578616d706c65c017",
                "c06b002f8001000000780008c017000440000008",
            )),
        );
    }

    #[test]
    fn compression_matches_the_vectors_past_the_pointer_range() {
        // Names after the first 16 KiB cannot be pointer targets, so the
        // second "late.big.local" repeats its first label.
        let msg = Message {
            is_response: true,
            answers: vec![
                a_record("a.local", 1),
                Record {
                    name: name("big.local"),
                    class: Class::IN,
                    cache_flush: false,
                    ttl: 1,
                    rdata: RData::Other {
                        rtype: RType(16),
                        bytes: vec![0x5a; 0x4000],
                    },
                },
                a_record("late.big.local", 3),
                a_record("late.big.local", 4),
                a_record("a.local", 5),
                a_record("x.late.big.LOCAL", 6),
            ],
            ..Message::default()
        };
        let mut expected = unhex(concat!(
            "000084000000000600000000",
            "0161056c6f63616c00",
            "00018001000000780004c0000201",
            "03626967c00e0010000100000001",
            "4000",
        ));
        expected.extend([0x5a; 0x4000]);
        expected.extend(unhex(concat!(
            "046c617465c02300018001000000780004c0000203",
            "046c617465c02300018001000000780004c0000204",
            "c00c00018001000000780004c0000205",
            "0178046c617465c02300018001000000780004c0000206",
        )));
        assert_encodes_to(&msg, &expected);
    }

    #[test]
    fn names_differing_only_in_case_are_equal() {
        let pairs = [
            ("APP.MyHost.local", "app.myhost.LOCAL"),
            ("a.b", "A.B"),
            ("Z@[.x", "z@[.X"),
        ];
        for (a, b) in pairs {
            assert_eq!(name(a), name(b));
        }
        // Folding stops at ASCII letters: '@' and '`', '[' and '{' differ.
        assert_ne!(name("a@.local"), name("a`.local"));
        assert_ne!(name("a[.local"), name("a{.local"));
        // Same bytes split into different labels.
        assert_ne!(name("ab.c"), name("a.bc"));
    }

    #[test]
    fn longest_label_and_name_parse_and_round_trip() {
        let label = "a".repeat(63);
        let long_label = name(&format!("{label}.local"));
        assert_eq!(long_label.to_string(), format!("{label}.local"));
        // 3 labels of 63, one of 61: 3 x 64 + 62 + 1 = 255 bytes.
        let text = format!("{label}.{label}.{label}.{}", "b".repeat(61));
        let longest = name(&text);
        assert_eq!(longest.to_wire().len(), 255);
        assert_eq!(longest.to_string(), text);
        for n in [long_label, longest] {
            let msg = Message {
                questions: vec![any_question(&n.to_string())],
                ..Message::default()
            };
            assert_eq!(parse(&encode(&msg)), Some(msg));
        }
        // One byte more is too long, as text or under a base.
        let over = format!("{label}.{label}.{label}.{}", "b".repeat(62));
        assert_eq!(Name::parse(&over), Err(NameError::TooLong));
        let base = name(&format!("{label}.{label}.{label}"));
        assert_eq!(
            name(&"b".repeat(61)).under(&base).unwrap().to_wire().len(),
            255
        );
        assert_eq!(name(&"b".repeat(62)).under(&base), Err(NameError::TooLong));
    }

    #[test]
    fn parse_reports_the_first_label_error_before_the_length() {
        let long = "a".repeat(300);
        assert_eq!(
            Name::parse(&format!("{long}.x..")),
            Err(NameError::LabelTooLong)
        );
        let many = vec!["a"; 200].join(".");
        assert_eq!(
            Name::parse(&format!("{many}..x")),
            Err(NameError::EmptyLabel)
        );
        assert_eq!(Name::parse(&many), Err(NameError::TooLong));
    }

    /// A query for one name given as raw wire bytes.
    fn query_for(name_bytes: &[u8]) -> Vec<u8> {
        let mut p = header(0, [1, 0, 0, 0]);
        p.extend_from_slice(name_bytes);
        p.extend_from_slice(&[0, 1, 0, 1]);
        p
    }

    #[test]
    fn read_name_keeps_the_255_byte_limit() {
        let label = [&[63u8][..], &[b'a'; 63]].concat();
        let mut wire = [&label[..], &label, &label].concat();
        wire.push(61);
        wire.extend([b'b'; 61]);
        wire.push(0);
        assert_eq!(wire.len(), 255);
        let msg = parse(&query_for(&wire)).unwrap();
        assert_eq!(msg.questions[0].name.to_wire(), &wire[..]);
        // One more byte in the last label.
        let mut over = [&label[..], &label, &label].concat();
        over.push(62);
        over.extend([b'b'; 62]);
        over.push(0);
        assert_eq!(parse(&query_for(&over)), None);
    }

    #[test]
    fn the_root_name_reads_and_displays() {
        let msg = parse(&query_for(b"\x00")).unwrap();
        let root = &msg.questions[0].name;
        assert_eq!(root.to_string(), ".");
        assert_eq!(root.to_wire(), b"\x00");
        assert!(!root.is_local());
        assert_eq!(parse(&encode(&msg)), Some(msg.clone()));
    }

    #[test]
    fn local_needs_a_whole_last_label() {
        // A last label that merely ends in the bytes of "\x05local".
        let msg = parse(&query_for(b"\x01a\x07x\x05local\x00")).unwrap();
        assert!(!msg.questions[0].name.is_local());
    }
}
