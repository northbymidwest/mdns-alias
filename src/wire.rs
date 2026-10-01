//! DNS wire format, as far as mDNS needs it here: parse any message, and
//! encode messages holding questions and records (RFC 1035 section 4, RFC
//! 6762 section 18). Pure: no I/O.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;

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

/// A domain name. Labels keep the case they came with, for display and for
/// record comparison; equality ignores ASCII case, as DNS does.
#[derive(Clone, Debug)]
pub struct Name(Vec<Vec<u8>>);

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
    pub fn parse(text: &str) -> Result<Name, NameError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        Name::from_labels(text.split('.').map(|l| l.as_bytes().to_vec()).collect())
    }

    fn from_labels(labels: Vec<Vec<u8>>) -> Result<Name, NameError> {
        let mut len = 1;
        for label in &labels {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL {
                return Err(NameError::LabelTooLong);
            }
            len += 1 + label.len();
        }
        if len > MAX_NAME {
            return Err(NameError::TooLong);
        }
        Ok(Name(labels))
    }

    /// Whether this is a name under `.local`: at least one label, then
    /// `local` in any case.
    pub fn is_local(&self) -> bool {
        self.0.len() >= 2
            && self
                .0
                .last()
                .is_some_and(|l| l.eq_ignore_ascii_case(b"local"))
    }

    /// This name with `base` appended: `seerr` under `myhost.local` is
    /// `seerr.myhost.local`. Fails if the result is too long.
    pub fn under(&self, base: &Name) -> Result<Name, NameError> {
        Name::from_labels(self.0.iter().chain(&base.0).cloned().collect())
    }

    /// Uncompressed wire form, which record comparison (RFC 6762 section
    /// 8.2) is defined on.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for label in &self.0 {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl Eq for Name {}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str(".");
        }
        for (i, label) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            f.write_str(&String::from_utf8_lossy(label))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    /// Class without the unicast-response bit.
    pub qclass: u16,
    pub unicast_response: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    /// NSEC (RFC 4034 section 4): in mDNS the next name is the owner itself,
    /// and the types are those the owner has. Sorted, without duplicates.
    Nsec {
        next: Name,
        types: Vec<u16>,
    },
    /// Any other type, or an address record of the wrong length, as raw
    /// bytes.
    Other(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    /// Class without the cache-flush bit.
    pub class: u16,
    pub cache_flush: bool,
    pub ttl: u32,
    pub rdata: RData,
}

impl Record {
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
            RData::Other(bytes) => bytes.clone(),
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
        let qtype = r.u16()?;
        let class = r.u16()?;
        msg.questions.push(Question {
            name,
            qtype,
            qclass: class & !QU_BIT,
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
        let rtype = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let len = usize::from(self.u16()?);
        let start = self.pos;
        let raw = self.bytes(len)?.to_vec();
        let rdata = match rtype {
            TYPE_CNAME => {
                // The target may use compression, so it is read from the
                // whole packet, and must fill the rdata exactly.
                let (target, end) = read_name(self.packet, start)?;
                if end != start + len {
                    return None;
                }
                RData::Cname(target)
            }
            TYPE_A if len == 4 => RData::A(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
            TYPE_AAAA if len == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            TYPE_NSEC => {
                // The next name may be compressed (RFC 6762 section 18.14);
                // the type bitmap fills the rest of the rdata.
                let (next, end) = read_name(self.packet, start)?;
                let types = bitmap_types(self.packet.get(end..start + len)?)?;
                RData::Nsec { next, types }
            }
            _ => RData::Other(raw),
        };
        Some(Record {
            name,
            rtype,
            class: class & !CACHE_FLUSH_BIT,
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
    let mut labels = Vec::new();
    let mut len = 1;
    let mut end = None;
    loop {
        let byte = usize::from(*packet.get(pos)?);
        match byte & 0xC0 {
            0x00 if byte == 0 => break,
            0x00 => {
                let label = packet.get(pos + 1..pos + 1 + byte)?;
                len += 1 + byte;
                if len > MAX_NAME {
                    return None;
                }
                labels.push(label.to_vec());
                pos += 1 + byte;
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
    Some((Name(labels), end.unwrap_or(pos + 1)))
}

/// The types in an NSEC type bitmap (RFC 4034 section 4.1.2): windows of a
/// block number, a length of 1-32 and that many bitmap octets. The windows
/// must be in strictly increasing order, so the types come out sorted and
/// unique without a sort. `None` if malformed.
fn bitmap_types(mut b: &[u8]) -> Option<Vec<u16>> {
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
                    types.push(window * 256 + (octet * 8 + bit) as u16);
                }
            }
        }
        b = &b[2 + len..];
    }
    Some(types)
}

/// The NSEC type bitmap for `types`. The sort is linear for parsed records
/// only because `bitmap_types` guarantees they are already sorted.
fn type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut sorted = types.to_vec();
    crate::order::sort(&mut sorted);
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let window = sorted[i] >> 8;
        let mut octets = [0u8; 32];
        let mut len = 0;
        while i < sorted.len() && sorted[i] >> 8 == window {
            let low = usize::from(sorted[i] & 0xff);
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
        w.u16(q.qtype);
        w.u16(q.qclass | if q.unicast_response { QU_BIT } else { 0 });
    }
    for rec in msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
    {
        w.name(&rec.name);
        w.u16(rec.rtype);
        w.u16(rec.class | if rec.cache_flush { CACHE_FLUSH_BIT } else { 0 });
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
            RData::Other(bytes) => w.out.extend_from_slice(bytes),
        }
        let len = (w.out.len() - len_at - 2) as u16;
        w.out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
    }
    w.out
}

struct Writer {
    out: Vec<u8>,
    /// Name suffixes written so far, lowercased, with their offsets.
    suffixes: Vec<(Vec<Vec<u8>>, u16)>,
}

impl Writer {
    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn name(&mut self, name: &Name) {
        for i in 0..name.0.len() {
            let key: Vec<Vec<u8>> = name.0[i..].iter().map(|l| l.to_ascii_lowercase()).collect();
            if let Some((_, offset)) = self.suffixes.iter().find(|(s, _)| *s == key) {
                self.u16(0xC000 | *offset);
                return;
            }
            // Pointers hold 14 bits, so later offsets cannot be targets.
            if let Ok(offset) = u16::try_from(self.out.len())
                && offset <= 0x3FFF
            {
                self.suffixes.push((key, offset));
            }
            let label = &name.0[i];
            self.out.push(label.len() as u8);
            self.out.extend_from_slice(label);
        }
        self.out.push(0);
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
                qtype: TYPE_A,
                qclass: CLASS_IN,
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
                    rtype: TYPE_CNAME,
                    class: CLASS_IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::Cname(name("local")),
                },
                Record {
                    name: name("app.local"),
                    rtype: TYPE_A,
                    class: CLASS_IN,
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
            rtype: TYPE_CNAME,
            class: CLASS_IN,
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
                qtype: TYPE_ANY,
                qclass: CLASS_IN,
                unicast_response: true,
            }],
            answers: vec![cname("app.myhost.local", "myhost.local")],
            authorities: vec![Record {
                name: name("App.MYhost.local"),
                rtype: TYPE_A,
                class: CLASS_IN,
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
                    rtype: TYPE_A,
                    class: CLASS_IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::A("192.0.2.10".parse().unwrap()),
                },
                Record {
                    name: name("app.myhost.local"),
                    rtype: TYPE_AAAA,
                    class: CLASS_IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::Aaaa("fe80::1".parse().unwrap()),
                },
                Record {
                    name: name("app.myhost.local"),
                    rtype: TYPE_NSEC,
                    class: CLASS_IN,
                    cache_flush: true,
                    ttl: 120,
                    rdata: RData::Nsec {
                        next: name("app.myhost.local"),
                        types: vec![TYPE_A, TYPE_AAAA],
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
            rtype: TYPE_NSEC,
            class: CLASS_IN,
            cache_flush: false,
            ttl: 120,
            rdata: RData::Nsec {
                next: name("app.local"),
                types: vec![TYPE_AAAA, TYPE_A],
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
        let types = vec![1, 28, 256 + 1];
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
        assert_eq!(msg.answers[0].rdata, RData::Other(vec![192, 0, 2]));
    }
}
