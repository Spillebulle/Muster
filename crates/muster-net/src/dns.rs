//! The DNS wire format, as pure functions.
//!
//! One codec serves two questions Muster asks, because mDNS *is* DNS on the
//! wire — the differences are the address it is sent to (`224.0.0.251:5353`),
//! the absence of a meaningful transaction id, and one bit in the query class.
//! Writing a second parser for it would be two statements of the same byte
//! layout, which is the thing `CLAUDE.md` warns about for the setup payload and
//! applies just as well here.
//!
//! Nothing in this module opens a socket. Every function takes bytes and
//! returns values, so the tests drive it with captured replies and the whole of
//! the tricky part — name compression — is exercised without a network.
//!
//! ## The trap: compression pointers
//!
//! A name in a DNS message may end with a *pointer* to a name earlier in the
//! same message, so that `www.example.com` and `mail.example.com` share their
//! tail. A pointer that points forwards, or at itself, is a loop, and a decoder
//! that follows pointers without a budget hangs on a malformed packet. Since
//! the packets here come from whatever is on the network — including a device
//! that is broken or hostile — [`read_name`] counts its jumps and gives up.
//! That bound is the single most important line in this file.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const CLASS_IN: u16 = 1;

/// mDNS: ask the responder to answer to our own port rather than to the
/// multicast group. Set in the top bit of the question's class.
///
/// Without it the reply goes to `224.0.0.251:5353`, which means joining the
/// group and receiving every other machine's mDNS traffic to find our own
/// answer. With it, an ordinary unbound socket gets a direct reply.
pub const QU_BIT: u16 = 0x8000;

/// The most compression pointers one name may follow before the decoder
/// decides the message is malformed.
///
/// A legitimate name needs one, occasionally two. Anything beyond that is a
/// packet built to make a parser loop.
const MAX_JUMPS: usize = 8;

/// A resource record, decoded far enough to be useful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

/// The record payloads Muster reads. Everything else is kept as raw bytes
/// rather than dropped, because an unrecognised record is still evidence that
/// something answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    /// A `PTR` target, or the name from a `CNAME`. Already decompressed.
    Name(String),
    A(Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    /// `TXT` strings, each already split on its length byte.
    Txt(Vec<String>),
    /// `SRV`: priority, weight, port, target.
    Srv {
        port: u16,
        target: String,
    },
    Other(Vec<u8>),
}

/// A decoded message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<(String, u16)>,
    pub answers: Vec<Record>,
    /// Authority and additional sections, which is where mDNS puts most of what
    /// is worth having: a responder answering a PTR query commonly includes the
    /// SRV, TXT and A records for the same service without being asked.
    pub extra: Vec<Record>,
}

impl Message {
    /// Every record in the message, wherever it was filed. Callers looking for
    /// a fact rarely care which section carried it.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.answers.iter().chain(self.extra.iter())
    }

    /// The first `PTR` target, which is the answer to a reverse lookup.
    pub fn first_ptr(&self) -> Option<&str> {
        self.records().find_map(|r| match (&r.data, r.kind) {
            (RData::Name(n), TYPE_PTR) => Some(n.as_str()),
            _ => None,
        })
    }
}

/// Builds a query for one name and type.
///
/// `unicast` sets the mDNS QU bit; it must be false for ordinary DNS, where
/// that bit is part of the class and setting it asks for class 32769.
pub fn query(id: u16, name: &str, kind: u16, unicast: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 20);
    out.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired. Recursion is meaningless to an mDNS
    // responder and harmless: it ignores the bit.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // one question
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answers, authority, extra

    write_name(&mut out, name);
    out.extend_from_slice(&kind.to_be_bytes());
    let class = if unicast { CLASS_IN | QU_BIT } else { CLASS_IN };
    out.extend_from_slice(&class.to_be_bytes());
    out
}

/// The `in-addr.arpa` name for a reverse lookup: `192.168.0.1` becomes
/// `1.0.168.192.in-addr.arpa`.
pub fn reverse_name(addr: Ipv4Addr) -> String {
    let [a, b, c, d] = addr.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        // A label is length-prefixed with one byte, so 63 is the ceiling. A
        // longer one is truncated rather than refused: the caller is asking a
        // question, and a slightly wrong question gets no answer where a panic
        // would take the scan down.
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

/// Decodes a message. Returns [`None`] for anything malformed rather than
/// guessing, because the alternative is a device name invented out of a
/// truncated packet.
pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < 12 {
        return None;
    }
    let id = be16(buf, 0)?;
    let flags = be16(buf, 2)?;
    let counts = [be16(buf, 4)?, be16(buf, 6)?, be16(buf, 8)?, be16(buf, 10)?];

    let mut at = 12;
    let mut msg = Message {
        id,
        flags,
        ..Default::default()
    };

    for _ in 0..counts[0] {
        let (name, next) = read_name(buf, at)?;
        let kind = be16(buf, next)?;
        at = next + 4; // type and class
        msg.questions.push((name, kind));
    }

    // Answers, then authority, then additional. The first goes in `answers`
    // and the other two in `extra`, because mDNS files most of what is worth
    // having in the additional section and callers do not care which.
    for (section, count) in counts.iter().enumerate().skip(1) {
        for _ in 0..*count {
            let (record, next) = read_record(buf, at)?;
            at = next;
            if section == 1 {
                msg.answers.push(record);
            } else {
                msg.extra.push(record);
            }
        }
    }
    Some(msg)
}

fn read_record(buf: &[u8], at: usize) -> Option<(Record, usize)> {
    let (name, at) = read_name(buf, at)?;
    let kind = be16(buf, at)?;
    let class = be16(buf, at + 2)?;
    let ttl = be32(buf, at + 4)?;
    let len = be16(buf, at + 8)? as usize;
    let start = at + 10;
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let body = &buf[start..end];

    let data = match kind {
        // The target is read against the whole message, not against `body`: a
        // compression pointer in a PTR record points into the message, and
        // decoding it in isolation yields a truncated name or nothing.
        TYPE_PTR => RData::Name(read_name(buf, start)?.0),
        TYPE_A if len == 4 => RData::A(Ipv4Addr::new(body[0], body[1], body[2], body[3])),
        TYPE_AAAA if len == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(body);
            RData::Aaaa(o.into())
        }
        TYPE_SRV if len >= 7 => RData::Srv {
            port: be16(buf, start + 4)?,
            target: read_name(buf, start + 6)?.0,
        },
        TYPE_TXT => {
            let mut strings = Vec::new();
            let mut i = 0;
            while i < body.len() {
                let n = body[i] as usize;
                i += 1;
                if i + n > body.len() {
                    break;
                }
                strings.push(String::from_utf8_lossy(&body[i..i + n]).into_owned());
                i += n;
            }
            RData::Txt(strings)
        }
        _ => RData::Other(body.to_vec()),
    };

    Some((
        Record {
            name,
            kind,
            class,
            ttl,
            data,
        },
        end,
    ))
}

/// Reads a name, following compression pointers, and returns it with the offset
/// just past the name *in the record* — which is not where the pointer led.
fn read_name(buf: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut jumps = 0usize;
    // Where reading continues once a pointer has been taken. The first jump
    // fixes it; later jumps must not move it.
    let mut after: Option<usize> = None;

    loop {
        let len = *buf.get(at)?;
        match len & 0xc0 {
            0 => {
                if len == 0 {
                    at += 1;
                    break;
                }
                let start = at + 1;
                let end = start.checked_add(len as usize)?;
                if end > buf.len() {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                // Names are meant to be ASCII, and are not always. Lossy rather
                // than a refusal: a printer with a byte of Latin-1 in its name
                // is still a printer.
                out.push_str(&String::from_utf8_lossy(&buf[start..end]));
                at = end;
            }
            0xc0 => {
                // A pointer: fourteen bits of offset.
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                let target = (((len & 0x3f) as usize) << 8) | *buf.get(at + 1)? as usize;
                after.get_or_insert(at + 2);
                if target >= buf.len() {
                    return None;
                }
                at = target;
            }
            // 0x40 and 0x80 are reserved label types that nothing sends.
            _ => return None,
        }
        if out.len() > 255 {
            return None;
        }
    }
    Some((out, after.unwrap_or(at)))
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_reverse_name() {
        assert_eq!(
            reverse_name("192.168.0.1".parse().unwrap()),
            "1.0.168.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name(Ipv4Addr::new(10, 0, 0, 255)),
            "255.0.0.10.in-addr.arpa"
        );
    }

    #[test]
    fn a_query_round_trips_through_the_parser() {
        let q = query(0x1234, "1.0.168.192.in-addr.arpa", TYPE_PTR, false);
        let m = parse(&q).expect("our own query must parse");
        assert_eq!(m.id, 0x1234);
        assert_eq!(
            m.questions,
            vec![("1.0.168.192.in-addr.arpa".to_string(), TYPE_PTR)]
        );
    }

    /// The mDNS bit goes in the class, and must not be set for ordinary DNS —
    /// a resolver asked for class 32769 answers nothing.
    #[test]
    fn the_unicast_bit_is_only_set_when_asked_for() {
        let plain = query(1, "x.local", TYPE_PTR, false);
        let mdns = query(1, "x.local", TYPE_PTR, true);
        let class_at = plain.len() - 2;
        assert_eq!(be16(&plain, class_at), Some(CLASS_IN));
        assert_eq!(be16(&mdns, class_at), Some(CLASS_IN | QU_BIT));
    }

    /// A real reverse-lookup reply, built by hand: the answer's name is a
    /// pointer back to the question, which is what every resolver does and what
    /// a naive decoder gets wrong.
    #[test]
    fn decodes_a_ptr_answer_that_uses_compression() {
        let mut m = Vec::new();
        m.extend_from_slice(&0xbeefu16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // response, no error
        m.extend_from_slice(&1u16.to_be_bytes()); // questions
        m.extend_from_slice(&1u16.to_be_bytes()); // answers
        m.extend_from_slice(&[0, 0, 0, 0]);
        write_name(&mut m, "1.0.168.192.in-addr.arpa");
        m.extend_from_slice(&TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());

        // Answer: name is a pointer to offset 12, the question's name.
        m.extend_from_slice(&[0xc0, 12]);
        m.extend_from_slice(&TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes());
        let mut target = Vec::new();
        write_name(&mut target, "router.lan");
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        m.extend_from_slice(&target);

        let parsed = parse(&m).expect("should decode");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "1.0.168.192.in-addr.arpa");
        assert_eq!(parsed.first_ptr(), Some("router.lan"));
    }

    /// The bound that keeps a malformed packet from hanging the scan. A pointer
    /// to itself is the smallest version of the attack.
    #[test]
    fn a_pointer_loop_is_refused_rather_than_followed() {
        let mut m = vec![0u8; 12];
        m[4..6].copy_from_slice(&1u16.to_be_bytes()); // one question
        // At offset 12: a pointer to offset 12.
        m.extend_from_slice(&[0xc0, 12]);
        assert_eq!(parse(&m), None);

        // And a two-step loop, which a decoder guarding only self-reference
        // would still follow for ever.
        let mut m = vec![0u8; 12];
        m[4..6].copy_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0xc0, 14, 0xc0, 12]);
        assert_eq!(parse(&m), None);
    }

    #[test]
    fn truncated_messages_are_refused_rather_than_guessed() {
        let full = query(1, "host.local", TYPE_A, false);
        for cut in 0..full.len() {
            // Any prefix must either parse or be refused; never panic.
            let _ = parse(&full[..cut]);
        }
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0; 11]), None);
    }

    /// A record whose length field claims more than the packet holds.
    #[test]
    fn a_lying_length_field_is_refused() {
        let mut m = Vec::new();
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&[0, 0]); // no questions
        m.extend_from_slice(&1u16.to_be_bytes()); // one answer
        m.extend_from_slice(&[0, 0, 0, 0]);
        write_name(&mut m, "a.b");
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&9999u16.to_be_bytes()); // rdlength, a lie
        m.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(parse(&m), None);
    }

    #[test]
    fn reads_the_record_types_identification_needs() {
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8400u16.to_be_bytes());
        m.extend_from_slice(&[0, 0]);
        m.extend_from_slice(&3u16.to_be_bytes()); // three answers
        m.extend_from_slice(&[0, 0, 0, 0]);

        let push = |name: &str, kind: u16, body: &[u8], m: &mut Vec<u8>| {
            write_name(m, name);
            m.extend_from_slice(&kind.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&120u32.to_be_bytes());
            m.extend_from_slice(&(body.len() as u16).to_be_bytes());
            m.extend_from_slice(body);
        };

        push("box.local", TYPE_A, &[192, 168, 0, 9], &mut m);

        let mut txt = Vec::new();
        for s in ["model=J9V80B", "usb_MDL=OfficeJet"] {
            txt.push(s.len() as u8);
            txt.extend_from_slice(s.as_bytes());
        }
        push("box._ipp._tcp.local", TYPE_TXT, &txt, &mut m);

        let mut srv = Vec::new();
        srv.extend_from_slice(&0u16.to_be_bytes()); // priority
        srv.extend_from_slice(&0u16.to_be_bytes()); // weight
        srv.extend_from_slice(&631u16.to_be_bytes());
        write_name(&mut srv, "box.local");
        push("box._ipp._tcp.local", TYPE_SRV, &srv, &mut m);

        let parsed = parse(&m).expect("should decode");
        assert_eq!(parsed.answers.len(), 3);
        assert_eq!(
            parsed.answers[0].data,
            RData::A("192.168.0.9".parse().unwrap())
        );
        assert_eq!(
            parsed.answers[1].data,
            RData::Txt(vec!["model=J9V80B".into(), "usb_MDL=OfficeJet".into()])
        );
        assert_eq!(
            parsed.answers[2].data,
            RData::Srv {
                port: 631,
                target: "box.local".into()
            }
        );
    }

    /// Fuzzing in the small: no input may panic. The parser is fed bytes from
    /// whatever is on the network, so this is the property that matters most.
    #[test]
    fn no_input_panics() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..4000 {
            let len = (next() % 300) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = parse(&buf);
        }
    }
}
