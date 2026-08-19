//! NetBIOS node status, which is how a Windows machine says its own name.
//!
//! One UDP datagram to port 137 and the machine answers with its name, its
//! workgroup and its hardware address. It needs no privileges, no
//! authentication and no session, and it is answered by Windows machines that
//! ignore ping — which on a home network is most of them, because the public
//! network profile blocks ICMP by default and does not block this.
//!
//! It is old and it is odd. The wire format is DNS-shaped but not DNS: the
//! header is the same twelve bytes, and then the question name is a NetBIOS
//! name in *first-level encoding*, which spreads each byte across two
//! characters in the range `A`–`P`. A sixteen-byte name therefore occupies
//! thirty-two bytes, and the wildcard query Muster sends — `*` followed by
//! fifteen NULs — encodes to `CKAAAA...`. Getting that encoding wrong produces
//! a datagram that is silently ignored rather than refused, which is why
//! [`node_status_query`] is checked against its exact bytes in a test.
//!
//! As everywhere else in this crate, nothing here opens a socket.

use crate::mac::MacAddr;

/// `NBSTAT`, the node status query type.
const TYPE_NBSTAT: u16 = 0x0021;
const CLASS_IN: u16 = 0x0001;

/// One name a node claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbName {
    pub name: String,
    /// The suffix byte, which says what the name is *for*. `0x00` is the
    /// workstation, `0x20` the file server, `0x1c` a domain controller.
    pub suffix: u8,
    /// A group name is a workgroup or domain rather than this machine.
    pub group: bool,
}

/// What a node answered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeStatus {
    pub names: Vec<NbName>,
    /// The adapter address from the statistics block. Worth having even when
    /// ARP already found one: they disagree on a machine answering for another.
    pub mac: Option<MacAddr>,
}

impl NodeStatus {
    /// The machine's own name.
    ///
    /// The unique workstation name — suffix `0x00`, not a group — is the one
    /// that means "this computer". Taking the first name in the list instead
    /// yields the workgroup about as often as the hostname.
    pub fn hostname(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|n| n.suffix == 0x00 && !n.group)
            .map(|n| n.name.as_str())
    }

    /// The workgroup or domain, which is the group name with suffix `0x00`.
    pub fn workgroup(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|n| n.suffix == 0x00 && n.group)
            .map(|n| n.name.as_str())
    }
}

/// Builds the wildcard node status query.
pub fn node_status_query(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0000u16.to_be_bytes()); // a query, no flags
    out.extend_from_slice(&1u16.to_be_bytes()); // one question
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    // The wildcard name: '*' then fifteen NULs, first-level encoded.
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    let encoded = encode_name(&raw);
    out.push(encoded.len() as u8);
    out.extend_from_slice(&encoded);
    out.push(0); // end of name

    out.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// First-level encoding: each byte becomes two characters, the high and low
/// nibbles offset from `A`.
fn encode_name(raw: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for &b in raw {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0f));
    }
    out
}

/// Decodes a node status reply. [`None`] for anything malformed.
pub fn parse_node_status(buf: &[u8]) -> Option<NodeStatus> {
    if buf.len() < 12 {
        return None;
    }
    let answers = u16::from_be_bytes([buf[6], buf[7]]);
    if answers == 0 {
        return None;
    }

    // Skip the question-shaped name at the start of the answer. It is a
    // length-prefixed label sequence, same as DNS, and a node status reply does
    // not compress it.
    let mut at = 12;
    loop {
        let len = *buf.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        // A compression pointer here would be unusual; refusing is safer than
        // following one into a loop, and nothing sends it.
        if len & 0xc0 != 0 {
            return None;
        }
        at = at.checked_add(len)?;
        if at > buf.len() {
            return None;
        }
    }

    // type, class, ttl, rdlength
    at = at.checked_add(8)?;
    let rdlength = u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]) as usize;
    at += 2;
    let end = at.checked_add(rdlength)?;
    if end > buf.len() {
        return None;
    }

    let count = *buf.get(at)? as usize;
    at += 1;

    let mut status = NodeStatus::default();
    for _ in 0..count {
        // Fifteen bytes of name, one suffix byte, two of flags.
        let name_end = at.checked_add(15)?;
        let raw = buf.get(at..name_end)?;
        let suffix = *buf.get(name_end)?;
        let flags = u16::from_be_bytes([*buf.get(name_end + 1)?, *buf.get(name_end + 2)?]);
        at = name_end + 3;

        // Names are space-padded to fifteen bytes and are not always valid
        // UTF-8 on a machine with a non-Latin locale.
        let name = String::from_utf8_lossy(raw).trim_end().to_string();
        if !name.is_empty() {
            status.names.push(NbName {
                name,
                suffix,
                group: flags & 0x8000 != 0,
            });
        }
    }

    // The statistics block follows, and opens with the six-byte adapter
    // address. A reply that was truncated before it simply has no MAC, which is
    // different from having a zero one.
    if let Some(mac) = buf.get(at..at + 6) {
        let found = MacAddr::new(mac.try_into().ok()?);
        if !found.is_zero() {
            status.mac = Some(found);
        }
    }

    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoding is the part that fails silently when it is wrong: a
    /// malformed query is ignored rather than refused, so there is nothing to
    /// notice at run time. These are the exact bytes every implementation
    /// sends.
    #[test]
    fn the_wildcard_query_is_encoded_exactly() {
        let q = node_status_query(0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34], "transaction id");
        assert_eq!(&q[2..4], &[0x00, 0x00], "a query, no flags set");
        assert_eq!(&q[4..6], &[0x00, 0x01], "one question");

        assert_eq!(q[12], 32, "the encoded name is thirty-two bytes");
        let name = std::str::from_utf8(&q[13..45]).unwrap();
        // '*' is 0x2A, so 'C' then 'K'; fifteen NULs are thirty 'A's.
        assert_eq!(name, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(q[45], 0, "name terminator");
        assert_eq!(&q[46..48], &[0x00, 0x21], "NBSTAT");
        assert_eq!(&q[48..50], &[0x00, 0x01], "class IN");
        assert_eq!(q.len(), 50);
    }

    /// A reply from a Windows machine, built to the shape one really has.
    fn reply(names: &[(&str, u8, bool)], mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        m.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
        m.extend_from_slice(&0u16.to_be_bytes()); // questions
        m.extend_from_slice(&1u16.to_be_bytes()); // one answer
        m.extend_from_slice(&[0, 0, 0, 0]);

        let mut raw = [0u8; 16];
        raw[0] = b'*';
        let encoded = encode_name(&raw);
        m.push(encoded.len() as u8);
        m.extend_from_slice(&encoded);
        m.push(0);
        m.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes()); // ttl

        let mut body = Vec::new();
        body.push(names.len() as u8);
        for (name, suffix, group) in names {
            let mut padded = format!("{name:<15}").into_bytes();
            padded.truncate(15);
            body.extend_from_slice(&padded);
            body.push(*suffix);
            body.extend_from_slice(&(if *group { 0x8000u16 } else { 0x0400 }).to_be_bytes());
        }
        if let Some(mac) = mac {
            body.extend_from_slice(&mac);
            body.extend_from_slice(&[0u8; 40]); // the rest of the statistics
        }

        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn reads_the_hostname_workgroup_and_hardware_address() {
        let buf = reply(
            &[
                ("DESKTOP-7F3A", 0x00, false),
                ("DESKTOP-7F3A", 0x20, false),
                ("WORKGROUP", 0x00, true),
            ],
            Some([0x4c, 0xed, 0xfb, 0xb8, 0x1f, 0x75]),
        );
        let s = parse_node_status(&buf).expect("should decode");
        assert_eq!(s.hostname(), Some("DESKTOP-7F3A"));
        assert_eq!(s.workgroup(), Some("WORKGROUP"));
        assert_eq!(s.mac, Some("4c:ed:fb:b8:1f:75".parse().unwrap()));
        assert_eq!(s.names.len(), 3);
    }

    /// The workgroup is a *group* name with the same suffix as the hostname, so
    /// taking the first entry gets it wrong about half the time. This orders
    /// them the awkward way round to prove the flag is what decides.
    #[test]
    fn the_workgroup_is_not_mistaken_for_the_hostname() {
        let buf = reply(&[("WORKGROUP", 0x00, true), ("LAPTOP", 0x00, false)], None);
        let s = parse_node_status(&buf).unwrap();
        assert_eq!(s.hostname(), Some("LAPTOP"));
        assert_eq!(s.workgroup(), Some("WORKGROUP"));
        assert_eq!(s.mac, None, "a reply with no statistics block has no MAC");
    }

    #[test]
    fn a_reply_with_no_answers_is_not_a_node() {
        let mut m = vec![0u8; 12];
        m[2..4].copy_from_slice(&0x8400u16.to_be_bytes());
        assert_eq!(parse_node_status(&m), None);
    }

    #[test]
    fn truncated_and_random_input_is_refused_rather_than_panicking() {
        let full = reply(&[("BOX", 0x00, false)], Some([1, 2, 3, 4, 5, 6]));
        for cut in 0..full.len() {
            let _ = parse_node_status(&full[..cut]);
        }

        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..3000 {
            let len = (next() % 200) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = parse_node_status(&buf);
        }
    }
}
