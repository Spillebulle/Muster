//! Asking the network who hands out addresses, and noticing when two do.
//!
//! `CLAUDE.md` states the feature in one line: collect **all** offers, not the
//! first, because two offers is a rogue DHCP server and detecting that is a
//! feature rather than an error case. That is the whole reason this module
//! exists as something other than a lease reader. `survey` already reports the
//! server your current lease came from; that tells you who *won* a negotiation
//! that happened before Muster started. Only a fresh DISCOVER tells you who
//! else was willing to answer.
//!
//! A second DHCP server is one of the few things on a home or office network
//! that is nearly always a fault: a router plugged into the LAN by its WAN
//! port, a forgotten test server, a virtual machine bridging its own. It breaks
//! addressing intermittently and for some devices only, which makes it one of
//! the hardest faults to find by hand and one of the easiest to find by asking.
//!
//! ## Nothing here opens a socket
//!
//! The wire format is pure functions over bytes and the exchange goes through
//! [`Broadcaster`], for the same reason [`crate::discover`] and
//! [`crate::identify`] do: every test in this module runs against recorded
//! replies, and none of them needs a DHCP server or a network.
//!
//! ## The trap: this is a request nobody should answer twice
//!
//! A DISCOVER is a broadcast that asks every server on the link to reserve an
//! address. Muster **never sends a REQUEST**, so no lease is ever taken and
//! every offer is abandoned; a server holds the reservation for a few seconds
//! and gives it back. That is the difference between probing and consuming, and
//! it is why [`discover_message`] is the only message this module can build.

use crate::mac::MacAddr;
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

/// The four bytes that mark a BOOTP packet as carrying DHCP options.
const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

const OP_REQUEST: u8 = 1;
const OP_REPLY: u8 = 2;
/// Ethernet, and the only hardware type Muster speaks.
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;

/// The fixed part of a BOOTP message, before the options.
const HEADER: usize = 236;

// Option codes, by their numbers in RFC 2132.
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_DOMAIN: u8 = 15;
const OPT_LEASE: u8 = 51;
const OPT_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMS: u8 = 55;
const OPT_END: u8 = 255;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;

/// One server's answer to a DISCOVER.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// Who answered, from option 54. **Not** the source address of the packet:
    /// a relay rewrites the latter and the server identifier is what a client
    /// would address its REQUEST to, so it is the honest answer to "who is
    /// offering".
    pub server: Ipv4Addr,
    /// The address being offered.
    pub offered: Ipv4Addr,
    pub mask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub lease: Option<Duration>,
}

/// What a DISCOVER turned up.
#[derive(Clone, Debug, Default)]
pub struct Probe {
    /// Every offer that came back, in arrival order, one per server.
    pub offers: Vec<Offer>,
    /// Why the probe could not be made, where it could not.
    ///
    /// `CLAUDE.md`'s rule against silent degradation: a machine that cannot
    /// bind port 68 has learned nothing, and "no rogue server found" would be a
    /// lie about a question that was never asked.
    pub not_done: Option<String>,
}

impl Probe {
    /// Did more than one server offer?
    ///
    /// Counted by server identifier, so a server that answers twice — which is
    /// ordinary on a lossy link, because clients retransmit — is one server.
    pub fn servers(&self) -> Vec<Ipv4Addr> {
        let mut seen: Vec<Ipv4Addr> = Vec::new();
        for offer in &self.offers {
            if !seen.contains(&offer.server) {
                seen.push(offer.server);
            }
        }
        seen
    }

    /// True when more than one distinct server answered.
    pub fn is_contested(&self) -> bool {
        self.servers().len() > 1
    }

    /// The sentence the interface shows.
    pub fn verdict(&self) -> String {
        if let Some(why) = &self.not_done {
            return why.clone();
        }
        match self.servers().as_slice() {
            [] => "No DHCP server answered.".to_string(),
            [one] => format!("One DHCP server: {one}."),
            many => format!(
                "{} DHCP servers answered: {}. Only one should.",
                many.len(),
                many.iter()
                    .map(Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// Build a DISCOVER from `mac`, tagged with `xid`.
///
/// The broadcast flag is set, because Muster has no address on this network yet
/// as far as the server is concerned and a unicast reply to an unconfigured
/// address is dropped by most stacks.
pub fn discover_message(mac: MacAddr, xid: u32) -> Vec<u8> {
    let mut m = vec![0u8; HEADER];
    m[0] = OP_REQUEST;
    m[1] = HTYPE_ETHERNET;
    m[2] = HLEN_ETHERNET;
    m[3] = 0; // hops
    m[4..8].copy_from_slice(&xid.to_be_bytes());
    // secs stays zero; flags gets the broadcast bit.
    m[10] = 0x80;
    // ciaddr, yiaddr, siaddr, giaddr all stay zero: nothing is known yet.
    m[28..34].copy_from_slice(&mac.0);

    m.extend_from_slice(&MAGIC);
    m.extend_from_slice(&[OPT_TYPE, 1, DHCP_DISCOVER]);
    // What to send back. Asking for these is what makes an offer worth
    // comparing between servers: two servers handing out different gateways is
    // the shape the fault usually takes.
    m.extend_from_slice(&[
        OPT_PARAMS,
        4,
        OPT_SUBNET_MASK,
        OPT_ROUTER,
        OPT_DNS,
        OPT_DOMAIN,
    ]);
    m.push(OPT_END);
    m
}

/// Read an OFFER, or `None` for anything that is not one of ours.
///
/// Everything is checked rather than assumed: this reads packets from whatever
/// is on the network, including something broken or hostile. A short message, a
/// missing cookie, an option that runs off the end, a reply to somebody else's
/// transaction — all of them return `None` rather than panicking or inventing a
/// field.
pub fn parse_offer(bytes: &[u8], xid: u32) -> Option<Offer> {
    if bytes.len() < HEADER + MAGIC.len() {
        return None;
    }
    if bytes[0] != OP_REPLY || bytes[1] != HTYPE_ETHERNET {
        return None;
    }
    if u32::from_be_bytes(bytes[4..8].try_into().ok()?) != xid {
        return None;
    }
    if bytes[HEADER..HEADER + 4] != MAGIC {
        return None;
    }

    let offered = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let mut kind = None;
    let mut server = None;
    let mut mask = None;
    let mut router = None;
    let mut dns = Vec::new();
    let mut domain = None;
    let mut lease = None;

    for (code, value) in options(&bytes[HEADER + 4..]) {
        match code {
            OPT_TYPE => kind = value.first().copied(),
            OPT_SERVER_ID => server = ipv4(value),
            OPT_SUBNET_MASK => mask = ipv4(value),
            OPT_ROUTER => router = ipv4(value),
            OPT_DNS => dns = value.chunks_exact(4).filter_map(ipv4).collect(),
            OPT_DOMAIN => domain = String::from_utf8(value.to_vec()).ok(),
            OPT_LEASE => {
                lease = value
                    .try_into()
                    .ok()
                    .map(|b| Duration::from_secs(u32::from_be_bytes(b) as u64));
            }
            _ => {}
        }
    }

    if kind != Some(DHCP_OFFER) {
        return None;
    }
    // A server that offers without identifying itself cannot be told apart from
    // any other, which makes it useless for the one question this module asks.
    Some(Offer {
        server: server?,
        offered,
        mask,
        router,
        dns,
        domain,
        lease,
    })
}

fn ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let b: [u8; 4] = value.get(..4)?.try_into().ok()?;
    Some(Ipv4Addr::from(b))
}

/// Walk the option list, stopping at the end marker or at a length that runs
/// off the end of the buffer.
fn options(mut rest: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            OPT_END => break,
            // Padding, which carries no length byte.
            0 => rest = tail,
            _ => {
                let Some((&len, tail)) = tail.split_first() else {
                    break;
                };
                let len = len as usize;
                if tail.len() < len {
                    // A length longer than what is left is a malformed packet,
                    // and the bound is what stops it being read as one.
                    break;
                }
                out.push((code, &tail[..len]));
                rest = &tail[len..];
            }
        }
    }
    out
}

/// Sending a broadcast and collecting whatever answers.
///
/// The whole platform surface, one method, for the same reason the sweep's
/// transport is one trait: everything above it is testable without a network.
pub trait Broadcaster {
    /// Broadcast `payload` to the DHCP server port and gather replies for
    /// `window`. Returns every datagram received, in arrival order.
    fn broadcast(&self, payload: &[u8], window: Duration) -> io::Result<Vec<Vec<u8>>>;
}

/// Ask the link who offers addresses.
///
/// `xid` is the caller's, so a test can use a fixed one and the real caller can
/// use a random one. It is what tells our replies from another client's, and a
/// predictable value on a real network would collect somebody else's lease
/// negotiation.
pub fn probe<B: Broadcaster>(transport: &B, mac: MacAddr, xid: u32, window: Duration) -> Probe {
    let message = discover_message(mac, xid);
    match transport.broadcast(&message, window) {
        Ok(replies) => Probe {
            offers: replies
                .iter()
                .filter_map(|bytes| parse_offer(bytes, xid))
                .collect(),
            not_done: None,
        },
        Err(e) => Probe {
            offers: Vec::new(),
            not_done: Some(format!(
                "Could not ask for DHCP offers: {e}. On Linux this needs \
                 permission to use port 68; on Windows the DHCP Client service \
                 may already hold it."
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr::new([0x3c, 0x22, 0xfb, 0x1a, 0x0c, 0x4e]);
    const XID: u32 = 0x1234_5678;

    /// Build an OFFER the way a server would.
    fn offer_bytes(server: [u8; 4], offered: [u8; 4], xid: u32) -> Vec<u8> {
        let mut m = vec![0u8; HEADER];
        m[0] = OP_REPLY;
        m[1] = HTYPE_ETHERNET;
        m[2] = HLEN_ETHERNET;
        m[4..8].copy_from_slice(&xid.to_be_bytes());
        m[16..20].copy_from_slice(&offered);
        m[28..34].copy_from_slice(&MAC.0);
        m.extend_from_slice(&MAGIC);
        m.extend_from_slice(&[OPT_TYPE, 1, DHCP_OFFER]);
        m.extend_from_slice(&[OPT_SERVER_ID, 4]);
        m.extend_from_slice(&server);
        m.extend_from_slice(&[OPT_SUBNET_MASK, 4, 255, 255, 255, 0]);
        m.extend_from_slice(&[OPT_ROUTER, 4]);
        m.extend_from_slice(&server);
        m.extend_from_slice(&[OPT_LEASE, 4, 0, 0, 0x0e, 0x10]); // 3600 s
        m.push(OPT_END);
        m
    }

    struct Recorded(Vec<Vec<u8>>);

    impl Broadcaster for Recorded {
        fn broadcast(&self, _payload: &[u8], _window: Duration) -> io::Result<Vec<Vec<u8>>> {
            Ok(self.0.clone())
        }
    }

    struct Refused;

    impl Broadcaster for Refused {
        fn broadcast(&self, _payload: &[u8], _window: Duration) -> io::Result<Vec<Vec<u8>>> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    #[test]
    fn a_discover_is_shaped_the_way_a_server_expects() {
        let m = discover_message(MAC, XID);
        assert_eq!(m[0], OP_REQUEST);
        assert_eq!(m[1], HTYPE_ETHERNET);
        assert_eq!(m[2], HLEN_ETHERNET);
        assert_eq!(&m[4..8], &XID.to_be_bytes());
        assert_eq!(m[10] & 0x80, 0x80, "the broadcast flag must be set");
        assert_eq!(&m[28..34], &MAC.0, "our hardware address identifies us");
        assert_eq!(&m[HEADER..HEADER + 4], &MAGIC);
        assert!(
            m.windows(3).any(|w| w == [OPT_TYPE, 1, DHCP_DISCOVER]),
            "it must say it is a DISCOVER"
        );
        assert_eq!(*m.last().expect("a message"), OPT_END);
    }

    #[test]
    fn there_is_no_way_to_build_a_request() {
        // The safety property of this module, stated as a test because it is a
        // property of the *interface*: a DISCOVER reserves an address for a few
        // seconds, and only a REQUEST takes it. Muster probes; it never
        // consumes a lease. If a REQUEST builder is ever added, this test is
        // the place the decision has to be argued.
        let m = discover_message(MAC, XID);
        let kind = m
            .windows(3)
            .find(|w| w[0] == OPT_TYPE && w[1] == 1)
            .map(|w| w[2]);
        assert_eq!(kind, Some(DHCP_DISCOVER));
    }

    #[test]
    fn an_offer_is_read_field_by_field() {
        let bytes = offer_bytes([192, 0, 2, 1], [192, 0, 2, 50], XID);
        let offer = parse_offer(&bytes, XID).expect("an offer");
        assert_eq!(offer.server, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(offer.offered, Ipv4Addr::new(192, 0, 2, 50));
        assert_eq!(offer.mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(offer.router, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(offer.lease, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn two_servers_answering_is_the_fault_this_exists_to_find() {
        let probe = probe(
            &Recorded(vec![
                offer_bytes([192, 0, 2, 1], [192, 0, 2, 50], XID),
                offer_bytes([192, 0, 2, 77], [10, 0, 0, 5], XID),
            ]),
            MAC,
            XID,
            Duration::from_secs(1),
        );
        assert_eq!(probe.offers.len(), 2);
        assert!(probe.is_contested());
        assert!(
            probe.verdict().contains("Only one should"),
            "{}",
            probe.verdict()
        );
    }

    #[test]
    fn one_server_answering_twice_is_still_one_server() {
        // Ordinary on a lossy link. Counting datagrams instead of servers would
        // report a rogue server on every retransmit, which is the false alarm
        // that would make the feature worthless.
        let probe = probe(
            &Recorded(vec![
                offer_bytes([192, 0, 2, 1], [192, 0, 2, 50], XID),
                offer_bytes([192, 0, 2, 1], [192, 0, 2, 50], XID),
            ]),
            MAC,
            XID,
            Duration::from_secs(1),
        );
        assert_eq!(probe.offers.len(), 2);
        assert!(!probe.is_contested());
        assert_eq!(probe.servers().len(), 1);
    }

    #[test]
    fn somebody_elses_negotiation_is_not_ours() {
        let probe = probe(
            &Recorded(vec![offer_bytes([192, 0, 2, 1], [192, 0, 2, 50], 0xdead)]),
            MAC,
            XID,
            Duration::from_secs(1),
        );
        assert!(
            probe.offers.is_empty(),
            "a different xid is a different client"
        );
    }

    #[test]
    fn a_probe_that_could_not_run_says_so_rather_than_reporting_none() {
        // The rule against silent degradation: "no rogue server found" from a
        // probe that never went out is the worst answer this could give.
        let probe = probe(&Refused, MAC, XID, Duration::from_secs(1));
        assert!(probe.not_done.is_some());
        assert!(!probe.is_contested());
        assert!(probe.verdict().contains("port 68"), "{}", probe.verdict());
    }

    #[test]
    fn a_truncated_or_lying_packet_is_refused_rather_than_believed() {
        assert_eq!(parse_offer(&[], XID), None);
        assert_eq!(parse_offer(&[0u8; 10], XID), None);
        // Right length, no magic cookie.
        assert_eq!(parse_offer(&[0u8; HEADER + 8], XID), None);

        // An option whose length runs off the end of the buffer. The bound in
        // `options` is what stops this being read as a valid offer.
        let mut bytes = offer_bytes([192, 0, 2, 1], [192, 0, 2, 50], XID);
        bytes.pop(); // drop the end marker
        bytes.extend_from_slice(&[OPT_DNS, 40, 1, 2, 3]);
        let offer = parse_offer(&bytes, XID).expect("the good options still read");
        assert!(offer.dns.is_empty(), "a lying length yields no addresses");
    }

    #[test]
    fn an_offer_with_no_server_identifier_is_not_usable() {
        // Without option 54 there is no way to tell one offer's source from
        // another's, which is the only question being asked.
        let mut m = vec![0u8; HEADER];
        m[0] = OP_REPLY;
        m[1] = HTYPE_ETHERNET;
        m[4..8].copy_from_slice(&XID.to_be_bytes());
        m.extend_from_slice(&MAGIC);
        m.extend_from_slice(&[OPT_TYPE, 1, DHCP_OFFER]);
        m.push(OPT_END);
        assert_eq!(parse_offer(&m, XID), None);
    }

    #[test]
    fn nothing_answering_is_reported_as_nothing_answering() {
        let probe = probe(&Recorded(Vec::new()), MAC, XID, Duration::from_secs(1));
        assert!(!probe.is_contested());
        assert_eq!(probe.verdict(), "No DHCP server answered.");
    }
}
