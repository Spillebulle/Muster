//! Asking the devices that answer nothing else.
//!
//! Switches, access points, printers and uninterruptible power supplies
//! advertise no mDNS, usually no UPnP and nothing over NetBIOS, so they are the
//! blank rows in the device table: an address, a hardware address, a vendor,
//! and nothing about what the thing actually is. Every one of them ships an
//! SNMP agent, and the three objects at the top of the standard system group
//! are the answer to exactly the question the row is missing.
//!
//! * **`sysDescr.0`** is the device's own full product string, and on most
//!   network gear it carries the firmware version as well. `RouterOS
//!   RB750Gr3`. It is the single most informative thing a switch will ever say
//!   about itself.
//! * **`sysName.0`** is the name somebody configured, which on managed
//!   equipment is the name it is known by in the rack.
//! * **`sysObjectID.0`** is an OID under `1.3.6.1.4.1.<n>`, and `<n>` is the
//!   Private Enterprise Number IANA gave the organisation that registered it.
//!   [`enterprise`] turns it into a name out of a table compiled into this
//!   binary, so the vendor is read with no lookup leaving the machine.
//!
//! ## The community string, which is the whole conduct question
//!
//! **`public` is sent exactly once and no second string is ever tried.** That
//! is the line, and it is worth stating why it falls where it does. Sending a
//! *list* of communities until one answers is credential guessing, which
//! `CLAUDE.md` forbids outright and which no amount of "but they are the
//! defaults" makes into something else. Sending `public` once is not the same
//! act: it is the community the standard names as the default, it is what every
//! agent that has not been configured otherwise publishes to the whole network,
//! and a device that answers it has been set up to answer anybody who asks.
//! Nothing is written, nothing is authenticated and nothing is retried with a
//! different string.
//!
//! Only the three objects above are read. There is no walk: a walk is how a
//! scanner ends up holding a device's interface table, its ARP cache and its
//! routing table, none of which Muster asked a question about.
//!
//! **It is off until somebody turns it on**, behind the same switch as the
//! connected questions in [`crate::service`]. The reasoning there was that a
//! connection is a thing the far end writes down; this is a datagram, but a
//! great many agents log a community mismatch and some raise a trap on one, so
//! it is treated as the deliberate act it is.
//!
//! ## SNMPv2c, and a hand-written BER
//!
//! Three objects in one `GetRequest`, which is one datagram out and one back,
//! and the reply carries a variable binding per object so a device that has
//! nothing for one of them still answers about the other two. Version 2c is
//! what makes that true: v1 fails a whole PDU when one name is missing, and v2c
//! marks the missing binding `noSuchObject` and answers the rest.
//!
//! **No dependency was added for the encoding.** What is needed here is four
//! ASN.1 types — an integer, an octet string, an object identifier and a
//! sequence — in the definite-length form, which is the two hundred lines
//! below. Every general-purpose ASN.1 crate brings a DER validator, a schema
//! derive and a parser for types this module will never see, and `CLAUDE.md`'s
//! standard for a dependency is `socket2`'s: the one thing `std` cannot do.
//! This is not that.
//!
//! Nothing here opens a socket. The transport is [`Ask`], the same trait the
//! rest of phase four is written against, and the tests drive it with recorded
//! replies.

use crate::identify::Ask;
use crate::rate::Bucket;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Where an agent listens. Fixed by the standard.
pub const PORT: u16 = 161;

/// The only community string Muster ever sends, and it is sent once.
///
/// See the module note. This is a constant rather than a field on [`Options`]
/// on purpose: a caller that could supply one could supply a list of them, and
/// there is no shape of this code in which that is allowed.
pub const COMMUNITY: &str = "public";

/// `sysDescr.0`, the device's own description of itself.
pub const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
/// `sysObjectID.0`, whose value names the organisation that registered it.
pub const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
/// `sysName.0`, the name somebody configured.
pub const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];

/// `iso.org.dod.internet.private.enterprise`, the arc every vendor's own OIDs
/// hang under. The arc after it is the Private Enterprise Number.
const ENTERPRISES: [u32; 6] = [1, 3, 6, 1, 4, 1];

/// The longest reply worth reading.
///
/// A system group response is a few hundred bytes. The cap is what keeps a
/// device that answers with a megabyte from being able to spend this machine's
/// memory, and it is the same reasoning [`crate::service`]'s cap follows.
const MOST: usize = 4096;

/// The longest description worth keeping, in characters.
///
/// Cisco's runs to about two hundred and the standard allows two hundred and
/// fifty-five, so this is well clear of anything honest. What is longer than
/// this is truncated **visibly**, with an ellipsis, because a string that
/// quietly stops short shows a device saying less than it did.
const MOST_TEXT: usize = 512;

/// What an SNMP agent said about itself.
///
/// Its existence is itself a fact: this is [`Some`] only when a device answered
/// a `GetResponse` carrying the request's own id, so an [`Agent`] with three
/// empty fields still means "there is an agent here that answers `public`".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Agent {
    /// `sysDescr.0`, whitespace collapsed.
    ///
    /// **Free text, and ranked as free text.** It is the device writing about
    /// itself with nothing checking it, which is the same class of evidence as
    /// an SSDP `SERVER` header or an mDNS `model=`, so [`crate::kind`] reads it
    /// at `Clue::Product` and never above a service.
    pub description: Option<String>,
    /// `sysName.0`, the configured name.
    ///
    /// Kept here rather than added to [`crate::identify::Identity::names`], for
    /// the reason `CLAUDE.md` gives for keeping hostnames out of [`crate::kind`]
    /// altogether: this is a string a person typed, so it is evidence about
    /// whoever set the device up.
    pub name: Option<String>,
    /// `sysObjectID.0` in dotted form, `1.3.6.1.4.1.14988.1`.
    pub object_id: Option<String>,
    /// The Private Enterprise Number out of [`Self::object_id`].
    pub enterprise: Option<u32>,
}

impl Agent {
    /// Did it say anything beyond being there?
    pub fn is_empty(&self) -> bool {
        self.description.is_none() && self.name.is_none() && self.object_id.is_none()
    }

    /// The organisation IANA gave [`Self::enterprise`] to.
    ///
    /// **This is a weaker claim than it looks, and the wording around it has to
    /// say so.** A Private Enterprise Number belongs to whoever registered the
    /// OID branch, which is not always whoever made the box: an OEM ships its
    /// customers' hardware under its own arc, an acquired company's number
    /// outlives it by years, and a white-label switch answers with the number
    /// of the firmware's author. It is a structured fact where [`Self::description`]
    /// is free text, which makes it the better *identifier*; it is not a claim
    /// about a manufacturer, and nothing here infers a [`crate::Kind`] from it.
    pub fn registrant(&self) -> Option<&'static str> {
        self.enterprise.and_then(enterprise)
    }

    /// One line for the interface, in every case.
    ///
    /// A device that answered and named nothing gets a sentence rather than a
    /// blank, because the fact that it answered at all is the fact.
    pub fn summary(&self) -> String {
        match &self.description {
            Some(description) => description.clone(),
            None => "it answered on port 161 and named nothing".to_string(),
        }
    }

    /// Who the OID is registered to, worded for what is actually known.
    pub fn registered_to(&self) -> Option<String> {
        let (name, number) = (self.registrant()?, self.enterprise?);
        Some(format!("{name}, enterprise {number}"))
    }
}

/// What to ask, and how long to wait for it.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// How long one exchange may take.
    ///
    /// Longer than [`crate::identify::Options::timeout`]: the devices this
    /// phase exists for are embedded, an agent on a busy switch answers out of
    /// a low-priority task, and the whole phase is one datagram per device.
    pub timeout: Duration,
    pub workers: usize,
    /// Ask at all.
    ///
    /// Off, and the same decision [`crate::service::Options`] records. See the
    /// module note on the community string.
    pub ask: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(900),
            workers: 32,
            ask: false,
        }
    }
}

impl Options {
    /// Is there anything to ask at all?
    pub fn any(&self) -> bool {
        self.ask
    }
}

/// Asks one device for the three system objects.
///
/// [`None`] is "it did not answer", which is never "there is no agent there":
/// a filtered port, a community that is not `public` and a device that is
/// simply slow all arrive here the same way, and none of them is evidence.
pub fn one<A: Ask + ?Sized>(
    address: IpAddr,
    ask: &A,
    rate: &Bucket,
    opts: Options,
    id: u32,
) -> Option<Agent> {
    if !opts.ask {
        return None;
    }
    rate.wait();
    let id = i64::from(id);
    let question = get_request(id, &[SYS_DESCR, SYS_OBJECT_ID, SYS_NAME]);
    let reply = ask
        .ask(SocketAddr::new(address, PORT), &question, opts.timeout)
        .ok()?;
    read(&reply, id)
}

/// Asks many devices, in parallel, cancellably.
///
/// Returns one answer per input address, in the same order, so the caller can
/// zip it against the sweep the way it does with [`crate::identify::many`].
pub fn many<A: Ask + ?Sized>(
    addresses: &[IpAddr],
    ask: &A,
    rate: &Bucket,
    opts: Options,
    cancel: &AtomicBool,
    progress: &(dyn Fn(usize, usize) + Sync),
) -> Vec<Option<Agent>> {
    let next = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let mut out: Vec<Option<Agent>> = vec![None; addresses.len()];
    if !opts.any() {
        return out;
    }
    let workers = opts.workers.clamp(1, 256).min(addresses.len().max(1));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (next, done) = (&next, &done);
            handles.push(scope.spawn(move || {
                let mut mine: Vec<(usize, Option<Agent>)> = Vec::new();
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                    let Some(&address) = addresses.get(i) else {
                        break;
                    };
                    // The request id is the index, which makes a reply meant
                    // for another device recognisable rather than merely
                    // unlikely. Same reasoning as `identify::many`'s.
                    mine.push((i, one(address, ask, rate, opts, i as u32)));
                    progress(
                        done.fetch_add(1, Ordering::Relaxed) as usize + 1,
                        addresses.len(),
                    );
                }
                mine
            }));
        }
        for handle in handles {
            for (i, agent) in handle.join().unwrap_or_default() {
                out[i] = agent;
            }
        }
    });

    out
}

// ---------------------------------------------------------------------------
// The message
// ---------------------------------------------------------------------------

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTETS: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
/// `GetRequest-PDU`, context-specific and constructed.
const TAG_GET: u8 = 0xa0;
/// `Response-PDU`.
const TAG_RESPONSE: u8 = 0xa2;
/// The three exception values v2c puts in a binding it cannot fill:
/// `noSuchObject`, `noSuchInstance`, `endOfMibView`.
const TAG_ABSENT: [u8; 3] = [0x80, 0x81, 0x82];

/// SNMPv2c, which the message encodes as version 1. Version 1 of the protocol
/// is 0, and the off-by-one is the standard's rather than anybody's mistake.
const VERSION_2C: i64 = 1;

/// Builds a `GetRequest` for the given object identifiers.
///
/// One PDU for all of them: a `GetRequest` carries a list of bindings, and a
/// v2c agent that has nothing for one name fills that binding with an exception
/// and answers about the others. Three separate datagrams would buy nothing and
/// cost a device three wakeups.
pub fn get_request(id: i64, objects: &[&[u32]]) -> Vec<u8> {
    let mut bindings = Vec::new();
    for object in objects {
        let mut binding = encode_oid(object);
        // The value of a request's binding is unused and must be present.
        binding.extend_from_slice(&[TAG_NULL, 0]);
        tlv(TAG_SEQUENCE, &binding, &mut bindings);
    }

    let mut list = Vec::new();
    tlv(TAG_SEQUENCE, &bindings, &mut list);

    let mut pdu = encode_integer(id);
    pdu.extend_from_slice(&encode_integer(0)); // error-status
    pdu.extend_from_slice(&encode_integer(0)); // error-index
    pdu.extend_from_slice(&list);

    let mut body = encode_integer(VERSION_2C);
    tlv(TAG_OCTETS, COMMUNITY.as_bytes(), &mut body);
    tlv(TAG_GET, &pdu, &mut body);

    let mut out = Vec::new();
    tlv(TAG_SEQUENCE, &body, &mut out);
    out
}

/// What one variable binding held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bytes(Vec<u8>),
    Oid(Vec<u32>),
    Int(i64),
    /// The agent said it has nothing under that name.
    ///
    /// **An answer, not a failure**, and the reason v2c is worth the extra
    /// code: a printer that publishes `sysDescr` and no `sysName` is describing
    /// itself accurately, and a reader that treated this as an error would
    /// throw the rest of the reply away.
    Absent,
    /// A type in the protocol this reader does not decode: a counter, a gauge,
    /// an address. None of the three objects asked for is one.
    Other,
}

/// A parsed `Response-PDU`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub id: i64,
    /// Non-zero where the agent refused the whole PDU. Read rather than
    /// assumed: a reply in the protocol is the test, so a refusal still proves
    /// an agent is there, and the bindings are still worth walking.
    pub error: i64,
    pub bindings: Vec<(Vec<u32>, Value)>,
}

/// Reads a datagram as a `Response-PDU`.
///
/// [`None`] means it was not one: not SNMP, not a response, truncated, or
/// encoded in a way this reader does not accept. Nothing here trusts a length
/// it has not checked against what is left of the buffer.
pub fn parse_response(datagram: &[u8]) -> Option<Response> {
    let (tag, body) = one_tlv(datagram)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let mut message = Reader::new(body);
    let (version_tag, version) = message.next()?;
    if version_tag != TAG_INTEGER || decode_integer(version)? != VERSION_2C {
        return None;
    }
    // The community is echoed and deliberately not checked. Nothing depends on
    // it: the request id is what says a reply belongs to this question, and an
    // agent that echoed something else has still answered in the protocol.
    let (community_tag, _) = message.next()?;
    if community_tag != TAG_OCTETS {
        return None;
    }
    let (pdu_tag, pdu) = message.next()?;
    if pdu_tag != TAG_RESPONSE {
        return None;
    }

    let mut fields = Reader::new(pdu);
    let (id_tag, id) = fields.next()?;
    if id_tag != TAG_INTEGER {
        return None;
    }
    let id = decode_integer(id)?;
    let (error_tag, error) = fields.next()?;
    if error_tag != TAG_INTEGER {
        return None;
    }
    let error = decode_integer(error)?;
    let (index_tag, _) = fields.next()?;
    if index_tag != TAG_INTEGER {
        return None;
    }
    let (list_tag, list) = fields.next()?;
    if list_tag != TAG_SEQUENCE {
        return None;
    }

    let mut bindings = Vec::new();
    for (tag, binding) in Reader::new(list) {
        if tag != TAG_SEQUENCE {
            continue;
        }
        let mut pair = Reader::new(binding);
        let Some((name_tag, name)) = pair.next() else {
            continue;
        };
        if name_tag != TAG_OID {
            continue;
        }
        let Some(name) = decode_oid(name) else {
            continue;
        };
        let value = match pair.next() {
            Some((TAG_OCTETS, bytes)) => Value::Bytes(bytes.to_vec()),
            Some((TAG_OID, bytes)) => match decode_oid(bytes) {
                Some(arcs) => Value::Oid(arcs),
                None => Value::Other,
            },
            Some((TAG_INTEGER, bytes)) => match decode_integer(bytes) {
                Some(value) => Value::Int(value),
                None => Value::Other,
            },
            Some((tag, _)) if TAG_ABSENT.contains(&tag) => Value::Absent,
            Some(_) => Value::Other,
            None => continue,
        };
        bindings.push((name, value));
    }

    Some(Response {
        id,
        error,
        bindings,
    })
}

/// Reads a reply into an [`Agent`], where it is a reply to this question.
///
/// The request id is checked, which is what makes an answer meant for another
/// device recognisable rather than merely unlikely.
pub fn read(reply: &[u8], id: i64) -> Option<Agent> {
    let response = parse_response(&reply[..reply.len().min(MOST)])?;
    if response.id != id {
        return None;
    }

    let mut agent = Agent::default();
    for (name, value) in &response.bindings {
        match (name.as_slice(), value) {
            (n, Value::Bytes(bytes)) if n == SYS_DESCR => agent.description = text(bytes),
            (n, Value::Bytes(bytes)) if n == SYS_NAME => agent.name = text(bytes),
            (n, Value::Oid(arcs)) if n == SYS_OBJECT_ID => {
                agent.enterprise = enterprise_of(arcs);
                agent.object_id = Some(dotted(arcs));
            }
            _ => {}
        }
    }
    Some(agent)
}

/// The Private Enterprise Number an OID hangs under, where it hangs under one.
///
/// `1.3.6.1.4.1.9.1.696` is Cisco's, so this is `9`. An OID outside the private
/// enterprise arc has no number and answers [`None`] rather than a wrong one:
/// a handful of agents answer `sysObjectID` with a name from the standard tree,
/// and there is no organisation behind those.
pub fn enterprise_of(arcs: &[u32]) -> Option<u32> {
    (arcs.len() > ENTERPRISES.len() && arcs.starts_with(&ENTERPRISES))
        .then(|| arcs[ENTERPRISES.len()])
}

/// An OID in the form everybody writes it in.
pub fn dotted(arcs: &[u32]) -> String {
    arcs.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// One octet string as a line fit to show somebody.
///
/// Three things have to happen to it and all three were bought by a real
/// product string. `sysDescr` is octets, not text, so it is read leniently
/// rather than rejected; a Cisco switch's runs to three lines, and a newline in
/// a table cell is a broken row rather than a long one; and the length is the
/// device's to choose, so it is capped here and the truncation is shown.
fn text(bytes: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut kept = 0usize;
    let mut space = false;
    for c in String::from_utf8_lossy(bytes).chars() {
        if c.is_whitespace() || c.is_control() {
            // A run of any length becomes one space, and a run before anything
            // has been kept becomes nothing.
            space = kept > 0;
            continue;
        }
        if kept >= MOST_TEXT {
            out.push('…');
            break;
        }
        if space {
            out.push(' ');
            kept += 1;
            space = false;
        }
        out.push(c);
        kept += 1;
    }
    (!out.is_empty()).then_some(out)
}

// ---------------------------------------------------------------------------
// BER, in the definite-length form and no more of it than this needs
// ---------------------------------------------------------------------------

/// Appends one tag, its length and its body.
fn tlv(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let wide = n.to_be_bytes();
        let first = wide.iter().position(|b| *b != 0).unwrap_or(wide.len() - 1);
        out.push(0x80 | (wide.len() - first) as u8);
        out.extend_from_slice(&wide[first..]);
    }
    out.extend_from_slice(body);
}

/// An INTEGER, in the minimal two's-complement form the encoding requires.
fn encode_integer(value: i64) -> Vec<u8> {
    let wide = value.to_be_bytes();
    let mut at = 0;
    while at < wide.len() - 1 {
        // A leading byte is redundant only when the next one already carries
        // the sign. Dropping one that does not would change the number.
        let redundant = (wide[at] == 0x00 && wide[at + 1] & 0x80 == 0)
            || (wide[at] == 0xff && wide[at + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        at += 1;
    }
    let mut out = Vec::new();
    tlv(TAG_INTEGER, &wide[at..], &mut out);
    out
}

/// An OBJECT IDENTIFIER. The first two arcs share a byte, as the encoding says.
fn encode_oid(arcs: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        body.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            base128(arc, &mut body);
        }
    }
    let mut out = Vec::new();
    tlv(TAG_OID, &body, &mut out);
    out
}

fn base128(value: u32, out: &mut Vec<u8>) {
    let mut stack = [0u8; 5];
    let mut n = 0;
    let mut left = value;
    loop {
        stack[n] = (left & 0x7f) as u8;
        n += 1;
        left >>= 7;
        if left == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(if i == 0 { stack[i] } else { stack[i] | 0x80 });
    }
}

/// Walks a sequence's body, one tag at a time.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = (u8, &'a [u8]);

    /// The next tag and its body, and [`None`] at the end **and on anything
    /// malformed**. There is no error type on purpose: every caller here treats
    /// "could not read it" and "it was not there" the same way, and a reader
    /// that stops at the first thing it cannot make sense of is what keeps a
    /// hostile datagram from reaching any of the code above.
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (tag, body, after) = tlv_at(self.bytes, self.at)?;
        self.at = after;
        Some((tag, body))
    }
}

/// The whole of one tag, where the buffer is exactly one.
fn one_tlv(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, body, _) = tlv_at(bytes, 0)?;
    Some((tag, body))
}

/// Reads the tag at `at`, and says where the next one starts.
///
/// Everything this rejects, it rejects because accepting it would mean reading
/// past the datagram: a high tag number, an indefinite length, a length whose
/// own length will not fit a `usize`, and a length that runs off the end.
fn tlv_at(bytes: &[u8], at: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *bytes.get(at)?;
    // A tag number of 31 means the number continues into the following bytes.
    // Nothing in an SNMP message uses one.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *bytes.get(at + 1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        // Zero is the indefinite form, which BER allows and DER does not, and
        // which no agent sends. Anything past four bytes is a length no
        // datagram can have.
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *bytes.get(at + 2 + i)? as usize;
        }
        (len, 2 + count)
    };
    let start = at + header;
    let end = start.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some((tag, &bytes[start..end], end))
}

fn decode_integer(body: &[u8]) -> Option<i64> {
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    let mut value = if body[0] & 0x80 != 0 { -1i64 } else { 0 };
    for byte in body {
        value = (value << 8) | i64::from(*byte);
    }
    Some(value)
}

fn decode_oid(body: &[u8]) -> Option<Vec<u32>> {
    let first = *body.first()? as u32;
    let mut arcs = vec![first / 40, first % 40];
    let mut arc: u32 = 0;
    let mut partial = false;
    for byte in &body[1..] {
        arc = arc.checked_mul(128)?.checked_add(u32::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            arcs.push(arc);
            arc = 0;
            partial = false;
        } else {
            partial = true;
        }
    }
    // A trailing byte with the continuation bit still set is a truncated arc.
    (!partial).then_some(arcs)
}

// ---------------------------------------------------------------------------
// The IANA Private Enterprise Number registry, compiled in
// ---------------------------------------------------------------------------

/// The compiled registry. See `build.rs` for the layout, and
/// `tools/fetch-pen.sh` for where the data file comes from.
static TABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pen.bin"));

const PEN_MAGIC: u32 = 0x4d50_454e;

/// The organisation IANA gave an enterprise number to.
///
/// [`None`] where the number is not in the table, which is either a number
/// issued since the file was refreshed or one nobody holds. The same three
/// answers [`crate::vendor`] distinguishes do not arise here: an enterprise
/// number is never randomised, so there is nothing to tell apart from a gap.
pub fn enterprise(number: u32) -> Option<&'static str> {
    assert_eq!(
        u32le(TABLE, 0),
        PEN_MAGIC,
        "the compiled enterprise table is not one"
    );
    let count = u32le(TABLE, 4) as usize;
    let blob_at = 12 + count * 8;

    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        match u32le(TABLE, 12 + mid * 4).cmp(&number) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                let at = blob_at + u32le(TABLE, 12 + count * 4 + mid * 4) as usize;
                let len = u16le(TABLE, at) as usize;
                // `build.rs` wrote these out of a `String`, so they are UTF-8
                // by construction; the checked conversion is still the honest
                // one to reach for over an unchecked cast.
                return std::str::from_utf8(&TABLE[at + 2..at + 2 + len]).ok();
            }
        }
    }
    None
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::Mutex;

    /// Turns the fixtures below into bytes.
    ///
    /// The fixtures are written as hex rather than as calls to this module's
    /// own encoder, which is the point of them: a fixture built by the code
    /// under test proves only that the code agrees with itself.
    fn bytes(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2), "half a byte in a fixture");
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    }

    /// A `GetRequest` for the three system objects, request id 1, community
    /// `public`.
    ///
    /// **Provenance:** constructed from RFC 3416 §3 (the PDU) and RFC 3417 §2
    /// (the message wrapper), encoded by hand against X.690's definite-length
    /// rules. It is the exact datagram `snmpget -v2c -c public <host>
    /// sysDescr.0 sysObjectID.0 sysName.0` puts on the wire, and it exercises
    /// the short-form length only.
    const REQUEST: &str = "304202010104067075626c6963a035020101020100020100302a300c06082b060102010101000500300c06082b060102010102000500300c06082b060102010105000500";

    /// A `GetResponse` from a Cisco Catalyst 2960.
    ///
    /// **Provenance:** constructed to the same two RFCs, carrying the
    /// `sysDescr` string Cisco's IOS 15.0(2)SE11 publishes verbatim — including
    /// the CR LF in the middle of it, which is what the whitespace rule in
    /// `text` exists for — and `sysObjectID` `1.3.6.1.4.1.9.1.696`, the
    /// registered identifier of that switch. At 245 bytes it is the fixture
    /// that exercises the **long-form** length, twice: once for the message and
    /// once for the description.
    const CISCO: &str = "3081f202010104067075626c6963a281e40201010201000201003081d83081a506082b06010201010100048198436973636f20494f5320536f6674776172652c20433239363020536f667477617265202843323936302d4c414e424153454b392d4d292c2056657273696f6e2031352e30283229534531312c2052454c4541534520534f4654574152452028666333290d0a546563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74656368737570706f7274301506082b0601020101020006092b0601040109018538301706082b06010201010500040b73772d6f66666963652d31";

    /// A `GetResponse` from a MikroTik router, request id 1.
    ///
    /// **Provenance:** the same construction, with `RouterOS RB750Gr3` as
    /// `sysDescr` and `1.3.6.1.4.1.14988.1` as `sysObjectID`, which is
    /// MikroTik's arc. Enterprise 14988 needs two base-128 groups, so this is
    /// the fixture that proves the OID reader handles an arc over 127.
    const MIKROTIK: &str = "306302010104067075626c6963a256020101020100020100304b301d06082b060102010101000411526f757465724f53205242373530477233301406082b0601020101020006082b06010401f50c01301406082b0601020101050004084d696b726f54696b";

    /// A `GetResponse` from an APC network management card, request id 3, whose
    /// third binding is `noSuchObject`.
    ///
    /// **Provenance:** constructed from RFC 3416 §4.2.1, which is where v2c
    /// defines the exception it puts in a binding it cannot fill, tagged
    /// `[1] 0x81`. The device is real about this: a card with no system name
    /// configured answers exactly this way, and it is the case that makes v2c
    /// worth encoding rather than v1, which would have failed the whole PDU.
    const APC: &str = "306902010104067075626c6963a25c0201030201000201003051302806082b06010201010100041c415043205765622f534e4d50204d616e6167656d656e742043617264301706082b06010201010200060b2b06010401823e0103020b300c06082b060102010105008100";

    /// A `GetResponse` from a router running OpenWrt, request id 1.
    ///
    /// **Provenance:** the same construction, carrying what OpenWrt 23.05
    /// publishes: `sysDescr` as the release and kernel, and `sysObjectID`
    /// `1.3.6.1.4.1.8072.3.2.10`, which is net-snmp's own identifier for a
    /// Linux host. It is here as the standing example of the caveat on
    /// [`Agent::registrant`]: enterprise 8072 is **net-snmp**, the software
    /// answering, and no part of the box in front of you.
    const OPENWRT: &str = "307102010104067075626c6963a2640201010201000201003059302a06082b06010201010100041e4f70656e5772742032332e30352e33204c696e757820352e31352e313530301606082b06010201010200060a2b06010401bf0803020a301306082b0601020101050004074f70656e577274";

    /// One recorded reply, keyed by where the question went.
    #[derive(Default)]
    struct Fake {
        replies: BTreeMap<SocketAddr, Vec<u8>>,
        asked: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    impl Ask for Fake {
        fn ask(&self, to: SocketAddr, payload: &[u8], _t: Duration) -> io::Result<Vec<u8>> {
            self.asked.lock().unwrap().push((to, payload.to_vec()));
            match self.replies.get(&to) {
                Some(reply) => Ok(reply.clone()),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, "nothing answered")),
            }
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn asking() -> Options {
        Options {
            ask: true,
            ..Default::default()
        }
    }

    #[test]
    fn the_request_is_the_one_the_standard_describes() {
        assert_eq!(
            get_request(1, &[SYS_DESCR, SYS_OBJECT_ID, SYS_NAME]),
            bytes(REQUEST)
        );
    }

    /// The rule the module exists under, and the one test that must never be
    /// relaxed: one community string, sent once, and it is the standard's
    /// default rather than a guess at somebody's.
    #[test]
    fn exactly_one_community_string_is_ever_sent() {
        let mut fake = Fake::default();
        fake.replies
            .insert(SocketAddr::new(ip("192.168.0.2"), PORT), bytes(CISCO));

        let found = one(
            ip("192.168.0.2"),
            &fake,
            &Bucket::new(1_000_000),
            asking(),
            1,
        );
        assert!(found.is_some());

        let asked = fake.asked.lock().unwrap();
        assert_eq!(
            asked.len(),
            1,
            "one datagram, no retry with a second string"
        );
        let sent = &asked[0].1;
        assert_eq!(asked[0].0.port(), PORT);
        let strings: Vec<String> = Reader::new(one_tlv(sent).unwrap().1)
            .filter(|(tag, _)| *tag == TAG_OCTETS)
            .map(|(_, body)| String::from_utf8_lossy(body).into_owned())
            .collect();
        assert_eq!(strings, vec![COMMUNITY.to_string()]);
        // And the word itself appears once in the whole datagram, so a second
        // string smuggled into any other field would fail this too.
        let occurrences = sent
            .windows(COMMUNITY.len())
            .filter(|w| *w == COMMUNITY.as_bytes())
            .count();
        assert_eq!(occurrences, 1);
    }

    /// Nothing is asked at all until somebody switches it on.
    #[test]
    fn it_is_off_until_it_is_asked_for() {
        let mut fake = Fake::default();
        fake.replies
            .insert(SocketAddr::new(ip("192.168.0.2"), PORT), bytes(CISCO));

        let found = one(
            ip("192.168.0.2"),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
            1,
        );
        assert_eq!(found, None);
        assert!(fake.asked.lock().unwrap().is_empty(), "it sent something");
    }

    #[test]
    fn a_switch_is_read_out_of_its_own_description() {
        let agent = read(&bytes(CISCO), 1).expect("a response to this question");
        let description = agent.description.as_deref().unwrap();
        assert!(description.starts_with("Cisco IOS Software, C2960 Software"));
        // The CR LF and the indentation around it are gone, and nothing was
        // dropped where they were.
        assert!(!description.contains('\n'));
        assert!(description.contains("(fc3) Technical Support:"));
        assert_eq!(agent.name.as_deref(), Some("sw-office-1"));
        assert_eq!(agent.object_id.as_deref(), Some("1.3.6.1.4.1.9.1.696"));
        assert_eq!(agent.enterprise, Some(9));
        assert_eq!(agent.registrant(), Some("ciscoSystems"));
        assert_eq!(
            agent.registered_to().as_deref(),
            Some("ciscoSystems, enterprise 9")
        );
    }

    /// An arc over 127 needs two base-128 groups, and getting that wrong turns
    /// MikroTik's 14988 into something else entirely.
    #[test]
    fn an_enterprise_over_a_hundred_and_twenty_seven_survives_the_encoding() {
        let agent = read(&bytes(MIKROTIK), 1).expect("a response to this question");
        assert_eq!(agent.enterprise, Some(14988));
        assert_eq!(agent.registrant(), Some("MikroTik"));
        assert_eq!(agent.description.as_deref(), Some("RouterOS RB750Gr3"));
        assert_eq!(agent.object_id.as_deref(), Some("1.3.6.1.4.1.14988.1"));
    }

    /// A missing object is a missing object, and the rest of the reply stands.
    #[test]
    fn a_binding_the_agent_cannot_fill_does_not_lose_the_others() {
        let response = parse_response(&bytes(APC)).expect("a response");
        assert_eq!(response.error, 0);
        assert_eq!(response.bindings.len(), 3);
        assert_eq!(response.bindings[2].1, Value::Absent);

        let agent = read(&bytes(APC), 3).expect("a response to this question");
        assert_eq!(
            agent.description.as_deref(),
            Some("APC Web/SNMP Management Card")
        );
        assert_eq!(agent.name, None);
        assert_eq!(agent.enterprise, Some(318));
        assert!(agent.registrant().unwrap().contains("American Power"));
    }

    /// A reply to somebody else's question is not this device's answer.
    /// A reply meant for another device is refused rather than believed.
    ///
    /// One socket per exchange makes this unlikely and never impossible: an
    /// agent that is slow to answer replies while the next address is being
    /// asked, and without the id its description would land on the wrong row.
    #[test]
    fn a_reply_carrying_another_questions_id_is_refused() {
        assert_eq!(read(&bytes(CISCO), 2), None);
        assert_eq!(read(&bytes(APC), 1), None);
        assert!(read(&bytes(APC), 3).is_some());
    }

    /// Every prefix of a real reply, and a page of noise. None of it may panic,
    /// and none of it may come back as an answer.
    #[test]
    fn a_malformed_datagram_is_never_read_as_an_answer() {
        let whole = bytes(CISCO);
        for n in 0..whole.len() {
            assert_eq!(read(&whole[..n], 1), None, "a {n}-byte prefix answered");
        }
        assert_eq!(read(&[0u8; 64], 1), None);
        assert_eq!(read(&[0xffu8; 512], 1), None);
        // A sequence claiming four gigabytes inside a forty-byte datagram.
        assert_eq!(read(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02], 1), None);
        // The indefinite length form, which BER allows and this refuses.
        assert_eq!(read(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00], 1), None);
    }

    /// A request-scoped truncation: the reader must not read past `MOST`, and
    /// a device answering with more than that gets nothing rather than a panic.
    #[test]
    fn an_enormous_reply_is_cut_rather_than_read() {
        let mut huge = bytes(CISCO);
        huge.resize(MOST * 4, 0);
        // The message's own length still describes the real reply, so cutting
        // the buffer at `MOST` leaves the message intact and the padding gone.
        assert!(read(&huge, 1).is_some());
    }

    /// Only the three system objects are asked for, and there is no walk.
    #[test]
    fn nothing_beyond_the_three_system_objects_is_asked_for() {
        let request = get_request(1, &[SYS_DESCR, SYS_OBJECT_ID, SYS_NAME]);
        let asked: Vec<Vec<u32>> = Reader::new(one_tlv(&request).unwrap().1)
            .filter(|(tag, _)| *tag == TAG_GET)
            .flat_map(|(_, pdu)| Reader::new(pdu))
            .filter(|(tag, _)| *tag == TAG_SEQUENCE)
            .flat_map(|(_, list)| Reader::new(list))
            .filter_map(|(_, binding)| {
                let (tag, name) = one_tlv(binding)?;
                (tag == TAG_OID).then_some(())?;
                decode_oid(name)
            })
            .collect();
        assert_eq!(
            asked,
            vec![
                SYS_DESCR.to_vec(),
                SYS_OBJECT_ID.to_vec(),
                SYS_NAME.to_vec()
            ]
        );
    }

    /// The description reaches [`crate::kind`], and reaches it as free text.
    ///
    /// A router is the case this whole module was written for: it advertises no
    /// mDNS, no UPnP and no NetBIOS, so before SNMP its row was an address and a
    /// vendor. `Clue::Product` is where the claim lands, which is below a
    /// service and above a port, and that is the rank `CLAUDE.md` gives
    /// anything a device wrote about itself in free text.
    #[test]
    fn a_description_names_a_kind_and_ranks_as_a_product_string() {
        use crate::discover::{Found, Protocol};
        use crate::identify::Identity;
        use crate::kind::{Clue, Kind, Vantage};

        let host = Found::announced(ip("10.0.0.2"), Protocol::Mdns);
        let identity = Identity {
            snmp: read(&bytes(OPENWRT), 1),
            ..Default::default()
        };
        let guess = crate::kind::identify(&host, &identity, Vantage::default())
            .expect("the description names it");
        assert_eq!(guess.kind, Kind::NetworkGear);
        assert_eq!(guess.clue, Clue::Product);
        // And a service, where one is advertised, still beats it.
        let with_service = Identity {
            services: vec!["_ipp._tcp".to_string()],
            ..identity
        };
        let beaten = crate::kind::identify(&host, &with_service, Vantage::default()).unwrap();
        assert_eq!(beaten.kind, Kind::Printer);
        assert_eq!(beaten.clue, Clue::Service);
    }

    /// The enterprise number names whoever registered the OID, and that is not
    /// always whoever made the device.
    ///
    /// This is the reason nothing infers a [`crate::Kind`] from it. OpenWrt's
    /// agent is net-snmp, so the router answers with net-snmp's number, and a
    /// row reading "made by net-snmp" would be a plain falsehood about the
    /// hardware. What is true is what [`Agent::registered_to`] says: the OID is
    /// registered to that organisation.
    #[test]
    fn an_enterprise_number_is_who_registered_the_oid_and_says_so() {
        let agent = read(&bytes(OPENWRT), 1).expect("a response to this question");
        assert_eq!(agent.enterprise, Some(8072));
        assert_eq!(agent.registrant(), Some("net-snmp"));
        assert_eq!(
            agent.registered_to().as_deref(),
            Some("net-snmp, enterprise 8072")
        );
        assert_eq!(agent.name.as_deref(), Some("OpenWrt"));
    }

    #[test]
    fn the_enterprise_table_is_present_and_sane() {
        let count = u32le(TABLE, 4) as usize;
        assert!(count > 50_000, "only {count} enterprises");
        // A spread of the numbers that turn up on a real network, and one that
        // does not exist. Each is a row in `data/pen.tsv`.
        assert_eq!(enterprise(9), Some("ciscoSystems"));
        assert_eq!(enterprise(311), Some("Microsoft"));
        assert_eq!(enterprise(2636), Some("Juniper Networks, Inc."));
        assert_eq!(enterprise(8072), Some("net-snmp"));
        assert_eq!(enterprise(14988), Some("MikroTik"));
        assert_eq!(enterprise(41112), Some("Ubiquiti Networks, Inc."));
        assert_eq!(enterprise(u32::MAX), None);
    }

    /// Every row in the table has to be findable, which is the only way to know
    /// the search agrees with the layout the generator wrote. The same walk
    /// `vendor.rs` does over the OUI table, for the same reason.
    #[test]
    fn every_enterprise_can_be_found() {
        let count = u32le(TABLE, 4) as usize;
        for i in 0..count {
            let number = u32le(TABLE, 12 + i * 4);
            let name = enterprise(number);
            assert!(name.is_some(), "row {i} (enterprise {number}) not found");
            assert!(!name.unwrap().is_empty());
        }
    }

    /// A number nobody holds is not in the table at all, so it cannot be
    /// reported as somebody. `Unassigned` and `Reserved` rows are dropped by
    /// `tools/fetch-pen.sh` for exactly this.
    #[test]
    fn an_unheld_number_is_nobody() {
        assert_eq!(enterprise(0), None);
        for name in (0..u32::MAX)
            .step_by(1_000_003)
            .take(200)
            .filter_map(enterprise)
        {
            let lower = name.to_ascii_lowercase();
            assert!(!lower.contains("unassigned"), "{name}");
            assert_ne!(lower, "reserved", "{name}");
        }
    }

    #[test]
    fn an_object_id_outside_the_private_arc_names_no_organisation() {
        // `1.3.6.1.2.1` is the standard MIB-2 tree, which some agents answer
        // `sysObjectID` with. Nobody registered it, and inventing an
        // organisation for it would be the confident nonsense to avoid.
        assert_eq!(enterprise_of(&[1, 3, 6, 1, 2, 1, 1]), None);
        // The bare arc with no number after it.
        assert_eq!(enterprise_of(&[1, 3, 6, 1, 4, 1]), None);
        assert_eq!(enterprise_of(&[1, 3, 6, 1, 4, 1, 9, 1, 696]), Some(9));
    }

    #[test]
    fn a_description_longer_than_a_device_should_send_is_cut_visibly() {
        let long = "a".repeat(MOST_TEXT * 2);
        let out = text(long.as_bytes()).unwrap();
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), MOST_TEXT + 1);
    }

    #[test]
    fn octets_that_are_not_text_do_not_come_back_as_a_description() {
        assert_eq!(text(b""), None);
        assert_eq!(text(b"   \r\n\t "), None);
        // Invalid UTF-8 is read leniently rather than thrown away: `sysDescr`
        // is octets, and a device with a Latin-1 product name has still named
        // itself.
        assert!(text(&[0xff, b'A', b'B']).is_some());
    }

    #[test]
    fn many_asks_each_address_once_and_keeps_the_order() {
        let mut fake = Fake::default();
        fake.replies
            .insert(SocketAddr::new(ip("10.0.0.2"), PORT), bytes(MIKROTIK));

        let addresses = [ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")];
        let found = many(
            &addresses,
            &fake,
            &Bucket::new(1_000_000),
            Options {
                ask: true,
                workers: 1,
                ..Default::default()
            },
            &AtomicBool::new(false),
            &|_, _| {},
        );
        assert_eq!(found.len(), 3);
        // The answer lands on the address that gave it, and the two silences
        // stay silences rather than shuffling up the list.
        assert_eq!(found[0], None);
        assert_eq!(
            found[1].as_ref().and_then(|a| a.description.as_deref()),
            Some("RouterOS RB750Gr3")
        );
        assert_eq!(found[2], None);
        assert_eq!(fake.asked.lock().unwrap().len(), 3);
    }

    #[test]
    fn an_agent_that_answered_and_said_nothing_is_still_an_agent() {
        // The APC reply's third binding is empty, but the first two are not, so
        // build the degenerate case: a response with no bindings at all.
        let empty = get_response_with_no_bindings(5);
        let agent = read(&empty, 5).expect("it answered in the protocol");
        assert!(agent.is_empty());
        assert_eq!(agent.summary(), "it answered on port 161 and named nothing");
    }

    /// A `GetResponse` carrying an empty binding list.
    ///
    /// **Provenance:** built here rather than captured, because it is the one
    /// shape no device volunteers: an agent answering a `GetRequest` echoes the
    /// names it was asked about. It exists to prove the rule that a reply in
    /// the protocol is the test, never a useful one.
    fn get_response_with_no_bindings(id: i64) -> Vec<u8> {
        let mut pdu = encode_integer(id);
        pdu.extend_from_slice(&encode_integer(0));
        pdu.extend_from_slice(&encode_integer(0));
        tlv(TAG_SEQUENCE, &[], &mut pdu);
        let mut body = encode_integer(VERSION_2C);
        tlv(TAG_OCTETS, COMMUNITY.as_bytes(), &mut body);
        tlv(TAG_RESPONSE, &pdu, &mut body);
        let mut out = Vec::new();
        tlv(TAG_SEQUENCE, &body, &mut out);
        out
    }

    #[test]
    fn integers_round_trip_at_the_edges() {
        for value in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            i64::MAX,
            i64::MIN,
        ] {
            let encoded = encode_integer(value);
            let (tag, body) = one_tlv(&encoded).unwrap();
            assert_eq!(tag, TAG_INTEGER);
            assert_eq!(decode_integer(body), Some(value), "{value}");
        }
        // The minimal form: 127 fits one byte, 128 needs two because the top
        // bit would otherwise read as a sign.
        assert_eq!(encode_integer(127), vec![0x02, 0x01, 0x7f]);
        assert_eq!(encode_integer(128), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn object_identifiers_round_trip() {
        for arcs in [
            SYS_DESCR.to_vec(),
            vec![1, 3, 6, 1, 4, 1, 14988, 1],
            vec![1, 3, 6, 1, 4, 1, 4_294_967_295],
            vec![0, 0],
        ] {
            let encoded = encode_oid(&arcs);
            let (tag, body) = one_tlv(&encoded).unwrap();
            assert_eq!(tag, TAG_OID);
            assert_eq!(decode_oid(body), Some(arcs.clone()), "{arcs:?}");
        }
        // A truncated arc, whose last byte still asks for a continuation.
        assert_eq!(decode_oid(&[0x2b, 0x86]), None);
    }
}
