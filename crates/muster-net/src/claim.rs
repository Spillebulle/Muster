//! Hardware addresses a device *said*, as against ones its stack answered.
//!
//! ## Why this is a separate kind of claim
//!
//! An ARP reply is answered below the level anything on the device can lie
//! about: the address in it is the address the frame was sent from, and the
//! kernel that wrote it has no opinion. Every route in this module is the
//! opposite — a device writing its own hardware address into the *payload* of
//! a message it composed. A responder that gets it wrong, a proxy answering on
//! somebody else's behalf, or a device that prints the address of an interface
//! it is not answering on all produce a MAC that is confidently stated and not
//! true of the address it arrived from.
//!
//! Both are worth having and they are not the same fact, so [`Route`] names
//! which of them is being shown and [`crate::discover::Found::mac_said`]
//! carries it as far as the interface. `CLAUDE.md`: every claim about a device
//! is a claim with a reason, and the reason is stored beside it and shown.
//!
//! ## Why it is worth having at all
//!
//! The link phase and the listen add devices the sweep never probed, and those
//! rows have no ARP entry, no neighbour-table entry and therefore no vendor at
//! all — a blank hardware column beside a name and a model. A great many of
//! those same devices have already written their hardware address into the
//! reply that put them on the list. Muster was receiving the bytes and reading
//! one of them: [`crate::netbios`] takes the adapter address out of a node
//! status reply's statistics block, and nothing else did the same.
//!
//! ## A hex string that looks like a MAC is not a MAC
//!
//! That is the rule the whole module is built on, and it is enforced twice.
//!
//! **First, by service.** A route is read only out of the field of the
//! protocol it belongs to. HomeKit's `_hap._tcp` `id=` is six colon-separated
//! hex octets and is specified to be *random*, to persist across reboots and
//! to be regenerated on a factory reset — an accessory identifier wearing a
//! hardware address's clothes. Handing it to [`crate::vendor`] invents a maker
//! for a number nobody assigned, and because such an identifier usually has
//! the local bit set it would more often be reported as "randomised", which is
//! the right answer for entirely the wrong reason and looks like nothing is
//! wrong. So `id` is not a key this module knows, anywhere.
//!
//! **Second, by the registry**, for every route where the address is
//! *inferred* from an identifier rather than written into a field that means
//! it. See [`Test`]: the shape of a value proves nothing, and the test for
//! those routes is that it resolves to a manufacturer. Where it does not, the
//! value stays an opaque identity and no vendor claim is made — a blank
//! hardware column, which is an answer.
//!
//! ## What is not a route
//!
//! * **`_hap._tcp` `id=`**, for the reason above.
//! * **A Shelly instance name**, `shellyplug-s-6a78b4`. The hex is the *last
//!   three octets* of the address and nothing else, so there is no OUI in it
//!   at all: looking those three bytes up as a prefix would name a
//!   manufacturer chosen essentially at random. It is a name, it is already
//!   kept as one, and it is not an address.
//! * **A DHCP `chaddr`.** An offer echoes the `chaddr` of the DISCOVER that
//!   asked for it, and the DISCOVER is Muster's own: the field in every offer
//!   [`crate::dhcp`] parses holds *this machine's* hardware address, not the
//!   server's. It becomes a route the day something reads DHCP traffic it did
//!   not send, which is the continuous listen on ports 67 and 68 that
//!   `CLAUDE.md` describes and this is not.
//! * **A bare `A` record whose name is twelve hex digits.** Matter builds its
//!   host name that way and so does very little else, but twelve hex digits
//!   prove nothing on their own, so the address is taken from the `SRV` of a
//!   Matter service and not from a host name wherever it turns up.
//! * **A 64-bit Matter host name.** The specification permits the Thread
//!   extended address as well as the 48-bit MAC, and an EUI-64 is not a MAC:
//!   it is frequently generated at random, and the two ways of folding one
//!   back to six bytes disagree. Sixteen hex digits are read as no answer.

use crate::dns;
use crate::mac::MacAddr;
use crate::vendor::{self, Origin};

/// How much checking a route's value needs before it is a hardware address.
///
/// **The distinction is the whole of the module's honesty.** Some of these
/// fields exist to hold the interface's address and say so; the rest are
/// identifiers that happen to have been built out of one, and for those the
/// shape is not evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Test {
    /// The publisher writes the interface's own address into this field. The
    /// value is the answer, a locally administered one included — that is a
    /// device that randomised its address and then told the truth about it,
    /// and [`crate::vendor::lookup`] reports it as randomised, which is a fact
    /// rather than a failed lookup.
    AsGiven,
    /// The address is inferred from an identifier, so the registry is the
    /// test: a value that resolves to a manufacturer is a hardware address and
    /// one that does not is a number. This also refuses a locally administered
    /// value outright, because on an inferred route there is no telling a
    /// device that randomised its address from a device that never had one
    /// here.
    Registered,
    /// The same, after clearing the local bit, which one publisher is known to
    /// set. See [`Route::Cast`].
    Flipped,
}

/// Which route carried a hardware address a device stated about itself.
///
/// The order of the variants is the priority order, so `derive(Ord)` is the
/// comparison and there is no second list to keep in step — the same rule
/// [`crate::identify::Source`] follows. It runs from the fields that exist to
/// hold an address down to the identifiers an address was inferred from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Route {
    /// The statistics block of a NetBIOS node status reply, whose first six
    /// bytes are the adapter address by specification.
    NetBios,
    /// The instance name of an mDNS `_workstation._tcp` record. Avahi
    /// publishes `hostname [aa:bb:cc:dd:ee:ff]` — its `%h [%m]`, where `%m` is
    /// the interface's address — and Avahi is what every Debian, Ubuntu and
    /// Pop!_OS machine on the network is running by default.
    Workstation,
    /// An ESPHome node's `mac=` in its `_esphomelib._tcp` `TXT` record: plain
    /// unseparated hex, in a key that means exactly what it says.
    ///
    /// The cheapest route here and the one that reaches the class of device
    /// `CLAUDE.md` singles out as answering nothing else — the ESP-based smart
    /// plug, which ignores the `_services._dns-sd._udp` meta-query and answers
    /// a question about its own type at once.
    EspHome,
    /// An mDNS `deviceid=` in an `_airplay._tcp` `TXT` record.
    ///
    /// Apple's own receivers put the interface's address here. Software
    /// receivers synthesise one, so the registry is the test.
    AirPlay,
    /// The instance name of an mDNS `_raop._tcp` record. AirPlay receivers
    /// publish `5855CA1AE288@Apple TV`, the address before the `@`.
    Raop,
    /// A Matter service's `SRV` target. The specification builds the host name
    /// out of the 48-bit MAC as twelve hex digits.
    Matter,
    /// An mDNS `bs=` in a `_googlecast._tcp` `TXT` record.
    ///
    /// **Inferred, and it is the route with the least documentation behind
    /// it.** Nothing specifies `bs`, and the observed values are the device's
    /// address with the local bit *set*: `FA8FCA890C6C` is not in any registry
    /// and `F88FCA…` is Google. So the bit is cleared, the cleared form has to
    /// resolve, and what is kept is the cleared form, which is the address the
    /// interface actually holds.
    Cast,
    /// A Sonos `USN`, `uuid:RINCON_<mac>…`: the prefix, the twelve hex digits
    /// of the address, then a port and a serial.
    Sonos,
    /// The node field of a UPnP `USN` uuid, where the uuid is RFC 4122
    /// version 1.
    UpnpUuid,
    /// The node field of a WS-Discovery endpoint reference, under the same
    /// rule.
    WsdUuid,
}

impl Route {
    /// Where it was said, for a column or a fact row.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NetBios => "NetBIOS",
            Self::Workstation => "mDNS, _workstation._tcp",
            Self::EspHome => "mDNS, ESPHome mac",
            Self::AirPlay => "mDNS, AirPlay deviceid",
            Self::Raop => "mDNS, _raop._tcp",
            Self::Matter => "mDNS, Matter host name",
            Self::Cast => "mDNS, Google Cast bs",
            Self::Sonos => "UPnP, Sonos identifier",
            Self::UpnpUuid => "UPnP, uuid node",
            Self::WsdUuid => "WS-Discovery, uuid node",
        }
    }

    /// What the route means, for the tooltip. Every one of these says the same
    /// thing in different words, and it is the thing worth saying: the device
    /// wrote this down, and nothing has checked it against a frame.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NetBios => "the device gave it in a NetBIOS node status reply",
            Self::Workstation => "the device published it in its mDNS workstation name",
            Self::EspHome => "the device published it as its ESPHome hardware address",
            Self::AirPlay => "the device published it as its AirPlay device id",
            Self::Raop => "the device published it in its AirPlay receiver name",
            Self::Matter => "the device built its Matter host name out of it",
            Self::Cast => "the device built its Google Cast device id out of it",
            Self::Sonos => "the device built its Sonos identifier out of it",
            Self::UpnpUuid => "the device built its UPnP uuid out of it",
            Self::WsdUuid => "the device built its WS-Discovery uuid out of it",
        }
    }

    /// How far the value has to be checked before it is believed.
    const fn test(self) -> Test {
        match self {
            Self::NetBios | Self::Workstation | Self::EspHome => Test::AsGiven,
            Self::Cast => Test::Flipped,
            _ => Test::Registered,
        }
    }

    /// Is this route's address inferred from an identifier rather than read out
    /// of a field that means it?
    ///
    /// The interface has a different sentence for each, and so does anybody
    /// deciding how much to trust a row.
    pub const fn is_inferred(self) -> bool {
        !matches!(self.test(), Test::AsGiven)
    }
}

/// A hardware address a device stated about itself, and where it stated it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Claim {
    pub mac: MacAddr,
    pub route: Route,
}

impl Claim {
    pub const fn new(mac: MacAddr, route: Route) -> Self {
        Self { mac, route }
    }
}

/// Reads a stated address, and applies the route's own test to it.
///
/// Multicast and all-zero are refused everywhere: the group bit names a set of
/// receivers and the zero address is what a field nobody filled in looks like,
/// and neither is anybody's interface.
fn believable(text: &str, route: Route) -> Option<Claim> {
    let mac: MacAddr = text.parse().ok()?;
    if mac.is_multicast() || mac.is_zero() {
        return None;
    }
    match route.test() {
        Test::AsGiven => Some(Claim::new(mac, route)),
        Test::Registered => registered(mac, route),
        // The local bit cleared, and the *cleared* address is what is kept:
        // that is the one the interface holds and the one the registry knows.
        Test::Flipped => {
            let mut octets = mac.octets();
            octets[0] &= !0x02;
            registered(MacAddr::new(octets), route)
        }
    }
}

/// The registry is the test for an inferred route.
fn registered(mac: MacAddr, route: Route) -> Option<Claim> {
    matches!(vendor::lookup(mac), Origin::Registered { .. }).then_some(Claim::new(mac, route))
}

/// The instance label of `name`, where `name` is an instance of `service`.
///
/// Compared from the right, because a DNS name arrives as labels joined with
/// dots and an instance label is free to contain one: `Ulrik's TV
/// 2.0._airplay._tcp.local` is one instance and not three labels of nonsense.
/// [`None`] where the name is not that service at all, which is what makes
/// every route below a whitelist rather than a pattern match on a value.
fn instance_of<'a>(name: &'a str, service: &str) -> Option<&'a str> {
    let trimmed = name.trim_end_matches('.').trim_end_matches(".local");
    let instance = trimmed.strip_suffix(service)?.strip_suffix('.')?;
    (!instance.is_empty()).then_some(instance)
}

/// Avahi's `hostname [aa:bb:cc:dd:ee:ff]`.
///
/// Read from the last bracket rather than the first: a machine called
/// `lab [spare]` is a real name, and the address is what the *publisher*
/// appended, which is always last.
fn bracketed(instance: &str) -> Option<&str> {
    let close = instance.rfind(']')?;
    let open = instance[..close].rfind('[')?;
    Some(&instance[open + 1..close])
}

/// AirPlay's `5855CA1AE288@Apple TV`.
///
/// The whole of the part before the `@` has to be the address, not merely
/// start with it: a receiver named `me@home` splits perfectly well and has
/// said nothing.
fn before_at(instance: &str) -> Option<&str> {
    let (head, _) = instance.split_once('@')?;
    is_hex(head, 12).then_some(head)
}

/// Matter's host name, which the specification writes as the 48-bit MAC in
/// twelve hex digits.
///
/// Sixteen digits is the Thread extended address and is refused; see the
/// module note.
fn matter_host(target: &str) -> Option<&str> {
    let label = target
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .split('.')
        .next()?;
    is_hex(label, 12).then_some(label)
}

/// Sonos writes `RINCON_` and then the address, then a port and a serial.
const RINCON: &str = "RINCON_";

/// Is `text` exactly `digits` hexadecimal characters?
fn is_hex(text: &str, digits: usize) -> bool {
    text.len() == digits && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The service types whose instance name carries an address.
const NAMED: &[(&str, Route)] = &[
    ("_workstation._tcp", Route::Workstation),
    ("_raop._tcp", Route::Raop),
];

/// The `TXT` keys that carry an address, and the one service type each is
/// believed in.
///
/// **The pairing is the point.** `deviceid` read out of any record at all
/// would take HomeKit's accessory identifier the moment somebody published one
/// under that key, and `id` is not here at any price.
const KEYED: &[(&str, &str, Route)] = &[
    ("_esphomelib._tcp", "mac", Route::EspHome),
    ("_airplay._tcp", "deviceid", Route::AirPlay),
    ("_googlecast._tcp", "bs", Route::Cast),
];

/// The Matter service types, whose `SRV` target is the host name.
const MATTER: &[&str] = &["_matter._tcp", "_matterc._udp"];

/// Is this record's name an instance of one of them?
fn is_matter(name: &str) -> bool {
    MATTER
        .iter()
        .any(|service| instance_of(name, service).is_some())
}

/// Every hardware address one mDNS message states, in the order the records
/// carry them.
///
/// The message is whichever one arrived; the caller has already decided which
/// device it is *about* with [`crate::identify::subject`], which matters here
/// as much as it does for a name — a sleep proxy answering for a sleeping
/// laptop is publishing the laptop's address, not its own.
pub fn from_mdns(msg: &dns::Message) -> Vec<Claim> {
    let mut out: Vec<Claim> = Vec::new();
    let mut take = |claim: Option<Claim>| {
        if let Some(claim) = claim
            && !out.contains(&claim)
        {
            out.push(claim);
        }
    };

    for record in msg.records() {
        // An instance name is written in two places and both arrive: a `PTR`
        // answering an enumeration carries it as its *data*, and the `SRV` and
        // `TXT` for the same service carry it as their own name.
        let written = [
            Some(record.name.as_str()),
            match &record.data {
                dns::RData::Name(target) => Some(target.as_str()),
                _ => None,
            },
        ];
        for name in written.into_iter().flatten() {
            for (service, route) in NAMED {
                let Some(instance) = instance_of(name, service) else {
                    continue;
                };
                let found = match route {
                    Route::Workstation => bracketed(instance),
                    _ => before_at(instance),
                };
                take(found.and_then(|text| believable(text, *route)));
            }
        }

        match &record.data {
            dns::RData::Txt(strings) => {
                for (service, key, route) in KEYED {
                    if instance_of(&record.name, service).is_none() {
                        continue;
                    }
                    for entry in strings {
                        let Some((name, value)) = entry.split_once('=') else {
                            continue;
                        };
                        if name.trim().eq_ignore_ascii_case(key) {
                            take(believable(value.trim(), *route));
                        }
                    }
                }
            }
            dns::RData::Srv { target, .. } if is_matter(&record.name) => {
                take(matter_host(target).and_then(|text| believable(text, Route::Matter)));
            }
            _ => {}
        }
    }
    out
}

/// The hardware address a UPnP `USN` states, where it states one.
///
/// Two shapes, and both are the device's own *identifier* rather than a field
/// meant to hold an address:
///
/// * **Sonos.** `uuid:RINCON_949F3EC0A1B201400`, which is the vendor's own
///   form: the prefix, the twelve hex digits of the address, then the port and
///   a serial. Twelve digits and no more — the tail is not part of it.
/// * **RFC 4122 version 1.** UPnP Device Architecture recommends the
///   time-and-MAC algorithm for a `UDN`, and that algorithm puts the
///   interface's address in the node field, the last twelve hex digits.
///
/// The version nibble is checked before the low bits are believed, and that is
/// the part which has to be right: a version 4 uuid is 122 bits of randomness
/// and its last twelve digits are a number, not an address. So are a version 3
/// or 5 name hash's. RFC 4122 §4.5 also says a version 1 generator with no
/// hardware address to hand must set the multicast bit on the node it invents,
/// which [`believable`] refuses for exactly that reason — and the registry
/// check refuses the rest.
pub fn from_usn(usn: &str) -> Option<Claim> {
    let id = identifier(usn)?;
    if let Some(rest) = id.strip_prefix(RINCON)
        && rest.len() >= 12
        && is_hex(&rest[..12], 12)
    {
        return believable(&rest[..12], Route::Sonos);
    }
    uuid_node(&id).and_then(|node| believable(&node, Route::UpnpUuid))
}

/// The same, for a WS-Discovery endpoint reference: `urn:uuid:…`.
///
/// The address a `ProbeMatch` carries is a stable identifier for the device by
/// specification, and it is a uuid, so it takes the version 1 guard exactly as
/// a `UDN` does. Windows generates a version 4 one and this therefore answers
/// [`None`] for every Windows machine on the network, which is correct.
pub fn from_endpoint(address: &str) -> Option<Claim> {
    let id = identifier(address)?;
    uuid_node(&id).and_then(|node| believable(&node, Route::WsdUuid))
}

/// The identifier out of a `USN`, an endpoint reference or a bare uuid.
///
/// `USN` is `uuid:<id>::<type>`, so the identifier is everything before the
/// double colon; WS-Discovery writes `urn:uuid:<id>` and nothing after it.
fn identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let body = strip_prefix_ignoring_case(text, "urn:uuid:")
        .or_else(|| strip_prefix_ignoring_case(text, "uuid:"))?;
    let body = body.split("::").next()?.trim();
    (!body.is_empty()).then(|| body.to_string())
}

fn strip_prefix_ignoring_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &text[prefix.len()..])
}

/// The node field of an RFC 4122 version 1 uuid, and [`None`] for every other
/// kind of uuid there is.
fn uuid_node(id: &str) -> Option<String> {
    let fields: Vec<&str> = id.split('-').collect();
    let [time_low, time_mid, time_high, clock, node] = fields[..] else {
        return None;
    };
    let shaped = is_hex(time_low, 8)
        && is_hex(time_mid, 4)
        && is_hex(time_high, 4)
        && is_hex(clock, 4)
        && is_hex(node, 12);
    if !shaped {
        return None;
    }
    // The version is the top nibble of `time_high`, and only version 1 puts a
    // hardware address anywhere in the value.
    if !time_high.starts_with('1') {
        return None;
    }
    // And the variant is the top bits of the clock sequence: `10xx` is RFC
    // 4122's own layout, and anything else is a Microsoft or NCS legacy one
    // whose fields are not in these places at all.
    let variant = clock.as_bytes()[0].to_ascii_lowercase();
    if !matches!(variant, b'8'..=b'9' | b'a'..=b'b') {
        return None;
    }
    Some(node.to_string())
}

/// The `uuid:` half of a `USN`, kept as itself.
///
/// UPnP Device Architecture requires a `UDN` to be fixed over time and to
/// survive a reboot, which makes it the most stable per-device identifier
/// available for the televisions and set-top boxes ARP is worst at — the ones
/// that answer a multicast search and nothing else. **Every version of uuid
/// is kept**, because the identity is good whatever the algorithm behind it
/// was; only the *address* needs [`uuid_node`]'s guard.
pub fn udn_of(usn: &str) -> Option<String> {
    identifier(usn).map(|id| format!("uuid:{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(text: &str) -> MacAddr {
        text.parse().unwrap()
    }

    /// Builds a message out of records, the way the decoder would hand one
    /// over. The wire format is [`crate::dns`]'s to test; what is under test
    /// here is which of the records are believed.
    fn message(records: Vec<dns::Record>) -> dns::Message {
        dns::Message {
            id: 0,
            flags: 0x8400,
            questions: Vec::new(),
            answers: records,
            extra: Vec::new(),
        }
    }

    fn record(name: &str, kind: u16, data: dns::RData) -> dns::Record {
        dns::Record {
            name: name.to_string(),
            kind,
            class: 1,
            ttl: 120,
            data,
        }
    }

    fn txt(name: &str, entries: &[&str]) -> dns::Record {
        record(
            name,
            dns::TYPE_TXT,
            dns::RData::Txt(entries.iter().map(|e| (*e).to_string()).collect()),
        )
    }

    fn srv(name: &str, target: &str) -> dns::Record {
        record(
            name,
            dns::TYPE_SRV,
            dns::RData::Srv {
                port: 9,
                target: target.into(),
            },
        )
    }

    /// Avahi publishes `_workstation._tcp` on every Debian, Ubuntu and Pop!_OS
    /// machine with its default configuration, and the instance it publishes
    /// is `%h [%m]`. Constructed from that format; the address is an LCFC
    /// block, which is the maker of a great many laptop cards.
    #[test]
    fn avahi_publishes_the_address_in_its_workstation_name() {
        let msg = message(vec![record(
            "_workstation._tcp.local",
            dns::TYPE_PTR,
            dns::RData::Name("pop-os [8c:8c:aa:1b:2c:3d]._workstation._tcp.local".into()),
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("8c:8c:aa:1b:2c:3d"), Route::Workstation)]
        );
    }

    /// The same record arriving as an `SRV` rather than as the answer to an
    /// enumeration, which is how it turns up when the named question asks for
    /// the type directly. The address is a Synology block.
    #[test]
    fn the_workstation_name_is_read_from_a_records_own_name_too() {
        let msg = message(vec![srv(
            "nas [00:11:32:aa:bb:cc]._workstation._tcp.local",
            "nas.local",
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("00:11:32:aa:bb:cc"), Route::Workstation)]
        );
    }

    /// A name with a bracket in it that is not an address says nothing, and
    /// must not be read as a failed parse of one.
    #[test]
    fn a_bracket_that_is_not_an_address_is_not_one() {
        let msg = message(vec![srv(
            "lab [spare]._workstation._tcp.local",
            "lab.local",
        )]);
        assert!(from_mdns(&msg).is_empty());
    }

    /// **The route that reaches the devices nothing else does.** ESPHome puts
    /// the address in a `TXT` key called `mac`, unseparated, and
    /// `_esphomelib._tcp` is already one of the types the link phase asks for
    /// by name. Constructed from an ESPHome node's advertised key set; the
    /// address is an Espressif block, which is what every one of them is.
    #[test]
    fn esphome_states_its_address_outright() {
        let msg = message(vec![txt(
            "livingroom-plug._esphomelib._tcp.local",
            &["version=2024.6.4", "mac=f4cfa2f75c84", "platform=ESP32"],
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("f4:cf:a2:f7:5c:84"), Route::EspHome)]
        );
    }

    /// An AirPlay receiver's `_raop._tcp` instance is the address, an `@`, and
    /// the name. Constructed from that format; `5855CA` is an Apple block, and
    /// the registry is what the route is checked against.
    #[test]
    fn a_raop_instance_names_the_address_before_the_at() {
        let msg = message(vec![record(
            "_raop._tcp.local",
            dns::TYPE_PTR,
            dns::RData::Name("5855CA1AE288@Apple TV._raop._tcp.local".into()),
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("58:55:ca:1a:e2:88"), Route::Raop)]
        );
    }

    /// The negatives: an instance with no `@`, one whose head is a word, one
    /// whose head is too short, and one whose head is twelve perfectly good
    /// hex digits that no manufacturer holds. The last is the one that matters
    /// — a software receiver synthesises its `deviceid`, and the registry is
    /// what tells the synthesised ones from the real.
    #[test]
    fn a_raop_instance_without_a_real_address_says_nothing() {
        for instance in [
            "Apple TV",
            "me@home",
            "5855CA1AE2@Apple TV",
            "AABBCCDDEEFF@shairport",
        ] {
            let msg = message(vec![record(
                "_raop._tcp.local",
                dns::TYPE_PTR,
                dns::RData::Name(format!("{instance}._raop._tcp.local")),
            )]);
            assert!(from_mdns(&msg).is_empty(), "believing {instance}");
        }
    }

    /// AirPlay's `TXT` carries `deviceid`, the receiver's address in the
    /// ordinary colon-separated form. Constructed from the `_airplay._tcp` key
    /// list, with the same Apple address as the `_raop` fixture because on a
    /// real device the two agree.
    #[test]
    fn airplay_states_its_device_id() {
        let msg = message(vec![txt(
            "Apple TV._airplay._tcp.local",
            &[
                "deviceid=58:55:CA:1A:E2:88",
                "model=AppleTV6,2",
                "features=0x5A7FFFF7,0xE",
            ],
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("58:55:ca:1a:e2:88"), Route::AirPlay)]
        );
    }

    /// **The one that would have libelled every Chromecast on the network.**
    /// Google Cast's `bs` is twelve hex digits with the local bit *set*:
    /// `FA8FCA890C6C` is in no registry at all, and `F88FCA` is Google. Taken
    /// raw it would have read as a randomised address on a device that
    /// randomised nothing — a false claim of exactly the kind the randomised
    /// rule exists to prevent. So the bit is cleared, the cleared form has to
    /// resolve, and the cleared form is what is kept.
    ///
    /// Constructed from a Chromecast's advertised key set.
    #[test]
    fn google_cast_states_its_address_with_the_local_bit_set() {
        let msg = message(vec![txt(
            "Chromecast-1a2b._googlecast._tcp.local",
            &["id=8ba1a2b3c4d5e6f7", "md=Chromecast", "bs=FA8FCA890C6C"],
        )]);
        let found = from_mdns(&msg);
        assert_eq!(
            found,
            vec![Claim::new(mac("f8:8f:ca:89:0c:6c"), Route::Cast)]
        );
        assert!(!found[0].mac.is_randomised(), "it randomised nothing");
        assert_eq!(
            vendor::lookup(found[0].mac).name(),
            Some("Google, Inc."),
            "and the maker is the point of taking it at all"
        );
    }

    /// The same key with a value that resolves to nobody once the bit is
    /// cleared. Nothing is claimed, because the inference is only worth
    /// anything where the registry agrees with it.
    #[test]
    fn a_cast_id_that_names_no_maker_is_not_an_address() {
        let msg = message(vec![txt(
            "thing._googlecast._tcp.local",
            &["bs=AABBCCDDEEFF"],
        )]);
        assert!(from_mdns(&msg).is_empty());
    }

    /// **The road not taken, and it is the one that looks most like a road.**
    /// HomeKit's `_hap._tcp` `TXT` carries `id=`, six colon-separated hex
    /// octets — indistinguishable from a hardware address by shape. The HAP
    /// specification says it is a random accessory identifier, that it
    /// persists across reboots and that it is regenerated on a factory reset:
    /// it is not the interface's address and nobody assigned it, so no
    /// registry has anything to say about it.
    ///
    /// Worse than useless if it were taken. Such an identifier usually carries
    /// the local bit, so it would be reported as "randomised" — a true-looking
    /// answer from a false premise, on a row where nothing else would look
    /// wrong. So `id` is not a key this module knows, in `_hap` or anywhere
    /// else, and the record is read for its accessory category and nothing
    /// more.
    ///
    /// Fixture constructed from the HAP specification's `TXT` key list.
    #[test]
    fn a_homekit_accessory_id_is_never_a_hardware_address() {
        for service in ["_hap._tcp", "_hap._udp"] {
            let msg = message(vec![txt(
                &format!("Lamp 2B3C.{service}.local"),
                &["c#=2", "id=B2:4C:71:E1:0F:9A", "md=Hue go", "ci=5"],
            )]);
            assert!(
                from_mdns(&msg).is_empty(),
                "a HAP id is an identity, not an address"
            );
        }
    }

    /// A Shelly names itself after the last three octets of its address, and
    /// three octets are not an OUI: read as a prefix they would name a
    /// manufacturer picked at random out of the registry. The name is already
    /// kept as a name, and no address comes out of it.
    #[test]
    fn a_shelly_name_carries_a_suffix_and_not_an_address() {
        let msg = message(vec![
            record(
                "_shelly._tcp.local",
                dns::TYPE_PTR,
                dns::RData::Name("shellyplug-s-6A78B4._shelly._tcp.local".into()),
            ),
            srv(
                "shellyplug-s-6A78B4._shelly._tcp.local",
                "shelly-6a78b4.local",
            ),
        ]);
        assert!(from_mdns(&msg).is_empty());
    }

    /// And a key in a service that does not mean it by it. `deviceid` is
    /// believed under `_airplay._tcp` and nowhere else, which is what stops a
    /// key spreading to a protocol that means something different.
    #[test]
    fn a_device_id_outside_airplay_is_not_read() {
        let msg = message(vec![txt(
            "thing._http._tcp.local",
            &["deviceid=58:55:CA:1A:E2:88"],
        )]);
        assert!(from_mdns(&msg).is_empty());
    }

    /// Matter's specification builds the DNS-SD host name out of the 48-bit
    /// MAC as twelve hex digits. Constructed from that rule, with the
    /// operational service's 64-hex instance name; the address is an Espressif
    /// block, which is what most Matter silicon is.
    #[test]
    fn a_matter_host_name_is_the_address() {
        let msg = message(vec![srv(
            "0123456789ABCDEF-8FC7772401CD0696._matter._tcp.local",
            "F4CFA2F75C84.local",
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("f4:cf:a2:f7:5c:84"), Route::Matter)]
        );
    }

    /// The commissionable half of the same protocol, over UDP.
    #[test]
    fn a_commissionable_matter_host_name_is_read_too() {
        let msg = message(vec![srv(
            "F1B2C3D4E5F60708._matterc._udp.local",
            "F4CFA2F75C84.local",
        )]);
        assert_eq!(
            from_mdns(&msg),
            vec![Claim::new(mac("f4:cf:a2:f7:5c:84"), Route::Matter)]
        );
    }

    /// The specification's other permitted form is the Thread extended
    /// address, sixteen hex digits. An EUI-64 is not a MAC and is frequently
    /// generated at random, so it must never reach the vendor table: sixteen
    /// digits are read as no answer, and a blank hardware column is an answer.
    #[test]
    fn a_sixty_four_bit_matter_host_name_is_refused() {
        let msg = message(vec![srv(
            "0123456789ABCDEF-8FC7772401CD0696._matter._tcp.local",
            "F4CFA2F75C840123.local",
        )]);
        assert!(from_mdns(&msg).is_empty());
    }

    /// A twelve-hex host name that is not a Matter service's is not read, and
    /// neither is one no manufacturer holds.
    #[test]
    fn a_hex_host_name_proves_nothing_on_its_own() {
        let elsewhere = message(vec![srv("thing._http._tcp.local", "F4CFA2F75C84.local")]);
        assert!(from_mdns(&elsewhere).is_empty());

        let unregistered = message(vec![srv(
            "0123456789ABCDEF-8FC7772401CD0696._matter._tcp.local",
            "AABBCCDDEEFF.local",
        )]);
        assert!(from_mdns(&unregistered).is_empty());
    }

    /// One reply naming several routes at once, which is what a generous
    /// responder actually sends: it is one device and the claims agree, so
    /// both are kept and [`Route`]'s order settles which is shown.
    #[test]
    fn several_routes_in_one_reply_are_all_read() {
        let msg = message(vec![
            record(
                "_raop._tcp.local",
                dns::TYPE_PTR,
                dns::RData::Name("5855CA1AE288@Apple TV._raop._tcp.local".into()),
            ),
            txt(
                "Apple TV._airplay._tcp.local",
                &["deviceid=58:55:CA:1A:E2:88"],
            ),
        ]);
        let found = from_mdns(&msg);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|c| c.mac == mac("58:55:ca:1a:e2:88")));
    }

    /// A randomised address published in a field that means the interface's
    /// own is a fact, and it is carried as one: the lookup is what says
    /// "randomised", and refusing the value would leave the row looking as
    /// though nothing had answered. This is only true of the routes that read
    /// a field rather than infer from an identifier; see [`Test`].
    #[test]
    fn a_randomised_address_a_device_published_is_still_carried() {
        let msg = message(vec![srv(
            "phone [b2:11:22:33:44:55]._workstation._tcp.local",
            "phone.local",
        )]);
        let found = from_mdns(&msg);
        assert_eq!(found.len(), 1);
        assert!(found[0].mac.is_randomised());
        assert_eq!(vendor::lookup(found[0].mac), Origin::Randomised);
        assert!(!found[0].route.is_inferred());
    }

    /// The two shapes nothing on a network holds, refused on every route: a
    /// multicast address, and the all-zero one a field nobody filled in reads
    /// as.
    #[test]
    fn a_multicast_or_empty_address_is_not_a_device() {
        for text in ["01:00:5e:00:00:fb", "00:00:00:00:00:00"] {
            let msg = message(vec![srv(
                &format!("host [{text}]._workstation._tcp.local"),
                "host.local",
            )]);
            assert!(from_mdns(&msg).is_empty(), "believing {text}");
        }
    }

    /// Sonos writes its own address into the `USN` after `RINCON_`, then a
    /// port and a serial. Constructed from that form; `949F3E` is a Sonos
    /// block, as is the truncated `48A6B8` already in `ssdp.rs`'s fixture.
    /// **Twelve digits and no more** — the tail is the port and the serial and
    /// reading the whole of it would give an address of the wrong length.
    #[test]
    fn a_sonos_usn_names_the_address() {
        let claim =
            from_usn("uuid:RINCON_949F3EC0A1B201400::urn:schemas-upnp-org:device:ZonePlayer:1")
                .expect("a Sonos identifier");
        assert_eq!(claim, Claim::new(mac("94:9f:3e:c0:a1:b2"), Route::Sonos));
    }

    /// A version 1 uuid is the time-and-MAC algorithm and its node field is
    /// the interface's address. This is the identifier out of `ssdp.rs`'s own
    /// `a_bare_identifier_is_not_a_type` fixture, whose node is a Philips
    /// Lighting block.
    #[test]
    fn a_version_one_uuid_names_the_address() {
        let claim = from_usn("uuid:2f402f80-da50-11e1-9b23-0017881b1cc6::upnp:rootdevice")
            .expect("a time-and-MAC uuid");
        assert_eq!(claim, Claim::new(mac("00:17:88:1b:1c:c6"), Route::UpnpUuid));
    }

    /// **The negative that matters most.** A version 4 uuid is 122 bits of
    /// randomness and its last twelve digits are a number that has never named
    /// anything. Reading them would put a vendor beside every device whose
    /// firmware uses a random identifier, which is most of them — invented
    /// data, which is the worst thing this feature could produce. The node of
    /// the version 4 case below is a real Apple block, so shape and registry
    /// both agree with it and only the version says no.
    #[test]
    fn a_random_uuid_is_not_an_address() {
        for usn in [
            // Version 4, random, with a node that would resolve.
            "uuid:9f2c1b6e-5a3d-4c8f-9e21-3c22fb112233::upnp:rootdevice",
            // Version 3, an MD5 name hash.
            "uuid:9f2c1b6e-5a3d-3c8f-9e21-3c22fb112233",
            // Version 5, a SHA-1 name hash.
            "uuid:9f2c1b6e-5a3d-5c8f-9e21-3c22fb112233",
        ] {
            assert_eq!(from_usn(usn), None, "believing {usn}");
        }
    }

    /// RFC 4122 §4.5: a version 1 generator with no hardware address to use
    /// invents a node and sets its multicast bit to say so. That bit is the
    /// generator telling us not to read it, and it is read.
    #[test]
    fn an_invented_node_says_so_and_is_refused() {
        assert_eq!(
            from_usn("uuid:2f402f80-da50-11e1-9b23-0117881b1cc6"),
            None,
            "the multicast bit means the node was made up"
        );
    }

    /// A version 1 uuid whose node is in no registry. The algorithm is right
    /// and the number still names nobody, so nothing is claimed.
    #[test]
    fn a_version_one_node_that_names_no_maker_is_refused() {
        assert_eq!(from_usn("uuid:2f402f80-da50-11e1-9b23-aabbccddeeff"), None);
    }

    /// The legacy variants put their fields somewhere else entirely, so the
    /// low bits of one are not a node at all.
    #[test]
    fn a_uuid_that_is_not_rfc_4122_is_refused() {
        // Variant nibble `c`, which is Microsoft's legacy layout.
        assert_eq!(from_usn("uuid:2f402f80-da50-11e1-cb23-0017881b1cc6"), None);
    }

    /// A WS-Discovery endpoint reference is a uuid under the same rule, and
    /// Windows generates a version 4 one — so the common case is correctly no
    /// answer, and only a device whose endpoint was built the old way says
    /// anything.
    #[test]
    fn a_wsd_endpoint_takes_the_same_version_guard() {
        assert_eq!(
            from_endpoint("urn:uuid:2f402f80-da50-11e1-9b23-0017881b1cc6"),
            Some(Claim::new(mac("00:17:88:1b:1c:c6"), Route::WsdUuid))
        );
        assert_eq!(
            from_endpoint("urn:uuid:cafe0001-0000-0000-0000-00000000abcd"),
            None,
            "the version nibble is 0, which is no version at all"
        );
    }

    #[test]
    fn rubbish_in_a_usn_is_not_an_address() {
        for usn in [
            "",
            "uuid:",
            "uuid:not-a-uuid",
            "urn:schemas-upnp-org:device:MediaRenderer:1",
            "uuid:2f402f80-da50-11e1-9b23-0017881b1cc",
            "uuid:RINCON_ZZZZZZZZZZZZ01400",
            "uuid:RINCON_949F3E",
        ] {
            assert_eq!(from_usn(usn), None, "believing {usn:?}");
        }
    }

    /// The identifier itself, which is worth keeping whether or not an address
    /// came out of it: UPnP requires a `UDN` to survive a reboot, which makes
    /// it the most stable thing a television ever says. **Every version is
    /// kept** — the guard is on the address, not on the identity.
    #[test]
    fn the_identifier_is_kept_whole_whatever_the_uuid_is() {
        assert_eq!(
            udn_of("uuid:9f2c1b6e-5a3d-4c8f-9e21-3c22fb112233::upnp:rootdevice").as_deref(),
            Some("uuid:9f2c1b6e-5a3d-4c8f-9e21-3c22fb112233")
        );
        assert_eq!(
            udn_of("uuid:RINCON_949F3EC0A1B201400").as_deref(),
            Some("uuid:RINCON_949F3EC0A1B201400")
        );
        assert_eq!(udn_of("upnp:rootdevice"), None);
        assert_eq!(udn_of("uuid:"), None);
    }

    /// The priority is the enum's own order, so a device that stated the same
    /// address by two routes is shown the stronger one.
    #[test]
    fn the_routes_rank_from_stated_to_inferred() {
        let mut routes = vec![Route::UpnpUuid, Route::Cast, Route::NetBios, Route::EspHome];
        routes.sort_unstable();
        assert_eq!(
            routes,
            vec![Route::NetBios, Route::EspHome, Route::Cast, Route::UpnpUuid],
            "a field that means the address first, an identifier's low bits last"
        );
        assert!(!Route::NetBios.is_inferred());
        assert!(Route::UpnpUuid.is_inferred());
    }
}
