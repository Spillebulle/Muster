//! SSDP: asking a device to announce itself, and reading what it says.
//!
//! Part of phase four, and the piece that was missing from it. mDNS is how
//! Apple devices, printers and anything running Avahi describe themselves;
//! SSDP is how nearly everything *else* does — televisions, set-top boxes,
//! media players, routers, network printers and the Windows machines that have
//! network discovery switched on. A network where mDNS finds three devices
//! commonly has a dozen answering here.
//!
//! ## Unicast, not multicast
//!
//! The protocol's own shape is a multicast `M-SEARCH` to `239.255.255.250:1900`
//! and a shower of unicast replies from everything on the link. That is one
//! datagram for a whole network, and it is tempting, but it does not fit: the
//! reply carries no reliable statement of *which* address it came from beyond
//! the source of the datagram, discovery would run before the sweep knows which
//! addresses exist, and one device answering seven times would need dividing up
//! again afterwards. Identification is already per-device and already has a
//! rate limiter and a worker pool, so the search goes to the device directly.
//! UPnP 1.1 §1.3.2 provides for exactly this — a unicast search, with `HOST`
//! naming the device rather than the group.
//!
//! `MX` is included even though a 1.1 sender is told not to use it on a unicast
//! search, because a 1.0-era responder can require it and no responder has ever
//! been observed to reject it. The cost of being wrong in one direction is a
//! silent device; in the other it is nothing.
//!
//! ## One search, several replies
//!
//! A device answers `ST: ssdp:all` once per device and service it hosts, which
//! is why [`crate::identify::Ask::ask_all`] exists: a television replies as a
//! root device, as a `MediaRenderer`, as a DIAL server and as three services,
//! and the interesting one is rarely the first to arrive. Taking only the first
//! datagram would have made the answer depend on the order the device happened
//! to send in, which is the same defect the mDNS table's ordering note is
//! about.
//!
//! ## What is read here, and what is read next door
//!
//! The headers, and nothing more. That is enough for a kind: `SERVER` and the
//! device type URNs are in the datagram already, they cost no connection, and
//! they are what this module is for.
//!
//! **The `LOCATION` is the exception, and following it is [`crate::igd`]'s
//! job.** It points at an XML description carrying the manufacturer, the model
//! name and often a serial number, and on a router it carries the control URL
//! that leads to the port forwards and the public address as well. All of that
//! costs a TCP request per device, which is a different shape of question from
//! a datagram and is off by default for the reason
//! [`crate::igd::Options`] gives, so it lives beside this module rather than
//! inside it. What is kept here is the header, unfollowed, which is the honest
//! division: this module reads what arrived, and the other one decides whether
//! to open a connection about it.

use crate::identify::Ask;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Where SSDP listens. Fixed by the standard.
pub const PORT: u16 = 1900;

/// The group every device on the link is listening to.
pub const GROUP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), PORT);

/// How long a device may wait before answering, in seconds.
///
/// A responder spreads its replies at random across this window so that a
/// hundred devices do not answer a search in the same millisecond. Two is the
/// usual choice: long enough to be honoured by the stacks that honour it, short
/// enough that a scan is not left waiting on it.
const MX: u8 = 2;

/// An `M-SEARCH` for everything on the link.
///
/// `to` is what goes in `HOST`, and it is [`GROUP`] for the search this module
/// sends. It is a parameter rather than an assumption so that the request can
/// be aimed at a single device, which the protocol allows and which almost
/// nothing answers; see the module note.
pub fn search(to: SocketAddr) -> Vec<u8> {
    search_target(to, "ssdp:all")
}

/// The same request, aimed at one kind of device.
///
/// **A minority of responders answer their own type and ignore `ssdp:all`.**
/// A Hue bridge is the clearest case, and some Roku and Sonos firmware behaves
/// the same way; the specification does not permit it and the devices do it
/// anyway. So [`crate::link`] sends a handful of these beside the search for
/// everything, each aimed at a device that would otherwise be a blank row.
pub fn search_target(to: SocketAddr, target: &str) -> Vec<u8> {
    // `MAN` is quoted, and the quotes are part of the token rather than
    // decoration: a responder comparing against `"ssdp:discover"` literally,
    // as the specification writes it, does not answer `ssdp:discover`.
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {to}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {MX}\r\n\
         ST: {target}\r\n\
         \r\n"
    )
    .into_bytes()
}

/// How many datagrams a search will read before it stops listening.
///
/// A link with a television, a router and a media server on it produces some
/// forty; the cap bounds what a hostile responder can make this allocate, and
/// is not a target.
const MOST: usize = 512;

/// Searches the link, and returns what answered, by address.
///
/// One datagram out. Everything that comes back inside `window` is attributed
/// to the address it came from, which is the whole of SSDP's addressing: a
/// reply is an ordinary unicast datagram from the device, and there is nothing
/// else in it that says who sent it.
///
/// Never fails. A link where nothing answers and a machine where the datagram
/// could not be sent both give an empty map, because neither is a fact about a
/// device and the caller has nothing different to do about them.
pub fn discover<A: Ask + ?Sized>(ask: &A, window: Duration) -> BTreeMap<IpAddr, Vec<Announcement>> {
    collect(ask, &search(GROUP), window)
}

/// Sends one search and reads everything that answers it.
fn collect<A: Ask + ?Sized>(
    ask: &A,
    request: &[u8],
    window: Duration,
) -> BTreeMap<IpAddr, Vec<Announcement>> {
    let mut found: BTreeMap<IpAddr, Vec<Announcement>> = BTreeMap::new();
    let Ok(replies) = ask.ask_all(GROUP, request, window, MOST) else {
        return found;
    };
    for (from, reply) in replies {
        let Some(announcement) = parse(&reply) else {
            continue;
        };
        let seen = found.entry(from).or_default();
        // A device repeats its `SERVER` on every reply, and repeats whole
        // announcements when it hosts one service under two root devices.
        if !seen.contains(&announcement) {
            seen.push(announcement);
        }
    }
    found
}

/// Searches the link for one kind of device, and returns what answered.
///
/// [`discover`] with an `ST` of its own. Separate rather than a parameter on
/// `discover` because the two are asked for different reasons and the ordinary
/// one should stay the ordinary one to call.
pub fn search_for<A: Ask + ?Sized>(
    ask: &A,
    target: &str,
    window: Duration,
) -> BTreeMap<IpAddr, Vec<Announcement>> {
    collect(ask, &search_target(GROUP, target), window)
}

/// What one SSDP datagram said about the device that sent it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Announcement {
    /// The device or service type this reply is about: `ST` on a search reply,
    /// `NT` on an unsolicited notification.
    pub target: Option<String>,
    /// `USN`, which repeats the type after the device's `uuid:`. Kept because
    /// a few implementations fill it in and leave `ST` as `upnp:rootdevice`.
    pub usn: Option<String>,
    /// `SERVER`: the operating system and product, in HTTP product-token form.
    /// `Linux/4.19 UPnP/1.0 LG WebOS TV/1.0` names a television outright.
    pub server: Option<String>,
    /// Where the XML description lives.
    ///
    /// Read out of the datagram and left alone here. It is **text a device
    /// wrote**, so nothing in this module treats it as an address, and
    /// [`crate::igd::describe`] refuses it outright unless it names the device
    /// that sent it: a `LOCATION` of `http://example.com/` would otherwise have
    /// this machine open a connection to the internet on a stranger's say-so.
    pub location: Option<String>,
}

impl Announcement {
    /// The device's own identifier, out of `USN`, kept whole.
    ///
    /// **This used to be thrown away.** [`Self::types`] splits `USN` on the
    /// `::` and keeps the half after it, and the half before it — the `UDN` —
    /// was dropped on the floor. UPnP Device Architecture requires that
    /// identifier to be fixed over time and to survive a reboot, which makes
    /// it the most stable thing a television or a set-top box ever says about
    /// itself, and those are precisely the devices ARP is worst at. Carried as
    /// an opaque string; nothing here reads meaning into it beyond
    /// [`Self::hardware`].
    pub fn udn(&self) -> Option<String> {
        self.usn.as_deref().and_then(crate::claim::udn_of)
    }

    /// The hardware address this reply states, where it states one.
    ///
    /// A `UDN` is an identifier rather than an address field, and two of the
    /// ways one is built put the interface's address in it: Sonos writes it
    /// after `RINCON_`, and the RFC 4122 time-and-MAC algorithm that UPnP
    /// recommends puts it in the node field. Neither is a promise, so
    /// [`crate::claim`] checks the shape before believing it and the route is
    /// carried beside the address all the way to the screen.
    pub fn hardware(&self) -> Option<crate::claim::Claim> {
        self.usn.as_deref().and_then(crate::claim::from_usn)
    }

    /// Every type this reply claims, both the header's and the one folded into
    /// `USN`, lower cased for matching.
    pub fn types(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |value: &str| {
            let value = value.trim().to_ascii_lowercase();
            // `upnp:rootdevice` and a bare `uuid:` say only "a UPnP device is
            // here", which the reply itself already said.
            if value.is_empty() || value == "upnp:rootdevice" || value.starts_with("uuid:") {
                return;
            }
            if !out.contains(&value) {
                out.push(value);
            }
        };
        if let Some(target) = &self.target {
            push(target);
        }
        // `USN` is `uuid:<id>::<type>`, so the type is what follows the double
        // colon. A `USN` without one is the device's identifier alone.
        if let Some(usn) = &self.usn
            && let Some((_, kind)) = usn.split_once("::")
        {
            push(kind);
        }
        out
    }
}

/// Reads one SSDP datagram.
///
/// Accepts both a search reply (`HTTP/1.1 200 OK`) and a notification
/// (`NOTIFY * HTTP/1.1`), because a device that is announcing itself while the
/// search runs is saying the same thing by a different verb. Anything else —
/// including the `M-SEARCH` of another scanner on the link — is not an answer
/// and yields [`None`].
pub fn parse(buf: &[u8]) -> Option<Announcement> {
    // The headers are ASCII by specification. A device with a non-ASCII model
    // name in `SERVER` does exist, so the body is read lossily rather than
    // thrown away for one bad byte.
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split('\n');
    let start = lines.next()?.trim_end_matches('\r').trim();
    let ok = start.starts_with("HTTP/1.1 200") || start.starts_with("HTTP/1.0 200");
    if !ok && !start.to_ascii_uppercase().starts_with("NOTIFY ") {
        return None;
    }

    let mut found = Announcement::default();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        // Header names are case-insensitive, and devices use every casing there
        // is: `ST`, `St`, `Server`, `SERVER`, `Location`.
        match name.trim().to_ascii_uppercase().as_str() {
            "ST" | "NT" => found.target = Some(value),
            "USN" => found.usn = Some(value),
            "SERVER" => found.server = Some(value),
            "LOCATION" => found.location = Some(value),
            _ => {}
        }
    }

    // A datagram with the right first line and none of the headers that matter
    // is not worth carrying up.
    if found.target.is_none() && found.usn.is_none() && found.server.is_none() {
        return None;
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Sonos speaker's reply, as recorded.
    const SONOS: &[u8] = b"HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=1800\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.51:1400/xml/device_description.xml\r\n\
SERVER: Linux UPnP/1.0 Sonos/70.3-35220\r\n\
ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
USN: uuid:RINCON_48A6B8::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n";

    #[test]
    fn a_search_names_the_device_it_is_sent_to() {
        let q = String::from_utf8(search("192.168.1.51:1900".parse().unwrap())).unwrap();
        assert!(q.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(q.contains("HOST: 192.168.1.51:1900\r\n"));
        assert!(q.contains("MAN: \"ssdp:discover\""));
        assert!(q.ends_with("\r\n\r\n"), "the blank line ends the request");
    }

    #[test]
    fn a_reply_gives_its_type_and_its_product() {
        let a = parse(SONOS).expect("a well formed reply");
        assert_eq!(
            a.target.as_deref(),
            Some("urn:schemas-upnp-org:device:ZonePlayer:1")
        );
        assert_eq!(a.server.as_deref(), Some("Linux UPnP/1.0 Sonos/70.3-35220"));
        assert_eq!(
            a.location.as_deref(),
            Some("http://192.168.1.51:1400/xml/device_description.xml")
        );
    }

    #[test]
    fn header_names_are_read_whatever_their_casing() {
        let reply = b"HTTP/1.1 200 OK\r\nSt: urn:dial-multiscreen-org:service:dial:1\r\n\
Server: Roku/12.0.0 UPnP/1.0 Roku/12.0.0\r\n\r\n";
        let a = parse(reply).expect("a reply");
        assert_eq!(
            a.target.as_deref(),
            Some("urn:dial-multiscreen-org:service:dial:1")
        );
        assert!(a.server.is_some());
    }

    /// The type in `USN` is taken as well, because some devices leave `ST` as
    /// the root device and put what they are only there.
    #[test]
    fn the_type_folded_into_usn_is_taken_too() {
        let reply = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\
USN: uuid:2f402f80::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";
        let a = parse(reply).expect("a reply");
        assert_eq!(
            a.types(),
            vec!["urn:schemas-upnp-org:device:mediarenderer:1"],
            "the root device says nothing and is dropped; the USN type is kept"
        );
    }

    #[test]
    fn a_bare_identifier_is_not_a_type() {
        let reply = b"HTTP/1.1 200 OK\r\nST: uuid:2f402f80-da50-11e1-9b23-0017881b1cc6\r\n\
SERVER: Linux/3.4 UPnP/1.0\r\n\r\n";
        let a = parse(reply).expect("a reply");
        assert!(a.types().is_empty(), "a uuid names nothing");
    }

    #[test]
    fn a_notification_is_read_as_an_announcement() {
        let reply = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
NTS: ssdp:alive\r\nSERVER: Linux/2.6 UPnP/1.0 MiniUPnPd/1.9\r\n\r\n";
        let a = parse(reply).expect("a notification is an announcement");
        assert_eq!(
            a.types(),
            vec!["urn:schemas-upnp-org:device:internetgatewaydevice:1"]
        );
    }

    /// Another scanner's search arriving on the socket is not an answer.
    #[test]
    fn a_search_is_not_a_reply() {
        let other = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n";
        assert_eq!(parse(other), None);
    }

    #[test]
    fn rubbish_is_not_an_announcement() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"\x00\x01\x02\x03"), None);
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\n\r\n"),
            None,
            "no headers worth it"
        );
    }
}
