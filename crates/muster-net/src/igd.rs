//! Following a `LOCATION`: the UPnP description, and what a gateway will say
//! about itself.
//!
//! **The gateway is the best-documented device on the link and Muster has never
//! asked it anything.** Every SSDP reply carries a `LOCATION` header pointing
//! at an XML description, [`crate::ssdp`] has read that header since the day it
//! was written, and nothing has ever fetched the document. Three things come
//! out of following it, and they are three different sizes of answer.
//!
//! ## One: what the device says it is
//!
//! [`Description`] is the manufacturer, the model name, the model number and
//! often a serial number, in the device's own words, for **every** device that
//! answers SSDP rather than only for the router. It is one connection per
//! device, which is why it is off by default; see [`Options`].
//!
//! What comes back is a model string, and a model string is
//! [`crate::kind::Clue::Product`] — **below a service**, for the reason that
//! clue documents at length. Samba's `fruit:model` has every NAS on the network
//! advertising `MacPro7,1`, and a UPnP `modelName` is free text in exactly the
//! same way. It is precise and it is not authoritative, and the ranking is what
//! keeps those two facts apart.
//!
//! ## Two: every port forward on the router
//!
//! An Internet Gateway Device publishes `GetGenericPortMappingEntry`, which
//! walks its forwarding table by index. Asking it from zero until it stops
//! enumerates **every port forward the router is doing** — including the ones a
//! games console, a torrent client or a compromised camera opened for itself
//! without anybody being asked. That is frequently the most alarming thing a
//! scan of a home network can produce, and it takes no credential of any kind:
//! IGD is deliberately open to the LAN, which is the whole reason the answer is
//! worth having.
//!
//! **It is presented as facts and not graded.** External port, internal client,
//! protocol, description, lease. Muster does not decide that a forward is
//! dangerous, because that depends on what is behind it, and a scanner that
//! cries wolf over a deliberate one teaches its user to ignore the column.
//!
//! **The line this module does not cross is writing.** IGD defines two actions
//! that change a router's forwarding table, one to add a mapping and one to
//! remove it, and neither is implemented here — not behind a switch, not behind
//! a confirmation. Muster looks at networks; a write to somebody's gateway is a
//! different argument and this project has not had it. The guard is structural:
//! [`Action`] is an enum, [`Control::call`] takes one, and a write cannot be
//! spelled without adding a variant. A test reads this file's own source and
//! fails if either name appears in it.
//!
//! ## Three: the public address, without asking the internet
//!
//! `GetExternalIPAddress`. Every other tool learns a public address by asking a
//! service on the internet, which is a lookup leaving the machine and is
//! forbidden here outright — `CLAUDE.md`'s conduct rule allows exactly one
//! outbound request and it is the update check. The router already knows, it is
//! on the LAN, and asking it sends nothing outside.
//!
//! **Where there is no IGD the answer is blank.** There is no fallback to an
//! external service and there will not be one. That strictness is the feature:
//! a blank means "this network has no gateway that would say", which is itself
//! worth knowing, and it is a fact rather than a number obtained by telling
//! somebody else what network this is.
//!
//! ## Two more, because the control URL was already in hand
//!
//! [`Status`] is the WAN connection's state and how long it has been up, and
//! [`Traffic`] is the byte counters. Both are one call each on a service the
//! description has already named, so they cost a request and no new machinery.
//! The counters are `ui4` in the specification and wrap at four gigabytes on
//! most firmware, which is a property of the answer rather than a defect, so it
//! is written down here and the number is passed through as given.

use crate::http::{self, Session, Url, Wire};
use crate::rate::Bucket;
use crate::ssdp;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// The service types that answer the questions above, matched without their
/// trailing version.
///
/// A gateway publishes its WAN connection as `WANIPConnection` when it holds
/// the address itself and `WANPPPConnection` when the link is PPPoE, which is
/// most DSL. They answer the same actions, so both are looked for and the first
/// found is used.
pub const WAN_SERVICES: [&str; 2] = [
    "urn:schemas-upnp-org:service:wanipconnection",
    "urn:schemas-upnp-org:service:wanpppconnection",
];

/// Where the byte counters live, which is not the connection service.
pub const WAN_COMMON: &str = "urn:schemas-upnp-org:service:wancommoninterfaceconfig";

/// The most port mappings that will be walked.
///
/// A home router holds a handful and a busy one holds dozens. The cap is not a
/// judgement about how many is too many; it is what stops a device that answers
/// every index for ever from turning one scan into an unbounded loop.
pub const MOST_MAPPINGS: usize = 256;

/// What a router says when the index is past the end of its table.
///
/// 713, `SpecifiedArrayIndexInvalid`, is what the service template specifies,
/// and 402 is what several firmwares substitute for it. **Only these two end
/// the walk quietly.** Any other refusal is the router declining to answer
/// rather than saying it has nothing more, and the difference is the whole of
/// [`Wan::mappings_cut_short`]: a list that stopped early must not be shown as
/// the complete one.
const END_OF_TABLE: [u16; 2] = [713, 402];

/// How long a field a device names for itself is worth keeping.
///
/// A model name is a few words and a mapping's description is a line. A device
/// sending a paragraph is not naming a model, and the table is not the place to
/// discover that.
const SHORT: usize = 96;

/// The same, for a URL, which is legitimately longer than a label.
const URL_MOST: usize = 256;

// ---------------------------------------------------------------------------
// Reading XML
// ---------------------------------------------------------------------------

/// Where each element with this local name starts, and the raw text inside it.
///
/// Local name, so `<service>` and `<u:service>` are the same element: UPnP
/// documents are written with and without a prefix by different stacks and the
/// prefix is never the meaning. Nesting of an element inside another of its own
/// name is counted, which `<deviceList><device>` needs and which is the case a
/// simple search-for-the-closing-tag reader gets wrong.
fn scan<'a>(xml: &'a str, name: &str) -> Vec<(usize, &'a str)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut opened = 0usize;
    let mut body = 0usize;
    let mut at = 0usize;

    while at < xml.len() {
        let Some(found) = xml[at..].find('<') else {
            break;
        };
        let open = at + found;
        // Comments, the declaration and a doctype are not elements, and a
        // comment may contain something that looks like one.
        if xml[open..].starts_with("<!--") {
            match xml[open..].find("-->") {
                Some(shut) => {
                    at = open + shut + 3;
                    continue;
                }
                None => break,
            }
        }
        if xml[open..].starts_with("<?") || xml[open..].starts_with("<!") {
            match xml[open..].find('>') {
                Some(shut) => {
                    at = open + shut + 1;
                    continue;
                }
                None => break,
            }
        }
        let Some(shut) = xml[open..].find('>') else {
            break;
        };
        let shut = open + shut;
        let inside = &xml[open + 1..shut];
        at = shut + 1;

        let closing = inside.starts_with('/');
        let empty = inside.ends_with('/');
        let local = inside
            .trim_matches('/')
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit(':')
            .next()
            .unwrap_or("");
        if local != name {
            continue;
        }

        if empty && !closing {
            // `<serialNumber/>`: the element is there and says nothing, which
            // is a different answer from not being there and is not one this
            // has to tell apart.
            if depth == 0 {
                out.push((open, ""));
            }
            continue;
        }
        if closing {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                out.push((opened, &xml[body..open]));
            }
        } else {
            if depth == 0 {
                opened = open;
                body = at;
            }
            depth += 1;
        }
    }
    out
}

/// The raw text of every element with this local name, at any depth.
fn elements<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    scan(xml, name).into_iter().map(|(_, body)| body).collect()
}

/// The first element with this local name.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    elements(xml, name).into_iter().next()
}

/// One element's text: decoded, trimmed, and shortened.
///
/// [`None`] for an element that is not there **and** for one that is there and
/// empty, because a manufacturer field with nothing in it is not a manufacturer
/// and carrying an empty string up would put a blank where the interface
/// expects a fact.
fn field(xml: &str, name: &str) -> Option<String> {
    text(element(xml, name)?, SHORT)
}

/// The same, for something that is legitimately long.
fn long_field(xml: &str, name: &str) -> Option<String> {
    text(element(xml, name)?, URL_MOST)
}

fn text(raw: &str, most: usize) -> Option<String> {
    // An element with a child in it is not a text field; a device that writes
    // markup into `modelName` is not naming a model.
    if raw.contains('<') {
        return None;
    }
    let decoded: String = decode(raw.trim()).chars().take(most).collect();
    let decoded = decoded.trim().to_string();
    (!decoded.is_empty()).then_some(decoded)
}

/// The five named entities XML defines, and numeric references.
///
/// `AT&amp;T` is the one that turns up in a manufacturer field, and a reader
/// that left it alone would put the ampersand's spelling in the table.
fn decode(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(shut) = rest.find(';').filter(|shut| *shut <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..shut];
        let replacement = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix('#')
                .and_then(|number| match number.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => number.parse::<u32>().ok(),
                })
                .and_then(char::from_u32),
        };
        match replacement {
            Some(c) => {
                out.push(c);
                rest = &rest[shut + 1..];
            }
            // Not an entity this knows, so it is part of the text.
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// The description
// ---------------------------------------------------------------------------

/// One service a described device offers, and where to speak to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    /// `urn:schemas-upnp-org:service:WANIPConnection:1`, as written.
    pub service_type: String,
    /// The `controlURL`, still as the description wrote it. Resolving it needs
    /// the description's own URL and the `URLBase`, which [`Described`] holds.
    pub control_url: Option<String>,
}

impl Service {
    /// Is this the service that type names, whatever version it is?
    ///
    /// The version is deliberately not compared. A gateway publishing
    /// `WANIPConnection:2` answers every action asked of it here, and a match
    /// that insisted on `:1` would ignore every IGD2 router on the market.
    pub fn is(&self, kind: &str) -> bool {
        let full = self.service_type.to_ascii_lowercase();
        let without_version = full
            .rsplit_once(':')
            .map_or(full.as_str(), |(head, _)| head);
        without_version == kind
    }
}

/// What a device's own description document says about it.
///
/// Every field is the device's own words, decoded and trimmed and nothing more.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Description {
    /// `deviceType`, which says what class of thing it claims to be.
    pub device_type: Option<String>,
    /// `friendlyName`. Often the name somebody typed into a setup page, so it
    /// is a name rather than a model and it is kept apart from one.
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub model_description: Option<String>,
    /// The serial number, where the device volunteers one. A great many do.
    pub serial_number: Option<String>,
    /// `UDN`, the device's own identifier. Stable across reboots on most
    /// firmware, which makes it the one thing here that could tell two
    /// identical models apart.
    pub udn: Option<String>,
    /// Every service in the document, including those of the devices embedded
    /// in it: a gateway publishes its WAN connection two levels down.
    pub services: Vec<Service>,
}

impl Description {
    pub fn is_empty(&self) -> bool {
        self.device_type.is_none()
            && self.friendly_name.is_none()
            && self.manufacturer.is_none()
            && self.model_name.is_none()
            && self.model_number.is_none()
            && self.model_description.is_none()
            && self.serial_number.is_none()
            && self.udn.is_none()
            && self.services.is_empty()
    }

    /// The model, in one string, for [`crate::kind`] to match against.
    ///
    /// Manufacturer then model then number, with each part dropped when it is
    /// already inside what came before and each part *replacing* what came
    /// before when it contains it. Firmware writes all four combinations and
    /// the repetition is the common one, so `Synology` followed by
    /// `Synology DS920+` is `Synology DS920+` rather than the maker's name
    /// said twice.
    ///
    /// **The friendly name is not in it**, and that is the point of the
    /// separation: `Dave's router` is a name somebody typed and would match
    /// nothing, while treating a hostname-shaped string as a model is the
    /// mistake `CLAUDE.md` records this project having made once already.
    pub fn product(&self) -> Option<String> {
        let mut out = String::new();
        for part in [&self.manufacturer, &self.model_name, &self.model_number] {
            let Some(part) = part.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
                continue;
            };
            let said = out.to_ascii_lowercase();
            let adding = part.to_ascii_lowercase();
            if said.contains(&adding) {
                continue;
            }
            if !out.is_empty() && adding.contains(&said) {
                out = part.to_string();
                continue;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(part);
        }
        // A manufacturer on its own names a company, not a model, and handing
        // one to the product table would have every device that answers SSDP
        // claiming to have named itself.
        let named = self.model_name.is_some() || self.model_number.is_some();
        (named && !out.is_empty()).then_some(out)
    }

    /// The first service of this type, at any depth.
    pub fn service(&self, kind: &str) -> Option<&Service> {
        self.services.iter().find(|service| service.is(kind))
    }

    /// The WAN connection service, whichever of the two a gateway publishes.
    pub fn wan(&self) -> Option<&Service> {
        WAN_SERVICES.into_iter().find_map(|kind| self.service(kind))
    }
}

/// A description, and the base every relative URL in it is resolved against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Described {
    pub description: Description,
    /// Where the document was fetched from.
    pub location: Url,
    /// The `URLBase` the document declared, where it declared one.
    ///
    /// UPnP 1.1 deprecated it and firmware still sends it, sometimes naming a
    /// port other than the one the description was served on. Where it is
    /// there it wins, because the device is stating outright where its control
    /// URLs live.
    pub base: Option<Url>,
}

impl Described {
    /// Turns a `controlURL` into somewhere a request can go.
    pub fn resolve(&self, relative: &str) -> Option<Url> {
        self.base.as_ref().unwrap_or(&self.location).join(relative)
    }
}

/// Reads a description document.
///
/// The identity fields are taken from the **root** device and no other, which
/// matters because a gateway's document describes three or four devices nested
/// inside each other and the innermost is a `WANConnectionDevice` whose
/// manufacturer is frequently blank or the name of the UPnP daemon. The root
/// device's own fields are written before its `deviceList`, so the root's text
/// is everything up to that element.
///
/// The services are taken from the whole document, which is the opposite choice
/// and the right one for the same reason: the service worth calling is in the
/// innermost device.
pub fn parse(xml: &str) -> Option<Description> {
    let root = elements(xml, "device").into_iter().next()?;
    // The root device's own fields end where its children begin. The list is
    // found by local name, so a prefixed `<d:deviceList>` cuts here too.
    let mine = match scan(root, "deviceList").first() {
        Some((at, _)) => &root[..*at],
        None => root,
    };

    let mut found = Description {
        device_type: field(mine, "deviceType"),
        friendly_name: field(mine, "friendlyName"),
        manufacturer: field(mine, "manufacturer"),
        model_name: field(mine, "modelName"),
        model_number: field(mine, "modelNumber"),
        model_description: field(mine, "modelDescription"),
        serial_number: field(mine, "serialNumber"),
        udn: field(mine, "UDN"),
        services: Vec::new(),
    };

    for raw in elements(xml, "service") {
        let Some(service_type) = field(raw, "serviceType") else {
            continue;
        };
        let service = Service {
            service_type,
            control_url: long_field(raw, "controlURL"),
        };
        if !found.services.contains(&service) {
            found.services.push(service);
        }
    }

    (!found.is_empty()).then_some(found)
}

/// Fetches and reads the description a `LOCATION` points at.
///
/// [`None`] where the URL is not `http`, where it names anywhere but the device
/// that gave it, where nothing answered, or where what answered was not a
/// description. All four are blanks, and a blank is an answer; none of them is
/// worth an error the interface would have to phrase.
pub fn describe<W: Wire + ?Sized>(session: &Session<'_, W>, location: &str) -> Option<Described> {
    let url = Url::parse(location)?;
    let response = session.get(&url).ok()?;
    if response.status != 200 {
        return None;
    }
    let body = response.text();
    let description = parse(&body)?;
    let base = long_field(&body, "URLBase")
        .and_then(|raw| url.join(&raw))
        // A `URLBase` naming another host is the same trick a `LOCATION` off
        // the link would be, and it is refused the same way rather than
        // quietly followed.
        .filter(|base| base.names(session.address));
    Some(Described {
        description,
        location: url,
        base,
    })
}

// ---------------------------------------------------------------------------
// SOAP
// ---------------------------------------------------------------------------

/// Every action this module can send.
///
/// **An enum rather than a string, and that is the guard.** IGD's two write
/// actions change a router's forwarding table, and a `call` taking a `&str`
/// would let the next question added here be one of them, by a typo or by a
/// good intention. Adding a write means adding a variant, which is a change
/// somebody has to make on purpose and a reviewer can see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// The public address, from the device that already knows it.
    ExternalAddress,
    /// One row of the forwarding table, by index.
    PortMapping,
    /// The WAN link's state and how long it has been up.
    StatusInfo,
    /// The byte counters, on the common interface service.
    BytesSent,
    BytesReceived,
}

impl Action {
    /// The name that goes in the envelope and in `SOAPACTION`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ExternalAddress => "GetExternalIPAddress",
            Self::PortMapping => "GetGenericPortMappingEntry",
            Self::StatusInfo => "GetStatusInfo",
            Self::BytesSent => "GetTotalBytesSent",
            Self::BytesReceived => "GetTotalBytesReceived",
        }
    }
}

/// A SOAP envelope for one action.
///
/// Built by hand rather than by a serialiser, and written a piece at a time
/// rather than as one continued literal: the request is fifteen lines of fixed
/// text with two substitutions in it, and the continued form is where a lost
/// backslash puts the source's indentation into what goes on the wire.
pub fn envelope(service_type: &str, action: Action, args: &[(&str, String)]) -> Vec<u8> {
    let name = action.name();
    let mut body = String::with_capacity(512);
    body.push_str("<?xml version=\"1.0\"?>\r\n");
    body.push_str("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"");
    body.push_str(" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n");
    body.push_str("<s:Body>\r\n<u:");
    body.push_str(name);
    body.push_str(" xmlns:u=\"");
    body.push_str(service_type);
    body.push_str("\">\r\n");
    for (argument, value) in args {
        body.push('<');
        body.push_str(argument);
        body.push('>');
        body.push_str(value);
        body.push_str("</");
        body.push_str(argument);
        body.push_str(">\r\n");
    }
    body.push_str("</u:");
    body.push_str(name);
    body.push_str(">\r\n</s:Body>\r\n</s:Envelope>\r\n");
    body.into_bytes()
}

/// What a device said when it would not answer.
///
/// UPnP puts its own error inside a SOAP fault, and the code is the useful
/// half: 713 is "there is no such index", which is how the walk below learns it
/// has reached the end of the table, and 401 is "that action is not
/// implemented", which is a gateway saying it does not do this at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fault {
    pub code: Option<u16>,
    pub description: Option<String>,
}

/// The fault in a reply, where the reply is one.
pub fn fault(body: &str) -> Option<Fault> {
    let inside = element(body, "UPnPError").or_else(|| element(body, "Fault"))?;
    Some(Fault {
        code: field(inside, "errorCode").and_then(|code| code.parse().ok()),
        description: field(inside, "errorDescription"),
    })
}

/// Why a call produced no answer, and the distinction the walk depends on.
///
/// **A refusal in the protocol is not the same as silence**, which is the same
/// rule the port scan's receive path is written around: a router that answers
/// "no such index" has told this scan something, and a router that answered
/// nothing at all has not. Flattening the two would let a timeout half way
/// through a forwarding table be reported as the end of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// It answered in UPnP and said no.
    Said(Fault),
    /// It answered something that was not a UPnP fault: an HTTP status with no
    /// error in it, or a body that could not be read.
    Confused,
    /// Nothing answered, the connection failed, or the scan was cancelled.
    Silence,
}

impl Refused {
    /// Is this the router saying its table has no more rows?
    pub fn is_end_of_table(&self) -> bool {
        matches!(self, Self::Said(fault)
            if fault.code.is_some_and(|code| END_OF_TABLE.contains(&code)))
    }
}

/// The control point for one service on one device.
pub struct Control<'a, W: Wire + ?Sized> {
    pub session: &'a Session<'a, W>,
    pub url: Url,
    pub service_type: String,
}

impl<W: Wire + ?Sized> Control<'_, W> {
    /// Sends one action and gives back the body of what came back.
    ///
    /// A fault is a [`Refused`] rather than a body, because every caller here
    /// wants to stop on one: a caller that read a fault as an empty answer
    /// would report "this router forwards nothing" for a router that declined
    /// to say.
    pub fn call(&self, action: Action, args: &[(&str, String)]) -> Result<String, Refused> {
        let body = envelope(&self.service_type, action, args);
        let soap_action = format!("\"{}#{}\"", self.service_type, action.name());
        let response = self
            .session
            .post(
                &self.url,
                "text/xml; charset=\"utf-8\"",
                &[("SOAPACTION", soap_action)],
                &body,
            )
            .map_err(|_| Refused::Silence)?;
        let text = response.text();
        if response.status == 200 && fault(&text).is_none() {
            return Ok(text);
        }
        Err(match fault(&text) {
            Some(fault) => Refused::Said(fault),
            None => Refused::Confused,
        })
    }
}

// ---------------------------------------------------------------------------
// The three answers
// ---------------------------------------------------------------------------

/// One row of a router's forwarding table.
///
/// Facts, in the order somebody reads them: what arrives from outside, where it
/// goes, and what says it should. Nothing here is graded; see the module note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Where it was in the table. Kept because the table's order is how a
    /// second scan tells the same forward from a new one.
    pub index: u16,
    /// `TCP` or `UDP`, upper cased, because firmware writes it both ways.
    pub protocol: String,
    /// The port on the public address.
    pub external_port: u16,
    /// The one remote address this forward is restricted to, where it is
    /// restricted at all. Empty in the reply means "from anywhere", which is
    /// the common case and is [`None`] here.
    pub remote_host: Option<String>,
    /// The device on this network the traffic is sent to.
    pub internal_client: Option<IpAddr>,
    pub internal_port: u16,
    /// What opened it, in whatever words it used. `Steam`, `libtorrent`,
    /// the name of a camera's firmware, or blank.
    pub description: Option<String>,
    pub enabled: bool,
    /// How long is left on it. **A lease of zero does not expire**, which is
    /// what the specification says and the opposite of what a nought reads as,
    /// so it is [`None`] here and the interface says so in words rather than
    /// printing a zero.
    pub lease: Option<Duration>,
}

/// Reads one `GetGenericPortMappingEntry` reply.
fn mapping(index: u16, body: &str) -> Option<Mapping> {
    // The two ports and the protocol are what make a row a row. A reply missing
    // any of them is not an entry, which is how a router that answers 200 with
    // an empty envelope past the end of its table is told from one that has a
    // mapping to report.
    let external_port = field(body, "NewExternalPort")?.parse().ok()?;
    let internal_port = field(body, "NewInternalPort")?.parse().ok()?;
    let protocol = field(body, "NewProtocol")?.to_ascii_uppercase();
    Some(Mapping {
        index,
        protocol,
        external_port,
        remote_host: field(body, "NewRemoteHost"),
        internal_client: field(body, "NewInternalClient").and_then(|c| c.parse().ok()),
        internal_port,
        description: field(body, "NewPortMappingDescription"),
        // `1` and `true` are both sent, and anything else is not an enabled
        // row.
        enabled: field(body, "NewEnabled")
            .is_some_and(|on| on == "1" || on.eq_ignore_ascii_case("true")),
        lease: field(body, "NewLeaseDuration")
            .and_then(|left| left.parse::<u64>().ok())
            .filter(|left| *left > 0)
            .map(Duration::from_secs),
    })
}

/// The WAN link's own account of itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// `Connected`, `Disconnected`, `Connecting`, as the router wrote it.
    pub connection: Option<String>,
    /// `ERROR_NONE` on a healthy link and something else on one that dropped.
    /// Kept as written: it is the router's own word for what went wrong, and
    /// paraphrasing it would lose the thing somebody would search for.
    pub last_error: Option<String>,
    /// How long the connection has been up.
    pub uptime: Option<Duration>,
}

impl Status {
    pub fn is_empty(&self) -> bool {
        self.connection.is_none() && self.last_error.is_none() && self.uptime.is_none()
    }
}

/// The byte counters, as the router keeps them.
///
/// **They are `ui4` and they wrap**, at four gigabytes, on most firmware, and
/// on some they reset when the WAN link does. That makes each one a reading
/// rather than a total, so nothing here adds them up, compares them or turns
/// them into a rate. The number is passed through as given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub sent: Option<u64>,
    pub received: Option<u64>,
}

impl Traffic {
    pub fn is_empty(&self) -> bool {
        self.sent.is_none() && self.received.is_none()
    }
}

/// What a gateway said about its connection to the world.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wan {
    /// Which service answered. `WANPPPConnection` rather than
    /// `WANIPConnection` is itself a fact about the link.
    pub service: String,
    /// The public address, from the router. Blank where it would not say, and
    /// never from anywhere else.
    pub external: Option<IpAddr>,
    pub status: Option<Status>,
    pub traffic: Option<Traffic>,
    /// Every forward the router is doing, in table order.
    pub mappings: Vec<Mapping>,
    /// Was the table walked at all?
    ///
    /// The difference between "this router forwards nothing" and "nobody
    /// looked", which is the same distinction the Ports column draws and is not
    /// one an empty list can carry on its own.
    pub walked_mappings: bool,
    /// The walk stopped before the router said it had reached the end.
    ///
    /// A cap reached, a timeout, or a refusal that was not "no such index". It
    /// means the list is a prefix of the truth rather than the whole of it, and
    /// a list that might be short has to say so.
    pub mappings_cut_short: bool,
}

/// What to ask a described device, and how much of it.
///
/// **Everything is off by default**, which is `CLAUDE.md`'s rule and the same
/// decision [`crate::service::Options`] records: a connection is a thing the far
/// end writes down, where a datagram to a name server is not, so opening one is
/// a deliberate act rather than something a scan does on its own.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub timeout: Duration,
    /// Fetch the XML description every SSDP `LOCATION` points at. One
    /// connection per device that answered SSDP.
    pub description: bool,
    /// Ask a gateway for its public address, its link state and its counters.
    /// Four requests, and only to a device whose description names a WAN
    /// service.
    pub gateway: bool,
    /// Walk the forwarding table. Up to [`Options::most_mappings`] requests,
    /// and the answer somebody scans a home network to find.
    pub mappings: bool,
    pub most_mappings: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: http::TIMEOUT,
            description: false,
            gateway: false,
            mappings: false,
            most_mappings: MOST_MAPPINGS,
        }
    }
}

impl Options {
    /// Is there anything to ask at all?
    pub fn any(&self) -> bool {
        self.description || self.gateway || self.mappings
    }
}

/// Everything one device's description led to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub description: Option<Description>,
    /// Present only where the description named a WAN service and something
    /// answered on it. Absent is "this is not a gateway, or it would not say",
    /// and it is why the public address has no other source.
    pub wan: Option<Wan>,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.description.is_none() && self.wan.is_none()
    }

    /// The model to hand [`crate::kind`], where the description named one.
    pub fn product(&self) -> Option<String> {
        self.description.as_ref()?.product()
    }
}

/// Follows one `LOCATION` and asks whatever [`Options`] allows.
///
/// Never fails. Everything it cannot learn is a blank, and every blank means
/// what a blank means everywhere else here: nobody said.
pub fn interrogate<W: Wire + ?Sized>(
    session: &Session<'_, W>,
    location: &str,
    opts: Options,
) -> Report {
    let mut report = Report::default();
    if !opts.any() {
        return report;
    }
    // The description is the way in: the control URL is written in it, so there
    // is no asking a gateway anything without fetching it first. It is fetched
    // whenever anything at all was asked for, and reported only when it was the
    // description that was asked for.
    let Some(described) = describe(session, location) else {
        return report;
    };
    if opts.description {
        report.description = Some(described.description.clone());
    }
    if !opts.gateway && !opts.mappings {
        return report;
    }

    let Some(service) = described.description.wan() else {
        return report;
    };
    let Some(url) = service
        .control_url
        .as_deref()
        .and_then(|url| described.resolve(url))
    else {
        return report;
    };
    let control = Control {
        session,
        url,
        service_type: service.service_type.clone(),
    };

    let mut wan = Wan {
        service: service.service_type.clone(),
        ..Default::default()
    };

    if opts.gateway {
        wan.external = control
            .call(Action::ExternalAddress, &[])
            .ok()
            .and_then(|body| field(&body, "NewExternalIPAddress"))
            // A router with no lease answers with an empty element or with
            // `0.0.0.0`, and both mean "there is no public address just now"
            // rather than that the address is nought.
            .filter(|address| address != "0.0.0.0")
            .and_then(|address| address.parse().ok());

        wan.status = control
            .call(Action::StatusInfo, &[])
            .ok()
            .map(|body| Status {
                connection: field(&body, "NewConnectionStatus"),
                last_error: field(&body, "NewLastConnectionError"),
                uptime: field(&body, "NewUptime")
                    .and_then(|seconds| seconds.parse::<u64>().ok())
                    .map(Duration::from_secs),
            })
            .filter(|status| !status.is_empty());

        wan.traffic = traffic(session, &described).filter(|traffic| !traffic.is_empty());
    }

    if opts.mappings {
        wan.walked_mappings = true;
        let cap = opts.most_mappings.min(MOST_MAPPINGS);
        wan.mappings_cut_short = true;
        for index in 0..cap {
            let index = index as u16;
            match control.call(
                Action::PortMapping,
                &[("NewPortMappingIndex", index.to_string())],
            ) {
                Ok(body) => match mapping(index, &body) {
                    Some(entry) => wan.mappings.push(entry),
                    // A 200 with nothing in it is how a handful of firmwares
                    // say the same thing 713 says.
                    None => {
                        wan.mappings_cut_short = false;
                        break;
                    }
                },
                Err(refused) => {
                    wan.mappings_cut_short = !refused.is_end_of_table();
                    break;
                }
            }
        }
    }

    report.wan = Some(wan);
    report
}

/// The byte counters, which live on a different service from everything else.
fn traffic<W: Wire + ?Sized>(session: &Session<'_, W>, described: &Described) -> Option<Traffic> {
    let service = described.description.service(WAN_COMMON)?;
    let url = described.resolve(service.control_url.as_deref()?)?;
    let control = Control {
        session,
        url,
        service_type: service.service_type.clone(),
    };
    let read = |action: Action, name: &str| -> Option<u64> {
        control
            .call(action, &[])
            .ok()
            .and_then(|body| field(&body, name))
            .and_then(|count| count.parse().ok())
    };
    Some(Traffic {
        sent: read(Action::BytesSent, "NewTotalBytesSent"),
        received: read(Action::BytesReceived, "NewTotalBytesReceived"),
    })
}

/// Every distinct `LOCATION` a device announced, in the order it announced
/// them.
///
/// A device answering `ssdp:all` repeats the same `LOCATION` on every reply and
/// occasionally sends two, one per root device it hosts. Fetching the same
/// document once per announcement would be a dozen connections to one
/// television for one answer.
pub fn locations(announcements: &[ssdp::Announcement]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for announcement in announcements {
        let Some(location) = announcement.location.as_deref() else {
            continue;
        };
        let location = location.trim();
        if !location.is_empty() && !out.iter().any(|had| had == location) {
            out.push(location.to_string());
        }
    }
    out
}

/// Follows what a whole SSDP sweep found, one device at a time.
///
/// Takes what [`crate::ssdp::discover`] gives back and returns one [`Report`]
/// per address that had anything to follow. **An address is only ever asked
/// about itself**: the session is built around it, so a `LOCATION` pointing
/// anywhere else is refused rather than followed. See [`crate::http`].
pub fn follow<W: Wire + ?Sized>(
    wire: &W,
    rate: &Bucket,
    cancel: &AtomicBool,
    announced: &BTreeMap<IpAddr, Vec<ssdp::Announcement>>,
    opts: Options,
) -> BTreeMap<IpAddr, Report> {
    let mut out = BTreeMap::new();
    if !opts.any() {
        return out;
    }
    for (address, announcements) in announced {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let session = Session {
            wire,
            address: *address,
            rate,
            timeout: opts.timeout,
            cancel,
        };
        // One report per device, merged across the locations it gave: a device
        // with two root devices describes itself twice, and the second is
        // usually the emptier of the two.
        let mut merged = Report::default();
        for location in locations(announcements) {
            let report = interrogate(&session, &location, opts);
            if merged.description.is_none() {
                merged.description = report.description;
            }
            if merged.wan.is_none() {
                merged.wan = report.wan;
            }
        }
        if !merged.is_empty() {
            out.insert(*address, merged);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    //! Where the fixtures come from, stated plainly.
    //!
    //! This crate has no network and no test may put a packet on a wire, so
    //! these documents are **written from the specifications** — the UPnP
    //! Device Architecture for the description and the SOAP envelopes, and the
    //! `WANIPConnection:1` service template for the actions, their arguments
    //! and their error codes — in the shapes MiniUPnPd and stock consumer
    //! firmware emit: the nested `InternetGatewayDevice` / `WANDevice` /
    //! `WANConnectionDevice` tree, a `URLBase` naming a different port from the
    //! one the document was served on, prefixed and unprefixed elements, and a
    //! 500 carrying a `UPnPError` 713 at the end of the mapping table.
    //!
    //! **They are not captures from a device on anybody's network**, and the
    //! first person with a router in front of them should replace them with
    //! ones that are. Saying so here is cheaper than rediscovering it.

    use super::*;
    use crate::http::tests::Fake;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// A gateway's description, in the nested shape every IGD uses.
    const GATEWAY: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<URLBase>http://192.168.1.1:5001/</URLBase>
<device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Home gateway</friendlyName>
<manufacturer>ASUSTeK Computer Inc.</manufacturer>
<modelDescription>Wireless router</modelDescription>
<modelName>RT-AC68U</modelName>
<modelNumber>1.0</modelNumber>
<serialNumber>0123456789AB</serialNumber>
<UDN>uuid:75802409-bccb-40e7-8e6c-fa095ecce13e</UDN>
<serviceList>
<service>
<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<controlURL>/ctl/L3F</controlURL>
</service>
</serviceList>
<deviceList>
<device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<friendlyName>WANDevice</friendlyName>
<manufacturer>MiniUPnP</manufacturer>
<modelName>WAN Device</modelName>
<serviceList>
<service>
<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
<controlURL>/ctl/CmnIfCfg</controlURL>
</service>
</serviceList>
<deviceList>
<device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<friendlyName>WANConnectionDevice</friendlyName>
<serviceList>
<service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL>
</service>
</serviceList>
</device>
</deviceList>
</device>
</deviceList>
</device>
</root>
"#;

    /// A television's description: no gateway, no service worth calling, and
    /// the model somebody actually wants on the row.
    const TELEVISION: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<device>
<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
<friendlyName>Living room</friendlyName>
<manufacturer>LG Electronics.</manufacturer>
<modelName>LG TV</modelName>
<modelNumber>OLED55C1</modelNumber>
<UDN>uuid:5f9ec1b3-ff59-19bb-8530-0005cd2fbd0c</UDN>
</device>
</root>
"#;

    fn wrap(body: &str) -> String {
        let head = "<?xml version=\"1.0\"?>";
        let open = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>";
        format!("{head}{open}{body}</s:Body></s:Envelope>")
    }

    fn rate() -> Bucket {
        Bucket::new(1_000_000)
    }

    fn session<'a, W: Wire + ?Sized>(
        wire: &'a W,
        address: &str,
        rate: &'a Bucket,
        cancel: &'a AtomicBool,
    ) -> Session<'a, W> {
        Session {
            wire,
            address: address.parse().expect("an address"),
            rate,
            timeout: http::TIMEOUT,
            cancel,
        }
    }

    // -- reading a description ------------------------------------------

    #[test]
    fn a_description_names_the_root_device_and_not_the_one_inside_it() {
        let d = parse(GATEWAY).expect("a description");
        assert_eq!(d.manufacturer.as_deref(), Some("ASUSTeK Computer Inc."));
        assert_eq!(d.model_name.as_deref(), Some("RT-AC68U"));
        assert_eq!(d.model_number.as_deref(), Some("1.0"));
        assert_eq!(d.serial_number.as_deref(), Some("0123456789AB"));
        assert_eq!(d.friendly_name.as_deref(), Some("Home gateway"));
        assert_eq!(
            d.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
        // The embedded `WANDevice` says MiniUPnP and `WAN Device`, and a reader
        // that took the last of each would put that on the row instead.
        assert_ne!(d.manufacturer.as_deref(), Some("MiniUPnP"));
        assert_ne!(d.model_name.as_deref(), Some("WAN Device"));
    }

    /// The other half of the same rule, in the other direction: the service
    /// worth calling is two devices deep.
    #[test]
    fn the_services_are_taken_from_the_whole_document() {
        let d = parse(GATEWAY).expect("a description");
        assert_eq!(d.services.len(), 3, "one per device, at three depths");
        let wan = d.wan().expect("the WAN connection service");
        assert_eq!(wan.control_url.as_deref(), Some("/ctl/IPConn"));
        assert!(d.service(WAN_COMMON).is_some());
    }

    /// A gateway published as IGD2 answers the same actions, and a match that
    /// insisted on the version would ignore every one of them.
    #[test]
    fn a_service_matches_whatever_version_it_is() {
        let two = Service {
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:2".into(),
            control_url: None,
        };
        assert!(two.is(WAN_SERVICES[0]));
        assert!(!two.is(WAN_COMMON));
    }

    #[test]
    fn a_model_is_joined_without_repeating_itself() {
        let d = parse(GATEWAY).expect("a description");
        assert_eq!(
            d.product().as_deref(),
            Some("ASUSTeK Computer Inc. RT-AC68U 1.0")
        );

        // The common firmware shape: the maker's name already inside the model.
        let repeated = Description {
            manufacturer: Some("Synology".into()),
            model_name: Some("Synology DS920+".into()),
            ..Default::default()
        };
        assert_eq!(repeated.product().as_deref(), Some("Synology DS920+"));
    }

    /// A company name is not a model, and handing one to the product table
    /// would have every device that answers SSDP claiming to have named itself.
    #[test]
    fn a_manufacturer_on_its_own_is_not_a_product() {
        let only = Description {
            manufacturer: Some("Belkin International Inc.".into()),
            ..Default::default()
        };
        assert_eq!(only.product(), None);
    }

    #[test]
    fn a_television_gives_a_model_and_no_gateway() {
        let d = parse(TELEVISION).expect("a description");
        assert_eq!(
            d.product().as_deref(),
            Some("LG Electronics. LG TV OLED55C1")
        );
        assert!(d.wan().is_none(), "and there is nothing to interrogate");
        assert!(d.services.is_empty());
    }

    #[test]
    fn an_entity_in_a_manufacturer_is_decoded() {
        assert_eq!(decode("AT&amp;T"), "AT&T");
        assert_eq!(decode("Sagemcom &lt;Fast&gt;"), "Sagemcom <Fast>");
        assert_eq!(decode("caf&#233;"), "café");
        assert_eq!(decode("100% &nothing;"), "100% &nothing;", "left alone");
        assert_eq!(decode("plain"), "plain");
    }

    #[test]
    fn rubbish_is_not_a_description() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("<html><body>404 not found</body></html>"), None);
        assert_eq!(parse("<root><device></device></root>"), None);
    }

    // -- the envelope ---------------------------------------------------

    #[test]
    fn an_envelope_is_the_shape_a_router_expects() {
        let raw = envelope(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            Action::PortMapping,
            &[("NewPortMappingIndex", "3".to_string())],
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("<u:GetGenericPortMappingEntry"));
        assert!(text.contains("xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\""));
        assert!(text.contains("<NewPortMappingIndex>3</NewPortMappingIndex>"));
        assert!(text.trim_end().ends_with("</s:Envelope>"));
    }

    /// The line this module does not cross, checked against this module's own
    /// source rather than against a comment about it. The names are assembled
    /// so that the guard does not contain what it forbids.
    #[test]
    fn nothing_here_can_write_to_a_router() {
        let source = include_str!("igd.rs");
        for forbidden in [
            concat!("Add", "PortMapping"),
            concat!("Delete", "PortMapping"),
            concat!("Add", "AnyPortMapping"),
        ] {
            assert!(
                !source.contains(forbidden),
                "{forbidden} is a write to somebody's gateway, and this module does not write"
            );
        }
        // And every action that can be spelled at all is one of the five reads.
        for action in [
            Action::ExternalAddress,
            Action::PortMapping,
            Action::StatusInfo,
            Action::BytesSent,
            Action::BytesReceived,
        ] {
            assert!(action.name().starts_with("Get"), "{}", action.name());
        }
    }

    #[test]
    fn a_upnp_error_is_read_out_of_a_fault() {
        let body = wrap(
            "<s:Fault><faultcode>s:Client</faultcode><detail><UPnPError><errorCode>713</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault>",
        );
        let f = fault(&body).expect("a fault");
        assert_eq!(f.code, Some(713));
        assert_eq!(f.description.as_deref(), Some("SpecifiedArrayIndexInvalid"));
        assert!(Refused::Said(f).is_end_of_table());
    }

    /// The distinction the walk depends on. Silence is not the end of a table.
    #[test]
    fn a_refusal_that_is_not_an_index_error_is_not_the_end_of_the_table() {
        assert!(!Refused::Silence.is_end_of_table());
        assert!(!Refused::Confused.is_end_of_table());
        assert!(
            !Refused::Said(Fault {
                code: Some(606),
                description: Some("Action not authorized".into()),
            })
            .is_end_of_table()
        );
    }

    // -- a recorded router ----------------------------------------------

    /// A gateway that answers, keyed the way a real one keys: the description
    /// on the URL it was fetched from, and each action on the control URL by
    /// the `SOAPACTION` header.
    ///
    /// Nothing here opens a socket. It exists because the port mapping walk is
    /// a *sequence* of requests with different answers, which an
    /// address-keyed fake cannot record.
    #[derive(Default)]
    struct Router {
        /// One body per index, in table order.
        mappings: Vec<String>,
        /// The reply to each other action, by name.
        answers: BTreeMap<&'static str, String>,
        sent: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    impl Router {
        fn new() -> Self {
            let mut answers = BTreeMap::new();
            answers.insert(
                Action::ExternalAddress.name(),
                wrap("<u:GetExternalIPAddressResponse><NewExternalIPAddress>81.166.42.7</NewExternalIPAddress></u:GetExternalIPAddressResponse>"),
            );
            answers.insert(
                Action::StatusInfo.name(),
                wrap("<u:GetStatusInfoResponse><NewConnectionStatus>Connected</NewConnectionStatus><NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>864000</NewUptime></u:GetStatusInfoResponse>"),
            );
            answers.insert(
                Action::BytesSent.name(),
                wrap("<u:GetTotalBytesSentResponse><NewTotalBytesSent>3221225472</NewTotalBytesSent></u:GetTotalBytesSentResponse>"),
            );
            answers.insert(
                Action::BytesReceived.name(),
                wrap("<u:GetTotalBytesReceivedResponse><NewTotalBytesReceived>4026531840</NewTotalBytesReceived></u:GetTotalBytesReceivedResponse>"),
            );
            Self {
                mappings: Vec::new(),
                answers,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn forwarding(mut self, rows: &[(&str, u16, &str, u16, &str, u64)]) -> Self {
            for (protocol, external, client, internal, description, lease) in rows {
                self.mappings.push(wrap(&format!(
                    "<u:GetGenericPortMappingEntryResponse><NewRemoteHost></NewRemoteHost><NewExternalPort>{external}</NewExternalPort><NewProtocol>{protocol}</NewProtocol><NewInternalPort>{internal}</NewInternalPort><NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{description}</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration></u:GetGenericPortMappingEntryResponse>"
                )));
            }
            self
        }

        fn ok(body: &str) -> Vec<u8> {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        }

        fn refused(code: u16) -> Vec<u8> {
            let body = wrap(&format!(
                "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError><errorCode>{code}</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault>"
            ));
            format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        }

        /// The action out of a `SOAPACTION` header, and the index out of a
        /// body, the same two things a router reads.
        fn asked(request: &str) -> (Option<String>, Option<usize>) {
            let action = request
                .lines()
                .find(|line| line.to_ascii_uppercase().starts_with("SOAPACTION:"))
                .and_then(|line| line.split_once('#'))
                .map(|(_, name)| name.trim().trim_matches('"').to_string());
            let index = element(request, "NewPortMappingIndex").and_then(|i| i.trim().parse().ok());
            (action, index)
        }
    }

    impl Wire for Router {
        fn exchange(
            &self,
            to: SocketAddr,
            request: &[u8],
            _timeout: Duration,
            _most: usize,
        ) -> io::Result<Vec<u8>> {
            self.sent.lock().unwrap().push((to, request.to_vec()));
            let text = String::from_utf8_lossy(request).into_owned();
            if text.starts_with("GET /rootDesc.xml ") {
                return Ok(Self::ok(GATEWAY));
            }
            let (action, index) = Self::asked(&text);
            let Some(action) = action else {
                return Ok(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
            };
            if action == Action::PortMapping.name() {
                return Ok(match index.and_then(|i| self.mappings.get(i)) {
                    Some(body) => Self::ok(body),
                    // 713 is what the service template specifies for an index
                    // past the end.
                    None => Self::refused(713),
                });
            }
            Ok(match self.answers.get(action.as_str()) {
                Some(body) => Self::ok(body),
                None => Self::refused(401),
            })
        }
    }

    const ROOT: &str = "http://192.168.1.1:5000/rootDesc.xml";

    // -- the whole conversation -----------------------------------------

    #[test]
    fn a_description_is_fetched_from_the_device_that_gave_the_location() {
        let router = Router::new();
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        let described = describe(&session, ROOT).expect("a description");
        assert_eq!(
            described.description.model_name.as_deref(),
            Some("RT-AC68U")
        );
        // The `URLBase` won, and it names a different port from the one the
        // document was served on, which is what firmware does and what a
        // reader ignoring `URLBase` would get wrong.
        assert_eq!(described.base.as_ref().map(|b| b.port), Some(5001));
        assert_eq!(described.resolve("/ctl/IPConn").unwrap().port, 5001);
    }

    /// The conduct rule, from the top: a device saying its description lives on
    /// the internet does not get this machine to fetch it.
    #[test]
    fn a_location_pointing_off_the_link_is_not_followed() {
        let router = Router::new();
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        assert_eq!(describe(&session, "http://example.com/rootDesc.xml"), None);
        assert!(router.sent.lock().unwrap().is_empty(), "nothing was opened");
    }

    #[test]
    fn nothing_at_all_is_asked_when_nothing_was_switched_on() {
        let router = Router::new();
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        let report = interrogate(&session, ROOT, Options::default());
        assert!(report.is_empty());
        assert!(router.sent.lock().unwrap().is_empty());
        assert!(!Options::default().any());
    }

    #[test]
    fn the_public_address_comes_from_the_router_and_nowhere_else() {
        let router = Router::new();
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        let report = interrogate(
            &session,
            ROOT,
            Options {
                gateway: true,
                ..Default::default()
            },
        );
        let wan = report.wan.expect("a WAN service answered");
        assert_eq!(wan.external, Some("81.166.42.7".parse::<IpAddr>().unwrap()));
        assert_eq!(
            wan.service,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );

        // And every connection the answer took went to the router.
        for (to, _) in router.sent.lock().unwrap().iter() {
            assert_eq!(to.ip().to_string(), "192.168.1.1");
        }
    }

    #[test]
    fn the_link_state_and_the_counters_come_back_with_it() {
        let router = Router::new();
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        let wan = interrogate(
            &session,
            ROOT,
            Options {
                gateway: true,
                ..Default::default()
            },
        )
        .wan
        .expect("a WAN service");

        let status = wan.status.expect("a status");
        assert_eq!(status.connection.as_deref(), Some("Connected"));
        assert_eq!(status.last_error.as_deref(), Some("ERROR_NONE"));
        assert_eq!(status.uptime, Some(Duration::from_secs(864_000)));

        let traffic = wan.traffic.expect("counters");
        assert_eq!(traffic.sent, Some(3_221_225_472));
        assert_eq!(traffic.received, Some(4_026_531_840));
    }

    /// The strict rule that makes the feature: a device with no IGD leaves the
    /// public address blank, and there is nowhere else it could come from.
    #[test]
    fn a_device_with_no_gateway_service_leaves_the_address_blank() {
        let mut fake = Fake::default();
        fake.answers("192.168.1.30:2869", "text/xml", TELEVISION);
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&fake, "192.168.1.30", &rate, &cancel);
        let report = interrogate(
            &session,
            "http://192.168.1.30:2869/desc.xml",
            Options {
                description: true,
                gateway: true,
                mappings: true,
                ..Default::default()
            },
        );
        assert!(
            report.wan.is_none(),
            "no IGD, so no address and no fallback"
        );
        assert_eq!(
            report.product().as_deref(),
            Some("LG Electronics. LG TV OLED55C1"),
            "and the model is still worth the connection"
        );
    }

    #[test]
    fn a_router_with_no_lease_reports_no_address_rather_than_nought() {
        let mut router = Router::new();
        router.answers.insert(
            Action::ExternalAddress.name(),
            wrap("<u:GetExternalIPAddressResponse><NewExternalIPAddress>0.0.0.0</NewExternalIPAddress></u:GetExternalIPAddressResponse>"),
        );
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        let wan = interrogate(
            &session,
            ROOT,
            Options {
                gateway: true,
                ..Default::default()
            },
        )
        .wan
        .expect("a WAN service");
        assert_eq!(wan.external, None);
    }

    /// The answer somebody scans a home network to find: everything the router
    /// is forwarding, including what nobody set up on purpose.
    #[test]
    fn the_forwarding_table_is_walked_to_its_end() {
        let router = Router::new().forwarding(&[
            ("TCP", 25565, "192.168.1.42", 25565, "Minecraft", 0),
            ("UDP", 6881, "192.168.1.55", 6881, "libtorrent", 3600),
            ("TCP", 8080, "192.168.1.77", 80, "IPCAM", 604800),
        ]);
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);
        let wan = interrogate(
            &session,
            ROOT,
            Options {
                mappings: true,
                ..Default::default()
            },
        )
        .wan
        .expect("a WAN service");

        assert!(wan.walked_mappings);
        assert!(!wan.mappings_cut_short, "the router said it had no more");
        assert_eq!(wan.mappings.len(), 3);

        let camera = &wan.mappings[2];
        assert_eq!(camera.external_port, 8080);
        assert_eq!(camera.internal_port, 80);
        assert_eq!(camera.protocol, "TCP");
        assert_eq!(
            camera.internal_client,
            Some("192.168.1.77".parse::<IpAddr>().unwrap())
        );
        assert_eq!(camera.description.as_deref(), Some("IPCAM"));
        assert_eq!(camera.lease, Some(Duration::from_secs(604_800)));
        assert!(camera.enabled);
        assert_eq!(camera.remote_host, None, "empty means from anywhere");

        // A lease of zero does not expire, and is not nought seconds.
        assert_eq!(wan.mappings[0].lease, None);
        assert_eq!(wan.mappings[1].protocol, "UDP");
    }

    /// A router that forwards nothing says so, and that is different from
    /// nobody having looked.
    #[test]
    fn a_router_that_forwards_nothing_is_not_a_router_nobody_asked() {
        let router = Router::new();
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);

        let walked = interrogate(
            &session,
            ROOT,
            Options {
                mappings: true,
                ..Default::default()
            },
        )
        .wan
        .expect("a WAN service");
        assert!(walked.mappings.is_empty());
        assert!(walked.walked_mappings, "and the list means it");

        let unasked = interrogate(
            &session,
            ROOT,
            Options {
                gateway: true,
                ..Default::default()
            },
        )
        .wan
        .expect("a WAN service");
        assert!(unasked.mappings.is_empty());
        assert!(!unasked.walked_mappings, "which is the other answer");
    }

    /// The rule the port scan's receive path is written around, applied here:
    /// a walk that stopped early must not be shown as a complete table.
    #[test]
    fn a_walk_cut_short_says_so() {
        let mut router = Router::new().forwarding(&[
            ("TCP", 80, "192.168.1.2", 80, "one", 0),
            ("TCP", 81, "192.168.1.3", 81, "two", 0),
        ]);
        // The second index is answered with a refusal that is not "no such
        // index", which is a router declining rather than a table ending.
        router.mappings.truncate(1);
        router.answers.remove(Action::PortMapping.name());
        let rate = rate();
        let cancel = AtomicBool::new(false);
        let session = session(&router, "192.168.1.1", &rate, &cancel);

        let wan = interrogate(
            &session,
            ROOT,
            Options {
                mappings: true,
                most_mappings: 1,
                ..Default::default()
            },
        )
        .wan
        .expect("a WAN service");
        assert_eq!(wan.mappings.len(), 1);
        assert!(
            wan.mappings_cut_short,
            "the cap was reached, so this list is a prefix"
        );
    }

    #[test]
    fn a_sweep_is_followed_one_device_at_a_time_and_a_location_only_once() {
        let mut fake = Fake::default();
        fake.answers("192.168.1.30:2869", "text/xml", TELEVISION);
        let announcement = ssdp::Announcement {
            location: Some("http://192.168.1.30:2869/desc.xml".into()),
            ..Default::default()
        };
        let mut announced: BTreeMap<IpAddr, Vec<ssdp::Announcement>> = BTreeMap::new();
        announced.insert(
            "192.168.1.30".parse().unwrap(),
            vec![
                announcement.clone(),
                announcement.clone(),
                announcement.clone(),
            ],
        );

        let rate = rate();
        let cancel = AtomicBool::new(false);
        let out = follow(
            &fake,
            &rate,
            &cancel,
            &announced,
            Options {
                description: true,
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(
            fake.sent.lock().unwrap().len(),
            1,
            "three announcements, one document, one connection"
        );
        assert!(out.values().next().unwrap().description.is_some());
    }

    #[test]
    fn a_cancelled_follow_asks_nothing() {
        let mut fake = Fake::default();
        fake.answers("192.168.1.30:2869", "text/xml", TELEVISION);
        let mut announced: BTreeMap<IpAddr, Vec<ssdp::Announcement>> = BTreeMap::new();
        announced.insert(
            "192.168.1.30".parse().unwrap(),
            vec![ssdp::Announcement {
                location: Some("http://192.168.1.30:2869/desc.xml".into()),
                ..Default::default()
            }],
        );
        let rate = rate();
        let out = follow(
            &fake,
            &rate,
            &AtomicBool::new(true),
            &announced,
            Options {
                description: true,
                ..Default::default()
            },
        );
        assert!(out.is_empty());
        assert!(fake.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn one_device_that_announced_twice_is_asked_about_each_document_once() {
        let announcements = vec![
            ssdp::Announcement {
                location: Some("http://192.168.1.5:80/a.xml".into()),
                ..Default::default()
            },
            ssdp::Announcement {
                location: Some("http://192.168.1.5:80/a.xml".into()),
                ..Default::default()
            },
            ssdp::Announcement {
                location: Some("http://192.168.1.5:80/b.xml".into()),
                ..Default::default()
            },
            ssdp::Announcement::default(),
        ];
        assert_eq!(
            locations(&announcements),
            vec![
                "http://192.168.1.5:80/a.xml".to_string(),
                "http://192.168.1.5:80/b.xml".to_string()
            ]
        );
    }
}
