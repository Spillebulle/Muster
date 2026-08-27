//! WS-Discovery: the question Windows answers when it answers nothing else.
//!
//! mDNS finds Apple devices, printers and anything running Avahi. SSDP finds
//! televisions, media players and routers. Between them they miss the device
//! that is commonest on an office network and among the commonest at home: a
//! Windows machine. Windows stopped enabling NetBIOS by default, does not run
//! an mDNS responder for its own name, does not answer SSDP, and blocks ICMP on
//! the public network profile — so on a real network it is a row with a
//! hardware address, a vendor and nothing else, and it is very often not a row
//! at all.
//!
//! What it *does* run is `WSDAPI`, behind the Function Discovery Resource
//! Publication service, and that answers a WS-Discovery `Probe` sent to the
//! link. So do network printers, which have shipped WSD-Print for fifteen
//! years, and so do IP cameras, because ONVIF profile S mandates exactly this
//! protocol for discovery. Three kinds of device that are hard to find any
//! other way, all answering one datagram.
//!
//! ## The versions, and why only one is sent
//!
//! There are two WS-Discovery namespaces in the wild: the 2005/04 draft and the
//! 2009/01 OASIS standard. Windows, every ONVIF camera and every WSD printer
//! observed speak the **2005/04** one, and the standard's own appendix provides
//! for that by leaving the older namespace in service. Sending both would
//! double the traffic to reach the same devices, so this sends the draft and
//! nothing else. If a device is ever found that answers only 2009/01, the
//! change is a second constant and a second datagram.
//!
//! ## Reading it
//!
//! The reply is a SOAP envelope, and this parses it with a tag scanner rather
//! than an XML parser. That is a deliberate limit, not a shortcut: what is
//! wanted is four fields — the device's types, its scopes, its transport
//! addresses and its identifier — each of which is a text node inside a
//! uniquely named element,
//! and no responder has ever put one of them in an attribute. A real parser
//! would be a dependency and a much larger surface for a hostile responder to
//! aim at. The scanner ignores namespace prefixes, because every implementation
//! chooses its own: `wsd:Types`, `d:Types` and `Types` are all the same element
//! and all three have been seen.
//!
//! ## The scopes were already in hand and were thrown away
//!
//! `Scopes` is a whitespace-separated list of URIs a device publishes about
//! itself, and on the two kinds of device that answer this protocol most it is
//! the only place the hardware is named. ONVIF Core §7.3.2 gives cameras five
//! scope categories under `onvif://www.onvif.org/`, of which `hardware` is the
//! model number stamped at the factory; Microsoft's WSD-Print device identifier
//! writes the same thing as `MFG:` and `MDL:` fields. Both arrived in every
//! `ProbeMatch` this has ever read, and both were parsed straight past.
//!
//! **The `name` scope is read and deliberately not used as a model.** It is the
//! device's *friendly name*, which is to say the thing whoever installed the
//! camera typed into a web form, and `CLAUDE.md` has already settled what this
//! project does with evidence of that class: a name is evidence about a person,
//! not about the hardware. On a factory-fresh Hikvision it is
//! `HIKVISION DS-2CD2042WD-I` and looks like the best answer on the network; on
//! the one beside it that somebody labelled, it is `Front door`, and a
//! "Model: Front door" row is exactly the confident nonsense the hostname rule
//! exists to refuse. So [`Match::model`] reads `hardware` and `MDL`, which no
//! installer can change, and leaves `name` to [`Match::scope`] for anything
//! that wants it for something other than an inference.
//!
//! As everywhere else in this crate, nothing here opens a socket.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Where WS-Discovery listens. Fixed by the specification.
pub const PORT: u16 = 3702;

/// The group every WSD responder on the link joins.
///
/// The same address SSDP uses, on a different port. That is not a coincidence
/// and not a mistake: `239.255.255.250` is the administratively scoped group
/// assigned to local discovery, and the two protocols share it.
pub const GROUP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), PORT);

/// The 2005/04 discovery namespace, which is what everything answers.
const DISCOVERY: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

/// Builds a `Probe` that matches every device on the link.
///
/// **The `Probe` body is empty, and that is what makes it match everything.**
/// The element may carry a `Types` filter, and a responder that does not match
/// the filter stays silent; omitting it asks for everybody. Sending a filter
/// for the three kinds this is aimed at would have found only devices that
/// describe themselves in exactly the words guessed for them, and the whole
/// point of asking the link is not to have to guess.
///
/// `id` becomes the `MessageID`, which the specification requires to be a URI
/// unique to the message. A responder echoes it in `RelatesTo`, and a
/// well-behaved one ignores a `Probe` whose id it has already answered — so an
/// id that repeats between scans is a scan that gets quieter every time it is
/// run. The caller passes something fresh.
pub fn probe(id: u128) -> Vec<u8> {
    build(id, None)
}

/// A `Probe` filtered to one type, which every other kind of device ignores.
///
/// The opposite of [`probe`], for the opposite purpose. [`crate::link`] wants
/// every device on the link to answer; [`crate::listen`] wants a well-formed
/// datagram that provokes nothing at all, because its only job is to open a
/// path back through a stateful firewall. A `Types` filter no device can match
/// is the smallest thing that does that.
pub fn probe_for(id: u128, types: &str) -> Vec<u8> {
    build(id, Some(types))
}

fn build(id: u128, types: Option<&str>) -> Vec<u8> {
    // An empty `Probe` matches every device on the link; one carrying a
    // `Types` filter matches only what is named in it.
    let body = match types {
        Some(types) => format!("<d:Probe><d:Types>{types}</d:Types></d:Probe>"),
        None => "<d:Probe/>".to_string(),
    };
    // Formatted as a UUID because the specification asks for a URI and every
    // responder in the field expects this shape of one. The bytes are the
    // caller's; nothing here claims they are a real version-4 UUID.
    let id = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (id >> 96) as u32,
        (id >> 80) as u16,
        (id >> 64) as u16,
        (id >> 48) as u16,
        (id & 0xffff_ffff_ffff) as u64
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <s:Envelope \
         xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
         xmlns:d=\"{DISCOVERY}\">\
         <s:Header>\
         <a:Action>{DISCOVERY}/Probe</a:Action>\
         <a:MessageID>urn:uuid:{id}</a:MessageID>\
         <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>\
         </s:Header>\
         <s:Body>{body}</s:Body>\
         </s:Envelope>"
    )
    .into_bytes()
}

/// What one `ProbeMatch` said about the device that sent it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Match {
    /// The `Types` the device claims, lower cased and with namespace prefixes
    /// left on: `wsdp:device`, `pub:computer`, `dn:networkvideotransmitter`,
    /// `print:printdevicetype`.
    ///
    /// The prefix is kept because it is half the meaning. `pub:Computer` is
    /// Windows' publication namespace and says the thing is a PC; a bare
    /// `Computer` from some other namespace would not be the same claim.
    pub types: Vec<String>,
    /// `XAddrs`: where the device's services live, as URLs. Usually one HTTP
    /// address on the device's own IP, which is worth having because it is a
    /// port worth knowing about even when nothing is fetched from it.
    pub addresses: Vec<String>,
    /// The `EndpointReference` address, which is a stable identifier for the
    /// device: `urn:uuid:...`. The same device answering twice gives the same
    /// one, which is how two replies are known to be one device.
    pub endpoint: Option<String>,
    /// `Scopes`: the URIs the device publishes about itself, as it wrote them.
    ///
    /// Kept verbatim rather than decoded into fields, because the vocabulary is
    /// open: ONVIF defines five categories, Microsoft's print stack writes
    /// `MFG:`/`MDL:` pairs, and a vendor is free to publish an `ldap:///` path
    /// or anything else it likes. What is understood is read by
    /// [`Match::scope`] and [`Match::model`]; the rest is still evidence that
    /// something answered, and is not dropped to make a struct tidier.
    pub scopes: Vec<String>,
}

impl Match {
    /// Nothing was in it worth keeping.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
            && self.addresses.is_empty()
            && self.endpoint.is_none()
            && self.scopes.is_empty()
    }

    /// The value of one ONVIF scope category, percent-decoded.
    ///
    /// ONVIF Core §7.3.2 writes a scope as
    /// `onvif://www.onvif.org/<category>/<value>` and defines `name`,
    /// `location`, `hardware`, `Profile` and `type`. The category is compared
    /// without regard to case, because the specification capitalises `Profile`
    /// and nothing else, and implementations are not consistent about it.
    ///
    /// The value is percent-decoded, because a space in a model or a location
    /// arrives as `%20` and `HIKVISION%20DS-2CD2042WD-I` is not a string to put
    /// in front of somebody.
    pub fn scope(&self, category: &str) -> Option<String> {
        let prefix = format!("{ONVIF}{}/", category.to_ascii_lowercase());
        self.scopes.iter().find_map(|scope| {
            let head = scope.get(..prefix.len())?;
            (head.to_ascii_lowercase() == prefix)
                .then(|| unescape(scope[prefix.len()..].trim_end_matches('/')))
                .filter(|value| !value.is_empty())
        })
    }

    /// The model the device named for itself in its scopes, where it named one.
    ///
    /// Two vocabularies, in the order of how hard each is to falsify:
    ///
    /// * **`MFG:` and `MDL:`**, the fields of Microsoft's WSD-Print device
    ///   identifier, which a print device publishes and which name the maker
    ///   and the model outright. The two are joined, unless the model already
    ///   begins with the maker's name, which is how most printers write it.
    /// * **The ONVIF `hardware` scope**, which is the model number in the
    ///   camera's own firmware.
    ///
    /// **`name` is not among them**, and the module note says why: it is a
    /// friendly name somebody typed, and this project does not infer hardware
    /// from what a person wrote down.
    pub fn model(&self) -> Option<String> {
        let (mut maker, mut model) = (None, None);
        for field in self.scopes.iter().flat_map(|scope| scope.split(';')) {
            let Some((key, value)) = field.split_once(':') else {
                continue;
            };
            let value = unescape(value.trim());
            if value.is_empty() {
                continue;
            }
            match key.trim().to_ascii_uppercase().as_str() {
                "MFG" => maker = Some(value),
                "MDL" => model = Some(value),
                _ => {}
            }
        }
        match (maker, model) {
            (Some(maker), Some(model)) => {
                let same = model
                    .to_ascii_lowercase()
                    .starts_with(&maker.to_ascii_lowercase());
                Some(if same {
                    model
                } else {
                    format!("{maker} {model}")
                })
            }
            (None, Some(model)) => Some(model),
            // A maker with no model names nobody's hardware, so it is not a
            // model and is not offered as one.
            _ => self.scope("hardware"),
        }
    }
}

/// The stem every ONVIF scope is written under. ONVIF Core §7.3.2.
const ONVIF: &str = "onvif://www.onvif.org/";

/// Percent-decoding, and nothing else.
///
/// A scope is a URI, so a space in a model name arrives as `%20`. This is not a
/// general URI decoder and does not want to be: `+` is left alone, because a
/// scope is a path rather than a query string and a `+` in a model number is a
/// `+`. A malformed escape is kept as it was written rather than dropped, on
/// the same principle as everything else here that reads a stranger's bytes.
fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(pair) = text.get(at + 1..at + 3)
            && let Ok(byte) = u8::from_str_radix(pair, 16)
        {
            out.push(byte);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads one WS-Discovery datagram.
///
/// Accepts a `ProbeMatch`, a `ResolveMatch` and a `Hello`, because all three
/// carry the same three fields and a device that announced itself while the
/// probe was in flight is saying the same thing by a different verb — the rule
/// [`crate::ssdp::parse`] follows for `NOTIFY`. A `Bye` is deliberately **not**
/// accepted: it is a device saying it is leaving, and reading it as an arrival
/// would put a row on the list for something that has just gone.
///
/// [`None`] for anything that is not one of those, which includes another
/// scanner's `Probe` arriving on the same group.
pub fn parse(buf: &[u8]) -> Option<Match> {
    // The envelope is XML and therefore text, but a device with a non-ASCII
    // model name in a `Types` list does exist, so this is read lossily rather
    // than thrown away for one bad byte.
    let text = String::from_utf8_lossy(buf);

    // The action says which message this is, and it is the one field that has
    // to be right: everything below reads the same elements out of any of them.
    let action = element(&text, "Action").unwrap_or_default();
    let action = action.to_ascii_lowercase();
    if !(action.ends_with("/probematches")
        || action.ends_with("/resolvematches")
        || action.ends_with("/hello"))
    {
        return None;
    }

    let mut found = Match {
        types: Vec::new(),
        scopes: split(element(&text, "Scopes").as_deref()),
        addresses: split(element(&text, "XAddrs").as_deref()),
        // The endpoint is inside `EndpointReference`, and the element that
        // holds it is `Address` — a name common enough that scanning for it
        // alone would find some other element in some other responder's
        // envelope. So the reference is cut out first and the address read from
        // inside it.
        endpoint: element(&text, "EndpointReference")
            .as_deref()
            .and_then(|r| element(r, "Address"))
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty()),
    };

    for kind in split(element(&text, "Types").as_deref()) {
        let kind = kind.to_ascii_lowercase();
        if !found.types.contains(&kind) {
            found.types.push(kind);
        }
    }

    (!found.is_empty()).then_some(found)
}

/// The text inside the first element with this local name, whatever namespace
/// prefix it wears.
///
/// Matches `<d:Types ...>` and `<Types>` alike by looking for the name preceded
/// by `<` or `:` and followed by `>`, `/` or whitespace, which is what stops
/// `Types` matching inside `MetadataTypes`. Returns the raw inner text,
/// including any child elements: the one caller that needs to go deeper —
/// `EndpointReference` — calls this again on what comes back.
fn element(text: &str, name: &str) -> Option<String> {
    let mut at = 0;
    while let Some(found) = text[at..].find(name) {
        let start = at + found;
        at = start + name.len();
        // What comes before has to be the start of a tag or the end of a
        // namespace prefix, or this is a match inside a longer name.
        if !matches!(text[..start].chars().next_back(), Some('<' | ':')) {
            continue;
        }
        // And what comes after has to end the name, or `Types` matches inside
        // `MetadataTypes` and answers with the wrong element's text.
        if !text[at..]
            .chars()
            .next()
            .is_some_and(|c| c == '>' || c == '/' || c.is_whitespace())
        {
            continue;
        }
        // Past the rest of the opening tag.
        let shut = text[at..].find('>')?;
        // A self-closing element has no text in it, which is a different
        // answer from not being there and is not one this needs to tell apart.
        if text[at..at + shut].trim_end().ends_with('/') {
            return None;
        }
        let body = at + shut + 1;
        // The closing tag, found by its local name for the same reason the
        // opening one was. Nesting of two elements with the same local name
        // would defeat this; no responder nests any of the three fields read
        // here inside another of its own name.
        let mut scan = body;
        while let Some(found) = text[scan..].find("</") {
            let tag = scan + found + 2;
            let shut = text[tag..].find('>')?;
            if text[tag..tag + shut].trim().rsplit(':').next() == Some(name) {
                return Some(text[body..scan + found].to_string());
            }
            scan = tag + shut;
        }
        return None;
    }
    None
}

/// Splits a whitespace-separated list, which is how WS-Discovery writes both
/// `Types` and `XAddrs`.
fn split(text: Option<&str>) -> Vec<String> {
    text.into_iter()
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ProbeMatch` from a Windows 11 machine, as one answered on a real
    /// network. The `pub:Computer` type is the whole reason this protocol is
    /// here: nothing else that machine said all scan named it a computer.
    const WINDOWS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
 xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
 <soap:Header>
  <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
  <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
  <wsa:MessageID>urn:uuid:8f3a1c0e-1111-2222-3333-444455556666</wsa:MessageID>
 </soap:Header>
 <soap:Body>
  <wsd:ProbeMatches>
   <wsd:ProbeMatch>
    <wsa:EndpointReference>
     <wsa:Address>urn:uuid:cafe0001-0000-0000-0000-00000000abcd</wsa:Address>
    </wsa:EndpointReference>
    <wsd:Types>wsdp:Device pub:Computer</wsd:Types>
    <wsd:XAddrs>http://192.168.1.42:5357/cafe0001/</wsd:XAddrs>
    <wsd:MetadataVersion>2</wsd:MetadataVersion>
   </wsd:ProbeMatch>
  </wsd:ProbeMatches>
 </soap:Body>
</soap:Envelope>"#;

    /// An ONVIF camera, which answers the same probe in the same namespace and
    /// names itself a video transmitter.
    ///
    /// The `Scopes` line is the one a Hikvision DS-2CD2042WD-I publishes, which
    /// is the shape ONVIF Core §7.3.2 mandates and the one reported from these
    /// cameras in the field: a type, a hardware model and a friendly name that
    /// happens, on a camera nobody has renamed, to be the maker and the model
    /// again.
    const CAMERA: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
 <s:Header>
  <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
 </s:Header>
 <s:Body><d:ProbeMatches><d:ProbeMatch>
  <a:EndpointReference><a:Address>urn:uuid:11112222-3333-4444-5555-666677778888</a:Address></a:EndpointReference>
  <d:Types>dn:NetworkVideoTransmitter</d:Types>
  <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/hardware/DS-2CD2042WD-I onvif://www.onvif.org/name/HIKVISION%20DS-2CD2042WD-I</d:Scopes>
  <d:XAddrs>http://192.168.1.90/onvif/device_service</d:XAddrs>
 </d:ProbeMatch></d:ProbeMatches></s:Body>
</s:Envelope>"#;

    #[test]
    fn a_probe_asks_everybody() {
        let sent = String::from_utf8(probe(0x1234_5678_9abc_def0_1122_3344_5566_7788)).unwrap();
        // An empty `Probe` with no `Types` filter is what matches every device.
        assert!(sent.contains("<d:Probe/>"));
        assert!(!sent.contains("Types"));
        assert!(sent.contains("/Probe</a:Action>"));
        assert!(sent.contains("urn:schemas-xmlsoap-org:ws:2005:04:discovery"));
    }

    /// The id is a URI, and a fresh one each time. A responder that has already
    /// answered a `MessageID` is entitled to ignore it, so a constant here
    /// would make every scan after the first find fewer devices.
    #[test]
    fn each_probe_carries_its_own_identifier() {
        let one = String::from_utf8(probe(1)).unwrap();
        let two = String::from_utf8(probe(2)).unwrap();
        assert!(one.contains("<a:MessageID>urn:uuid:"));
        assert_ne!(one, two);
    }

    #[test]
    fn a_windows_machine_names_itself_a_computer() {
        let m = parse(WINDOWS.as_bytes()).expect("a probe match");
        assert!(m.types.contains(&"pub:computer".to_string()));
        assert!(m.types.contains(&"wsdp:device".to_string()));
        assert_eq!(
            m.endpoint.as_deref(),
            Some("urn:uuid:cafe0001-0000-0000-0000-00000000abcd")
        );
        assert_eq!(m.addresses, vec!["http://192.168.1.42:5357/cafe0001/"]);
    }

    #[test]
    fn a_camera_names_itself_a_video_transmitter() {
        let m = parse(CAMERA.as_bytes()).expect("a probe match");
        assert_eq!(m.types, vec!["dn:networkvideotransmitter"]);
        assert_eq!(
            m.addresses,
            vec!["http://192.168.1.90/onvif/device_service"]
        );
    }

    /// The scopes were in every reply all along, and the model is in them.
    #[test]
    fn a_cameras_scopes_name_its_hardware() {
        let m = parse(CAMERA.as_bytes()).expect("a probe match");
        assert_eq!(m.scope("hardware").as_deref(), Some("DS-2CD2042WD-I"));
        assert_eq!(m.model().as_deref(), Some("DS-2CD2042WD-I"));
        // The category is matched without regard to case, which is what the
        // capitalised `Profile` in the specification requires of a reader.
        assert_eq!(m.scope("profile").as_deref(), Some("Streaming"));
        // And the escape is undone, or the model arrives with a `%20` in it.
        assert_eq!(
            m.scope("name").as_deref(),
            Some("HIKVISION DS-2CD2042WD-I"),
            "the friendly name is read"
        );
    }

    /// **The rule this file's note argues for.** The friendly name on a
    /// factory-fresh camera is the maker and the model; on the camera next to
    /// it, it is whatever the installer typed, and a "Model: Front door" row
    /// is what `CLAUDE.md` refuses. So the model comes from `hardware`, which
    /// nobody can edit, and the renamed camera reports the same model as the
    /// one that was left alone.
    #[test]
    fn a_camera_somebody_renamed_still_reports_its_own_model() {
        let renamed = CAMERA.replace("HIKVISION%20DS-2CD2042WD-I", "Front%20door");
        let m = parse(renamed.as_bytes()).expect("a probe match");
        assert_eq!(m.scope("name").as_deref(), Some("Front door"));
        assert_eq!(
            m.model().as_deref(),
            Some("DS-2CD2042WD-I"),
            "the model is the hardware and never the label"
        );
    }

    /// A WSD print device writes its maker and model as the fields of a device
    /// identifier rather than as ONVIF scopes.
    ///
    /// **Constructed from Microsoft's WS-Print documentation rather than
    /// captured**: no printer on the network this was written against speaks
    /// WSD. The field spelling is the one that documentation gives, and it is
    /// the same one a Dell 2330dn publishes.
    #[test]
    fn a_printers_scopes_name_its_maker_and_its_model() {
        let printer = CAMERA
            .replace("dn:NetworkVideoTransmitter", "wsdp:Device wprt:PrintDeviceType")
            .replace(
                "onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/hardware/DS-2CD2042WD-I onvif://www.onvif.org/name/HIKVISION%20DS-2CD2042WD-I",
                "ldap:///ou=floor2,o=example MFG:Brother;MDL:HL-L2350DW;CLS:Printer",
            );
        let m = parse(printer.as_bytes()).expect("a probe match");
        assert_eq!(m.model().as_deref(), Some("Brother HL-L2350DW"));
    }

    /// Most printers write the maker into the model as well, and a row reading
    /// "Brother Brother HL-L2350DW" is the sort of thing nobody notices until
    /// it is on a screen.
    #[test]
    fn a_maker_is_not_said_twice() {
        let m = Match {
            scopes: vec!["MFG:Brother;MDL:Brother HL-L2350DW".to_string()],
            ..Default::default()
        };
        assert_eq!(m.model().as_deref(), Some("Brother HL-L2350DW"));

        // A maker with no model names nobody's hardware.
        let m = Match {
            scopes: vec!["MFG:Brother".to_string()],
            ..Default::default()
        };
        assert_eq!(m.model(), None);
    }

    /// A device with no scopes at all is the ordinary case, and it has to come
    /// out as "nothing" rather than as an empty string in a Model row.
    #[test]
    fn a_reply_with_no_scopes_names_nothing() {
        let m = parse(WINDOWS.as_bytes()).expect("a probe match");
        assert!(m.scopes.is_empty());
        assert_eq!(m.model(), None);
        assert_eq!(m.scope("hardware"), None);
    }

    /// The prefix a responder chooses is its own business, and three different
    /// ones have been seen for the same element.
    #[test]
    fn the_namespace_prefix_is_not_part_of_the_element() {
        let bare = WINDOWS
            .replace("wsd:Types", "Types")
            .replace("d:Types", "Types");
        let m = parse(bare.as_bytes()).expect("a probe match");
        assert!(m.types.contains(&"pub:computer".to_string()));
    }

    /// Another scanner's probe arrives on the same group, and it is a question
    /// rather than an answer.
    #[test]
    fn a_probe_is_not_an_answer() {
        assert_eq!(parse(&probe(7)), None);
    }

    /// A device saying goodbye has just left. Putting it on the list would be
    /// the one thing worse than missing it.
    #[test]
    fn a_farewell_is_not_an_arrival() {
        let bye = WINDOWS.replace("/ProbeMatches", "/Bye");
        assert_eq!(parse(bye.as_bytes()), None);
    }

    #[test]
    fn rubbish_is_not_a_device() {
        assert_eq!(parse(b"not xml at all"), None);
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"<s:Envelope><s:Body/></s:Envelope>"), None);
    }
}
