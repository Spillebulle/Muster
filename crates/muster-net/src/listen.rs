//! Hearing the devices that never answer anything.
//!
//! Every other phase asks a question. This one asks nothing at all: it sits on
//! the ports the discovery protocols use, joins the groups they multicast to,
//! and writes down who speaks. **It is the only part of the engine that finds a
//! device without sending it a single packet**, and it reaches a class of
//! device nothing else here can.
//!
//! ## Why it works when everything else fails
//!
//! A device that ignores ping, drops every connection and answers no search is
//! still on a network it needs something from. It looks for its
//! Chromecast, it resolves a name over mDNS, it renews a DHCP lease, it asks
//! SSDP where the media server is. **Those questions are multicast, and a
//! question identifies its asker exactly as well as an answer does.**
//!
//! Measured on one real network over 150 seconds, eight addresses spoke. Two of
//! them were revealed *only* by questions they asked — nothing sent to them
//! would have made either one say a word.
//!
//! ## It costs nothing, because it runs beside everything else
//!
//! The window is the whole cost, and the window is spent waiting on a socket
//! while the sweep, the link phase and identification all run. So the listen
//! starts when the scan starts and is collected when the scan ends, and a scan
//! that would have taken twelve seconds still takes twelve seconds.
//!
//! ## The Windows firewall, and the one datagram that has to be sent
//!
//! **A listener that truly sends nothing hears nothing at all on Windows**, and
//! it fails silently, which is the worst way for it to fail: no error, no
//! clue, just a quiet network. Windows Firewall is stateful, and unsolicited
//! inbound multicast to a joined group has no state to match, so it is dropped
//! before the socket sees it. Measured on the same machine, same socket, same
//! forty-second window: nothing sent, **zero** datagrams from **zero** sources;
//! one datagram sent first, **fifty-three** datagrams from **four** sources.
//!
//! So each watch sends one datagram from its own bound port to its own group
//! before it starts listening, and again every [`POKE_EVERY`] to keep the
//! mapping alive. It is the smallest thing that can be sent that is still a
//! well-formed question in the protocol, and every one of them is chosen to
//! match nothing, so no device is asked to answer and nothing is provoked. The
//! link phase is where the questions that expect answers are asked.
//!
//! ## And the ports are shared, not taken
//!
//! Port 5353 belongs to this machine's own mDNS responder, 1900 to its SSDP
//! service and 3702 to WSDAPI. Muster does not take any of them: every socket
//! sets `SO_REUSEADDR` first, which on both platforms lets a second listener
//! join a multicast port beside the first and have the datagrams delivered to
//! both. **Nothing here ever replies**, so the responders that own those ports
//! keep answering for the machine exactly as they did before.
//!
//! As everywhere else in this crate, nothing in this file opens a socket: the
//! real one is in `platform`, and every test runs against a recorded ear.

use crate::discover::Protocol;
use crate::identify::{Identity, Source};
use crate::link::{Heard, Voice};
use crate::{dns, netbios, ssdp, wsd};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// How often the pinhole is re-opened.
///
/// Windows keeps a stateful mapping for a datagram flow for rather longer than
/// this, and the cost of being wrong is the whole listen going deaf halfway
/// through with nothing on screen to say so. Twenty seconds is four datagrams
/// in a long scan.
pub const POKE_EVERY: Duration = Duration::from_secs(20);

/// A port to sit on, and the group to join while sitting there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch {
    /// What is credited when something is heard here.
    pub protocol: Protocol,
    pub port: u16,
    /// The multicast group to join. [`None`] for the protocols that broadcast
    /// instead, where being bound to the port is enough.
    pub group: Option<Ipv4Addr>,
}

/// The ports worth sitting on.
///
/// Four, and each hears a different kind of device:
///
/// * **5353** is the loudest port on any modern network. Every Apple device,
///   every printer, every Chromecast and everything running Avahi announces
///   here — and, more usefully, *queries* here, which is how a device that
///   advertises nothing gives itself away.
/// * **1900** carries `NOTIFY ssdp:alive`, which every UPnP device repeats on
///   its own `CACHE-CONTROL` cycle. A router advertising `max-age=60` says
///   something every thirty seconds without being asked.
/// * **3702** carries WS-Discovery `Hello`, which a Windows machine sends when
///   it wakes and a printer sends when it joins.
/// * **137** is the NetBIOS name service, and it is here for the questions
///   rather than the answers: a Windows machine resolving a neighbour's name
///   broadcasts to it, which identifies the asker whether or not anybody
///   replies.
///
/// Port 5355 (LLMNR) is deliberately not here. It carries queries from Windows
/// machines, which would be worth hearing, but a Windows machine that queries
/// LLMNR has already announced itself on 5353 or 3702 in the same minute — and
/// a fifth socket for a device already found is a socket for nothing.
pub const WATCHED: &[Watch] = &[
    Watch {
        protocol: Protocol::Mdns,
        port: 5353,
        group: Some(Ipv4Addr::new(224, 0, 0, 251)),
    },
    Watch {
        protocol: Protocol::Ssdp,
        port: 1900,
        group: Some(Ipv4Addr::new(239, 255, 255, 250)),
    },
    Watch {
        protocol: Protocol::WsDiscovery,
        port: 3702,
        group: Some(Ipv4Addr::new(239, 255, 255, 250)),
    },
    Watch {
        protocol: Protocol::NetBios,
        port: 137,
        group: None,
    },
];

/// The datagram sent to open a path back through a stateful firewall.
///
/// **Every one of these is a well-formed question that matches nothing.** That
/// is the whole design of them: the datagram has to be real enough that the
/// firewall records a flow and the responders on the link do not take offence,
/// and empty enough that no device is asked for anything. The questions that
/// expect answers are [`crate::link`]'s, and they are asked once, there.
pub fn poke(watch: &Watch) -> Vec<u8> {
    match watch.protocol {
        // A service type nobody offers. A responder reads it, finds no record
        // for the name, and by RFC 6762 says nothing at all.
        Protocol::Mdns => dns::query(0, "_muster-probe._udp.local", dns::TYPE_PTR, false),
        // A search target no device can match, so every responder ignores it.
        Protocol::Ssdp => ssdp::search_target(ssdp::GROUP, "urn:muster-probe:service:none:1"),
        // A `Probe` filtered to a type that does not exist. An empty `Probe`
        // would match every device on the link and bring a shower of replies,
        // which is [`crate::link`]'s job and not this one's.
        Protocol::WsDiscovery => wsd::probe_for(0, "muster:None"),
        // NetBIOS is a broadcast rather than a group, and a wildcard node
        // status is the smallest well-formed thing there is. It may be
        // answered, and an answer is welcome: it carries a name, a workgroup
        // and a hardware address.
        Protocol::NetBios => netbios::node_status_query(0),
        // Nothing is watched for these, and there is nothing to send.
        Protocol::Dns => Vec::new(),
    }
}

/// One watch's findings: who spoke, and the sentence for a port that could not
/// be had.
type Overheard = (Vec<(IpAddr, Protocol, Identity)>, Option<String>);

/// Where the datagrams come from. The whole platform surface of this phase.
pub trait Ear: Sync {
    /// Sits on `watch`'s port for `window`, and answers with every datagram
    /// that arrived and the address it came from.
    ///
    /// The implementation joins `watch.group` on each address in `on`, sends
    /// `poke` from the bound port before listening and again every
    /// [`POKE_EVERY`], and stops early when `cancel` is set. An error means the
    /// port could not be had at all, which the caller reports rather than
    /// treating as a quiet link.
    fn overhear(
        &self,
        watch: &Watch,
        on: &[Ipv4Addr],
        poke: &[u8],
        window: Duration,
        cancel: &AtomicBool,
    ) -> io::Result<Vec<(IpAddr, Vec<u8>)>>;
}

/// Listens on every watched port at once, and returns who spoke.
///
/// One thread and one socket per watch, because each has to be bound to its own
/// port and they all wait at the same time.
///
/// **Never fails.** A port that could not be had is a line in
/// [`Heard::not_done`]: the whole point of this phase is finding devices that
/// hide, so a phase that could not run and did not say so would be reporting
/// their absence as a fact.
pub fn overhear<E: Ear>(ear: &E, on: &[Ipv4Addr], window: Duration, cancel: &AtomicBool) -> Heard {
    let answers: Vec<Overheard> = std::thread::scope(|scope| {
        let handles: Vec<_> = WATCHED
            .iter()
            .map(|watch| {
                scope.spawn(
                    move || match ear.overhear(watch, on, &poke(watch), window, cancel) {
                        Ok(datagrams) => (read(watch, datagrams), None),
                        Err(e) => (Vec::new(), Some(deaf(watch, &e))),
                    },
                )
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_default())
            .collect()
    });

    let mut heard = Heard::default();
    for (spoke, gap) in answers {
        for (address, protocol, identity) in spoke {
            let voice = heard.by.entry(address).or_insert_with(Voice::default);
            voice.protocols.insert(protocol);
            voice.identity.merge(&identity);
        }
        if let Some(gap) = gap {
            heard.not_done.push(gap);
        }
    }
    heard
}

/// The sentence for a port that could not be listened on.
fn deaf(watch: &Watch, error: &io::Error) -> String {
    format!(
        "could not listen on port {} for {} ({error}), so devices that only ever speak there were missed",
        watch.port,
        watch.protocol.label()
    )
}

/// Reads what arrived on one port.
///
/// **The sender is the finding, and the contents are a bonus.** A datagram on
/// one of these ports proves a device at the address it came from, whether it
/// was an announcement, a reply or a question — and a question is the case this
/// phase exists for, because a device asking one is a device that will never
/// answer one. So an unparseable datagram still puts the address on the list;
/// only the identity depends on being able to read it.
fn read(watch: &Watch, datagrams: Vec<(IpAddr, Vec<u8>)>) -> Vec<(IpAddr, Protocol, Identity)> {
    let mut by: std::collections::BTreeMap<IpAddr, Identity> = std::collections::BTreeMap::new();
    for (from, datagram) in datagrams {
        // The address is recorded first and unconditionally. Everything below
        // may add to the identity and none of it can take the device away.
        let entry = by.entry(from).or_default();
        match watch.protocol {
            Protocol::Mdns => {
                if let Some(message) = dns::parse(&datagram) {
                    // Only a *reply* describes a device. A query names what its
                    // asker is looking for, which says nothing about what the
                    // asker is — and harvesting it would put the Chromecast's
                    // service type on the phone looking for one.
                    if message.is_response() {
                        let mut models = Vec::new();
                        crate::identify::harvest(&message, entry, &mut models);
                        models.sort_by_key(|(rank, _)| *rank);
                        if entry.model.is_none() {
                            entry.model = models.into_iter().next().map(|(_, v)| v);
                        }
                    }
                }
            }
            Protocol::Ssdp => {
                if let Some(announcement) = ssdp::parse(&datagram) {
                    entry.announced(&announcement);
                }
            }
            Protocol::WsDiscovery => {
                if let Some(matched) = wsd::parse(&datagram) {
                    entry.probed(&matched);
                }
            }
            Protocol::NetBios => {
                if let Some(status) = netbios::parse_node_status(&datagram) {
                    if let Some(name) = status.hostname() {
                        entry.add(name.to_string(), Source::NetBios);
                    }
                    if entry.workgroup.is_none() {
                        entry.workgroup = status.workgroup().map(str::to_string);
                    }
                    if entry.mac.is_none() {
                        entry.mac = status.mac;
                    }
                }
            }
            Protocol::Dns => {}
        }
    }
    by.into_iter()
        .map(|(address, identity)| (address, watch.protocol, identity))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A recorded link: what was overheard on each port.
    #[derive(Default)]
    struct Recorded {
        on: BTreeMap<u16, Vec<(IpAddr, Vec<u8>)>>,
        deaf_to: Vec<u16>,
        poked: Mutex<Vec<(u16, Vec<u8>)>>,
    }

    impl Ear for Recorded {
        fn overhear(
            &self,
            watch: &Watch,
            _on: &[Ipv4Addr],
            poke: &[u8],
            _window: Duration,
            _cancel: &AtomicBool,
        ) -> io::Result<Vec<(IpAddr, Vec<u8>)>> {
            self.poked.lock().unwrap().push((watch.port, poke.to_vec()));
            if self.deaf_to.contains(&watch.port) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "something already holds it",
                ));
            }
            Ok(self.on.get(&watch.port).cloned().unwrap_or_default())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn run(ear: &Recorded) -> Heard {
        overhear(
            ear,
            &[Ipv4Addr::new(192, 168, 1, 150)],
            Duration::from_millis(1),
            &AtomicBool::new(false),
        )
    }

    /// **The whole reason this phase exists.** A device that asks a question
    /// has proved it is there, and no answer it gives is needed. This is the
    /// case nothing else in the engine can reach.
    #[test]
    fn a_device_that_only_ever_asks_a_question_is_found() {
        let mut ear = Recorded::default();
        // A phone looking for a Chromecast. It is a query, not a reply.
        ear.on.insert(
            5353,
            vec![(
                ip("192.168.1.77"),
                dns::query(0, "_googlecast._tcp.local", dns::TYPE_PTR, false),
            )],
        );

        let heard = run(&ear);
        let voice = heard.by.get(&ip("192.168.1.77")).expect("a device");
        assert!(voice.protocols.contains(&Protocol::Mdns));
        assert!(voice.spoke());
        // And it is not credited with what it was *looking for*.
        assert!(
            voice.identity.services.is_empty(),
            "a question says what it wants, not what it is"
        );
    }

    /// An announcement is a device describing itself, and that is read.
    #[test]
    fn an_unsolicited_announcement_names_the_device_that_sent_it() {
        let mut ear = Recorded::default();
        ear.on.insert(
            1900,
            vec![(
                ip("192.168.1.1"),
                b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: TP-LINK/TP-LINK UPnP/1.1\r\nNTS: ssdp:alive\r\n\r\n".to_vec(),
            )],
        );

        let heard = run(&ear);
        let voice = &heard.by[&ip("192.168.1.1")];
        assert_eq!(
            voice.identity.product.as_deref(),
            Some("TP-LINK/TP-LINK UPnP/1.1")
        );
        assert!(
            voice
                .identity
                .upnp
                .iter()
                .any(|u| u.contains("internetgatewaydevice"))
        );
    }

    /// A datagram nothing can parse still proves a device. The address is the
    /// finding.
    #[test]
    fn rubbish_on_a_watched_port_is_still_a_device() {
        let mut ear = Recorded::default();
        ear.on.insert(
            3702,
            vec![(ip("192.168.1.30"), b"not a soap envelope".to_vec())],
        );

        let heard = run(&ear);
        let voice = heard.by.get(&ip("192.168.1.30")).expect("a device");
        assert!(voice.protocols.contains(&Protocol::WsDiscovery));
        assert!(voice.identity.is_empty(), "and it is not described");
    }

    /// A port that could not be had is said out loud, because the whole point
    /// of this phase is the devices that hide.
    #[test]
    fn a_port_that_could_not_be_had_is_said_out_loud() {
        let ear = Recorded {
            deaf_to: vec![5353],
            ..Default::default()
        };
        let heard = run(&ear);
        assert_eq!(heard.not_done.len(), 1);
        assert!(heard.not_done[0].contains("5353"));
        assert!(heard.not_done[0].contains("mDNS"));
    }

    /// Every watch sends its pinhole datagram, or the listener is deaf on
    /// Windows and says nothing about it.
    #[test]
    fn every_watch_opens_its_own_path_back() {
        let ear = Recorded::default();
        let _ = run(&ear);
        let poked = ear.poked.lock().unwrap().clone();
        assert_eq!(poked.len(), WATCHED.len());
        for (_, payload) in &poked {
            assert!(!payload.is_empty(), "an empty poke opens nothing");
        }
    }

    /// And every one of them matches nothing, so no device is asked to answer.
    #[test]
    fn the_pinhole_datagrams_ask_for_nothing_that_exists() {
        let ssdp = String::from_utf8(poke(&WATCHED[1])).unwrap();
        assert!(ssdp.contains("ST: urn:muster-probe:service:none:1"));

        let mdns = dns::parse(&poke(&WATCHED[0])).expect("a query");
        assert_eq!(mdns.questions[0].0, "_muster-probe._udp.local");
        assert!(!mdns.is_response());

        let probe = String::from_utf8(poke(&WATCHED[2])).unwrap();
        assert!(probe.contains("muster:None"), "{probe}");
        assert!(
            !probe.contains("<d:Probe/>"),
            "an empty probe matches everything"
        );
    }

    /// Two ports hearing the same device is one device with two protocols
    /// against its name.
    #[test]
    fn one_device_heard_twice_is_one_device() {
        let mut ear = Recorded::default();
        ear.on.insert(
            5353,
            vec![(
                ip("192.168.1.20"),
                dns::query(0, "_ipp._tcp.local", dns::TYPE_PTR, false),
            )],
        );
        ear.on.insert(
            3702,
            vec![(ip("192.168.1.20"), b"anything at all".to_vec())],
        );

        let heard = run(&ear);
        assert_eq!(heard.by.len(), 1);
        assert_eq!(
            heard.by[&ip("192.168.1.20")]
                .protocols
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![Protocol::Mdns, Protocol::WsDiscovery]
        );
    }
}
