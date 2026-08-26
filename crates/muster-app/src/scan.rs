//! The scan, as the window sees it.
//!
//! A scan runs on its own thread and reports through a channel; the window
//! polls that channel each frame. This module holds the state machine so that
//! what the interface *says* about a scan is decided in one place and can be
//! reasoned about without a window — the same division `CLAUDE.md` describes
//! for Umber's update dialog, where the model is one file and the drawing is
//! another.
//!
//! Two rules from `CLAUDE.md` live here rather than in the painting:
//!
//! * **A scan in progress is a normal state, not a modal.** So [`State`] is a
//!   field of the app rather than something that blocks it, results arrive
//!   incrementally, and cancelling is available throughout.
//! * **Progress over a known total is reported; anything else leaves the bar
//!   empty.** [`Phase::fraction`] returns an [`Option`], and the sweep is the
//!   only phase that can fill it in — the survey is instant and identification
//!   is counted but so short that a bar for it would be a flicker.

use muster_net::discover::{self, Found};
use muster_net::identify::{self, Identity};
use muster_net::link;
use muster_net::rate::Bucket;
use muster_net::{Prefix, Survey};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

/// How long to listen for DHCP offers.
///
/// A server on a healthy link answers in milliseconds. The window is this long
/// because the *second* server is the one being looked for, and a rogue is
/// often a slow one: a small router doing NAT on a busy uplink, or a virtual
/// machine that has to be woken.
const DHCP_WINDOW: Duration = Duration::from_secs(3);

/// What a scan is asked to do.
///
/// Built from the settings, and passed down rather than read from a global: a
/// scan running on its own thread must not be able to change its mind halfway
/// because somebody moved a slider. Every field is a decision somebody made
/// once, in the scan menu or in the settings page, and both write the same
/// [`crate::prefs::Prefs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Probes a second, shared by every probe in the scan.
    pub rate: u32,
    /// Ask each device what it is. Off leaves a list of addresses and vendors.
    pub identify: bool,
    /// Ask each device that answered whether it is a name server.
    pub dns: bool,
    /// Broadcast a DHCP DISCOVER and collect every offer.
    pub dhcp: bool,
    /// Ask each device that answered whether it serves files over SMB.
    pub smb: bool,
    /// The same question over NFS.
    pub nfs: bool,
    /// Read the greeting an SSH server volunteers. Nothing is sent.
    pub ssh: bool,
    /// Ask this network's own resolver for a name for every address in it.
    ///
    /// Separate from [`Self::identify`] because it is a different kind of
    /// question: the others are put to the devices, and this one is put to the
    /// router about them. See [`muster_net::link`] for why it is asked only of
    /// a resolver on this machine's own link.
    pub reverse: bool,
    /// Sit on the discovery ports for the length of the scan and write down
    /// who speaks. See [`muster_net::listen`].
    pub listen: bool,
}

impl Options {
    /// What [`muster_net::service`] is to be asked, out of the three flags
    /// above. One place, so the phase that runs it and the phase that decides
    /// whether to run it at all cannot disagree.
    pub fn serving(self) -> muster_net::service::Options {
        muster_net::service::Options {
            smb: self.smb,
            nfs: self.nfs,
            ssh: self.ssh,
            ..Default::default()
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            rate: muster_net::rate::DEFAULT_RATE,
            identify: true,
            dns: true,
            // See `prefs::Prefs::scan_dhcp`: asking servers to reserve an
            // address is a deliberate act, so it is off until somebody says so.
            dhcp: false,
            // And these three are connections rather than datagrams, which the
            // far end writes down. Same rule, same answer.
            smb: false,
            nfs: false,
            ssh: false,
            // On, and it is the only new question here that is. It goes to one
            // server that already holds the answers, it never leaves the link,
            // and it is what names the devices that are asleep.
            reverse: true,
            // On, and it sends nothing at all. It is the only phase that finds
            // a device by the questions the device itself asks.
            listen: true,
        }
    }
}

/// What the scan thread reports.
pub enum Update {
    Swept {
        probed: u64,
        total: u64,
        found: u64,
        /// The device this probe found, where it found one.
        ///
        /// Carried so the table can fill as the sweep runs. `CLAUDE.md` asks
        /// for results to arrive incrementally, and this is what makes that
        /// true of the devices themselves rather than only of the counter.
        hit: Option<Box<Found>>,
    },
    /// A device the *link* answered for, which the sweep never found.
    ///
    /// Sent between the sweep and identification, so the row appears as soon as
    /// it is known rather than at the end of the scan. There is no progress in
    /// it: the link phase counts nothing, because the number of devices that
    /// are going to answer a multicast question is not knowable before they do.
    Heard {
        address: IpAddr,
        /// Which question it answered, so the row shows the same reason the
        /// finished scan will show.
        protocol: muster_net::discover::Protocol,
    },
    Identifying {
        done: usize,
        total: usize,
    },
    Serving {
        done: usize,
        total: usize,
    },
    Listening {
        left: Duration,
        window: Duration,
    },
    /// The whole result. Sent once, at the end, cancelled or not.
    Done(Box<Outcome>),
}

/// A finished scan.
pub struct Outcome {
    pub sweep: discover::Sweep,
    pub names: Vec<Identity>,
    pub prefix: Prefix,
    /// What answered a DHCP DISCOVER, where one was sent.
    ///
    /// [`None`] means the question was not asked, which is a different thing
    /// from nobody answering and is shown as a different thing:
    /// `dhcp::Probe::not_done` covers "asked and could not", and this covers
    /// "not asked".
    pub dhcp: Option<Box<muster_net::dhcp::Probe>>,
}

/// Which part of a scan is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Sweeping {
        probed: u64,
        total: u64,
    },
    Identifying {
        done: usize,
        total: usize,
    },
    /// Asking the devices that answered what they serve: the connected
    /// questions, which are a phase of their own because they are a different
    /// shape from the datagrams above and are usually not asked at all.
    Serving {
        done: usize,
        total: usize,
    },
    /// Sitting on the discovery ports with nothing left to ask.
    ///
    /// It ran through every phase above it and this is only what is left of its
    /// window, so the bar counts the seconds rather than the devices: how many
    /// devices are going to speak is not knowable, and a bar over an unknown is
    /// refused here as it is everywhere else.
    Listening {
        left: Duration,
        window: Duration,
    },
}

impl Phase {
    /// How far along, where that is knowable.
    ///
    /// Always knowable here, because both phases count over a total decided
    /// before they start. The [`Option`] is kept because the moment a phase
    /// arrives that cannot count — a passive listen, a continuous monitor — the
    /// bar must draw empty rather than animate, and a function returning `f32`
    /// would have nowhere to say so.
    pub fn fraction(self) -> Option<f32> {
        match self {
            Self::Sweeping { probed, total } if total > 0 => Some(probed as f32 / total as f32),
            Self::Identifying { done, total } | Self::Serving { done, total } if total > 0 => {
                Some(done as f32 / total as f32)
            }
            // The seconds are the total, and they are knowable.
            Self::Listening { left, window } if !window.is_zero() => {
                Some(1.0 - left.as_secs_f32() / window.as_secs_f32())
            }
            _ => None,
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::Sweeping { probed, total } => format!("Sweeping {probed} of {total}"),
            Self::Identifying { done, total } => format!("Identifying {done} of {total}"),
            Self::Serving { done, total } => {
                format!("Asking {done} of {total} what they serve")
            }
            Self::Listening { left, .. } => {
                format!("Listening for {} more seconds", left.as_secs() + 1)
            }
        }
    }
}

/// The scan as the window holds it.
pub enum State {
    Idle,
    Running {
        phase: Phase,
        found: u64,
        /// Devices found so far, in the order they answered.
        ///
        /// **Kept here rather than waited for.** The table reads this while the
        /// sweep runs, so a device appears the moment it answers instead of
        /// when the last address in the prefix has been probed. On a /24 that
        /// is a few seconds; on anything larger it is the difference between a
        /// tool that is working and a tool that has hung.
        devices: Vec<Found>,
        cancel: Arc<AtomicBool>,
        rx: Receiver<Update>,
    },
    Finished(Box<Outcome>),
}

impl State {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Starts a scan of one prefix.
    pub fn start(survey: &Survey, prefix: Prefix, on_link: bool, opts: Options) -> Self {
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        // **Only a resolver on this machine's own link is ever asked**, which
        // is `CLAUDE.md`'s rule about somebody else's resolver and is enforced
        // in one place rather than at each question. See
        // `Survey::local_resolver`.
        let resolver = survey.local_resolver();
        // The hardware address of the interface a scan would go out of. A
        // DISCOVER is answered to whoever sent it, so an address nothing on
        // this link owns collects nothing.
        let mac = survey
            .interfaces
            .iter()
            .find(|i| i.is_scannable())
            .and_then(|i| i.mac);
        // What the operating system already knows about this network, read
        // before anything is sent. Devices, at no cost, that no question could
        // reach.
        let neighbours: Vec<(IpAddr, muster_net::MacAddr)> = survey
            .known_in(prefix)
            .map(|n| (n.address, n.mac))
            .collect();
        // Every address this machine holds on a link worth scanning, which is
        // what the listener joins its multicast groups on.
        let own: Vec<std::net::Ipv4Addr> = survey
            .interfaces
            .iter()
            .filter(|i| i.is_scannable())
            .flat_map(|i| i.addresses.iter())
            .filter_map(|a| match a.address {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect();

        {
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                run(Job {
                    prefix,
                    on_link,
                    resolver,
                    mac,
                    neighbours,
                    own,
                    opts,
                    cancel,
                    tx,
                });
            });
        }

        Self::Running {
            phase: Phase::Sweeping {
                probed: 0,
                total: prefix.host_count(),
            },
            found: 0,
            devices: Vec::new(),
            cancel,
            rx,
        }
    }

    /// Drains whatever the thread has said. Returns true when something moved,
    /// which is what tells the window to ask for another frame.
    pub fn poll(&mut self) -> bool {
        let mut moved = false;
        let mut finished = None;

        if let Self::Running {
            phase,
            found,
            devices,
            rx,
            ..
        } = self
        {
            loop {
                match rx.try_recv() {
                    Ok(Update::Swept {
                        probed,
                        total,
                        found: f,
                        hit,
                    }) => {
                        *phase = Phase::Sweeping { probed, total };
                        *found = f;
                        if let Some(device) = hit {
                            devices.push(*device);
                        }
                        moved = true;
                    }
                    Ok(Update::Heard { address, protocol }) => {
                        // Kept in the same order the finished sweep will use,
                        // so a row does not jump when the scan ends.
                        if let Err(at) = devices.binary_search_by_key(&address, |d| d.address) {
                            devices.insert(at, Found::announced(address, protocol));
                            *found += 1;
                        }
                        moved = true;
                    }
                    Ok(Update::Identifying { done, total }) => {
                        *phase = Phase::Identifying { done, total };
                        moved = true;
                    }
                    Ok(Update::Serving { done, total }) => {
                        *phase = Phase::Serving { done, total };
                        moved = true;
                    }
                    Ok(Update::Listening { left, window }) => {
                        *phase = Phase::Listening { left, window };
                        moved = true;
                    }
                    Ok(Update::Done(outcome)) => {
                        finished = Some(outcome);
                        moved = true;
                        break;
                    }
                    // Disconnected without a result means the thread died,
                    // which can only be a panic in it.
                    //
                    // **This must return to idle, and for a while it said so
                    // and did not.** The comment here described the behaviour
                    // and the code only broke out of the loop, leaving `self`
                    // in `Running`: the bar sat at "Sweeping n of m" for ever,
                    // Stop did nothing anybody could see, the Scan button stayed
                    // unreachable because `scan_control` returns early while a
                    // scan is running, and the window asked for a repaint every
                    // 60 ms for the rest of the session. `ports.rs` and
                    // `dhcpcheck.rs` both handle this correctly, which is what
                    // makes the omission plainly accidental rather than a
                    // decision.
                    //
                    // No outcome is invented: idle is "no scan", which is what
                    // is true, where an empty `Finished` would claim the network
                    // was swept and found nothing.
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        *self = Self::Idle;
                        return true;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            }
        }

        if let Some(outcome) = finished {
            *self = Self::Finished(outcome);
        }
        moved
    }

    /// Asks the scan to stop. It stops at the next probe rather than at the end
    /// of a phase, which is `CLAUDE.md`'s rule.
    pub fn cancel(&self) {
        if let Self::Running { cancel, .. } = self {
            cancel.store(true, Ordering::SeqCst);
        }
    }

    /// The devices to show: the finished ones, or nothing yet.
    /// Every device known so far, finished or not.
    ///
    /// While a sweep runs this is what has answered up to now; once it ends it
    /// is the sweep's own list. Both are "what Muster has found", which is the
    /// only thing the table ever wants.
    pub fn devices(&self) -> &[Found] {
        match self {
            Self::Finished(o) => &o.sweep.found,
            Self::Running { devices, .. } => devices,
            Self::Idle => &[],
        }
    }

    /// Record what a port scan found, so identification can use it.
    ///
    /// **Without this the port half of `kind::identify` is dead code.** The
    /// only producer of `Evidence::TcpOpen` in the engine is the sweep's knock,
    /// which tries 80, 443, 22 and 445 — and `kind`'s port table deliberately
    /// excludes exactly those four, because they are on everything and name
    /// nothing. So the ports that *do* name a kind (9100 a printer, 32400 a
    /// Plex server, 554 a camera) were never in the evidence a guess was made
    /// from, and a device stayed `Unknown` even after the user had run a port
    /// scan and could see 9100 open in the panel.
    ///
    /// Folding the result back into the device's own evidence is what closes
    /// that, and it keeps the existing rule intact: the guess is still made
    /// from evidence attached to the device, and the row's tooltip still names
    /// the clue.
    pub fn record_open_ports(&mut self, address: IpAddr, open: &[u16]) {
        let devices = match self {
            Self::Finished(outcome) => &mut outcome.sweep.found,
            Self::Running { devices, .. } => devices,
            Self::Idle => return,
        };
        let Some(device) = devices.iter_mut().find(|d| d.address == address) else {
            return;
        };
        for port in open {
            let evidence = muster_net::discover::Evidence::TcpOpen(*port);
            if !device.evidence.contains(&evidence) {
                device.evidence.push(evidence);
            }
        }
    }

    /// The names learned, parallel to [`Self::devices`].
    ///
    /// Empty while a sweep is running: identification is phase four and has not
    /// started yet, so a device on screen mid-scan has an address and no name.
    /// That is honest — the alternative is holding the whole table back until
    /// every name is in.
    pub fn names(&self) -> &[Identity] {
        match self {
            Self::Finished(o) => &o.names,
            _ => &[],
        }
    }
}

/// Everything one scan needs, so the thread takes one argument rather than
/// eight and adding a source does not change a signature in three places.
struct Job {
    prefix: Prefix,
    on_link: bool,
    /// The resolver, **already checked to be on this machine's own link**.
    resolver: Option<IpAddr>,
    mac: Option<muster_net::MacAddr>,
    /// What the neighbour table held before the scan started.
    neighbours: Vec<(IpAddr, muster_net::MacAddr)>,
    /// This machine's own IPv4 addresses, which is what a multicast group is
    /// joined on. A machine with a VPN up has more than one, and joining the
    /// wrong one listens to the wrong link.
    own: Vec<std::net::Ipv4Addr>,
    opts: Options,
    cancel: Arc<AtomicBool>,
    tx: Sender<Update>,
}

/// How long the listen runs for.
///
/// It overlaps everything else, so on an ordinary /24 — eight seconds of sweep
/// and identification — this adds about seven seconds to a scan and hears the
/// whole of it. Longer is better and there is no cliff: the devices arrive
/// steadily, and on the network this was measured against half of them spoke
/// after the first eighty seconds. A scan is not the place to wait that long,
/// and that measurement is the argument for the monitoring mode `CLAUDE.md`
/// lists as open rather than for a slower scan here.
const LISTEN_WINDOW: Duration = Duration::from_secs(15);

/// How often the tail of the listen reports itself.
const LISTEN_TICK: Duration = Duration::from_millis(200);

fn run(job: Job) {
    let Job {
        prefix,
        on_link,
        resolver,
        mac,
        neighbours,
        own,
        opts,
        cancel,
        tx,
    } = job;

    let transport = muster_net::platform::Host;
    let rate = Bucket::new(opts.rate);
    let started = std::time::Instant::now();
    // The listen runs through every phase below and is stopped when they are
    // all done. It is a flag of its own rather than the scan's `cancel`,
    // because "the rest of the scan has finished" and "the user pressed stop"
    // are different things and only one of them means the results are partial.
    let hush = AtomicBool::new(false);

    // **Started first and collected last.** A DISCOVER is one broadcast and
    // then a wait on a socket, which overlaps the sweep and the identification
    // for nothing: by the time there is a device list to attribute offers to,
    // the offers are already in. Running it as a phase of its own would have
    // added its whole window to every scan.
    let dhcp = (opts.dhcp && mac.is_some()).then(|| {
        let mac = mac.expect("checked");
        std::thread::spawn(move || {
            // A fresh transaction id per probe, from the clock rather than a
            // counter: a predictable id on a real network collects somebody
            // else's negotiation.
            let xid = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0x4d75_7374, |d| d.subsec_nanos() ^ d.as_secs() as u32);
            muster_net::dhcp::probe(&muster_net::platform::udp::Dhcp, mac, xid, DHCP_WINDOW)
        })
    });

    let sweep_opts = if on_link {
        discover::Options::on_link()
    } else {
        discover::Options::default()
    };

    // What the link is asked, and it is asked **beside the sweep** for the
    // same reason the DISCOVER is: every question in it is one datagram and
    // then a wait, so running it as a phase of its own would add its whole
    // window to every scan for nothing. See `muster_net::link`.
    let link_opts = link::Options {
        mdns: opts.identify,
        ssdp: opts.identify,
        wsd: opts.identify,
        // A broadcast is only meaningful on a link this machine is on, and
        // `Prefix::broadcast` is `None` for anything without host bits to
        // spare.
        netbios: opts.identify && on_link,
        reverse: opts.reverse,
        broadcast: on_link.then(|| prefix.broadcast()).flatten(),
        resolver,
        ..Default::default()
    };
    // The addresses the reverse question asks about: the whole prefix, because
    // the point of it is the addresses the sweep is going to miss.
    let every: Vec<IpAddr> = prefix
        .hosts()
        .map(|hosts| hosts.collect())
        .unwrap_or_default();

    std::thread::scope(|scope| {
        // Sits on the discovery ports for as long as everything else takes, and
        // sends nothing but the datagram that keeps a stateful firewall from
        // dropping what it is listening for. See `muster_net::listen`.
        let ears = opts.listen.then(|| {
            scope.spawn(|| {
                muster_net::listen::overhear(
                    &muster_net::platform::listen::Link,
                    &own,
                    LISTEN_WINDOW,
                    &hush,
                )
            })
        });

        let (mut sweep, heard) = std::thread::scope(|scope| {
            let asked = scope.spawn(|| {
                link::ask(
                    &muster_net::platform::udp::Udp,
                    link_opts,
                    &every,
                    &rate,
                    &cancel,
                )
            });

            let sweep =
                discover::sweep(prefix, &transport, &rate, sweep_opts, &cancel, &|p, hit| {
                    let _ = tx.send(Update::Swept {
                        probed: p.probed,
                        total: p.total,
                        found: p.found,
                        hit: hit.cloned().map(Box::new),
                    });
                });

            (sweep, asked.join().unwrap_or_default())
        });

        // **The union, and the whole point of the link phase.** A device that
        // answered a group question is a device, whether or not anything sent to
        // its own address came back, so it goes on the list with the protocol it
        // answered as its evidence. A device the sweep already found gains a
        // reason rather than a row.
        //
        // Only what *spoke* is admitted. A resolver's `PTR` record names an
        // address without proving anything is at it, so it names the devices found
        // by other means and never puts a row on the list by itself.
        for (address, _) in heard.speakers() {
            if let Some(protocol) = heard.credit(address)
                && sweep.admit(Found::announced(address, protocol))
            {
                let _ = tx.send(Update::Heard { address, protocol });
            }
        }

        // And what the operating system knew before any of this started. The
        // cheapest source there is, and the weakest, and it says so on the row.
        for (address, mac) in neighbours {
            sweep.admit_neighbour(address, mac);
        }

        sweep.not_done.extend(heard.not_done.iter().cloned());

        let addresses: Vec<_> = sweep.found.iter().map(|f| f.address).collect();
        let mut names = identify::many(
            &addresses,
            &muster_net::platform::udp::Udp,
            &rate,
            identify::Options {
                resolver,
                mdns: opts.identify,
                netbios: opts.identify,
                ssdp: opts.identify,
                llmnr: opts.identify,
                dns: opts.dns,
                ..Default::default()
            },
            &cancel,
            &|done, total| {
                let _ = tx.send(Update::Identifying { done, total });
            },
        );

        // What the link said about each of them, folded in beside what they said
        // when asked privately. This is where a device that answered only the
        // group gets its name, its services and its model.
        for (address, identity) in addresses.iter().zip(names.iter_mut()) {
            if let Some(voice) = heard.by.get(address) {
                identity.merge(&voice.identity);
            }
        }

        // What the devices serve, over a connection rather than a datagram. A
        // phase of its own and after identification rather than inside it: these
        // are TCP, they are off unless somebody switched one on, and a device that
        // never answered the sweep is never connected to.
        if opts.serving().any() && !cancel.load(Ordering::SeqCst) {
            let serving = muster_net::service::many(
                &addresses,
                &muster_net::platform::tcp::Stream,
                &rate,
                opts.serving(),
                &cancel,
                &|done, total| {
                    let _ = tx.send(Update::Serving { done, total });
                },
            );
            for (identity, serves) in names.iter_mut().zip(serving.iter()) {
                identity.serves(serves);
            }
        }

        // The offers, and who made them. A server that answered is a device on the
        // list — usually the gateway — so the badge goes on its row rather than
        // only into a paragraph on another screen.
        //
        // A thread that panicked gives `None`, which is "not asked" rather than
        // "nobody answered". The two must not collapse into one another.
        let dhcp = dhcp.and_then(|handle| handle.join().ok());
        if let Some(probe) = &dhcp {
            for server in probe.servers() {
                let server = IpAddr::V4(server);
                if let Some(i) = addresses.iter().position(|a| *a == server) {
                    names[i].offers_addresses();
                }
            }
        }

        // Everything that asks a question is done. What is left is the listen,
        // and the only honest thing to show is how much of its window remains.
        if let Some(ears) = ears {
            while !cancel.load(Ordering::SeqCst) {
                let left = LISTEN_WINDOW.saturating_sub(started.elapsed());
                if left.is_zero() {
                    break;
                }
                let _ = tx.send(Update::Listening {
                    left,
                    window: LISTEN_WINDOW,
                });
                std::thread::sleep(LISTEN_TICK.min(left));
            }
            hush.store(true, Ordering::SeqCst);

            let overheard = ears.join().unwrap_or_default();
            // Folded in the same way the link phase's answers were, and by the same
            // function, so the device list and the names beside it stay in step.
            link::fold(&overheard, &mut sweep, &mut names);
            sweep.not_done.extend(overheard.not_done.iter().cloned());
        }

        let _ = tx.send(Update::Done(Box::new(Outcome {
            sweep,
            names,
            prefix,
            dhcp: dhcp.map(Box::new),
        })));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule: a bar over an unknown total draws empty rather than animating.
    /// Both phases can count today, so the guard is what keeps the next one
    /// honest.
    #[test]
    fn progress_over_nothing_is_not_a_fraction() {
        assert_eq!(
            Phase::Sweeping {
                probed: 0,
                total: 0
            }
            .fraction(),
            None
        );
        assert_eq!(Phase::Identifying { done: 3, total: 0 }.fraction(), None);
    }

    #[test]
    fn progress_over_a_known_total_is_reported() {
        assert_eq!(
            Phase::Sweeping {
                probed: 127,
                total: 254
            }
            .fraction(),
            Some(0.5)
        );
        assert_eq!(
            Phase::Identifying { done: 1, total: 4 }.fraction(),
            Some(0.25)
        );
    }

    #[test]
    fn a_phase_says_what_it_is_doing() {
        assert_eq!(
            Phase::Sweeping {
                probed: 10,
                total: 254
            }
            .label(),
            "Sweeping 10 of 254"
        );
        assert_eq!(
            Phase::Identifying { done: 2, total: 9 }.label(),
            "Identifying 2 of 9"
        );
    }

    /// An idle or running scan shows no devices rather than a stale list from
    /// the run before, which would be the wrong network entirely after the
    /// target changed.
    #[test]
    fn only_a_finished_scan_has_devices() {
        assert!(State::Idle.devices().is_empty());
        assert!(State::Idle.names().is_empty());
        assert!(!State::Idle.is_running());
    }

    /// Cancelling an idle scan is a no-op rather than a panic: the button is
    /// drawn from the same state that decides whether it does anything.
    #[test]
    fn cancelling_nothing_is_harmless() {
        State::Idle.cancel();
    }
}
