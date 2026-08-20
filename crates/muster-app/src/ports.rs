//! One device's ports, as the window sees it.
//!
//! The same division `scan.rs` keeps: the state machine is here so that what
//! the interface *says* about a port scan is decided in one place and can be
//! reasoned about without a window, and `app.rs` only draws it.
//!
//! Two rules from `CLAUDE.md` live here rather than in the painting.
//!
//! * **An unanswered probe is filtered, never closed.** [`muster_net::portscan`]
//!   keeps the three states apart all the way from the socket, and this module
//!   carries that distinction to the screen instead of collapsing it into "not
//!   open". A port nothing came back from is not evidence that the port is
//!   shut, and reporting it as such invents a fact about somebody's network.
//! * **The interface says which engine produced a result.** [`Scan::method`] is
//!   `connect()` today and will be a SYN scan when there is raw packet access;
//!   [`Ports::caveats`] carries whatever the engine wants said, and the panel
//!   shows it rather than presenting one method's answer as the other's.
//!
//! A scan is per device and runs on its own thread. Only one runs at a time:
//! the rate limiter is global, so two at once would each get half the budget
//! and both look broken, and there is one panel to show a result in.

use muster_net::portscan::{self, Method, PortState, Ports as PortList, Scan};
use muster_net::rate::Bucket;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};

/// Probes a second, for one host.
///
/// Far below the sweep's budget and deliberately so. This is one machine being
/// asked several hundred questions in a row, which is the shape of traffic a
/// consumer firewall reads as a port scan and starts dropping — and dropped
/// probes come back as `Filtered`, so an impatient scan reports a machine as
/// more closed than it is.
const RATE: u32 = 400;

/// What the worker reports.
///
/// Public only because it appears in [`State::Running`]'s receiver, which a
/// public enum's variant makes reachable. Nothing outside this module
/// constructs or reads one.
pub enum Update {
    Progress { probed: u64, total: u64 },
    Done(Box<Scan>),
}

/// A port scan of one device.
pub enum State {
    /// Nothing asked for this device yet.
    Idle,
    Running {
        address: IpAddr,
        probed: u64,
        total: u64,
        cancel: Arc<AtomicBool>,
        rx: Receiver<Update>,
    },
    Finished {
        address: IpAddr,
        scan: Box<Scan>,
    },
}

impl State {
    /// Start scanning `address` over `ports`.
    pub fn start(address: IpAddr, ports: PortList) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        let total = ports.len() as u64;

        let worker_cancel = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let bucket = Bucket::new(RATE);
            let progress_tx = tx.clone();
            let scan = portscan::scan(
                &[address],
                &ports,
                &portscan::ConnectScanner,
                &bucket,
                portscan::Options::default(),
                &worker_cancel,
                &move |probed, total| {
                    let _ = progress_tx.send(Update::Progress { probed, total });
                },
            );
            let _ = tx.send(Update::Done(Box::new(scan)));
        });

        Self::Running {
            address,
            probed: 0,
            total,
            cancel,
            rx,
        }
    }

    /// Take whatever the worker has said. Returns true when something changed,
    /// which is what tells the window to ask for another frame.
    pub fn poll(&mut self) -> bool {
        let Self::Running {
            address,
            probed,
            total,
            rx,
            ..
        } = self
        else {
            return false;
        };

        let mut changed = false;
        let mut finished = None;
        loop {
            match rx.try_recv() {
                Ok(Update::Progress {
                    probed: p,
                    total: t,
                }) => {
                    *probed = p;
                    *total = t;
                    changed = true;
                }
                Ok(Update::Done(scan)) => {
                    finished = Some(scan);
                    changed = true;
                    break;
                }
                // The worker ended without a result, which can only be a panic
                // in it. Fall back to idle rather than sitting on a bar for
                // ever.
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if finished.is_none() {
                        *self = Self::Idle;
                        return true;
                    }
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }

        if let Some(scan) = finished {
            *self = Self::Finished {
                address: *address,
                scan,
            };
        }
        changed
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Stop, at the next probe rather than at the end.
    pub fn cancel(&mut self) {
        if let Self::Running { cancel, .. } = self {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Which device this is about, where it is about one.
    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Self::Idle => None,
            Self::Running { address, .. } | Self::Finished { address, .. } => Some(*address),
        }
    }

    /// How far along, or `None` where that cannot be said.
    ///
    /// The `Option` is honoured rather than defaulted, for the reason it is
    /// honoured everywhere else in this application: a bar that animates over
    /// an unknown is a lie about somebody's network.
    pub fn fraction(&self) -> Option<f32> {
        match self {
            Self::Running { probed, total, .. } if *total > 0 => {
                Some(*probed as f32 / *total as f32)
            }
            _ => None,
        }
    }

    /// The finished result for `address`, if that is what is held.
    pub fn result_for(&self, address: IpAddr) -> Option<&Scan> {
        match self {
            Self::Finished { address: a, scan } if *a == address => Some(scan),
            _ => None,
        }
    }
}

/// The line under the result: what was found, and what the method cannot say.
pub fn summary(scan: &Scan) -> String {
    let host = scan.hosts.first();
    let open = host.map_or(0, |h| h.open().count());
    let closed = host.map_or(0, |h| h.closed());
    let filtered = host.map_or(0, |h| h.filtered);

    let mut line = match open {
        0 => "No open ports".to_string(),
        1 => "1 open port".to_string(),
        n => format!("{n} open ports"),
    };
    // Closed and filtered are reported separately and always. Rolling them
    // together into "not open" is the collapse this whole module exists to
    // avoid: a refusal is a machine answering, and silence is not.
    line.push_str(&format!(", {closed} closed, {filtered} filtered"));
    if scan.cancelled {
        line.push_str(" (stopped early)");
    }
    line
}

/// How one port reads.
pub fn state_label(state: PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
    }
}

/// The name of the service usually found on a port.
///
/// Shown as a hint and never as a claim: this is a lookup table of conventions,
/// not something the device said. Muster reads no banner here, so "80 http" is
/// "port 80 is open, and 80 is usually http".
pub fn service_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        515 => "lpd",
        548 => "afp",
        554 => "rtsp",
        587 => "smtp",
        631 => "ipp",
        993 => "imaps",
        995 => "pop3s",
        1883 => "mqtt",
        1900 => "ssdp",
        2049 => "nfs",
        3000 => "http-alt",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "upnp",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8009 => "cast",
        8080 => "http-alt",
        8123 => "home-assistant",
        8443 => "https-alt",
        9100 => "jetdirect",
        32400 => "plex",
        _ => return None,
    })
}

/// What the engine wants said beside the result, if anything.
pub fn caveats(scan: &Scan) -> Vec<String> {
    scan.caveats()
}

/// Which engine produced this.
pub fn method_label(method: Method) -> &'static str {
    method.label()
}

#[cfg(test)]
mod tests {
    use super::*;
    use muster_net::portscan::HostPorts;
    use std::net::Ipv4Addr;

    fn scan_of(answered: Vec<(u16, PortState)>, filtered: usize, cancelled: bool) -> Scan {
        Scan {
            hosts: vec![HostPorts {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                answered,
                filtered,
            }],
            method: Method::Connect,
            probed: 10,
            total: 10,
            cancelled,
        }
    }

    #[test]
    fn closed_and_filtered_are_never_rolled_together() {
        // The distinction this module exists to carry: a refusal is a machine
        // answering, and silence is not evidence of anything.
        let line = summary(&scan_of(
            vec![(80, PortState::Open), (443, PortState::Closed)],
            7,
            false,
        ));
        assert!(line.contains("1 open port"), "{line}");
        assert!(line.contains("1 closed"), "{line}");
        assert!(line.contains("7 filtered"), "{line}");
    }

    #[test]
    fn a_scan_that_found_nothing_says_so_without_claiming_the_host_is_shut() {
        let line = summary(&scan_of(vec![], 40, false));
        assert!(line.starts_with("No open ports"), "{line}");
        assert!(line.contains("40 filtered"), "{line}");
    }

    #[test]
    fn a_stopped_scan_says_it_was_stopped() {
        // Otherwise a partial answer reads as a complete one, which is the
        // worst way for a cancel to behave.
        let line = summary(&scan_of(vec![(22, PortState::Open)], 3, true));
        assert!(line.contains("stopped early"), "{line}");
    }

    #[test]
    fn progress_over_a_known_total_is_reported_and_nothing_else_is() {
        let idle = State::Idle;
        assert_eq!(idle.fraction(), None);
        assert_eq!(idle.address(), None);
    }

    #[test]
    fn a_service_hint_is_offered_only_where_there_is_a_convention() {
        assert_eq!(service_hint(22), Some("ssh"));
        assert_eq!(service_hint(9100), Some("jetdirect"));
        assert_eq!(service_hint(47811), None, "invented hints are not hints");
    }

    #[test]
    fn every_port_state_reads_as_itself() {
        assert_eq!(state_label(PortState::Open), "open");
        assert_eq!(state_label(PortState::Closed), "closed");
        assert_eq!(state_label(PortState::Filtered), "filtered");
    }
}
