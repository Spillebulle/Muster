//! The one place in the crate that talks to an operating system.
//!
//! Everything above this module works through
//! [`SystemProbe`](crate::sysinfo::SystemProbe), so this is the only code that
//! has to be reasoned about per platform, and the only code a test cannot run.
//!
//! An unsupported platform gets [`Unsupported`], which fails every reading
//! rather than answering emptily. That is not a courtesy: a survey of failures
//! reports gaps, and gaps are what the interface shows instead of "no devices
//! found". Compiling on a platform Muster does not support should look like a
//! platform Muster does not support.

pub mod procfs;
pub mod tcp;
pub mod udp;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Host;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Host;

#[cfg(not(any(windows, target_os = "linux")))]
pub use unsupported::Host;

#[cfg(not(any(windows, target_os = "linux")))]
mod unsupported {
    use crate::discover::{Capabilities, Outcome, Transport};
    use crate::mac::MacAddr;
    use crate::sysinfo::{Interface, Neighbour, Route, SystemProbe};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Host;

    fn no(reading: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Muster does not read {reading} on this platform"),
        )
    }

    impl SystemProbe for Host {
        fn interfaces(&self) -> io::Result<Vec<Interface>> {
            Err(no("the interface list"))
        }
        fn routes(&self) -> io::Result<Vec<Route>> {
            Err(no("the routing table"))
        }
        fn neighbours(&self) -> io::Result<Vec<Neighbour>> {
            Err(no("the neighbour table"))
        }
        fn resolvers(&self) -> io::Result<Vec<IpAddr>> {
            Err(no("the resolver configuration"))
        }
    }

    /// TCP is `std` and works anywhere, so it is offered even here. ARP and
    /// ICMP are not, and saying so is what turns an unsupported platform into
    /// a sweep that reports what it could not do.
    impl Transport for Host {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                arp: false,
                icmp: false,
                tcp: true,
            }
        }
        fn arp(&self, _: Ipv4Addr, _: Duration) -> io::Result<Option<MacAddr>> {
            Err(no("hardware addresses"))
        }
        fn ping(&self, _: IpAddr, _: Duration) -> io::Result<Option<Duration>> {
            Err(no("ICMP echoes"))
        }
        fn tcp(&self, addr: IpAddr, port: u16, timeout: Duration) -> Outcome {
            super::tcp::knock(addr, port, timeout)
        }
    }
}
