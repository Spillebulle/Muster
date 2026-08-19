//! Muster's scan engine.
//!
//! No window, no rendering, and — the boundary that matters — no direct call to
//! the operating system outside [`platform`]. Everything the engine learns from
//! the machine arrives through [`sysinfo::SystemProbe`], which is what lets the
//! whole crate be tested with `cargo test -p muster-net` on a machine with no
//! network worth scanning. `CLAUDE.md` states the rule that follows from it:
//! **no test may put a packet on a wire.**
//!
//! ## What is here
//!
//! * **Phase one**, [`survey`]: the interfaces, the gateway, the resolvers, the
//!   DHCP server and the neighbour table, read from the OS with no packets sent
//!   and no privileges required. Useful on its own, not a preamble.
//! * **Phase two**, [`discover`]: the sweep. ARP, ICMP and a short TCP knock,
//!   through [`discover::Transport`], rate limited by [`rate`]. Unprivileged on
//!   both platforms.
//! * **Part of phase four**, [`vendor`]: the IEEE registry, compiled in, which
//!   turns a hardware address into the company that made it.
//!
//! ## What is next
//!
//! The stateless port scan (phase three) and the rest of identification —
//! hostnames, mDNS, SSDP, NetBIOS, TLS certificates. `CLAUDE.md` describes
//! both. The shape to preserve is that each phase is a pure function of
//! readings plus a transport, with the transport behind a trait for the same
//! reason [`sysinfo::SystemProbe`] is.
//!
//! Phase three is the first thing here that will need privileges: a stateless
//! SYN scan means writing packets, which is Npcap on Windows and `CAP_NET_RAW`
//! on Linux. Everything above this line runs as an ordinary user and that is
//! worth keeping true for as much of the engine as possible.

pub mod discover;
pub mod dns;
pub mod identify;
pub mod mac;
pub mod netbios;
pub mod platform;
pub mod portscan;
pub mod prefix;
pub mod rate;
pub mod siphash;
pub mod survey;
pub mod sysinfo;
pub mod vendor;

pub use discover::Sweep;
pub use mac::MacAddr;
pub use prefix::Prefix;
pub use survey::Survey;
pub use vendor::Origin;

/// Takes the survey of the machine this is running on.
///
/// The one convenience over `Survey::take(platform::Host)`, and the entry point
/// the binary and the window both use.
pub fn survey() -> Survey {
    Survey::take(platform::Host)
}
