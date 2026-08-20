//! The Linux readings: `getifaddrs` for the addresses, `/sys` and `/proc` for
//! everything else.
//!
//! Nothing here needs `CAP_NET_RAW`. The addresses come through `getifaddrs`
//! because there is no readable file that lists them — `/proc/net/fib_trie` is
//! not an interface — and every other reading is text, which is why the parsing
//! lives in [`super::procfs`] where it can be tested on any platform. This file
//! is the part that cannot: opening files and walking a linked list from libc.
//!
//! What is deliberately not here yet:
//!
//! * **IPv6 neighbours.** The kernel publishes no `/proc` equivalent of the ARP
//!   table for v6, so that reading needs a netlink socket (`RTM_GETNEIGH`).
//!   Until it exists the v6 neighbour list is empty, and it is empty *quietly*
//!   only because the v4 table is the one the sweep uses; when NDP discovery
//!   arrives this has to arrive with it.
//! * **`dhclient` leases.** Only the `systemd-networkd` lease path is read.
//!   `/var/lib/dhcp/dhclient.*.leases` is a different format and is usually
//!   root-only, so a machine on `dhclient` reports no DHCP server rather than a
//!   wrong one.

use super::procfs;
use crate::discover::{Capabilities, Outcome, Transport};
use crate::mac::MacAddr;
use crate::prefix::Prefix;
use crate::sysinfo::{IfAddr, IfFlags, Interface, LinkKind, Neighbour, Route, SystemProbe};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub struct Host;

impl SystemProbe for Host {
    fn interfaces(&self) -> io::Result<Vec<Interface>> {
        interfaces()
    }

    fn routes(&self) -> io::Result<Vec<Route>> {
        let index = name_to_index();
        let mut out = Vec::new();
        // The v4 table must exist; the v6 one is absent on a kernel built
        // without IPv6, which is a configuration rather than a failure.
        let v4 = std::fs::read_to_string("/proc/net/route")?;
        let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
        for (name, mut route) in procfs::routes_v4(&v4)
            .into_iter()
            .chain(procfs::routes_v6(&v6))
        {
            route.interface_index = index.get(&name).copied().unwrap_or(0);
            out.push(route);
        }
        Ok(out)
    }

    fn neighbours(&self) -> io::Result<Vec<Neighbour>> {
        let index = name_to_index();
        let text = std::fs::read_to_string("/proc/net/arp")?;
        Ok(procfs::neighbours_v4(&text)
            .into_iter()
            .map(|(name, mut n)| {
                n.interface_index = index.get(&name).copied().unwrap_or(0);
                n
            })
            .collect())
    }

    fn resolvers(&self) -> io::Result<Vec<IpAddr>> {
        // `systemd-resolved` writes the real list here and leaves the stub in
        // `/etc/resolv.conf`; preferring it gives the servers actually queried
        // rather than `127.0.0.53`. Falling back is what makes this work on a
        // machine that has never heard of systemd.
        for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
            if let Ok(text) = std::fs::read_to_string(path) {
                let found = procfs::resolvers(&text);
                if !found.is_empty() {
                    return Ok(found);
                }
            }
        }
        Ok(Vec::new())
    }
}

/// The unprivileged sweep on Linux.
///
/// Neither probe here needs `CAP_NET_RAW`, and both are worth explaining
/// because neither is the obvious implementation:
///
/// * **ARP is provoked rather than sent.** An unprivileged process cannot put
///   an ARP request on the wire, but it can make the *kernel* do it: send a
///   datagram to the address and the stack must resolve the hardware address
///   before it can transmit. The answer then appears in `/proc/net/arp`, which
///   is world readable. The datagram goes to the discard port and its contents
///   are never seen by anything.
/// * **ICMP goes through a ping socket** (`SOCK_DGRAM`, `IPPROTO_ICMP`), which
///   exists precisely so that `ping` need not be setuid. It is gated on
///   `net.ipv4.ping_group_range` including the user's group — commonly it does
///   not — so the capability is *probed* at startup rather than assumed, and a
///   machine where it is closed reports that it could not ping instead of
///   reporting a network of silent hosts.
impl Transport for Host {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            arp: true,
            icmp: ping_socket().is_ok(),
            tcp: true,
        }
    }

    fn arp(&self, addr: Ipv4Addr, timeout: Duration) -> io::Result<Option<MacAddr>> {
        // Already known? A neighbour entry costs nothing and is often already
        // there for the gateway and anything recently spoken to.
        if let Some(mac) = arp_cache(addr)? {
            return Ok(Some(mac));
        }

        // Provoke. `send_to` returns as soon as the datagram is queued, so the
        // failure of an unreachable address arrives later and is ignored here:
        // the reading is the cache, not the send.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let _ = socket.set_write_timeout(Some(timeout));
        // Port 9 is discard. Nothing listens, nothing logs, and the datagram
        // exists only to make the kernel resolve the address.
        let _ = socket.send_to(&[0u8; 0], (addr, 9));

        // Poll rather than sleeping the whole timeout: a local wire answers in
        // well under a millisecond, and waiting 300 ms per address to find that
        // out is most of a sweep.
        let deadline = Instant::now() + timeout;
        loop {
            std::thread::sleep(procfs::ARP_SNAPSHOT_TTL);
            if let Some(mac) = arp_cache(addr)? {
                return Ok(Some(mac));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn ping(&self, addr: IpAddr, timeout: Duration) -> io::Result<Option<Duration>> {
        let IpAddr::V4(v4) = addr else {
            // A v6 echo is a ping socket of its own (`AF_INET6`,
            // `IPPROTO_ICMPV6`) and a different header, and it is not written.
            // This is reached: `Prefix::hosts` gates on the size of a prefix
            // rather than on its family, so a /112 or longer is walked address
            // by address. `Capabilities` has no family axis to say so in
            // advance, so the error is what carries it, and `discover` puts it
            // in `Sweep::not_done` rather than letting every v6 address read as
            // a silent host.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 echo is not implemented",
            ));
        };
        echo(v4, timeout)
    }

    fn tcp(&self, addr: IpAddr, port: u16, timeout: Duration) -> Outcome {
        super::tcp::knock(addr, port, timeout)
    }
}

/// The one snapshot of `/proc/net/arp` the whole process shares.
///
/// A `static` because `Host` is a unit struct that callers construct freshly
/// wherever they need one, and the thing being shared is a reading of the
/// machine rather than anything a `Host` owns. One process, one kernel table,
/// one copy of it.
static ARP_TABLE: LazyLock<procfs::ArpSnapshot> =
    LazyLock::new(|| procfs::ArpSnapshot::new(procfs::ARP_SNAPSHOT_TTL));

/// Looks one address up in the kernel's ARP table, ignoring entries that are
/// only a record of a question nobody answered.
///
/// **Through a shared snapshot, not a fresh read.** Written the obvious way
/// this was `read_to_string` plus a parse of the whole table for one address,
/// called by every worker every five milliseconds: a mostly empty /24 with 256
/// workers issued some fifteen thousand whole-table reads, and the cost grew
/// with the square of the address count. The answer is the same one; see
/// `procfs::ArpSnapshot`.
fn arp_cache(addr: Ipv4Addr) -> io::Result<Option<MacAddr>> {
    ARP_TABLE.lookup(addr, Instant::now(), || {
        std::fs::read_to_string("/proc/net/arp")
    })
}

/// Opens a ping socket, or reports why not.
///
/// This is the capability probe. It is a real socket rather than a read of
/// `/proc/sys/net/ipv4/ping_group_range`, because the sysctl has to be compared
/// against the process's supplementary groups to mean anything and the kernel
/// is already willing to answer the question directly.
fn ping_socket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedFd(fd))
}

/// A file descriptor that closes itself. Small enough to own here rather than
/// reaching for `std::os::fd::OwnedFd`, which would need the socket to be built
/// through a type that does not exist for ping sockets.
struct OwnedFd(libc::c_int);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// One ICMP echo over a ping socket.
///
/// The kernel rewrites the identifier to one it has assigned this socket and
/// recomputes the checksum, so neither has to be right going out — but both are
/// filled in anyway, because a header that is only correct by the kernel's
/// courtesy is one that breaks the day it is sent down a raw socket instead.
fn echo(addr: Ipv4Addr, timeout: Duration) -> io::Result<Option<Duration>> {
    let sock = ping_socket()?;

    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            sock.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&tv).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Type 8 (echo request), code 0, checksum, identifier, sequence, then the
    // same 32 bytes `ping` sends.
    let mut packet = [0u8; 40];
    packet[0] = 8;
    packet[6..8].copy_from_slice(&1u16.to_be_bytes());
    packet[8..].fill(0x61);
    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());

    let dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    };

    let sent = Instant::now();
    let n = unsafe {
        libc::sendto(
            sock.0,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            std::ptr::from_ref(&dest).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        // An unreachable address fails here rather than timing out, and that
        // is silence rather than a broken mechanism.
        return Ok(None);
    }

    let mut buf = [0u8; 128];
    let deadline = sent + timeout;
    loop {
        let got = unsafe { libc::recv(sock.0, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if got < 0 {
            return Ok(None); // Timed out.
        }
        // Type 0 is an echo reply. Anything else on this socket is a router
        // talking *about* the probe, which is not the host answering.
        if got >= 8 && buf[0] == 0 {
            return Ok(Some(sent.elapsed()));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

/// The internet checksum: one's complement of the one's complement sum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_POINTOPOINT: u32 = 0x10;

fn interfaces() -> io::Result<Vec<Interface>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // Keyed by name and kept in insertion order by a second vector, because
    // `getifaddrs` reports one node per *address* and an interface with four
    // addresses is four nodes that have to merge into one entry.
    let mut by_name: BTreeMap<String, Interface> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();

    let mut node = list;
    while !node.is_null() {
        let entry = unsafe { &*node };
        node = entry.ifa_next;

        if entry.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();

        let iface = by_name.entry(name.clone()).or_insert_with(|| {
            order.push(name.clone());
            let flags = entry.ifa_flags;
            Interface {
                friendly: name.clone(),
                index: index_of(&name),
                mac: None,
                addresses: Vec::new(),
                kind: link_kind(&name, flags),
                flags: IfFlags {
                    up: flags & IFF_UP != 0,
                    loopback: flags & IFF_LOOPBACK != 0,
                    point_to_point: flags & IFF_POINTOPOINT != 0,
                },
                mtu: sys_number(&name, "mtu").unwrap_or(0) as u32,
                dns: Vec::new(),
                dhcp_server: None,
                name,
            }
        });

        // An `AF_PACKET` node is the interface's own hardware address rather
        // than an address on it, which is how the MAC arrives at all.
        if let Some(mac) = unsafe { packet_mac(entry.ifa_addr) } {
            if !mac.is_zero() {
                iface.mac = Some(mac);
            }
            continue;
        }

        if let Some(address) = unsafe { sockaddr_ip(entry.ifa_addr) } {
            let len = unsafe { netmask_len(entry.ifa_netmask) }.unwrap_or(if address.is_ipv4() {
                32
            } else {
                128
            });
            if let Ok(prefix) = Prefix::new(address, len) {
                iface.addresses.push(IfAddr { address, prefix });
            }
        }
    }

    unsafe { libc::freeifaddrs(list) };

    let mut out: Vec<Interface> = order
        .into_iter()
        .filter_map(|n| by_name.remove(&n))
        .collect();

    for iface in &mut out {
        iface.dhcp_server = lease_server(iface.index);
    }
    Ok(out)
}

fn index_of(name: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(name) else {
        return 0;
    };
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// Interfaces by name, for turning the names in `/proc/net/*` into indices.
fn name_to_index() -> BTreeMap<String, u32> {
    let mut map = BTreeMap::new();
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return map;
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let index = index_of(&name);
        if index != 0 {
            map.insert(name, index);
        }
    }
    map
}

/// A wireless interface has a `phy80211` link in `/sys`, which is the check
/// that works for every driver; `ARPHRD` reports plain Ethernet for most of
/// them and would call a laptop's Wi-Fi a cable.
fn link_kind(name: &str, flags: u32) -> LinkKind {
    if flags & IFF_LOOPBACK != 0 {
        return LinkKind::Loopback;
    }
    if Path::new(&format!("/sys/class/net/{name}/phy80211")).exists() {
        return LinkKind::Wireless;
    }
    if flags & IFF_POINTOPOINT != 0 {
        return LinkKind::Tunnel;
    }
    match sys_number(name, "type") {
        Some(1) => LinkKind::Ethernet,
        Some(772) => LinkKind::Loopback,
        _ => LinkKind::Unknown,
    }
}

fn sys_number(name: &str, file: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/{file}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn lease_server(index: u32) -> Option<IpAddr> {
    let text = std::fs::read_to_string(format!("/run/systemd/netif/leases/{index}")).ok()?;
    procfs::lease_server(&text)
}

/// # Safety
/// `p` is a valid `sockaddr` for its family, or null.
unsafe fn sockaddr_ip(p: *const libc::sockaddr) -> Option<IpAddr> {
    if p.is_null() {
        return None;
    }
    unsafe {
        match (*p).sa_family as i32 {
            libc::AF_INET => {
                let v4 = &*p.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes())))
            }
            libc::AF_INET6 => {
                let v6 = &*p.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

/// # Safety
/// `p` is a valid `sockaddr` for its family, or null.
unsafe fn packet_mac(p: *const libc::sockaddr) -> Option<MacAddr> {
    if p.is_null() {
        return None;
    }
    unsafe {
        if (*p).sa_family as i32 != libc::AF_PACKET {
            return None;
        }
        let ll = &*p.cast::<libc::sockaddr_ll>();
        (ll.sll_halen == 6).then(|| MacAddr::new(ll.sll_addr[..6].try_into().expect("6 bytes")))
    }
}

/// # Safety
/// `p` is a valid `sockaddr` for its family, or null.
unsafe fn netmask_len(p: *const libc::sockaddr) -> Option<u8> {
    Some(match unsafe { sockaddr_ip(p) }? {
        IpAddr::V4(a) => u32::from(a).count_ones() as u8,
        IpAddr::V6(a) => u128::from(a).count_ones() as u8,
    })
}
