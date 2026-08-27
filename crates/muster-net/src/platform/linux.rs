//! The Linux readings: `getifaddrs` for the addresses, `/sys` and `/proc` for
//! everything else.
//!
//! None of the *readings* needs `CAP_NET_RAW`. The addresses come through
//! `getifaddrs`
//! because there is no readable file that lists them — `/proc/net/fib_trie` is
//! not an interface — and every other reading is text, which is why the parsing
//! lives in [`super::procfs`] where it can be tested on any platform. This file
//! is the part that cannot: opening files and walking a linked list from libc.
//!
//! The one thing here that will *take* the capability if it is offered is the
//! echo, and it asks for it second: see [`EchoSocket`].
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
use crate::discover::{Capabilities, Echo, Outcome, Transport};
use crate::mac::MacAddr;
use crate::prefix::Prefix;
use crate::sysinfo::{IfAddr, IfFlags, Interface, LinkKind, Neighbour, Route, SystemProbe};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::Path;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU16, Ordering};
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
///   `net.ipv4.ping_group_range` including the user's group — on Debian,
///   Ubuntu and Pop!_OS it does not — and where it is shut the raw socket
///   below is tried instead, which is what makes `sudo muster` ping on a
///   machine where an ordinary launch cannot. The capability is *probed* at
///   startup rather than assumed, and a machine where neither is open reports
///   that it could not ping instead of reporting a network of silent hosts.
impl Transport for Host {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            arp: true,
            icmp: EchoSocket::open().is_ok(),
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

    fn ping(&self, addr: IpAddr, timeout: Duration) -> io::Result<Option<Echo>> {
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

/// Opens a raw ICMP socket, which needs `CAP_NET_RAW` or root.
///
/// The second half of [`EchoSocket`], and the reason this file no longer says
/// that nothing in it wants the capability: on Debian, Ubuntu and Pop!_OS the ping
/// socket is shut for everybody, and a user who runs Muster with `sudo` has
/// every right to expect an echo out of it. Asked for second, so an
/// unprivileged process never pays for a socket it cannot have.
fn raw_icmp_socket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedFd(fd))
}

/// The two ways this process can put an ICMP echo on the wire, cheapest first.
///
/// They are not the same socket wearing two names, and the difference is all in
/// what comes *back*:
///
/// * [`EchoSocket::Ping`] is demultiplexed by the kernel, which rewrote the
///   identifier on the way out to one it owns and hands this socket the replies
///   that carry it. What arrives is already ours, and it arrives as an ICMP
///   message with no IP header on the front.
/// * [`EchoSocket::Raw`] is told nothing. **Every** ICMP packet the machine
///   receives is copied to it — including the replies to other processes' pings
///   and to the other threads of this one — and each arrives with its IP header
///   attached. So the identifier and the sequence number are ours to choose and
///   ours to check, and [`EchoSocket::reply`] is where that check lives.
///
/// Which of the two also decides **how the TTL is read**, which is the other
/// asymmetry and the reason this is not one socket with a flag on it. A raw
/// socket is handed the IP header, so the TTL is a byte already in the buffer.
/// A ping socket is handed the ICMP message with the header stripped off, so
/// the kernel has to be asked for the TTL separately, with `IP_RECVTTL` and a
/// control message beside the datagram. Neither is more privileged than the
/// other; they are two shapes of the same reading.
enum EchoSocket {
    Ping(OwnedFd),
    Raw(OwnedFd),
}

impl EchoSocket {
    /// A ping socket if this user may have one, a raw socket if this process
    /// has the privilege, and otherwise the ping socket's own error.
    ///
    /// **The error is deliberately the first one.** `EACCES` from the ping
    /// socket is the failure [`super::ICMP_HINT`] explains, and reporting the
    /// raw socket's `EPERM` instead would answer a question about a shut
    /// sysctl with a sentence about capabilities.
    fn open() -> io::Result<Self> {
        match ping_socket() {
            Ok(fd) => Ok(Self::Ping(fd)),
            Err(shut) => raw_icmp_socket().map(Self::Raw).map_err(|_| shut),
        }
    }

    fn fd(&self) -> libc::c_int {
        match self {
            Self::Ping(fd) | Self::Raw(fd) => fd.0,
        }
    }

    /// The ICMP message inside a datagram this socket received, if it is one
    /// this call asked for.
    ///
    /// `None` means "not ours", which is an ordinary thing to be: a router
    /// talking *about* the probe, a reply to another thread, or on a raw socket
    /// the tail of somebody else's ping. The caller keeps waiting rather than
    /// calling it silence.
    fn reply<'a>(&self, datagram: &'a [u8], id: u16, seq: u16) -> Option<&'a [u8]> {
        let icmp = match self {
            Self::Ping(_) => datagram,
            Self::Raw(_) => {
                // An IPv4 header, whose length is in the low nibble of the
                // first byte counted in 32-bit words. Not a constant 20: an
                // option-carrying header is longer, and reading the ICMP type
                // out of a fixed offset would then read a byte of the options.
                let first = *datagram.first()?;
                if first >> 4 != 4 {
                    return None;
                }
                let header = usize::from(first & 0x0f) * 4;
                datagram.get(header..)?
            }
        };
        // Type 0 is an echo reply. Anything else is a router talking about the
        // probe rather than the host answering it.
        if icmp.len() < 8 || icmp[0] != 0 {
            return None;
        }
        // The sequence number is ours on both sockets: the kernel rewrites the
        // identifier of a ping socket's echo and recomputes the checksum, and
        // it leaves the sequence alone. The identifier is only ours to compare
        // on a raw socket, where nothing was rewritten.
        if u16::from_be_bytes([icmp[6], icmp[7]]) != seq {
            return None;
        }
        if matches!(self, Self::Raw(_)) && u16::from_be_bytes([icmp[4], icmp[5]]) != id {
            return None;
        }
        Some(icmp)
    }
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

/// One ICMP echo, over whichever socket [`EchoSocket::open`] could get.
///
/// The header is filled in completely for both. A ping socket rewrites the
/// identifier and recomputes the checksum, so neither has to be right going out
/// — but a header that is only correct by the kernel's courtesy is one that
/// breaks the day it is sent down a raw socket instead, and that day has now
/// arrived.
fn echo(addr: Ipv4Addr, timeout: Duration) -> io::Result<Option<Echo>> {
    let sock = EchoSocket::open()?;
    let fd = sock.fd();

    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&tv).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // **Ask for the TTL, on the socket that cannot see it.** A ping socket is
    // handed the ICMP message with the IP header already stripped, so without
    // this the byte is simply gone; with it the kernel puts the header's TTL in
    // a control message beside the datagram. A raw socket needs nothing,
    // because it is handed the header itself.
    //
    // Best effort, and deliberately not an error: a kernel that will not do
    // this leaves the reply's TTL unread, which is a device with no stack
    // claimed against it rather than a device that did not answer.
    if matches!(sock, EchoSocket::Ping(_)) {
        let on: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                std::ptr::from_ref(&on).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // Type 8 (echo request), code 0, checksum, identifier, sequence, then the
    // same 32 bytes `ping` sends.
    //
    // The identifier names this process and the sequence names this call, which
    // on a raw socket is the whole of how a reply is told from the traffic of
    // every other pinger on the machine. A sweep runs 254 of these at once, so
    // the sequence has to be per call rather than the constant 1 it was when
    // the kernel was doing the sorting.
    let id = echo_id();
    let seq = ECHO_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut packet = [0u8; 40];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
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

    // **A raw socket is handed every ICMP packet the machine receives**, and a
    // sweep runs 254 of them at once: unfiltered, each socket would be given a
    // copy of every other worker's reply and have to step over 253 of them to
    // find its own. Connecting names the one peer this socket cares about and
    // the kernel does the filtering. Best effort: [`EchoSocket::reply`] checks
    // the identifier and the sequence anyway, so a kernel that refuses this is
    // slower and not wrong.
    if matches!(sock, EchoSocket::Raw(_)) {
        unsafe {
            libc::connect(
                fd,
                std::ptr::from_ref(&dest).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
    }

    let sent = Instant::now();
    let n = unsafe {
        libc::sendto(
            fd,
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

    // Wide enough for a raw socket's reply, which carries the IP header, its
    // options and the 40 bytes above.
    let mut buf = [0u8; 256];
    // A `[u64; 8]` rather than a `[u8; 64]` for the same reason the Windows
    // adapter buffer is a `Vec<u64>`: the kernel writes `cmsghdr` structures in
    // here and a byte array promises no alignment for one.
    let mut control = [0u64; 8];
    let deadline = sent + timeout;
    loop {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control) as _;

        // `recvmsg` rather than `recv` because the TTL of a ping socket's reply
        // arrives beside the datagram rather than in it. The datagram itself is
        // read exactly as before.
        let got = unsafe { libc::recvmsg(fd, &raw mut msg, 0) };
        if got < 0 {
            return Ok(None); // Timed out.
        }
        let got = got as usize;
        let datagram = &buf[..got.min(buf.len())];
        if sock.reply(datagram, id, seq).is_some() {
            // Two shapes, one reading: the control message where the kernel
            // was asked for it, and the header itself where the socket was
            // given one. Neither is a guess, and where neither answers the
            // reply carries no TTL and claims no stack.
            let ttl = match sock {
                EchoSocket::Ping(_) => unsafe { control_ttl(&msg) },
                EchoSocket::Raw(_) => super::datagram_ttl(datagram),
            };
            return Ok(Some(Echo {
                rtt: sent.elapsed(),
                ttl,
            }));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

/// The TTL out of the control messages `recvmsg` filled in, where `IP_RECVTTL`
/// put one there.
///
/// The kernel writes it as an `int` rather than as the byte it came off the
/// wire as, so it is read as one and narrowed; a value that will not fit in a
/// byte is not a TTL and is dropped rather than truncated into a plausible one.
///
/// # Safety
/// `msg` was filled in by a `recvmsg` on a control buffer that is still alive.
unsafe fn control_ttl(msg: &libc::msghdr) -> Option<u8> {
    let mut header = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !header.is_null() {
        let cmsg = unsafe { &*header };
        if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_TTL {
            let mut value: libc::c_int = 0;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(header),
                    std::ptr::from_mut(&mut value).cast::<u8>(),
                    size_of::<libc::c_int>(),
                );
            }
            return u8::try_from(value).ok();
        }
        header = unsafe { libc::CMSG_NXTHDR(msg, header) };
    }
    None
}

/// The identifier every echo from this process carries.
///
/// The process id, which is what `ping` itself uses and what makes one Muster's
/// replies distinguishable from another's on a raw socket. Truncated to sixteen
/// bits because the field is sixteen bits; two processes whose ids differ only
/// above that would collide, and the sequence number then separates them.
fn echo_id() -> u16 {
    unsafe { libc::getpid() as u16 }
}

/// One number per echo this process sends, so a reply can name the call it
/// belongs to. Wrapping after 65536 pings is fine: what it has to be is
/// different from the pings in flight beside it, not unique for ever.
static ECHO_SEQUENCE: AtomicU16 = AtomicU16::new(1);

/// The internet checksum: one's complement of the one's complement sum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    // The pairs, and then whatever odd byte is left over: an ICMP payload is
    // not required to be an even length, and the odd byte is padded on the
    // right rather than the left.
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::Stack;

    /// A control buffer laid out the way the kernel lays one out for a ping
    /// socket that asked for `IP_RECVTTL`: one `cmsghdr` at `IPPROTO_IP` /
    /// `IP_TTL`, and an `int` behind it.
    ///
    /// Built rather than captured because a control message is a structure
    /// with the platform's own padding in it, so the recording that means
    /// anything is one made with the platform's own macros. What is being
    /// tested is the walk over them, which is where a reader goes wrong.
    ///
    /// # Safety
    /// The returned header borrows `control`, which the caller keeps alive.
    unsafe fn recorded(
        control: &mut [u64; 8],
        level: libc::c_int,
        kind: libc::c_int,
        value: libc::c_int,
    ) -> libc::msghdr {
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(control) as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(&value).cast::<u8>(),
                libc::CMSG_DATA(header),
                size_of::<libc::c_int>(),
            );
        }
        // What the kernel leaves behind is what it wrote, not the room it was
        // given, and a walk that trusted the room would read past the end.
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as _;
        msg
    }

    /// The ping socket's shape: the TTL arrives beside the datagram, as an
    /// `int`, and it names a stack exactly as the raw socket's header byte
    /// does.
    #[test]
    fn a_ping_socket_reply_carries_its_ttl_in_a_control_message() {
        for (ttl, stack) in [
            (64, Stack::Unix),
            (128, Stack::Windows),
            (255, Stack::Embedded),
        ] {
            let mut control = [0u64; 8];
            let msg = unsafe { recorded(&mut control, libc::IPPROTO_IP, libc::IP_TTL, ttl) };
            let read = unsafe { control_ttl(&msg) };
            assert_eq!(read, Some(ttl as u8), "TTL {ttl}");
            assert_eq!(read.and_then(Stack::of), Some(stack));
        }
    }

    /// And a kernel that sent something else, or nothing: no TTL was read, so
    /// no stack is claimed. `IP_TOS` is what arrives instead when `IP_RECVTOS`
    /// is on and `IP_RECVTTL` was refused.
    #[test]
    fn a_reply_with_no_ttl_beside_it_reads_nothing() {
        let mut control = [0u64; 8];
        let other = unsafe { recorded(&mut control, libc::IPPROTO_IP, libc::IP_TOS, 64) };
        assert_eq!(unsafe { control_ttl(&other) }, None);

        let mut empty: libc::msghdr = unsafe { std::mem::zeroed() };
        empty.msg_control = std::ptr::null_mut();
        empty.msg_controllen = 0;
        assert_eq!(unsafe { control_ttl(&empty) }, None);
    }

    /// The raw socket's shape, read through the same crate-wide helper the
    /// echo path uses, so the two sockets cannot disagree about what a TTL of
    /// 64 means.
    #[test]
    fn a_raw_socket_reply_carries_its_ttl_in_the_header() {
        let mut datagram = vec![0u8; 20];
        datagram[0] = 0x45;
        datagram[8] = 64;
        datagram[9] = 1;
        assert_eq!(super::super::datagram_ttl(&datagram), Some(64));
        assert_eq!(
            super::super::datagram_ttl(&datagram).and_then(Stack::of),
            Some(Stack::Unix)
        );
    }
}
