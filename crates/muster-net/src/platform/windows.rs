//! The Windows readings, all of them out of the IP Helper API.
//!
//! **Not one call here needs elevation.** That is the point: `CLAUDE.md`
//! claims the unprivileged engine is more capable than it sounds, and this file
//! is most of the evidence. `GetAdaptersAddresses` alone answers the
//! interfaces, their hardware addresses, their prefixes, the per-adapter DNS
//! servers and the DHCP server the lease came from; `GetIpForwardTable2` gives
//! the gateway and `GetIpNetTable2` gives every neighbour the machine has
//! spoken to. A user with no administrator rights and no Npcap still gets the
//! whole of phase one.
//!
//! Three FFI shapes recur and each has a trap in it:
//!
//! * **`GetAdaptersAddresses` sizes its own buffer**, and the buffer must be
//!   aligned for the struct rather than for bytes. A `Vec<u8>` is one-byte
//!   aligned and reading `IP_ADAPTER_ADDRESSES_LH` out of it is undefined; the
//!   buffer here is a `Vec<u64>` for that reason alone.
//! * **The MIB tables allocate on our behalf** and must go back through
//!   `FreeMibTable`. Each one is a header with a flexible array member, so the
//!   rows are read by offsetting past the header rather than by indexing a
//!   fixed-size array of one.
//! * **Addresses arrive as `SOCKADDR_INET`**, a union whose discriminant is its
//!   own first field. Reading the wrong arm is silent, so it goes through
//!   [`sockaddr_ip`] once and nowhere else.

use crate::discover::{Capabilities, Outcome, Transport};
use crate::mac::MacAddr;
use crate::prefix::Prefix;
use crate::sysinfo::{
    IfAddr, IfFlags, Interface, LinkKind, Neighbour, NeighbourState, Route, SystemProbe,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIpForwardTable2, GetIpNetTable2, ICMP_ECHO_REPLY,
    IP_ADAPTER_ADDRESSES_LH, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, MIB_IPFORWARD_TABLE2,
    MIB_IPNET_TABLE2, SendARP,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_INET,
};

/// The real probe. Holds nothing: every call asks the OS afresh, because a
/// cached routing table is a wrong one the moment a cable moves.
#[derive(Clone, Copy, Debug, Default)]
pub struct Host;

impl SystemProbe for Host {
    fn interfaces(&self) -> io::Result<Vec<Interface>> {
        adapters()
    }

    fn routes(&self) -> io::Result<Vec<Route>> {
        routes()
    }

    fn neighbours(&self) -> io::Result<Vec<Neighbour>> {
        neighbours()
    }

    /// Windows has no machine-wide resolver list worth the name — the useful
    /// answer is per adapter, and the survey unions them. Returning nothing
    /// here is correct rather than a stub.
    fn resolvers(&self) -> io::Result<Vec<IpAddr>> {
        Ok(Vec::new())
    }
}

/// The unprivileged sweep on Windows.
///
/// Both of the interesting probes here run as an ordinary user, which is the
/// claim `CLAUDE.md` makes and the reason Npcap is an enhancement rather than a
/// requirement:
///
/// * **`SendARP`** hands the request to the stack, which sends it as itself.
///   The answer is the strongest evidence there is on a local wire — a device's
///   network stack replies below any firewall it has — and it yields the
///   hardware address the device list is keyed on. It is also the reason a
///   sweep here does not need a raw socket at all.
/// * **`IcmpSendEcho`** is the IP Helper API's ping, which needs no raw socket
///   either.
///
/// What is missing without Npcap is the *stateless* path: these calls are one
/// blocking round trip each, so the rate is set by how many can be in flight
/// rather than by how fast packets can be written. That is phase three's
/// problem, and it is why this type reports `arp` and `icmp` but not raw send.
impl Transport for Host {
    fn capabilities(&self) -> Capabilities {
        Capabilities::UNPRIVILEGED
    }

    fn arp(&self, addr: Ipv4Addr, _timeout: Duration) -> io::Result<Option<MacAddr>> {
        // `SendARP` takes addresses as `IPAddr`, which is a `u32` in *network*
        // byte order — the same layout as the octets, so `from_ne_bytes` of the
        // octets is the conversion and `u32::from(addr)` is not.
        let dest = u32::from_ne_bytes(addr.octets());
        // Eight rather than six: the API writes a whole word and `len` is the
        // count it filled in, so a six-byte buffer is a two-byte overrun on a
        // link whose addresses are longer.
        let mut mac = [0u8; 8];
        let mut len: u32 = mac.len() as u32;

        // A source of zero lets the stack pick the interface from its own
        // routing table, which is what makes this correct on a machine with a
        // VPN up without Muster having to choose.
        let rc = unsafe { SendARP(dest, 0, mac.as_mut_ptr().cast(), &mut len) };
        arp_result(rc, len, &mac)
    }

    fn ping(&self, addr: IpAddr, timeout: Duration) -> io::Result<Option<Duration>> {
        let IpAddr::V4(v4) = addr else {
            // v6 echo goes through `Icmp6SendEcho2`, which takes sockaddrs and
            // a source address rather than a bare word. It is not written yet,
            // and saying so is better than reporting every v6 host as silent.
            //
            // This *is* reached. An earlier note here claimed a v6 prefix is
            // never enumerated, which was wrong: `Prefix::hosts` gates on the
            // size of a prefix and not on its family, so a /112 or longer is
            // walked address by address, and the window has a field a user can
            // type one into. The error is what reaches `Sweep::not_done`.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 echo is not implemented",
            ));
        };

        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        // The payload is arbitrary; 32 bytes is what `ping.exe` sends, so the
        // probe looks like the thing every administrator already expects to see
        // in a capture.
        let payload = [0x61u8; 32];
        // The reply buffer must hold the reply struct, the echoed payload and
        // room for an ICMP error quotation, which is what the extra 8 is for.
        let mut reply = vec![0u8; size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8];

        let count = unsafe {
            IcmpSendEcho(
                handle,
                u32::from_ne_bytes(v4.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                std::ptr::null_mut(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout.as_millis().clamp(1, u32::MAX as u128) as u32,
            )
        };
        let answered = if count == 0 {
            None
        } else {
            // `IP_SUCCESS` is 0. A non-zero status is a reply *about* the
            // probe — a router's "unreachable" — and not the host answering,
            // so it is not evidence of a host.
            let echo = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
            (echo.Status == 0).then(|| Duration::from_millis(echo.RoundTripTime.into()))
        };

        unsafe { IcmpCloseHandle(handle) };
        Ok(answered)
    }

    fn tcp(&self, addr: IpAddr, port: u16, timeout: Duration) -> Outcome {
        super::tcp::knock(addr, port, timeout)
    }
}

/// Silences the unused-import warning on the handle type in builds where the
/// echo path is compiled but nothing names `HANDLE` directly.
const _: Option<HANDLE> = None;

/// The `SendARP` return codes that mean **nothing answered**, as opposed to
/// the mechanism failing.
///
/// This distinction is the whole of the function below, and getting it wrong is
/// the worst failure `CLAUDE.md` names. `discover::probe_one` treats `Ok(None)`
/// on an on-link sweep as proof the address is empty and stops probing it,
/// while an `Err` settles nothing and is carried into `Sweep::not_done`. So a
/// blanket `rc != NO_ERROR => Ok(None)` reported an invalid parameter, an
/// interface with no layer 2 under it, a denied handle and resource exhaustion
/// under 254 concurrent calls as "no device here" — for every address in the
/// prefix, producing "0 devices found" presented as a complete sweep.
///
/// The default is therefore `Err`, and only these are silence:
///
/// * `ERROR_GEN_FAILURE` — the ordinary answer for an address that did not
///   reply. It is what an empty address on a working wire returns.
/// * `ERROR_BAD_NET_NAME` — the stack has no path to the destination.
/// * `ERROR_NOT_FOUND` — no entry resulted from the request.
/// * `ERROR_HOST_UNREACHABLE` — the stack gave up resolving at layer 2, which
///   is the same event as silence and is reported by some drivers instead.
/// * `ERROR_TIMEOUT` — the request expired, which is silence with a clock on
///   it.
mod arp_rc {
    pub const GEN_FAILURE: u32 = 31;
    pub const BAD_NET_NAME: u32 = 67;
    pub const NOT_FOUND: u32 = 1168;
    pub const HOST_UNREACHABLE: u32 = 1232;
    pub const TIMEOUT: u32 = 1460;
}

/// Reads what `SendARP` filled in. A free function so that the one judgement
/// in this file that is not a syscall has a test.
fn arp_result(rc: u32, len: u32, mac: &[u8; 8]) -> io::Result<Option<MacAddr>> {
    if rc != NO_ERROR {
        return match rc {
            arp_rc::GEN_FAILURE
            | arp_rc::BAD_NET_NAME
            | arp_rc::NOT_FOUND
            | arp_rc::HOST_UNREACHABLE
            | arp_rc::TIMEOUT => Ok(None),
            other => Err(io::Error::from_raw_os_error(other as i32)),
        };
    }
    match len {
        // An Ethernet or Wi-Fi address, which is every link a sweep runs on.
        6 => {
            let found = MacAddr::new(mac[..6].try_into().expect("6 bytes"));
            // An all-zero address is the API saying nothing answered rather
            // than a device whose hardware address is zero.
            Ok((!found.is_zero()).then_some(found))
        }
        // A success that resolved nothing. Silence, and the address is settled.
        0 => Ok(None),
        // A success on a link whose hardware address is not six bytes:
        // Infiniband, a tunnel with a link layer of its own, and loopback
        // report other lengths. Muster has no way to hold one, and calling an
        // address that *did* answer empty is the lie this function exists to
        // avoid, so it is an error and the sweep says the prefix was not fully
        // looked at.
        other => Err(io::Error::other(format!(
            "the hardware address for this link is {other} bytes, and Muster \
             reads six"
        ))),
    }
}

/// `IfType` values worth telling apart, from `ipifcons.h`. Written out rather
/// than imported because the names move between `windows-sys` releases and
/// these five numbers have not changed since NT.
mod iftype {
    pub const ETHERNET: u32 = 6;
    pub const PPP: u32 = 23;
    pub const LOOPBACK: u32 = 24;
    pub const IEEE80211: u32 = 71;
    pub const TUNNEL: u32 = 131;
}

/// `IfOperStatusUp`.
const OPER_STATUS_UP: i32 = 1;

fn adapters() -> io::Result<Vec<Interface>> {
    // A `Vec<u64>` rather than a `Vec<u8>`: the buffer is read as
    // `IP_ADAPTER_ADDRESSES_LH`, which wants eight-byte alignment that a byte
    // vector does not promise.
    let mut buf: Vec<u64> = vec![0; 4096];
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;

    let mut size = (buf.len() * 8) as u32;
    // Twice is enough in principle; the loop is bounded anyway because an
    // interface list that keeps growing between calls is a machine problem and
    // not something to spin on.
    for _ in 0..4 {
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        match rc {
            NO_ERROR => return Ok(unsafe { walk_adapters(buf.as_ptr().cast()) }),
            ERROR_BUFFER_OVERFLOW => {
                buf = vec![0; (size as usize).div_ceil(8) + 64];
                size = (buf.len() * 8) as u32;
            }
            other => return Err(io::Error::from_raw_os_error(other as i32)),
        }
    }
    Err(io::Error::other("the adapter list kept growing"))
}

/// # Safety
/// `head` is the start of a `GetAdaptersAddresses` reply, or null.
unsafe fn walk_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Interface> {
    let mut out = Vec::new();
    let mut node = head;
    while !node.is_null() {
        let a = unsafe { &*node };

        let mac = (a.PhysicalAddressLength == 6)
            .then(|| MacAddr::new(a.PhysicalAddress[..6].try_into().expect("6 bytes")));

        let mut addresses = Vec::new();
        let mut uni = a.FirstUnicastAddress;
        while !uni.is_null() {
            let u = unsafe { &*uni };
            if let Some(address) = unsafe { sockaddr_ip(u.Address.lpSockaddr) }
                && let Ok(prefix) = Prefix::new(address, u.OnLinkPrefixLength)
            {
                addresses.push(IfAddr { address, prefix });
            }
            uni = u.Next;
        }

        let mut dns = Vec::new();
        let mut server = a.FirstDnsServerAddress;
        while !server.is_null() {
            let s = unsafe { &*server };
            if let Some(address) = unsafe { sockaddr_ip(s.Address.lpSockaddr) } {
                dns.push(address);
            }
            server = s.Next;
        }

        let kind = match a.IfType {
            iftype::ETHERNET => LinkKind::Ethernet,
            iftype::IEEE80211 => LinkKind::Wireless,
            iftype::LOOPBACK => LinkKind::Loopback,
            iftype::TUNNEL | iftype::PPP => LinkKind::Tunnel,
            _ => LinkKind::Unknown,
        };

        // `Dhcpv4Server` is a `SOCKET_ADDRESS` that is simply empty where there
        // is no lease, so the length check is the presence check.
        let dhcp_server = (a.Dhcpv4Server.iSockaddrLength > 0)
            .then(|| unsafe { sockaddr_ip(a.Dhcpv4Server.lpSockaddr) })
            .flatten();

        out.push(Interface {
            name: unsafe { from_pcstr(a.AdapterName) },
            friendly: unsafe { from_pcwstr(a.FriendlyName) },
            // `IfIndex` shares its word with a `Length`/`Flags` pair in a
            // union, so reading it is an unsafe access even inside an unsafe
            // function. The API always initialises it.
            index: unsafe { a.Anonymous1.Anonymous.IfIndex },
            mac,
            addresses,
            kind,
            flags: IfFlags {
                up: a.OperStatus == OPER_STATUS_UP,
                loopback: a.IfType == iftype::LOOPBACK,
                point_to_point: matches!(a.IfType, iftype::PPP | iftype::TUNNEL),
            },
            mtu: a.Mtu,
            dns,
            dhcp_server,
        });

        node = a.Next;
    }
    out
}

fn routes() -> io::Result<Vec<Route>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if rc != NO_ERROR {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    // From here to `FreeMibTable` there is no early return, so the table
    // cannot leak on an error path — there is no error path.
    let mut out = Vec::new();
    unsafe {
        let header = &*table;
        let rows = std::ptr::addr_of!(header.Table)
            .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>();
        for i in 0..header.NumEntries as usize {
            let row = &*rows.add(i);
            let Some(destination) = sockaddr_inet_ip(&row.DestinationPrefix.Prefix) else {
                continue;
            };
            let Ok(prefix) = Prefix::new(destination, row.DestinationPrefix.PrefixLength) else {
                continue;
            };
            // An on-link route reports the unspecified address as its next hop
            // rather than nothing at all, and telling those apart is what says
            // whether a network is on this wire.
            let gateway = sockaddr_inet_ip(&row.NextHop).filter(|a| !a.is_unspecified());
            out.push(Route {
                destination: prefix,
                gateway,
                interface_index: row.InterfaceIndex,
                metric: row.Metric,
            });
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

fn neighbours() -> io::Result<Vec<Neighbour>> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) };
    if rc != NO_ERROR {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let mut out = Vec::new();
    unsafe {
        let header = &*table;
        let rows = std::ptr::addr_of!(header.Table)
            .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2>();
        for i in 0..header.NumEntries as usize {
            let row = &*rows.add(i);
            let Some(address) = sockaddr_inet_ip(&row.Address) else {
                continue;
            };
            if row.PhysicalAddressLength != 6 {
                continue;
            }
            out.push(Neighbour {
                address,
                mac: MacAddr::new(row.PhysicalAddress[..6].try_into().expect("6 bytes")),
                interface_index: row.InterfaceIndex,
                state: neighbour_state(row.State),
            });
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

/// `NL_NEIGHBOR_STATE`, collapsed onto the three answers that change what the
/// engine does. `Probe` and `Delay` are entries mid-verification: they were
/// reachable and are being re-checked, so they are evidence, and calling them
/// stale is the closest true thing.
fn neighbour_state(state: i32) -> NeighbourState {
    match state {
        1 => NeighbourState::Incomplete, // NlnsIncomplete
        5 => NeighbourState::Reachable,  // NlnsReachable
        6 => NeighbourState::Static,     // NlnsPermanent
        2..=4 => NeighbourState::Stale,  // NlnsProbe, NlnsDelay, NlnsStale
        _ => NeighbourState::Incomplete, // NlnsUnreachable and anything new
    }
}

/// Reads a `SOCKADDR` of either family. Returns [`None`] for anything else,
/// which is how a link-layer or unspecified address gets skipped rather than
/// misread.
///
/// # Safety
/// `p` is a valid `SOCKADDR` for its family, or null.
unsafe fn sockaddr_ip(p: *const SOCKADDR) -> Option<IpAddr> {
    if p.is_null() {
        return None;
    }
    unsafe {
        match (*p).sa_family {
            AF_INET => {
                let v4 = &*p.cast::<windows_sys::Win32::Networking::WinSock::SOCKADDR_IN>();
                // `S_addr` holds the octets in network order, so the memory
                // order is the dotted-quad order.
                Some(IpAddr::V4(Ipv4Addr::from(
                    v4.sin_addr.S_un.S_addr.to_ne_bytes(),
                )))
            }
            AF_INET6 => {
                let v6 = &*p.cast::<windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

/// The same reading for the inline union the MIB tables use.
fn sockaddr_inet_ip(a: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe { sockaddr_ip(std::ptr::from_ref(a).cast::<SOCKADDR>()) }
}

/// # Safety
/// `p` is a NUL-terminated byte string, or null.
unsafe fn from_pcstr(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, len) }).into_owned()
}

/// # Safety
/// `p` is a NUL-terminated wide string, or null.
unsafe fn from_pcwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule this file gets held to: `Ok(None)` is proof an address is
    /// empty, so only the codes that really mean silence may become one.
    #[test]
    fn only_a_genuine_no_answer_settles_an_address() {
        let zero = [0u8; 8];
        for rc in [
            arp_rc::GEN_FAILURE,
            arp_rc::BAD_NET_NAME,
            arp_rc::NOT_FOUND,
            arp_rc::HOST_UNREACHABLE,
            arp_rc::TIMEOUT,
        ] {
            assert!(
                matches!(arp_result(rc, 0, &zero), Ok(None)),
                "{rc} is silence"
            );
        }
    }

    /// And the other half, which is the defect: a broken mechanism reported as
    /// an empty address turns one failure into a whole empty network.
    #[test]
    fn a_broken_mechanism_is_an_error_and_never_an_empty_address() {
        // ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED (an interface with no
        // layer 2 under it, such as a VPN), ERROR_ACCESS_DENIED, and
        // ERROR_NO_SYSTEM_RESOURCES under 254 calls at once.
        for rc in [87u32, 50, 5, 1450, 1] {
            let e = arp_result(rc, 0, &[0u8; 8]).expect_err("{rc} must not settle an address");
            assert_eq!(e.raw_os_error(), Some(rc as i32));
        }
    }

    #[test]
    fn a_six_byte_answer_is_the_hardware_address() {
        let mac = [0x3c, 0x22, 0xfb, 0xaa, 0xbb, 0xcc, 0, 0];
        assert_eq!(
            arp_result(NO_ERROR, 6, &mac).unwrap(),
            Some("3c:22:fb:aa:bb:cc".parse().unwrap())
        );
    }

    /// A success that resolved nothing, and a success on a link Muster cannot
    /// name. The first is silence; the second answered and cannot be held, so
    /// it is a gap rather than an empty address.
    #[test]
    fn a_success_with_no_usable_address_is_silence_or_a_gap_but_never_a_device() {
        assert_eq!(arp_result(NO_ERROR, 0, &[0u8; 8]).unwrap(), None);
        assert_eq!(arp_result(NO_ERROR, 6, &[0u8; 8]).unwrap(), None);
        assert!(arp_result(NO_ERROR, 8, &[1u8; 8]).is_err());
    }

    /// The state mapping is a pure function and is the one thing in this file
    /// that can be checked without a machine. The distinction that matters is
    /// `Incomplete`: an entry nothing answered is not a device.
    #[test]
    fn neighbour_states_map_onto_evidence() {
        assert_eq!(neighbour_state(1), NeighbourState::Incomplete);
        assert_eq!(neighbour_state(0), NeighbourState::Incomplete); // Unreachable
        assert_eq!(neighbour_state(5), NeighbourState::Reachable);
        assert_eq!(neighbour_state(6), NeighbourState::Static);
        for mid in [2, 3, 4] {
            assert_eq!(neighbour_state(mid), NeighbourState::Stale);
        }
        assert!(!neighbour_state(1).is_evidence());
        assert!(neighbour_state(4).is_evidence());
    }
}
