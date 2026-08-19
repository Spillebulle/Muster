//! Networks, and the addresses in them.
//!
//! One type over both families, because `CLAUDE.md` says an engine that models
//! an address as [`Ipv4Addr`] has to be rewritten. The interesting asymmetry is
//! not the width, though — it is that **a v4 prefix can be enumerated and a v6
//! one cannot**.
//!
//! A /64 is eighteen quintillion addresses. Sweeping it is not slow, it is
//! impossible, and no amount of rate limiting changes that; link-local
//! discovery on IPv6 is multicast (`ff02::1`) and the neighbour table, not a
//! loop. So [`Prefix::hosts`] returns an [`Option`] and answers [`None`] for
//! anything too large to walk, and the sweep is written against that answer
//! rather than against the address family. The same guard catches an
//! over-broad v4 prefix: a /8 is sixteen million probes and wants a decision
//! from the user, not a default.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// The largest prefix [`Prefix::hosts`] will enumerate without being asked
/// twice: 65 536 addresses, a v4 /16.
///
/// Chosen as the point where a sweep stops being interactive. At a polite
/// thousand probes a second a /16 is over a minute; a /8 is four and a half
/// hours, which is not a scan somebody starts by accident.
pub const ENUMERABLE_LIMIT: u64 = 1 << 16;

/// An address with a prefix length: `192.168.1.0/24`, `fe80::/64`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    base: IpAddr,
    len: u8,
}

impl Prefix {
    /// Builds a prefix, masking the address down to its network. Fails if the
    /// length is wider than the family allows.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let max = Self::max_len(&addr);
        if len > max {
            return Err(PrefixError::TooLong { len, max });
        }
        Ok(Self {
            base: mask(addr, len),
            len,
        })
    }

    /// The network address, with the host bits cleared.
    pub const fn network(&self) -> IpAddr {
        self.base
    }

    /// The prefix length: the 24 of a /24.
    ///
    /// Not a count of anything, which is why there is no `is_empty` beside it —
    /// a /0 is the whole internet rather than an empty network. Use
    /// [`Prefix::size`] or [`Prefix::host_count`] for how much is in it.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> u8 {
        self.len
    }

    pub const fn is_ipv4(&self) -> bool {
        matches!(self.base, IpAddr::V4(_))
    }

    const fn max_len(addr: &IpAddr) -> u8 {
        match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// Is this address inside the prefix? Answers `false` across families
    /// rather than pretending a v4 address can be in a v6 network.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(addr, self.len) == self.base
            }
            _ => false,
        }
    }

    /// How many addresses the prefix holds, saturating at [`u64::MAX`] for the
    /// v6 prefixes where the true answer does not fit and does not matter.
    pub fn size(&self) -> u64 {
        let host_bits = Self::max_len(&self.base) - self.len;
        if host_bits >= 64 {
            u64::MAX
        } else {
            1u64 << host_bits
        }
    }

    /// The addresses a sweep would probe, or [`None`] where that is not a
    /// sensible thing to do.
    ///
    /// For IPv4 this excludes the network and broadcast addresses, so a /24
    /// yields 254 and a /31 yields both of its addresses (RFC 3021 point to
    /// point links have no broadcast to exclude). For IPv6 it is always
    /// [`None`] below the limit's worth of addresses, because there is no
    /// prefix short enough to walk that is also small enough to finish.
    pub fn hosts(&self) -> Option<HostIter> {
        if self.size() > ENUMERABLE_LIMIT {
            return None;
        }
        Some(match self.base {
            IpAddr::V4(base) => {
                let first = u32::from(base);
                let last = first | !mask_bits_v4(self.len);
                // /31 and /32 have no network or broadcast address to skip.
                let (from, to) = if self.len >= 31 {
                    (first, last)
                } else {
                    (first + 1, last - 1)
                };
                HostIter {
                    next: u128::from(from),
                    last: u128::from(to),
                    v4: true,
                    done: false,
                }
            }
            IpAddr::V6(base) => {
                let first = u128::from(base);
                let last = first | !mask_bits_v6(self.len);
                HostIter {
                    next: first,
                    last,
                    v4: false,
                    done: false,
                }
            }
        })
    }

    /// The number of addresses [`Prefix::hosts`] would yield, without building
    /// the iterator. `0` where the prefix is not enumerable.
    pub fn host_count(&self) -> u64 {
        match self.hosts() {
            None => 0,
            Some(iter) => (iter.last - iter.next + 1) as u64,
        }
    }
}

fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask_bits_v4(len))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask_bits_v6(len))),
    }
}

/// `u32::MAX << (32 - len)`, written to survive `len == 0` — where that shift
/// is undefined and the answer wanted is zero.
const fn mask_bits_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

const fn mask_bits_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    }
}

/// Walks the addresses of a prefix. Held as `u128` for both families so there
/// is one loop rather than two; `v4` says which way to spell the result.
#[derive(Clone, Debug)]
pub struct HostIter {
    next: u128,
    last: u128,
    v4: bool,
    done: bool,
}

impl Iterator for HostIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        if self.done || self.next > self.last {
            return None;
        }
        let value = self.next;
        // The last address of the family would overflow the increment rather
        // than ending the walk, so the end is a flag instead of a comparison.
        if self.next == self.last {
            self.done = true;
        } else {
            self.next += 1;
        }
        Some(if self.v4 {
            IpAddr::V4(Ipv4Addr::from(value as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(value))
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = if self.done {
            0
        } else {
            (self.last - self.next + 1) as usize
        };
        (n, Some(n))
    }
}

impl ExactSizeIterator for HostIter {}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.len)
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prefix({self})")
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(PrefixError::Malformed)?;
        let addr: IpAddr = addr.trim().parse().map_err(|_| PrefixError::Malformed)?;
        let len: u8 = len.trim().parse().map_err(|_| PrefixError::Malformed)?;
        Self::new(addr, len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixError {
    Malformed,
    TooLong { len: u8, max: u8 },
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("not an address and prefix length"),
            Self::TooLong { len, max } => write!(f, "prefix /{len} is longer than /{max}"),
        }
    }
}

impl std::error::Error for PrefixError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn masks_the_address_down_to_its_network() {
        assert_eq!(p("192.168.1.37/24").to_string(), "192.168.1.0/24");
        assert_eq!(p("10.11.12.13/8").to_string(), "10.0.0.0/8");
        assert_eq!(p("2001:db8::dead:beef/32").to_string(), "2001:db8::/32");
    }

    #[test]
    fn rejects_a_length_the_family_cannot_hold() {
        assert!("192.168.1.0/33".parse::<Prefix>().is_err());
        assert!("::/129".parse::<Prefix>().is_err());
        assert!("192.168.1.0".parse::<Prefix>().is_err());
    }

    #[test]
    fn membership_does_not_cross_families() {
        let net = p("192.168.1.0/24");
        assert!(net.contains("192.168.1.1".parse().unwrap()));
        assert!(net.contains("192.168.1.255".parse().unwrap()));
        assert!(!net.contains("192.168.2.1".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));
    }

    /// The number every scan of a home network is quoted in.
    #[test]
    fn a_slash_24_sweeps_254_addresses() {
        let hosts: Vec<_> = p("192.168.1.0/24").hosts().unwrap().collect();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[253], "192.168.1.254".parse::<IpAddr>().unwrap());
    }

    /// RFC 3021: a /31 is a point to point link and both addresses are hosts.
    /// A /32 is one address and it is the host. Subtracting a network and a
    /// broadcast from either underflows into a sweep of four billion.
    #[test]
    fn short_prefixes_have_no_network_or_broadcast_to_skip() {
        let pair: Vec<_> = p("10.0.0.4/31").hosts().unwrap().collect();
        assert_eq!(pair.len(), 2);
        assert_eq!(pair[0], "10.0.0.4".parse::<IpAddr>().unwrap());

        let one: Vec<_> = p("10.0.0.7/32").hosts().unwrap().collect();
        assert_eq!(one, vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);
    }

    /// The rule this module exists for: an IPv6 prefix is not walked, and the
    /// sweep asks that question rather than assuming the family.
    #[test]
    fn ipv6_prefixes_refuse_to_be_enumerated() {
        assert!(p("fe80::/64").hosts().is_none());
        assert!(p("2001:db8::/32").hosts().is_none());
        assert_eq!(p("fe80::/64").host_count(), 0);
    }

    #[test]
    fn over_broad_v4_prefixes_refuse_too() {
        assert!(
            p("192.168.0.0/16").hosts().is_some(),
            "/16 is the limit, inclusive"
        );
        assert!(p("10.0.0.0/8").hosts().is_none());
    }

    /// Walking to the top of the address space must end rather than wrap.
    #[test]
    fn the_last_address_of_the_family_terminates_the_walk() {
        let top: Vec<_> = p("255.255.255.254/31").hosts().unwrap().collect();
        assert_eq!(top.len(), 2);
        assert_eq!(top[1], "255.255.255.255".parse::<IpAddr>().unwrap());

        let v6: Vec<_> = p("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127")
            .hosts()
            .unwrap()
            .collect();
        assert_eq!(v6.len(), 2);
        assert_eq!(
            v6[1],
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .unwrap()
        );
    }

    #[test]
    fn size_saturates_rather_than_overflowing() {
        assert_eq!(p("192.168.1.0/24").size(), 256);
        assert_eq!(p("0.0.0.0/0").size(), 1 << 32);
        assert_eq!(p("::/0").size(), u64::MAX);
        assert_eq!(p("2001:db8::/64").size(), u64::MAX);
    }

    #[test]
    fn host_count_agrees_with_the_iterator() {
        for text in [
            "192.168.1.0/24",
            "10.0.0.4/31",
            "10.0.0.7/32",
            "172.16.0.0/20",
        ] {
            let net = p(text);
            assert_eq!(
                net.host_count() as usize,
                net.hosts().unwrap().count(),
                "{text}"
            );
        }
    }
}
