//! Hardware addresses, and the two bits of one that carry meaning.
//!
//! A MAC is six bytes, but two of the bits in the first octet are flags rather
//! than address, and reading them is the difference between a device list that
//! is right and one that looks broken to the people who know most:
//!
//! * **Bit 0** (the low bit) is the group bit: set means multicast, and a
//!   multicast address is never a device's own.
//! * **Bit 1** is the local bit: set means the address was assigned by whoever
//!   is using it rather than by the IEEE. Every modern phone and laptop sets it
//!   when it randomises its address per network, which is most of the time.
//!
//! That second one is why [`MacAddr::is_randomised`] exists and why the vendor
//! lookup must ask it first. A randomised address has no manufacturer to find,
//! so reporting it as "unknown vendor" describes a failure of the lookup when
//! what actually happened is that the device declined to say. `CLAUDE.md`
//! states that as a rule; this is where it is enforced.

use std::fmt;
use std::str::FromStr;

/// A six-byte hardware address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The all-zero address, which is what an unresolved neighbour entry and an
    /// interface with no hardware address both report.
    pub const ZERO: Self = Self([0; 6]);

    /// The broadcast address, the destination of an ARP request.
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
    }

    pub const fn is_broadcast(self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Group bit: this address names a set of receivers, not one device.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Local bit: assigned by the user of the address rather than by the IEEE,
    /// so there is no manufacturer registration behind it.
    ///
    /// Callers wanting to know whether a *device* randomised its address should
    /// use [`MacAddr::is_randomised`], which excludes the multicast case.
    pub const fn is_locally_administered(self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// A device address that was not assigned by a manufacturer.
    ///
    /// This is the question the vendor lookup and the interface both want:
    /// broadcast and multicast addresses also carry the local bit in practice,
    /// and neither is a device, so they are excluded here rather than at every
    /// call site.
    pub const fn is_randomised(self) -> bool {
        self.is_locally_administered() && !self.is_multicast() && !self.is_zero()
    }

    /// The 24-bit OUI, for the vendor table. Meaningless unless
    /// [`MacAddr::is_randomised`] is false, which is the caller's to check.
    pub const fn oui(self) -> u32 {
        (self.0[0] as u32) << 16 | (self.0[1] as u32) << 8 | self.0[2] as u32
    }
}

/// Lower case, colon separated. The form every other tool on the machine
/// prints, so a MAC copied out of Muster pastes into them.
impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// Accepts the three separators the platforms disagree about: `:` from Unix
/// tooling, `-` from Windows, and none at all from Cisco-flavoured output
/// (which also uses `.` every four digits, hence its acceptance below).
impl FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut nibbles = 0usize;

        for ch in s.chars() {
            if matches!(ch, ':' | '-' | '.') {
                continue;
            }
            let value = ch.to_digit(16).ok_or(ParseMacError)? as u8;
            if nibbles >= 12 {
                return Err(ParseMacError);
            }
            let byte = &mut octets[nibbles / 2];
            *byte = if nibbles.is_multiple_of(2) {
                value << 4
            } else {
                *byte | value
            };
            nibbles += 1;
        }

        if nibbles == 12 {
            Ok(Self(octets))
        } else {
            Err(ParseMacError)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMacError;

impl fmt::Display for ParseMacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a hardware address")
    }
}

impl std::error::Error for ParseMacError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_lower_case_and_colon_separated() {
        let mac = MacAddr::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn parses_every_separator_the_platforms_use() {
        let want = MacAddr::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        for text in [
            "00:1a:2b:3c:4d:5e",
            "00-1A-2B-3C-4D-5E",
            "001a2b3c4d5e",
            "001a.2b3c.4d5e",
        ] {
            assert_eq!(text.parse::<MacAddr>(), Ok(want), "parsing {text}");
        }
    }

    #[test]
    fn rejects_the_wrong_number_of_digits() {
        for text in ["00:1a:2b:3c:4d", "00:1a:2b:3c:4d:5e:6f", "", "zz:zz"] {
            assert!(text.parse::<MacAddr>().is_err(), "accepting {text}");
        }
    }

    /// The rule from `CLAUDE.md`: a randomised address is reported as
    /// randomised, and the check is bit 1 of the first octet. `02:` and `06:`
    /// have it set, `00:` and `04:` do not.
    #[test]
    fn randomised_addresses_are_told_from_registered_ones() {
        let apple: MacAddr = "3c:22:fb:11:22:33".parse().unwrap();
        assert!(!apple.is_randomised());
        assert_eq!(apple.oui(), 0x3c22fb);

        for text in [
            "02:11:22:33:44:55",
            "06:11:22:33:44:55",
            "3e:22:fb:11:22:33",
        ] {
            let mac: MacAddr = text.parse().unwrap();
            assert!(mac.is_randomised(), "{text} should read as randomised");
        }
    }

    /// Broadcast and multicast carry the local bit but are not devices, so the
    /// vendor lookup must not be told they randomised anything.
    #[test]
    fn broadcast_and_multicast_are_not_randomised_devices() {
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::BROADCAST.is_randomised());
        assert!(!MacAddr::ZERO.is_randomised());

        // IPv4 multicast mapping, 01:00:5e:…
        let mcast: MacAddr = "01:00:5e:00:00:fb".parse().unwrap();
        assert!(mcast.is_multicast());
        assert!(!mcast.is_randomised());
    }
}
