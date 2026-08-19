//! Who made the hardware, according to the IEEE.
//!
//! The table is `build.rs`'s output, included in the binary. Nothing is fetched
//! and nothing is looked up remotely: `CLAUDE.md` says no lookup of a MAC
//! against a remote service, which is not only a privacy rule but the reason
//! this works on a network with no route to anywhere.
//!
//! ## Three answers, not two
//!
//! The rule this module exists to enforce is that **a randomised address is
//! reported as randomised, never as an unknown vendor.** They are different
//! facts. "Unknown" says the lookup failed; "randomised" says the device
//! deliberately declined to identify itself, which every modern phone does on
//! every network it joins. Collapsing the two makes the device list look broken
//! to exactly the people who know most, because they can see at a glance that
//! half the "unknown" rows are just iPhones behaving correctly.
//!
//! So [`Origin`] has three cases and the caller cannot accidentally get this
//! wrong: there is no function returning `Option<&str>` to misread.
//!
//! ## Most specific wins
//!
//! A 24-bit block can be subdivided and resold, so the same three leading
//! octets may belong to one company at MA-L and another at MA-S. The lookup
//! therefore asks the *longest* registry first — 36 bits, then 28, then 24 —
//! and the first hit is the answer. Asking MA-L first would attribute a small
//! company's devices to whoever holds the block above them.

use crate::mac::MacAddr;

/// The compiled registry. See `build.rs` for the layout.
static TABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oui.bin"));

const MAGIC: u32 = 0x4d4f_5549;

/// Which registry an assignment came from, which is also how large a block it
/// is and therefore how much the answer narrows things down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registry {
    /// 24-bit block, sixteen million addresses. The common case.
    MaL,
    /// 28-bit block, one million addresses.
    MaM,
    /// 36-bit block, four thousand addresses. A small manufacturer.
    MaS,
}

impl Registry {
    pub const fn bits(self) -> u8 {
        match self {
            Self::MaL => 24,
            Self::MaM => 28,
            Self::MaS => 36,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::MaL => "MA-L",
            Self::MaM => "MA-M",
            Self::MaS => "MA-S",
        }
    }
}

/// What can be said about where an address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The device generated this address itself. There is no manufacturer to
    /// look up and its absence is not a gap in the table.
    Randomised,
    /// Found in the registry.
    Registered {
        name: &'static str,
        registry: Registry,
    },
    /// A globally unique address that is not in the table. Either the table is
    /// older than the assignment, or the address was never registered at all.
    Unknown,
}

impl Origin {
    /// The name to show, or [`None`] where there is no name to show. Callers
    /// wanting to *say* something about the two nameless cases should match on
    /// [`Origin`] instead, because they read differently to a user.
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Self::Registered { name, .. } => Some(name),
            _ => None,
        }
    }

    /// A short phrase fit for a table cell, in every case.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Randomised => "randomised address",
            Self::Registered { name, .. } => name,
            Self::Unknown => "not in the registry",
        }
    }
}

/// Looks an address up.
///
/// Multicast and all-zero addresses answer [`Origin::Unknown`] rather than
/// being looked up: neither is a device's own address, so a vendor for one
/// would be meaningless even when the bits happen to match a real assignment.
pub fn lookup(mac: MacAddr) -> Origin {
    if mac.is_randomised() {
        return Origin::Randomised;
    }
    if mac.is_multicast() || mac.is_zero() {
        return Origin::Unknown;
    }

    let o = mac.octets();
    let wide = (o[0] as u64) << 40
        | (o[1] as u64) << 32
        | (o[2] as u64) << 24
        | (o[3] as u64) << 16
        | (o[4] as u64) << 8
        | o[5] as u64;

    // Longest first: a resold sub-block belongs to whoever bought it.
    for (section, registry) in [
        (2usize, Registry::MaS),
        (1, Registry::MaM),
        (0, Registry::MaL),
    ] {
        let bits = registry.bits();
        let key = wide >> (48 - bits);
        if let Some(name) = search(section, key) {
            return Origin::Registered { name, registry };
        }
    }
    Origin::Unknown
}

/// The header, read once per call. Cheap enough that caching it would be more
/// code than it saves, and it keeps the table a plain `&[u8]` with no lazy
/// state to get wrong.
struct Layout {
    counts: [usize; 3],
    blob_at: usize,
}

fn layout() -> Layout {
    assert_eq!(u32(TABLE, 0), MAGIC, "the compiled OUI table is not one");
    let counts = [
        u32(TABLE, 4) as usize,
        u32(TABLE, 8) as usize,
        u32(TABLE, 12) as usize,
    ];
    // Header is five words; then each section is its prefixes and its offsets.
    let mut at = 20;
    for (i, n) in counts.iter().enumerate() {
        at += n * if i == 2 { 8 } else { 4 }; // prefixes
        at += n * 4; // name offsets
    }
    Layout {
        counts,
        blob_at: at,
    }
}

fn section_start(l: &Layout, section: usize) -> usize {
    let mut at = 20;
    for (i, n) in l.counts.iter().enumerate().take(section) {
        at += n * if i == 2 { 8 } else { 4 };
        at += n * 4;
    }
    at
}

fn search(section: usize, key: u64) -> Option<&'static str> {
    let l = layout();
    let n = l.counts[section];
    if n == 0 {
        return None;
    }
    let wide = section == 2;
    let start = section_start(&l, section);
    let offsets_at = start + n * if wide { 8 } else { 4 };

    let prefix_at = |i: usize| -> u64 {
        if wide {
            u64le(TABLE, start + i * 8)
        } else {
            u32(TABLE, start + i * 4) as u64
        }
    };

    // Plain binary search over the blob. The table is byte-aligned, so this
    // reads each candidate rather than indexing a typed slice.
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        match prefix_at(mid).cmp(&key) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                let at = l.blob_at + u32(TABLE, offsets_at + mid * 4) as usize;
                let len = u16le(TABLE, at) as usize;
                let bytes = &TABLE[at + 2..at + 2 + len];
                // `build.rs` wrote these out of a `String`, so they are UTF-8
                // by construction; the lossless conversion is still the honest
                // one to reach for over an unchecked cast.
                return std::str::from_utf8(bytes).ok();
            }
        }
    }
    None
}

fn u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64le(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_table_is_present_and_sane() {
        let l = layout();
        assert!(
            l.counts[0] > 30_000,
            "MA-L should be the big one: {:?}",
            l.counts
        );
        assert!(l.counts[1] > 1_000, "MA-M: {:?}", l.counts);
        assert!(l.counts[2] > 1_000, "MA-S: {:?}", l.counts);
        assert!(l.blob_at < TABLE.len());
    }

    /// The rule this module exists for. A randomised address has no vendor and
    /// saying "unknown" would describe a failure that did not happen.
    #[test]
    fn a_randomised_address_is_never_an_unknown_vendor() {
        for text in [
            "36:d6:0f:80:3e:8a",
            "02:11:22:33:44:55",
            "46:67:e7:4a:6d:a4",
        ] {
            assert_eq!(lookup(mac(text)), Origin::Randomised, "{text}");
            assert_eq!(lookup(mac(text)).name(), None);
            assert_eq!(lookup(mac(text)).label(), "randomised address");
        }
    }

    #[test]
    fn a_registered_address_finds_its_organisation() {
        // Apple's, and one of the most common blocks on any home network.
        let found = lookup(mac("3c:22:fb:11:22:33"));
        let Origin::Registered { name, registry } = found else {
            panic!("expected a registration, got {found:?}");
        };
        assert!(name.contains("Apple"), "got {name}");
        assert_eq!(registry, Registry::MaL);
    }

    /// A block that was subdivided: the longer registry has to win, or a small
    /// manufacturer's devices are credited to whoever holds the block above.
    #[test]
    fn the_most_specific_registry_wins() {
        // Walk the table for a real MA-S assignment, then check that looking up
        // an address inside it does not return the MA-L holder of the same
        // three octets.
        let l = layout();
        let start = section_start(&l, 2);
        let mut checked = 0;
        for i in 0..l.counts[2] {
            let prefix = u64le(TABLE, start + i * 8); // 36 bits
            let full = prefix << 12; // pad to 48
            let m = MacAddr::new([
                (full >> 40) as u8,
                (full >> 32) as u8,
                (full >> 24) as u8,
                (full >> 16) as u8,
                (full >> 8) as u8,
                full as u8,
            ]);
            if m.is_randomised() || m.is_multicast() {
                continue;
            }
            let Origin::Registered { registry, .. } = lookup(m) else {
                panic!("an address from the MA-S table must be registered: {m}");
            };
            assert_eq!(
                registry,
                Registry::MaS,
                "{m} resolved to the wrong registry"
            );
            checked += 1;
            if checked == 200 {
                break;
            }
        }
        assert!(checked > 0, "no usable MA-S rows to check");
    }

    /// Every prefix in the table must be findable. This walks all fifty-odd
    /// thousand of them, which is the only way to know the search agrees with
    /// the layout the generator wrote.
    #[test]
    fn every_assignment_can_be_found() {
        let l = layout();
        for (section, bits) in [(0usize, 24u32), (1, 28), (2, 36)] {
            let start = section_start(&l, section);
            for i in 0..l.counts[section] {
                let prefix = if section == 2 {
                    u64le(TABLE, start + i * 8)
                } else {
                    u32(TABLE, start + i * 4) as u64
                };
                let name = search(section, prefix);
                assert!(
                    name.is_some(),
                    "section {section} row {i} (/{bits} prefix {prefix:x}) not found"
                );
                assert!(!name.unwrap().is_empty());
            }
        }
    }

    /// A globally unique address in a block nobody holds.
    ///
    /// The obvious fixture for this is `00:00:00`, and it is wrong: that is the
    /// first OUI the IEEE ever issued and it belongs to Xerox. `00:08:33` was
    /// picked by walking the table for a gap, and the walk below is what keeps
    /// it a gap — the registry does issue new blocks, and a refreshed data file
    /// could fill this one in.
    #[test]
    fn an_unassigned_address_is_unknown_rather_than_wrong() {
        let l = layout();
        let start = section_start(&l, 0);
        let assigned = |p: u64| (0..l.counts[0]).any(|i| u32(TABLE, start + i * 4) as u64 == p);
        assert!(
            !assigned(0x00_0833),
            "00:08:33 has been assigned since this test was written; pick another gap"
        );

        assert_eq!(
            lookup(mac("00:08:33:11:22:33")).label(),
            "not in the registry"
        );
        assert_eq!(lookup(mac("00:08:33:11:22:33")), Origin::Unknown);

        // And the counter-example, so the test cannot pass by the lookup being
        // broken for everything.
        assert!(
            lookup(mac("00:00:00:11:22:33"))
                .name()
                .is_some_and(|n| n.contains("XEROX"))
        );
    }

    #[test]
    fn multicast_and_zero_are_not_given_a_vendor() {
        assert_eq!(lookup(MacAddr::ZERO), Origin::Unknown);
        assert_eq!(lookup(mac("01:00:5e:00:00:fb")), Origin::Unknown);
        assert_eq!(lookup(MacAddr::BROADCAST), Origin::Unknown);
    }
}
