//! SipHash-2-4, which is what makes the stateless scan stateless.
//!
//! The port scan keeps no record of the probes it sent. Instead the probe's
//! identity is *computed* into the packet — a hash of source, destination, port
//! and a per-run secret goes in the TCP initial sequence number — and a reply
//! is recognised by recomputing it. That is the whole reason the scan needs no
//! per-port allocation, no timeout wheel and no table: the packet carries its
//! own identity, so the receiving thread can validate a reply it has no memory
//! of having asked for.
//!
//! **It has to be keyed, and it has to be a real hash.** A plain checksum or a
//! counter would let anything on the network fabricate a reply that Muster
//! accepts, and the result would be invented open ports on hosts that never
//! answered — the most damaging kind of wrong answer a scanner can give.
//! SipHash-2-4 is the function masscan uses for the same job; it is fast enough
//! to run per packet at line rate and keyed so the cookie cannot be predicted
//! without the secret.
//!
//! Implemented here rather than taken from a crate because it is forty lines,
//! it is fully specified, and the reference test vectors below pin it exactly.
//! `std`'s own SipHash is not exposed with a settable key.

/// SipHash-2-4 state.
///
/// Named for the two compression rounds per message block and four
/// finalisation rounds, which is the variant everything interoperable uses.
pub struct SipHasher {
    k0: u64,
    k1: u64,
}

impl SipHasher {
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// Hashes a message with this key.
    pub fn hash(&self, msg: &[u8]) -> u64 {
        let mut v0 = self.k0 ^ 0x736f_6d65_7073_6575;
        let mut v1 = self.k1 ^ 0x646f_7261_6e64_6f6d;
        let mut v2 = self.k0 ^ 0x6c79_6765_6e65_7261;
        let mut v3 = self.k1 ^ 0x7465_6462_7974_6573;

        let len = msg.len();
        let whole = len - (len % 8);

        for chunk in msg[..whole].chunks_exact(8) {
            let m = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
            v3 ^= m;
            round(&mut v0, &mut v1, &mut v2, &mut v3);
            round(&mut v0, &mut v1, &mut v2, &mut v3);
            v0 ^= m;
        }

        // The last block is the remaining bytes with the message length in its
        // top byte, which is what stops two different messages that share a
        // prefix from colliding.
        let mut last = ((len as u64) & 0xff) << 56;
        for (i, &b) in msg[whole..].iter().enumerate() {
            last |= (b as u64) << (8 * i);
        }
        v3 ^= last;
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= last;

        v2 ^= 0xff;
        for _ in 0..4 {
            round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^ v1 ^ v2 ^ v3
    }
}

#[inline(always)]
fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference vectors from the SipHash paper: key `00 01 02 … 0f`,
    /// message `00`, `00 01`, `00 01 02`, and so on.
    ///
    /// These are what make this file trustworthy. An implementation that is
    /// *nearly* right — a rotate by the wrong amount, the length byte omitted —
    /// still produces plausible-looking hashes and still validates its own
    /// replies, so nothing on a network would ever reveal the mistake. Only the
    /// published vectors do.
    const VECTORS: [u64; 16] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
    ];

    #[test]
    fn matches_the_reference_vectors() {
        let key0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let key1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let hasher = SipHasher::new(key0, key1);

        for (len, &want) in VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..len as u8).collect();
            assert_eq!(hasher.hash(&msg), want, "message of {len} bytes");
        }
    }

    #[test]
    fn the_empty_message_hashes() {
        let h = SipHasher::new(0, 0);
        // No vector for this beyond it not panicking and being stable.
        assert_eq!(h.hash(&[]), h.hash(&[]));
        assert_ne!(h.hash(&[]), h.hash(&[0]));
    }

    /// The property the scan depends on: a different key gives a different
    /// answer, so a cookie cannot be predicted without the run's secret.
    #[test]
    fn the_key_changes_the_answer() {
        let msg = b"192.168.0.1:443";
        let a = SipHasher::new(1, 2).hash(msg);
        let b = SipHasher::new(1, 3).hash(msg);
        let c = SipHasher::new(2, 2).hash(msg);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// Messages sharing a prefix must not collide, which is what the length
    /// byte in the final block is for.
    #[test]
    fn a_prefix_does_not_collide_with_what_extends_it() {
        let h = SipHasher::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
        let mut seen = std::collections::BTreeSet::new();
        for len in 0..64 {
            let msg = vec![0xaau8; len];
            assert!(seen.insert(h.hash(&msg)), "collision at length {len}");
        }
    }
}
