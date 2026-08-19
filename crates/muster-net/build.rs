//! Compiles the IEEE registry into the binary.
//!
//! `CLAUDE.md`: the vendor table is compiled in at build time from a checked-in
//! data file, so there is one binary with everything in it and the table
//! refreshes with a release rather than through a second update mechanism.
//!
//! It emits a **binary blob** that `vendor.rs` includes and searches, rather
//! than a generated Rust source file. Fifty-three thousand array entries is a
//! quarter of a million tokens for rustc to parse on every clean build, for a
//! table whose contents it can do nothing with; a sorted blob and a binary
//! search is the same lookup at a fraction of the build.
//!
//! Layout, little-endian throughout, no alignment assumed anywhere because
//! `include_bytes!` gives a byte-aligned slice:
//!
//! ```text
//! magic u32, then three counts u32, then the blob length u32
//! MA-L: n × u32 prefix (sorted), then n × u32 name offset
//! MA-M: the same
//! MA-S: n × u64 prefix (sorted), then n × u32 name offset
//! names: u16 length then that many UTF-8 bytes, repeatedly
//! ```
//!
//! Names are deduplicated: a company with forty assignments occupies the blob
//! once, which is most of the difference between a 1.8 MB source file and the
//! table that comes out of it.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

/// "MOUI", so a truncated or stale blob fails loudly rather than being searched
/// as though it were a table.
const MAGIC: u32 = 0x4d4f_5549;

fn main() {
    let data = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("data/oui.tsv");
    println!("cargo:rerun-if-changed={}", data.display());
    println!("cargo:rerun-if-changed=build.rs");

    let text = std::fs::read_to_string(&data)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", data.display()));

    // bits -> (prefix, name)
    let mut tables: HashMap<u8, Vec<(u64, String)>> = HashMap::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(bits), Some(prefix), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            panic!("{}:{}: expected three fields", data.display(), line_no + 1);
        };
        let bits: u8 = bits.parse().expect("bit width");
        let value = u64::from_str_radix(prefix, 16).expect("hex prefix");
        tables
            .entry(bits)
            .or_default()
            .push((value, name.to_string()));
    }

    // Deduplicated name blob. Every assignment points into it, and a company
    // holding many blocks is stored once.
    let mut blob: Vec<u8> = Vec::new();
    let mut offsets: HashMap<String, u32> = HashMap::new();
    let intern = |name: &str, blob: &mut Vec<u8>, offsets: &mut HashMap<String, u32>| -> u32 {
        if let Some(&at) = offsets.get(name) {
            return at;
        }
        let at = blob.len() as u32;
        let bytes = name.as_bytes();
        assert!(bytes.len() <= u16::MAX as usize, "name too long: {name}");
        blob.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        blob.extend_from_slice(bytes);
        offsets.insert(name.to_string(), at);
        at
    };

    let mut sections: Vec<(Vec<u64>, Vec<u32>)> = Vec::new();
    for bits in [24u8, 28, 36] {
        let mut rows = tables.remove(&bits).unwrap_or_default();
        rows.sort_by_key(|(p, _)| *p);
        // A duplicate prefix would make the binary search's answer depend on
        // where it happened to land. The generator upstream removes them; this
        // is the check that says so if it ever stops.
        for pair in rows.windows(2) {
            assert_ne!(
                pair[0].0, pair[1].0,
                "duplicate /{bits} prefix {:x}",
                pair[0].0
            );
        }
        let mut prefixes = Vec::with_capacity(rows.len());
        let mut names = Vec::with_capacity(rows.len());
        for (prefix, name) in rows {
            prefixes.push(prefix);
            names.push(intern(&name, &mut blob, &mut offsets));
        }
        sections.push((prefixes, names));
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("oui.bin");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&out).expect("create oui.bin"));

    f.write_all(&MAGIC.to_le_bytes()).unwrap();
    for (prefixes, _) in &sections {
        f.write_all(&(prefixes.len() as u32).to_le_bytes()).unwrap();
    }
    f.write_all(&(blob.len() as u32).to_le_bytes()).unwrap();

    for (i, (prefixes, names)) in sections.iter().enumerate() {
        // MA-S needs 36 bits; the other two fit in 32 and storing them wide
        // would add half a megabyte for nothing.
        for &p in prefixes {
            if i == 2 {
                f.write_all(&p.to_le_bytes()).unwrap();
            } else {
                f.write_all(&(p as u32).to_le_bytes()).unwrap();
            }
        }
        for &n in names {
            f.write_all(&n.to_le_bytes()).unwrap();
        }
    }
    f.write_all(&blob).unwrap();
    f.flush().unwrap();
}
