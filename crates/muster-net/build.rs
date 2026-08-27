//! Compiles the two registries into the binary.
//!
//! `CLAUDE.md`: the vendor table is compiled in at build time from a checked-in
//! data file, so there is one binary with everything in it and the table
//! refreshes with a release rather than through a second update mechanism.
//!
//! **Two tables now follow that rule rather than one.** `data/oui.tsv` is the
//! IEEE registry, which names the company that made a piece of hardware, and
//! `data/pen.tsv` is IANA's Private Enterprise Number registry, which names the
//! organisation that registered an OID. Both are compiled the same way for the
//! same reason: a lookup that went out to a network would be a lookup, and
//! `CLAUDE.md` says nothing leaves the machine.
//!
//! Each emits a **binary blob** that its module includes and searches, rather
//! than a generated Rust source file. Fifty-three thousand array entries is a
//! quarter of a million tokens for rustc to parse on every clean build, for a
//! table whose contents it can do nothing with; a sorted blob and a binary
//! search is the same lookup at a fraction of the build.
//!
//! Layout, little-endian throughout, no alignment assumed anywhere because
//! `include_bytes!` gives a byte-aligned slice:
//!
//! ```text
//! oui.bin
//!   magic u32, then three counts u32, then the blob length u32
//!   MA-L: n × u32 prefix (sorted), then n × u32 name offset
//!   MA-M: the same
//!   MA-S: n × u64 prefix (sorted), then n × u32 name offset
//!   names: u16 length then that many UTF-8 bytes, repeatedly
//!
//! pen.bin
//!   magic u32, then the count u32, then the blob length u32
//!   n × u32 enterprise number (sorted), then n × u32 name offset
//!   names: the same encoding
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

/// "MPEN", and there for the same reason.
const PEN_MAGIC: u32 = 0x4d50_454e;

/// A deduplicated name blob: `u16` length then that many UTF-8 bytes, and one
/// offset per distinct string however many rows point at it.
#[derive(Default)]
struct Blob {
    bytes: Vec<u8>,
    offsets: HashMap<String, u32>,
}

impl Blob {
    fn intern(&mut self, name: &str) -> u32 {
        if let Some(&at) = self.offsets.get(name) {
            return at;
        }
        let at = self.bytes.len() as u32;
        let bytes = name.as_bytes();
        assert!(bytes.len() <= u16::MAX as usize, "name too long: {name}");
        self.bytes
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.bytes.extend_from_slice(bytes);
        self.offsets.insert(name.to_string(), at);
        at
    }
}

fn data(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("data");
    println!("cargo:rerun-if-changed={}", path.join(name).display());
    path.join(name)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    oui();
    pen();
}

/// The IANA Private Enterprise Number registry.
///
/// One `u32` key and one name per row, which is a simpler table than the OUI's
/// three sections: enterprise numbers are one flat space and nothing subdivides
/// them. `tools/fetch-pen.sh` writes the file this reads.
fn pen() {
    let path = data("pen.tsv");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let mut rows: Vec<(u32, String)> = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let Some((number, name)) = line.split_once('\t') else {
            panic!("{}:{}: expected two fields", path.display(), line_no + 1);
        };
        let number: u32 = number
            .parse()
            .unwrap_or_else(|e| panic!("{}:{}: {e}", path.display(), line_no + 1));
        rows.push((number, name.to_string()));
    }

    rows.sort_by_key(|(number, _)| *number);
    // A duplicate would make the binary search's answer depend on where it
    // happened to land. The generator removes them; this says so if it stops.
    for pair in rows.windows(2) {
        assert_ne!(pair[0].0, pair[1].0, "duplicate enterprise {}", pair[0].0);
    }

    let mut blob = Blob::default();
    let mut numbers = Vec::with_capacity(rows.len());
    let mut names = Vec::with_capacity(rows.len());
    for (number, name) in &rows {
        numbers.push(*number);
        names.push(blob.intern(name));
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("pen.bin");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&out).expect("create pen.bin"));
    f.write_all(&PEN_MAGIC.to_le_bytes()).unwrap();
    f.write_all(&(numbers.len() as u32).to_le_bytes()).unwrap();
    f.write_all(&(blob.bytes.len() as u32).to_le_bytes())
        .unwrap();
    for number in &numbers {
        f.write_all(&number.to_le_bytes()).unwrap();
    }
    for at in &names {
        f.write_all(&at.to_le_bytes()).unwrap();
    }
    f.write_all(&blob.bytes).unwrap();
    f.flush().unwrap();
}

/// The IEEE MA-L, MA-M and MA-S registries.
fn oui() {
    let data = data("oui.tsv");

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
    let mut blob = Blob::default();

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
            names.push(blob.intern(&name));
        }
        sections.push((prefixes, names));
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("oui.bin");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&out).expect("create oui.bin"));

    f.write_all(&MAGIC.to_le_bytes()).unwrap();
    for (prefixes, _) in &sections {
        f.write_all(&(prefixes.len() as u32).to_le_bytes()).unwrap();
    }
    f.write_all(&(blob.bytes.len() as u32).to_le_bytes())
        .unwrap();

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
    f.write_all(&blob.bytes).unwrap();
    f.flush().unwrap();
}
