#!/bin/sh
# Refresh the IEEE registry data that `crates/muster-net/build.rs` compiles in.
#
#   sh tools/fetch-oui.sh
#
# Rewrites `crates/muster-net/data/oui.tsv` from the three IEEE registries. The
# result is checked in: `CLAUDE.md` says the table travels with a release rather
# than through a second update mechanism, so this is run by a person before
# cutting one, not by the application and not by the build.
#
# The registries are three files because the IEEE assigns three block sizes.
# All three are needed and the *longest* match wins at lookup time: a 24-bit
# block can be subdivided and resold, so MA-L alone would credit a small
# manufacturer's devices to whoever holds the block above them.
#
# Addresses are dropped. Muster shows the organisation and nothing else, and
# keeping the postal address of forty thousand companies would quadruple a file
# that is already the largest thing in the repository.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/crates/muster-net/data/oui.tsv"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
    printf 'fetching %s\n' "$2" >&2
    if ! curl -fsS --max-time 180 -o "$work/$1" "$2"; then
        echo "could not fetch $2" >&2
        exit 1
    fi
}

fetch oui.csv    https://standards-oui.ieee.org/oui/oui.csv
fetch mam.csv    https://standards-oui.ieee.org/oui28/mam.csv
fetch oui36.csv  https://standards-oui.ieee.org/oui36/oui36.csv

python3 - "$work" "$out" <<'PY'
import csv, pathlib, re, sys
from collections import Counter

work, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
rows, seen = [], set()

for name_, bits in [("oui.csv", 24), ("mam.csv", 28), ("oui36.csv", 36)]:
    with (work / name_).open(newline="", encoding="utf-8", errors="replace") as fh:
        for rec in csv.DictReader(fh):
            asn = (rec.get("Assignment") or "").strip().upper()
            org = (rec.get("Organization Name") or "").strip()
            if not asn or not org or len(asn) * 4 != bits:
                continue
            org = re.sub(r"\s+", " ", org).strip()
            # The registry's way of saying the holder asked not to be named.
            # That is a real answer and a different one from "not in the table",
            # so it is kept rather than dropped.
            if org.lower() in ("private", "ieee registration authority"):
                org = "unregistered (private)"
            key = (bits, asn)
            if key in seen:
                continue
            seen.add(key)
            rows.append((bits, asn, org))

if len(rows) < 40000:
    sys.exit(f"only {len(rows)} assignments; the registries are usually 50k+")

rows.sort(key=lambda r: (r[0], r[1]))
with out.open("w", encoding="utf-8", newline="\n") as fh:
    fh.write("# IEEE MA-L, MA-M and MA-S registries, stripped to the two fields\n")
    fh.write("# Muster uses. Regenerate with tools/fetch-oui.sh.\n")
    fh.write("# bits\tprefix\torganisation\n")
    for bits, asn, org in rows:
        fh.write(f"{bits}\t{asn}\t{org}\n")

counts = Counter(b for b, _, _ in rows)
print(f"{len(rows)} assignments "
      f"(MA-L {counts[24]}, MA-M {counts[28]}, MA-S {counts[36]}), "
      f"{out.stat().st_size / 1e6:.2f} MB")
PY
