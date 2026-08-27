#!/bin/sh
# Refresh the IANA Private Enterprise Number registry that
# `crates/muster-net/build.rs` compiles in.
#
#   sh tools/fetch-pen.sh
#
# Rewrites `crates/muster-net/data/pen.tsv`. The result is checked in, for the
# same reason `tools/fetch-oui.sh`'s is: `CLAUDE.md` says a table travels with a
# release rather than through a second update mechanism, so this is run by a
# person before cutting one, not by the application and not by the build.
#
# What the table is for. An SNMP agent answers `sysObjectID.0` with an OID under
# `1.3.6.1.4.1.<n>`, and `<n>` is the number IANA gave the organisation that
# registered it. That is the only vendor name a switch, an access point or a
# UPS ever volunteers, and looking it up here rather than over the network is
# what keeps the promise that nothing leaves the machine.
#
# Contacts and email addresses are dropped. Muster shows the organisation and
# nothing else, and sixty-six thousand people's names and addresses have no
# business in a network scanner's binary.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/crates/muster-net/data/pen.tsv"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

printf 'fetching the enterprise number registry\n' >&2
if ! curl -fsS --max-time 300 -o "$work/pen.txt" \
    https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers; then
    echo "could not fetch the registry" >&2
    exit 1
fi

python3 - "$work/pen.txt" "$out" <<'PY'
import pathlib, re, sys

src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
lines = src.read_text(encoding="utf-8", errors="replace").split("\n")

# The registry is a four-line record: the decimal at column zero, then the
# organisation, the contact and the email, each indented two spaces further.
# Only the first two are wanted, and the indentation is what tells them apart.
rows, seen = [], set()
i = 0
while i < len(lines) - 1:
    line = lines[i].rstrip()
    if re.fullmatch(r"\d+", line):
        number, org = int(line), lines[i + 1].rstrip()
        if org.startswith("  ") and not org.startswith("   "):
            org = re.sub(r"\s+", " ", org).strip()
            # The registry's ways of saying nobody holds this number. None of
            # them is an organisation, and reporting one as a vendor would be
            # the confident nonsense the whole table exists to avoid.
            if org.lower() not in ("unassigned", "reserved", "---none---", "none"):
                if number not in seen:
                    seen.add(number)
                    rows.append((number, org))
            i += 2
            continue
    i += 1

if len(rows) < 50000:
    sys.exit(f"only {len(rows)} enterprises; the registry is usually 60k+")

rows.sort()
with out.open("w", encoding="utf-8", newline="\n") as fh:
    fh.write("# IANA Private Enterprise Numbers, stripped to the two fields\n")
    fh.write("# Muster uses. Regenerate with tools/fetch-pen.sh.\n")
    fh.write("# number\torganisation\n")
    for number, org in rows:
        fh.write(f"{number}\t{org}\n")

print(f"{len(rows)} enterprises, {out.stat().st_size / 1e6:.2f} MB")
PY
