# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Muster is a network scanner for the network the machine is actually on: what is
here, what it is, and what it is offering. One native binary with a window,
Windows and Linux, installable and self-updating.

**Released and building out.** The survey, the sweep, identification by name
and vendor, device-kind inference, the `connect()` port scan, DHCP discovery,
the window, the text mode, the packaging and the updater are all built. The
**privileged engine** is not: no raw transport, so no SYN scan, no ARP sweep,
no passive fingerprinting and no LLDP or CDP. Neither is IPv6 sweeping.
`README.md`'s "What is not there yet" is the user-facing list and is kept
honest.

Everything below is still the decided shape rather than a description of code
where the two differ. Treat the "Decisions" and the invariants under
"Architecture" as settled — they were reasoned about before the first line was
written, and re-litigating them costs more than following them. Anything under
"Open" is genuinely open.

The house reference is `../Umber`, a Rust workspace with the same interface
language, the same installer and the same updater. When a question here has an
answer there, take it; Umber's CLAUDE.md is long because every rule in it was
learned from a shipped defect, and inheriting those is the whole point of the
family.

## Decisions

| | |
|---|---|
| Language | Rust, 2024 edition, stable toolchain, one workspace |
| Interface | egui + wgpu through winit, exactly Umber's stack |
| Shape | **One binary.** The window is the product; a `muster <subcommand>` text mode comes out of the same executable |
| Targets | Windows x86-64 + ARM64, Linux x86-64 + ARM64. macOS is not a target |
| Packages | `.msi` and a setup `.exe`, `.deb`, `.rpm`, Arch `PKGBUILD`, AppImage, tarball |
| Updates | Umber's `update` module, ported: asks the releases API, swaps the binary, never writes to a package manager's copy |
| Repo / id | `github.com/Spillebulle/muster`, application id `io.github.spillebulle.muster` |
| Accent | `--accent-h` **200**, signal cyan. Umber is 60, HomeLab 160, Tally 255 |

Rejected, so they do not come back:

- **Docker.** A container cannot see the LAN on Windows: Docker Desktop runs
  Linux containers in a NAT'd VM, so `--network host` attaches to the VM's
  network and an ARP sweep finds a 192.168.65.x with nothing on it. The core
  feature would be broken on half the targets. On native Linux it works, and it
  is still not worth two deployment stories for one product.
- **A web interface.** The design principles have a `class="web"` scale for
  hosted apps and Muster does not use it. Desktop app, not stamped.
- **A second binary for the GUI.** Two things to package, sign and update, and
  two things to keep in step.

## Commands

These all run.

```sh
cargo run --release                  # the window
cargo run --release -- scan          # text mode, same engine
cargo test                           # everything
cargo test -p muster-net             # engine only, no NIC touched, instant
cargo clippy --workspace --all-targets
cargo fmt --all
```

CI must run `fmt --check`, `clippy` and `test` on every runner `release.yml`
builds on, with `RUSTFLAGS: -D warnings`. Umber learned that one by tagging a
green release that then failed on `windows-11-arm`, a runner CI did not cover:
**adding a target to the release matrix means adding its runner to CI in the
same commit.**

Running a real scan needs packet privileges, which is a thing to plan the
session around rather than discover:

```sh
sudo -E cargo run --release -- scan                                # Linux
sudo setcap cap_net_raw,cap_net_admin+eip target/release/muster    # or grant once
```

On Windows a raw-socket session needs an elevated shell **and Npcap installed**;
see Platform support. `RUST_LOG=muster_net=debug` is the logging switch.

## Architecture

### Three crates, layered so the engine is testable without a network

| Crate | Contains | Must not depend on |
|---|---|---|
| `muster-net` | interfaces, discovery, port scan, probes, identification, device kinds, DHCP, the model of a scan | wgpu, winit, egui |
| `muster-app` | window, panels, the scan's presentation, `update/`, the installer | — |
| `muster-desktop` | binary entry point, subcommand dispatch | — |

`muster-net` free of GUI types is what makes the engine testable; **the same
crate free of the *operating system's* sockets is what makes it testable at
all.** Packet send and receive, the routing table, the neighbour table and the
resolver configuration go behind traits, with the real implementations in one
platform module and a recorded implementation for tests. A scanner whose tests
need a NIC has no tests, because CI runners have no LAN worth scanning and no
two developer machines see the same one. This is the boundary that matters most
in this project; it is Umber's `install::detect` rule — a pure function of an
injected probe — applied to the whole engine.

**No test may put a packet on a wire.** Fixtures are captured replies, the
fingerprint tables are driven from recorded observations, and the rate limiter
is driven from a clock the test controls.

### The scan pipeline

A scan is four phases with different shapes, and the mistake to avoid is running
them all through one mechanism.

1. **Enumerate.** Interfaces, addresses, prefixes, the routing table, the
   configured DNS servers and the DHCP lease. All of it read from the OS, no
   packets sent, instant, and it works with no privileges at all. This phase
   alone answers "what is my gateway, what is my DNS" and must be usable on its
   own.
2. **Sweep.** Find the hosts. ARP over the local prefix (NDP for IPv6), plus
   ICMP echo, plus the multicast discovery protocols below. Bounded by the
   prefix size, so a /24 is 254 addresses and a /16 needs a plan.
3. **Port scan.** The stateless path, below. This is where the performance is.
4. **Identify.** Per host, and only for hosts that answered: banner grabs, TLS
   certificates, mDNS/SSDP/NetBIOS queries, fingerprinting. Hundreds of short
   connections rather than millions of packets — a different shape from phase 3,
   and it does not belong in phase 3's loop.

**The port scan is stateless, in the masscan shape, and this is the whole
performance argument.** One thread sends, one thread receives, and there is no
per-probe record between them: the probe's identity is encoded in the packet it
sends, so a reply identifies itself. A SipHash of (source, destination, port,
per-run secret) goes in the TCP initial sequence number; a SYN-ACK is ours if
its acknowledgement minus one is that cookie. Nothing is allocated per port,
nothing times out per port, and the send rate is a function of nothing but the
rate limiter. The alternative — a socket, a task or a table entry per port — is
what makes conventional scanners slow, and it is not a thing to fall back to
"for now", because the reply-validation design is the part that has to be right
first.

Rules that come with it:

- **Every probe is rate limited, globally and per host.** A scanner that sends
  as fast as it can is indistinguishable from an attack, will be dropped by any
  switch with storm control, and produces false negatives that look like an
  empty network. The limiter is a token bucket the caller sets, with an adaptive
  mode that backs off on loss, and there is a hard default well below line rate.
- **The receive path must not assume it sees a reply.** Absence of a reply is
  "filtered or dropped", never "closed"; a RST is "closed"; only a SYN-ACK is
  "open". Reporting an unanswered probe as a closed port is the most common lie
  a scanner tells.
- **The scan is cancellable and reports real progress.** Progress over a known
  address count and a known port count is knowable, so it is reported. Where it
  is not knowable the bar stays empty; a progress bar that animates over an
  unknown is refused here as it is everywhere else in the family.
- **UDP is not TCP with a different number.** No reply means nothing at all, an
  ICMP port-unreachable means closed, and the only way to get a positive is a
  service-specific payload. So UDP scanning is a table of protocol probes (DNS,
  mDNS, SSDP, NetBIOS, SNMP, DHCP, NTP), not a port range.

### Privilege, and the fallback that must stay honest

Muster has to be useful without administrator rights, because a lot of the
people who want to know what is on their network cannot elevate. So there are
two engines under one API, and **the interface always says which one produced a
result.**

Privileged (raw packet access): ARP sweep at rate, SYN scan, DHCP discovery from
port 68, passive stack fingerprinting, LLDP/CDP listening.

Unprivileged, and more capable than it sounds:

- **Windows.** `SendARP` resolves a MAC for an address with no elevation at all,
  and `IcmpSendEcho2` pings. `GetAdaptersAddresses`, `GetIpForwardTable2` and
  `GetIpNetTable2` give the interfaces, the gateway, the DNS servers and the
  neighbour table.
- **Linux.** Netlink gives the routes and the neighbour table; `SOCK_DGRAM`
  `IPPROTO_ICMP` pings where `net.ipv4.ping_group_range` allows it. Neighbour
  entries can be *provoked* by touching each address and then re-reading the
  table, which is how an unprivileged sweep still learns MACs.
- **Both.** `connect()` scanning, and every one of the discovery protocols in
  the next section, which are ordinary UDP and need nothing.

The capability probe runs at start-up and is a pure function of injected
readings, the same rule `install::detect` follows. **Never degrade silently.** A
scan that fell back to `connect()` says so, and says what it could not do.
"No devices found" from an engine that could not send an ARP request is the
worst failure this application can produce, because it looks like an answer.

### Discovery is layered, and most of it is free

The devices announce themselves. Ask before probing:

| Source | Gives |
|---|---|
| mDNS / DNS-SD (`_services._dns-sd._udp.local`) | hostnames, service list, Apple `_device-info._tcp` model strings, printers, Chromecasts |
| SSDP / UPnP | a description URL, and from it manufacturer, model and serial |
| NetBIOS name service (UDP 137) | Windows names and workgroup |
| LLMNR | names on modern Windows networks |
| DHCP (`dhcp.rs`) | **all** offers, not the first — two offers is a rogue DHCP server, and detecting that is a feature, not an error case. Built |
| LLDP / CDP (privileged, passive) | the switch, and the port a device is on |
| TLS certificates on any open port | subject and SAN, often the best identifier on the network |

IPv6 is not an afterthought. Dual-stack is the normal case now, the LAN
primitive is NDP rather than ARP, and pinging `ff02::1` finds link-local
neighbours in one packet. An engine that models "address" as `Ipv4Addr` will
have to be rewritten; model it as `IpAddr` from the first commit.

### Identification carries its evidence

Every claim about a device is a claim with a reason, and the reason is stored
beside it and shown. "Probably an iPhone" with nothing behind it is a guess
wearing a confident face.

- **MAC vendor lookup is the IEEE registry (MA-L, MA-M, MA-S), compiled in at
  build time** from a checked-in data file, by a `build.rs` that emits a sorted
  table. One binary with everything in it, Umber's rule; the table refreshes
  with a release rather than through a second update mechanism.
- **A randomised MAC must be reported as randomised, never as "unknown
  vendor".** Every modern phone sets the locally-administered bit per network.
  Reading bit 1 of the first octet is the check, and getting this wrong makes
  the device list look broken to exactly the users who know most.
- **Fingerprinting states its confidence and its method.** Initial TTL and TCP
  window from a single SYN-ACK give a coarse OS class for free and should be
  taken; nmap-grade active fingerprinting is a much larger probe set and a much
  larger claim. Label which one answered.
- **What a device *is* comes from ranked clues, never from its name.**
  `kind.rs` infers a [`Kind`] from four sources in a fixed order: the routing
  table (the gateway is not a guess), a service the device advertises about
  itself, an open port only one kind of thing listens on, and — weakest — a
  vendor that makes only one kind of thing. The order is an `enum`'s `Ord` and
  the tables are data, so the priority is stated once rather than emerging from
  the shape of an `if` chain. A **hostname is deliberately not a clue**:
  `HP-Printer` is usually right and `daves-old-printer-pc` is a desktop, so a
  name is evidence about whoever set the device up. Every guess carries the
  clue that produced it and the interface shows both.
- **The vendor table earns its place by what is missing from it.** Apple,
  Samsung, Google and Amazon each make five of the kinds, so a match on one is a
  coin toss wearing a confident face. Only vendors with one product category are
  listed. Adding a broad vendor to make a screenshot look fuller is the failure
  mode to refuse.
- **Identity is a merge of independent sources with a priority, not a race.** A
  UPnP model string beats an OUI vendor; a `_device-info` record beats a TTL
  guess. Where sources disagree, keep both — a device answering as two things is
  information, often that it is a router or a VM host.

## Interface

UI follows `../Design-Principles/STYLE-GUIDE.md` and uses its tokens; accent hue
is **200**. Desktop app, so the root is not stamped `web`. Never a raw hex in a
widget. §16 of that guide is the checklist a new project is held to, and the
short version of what it means here: 34 px top bar with the accent mark, 240 px
sidebar, 26 px status bar; selection is a neutral fill plus strong text plus a
small accent mark and never an accent background; hairlines everywhere, shadows
only under things that float; every figure monospaced and tabular; icons from
one stroke set with a tooltip on every icon-only control; British spelling,
sentence case, and no em dashes in anything a user reads.

Two things the design language decides for this application specifically:

- **The device list is the app.** It is a dense table of figures — addresses,
  MACs, latencies, port counts — so it is `--font-figure` throughout and the
  columns align. This is the screen everything else hangs off.
- **The device icons are colourful, and that is a stated departure.** §11 of
  the style guide asks for one stroke set and §2.5 reserves colour for state;
  the kind icons are filled shapes in eleven hues. The reason is that twelve
  monochrome outlines are twelve things to *read*, and the column exists so that
  the printer can be found without reading. What keeps it in the family:
  **no icon names a colour.** Every one is `theme::hued`, the accent's own
  lightness and chroma with the hue moved, so both themes come out of the
  recipe and there is no device palette to drift. Hues stay clear of 20–40,
  where `caution` and `critical` live, so a device never reads as a warning.
- **A scan in progress is a normal state, not a modal.** Results arrive
  incrementally and the table fills; nothing blocks, and cancelling is always
  available and takes effect at the next packet rather than at the end of a
  phase.

Umber's `crates/umber-app/src/theme.rs` is the reference implementation of the
token table. Port it rather than re-deriving it, and keep the size table
identical — the point of the numbers is that they are the same in every app.

## Platform support

### Windows needs Npcap, and cannot bundle it

Windows has blocked sending raw TCP through `SOCK_RAW` since XP SP2, so SYN
scanning, ARP sweeping and DHCP discovery all go through Npcap's driver. Two
consequences:

- **Npcap cannot be redistributed in the installer.** Bundling it with other
  software requires a commercial OEM licence from its authors. So Muster
  **detects** Npcap, explains what it unlocks, and links to it. It never ships
  it, and the MSI never installs a driver.
- **Without Npcap, Muster still works**, on the unprivileged path above. That
  path is not a stub and is not allowed to rot; it is what most Windows users
  will run.

### Linux capabilities, and the packages that cannot grant them

`CAP_NET_RAW` (plus `CAP_NET_ADMIN` for promiscuous mode) is what the privileged
engine needs. `.deb`, `.rpm` and the Arch package can `setcap` the binary in a
post-install script, and should. **AppImage and Flatpak cannot**: an AppImage is
extracted at run time and loses file capabilities, and a Flatpak sandbox has no
mechanism to grant them. Those two builds are unprivileged-only, they must say
so on the screen where it matters rather than in a README, and the Flatpak
manifest's network permissions are a deliberate decision to write down when it
is authored.

A `setcap` binary runs in the loader's secure-execution mode, which drops
`LD_LIBRARY_PATH` and friends. That is fine in a package and surprising in a
development tree; it is why the dev instructions above offer `sudo -E` as well.

Distribution coverage is Debian/Ubuntu (`.deb`), Fedora/RHEL/openSUSE (`.rpm`),
Arch (`PKGBUILD`, x86-64 only, because Arch Linux is), plus AppImage, Flatpak
and a plain tarball for everything else. That is Umber's matrix, and the reasons
for its gaps — no musl, no RISC-V, no Snap — carry over unchanged.

## Packaging, the installer, the updater

Port these from Umber rather than designing them again. Its `packaging/` and
`tools/` are the templates, and `packaging/check.sh` is the script that keeps the
application id consistent across the AppStream file, the desktop entry, the
icons and all three packaging scripts.

The rules that were bought with broken releases:

- **Cutting a release is pushing a tag**, and the tag waits for CI to be green
  on that exact commit. A local pass is not evidence; three of Umber's releases
  broke on a platform the release machine was not.
- **The version lives in one place**, `[workspace.package]`, and `CHANGELOG.md`
  is the release notes, published verbatim. Tests fail the build when the
  changelog does not describe the version being released.
- **An asset name is stated in several places** — the release workflow, the
  README's download table, the test that checks them, and the updater's
  `wanted_asset`. Renaming one without the others gives users "no build for this
  machine" for ever.
- **The updater never writes to an installation a package manager owns.** It
  detects the owner and prints that manager's command instead. The MSI is the
  one managed case it still updates, by handing `msiexec` a package.
- **On Windows the swap is rename-then-replace**, and a failed update leaves a
  working Muster rather than none.
- **Nothing in the updater may say "verified" unless releases are signed.** They
  are not, so the language is HTTPS, an address from the API, and a length —
  Umber enforces that with a test that fails on the word appearing in a stage
  label. Signing is a real thing to add; until it exists, say what is true.
- **The Windows setup executable carries its payload appended after the PE**,
  with the length at the end, and the installer runs from a copy in the
  temporary directory because it would otherwise be a file inside the
  installation the package is replacing.

## Conduct

Muster is an administrator's tool for a network its user is on, and the defaults
are what keep that true.

- **The default target is the local prefix**, derived from the interface. Not a
  range somebody typed, and never a default that reaches beyond the link.
- **Scanning outside the local prefix is a deliberate act**, confirmed, and
  bounded. A scan of an arbitrary range is the user's decision and their
  responsibility, and the application should say so once, plainly, without
  moralising.
- **No exploitation.** Muster identifies services; it does not authenticate to
  them, does not try credentials, and does not carry payloads intended to make
  something crash. Banner grabbing, TLS certificate reading and protocol
  discovery are the whole of the interaction with a service.
- **Nothing leaves the machine.** No telemetry, and no lookups of a MAC or a
  hostname against a remote service. The one network request Muster makes on its
  own behalf is the update check, it is off until the user has been asked, and
  the setting that controls it is in one place.

## What to build next

Roughly in the order the value lands. Nothing here is committed to; the point is
that the next session does not have to rediscover the list.

**The privileged engine is the biggest single win, and everything in it is
already designed.** `portscan::Cookie` is written and tested with no transport
under it; ARP, DHCP from port 68 without fighting the system client, passive
fingerprinting and LLDP all wait on the same thing — raw packet access, which
is Npcap on Windows and `CAP_NET_RAW` on Linux. When it lands, the Linux
packages get their `setcap` back (see `build-packages.sh`, which says why they
do not have it yet) and the README's first "not there yet" entry goes.

Cheap and unprivileged, so worth doing before that:

- **SSDP and UPnP.** One multicast datagram, and the description URL it returns
  carries manufacturer, model and serial — the best identification on most home
  networks, and it would feed `kind.rs` a clue stronger than any vendor guess.
- **TLS certificate reading** on any open port. Subject and SAN are often the
  only place a device's real name is written. Reading a certificate is not
  authenticating, so it stays inside the conduct rules.
- **Banner grabbing**, for the same reason and with the same limit: read what a
  service volunteers, send nothing that is not a protocol's own greeting.
- **UDP service probes** as a table (DNS, mDNS, SSDP, NetBIOS, SNMP, NTP), which
  is the only honest way to scan UDP at all.
- **IPv6 by NDP.** Addresses and routes are already read for both families;
  pinging `ff02::1` finds link-local neighbours in one packet, which is a whole
  address family for very little code.

Interface work the device list is starting to ask for:

- **Filter and sort.** A /24 with forty devices is already past what an
  unsorted table serves well.
- **Export**, as CSV and JSON. The obvious next question after a scan is "put
  this in a ticket".
- **User labels**, kept beside the scan: somebody who knows their network can
  name the unknown devices once, and a label should outlive a rescan.
- **Wake-on-LAN**, which is one broadcast packet and the only *write* this
  application would ever make to the network. It needs its own argument before
  it is built, because it crosses the line from looking to acting.

Still genuinely open:

- Whether the identification phase justifies an async runtime. The stateless
  scan needs two threads and no runtime at all; the hundreds of short
  connections in phase 4 are the case for one. If a runtime is added it stays
  inside `muster-net` and never appears in `muster-app`'s API.
- How scans are persisted, and whether a saved scan is a document with a format
  worth versioning. It probably is, and comparing two scans of the same network
  a week apart is the feature that argument should be settled by. A saved scan
  is also what would bring back the MIME type and thumbnailer the packaging
  currently omits.
- Whether continuous monitoring — a scan that stays running and reports arrivals
  and departures — is version one or version two. It is the feature that would
  make "a new device appeared on your network" possible, which is the one alert
  worth having.
