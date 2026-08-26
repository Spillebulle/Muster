# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Muster is a network scanner for the network the machine is actually on: what is
here, what it is, and what it is offering. One native binary with a window,
Windows and Linux, installable and self-updating.

**Released and building out.** The survey, the sweep, identification by name
and vendor, device-kind inference, the `connect()` port scan, DHCP discovery,
SSDP and UPnP, the link phase and the passive listen, the window, the text
mode, the packaging and the updater are all built. The
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

A scan is five phases with different shapes, and the mistake to avoid is
running them all through one mechanism. **Two of them do not walk addresses at
all**, and that is the point of them: a sweep can only find what answers when it
is asked, and the devices somebody is scanning to find are very often the ones
that never do.

1. **Enumerate.** Interfaces, addresses, prefixes, the routing table, the
   configured DNS servers and the DHCP lease. All of it read from the OS, no
   packets sent, instant, and it works with no privileges at all. This phase
   alone answers "what is my gateway, what is my DNS" and must be usable on its
   own.
2. **Sweep.** Find the hosts. ARP over the local prefix (NDP for IPv6), plus
   ICMP echo, plus the multicast discovery protocols below. Bounded by the
   prefix size, so a /24 is 254 addresses and a /16 needs a plan.
3. **Port scan.** The stateless path, below. This is where the performance is.
4. **Ask the link** (`link.rs`). One datagram per question, put to the whole
   network at once: the mDNS enumeration, the mDNS service types by name, an
   SSDP search, a WS-Discovery probe, a broadcast NetBIOS node status, and a
   reverse lookup per address to this network's own resolver. **It runs beside
   the sweep rather than after it** — every question is one datagram and then a
   wait on a socket, so a phase of its own would add its whole window for
   nothing — and *it adds devices to the list*. That is the whole reason it is
   a phase: an answer from an address the sweep missed is the most valuable
   thing a scan can produce.
5. **Listen** (`listen.rs`). Sits on 5353, 1900, 3702 and 137 for the length of
   the scan and writes down who speaks. Sends nothing, except the one datagram
   per port that the Windows firewall requires; see below. Also adds devices.
6. **Identify.** Per host, and only for hosts on the list by then: banner grabs,
   TLS certificates, unicast mDNS/SSDP/NetBIOS queries, fingerprinting. Hundreds
   of short connections rather than millions of packets — a different shape from
   phase 3, and it does not belong in phase 3's loop.

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
- **The TCP knock's timeout is per platform, and it is not a preference.**
  Linux returns `ECONNREFUSED` on the first RST; **Windows retransmits the SYN
  first and only surfaces the refusal after about two seconds**. At the 400 ms
  the two used to share, `Outcome::Refused` was unreachable on Windows and every
  refusal became `NoAnswer` — the exact lie the receive-path rule below exists
  to forbid. Measured on eighteen devices, seventeen of which refuse: eleven
  proved at 400 ms, eighteen at 3000 ms. `TCP_MAXRT` looks like the cure and
  destroys the evidence, turning the refusal into `WSAETIMEDOUT`. The cost is
  paid in concurrency, never in elapsed time.
- **The knock has two rounds and the second is for the devices that drop.**
  Once a refusal is visible, port choice barely matters for anything that sends
  a RST — it sends one on every port. It matters entirely for the minority that
  drop everything, and there the only question that gets an answer is a port the
  device is *listening* on. `KNOCK_HARDER` is chosen that way and is paid only
  by an address that answered nothing at all.
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
  `IPPROTO_ICMP` pings where `net.ipv4.ping_group_range` allows it — Debian,
  Ubuntu and Pop!_OS do not, so `platform::linux::Echo` asks for a raw ICMP
  socket second and the packages grant `CAP_NET_RAW` for exactly that. Neighbour
  entries can be *provoked* by touching each address and then re-reading the
  table, which is how an unprivileged sweep still learns MACs.
- **Both.** `connect()` scanning, and every one of the discovery protocols in
  the next section, which are ordinary UDP and need nothing.

The capability probe runs at start-up and is a pure function of injected
readings, the same rule `install::detect` follows. **Never degrade silently.** A
scan that fell back to `connect()` says so, and says what it could not do. That
rule reaches further than the scan: `discover::recheck` exists because the Ping
button reported **"nothing came back this time"** on a machine whose ping
sockets were closed, which is the application blaming a device for a question
it never asked. A single re-check now carries the same `not_done` list a sweep
does, and the interface prints it.
"No devices found" from an engine that could not send an ARP request is the
worst failure this application can produce, because it looks like an answer.

### Discovery is layered, and most of it is free

The devices announce themselves. Ask before probing:

| Source | Gives |
|---|---|
| mDNS / DNS-SD (`_services._dns-sd._udp.local`) | hostnames, service list, Apple `_device-info._tcp` model strings, printers, Chromecasts. Built |
| SSDP / UPnP | device type URNs and a `SERVER` product string, from the headers; a description URL, and from it manufacturer, model and serial, which is not fetched yet. Built |
| NetBIOS name service (UDP 137) | Windows names and workgroup |
| LLMNR | names on modern Windows networks. Asked; no device on the network this was developed against has answered one, and it stays because it costs a datagram and is the only question a Windows machine with NetBIOS switched off answers |
| DHCP (`dhcp.rs`) | **all** offers, not the first — two offers is a rogue DHCP server, and detecting that is a feature, not an error case. Built, and part of a scan when the scan menu says so |
| DNS (`version.bind`, CHAOS) | which devices are name servers, and what software they run. Built |
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
- **A device that sends a datagram is a device, and it goes on the list.** This
  is the rule the link phase and the listen exist for, and for a long time the
  engine had it backwards: the multicast questions ran *inside*
  `identify::many`, which is handed the addresses the sweep found, so an answer
  from an address the sweep missed had nowhere to go and was silently dropped.
  Those are the devices worth finding. `discover::Evidence::Announced` and
  `Evidence::Neighbour` are how a row says it got there by a route other than a
  probe, `Found::was_probed` is what the interface asks before presenting a
  silence as a fact about the device, and `Sweep::heard` is what keeps the count
  honest. **A name is not a device**: a reverse `PTR` proves only that a router
  wrote something down once, so `link::Voice::spoke` keeps those out of the list
  while still letting them name the devices found by other means.
- **Listening is the only thing here that finds a device without sending it a
  packet, and on Windows it does not work unless one packet is sent.** Windows
  Firewall is stateful; unsolicited inbound multicast to a joined group matches
  no flow and is dropped before the socket sees it, silently. Measured: nothing
  sent, zero datagrams from zero sources; one datagram sent first, fifty-three
  from four. So every watch sends one well-formed question **that matches
  nothing** from its own bound port, and repeats it every twenty seconds. Get
  this wrong and the feature works perfectly on Linux and returns an empty list
  on Windows with no error anywhere.
- **A question identifies its asker as well as an answer does.** Half the value
  of the listen is other devices' *queries*: a phone searching for a Chromecast
  has proved it exists. So an unparseable datagram on a watched port still puts
  the address on the list — only the identity depends on reading it — and an
  mDNS **query** is never harvested for services, because what a device is
  looking for says nothing about what it is.
- **The ports are shared, never taken, and nothing ever replies.** 5353 belongs
  to the machine's own responder and 1900 to its SSDP service; `SO_REUSEADDR`
  before the bind is what lets Muster sit beside them. This is the one thing
  `std` cannot do, and the reason `socket2` is a dependency.
- **A question asked of the link is answered by devices that ignore the same
  question asked of them.** This is the single largest thing identification
  learned from a real network: a unicast SSDP `M-SEARCH` found one device out
  of twenty, and the multicast one found every television, set-top box and
  camera on the link. mDNS is the same — two televisions answer
  `_services._dns-sd._udp.local` sent to `224.0.0.251` and ignore it sent to
  themselves. So the link-wide questions are asked once per scan beside the
  per-device ones, and replies are attributed by the address they came from.
- **The machine running the scan is on its own list and answers none of its own
  questions.** Its mDNS, NetBIOS and SSDP responders do not reply to datagrams
  it sent out of its own interface, so it was the one permanently blank row.
  `kind::Vantage` carries what the survey knows about where the scan stands —
  the gateway, and this machine — and both are facts rather than inferences.
- **What a device *is* and what it *serves* are two answers, not one.**
  `Kind` is what a device is and `identify::Role` is what it does for the rest
  of the network, and the interface shows the first as an icon and the second
  as badges beside it. A gateway is a router *and* the DHCP server *and* the
  resolver; folding that into one label loses two of the three. **A role is
  only ever a service that answered** — never an open port, never a vendor that
  usually runs one — which is what keeps a badge from being a guess.
- **The roles that need a connection live in `service.rs`, behind `Speak`.**
  DHCP and DNS are datagrams and belong with the rest of `identify`; SMB, NFS
  and SSH cannot be asked without a TCP connection, so they are a phase of their
  own with a transport of their own and one recorded fake behind it. Each sends
  the protocol's *opening move* and nothing else: an SMB2 `NEGOTIATE`, an ONC
  RPC `NULL` call, and for SSH nothing at all, because a server greets whoever
  connects. Two rules came out of writing them and are worth keeping. **A reply
  in the protocol is the test, never a successful one** — a server refusing
  every SMB dialect has still proved it is a file server — and **an accept
  status is read**, because RPC `PROG_UNAVAIL` on port 2049 is something else
  answering there and badging it would be the port-scan mistake this whole rule
  exists to avoid. HTTP is deliberately not among them: every device on a
  network answers on 80, so a web badge would be a column of noise.
- **The connected questions are off by default and the datagram ones are not.**
  A connection is a thing the far end writes down; a datagram to port 53 is not.
  Same rule as `scan_dhcp`, same answer.
- **A question put to somebody else's resolver carries nothing about this
  network.** The DNS probe asks `version.bind` in the CHAOS class, which a name
  server answers out of itself and a forwarder has nowhere to forward; the
  fallback for servers that ignore CHAOS asks for `localhost` and nothing else.
  A device's own name or address must never appear in a question sent to a
  server that is not this machine's own resolver.
- **What a device *is* comes from ranked clues, never from its name.**
  `kind.rs` infers a [`Kind`] from ranked sources in a fixed order: where the
  scan stands (the gateway and this machine are not guesses), a service the
  device advertises about itself, a model it names for itself, an open port
  only one kind of thing listens on, and — weakest — a vendor that makes only
  one kind of thing. **A model ranks below a service**, because a service is a
  protocol a device has to implement and a model is free text: Samba's
  `fruit:model` has every NAS on the network advertising `model=MacPro7,1`. The order is an `enum`'s `Ord` and
  the tables are data, so the priority is stated once rather than emerging from
  the shape of an `if` chain. Every guess carries the clue that produced it and
  the interface shows both.
- **A hostname is deliberately not a clue, and it stays that way.**
  `HP-Printer` is usually right and `daves-old-printer-pc` is a desktop, so a
  name is evidence about whoever set the device up. **This was built the other
  way once and taken out again**, which is worth knowing before building it a
  third time: a name table did reach a printer, a television, a laptop and four
  card terminals that nothing else here can touch, and ranked last it lost to
  every other clue, so the desktop above stayed a desktop. It was still removed,
  because the standard this project holds identification to is certainty and a
  name cannot meet it. **A blank row is an answer.** The devices it would have
  named are kept as a test in `kind.rs`, with what would name each of them
  honestly written beside it, so the cost is on the record rather than being
  rediscovered.
- **The silicon is a separate claim from the vendor.** Component makers stay
  out of the vendor table for the reason below, but the laptop trade is the
  exception that the rule was getting wrong: an Intel Corporate block is a
  network card, and that card is in a computer. `CHIPSETS` says so as
  `Clue::Chipset`, worded for what is actually true, and the bar for a row is
  that every product the block turns up in is the same kind. Murata is not on
  it, and the reason is a payment terminal that was wearing one.
- **The vendor table earns its place by what is missing from it.** Apple,
  Samsung, Google and Amazon each make five of the kinds, so a match on one is a
  coin toss wearing a confident face. Only vendors with one product category are
  listed. Adding a broad vendor to make a screenshot look fuller is the failure
  mode to refuse.
- **A payment terminal is a kind.** Not a stretch of `Computer`: on the
  networks that have one there are eight, and they are what somebody is looking
  for. They are also the hardest thing here to name, because a terminal is
  built on somebody else's radio module — the four observed carried Huaqin,
  Zhong Ge, Murata and Quectel addresses — so the makers who own their blocks
  are in `VENDORS` and the rest cannot be named at all until one of them
  answers something. Reading the model out of their hostname is the thing that
  was tried and refused; see the rule above.
- **An mDNS reply names the device it is about, which is not always the sender.**
  A Bonjour sleep proxy — which is what an Apple TV or a HomePod quietly becomes
  — answers on behalf of machines that have gone to sleep, so attributing by
  sender put a sleeping laptop's services on the television's row and left the
  laptop off the list. `identify::subject` reads the reply's own address
  records, with the sender winning whenever it is named in them, which is what
  stops a dual-stacked device splitting into two rows. It is also free
  discovery: the address in a proxied record is usually one nothing swept.
- **The enumeration query is not enough, and asking by name is one datagram.**
  RFC 6763 §9 requires a responder to register itself in
  `_services._dns-sd._udp`, and a great many embedded ones — every ESP-based
  smart plug — simply do not. `link::NAMED_SERVICES` asks for the types
  outright, which reaches a whole class of device that answers nothing else.
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
one stroke set — **Lucide's**, whose path data is vendored verbatim in
`icons.rs` and flattened by `lucide.rs`, because the set drawn by hand here
first produced a settings "gear" that was a sun — with a tooltip on every
icon-only control; British spelling,
sentence case, and no em dashes in anything a user reads.

Two things the design language decides for this application specifically:

- **A control that acts and a menu that changes what it does are one control.**
  The scan control is a split button: the label acts, and a fenced-off arrow at
  its right end opens what the next scan will ask. This was a menu in the top
  bar and a button in the options strip, which put a control in one strip
  governing a menu in another; §6.2 wants the top bar empty of both, and the
  arrow is what let it be. **The popover it opens is not a menu and does not
  close on a click**, because it is a panel of switches and somebody turning two
  things on should not have to open it twice. It closes on a click outside, on
  escape, and on the Scan button at its foot.
- **The table is a set of devices, not one.** A row carries a mark, the
  heading carries a box that marks everything the *filter* is showing, and the
  toolbar's Copy and Actions act on the marks — or, with nothing marked, on
  everything shown, which the menus say out loud before anything is chosen.
  Marks are kept by address, so they survive a rescan the way the open panel
  does. **Everything means everything in front of the reader**: an action that
  reached devices a search had hidden would be the one surprise this control
  cannot afford, and "some devices are marked and none of them are on screen"
  is its own state rather than a silent fall back to the filtered set.
- **A column shows a fact, and blank is a fact too.** Ping is empty until
  somebody asks for one, because a sweep's round trip is a different
  measurement from a re-check's and overwriting one with the other would date
  the column silently. Ports is empty where nothing has looked, and the row's
  tooltip says which of "nothing found" and "not looked for" is meant. What
  does not fit in a cell is **counted, never dropped** — the badges and the
  ports both end in a `+n` — because a cell that quietly stops short shows a
  device serving less than it does.
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
- **A page that is a list of groups draws the groups.** `This network` is one
  §7.14 card per interface, each answering the same four questions — address,
  gateway, DNS, DHCP — rather than one column of eyebrows in the order the
  survey happens to be in. The old shape could not say which gateway belonged
  to which link, which is the whole question on a laptop with a VPN up. Where
  the platform keeps resolvers per interface the card shows that interface's,
  and where it keeps one list for the machine the card says so.
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

**Two capabilities, and they are not the same ask.**

`CAP_NET_BIND_SERVICE` is the right to bind a port below 1024, and the DHCP
check needs it *today*: a client has to listen on port 68 to hear an offer at
all, so without it that feature answers "Permission denied" on every Linux
where Muster is not root. The `.deb`, the `.rpm` and the Arch package grant it
in their install scriptlets, `packaging/check.sh` fails when a scriptlet or the
message that names it drifts, and `platform::dhcp_hint` prints the same
`setcap` line for everyone else.

`CAP_NET_RAW` is granted beside it, and the test for granting a capability is
unchanged: **a code path has to spend it.** One does. A ping socket is gated on
`net.ipv4.ping_group_range` and Debian, Ubuntu and Pop!_OS leave it shut for
everybody, so a packaged Muster there reported "no echo was sent" for every
device on the network; `Echo::open` falls back to a raw ICMP socket, which is
what the capability buys. `CAP_NET_ADMIN`, for the promiscuous mode the passive
half of the privileged engine will want, is still **not** granted and belongs in
the same scriptlets the moment there is something to spend it on.

**The two messages print one command**, because `setcap` replaces a binary's
capability set rather than adding to it: a user told to grant the raw socket
alone would silently give up port 68, and a user told to grant the port alone
would give up the echo. Both hints name
`cap_net_bind_service,cap_net_raw=+ep`, and so does the README.

**AppImage and Flatpak cannot**: an AppImage is
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

**The Linux packages enrol the machine in the house archive**, `../Packages`,
published at `spillebulle.github.io/packages`. This exists because the updater
told every `.deb` user to run `sudo apt install --only-upgrade muster` and that
command cannot ever have worked: the packages come from a release page, apt only
consults archives it has been given, and a machine with none answers "already
the newest version" in the voice of something that had checked. So the `.deb`
carries the archive's public key in `/usr/share/keyrings` and writes
`/etc/apt/sources.list.d/spillebulle.sources` from its `postinst`, the `.rpm`
does the same with `/etc/yum.repos.d/spillebulle.repo`, and from then on the
package manager keeps Muster current the way it keeps everything else current.
Three rules come with it:

- **The source file is written by the scriptlet, never shipped in the package.**
  A file under `/etc` that dpkg owns is a conffile, and dpkg removes a conffile
  on purge, so a source shared by four applications would be cut off the moment
  the first of them was uninstalled. Written by the scriptlet it belongs to
  nobody, every application creates it if it is missing, and `postrm` leaves it
  alone. `spillebulle.sources.disabled` is the opt-out and is honoured.
- **The path is stated in two languages and checked by `packaging/check.sh`.**
  The scriptlet writes it and `update::install::detect` looks for it; if they
  ever disagree nothing breaks visibly, and every user of the archive is simply
  told to download a file by hand for ever.
- **The updater says which of the two situations a machine is in.** With the
  archive it prints the upgrade command; without it, it names the exact package
  file to fetch. It never prints an upgrade command to a machine that has
  nowhere to upgrade from, and `install.rs` has a test that fails on any of the
  four commands that used to be printed.

The rules that were bought with broken releases:

- **A release is not finished when the tag is.** `release.yml`'s last step
  dispatches to `Spillebulle/packages`, which rebuilds the house apt and rpm
  archive from the newest release of every project it carries. Until that run
  is green, every Linux machine with the archive is still being offered the old
  version, and nothing in this repository will say so. Check it alongside the
  release page. It needs `ARCHIVE_DISPATCH_TOKEN` in this repository's secrets;
  the step is skipped when that is absent, so a release can still be cut
  without it, and the archive's weekly run is the backstop.
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
- **That one request has a budget, and it is small.** GitHub allows sixty
  unauthenticated requests an hour *per address*, shared with everything else on
  that network, and answers the sixty-first with **403** rather than 429 — which
  read as a bare status says "GitHub has blocked you" when it means "wait". 0.0.5
  checked on every launch and spent the budget in an afternoon. The automatic
  check is therefore throttled to one per six hours, persisted, and a check the
  user asks for is never held back. **The proper fix is a conditional request**:
  a stored `ETag` with `If-None-Match`, whose 304 replies GitHub does not count
  at all. That is the next thing to do here, and it needs the newest release
  cached beside the tag so a 304 can be answered without the body.
- **A message with a `\` line-continuation in it is a defect waiting to
  happen.** Lose the backslash and the literal keeps the source's indentation;
  it compiles, passes clippy, reads correctly in the editor, and is wrong only
  on screen. `crates/muster-app/tests/messages.rs` reads the crate's own source
  and fails on any string carrying a run of spaces mid-sentence.

## What to build next

Roughly in the order the value lands. Nothing here is committed to; the point is
that the next session does not have to rediscover the list.

**The privileged engine is the biggest single win, and everything in it is
already designed.** `portscan::Cookie` is written and tested with no transport
under it; ARP, DHCP from port 68 without fighting the system client, passive
fingerprinting and LLDP all wait on the same thing — raw packet access, which
is Npcap on Windows and `CAP_NET_RAW` on Linux — which the Linux packages now
grant, for the ICMP echo's raw fallback, so that half of the ask is already in
place and `build-packages.sh` argues what each capability buys. When the engine
lands, `CAP_NET_ADMIN` joins them and the README's first "not there yet" entry
goes.

Cheap and unprivileged, so worth doing before that:

- **Continuous monitoring is now the nearest big thing**, and `listen.rs` is
  most of it. The listen runs for the length of a scan and stops; a listen that
  kept running is what makes "a new device appeared on your network" possible.
  The measurement that argues for it: on one real network eight addresses spoke
  in 150 seconds and only four in the first 30, so the yield keeps climbing well
  past any window a scan can afford to wait for. Adding ports 67 and 68 to the
  watch list would give an address *and* a hardware address for every device
  that joins or renews a lease, which is the arrival event itself.

- **The UPnP description.** SSDP itself is built and its headers are read; the
  `LOCATION` they carry points at an XML document with the manufacturer, the
  model name and often a serial number, and fetching it is a TCP request per
  device that belongs with the banner grabbing below.
- **TLS certificate reading** on any open port. Subject and SAN are often the
  only place a device's real name is written. Reading a certificate is not
  authenticating, so it stays inside the conduct rules.
- **Banner grabbing** beyond the SSH greeting `service.rs` already reads, with
  the same limit: read what a service volunteers, send nothing that is not a
  protocol's own greeting. HTTP `Server` headers are the obvious next one, and
  they are a header to read rather than a badge to add.
- **UDP service probes** as a table (DNS, mDNS, SSDP, NetBIOS, SNMP, NTP), which
  is the only honest way to scan UDP at all.
- **IPv6 by NDP.** Addresses and routes are already read for both families;
  pinging `ff02::1` finds link-local neighbours in one packet, which is a whole
  address family for very little code.

Interface work the device list is starting to ask for:

- **Export**, as CSV and JSON, to a *file*. Copying a column of the marked
  devices to the clipboard is built, and it covers the "put this in a ticket"
  case one column at a time; a file with every column in it is the other half
  and is where a format worth versioning starts.
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
