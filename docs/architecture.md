# How a scan is put together

19 August 2026. What the engine is shaped like, and which of its shapes are
settled. `CLAUDE.md` carries the reasoning that led here; this page is the map.

## Three crates, and one boundary that matters

| Crate | Holds |
|---|---|
| `muster-net` | Interfaces, discovery, port scan, probes, identification, the model of a scan |
| `muster-app` | The window, the panels, the update check and the installer |
| `muster-desktop` | The binary, and what a subcommand means |

`muster-net` naming no GUI type is what keeps the engine testable. **The same
crate naming no operating-system socket is what makes it testable at all.**
Packet send and receive, the routing table, the neighbour table and the resolver
configuration all sit behind traits: `sysinfo::SystemProbe` for what the machine
knows, `discover::Transport` for the sweep, `identify::Ask` for the questions
asked over UDP. The real implementations live in one platform module, and the
tests drive recorded ones.

That is why `cargo test -p muster-net` runs in under a tenth of a second on a
machine with no network worth scanning, and why **no test in this repository
puts a packet on a wire**. A scanner whose tests need a LAN has no tests: CI
runners have nothing to scan, and no two development machines see the same
network.

## Four phases, four different shapes

A scan is four things, and running them all through one mechanism is the mistake
this layout exists to avoid.

1. **Survey.** Interfaces, addresses, prefixes, routes, resolvers, the DHCP
   server and the neighbour table, read from the operating system. No packets,
   no privileges, instant. It answers "what is my gateway" on its own and is not
   a preamble to anything.
2. **Sweep.** Find the hosts, bounded by the prefix. ICMP echo and a short TCP
   knock today; ARP when there is a raw transport to send one with.
3. **Port scan.** Where the performance is, and where it is not yet.
4. **Identify.** Only for hosts that answered. Hundreds of short exchanges
   rather than millions of packets, which is a different shape from phase three
   and does not belong in its loop.

## What is settled

**The stateless design is written before the transport that needs it.** The port
scan keeps no per-probe record: the probe's identity is a keyed hash of source,
destination, port and a per-run secret, written into the TCP initial sequence
number, so a reply identifies itself. `portscan::Cookie` is complete and tested
today even though nothing sends a raw SYN yet. That order is deliberate.
Reply validation is the part that has to be right, and retrofitting it under a
scanner that already works another way is how it ends up never being written.

**Absence of a reply is never "closed".** A SYN-ACK is open, a RST is closed,
and silence is filtered. Three states, and the third is not a synonym for the
second. Reporting an unanswered probe as shut invents a fact about somebody's
network, and it is the most common lie a scanner tells.

**A refusal proves a host.** A TCP RST is a machine declining a connection,
which means a machine was there to decline it. Counting only open ports as
evidence loses every device that refuses rather than drops, which on a home
network is most of them.

**Nothing degrades silently.** A transport says what it can do through
`discover::Capabilities`, and whatever the sweep therefore skipped is named in
`Sweep::not_done` and shown. "No devices found" from an engine that could not
send an ARP request is the worst result this application can produce, because it
looks like an answer rather than like a gap.

**Identity is a merge with a priority, not a race.** Self-reported names first:
mDNS and NetBIOS are the device speaking about itself, where reverse DNS is what
a router was told once, possibly by a previous occupant of the address. Where
sources disagree both are kept, because a device answering as two things is
information.

**Every probe is rate limited from a clock the caller controls.** A scanner that
sends as fast as it can is indistinguishable from an attack, is dropped by any
switch with storm control, and produces false negatives that look like an empty
network. The limiter is a token bucket, and the tests drive it from a clock they
own rather than from the wall.

## What was rejected

**A socket, a task or a table entry per port.** It is what makes conventional
scanners slow, and it is not available as a fallback "for now": the
reply-validation design is the part that has to be right first. The `connect()`
path that ships today is a *different method* that says so in its result, not a
cheaper version of the same one.

**Modelling an address as `Ipv4Addr`.** Dual stack is the normal case and the
LAN primitive is NDP rather than ARP. The types are `IpAddr` from the first
commit even though the sweep walks IPv4 today, because the alternative is a
rewrite rather than an addition.

**An animated progress bar over an unknown.** Progress over a known address
count and a known port count is knowable, so it is reported; everywhere else the
bar draws an empty track. `Phase::fraction` and `Stage::progress` both return an
`Option` so there is somewhere to say "no honest figure".

## What is not decided

- **Whether identification justifies an async runtime.** The stateless scan
  needs two threads and no runtime; phase four's hundreds of short connections
  are the argument for one. If it is added it stays inside `muster-net` and
  never appears in `muster-app`'s API.
- **How a scan is persisted**, and whether a saved scan is a document with a
  format worth versioning. It probably is, and comparing two scans of the same
  network a week apart is the feature that should settle it.
- **Whether continuous monitoring** — a scan that stays running and reports
  arrivals and departures — is version one or version two.
