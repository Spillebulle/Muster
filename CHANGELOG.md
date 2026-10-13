# Changelog

The notes for each version are what the GitHub release publishes, verbatim.
Newest first.

## 0.0.16

Added

- **Devices now say their own hardware address, and Muster listens.** A device
  found only because it was overheard has no ARP reply behind it, so its
  vendor column was blank - which is the column that tells a nameless row from
  a nameless row made by Espressif. Ten protocols write a hardware address
  into something they already send: a NetBIOS node status, an ESPHome `mac=`,
  Avahi's `_workstation` name, an AirPlay `deviceid`, a Chromecast's `bs`, a
  Sonos identifier, a Matter host name and a UPnP or WS-Discovery identifier
  built the one way that puts one there. Where the address is inferred rather
  than stated the IEEE registry is the test, because a hex string of the right
  shape is not a hardware address, and a device saying its own is a weaker
  claim than a stack answering for it - so the interface says which happened.
  HomeKit's identifier looks exactly like one and is deliberately refused: it
  is random by design.
- **A HomeKit accessory now says which kind it is.** Every one of them was a
  smart home icon; the accessory category is in the reply Muster was already
  reading, so the cameras, doorbells, televisions and speakers now look like
  what they are.
- **The reply to a ping carries a hint about the stack that sent it**, and the
  hint is free: the TTL is in the reply already. Rounded to the nearest of the
  three initial values, it tells a Windows stack from a Unix-like one, and only
  the Windows band names a kind, because 64 is every other kind on the list.
  It is ranked below everything a device actually said about itself.
- **SMB now answers more than whether it is there.** The negotiate reply
  carries the dialect, the server's clock and, on Windows, its uptime; a server
  that will go no higher than the Vista-era dialect is worth seeing. Muster can
  also ask whether SMB1 is still spoken, which is off unless you ask for it.
- **Networks that hand out a captive portal address now say so**, read from the
  DHCP offer itself rather than by making a request that gets intercepted.
- **A camera or printer that answers WS-Discovery now gives up its model**,
  which was in the reply and being dropped. The friendly name beside it is not
  read, because that is what somebody typed during the installation.
- **Muster can ask a device for its SNMP description**, which reaches the
  switches, access points, printers and power supplies that answer nothing
  else on the network and were the blank rows. It is off unless you ask for
  it, it sends one question carrying `public` - the community the standard
  names as the default - and it never sends a second.
- **Ping history now has arithmetic under it**: how many were sent, how many
  answered, the best, the mean and the worst, and the jitter. Probes this
  machine could not send are counted apart and left out of the loss, because a
  question never asked is not an answer never given.

Changed

- **The device list is quick again at two hundred rows.** Every frame was
  working out what kind each device was, twice per comparison while sorting,
  and copying the whole list to do it. It now works each one out once and
  draws only the rows on screen. Measured over a table of 250: 57 ms a frame
  before, 2.1 ms after.
- **The device list can be driven from the keyboard.** Ctrl+F to search, the
  arrows to move, Enter to open a device, Space to mark it, Ctrl+A to mark
  everything the search is showing, Escape to come back out. Each row now also
  says its address, its name and its kind in words to a screen reader, which
  the icon column could not do at all when its only explanation was a tooltip.
- **The device table's heading stays put** while the list scrolls under it.
- **The Arch package now keeps itself up to date.** Installing it adds the
  [Spillebulle archive](https://spillebulle.github.io/packages/) as a
  `[spillebulle]` repository at the end of `/etc/pacman.conf`, after your
  distribution's own, so on Arch, CachyOS, EndeavourOS and Manjaro
  `sudo pacman -Syu` brings the next Muster with everything else, as apt and
  dnf already did. When a new version is out, Muster says `pacman -Syu` on a
  machine with the archive and still names the file on one without.
  To leave it, delete the section and `/etc/pacman.d/spillebulle`, and create
  `/etc/pacman.d/spillebulle.disabled` so the next upgrade does not put it back.

Fixed

- **The `.deb` could not be installed beside another application from the same
  archive.** Both shipped the archive's key at the same path, and dpkg refuses
  a second package that owns a file the first already does, even an identical
  one. The key is now carried under Muster's own name and copied to
  `/etc/apt/keyrings` on install, and a source written by an earlier Muster is
  pointed at the new copy, so nothing has to be done by hand.

## 0.0.15

Changed

- **Nothing you can see, and that is the whole of it.** 0.0.14 fixed the mark on
  the About page and the path reader behind it. This release adds the test that
  would have caught the need for that fix, and nothing else: every binary here
  behaves exactly as 0.0.14's did.
- **The icon reader now has to prove it can read a number.** A number it scans
  past the end of parses as nothing and becomes a zero, and a zero is a legal
  coordinate in a legal box — so an icon drawn from it comes out quietly
  deformed and every check the icons had still passed. Every number in every
  icon is now required to parse before anything is drawn from it. The rule went
  into the house style guide as well, so the next application to copy this
  reader copies the guard with it.

## 0.0.14

Fixed

- **The link to the source on About carried a mark nobody would recognise as
  GitHub's.** It was Lucide's outlined `github`, drawn in the same stroke set
  as the gear and the radar, on the reasoning that one application should draw
  in one hand. A logo is not a symbol: what a symbol means comes from its
  shape, so it can be redrawn, while a mark means one company and only the
  known shape says so. About now shows GitHub's own silhouette, filled — the
  same one every other application in the family puts beside its source link.
- **A number written without a leading digit was read as nothing.** SVG ends a
  number at a second decimal point, so `-5.5.08` is two of them; the icon
  parser read straight on and got one token that parses as nothing, and a zero
  where a number belongs puts a curve's control point on the origin. No icon
  Muster shipped was affected, because Lucide writes its paths with the leading
  digits in place — but that is luck rather than correctness, and the mark
  above is written the other way throughout, which is half of why it looked the
  way it did.

## 0.0.13

Added

- **Ping history, beside the device rather than under it.** The device window
  has a History button; pressing it widens the window and fills what it grew by
  with the round trips, newest first, over a chart of the last minute. A probe
  that came back is a bar, a probe that went out and got nothing is red, and a
  probe this machine could not send at all is amber and never drawn as a lost
  packet. Every result is kept as it arrives, so a loop left running builds one.
- **Keep pinging is on the device window too**, where it was only in the
  table's Actions menu. It is one button that says Stop while a loop is going,
  and the loop it stops includes one started for a whole group.
- **The port list is a list.** It shows all sixty-four ports a scan tries with
  the service usually found on each, and you add to it or take from it a row at
  a time. It used to be one text field where empty meant the built-in list, so
  adding a single port meant typing out the other sixty-three; the built-in list
  is now written out the first time you touch it, and Reset puts it back.
- **A link to the source, on the About page**, with the repository's address
  written under it rather than hidden behind the words. Nothing is fetched:
  Muster hands the address to the desktop when you click it.
- **Listening and asking your own router for names now appear in Settings**,
  beside the other things a scan asks. They were only in the scan menu, and the
  two are meant to be two views of one set of switches.

Fixed

- **Keep pinging sent over a hundred probes a second.** There was no interval
  between passes at all — only the rate limiter — so a device that answered
  quickly was asked again immediately. It is now once every half second, and
  Settings, Scanning has the interval. A pass that takes longer than the
  interval simply goes again when it is done.
- **A group ping showed "asking…" on every device until the whole group had
  answered**, and then went on showing it for every pass after the first. Each
  device now shows its own result the moment that result arrives, and holds it —
  including "no reply" — until its next one. A row never goes back to blank.
- **The taskbar icon was three loose circles.** Below 40 px the mark dropped the
  strokes joining the hub to its satellites, on the reasoning that a two-pixel
  stroke is a smudge. What was left did not read as a network at all. The small
  sizes now keep their arms and draw them heavier rather than lighter.

## 0.0.12

Added

- **The table's columns resize.** Drag the line between two headings and that
  column follows; the edge lights up when you are on it, and double clicking one
  puts the column back to the width it shipped with. "Made by" takes up or gives
  back whatever the change costs, so there is never a strip of empty table down
  the right-hand side, and no column can be dragged shut or dragged wide enough
  to push the others off the window. The widths are remembered between runs.
- **What does not fit in a cell is cut with an ellipsis**, where it used to run
  on underneath the next column and make both unreadable. The whole value is
  still in the row's tooltip. The ports and the badges already counted what they
  could not show; this is the same rule for the columns that hold text.

Fixed

- **The chevron on the Copy and Actions buttons sat against the last letter of
  the word.** The button reserved a chevron-wide box after the label and drew
  the mark centred in it, so the only thing between the two was that box's own
  inset — under two pixels. Both now measure the mark rather than its box, and
  there is a proper gap.

## 0.0.11

Added

- **Muster finds the devices that answer nothing.** A scan used to be a sweep:
  ask every address, list what replies. That misses a whole class of device on
  purpose — a Windows machine on the public firewall profile, a television that
  drops every connection, a phone asleep behind a lease it took an hour ago.
  Those devices are not silent. They announce themselves to the network, and
  they ask it questions. Muster now listens to both, and anything that speaks
  goes on the list with the reason it got there.
- **WS-Discovery**, which is how Windows answers when it answers nothing else.
  It is also how every network printer of the last fifteen years and every
  ONVIF camera announce themselves, and the reply names what the device is:
  `pub:Computer`, `wprt:PrintDeviceType`, `dn:NetworkVideoTransmitter`. Three
  kinds of device that were hard to find any other way, from one datagram.
- **Muster listens, and sends nothing to do it.** For the length of a scan it
  sits on the four ports the discovery protocols use and writes down who
  speaks. **A question identifies its asker exactly as well as an answer
  does** — a phone looking for a Chromecast has just proved it is there — and
  this is the only thing here that finds a device without sending it a packet.
  It shares those ports rather than taking them, and it never replies to
  anything.
- **The link is asked by name as well as in general.** The mDNS question that
  lists a device's services is one many small responders simply do not answer,
  so Muster now also asks about thirty service types outright: the ESP-based
  smart plugs, the Avahi machines that publish `_workstation._tcp` with their
  hardware address in the name, HomeKit accessories, printers, scanners and
  the rest. SSDP gained three searches beside `ssdp:all` for the responders —
  Hue bridges among them — that answer only their own device type.
- **NetBIOS is asked of the whole network**, not one machine at a time. One
  broadcast, and every Windows and Samba host on the link answers with its
  name, its workgroup and its hardware address.
- **Muster asks your own router what it calls things.** One reverse lookup per
  address, which names the devices that took a lease and then went to sleep.
  It is sent only to a resolver on your own network, never to one beyond it,
  and it gives up after a dozen questions if the router keeps no such records.
- **Your machine already knew about some of this.** The neighbour table is now
  read into the results, so a device the operating system has spoken to
  recently is on the list even when it answers nothing today. It stays quiet
  about the devices that answered for themselves, where it would only repeat
  what ARP already said.
- **Four more ports are knocked on** — AirPlay, iPhone `lockdownd`, the
  Chromecast control channel and JetDirect — and only for an address that
  answered none of the first four. They are chosen for what a device *listens*
  on rather than what it refuses, because that is the only question a device
  that drops everything will answer. On the network this was built against,
  7000 was the only open port on either television.

Fixed

- **On Windows, a refused connection was being reported as silence.** Windows
  does not hand a TCP reset straight to the program: it retransmits first, and
  the refusal surfaces about two seconds later. Muster waited 400 ms, so every
  refusal became "nothing came back" — on a network of eighteen devices,
  seventeen of which refuse rather than drop, the same knock proved eleven
  hosts before and eighteen after. The timeout is now per platform.
- **A sleeping device's services were being credited to the machine covering
  for it.** An Apple TV or a HomePod answers mDNS on behalf of devices that
  have gone to sleep, and Muster read those answers as though the Apple TV had
  made all the claims itself. It now reads which device a reply is *about*,
  which both fixes the row and finds the sleeping machine.
- Identification learned everything the link had said about a device and then
  kept three fields of it. A device found only by the link now keeps its
  product, its model, its workgroup and its device types too.

Changed

- **A reverse lookup is never sent to a resolver off your own network.** It
  used to go to whichever resolver the machine had, which on a machine
  pointed at a public one meant handing a stranger the addresses of devices on
  your network. Where the resolver is not on your link the question is not
  asked, and the scan says so.
- The result says how many of the devices were heard rather than probed,
  because "twenty-one devices" from a sweep of 254 addresses is a different
  claim when three of them never answered anything sent to them.
- Every new question has a switch in the scan menu, and the two that send
  nothing to the devices themselves — listening, and asking your own router —
  are on.

## 0.0.10

Added

- **A table of devices you can act on.** Every row has a mark box and the
  heading has one that marks everything the filter is showing, so "the three
  printers" is a search and one click. **Copy** puts one column of the marked
  devices on the clipboard, one value per line — the addresses for a firewall
  rule, the hardware addresses for a set of DHCP reservations, or the whole row
  tab separated for a spreadsheet — and a pill at the foot of the window says
  how many of what it copied. **Actions** pings them, pings them until you stop
  it, or scans their ports one device at a time.
- **Two new columns.** Ping is the last re-check's round trip, and it stays
  blank until you ask for one rather than dressing up the sweep's own
  measurement as a fresh one. Ports is every port known open on the device: what
  the sweep's knock found, and whatever a port scan has added since, which now
  survives closing the panel it was run from.
- **Muster asks what a device serves over a connection, not only over a
  datagram.** Three new badges, each earned by an answer in the protocol
  itself: `SMB` from the negotiate an SMB client sends first, `NFS` from the
  null call the protocol defines for exactly this question, and `SSH` from the
  greeting a server volunteers to anything that connects — that last one sends
  nothing at all. Nothing is opened, listed or authenticated. All three are off
  until you turn them on, because a connection is a thing the far end writes
  down where a datagram to port 53 is not.
- **The scan control carries what a scan asks.** The arrow at the right of the
  Scan button opens it, and it stays open while you set it rather than closing
  on the first switch you touch: it closes when you click outside it, press
  escape, or press Scan at its foot.
- The text mode learned `--smb`, `--nfs` and `--ssh`, so it asks the same
  questions the window does.

Changed

- **This network is one card per network.** Each card answers the same
  questions — the address and its prefix, the gateway out of that link, the
  resolvers, the DHCP server that gave the lease, the hardware address — rather
  than one long column in the order the survey happens to be in. On a laptop
  with a VPN up, or one on wifi and Ethernet at once, which gateway belongs to
  which link is the whole question, and the old shape could not answer it.
- The scan menu has left the top bar, which is now the mark and the name and
  nothing else. Everything it held is behind the Scan button's arrow, beside
  the range it acts on.
- Table headings are set one rank larger, so a heading reads as the column's
  label rather than as another row of it.
- The icons are Lucide's throughout, drawn from vendored path data rather than
  by hand.

Fixed

- **A packaged Muster on Debian, Ubuntu and Pop!_OS reported every device as
  silent.** Those distributions leave `net.ipv4.ping_group_range` shut, so no
  echo was sent at all; Muster now falls back to a raw ICMP socket and the
  packages grant the one capability that buys, alongside the port 68 the DHCP
  check needs. Both hints name the same `setcap` command, because `setcap`
  replaces a capability set rather than adding to it.
- **A device with a long mDNS service list was identified on Linux and not on
  Windows.** An oversized datagram is truncated by one kernel and refused by
  the other, so the receive buffer is now as large as UDP can carry.
- The DHCP check's failure message named the wrong cure when the machine's own
  DHCP client was holding port 68, which is a different fault from not being
  allowed to bind it.
- A re-check's "could not send ARP requests" caveat printed with a run of
  spaces through the middle of it. The test that catches that class of defect
  reads the engine as well as the interface now, which is where most of these
  sentences are actually written.

## 0.0.9

Added

- **Muster asks the whole link, and many more devices answer.** A great many
  televisions, set-top boxes and cameras ignore a question addressed to them
  alone and answer the same question broadcast to the network. Muster now asks
  both ways, over SSDP and mDNS, and attributes each reply to the device it came
  from. On the network this was built against that is the difference between one
  device answering and every television, set-top box and camera in the house.
- **Devices are named by the model they give for themselves.** An SSDP reply
  carries a product string and an mDNS record often carries a model, and a
  device that advertises no service at all can still say what it is. A model
  ranks below a service, because a service is a protocol a device has to
  implement and a model is free text: Samba asks macOS to draw it a Mac, so
  every storage box on a network claims to be one.
- **What a device serves the network, beside what it is.** A router is a router
  and also the DHCP server and also the resolver, and one label cannot say all
  three, so the table carries `DNS` and `DHCP` badges next to the kind. A badge
  is only ever a service that answered: never an open port, never a guess from a
  vendor. The device window adds the software a name server named itself as, and
  whether it resolves for anyone or serves its own zones only.
- **The DHCP check can run as part of a scan**, under Scan in the top bar,
  rather than only from This network. It collects every offer rather than the
  first, because two servers answering is the fault worth finding.
- **The gateway and the machine you are sitting at are known without being
  asked.** A machine's own responders do not answer its own packets, so your own
  computer used to be the one permanently blank row in the middle of the list.
- **A Windows machine with its firewall up is no longer a blank row.** It
  answers no mDNS, no NetBIOS and no SSDP, and it does answer LLMNR, which only
  a general purpose computer speaks.
- **Payment terminals are a kind of their own**, with an icon of their own, for
  the makers whose hardware addresses name them.
- **A laptop that says nothing is identified by the network card inside it.** An
  Intel address is a network card, and a network card of that kind is in a
  computer.
- **Every column sorts, including the column of pictures.** Sorting by kind is
  how forty rows become "the three printers", and addresses sort as numbers, so
  `.9` comes before `.10`.
- **The Linux packages put the machine on the Spillebulle archive as they
  install**, so `apt upgrade`, `dnf upgrade` or your usual system update carries
  Muster along with everything else. Nothing to configure.
- Settings and About now sit at the foot of the sidebar rather than in two
  different corners of the window, and every navigation row carries an icon.

Changed

- The mark stands a sixth over the wordmark's caps in the banner and the
  installer, which is the measure the rest of the family uses.

Fixed

- **Muster had no icon in the taskbar on Linux.** On Wayland a window is matched
  to its icon by an application id, and Muster set none, so the launcher showed
  the mark and the taskbar showed a blank square.
- **The Ping button said "nothing came back this time" about echoes it never
  sent.** Where the kernel does not allow ping sockets, Muster sends no echo at
  all, and it was blaming the device for the silence. It now says which of the
  two happened, and names the setting that would let it ask.
- **The DHCP check said only "Permission denied".** It now names the one
  capability it needs and the command that grants it, and the `.deb`, the `.rpm`
  and the Arch package grant that capability on install, so a packaged Muster
  can simply ask.
- **The updater told `.deb` users to run a command that could not work.**
  `apt install --only-upgrade muster` needs an archive to upgrade from, and
  there was none, so apt answered "already the newest version" in the voice of
  something that had checked. With the archive it prints the upgrade command;
  without it, it names the exact file to download.

## 0.0.8

Changed

- **The interface has two weights now, and had one before.** Headings and the
  primary button are heavier than the text around them; everything else is
  lighter than it was. The font Muster bundles is a variable one whose default
  weight is semibold, and the drawing library cannot vary it, so every word in
  the application was coming out bold.
- **Buttons follow one table.** The thing to do on a screen is filled in the
  accent, everything else is a plain fill, and a button you cannot press is
  dimmed rather than left looking pressable.
- **The light theme is drawn from the light theme.** Scroll bars, tooltips,
  text selection and the dimming behind a dialog were all still taken from the
  dark one.
- The scan control sits next to the range it scans, in a strip of its own,
  rather than in the title bar.
- Text fields show where the keyboard is, which they did not before.
- Empty screens offer the thing to do instead of naming a button elsewhere.
- Sentences are set as sentences: several were monospaced as though they were
  figures.

## 0.0.7

Added

- **A settings page.** Theme, interface scale, how hard a scan knocks and which
  ports it tries. Settings apply as you change them, so there is nothing to
  confirm and nothing to lose, and Restore all is the way back.
- **Themes from files.** Muster reads the same `.umbertheme` files as the rest
  of the family, so a theme made in a sibling application opens here. Dark,
  Light, or follow the desktop.
- **Devices appear as they answer**, instead of after the whole range has been
  swept. A large range now fills as it goes.
- **A filter and a range field** above the table. The filter matches everything
  a row shows, so "epson" and "printer" find things, not just addresses. Leave
  the range empty and Muster sweeps the network this machine is on.
- **A window for each device**, in place of the panel that used to take a
  quarter of the table. It carries what Muster thinks the device is and why, a
  button to ask it again, its ports, and a copy control on every field.
- **Far more devices get a kind and an icon.** Printers, phones, televisions,
  speakers, cameras, network gear, storage and smart home devices are all
  recognised by many more makers than before. Phones especially: Muster could
  not identify a single handset by its hardware before this release.

Fixed

- **A scan of a network that filters ARP between clients reported it as empty
  and finished.** Guest Wi-Fi and any access point with client isolation do
  exactly that. Muster now says so rather than handing back nothing as though
  it were an answer.
- **On Windows, several kinds of ARP failure were reported as "no device
  here"** for every address, so a whole network could come back empty and
  apparently complete. Only a genuine silence counts as silence now.
- **Scanning a range off this link gave different answers on Windows and
  Linux**, because Windows resolved the next hop's hardware address and read it
  as the target's.
- **Stop now takes effect at the next probe** rather than the next address. It
  could previously send around a thousand more packets after being asked to
  stop.
- **A sweep on Linux read the system's ARP table tens of thousands of times a
  second.** It reads it once every few milliseconds now, which is a large
  saving on a big range.
- **Ctrl-C stops a scan on Linux** and prints what was found, as it already did
  on Windows.
- **A device with a long list of services was identified on Linux and not on
  Windows.**
- The port scan's notes are notes now, rather than amber warnings that made a
  successful scan look like a failure.
- The window no longer sits at "Sweeping" for ever if a scan fails.
- The mark in the top left is the real one.

## 0.0.6

Fixed

- **Muster spent GitHub's rate limit and then told you it had been blocked.**
  GitHub allows sixty checks an hour from one address, and Muster asked on every
  launch, which an afternoon of ordinary use gets through. The automatic check
  now runs at most once every six hours. A check you ask for yourself is never
  held back: you are looking at the answer, so you can see a failure and judge
  it.
- **Several messages were shown with runs of spaces in the middle of them**, so
  a sentence arrived looking like "60 checks an        hour from one address".
  A test now reads Muster's own source and fails the build on any message with
  that shape.

## 0.0.5

Added

- **Muster now tells you what each device is**, not only that it is there. A
  router, a printer, a television, a phone, a NAS: each gets its own icon and
  colour in the device list. The guess comes from what the device advertises
  about itself, the ports it answers on and who made its network hardware, in
  that order, and hovering a row says which of those it was. A device that said
  nothing is shown as unknown rather than guessed at.
- **Ports for one device, from the window.** Select a device and a panel opens
  beside the table with everything known about it and a button to scan its
  ports. Open ports are listed with the service usually found on them; closed
  and filtered are counted separately, because a refusal is a machine answering
  and silence is not.
- **A check for a second DHCP server**, in This network. Two servers handing out
  addresses is one of the few faults that is nearly always real and one of the
  hardest to find by hand: it breaks addressing for some devices and not others.
  Muster asks, collects every offer rather than the first, and names each server
  that answered. It never accepts an offer.

Changed

- The mark sits properly in the middle of its square. The glyph is taller above
  the centre than below it, so drawing it about the true centre left it looking
  high.

Known limits

- The DHCP check needs port 68, which on Linux is privileged and on Windows is
  usually held by the system's own DHCP client. Where it cannot have it, it says
  so rather than reporting that no second server was found.

## 0.0.4

Fixed

- **Muster had no icon on Windows.** Explorer, the Start menu shortcut and Add
  or remove programs all showed the default one. The mark is now compiled into
  the executable, which is where Windows looks before a process has started;
  setting the window's icon at run time, which is what earlier releases did,
  never reaches any of those.
- **Opening Muster from the Start menu put a console window behind it.** The
  release build now declares the windows subsystem, and takes the terminal's
  console when it was started from one, so `muster scan` still prints.
- **The update check reported "http status: 403" and left you none the wiser.**
  GitHub answers the sixty-first check in an hour from one address with 403,
  which is a quota that refills rather than a refusal. Muster now says so, and
  says how many minutes are left.

Changed

- The installer window carries the mark. It is the whole of what a first
  install shows, since the package is handed to Windows Installer quietly.

## 0.0.3

Changed

- **Muster has a mark.** The icon, the banner and the installer now carry a hub
  with three devices joined to it, knocked out of the accent square. It is
  drawn from the palette rather than stored as a picture, so it cannot drift
  from the colour the interface is painted in.
- At 16 px the mark is the plain square, without the glyph. There is not enough
  room there to draw four separate shapes with gaps between them, and a glyph
  drawn anyway is a dark blob that says less than the square alone.

## 0.0.2

Fixed

- **The Windows installer would not install on a machine with Umber on it**, and
  reported "A newer version of Muster is already installed" instead. Muster's
  package carried Umber's identity, so Windows believed the two were one
  product. Muster now has its own, and a test fails the build if it ever stops
  having one. If you already have Muster 0.0.1, this release installs over it
  normally.

## 0.0.1

First release. Muster tells you what is on the network you are on, and it runs
as an ordinary user on both platforms.

Added

- **This network**, which needs no packets and no privileges at all. It reads
  the interfaces, addresses, prefixes, routing table, gateway, configured DNS
  servers and neighbour table straight from the operating system, so it answers
  "what is my gateway, what is my DNS" the moment the window opens.
- **A sweep of the local network**, which finds the devices on it. The default
  target is the prefix this machine is on and nothing beyond it. A device that
  refuses a connection counts as found, which is how the sweep sees the many
  machines that ignore ping but answer with a refusal.
- **Names and vendors for what it finds.** Names come from reverse DNS, mDNS and
  NetBIOS, and where two sources disagree both are kept. Hardware vendors come
  from the IEEE registry compiled into the binary, so there is no lookup service
  and nothing to be online for.
- **A randomised hardware address is reported as randomised**, rather than as an
  unknown vendor. Every modern phone sets one per network.
- **A port scan for one host**, over the ports worth knowing about or any range
  you give it. An unanswered probe is reported as filtered, never as closed.
- **A text mode in the same binary**: `muster survey`, `muster scan` and
  `muster ports` run the same engine and print aligned tables. It needs no
  display server, so it works over SSH.
- **Windows and Linux packages**: an installer and an `.msi` for Windows, and
  `.deb`, `.rpm`, an Arch package, an AppImage, a Flatpak bundle and plain
  archives for Linux.
- **An update check**, off until you have been asked, that never writes over an
  installation a package manager owns.

Known limits

- The port scan opens a connection per port. That is correct and slow; the
  stateless SYN scan needs raw packet access, which is not built yet. The
  result says which one produced it.
- The sweep covers IPv4. An IPv6 prefix is not swept address by address, and
  the scan says so rather than reporting an empty result.
- Scans are not saved, and there is no continuous monitoring.
