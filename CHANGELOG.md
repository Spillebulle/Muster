# Changelog

The notes for each version are what the GitHub release publishes, verbatim.
Newest first.

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
