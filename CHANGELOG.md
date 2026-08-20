# Changelog

The notes for each version are what the GitHub release publishes, verbatim.
Newest first.

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
