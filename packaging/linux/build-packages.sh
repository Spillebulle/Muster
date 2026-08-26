#!/bin/bash
# Build the Linux packages from an already-compiled binary.
#
#   packaging/linux/build-packages.sh <version> <binary> <arch> [outdir]
#
#   version   0.0.1
#   binary    path to the compiled `muster`
#   arch      amd64 | arm64   (Debian spelling; the others are derived)
#
# Emits a .deb, an .rpm and an AppImage into <outdir> (default: dist/).
#
# Written with `dpkg-deb` and `rpmbuild` directly rather than with `cargo-deb`
# and `cargo-generate-rpm`. Two reasons, and the second is the one that decides
# it: the package trees are laid out here where they can be read, rather than
# inferred from manifest keys with their own relative-path rules; and the
# libraries that matter to this application are **dlopened**, not linked, so no
# amount of automatic dependency detection will find them. See DEPENDS below.
#
# Runnable on any Debian-ish box with the tools installed, not only in CI, which
# is the point — a release process only a robot can run cannot be rehearsed.

set -euo pipefail

if [ $# -lt 3 ]; then
    sed -n '2,12p' "$0" >&2
    exit 2
fi

version=$1
binary=$2
arch=$3
outdir=${4:-dist}

root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)

case "$arch" in
    amd64) rpm_arch=x86_64;  appimage_arch=x86_64  ;;
    arm64) rpm_arch=aarch64; appimage_arch=aarch64 ;;
    *) echo "unknown arch '$arch' (want amd64 or arm64)" >&2; exit 2 ;;
esac

if [ ! -x "$binary" ]; then
    echo "no executable at '$binary'" >&2
    exit 1
fi

# Every one of these is opened at runtime by winit or wgpu rather than being
# recorded in the ELF, so `dpkg-shlibdeps` and rpm's own scanner cannot see any
# of them. A package that omitted them would install cleanly and then fail to
# open a window, which is the worst shape a packaging bug can take.
#
# **Nothing here is about the scan.** Muster reaches the network through
# ordinary sockets in libc, which is already `libc6`; every library below is
# the window. That is worth saying because the list reads like a graphics
# application's and is one: `muster scan` in a terminal needs none of it, and a
# headless machine can run the text mode with this package installed and no
# display server present at all.
#
# The TLS roots the update check uses are compiled in (`webpki-roots`, see
# `muster-app`'s manifest), so there is no `ca-certificates` dependency and no
# host certificate store to find. That is also what lets the same binary work
# inside the Flatpak sandbox and in an extracted AppImage.
DEB_DEPENDS="libc6, libgcc-s1, libx11-6, libxcursor1, libxrandr2, libxi6, libxkbcommon0, libwayland-client0, libvulkan1"

# RPM requirements are stated as **sonames**, not as package names.
#
# Package names differ between rpm distributions for the same library — Fedora
# calls it `libX11` and `vulkan-loader`, openSUSE calls the same things
# `libX11-6` and `libvulkan1` — so a package naming one will refuse to install
# on the other. Every rpm distribution, though, records the sonames a package
# provides, so requiring `libvulkan.so.1` resolves correctly on all of them
# without this script knowing which one it is being installed on.
#
# The `()(64bit)` marker is rpm's own way of distinguishing a 64-bit provider
# from a 32-bit one, and both architectures Muster builds for are 64-bit.
RPM_SONAMES="libX11.so.6 libXcursor.so.1 libXrandr.so.2 libXi.so.6 libxkbcommon.so.0 libwayland-client.so.0 libvulkan.so.1"

# The application ID. The desktop entry, the icons and the AppStream file are
# all named for it, and the AppStream `launchable` points at that desktop entry.
# `appstreamcli compose` follows that reference to find the icon, so a name that
# does not line up costs the whole component: `gui-app-without-icon`, and the
# build fails. It reads as pedantry right up until it does that.
APP_ID=io.github.spillebulle.muster

# --- the house archive -------------------------------------------------------
#
# The `.deb` and the `.rpm` carry the archive's public key and add its source
# on install, so somebody who downloads one package from the release page ends
# up on a machine that upgrades Muster by itself from then on. Without this the
# package manager owns the installation, refuses to let Muster replace it, and
# has nowhere to get a newer one: `apt install --only-upgrade muster` answers
# "already the newest version" for ever and sounds authoritative doing it.
# That was the whole bug this exists to close.
#
# The key is not generated here and is not in git as a secret: it is the public
# half, taken from the archive's own Pages site, and checked in beside this
# script. When it is absent the packages are built exactly as they were before
# the archive existed, loudly, because a silent difference between two builds
# of the same package is the worst outcome available here.
#
# `../Packages` is the archive. `Design-Principles/STYLE-GUIDE.md` §18 is why.
ARCHIVE_KEYRING=spillebulle-archive
ARCHIVE_BASE=https://spillebulle.github.io/packages
archive_key=$root/packaging/linux/$ARCHIVE_KEYRING.asc

if [ -f "$archive_key" ]; then
    command -v gpg >/dev/null 2>&1 || {
        echo "gpg is needed to dearmour $archive_key" >&2
        exit 1
    }
    gpg --dearmor < "$archive_key" > "$work/$ARCHIVE_KEYRING.gpg"
    echo "==> packages will enrol the machine in $ARCHIVE_BASE"
else
    archive_key=
    echo "!! $ARCHIVE_KEYRING.asc is not checked in, so these packages will not" >&2
    echo "!! enrol the machine in the archive and will never be upgraded by a" >&2
    echo "!! package manager. See ../Packages/README.md." >&2
fi

# --- the shared install tree -------------------------------------------------
#
# One layout, used by all three formats. /usr for the packages; the AppImage
# gets the same tree with its own root, which is what AppImage expects.
stage_tree() {
    local prefix=$1
    install -Dm755 "$binary" "$prefix/bin/muster"
    install -Dm644 "$root/packaging/$APP_ID.desktop" \
        "$prefix/share/applications/$APP_ID.desktop"
    install -Dm644 "$root/packaging/$APP_ID.metainfo.xml" \
        "$prefix/share/metainfo/$APP_ID.metainfo.xml"
    # No MIME types and no thumbnailer: Muster opens no documents. Both come
    # back here when a saved scan becomes a file with a format.
    for size in 16 32 48 64 128 256; do
        install -Dm644 "$root/assets/icons/muster-$size.png" \
            "$prefix/share/icons/hicolor/${size}x${size}/apps/$APP_ID.png"
    done
    install -Dm644 "$root/LICENSE" "$prefix/share/doc/muster/LICENSE"
    install -Dm644 "$root/README.md" "$prefix/share/doc/muster/README.md"
    install -Dm644 "$root/CHANGELOG.md" "$prefix/share/doc/muster/CHANGELOG.md"
}

# --- .deb --------------------------------------------------------------------

echo "==> building muster_${version}_${arch}.deb"
deb="$work/deb"
stage_tree "$deb/usr"
mkdir -p "$deb/DEBIAN"
# `/usr/share/keyrings` rather than `/etc/apt/keyrings`: the first is where a
# package puts a keyring it owns and dpkg can track, the second is where a
# human puts one by hand. `Signed-By` in the source below names this file, so
# the key is never fetched over the network and the archive is trusted for
# these packages and for nothing else on the system.
if [ -n "$archive_key" ]; then
    install -Dm644 "$work/$ARCHIVE_KEYRING.gpg" \
        "$deb/usr/share/keyrings/$ARCHIVE_KEYRING.gpg"
fi
# Installed-Size is in kibibytes and Debian's own tools warn without it.
size=$(du -ks "$deb/usr" | cut -f1)
cat > "$deb/DEBIAN/control" <<EOF
Package: muster
Version: $version
Section: net
Priority: optional
Architecture: $arch
Depends: $DEB_DEPENDS
Installed-Size: $size
Maintainer: Spillebulle <spillebulle@gmail.com>
Homepage: https://github.com/Spillebulle/muster
Description: Network scanner for the network this machine is on
 Muster answers three questions about the network you are on: what is here,
 what is it, and what is it offering. It reads the interfaces, routes,
 resolvers and neighbour table from the kernel without sending a packet,
 sweeps the local prefix, and asks the devices that answer what they are.
 .
 Names come from reverse DNS, mDNS and NetBIOS; hardware vendors from the IEEE
 registry compiled into the binary. It runs as an ordinary user, and nothing
 about your network leaves the machine.
EOF
# `update-desktop-database` builds the cache a desktop reads to list an
# application at all. Cheap, idempotent, and guarded with `command -v`: a
# minimal system may not have it, and a package must not fail to install over a
# menu entry.
#
# **Two capabilities, and each is granted because a code path spends it.** The
# rule has not changed — a capability handed to a binary that cannot use it is a
# capability handed out for nothing — but `CAP_NET_RAW` now has a use:
#
# * `CAP_NET_BIND_SERVICE` is the right to bind a port below 1024, and the DHCP
#   check needs it: a client has to listen on port 68 to hear an offer at all,
#   so without this that feature fails with "Permission denied" on every Linux
#   where Muster is not run as root.
# * `CAP_NET_RAW` buys the ICMP echo where the kernel will not sell it. A ping
#   socket is gated on `net.ipv4.ping_group_range`, Debian, Ubuntu and Pop!_OS
#   leave that shut for everybody, and `platform::linux::Echo` falls back to a
#   raw socket — which is a code path, and a real one: without it a packaged
#   Muster on those distributions reports "no echo was sent" for every device on
#   the network and asks its user to run it from a terminal with sudo.
#
# It is still not the *privileged engine* — the SYN scan, the ARP sweep, the
# passive fingerprinting — and when that lands it will want promiscuous mode and
# `CAP_NET_ADMIN` beside this. It is the same capability `ping` itself carries on
# these distributions, for the same reason.
#
# `|| true` throughout: `setcap` is in `libcap2-bin`, which a minimal system may
# not have, and a package must not fail to install over an optional feature.
# The binary simply keeps saying what it cannot do, which is what it did before.
cat > "$deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
# Port 68 for the DHCP check, and the raw socket the ICMP echo falls back to.
# See the note in packaging/linux/build-packages.sh and `platform::dhcp_hint`
# and `platform::ICMP_HINT`, which name these same capabilities on screen.
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_bind_service,cap_net_raw=+ep /usr/bin/muster || true
fi
EOF
# The source file is **written by this script rather than shipped in the
# package**, and that is the whole design of it. A file under `/etc` that dpkg
# owns is a conffile, and dpkg removes a conffile when the package that owns it
# is purged, so a shared source shipped by four applications would be cut off
# the moment the first of them was removed. Written here it belongs to nobody,
# every application's package creates it if it is missing, and removing one
# leaves the other three upgrading normally.
#
# Only ever created, never overwritten: somebody who has edited it, pinned
# against it or pointed it somewhere else keeps their version. Deleting it and
# leaving `.disabled` beside it is the documented way off the archive, and is
# honoured here so that the next upgrade does not quietly put it back.
if [ -n "$archive_key" ]; then
    cat >> "$deb/DEBIAN/postinst" <<EOF

sources=/etc/apt/sources.list.d/spillebulle.sources
if [ ! -e "\$sources" ] && [ ! -e "\$sources.disabled" ]; then
    cat > "\$sources" <<'SOURCES'
Types: deb
URIs: $ARCHIVE_BASE/deb/
Suites: ./
Signed-By: /usr/share/keyrings/$ARCHIVE_KEYRING.gpg
SOURCES
fi
EOF
fi
# The same on the way out, so a removed Muster stops being listed rather than
# leaving a dead entry in every menu.
#
# **The source file is deliberately not removed here.** It is shared with every
# other application from the same archive, and taking it away because one of
# them was uninstalled would stop the others being updated, silently, months
# later. `README.md` says how to leave the archive on purpose.
cat > "$deb/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
EOF
chmod 755 "$deb/DEBIAN/postinst" "$deb/DEBIAN/postrm"
dpkg-deb --build --root-owner-group "$deb" "$outdir/muster_${version}_${arch}.deb" >/dev/null

# --- .rpm --------------------------------------------------------------------

echo "==> building muster-${version}-1.${rpm_arch}.rpm"
rpmroot="$work/rpm"
mkdir -p "$rpmroot"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
buildroot="$work/rpmtree"
stage_tree "$buildroot/usr"
# The armoured key, because `rpm --import` reads an armoured block where apt
# wants the dearmoured keyring. `/etc/pki/rpm-gpg` is where Fedora and RHEL
# keep them, and where a `gpgkey=file://` line in a `.repo` is expected to
# point; openSUSE has no directory of its own for this and reads whatever the
# repository file names.
rpm_key=/etc/pki/rpm-gpg/RPM-GPG-KEY-spillebulle
if [ -n "$archive_key" ]; then
    install -Dm644 "$archive_key" "$buildroot$rpm_key"
fi

{
    echo "Name:           muster"
    echo "Version:        $version"
    echo "Release:        1"
    echo "Summary:        Network scanner for the network this machine is on"
    echo "License:        GPL-3.0-or-later"
    echo "URL:            https://github.com/Spillebulle/muster"
    echo "BuildArch:      $rpm_arch"
    for so in $RPM_SONAMES; do echo "Requires:       ${so}()(64bit)"; done
    # The binary is already built and stripped; rpm's debuginfo pass would try
    # to rebuild it from sources that are not here.
    echo "%global debug_package %{nil}"
    echo
    echo "%description"
    echo "Muster answers three questions about the network you are on: what is"
    echo "here, what is it, and what is it offering. It runs as an ordinary user,"
    echo "and nothing about your network leaves the machine."
    echo
    echo "%install"
    echo "cp -a $buildroot/usr %{buildroot}/"
    [ -n "$archive_key" ] && echo "cp -a $buildroot/etc %{buildroot}/"
    echo
    # The same cache the `.deb` rebuilds, and for the same reason. Guarded,
    # because a package must not fail to install over a menu entry.
    echo "%post"
    echo "command -v update-desktop-database >/dev/null 2>&1 && \\"
    echo "    update-desktop-database -q /usr/share/applications || :"
    # And the same two capabilities, on the same terms. See the `.deb`'s
    # scriptlet above for what each of them buys.
    echo "command -v setcap >/dev/null 2>&1 && \\"
    echo "    setcap cap_net_bind_service,cap_net_raw=+ep /usr/bin/muster || :"
    # The archive, on the same terms as the `.deb`: created if absent, never
    # overwritten, honouring a `.disabled` marker, and never removed on the way
    # out because it is shared with every other application from the same
    # archive. `repo_gpgcheck` is what verifies the index before dnf will read
    # it, and `gpgcheck` is what verifies each package; the archive signs both,
    # so both are on.
    #
    # **No `rpm --import` here**, which is the tempting line to add. A scriptlet
    # runs inside the transaction that is installing this very package, and the
    # rpm database is locked by it; importing a key is a write to that database,
    # so the command fails, and with the `|| :` that a scriptlet needs it fails
    # silently. `gpgkey=file://` below is the supported route: dnf reads the key
    # from the installed file the first time it needs one, which is what every
    # third-party release package does.
    if [ -n "$archive_key" ]; then
        echo "repo=/etc/yum.repos.d/spillebulle.repo"
        echo "if [ ! -e \"\$repo\" ] && [ ! -e \"\$repo.disabled\" ]; then"
        echo "    cat > \"\$repo\" <<'REPO'"
        echo "[spillebulle]"
        echo "name=Spillebulle"
        echo "baseurl=$ARCHIVE_BASE/rpm/"
        echo "enabled=1"
        echo "gpgcheck=1"
        echo "repo_gpgcheck=1"
        echo "gpgkey=file://$rpm_key"
        echo "REPO"
        echo "fi"
    fi
    echo
    echo "%postun"
    echo "command -v update-desktop-database >/dev/null 2>&1 && \\"
    echo "    update-desktop-database -q /usr/share/applications || :"
    echo
    echo "%files"
    [ -n "$archive_key" ] && echo "$rpm_key"
    echo "/usr/bin/muster"
    echo "/usr/share/applications/$APP_ID.desktop"
    echo "/usr/share/metainfo/$APP_ID.metainfo.xml"
    echo "/usr/share/icons/hicolor/*/apps/$APP_ID.png"
    echo "/usr/share/doc/muster/"
} > "$rpmroot/SPECS/muster.spec"

rpmbuild --define "_topdir $rpmroot" \
         --define "_buildhost muster-release" \
         -bb "$rpmroot/SPECS/muster.spec" >/dev/null
find "$rpmroot/RPMS" -name '*.rpm' -exec cp {} "$outdir/" \;

# --- AppImage ----------------------------------------------------------------
#
# The one format that has to run on a distribution nobody chose, so it carries
# its libraries with it. linuxdeploy walks the ELF and copies what it finds;
# the dlopened set above is deliberately *not* bundled — the Vulkan loader and
# the display client must be the host's, or the AppImage would talk to the
# wrong driver.

echo "==> building Muster-${version}-${appimage_arch}.AppImage"
appdir="$work/AppDir"
stage_tree "$appdir/usr"
# linuxdeploy wants these at the AppDir root as well as under usr/share.
cp "$root/packaging/$APP_ID.desktop" "$appdir/$APP_ID.desktop"
cp "$root/assets/icons/muster-256.png" "$appdir/$APP_ID.png"

tools="${APPIMAGE_TOOL_DIR:-$work/tools}"
mkdir -p "$tools"
fetch_tool() {
    local name=$1 url=$2
    if [ ! -x "$tools/$name" ]; then
        curl -fsSL -o "$tools/$name" "$url"
        chmod +x "$tools/$name"
    fi
}
base=https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous
fetch_tool linuxdeploy "$base/linuxdeploy-${appimage_arch}.AppImage"

# `--appimage-extract-and-run` because a CI container has no FUSE, and an
# AppImage tool is itself an AppImage.
export APPIMAGE_EXTRACT_AND_RUN=1
export OUTPUT="$outdir/Muster-${version}-${appimage_arch}.AppImage"
export VERSION="$version"
"$tools/linuxdeploy" \
    --appdir "$appdir" \
    --desktop-file "$appdir/$APP_ID.desktop" \
    --icon-file "$appdir/$APP_ID.png" \
    --output appimage

echo
echo "built into $outdir:"
ls -1 "$outdir"
