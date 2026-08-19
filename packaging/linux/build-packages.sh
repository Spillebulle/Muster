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
# **There is no `setcap` here, and that is deliberate.** `CLAUDE.md` reserves
# one for the privileged engine, and that engine does not exist yet: the sweep
# and the port scan both run on ordinary sockets today. Granting `CAP_NET_RAW`
# to a binary with no code path that uses it would be a capability handed out
# for nothing. It belongs in this scriptlet the moment the raw transport lands,
# and the README says so where a user can read it rather than only here.
cat > "$deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
EOF
# The same on the way out, so a removed Muster stops being listed rather than
# leaving a dead entry in every menu.
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
    echo
    # The same cache the `.deb` rebuilds, and for the same reason. Guarded,
    # because a package must not fail to install over a menu entry. See the
    # `.deb`'s scriptlet above for why there is no `setcap` here yet.
    echo "%post"
    echo "command -v update-desktop-database >/dev/null 2>&1 && \\"
    echo "    update-desktop-database -q /usr/share/applications || :"
    echo
    echo "%postun"
    echo "command -v update-desktop-database >/dev/null 2>&1 && \\"
    echo "    update-desktop-database -q /usr/share/applications || :"
    echo
    echo "%files"
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
