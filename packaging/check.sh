#!/bin/sh
# Check that the packaging metadata agrees with itself.
#
#   sh packaging/check.sh
#
# Everything here was a real failure of a real release build, found in CI ten
# minutes at a time. None of it needs flatpak, rpm or WiX installed, so it can
# run on every push and on any machine.
#
# The rule these all serve: the AppStream component, the desktop entry and the
# icons must share one name — the application ID. `appstreamcli compose`
# follows the component's `launchable` to the desktop entry and the desktop
# entry's `Icon` key to the icon, and if either hop misses it reports
# `gui-app-without-icon` and discards the whole component, which fails the
# Flatpak build. Nothing else notices, so this is only ever discovered in the
# one place it is expensive to discover.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

fail() { printf 'packaging: %s\n' "$1" >&2; exit 1; }
ok()   { printf '  ok  %s\n' "$1"; }

APP_ID=io.github.spillebulle.muster

metainfo="packaging/$APP_ID.metainfo.xml"
desktop="packaging/$APP_ID.desktop"

[ -f "$metainfo" ] || fail "no AppStream file at $metainfo"
[ -f "$desktop" ]  || fail "no desktop entry at $desktop"
ok "both files are named for $APP_ID"

# The component id must be the application id.
id=$(sed -n 's/.*<id>\(.*\)<\/id>.*/\1/p' "$metainfo" | head -1)
[ "$id" = "$APP_ID" ] || fail "<id> is '$id', expected '$APP_ID'"
ok "<id> is $APP_ID"

# The launchable must name a desktop entry that is actually installed.
launchable=$(sed -n 's/.*<launchable[^>]*>\(.*\)<\/launchable>.*/\1/p' "$metainfo" | head -1)
[ -n "$launchable" ] || fail "the AppStream file has no <launchable>"
[ "$launchable" = "$APP_ID.desktop" ] || \
    fail "<launchable> is '$launchable' but the desktop entry installs as '$APP_ID.desktop'"
ok "<launchable> resolves to the installed desktop entry"

# The desktop entry's icon must name an icon that is actually installed.
icon=$(sed -n 's/^Icon=\(.*\)$/\1/p' "$desktop" | head -1)
[ -n "$icon" ] || fail "the desktop entry has no Icon key"
[ "$icon" = "$APP_ID" ] || \
    fail "Icon is '$icon' but the icons install as '$APP_ID.png'"
ok "Icon= resolves to the installed icons"

# AppStream wants a 64x64 at minimum, and every packaging script installs the
# same six sizes; a missing source file would fail the build much later.
for size in 16 32 48 64 128 256; do
    [ -f "assets/icons/muster-$size.png" ] || \
        fail "assets/icons/muster-$size.png is missing, and every package installs it"
done
ok "all six icon sizes are present"

# The Exec key names the binary, which is not renamed with everything else —
# `muster` is what a person types.
exec_line=$(sed -n 's/^Exec=\([^ ]*\).*$/\1/p' "$desktop" | head -1)
[ "$exec_line" = "muster" ] || fail "Exec runs '$exec_line', expected 'muster'"
ok "Exec runs muster"

# Every packaging script must agree on the application id. A rename that missed
# one of them is exactly how this check came to exist.
for f in packaging/linux/build-packages.sh packaging/linux/PKGBUILD \
         packaging/linux/$APP_ID.yml; do
    [ -f "$f" ] || fail "$f is missing"
    grep -q "$APP_ID" "$f" || fail "$f never mentions $APP_ID"
done
ok "every packaging script names $APP_ID"

# --- the icon on the running window ------------------------------------------
#
# A Wayland client cannot hand the compositor an icon; it hands it an app id,
# and the compositor reads the icon out of `<app id>.desktop`. So the string the
# window sets and the name of this desktop entry are one fact written in two
# languages, and when they disagree nothing breaks loudly: the launcher reads
# the entry by name and shows the mark, and the taskbar shows a blank square.
decl=$(grep '^pub const APP_ID' crates/muster-app/src/lib.rs | head -1)
[ -n "$decl" ] || fail "crates/muster-app/src/lib.rs declares no APP_ID"
window_id=$(printf '%s' "$decl" | cut -d '"' -f 2)
[ "$window_id" = "$APP_ID" ] || fail "the window's app id is '$window_id', expected '$APP_ID'"
grep -q 'with_app_id(APP_ID)' crates/muster-app/src/lib.rs || fail "the window never sets an app id, so Wayland has no icon to find"
ok "the window's app id resolves to the desktop entry"

# X11 takes no app id and matches on WM_CLASS instead, which winit leaves as the
# basename of argv[0] — the binary Exec runs.
wmclass=$(grep '^StartupWMClass=' "$desktop" | head -1 | cut -d = -f 2)
[ "$wmclass" = "$exec_line" ] || fail "StartupWMClass is '$wmclass' but the binary is called '$exec_line'"
ok "StartupWMClass is the binary's own name, which is X11's WM_CLASS"

# --- the two capabilities ----------------------------------------------------
#
# The DHCP check binds port 68, which is below 1024, so it needs
# `CAP_NET_BIND_SERVICE`; the ICMP echo falls back to a raw socket where ping
# sockets are shut, which needs `CAP_NET_RAW`. Three scriptlets grant them and
# the messages on screen name them, and if those ever disagree a feature simply
# reports "Permission denied" for ever with a message telling the user to grant
# something the packages already granted. Same shape of defect as the archive
# path below.
for CAP in cap_net_bind_service cap_net_raw; do
    for f in packaging/linux/build-packages.sh packaging/linux/muster.install; do
        [ -f "$f" ] || fail "$f is missing"
        grep -q "$CAP" "$f" || fail "$f never grants $CAP"
    done
    ok "the packages grant $CAP"
done
grep -q cap_net_bind_service crates/muster-net/src/platform/mod.rs || fail "the message that explains a failed DHCP check never names cap_net_bind_service"
ok "the message that explains a failed DHCP check names the capability"

# The Arch scriptlet only runs if the PKGBUILD names it, and makepkg only finds
# it if the workflow copies it next to the PKGBUILD.
grep -q '^install=muster.install$' packaging/linux/PKGBUILD ||     fail "the PKGBUILD does not name muster.install, so the scriptlet never runs"
grep -q 'packaging/linux/muster.install' .github/workflows/release.yml ||     fail "release.yml does not copy muster.install beside the PKGBUILD, so makepkg will fail"
ok "the Arch scriptlet is named by the PKGBUILD and shipped by the workflow"

# --- the house archive -------------------------------------------------------
#
# The path the `.deb` writes and the path the updater looks for have to be the
# same string, and they are written in two files in two languages that never
# see each other. Get it wrong and nothing breaks: the packages still install,
# the updater still runs, and it simply tells every user of the archive to go
# and download a file by hand for ever. That is the shape of defect this whole
# script exists for.
for path in /etc/apt/sources.list.d/spillebulle.sources \
            /etc/yum.repos.d/spillebulle.repo; do
    grep -q "$path" packaging/linux/build-packages.sh || \
        fail "packaging/linux/build-packages.sh never writes $path"
    grep -q "$path" crates/muster-app/src/update/install.rs || \
        fail "the updater never looks for $path"
done
ok "the packages and the updater agree on where the archive is configured"

# pacman has no drop-in directory for repositories, so on Arch the archive is a
# section in `/etc/pacman.conf` that `muster.install` appends, and the updater
# reads that file for the section by name. Same defect, same check: the file,
# the section and the settings file the section includes.
install_rs=crates/muster-app/src/update/install.rs
scriptlet=packaging/linux/muster.install
conf=$(tr -d '\r' < "$install_rs" | sed -n 's/^const PACMAN_CONF: &str = "\(.*\)";$/\1/p')
section=$(tr -d '\r' < "$install_rs" | sed -n 's/^const PACMAN_SECTION: &str = "\(.*\)";$/\1/p')
[ "$conf" = /etc/pacman.conf ] || fail "the updater reads '$conf' for the archive, not /etc/pacman.conf"
[ "$section" = '[spillebulle]' ] || fail "the updater looks for the section '$section', not [spillebulle]"
grep -qF ">> $conf" "$scriptlet" || fail "$scriptlet never appends to $conf, which is what the updater reads"
grep -qF "\\n$section\\nInclude = %s\\n" "$scriptlet" || fail "$scriptlet does not append the section $section the updater looks for"
grep -qF "grep -q '^\\[spillebulle\\]' $conf" "$scriptlet" || fail "$scriptlet does not check for $section before appending it, so every upgrade would add another"
grep -qF 'local conf=/etc/pacman.d/spillebulle' "$scriptlet" || fail "$scriptlet does not write /etc/pacman.d/spillebulle"
grep -qF 'Include = /etc/pacman.d/spillebulle' "$install_rs" || fail "the updater's tests do not include /etc/pacman.d/spillebulle the way the scriptlet does"
grep -qF '$conf.disabled' "$scriptlet" || fail "$scriptlet ignores the .disabled marker"
ok "the Arch scriptlet and the updater agree on $conf and $section"

# Each package ships the key under Muster's own name and the scriptlet puts the
# shared copy in place: dpkg refuses a second package that ships a path another
# already owns, so a shared path in the `.deb` is a second application that
# cannot be installed. The shipped path and the path the scriptlet reads from
# have to be the same file.
deb_key=/usr/share/muster/spillebulle-archive.gpg
apt_keyring=/etc/apt/keyrings/spillebulle-archive.gpg
grep -qF '"$deb/usr/share/muster/$ARCHIVE_KEYRING.gpg"' packaging/linux/build-packages.sh || \
    fail "the .deb does not ship its key at $deb_key"
grep -qF "install -m644 $deb_key \"\$keyring\"" packaging/linux/build-packages.sh || \
    fail "the .deb's postinst does not copy $deb_key to the shared keyring"
grep -qF "keyring=$apt_keyring" packaging/linux/build-packages.sh || \
    fail "the .deb's postinst does not write the shared keyring at $apt_keyring"
grep -qF 'Signed-By: $keyring' packaging/linux/build-packages.sh || \
    fail "the source the .deb writes does not name the shared keyring"
if grep -q '\$deb/usr/share/keyrings' packaging/linux/build-packages.sh; then
    fail "the .deb ships a file in /usr/share/keyrings, which every application would own"
fi
grep -qF "$apt_keyring" README.md || fail "README.md's apt instructions do not use $apt_keyring"
ok "the .deb ships its key as $deb_key and its postinst shares it at $apt_keyring"

arch_key=/usr/share/muster/spillebulle-archive.asc
grep -qF "\"\${pkgdir}$arch_key\"" packaging/linux/PKGBUILD || \
    fail "the PKGBUILD does not ship the key at $arch_key"
grep -qF "pacman-key --add $arch_key" "$scriptlet" || \
    fail "$scriptlet does not hand $arch_key to pacman-key"
grep -qF 'packaging/linux/spillebulle-archive.asc' packaging/linux/PKGBUILD || \
    fail "the PKGBUILD does not take the key from the packaging/ the release tarball carries"
ok "the Arch package ships $arch_key and its scriptlet trusts it"

# All of the above is about what the files say. Whether the installed packages
# do it is `check-enrolment.sh`, in a container per format, before publishing.
for format in deb rpm arch; do
    grep -q "format: $format, " .github/workflows/release.yml || \
        fail "release.yml never installs the $format package to check that it enrols"
done
grep -qF 'packaging/linux/check-enrolment.sh' .github/workflows/release.yml || \
    fail "release.yml never runs packaging/linux/check-enrolment.sh"
grep -q 'needs: \[build, arch, flatpak, enrol\]' .github/workflows/release.yml || \
    fail "release.yml publishes without waiting for the enrolment check"
ok "release.yml installs all three packages and checks they enrol before publishing"

# The fingerprint the scriptlet signs must be the key the packages carry, or
# pacman-key signs nothing and every `pacman -Syu` fails on the archive.
fpr=$(tr -d '\r' < "$scriptlet" | sed -n 's/^ *local fpr=\([0-9A-F]*\)$/\1/p')
[ "$fpr" = 7A9EA69E033F3C3EF4F53EB4A72BC0FD5E061ADA ] || \
    fail "$scriptlet signs '$fpr', not the archive's key"
if command -v gpg >/dev/null 2>&1 && [ -f packaging/linux/spillebulle-archive.asc ]; then
    shown=$(gpg --show-keys --with-colons packaging/linux/spillebulle-archive.asc 2>/dev/null \
        | sed -n 's/^fpr:*\([0-9A-F]*\):*$/\1/p' | head -1)
    [ "$shown" = "$fpr" ] || \
        fail "packaging/linux/spillebulle-archive.asc is '$shown', not the key $scriptlet signs"
    ok "the checked-in key is the one the scriptlet signs, $fpr"
fi

# Not a failure: the public key is checked in when the archive has one, and
# until then the packages build exactly as they did before it existed. Said out
# loud on every run, because a package that quietly stopped enrolling machines
# would look identical to one that never did.
if [ -f packaging/linux/spillebulle-archive.asc ]; then
    ok "the archive key is checked in, so packages will enrol the machine"
else
    printf '  --  no packaging/linux/spillebulle-archive.asc: packages will not\n'
    printf '      enrol the machine in the archive (see ../Packages/README.md)\n'
fi

printf 'packaging metadata is consistent\n'
