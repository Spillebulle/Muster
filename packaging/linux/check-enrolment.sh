#!/bin/bash
# Install a built package in a clean container and check that it enrolled the
# machine in the house archive, the way `../Packages/ENROLMENT.md` says.
#
#   packaging/linux/check-enrolment.sh deb  dist/muster_<v>_amd64.deb
#   packaging/linux/check-enrolment.sh rpm  dist/muster-<v>-1.x86_64.rpm
#   packaging/linux/check-enrolment.sh arch dist/muster-bin-<v>-1-x86_64.pkg.tar.zst
#
# Runs as root in a throwaway `debian`, `fedora` or `archlinux` container
# (`release.yml` is what runs it), and changes the machine it runs on: never
# run it on one you want to keep.
#
# Each of these is a defect a package could ship with and still install: a
# scriptlet that wrote the wrong path, a key nobody trusts, a section appended
# twice. Nothing on the release page shows any of them, and every one of them
# ends with a machine that is never offered another Muster. The `.deb` half
# also installs a second package that enrols, because the defect the contract
# exists to prevent - two packages shipping one path, which dpkg refuses - only
# shows when two applications are installed.

set -euo pipefail

if [ $# -ne 2 ]; then
    sed -n '2,7p' "$0" >&2
    exit 2
fi

format=$1
package=$(readlink -f "$2")
[ -f "$package" ] || { echo "no package at '$2'" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { printf 'enrolment: %s\n' "$1" >&2; exit 1; }
ok()   { printf '  ok  %s\n' "$1"; }

# Whether a file is exactly these lines. Compared in the shell rather than with
# `diff`, which the Arch and Fedora images do not necessarily carry.
same() {
    local file=$1
    shift
    local want
    want=$(printf '%s\n' "$@")
    if [ "$(cat "$file")" != "$want" ]; then
        printf -- '--- want\n%s\n--- %s\n' "$want" "$file" >&2
        cat "$file" >&2
        fail "$file is not what the contract writes"
    fi
}

FPR=7A9EA69E033F3C3EF4F53EB4A72BC0FD5E061ADA
BASE=https://spillebulle.github.io/packages

# --- apt -----------------------------------------------------------------------
check_deb() {
    local sources=/etc/apt/sources.list.d/spillebulle.sources
    local keyring=/etc/apt/keyrings/spillebulle-archive.gpg
    local shipped=/usr/share/muster/spillebulle-archive.gpg
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -q
    apt-get install -y -q "$package"

    [ -f "$shipped" ] || fail "the package did not ship $shipped"
    if dpkg -S /usr/share/keyrings/spillebulle-archive.gpg >/dev/null 2>&1; then
        fail "the package still ships /usr/share/keyrings/spillebulle-archive.gpg, which every application would own"
    fi
    ok "the key is shipped under Muster's own name"

    [ -f "$keyring" ] || fail "postinst did not write $keyring"
    cmp -s "$keyring" "$shipped" || fail "$keyring is not the key the package ships"
    ok "the shared keyring is in place"

    [ -f "$sources" ] || fail "postinst did not write $sources"
    same "$sources" 'Types: deb' "URIs: $BASE/deb/" 'Suites: ./' "Signed-By: $keyring"
    ok "the source names the archive and the shared keyring"

    # The source has to verify, not just exist. Any warning or error naming the
    # archive is a machine apt will not upgrade from.
    apt-get update 2>&1 | tee "$work/update.log"
    if grep -E '^(W|E):' "$work/update.log" | grep -q spillebulle; then
        fail "apt does not accept the archive"
    fi
    apt-cache policy muster | tee "$work/policy.log"
    grep -q "spillebulle.github.io" "$work/policy.log" || fail "apt cannot see muster in the archive"
    ok "apt verifies the archive and sees muster in it"

    # A second application that enrols. Built from this one's own control files
    # and scriptlets, renamed, carrying nothing but its own copy of the key, so
    # whatever this package does on install the second one does too.
    local twin=$work/twin
    mkdir -p "$twin/usr/share/muster-twin"
    dpkg-deb -e "$package" "$twin/DEBIAN"
    cp "$shipped" "$twin/usr/share/muster-twin/spillebulle-archive.gpg"
    sed -i 's|/usr/share/muster/|/usr/share/muster-twin/|g' "$twin/DEBIAN/postinst"
    printf '%s\n' \
        'Package: muster-twin' \
        'Version: 1' \
        'Architecture: all' \
        'Maintainer: Spillebulle <spillebulle@gmail.com>' \
        'Description: A second package that enrols, for this check only' > "$twin/DEBIAN/control"
    dpkg-deb --build --root-owner-group "$twin" "$work/twin.deb" >/dev/null

    # And an older source beside it, the shape packages wrote before the
    # contract, which the second install has to point at the shared keyring.
    # The keyring is backdated so that a scriptlet that overwrote it shows.
    sed -i "s|^Signed-By: .*|Signed-By: /usr/share/keyrings/spillebulle-archive.gpg|" "$sources"
    touch -d '2000-01-01 00:00:00' "$keyring"
    local before
    before=$(stat -c %Y "$keyring")

    dpkg -i "$work/twin.deb" || fail "a second package that enrols could not be installed beside the first"
    ok "a second package that enrols installs beside the first"
    grep -qx "Signed-By: $keyring" "$sources" || fail "an older source was not pointed at $keyring"
    ok "an older source is pointed at the shared keyring"
    [ "$(stat -c %Y "$keyring")" = "$before" ] || fail "the second package overwrote $keyring"
    ok "the shared keyring is created, never overwritten"

    # Removing one application leaves the others upgrading.
    dpkg --purge muster
    [ -f "$sources" ] && [ -f "$keyring" ] || fail "removing muster took the archive away from the other application"
    ok "removing muster leaves the archive in place"

    # The opt-out holds through an upgrade.
    rm "$sources"
    touch "$sources.disabled"
    dpkg -i "$work/twin.deb"
    [ ! -e "$sources" ] || fail "$sources.disabled was not honoured"
    ok "the .disabled marker is honoured"
}

# --- rpm -----------------------------------------------------------------------
check_rpm() {
    local repo=/etc/yum.repos.d/spillebulle.repo
    local key=/etc/pki/rpm-gpg/RPM-GPG-KEY-spillebulle

    dnf install -y "$package"

    [ -f "$key" ] || fail "the package did not ship $key"
    ok "the key is in place"
    [ -f "$repo" ] || fail "%post did not write $repo"
    grep -qx '\[spillebulle\]' "$repo" || fail "$repo has no [spillebulle] section"
    grep -qx "baseurl=$BASE/rpm/" "$repo" || fail "$repo does not point at the archive"
    grep -qx "gpgkey=file://$key" "$repo" || fail "$repo does not name the installed key"
    grep -qx 'gpgcheck=1' "$repo" && grep -qx 'repo_gpgcheck=1' "$repo" || \
        fail "$repo does not check signatures"
    ok "the repository names the archive and the installed key"

    # rpm, not dnf, so removing it does not consult the archive just added.
    rpm -e muster
    [ -f "$repo" ] || fail "removing muster took $repo away"
    ok "removing muster leaves the archive in place"

    rm "$repo"
    touch "$repo.disabled"
    rpm -i --nodeps "$package"
    [ ! -e "$repo" ] || fail "$repo.disabled was not honoured"
    ok "the .disabled marker is honoured"
}

# --- pacman --------------------------------------------------------------------
check_arch() {
    local conf=/etc/pacman.d/spillebulle

    # The archlinux image ships its keyring without the local master key that
    # every installed system has (`pacman-key --init` at install time), and a
    # local signature needs one. Without this the scriptlet's `--lsign-key`
    # fails here and nowhere else.
    pacman-key --init >/dev/null 2>&1

    # A full upgrade first, because installing the dependencies on top of the
    # image's older libraries is a partial upgrade, which Arch does not support.
    pacman -Syu --noconfirm
    # With scriptlets, which is the default and the whole point.
    pacman -U --noconfirm "$package"

    pacman -Qlq muster-bin | grep -qx /usr/share/muster/spillebulle-archive.asc || \
        fail "the package did not ship /usr/share/muster/spillebulle-archive.asc"
    ok "the key is shipped under Muster's own name"

    [ -f "$conf" ] || fail "the scriptlet did not write $conf"
    same "$conf" 'SigLevel = Required DatabaseRequired' "Server = $BASE/arch/\$arch"
    grep -qx '\[spillebulle\]' /etc/pacman.conf || fail "/etc/pacman.conf has no [spillebulle] section"
    grep -qx "Include = $conf" /etc/pacman.conf || fail "/etc/pacman.conf does not include $conf"
    ok "/etc/pacman.conf has the [spillebulle] section"

    pacman-key --list-keys "$FPR" >/dev/null || fail "pacman-key does not have the archive's key"
    ok "pacman-key has the archive's key"

    # `SigLevel = Required DatabaseRequired` makes this fail unless the key is
    # trusted, not merely present, so it is the test of the local signature.
    pacman -Sy --noconfirm || fail "pacman does not accept the archive"
    ok "pacman verifies the archive"

    # An upgrade runs the scriptlet again, and it must not add a second section.
    pacman -U --noconfirm "$package"
    [ "$(grep -c '^\[spillebulle\]' /etc/pacman.conf)" = 1 ] || \
        fail "an upgrade appended a second [spillebulle] section"
    ok "an upgrade leaves one section"

    pacman -R --noconfirm muster-bin
    [ -f "$conf" ] && grep -qx '\[spillebulle\]' /etc/pacman.conf || \
        fail "removing muster-bin took the archive away"
    ok "removing muster-bin leaves the archive in place"

    # Leaving the archive the way `../Packages/README.md` says: the section,
    # the settings file, and the marker that keeps them from coming back.
    sed -i '/^\[spillebulle\]$/,/^Include = \/etc\/pacman.d\/spillebulle$/d' /etc/pacman.conf
    rm "$conf"
    touch "$conf.disabled"
    pacman -U --noconfirm "$package"
    [ ! -e "$conf" ] || fail "$conf.disabled was not honoured"
    if grep -q '^\[spillebulle\]' /etc/pacman.conf; then
        fail "$conf.disabled was not honoured: the section came back"
    fi
    ok "the .disabled marker is honoured"
}

case "$format" in
    deb)  check_deb ;;
    rpm)  check_rpm ;;
    arch) check_arch ;;
    *) echo "unknown format '$format' (want deb, rpm or arch)" >&2; exit 2 ;;
esac

printf '%s package enrols the machine as ENROLMENT.md says\n' "$format"
