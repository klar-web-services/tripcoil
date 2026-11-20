#!/bin/sh
set -eu

say() { printf '%s\n' "$*"; }
fail() { printf 'tripcoil installer: %s\n' "$*" >&2; exit 1; }

main() {
	base=${TRIPCOIL_BASE_URL:-https://tools.klar.ws/tripcoil}
	base=${base%/}
	install_dir=${TRIPCOIL_INSTALL_DIR:-/usr/local/bin}
	version=${TRIPCOIL_VERSION:-}
	from=TRIPCOIL_VERSION

	[ "$(uname -s)" = Linux ] || fail "unsupported operating system: $(uname -s) (Tripcoil watches Linux servers)"
	[ "$(id -u)" = 0 ] || fail "run it as root: curl -fsSL https://tools.klar.ws/tripcoil/install.sh | sudo sh"
	case "$(uname -m)" in
	x86_64 | amd64) arch=x86_64 ;;
	arm64 | aarch64) arch=aarch64 ;;
	*) fail "unsupported architecture: $(uname -m)" ;;
	esac

	if command -v curl >/dev/null 2>&1; then
		fetch() { curl -fsSL "$1" -o "$2"; }
	elif command -v wget >/dev/null 2>&1; then
		fetch() { wget -q -O "$2" "$1"; }
	else
		fail "curl or wget is required"
	fi

	tmp=$(mktemp -d "${TMPDIR:-/tmp}/tripcoil-install.XXXXXX")
	new=
	# An interrupt exits, so the EXIT trap cleans up and nothing after it runs.
	trap 'rm -rf "$tmp"; [ -z "$new" ] || rm -f "$new"' EXIT
	trap 'exit 1' HUP INT TERM

	if [ -z "$version" ]; then
		fetch "$base/latest" "$tmp/latest" || fail "could not determine the latest version from $base/latest"
		version=$(cat "$tmp/latest")
		from="$base/latest"
	fi
	version=$(printf '%s' "$version" | tr -d '[:space:]')
	version=${version#v}
	# The value itself is not printed: it may come from the server.
	case $version in '' | *[!0-9A-Za-z._-]*) fail "invalid version from $from" ;; esac
	# tripcoil update sets TRIPCOIL_UPDATE_FROM to its own version, and restarts the service itself.
	if [ "$version" = "${TRIPCOIL_UPDATE_FROM:-}" ]; then
		say "tripcoil $version is already up to date."
		exit 0
	fi

	asset="tripcoil-$arch-unknown-linux-gnu.tar.gz"
	url="$base/v$version"
	fetch "$url/checksums.txt" "$tmp/checksums.txt" || fail "tripcoil $version not found at $url"
	expected=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1; exit }' "$tmp/checksums.txt")
	[ -n "$expected" ] || fail "no build of tripcoil $version for $arch Linux"
	fetch "$url/$asset" "$tmp/$asset" || fail "download of $asset failed"
	# Hash and unpack from stdin: GNU sha256sum escapes a file name containing a backslash,
	# and GNU tar reads host:path as a remote archive.
	command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
	actual=$(sha256sum <"$tmp/$asset" | awk '{print $1}')
	[ "$actual" = "$expected" ] || fail "checksum verification failed for $asset; nothing was installed"

	mkdir "$tmp/x"
	tar -xzf - -C "$tmp/x" <"$tmp/$asset" || fail "could not unpack $asset"
	src=$(find "$tmp/x" -type f -name tripcoil | head -n 1)
	[ -n "$src" ] || fail "tripcoil not found in $asset"
	mkdir -p "$install_dir"
	# mv would move the binary into a directory of that name and still report success.
	[ ! -d "$install_dir/tripcoil" ] || fail "could not write $install_dir/tripcoil: it is a directory"
	new="$install_dir/.tripcoil.new.$$"
	if ! install -m 0755 "$src" "$new" || ! chown 0:0 "$new" || ! mv -f "$new" "$install_dir/tripcoil"; then
		rm -f "$new"
		fail "could not write $install_dir/tripcoil"
	fi
	new=
	say "Installed tripcoil $version to $install_dir/tripcoil"
	[ -z "${TRIPCOIL_UPDATE_FROM:-}" ] || exit 0
	sudo=
	[ -z "${SUDO_USER:-}" ] || sudo="sudo "
	if [ -e /etc/systemd/system/tripcoil.service ]; then
		say "Restart the service to use it: ${sudo}systemctl restart tripcoil"
	elif [ -e /etc/init.d/tripcoil ]; then
		say "Restart the service to use it: ${sudo}rc-service tripcoil restart"
	else
		say "Next: ${sudo}tripcoil setup"
	fi
}

main "$@"
