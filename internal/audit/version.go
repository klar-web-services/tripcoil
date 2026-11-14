package audit

import (
	"cmp"
	"strings"
)

// compareVersions orders two versions of a package of a Grype package type. Distribution
// packages compare as dpkg compares them, which also orders RPM, apk and pacman versions. Other
// versions compare as semver when both are semver, and otherwise as dpkg compares them.
func compareVersions(typ, a, b string) int {
	switch typ {
	case "deb", "rpm", "alpm":
		return compareDpkg(a, b)
	case "apk":
		return compareDpkg(apkPreRelease.Replace(a), apkPreRelease.Replace(b))
	case "go-module":
		// Grype gives the Go standard library's version as go1.23.12, and its fixes as 1.24.9.
		a, b = strings.TrimPrefix(a, "go"), strings.TrimPrefix(b, "go")
	}
	if x, ok := parseSemver(a); ok {
		if y, ok := parseSemver(b); ok {
			return compareSemver(x, y)
		}
	}
	return compareDpkg(a, b)
}

// apkPreRelease sorts apk's pre-release suffixes before the release, as dpkg sorts a ~.
var apkPreRelease = strings.NewReplacer("_alpha", "~alpha", "_beta", "~beta", "_pre", "~pre", "_rc", "~rc")

// compareDpkg orders by the epoch (the number before a colon, else 0), then the version before
// the last hyphen, then the revision after it.
func compareDpkg(a, b string) int {
	ea, a := epoch(a)
	eb, b := epoch(b)
	va, ra := revision(a)
	vb, rb := revision(b)
	return cmp.Or(compareDecimal(ea, eb), verrevcmp(va, vb), verrevcmp(ra, rb))
}

func epoch(v string) (string, string) {
	if e, rest, ok := strings.Cut(v, ":"); ok && allDigits(e) {
		return strings.TrimLeft(e, "0"), rest
	}
	return "", v
}

func revision(v string) (string, string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// verrevcmp is dpkg's: it compares runs of non-digits character by character, where ~ sorts
// before everything, even the end, and letters before other characters, and runs of digits as
// numbers.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a[i]) || j < len(b) && !isDigit(b[j]) {
			if x, y := order(a, i), order(b, j); x != y {
				return cmp.Compare(x, y)
			}
			i, j = i+1, j+1
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if first == 0 {
				first = cmp.Compare(a[i], b[j])
			}
			i, j = i+1, j+1
		}
		switch {
		case i < len(a) && isDigit(a[i]):
			return 1
		case j < len(b) && isDigit(b[j]):
			return -1
		case first != 0:
			return first
		}
	}
	return 0
}

func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	switch c := s[i]; {
	case isDigit(c):
		return 0
	case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }
