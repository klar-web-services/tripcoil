package audit

import (
	"cmp"
	"slices"
	"strings"
)

// Upgrades returns the upgrade lines of spec section 6.6: for each package in an app directory or
// jar whose findings all have a fix, the one version that clears them all. That is the highest fix
// version, given only when every installed and fix version is semver, the highest is spelled one
// way only, and it is above every installed version. The version is always one that Grype
// reported; none is derived. Sorted by findings cleared, then path and package.
func Upgrades(findings []Finding) []Upgrade {
	type key struct{ origin, typ, pkg string }
	groups := map[key][]Finding{}
	var keys []key
	for _, f := range findings {
		if !strings.HasPrefix(f.Origin, "appdir:") {
			continue
		}
		k := key{f.Origin, f.Package.Type, f.Package.Name}
		if _, seen := groups[k]; !seen {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], f)
	}
	var out []Upgrade
	for _, k := range keys {
		if v, ok := upgradeVersion(groups[k]); ok {
			out = append(out, Upgrade{Origin: k.origin, Path: strings.TrimPrefix(k.origin, "appdir:"), Package: k.pkg, Type: k.typ, Version: v, Findings: len(groups[k])})
		}
	}
	slices.SortFunc(out, func(a, b Upgrade) int {
		return cmp.Or(cmp.Compare(b.Findings, a.Findings), cmp.Compare(a.Path, b.Path), cmp.Compare(a.Package, b.Package), cmp.Compare(a.Type, b.Type))
	})
	return out
}

// upgradeVersion is the highest fix version of one package's findings, if a line is allowed.
func upgradeVersion(findings []Finding) (string, bool) {
	var (
		best      string
		bestV     semver
		ambiguous bool
		installed []semver
	)
	for _, f := range findings {
		if f.Fix.State != "fixed" || len(f.Fix.Versions) == 0 {
			return "", false
		}
		iv, ok := parseSemver(f.Package.Version)
		if !ok {
			return "", false
		}
		installed = append(installed, iv)
		for _, s := range f.Fix.Versions {
			v, ok := parseSemver(s)
			if !ok {
				return "", false
			}
			switch c := compareSemver(v, bestV); {
			case best == "" || c > 0:
				best, bestV, ambiguous = s, v, false
			case c == 0 && s != best:
				ambiguous = true // e.g. 1.0.1 and v1.0.1, or 1.0.1+a and 1.0.1+b
			}
		}
	}
	if ambiguous {
		return "", false
	}
	for _, iv := range installed {
		if compareSemver(bestV, iv) <= 0 {
			return "", false
		}
	}
	return best, true
}

// semver is a parsed semver 2.0 version. Numbers stay decimal strings without leading zeros,
// so arbitrarily large values compare correctly. Build metadata is dropped.
type semver struct {
	core [3]string
	pre  []string // pre-release identifiers; empty for a release
}

// parseSemver parses MAJOR.MINOR.PATCH with optional -pre and +build and an optional leading v.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !validIdentifiers(s[i+1:], false) {
			return semver{}, false
		}
		s = s[:i]
	}
	var v semver
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if !validIdentifiers(s[i+1:], true) {
			return semver{}, false
		}
		v.pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	core := strings.Split(s, ".")
	if len(core) != 3 {
		return semver{}, false
	}
	for i, n := range core {
		if !allDigits(n) || (len(n) > 1 && n[0] == '0') {
			return semver{}, false
		}
		v.core[i] = n
	}
	return v, true
}

// validIdentifiers checks dot-separated pre-release (pre) or build identifiers.
func validIdentifiers(s string, pre bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '-') {
				return false
			}
		}
		if pre && allDigits(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// compareSemver orders by semver 2.0 precedence: numeric core, then a pre-release below its
// release, identifiers numerically or else in ASCII order, numeric below alphanumeric, and a
// shorter identifier list below a longer one with the same prefix.
func compareSemver(a, b semver) int {
	for i := range a.core {
		if c := compareDecimal(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	if len(a.pre) == 0 || len(b.pre) == 0 {
		return cmp.Compare(len(b.pre), len(a.pre)) // a release (no identifiers) sorts higher
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		var c int
		switch xn, yn := allDigits(x), allDigits(y); {
		case xn && yn:
			c = compareDecimal(x, y)
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a.pre), len(b.pre))
}

// compareDecimal compares decimal strings without leading zeros.
func compareDecimal(x, y string) int {
	return cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y))
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
