package audit

import (
	"cmp"
	"slices"
	"strings"
)

func compareVersions(typ, a, b string) int {
	switch typ {
	case "deb":
		return compareDpkg(a, b)
	case "rpm":
		return compareEVR(a, b, false)
	case "alpm":
		return compareEVR(a, b, true)
	case "apk":
		return compareApk(a, b)
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
	switch c := at(s, i); {
	case c == 0 || isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func compareEVR(a, b string, pacman bool) int {
	ea, va, ra, hasA := evr(a)
	eb, vb, rb, hasB := evr(b)
	if c := cmp.Or(rpmvercmp(ea, eb, pacman), rpmvercmp(va, vb, pacman)); c != 0 || pacman && !(hasA && hasB) {
		return c
	}
	return rpmvercmp(ra, rb, pacman)
}

func evr(s string) (epoch, version, release string, hasRelease bool) {
	n := 0
	for n < len(s) && isDigit(s[n]) {
		n++
	}
	epoch, version = "0", s
	if n < len(s) && s[n] == ':' {
		epoch, version = cmp.Or(s[:n], "0"), s[n+1:]
	}
	if i := strings.LastIndexByte(version, '-'); i >= 0 {
		return epoch, version[:i], version[i+1:], true
	}
	return epoch, version, "", false
}

// rpmvercmp is rpm's, or pacman's older copy of it. Both compare runs of digits as numbers and
// runs of letters as text, skip other characters, and rank a number above letters. rpm sorts ~
// before everything, even the end, and ^ after the end but before anything else; the version
// with more left over is newer. pacman has neither, ranks a version with more separators before
// a segment higher, and never lets letters left over beat the end.
func rpmvercmp(a, b string, pacman bool) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for pacman && i < len(a) && j < len(b) || !pacman && (i < len(a) || j < len(b)) {
		si, sj := i, j
		for i < len(a) && !isAlnum(a[i]) && (pacman || a[i] != '~' && a[i] != '^') {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && (pacman || b[j] != '~' && b[j] != '^') {
			j++
		}
		if x, y := at(a, i), at(b, j); !pacman && (x == '~' || y == '~') {
			if x != '~' {
				return 1
			}
			if y != '~' {
				return -1
			}
			i, j = i+1, j+1
			continue
		} else if !pacman && (x == '^' || y == '^') {
			switch {
			case x == 0:
				return -1
			case y == 0:
				return 1
			case x != '^':
				return 1
			case y != '^':
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i == len(a) || j == len(b) {
			break
		}
		if pacman && i-si != j-sj {
			return cmp.Compare(i-si, j-sj)
		}
		sa, sb := i, j
		num := isDigit(a[i])
		for i < len(a) && (num && isDigit(a[i]) || !num && isAlpha(a[i])) {
			i++
		}
		for j < len(b) && (num && isDigit(b[j]) || !num && isAlpha(b[j])) {
			j++
		}
		if j == sb {
			if num {
				return 1
			}
			return -1
		}
		x, y := a[sa:i], b[sb:j]
		if num {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if c := cmp.Compare(len(x), len(y)); c != 0 {
				return c
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch x, y := at(a, i), at(b, j); {
	case x == 0 && y == 0:
		return 0
	case !pacman && x == 0, pacman && (x == 0 && !isAlpha(y) || isAlpha(x)):
		return -1
	}
	return 1
}

const (
	apkInvalid = iota - 1
	apkDigitOrZero
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNo
	apkRevisionNo
	apkEnd
)

func compareApk(a, b string) int {
	ta, tb := apkDigit, apkDigit
	var va, vb int64
	for ta == tb && ta != apkEnd && ta != apkInvalid && va == vb {
		va = apkToken(&ta, &a)
		vb = apkToken(&tb, &b)
	}
	switch {
	case va != vb:
		return cmp.Compare(va, vb)
	case ta == tb:
		return 0
	}
	if t := ta; ta == apkSuffix && apkToken(&t, &a) < 0 {
		return -1
	}
	if t := tb; tb == apkSuffix && apkToken(&t, &b) < 0 {
		return 1
	}
	return cmp.Compare(tb, ta)
}

var (
	apkPreSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

func apkToken(t *int, s *string) int64 {
	if *s == "" {
		*t = apkEnd
		return 0
	}
	var v int64
	i, next := 0, apkInvalid
	switch *t {
	case apkDigitOrZero:
		if (*s)[0] == '0' {
			for i+1 < len(*s) && (*s)[i+1] == '0' {
				i++
			}
			v, next = int64(-i), apkDigit
			break
		}
		fallthrough
	case apkDigit, apkSuffixNo, apkRevisionNo:
		for i < len(*s) && isDigit((*s)[i]) {
			v = v*10 + int64((*s)[i]-'0')
			i++
		}
		if i >= 18 {
			*t = apkInvalid
			return -1
		}
	case apkLetter:
		v, i = int64((*s)[0]), 1
	case apkSuffix:
		prefix := func(p string) bool { return strings.HasPrefix(*s, p) }
		if k := slices.IndexFunc(apkPreSuffixes, prefix); k >= 0 {
			v, i = int64(k-len(apkPreSuffixes)), len(apkPreSuffixes[k])
		} else if k := slices.IndexFunc(apkPostSuffixes, prefix); k >= 0 {
			v, i = int64(k), len(apkPostSuffixes[k])
		} else {
			*t = apkInvalid
			return -1
		}
	default:
		*t = apkInvalid
		return -1
	}
	*s = (*s)[i:]
	switch {
	case *s == "":
		*t = apkEnd
	case next != apkInvalid:
		*t = next
	default:
		apkNextType(t, s)
	}
	return v
}

func apkNextType(t *int, s *string) {
	n, c := apkInvalid, (*s)[0]
	switch {
	case (*t == apkDigit || *t == apkDigitOrZero) && 'a' <= c && c <= 'z':
		n = apkLetter
	case *t == apkLetter && isDigit(c):
		n = apkDigit
	case *t == apkSuffix && isDigit(c):
		n = apkSuffixNo
	default:
		switch {
		case c == '.':
			n = apkDigitOrZero
		case c == '_':
			n = apkSuffix
		case c == '-' && len(*s) > 1 && (*s)[1] == 'r':
			n = apkRevisionNo
			*s = (*s)[1:]
		}
		*s = (*s)[1:]
	}
	if n < *t && !(n == apkDigitOrZero && *t == apkDigit || n == apkSuffix && *t == apkSuffixNo || n == apkDigit && *t == apkLetter) {
		n = apkInvalid
	}
	*t = n
}

func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
