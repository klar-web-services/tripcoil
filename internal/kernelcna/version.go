package kernelcna

import (
	"slices"
	"strconv"
	"strings"
)

type version struct {
	parts []int
	rc    int
}

func parseVersion(s string) (version, bool) {
	var v version
	if base, rc, ok := strings.Cut(s, "-rc"); ok {
		n, err := strconv.Atoi(rc)
		if !digits(rc) || err != nil || n < 1 {
			return version{}, false
		}
		s, v.rc = base, n
	}
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if !digits(p) || err != nil {
			return version{}, false
		}
		v.parts = append(v.parts, n)
	}
	return v, true
}

func digits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func compare(a, b version) int {
	for i := range max(len(a.parts), len(b.parts)) {
		x, y := at(a.parts, i), at(b.parts, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.rc == b.rc:
		return 0
	case a.rc == 0:
		return 1
	case b.rc == 0:
		return -1
	case a.rc < b.rc:
		return -1
	}
	return 1
}

func at(p []int, i int) int {
	if i < len(p) {
		return p[i]
	}
	return 0
}

func branch(v version) []int {
	n := 2
	if len(v.parts) >= 3 && v.parts[0] == 2 && v.parts[1] == 6 {
		n = 3
	}
	b := make([]int, n)
	for i := range b {
		b[i] = at(v.parts, i)
	}
	return b
}

func sameBranch(a, b version) bool { return slices.Equal(branch(a), branch(b)) }

func atMostPrefix(v version, prefix []int) bool { return comparePrefix(v, prefix) <= 0 }

func belowPrefix(v version, prefix []int) bool { return comparePrefix(v, prefix) < 0 }

func comparePrefix(v version, prefix []int) int {
	for i, p := range prefix {
		if x := at(v.parts, i); x != p {
			if x < p {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parsePrefix(s string) ([]int, bool) {
	base, ok := strings.CutSuffix(s, ".*")
	if !ok {
		return nil, false
	}
	v, ok := parseVersion(base)
	if !ok || v.rc != 0 {
		return nil, false
	}
	return v.parts, true
}
