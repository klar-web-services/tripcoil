package kernelcna

import (
	"sort"
	"strings"
	"time"
)

type Data struct {
	Commit  string    `json:"commit"`
	Checked time.Time `json:"checked"`
	Records []Record  `json:"records"`

	RefreshErr error `json:"-"`
}

type Match struct {
	CVE   string
	Fixed string
	CVSS  *CVSS
}

func (d *Data) Affected(upstream string) []Match {
	v, ok := parseVersion(upstream)
	if !ok {
		return nil
	}
	var out []Match
	for _, r := range d.Records {
		if r.affects(v) {
			out = append(out, Match{CVE: r.ID, Fixed: r.fixFor(v), CVSS: r.CVSS})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out
}

func IsVersion(upstream string) bool {
	_, ok := parseVersion(upstream)
	return ok
}

// affects applies CVE JSON 5's rule to each entry, and the record affects v when any entry says
// so: in an entry, the first range that covers v gives the status, otherwise the entry's default
// status. In an entry whose default is unaffected, a "0 < X.Y.Z" range counts only for X.Y.Z's own
// branch: the kernel CNA writes it when it does not know where a backported bug came in, and it
// means that branch only.
func (r Record) affects(v version) bool {
	for _, e := range r.Affected {
		if e.status(v) == "affected" {
			return true
		}
	}
	return false
}

func (e Entry) status(v version) string {
	for _, rg := range e.Versions {
		if e.DefaultStatus == "unaffected" && rg.Version == "0" && rg.LessThan != "" {
			if upper, ok := parseVersion(rg.LessThan); !ok || !sameBranch(upper, v) {
				continue
			}
		}
		if rg.covers(v) {
			return rg.Status
		}
	}
	return e.DefaultStatus
}

func (rg Range) covers(v version) bool {
	lower, ok := parseVersion(rg.Version)
	if !ok {
		return false
	}
	if rg.LessThan == "" && rg.LessThanOrEqual == "" {
		return compare(v, lower) == 0
	}
	if compare(lower, v) > 0 {
		return false
	}
	if rg.LessThan != "" {
		return below(v, rg.LessThan)
	}
	return atMost(v, rg.LessThanOrEqual)
}

func below(v version, upper string) bool {
	if upper == "*" {
		return true
	}
	if p, ok := parsePrefix(upper); ok {
		return belowPrefix(v, p)
	}
	u, ok := parseVersion(upper)
	return ok && compare(v, u) < 0
}

func atMost(v version, upper string) bool {
	if upper == "*" {
		return true
	}
	if p, ok := parsePrefix(upper); ok {
		return atMostPrefix(v, p)
	}
	u, ok := parseVersion(upper)
	return ok && compare(v, u) <= 0
}

func (r Record) fixFor(v version) string {
	var best string
	var bestV version
	bestSame := false
	consider := func(s string) {
		f, ok := parseVersion(s)
		if !ok || compare(f, v) <= 0 || r.affects(f) {
			return
		}
		same := sameBranch(f, v)
		if best == "" || (same && !bestSame) || (same == bestSame && compare(f, bestV) < 0) {
			best, bestV, bestSame = s, f, same
		}
	}
	for _, e := range r.Affected {
		for _, rg := range e.Versions {
			switch {
			case rg.Status == "unaffected" && rg.LessThanOrEqual == "*":
				consider(rg.Version)
			case rg.Status == "unaffected" && strings.HasSuffix(rg.LessThanOrEqual, ".*"):
				if f, ok := parseVersion(rg.Version); ok && sameBranch(f, v) {
					consider(rg.Version)
				}
			case rg.Status == "affected" && rg.LessThan != "" && rg.covers(v):
				if f, ok := parseVersion(rg.LessThan); ok && sameBranch(f, v) {
					consider(rg.LessThan)
				}
			}
		}
	}
	return best
}
