package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

type upgradeCandidate struct {
	Upgrade
	name  string
	check []component
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	CPE     string `json:"cpe,omitempty"`
}

func upgradeCandidates(findings []Finding) []upgradeCandidate {
	type key struct{ origin, typ, purl, name string }
	groups := map[key][]Finding{}
	var keys []key
	for _, f := range findings {
		if !strings.HasPrefix(f.Origin, "appdir:") {
			continue
		}
		k := key{origin: f.Origin, typ: f.Package.Type}
		if f.Package.PURL != "" {
			k.purl = purlWithoutVersion(f.Package.PURL)
		} else {
			k.name = f.Package.Name
		}
		if _, seen := groups[k]; !seen {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], f)
	}
	var out []upgradeCandidate
	for _, k := range keys {
		fs := groups[k]
		if v, ok := upgradeVersion(fs); ok {
			out = append(out, upgradeCandidate{
				Upgrade: Upgrade{Origin: k.origin, Path: strings.TrimPrefix(k.origin, "appdir:"), Package: upgradeName(fs[0].Package), Type: k.typ,
					Installed: installedVersions(fs), Version: v, Findings: len(fs)},
				name:  fs[0].Package.Name,
				check: matchAt(fs, v),
			})
		}
	}
	slices.SortStableFunc(out, func(a, b upgradeCandidate) int {
		return cmp.Or(cmp.Compare(b.Findings, a.Findings), cmp.Compare(a.Path, b.Path), cmp.Compare(a.Package, b.Package), cmp.Compare(a.Type, b.Type))
	})
	return out
}

// upgradeName names a package in an upgrade line: by its name, but a Maven package as
// groupId:artifactId from its purl, because Grype names it by the artifactId alone.
func upgradeName(p Package) string {
	coords, ok := strings.CutPrefix(purlWithoutVersion(p.PURL), "pkg:maven/")
	i := strings.LastIndexByte(coords, '/')
	if !ok || i < 0 {
		return p.Name
	}
	group, err1 := url.PathUnescape(coords[:i])
	artifact, err2 := url.PathUnescape(coords[i+1:])
	if err1 != nil || err2 != nil {
		return p.Name
	}
	return group + ":" + artifact
}

func installedVersions(findings []Finding) []string {
	var out []string
	for _, f := range findings {
		if !slices.Contains(out, f.Package.Version) {
			out = append(out, f.Package.Version)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		x, _ := parseSemver(a)
		y, _ := parseSemver(b)
		return cmp.Or(compareSemver(x, y), strings.Compare(a, b))
	})
	return out
}

func matchAt(findings []Finding, version string) []component {
	var out []component
	for _, f := range findings {
		purl, ok := purlWithVersion(f.Package.PURL, version)
		if !ok || (f.Source == "nvd:cpe" && len(f.Package.CPEs) == 0) {
			return nil
		}
		comps := []component{{Type: "library", Name: f.Package.Name, Version: version, PURL: purl}}
		if len(f.Package.CPEs) > 0 {
			comps = nil
		}
		for _, cpe := range f.Package.CPEs {
			c, ok := cpeWithVersion(cpe, version)
			if !ok {
				return nil
			}
			comps = append(comps, component{Type: "library", Name: f.Package.Name, Version: version, PURL: purl, CPE: c})
		}
		for _, c := range comps {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

func cpeWithVersion(cpe, version string) (string, bool) {
	var fields []string
	start := 0
	for i := 0; i < len(cpe); i++ {
		switch cpe[i] {
		case '\\':
			i++
		case ':':
			fields = append(fields, cpe[start:i])
			start = i + 1
		}
	}
	fields = append(fields, cpe[start:])
	if len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(version); i++ {
		c := version[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '.' || c == '-' || c == '_') {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	fields[5] = b.String()
	return strings.Join(fields, ":"), true
}

// purlVersion finds the version of a purl: after the last @ before the qualifiers (?) and the
// subpath (#). The @ of an npm scope is percent-encoded, so it is never taken for it.
func purlVersion(purl string) (start, end int, ok bool) {
	end = len(purl)
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		end = i
	}
	at := strings.LastIndexByte(purl[:end], '@')
	return at + 1, end, at >= 0
}

func purlWithoutVersion(purl string) string {
	start, end, ok := purlVersion(purl)
	if ok {
		return purl[:start-1]
	}
	return purl[:end]
}

func purlWithVersion(purl, version string) (string, bool) {
	start, end, ok := purlVersion(purl)
	if !ok {
		return "", false
	}
	return purl[:start] + strings.ReplaceAll(version, "+", "%2B") + purl[end:], true
}

func (au *auditor) checkUpgrades(ctx context.Context, cands []upgradeCandidate) []Upgrade {
	byPURL := map[string][]int{}
	seen := map[component]bool{}
	var comps []component
	for i, c := range cands {
		for _, p := range c.check {
			if !seen[p] {
				seen[p] = true
				comps = append(comps, p)
			}
			byPURL[p.PURL] = append(byPURL[p.PURL], i)
		}
	}
	out := []Upgrade{}
	if len(comps) == 0 {
		return out
	}
	rep, err := au.matchUpgrades(ctx, comps)
	switch {
	case ctx.Err() != nil:
		return out
	case err != nil:
		au.a.Warnings = append(au.a.Warnings, problem.New(problem.Warning, problem.UpgradeCheckFailed, "audit",
			"the upgrade lines could not be checked with Grype, so none are given: %v", err))
		return out
	}
	matched := make([]bool, len(cands))
	for _, m := range rep.Matches {
		if is, ok := byPURL[m.Artifact.PURL]; ok {
			for _, i := range is {
				matched[i] = true
			}
			continue
		}
		for i, c := range cands {
			matched[i] = matched[i] || (c.Type == m.Artifact.Type && c.name == m.Artifact.Name)
		}
	}
	for i, c := range cands {
		if c.check != nil && !matched[i] {
			out = append(out, c.Upgrade)
		}
	}
	return out
}

func (au *auditor) matchUpgrades(ctx context.Context, comps []component) (*grype.Report, error) {
	doc := struct {
		BOMFormat   string      `json:"bomFormat"`
		SpecVersion string      `json:"specVersion"`
		Components  []component `json:"components"`
	}{BOMFormat: "CycloneDX", SpecVersion: "1.5", Components: comps}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(au.scanDir(), 0o700); err != nil {
		return nil, err
	}
	sbom := filepath.Join(au.scanDir(), "upgrades.cdx.json")
	if err := os.WriteFile(sbom, data, 0o600); err != nil {
		return nil, err
	}
	return au.d.Grype.Match(ctx, sbom, filepath.Join(au.scanDir(), "upgrades.grype.json"), true)
}

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
				ambiguous = true
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

type semver struct {
	core [3]string
	pre  []string
}

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

func compareSemver(a, b semver) int {
	for i := range a.core {
		if c := compareDecimal(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	if len(a.pre) == 0 || len(b.pre) == 0 {
		return cmp.Compare(len(b.pre), len(a.pre))
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
