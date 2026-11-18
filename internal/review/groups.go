package review

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

type Groups struct {
	SchemaVersion string  `json:"schemaVersion"`
	Groups        []Group `json:"groups"`
}

type Group struct {
	ID             string     `json:"id"`
	Label          string     `json:"label"`
	Risk           RiskCounts `json:"risk"`
	KnownExploited int        `json:"knownExploited"`
	MaxEPSS        float64    `json:"maxEpss"`
	FixedIn        []string   `json:"fixedIn"`
	Items          []string   `json:"items"`
	Findings       []string   `json:"findings"`
}

type RiskCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

const kernelPrefix = "In the Linux kernel, the following vulnerability has been resolved:"

func GroupFindings(aud *audit.Audit, inv *inventory.Inventory) Groups {
	names := map[string]string{}
	if inv != nil {
		for _, it := range inv.Items {
			names[it.ID] = it.Name
		}
	}
	type acc struct {
		g        Group
		findings []*audit.Finding
	}
	byID := map[string]*acc{}
	for i := range aud.Findings {
		f := &aud.Findings[i]
		var id, label string
		if f.Source == "kernel-cna" || slices.Contains(f.Items, inventory.KernelItemID) {
			if s := subsystem(f.Vulnerability.Description); s != "" {
				id, label = "kernel:"+s, "Linux kernel "+s+" subsystem"
			} else {
				id, label = "kernel:other", "Linux kernel, subsystem not named in the description"
			}
		} else {
			sum := sha256.Sum256([]byte(f.Origin + "\x00" + f.Package.Name + "\x00" + f.Package.Version))
			id, label = "pkg:"+hex.EncodeToString(sum[:6]), f.Package.Name+" "+f.Package.Version
		}
		a := byID[id]
		if a == nil {
			a = &acc{g: Group{ID: id, Label: label}}
			byID[id] = a
		}
		a.findings = append(a.findings, f)
	}
	tier := func(f *audit.Finding) int { // an unknown tier sorts after low, where it is counted
		if i := slices.Index(audit.Tiers, f.Risk); i >= 0 {
			return i
		}
		return len(audit.Tiers)
	}
	out := Groups{SchemaVersion: "1", Groups: []Group{}}
	for _, a := range byID {
		g := &a.g
		slices.SortFunc(a.findings, func(x, y *audit.Finding) int { return cmp.Or(cmp.Compare(tier(x), tier(y)), cmp.Compare(x.ID, y.ID)) })
		var fixed, items []string
		for _, f := range a.findings {
			switch f.Risk {
			case audit.RiskCritical:
				g.Risk.Critical++
			case audit.RiskHigh:
				g.Risk.High++
			case audit.RiskMedium:
				g.Risk.Medium++
			default:
				g.Risk.Low++
			}
			if f.Vulnerability.KnownExploited {
				g.KnownExploited++
			}
			g.MaxEPSS = max(g.MaxEPSS, f.Vulnerability.EPSS)
			fixed = append(fixed, f.Fix.Versions...)
			items = append(items, f.Items...)
			g.Findings = append(g.Findings, f.ID)
		}
		slices.Sort(fixed)
		slices.Sort(items)
		g.FixedIn, g.Items = append([]string{}, slices.Compact(fixed)...), append([]string{}, slices.Compact(items)...)
		if strings.HasPrefix(g.ID, "pkg:") {
			g.Label += " in " + itemNames(g.Items, names)
		}
		out.Groups = append(out.Groups, *g)
	}
	best := func(g Group) int {
		switch {
		case g.Risk.Critical > 0:
			return 0
		case g.Risk.High > 0:
			return 1
		case g.Risk.Medium > 0:
			return 2
		}
		return 3
	}
	slices.SortFunc(out.Groups, func(x, y Group) int {
		return cmp.Or(cmp.Compare(best(x), best(y)), cmp.Compare(len(y.Findings), len(x.Findings)), cmp.Compare(x.ID, y.ID))
	})
	return out
}

func subsystem(desc string) string {
	rest, ok := strings.CutPrefix(desc, kernelPrefix)
	if !ok {
		return ""
	}
	head, _, ok := strings.Cut(strings.TrimSpace(rest), ":")
	if !ok {
		return ""
	}
	head, _, _ = strings.Cut(head, "/")
	if head == "" || strings.ContainsFunc(head, unicode.IsSpace) {
		return ""
	}
	return strings.ToLower(head)
}

func itemNames(ids []string, names map[string]string) string {
	if len(ids) == 0 {
		return "no item"
	}
	var out []string
	for _, id := range ids[:min(3, len(ids))] {
		out = append(out, cmp.Or(names[id], id))
	}
	s := strings.Join(out, ", ")
	if len(ids) > 3 {
		s += fmt.Sprintf(" and %d more", len(ids)-3)
	}
	return s
}
