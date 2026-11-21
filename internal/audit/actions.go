package audit

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
)

const (
	ActionKernel   = "kernel"
	ActionImage    = "image"
	ActionPackages = "packages"
	ActionAppDir   = "appdir"
	ActionBinary   = "binary"
)

// The limits of an action card's texts, in bytes of UTF-8, and of its lists. Zosia refuses a
// report that holds a longer text, so everything a card carries is cut to them.
const (
	MaxTitle      = 80
	MaxName       = 120
	MaxTarget     = 300
	MaxItemName   = 100
	MaxItems      = 20
	MaxChangeName = 100
	MaxVersion    = 80
	MaxAlso       = 120
	MaxAlsoLines  = 4
	MaxStepText   = 160
	MaxSteps      = 12
	MaxCommand    = 500
	MaxNote       = 200
	MaxSource     = 500
	MaxWhy        = 300
	// MaxCards is how many cards a report carries, the most urgent ones.
	MaxCards = 500

	maxChanges = 50
)

// Action is one thing a person updates in one go, with the findings that updating it is about.
type Action struct {
	ID          string       `json:"id"`
	Kind        string       `json:"kind"`
	Name        string       `json:"name"`
	Target      string       `json:"target,omitempty"`
	Items       []string     `json:"items"`
	MoreItems   int          `json:"moreItems,omitempty"`
	Changes     []Change     `json:"changes"`
	MoreChanges int          `json:"moreChanges,omitempty"`
	Steps       []Step       `json:"steps"`
	Counts      ActionCounts `json:"counts"`
}

// Change is one package inside the thing: the installed version and the lowest version that
// clears every fixable finding of it ("" when none has a fix).
type Change struct {
	Name    string `json:"name"`
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Clears  int    `json:"clears"`
	Unfixed int    `json:"unfixed"`
}

type Step struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

type ActionCounts struct {
	Findings       int `json:"findings"`
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
	KnownExploited int `json:"knownExploited"`
}

// Cut shortens s to at most n bytes on a character boundary; a cut text ends in "…".
func Cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const mark = "…"
	return strings.ToValidUTF8(s[:n-len(mark)], "") + mark
}

func ActionID(kind, key string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + key))
	return "a:" + hex.EncodeToString(sum[:6])
}

func (r remediation) actionOf(f Finding) (kind, key string) {
	if f.Source == "kernel-cna" || slices.Contains(f.Items, inventory.KernelItemID) {
		return ActionKernel, ActionKernel
	}
	switch r.origins[f.Origin].Kind {
	case inventory.OriginImage:
		return ActionImage, f.Origin
	case inventory.OriginAppDir:
		return ActionAppDir, f.Origin
	case inventory.OriginBinary:
		return ActionBinary, f.Origin
	}
	return ActionPackages, ActionPackages
}

// SetActions gives every finding of a its action, and a its actions.
func SetActions(family osrel.Family, inv *inventory.Inventory, a *Audit) {
	a.Actions = newRemediation(family, inv).actions(a.Findings, a.Upgrades)
}

// actions sets each finding's action and returns the actions, by name.
func (r remediation) actions(findings []Finding, upgrades []Upgrade) []Action {
	type acc struct {
		a        Action
		origins  []string
		findings []Finding
	}
	byID := map[string]*acc{}
	for i := range findings {
		f := &findings[i]
		kind, key := r.actionOf(*f)
		f.Action = ActionID(kind, key)
		a := byID[f.Action]
		if a == nil {
			a = &acc{a: Action{ID: f.Action, Kind: kind}}
			byID[f.Action] = a
		}
		if !slices.Contains(a.origins, f.Origin) {
			a.origins = append(a.origins, f.Origin)
		}
		a.findings = append(a.findings, *f)
	}
	out := []Action{}
	for _, acc := range byID {
		a := acc.a
		slices.Sort(acc.origins)
		o := r.origins[acc.origins[0]]
		users := r.users[o.ID]
		switch a.Kind {
		case ActionKernel:
			a.Name, a.Items = "Linux kernel", []string{inventory.KernelItemID}
		case ActionPackages:
			a.Name = "System packages"
			for _, id := range acc.origins {
				a.Items = append(a.Items, r.itemIDs(id)...)
			}
			slices.Sort(a.Items)
			a.Items = slices.Compact(a.Items)
		case ActionImage:
			a.Target, a.Items = imageName(o), r.itemIDs(o.ID)
			if len(users) == 1 {
				a.Name = users[0].Name
			} else {
				a.Name = imageShortName(a.Target)
			}
		case ActionAppDir:
			a.Name, a.Target, a.Items = o.Path, o.Path, r.itemIDs(o.ID)
		case ActionBinary:
			a.Name, a.Items = cmp.Or(first(o.Paths), o.ID), r.itemIDs(o.ID)
			a.Target = first(o.Paths)
		}
		if a.Items == nil {
			a.Items = []string{}
		}
		if len(a.Items) > MaxItems {
			a.MoreItems, a.Items = len(a.Items)-MaxItems, a.Items[:MaxItems]
		}
		all := changes(acc.findings, upgrades, a.Kind == ActionAppDir)
		a.Steps = r.steps(a.Kind, o, acc.origins, all)
		a.Changes = all
		if len(all) > maxChanges {
			a.MoreChanges, a.Changes = len(all)-maxChanges, all[:maxChanges]
		}
		for _, f := range acc.findings {
			a.Counts.Findings++
			switch f.Risk {
			case RiskCritical:
				a.Counts.Critical++
			case RiskHigh:
				a.Counts.High++
			case RiskMedium:
				a.Counts.Medium++
			default:
				a.Counts.Low++
			}
			if f.Vulnerability.KnownExploited {
				a.Counts.KnownExploited++
			}
		}
		out = append(out, a)
	}
	slices.SortFunc(out, func(x, y Action) int { return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.ID, y.ID)) })
	return out
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// imageShortName is an image reference's last path component, without its tag or digest.
func imageShortName(ref string) string {
	name := path.Base(ref)
	if i := strings.IndexAny(name, ":@"); i > 0 {
		name = name[:i]
	}
	return name
}

// changes gives one change per package name and installed version among an action's findings:
// those with a fix first, then by the highest risk tier, findings on the KEV list, findings
// cleared and name.
func changes(findings []Finding, upgrades []Upgrade, appDir bool) []Change {
	type key struct{ name, from string }
	type acc struct {
		c    Change
		typ  string
		to   string // under the comparison key
		tier int
		kev  int
	}
	byKey := map[key]*acc{}
	var keys []key
	for _, f := range findings {
		k := key{f.Package.Name, f.Package.Version}
		a := byKey[k]
		if a == nil {
			a = &acc{c: Change{Name: k.name, From: k.from}, typ: f.Package.Type, tier: len(Tiers)}
			byKey[k] = a
			keys = append(keys, k)
		}
		if i := slices.Index(Tiers, f.Risk); i >= 0 && i < a.tier {
			a.tier = i
		}
		if f.Vulnerability.KnownExploited {
			a.kev++
		}
		if u, ok := upgradeFor(upgrades, f); appDir && ok {
			a.c.To, a.to = u.Version, u.Version
			a.c.Clears++
			continue
		}
		above, cmpKey := fixesAbove(f)
		if f.Fix.State != "fixed" || len(above) == 0 {
			a.c.Unfixed++
			continue
		}
		a.c.Clears++
		if a.c.To == "" || compareVersions(a.typ, cmpKey(above[0]), a.to) > 0 {
			a.c.To, a.to = above[0], cmpKey(above[0])
		}
	}
	out := make([]Change, 0, len(keys))
	rank := map[Change][2]int{}
	for _, k := range keys {
		a := byKey[k]
		out = append(out, a.c)
		rank[a.c] = [2]int{a.tier, a.kev}
	}
	unfixed := func(c Change) int {
		if c.To == "" {
			return 1
		}
		return 0
	}
	slices.SortFunc(out, func(x, y Change) int {
		rx, ry := rank[x], rank[y]
		return cmp.Or(cmp.Compare(unfixed(x), unfixed(y)), cmp.Compare(rx[0], ry[0]), cmp.Compare(ry[1], rx[1]),
			cmp.Compare(y.Clears, x.Clears), cmp.Compare(x.Name, y.Name), cmp.Compare(x.From, y.From))
	})
	return out
}

// upgradeFor finds the verified upgrade line that covers a finding of an app directory.
func upgradeFor(upgrades []Upgrade, f Finding) (Upgrade, bool) {
	for _, u := range upgrades {
		if u.Origin == f.Origin && u.Type == f.Package.Type && u.Package == upgradeName(f.Package) && slices.Contains(u.Installed, f.Package.Version) {
			return u, true
		}
	}
	return Upgrade{}, false
}

// steps are an action's default instructions. o is its origin (the first of several for the
// system's packages).
func (r remediation) steps(kind string, o inventory.Origin, origins []string, all []Change) []Step {
	var steps []Step
	add := func(text, command string) {
		steps = append(steps, Step{Text: Cut(text, MaxStepText), Command: command})
	}
	restart := func() {
		if names := r.restartNames(origins...); len(names) > 0 {
			add("Restart "+list(names), "")
		}
	}
	switch kind {
	case ActionKernel:
		cmd := ""
		if o.Kind == inventory.OriginPackage || r.kernelPackaged() {
			cmd = r.systemUpgrade()
		}
		add("Upgrade the kernel", cmd)
		add("Reboot", "")
	case ActionPackages:
		var names []string
		for _, c := range all {
			if c.To != "" && !slices.Contains(names, c.Name) {
				names = append(names, c.Name)
			}
		}
		slices.Sort(names)
		cmd := ""
		if len(names) > 0 {
			cmd = r.packageUpgrade(strings.Join(names, " "))
		}
		if cmd == "" || len(cmd) > MaxCommand {
			cmd = r.systemUpgrade()
		}
		add("Upgrade the packages", cmd)
		restart()
	case ActionImage:
		add("Pull or rebuild "+imageName(o), "")
		users := slices.Clone(r.users[o.ID])
		slices.SortFunc(users, func(x, y inventory.Item) int { return cmp.Compare(x.Name, y.Name) })
		for i, it := range users {
			if it.Kind != inventory.KindContainer {
				continue
			}
			if len(steps) == MaxSteps-1 && len(users)-i > 1 {
				add(fmt.Sprintf("Recreate the other %d containers", len(users)-i), "")
				break
			}
			if cmd := composeRecreate(it.Compose); cmd != "" && len(cmd) <= MaxCommand {
				add("Recreate "+it.Name, cmd)
			} else {
				add("Recreate the container "+it.Name, "")
			}
		}
	case ActionAppDir:
		add("Upgrade the packages below in "+o.Path, "")
		restart()
	case ActionBinary:
		add("Replace or rebuild "+named(o.Paths, "the binary"), "")
		restart()
	}
	return steps
}
