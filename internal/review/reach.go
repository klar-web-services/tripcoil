package review

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// How a finding is attacked. Only an inbound one depends on who can connect to the item.
const (
	VectorInbound = "inbound"
	VectorContent = "content"
	VectorLocal   = "local"
)

const (
	maxReachEvidence = 3
	// MaxEvidenceLine bounds one evidence line of a reach entry, in bytes.
	MaxEvidenceLine = 200
)

var (
	vectors = []string{VectorInbound, VectorContent, VectorLocal}
	froms   = []string{facts.ReachInternet, facts.ReachLAN, facts.ReachTailnet, facts.ReachLocalhost, facts.ReachNone, facts.ReachUnknown}
	vias    = []string{facts.ViaDirect, facts.ViaProxy, facts.ViaTunnel, facts.ViaForward}
	// narrower are the values a finding's own reach may have: fewer places than its item.
	narrower = []string{facts.ReachLAN, facts.ReachTailnet, facts.ReachLocalhost, facts.ReachNone}
)

// ReachEntry is what the reviewer found out about one item: from where it can be reached, and how
// it knows.
type ReachEntry struct {
	Item     string   `json:"item"`
	From     string   `json:"from"`
	Via      string   `json:"via,omitempty"`
	Evidence []string `json:"evidence"`
}

// Adjusted keeps what the reviewer said about a finding that Tripcoil lowered, and the reach it was
// lowered for.
type Adjusted struct {
	Exploitability string `json:"exploitability"`
	Priority       string `json:"priority"`
	Rule           string `json:"rule"`
}

var reachKeys = []string{"item", "from", "via", "evidence"}

func decodeReach(raw json.RawMessage) (ReachEntry, error) {
	if err := keysOf("a reach entry", raw, reachKeys); err != nil {
		return ReachEntry{}, err
	}
	var a struct {
		Item     string   `json:"item"`
		From     string   `json:"from"`
		Via      *string  `json:"via"`
		Evidence []string `json:"evidence"`
	}
	if err := strict(raw, &a); err != nil {
		return ReachEntry{}, err
	}
	e := ReachEntry{Item: a.Item, From: a.From, Evidence: a.Evidence}
	if a.Via != nil {
		e.Via = *a.Via
	}
	return e, nil
}

// tidy checks an entry's values and cuts its evidence. It says why when the entry cannot be used:
// a reach without evidence establishes nothing.
func (e *ReachEntry) tidy() string {
	switch {
	case !slices.Contains(froms, e.From):
		return fmt.Sprintf("from %q is not one of %s", e.From, strings.Join(froms, ", "))
	case e.Via != "" && !slices.Contains(vias, e.Via):
		return fmt.Sprintf("via %q is not one of %s", e.Via, strings.Join(vias, ", "))
	}
	var lines []string
	for _, l := range e.Evidence {
		if l = oneLine(l, MaxEvidenceLine); l != "" && len(lines) < maxReachEvidence {
			lines = append(lines, l)
		}
	}
	if e.Evidence = lines; len(lines) == 0 {
		return "it has no evidence"
	}
	return ""
}

// Established is each item's reach as far as the review settled it: the reviewer's entries that
// say where from. Where the owner stated the machine's public ports, an entry may narrow the
// item's default but not widen it through the machine's own ports. An item that is missing here
// has no established reach, whatever its default.
func Established(rev *Review, def *facts.Reach) map[string]ReachEntry {
	out := map[string]ReachEntry{}
	if rev == nil || def == nil {
		return out
	}
	stated, unsure := map[string]string{}, map[string]bool{}
	for _, d := range def.Items {
		if d.Stated {
			stated[d.Item] = d.Default
		}
		unsure[d.Item] = d.Unsure != ""
	}
	for _, e := range rev.Reach {
		if e.From == facts.ReachUnknown {
			continue
		}
		if limit, ok := stated[e.Item]; ok && e.Via != facts.ViaProxy && e.Via != facts.ViaTunnel && facts.ReachRank(e.From) > facts.ReachRank(limit) {
			// The reviewer saw the item further out than the owner's ports allow. While a proxy or
			// tunnel may publish it, that is no ground to call it narrow: nothing is established.
			if unsure[e.Item] {
				continue
			}
			e.From, e.Via = limit, facts.ViaDirect
		}
		out[e.Item] = e
	}
	return out
}

// ApplyReach lowers the findings that need a connection nobody outside can make, and says how many
// it changed. It only acts on an inbound finding whose items all have an established reach, never on
// a default or on missing information, and never on the kernel's findings. It starts from what the
// reviewer said, so applying it again, after a carry-forward or with another exposure.lan, gives the
// same result as applying it once.
func ApplyReach(rev *Review, aud *audit.Audit, def *facts.Reach, lan string) int {
	if rev == nil {
		return 0
	}
	for i := range rev.Findings {
		if e := &rev.Findings[i]; e.Adjusted != nil {
			e.Exploitability, e.Priority, e.Adjusted = e.Adjusted.Exploitability, e.Adjusted.Priority, nil
		}
	}
	if def == nil || aud == nil {
		return 0
	}
	established := Established(rev, def)
	kernel, kernelItems := map[string]bool{}, map[string]bool{inventory.KernelItemID: true}
	for _, a := range aud.Actions {
		if a.Kind == audit.ActionKernel {
			kernel[a.ID] = true
			for _, item := range a.Items {
				kernelItems[item] = true
			}
		}
	}
	itemsOf := map[string][]string{}
	for _, f := range aud.Findings {
		if !kernel[f.Action] {
			itemsOf[f.ID] = f.Items
		}
	}
	changed := 0
	for i := range rev.Findings {
		e := &rev.Findings[i]
		if e.Vector != VectorInbound || (e.Exploitability != Exploitable && e.Exploitability != Conditional) {
			continue
		}
		items := itemsOf[e.FindingID]
		if e.Verdict == Added {
			items = []string{e.Item}
		}
		if slices.ContainsFunc(items, func(item string) bool { return kernelItems[item] }) {
			continue
		}
		reach, ok := facts.ReachNone, len(items) > 0
		for _, item := range items {
			r, known := established[item]
			if ok = ok && known; facts.ReachRank(r.From) > facts.ReachRank(reach) {
				reach = r.From
			}
		}
		if !ok {
			continue
		}
		if slices.Contains(narrower, e.Reach) && len(e.Evidence) > 0 && facts.ReachRank(e.Reach) <= facts.ReachRank(reach) {
			reach = e.Reach
		}
		was := Adjusted{Exploitability: e.Exploitability, Priority: e.Priority, Rule: reach}
		switch {
		case reach == facts.ReachInternet, reach == facts.ReachLAN && lan == config.LANUntrusted:
			continue
		case reach == facts.ReachLAN && lan != config.LANTrusted:
			e.Exploitability = Conditional
			if e.Priority == "now" || e.Priority == "soon" {
				e.Priority = "scheduled"
			}
		default:
			e.Exploitability, e.Priority = NotExploitable, "none"
		}
		if e.Exploitability != was.Exploitability || e.Priority != was.Priority {
			e.Adjusted = &was
			changed++
		}
	}
	return changed
}
