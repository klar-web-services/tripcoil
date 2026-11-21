package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/review"
)

// MaxReachLines is how many lines of "Who can reach what" a report carries: the widest.
const MaxReachLines = 200

// Where a reach line's value comes from.
const (
	ReachFromReview  = "review"
	ReachFromDefault = "default"
	ReachFromConfig  = "config"
)

// ReachLine says from where one item can be reached, and how the report knows.
type ReachLine struct {
	Item     string `json:"item"`
	From     string `json:"from"`
	Via      string `json:"via,omitempty"`
	Source   string `json:"source"`
	Evidence string `json:"evidence,omitempty"`
}

// reachOrder sorts the widest first; what is not established comes right after the internet,
// because it may be that.
func reachOrder(from string) int {
	if from == facts.ReachUnknown {
		return 2*facts.ReachRank(facts.ReachInternet) - 1
	}
	return 2 * facts.ReachRank(from)
}

// Reaches lists who can reach what: the reviewer's entry for an item where there is one, else
// Tripcoil's default, which was never reviewed and counts as not established while it is unsure.
// An item that nothing can reach and the reviewer did not look at is left out.
func Reaches(in Input) []ReachLine {
	out := []ReachLine{}
	names := itemNamesByID(in.Inventory)
	name := func(id string) string { return audit.Cut(cmp.Or(names[id], id), audit.MaxName) }
	seen, stated := map[string]bool{}, map[string]bool{}
	if in.Reach != nil {
		for _, d := range in.Reach.Items {
			stated[d.Item] = d.Stated
		}
	}
	if reviewedReport(in) {
		established := review.Established(in.Review, in.Reach)
		for _, e := range in.Review.Reach {
			l := ReachLine{Item: name(e.Item), From: facts.ReachUnknown, Source: ReachFromReview}
			if est, ok := established[e.Item]; ok {
				l.From, l.Via = est.From, est.Via
			}
			if len(e.Evidence) > 0 {
				l.Evidence = e.Evidence[0]
			}
			if stated[e.Item] && l.From != e.From && e.From != facts.ReachUnknown { // the owner's statement held the reviewer's entry back
				l.Via, l.Source = facts.ViaDirect, ReachFromConfig
				l.Evidence = "exposure.internetPorts does not list its ports; the reviewer said " + e.From
			}
			seen[e.Item] = true
			out = append(out, l)
		}
	}
	if in.Reach != nil {
		for _, d := range in.Reach.Items {
			if seen[d.Item] || d.Default == facts.ReachNone && d.Unsure == "" {
				continue
			}
			l := ReachLine{Item: name(d.Item), From: d.Default, Via: d.Via, Source: ReachFromDefault, Evidence: d.Unsure}
			if d.Unsure != "" { // it may be published further than its sockets say
				l.From, l.Via = facts.ReachUnknown, ""
			} else if d.Stated {
				l.Source = ReachFromConfig
			}
			if l.Evidence == "" && len(d.Sockets) > 0 {
				s := d.Sockets[0]
				l.Evidence = fmt.Sprintf("%s %s port %d", s.Proto, cmp.Or(s.Address, "every address"), s.Port)
			}
			l.Evidence = audit.Cut(oneLine(l.Evidence), review.MaxEvidenceLine)
			out = append(out, l)
		}
	}
	slices.SortStableFunc(out, func(x, y ReachLine) int {
		return cmp.Or(cmp.Compare(reachOrder(y.From), reachOrder(x.From)), cmp.Compare(x.Item, y.Item))
	})
	return out[:min(len(out), MaxReachLines)]
}

// cardReach is the reach of a card's items together: the internet when any of them is established
// as that, unknown when any is not established, otherwise the widest. An item that listens nowhere
// counts as unreachable here while no proxy or tunnel runs that could publish it, unless the
// reviewer wrote an entry for it (asked) that established nothing.
func cardReach(items []string, established map[string]review.ReachEntry, def *facts.Reach, asked map[string]bool) (from, via string) {
	from = facts.ReachNone
	unknown := len(items) == 0
	for _, item := range items {
		e, ok := established[item]
		if !ok {
			if asked[item] || def == nil || len(def.Routers) > 0 || slices.ContainsFunc(def.Items, func(d facts.ItemReach) bool { return d.Item == item }) {
				unknown = true
			}
			continue
		}
		if facts.ReachRank(e.From) > facts.ReachRank(from) {
			from, via = e.From, e.Via
		}
	}
	if unknown && from != facts.ReachInternet {
		return facts.ReachUnknown, ""
	}
	return from, via
}

var reachWords = map[string]string{
	facts.ReachInternet:  "reachable from the internet",
	facts.ReachLAN:       "reachable from the LAN",
	facts.ReachTailnet:   "reachable from the tailnet only",
	facts.ReachLocalhost: "reachable from this machine only",
	facts.ReachNone:      "not reachable from outside",
	facts.ReachUnknown:   "reach not established",
}

var viaWords = map[string]string{
	facts.ViaProxy: " through a proxy", facts.ViaTunnel: " through a tunnel", facts.ViaForward: " through a port forward",
}

var reachSources = map[string]string{
	ReachFromReview: "the reviewer", ReachFromDefault: "Tripcoil's default, not reviewed", ReachFromConfig: "the owner's statement",
}

func writeReaches(b *strings.Builder, lines []ReachLine) {
	if len(lines) == 0 {
		return
	}
	b.WriteString("## Who can reach what\n\n")
	for _, l := range lines {
		fmt.Fprintf(b, "- %s: %s%s (%s)", md(l.Item), reachWords[l.From], viaWords[l.Via], reachSources[l.Source])
		if l.Evidence != "" {
			b.WriteString(": " + md(l.Evidence))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

// lowered says what the reach rule did to a finding, or nothing.
func lowered(e review.Entry) string {
	if e.Adjusted == nil {
		return ""
	}
	return fmt.Sprintf("Lowered by Tripcoil: %s; the reviewer said %s, %s", reachWords[e.Adjusted.Rule], strings.ReplaceAll(e.Adjusted.Exploitability, "_", " "), e.Adjusted.Priority)
}
