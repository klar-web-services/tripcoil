package review

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// PromptVersion is the prompt's version. Change it with any change to the prompt
// or the schema: it is part of the change check's fingerprint.
const PromptVersion = "10"

// Prompt is the fixed task the agent gets. It holds no untrusted text: the agent reads the run's
// files itself.
//
//go:embed prompt.md
var Prompt string

// Schema is the JSON Schema of the agent's output, which both CLIs enforce. Every property is
// required and objects allow no others, as OpenAI's strict structured outputs demand; optional
// values are nullable instead.
//
//go:embed schema.json
var Schema []byte

const (
	Confirmed     = "confirmed"
	Corrected     = "corrected"
	FalsePositive = "false_positive"
	Added         = "added"

	Exploitable    = "exploitable"
	Conditional    = "conditional"
	NotExploitable = "not_exploitable"
	Unknown        = "unknown"
)

var (
	verdicts       = []string{Confirmed, Corrected, FalsePositive, Added}
	exploitability = []string{Exploitable, Conditional, NotExploitable, Unknown}
	priorities     = []string{"now", "soon", "scheduled", "none"}
)

type Review struct {
	SchemaVersion string  `json:"schemaVersion"`
	Summary       string  `json:"summary"`
	Findings      []Entry `json:"findings"`
	// Actions are the reviewer's texts for the audit's actions and for findings it added. A
	// review from before prompt 4 has none.
	Actions []ActionEntry `json:"actions"`
	// Reach is what the reviewer found out about who can reach each item, as it wrote it. A review
	// from before prompt 5 has none.
	Reach         []ReachEntry `json:"reach"`
	CoverageNotes []string     `json:"coverageNotes"`
	NotReviewed   []string     `json:"notReviewed"`
}

type Entry struct {
	FindingID      string       `json:"findingId"`
	Verdict        string       `json:"verdict"`
	Exploitability string       `json:"exploitability,omitempty"`
	Priority       string       `json:"priority,omitempty"`
	Reasoning      string       `json:"reasoning"`
	Evidence       []string     `json:"evidence,omitempty"`
	Fix            []string     `json:"fix,omitempty"`
	Sources        []string     `json:"sources,omitempty"`
	Corrections    []Correction `json:"corrections,omitempty"`
	Item           string       `json:"item,omitempty"`
	Vulnerability  string       `json:"vulnerability,omitempty"`
	// Vector says how the finding is attacked; empty when the reviewer did not say.
	Vector string `json:"vector,omitempty"`
	// Reach is set when the vulnerable part can be reached from fewer places than its item.
	Reach string `json:"reach,omitempty"`
	// Adjusted is set when ApplyReach lowered the finding.
	Adjusted *Adjusted `json:"adjusted,omitempty"`
}

type Correction struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
	Why   string `json:"why"`
}

func Load(runDir string) (*Review, error) {
	data, err := os.ReadFile(filepath.Join(runDir, "review.json"))
	if err != nil {
		return nil, err
	}
	var r Review
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func Carry(prev *Review, aud *audit.Audit, inv *inventory.Inventory) *Review {
	ids, items := findingIDs(aud), itemIDs(inv)
	out := &Review{SchemaVersion: "1", Summary: prev.Summary, Findings: []Entry{}, Actions: []ActionEntry{}, Reach: []ReachEntry{}, CoverageNotes: prev.CoverageNotes}
	if out.CoverageNotes == nil {
		out.CoverageNotes = []string{}
	}
	for _, e := range prev.Findings {
		if e.Verdict == Added && items[e.Item] || e.Verdict != Added && ids[e.FindingID] {
			out.Findings = append(out.Findings, e)
		}
	}
	known := actionPackages(aud)
	for _, e := range out.Findings {
		if e.Verdict == Added {
			known[e.FindingID] = nil
		}
	}
	for _, a := range prev.Actions {
		if _, ok := known[a.Action]; ok {
			out.Actions = append(out.Actions, a)
		}
	}
	for _, r := range prev.Reach {
		if items[r.Item] {
			out.Reach = append(out.Reach, r)
		}
	}
	out.NotReviewed = notReviewed(aud, out.Findings)
	return out
}

func findingIDs(aud *audit.Audit) map[string]bool {
	out := map[string]bool{}
	if aud != nil {
		for _, f := range aud.Findings {
			out[f.ID] = true
		}
	}
	return out
}

func itemIDs(inv *inventory.Inventory) map[string]bool {
	out := map[string]bool{}
	if inv != nil {
		for _, it := range inv.Items {
			out[it.ID] = true
		}
	}
	return out
}

func notReviewed(aud *audit.Audit, entries []Entry) []string {
	done := map[string]bool{}
	for _, e := range entries {
		done[e.FindingID] = true
	}
	out := []string{}
	if aud != nil {
		for _, f := range aud.Findings {
			if !done[f.ID] {
				out = append(out, f.ID)
			}
		}
	}
	slices.Sort(out)
	return out
}

func (r *Review) Index() map[string]Entry {
	out := map[string]Entry{}
	if r != nil {
		for _, e := range r.Findings {
			out[e.FindingID] = e
		}
	}
	return out
}
