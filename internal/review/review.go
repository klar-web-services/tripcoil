// Package review holds what the AI Review shares between the agent adapters: the prompt, the
// output schema, review.json, its validation, and carrying a review forward (spec section 8).
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

// PromptVersion is the prompt's version (spec section 8.4). Change it with any change to the prompt
// or the schema: it is part of the change check's fingerprint.
const PromptVersion = "2"

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

// Verdicts and the other values of review.json (spec section 8.5).
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

// Review is review.json.
type Review struct {
	SchemaVersion string   `json:"schemaVersion"`
	Summary       string   `json:"summary"`
	Findings      []Entry  `json:"findings"`
	CoverageNotes []string `json:"coverageNotes"`
	// NotReviewed lists the audit findings the agent did not address, by ID.
	NotReviewed []string `json:"notReviewed"`
}

// Entry is the review of one finding, or a finding the agent added.
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
	Item           string       `json:"item,omitempty"`          // added findings
	Vulnerability  string       `json:"vulnerability,omitempty"` // added findings
}

// Correction is one field the agent corrected.
type Correction struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
	Why   string `json:"why"`
}

// Load reads a run's review.json.
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

// Carry returns an earlier run's review for this run's findings (spec section 8.6): entries for
// findings that no longer exist, or added findings whose item no longer runs, are dropped, and the
// findings it does not address are not reviewed.
func Carry(prev *Review, aud *audit.Audit, inv *inventory.Inventory) *Review {
	ids, items := findingIDs(aud), itemIDs(inv)
	out := &Review{SchemaVersion: "1", Summary: prev.Summary, Findings: []Entry{}, CoverageNotes: prev.CoverageNotes}
	if out.CoverageNotes == nil {
		out.CoverageNotes = []string{}
	}
	for _, e := range prev.Findings {
		if e.Verdict == Added && items[e.Item] || e.Verdict != Added && ids[e.FindingID] {
			out.Findings = append(out.Findings, e)
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

// notReviewed lists the audit findings without an entry, sorted.
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

// Index maps finding IDs to their entries.
func (r *Review) Index() map[string]Entry {
	out := map[string]Entry{}
	if r != nil {
		for _, e := range r.Findings {
			out[e.FindingID] = e
		}
	}
	return out
}
