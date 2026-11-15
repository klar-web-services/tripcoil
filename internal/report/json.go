package report

import (
	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// JSONReport is `tripcoil report --json` (spec section 9).
type JSONReport struct {
	Run      *run.Record       `json:"run"`
	Summary  *string           `json:"summary"` // the review's; null without a review
	Findings []JSONFinding     `json:"findings"`
	Added    []review.Entry    `json:"added"`
	Coverage []JSONGap         `json:"coverage"`
	Errors   []problem.Problem `json:"errors"`
}

// JSONFinding is an audit finding with its review entry: null without a review, and
// {"verdict": "not_reviewed"} for a finding the review did not address.
type JSONFinding struct {
	audit.Finding
	Review any `json:"review"`
}

// JSONGap is one coverage gap.
type JSONGap struct {
	Code    string `json:"code"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

// JSON builds `tripcoil report --json` from what a run produced.
func JSON(in Input) JSONReport {
	out := JSONReport{Run: in.Run, Findings: []JSONFinding{}, Added: []review.Entry{}, Coverage: []JSONGap{}, Errors: in.Run.Errors}
	if out.Errors == nil {
		out.Errors = []problem.Problem{}
	}
	entries := in.Review.Index()
	if in.Review != nil {
		out.Summary = &in.Review.Summary
		for _, e := range in.Review.Findings {
			if e.Verdict == review.Added {
				out.Added = append(out.Added, e)
			}
		}
	}
	if in.Audit != nil {
		for _, f := range in.Audit.Findings {
			jf := JSONFinding{Finding: f}
			if in.Review != nil {
				if e, ok := entries[f.ID]; ok {
					jf.Review = e
				} else {
					jf.Review = map[string]string{"verdict": "not_reviewed"}
				}
			}
			out.Findings = append(out.Findings, jf)
		}
	}
	for _, g := range Gaps(in.Inventory, in.Audit, in.Facts) {
		out.Coverage = append(out.Coverage, JSONGap{Code: g.Code, Subject: g.Subject, Detail: g.Detail})
	}
	return out
}
