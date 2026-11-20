package report

import (
	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

type JSONReport struct {
	Run      *run.Record       `json:"run"`
	Summary  *string           `json:"summary"`
	Findings []JSONFinding     `json:"findings"`
	Added    []review.Entry    `json:"added"`
	Coverage []JSONGap         `json:"coverage"`
	Errors   []problem.Problem `json:"errors"`

	Verdict   run.Verdict     `json:"verdict"`
	Host      *JSONHost       `json:"host"`
	Names     JSONNames       `json:"names"`
	Restarts  []JSONRestart   `json:"restarts"`
	Upgrades  []audit.Upgrade `json:"upgrades"`
	Freshness *JSONFreshness  `json:"freshness"`
}

type JSONFinding struct {
	audit.Finding
	Review any `json:"review"`
}

type JSONGap struct {
	Code    string `json:"code"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

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
	if in.Run.Verdict != nil {
		out.Verdict = *in.Run.Verdict
	} else {
		out.Verdict = Summarize(in) // a run from before 1.2.0: the caller fills in the line from report.md
	}
	out.Host = jsonHost(in.Inventory)
	out.Names = jsonNames(in.Inventory, in.Audit, out.Added)
	out.Restarts = jsonRestarts(in.Inventory)
	out.Upgrades = []audit.Upgrade{}
	if in.Audit != nil && in.Audit.Upgrades != nil {
		out.Upgrades = in.Audit.Upgrades
	}
	out.Freshness = jsonFreshness(in.Audit)
	return out
}
