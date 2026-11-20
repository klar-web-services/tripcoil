package report

import (
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const (
	VerdictIncomplete  = "incomplete"
	VerdictAuditOnly   = "audit_only"
	VerdictExploitable = "exploitable"
	VerdictConditional = "conditional"
	VerdictUnassessed  = "unassessed"
	VerdictClean       = "clean"
)

func reviewedReport(in Input) bool {
	return in.Review != nil && in.Audit != nil && in.Run.Status != run.Interrupted && in.Run.Stages["audit"] != run.StageFailed
}

// Summarize gives the verdict code and the counts the report's sections use, by the same rules as
// Render's verdict line. The line itself is Render's first line (see VerdictOf).
func Summarize(in Input) run.Verdict {
	c := map[string]int{"exploitable": 0, "conditional": 0, "conditionalLower": 0, "notExploitable": 0, "falsePositive": 0, "unassessed": 0}
	for _, t := range audit.Tiers {
		c[t] = 0
	}
	c["gaps"] = len(Gaps(in.Inventory, in.Audit, in.Facts))
	c["errors"] = len(in.Run.Errors)
	if in.Audit != nil {
		for _, f := range in.Audit.Findings {
			c[f.Risk]++
		}
	}
	v := run.Verdict{Counts: c}
	switch {
	case in.Run.Status == run.Interrupted || in.Audit == nil || in.Run.Stages["audit"] == run.StageFailed:
		v.Code = VerdictIncomplete
		return v
	case !reviewedReport(in):
		v.Code = VerdictAuditOnly
		return v
	}
	for _, e := range in.Review.Findings {
		switch {
		case e.Verdict == review.FalsePositive:
			c["falsePositive"]++
		case e.Exploitability == review.Exploitable:
			c["exploitable"]++
		case e.Exploitability == review.Conditional && (e.Priority == "now" || e.Priority == "soon"):
			c["conditional"]++
		case e.Exploitability == review.Conditional:
			c["conditionalLower"]++
		case e.Exploitability == review.NotExploitable:
			c["notExploitable"]++
		case e.Exploitability == review.Unknown:
			c["unassessed"]++
		}
	}
	ids := map[string]bool{}
	for _, f := range in.Audit.Findings {
		ids[f.ID] = true
	}
	for _, id := range in.Review.NotReviewed {
		if ids[id] {
			c["unassessed"]++
		}
	}
	switch {
	case c["exploitable"] > 0:
		v.Code = VerdictExploitable
	case c["conditional"] > 0:
		v.Code = VerdictConditional
	case c["unassessed"] > 0:
		v.Code = VerdictUnassessed
	default:
		v.Code = VerdictClean
	}
	return v
}

// VerdictOf is Summarize with the line taken from the rendered report.
func VerdictOf(in Input, md string) run.Verdict {
	v := Summarize(in)
	v.Line, _, _ = strings.Cut(md, "\n")
	return v
}
