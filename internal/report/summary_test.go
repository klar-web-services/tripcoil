package report

import (
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

var codeOfEmoji = map[string]string{"🔴": VerdictExploitable, "🟠": VerdictConditional, "🟡": VerdictUnassessed,
	"🟢": VerdictClean, "⚠️": VerdictAuditOnly, "⛔": VerdictIncomplete}

func checkVerdict(t *testing.T, name string, in Input) map[string]int {
	t.Helper()
	md := Render(in)
	v := VerdictOf(in, md)
	emoji, _, _ := strings.Cut(v.Line, " ")
	if want := codeOfEmoji[emoji]; v.Code != want || v.Line != strings.SplitN(md, "\n", 2)[0] {
		t.Errorf("%s: code %q for line %q", name, v.Code, v.Line)
	}
	return v.Counts
}

func TestVerdictCodeFollowsTheLine(t *testing.T) {
	ok := map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"}
	c := checkVerdict(t, "reviewed", Input{Run: record(ok), Inventory: hostInventory(), Audit: hostAudit(), Review: hostReview()})
	if c["exploitable"] == 0 || c["critical"]+c["high"]+c["medium"]+c["low"] != len(hostAudit().Findings) {
		t.Errorf("counts %v", c)
	}
	checkVerdict(t, "audit only", Input{Run: record(ok), Inventory: hostInventory(), Audit: hostAudit(), NoReview: "review.agent is none"})
	checkVerdict(t, "audit failed", Input{Run: record(map[string]string{"inventory": "ok", "audit": run.StageFailed},
		problem.New(problem.Error, problem.DBStale, "audit", "stale"))})
	interrupted := record(ok)
	interrupted.Status = run.Interrupted
	checkVerdict(t, "interrupted", Input{Run: interrupted, Inventory: hostInventory(), Audit: hostAudit(), Review: hostReview()})

	lower := hostReview()
	lower.Findings = append(lower.Findings[:0:0], lower.Findings...)
	for i := range lower.Findings {
		if lower.Findings[i].Exploitability == review.Exploitable {
			lower.Findings[i].Exploitability, lower.Findings[i].Priority = review.Conditional, "scheduled"
		}
	}
	c = checkVerdict(t, "lower", Input{Run: record(ok), Inventory: hostInventory(), Audit: hostAudit(), Review: lower})
	if c["exploitable"] != 0 || c["conditionalLower"] == 0 {
		t.Errorf("counts %v", c)
	}
}
