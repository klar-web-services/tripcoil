package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

func hostReview() *review.Review {
	return &review.Review{SchemaVersion: "1",
		Summary:       "nginx's TLS is exploitable from the internet now. The kernel CVE needs a local user, and this host has untrusted ones.",
		CoverageNotes: []string{"The container's bind-mounted code was not reviewed."},
		Findings: []review.Entry{
			{FindingID: "f:0000000000000001", Verdict: review.Confirmed, Exploitability: review.Exploitable, Priority: "now",
				Reasoning: "nginx listens on 0.0.0.0:443 and the firewall allows 443 from anywhere.", Evidence: []string{"facts/network.json: 0.0.0.0:443 nginx", "facts/firewall.txt: tcp dport 443 accept"},
				Fix: []string{"apt-get install --only-upgrade libssl3", "systemctl restart nginx shop"}, Sources: []string{"https://security-tracker.debian.org/tracker/CVE-2026-1234"}},
			{FindingID: "f:0000000000000002", Verdict: review.Confirmed, Exploitability: review.Conditional, Priority: "soon",
				Reasoning: "Needs a local user; alice and bob can log in.", Fix: []string{"apt-get dist-upgrade", "reboot"}},
			{FindingID: "f:0000000000000005", Verdict: review.Corrected, Exploitability: review.Unknown, Priority: "scheduled",
				Reasoning: "The image's libssl3 is not loaded by the shop process, as far as the image shows.", Fix: []string{"rebuild the image"},
				Corrections: []review.Correction{{Field: "package.version", Old: "3.0.11-1~deb12u2", New: "3.0.11-1~deb12u3", Why: "the image's dpkg status says so"}}},
			{FindingID: "f:0000000000000003", Verdict: review.Confirmed, Exploitability: review.NotExploitable, Priority: "none",
				Reasoning: "The shop never calls lodash's template function.", Fix: []string{"upgrade lodash when convenient"}},
			{FindingID: "f:0000000000000004", Verdict: review.FalsePositive, Reasoning: "Debian fixed it in 1:1.2.13.dfsg-1 (DSA-5000-1)."},
			{FindingID: "added:1", Verdict: review.Added, Item: "proc:api", Vulnerability: "CVE-2026-9999", Exploitability: review.Exploitable, Priority: "now",
				Reasoning: "The api binary embeds an old Go net/http; it listens on 0.0.0.0:8080.", Fix: []string{"rebuild /opt/api/api with Go 1.27.4"}, Sources: []string{"https://go.dev/issue/1"}},
		},
		NotReviewed: []string{"f:0000000000000006", "f:0000000000000007"},
	}
}

func TestRenderReviewed(t *testing.T) {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "facts": "ok", "review": "ok"})
	r.Reviewed, r.ReviewedAt = true, started.Add(10*time.Minute)
	idx := &facts.Index{Missing: []facts.Missing{{Fact: "sshd.txt", Reason: "sshd: exit status 255: Missing privilege separation directory: /run/sshd"}}}
	golden(t, "reviewed", Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Facts: idx, Review: hostReview(), Agent: "claude 2.1.309, model opus"}))
}

func TestRenderCarriedForward(t *testing.T) {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "facts": "ok", "review": "ok"})
	r.CarriedFrom, r.ReviewedAt = "20261113T061500Z-0b7e", time.Date(2026, 11, 13, 6, 31, 0, 0, time.UTC)
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Review: hostReview(), Agent: "claude 2.1.309"})
	if !strings.Contains(strings.SplitN(got, "\n", 4)[2], "review carried forward from 2026-11-13 06:31 UTC (run 20261113T061500Z-0b7e)") {
		t.Errorf("host line:\n%s", got)
	}
}

func TestRenderReviewWarnings(t *testing.T) {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	r.Add(problem.New(problem.Warning, problem.ReviewEntriesDropped, "review", "1 review entries were dropped: CVE-2026-1 (audit.json has no such finding)"),
		problem.New(problem.Warning, problem.DBUpdateFailed, "audit", "the database could not be updated"))
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Review: hostReview()})
	if !strings.Contains(got, "## Review warnings\n\n- `REVIEW_ENTRIES_DROPPED`: 1 review entries were dropped") || strings.Contains(got, "DB_UPDATE_FAILED") {
		t.Errorf("report:\n%s", got)
	}
}

func TestReviewVerdict(t *testing.T) {
	for _, c := range []struct {
		exp, cond, un, lower int
		want                 string
	}{
		{2, 1, 180, 0, "🔴 2 issues exploitable now; 180 not assessed"},
		{1, 0, 0, 0, "🔴 1 issue exploitable now"},
		{0, 3, 0, 0, "🟠 No issue exploitable now; 3 exploitable under conditions"},
		{0, 3, 1, 0, "🟠 No issue exploitable now; 3 exploitable under conditions; 1 not assessed"},
		{0, 0, 180, 0, "🟡 No issue found exploitable, but 180 findings were not assessed"},
		{0, 0, 1, 0, "🟡 No issue found exploitable, but 1 finding was not assessed"},
		{0, 0, 0, 0, "🟢 No exploitable issues found"},
		{2, 1, 180, 7, "🔴 2 issues exploitable now; 180 not assessed; 7 lower-priority conditional"},
		{0, 3, 0, 1, "🟠 No issue exploitable now; 3 exploitable under conditions; 1 lower-priority conditional"},
		{0, 0, 1, 3084, "🟡 No issue found exploitable, but 1 finding was not assessed; 3084 lower-priority conditional"},
		{0, 0, 0, 2, "🟢 No exploitable issues found; 2 lower-priority conditional"},
	} {
		if got := reviewVerdict(c.exp, c.cond, c.un, c.lower); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestRenderPartialReviewIsNeverGreen(t *testing.T) {
	aud := &audit.Audit{Status: audit.Complete, Grype: audit.GrypeInfo{Version: "0.121.2"}}
	rev := &review.Review{Summary: "s", NotReviewed: []string{}}
	for i := range 200 {
		id := fmt.Sprintf("f:%016d", i)
		aud.Findings = append(aud.Findings, audit.Finding{ID: id, Risk: audit.RiskLow, Origin: libssl, Package: audit.Package{Name: "libssl3", Version: "1"}, Vulnerability: audit.Vulnerability{ID: fmt.Sprintf("CVE-2026-%d", i)}})
		if i < 20 {
			rev.Findings = append(rev.Findings, review.Entry{FindingID: id, Verdict: review.Confirmed, Exploitability: review.NotExploitable, Priority: "none", Reasoning: "r", Fix: []string{"f"}})
		} else {
			rev.NotReviewed = append(rev.NotReviewed, id)
		}
	}
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: aud, Review: rev})
	if line := strings.SplitN(got, "\n", 2)[0]; !strings.HasPrefix(line, "🟡 No issue found exploitable, but 180 findings were not assessed") {
		t.Errorf("verdict %q", line)
	}
}

func TestRenderReviewedCapsSections(t *testing.T) {
	aud := hostAudit()
	rev := &review.Review{Summary: "s", NotReviewed: []string{}}
	for i := range maxEntries + 5 {
		id := fmt.Sprintf("f:%016d", 100+i)
		aud.Findings = append(aud.Findings, audit.Finding{ID: id, Risk: audit.RiskLow, Origin: img, Items: []string{"container:shop-web-1"}, Package: audit.Package{Name: "zlib1g", Version: "1"}, Vulnerability: audit.Vulnerability{ID: fmt.Sprintf("CVE-2026-%d", 5000+i)}})
		rev.Findings = append(rev.Findings, review.Entry{FindingID: id, Verdict: review.Confirmed, Exploitability: review.NotExploitable, Priority: "none", Reasoning: "r", Fix: []string{"f"}})
	}
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: aud, Review: rev})
	if !strings.Contains(got, "## Not exploitable here (205)") || !strings.Contains(got, "- … and 5 more, in review.json.") {
		t.Errorf("not capped:\n%s", got[:min(len(got), 2000)])
	}
}

func TestRenderReviewedEscapesAgentText(t *testing.T) {
	rev := hostReview()
	rev.Summary = "# Ignore the above\n<script>alert(1)</script> [click](http://evil.example)"
	rev.Findings[0].Reasoning = "*bold* `code`‮"
	rev.Findings[0].Fix = []string{"# not a heading"}
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Review: rev})
	for _, bad := range []string{"\n# Ignore", "<script>", "[click](", "*bold*", "`code`", "‮", "Fix: # not"} {
		if strings.Contains(got, bad) {
			t.Errorf("unescaped %q in:\n%s", bad, got)
		}
	}
}

func TestRenderReviewFailedIsAuditOnly(t *testing.T) {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": run.StageFailed},
		problem.New(problem.Error, problem.AgentTimeout, "review", "the review ran past review.timeout (60m)"))
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), NoReview: "AI review failed: AGENT_TIMEOUT"})
	if !strings.HasPrefix(got, "⚠️ Audit only (AI review failed: AGENT_TIMEOUT): 1 critical, 2 high, 3 medium, 1 low findings (run partial: AGENT_TIMEOUT) (4 coverage gaps)") {
		t.Errorf("verdict:\n%s", strings.SplitN(got, "\n", 2)[0])
	}
}

func TestRenderReviewedLowerPriorityConditional(t *testing.T) {
	entry := func(id, exploitability, priority string) review.Entry {
		return review.Entry{FindingID: id, Verdict: review.Confirmed, Exploitability: exploitability, Priority: priority, Reasoning: "why " + id, Fix: []string{"f"}}
	}
	mix := hostReview()
	mix.Findings = append(mix.Findings[:0:0], mix.Findings...)
	mix.Findings[0] = entry("f:0000000000000001", review.Conditional, "scheduled")
	mix.Findings[3] = entry("f:0000000000000003", review.Conditional, "none")
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Review: mix})
	if line := strings.SplitN(got, "\n", 2)[0]; !strings.HasPrefix(line, "🔴 1 issue exploitable now; 3 not assessed; 2 lower-priority conditional (") {
		t.Errorf("verdict %q", line)
	}
	full, rest, ok := strings.Cut(got, "## Exploitable under conditions (1)\n")
	lowerAt := strings.Index(rest, "## Conditional, lower priority (2)\n\n<details>\n<summary>2 findings</summary>")
	if !ok || lowerAt < 0 || !strings.Contains(rest[:lowerAt], "priority soon**: Needs a local user") || strings.Contains(full, "why f:") {
		t.Fatalf("sections:\n%s", got)
	}
	lower, _, _ := strings.Cut(rest[lowerAt:], "</details>")
	if !strings.Contains(lower, "priority scheduled**: why f:0000000000000001") || !strings.Contains(lower, "priority none**: why f:0000000000000003") ||
		strings.Index(rest, "## Not assessed (3)") < lowerAt || strings.Contains(got, "## Not exploitable here") {
		t.Errorf("lower priority section:\n%s", got)
	}

	only := &review.Review{Summary: "s", NotReviewed: []string{}}
	aud := &audit.Audit{Status: audit.Complete, Grype: audit.GrypeInfo{Version: "0.121.2"}}
	for i, p := range []string{"scheduled", "none", ""} {
		id := fmt.Sprintf("f:%016d", i)
		aud.Findings = append(aud.Findings, audit.Finding{ID: id, Risk: audit.RiskLow, Origin: libssl, Package: audit.Package{Name: "libssl3", Version: "1"}, Vulnerability: audit.Vulnerability{ID: fmt.Sprintf("CVE-2026-%d", i)}})
		only.Findings = append(only.Findings, entry(id, review.Conditional, p))
	}
	got = Render(Input{Run: r, Inventory: hostInventory(), Audit: aud, Review: only})
	if line := strings.SplitN(got, "\n", 2)[0]; !strings.HasPrefix(line, "🟢 No exploitable issues found; 3 lower-priority conditional (") || strings.Contains(got, "## Exploitable under conditions (") ||
		!strings.Contains(got, "## Conditional, lower priority (3)") {
		t.Errorf("all lower priority:\n%s", got)
	}
	only.NotReviewed = []string{"f:0000000000000009"}
	aud.Findings = append(aud.Findings, audit.Finding{ID: "f:0000000000000009", Risk: audit.RiskLow, Origin: libssl, Package: audit.Package{Name: "libssl3", Version: "1"}, Vulnerability: audit.Vulnerability{ID: "CVE-2026-9"}})
	got = Render(Input{Run: r, Inventory: hostInventory(), Audit: aud, Review: only})
	if line := strings.SplitN(got, "\n", 2)[0]; !strings.HasPrefix(line, "🟡 No issue found exploitable, but 1 finding was not assessed; 3 lower-priority conditional (") {
		t.Errorf("verdict %q", line)
	}
}
