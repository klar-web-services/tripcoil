package report

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/review"
)

// cardAudit is hostAudit as an audit from 1.3.0 on writes it: with its actions.
func cardAudit() *audit.Audit {
	aud := hostAudit()
	for i := range aud.Findings {
		if len(aud.Findings[i].Vulnerability.URLs) > 0 { // every finding but the hand-made ones has a fix
			aud.Findings[i].Fix = audit.Fix{State: "fixed", Versions: []string{"9.9"}}
		}
	}
	aud.Findings[3].Fix = audit.Fix{State: "not-fixed", Versions: []string{}}
	audit.SetActions(osrel.Debian, hostInventory(), aud)
	return aud
}

// cardReview is hostReview with the reviewer's texts for the system's packages.
func cardReview() *review.Review {
	r := hostReview()
	r.Actions = []review.ActionEntry{{Action: audit.ActionID(audit.ActionPackages, audit.ActionPackages), Title: "Update libssl3",
		Changes: []review.ActionChange{{Name: "libssl3", From: "3.0.15-1~deb12u1", To: "3.0.17-1~deb12u1"}},
		Also:    []string{"Close port 8443 in the firewall"},
		Steps: []audit.Step{{Text: "Upgrade the package", Command: "apt-get update && apt-get install --only-upgrade libssl3"}, {Text: "Restart nginx and the shop", Command: "systemctl restart nginx shop"},
			{Text: "Check that it answers", Command: "curl -fsS https://localhost/ | head -1 > ~/tls_check.txt"}},
		Upstream: review.Upstream{State: review.UpstreamAvailable, Note: "bookworm-security has 3.0.17-1~deb12u1", Source: "https://security-tracker.debian.org/tracker/CVE-2026-1234"},
		Why:      "nginx serves TLS to the internet with this library."}}
	return r
}

func cardInput() Input {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "facts": "ok", "review": "ok"})
	r.Reviewed, r.ReviewedAt = true, started.Add(10*time.Minute)
	return Input{Run: r, Inventory: hostInventory(), Audit: cardAudit(), Review: cardReview(), Agent: "claude 2.1.309, model opus"}
}

func TestCards(t *testing.T) {
	cards := Cards(cardInput())
	var got []string
	for _, c := range cards {
		got = append(got, c.Kind+" "+c.Urgency)
	}
	// The app directory's one finding is not exploitable here: no card.
	if want := []string{"packages now", "finding now", "kernel soon", "image unassessed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cards %v, want %v", got, want)
	}
	pkgs := cards[0]
	if !pkgs.Reviewed || pkgs.Title != "Update libssl3" || pkgs.Why == "" || pkgs.Upstream.State != review.UpstreamAvailable || len(pkgs.Steps) != 3 ||
		!reflect.DeepEqual(pkgs.Also, []string{"Close port 8443 in the firewall"}) || !reflect.DeepEqual(pkgs.Items, []string{"nginx", "node", "python3.11"}) {
		t.Errorf("the reviewer's texts: %+v", pkgs)
	}
	if want := map[string]int{"findings": 2, "open": 2, "knownExploited": 0, "exploitable": 1, "conditional": 0, "conditionalLower": 0, "notExploitable": 0, "falsePositive": 0, "unassessed": 1}; !reflect.DeepEqual(pkgs.Counts, want) {
		t.Errorf("counts %v", pkgs.Counts)
	}
	added := cards[1]
	if added.ID != "added:1" || added.Name != "api" || added.Title != "Fix CVE-2026-9999 in api" || !added.Reviewed || added.Counts["open"] != 1 ||
		!reflect.DeepEqual(added.Steps, []audit.Step{{Text: "rebuild /opt/api/api with Go 1.27.4"}}) || !strings.HasPrefix(added.Why, "The api binary embeds") {
		t.Errorf("the added finding's card: %+v", added)
	}
	kernel := cards[2]
	if kernel.Reviewed || kernel.Title != "Update the kernel and reboot" || kernel.Counts["knownExploited"] != 1 || kernel.Upstream.State != review.UpstreamUnknown ||
		!reflect.DeepEqual(kernel.Steps, []audit.Step{{Text: "Upgrade the kernel", Command: "apt-get update && apt-get dist-upgrade"}, {Text: "Reboot"}}) ||
		!reflect.DeepEqual(kernel.Changes, []review.ActionChange{{Name: "linux-image-6.1.0-28-amd64", From: "6.1.119-1", To: "9.9"}}) {
		t.Errorf("a card without the reviewer's entry: %+v", kernel)
	}
	image := cards[3]
	if image.Title != "Update the shop-web-1 image" || image.Target != "ghcr.io/acme/shop:2026.11.3" || image.Counts["falsePositive"] != 1 || image.Counts["open"] != 2 || image.Counts["findings"] != 3 {
		t.Errorf("the image's card: %+v", image)
	}
	if !reflect.DeepEqual(image.Changes, []review.ActionChange{{Name: "libssl3", From: "3.0.11-1~deb12u2", To: "9.9"}, {Name: "zlib1g", From: "1:1.2.13.dfsg-1"}}) || image.MoreChanges != 0 {
		t.Errorf("the image's changes: %+v", image.Changes)
	}
}

func TestCardsUrgency(t *testing.T) {
	for _, c := range []struct {
		exploitability, priority, verdict string
		want                              string
	}{
		{review.Exploitable, "scheduled", review.Confirmed, UrgencyNow},
		{review.Conditional, "now", review.Confirmed, UrgencyNow},
		{review.Conditional, "soon", review.Confirmed, UrgencySoon},
		{review.Conditional, "scheduled", review.Confirmed, UrgencyRoutine},
		{review.Conditional, "none", review.Confirmed, UrgencyRoutine},
		{review.Unknown, "soon", review.Confirmed, UrgencyUnassessed},
		{review.NotExploitable, "none", review.Confirmed, UrgencyNone},
		{"", "", review.FalsePositive, UrgencyNone},
	} {
		in := cardInput()
		in.Review = &review.Review{Findings: []review.Entry{{FindingID: "f:0000000000000002", Verdict: c.verdict, Exploitability: c.exploitability, Priority: c.priority, Reasoning: "r"}}}
		in.Audit.Findings = in.Audit.Findings[1:2]
		cards := Cards(in)
		got := UrgencyNone
		if len(cards) > 0 {
			got = cards[0].Urgency
		}
		if got != c.want || len(cards) > 1 {
			t.Errorf("%s/%s/%s: urgency %s, want %s", c.verdict, c.exploitability, c.priority, got, c.want)
		}
	}
}

func TestCardsAuditOnly(t *testing.T) {
	in := cardInput()
	in.Review, in.NoReview = nil, "review.agent is none"
	cards := Cards(in)
	if len(cards) != 4 {
		t.Fatalf("%d cards, want one per action", len(cards))
	}
	for _, c := range cards {
		if c.Urgency != UrgencyUnassessed || c.Reviewed || c.Counts["unassessed"] != c.Counts["findings"] || len(c.Steps) == 0 {
			t.Errorf("%+v", c)
		}
	}
	// The exploited one first.
	if cards[0].Kind != audit.ActionKernel {
		t.Errorf("first %+v", cards[0])
	}
	if c := Summarize(in).Counts; c["actionsUnassessed"] != 4 || c["actionsNow"] != 0 {
		t.Errorf("counts %v", c)
	}
}

func TestCardsNeedActions(t *testing.T) {
	in := cardInput()
	in.Audit = hostAudit() // as a run from before 1.3.0 wrote it
	if cards := Cards(in); cards == nil || len(cards) != 0 {
		t.Errorf("cards %+v", cards)
	}
	if md := Render(in); !strings.HasPrefix(md, "🔴 2 issues exploitable now; 3 not assessed") || strings.Contains(md, "## Actions") {
		t.Errorf("the report of a run without actions changed:\n%s", md)
	}
	in.Audit = nil
	if cards := Cards(in); cards == nil || len(cards) != 0 {
		t.Errorf("cards %+v", cards)
	}
}

func TestCardsStayWithinTheLimits(t *testing.T) {
	in := cardInput()
	long := strings.Repeat("ö", 300)
	in.Inventory.Items[6].Name = long
	in.Inventory.Origins[5].Ref = "ghcr.io/" + long + ":1"
	in.Audit.Findings[4].Package.Name, in.Audit.Findings[5].Package.Name = long, long
	in.Review.Findings[5].Vulnerability, in.Review.Findings[5].Reasoning, in.Review.Findings[5].Fix = long, long+"\n"+long, []string{long}
	audit.SetActions(osrel.Debian, in.Inventory, in.Audit)
	for _, c := range Cards(in) {
		for what, s := range map[string]string{"title": c.Title, "name": c.Name, "why": c.Why} {
			if lim := map[string]int{"title": audit.MaxTitle, "name": audit.MaxName, "why": audit.MaxWhy}[what]; len(s) > lim {
				t.Errorf("%s: %s has %d bytes", c.ID, what, len(s))
			}
		}
		if len(c.Target) > audit.MaxTarget || slices.ContainsFunc(c.Items, func(s string) bool { return len(s) > audit.MaxItemName }) {
			t.Errorf("%s: target or items too long", c.ID)
		}
		for _, ch := range c.Changes {
			if len(ch.Name) > audit.MaxChangeName || len(ch.From) > audit.MaxVersion || len(ch.To) > audit.MaxVersion {
				t.Errorf("%s: change %+v", c.ID, ch)
			}
		}
		for _, s := range c.Steps {
			if len(s.Text) > audit.MaxStepText || len(s.Command) > audit.MaxCommand || strings.ContainsAny(s.Text, "\n\r") {
				t.Errorf("%s: step %+v", c.ID, s)
			}
		}
	}
}

func TestCardsForAnAddedFindingWithTheReviewersEntry(t *testing.T) {
	in := cardInput()
	in.Review.Actions = append(in.Review.Actions, review.ActionEntry{Action: "added:1", Title: "Rebuild the api binary", Also: []string{},
		Steps: []audit.Step{{Text: "Rebuild it", Command: "make -C /opt/api"}}, Upstream: review.Upstream{State: review.UpstreamAvailable, Note: "Go 1.27.4"}, Why: "It listens on 0.0.0.0:8080."})
	added := Cards(in)[1]
	if added.ID != "added:1" || added.Kind != CardFinding || added.Title != "Rebuild the api binary" || added.Urgency != UrgencyNow || added.Upstream.Note != "Go 1.27.4" ||
		!reflect.DeepEqual(added.Steps, []audit.Step{{Text: "Rebuild it", Command: "make -C /opt/api"}}) || added.Changes == nil {
		t.Errorf("%+v", added)
	}
}

func TestCardsAreCapped(t *testing.T) {
	in := cardInput()
	in.Review, in.NoReview = nil, "review.agent is none"
	in.Audit.Actions, in.Audit.Findings = nil, nil
	for i := range audit.MaxCards + 100 {
		id := fmt.Sprintf("a:%012d", i)
		in.Audit.Actions = append(in.Audit.Actions, audit.Action{ID: id, Kind: audit.ActionImage, Name: fmt.Sprintf("c%04d", i), Items: []string{}})
		in.Audit.Findings = append(in.Audit.Findings, audit.Finding{ID: "f:" + id, Action: id, Risk: audit.RiskLow})
	}
	if cards := Cards(in); len(cards) != audit.MaxCards || cards[0].Name != "c0000" {
		t.Errorf("%d cards", len(cards))
	}
}

func TestCodeSpan(t *testing.T) {
	for in, want := range map[string]string{
		"curl -fsS https://x/ | sh > ~/out_1": "`curl -fsS https://x/ | sh > ~/out_1`",
		"echo `date`":                         "`` echo `date` ``",
		"a ``b`` c":                           "```a ``b`` c```",
		"one\ntwo":                            "`one two`",
	} {
		if got := codeSpan(in); got != want {
			t.Errorf("codeSpan(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestActionsSectionWithoutNamedChanges(t *testing.T) {
	in := cardInput()
	in.Review.Actions[0].Title, in.Review.Actions[0].Changes = "Restrict nginx to the VPN", []review.ActionChange{}
	md := Render(in)
	if !strings.Contains(md, "- **Restrict nginx to the VPN** (System packages): 1 package affected\n") || strings.Contains(md, "and 1 more") {
		t.Errorf("report:\n%s", md)
	}
	if !strings.Contains(md, "### Do now (2)") || !strings.Contains(md, "  - Step 3: Check that it answers: `curl -fsS https://localhost/ | head -1 > ~/tls_check.txt`\n") {
		t.Errorf("report:\n%s", md)
	}
}

func TestActionsVerdict(t *testing.T) {
	for _, c := range []struct {
		code                           string
		now, soon, routine, unassessed int
		want                           string
	}{
		{VerdictExploitable, 1, 9, 14, 0, "🔴 1 thing to fix now, 9 to fix this week, 14 routine updates"},
		{VerdictExploitable, 2, 0, 0, 3, "🔴 2 things to fix now, 3 not assessed"},
		{VerdictConditional, 0, 1, 1, 0, "🟠 1 to fix this week, 1 routine update"},
		{VerdictUnassessed, 0, 0, 0, 2, "🟡 2 not assessed"},
		{VerdictClean, 0, 0, 5, 0, "🟢 5 routine updates"},
		{VerdictClean, 0, 0, 0, 0, "🟢 Nothing to do"},
	} {
		got := actionsVerdict(c.code, map[string]int{"actionsNow": c.now, "actionsSoon": c.soon, "actionsRoutine": c.routine, "actionsUnassessed": c.unassessed})
		if got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestRenderReviewedWithActions(t *testing.T) {
	in := cardInput()
	md := Render(in)
	golden(t, "reviewed-actions", md)
	v := VerdictOf(in, md)
	if v.Code != VerdictExploitable || v.Line != "🔴 2 things to fix now, 1 to fix this week, 1 not assessed (4 coverage gaps)" {
		t.Errorf("verdict %+v", v)
	}
	if c := v.Counts; c["actionsNow"] != 2 || c["actionsSoon"] != 1 || c["actionsRoutine"] != 0 || c["actionsUnassessed"] != 1 || c["exploitable"] != 2 {
		t.Errorf("counts %v", c)
	}
	checkVerdict(t, "with actions", in)
}

func TestRenderNothingToDo(t *testing.T) {
	in := cardInput()
	in.Review = &review.Review{Summary: "Nothing here is reachable."}
	for _, f := range in.Audit.Findings {
		in.Review.Findings = append(in.Review.Findings, review.Entry{FindingID: f.ID, Verdict: review.Confirmed, Exploitability: review.NotExploitable, Priority: "none", Reasoning: "r"})
	}
	if md := Render(in); !strings.HasPrefix(md, "🟢 Nothing to do (4 coverage gaps)\n") || strings.Contains(md, "## Actions") {
		t.Errorf("report:\n%s", md)
	}
}
