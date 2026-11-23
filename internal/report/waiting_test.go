package report

import (
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/waiting"
)

// waitingInput is a reviewed run with one image that has one finding. The review found no fixed
// release, and gives the steps it is called with.
func waitingInput(exploitability string, steps ...audit.Step) Input {
	a := audit.Action{ID: "a:aaaaaaaaaaaa", Kind: audit.ActionImage, Name: "flaresolverr", Target: "ghcr.io/flaresolverr/flaresolverr:latest", Items: []string{},
		Changes: []audit.Change{{Name: "chromium", From: "152"}}, Steps: []audit.Step{{Text: "Pull or rebuild ghcr.io/flaresolverr/flaresolverr:latest"}},
		Update: &audit.Update{State: audit.UpdateCurrent}}
	aud := &audit.Audit{Status: "complete", Actions: []audit.Action{a},
		Findings: []audit.Finding{{ID: "f:0000000000000001", Action: a.ID, Risk: "critical", Package: audit.Package{Name: "chromium", Version: "152"}, Fix: audit.Fix{State: "not-fixed"}}}}
	rev := &review.Review{Summary: "s", NotReviewed: []string{},
		Findings: []review.Entry{{FindingID: "f:0000000000000001", Verdict: review.Confirmed, Exploitability: exploitability, Priority: "soon", Reasoning: "r"}},
		Actions: []review.ActionEntry{{Action: a.ID, Title: "Keep flaresolverr on localhost", Changes: []review.ActionChange{{Name: "chromium", From: "152"}},
			Also: []string{"Keep port 8891 bound to 127.0.0.1"}, Steps: steps, Upstream: review.Upstream{State: review.UpstreamNone, Note: "No image ships a newer Chromium"}}}}
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "facts": "ok", "review": "ok"})
	r.Reviewed, r.ReviewedAt = true, started.Add(10*time.Minute)
	return Input{Run: r, Inventory: hostInventory(), Audit: aud, Review: rev}
}

var replace = audit.Step{Text: "Replace FlareSolverr with Byparr", Command: "docker compose up -d byparr"}

func TestACardWithNoFixAndNoStepsWaits(t *testing.T) {
	in := waitingInput(review.Conditional)
	key := audit.WaitingKey(in.Audit.Actions[0])
	cards := Cards(in)
	if len(cards) != 1 || cards[0].Urgency != UrgencyWaiting || len(cards[0].Steps) != 0 {
		t.Fatalf("%+v", cards)
	}
	// It waits for the first time: its clock starts with this run.
	if w := cards[0].Waiting; w == nil || w.Key != key || !w.Since.Equal(started) || w.Overdue || w.Until != nil {
		t.Errorf("the clock: %+v", w)
	}
	v := Summarize(in)
	if v.Code != VerdictClean || v.Counts["actionsWaiting"] != 1 || v.Counts["actionsSoon"] != 0 || v.Counts["conditional"] != 1 {
		t.Errorf("the verdict: %+v", v)
	}
	md := Render(in)
	if !strings.HasPrefix(md, "🟢 Nothing to do, 1 waiting for a fix (") {
		t.Errorf("the verdict line: %q", strings.SplitN(md, "\n", 2)[0])
	}
	for _, want := range []string{"### Waiting for a fix (1)\n\n- **Keep flaresolverr on localhost**", "  - No fixed release since 2026-11-14. Without one, this comes back on 2026-12-14.\n",
		"  - Meanwhile: Keep port 8891 bound to 127.0.0.1\n", "  - Upstream has no fixed release yet: No image ships a newer Chromium.\n"} {
		if !strings.Contains(md, want) {
			t.Errorf("the report lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "Step 1") || strings.Contains(md, "### Do this week") {
		t.Errorf("a waiting card is no to-do:\n%s", md)
	}
	if got := WaitingCards(in); len(got) != 1 || got[0] != (waiting.Card{Key: key, Waits: true, NoFix: true}) {
		t.Errorf("for the clock: %+v", got)
	}
	// A clock that already runs keeps its start.
	in.Audit.Actions[0].Waiting = &audit.Waiting{Key: key, Since: started.Add(-72 * time.Hour), Days: 3}
	if w := Cards(in)[0].Waiting; w == nil || !w.Since.Equal(started.Add(-72*time.Hour)) {
		t.Errorf("a running clock: %+v", w)
	}
}

func TestWhatDoesNotWait(t *testing.T) {
	// A finding that is exploitable as things stand never waits; without the reviewer's steps the card has Tripcoil's.
	in := waitingInput(review.Exploitable)
	if c := Cards(in)[0]; c.Urgency != UrgencyNow || len(c.Steps) != 1 || c.Steps[0].Text != "Pull or rebuild ghcr.io/flaresolverr/flaresolverr:latest" || c.Waiting != nil {
		t.Errorf("exploitable: %+v", c)
	}
	if got := WaitingCards(in); len(got) != 1 || got[0].Waits || !got[0].NoFix {
		t.Errorf("exploitable, for the clock: %+v", got)
	}
	// Steps mean there is something to do.
	in = waitingInput(review.Conditional, audit.Step{Text: "Bind port 8891 to 127.0.0.1"})
	if c := Cards(in)[0]; c.Urgency != UrgencySoon || len(c.Steps) != 1 || c.Waiting != nil {
		t.Errorf("with steps: %+v", c)
	}
	// A newer image that clears findings is a fix to pull.
	in = waitingInput(review.Conditional)
	in.Audit.Actions[0].Update = &audit.Update{State: audit.UpdateScanned, Clears: 1}
	if c := Cards(in)[0]; c.Urgency != UrgencySoon || len(c.Steps) != 1 {
		t.Errorf("a newer image: %+v", c)
	}
	// A fixed release exists.
	in = waitingInput(review.Conditional)
	in.Review.Actions[0].Upstream.State = review.UpstreamAvailable
	if c := Cards(in)[0]; c.Urgency != UrgencySoon {
		t.Errorf("a fixed release: %+v", c)
	}
	if got := WaitingCards(in); len(got) != 1 || got[0].Waits || got[0].NoFix {
		t.Errorf("a fixed release, for the clock: %+v", got)
	}
	// No review, no waiting.
	in = waitingInput(review.Conditional)
	in.Review = nil
	if c := Cards(in)[0]; c.Urgency != UrgencyUnassessed || c.Waiting != nil || len(WaitingCards(in)) != 0 {
		t.Errorf("not reviewed: %+v", c)
	}
}

func TestAnOverdueCardComesBackUnlessItIsKeptWaiting(t *testing.T) {
	in := waitingInput(review.Conditional, replace)
	key := audit.WaitingKey(in.Audit.Actions[0])
	since := started.Add(-40 * 24 * time.Hour)
	in.Audit.Actions[0].Waiting = &audit.Waiting{Key: key, Since: since, Days: 40, Overdue: true}
	c := Cards(in)[0]
	if c.Urgency != UrgencySoon || len(c.Steps) != 1 || c.Waiting == nil || !c.Waiting.Overdue || !c.Waiting.Since.Equal(since) || c.Waiting.Until != nil {
		t.Fatalf("overdue: %+v %+v", c, c.Waiting)
	}
	md := Render(in)
	if !strings.HasPrefix(md, "🟠 1 to fix this week (") || !strings.Contains(md, "  - No fixed release for 40 days, since 2026-10-05.\n") || !strings.Contains(md, "  - Step 1: Replace FlareSolverr with Byparr") {
		t.Errorf("overdue:\n%s", md)
	}
	// An overdue card without steps does not wait on: it shows Tripcoil's steps until the review has written what to do instead.
	in.Review.Actions[0].Steps = nil
	if c := Cards(in)[0]; c.Urgency != UrgencySoon || len(c.Steps) != 1 {
		t.Errorf("overdue without steps: %+v", c)
	}
	// Kept waiting through Zosia's settings: it waits again, and its steps are what to do if no fix comes.
	in = waitingInput(review.Conditional, replace)
	until := started.Add(20 * 24 * time.Hour)
	in.Audit.Actions[0].Waiting = &audit.Waiting{Key: key, Since: since, Days: 40, Overdue: true, Until: &until}
	c = Cards(in)[0]
	if c.Urgency != UrgencyWaiting || len(c.Steps) != 1 || c.Waiting == nil || c.Waiting.Until == nil || !c.Waiting.Until.Equal(until) {
		t.Fatalf("kept: %+v", c)
	}
	md = Render(in)
	for _, want := range []string{"🟢 Nothing to do, 1 waiting for a fix (", "  - No fixed release since 2026-10-05. Kept waiting until 2026-12-04.\n", "  - If no fix comes, step 1: Replace FlareSolverr with Byparr: `docker compose up -d byparr`\n"} {
		if !strings.Contains(md, want) {
			t.Errorf("kept: the report lacks %q:\n%s", want, md)
		}
	}
	// The settings can keep a card with no fix quiet, and never hide a to-do: an exploitable finding comes back.
	in.Review.Findings[0].Exploitability = review.Exploitable
	if c := Cards(in)[0]; c.Urgency != UrgencyNow {
		t.Errorf("kept, but exploitable: %+v", c)
	}
	// A time that has passed keeps nothing.
	in = waitingInput(review.Conditional, replace)
	past := started.Add(-time.Hour)
	in.Audit.Actions[0].Waiting = &audit.Waiting{Key: key, Since: since, Days: 40, Overdue: true, Until: &past}
	if c := Cards(in)[0]; c.Urgency != UrgencySoon {
		t.Errorf("kept until the past: %+v", c)
	}
}
