package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/waiting"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

var waitingAction = audit.Action{ID: "a:aaaaaaaaaaaa", Kind: audit.ActionBinary, Name: "caddy", Target: "/usr/local/bin/caddy", Items: []string{},
	Changes: []audit.Change{{Name: "linux", From: "7.3.3"}}, Steps: []audit.Step{{Text: "Replace or rebuild /usr/local/bin/caddy"}}}

// waitingReview is a review that finds no fixed release for the one action, with these steps.
func waitingReview(steps string) string {
	return `{"summary":"s","coverageNotes":[],"reach":[],"findings":[
{"findingId":"f:0000000000000001","verdict":"confirmed","exploitability":"conditional","priority":"soon","reasoning":"Needs a hostile page.",
 "evidence":["e"],"fix":[],"sources":[],"corrections":[],"item":null,"vulnerability":null}],
"actions":[{"action":"a:aaaaaaaaaaaa","title":"Wait for a fixed caddy","changes":[{"name":"linux","from":"7.3.3","to":null}],"also":[],"steps":` + steps + `,
 "upstream":{"state":"none","note":"no release has the fix","source":"https://example.org/releases"},"why":"It serves the tunnel."}]}`
}

func TestACardWaitsComesBackAndIsKeptWaiting(t *testing.T) {
	calls := 0
	agent := fakeAgent{out: waitingReview("[]"), calls: &calls}
	d := reviewDeps(t, agent)
	d.random = bytes.NewReader([]byte{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}) // two bytes per run ID
	d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
		a := sampleAudit(audit.Complete)
		a.Findings[0].Action = waitingAction.ID
		a.Actions = []audit.Action{waitingAction}
		return a
	}
	key := audit.WaitingKey(waitingAction)
	settings, fetchErr, fetches := `{"schema":"zosia.settings/1","version":0,"keepWaiting":[]}`, error(nil), 0
	var sent zosia.Request
	d.zosiaSecret = func(string) (string, bool, error) { return "zosia_x", true, nil }
	d.machineKey = func() (string, error) { return "0123456789abcdef0123456789abcdef", nil }
	d.zosiaSettings = func(_ context.Context, url, secret, machine string) ([]byte, error) {
		if fetches++; secret != "zosia_x" || machine != "0123456789abcdef0123456789abcdef" || url != "https://zosiasec.com" {
			t.Errorf("the fetch: %s %s %s", url, secret, machine)
		}
		return []byte(settings), fetchErr
	}
	d.sendZosia = func(_ context.Context, r zosia.Request) (zosia.Result, error) {
		sent = r
		return zosia.Result{URL: "https://zosiasec.com/app/reports/1"}, nil
	}
	marked := func() *audit.Waiting {
		t.Helper()
		var aud audit.Audit
		data, _ := os.ReadFile(filepath.Join(d.stateDir, "runs", "latest", "audit.json"))
		if err := json.Unmarshal(data, &aud); err != nil || len(aud.Actions) != 1 {
			t.Fatalf("audit.json: %v", err)
		}
		return aud.Actions[0].Waiting
	}
	first := d.now()

	// It waits from the first run on: nothing to do, and the clock starts.
	_, rec, md := runOnce(t, d)
	if !strings.HasPrefix(md, "🟢 Nothing to do, 1 waiting for a fix") || rec.Verdict.Code != "clean" || calls != 1 || fetches != 1 || marked() != nil {
		t.Fatalf("first run: %q %+v, %d reviews, %d fetches, mark %+v", strings.SplitN(md, "\n", 2)[0], rec.Verdict, calls, fetches, marked())
	}
	if st, err := waiting.Read(d.stateDir); err != nil || len(st) != 1 || !st[key].Equal(first) {
		t.Fatalf("the clock after the first run: %v %v", st, err)
	}
	if src := sent.Source.(map[string]any); src["settingsVersion"] != 0 {
		t.Errorf("the settings version sent: %v", src["settingsVersion"])
	}

	// The next run carries the review forward; the reviewer would read the clock.
	_, rec, md = runOnce(t, d)
	if w := marked(); calls != 1 || rec.CarriedFrom == "" || w == nil || w.Key != key || w.Overdue || !strings.Contains(md, "1 waiting for a fix") {
		t.Fatalf("second run: %d reviews, carried from %q, mark %+v", calls, rec.CarriedFrom, w)
	}

	// After 30 days it is overdue: reviewed afresh, and a to-do again with the steps that say what to do instead.
	late := first.Add(31 * 24 * time.Hour)
	d.now = func() time.Time { return late }
	agent.out = waitingReview(`[{"text":"Replace caddy with the distribution's package","command":"apt-get install caddy"}]`)
	d.agent = func(config.Config) review.Agent { return agent }
	_, rec, md = runOnce(t, d)
	if w := marked(); calls != 2 || w == nil || !w.Overdue || w.Days != 31 || rec.Verdict.Code != "conditional" || !strings.HasPrefix(md, "🟠 1 to fix this week") ||
		!strings.Contains(md, "No fixed release for 31 days") || !strings.Contains(md, "Step 1: Replace caddy") {
		t.Fatalf("overdue: %d reviews, mark %+v, %+v\n%s", calls, w, rec.Verdict, md)
	}
	if st, _ := waiting.Read(d.stateDir); len(st) != 1 || !st[key].Equal(first) {
		t.Errorf("the clock of an overdue card: %v", st)
	}

	// "Keep waiting" in Zosia: the next run fetches it, and the card waits again without a new review.
	until := d.now().Add(30 * 24 * time.Hour)
	settings = fmt.Sprintf(`{"schema":"zosia.settings/1","version":3,"keepWaiting":[{"key":%q,"until":%q}]}`, key, until.Format(time.RFC3339))
	_, rec, md = runOnce(t, d)
	if w := marked(); calls != 2 || w == nil || w.Until == nil || !w.Until.Equal(until) || rec.Verdict.Code != "clean" || !strings.Contains(md, "Kept waiting until "+until.Format("2006-01-02")) ||
		!strings.Contains(md, "If no fix comes, step 1: Replace caddy") {
		t.Fatalf("kept: %d reviews, mark %+v, %+v\n%s", calls, w, rec.Verdict, md)
	}
	if src := sent.Source.(map[string]any); src["settingsVersion"] != 3 {
		t.Errorf("the settings version sent: %v", src["settingsVersion"])
	}

	// Zosia cannot be reached: the copy of the last fetch counts, and the run says so.
	fetchErr = &zosia.Error{Code: "NETWORK", Message: "cannot reach Zosia: connection refused"}
	_, rec, md = runOnce(t, d)
	if rec.Verdict.Code != "clean" || !strings.Contains(md, "Kept waiting until") || len(rec.Notices) == 0 {
		t.Fatalf("Zosia down: %+v notices %+v", rec.Verdict, rec.Notices)
	}
	found := false
	for _, n := range rec.Notices {
		found = found || n.Code == "ZOSIA_SETTINGS_UNREACHABLE" && strings.Contains(n.Message, "connection refused") && strings.Contains(n.Message, "the copy of the last fetch")
	}
	if !found || rec.Status != "complete" {
		t.Errorf("the notice: %+v, status %s", rec.Notices, rec.Status)
	}

	// Settings that are no settings change nothing either.
	settings, fetchErr = `{"schema":"zosia.settings/9","keepWaiting":"all","run":"rm -rf /"}`, nil
	if _, rec, _ = runOnce(t, d); rec.Verdict.Code != "clean" || rec.Status != "complete" {
		t.Errorf("bad settings: %+v", rec.Verdict)
	}
}

func TestARunWithoutZosiaFetchesNothingAndStillWaits(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: waitingReview("[]"), calls: &calls})
	d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
		a := sampleAudit(audit.Complete)
		a.Findings[0].Action = waitingAction.ID
		a.Actions = []audit.Action{waitingAction}
		return a
	}
	d.zosiaSettings = func(context.Context, string, string, string) ([]byte, error) {
		t.Error("no secret, no fetch")
		return nil, errors.New("x")
	}
	_, rec, md := runOnce(t, d)
	if !strings.HasPrefix(md, "🟢 Nothing to do, 1 waiting for a fix") || len(rec.Notices) != 0 {
		t.Errorf("%q %+v", strings.SplitN(md, "\n", 2)[0], rec.Notices)
	}
	if _, err := os.Stat(filepath.Join(d.stateDir, "zosia-settings.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a settings copy without Zosia: %v", err)
	}
}
