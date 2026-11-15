package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const validReview = `{"summary":"The kernel CVE needs a local user.","coverageNotes":[],"findings":[
{"findingId":"f:0000000000000001","verdict":"confirmed","exploitability":"conditional","priority":"soon","reasoning":"Needs a local user.",
 "evidence":["facts/users.json: alice can log in"],"fix":["pacman -Syu","reboot"],"sources":[],"corrections":[],"item":null,"vulnerability":null}]}`

type fakeAgent struct {
	out   string
	err   error
	calls *int
	dirs  *[]string
}

func (a fakeAgent) Review(_ context.Context, dir string) (review.Output, error) {
	*a.calls++
	if a.dirs != nil {
		*a.dirs = append(*a.dirs, dir)
	}
	return review.Output{Data: []byte(a.out), CLI: "claude 2.1.309"}, a.err
}

// reviewDeps runs with a fake agent; each run gets its own ID and starts an hour after the last.
func reviewDeps(t *testing.T, agent fakeAgent) *deps {
	d := testDeps(t, sampleInventory(), nil)
	d.random = bytes.NewReader([]byte{0, 1, 0, 2, 0, 3, 0, 4})
	clock := time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return clock }
	d.agent = func(config.Config) review.Agent { return agent }
	return &d
}

func runOnce(t *testing.T, d *deps, args ...string) (int, *run.Record, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := dispatch(append([]string{"run"}, args...), &out, &errb, *d)
	entries, _ := os.ReadDir(filepath.Join(d.stateDir, "runs"))
	var last string
	for _, e := range entries {
		if e.IsDir() && e.Name() > last {
			last = e.Name()
		}
	}
	rec, err := run.ReadRecord(filepath.Join(d.stateDir, "runs", last))
	if err != nil {
		t.Fatalf("%v (stderr %q)", err, errb.String())
	}
	md, _ := os.ReadFile(filepath.Join(d.stateDir, "runs", last, "report.md"))
	advance := d.now().Add(time.Hour)
	d.now = func() time.Time { return advance }
	return code, rec, string(md)
}

func TestRunWithReviewThenCarryForward(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	code, rec, md := runOnce(t, d)
	if code != 0 || !rec.Reviewed || rec.CarriedFrom != "" || rec.Stages["review"] != run.StageOK || rec.Stages["facts"] != run.StageOK || calls != 1 {
		t.Fatalf("exit %d, run.json %+v", code, rec)
	}
	if rec.Fingerprint == "" || rec.Versions["prompt"] != review.PromptVersion || rec.Versions["agentCli"] != "claude 2.1.309" ||
		rec.Counts["reviewConditional"] != 1 || rec.Counts["notReviewed"] != 0 || !rec.ReviewedAt.Equal(time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("run.json %+v", rec)
	}
	if !strings.HasPrefix(md, "🟠 No issue exploitable now; 1 exploitable under conditions") || !strings.Contains(md, "reviewed by claude 2.1.309") {
		t.Errorf("report:\n%s", md)
	}
	first := rec.RunID
	if target, _ := os.Readlink(filepath.Join(d.stateDir, "runs", "latest-reviewed")); target != first {
		t.Errorf("latest-reviewed -> %q", target)
	}

	code, rec, md = runOnce(t, d) // nothing changed
	if code != 0 || rec.Reviewed || rec.CarriedFrom != first || calls != 1 || rec.Stages["review"] != run.StageOK {
		t.Fatalf("exit %d, calls %d, run.json %+v", code, calls, rec)
	}
	if rec.Versions["agentCli"] != "claude 2.1.309" {
		t.Errorf("a carried review's CLI: %v", rec.Versions)
	}
	if !strings.Contains(md, "review carried forward from 2026-11-14 06:00 UTC (run "+first+")") || !strings.Contains(md, "reviewed by claude 2.1.309") {
		t.Errorf("report:\n%s", md)
	}
	if _, err := review.Load(filepath.Join(d.stateDir, "runs", rec.RunID)); err != nil {
		t.Errorf("the carried review.json: %v", err)
	}
	if target, _ := os.Readlink(filepath.Join(d.stateDir, "runs", "latest-reviewed")); target != first {
		t.Errorf("a carried review moved latest-reviewed to %q", target)
	}

	_, rec, _ = runOnce(t, d, "--force-review")
	if calls != 2 || !rec.Reviewed {
		t.Errorf("--force-review: calls %d, %+v", calls, rec)
	}
}

func TestRunReviewsAgainWhenSomethingChanged(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	runOnce(t, d)
	d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
		a := sampleAudit(audit.Complete)
		a.Findings[0].Risk = audit.RiskCritical // now on the KEV list
		return a
	}
	_, rec, _ := runOnce(t, d)
	if calls != 2 || !rec.Reviewed || rec.CarriedFrom != "" {
		t.Errorf("calls %d, %+v", calls, rec)
	}
}

func TestRunNoReview(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	code, rec, md := runOnce(t, d, "--no-review")
	if code != 0 || calls != 0 || rec.Stages["review"] != run.StageSkipped || rec.Fingerprint == "" || !strings.HasPrefix(md, "⚠️ Audit only (--no-review)") {
		t.Errorf("exit %d calls %d %+v\n%s", code, calls, rec, md)
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run", "--no-review", "--force-review"}, &out, &errb, *d); code != 2 {
		t.Errorf("both flags: exit %d", code)
	}
}

func TestRunAgentNone(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	if err := os.WriteFile(d.configPath, []byte("version: 1\nreview:\n  agent: none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, rec, md := runOnce(t, d)
	if code != 0 || calls != 0 || rec.Status != run.Complete || !strings.HasPrefix(md, "⚠️ Audit only (review.agent is none)") {
		t.Errorf("exit %d calls %d %+v\n%s", code, calls, rec, md)
	}
}

func TestRunWithoutAgentInThisBuild(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d", code)
	}
	rec := readRecord(t, d.stateDir)
	md, _ := os.ReadFile(filepath.Join(d.stateDir, "runs", runID, "report.md"))
	if rec.Stages["review"] != run.StageSkipped || rec.Status != run.Complete || !strings.HasPrefix(string(md), "⚠️ Audit only (the AI review is not part of this build)") {
		t.Errorf("%+v\n%s", rec, md)
	}
}

func TestRunReviewFailures(t *testing.T) {
	for name, c := range map[string]struct {
		agent fakeAgent
		code  string
	}{
		"timeout":        {fakeAgent{err: &review.Failure{Code: problem.AgentTimeout, Message: "the review ran past review.timeout (1h0m0s)"}}, problem.AgentTimeout},
		"plain error":    {fakeAgent{err: errors.New("exit status 3")}, problem.AgentFailed},
		"invalid output": {fakeAgent{out: `{"summary":"s"}`}, problem.AgentOutputInvalid},
		"not JSON":       {fakeAgent{out: "I cannot help with that."}, problem.AgentOutputInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c.agent.calls = &calls
			d := reviewDeps(t, c.agent)
			code, rec, md := runOnce(t, d)
			if code != 1 || rec.Status != run.Partial || rec.Stages["review"] != run.StageFailed || len(rec.Errors) != 1 || rec.Errors[0].Code != c.code || rec.Reviewed {
				t.Fatalf("exit %d, %+v", code, rec)
			}
			if !strings.HasPrefix(md, "⚠️ Audit only (AI review failed: "+c.code+"): ") {
				t.Errorf("report:\n%s", md)
			}
			if _, err := os.Lstat(filepath.Join(d.stateDir, "runs", "latest-reviewed")); err == nil {
				t.Error("a failed review set latest-reviewed")
			}
			runOnce(t, d) // the next run tries again
			if calls != 2 {
				t.Errorf("calls %d", calls)
			}
		})
	}
}

func TestRunReviewDropsUnknownEntries(t *testing.T) {
	calls := 0
	out := strings.Replace(validReview, `"findings":[`, `"findings":[{"findingId":"f:ffffffffffffffff","verdict":"confirmed","exploitability":"unknown","priority":"none","reasoning":"r","evidence":[],"fix":["x"],"sources":[],"corrections":[],"item":null,"vulnerability":null},`, 1)
	d := reviewDeps(t, fakeAgent{out: out, calls: &calls})
	code, rec, _ := runOnce(t, d)
	if code != 0 || !rec.Reviewed || len(rec.Warnings) != 1 || rec.Warnings[0].Code != problem.ReviewEntriesDropped {
		t.Errorf("exit %d %+v", code, rec)
	}
}

func TestRunInterruptedDuringReview(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	d.interrupts = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	d.agent = func(config.Config) review.Agent {
		cancel()
		return fakeAgent{err: errors.New("signal: terminated"), calls: &calls}
	}
	code, rec, _ := runOnce(t, d)
	if code != 2 || rec.Status != run.Interrupted || rec.Stages["review"] != run.StageFailed || rec.Errors[0].Code != problem.Interrupted {
		t.Errorf("exit %d %+v", code, rec)
	}
}

func TestRunFactsWriteFailed(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	d.facts = func(context.Context, *inventory.Inventory, string) (*facts.Index, error) {
		return nil, errors.New("no space left on device")
	}
	code, rec, _ := runOnce(t, d)
	if code != 1 || rec.Stages["facts"] != run.StageFailed || rec.Errors[0].Code != problem.RunFolderUnwritable {
		t.Errorf("exit %d %+v", code, rec)
	}
}

func TestRunCountsMissingFacts(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	d.facts = func(context.Context, *inventory.Inventory, string) (*facts.Index, error) {
		return &facts.Index{Collected: []string{}, Missing: []facts.Missing{{Fact: "firewall.txt", Reason: "nft: not permitted"}}}, nil
	}
	code, rec, md := runOnce(t, d)
	if code != 0 || rec.Counts["coverageGaps"] != 1 || !strings.Contains(md, "`FACT_MISSING` facts/firewall.txt: nft: not permitted") {
		t.Errorf("exit %d %+v\n%s", code, rec.Counts, md)
	}
}

func TestRunReviewsAgainWhenUsersChange(t *testing.T) {
	calls := 0
	d := reviewDeps(t, fakeAgent{out: validReview, calls: &calls})
	users := `[{"name":"root","uid":0,"home":"/root","shell":"/bin/bash","password":"none","authorizedKeys":1,"keyFiles":[]}]`
	d.facts = func(_ context.Context, _ *inventory.Inventory, dir string) (*facts.Index, error) {
		if err := os.MkdirAll(filepath.Join(dir, "facts"), 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "facts", "users.json"), []byte(users), 0o640); err != nil {
			return nil, err
		}
		return &facts.Index{Collected: []string{"users.json"}, Missing: []facts.Missing{}}, nil
	}
	runOnce(t, d)
	_, rec, _ := runOnce(t, d)
	if calls != 1 || rec.CarriedFrom == "" {
		t.Fatalf("unchanged users: calls %d, %+v", calls, rec)
	}
	users = strings.Replace(users, "]", `,{"name":"bob","uid":1001,"home":"/home/bob","shell":"/bin/sh","password":"empty","authorizedKeys":0,"keyFiles":[]}]`, 1)
	_, rec, _ = runOnce(t, d)
	if calls != 2 || !rec.Reviewed {
		t.Errorf("a new user with an empty password: calls %d, %+v", calls, rec)
	}
}
