package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/run"
)

func init() { run.AgentGID = func() (int, bool) { return 0, false } }

func reviewedRun(t *testing.T, state, id, fp string, at time.Time, withReview bool) {
	t.Helper()
	dir := filepath.Join(state, "runs", id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	rec := run.NewRecord(id, at, "schedule", map[string]string{})
	rec.Reviewed, rec.Fingerprint, rec.ReviewedAt = true, fp, at
	if err := run.WriteJSON(filepath.Join(dir, "run.json"), rec, 0o640); err != nil {
		t.Fatal(err)
	}
	if withReview {
		if err := run.WriteJSON(filepath.Join(dir, "review.json"), &Review{SchemaVersion: "1", Summary: "s", Findings: []Entry{}, CoverageNotes: []string{}, NotReviewed: []string{}}, 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLastReviewedAndNeedsReview(t *testing.T) {
	state := t.TempDir()
	if LastReviewed(state) != nil {
		t.Fatal("a review without runs")
	}
	at := time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)
	reviewedRun(t, state, "20261114T060000Z-0001", "fp1", at, true)
	if err := run.UpdateLatest(state, "latest-reviewed", "20261114T060000Z-0001"); err != nil {
		t.Fatal(err)
	}
	prev := LastReviewed(state)
	if prev == nil || prev.RunID != "20261114T060000Z-0001" || prev.Review.Summary != "s" {
		t.Fatalf("%+v", prev)
	}
	week := 168 * time.Hour
	for _, c := range []struct {
		prev  *Previous
		fp    string
		now   time.Time
		force bool
		want  string
	}{
		{prev, "fp1", at.Add(6 * time.Hour), false, ""},
		{prev, "fp1", at.Add(6 * time.Hour), true, "--force-review"},
		{nil, "fp1", at, false, "no earlier review"},
		{prev, "fp2", at.Add(time.Hour), false, "changed"},
		{prev, "fp1", at.Add(week), false, "older than 168h0m0s"},
		{prev, "fp1", at.Add(-time.Hour), false, "in the future"},
	} {
		if got := NeedsReview(c.prev, c.fp, c.now, week, c.force); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("NeedsReview(%v, %s, force=%v) = %q, want %q", c.prev != nil, c.fp, c.force, got, c.want)
		}
	}

	reviewedRun(t, state, "20261115T060000Z-0002", "fp1", at, false)
	run.UpdateLatest(state, "latest-reviewed", "20261115T060000Z-0002")
	if LastReviewed(state) != nil {
		t.Error("a run without review.json was carried")
	}
	os.Remove(filepath.Join(state, "runs", "latest-reviewed"))
	os.Symlink("../../etc", filepath.Join(state, "runs", "latest-reviewed"))
	if LastReviewed(state) != nil {
		t.Error("a link out of runs/ was followed")
	}
}
