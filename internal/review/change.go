package review

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/klar-web-services/tripcoil/internal/run"
)

// Previous is the last run with a review of its own, which runs/latest-reviewed points to.
type Previous struct {
	RunID  string
	Record *run.Record
	Review *Review
}

// LastReviewed returns the last reviewed run in stateDir, or nil when there is none, or when its
// run.json or review.json cannot be read (a run that lost its review cannot be carried forward).
func LastReviewed(stateDir string) *Previous {
	runs := filepath.Join(stateDir, "runs")
	target, err := os.Readlink(filepath.Join(runs, "latest-reviewed"))
	if err != nil || filepath.Base(target) != target {
		return nil
	}
	dir := filepath.Join(runs, target)
	rec, err := run.ReadRecord(dir)
	if err != nil || !rec.Reviewed || rec.Fingerprint == "" {
		return nil
	}
	rev, err := Load(dir)
	if err != nil {
		return nil
	}
	return &Previous{RunID: target, Record: rec, Review: rev}
}

// NeedsReview says why a run needs a new review, or "" when it can carry the last one forward
// (spec section 8.6): the review runs when forced, when there is no earlier review, when the
// fingerprint differs from the last reviewed run's, or when that review is older than maxAge or dated
// after now.
func NeedsReview(prev *Previous, fingerprint string, now time.Time, maxAge time.Duration, force bool) string {
	switch {
	case force:
		return "--force-review"
	case prev == nil:
		return "there is no earlier review"
	case prev.Record.Fingerprint != fingerprint:
		return "something relevant changed since the last review"
	case now.Sub(prev.Record.ReviewedAt) >= maxAge:
		return fmt.Sprintf("the last review is older than %s", maxAge)
	case now.Before(prev.Record.ReviewedAt):
		return "the last review is dated in the future (the clock was set back)"
	}
	return ""
}
