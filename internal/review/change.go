package review

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/klar-web-services/tripcoil/internal/run"
)

type Previous struct {
	RunID  string
	Record *run.Record
	Review *Review
}

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
