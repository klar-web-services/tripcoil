package run

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateMissingIsEmpty(t *testing.T) {
	s, err := ReadState(t.TempDir())
	if err != nil || s != (State{}) {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestStateRecordsRuns(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)
	var s State
	s.Record(&Record{RunID: "a", StartedAt: t0, Status: Partial})
	s.Record(&Record{RunID: "b", StartedAt: t0.Add(time.Hour), Status: Failed, Reviewed: true, ReviewedAt: t0.Add(2 * time.Hour)})
	s.Record(&Record{RunID: "c", StartedAt: t0.Add(3 * time.Hour), Status: Interrupted})
	want := State{LastRun: "b", LastRunAt: t0.Add(time.Hour), LastStatus: Failed, LastReviewed: "b", LastReviewedAt: t0.Add(2 * time.Hour), ConsecutiveFailures: 2}
	if s != want {
		t.Fatalf("got %+v\nwant %+v", s, want)
	}
	if err := WriteState(dir, s); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.json %v %v", fi.Mode(), err)
	}
	got, err := ReadState(dir)
	if err != nil || got != want {
		t.Fatalf("read back %+v %v", got, err)
	}
	s.Record(&Record{RunID: "d", StartedAt: t0.Add(4 * time.Hour), Status: Complete})
	if s.ConsecutiveFailures != 0 || s.LastRun != "d" || s.LastReviewed != "b" {
		t.Fatalf("after a complete run %+v", s)
	}
}

func TestStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{"), 0o600)
	if _, err := ReadState(dir); err == nil {
		t.Fatal("a corrupt state.json must be an error")
	}
}
