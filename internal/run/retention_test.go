package run

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPrune(t *testing.T) {
	noAgentGroup(t)
	state := t.TempDir()
	var ids []string
	for i := range 6 {
		id := fmt.Sprintf("2026111%dT061500Z-000%d", i, i)
		ids = append(ids, id)
		if _, err := CreateFolder(state, id); err != nil {
			t.Fatal(err)
		}
	}
	runs := filepath.Join(state, "runs")
	// ids[5] carries the review of ids[1]; latest-reviewed points at ids[0]; ids[3] has no run.json.
	for i, id := range ids {
		if i == 3 {
			continue
		}
		r := &Record{RunID: id}
		if i == 5 {
			r.CarriedFrom = ids[1]
		}
		if err := WriteJSON(filepath.Join(runs, id, "run.json"), r, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpdateLatest(state, "latest", ids[5]); err != nil {
		t.Fatal(err)
	}
	if err := UpdateLatest(state, "latest-reviewed", ids[0]); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".probe-abc", ".tmp-1"} { // what a killed run left: not retention's
		os.Mkdir(filepath.Join(runs, p), 0o700)
	}
	removed, err := Prune(state, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(removed, []string{ids[3], ids[2]}) {
		t.Fatalf("removed %v", removed)
	}
	es, _ := os.ReadDir(runs)
	var left []string
	for _, e := range es {
		left = append(left, e.Name())
	}
	want := []string{".probe-abc", ".tmp-1", ids[0], ids[1], ids[4], ids[5], "latest", "latest-reviewed"}
	if !slices.Equal(left, want) {
		t.Fatalf("left %v\nwant %v", left, want)
	}
}

func TestPruneNoRuns(t *testing.T) {
	if _, err := Prune(t.TempDir(), 3); !os.IsNotExist(err) {
		t.Fatalf("got %v", err)
	}
}
