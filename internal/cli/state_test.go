package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/run"
)

func TestRunRecordsStateAndPrunes(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	if err := os.WriteFile(d.configPath, []byte("version: 1\nretention:\n  keepRuns: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.random = bytes.NewReader([]byte{0, 1, 0, 2, 0, 3})
	t0 := time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)
	now := t0
	d.now = func() time.Time { return now }
	failing := true
	d.collect = func(context.Context, string) (*inventory.Inventory, error) {
		if failing {
			return nil, os.ErrPermission
		}
		return sampleInventory(), nil
	}
	for i := range 3 {
		failing = i < 2
		now = t0.Add(time.Duration(i) * time.Hour)
		var out, errb bytes.Buffer
		dispatch([]string{"run"}, &out, &errb, d)
		st, err := run.ReadState(d.stateDir)
		if err != nil {
			t.Fatal(err)
		}
		wantFails := []int{1, 2, 0}[i]
		if st.LastRunAt != now || st.ConsecutiveFailures != wantFails {
			t.Fatalf("run %d: state %+v, stderr %q", i, st, errb.String())
		}
	}
	es, _ := os.ReadDir(filepath.Join(d.stateDir, "runs"))
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	if len(names) != 2 || names[0] != "20261114T081500Z-0003" || names[1] != "latest" {
		t.Fatalf("runs/ holds %v", names)
	}
}

func TestRunInterruptedLeavesState(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.interrupts = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	var out, errb bytes.Buffer
	dispatch([]string{"run"}, &out, &errb, d)
	st, err := run.ReadState(d.stateDir)
	if err != nil || st != (run.State{}) {
		t.Fatalf("state %+v %v", st, err)
	}
}
