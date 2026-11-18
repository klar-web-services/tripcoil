package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/run"
)

func daemonDeps(t *testing.T, stopAfter int) (deps, *[]time.Time) {
	d := testDeps(t, sampleInventory(), nil)
	d.random = bytes.NewReader(bytes.Repeat([]byte{0xab}, 64))
	now := time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	d.after = func(w time.Duration) <-chan time.Time {
		now = now.Add(w)
		c := make(chan time.Time, 1)
		c <- now
		return c
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.interrupts = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	var runs []time.Time
	d.collect = func(context.Context, string) (*inventory.Inventory, error) {
		runs = append(runs, now)
		if len(runs) == stopAfter {
			cancel()
		}
		now = now.Add(time.Minute)
		return sampleInventory(), nil
	}
	return d, &runs
}

func TestDaemonRunsEveryInterval(t *testing.T) {
	d, runs := daemonDeps(t, 3)
	if err := os.WriteFile(d.configPath, []byte("version: 1\ninterval: 2h\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"daemon"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	t0 := time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)
	want := []time.Time{t0, t0.Add(2 * time.Hour), t0.Add(4 * time.Hour)}
	if len(*runs) != 3 || (*runs)[1] != want[1] || (*runs)[2] != want[2] {
		t.Fatalf("runs at %v", *runs)
	}
	st, _ := run.ReadState(d.stateDir)
	rec, err := run.ReadRecord(d.stateDir + "/runs/" + st.LastRun)
	if err != nil || rec.Trigger != "schedule" || st.LastRunAt != want[1] {
		t.Fatalf("state %+v, last run %+v %v", st, rec, err)
	}
	for _, s := range []string{"Tripcoil daemon started: a run every 2h0m0s.", "Next run at 2026-11-14T08:15:00Z.", ": complete.", "Tripcoil daemon stopped."} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("stdout lacks %q:\n%s", s, out.String())
		}
	}
}

func TestDaemonWaitsForTheLastRun(t *testing.T) {
	d, runs := daemonDeps(t, 1)
	last := time.Date(2026, 11, 14, 5, 15, 0, 0, time.UTC)
	if err := run.WriteState(d.stateDir, run.State{LastRun: "x", LastRunAt: last}); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	dispatch([]string{"daemon"}, &out, &errb, d)
	if len(*runs) != 1 || (*runs)[0] != last.Add(6*time.Hour) {
		t.Fatalf("runs at %v", *runs)
	}
}

func TestDaemonReload(t *testing.T) {
	d, _ := daemonDeps(t, 1)
	os.WriteFile(d.configPath, []byte("version: 1\ninterval: 1h\n"), 0o644)
	hup := make(chan struct{}, 1)
	d.hangups = func() <-chan struct{} { return hup }
	waits := 0
	d.after = func(time.Duration) <-chan time.Time {
		waits++
		switch waits {
		case 1:
			os.WriteFile(d.configPath, []byte("version: 1\ninterval: 1m\n"), 0o644)
		case 2:
			os.WriteFile(d.configPath, []byte("version: 1\ninterval: 2h\n"), 0o644)
		default:
			_, stop := d.interrupts()
			stop()
			return nil
		}
		hup <- struct{}{}
		return nil
	}
	run.WriteState(d.stateDir, run.State{LastRun: "x", LastRunAt: time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)})
	var out, errb bytes.Buffer
	dispatch([]string{"daemon"}, &out, &errb, d)
	if !strings.Contains(errb.String(), "interval must be at least 15m") || !strings.Contains(errb.String(), "The configuration stays as it was.") {
		t.Fatalf("stderr %q", errb.String())
	}
	for _, s := range []string{"Next run at 2026-11-14T07:00:00Z.\nNext run at 2026-11-14T07:00:00Z.\nReloaded", "Next run at 2026-11-14T08:00:00Z."} {
		if !strings.Contains(out.String(), s) {
			t.Fatalf("stdout lacks %q:\n%s", s, out.String())
		}
	}
}

func TestDaemonRefusals(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"daemon", "--check-config"}, &out, &errb, d); code != 0 {
		t.Fatalf("a missing config is valid: exit %d %q", code, errb.String())
	}
	os.WriteFile(d.configPath, []byte("version: 2\n"), 0o644)
	if code := dispatch([]string{"daemon", "--check-config"}, &out, &errb, d); code != 78 || !strings.Contains(errb.String(), "CONFIG_INVALID") {
		t.Fatalf("exit %d %q", code, errb.String())
	}
	errb.Reset()
	if code := dispatch([]string{"daemon"}, &out, &errb, d); code != 78 || !strings.Contains(errb.String(), "version must be 1") {
		t.Fatalf("exit %d %q", code, errb.String())
	}
	d.euid = func() int { return 1000 }
	if code := dispatch([]string{"daemon"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("exit %d %q", code, errb.String())
	}
}
