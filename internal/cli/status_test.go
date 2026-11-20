package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/setup"
)

func TestStatus(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.now = func() time.Time { return time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC) }
	d.service = func() (setup.Service, error) {
		return setup.Service{Manager: setup.Systemd, Installed: true, Running: true}, nil
	}
	last := time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC)
	id := "20261116T070000Z-0a0b"
	dir, err := run.CreateFolder(d.stateDir, id)
	if err != nil {
		t.Fatal(err)
	}
	rec := run.NewRecord(id, last, "schedule", map[string]string{"grypeDB": "2026-11-16T03:00:00Z", "kernelData": "2026-11-15T07:00:00Z", "agentCli": "claude 2.1.309"})
	if err := run.WriteJSON(filepath.Join(dir, "run.json"), rec, 0o640); err != nil {
		t.Fatal(err)
	}
	run.WriteState(d.stateDir, run.State{LastRun: id, LastRunAt: last, LastStatus: "partial", LastReviewed: "20261113T070000Z-0c0d",
		LastReviewedAt: time.Date(2026, 11, 13, 7, 30, 0, 0, time.UTC), ConsecutiveFailures: 2})
	var out, errb bytes.Buffer
	if code := dispatch([]string{"status"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	want := `Service:           running (systemd)
Last run:          20261116T070000Z-0a0b, partial, 2026-11-16 07:00 UTC (4h ago)
Next run:          2026-11-16 13:00 UTC
Last reviewed:     20261113T070000Z-0c0d, review made 2026-11-13 07:30 UTC (3d ago)
Failures in a row: 2
Zosia:             not connected
Grype database:    built 2026-11-16 03:00 UTC (8h ago) (as of the last run)
Kernel CNA data:   checked 2026-11-15 07:00 UTC (28h ago) (as of the last run)
Agent CLI:         claude 2.1.309 (as of the last run)
`
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
}

func TestStatusBeforeTheFirstRun(t *testing.T) {
	d := testDeps(t, nil, nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"status"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	want := `Service:           not installed; set it up with: tripcoil setup
Last run:          none yet
Next run:          none: the service is not running
Last reviewed:     none yet
Failures in a row: 0
Zosia:             not connected
Grype database:    unknown until a run has used it
Kernel CNA data:   unknown until a run has used it
Agent CLI:         claude, version unknown until a review has run
`
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	d.service = func() (setup.Service, error) {
		return setup.Service{Manager: setup.OpenRC, Installed: true, Running: true}, nil
	}
	out.Reset()
	dispatch([]string{"status"}, &out, &errb, d)
	if !strings.Contains(out.String(), "Service:           running (openrc)\n") || !strings.Contains(out.String(), "Next run:          due now\n") {
		t.Fatalf("got\n%s", out.String())
	}
	d.service = func() (setup.Service, error) {
		return setup.Service{}, errors.New("this host runs neither systemd nor OpenRC")
	}
	out.Reset()
	dispatch([]string{"status"}, &out, &errb, d)
	if !strings.Contains(out.String(), "Service:           this host runs neither systemd nor OpenRC\n") {
		t.Fatalf("got\n%s", out.String())
	}
}

func TestStatusWarnings(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.now = func() time.Time { return time.Date(2026, 11, 16, 23, 0, 0, 0, time.UTC) }
	d.service = func() (setup.Service, error) {
		return setup.Service{Manager: setup.Systemd, Installed: true, Running: true}, nil
	}
	run.WriteState(d.stateDir, run.State{LastRun: "x", LastRunAt: time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC), LastStatus: "complete"})
	var out, errb bytes.Buffer
	if code := dispatch([]string{"status"}, &out, &errb, d); code != 0 ||
		!strings.Contains(out.String(), "Warning:           no run has finished for more than two intervals; see the service's log\n") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	os.WriteFile(filepath.Join(d.stateDir, "state.json"), []byte("{"), 0o600)
	out.Reset()
	if code := dispatch([]string{"status"}, &out, &errb, d); code != 0 ||
		!strings.Contains(out.String(), "State:             state.json is damaged and starts over at the next run: unexpected end of JSON input\n") ||
		!strings.Contains(out.String(), "Last run:          none yet\n") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestStatusRefusals(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.euid = func() int { return 1000 }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"status"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func TestStatusZosia(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.now = func() time.Time { return time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC) }
	d.zosiaSecret = func(string) (string, bool, error) { return "zosia_x", true, nil }
	at := time.Date(2026, 11, 16, 7, 1, 0, 0, time.UTC)
	for _, c := range []struct {
		zosia *run.Zosia
		want  string
	}{
		{nil, "connected, no report sent yet"},
		{&run.Zosia{LastAttemptAt: at, LastRun: "x", LastSentAt: at, LastURL: "https://zosiasec.com/app/reports/1"},
			"last report sent 2026-11-16 07:01 UTC (3h ago) (https://zosiasec.com/app/reports/1)"},
		{&run.Zosia{LastAttemptAt: at, LastRun: "x", LastError: &run.ZosiaError{Code: "BAD_SECRET", Message: "This secret is unknown or was revoked."}},
			"last send failed 2026-11-16 07:01 UTC (3h ago): This secret is unknown or was revoked. (BAD_SECRET)"},
	} {
		run.WriteState(d.stateDir, run.State{Zosia: c.zosia})
		var out, errb bytes.Buffer
		if code := dispatch([]string{"status"}, &out, &errb, d); code != 0 || !strings.Contains(out.String(), "Zosia:             "+c.want+"\n") {
			t.Errorf("exit %d, want %q in\n%s", code, c.want, out.String())
		}
	}
	d.zosiaSecret = func(string) (string, bool, error) {
		return "", true, errors.New("zosia.secretFile /etc/tripcoil/zosia.secret must be owned by root")
	}
	var out, errb bytes.Buffer
	dispatch([]string{"status"}, &out, &errb, d)
	if !strings.Contains(out.String(), "Zosia:             secret file unusable: zosia.secretFile /etc/tripcoil/zosia.secret must be owned by root\n") {
		t.Errorf("got\n%s", out.String())
	}
}
