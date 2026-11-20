package setup

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/run"
)

func updated(t *testing.T, m Manager, running bool) *fakeHost {
	t.Helper()
	f, _ := installed(t, m)
	if !running {
		f.fail["systemctl is-active"], f.fail["rc-service tripcoil status"] = true, true
	}
	return f
}

func TestRestartUpdatedIdle(t *testing.T) {
	for m, want := range map[Manager][]string{
		Systemd: {"systemctl is-active --quiet tripcoil.service", "systemctl restart tripcoil.service"},
		OpenRC:  {"rc-service tripcoil status", "rc-service tripcoil restart"},
	} {
		f := updated(t, m, true)
		if err := f.RestartUpdated("/var/lib/tripcoil"); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if !slices.Equal(f.cmds, want) || f.out.String() != "Restarted the tripcoil service.\n" {
			t.Errorf("%s: commands %q, want %q; output %q", m, f.cmds, want, f.out.String())
		}
	}
}

func TestRestartUpdatedServiceNotRunning(t *testing.T) {
	f := updated(t, Systemd, false)
	if err := f.RestartUpdated("/var/lib/tripcoil"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"systemctl is-active --quiet tripcoil.service"}; !slices.Equal(f.cmds, want) || f.out.Len() != 0 {
		t.Errorf("commands %q, want %q; output %q", f.cmds, want, f.out.String())
	}
}

func TestRestartUpdatedRunInProgress(t *testing.T) {
	const question = "A run is in progress. Interrupt it and restart the service now? yes or no [no]: "
	for _, c := range []struct {
		answer  string
		restart bool
		out     string
	}{
		{"yes\n", true, question + "Restarted the tripcoil service.\n"},
		{"y\n", true, question + "Restarted the tripcoil service.\n"},
		{"no\n", false, question + "Restart the service to use the new version: sudo systemctl restart tripcoil\n"},
		{"n\n", false, question + "Restart the service to use the new version: sudo systemctl restart tripcoil\n"},
		{"\n", false, question + "Restart the service to use the new version: sudo systemctl restart tripcoil\n"},
		{"", false, question + "\nRestart the service to use the new version: sudo systemctl restart tripcoil\n"},
	} {
		f := updated(t, Systemd, true)
		f.Sudo = "sudo "
		f.In = strings.NewReader(c.answer)
		unlock, err := run.Lock(filepath.Join(f.Root, "var/lib/tripcoil"), func() {})
		if err != nil {
			t.Fatal(err)
		}
		err = f.RestartUpdated("/var/lib/tripcoil")
		unlock()
		if err != nil {
			t.Fatalf("%q: %v", c.answer, err)
		}
		if got := slices.Contains(f.cmds, "systemctl restart tripcoil.service"); got != c.restart || f.out.String() != c.out {
			t.Errorf("%q: restarted %v, want %v; output %q, want %q", c.answer, got, c.restart, f.out.String(), c.out)
		}
	}
}

func TestRestartUpdatedOpenRCHint(t *testing.T) {
	f := updated(t, OpenRC, true)
	f.In = strings.NewReader("no\n")
	unlock, err := run.Lock(filepath.Join(f.Root, "var/lib/tripcoil"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := f.RestartUpdated("/var/lib/tripcoil"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(f.out.String(), "Restart the service to use the new version: rc-service tripcoil restart\n") {
		t.Errorf("output %q", f.out.String())
	}
}

func TestRestartUpdatedFails(t *testing.T) {
	f := updated(t, Systemd, true)
	f.fail["systemctl restart"] = true
	f.replies["systemctl restart tripcoil.service"] = "Job for tripcoil.service failed.\n"
	err := f.RestartUpdated("/var/lib/tripcoil")
	if err == nil || err.Error() != "systemctl restart tripcoil.service: exit status 3: Job for tripcoil.service failed." {
		t.Fatalf("error %v", err)
	}
}
