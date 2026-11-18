package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestScopeArgs(t *testing.T) {
	got := scopeArgs("/usr/bin/systemd-run", "/usr/local/bin/tripcoil", 4242, true, []string{"--json", "--no-review"})
	want := []string{"/usr/bin/systemd-run", "--scope", "--quiet", "--collect", "--unit=tripcoil-run-4242", "-p", "CPUWeight=20",
		"-p", "MemoryMax=4G", "-p", "OOMPolicy=continue", "--", "/usr/local/bin/tripcoil", "run", "--json", "--no-review"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if got := scopeArgs("/usr/bin/systemd-run", "/t", 1, false, nil); slices.Contains(got, "OOMPolicy=continue") {
		t.Fatalf("systemd before 252 refuses OOMPolicy for a scope: %q", got)
	}
}

func script(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunScoped(t *testing.T) {
	systemdRun := script(t, `while [ "$1" != "--" ]; do shift; done; shift; exec "$@"`)
	run := script(t, `[ "$TRIPCOIL_SCOPE" = 1 ] && printf x >&3; exit 5`)
	if code, ran, err := runScoped([]string{systemdRun, "--scope", "--", run}); code != 5 || !ran || err != nil {
		t.Fatalf("code %d, ran %v, err %v", code, ran, err)
	}
	failing := script(t, `echo "Failed to start transient scope unit" >&2; exit 1`)
	if code, ran, err := runScoped([]string{failing, "--", run}); ran || err == nil || !strings.Contains(err.Error(), "did not start the scope") {
		t.Fatalf("code %d, ran %v, err %v", code, ran, err)
	}
	killed := script(t, `printf x >&3; kill -KILL $$`)
	if code, ran, _ := runScoped([]string{systemdRun, "--", killed}); code != 2 || !ran {
		t.Fatalf("a killed run: code %d, ran %v", code, ran)
	}
	killedEarly := script(t, `kill -KILL $$`)
	if code, ran, _ := runScoped([]string{killedEarly, "--", run}); code != 2 || !ran {
		t.Fatalf("systemd-run killed: code %d, ran %v", code, ran)
	}
}

func TestRunEntersItsScope(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var got []string
	d.enterScope = func(args []string) (int, bool, error) { got = args; return 1, true, nil }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run", "--no-review"}, &out, &errb, d); code != 1 || !slices.Equal(got, []string{"--no-review"}) {
		t.Fatalf("exit %d, scope args %q", code, got)
	}
	if _, err := os.Stat(filepath.Join(d.stateDir, "runs")); !os.IsNotExist(err) {
		t.Fatal("the run in the scope does the run, not this one")
	}
	d.enterScope = func([]string) (int, bool, error) { return 0, false, errors.New("systemd-run is not installed") }
	if code := dispatch([]string{"run", "--no-review"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "cannot move the run into a transient scope, so only its nice level makes it light: systemd-run is not installed") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestRunRefusalsComeBeforeTheScope(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.euid = func() int { return 1000 }
	d.enterScope = func([]string) (int, bool, error) {
		t.Fatal("a refused run must not move into a scope")
		return 0, false, nil
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
}
