package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/setup"
)

func TestUninstallCommand(t *testing.T) {
	d := testDeps(t, nil, nil)
	var got setup.UninstallOptions
	d.uninstall = func(o setup.UninstallOptions, out io.Writer) error { got = o; return nil }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"uninstall", "--yes"}, &out, &errb, d); code != 0 || got != (setup.UninstallOptions{Yes: true, StateDir: d.stateDir}) {
		t.Fatalf("exit %d, options %+v, stderr %q", code, got, errb.String())
	}
	d.uninstall = func(setup.UninstallOptions, io.Writer) error { return errors.New("some steps failed") }
	if code := dispatch([]string{"uninstall"}, &out, &errb, d); code != 1 || !strings.Contains(errb.String(), "tripcoil uninstall: some steps failed") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func TestUninstallRefusals(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.uninstall = func(setup.UninstallOptions, io.Writer) error { t.Fatal("uninstall must not run"); return nil }
	for _, c := range []struct {
		args []string
		euid int
		msg  string
	}{
		{[]string{"uninstall", "now"}, 0, `unexpected argument "now"`},
		{[]string{"uninstall"}, 1000, "tripcoil uninstall must run as root (try: sudo tripcoil uninstall)"},
		{[]string{"uninstall", "-h"}, 0, "Usage: tripcoil uninstall [--yes]"},
	} {
		d.euid = func() int { return c.euid }
		var out, errb bytes.Buffer
		want := 2
		if c.args[len(c.args)-1] == "-h" {
			want = 0
		}
		if code := dispatch(c.args, &out, &errb, d); code != want || !strings.Contains(errb.String(), c.msg) {
			t.Errorf("%q: exit %d, stderr %q", c.args, code, errb.String())
		}
	}
	var out bytes.Buffer
	dispatch([]string{"help"}, &out, &out, d)
	if !strings.Contains(out.String(), "tripcoil uninstall       Remove what setup and the installer added (as root)") {
		t.Errorf("usage:\n%s", out.String())
	}
}
