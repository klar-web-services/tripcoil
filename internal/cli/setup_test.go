package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/setup"
)

func TestSetupCommand(t *testing.T) {
	d := testDeps(t, nil, nil)
	var got setup.Options
	d.setup = func(o setup.Options, out io.Writer) (bool, func() error, error) { got = o; return false, nil, nil }
	d.doctor.packages = func(context.Context) error { t.Fatal("doctor must not run"); return nil }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"setup", "--agent", "codex", "--yes"}, &out, &errb, d); code != 0 || got != (setup.Options{Agent: "codex", Yes: true}) ||
		out.String() != "" {
		t.Fatalf("exit %d, options %+v, stdout %q, stderr %q", code, got, out.String(), errb.String())
	}
	d.setup = func(setup.Options, io.Writer) (bool, func() error, error) {
		return false, nil, errors.New("this host runs neither systemd nor OpenRC")
	}
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "tripcoil setup: this host runs neither") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func TestSetupRunsDoctor(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	d.setup = func(o setup.Options, out io.Writer) (bool, func() error, error) {
		io.WriteString(out, "· The user tripcoil-agent exists.\n")
		return true, nil, nil
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 0 ||
		!strings.HasPrefix(out.String(), "· The user tripcoil-agent exists.\n\nChecking the host (tripcoil doctor):\n✓ ") || !strings.HasSuffix(out.String(), "Every check passed.\n") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	d.doctor.grype = func(context.Context) error { return errors.New("no route to host") }
	out.Reset()
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 1 || !strings.HasSuffix(out.String(), "Some checks failed.\n") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestSetupStartsTheServiceAfterDoctor(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	running := false
	d.service = func() (setup.Service, error) {
		return setup.Service{Manager: setup.Systemd, Installed: true, Running: running}, nil
	}
	var out, errb bytes.Buffer
	d.setup = func(o setup.Options, w io.Writer) (bool, func() error, error) {
		io.WriteString(w, "✓ Installed the tripcoil service; it starts after the checks.\n")
		return true, func() error {
			if checked == "" {
				t.Error("the service started before doctor's checks")
			}
			running = true
			io.WriteString(w, "✓ Started the tripcoil service.\n")
			return nil
		}, nil
	}
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 0 || !running ||
		!strings.Contains(out.String(), "\n· The tripcoil service is installed and starts after the checks.\n") ||
		!strings.HasSuffix(out.String(), "Every check passed.\n✓ Started the tripcoil service.\n") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}

	running = false
	d.doctor.grype = func(context.Context) error { return errors.New("no route to host") }
	d.setup = func(o setup.Options, w io.Writer) (bool, func() error, error) {
		return true, func() error { running = true; return nil }, nil
	}
	out.Reset()
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 1 || !running {
		t.Fatalf("a failed check: exit %d, started %v\n%s", code, running, out.String())
	}

	d.setup = func(o setup.Options, w io.Writer) (bool, func() error, error) {
		return true, func() error { return errors.New("systemctl start tripcoil.service: exit status 1: failed") }, nil
	}
	errb.Reset()
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 2 || errb.String() != "tripcoil setup: systemctl start tripcoil.service: exit status 1: failed\n" {
		t.Fatalf("a failed start: exit %d, stderr %q", code, errb.String())
	}
}

func TestSetupRefusals(t *testing.T) {
	d := testDeps(t, nil, nil)
	for _, c := range []struct {
		args []string
		euid int
		msg  string
	}{
		{[]string{"setup", "--agent", "gemini"}, 0, "--agent must be claude, codex or none"},
		{[]string{"setup", "now"}, 0, `unexpected argument "now"`},
		{[]string{"setup"}, 1000, "must run as root"},
	} {
		d.euid = func() int { return c.euid }
		var out, errb bytes.Buffer
		if code := dispatch(c.args, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), c.msg) {
			t.Errorf("%q: exit %d, stderr %q", c.args, code, errb.String())
		}
	}
}
