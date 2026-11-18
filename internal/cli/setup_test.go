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
	d.setup = func(o setup.Options, out io.Writer) (bool, error) { got = o; return false, nil }
	d.doctor.packages = func(context.Context) error { t.Fatal("doctor must not run"); return nil }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"setup", "--agent", "codex", "--yes"}, &out, &errb, d); code != 0 || got != (setup.Options{Agent: "codex", Yes: true}) ||
		out.String() != "" {
		t.Fatalf("exit %d, options %+v, stdout %q, stderr %q", code, got, out.String(), errb.String())
	}
	d.setup = func(setup.Options, io.Writer) (bool, error) {
		return false, errors.New("this host runs neither systemd nor OpenRC")
	}
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "tripcoil setup: this host runs neither") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func TestSetupRunsDoctor(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	d.setup = func(o setup.Options, out io.Writer) (bool, error) {
		io.WriteString(out, "· The user tripcoil-agent exists.\n")
		return true, nil
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
