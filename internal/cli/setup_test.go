package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/setup"
)

func TestSetupCommand(t *testing.T) {
	d := testDeps(t, nil, nil)
	var got setup.Options
	d.setup = func(o setup.Options, out io.Writer) error { got = o; return nil }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"setup", "--agent", "codex", "--yes"}, &out, &errb, d); code != 0 || got != (setup.Options{Agent: "codex", Yes: true}) {
		t.Fatalf("exit %d, options %+v, stderr %q", code, got, errb.String())
	}
	d.setup = func(setup.Options, io.Writer) error { return errors.New("this host runs neither systemd nor OpenRC") }
	if code := dispatch([]string{"setup"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "tripcoil setup: this host runs neither") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
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
