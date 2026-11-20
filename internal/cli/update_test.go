package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateCommand(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.update = func(stdout, stderr io.Writer) error { io.WriteString(stdout, "Installed tripcoil 9.8.7\n"); return nil }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"update"}, &out, &errb, d); code != 0 || out.String() != "Installed tripcoil 9.8.7\n" || errb.Len() != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	d.update = func(io.Writer, io.Writer) error { return errors.New("nothing was updated") }
	if code := dispatch([]string{"update"}, &out, &errb, d); code != 1 || errb.String() != "tripcoil update: nothing was updated\n" {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func TestUpdateRefusals(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.update = func(io.Writer, io.Writer) error { t.Fatal("update must not run"); return nil }
	for _, c := range []struct {
		args []string
		euid int
		msg  string
	}{
		{[]string{"update", "now"}, 0, `unexpected argument "now"`},
		{[]string{"update"}, 1000, "tripcoil update must run as root (try: sudo tripcoil update)"},
		{[]string{"update", "-h"}, 0, "Usage: tripcoil update\n"},
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
	if !strings.Contains(out.String(), "\n  tripcoil update          Update to the latest release and restart the service (as root)\n") {
		t.Errorf("usage:\n%s", out.String())
	}
}

func TestInstallLatest(t *testing.T) {
	const replace = `printf 'dir=%s from=%s\n' "$TRIPCOIL_INSTALL_DIR" "$TRIPCOIL_UPDATE_FROM"
printf new > "$TRIPCOIL_INSTALL_DIR/.new" && mv "$TRIPCOIL_INSTALL_DIR/.new" "$TRIPCOIL_INSTALL_DIR/tripcoil"`
	t.Setenv("TRIPCOIL_INSTALL_DIR", "/elsewhere")
	for _, c := range []struct {
		name, base, script string
		changed            bool
		err, out, errOut   string
	}{
		{"replaced", "tripcoil", replace, true, "", "dir=%s from=1.0.3\n", ""},
		{"up to date", "tripcoil", "echo same", false, "", "same\n", ""},
		{"installer fails", "tripcoil", "echo broken >&2; exit 1", false, "nothing was updated", "", "broken\n"},
		{"renamed binary", "tc", replace, false, "is not named tripcoil, so the installer cannot replace it", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			exe := filepath.Join(dir, c.base)
			if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			changed, err := installLatest([]byte(c.script), exe, "1.0.3", &out, &errb)
			if changed != c.changed || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
				t.Fatalf("changed %v, error %v", changed, err)
			}
			if want := strings.ReplaceAll(c.out, "%s", dir); out.String() != want || errb.String() != c.errOut {
				t.Errorf("stdout %q, want %q; stderr %q, want %q", out.String(), want, errb.String(), c.errOut)
			}
			want := "old"
			if c.changed {
				want = "new"
			}
			if got, _ := os.ReadFile(exe); string(got) != want {
				t.Errorf("binary holds %q, want %q", got, want)
			}
		})
	}
}
