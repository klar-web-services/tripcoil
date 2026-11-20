package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/config"
)

const zosiaPrompt = "Zosia secret from https://zosiasec.com/app/secrets (input hidden, empty to skip): \n"

func zosiaHost(t *testing.T, input string) (*fakeHost, *[]string) {
	f := newFake(t, Systemd)
	f.In = strings.NewReader(input)
	f.Terminal = func() bool { return true }
	f.Sudo = "sudo "
	var pinged []string
	f.PingZosia = func(url, secret string) (string, error) {
		pinged = append(pinged, url+" "+secret)
		if secret != "zosia_good" {
			return "", errors.New("This secret is unknown or was revoked.")
		}
		return "web-1", nil
	}
	return f, &pinged
}

func (f *fakeHost) secret(t *testing.T) (string, os.FileMode) {
	t.Helper()
	p := filepath.Join(f.Root, config.DefaultZosiaSecretFile)
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return "", 0
	}
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	return string(data), fi.Mode().Perm()
}

func TestSetupConnectsToZosia(t *testing.T) {
	f, pinged := zosiaHost(t, "  zosia_good \n")
	hidden := 0
	f.NoEcho = func() (func(), error) { hidden++; return func() { hidden-- }, nil }
	if _, _, err := f.Setup(Options{Agent: "none"}); err != nil || hidden != 0 {
		t.Fatalf("%v, hidden %d", err, hidden)
	}
	if s, mode := f.secret(t); s != "zosia_good\n" || mode != 0o600 {
		t.Fatalf("secret file %q %o", s, mode)
	}
	out := f.out.String()
	if !strings.Contains(out, zosiaPrompt+"✓ Connected to Zosia as \"web-1\".\n") || strings.Contains(out, "zosia_good") ||
		len(*pinged) != 1 || (*pinged)[0] != "https://zosiasec.com zosia_good" {
		t.Fatalf("pinged %q, output:\n%s", *pinged, out)
	}
	if left, _ := filepath.Glob(filepath.Join(f.Root, "etc/tripcoil/.zosia.secret-*")); len(left) > 0 {
		t.Fatalf("left %q", left)
	}

	f.out.Reset()
	f.In = strings.NewReader("")
	f.PingZosia = func(string, string) (string, error) { t.Fatal("already connected"); return "", nil }
	if _, _, err := f.Setup(Options{}); err != nil || !strings.Contains(f.out.String(), "· Zosia: connected (/etc/tripcoil/zosia.secret).\n") ||
		strings.Contains(f.out.String(), "Zosia secret") {
		t.Fatalf("%v:\n%s", err, f.out.String())
	}
}

func TestSetupZosiaWrongSecretThenSkipped(t *testing.T) {
	f, pinged := zosiaHost(t, "zosia_bad\n\n")
	if _, _, err := f.Setup(Options{Agent: "none"}); err != nil {
		t.Fatal(err)
	}
	want := zosiaPrompt + "! Zosia: This secret is unknown or was revoked.\n" + zosiaPrompt + "· Zosia: skipped; connect later with sudo tripcoil setup.\n"
	if s, _ := f.secret(t); s != "" || len(*pinged) != 1 || !strings.Contains(f.out.String(), want) {
		t.Fatalf("secret %q, pinged %q, output:\n%s", s, *pinged, f.out.String())
	}

	f, pinged = zosiaHost(t, "zosia_bad\nzosia_worse\nzosia_good\n")
	f.Setup(Options{Agent: "none"})
	if s, _ := f.secret(t); s != "" || len(*pinged) != 2 || strings.Count(f.out.String(), "! Zosia: ") != 2 {
		t.Fatalf("a second wrong secret skips: secret %q, pinged %q, output:\n%s", s, *pinged, f.out.String())
	}
}

func TestSetupDoesNotAskForZosia(t *testing.T) {
	for _, c := range []struct {
		name   string
		o      Options
		term   bool
		config string
	}{
		{"--yes", Options{Agent: "none", Yes: true}, true, ""},
		{"no terminal", Options{Agent: "none"}, false, ""},
		{"secretFile empty", Options{}, true, "version: 1\nreview:\n  agent: none\nzosia:\n  secretFile: \"\"\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, pinged := zosiaHost(t, "zosia_good\n")
			f.Terminal = func() bool { return c.term }
			if c.config != "" {
				os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
				os.WriteFile(filepath.Join(f.Root, config.DefaultPath), []byte(c.config), 0o644)
			}
			if _, _, err := f.Setup(c.o); err != nil {
				t.Fatal(err)
			}
			if s, _ := f.secret(t); s != "" || len(*pinged) != 0 || strings.Contains(f.out.String(), "Zosia") {
				t.Fatalf("secret %q, pinged %q, output:\n%s", s, *pinged, f.out.String())
			}
		})
	}
}
