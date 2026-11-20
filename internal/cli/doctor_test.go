package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/setup"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

func healthy(t *testing.T, d *deps, checked *string) {
	d.service = func() (setup.Service, error) {
		return setup.Service{Manager: setup.Systemd, Installed: true, Running: true}, nil
	}
	d.doctor = doctorHost{
		packages:  func(context.Context) error { return nil },
		docker:    func(context.Context) (bool, error) { return false, nil },
		grype:     func(context.Context) error { return nil },
		agentUser: func() error { return nil },
		findCLI:   func(c, n string) (string, error) { return "/usr/local/bin/" + n, nil },
		booted:    func() bool { return true },
		bwrap:     func() error { return nil },
		check: func(_ context.Context, cfg config.Config, dir string) (string, error) {
			if _, err := os.Stat(dir); err != nil {
				t.Errorf("the check's run folder: %v", err)
			}
			*checked = dir
			return cfg.Review.Agent + " 1.0", nil
		},
	}
}

func TestDoctorPasses(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	os.MkdirAll(filepath.Join(d.stateDir, "runs", ".doctor", "agent"), 0o700)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	want := `✓ ` + d.configPath + ` does not exist, so the defaults apply.
✓ The tripcoil service is running (systemd).
✓ The package tool can read the package database.
✓ Docker answers.
✓ Zosia: not connected (optional).
✓ Grype 0.121.2 is ready.
✓ The agent's user tripcoil-agent exists.
✓ The agent CLI /usr/local/bin/claude is safely owned.
✓ The sandbox holds, and claude 1.0 answered with its credentials.
Every check passed.
`
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	if checked != filepath.Join(d.stateDir, "runs", ".doctor") {
		t.Fatalf("checked in %s", checked)
	}
	if _, err := os.Stat(checked); !os.IsNotExist(err) {
		t.Fatal("the check's run folder must be removed")
	}
}

func TestDoctorFailures(t *testing.T) {
	d := testDeps(t, nil, nil)
	d.sudo = "sudo "
	var checked string
	healthy(t, &d, &checked)
	os.WriteFile(d.configPath, []byte("version: 1\nreview:\n  agent: codex\n"), 0o644)
	d.service = func() (setup.Service, error) { return setup.Service{Manager: setup.OpenRC, Installed: true}, nil }
	d.doctor.packages = func(context.Context) error { return errors.New("cannot run dpkg-query") }
	d.doctor.docker = func(context.Context) (bool, error) { return true, nil }
	d.doctor.grype = func(context.Context) error { return errors.New("download Grype 0.121.2: no route to host") }
	d.doctor.bwrap = func() error { return errors.New("not installed") }
	d.doctor.check = func(context.Context, config.Config, string) (string, error) {
		return "codex 0.154.0", &review.Failure{Code: problem.AgentAuth, Message: "codex has no working credentials"}
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, l := range []string{
		"✗ The tripcoil service is installed but not running.\n  Fix: sudo rc-service tripcoil start; its log: /var/log/tripcoil.log\n",
		"✗ The package tool: cannot run dpkg-query\n",
		"✓ Docker is not installed, so there are no containers to audit.\n",
		"✗ Grype: download Grype 0.121.2: no route to host\n",
		"✗ bubblewrap is not installed, and Codex's own sandbox needs it.\n",
		"✗ AGENT_AUTH: codex has no working credentials\n  Fix: give the CLI credentials in review.envFile",
		"Some checks failed.\n",
	} {
		if !strings.Contains(out.String(), l) {
			t.Errorf("output lacks %q:\n%s", l, out.String())
		}
	}
}

func TestDoctorSkipsTheCheckWithoutACLI(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	d.doctor.findCLI = func(string, string) (string, error) { return "", errors.New("claude is not installed on /usr/bin") }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 1 || checked != "" {
		t.Fatalf("exit %d, checked %q", code, checked)
	}
	if !strings.Contains(out.String(), "✗ The agent CLI: claude is not installed on /usr/bin\n") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestDoctorOldSystemdPasses(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	d.doctor.check = func(context.Context, config.Config, string) (string, error) {
		return "", &review.Failure{Code: problem.ReviewUnsupported, Message: "systemd 245 is older than 247, which the review's sandbox needs"}
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "! systemd 245 is older than 247, which the review's sandbox needs: reports are audit-only.\n") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestDoctorNoReview(t *testing.T) {
	d := testDeps(t, nil, nil)
	var checked string
	healthy(t, &d, &checked)
	os.WriteFile(d.configPath, []byte("version: 1\nreview:\n  agent: none\n"), 0o644)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 0 || checked != "" {
		t.Fatalf("exit %d, checked %q", code, checked)
	}
	if !strings.HasSuffix(out.String(), "✓ review.agent is none, so there is no review to check.\nEvery check passed.\n") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestDoctorInvalidConfig(t *testing.T) {
	d := testDeps(t, nil, nil)
	os.WriteFile(d.configPath, []byte("version: 2\n"), 0o644)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 1 || !strings.Contains(out.String(), "✗ CONFIG_INVALID: invalid configuration") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	d.euid = func() int { return 1000 }
	if code := dispatch([]string{"doctor"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestDoctorZosia(t *testing.T) {
	const file = "/etc/tripcoil/zosia.secret"
	for _, c := range []struct {
		name   string
		config string
		secret func(string) (string, bool, error)
		ping   func(context.Context, string, string) (string, error)
		code   int
		want   string
	}{
		{"accepted", "zosia:\n  key: " + testZosiaKey + "\n", func(string) (string, bool, error) { return "zosia_x", true, nil },
			func(_ context.Context, url, secret string) (string, error) {
				if url != "https://zosiasec.com" || secret != "zosia_x" {
					return "", errors.New("pinged " + url)
				}
				return "taskmaster", nil
			}, 0, "✓ Zosia accepts the secret \"taskmaster\".\n"},
		{"unsafe file", "zosia:\n  key: " + testZosiaKey + "\n", func(string) (string, bool, error) {
			return "", true, errors.New("zosia.secretFile " + file + " must not be readable by group or others (chmod 600 " + file + ")")
		}, nil, 1, "✗ Zosia: zosia.secretFile " + file + " must not be readable by group or others (chmod 600 " + file + ")\n" +
			"  Fix: chmod 600 " + file + " and chown root:root " + file + "\n"},
		{"revoked", "zosia:\n  key: " + testZosiaKey + "\n  url: http://127.0.0.1:3000\n", func(string) (string, bool, error) { return "zosia_x", true, nil },
			func(context.Context, string, string) (string, error) {
				return "", &zosia.Error{Code: "BAD_SECRET", Message: "This secret is unknown or was revoked."}
			}, 1, "✗ Zosia: This secret is unknown or was revoked.\n  Fix: sudo tripcoil zosia connect --replace, or make a new secret at " +
				"http://127.0.0.1:3000/app/secrets and write it to " + file + "\n"},
		{"unreachable", "zosia:\n  key: " + testZosiaKey + "\n", func(string) (string, bool, error) { return "zosia_x", true, nil },
			func(context.Context, string, string) (string, error) {
				return "", &zosia.Error{Code: "NETWORK", Message: "cannot reach Zosia: no route to host"}
			}, 1, "✗ Zosia: cannot reach Zosia: no route to host\n"},
	} {
		d := testDeps(t, nil, nil)
		d.sudo = "sudo "
		var checked string
		healthy(t, &d, &checked)
		os.WriteFile(d.configPath, []byte("version: 1\nreview:\n  agent: none\n"+c.config), 0o644)
		d.zosiaSecret, d.pingZosia = c.secret, c.ping
		var out, errb bytes.Buffer
		if code := dispatch([]string{"doctor"}, &out, &errb, d); code != c.code || !strings.Contains(out.String(), c.want) || strings.Contains(out.String(), "zosia_x") {
			t.Errorf("%s: exit %d, want %q in\n%s", c.name, code, c.want, out.String())
		}
	}
}
