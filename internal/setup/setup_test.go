package setup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/config"
)

type fakeHost struct {
	Host
	cmds    []string
	fail    map[string]bool
	tools   map[string]bool
	users   map[string]bool
	replies map[string]string
	out     bytes.Buffer
}

func newFake(t *testing.T, m Manager) *fakeHost {
	f := &fakeHost{fail: map[string]bool{}, tools: map[string]bool{"claude": true}, users: map[string]bool{}, replies: map[string]string{}}
	root := t.TempDir()
	switch m {
	case Systemd:
		os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755)
		f.tools["useradd"] = true
		os.MkdirAll(filepath.Join(root, "usr/sbin"), 0o755)
		os.WriteFile(filepath.Join(root, "usr/sbin/nologin"), nil, 0o755)
	case OpenRC:
		os.MkdirAll(filepath.Join(root, "sbin"), 0o755)
		os.WriteFile(filepath.Join(root, "sbin/openrc-run"), nil, 0o755)
		f.tools["apk"] = true
	}
	for _, c := range []string{"systemctl is-enabled", "systemctl is-active", "rc-service tripcoil status"} {
		f.fail[c] = true
	}
	f.Host = Host{
		Root: root, Exe: "/usr/local/bin/tripcoil", Out: &f.out, In: strings.NewReader(""),
		Run: func(name string, args ...string) ([]byte, error) {
			c := strings.Join(append([]string{name}, args...), " ")
			f.cmds = append(f.cmds, c)
			switch {
			case c == "systemctl --version":
				return []byte("systemd 257 (257.13-1)\n+PAM\n"), nil
			case strings.HasPrefix(c, "useradd ") || strings.HasPrefix(c, "adduser "):
				f.users["user"] = true
			case strings.HasPrefix(c, "addgroup "):
				f.users["group"] = true
			case c == "apk add bubblewrap":
				f.tools["bwrap"] = true
			case slices.Contains([]string{"apk add nodejs npm", "pacman -S --noconfirm --needed nodejs npm", "apt-get install -y nodejs npm",
				"apt-get install -y nodejs", "dnf install -y nodejs npm", "dnf install -y nodejs"}, c):
				f.tools["node"], f.tools["npm"] = true, true
				if _, ok := f.replies["node --version"]; !ok {
					f.replies["node --version"] = "v22.11.0\n"
				}
			case c == "npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code":
				f.tools["claude"] = true
			}
			for k := range f.fail {
				if strings.HasPrefix(c, k) {
					out, ok := f.replies[c]
					if !ok {
						out = "inactive\n"
					}
					return []byte(out), errors.New("exit status 3")
				}
			}
			return []byte(f.replies[c]), nil
		},
		LookPath: func(n string) (string, error) {
			if f.tools[n] {
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		},
		UserExists:  func(string) bool { return f.users["user"] },
		GroupExists: func(string) bool { return f.users["group"] || (f.users["user"] && f.tools["useradd"]) },
		CheckBinary: func(string) error { return nil },
		FindCLI: func(command, name string) (string, error) {
			if f.tools[name] {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New(name + " is not installed")
		},
		Fetch:      func(url string) ([]byte, error) { return nil, errors.New("no network in tests") },
		Stat:       rootStat,
		Terminal:   func() bool { return false },
		NoEcho:     func() (func(), error) { return func() {}, nil },
		SetupToken: func(string) ([]byte, error) { return nil, errors.New("no claude setup-token in tests") },
	}
	return f
}

func rootStat(p string) (config.FileInfo, error) {
	fi, err := config.OSStat(p)
	fi.UID = 0
	return fi, err
}

func anyEnvFile(string) (config.FileInfo, error) {
	return config.FileInfo{Mode: 0o600, Regular: true}, nil
}

func (f *fakeHost) started() {
	for _, c := range []string{"systemctl is-enabled", "systemctl is-active", "rc-service tripcoil status"} {
		delete(f.fail, c)
	}
}

func (f *fakeHost) read(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.Root, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSetupSystemdTwice(t *testing.T) {
	f := newFake(t, Systemd)
	if _, _, err := f.Setup(Options{Agent: "codex"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl --version",
		"useradd --system --user-group --no-create-home --shell /usr/sbin/nologin tripcoil-agent",
		"systemctl is-enabled --quiet tripcoil.service", "systemctl is-active --quiet tripcoil.service",
		"systemctl daemon-reload", "systemctl enable --quiet tripcoil.service", "systemctl start tripcoil.service",
	}
	if !slices.Equal(f.cmds, want) {
		t.Fatalf("commands\n%q\nwant\n%q", f.cmds, want)
	}
	if c, err := config.Parse("x", []byte(f.read(t, config.DefaultPath)), anyEnvFile); err != nil || c.Review.Agent != "codex" ||
		c.Review.EnvFile != "/etc/tripcoil/agent.env" {
		t.Fatalf("config %+v %v", c, err)
	}
	if fi, err := os.Stat(filepath.Join(f.Root, EnvFilePath)); err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
		t.Fatalf("agent.env: %v %v", fi, err)
	}
	unit := f.read(t, UnitPath)
	for _, l := range []string{"ExecStart=/usr/local/bin/tripcoil daemon\n", "Nice=10\n", "IOSchedulingClass=idle\n", "CPUWeight=20\n", "MemoryMax=4G\n",
		"RestartPreventExitStatus=78\n", "OOMPolicy=continue\n"} {
		if !strings.Contains(unit, l) {
			t.Errorf("the unit lacks %q", l)
		}
	}
	for _, l := range []string{"✓ Created the user and group tripcoil-agent.", "✓ Wrote /etc/tripcoil/tripcoil.yaml (review.agent: codex) and /etc/tripcoil/agent.env.",
		"✓ Installed and started the tripcoil service.", "       npm install -g @openai/codex",
		"Add it to /etc/tripcoil/agent.env as the line CODEX_API_KEY=<key>:\n       vi /etc/tripcoil/agent.env\n"} {
		if !strings.Contains(f.out.String(), l) {
			t.Errorf("output lacks %q:\n%s", l, f.out.String())
		}
	}

	f.started()
	f.cmds, f.out = nil, bytes.Buffer{}
	os.Remove(filepath.Join(f.Root, EnvFilePath))
	if _, _, err := f.Setup(Options{Agent: "claude", Yes: true}); err == nil || !strings.Contains(err.Error(), "review.envFile /etc/tripcoil/agent.env cannot be read") {
		t.Fatalf("an existing config is not rewritten, and does not create agent.env: %v", err)
	}
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), nil, 0o600)
	f.cmds, f.out = nil, bytes.Buffer{}
	if _, _, err := f.Setup(Options{Agent: "claude", Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.cmds, []string{"systemctl --version", "systemctl is-enabled --quiet tripcoil.service", "systemctl is-active --quiet tripcoil.service"}) {
		t.Fatalf("the second setup ran %q", f.cmds)
	}
	for _, l := range []string{"· The user tripcoil-agent exists.", "! --agent claude: /etc/tripcoil/tripcoil.yaml keeps review.agent: codex",
		"· The tripcoil service is installed and running.", "Nothing changed."} {
		if !strings.Contains(f.out.String(), l) {
			t.Errorf("output lacks %q:\n%s", l, f.out.String())
		}
	}
}

func TestSetupRestartsAChangedService(t *testing.T) {
	f := newFake(t, Systemd)
	f.started()
	f.users["user"] = true
	os.MkdirAll(filepath.Join(f.Root, "etc/systemd/system"), 0o755)
	os.WriteFile(filepath.Join(f.Root, UnitPath), []byte("old"), 0o644)
	if _, _, err := f.Setup(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.cmds, "systemctl daemon-reload") || !slices.Contains(f.cmds, "systemctl restart tripcoil.service") {
		t.Fatalf("commands %q", f.cmds)
	}
}

func TestSetupOpenRC(t *testing.T) {
	f := newFake(t, OpenRC)
	f.In = strings.NewReader("maybe\n\nyes\n")
	if _, _, err := f.Setup(Options{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"addgroup -S tripcoil-agent", "adduser -S -D -H -s /sbin/nologin -G tripcoil-agent tripcoil-agent",
		"apk add bubblewrap", "rc-update show default", "rc-service tripcoil status", "rc-update add tripcoil default", "rc-service tripcoil start"}
	if !slices.Equal(f.cmds, want) {
		t.Fatalf("commands\n%q\nwant\n%q", f.cmds, want)
	}
	if !strings.Contains(f.read(t, config.DefaultPath), "agent: claude") {
		t.Fatal("the default agent is claude")
	}
	init := f.read(t, InitScriptPath)
	if !strings.Contains(init, "command=/usr/local/bin/tripcoil\n") || !strings.Contains(init, `"$command" daemon --check-config`) ||
		!strings.Contains(init, `retry="TERM/120/KILL/5"`) {
		t.Fatalf("init script:\n%s", init)
	}
	if fi, _ := os.Stat(filepath.Join(f.Root, InitScriptPath)); fi.Mode().Perm() != 0o755 {
		t.Fatalf("init script mode %v", fi.Mode())
	}
	if !strings.Contains(f.read(t, ConfDPath), "cpu.weight 20\nmemory.max 4294967296\n") {
		t.Fatalf("conf.d:\n%s", f.read(t, ConfDPath))
	}
	if strings.Count(f.out.String(), "Which agent CLI") != 2 {
		t.Fatalf("output:\n%s", f.out.String())
	}
}

func TestSetupOpenRCWithoutBubblewrap(t *testing.T) {
	f := newFake(t, OpenRC)
	f.In = strings.NewReader("no\n")
	_, _, err := f.Setup(Options{Agent: "claude"})
	if err == nil || !strings.Contains(err.Error(), "reviews cannot run without it") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, OpenRC)
	if _, _, err := f.Setup(Options{Agent: "none"}); err != nil || slices.Contains(f.cmds, "apk add bubblewrap") {
		t.Fatalf("no review needs no bubblewrap: %v %q", err, f.cmds)
	}
}

func TestSetupRefusals(t *testing.T) {
	f := newFake(t, Systemd)
	f.Exe = "/home/fkws/bin/tripcoil"
	if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "is under /home") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	f.Exe = "/opt/my tools/tripcoil"
	if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "has characters the service files cannot hold") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	f.CheckBinary = func(string) error { return errors.New("/usr/local/bin is not owned by root") }
	if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "the service would run /usr/local/bin/tripcoil as root, but /usr/local/bin is not owned by root") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	f.users["group"] = true
	f.tools["useradd"] = false
	f.GroupExists = func(string) bool { return true }
	if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "only one of the user and the group") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, "")
	if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "neither systemd nor OpenRC") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, config.DefaultPath), []byte("version: 2\n"), 0o644)
	if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "version must be 1") {
		t.Fatalf("got %v", err)
	}
}

func TestSetupWarnsAboutOldSystemd(t *testing.T) {
	f := newFake(t, Systemd)
	run := f.Run
	f.Run = func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" && args[0] == "--version" {
			return []byte("systemd 245 (245.4-4ubuntu3)\n"), nil
		}
		return run(name, args...)
	}
	if _, _, err := f.Setup(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "! systemd 245 is older than 247, which the review's sandbox needs: reports will be audit-only.") {
		t.Fatalf("output:\n%s", f.out.String())
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	for _, a := range []string{"claude", "codex", "none"} {
		c, err := config.Parse("x", []byte(DefaultConfig(a)), anyEnvFile)
		if err != nil || c.Review.Agent != a {
			t.Fatalf("%s: %+v %v", a, c, err)
		}
		d := config.Default()
		if c.Review.EnvFile != EnvFilePath {
			t.Fatalf("%s: review.envFile %q", a, c.Review.EnvFile)
		}
		if c.Interval != d.Interval || c.Review.Timeout != d.Review.Timeout || c.Retention != d.Retention || c.Review.MemoryMax != d.Review.MemoryMax {
			t.Fatalf("%s: the written config must hold the defaults: %+v", a, c)
		}
	}
}

func TestService(t *testing.T) {
	for _, m := range []Manager{Systemd, OpenRC} {
		f := newFake(t, m)
		if s, err := f.Service(); err != nil || s != (Service{Manager: m}) {
			t.Fatalf("%s before setup: %+v %v", m, s, err)
		}
		if _, _, err := f.Setup(Options{Agent: "none"}); err != nil {
			t.Fatal(err)
		}
		if s, _ := f.Service(); s != (Service{Manager: m, Installed: true}) {
			t.Fatalf("%s stopped: %+v", m, s)
		}
		f.started()
		if s, _ := f.Service(); s != (Service{Manager: m, Installed: true, Running: true}) {
			t.Fatalf("%s running: %+v", m, s)
		}
	}
}

func TestSetupKeepsAnExistingEnvFile(t *testing.T) {
	f := newFake(t, Systemd)
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), []byte("CLAUDE_CODE_OAUTH_TOKEN=x\n"), 0o600)
	if _, _, err := f.Setup(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.read(t, EnvFilePath); got != "CLAUDE_CODE_OAUTH_TOKEN=x\n" {
		t.Fatalf("agent.env %q", got)
	}
	if out := f.out.String(); !strings.Contains(out, "✓ Wrote /etc/tripcoil/tripcoil.yaml (review.agent: claude).\n") || strings.Contains(out, "and /etc/tripcoil/agent.env") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestSetupRefusesABadEnvFile(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		stat       config.StatFunc
	}{
		{"owner", "review.envFile /etc/tripcoil/agent.env must be owned by root", func(p string) (config.FileInfo, error) {
			fi, err := config.OSStat(p)
			fi.UID = 1000
			return fi, err
		}},
		{"mode", "review.envFile /etc/tripcoil/agent.env must not be readable by group or others", func(p string) (config.FileInfo, error) {
			fi, err := rootStat(p)
			fi.Mode = 0o644
			return fi, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, Systemd)
			f.Stat = tc.stat
			if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("a new config: %v", err)
			}
			if _, _, err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("an existing config: %v", err)
			}
		})
	}
}

func TestSudo(t *testing.T) {
	for _, c := range []struct {
		euid     int
		sudoUser string
		want     string
	}{{0, "", ""}, {0, "alice", "sudo "}, {1000, "", "sudo "}, {1000, "alice", "sudo "}} {
		if got := Sudo(c.euid, c.sudoUser); got != c.want {
			t.Errorf("Sudo(%d, %q) = %q, want %q", c.euid, c.sudoUser, got, c.want)
		}
	}
}

func TestNextSteps(t *testing.T) {
	claude := nextSteps("claude", "/etc/tripcoil/agent.env", "sudo ", false, false)
	for _, l := range []string{"sudo npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code", `"claude setup-token"`, "subscription (Pro or Max), not API billing",
		"  3. Add it to /etc/tripcoil/agent.env as the line CLAUDE_CODE_OAUTH_TOKEN=<token>:\n       sudoedit /etc/tripcoil/agent.env\n"} {
		if !strings.Contains(claude, l) {
			t.Errorf("claude lacks %q:\n%s", l, claude)
		}
	}
	old := nextSteps("codex", "", "", false, false)
	for _, l := range []string{"       npm install -g @openai/codex", "per use through the OpenAI API", "Store it root-only as the line CODEX_API_KEY=<key>",
		"set review.envFile in\n     /etc/tripcoil/tripcoil.yaml", "       install -m 600 /dev/null /etc/tripcoil/agent.env\n       vi /etc/tripcoil/agent.env\n"} {
		if !strings.Contains(old, l) {
			t.Errorf("codex without envFile lacks %q:\n%s", l, old)
		}
	}
	installed := nextSteps("claude", "/etc/tripcoil/agent.env", "", true, false)
	if strings.Contains(installed, "npm install") || !strings.Contains(installed, "  1. Create a token") || !strings.Contains(installed, "  2. Add it to") {
		t.Errorf("claude installed:\n%s", installed)
	}
	if s := nextSteps("codex", "/etc/tripcoil/agent.env", "", true, false); strings.Contains(s, "Install Codex") || !strings.Contains(s, "  1. Create an OpenAI API key") {
		t.Errorf("codex installed:\n%s", s)
	}
	if s := nextSteps("claude", "/etc/tripcoil/agent.env", "", true, true); s != "\nThen check the host: tripcoil doctor\n" {
		t.Errorf("nothing left:\n%s", s)
	}
	keyed := nextSteps("codex", "/etc/tripcoil/agent.env", "sudo ", false, true)
	if keyed != "\nNext, install the agent CLI:\n  1. Install Codex system-wide (root-owned, outside /home), for example:\n       sudo npm install -g @openai/codex\nThen check the host: sudo tripcoil doctor\n" {
		t.Errorf("codex with a key:\n%s", keyed)
	}
}

func TestSetupDefersTheStartWhenReady(t *testing.T) {
	for _, m := range []Manager{Systemd, OpenRC} {
		f := newFake(t, m)
		ready, start, err := f.Setup(Options{Agent: "none"})
		if err != nil || !ready || start == nil {
			t.Fatalf("%s: ready %v, start %v, %v", m, ready, start != nil, err)
		}
		startCmd, restartCmd, enable := "systemctl start tripcoil.service", "systemctl restart tripcoil.service", "systemctl enable --quiet tripcoil.service"
		if m == OpenRC {
			startCmd, restartCmd, enable = "rc-service tripcoil start", "rc-service tripcoil restart", "rc-update add tripcoil default"
		}
		if !slices.Contains(f.cmds, enable) || slices.Contains(f.cmds, startCmd) ||
			!strings.Contains(f.out.String(), "✓ Installed the tripcoil service; it starts after the checks.\n") {
			t.Fatalf("%s: commands %q\n%s", m, f.cmds, f.out.String())
		}
		f.cmds = nil
		if err := start(); err != nil || !slices.Equal(f.cmds, []string{startCmd}) || !strings.HasSuffix(f.out.String(), "✓ Started the tripcoil service.\n") {
			t.Fatalf("%s: start %v, commands %q\n%s", m, err, f.cmds, f.out.String())
		}

		f.started()
		f.replies["rc-update show default"] = " tripcoil | default\n"
		f.out.Reset()
		if ready, start, err := f.Setup(Options{}); err != nil || !ready || start != nil || !strings.Contains(f.out.String(), "Nothing changed.\n") {
			t.Fatalf("%s again: ready %v, start %v, %v\n%s", m, ready, start != nil, err, f.out.String())
		}

		status := "systemctl is-active"
		if m == OpenRC {
			status = "rc-service tripcoil status"
		}
		f.fail[status] = true
		f.out.Reset()
		f.cmds = nil
		ready, start, err = f.Setup(Options{})
		if err != nil || !ready || start == nil || slices.Contains(f.cmds, startCmd) ||
			!strings.Contains(f.out.String(), "✓ The tripcoil service starts after the checks.\n") || strings.Contains(f.out.String(), "Nothing changed.") {
			t.Fatalf("%s stopped: ready %v, %v, commands %q\n%s", m, ready, err, f.cmds, f.out.String())
		}
		delete(f.fail, status)

		os.WriteFile(filepath.Join(f.Root, ServiceFiles(m, f.Exe)[0].Path), []byte("old\n"), 0o644)
		f.out.Reset()
		f.cmds = nil
		ready, start, err = f.Setup(Options{})
		if err != nil || !ready || start == nil || slices.Contains(f.cmds, restartCmd) ||
			!strings.Contains(f.out.String(), "✓ Updated the tripcoil service; it restarts after the checks.\n") {
			t.Fatalf("%s changed: ready %v, %v, commands %q\n%s", m, ready, err, f.cmds, f.out.String())
		}
		f.fail[restartCmd] = true
		if err := start(); err == nil || !strings.HasPrefix(err.Error(), restartCmd+": exit status 3") {
			t.Fatalf("%s restart: %v", m, err)
		}
		delete(f.fail, restartCmd)
		if err := start(); err != nil || !strings.HasSuffix(f.out.String(), "✓ Restarted the tripcoil service.\n") {
			t.Fatalf("%s restart: %v\n%s", m, err, f.out.String())
		}
	}
}

func TestSetupStartsTheServiceWhenNotReady(t *testing.T) {
	f := newFake(t, Systemd)
	if ready, start, err := f.Setup(Options{Agent: "codex"}); err != nil || ready || start != nil || !slices.Contains(f.cmds, "systemctl start tripcoil.service") {
		t.Fatalf("ready %v, start %v, %v, commands %q", ready, start != nil, err, f.cmds)
	}
}
