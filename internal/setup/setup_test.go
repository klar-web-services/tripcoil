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

// fakeHost is a host in a folder. Commands are recorded; fail names commands that fail (by their
// first two words), and creating the user makes it exist.
type fakeHost struct {
	Host
	cmds  []string
	fail  map[string]bool
	tools map[string]bool
	users map[string]bool
	out   bytes.Buffer
}

func newFake(t *testing.T, m Manager) *fakeHost {
	f := &fakeHost{fail: map[string]bool{}, tools: map[string]bool{}, users: map[string]bool{}}
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
	// Until the service is set up, it is neither enabled nor running.
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
			}
			for k := range f.fail {
				if strings.HasPrefix(c, k) {
					return []byte("inactive\n"), errors.New("exit status 3")
				}
			}
			return nil, nil
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
		Stat:        rootStat,
	}
	return f
}

// rootStat stats a file but reports root as its owner, since the tests do not run as root.
func rootStat(p string) (config.FileInfo, error) {
	fi, err := config.OSStat(p)
	fi.UID = 0
	return fi, err
}

// anyEnvFile is a stat that finds review.envFile root-only, wherever the config points it.
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
	if err := f.Setup(Options{Agent: "codex"}); err != nil {
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
		"✓ Installed and started the tripcoil service.", "sudo npm install -g @openai/codex",
		"Add it to /etc/tripcoil/agent.env as the line CODEX_API_KEY=<key>:\n       sudoedit /etc/tripcoil/agent.env\n"} {
		if !strings.Contains(f.out.String(), l) {
			t.Errorf("output lacks %q:\n%s", l, f.out.String())
		}
	}

	f.started()
	f.cmds, f.out = nil, bytes.Buffer{}
	os.Remove(filepath.Join(f.Root, EnvFilePath))
	if err := f.Setup(Options{Agent: "claude", Yes: true}); err == nil || !strings.Contains(err.Error(), "review.envFile /etc/tripcoil/agent.env cannot be read") {
		t.Fatalf("an existing config is not rewritten, and does not create agent.env: %v", err)
	}
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), nil, 0o600)
	f.cmds, f.out = nil, bytes.Buffer{}
	if err := f.Setup(Options{Agent: "claude", Yes: true}); err != nil {
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
	if err := f.Setup(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.cmds, "systemctl daemon-reload") || !slices.Contains(f.cmds, "systemctl restart tripcoil.service") {
		t.Fatalf("commands %q", f.cmds)
	}
}

func TestSetupOpenRC(t *testing.T) {
	f := newFake(t, OpenRC)
	f.In = strings.NewReader("maybe\n\nyes\n") // an invalid answer is asked again; empty is the default
	if err := f.Setup(Options{}); err != nil {
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
	err := f.Setup(Options{Agent: "claude"})
	if err == nil || !strings.Contains(err.Error(), "reviews cannot run without it") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, OpenRC)
	if err := f.Setup(Options{Agent: "none"}); err != nil || slices.Contains(f.cmds, "apk add bubblewrap") {
		t.Fatalf("no review needs no bubblewrap: %v %q", err, f.cmds)
	}
}

func TestSetupRefusals(t *testing.T) {
	f := newFake(t, Systemd)
	f.Exe = "/home/fkws/bin/tripcoil"
	if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "is under /home") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	f.Exe = "/opt/my tools/tripcoil"
	if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "has characters the service files cannot hold") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	f.CheckBinary = func(string) error { return errors.New("/usr/local/bin is not owned by root") }
	if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "the service would run /usr/local/bin/tripcoil as root, but /usr/local/bin is not owned by root") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	f.users["group"] = true
	f.tools["useradd"] = false
	f.GroupExists = func(string) bool { return true }
	if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "only one of the user and the group") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, "")
	if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "neither systemd nor OpenRC") {
		t.Fatalf("got %v", err)
	}
	f = newFake(t, Systemd)
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, config.DefaultPath), []byte("version: 2\n"), 0o644)
	if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "version must be 1") {
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
	if err := f.Setup(Options{Yes: true}); err != nil {
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
		if err := f.Setup(Options{Agent: "none"}); err != nil {
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
	if err := f.Setup(Options{Yes: true}); err != nil {
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
			if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("a new config: %v", err)
			}
			if err := f.Setup(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("an existing config: %v", err)
			}
		})
	}
}

func TestNextSteps(t *testing.T) {
	claude := nextSteps("claude", "/etc/tripcoil/agent.env")
	for _, l := range []string{"sudo npm install -g @anthropic-ai/claude-code", `"claude setup-token"`, "subscription (Pro or Max), not API billing",
		"  3. Add it to /etc/tripcoil/agent.env as the line CLAUDE_CODE_OAUTH_TOKEN=<token>:\n       sudoedit /etc/tripcoil/agent.env\n"} {
		if !strings.Contains(claude, l) {
			t.Errorf("claude lacks %q:\n%s", l, claude)
		}
	}
	old := nextSteps("codex", "")
	for _, l := range []string{"sudo npm install -g @openai/codex", "per use through the OpenAI API", "Store it root-only as the line CODEX_API_KEY=<key>",
		"set review.envFile in\n     /etc/tripcoil/tripcoil.yaml", "sudo install -m 600 /dev/null /etc/tripcoil/agent.env\n       sudoedit /etc/tripcoil/agent.env\n"} {
		if !strings.Contains(old, l) {
			t.Errorf("codex without envFile lacks %q:\n%s", l, old)
		}
	}
	if !strings.Contains(nextSteps("none", ""), "audit-only") {
		t.Error("none")
	}
}
