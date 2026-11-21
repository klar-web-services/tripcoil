package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/agentnet"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/probe"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

type fakeSandbox struct {
	mu         sync.Mutex
	specs      []sandbox.Spec
	notBlocked string
	leak       bool
	version    int
	agent      func(ctx context.Context, s sandbox.Spec) (sandbox.Result, error)
}

func (f *fakeSandbox) Run(ctx context.Context, s sandbox.Spec) (sandbox.Result, error) {
	f.mu.Lock()
	f.specs = append(f.specs, s)
	f.mu.Unlock()
	switch {
	case len(s.Command) == 3 && s.Command[1] == "sandbox-probe":
		var a probe.Args
		if err := json.Unmarshal([]byte(s.Command[2]), &a); err != nil {
			return sandbox.Result{}, err
		}
		var checks []probe.Check
		if f.leak {
			os.WriteFile(a.Private[0], []byte("x"), 0o600)
		}
		for _, list := range [][]string{a.Reads, a.Writes, a.Private, {a.Runs}, {a.Home}, {fmt.Sprintf("/proc/%d/cmdline", a.RootPID)}, a.TCP, a.UDP} {
			for _, target := range list {
				checks = append(checks, probe.Check{Check: "x", Target: target, Result: "r", Blocked: target != f.notBlocked})
			}
		}
		data, _ := json.Marshal(checks)
		s.Stdout.Write(data)
		return sandbox.Result{}, nil
	case len(s.Command) == 2 && s.Command[1] == "--version":
		fmt.Fprintln(s.Stdout, "2.1.309 (Claude Code)")
		return sandbox.Result{ExitCode: f.version}, nil
	}
	return f.agent(ctx, s)
}

type fakeNet struct {
	mu       sync.Mutex
	applied  []agentnet.Policy
	removed  int
	present  []bool
	applyErr []error
}

func (n *fakeNet) deps(d *deps) {
	d.apply = func(p agentnet.Policy) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.applied = append(n.applied, p)
		if len(n.applyErr) > 0 {
			err := n.applyErr[0]
			n.applyErr = n.applyErr[1:]
			return err
		}
		return nil
	}
	d.present = func() (bool, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		if len(n.present) == 0 {
			return true, nil
		}
		ok := n.present[0]
		n.present = n.present[1:]
		return ok, nil
	}
	d.remove = func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.removed++
		return nil
	}
}

type env struct {
	h      *Host
	sb     *fakeSandbox
	net    *fakeNet
	runDir string
}

func newEnv(t *testing.T, agent string, run func(ctx context.Context, s sandbox.Spec) (sandbox.Result, error)) *env {
	state, cfgDir := t.TempDir(), t.TempDir()
	runDir := filepath.Join(state, "runs", "20261115T061500Z-3fa2")
	for _, d := range []string{runDir, filepath.Join(state, "cache")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	resolv := filepath.Join(cfgDir, "resolv.conf")
	os.WriteFile(resolv, []byte("nameserver 127.0.0.53\n"), 0o644)
	exe := filepath.Join(cfgDir, "tripcoil")
	os.WriteFile(exe, []byte("binary"), 0o755)
	cfg := config.Default()
	cfg.Review.Agent, cfg.Review.Timeout, cfg.Review.AllowAddresses = agent, config.Duration(time.Hour), []string{"10.9.9.9"}
	sb := &fakeSandbox{agent: run}
	n := &fakeNet{}
	h := New(cfg, state, cfgDir)
	h.d.platform = func() (sandbox.Sandbox, func() error, error) { return sb, nil, nil }
	h.d.user = func() (sandbox.User, error) {
		return sandbox.User{Name: UserName, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, nil
	}
	h.d.findCLI = func(command, name string) (string, error) { return "/usr/local/bin/" + name, nil }
	h.d.own = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil }
	h.d.resolv, h.d.exe, h.d.watch = resolv, func() (string, error) { return exe, nil }, 10*time.Millisecond
	h.d.mount = func(home string, size int64, uid, gid uint32) error {
		if size != 2<<30 || uid != uint32(os.Getuid()) {
			t.Errorf("mount %s size %d uid %d", home, size, uid)
		}
		return nil
	}
	h.d.unmount = func(string) {}
	n.deps(&h.d)
	return &env{h: h, sb: sb, net: n, runDir: runDir}
}

func print(stdout []byte, code int) func(context.Context, sandbox.Spec) (sandbox.Result, error) {
	return func(_ context.Context, s sandbox.Spec) (sandbox.Result, error) {
		s.Stdout.Write(stdout)
		return sandbox.Result{ExitCode: code}, nil
	}
}

func TestReviewClaude(t *testing.T) {
	e := newEnv(t, "claude", print(fixture(t, "agent/claude-success.json"), 0))
	out, err := e.h.Review(context.Background(), e.runDir)
	if err != nil {
		t.Fatal(err)
	}
	var r struct{ Summary string }
	if json.Unmarshal(out.Data, &r) != nil || !strings.HasPrefix(r.Summary, "audit.json has two findings") || out.CLI != "claude 2.1.309" || len(out.Warnings) != 0 {
		t.Errorf("output %q %s %v", out.CLI, out.Data, out.Warnings)
	}
	if len(e.sb.specs) != 3 {
		t.Fatalf("%d sandbox runs", len(e.sb.specs))
	}
	p, v, a := e.sb.specs[0], e.sb.specs[1], e.sb.specs[2]
	if p.Name != "20261115T061500Z-3fa2-probe" || p.Command[0] != filepath.Join(e.h.stateDir, "sandbox-probe") || p.Timeout != probeTimeout {
		t.Errorf("probe %+v", p)
	}
	if v.Name != "20261115T061500Z-3fa2-version" || !slices.Equal(v.Command, []string{"/usr/local/bin/claude", "--version"}) {
		t.Errorf("version %+v", v)
	}
	if a.Name != "20261115T061500Z-3fa2-agent" || a.Command[0] != "/usr/local/bin/claude" || a.Command[1] != "-p" || a.Timeout != time.Hour ||
		a.RunDir != e.runDir || a.MemoryMax != "2G" || a.CPUQuota != "100%" || !slices.Contains(a.Env, "DISABLE_AUTOUPDATER=1") {
		t.Errorf("agent %+v", a)
	}
	want := agentnet.Policy{UID: uint32(os.Getuid()), Nameservers: []netip.Addr{netip.MustParseAddr("127.0.0.53")},
		Allow: []netip.Prefix{netip.MustParsePrefix("10.9.9.9/32")}, Own: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}
	if len(e.net.applied) != 1 || fmt.Sprint(e.net.applied[0]) != fmt.Sprint(want) || e.net.removed != 1 {
		t.Errorf("network: applied %v removed %d", e.net.applied, e.net.removed)
	}
	for _, f := range []string{"stdout", "stderr", "probe.json"} {
		fi, err := os.Stat(filepath.Join(e.runDir, "agent", f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("agent/%s: %v", f, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(e.runDir, "agent")); fi.Mode().Perm() != 0o700 {
		t.Errorf("agent/ mode %v", fi.Mode().Perm())
	}
	for _, gone := range []string{"agent-home", "sandbox-probe"} {
		if _, err := os.Stat(filepath.Join(e.h.stateDir, gone)); err == nil {
			t.Errorf("%s left behind", gone)
		}
	}
	if es, _ := os.ReadDir(filepath.Join(e.h.stateDir, "runs")); len(es) != 1 {
		t.Errorf("the probe's decoy run is left behind: %v", es)
	}
}

func TestReviewCodexGetsItsSchema(t *testing.T) {
	var schema []byte
	e := newEnv(t, "codex", nil)
	final := fixture(t, "review/codex-0.154.0.json")
	e.sb.agent = func(_ context.Context, s sandbox.Spec) (sandbox.Result, error) {
		schema, _ = os.ReadFile(filepath.Join(s.Home(), "tripcoil-schema.json"))
		s.Stdout.Write(final)
		return sandbox.Result{}, nil
	}
	out, err := e.h.Review(context.Background(), e.runDir)
	if err != nil || string(schema) != string(review.Schema) || string(out.Data) != strings.TrimSpace(string(final)) {
		t.Fatalf("%v schema %d bytes", err, len(schema))
	}
	if out.CLI != "codex 2.1.309" {
		t.Errorf("cli %q", out.CLI)
	}
}

func TestReviewReadsTheEntriesFile(t *testing.T) {
	final := fixture(t, "agent/claude-success.json")
	e := newEnv(t, "claude", func(_ context.Context, s sandbox.Spec) (sandbox.Result, error) {
		os.WriteFile(filepath.Join(s.Home(), "entries.jsonl"), []byte("{\"findingId\":\"f:1\"}\n"), 0o600)
		s.Stdout.Write(final)
		return sandbox.Result{}, nil
	})
	out, err := e.h.Review(context.Background(), e.runDir)
	if err != nil || string(out.Entries) != "{\"findingId\":\"f:1\"}\n" || len(out.Warnings) != 0 {
		t.Fatalf("%v entries %q warnings %v", err, out.Entries, out.Warnings)
	}
	kept, err := os.ReadFile(filepath.Join(e.runDir, "agent", "entries.jsonl"))
	if fi, _ := os.Stat(filepath.Join(e.runDir, "agent", "entries.jsonl")); err != nil || string(kept) != string(out.Entries) || fi.Mode().Perm() != 0o600 {
		t.Errorf("agent/entries.jsonl: %q %v", kept, err)
	}

	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("root only"), 0o600)
	e = newEnv(t, "claude", func(_ context.Context, s sandbox.Spec) (sandbox.Result, error) {
		os.Symlink(secret, filepath.Join(s.Home(), "entries.jsonl"))
		s.Stdout.Write(final)
		return sandbox.Result{}, nil
	})
	out, err = e.h.Review(context.Background(), e.runDir)
	if err != nil || out.Entries != nil || len(out.Warnings) != 1 || out.Warnings[0].Code != problem.ReviewEntriesDropped ||
		!strings.Contains(out.Warnings[0].Message, "entries.jsonl was ignored: it is a symbolic link") {
		t.Fatalf("%v entries %q warnings %v", err, out.Entries, out.Warnings)
	}
	if _, err := os.Stat(filepath.Join(e.runDir, "agent", "entries.jsonl")); err == nil {
		t.Error("a linked file was kept")
	}

	e = newEnv(t, "claude", func(_ context.Context, s sandbox.Spec) (sandbox.Result, error) {
		os.WriteFile(filepath.Join(s.Home(), "entries.jsonl"), []byte("{}\n"), 0o600)
		s.Stdout.Write(final)
		return sandbox.Result{}, nil
	})
	os.MkdirAll(filepath.Join(e.runDir, "agent", "entries.jsonl"), 0o700)
	out, err = e.h.Review(context.Background(), e.runDir)
	if err != nil || string(out.Entries) != "{}\n" || len(out.Warnings) != 1 || out.Warnings[0].Code != problem.RunFolderUnwritable ||
		out.Warnings[0].Kind != problem.Warning || !strings.Contains(out.Warnings[0].Message, "cannot keep a copy of the agent's entries.jsonl") {
		t.Fatalf("%v entries %q warnings %v", err, out.Entries, out.Warnings)
	}
}

func TestReviewFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *env)
		code  string
		msg   string
		runs  int
	}{
		{"unsupported", func(e *env) {
			e.h.d.platform = func() (sandbox.Sandbox, func() error, error) {
				return nil, nil, &review.Failure{Code: problem.ReviewUnsupported, Message: "systemd 245"}
			}
		}, problem.ReviewUnsupported, "systemd 245", 0},
		{"no CLI", func(e *env) {
			e.h.d.findCLI = func(string, string) (string, error) { return "", errors.New("claude is not installed") }
		}, problem.AgentMissing, "claude is not installed", 0},
		{"no user", func(e *env) {
			e.h.d.user = func() (sandbox.User, error) {
				return sandbox.User{}, errors.New("the user tripcoil-agent does not exist")
			}
		}, problem.AgentSandbox, "does not exist", 0},
		{"leftovers", func(e *env) {
			e.h.d.platform = func() (sandbox.Sandbox, func() error, error) {
				return e.sb, func() error { return errors.New("systemctl stop failed") }, nil
			}
		}, problem.AgentSandbox, "systemctl stop failed", 0},
		{"no nftables", func(e *env) { e.net.applyErr = []error{errors.New("protocol not supported")} },
			problem.AgentSandbox, "cannot write the agent's network table (nftables): protocol not supported", 0},
		{"probe not blocked", func(e *env) { e.sb.notBlocked = "169.254.169.254:80" },
			problem.AgentSandbox, "the sandbox does not hold: x 169.254.169.254:80: r", 1},
		{"probe write outlived the sandbox", func(e *env) { e.sb.leak = true },
			problem.AgentSandbox, "/tmp/.probe-", 1},
		{"version fails", func(e *env) { e.sb.version = 127 },
			problem.AgentFailed, "/usr/local/bin/claude --version failed (exit 127): 2.1.309 (Claude Code)", 2},
		{"too much output", func(e *env) {
			e.sb.agent = func(_ context.Context, s sandbox.Spec) (sandbox.Result, error) {
				chunk := make([]byte, 1<<20)
				for range review.MaxOutput>>20 + 1 {
					s.Stdout.Write(chunk)
				}
				return sandbox.Result{}, nil
			}
		}, problem.AgentOutputInvalid, "printed more than 16 MiB", 3},
		{"no credentials", func(e *env) { e.sb.agent = print(fixture(t, "agent/claude-noauth.json"), 1) },
			problem.AgentAuth, "Not logged in", 3},
		{"timeout", func(e *env) {
			e.sb.agent = func(context.Context, sandbox.Spec) (sandbox.Result, error) {
				return sandbox.Result{TimedOut: true, ExitCode: 1}, nil
			}
		}, problem.AgentTimeout, "longer than review.timeout (1h0m0s)", 3},
		{"cannot start", func(e *env) {
			e.sb.agent = func(context.Context, sandbox.Spec) (sandbox.Result, error) {
				return sandbox.Result{}, errors.New("exec: no such file")
			}
		}, problem.AgentFailed, "cannot run /usr/local/bin/claude: exec: no such file", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, "claude", print(fixture(t, "agent/claude-success.json"), 0))
			tc.setup(e)
			_, err := e.h.Review(context.Background(), e.runDir)
			if code(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("got %s %v", code(err), err)
			}
			if len(e.sb.specs) != tc.runs {
				t.Errorf("%d sandbox runs, want %d", len(e.sb.specs), tc.runs)
			}
			if len(e.net.applied) != e.net.removed && tc.name != "no nftables" {
				t.Errorf("network table applied %d, removed %d", len(e.net.applied), e.net.removed)
			}
			if _, err := os.Stat(filepath.Join(e.h.stateDir, "agent-home")); err == nil {
				t.Error("agent-home left behind")
			}
		})
	}
}

func TestReviewWritesFilesFirst(t *testing.T) {
	var seen []byte
	e := newEnv(t, "codex", print(fixture(t, "review/codex-0.154.0.json"), 0))
	stops := 0
	e.h.d.platform = func() (sandbox.Sandbox, func() error, error) {
		return e.sb, func() error { stops++; return nil }, nil
	}
	inner := e.sb.agent
	e.sb.agent = func(ctx context.Context, s sandbox.Spec) (sandbox.Result, error) {
		seen, _ = os.ReadFile(filepath.Join(s.Home(), "tripcoil-schema.json"))
		return inner(ctx, s)
	}
	if _, err := e.h.Review(context.Background(), e.runDir); err != nil {
		t.Fatal(err)
	}
	if string(seen) != string(review.Schema) || stops != 2 {
		t.Errorf("schema %d bytes, %d stops", len(seen), stops)
	}
	tmpl := filepath.Join(e.h.configDir, "agent-home")
	os.MkdirAll(tmpl, 0o700)
	os.Symlink("/etc/passwd", filepath.Join(tmpl, "tripcoil-schema.json"))
	if _, err := e.h.Review(context.Background(), e.runDir); code(err) != problem.AgentSandbox || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("got %v", err)
	}
}

func TestReviewMountsHome(t *testing.T) {
	e := newEnv(t, "claude", print(fixture(t, "agent/claude-success.json"), 0))
	var calls []string
	e.h.d.mount = func(home string, size int64, uid, gid uint32) error {
		calls = append(calls, "mount "+filepath.Base(home))
		return nil
	}
	e.h.d.unmount = func(home string) { calls = append(calls, "unmount "+filepath.Base(home)) }
	if _, err := e.h.Review(context.Background(), e.runDir); err != nil {
		t.Fatal(err)
	}
	if want := []string{"unmount agent-home", "mount agent-home", "unmount agent-home"}; !slices.Equal(calls, want) {
		t.Errorf("got %q", calls)
	}
	e.h.d.mount = func(string, int64, uint32, uint32) error { return errors.New("operation not permitted") }
	if _, err := e.h.Review(context.Background(), e.runDir); code(err) != problem.AgentSandbox || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("got %v", err)
	}
}

func TestReviewKeepsNetworkWhenUnitsStay(t *testing.T) {
	e := newEnv(t, "claude", print(fixture(t, "agent/claude-success.json"), 0))
	calls := 0
	e.h.d.platform = func() (sandbox.Sandbox, func() error, error) {
		return e.sb, func() error {
			if calls++; calls > 1 {
				return errors.New("Failed to stop tripcoil-review-x.service: Connection timed out")
			}
			return nil
		}, nil
	}
	out, err := e.h.Review(context.Background(), e.runDir)
	if err != nil || e.net.removed != 0 || len(out.Warnings) != 1 || out.Warnings[0].Code != problem.AgentUnitLeft || !strings.Contains(out.Warnings[0].Message, "network table stays in place") {
		t.Fatalf("%v removed %d warnings %v", err, e.net.removed, out.Warnings)
	}
}

func TestReviewRestoresNetwork(t *testing.T) {
	e := newEnv(t, "claude", func(ctx context.Context, s sandbox.Spec) (sandbox.Result, error) {
		time.Sleep(100 * time.Millisecond)
		return sandbox.Result{TimedOut: true}, nil
	})
	e.net.present = []bool{false}
	out, err := e.h.Review(context.Background(), e.runDir)
	if code(err) != problem.AgentTimeout {
		t.Fatalf("got %v", err)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != problem.AgentNetworkRestored || len(e.net.applied) != 2 {
		t.Errorf("warnings %v, applied %d", out.Warnings, len(e.net.applied))
	}
}

func TestReviewStopsWhenNetworkLost(t *testing.T) {
	e := newEnv(t, "claude", func(ctx context.Context, s sandbox.Spec) (sandbox.Result, error) {
		<-ctx.Done()
		return sandbox.Result{}, ctx.Err()
	})
	e.net.present = []bool{false}
	e.net.applyErr = []error{nil, errors.New("netlink: permission denied")}
	_, err := e.h.Review(context.Background(), e.runDir)
	if code(err) != problem.AgentSandbox || !strings.Contains(err.Error(), "could not be restored: netlink: permission denied") {
		t.Fatalf("got %s %v", code(err), err)
	}
}

func TestReviewInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := newEnv(t, "claude", func(rctx context.Context, s sandbox.Spec) (sandbox.Result, error) {
		cancel()
		<-rctx.Done()
		return sandbox.Result{}, rctx.Err()
	})
	_, err := e.h.Review(ctx, e.runDir)
	if !errors.Is(err, context.Canceled) || e.net.removed != 1 {
		t.Fatalf("got %v, removed %d", err, e.net.removed)
	}
	if _, err := os.Stat(filepath.Join(e.h.stateDir, "agent-home")); err == nil {
		t.Error("agent-home left behind")
	}
}

func TestCheck(t *testing.T) {
	claudeOK := []byte(`{"type":"result","subtype":"success","is_error":false,"stop_reason":"tool_use","structured_output":{"ok":true}}`)
	e := newEnv(t, "claude", print(claudeOK, 0))
	dir := filepath.Join(e.h.stateDir, "runs", ".doctor")
	os.Mkdir(dir, 0o750)
	cli, err := e.h.Check(context.Background(), dir)
	if err != nil || cli != "claude 2.1.309" {
		t.Fatalf("%q %v", cli, err)
	}
	a := e.sb.specs[2]
	if a.Name != "doctor-agent" || a.Command[2] != checkPrompt || a.Command[6] != checkSchema || e.sb.specs[0].Name != "doctor-probe" {
		t.Fatalf("agent %q %q", a.Name, a.Command)
	}

	e = newEnv(t, "codex", print([]byte(`{"ok":false}`), 0))
	os.Mkdir(dir, 0o750)
	if _, err := e.h.Check(context.Background(), e.runDir); !isCode(err, problem.AgentOutputInvalid) || !strings.Contains(err.Error(), `answered the check with "{\"ok\":false}"`) {
		t.Fatalf("got %v", err)
	}
	e = newEnv(t, "claude", print(fixture(t, "agent/claude-noauth.json"), 1))
	if _, err := e.h.Check(context.Background(), e.runDir); !isCode(err, problem.AgentAuth) {
		t.Fatalf("got %v", err)
	}
}

func isCode(err error, code string) bool {
	var f *review.Failure
	return errors.As(err, &f) && f.Code == code
}
