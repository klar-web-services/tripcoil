package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/klar-web-services/tripcoil/internal/agentnet"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/probe"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

// UserName is the agent's system user, which tripcoil setup creates with its own group.
const UserName = "tripcoil-agent"

// Host reviews runs on this machine. It implements review.Agent.
type Host struct {
	cfg       config.Config
	stateDir  string
	configDir string
	d         deps
}

// deps is what Host takes from the machine, so tests can replace it.
type deps struct {
	// platform returns the sandbox of this machine and, on systemd, the function that stops
	// units left over from earlier reviews; or a *review.Failure.
	platform func() (sandbox.Sandbox, func() error, error)
	user     func() (sandbox.User, error)
	findCLI  func(command, name string) (string, error)
	apply    func(agentnet.Policy) error
	present  func() (bool, error)
	remove   func() error
	own      func() ([]netip.Addr, error)
	resolv   string // resolv.conf
	exe      func() (string, error)
	watch    time.Duration // how often the network table is checked
}

// New returns the agent for the config's review settings.
func New(cfg config.Config, stateDir, configDir string) *Host {
	return &Host{cfg: cfg, stateDir: stateDir, configDir: configDir, d: deps{
		platform: hostPlatform, user: lookupUser, findCLI: FindCLI,
		apply: agentnet.Apply, present: agentnet.Present, remove: agentnet.Delete, own: agentnet.OwnAddrs,
		resolv: "/etc/resolv.conf", exe: os.Executable, watch: 5 * time.Second,
	}}
}

// probeTimeout bounds the probe and the CLI's --version, which take seconds.
const probeTimeout = 2 * time.Minute

// Review runs one review of runDir in the sandbox. The output's warnings are set on every return
// after the network table was written.
func (h *Host) Review(ctx context.Context, runDir string) (out review.Output, _ error) {
	ad := For(h.cfg.Review.Agent)
	sb, stopLeftovers, err := h.d.platform()
	if err != nil {
		return out, err
	}
	cli, err := h.d.findCLI(h.cfg.Review.Command, h.cfg.Review.Agent)
	if err != nil {
		return out, fail(problem.AgentMissing, "%v", err)
	}
	u, err := h.d.user()
	if err != nil {
		return out, fail(problem.AgentSandbox, "%v", err)
	}
	if stopLeftovers != nil {
		if err := stopLeftovers(); err != nil {
			return out, fail(problem.AgentSandbox, "%v", err)
		}
	}
	agentDir := filepath.Join(runDir, "agent")
	if err := os.Mkdir(agentDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return out, &review.Failure{Code: problem.RunFolderUnwritable, Message: err.Error()}
	}
	base := sandbox.Spec{StateDir: h.stateDir, ConfigDir: h.configDir, RunDir: runDir, User: u, EnvFile: h.cfg.Review.EnvFile,
		MemoryMax: h.cfg.Review.MemoryMax, CPUQuota: h.cfg.Review.CPUQuota}
	home := base.Home()
	if err := ResetHome(home, filepath.Join(h.configDir, "agent-home"), int(u.UID), int(u.GID)); err != nil {
		return out, fail(problem.AgentSandbox, "cannot prepare the agent's home %s: %v", home, err)
	}
	defer os.RemoveAll(home)
	// The adapter's files go in before anything runs as the agent, so no link or pipe it made
	// can be in their way.
	in := Inputs{Prompt: review.Prompt, Schema: review.Schema, Home: home, Model: h.cfg.Review.Model, Extra: h.cfg.Review.ExtraArgs}
	for name, data := range ad.Files(in) {
		if err := writeNew(filepath.Join(home, name), data); err != nil {
			return out, fail(problem.AgentSandbox, "cannot prepare the agent's home: %v", err)
		}
	}

	policy, err := h.policy(u)
	if err != nil {
		return out, fail(problem.AgentSandbox, "%v", err)
	}
	if err := h.d.apply(policy); err != nil {
		return out, fail(problem.AgentSandbox, "cannot write the agent's network table (nftables): %v", err)
	}
	defer h.d.remove()
	if stopLeftovers != nil {
		defer stopLeftovers() // no unit of this review may outlive its network table
	}
	rctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	warnings := h.watchNetwork(rctx, cancel, policy)
	defer func() { out.Warnings = warnings() }()
	stopped := func(err error) error { // why a sandbox run ended early
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c := context.Cause(rctx); c != nil {
			return c
		}
		return err
	}

	id := filepath.Base(runDir)
	if err := h.probe(rctx, sb, base, id, agentDir, policy); err != nil {
		return out, stopped(err)
	}
	var ver, verErr tail
	vs := base
	vs.Name, vs.Command, vs.Timeout, vs.Env, vs.Stdout, vs.Stderr = id+"-version", []string{cli, "--version"}, probeTimeout, ad.Env(), &ver, &verErr
	vres, err := sb.Run(rctx, vs)
	switch {
	case err != nil:
		return out, stopped(fail(problem.AgentFailed, "cannot run %s --version: %v", cli, err))
	case vres.TimedOut || vres.ExitCode != 0:
		return out, fail(problem.AgentFailed, "%s --version failed (exit %d): %s", cli, vres.ExitCode, lastLine(append(verErr.b, ver.b...)))
	}
	out.CLI = ad.Version(ver.b)

	stdout, err := os.OpenFile(filepath.Join(agentDir, "stdout"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return out, &review.Failure{Code: problem.RunFolderUnwritable, Message: err.Error()}
	}
	defer stdout.Close()
	stderr, err := os.OpenFile(filepath.Join(agentDir, "stderr"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return out, &review.Failure{Code: problem.RunFolderUnwritable, Message: err.Error()}
	}
	defer stderr.Close()
	// The agent can write to its CLI's output, so what Tripcoil keeps of it is capped.
	var outBuf bytes.Buffer
	var errTail tail
	outCap := &capped{w: io.MultiWriter(stdout, &outBuf), left: review.MaxOutput}
	rs := base
	rs.Name, rs.Command, rs.Timeout, rs.Env = id+"-agent", append([]string{cli}, ad.Args(in)...), time.Duration(h.cfg.Review.Timeout), ad.Env()
	rs.Stdout, rs.Stderr = outCap, io.MultiWriter(&capped{w: stderr, left: review.MaxOutput}, &errTail)
	if context.Cause(rctx) != nil {
		return out, stopped(nil)
	}
	res, err := sb.Run(rctx, rs)
	switch {
	case err != nil:
		return out, stopped(fail(problem.AgentFailed, "cannot run %s: %v", cli, err))
	case context.Cause(rctx) != nil:
		return out, stopped(nil)
	case res.TimedOut:
		return out, fail(problem.AgentTimeout, "the review ran longer than review.timeout (%s) and was stopped", h.cfg.Review.Timeout.Std())
	case outCap.over:
		return out, fail(problem.AgentOutputInvalid, "%s printed more than %d MiB", cli, review.MaxOutput>>20)
	}
	out.Data, err = ad.Parse(outBuf.Bytes(), errTail.b, res.ExitCode)
	return out, err
}

// policy is the network table's policy for this review.
func (h *Host) policy(u sandbox.User) (agentnet.Policy, error) {
	own, err := h.d.own()
	if err != nil {
		return agentnet.Policy{}, fmt.Errorf("cannot list the host's addresses: %v", err)
	}
	conf, err := os.ReadFile(h.d.resolv)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return agentnet.Policy{}, err
	}
	return agentnet.Policy{UID: u.UID, Nameservers: agentnet.Nameservers(conf), Allow: agentnet.ParseAllow(h.cfg.Review.AllowAddresses), Own: own}, nil
}

// probe runs tripcoil sandbox-probe in the sandbox and fails unless every check was blocked.
func (h *Host) probe(ctx context.Context, sb sandbox.Sandbox, base sandbox.Spec, id, agentDir string, policy agentnet.Policy) error {
	exe, err := h.d.exe()
	if err != nil {
		return fail(problem.AgentSandbox, "cannot find Tripcoil's own binary for the probe: %v", err)
	}
	// A copy in the state folder, which the sandbox shows: Tripcoil may run from a folder it hides.
	bin := filepath.Join(h.stateDir, "sandbox-probe")
	if err := copyBinary(exe, bin); err != nil {
		return fail(problem.AgentSandbox, "cannot copy Tripcoil's binary for the probe: %v", err)
	}
	defer os.Remove(bin)
	setup, err := probe.Prepare(h.stateDir, h.configDir, base.RunDir, int(base.User.UID), int(base.User.GID), policy.Own, policy.Nameservers)
	if err != nil {
		return fail(problem.AgentSandbox, "cannot prepare the sandbox probe: %v", err)
	}
	defer setup.Close()
	args, _ := json.Marshal(setup.Args)
	var stdout, stderr tail
	s := base
	s.Name, s.Command, s.Timeout, s.Stdout, s.Stderr = id+"-probe", []string{bin, "sandbox-probe", string(args)}, probeTimeout, &stdout, &stderr
	res, err := sb.Run(ctx, s)
	os.WriteFile(filepath.Join(agentDir, "probe.json"), stdout.b, 0o600)
	if err != nil {
		return fail(problem.AgentSandbox, "cannot start the sandbox: %v", err)
	}
	fails := append(probe.Failures(setup.Args, stdout.b), setup.Leaked()...)
	if len(fails) > 0 {
		msg := "the sandbox does not hold: " + strings.Join(fails, "; ")
		if res.ExitCode != 0 || res.TimedOut {
			msg += fmt.Sprintf(" (the probe exited with %d: %s)", res.ExitCode, lastLine(stderr.b))
		}
		return fail(problem.AgentSandbox, "%s", msg)
	}
	return nil
}

// watchNetwork checks the network table every few seconds and restores it when a firewall reload
// removed it. When it cannot, it stops the review. The function it returns stops the watch and
// returns the warnings.
func (h *Host) watchNetwork(ctx context.Context, stop context.CancelCauseFunc, p agentnet.Policy) func() []problem.Problem {
	wctx, wcancel := context.WithCancel(ctx)
	var mu sync.Mutex
	var warns []problem.Problem
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(h.d.watch)
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
			}
			if ok, err := h.d.present(); err == nil && ok {
				continue
			}
			if err := h.d.apply(p); err != nil {
				stop(fail(problem.AgentSandbox, "the agent's network table was removed and could not be restored: %v", err))
				return
			}
			mu.Lock()
			warns = append(warns, problem.New(problem.Warning, problem.AgentNetworkRestored, "review",
				"the agent's network table was removed during the review (by a firewall reload?) and was restored"))
			mu.Unlock()
		}
	}()
	return func() []problem.Problem {
		wcancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		return warns
	}
}

// hostPlatform picks the sandbox: a transient unit when systemd is the init system (247 or
// later), bubblewrap with cgroup v2 otherwise.
func hostPlatform() (sandbox.Sandbox, func() error, error) {
	if sandbox.Booted() {
		systemctl, err1 := lookPath("systemctl")
		systemdRun, err2 := lookPath("systemd-run")
		if err := errors.Join(err1, err2); err != nil {
			return nil, nil, fail(problem.AgentSandbox, "%v", err)
		}
		vout, err := exec.Command(systemctl, "--version").Output()
		if err != nil {
			return nil, nil, fail(problem.AgentSandbox, "systemctl --version: %v", err)
		}
		v, err := sandbox.SystemdVersion(vout)
		if err != nil {
			return nil, nil, fail(problem.AgentSandbox, "%v", err)
		}
		if v < sandbox.MinSystemd {
			return nil, nil, fail(problem.ReviewUnsupported, "systemd %d is older than %d, which the review's sandbox needs", v, sandbox.MinSystemd)
		}
		s := sandbox.Systemd{SystemdRun: systemdRun, Systemctl: systemctl}
		return s, s.StopLeftovers, nil
	}
	bwrap, err := lookPath("bwrap")
	if err != nil {
		return nil, nil, fail(problem.AgentSandbox, "bubblewrap is not installed (on Alpine: apk add bubblewrap)")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return nil, nil, fail(problem.AgentSandbox, "the review's sandbox needs cgroup v2 mounted at /sys/fs/cgroup")
	}
	return sandbox.Bwrap{Bwrap: bwrap, CgroupRoot: "/sys/fs/cgroup"}, nil, nil
}

// lookPath finds a tool on the fixed system path.
func lookPath(name string) (string, error) {
	for _, dir := range filepath.SplitList(sandbox.Path) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is not installed on %s", name, sandbox.Path)
}

// lookupUser finds the agent's user, and its group, which may read run folders.
func lookupUser() (sandbox.User, error) {
	hint := "create it with: useradd --system --user-group --no-create-home --shell /usr/sbin/nologin " + UserName
	u, err := user.Lookup(UserName)
	if err != nil {
		return sandbox.User{}, fmt.Errorf("the user %s does not exist; %s", UserName, hint)
	}
	gid, ok := run.AgentGID()
	if !ok {
		return sandbox.User{}, fmt.Errorf("the group %s does not exist; %s", run.AgentGroup, hint)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return sandbox.User{}, fmt.Errorf("the user %s has the unusable UID %s", UserName, u.Uid)
	}
	return sandbox.User{Name: UserName, UID: uint32(uid), GID: uint32(gid)}, nil
}

func copyBinary(src, dst string) error {
	os.Remove(dst)
	if err := copyFile(src, dst, 0o755); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}

// writeNew creates a file that must not exist yet, following no link.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// capped passes on at most left bytes and drops the rest.
type capped struct {
	w    io.Writer
	left int64
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if int64(len(p)) > c.left {
		p, c.over = p[:c.left], true
	}
	c.left -= int64(len(p))
	if len(p) > 0 {
		if _, err := c.w.Write(p); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// tail keeps the last 64 KiB written to it.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 64<<10 {
		t.b = t.b[len(t.b)-64<<10:]
	}
	return len(p), nil
}
