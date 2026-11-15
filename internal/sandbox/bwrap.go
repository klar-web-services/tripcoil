package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Bwrap runs the command under bubblewrap, started as the agent's user so that bubblewrap uses
// unprivileged user namespaces, in its own cgroup v2 group with memory and CPU caps.
type Bwrap struct {
	Bwrap      string // the bwrap binary
	CgroupRoot string // /sys/fs/cgroup
}

// BwrapArgs is bubblewrap's command line for s. The environment is bubblewrap's own, which it
// passes on: values on the command line, such as credentials, would show in ps.
func BwrapArgs(s Spec) []string {
	a := []string{"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"}
	for _, h := range append([]string{"/home", "/root"}, s.hidden()...) {
		if exists(h) {
			a = append(a, "--tmpfs", h)
		}
	}
	a = append(a, "--tmpfs", s.runs(), "--ro-bind", s.RunDir, s.RunDir,
		"--bind", s.Home(), s.Home(), "--chdir", s.RunDir,
		// A private IPC namespace: shared memory or queues left by one review cannot reach the next.
		"--unshare-pid", "--unshare-ipc", "--die-with-parent", "--new-session", "--")
	return append(a, s.Command...)
}

// env is the sandbox's environment: the fixed path, the home, the variables of the env file and
// the adapter's.
func (s Spec) env() ([]string, error) {
	env := []string{"PATH=" + Path, "HOME=" + s.Home(), "LANG=C.UTF-8"}
	if s.EnvFile != "" {
		data, err := os.ReadFile(s.EnvFile)
		if err != nil {
			return nil, err
		}
		vars, err := ParseEnvFile(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", s.EnvFile, err)
		}
		env = append(env, vars...)
	}
	return append(env, s.Env...), nil
}

// Cgroup is the agent's cgroup v2 group.
func (d Bwrap) Cgroup() string { return filepath.Join(d.CgroupRoot, "tripcoil-agent") }

// Run starts bubblewrap in the agent's cgroup and waits for it. At the timeout, or when ctx is
// cancelled, every process in the cgroup is killed.
func (d Bwrap) Run(ctx context.Context, s Spec) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	env, err := s.env()
	if err != nil {
		return Result{}, err
	}
	cg, err := d.prepare(s)
	if err != nil {
		return Result{}, fmt.Errorf("cgroup %s: %w", d.Cgroup(), err)
	}
	defer cg.Close()
	defer d.remove()
	cmd := exec.Command(d.Bwrap, BwrapArgs(s)...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = s.Stdout, s.Stderr
	cmd.WaitDelay = 5 * time.Second
	// No core dumps: one would keep the agent's memory where a later review can read it. The
	// limit is set on Tripcoil itself, which needs none, and inherited.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return Result{}, fmt.Errorf("RLIMIT_CORE: %w", err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: s.User.UID, Gid: s.User.GID, Groups: []uint32{}},
		UseCgroupFD: true, CgroupFD: int(cg.Fd()),
		Setpgid: true, Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(s.Timeout)
	defer timer.Stop()
	var res Result
	select {
	case err = <-done:
	case <-timer.C:
		res.TimedOut = true
		d.kill(cmd)
		err = <-done
	case <-ctx.Done():
		d.kill(cmd)
		err = <-done
	}
	d.kill(cmd) // whatever the command left behind
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
	case err != nil:
		return res, err
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, nil
}

// prepare creates the cgroup with its caps and opens it for CgroupFD.
func (d Bwrap) prepare(s Spec) (*os.File, error) {
	mem, err := Bytes(s.MemoryMax)
	if err != nil {
		return nil, err
	}
	quota, err := strconv.Atoi(strings.TrimSuffix(s.CPUQuota, "%"))
	if err != nil || quota < 1 {
		return nil, fmt.Errorf("invalid CPU quota %q", s.CPUQuota)
	}
	ctl := filepath.Join(d.CgroupRoot, "cgroup.subtree_control")
	have, err := os.ReadFile(ctl)
	if err != nil {
		return nil, err
	}
	for _, c := range []string{"memory", "cpu"} {
		if !strings.Contains(" "+strings.TrimSpace(string(have))+" ", " "+c+" ") {
			if err := os.WriteFile(ctl, []byte("+"+c), 0); err != nil {
				return nil, fmt.Errorf("enable the %s controller: %w", c, err)
			}
		}
	}
	d.remove() // a group a killed Tripcoil left behind
	if err := os.Mkdir(d.Cgroup(), 0o755); err != nil {
		return nil, err
	}
	for f, v := range map[string]string{"memory.max": strconv.FormatInt(mem, 10), "cpu.max": fmt.Sprintf("%d 100000", quota*1000)} {
		if err := os.WriteFile(filepath.Join(d.Cgroup(), f), []byte(v), 0); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	// Without swap the memory cap holds; a kernel without swap accounting has no such file.
	if err := os.WriteFile(filepath.Join(d.Cgroup(), "memory.swap.max"), []byte("0"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("memory.swap.max: %w", err)
	}
	return os.Open(d.Cgroup())
}

// kill ends bubblewrap's process group and every process left in the cgroup.
func (d Bwrap) kill(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	os.WriteFile(filepath.Join(d.Cgroup(), "cgroup.kill"), []byte("1"), 0)
}

// remove deletes the cgroup once its processes are gone.
func (d Bwrap) remove() {
	if !exists(d.Cgroup()) {
		return
	}
	os.WriteFile(filepath.Join(d.Cgroup(), "cgroup.kill"), []byte("1"), 0)
	for range 50 {
		if err := os.Remove(d.Cgroup()); err == nil || errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
