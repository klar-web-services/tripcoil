package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/agent"
	"github.com/klar-web-services/tripcoil/internal/priority"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

// scopeEnv marks a run that runs in its transient scope; it reports on fd 3, a pipe, that it
// started.
const scopeEnv = "TRIPCOIL_SCOPE"

// oomScopeSystemd is the first systemd version (of those tested: 247, 249, 252, 257) whose scopes
// take OOMPolicy=.
const oomScopeSystemd = 252

// scopeArgs is the command line that runs "tripcoil run <args>" again in a transient scope with
// the service unit's CPU weight and memory cap. systemd-run --scope executes the command in place.
// oom keeps the run going when the kernel kills a Grype process for memory: that origin fails.
func scopeArgs(systemdRun, exe string, pid int, oom bool, args []string) []string {
	a := []string{systemdRun, "--scope", "--quiet", "--collect", fmt.Sprintf("--unit=tripcoil-run-%d", pid),
		"-p", fmt.Sprintf("CPUWeight=%d", priority.CPUWeight), "-p", "MemoryMax=" + priority.MemoryMax}
	if oom {
		a = append(a, "-p", "OOMPolicy=continue")
	}
	return append(append(a, "--", exe, "run"), args...)
}

// enterScope runs a manual run on a systemd host again in its transient scope (spec section 13)
// and returns its exit code with ran set. ran is false when the run should go on here: not
// systemd, already in the scope, or the scope could not be started (err says why).
func enterScope(args []string) (code int, ran bool, err error) {
	if os.Getenv(scopeEnv) != "" {
		os.Unsetenv(scopeEnv) // not for the run's own children
		// Only the pipe runScoped gave: a stray variable must not write into, or close, any other fd 3.
		var st syscall.Stat_t
		if syscall.Fstat(3, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFIFO {
			f := os.NewFile(3, "scope")
			f.Write([]byte{1})
			f.Close()
		}
		return 0, false, nil
	}
	if !sandbox.Booted() {
		return 0, false, nil
	}
	systemdRun, err := agent.LookPath("systemd-run")
	if err != nil {
		return 0, false, err
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, false, err
	}
	oom := false
	if systemctl, err := agent.LookPath("systemctl"); err == nil {
		if out, err := exec.Command(systemctl, "--version").Output(); err == nil {
			v, err := sandbox.SystemdVersion(out)
			oom = err == nil && v >= oomScopeSystemd
		}
	}
	return runScoped(scopeArgs(systemdRun, exe, os.Getpid(), oom, args))
}

// runScoped runs argv with a pipe on fd 3, which the run in the scope writes to as it starts.
// When nothing arrives, systemd-run failed before it started the run (its message is on stderr),
// and ran is false, unless a signal stopped it: then the run counts as interrupted (exit 2). The
// run has a process group of its own, so a terminal's Ctrl-C reaches only this process, which
// passes each signal on once (a second one ends a run at once); a hangup goes on as SIGTERM,
// once (bash and the kernel may each send one), so the run still writes its record. SIGTTOU is
// ignored, so the run, in a background group, may write to the terminal under stty tostop.
// pkill matches both processes, so the run would get its signal twice: signal this process
// instead. Ctrl-Z and Ctrl-\ reach only this process.
func runScoped(argv []string) (code int, ran bool, err error) {
	r, w, err := os.Pipe()
	if err != nil {
		return 0, false, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{w}
	cmd.Env = append(os.Environ(), scopeEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	signal.Ignore(syscall.SIGTTOU) // inherited by the run across exec
	sigs := make(chan os.Signal, 4)
	stops := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) { // under nohup the run must keep ignoring it
		stops = append(stops, syscall.SIGHUP)
	}
	signal.Notify(sigs, stops...)
	defer signal.Stop(sigs)
	err = cmd.Start()
	w.Close()
	if err != nil {
		r.Close()
		return 0, false, err
	}
	started := make(chan bool, 1)
	go func() {
		b := make([]byte, 1)
		n, _ := r.Read(b)
		r.Close()
		started <- n == 1
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped, hungUp := false, false
	for {
		select {
		case sig := <-sigs:
			stopped = true
			if sig == syscall.SIGHUP {
				if hungUp {
					continue
				}
				hungUp, sig = true, syscall.SIGTERM
			}
			cmd.Process.Signal(sig)
		case err := <-done:
			began := <-started
			select { // a signal that came with the exit
			case <-sigs:
				stopped = true
			default:
			}
			var ee *exec.ExitError
			code, exited := 0, err == nil
			if errors.As(err, &ee) && ee.ExitCode() >= 0 {
				code, exited = ee.ExitCode(), true
			}
			switch {
			case !began && (stopped || !exited):
				return 2, true, nil // stopped before the run began: interrupted, not run unscoped
			case !began:
				return 0, false, fmt.Errorf("systemd-run did not start the scope (%v)", err)
			case !exited:
				return 2, true, nil // killed by a signal: interrupted
			}
			return code, true, nil
		}
	}
}
