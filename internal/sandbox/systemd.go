package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Systemd struct {
	SystemdRun string
	Systemctl  string
}

// SystemdArgs is systemd-run's command line for s. It leaves out --quiet: systemd-run then ends
// its output with "Finished with result: <result>", which tells a timeout from a failure.
func SystemdArgs(s Spec) []string {
	a := []string{"--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + UnitPrefix + s.Name,
		"--uid=" + s.User.Name, "--gid=" + s.User.Name, "--working-directory=" + s.RunDir,
		"-p", "ProtectSystem=strict", "-p", "ProtectHome=yes", "-p", "PrivateDevices=yes",
		"-p", "ProtectProc=invisible", "-p", "NoNewPrivileges=yes",
		"-p", "ReadWritePaths=" + s.Home()}
	var hide []string
	for _, h := range s.hidden() {
		hide = append(hide, "-"+h)
	}
	a = append(a, "-p", "InaccessiblePaths="+strings.Join(hide, " "),
		"-p", "TemporaryFileSystem="+s.runs(), "-p", "BindReadOnlyPaths="+s.RunDir,
		// Private tmpfs instead of PrivateTmp's folders on disk: what the agent writes there counts
		// against MemoryMax and cannot fill the host's disk. PrivateDevices binds the host's
		// /dev/shm; a private one leaves nothing behind.
		"-p", "TemporaryFileSystem=/tmp:mode=1777 /var/tmp:mode=1777 /dev/shm:mode=1777", "-p", "RemoveIPC=yes",
		// ProtectSystem=strict leaves /run writable, with world-writable folders such as /run/lock.
		"-p", "ReadOnlyPaths=/run",
		// The kernel's keyrings and core dumps belong to the user, not the unit, and would carry
		// what one review stored or held in memory into the next.
		"-p", "SystemCallFilter=~@keyring", "-p", "SystemCallErrorNumber=EPERM", "-p", "LimitCORE=0",
		"-p", fmt.Sprintf("RuntimeMaxSec=%d", int(s.Timeout.Seconds())), "-p", "MemoryMax="+s.MemoryMax, "-p", "CPUQuota="+s.CPUQuota,
		"-p", "MemorySwapMax=0", "-p", fmt.Sprintf("TasksMax=%d", MaxTasks),
		"-p", "Nice=10", "-p", "IOSchedulingClass=idle")
	if s.EnvFile != "" {
		a = append(a, "-p", "EnvironmentFile="+s.EnvFile)
	}
	a = append(a, "-E", "HOME="+s.Home(), "-E", "LANG=C.UTF-8")
	for _, e := range s.Env {
		a = append(a, "-E", e)
	}
	return append(append(a, "--"), s.Command...)
}

func (d Systemd) Run(ctx context.Context, s Spec) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	unit := UnitPrefix + s.Name + ".service"
	defer d.stop(unit)
	var tail tailBuffer
	cmd := exec.Command(d.SystemdRun, SystemdArgs(s)...)
	cmd.Env = []string{"PATH=" + Path, "LANG=C.UTF-8"}
	cmd.Stdout = s.Stdout
	cmd.Stderr = io.MultiWriter(s.Stderr, &tail)
	cmd.WaitDelay = 5 * time.Second
	// Its own process group: a Ctrl-C or a service stop that signals Tripcoil's group must not
	// end systemd-run before Tripcoil has stopped the unit.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	backstop := time.NewTimer(s.Timeout + 2*time.Minute)
	defer backstop.Stop()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		d.stop(unit)
		err = waitOrKill(cmd, done)
	case <-backstop.C:
		d.stop(unit)
		waitOrKill(cmd, done)
		return Result{TimedOut: true, ExitCode: -1}, nil
	}
	res := Result{TimedOut: tail.finished() == "timeout"}
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

func (d Systemd) StopLeftovers() error {
	out, err := exec.Command(d.Systemctl, "stop", UnitPrefix+"*.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s*.service: %v: %s", UnitPrefix, err, bytes.TrimSpace(out))
	}
	return nil
}

func (d Systemd) stop(unit string) {
	exec.Command(d.Systemctl, "stop", unit).Run()
}

func waitOrKill(cmd *exec.Cmd, done chan error) error {
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		cmd.Process.Signal(syscall.SIGKILL)
		return <-done
	}
}

type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

func (t *tailBuffer) finished() string {
	const marker = "Finished with result: "
	i := bytes.LastIndex(t.b, []byte(marker))
	if i < 0 {
		return ""
	}
	rest, _, _ := bytes.Cut(t.b[i+len(marker):], []byte("\n"))
	return strings.TrimSpace(string(rest))
}
