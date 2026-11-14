package pkgtool

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// Result is what a finished command printed and how it exited.
type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// Runner runs a command. The error is only for a command that could not run at all; a non-zero
// exit is reported in Result.ExitCode.
type Runner func(ctx context.Context, name string, args ...string) (Result, error)

// Exec runs the command with a fixed environment, so messages are untranslated and PATH is the
// system's.
func Exec(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: ee.ExitCode()}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}
