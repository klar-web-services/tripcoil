package pkgtool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
}

type Runner func(ctx context.Context, name string, args ...string) (Result, error)

func Exec(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil && ctx.Err() != nil {
		return Result{}, fmt.Errorf("%s was stopped: %w", name, ctx.Err())
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: ee.ExitCode()}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}
