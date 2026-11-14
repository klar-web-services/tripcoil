package pkgtool

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExec(t *testing.T) {
	res, err := Exec(context.Background(), "sh", "-c", "echo out; echo err >&2; echo $LC_ALL; exit 3")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || string(res.Stdout) != "out\nC\n" || string(res.Stderr) != "err\n" {
		t.Fatalf("%+v", res)
	}
	if _, err := Exec(context.Background(), "tripcoil-no-such-command"); err == nil {
		t.Fatal("a missing command must be an error")
	}
}

func TestExecInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if res, err := Exec(ctx, "sleep", "10"); !errors.Is(err, context.Canceled) {
		t.Fatalf("result %+v, error %v: a killed command is not a tool failure", res, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if res, err := Exec(ctx, "sleep", "10"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("result %+v, error %v", res, err)
	}
}
