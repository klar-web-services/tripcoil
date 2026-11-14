package pkgtool

import (
	"context"
	"testing"
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
