package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	code := dispatch([]string{"version"}, &out, &errb, deps{})
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if out.String() != "tripcoil dev\ngrype 0.121.2\nprompt 3\n" {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := dispatch(nil, &out, &errb, deps{}); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := dispatch([]string{"frob"}, &out, &errb, deps{}); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), `unknown command "frob"`) {
		t.Fatalf("stderr %q", errb.String())
	}
}
