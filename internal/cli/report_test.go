package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReport(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"report"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "No run has finished yet") {
		t.Fatalf("before any run: exit %d, stderr %q", code, errb.String())
	}
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 0 {
		t.Fatalf("run: exit %d", code)
	}
	want, _ := os.ReadFile(filepath.Join(d.stateDir, "runs", runID, "report.md"))
	for _, args := range [][]string{{"report"}, {"report", "--run", runID}} {
		out.Reset()
		if code := dispatch(args, &out, &errb, d); code != 0 || out.String() != string(want) || len(want) == 0 {
			t.Fatalf("%v: exit %d, stdout %q", args, code, out.String())
		}
	}
	for args, msg := range map[string]string{
		"report --run ../../etc":             "is not a run ID",
		"report --run 20261114T061500Z-0000": "has no report",
		"report extra":                       "unexpected argument",
	} {
		errb.Reset()
		if code := dispatch(strings.Fields(args), &out, &errb, d); code != 2 || !strings.Contains(errb.String(), msg) {
			t.Errorf("%s: exit %d, stderr %q", args, code, errb.String())
		}
	}
	d.euid = func() int { return 1000 }
	errb.Reset()
	if code := dispatch([]string{"report"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("not root: exit %d, stderr %q", code, errb.String())
	}
}

func TestReportLatestWithoutReport(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	runs := filepath.Join(d.stateDir, "runs")
	if err := os.MkdirAll(runs, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(){
		"dangling":  func() {},
		"no report": func() { os.MkdirAll(filepath.Join(runs, runID), 0o750) },
	} {
		os.Remove(filepath.Join(runs, "latest"))
		os.Symlink(runID, filepath.Join(runs, "latest"))
		setup()
		var out, errb bytes.Buffer
		if code := dispatch([]string{"report"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "The latest run ("+runID+") has no report.") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errb.String())
		}
	}
}
