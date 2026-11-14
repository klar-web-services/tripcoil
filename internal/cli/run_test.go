package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const runID = "20261114T061500Z-3fa2"

func testDeps(t *testing.T, inv *inventory.Inventory, err error) deps {
	old := run.AgentGID
	run.AgentGID = func() (int, bool) { return 0, false } // independent of a tripcoil-agent group on this machine
	t.Cleanup(func() { run.AgentGID = old })
	return deps{
		euid:       func() int { return 0 },
		now:        func() time.Time { return time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC) },
		random:     bytes.NewReader([]byte{0x3f, 0xa2}),
		configPath: filepath.Join(t.TempDir(), "tripcoil.yaml"),
		stateDir:   t.TempDir(),
		collect:    func(context.Context, string) (*inventory.Inventory, error) { return inv, err },
		interrupts: func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
	}
}

func TestRunInterrupted(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.interrupts = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Ctrl-C arrives while the inventory runs
		return ctx, func() {}
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	rec := readRecord(t, d.stateDir)
	if rec.Status != run.Interrupted || len(rec.Errors) != 1 || rec.Errors[0].Code != problem.Interrupted {
		t.Fatalf("run.json %+v", rec)
	}
	if _, err := os.Lstat(filepath.Join(d.stateDir, "runs", "latest")); !os.IsNotExist(err) {
		t.Fatal("latest must keep pointing at the last finished run")
	}
	if _, err := os.Stat(filepath.Join(d.stateDir, "runs", runID, "inventory.json")); err != nil {
		t.Fatalf("what was collected must be written: %v", err)
	}
	if rec.Counts["items"] != 1 || rec.Counts["origins"] != 1 {
		t.Fatalf("counts %+v", rec.Counts)
	}
}

func TestRunInterruptedInventoryWriteFailed(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.collect = func(context.Context, string) (*inventory.Inventory, error) {
		blocker := filepath.Join(d.stateDir, "runs", runID, "inventory.json", "x")
		if err := os.MkdirAll(blocker, 0o750); err != nil { // a directory where inventory.json goes
			t.Fatal(err)
		}
		return sampleInventory(), nil
	}
	d.interrupts = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	rec := readRecord(t, d.stateDir)
	if rec.Status != run.Interrupted || len(rec.Errors) != 2 || rec.Errors[0].Code != problem.Interrupted ||
		rec.Errors[1].Code != problem.RunFolderUnwritable {
		t.Fatalf("run.json %+v", rec)
	}
	if _, err := os.Lstat(filepath.Join(d.stateDir, "runs", "latest")); !os.IsNotExist(err) {
		t.Fatal("latest must keep pointing at the last finished run")
	}
}

func sampleInventory(errs ...problem.Problem) *inventory.Inventory {
	return &inventory.Inventory{
		SchemaVersion: "1",
		Items:         []inventory.Item{{ID: "kernel", Kind: "kernel", Name: "kernel", Origins: []string{"kernel-upstream:7.3.3"}}},
		Origins:       []inventory.Origin{{ID: "kernel-upstream:7.3.3", Kind: "kernel-upstream", UpstreamVersion: "7.3.3"}},
		Errors:        append([]problem.Problem{}, errs...),
		Warnings:      []problem.Problem{},
		Notices:       []problem.Problem{},
	}
}

func readRecord(t *testing.T, state string) run.Record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(state, "runs", runID, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec run.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestRunWritesEvidence(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	dir := filepath.Join(d.stateDir, "runs", runID)
	rec := readRecord(t, d.stateDir)
	if rec.Status != run.Complete || rec.Stages["inventory"] != run.StageOK || rec.Counts["items"] != 1 || rec.Trigger != "manual" || rec.Versions["tripcoil"] != "dev" {
		t.Fatalf("run.json %+v", rec)
	}
	if fi, err := os.Stat(filepath.Join(dir, "inventory.json")); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("inventory.json %v %v", fi, err)
	}
	if target, err := os.Readlink(filepath.Join(d.stateDir, "runs", "latest")); err != nil || target != runID {
		t.Fatalf("latest -> %q %v", target, err)
	}
	if want := "Run " + runID + ": complete. 1 item, 1 origin.\nEvidence: " + dir + "\n"; out.String() != want {
		t.Fatalf("stdout %q, want %q", out.String(), want)
	}
	if !strings.Contains(errb.String(), "does not exist yet, so the defaults apply") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestRunPartial(t *testing.T) {
	d := testDeps(t, sampleInventory(problem.New(problem.Error, problem.DockerUnavailable, "inventory", "Docker does not answer")), nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "error DOCKER_UNAVAILABLE: Docker does not answer") {
		t.Fatalf("stdout %q", out.String())
	}
	if rec := readRecord(t, d.stateDir); rec.Status != run.Partial || len(rec.Errors) != 1 {
		t.Fatalf("run.json %+v", rec)
	}
}

func TestRunInventoryFailed(t *testing.T) {
	d := testDeps(t, nil, errors.New("cannot list processes: permission denied"))
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	rec := readRecord(t, d.stateDir)
	if rec.Status != run.Failed || rec.Stages["inventory"] != run.StageFailed || len(rec.Errors) != 1 || rec.Errors[0].Code != problem.InventoryFailed {
		t.Fatalf("run.json %+v", rec)
	}
	if _, err := os.Stat(filepath.Join(d.stateDir, "runs", runID, "inventory.json")); !os.IsNotExist(err) {
		t.Fatal("no inventory.json without an inventory")
	}
}

func TestRunJSON(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run", "--json"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var rec run.Record
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil || rec.RunID != runID {
		t.Fatalf("stdout is not run.json: %v\n%s", err, out.String())
	}
}

func TestRunRefusals(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.euid = func() int { return 1000 }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("not root: exit %d, stderr %q", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(d.stateDir, "runs")); !os.IsNotExist(err) {
		t.Fatal("nothing may be written without root")
	}

	d = testDeps(t, sampleInventory(), nil)
	if err := os.WriteFile(d.configPath, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "CONFIG_INVALID") || !strings.Contains(errb.String(), "version must be 1") {
		t.Fatalf("bad config: exit %d, stderr %q", code, errb.String())
	}

	errb.Reset()
	if code := dispatch([]string{"run", "extra"}, &out, &errb, testDeps(t, sampleInventory(), nil)); code != 2 {
		t.Fatalf("extra argument: exit %d", code)
	}
}

func TestRunInventoryWriteFailed(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.collect = func(context.Context, string) (*inventory.Inventory, error) {
		blocker := filepath.Join(d.stateDir, "runs", runID, "inventory.json", "x")
		if err := os.MkdirAll(blocker, 0o750); err != nil { // a directory where inventory.json goes
			t.Fatal(err)
		}
		return sampleInventory(), nil
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	rec := readRecord(t, d.stateDir)
	if rec.Status != run.Failed || rec.ExitCode != 2 || rec.Stages["inventory"] != run.StageFailed ||
		len(rec.Errors) != 1 || rec.Errors[0].Code != problem.RunFolderUnwritable {
		t.Fatalf("run.json %+v", rec)
	}
	if target, err := os.Readlink(filepath.Join(d.stateDir, "runs", "latest")); err != nil || target != runID {
		t.Fatalf("latest -> %q %v", target, err)
	}
}

func TestRunLatestUpdateFailed(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		d := testDeps(t, sampleInventory(), nil)
		d.collect = func(context.Context, string) (*inventory.Inventory, error) {
			blocker := filepath.Join(d.stateDir, "runs", "latest", "x")
			if err := os.MkdirAll(blocker, 0o750); err != nil { // a directory where latest goes
				t.Fatal(err)
			}
			return sampleInventory(), nil
		}
		args := []string{"run"}
		if asJSON {
			args = append(args, "--json")
		}
		var out, errb bytes.Buffer
		if code := dispatch(args, &out, &errb, d); code != 0 {
			t.Fatalf("json=%v: exit %d, stderr %q", asJSON, code, errb.String())
		}
		if !strings.Contains(errb.String(), "cannot update runs/latest") {
			t.Fatalf("json=%v: stderr %q", asJSON, errb.String())
		}
		if asJSON {
			var rec run.Record
			if err := json.Unmarshal(out.Bytes(), &rec); err != nil || rec.RunID != runID {
				t.Fatalf("stdout is not run.json: %v\n%s", err, out.String())
			}
		} else if !strings.Contains(out.String(), "Run "+runID+": complete.") {
			t.Fatalf("stdout %q", out.String())
		}
		if rec := readRecord(t, d.stateDir); rec.Status != run.Complete {
			t.Fatalf("run.json %+v", rec)
		}
	}
}
