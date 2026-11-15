package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
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
		audit: func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
			return sampleAudit(audit.Complete)
		},
		facts: func(context.Context, *inventory.Inventory, string) (*facts.Index, error) {
			return &facts.Index{Collected: []string{}, Missing: []facts.Missing{}, Notes: []string{}}, nil
		},
		agent:         func(config.Config) review.Agent { return nil },
		lowerPriority: func() error { return nil },
		interrupts:    func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
	}
}

// sampleAudit is an audit of sampleInventory with one finding.
func sampleAudit(status string, errs ...problem.Problem) *audit.Audit {
	a := &audit.Audit{SchemaVersion: "1", Status: status,
		Grype:    audit.GrypeInfo{Version: "0.121.2", DBBuilt: time.Date(2026, 11, 14, 3, 0, 0, 0, time.UTC)},
		Origins:  []audit.OriginResult{{ID: "kernel-upstream:7.3.3", Kind: "kernel-upstream", Status: audit.Scanned}},
		Findings: []audit.Finding{}, Upgrades: []audit.Upgrade{}, Errors: append([]problem.Problem{}, errs...), Warnings: []problem.Problem{}}
	if status != audit.Failed {
		a.Findings = append(a.Findings, audit.Finding{ID: "f:0000000000000001", Origin: "kernel-upstream:7.3.3", Risk: audit.RiskHigh, Items: []string{"kernel"},
			Vulnerability: audit.Vulnerability{ID: "CVE-2026-1", Severity: "High", EPSS: 0.2}, Package: audit.Package{Name: "linux", Version: "7.3.3"}, Source: "kernel-cna"})
	}
	return a
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
	if rec.Status != run.Complete || rec.Stages["inventory"] != run.StageOK || rec.Stages["audit"] != run.StageOK || rec.Counts["items"] != 1 ||
		rec.Trigger != "manual" || rec.Versions["tripcoil"] != "dev" || rec.Versions["grype"] != "0.121.2" || rec.Versions["grypeDB"] != "2026-11-14T03:00:00Z" {
		t.Fatalf("run.json %+v", rec)
	}
	if rec.Counts["findings"] != 1 || rec.Counts["findingsHigh"] != 1 || rec.Counts["findingsCritical"] != 0 || rec.Counts["coverageGaps"] != 0 {
		t.Fatalf("counts %+v", rec.Counts)
	}
	for _, name := range []string{"inventory.json", "audit.json", "report.md"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o640 {
			t.Fatalf("%s %v %v", name, fi, err)
		}
	}
	if md, _ := os.ReadFile(filepath.Join(dir, "report.md")); !strings.HasPrefix(string(md), "⚠️ Audit only (the AI review is not part of this build): 0 critical, 1 high") {
		t.Fatalf("report.md %s", md)
	}
	if target, err := os.Readlink(filepath.Join(d.stateDir, "runs", "latest")); err != nil || target != runID {
		t.Fatalf("latest -> %q %v", target, err)
	}
	if want := "Run " + runID + ": complete. 1 item, 1 origin, 1 finding, 0 coverage gaps.\nEvidence: " + dir + "\nRead the report with: sudo tripcoil report --run " + runID + "\n"; out.String() != want {
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
	if rec.Stages["audit"] != run.StageSkipped || rec.Stages["facts"] != run.StageSkipped {
		t.Fatalf("stages %v", rec.Stages)
	}
	if md, _ := os.ReadFile(filepath.Join(d.stateDir, "runs", runID, "report.md")); !strings.HasPrefix(string(md), "⛔ Run incomplete: cannot inventory the host") {
		t.Fatalf("report.md %s", md)
	}
}

func TestRunAuditFailedOrPartial(t *testing.T) {
	for _, tc := range []struct {
		status, stage, run string
		code               int
		err                problem.Problem
	}{
		{audit.Failed, run.StageFailed, run.Failed, 2, problem.New(problem.Error, problem.DBStale, "audit", "the vulnerability database is 73 hours old")},
		{audit.Partial, run.StagePartial, run.Partial, 1, problem.New(problem.Error, problem.OriginScanFailed, "audit", "/opt/api/api: Grype failed")},
	} {
		d := testDeps(t, sampleInventory(), nil)
		d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
			return sampleAudit(tc.status, tc.err)
		}
		var out, errb bytes.Buffer
		if code := dispatch([]string{"run"}, &out, &errb, d); code != tc.code {
			t.Fatalf("%s: exit %d", tc.status, code)
		}
		rec := readRecord(t, d.stateDir)
		if rec.Status != tc.run || rec.Stages["audit"] != tc.stage || len(rec.Errors) != 1 || rec.Errors[0].Code != tc.err.Code {
			t.Fatalf("%s: run.json %+v", tc.status, rec)
		}
		if target, err := os.Readlink(filepath.Join(d.stateDir, "runs", "latest")); err != nil || target != runID {
			t.Fatalf("%s: latest -> %q %v", tc.status, target, err)
		}
	}
}

func TestRunInterruptedDuringAudit(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	d.interrupts = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
		cancel() // Ctrl-C arrives while Grype runs
		return sampleAudit(audit.Partial)
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	rec := readRecord(t, d.stateDir)
	if rec.Status != run.Interrupted || rec.Stages["inventory"] != run.StageOK || rec.Stages["audit"] != run.StageFailed || rec.Errors[0].Code != problem.Interrupted {
		t.Fatalf("run.json %+v", rec)
	}
	for _, name := range []string{"inventory.json", "audit.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(d.stateDir, "runs", runID, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(d.stateDir, "runs", "latest")); !os.IsNotExist(err) {
		t.Fatal("latest must keep pointing at the last finished run")
	}
}

func TestRunLowersItsPriority(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	called := false
	d.lowerPriority = func() error { called = true; return errors.New("operation not permitted") }
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 0 || !called {
		t.Fatalf("exit %d, called %v", code, called)
	}
	if !strings.Contains(errb.String(), "cannot lower the run's priority: operation not permitted") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestRunReportWriteFailed(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
		if err := os.MkdirAll(filepath.Join(d.stateDir, "runs", runID, "report.md", "x"), 0o750); err != nil { // a directory where report.md goes
			t.Fatal(err)
		}
		return sampleAudit(audit.Complete)
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if rec := readRecord(t, d.stateDir); rec.Status != run.Failed || rec.Errors[0].Code != problem.RunFolderUnwritable {
		t.Fatalf("run.json %+v", rec)
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

func TestRunPrintsErrorsOnOneLine(t *testing.T) {
	d := testDeps(t, nil, errors.New("bad\x1b[2J path\nsecond\rline\x07 \u202egnp.exe\u200b/x"))
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	for _, r := range strings.ReplaceAll(out.String(), "\n", "") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("control or format character %q in %q", r, out.String())
		}
	}
	if !strings.Contains(out.String(), "bad [2J path second line   gnp.exe /x") {
		t.Fatalf("stdout %q", out.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 4 {
		t.Fatalf("%d lines in %q", n, out.String())
	}
}

func TestRunPointsAtThisRunsReport(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	var out, errb bytes.Buffer
	dispatch([]string{"run"}, &out, &errb, d)
	if !strings.Contains(out.String(), "sudo tripcoil report --run "+runID+"\n") {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestRunPriorityWarningOnOneLine(t *testing.T) {
	d := testDeps(t, sampleInventory(), nil)
	d.lowerPriority = func() error { return errors.Join(errors.New("setpriority: denied"), errors.New("ionice: denied")) }
	var out, errb bytes.Buffer
	dispatch([]string{"run"}, &out, &errb, d)
	want := "tripcoil: cannot lower the run's priority: setpriority: denied; ionice: denied\n"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestRunInterruptedKeepsStageProblems(t *testing.T) {
	warn := problem.New(problem.Warning, "W_ONE", "inventory", "inv warning")
	e1 := problem.New(problem.Error, "E_INV", "inventory", "inv error")
	d := testDeps(t, sampleInventory(e1, warn), nil)
	d.interrupts = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	var out, errb bytes.Buffer
	dispatch([]string{"run"}, &out, &errb, d)
	rec := readRecord(t, d.stateDir)
	if len(rec.Errors) != 2 || rec.Errors[1].Code != "E_INV" || len(rec.Warnings) != 1 || rec.Warnings[0].Code != "W_ONE" {
		t.Fatalf("inventory problems lost: %+v", rec)
	}
	if rec.Stages["audit"] != run.StageSkipped {
		t.Fatalf("stages %+v", rec.Stages)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d = testDeps(t, sampleInventory(), nil)
	d.interrupts = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	d.audit = func(context.Context, *inventory.Inventory, string, string, config.Config) *audit.Audit {
		cancel()
		a := sampleAudit(audit.Partial, problem.New(problem.Error, "E_AUD", "audit", "audit error"),
			problem.New(problem.Error, problem.Interrupted, "audit", "stopped"))
		a.Warnings = append(a.Warnings, problem.New(problem.Warning, "W_AUD", "audit", "audit warning"))
		return a
	}
	out.Reset()
	dispatch([]string{"run"}, &out, &errb, d)
	rec = readRecord(t, d.stateDir)
	if len(rec.Errors) != 2 || rec.Errors[0].Code != problem.Interrupted || rec.Errors[1].Code != "E_AUD" ||
		len(rec.Warnings) != 1 || rec.Warnings[0].Code != "W_AUD" {
		t.Fatalf("audit problems lost: %+v", rec)
	}
}

// The Audit checks images at the Docker socket the Inventory reads.
func TestDockerImages(t *testing.T) {
	if dockerImages("tcp://10.0.0.5:2375") != nil {
		t.Fatal("DOCKER_HOST is not a unix socket, so the Inventory found no containers")
	}
	if dockerImages("") == nil {
		t.Fatal("the default socket")
	}
	dir, err := os.MkdirTemp("", "tc-docker") // short path: unix socket paths are limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	if ok, err := dockerImages("unix://"+sock).ImageExists(context.Background(), "sha256:1111"); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
}
