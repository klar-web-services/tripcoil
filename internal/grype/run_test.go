package grype

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newRunner(t *testing.T, extraEnv ...string) (*Runner, string, string) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	r := &Runner{
		Binary:   fakeGrype(t),
		CacheDir: filepath.Join(dir, "cache"),
		Environ:  append(append(os.Environ(), "FAKE_GRYPE_LOG="+log), extraEnv...),
	}
	return r, dir, log
}

func args(t *testing.T, log string) []string {
	return strings.Split(strings.TrimSpace(read(t, log)), "\n")
}

func noWorkDirs(t *testing.T, r *Runner) {
	t.Helper()
	left, err := os.ReadDir(filepath.Join(r.CacheDir, "tmp"))
	if err != nil || len(left) > 0 {
		t.Fatalf("work directories left behind: %v %v", left, err)
	}
}

func TestScanRunsGrypeIsolated(t *testing.T) {
	r, dir, log := newRunner(t, "GRYPE_DB_AUTO_UPDATE=true", "SYFT_EXCLUDE=x", "TMPDIR=/tmp")
	raw, sbom := filepath.Join(dir, "out.json"), filepath.Join(dir, "out.cdx.json")
	rep, err := r.Scan(context.Background(), "dir:/srv/shop", raw, sbom)
	if err != nil || !rep.DBBuilt.Equal(time.Date(2026, 11, 14, 3, 12, 0, 0, time.UTC)) {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := args(t, log); !slices.Equal(got[:6], []string{"dir:/srv/shop", "-o", "json=" + raw, "-o", "cyclonedx-json=" + sbom, "-c"}) {
		t.Fatalf("args %q", got)
	}
	env := read(t, log+".env")
	if strings.Contains(env, "GRYPE_DB_AUTO_UPDATE") || strings.Contains(env, "SYFT_EXCLUDE") || strings.Contains(env, "TMPDIR=/tmp\n") {
		t.Fatalf("the caller's GRYPE_*, SYFT_* and TMPDIR reach Grype:\n%s", env)
	}
	work := strings.TrimSpace(read(t, log+".pwd"))
	if !strings.HasPrefix(work, filepath.Join(dir, "cache", "tmp")+"/") {
		t.Fatalf("work directory %s is not below the cache", work)
	}
	for _, want := range []string{"TMPDIR=" + work + "\n", "XDG_CONFIG_HOME=" + work + "/xdg\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("environment lacks %q", want)
		}
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("work directory left behind: %v", err)
	}
	cfg := read(t, log+".cfg")
	for _, s := range []string{"check-for-app-update: false", "auto-update: false", "validate-age: false", filepath.Join(dir, "cache", "grype-db")} {
		if !strings.Contains(cfg, s) {
			t.Errorf("config lacks %q:\n%s", s, cfg)
		}
	}
	if !strings.Contains(read(t, sbom), "CycloneDX") {
		t.Fatal("no SBOM written")
	}
}

func TestMatchParsesTheReport(t *testing.T) {
	r, dir, log := newRunner(t)
	raw := filepath.Join(dir, "raw.json")
	rep, err := r.Match(context.Background(), "relative/a.cdx.json", raw, false)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs("relative/a.cdx.json")
	if got := args(t, log); !slices.Equal(got[:3], []string{"sbom:" + abs, "-o", "json=" + raw}) {
		t.Fatalf("args %q", got)
	}
	if !rep.DBBuilt.Equal(time.Date(2026, 11, 14, 3, 12, 0, 0, time.UTC)) {
		t.Fatalf("report %+v", rep)
	}
}

func TestUpdateAndStatus(t *testing.T) {
	r, _, log := newRunner(t, `FAKE_GRYPE_STATUS={"schemaVersion":"v6.1.10","from":"x","built":"2026-11-14T03:12:00Z","valid":true}`)
	if err := r.UpdateDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := args(t, log); !slices.Equal(got[:3], []string{"db", "update", "-c"}) {
		t.Fatalf("args %q", got)
	}
	st, err := r.DBStatus(context.Background())
	if err != nil || !st.Valid || st.SchemaVersion != "v6.1.10" || !st.Built.Equal(time.Date(2026, 11, 14, 3, 12, 0, 0, time.UTC)) {
		t.Fatalf("%+v %v", st, err)
	}
	r, _, _ = newRunner(t, "FAKE_GRYPE_STATUS_EXIT=1")
	if _, err := r.DBStatus(context.Background()); err == nil {
		t.Fatal("a failing db status must be an error")
	}
}

func TestUpdateDBRemovesUnpackedDownloads(t *testing.T) {
	for _, exit := range []string{"0", "1"} {
		r, _, log := newRunner(t, "FAKE_GRYPE_EXIT="+exit)
		db := filepath.Join(r.CacheDir, "grype-db")
		r.Environ = append(r.Environ, "FAKE_GRYPE_DB="+db)
		for _, dir := range []string{"6", "grype-db-download1"} {
			if err := os.MkdirAll(filepath.Join(db, dir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(db, dir, "vulnerability.db"), []byte("db"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.UpdateDB(context.Background()); (err != nil) != (exit == "1") {
			t.Fatalf("exit %s: %v", exit, err)
		}
		if seen := read(t, log+".db"); strings.Contains(seen, "grype-db-download") {
			t.Errorf("exit %s: Grype started with an earlier download still there:\n%s", exit, seen)
		}
		if left, _ := filepath.Glob(filepath.Join(db, "grype-db-download*")); len(left) > 0 {
			t.Errorf("exit %s: downloads left behind: %q", exit, left)
		}
		if _, err := os.Stat(filepath.Join(db, "6", "vulnerability.db")); err != nil {
			t.Errorf("exit %s: the current database is gone: %v", exit, err)
		}
	}
}

func TestRunFailuresAndTimeouts(t *testing.T) {
	r, dir, _ := newRunner(t, "FAKE_GRYPE_EXIT=1", "FAKE_GRYPE_STDERR=could not fetch image")
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if _, err := r.Scan(context.Background(), "docker:sha256:1", a, b); err == nil || !strings.Contains(err.Error(), "could not fetch image") {
		t.Fatalf("err %v", err)
	}
	noWorkDirs(t, r)
	r, dir, _ = newRunner(t, "FAKE_GRYPE_SLEEP=5")
	r.Timeout = 300 * time.Millisecond
	if _, err := r.Scan(context.Background(), "dir:/src", a, b); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err %v", err)
	}
	noWorkDirs(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Scan(ctx, "dir:/src", a, b); err != context.Canceled {
		t.Fatalf("cancelled: %v", err)
	}
	noWorkDirs(t, r)
}

func TestCancelWhileGrypeRuns(t *testing.T) {
	r, dir, log := newRunner(t, "FAKE_GRYPE_SLEEP=5")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for range 500 {
			if _, err := os.Stat(log + ".pwd"); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	if _, err := r.Scan(ctx, "dir:/src", filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != context.Canceled {
		t.Fatalf("err %v", err)
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Fatalf("Grype was not stopped: Scan returned after %s", took)
	}
	noWorkDirs(t, r)
}

// Grype is stopped when the cache file system runs low on space while it runs: what it unpacks
// into its temporary directory depends on what it scans.
func TestGrypeStopsWhenTheCacheRunsLow(t *testing.T) {
	old := spaceCheckEvery
	spaceCheckEvery = 20 * time.Millisecond
	defer func() { spaceCheckEvery = old }()
	r, dir, _ := newRunner(t, "FAKE_GRYPE_SLEEP=10")
	var mu sync.Mutex
	var asked []string
	r.HasRoom = func(d string) bool {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, d)
		return len(asked) < 3
	}
	start := time.Now()
	_, err := r.Scan(context.Background(), "dir:/src", filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	if err == nil || err.Error() != "the cache file system ran low on space while Grype ran" {
		t.Fatalf("err %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("Grype was not stopped: Scan returned after %s", took)
	}
	mu.Lock()
	if len(asked) != 3 || !strings.HasPrefix(asked[0], filepath.Join(r.CacheDir, "tmp", "grype-")) {
		t.Fatalf("asked about %q, want Grype's temporary directory three times", asked)
	}
	mu.Unlock()
	noWorkDirs(t, r)
	r, dir, _ = newRunner(t)
	r.HasRoom = func(string) bool { return true }
	if _, err := r.Scan(context.Background(), "dir:/src", filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
		t.Fatalf("with room: %v", err)
	}
}

// A database update runs without the free-space check: it briefly needs about 3.4 GB of the cache
// file system, which the floor does not leave on a small disk that has room for every scan.
func TestUpdateDBDoesNotAskAboutSpace(t *testing.T) {
	old := spaceCheckEvery
	spaceCheckEvery = 5 * time.Millisecond
	defer func() { spaceCheckEvery = old }()
	r, _, _ := newRunner(t, "FAKE_GRYPE_SLEEP=0.3")
	var asked atomic.Int32
	r.HasRoom = func(string) bool {
		asked.Add(1)
		return false
	}
	if err := r.UpdateDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("UpdateDB asked about free space %d times", n)
	}
}

// The plain file and directory sources are given to Grype by absolute path too.
func TestScanTakesPlainSourcesByAbsolutePath(t *testing.T) {
	for _, scheme := range []string{"local-file:", "local-directory:"} {
		r, dir, log := newRunner(t)
		if _, err := r.Scan(context.Background(), scheme+"relative/x", filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
			t.Fatal(err)
		}
		abs, _ := filepath.Abs("relative/x")
		if got := args(t, log); got[0] != scheme+abs {
			t.Errorf("source %q, want %q", got[0], scheme+abs)
		}
	}
}

// A report of what users control that is larger than the cap is not read: users control how many
// matches it holds.
func TestReportsAboveTheCapAreNotRead(t *testing.T) {
	old := maxReportSize
	maxReportSize = 100
	defer func() { maxReportSize = old }()
	r, dir, _ := newRunner(t) // the fake's report is longer than 100 bytes
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, source := range []string{"local-file:/x", "local-directory:/srv/shop"} {
		if _, err := r.Scan(context.Background(), source, a, b); err == nil || err.Error() != "Grype's report is larger than 100 bytes" {
			t.Fatalf("scan of %s: %v", source, err)
		}
	}
	if _, err := r.Match(context.Background(), b, a, true); err == nil || err.Error() != "Grype's report is larger than 100 bytes" {
		t.Fatalf("match: %v", err)
	}
	maxReportSize = old
	if _, err := r.Scan(context.Background(), "local-file:/x", a, b); err != nil {
		t.Fatal(err)
	}
}

// The package database's and images' reports are read past the cap on what users control, up to
// their own: Grype lists every match that its rules ignore, and Debian's and Ubuntu's kernel
// headers give tens of thousands, about 5 KB each. The report stays in the run folder as Grype
// wrote it.
func TestSystemReportsAreReadPastTheUsersCap(t *testing.T) {
	report, err := io.ReadAll(reportWithIgnored(200))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, report, 0o600); err != nil {
		t.Fatal(err)
	}
	old, oldSystem := maxReportSize, maxSystemReportSize
	maxReportSize = 64 << 10
	defer func() { maxReportSize, maxSystemReportSize = old, oldSystem }()
	r, dir, _ := newRunner(t, "FAKE_GRYPE_JSON_FILE="+path)
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, source := range []string{"dir:/var/lib/tripcoil/cache/staging", "docker:sha256:1111"} {
		if rep, err := r.Scan(context.Background(), source, a, b); err != nil || len(rep.Matches) != 1 {
			t.Errorf("scan of %s: %+v %v", source, rep, err)
		}
	}
	if rep, err := r.Match(context.Background(), b, a, false); err != nil || len(rep.Matches) != 1 {
		t.Errorf("match: %+v %v", rep, err)
	}
	if read(t, a) != string(report) {
		t.Error("the report left in place is not Grype's")
	}
	if _, err := r.Scan(context.Background(), "local-directory:/srv/shop", a, b); err == nil || err.Error() != "Grype's report is larger than 65536 bytes" {
		t.Errorf("scan of what users control: %v", err)
	}
	if _, err := r.Match(context.Background(), b, a, true); err == nil || err.Error() != "Grype's report is larger than 65536 bytes" {
		t.Errorf("match of what users control: %v", err)
	}
	maxSystemReportSize = 64 << 10
	if _, err := r.Scan(context.Background(), "dir:/var/lib/tripcoil/cache/staging", a, b); err == nil || err.Error() != "Grype's report is larger than 65536 bytes" {
		t.Errorf("above the cap on other reports: %v", err)
	}
}

// Grype dies with Tripcoil, also when Tripcoil is killed with SIGKILL, which it cannot handle. The
// test runs Tripcoil's side in a child process, kills it, and watches Grype.
func TestGrypeDiesWithTripcoil(t *testing.T) {
	if dir := os.Getenv("TRIPCOIL_TEST_GRYPE_DIR"); dir != "" {
		r := &Runner{Binary: filepath.Join(dir, "grype"), CacheDir: filepath.Join(dir, "cache"),
			Environ: append(os.Environ(), "FAKE_GRYPE_SLEEP=60", "FAKE_GRYPE_PID="+filepath.Join(dir, "grype.pid"))}
		r.Scan(context.Background(), "dir:/src", filepath.Join(dir, "a"), filepath.Join(dir, "b"))
		return
	}
	dir := t.TempDir()
	if err := os.Rename(fakeGrype(t), filepath.Join(dir, "grype")); err != nil {
		t.Fatal(err)
	}
	tripcoil := exec.Command(os.Args[0], "-test.run=^TestGrypeDiesWithTripcoil$")
	tripcoil.Env = append(os.Environ(), "TRIPCOIL_TEST_GRYPE_DIR="+dir)
	if err := tripcoil.Start(); err != nil {
		t.Fatal(err)
	}
	pid := 0
	for range 500 {
		if data, err := os.ReadFile(filepath.Join(dir, "grype.pid")); err == nil {
			if pid, _ = strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	tripcoil.Process.Kill()
	tripcoil.Wait()
	if pid == 0 {
		t.Fatal("Grype did not start")
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	for range 500 {
		if !running(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Grype (PID %d) outlived Tripcoil", pid)
}

// running reports whether a process exists and is not a zombie.
func running(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(data, ')') // the state follows the command name
	return i+2 < len(data) && data[i+2] != 'Z'
}
