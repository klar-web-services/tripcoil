package grype

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	rep, err := r.Match(context.Background(), "relative/a.cdx.json", raw)
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

func TestRunFailuresAndTimeouts(t *testing.T) {
	r, dir, _ := newRunner(t, "FAKE_GRYPE_EXIT=1", "FAKE_GRYPE_STDERR=could not fetch image")
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if _, err := r.Scan(context.Background(), "docker:sha256:1", a, b); err == nil || !strings.Contains(err.Error(), "could not fetch image") {
		t.Fatalf("err %v", err)
	}
	r, dir, _ = newRunner(t, "FAKE_GRYPE_SLEEP=5")
	r.Timeout = 300 * time.Millisecond
	if _, err := r.Scan(context.Background(), "dir:/src", a, b); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Scan(ctx, "dir:/src", a, b); err != context.Canceled {
		t.Fatalf("cancelled: %v", err)
	}
}
