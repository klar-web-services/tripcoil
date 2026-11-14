package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

var (
	errGrypeTimeout = errors.New("grype timeout")
	errLowSpace     = errors.New("the cache file system ran low on space while Grype ran")
)

// The largest reports that Scan and Match read. Parse holds every match, and users control how
// many a report of their files holds, such as of an app directory's lockfile: a report of a
// local-file: or local-directory: source, or of an SBOM cataloged from one, is read up to
// maxReportSize. Any other, of the package database or an image, is read up to
// maxSystemReportSize: Grype also lists every match that its rules ignore, which Parse reads past,
// and the default rules ignore Debian's and Ubuntu's kernel headers. An Ubuntu 22.04 host with two
// kernels gives 35,000 such matches, in a report of 326 MB.
var (
	maxReportSize       int64 = 128 << 20 // lowered by tests
	maxSystemReportSize int64 = 4 << 30   // lowered by tests
)

// spaceCheckEvery is how often HasRoom is asked while Grype runs: a nested-jar bomb unpacks about
// 0.9 GB in 500 ms. A check costs one statfs.
var spaceCheckEvery = 50 * time.Millisecond // lowered by tests

// Runner runs the verified Grype binary, isolated from any user or project configuration.
type Runner struct {
	Binary   string
	CacheDir string        // Tripcoil's cache; the database lives in CacheDir/grype-db
	Timeout  time.Duration // per invocation; default 15 minutes
	Environ  []string      // the parent environment, usually os.Environ()
	// HasRoom reports whether the file system that holds dir has free space above its floor. While
	// Grype runs, it is asked about Grype's temporary directory every spaceCheckEvery, and Grype is
	// stopped when it says no: what Grype unpacks there depends on what it scans, which users
	// control, and a small archive can unpack to gigabytes. Nil: no check.
	HasRoom func(dir string) bool
}

// Scan catalogs a source, such as "local-directory:/srv/shop", "local-file:/path" or
// "docker:sha256:…", and matches it: it writes Grype's JSON report to raw and the SBOM, as
// CycloneDX JSON, to sbom, and parses the report. When Grype fails, it leaves both files empty.
func (r *Runner) Scan(ctx context.Context, source, raw, sbom string) (*Report, error) {
	if err := r.run(ctx, []string{source, "-o", "json=" + raw, "-o", "cyclonedx-json=" + sbom}, io.Discard); err != nil {
		return nil, err
	}
	users := strings.HasPrefix(source, "local-file:") || strings.HasPrefix(source, "local-directory:")
	return readReport(raw, users)
}

// Match matches an SBOM against the database, writes Grype's JSON report to raw and parses it.
// users says that users control what the SBOM holds: it was cataloged from a local-file: or
// local-directory: source.
func (r *Runner) Match(ctx context.Context, sbom, raw string, users bool) (*Report, error) {
	if err := r.run(ctx, []string{"sbom:" + sbom, "-o", "json=" + raw}, io.Discard); err != nil {
		return nil, err
	}
	return readReport(raw, users)
}

// readReport parses the report at path, unless it is larger than its cap: then it is not read at
// all.
func readReport(path string, users bool) (*Report, error) {
	limit := maxSystemReportSize
	if users {
		limit = maxReportSize
	}
	f, err := openOutput(path, "Grype's report", limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(io.LimitReader(f, limit))
}

// ReadOutput reads a file that Grype wrote, named what in errors, unless it is larger than limit
// bytes: then it is not read at all.
func ReadOutput(path, what string, limit int64) ([]byte, error) {
	f, err := openOutput(path, what, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// openOutput opens a file that Grype wrote, named what in errors, unless it is larger than limit
// bytes.
func openOutput(path, what string, limit int64) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && fi.Size() > limit {
		err = fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// dbUpdateTimeout bounds a database update: about 3 GB, at the idle IO class.
const dbUpdateTimeout = time.Hour

// UpdateDB downloads a newer vulnerability database when there is one. It also removes the
// grype-db-download* directories before and after, so callers must hold the run lock: a
// concurrent run could still be unpacking a database into one of them. HasRoom is not asked while
// it runs: an update briefly needs about 3.4 GB of the cache file system, which the floor does not
// leave on a 40 GB disk with 7 GB free, and what it unpacks is the database, not what users control.
func (r *Runner) UpdateDB(ctx context.Context) error {
	r.removeDownloads()
	defer r.removeDownloads()
	return r.runFor(ctx, []string{"db", "update"}, io.Discard, max(r.Timeout, dbUpdateTimeout), false)
}

// removeDownloads removes the grype-db-download* directories that `grype db update` unpacks a
// new database into, up to 3 GB each, and leaves behind when it is stopped or fails.
func (r *Runner) removeDownloads() {
	db := filepath.Join(r.CacheDir, "grype-db")
	entries, _ := os.ReadDir(db)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "grype-db-download") {
			os.RemoveAll(filepath.Join(db, e.Name()))
		}
	}
}

// DBStatus is what `grype db status -o json` reports about the cached database.
type DBStatus struct {
	SchemaVersion string
	Built         time.Time
	Valid         bool
}

// DBStatus runs Grype's status check on the cached database. A database that does not exist or
// cannot be read makes Grype exit non-zero, which is an error here.
func (r *Runner) DBStatus(ctx context.Context) (DBStatus, error) {
	var out bytes.Buffer
	if err := r.run(ctx, []string{"db", "status", "-o", "json"}, &out); err != nil {
		return DBStatus{}, err
	}
	var raw struct {
		SchemaVersion string `json:"schemaVersion"`
		Built         string `json:"built"`
		Valid         bool   `json:"valid"`
	}
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		return DBStatus{}, fmt.Errorf("unexpected output from grype db status: %w", err)
	}
	built, err := time.Parse(time.RFC3339, raw.Built)
	if err != nil {
		return DBStatus{}, fmt.Errorf("grype db status reports no valid build time: %q", raw.Built)
	}
	return DBStatus{SchemaVersion: raw.SchemaVersion, Built: built.UTC(), Valid: raw.Valid}, nil
}

func (r *Runner) run(ctx context.Context, args []string, stdout io.Writer) error {
	return r.runFor(ctx, args, stdout, r.Timeout, true)
}

// runFor runs Grype with the private configuration, writing its stdout to stdout, for at most
// timeout (15 minutes when it is 0). Grype works in a fresh directory below the cache, also for
// its temporary files: an image's layers are unpacked there, on the cache's disk rather than in a
// /tmp that may be held in memory. watch says that HasRoom is asked while Grype runs.
func (r *Runner) runFor(ctx context.Context, args []string, stdout io.Writer, timeout time.Duration, watch bool) error {
	binary, err := filepath.Abs(r.Binary)
	if err != nil {
		return err
	}
	cacheDir, err := filepath.Abs(r.CacheDir)
	if err != nil {
		return err
	}
	args = append([]string{}, args...)
	for i, a := range args {
		for _, prefix := range []string{"dir:", "file:", "local-directory:", "local-file:", "sbom:"} {
			if rest, ok := strings.CutPrefix(a, prefix); ok {
				abs, err := filepath.Abs(rest)
				if err != nil {
					return err
				}
				args[i] = prefix + abs
			}
		}
		for _, prefix := range []string{"json=", "cyclonedx-json="} {
			if rest, ok := strings.CutPrefix(a, prefix); ok {
				abs, err := filepath.Abs(rest)
				if err != nil {
					return err
				}
				args[i] = prefix + abs
			}
		}
	}
	environ := r.Environ
	if environ == nil {
		environ = os.Environ()
	}
	tmpRoot := filepath.Join(cacheDir, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return err
	}
	work, err := os.MkdirTemp(tmpRoot, "grype-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	cfgPath := filepath.Join(work, "grype.yaml")
	if err := os.WriteFile(cfgPath, configYAML(cacheDir), 0o600); err != nil {
		return err
	}
	args = append(args, "-c", cfgPath)
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, errGrypeTimeout)
	defer cancel()
	if watch && r.HasRoom != nil {
		watched := make(chan struct{})
		go func() {
			defer close(watched)
			r.watchSpace(ctx, work, spaceCheckEvery, stop)
		}()
		defer func() {
			cancel()
			<-watched
		}()
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = work
	cmd.Env = isolatedEnv(environ, work)
	var stderr tailBuffer
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 10 * time.Second
	// Grype dies with Tripcoil, also when Tripcoil is killed. The kernel sends the signal when the
	// thread that started Grype exits, so the goroutine keeps that thread until Grype has ended:
	// the Go runtime ends a thread when a goroutine that locked it exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	err = cmd.Run()
	runtime.UnlockOSThread()
	if err == nil {
		return nil
	}
	switch {
	case context.Cause(ctx) == errGrypeTimeout:
		return fmt.Errorf("Grype timed out after %s", timeout)
	case context.Cause(ctx) == errLowSpace:
		return errLowSpace
	case ctx.Err() != nil:
		return ctx.Err()
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("Grype failed: %s", msg)
}

// watchSpace asks HasRoom about dir every interval until ctx ends, and stops Grype through stop
// when it says that dir's file system ran low on space.
func (r *Runner) watchSpace(ctx context.Context, dir string, interval time.Duration, stop context.CancelCauseFunc) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !r.HasRoom(dir) {
				stop(errLowSpace)
				return
			}
		}
	}
}

// configYAML is the only Grype configuration used: no update checks, a database in Tripcoil's
// cache that only UpdateDB updates, and no Grype-side age check (the Audit enforces
// audit.maxDatabaseAgeHours itself).
func configYAML(cacheDir string) []byte {
	type db struct {
		CacheDir    string `yaml:"cache-dir"`
		AutoUpdate  bool   `yaml:"auto-update"`
		ValidateAge bool   `yaml:"validate-age"`
	}
	cfg := struct {
		CheckForAppUpdate bool `yaml:"check-for-app-update"`
		DB                db   `yaml:"db"`
	}{false, db{CacheDir: filepath.Join(cacheDir, "grype-db"), AutoUpdate: false, ValidateAge: false}}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		panic(err) // a fixed struct always marshals
	}
	return out
}

// isolatedEnv drops GRYPE_* and SYFT_* settings, and points XDG_CONFIG_HOME and TMPDIR into the
// private work directory.
func isolatedEnv(parent []string, work string) []string {
	env := make([]string, 0, len(parent)+2)
	for _, kv := range parent {
		if strings.HasPrefix(kv, "GRYPE_") || strings.HasPrefix(kv, "SYFT_") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") || strings.HasPrefix(kv, "TMPDIR=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "XDG_CONFIG_HOME="+filepath.Join(work, "xdg"), "TMPDIR="+work)
}

// tailBuffer keeps the last 8 KiB written to it.
type tailBuffer struct{ buf []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 8192 {
		t.buf = t.buf[len(t.buf)-8192:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }
