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
	"slices"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

var (
	errGrypeTimeout = errors.New("grype timeout")
	errLowSpace     = errors.New("the cache file system ran low on space while Grype ran")
	errTooLarge     = errors.New("the image is larger than Tripcoil downloads for a scan")
)

// MaxDownload is how much an image read from its registry may take on disk while it is scanned.
var MaxDownload int64 = 3 << 30

var sizeCheckEvery = time.Second

var (
	maxReportSize       int64 = 128 << 20
	maxSystemReportSize int64 = 4 << 30
)

var spaceCheckEvery = 50 * time.Millisecond

type Runner struct {
	Binary   string
	CacheDir string
	Timeout  time.Duration
	Environ  []string
	HasRoom  func(dir string) bool
}

func (r *Runner) Scan(ctx context.Context, source, raw, sbom string) (*Report, error) {
	if err := r.run(ctx, []string{source, "-o", "json=" + raw, "-o", "cyclonedx-json=" + sbom}, io.Discard); err != nil {
		return nil, err
	}
	users := strings.HasPrefix(source, "local-file:") || strings.HasPrefix(source, "local-directory:")
	return readReport(raw, users)
}

func (r *Runner) Match(ctx context.Context, sbom, raw string, users bool) (*Report, error) {
	if err := r.run(ctx, []string{"sbom:" + sbom, "-o", "json=" + raw}, io.Discard); err != nil {
		return nil, err
	}
	return readReport(raw, users)
}

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

func ReadOutput(path, what string, limit int64) ([]byte, error) {
	f, err := openOutput(path, what, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

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

func (r *Runner) removeDownloads() {
	db := filepath.Join(r.CacheDir, "grype-db")
	entries, _ := os.ReadDir(db)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "grype-db-download") {
			os.RemoveAll(filepath.Join(db, e.Name()))
		}
	}
}

type DBStatus struct {
	SchemaVersion string
	Built         time.Time
	Valid         bool
}

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
	if slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "registry:") }) {
		sized := make(chan struct{})
		go func() {
			defer close(sized)
			watchSize(ctx, work, MaxDownload, sizeCheckEvery, stop)
		}()
		defer func() {
			cancel()
			<-sized
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
	case context.Cause(ctx) == errTooLarge:
		return fmt.Errorf("%w (%d GiB)", errTooLarge, MaxDownload>>30)
	case ctx.Err() != nil:
		return ctx.Err()
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("Grype failed: %s", msg)
}

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

// watchSize stops Grype when the files below dir take more than limit bytes: an image that is read
// from its registry lands there, and its size is not known beforehand.
func watchSize(ctx context.Context, dir string, limit int64, interval time.Duration, stop context.CancelCauseFunc) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			var size int64
			filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
				if err == nil && d.Type().IsRegular() {
					if fi, err := d.Info(); err == nil {
						size += fi.Size()
					}
				}
				return nil
			})
			if size > limit {
				stop(errTooLarge)
				return
			}
		}
	}
}

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
		panic(err)
	}
	return out
}

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

type tailBuffer struct{ buf []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 8192 {
		t.buf = t.buf[len(t.buf)-8192:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }
