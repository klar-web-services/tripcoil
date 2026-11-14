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
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

var errGrypeTimeout = errors.New("grype timeout")

// Runner runs the verified Grype binary, isolated from any user or project configuration.
type Runner struct {
	Binary   string
	CacheDir string        // Tripcoil's cache; the database lives in CacheDir/grype-db
	Timeout  time.Duration // per invocation; default 15 minutes
	Environ  []string      // the parent environment, usually os.Environ()
}

// Scan catalogs a source, such as "dir:/srv/shop", "file:/path" or "docker:sha256:…", and
// matches it: it writes Grype's JSON report to raw and the SBOM, as CycloneDX JSON, to sbom, and
// parses the report. When Grype fails, it leaves both files empty.
func (r *Runner) Scan(ctx context.Context, source, raw, sbom string) (*Report, error) {
	if err := r.run(ctx, []string{source, "-o", "json=" + raw, "-o", "cyclonedx-json=" + sbom}, io.Discard); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Match matches an SBOM against the database, writes Grype's JSON report to raw and parses it.
func (r *Runner) Match(ctx context.Context, sbom, raw string) (*Report, error) {
	if err := r.run(ctx, []string{"sbom:" + sbom, "-o", "json=" + raw}, io.Discard); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// dbUpdateTimeout bounds a database update: about 3 GB, at the idle IO class.
const dbUpdateTimeout = time.Hour

// UpdateDB downloads a newer vulnerability database when there is one.
func (r *Runner) UpdateDB(ctx context.Context) error {
	return r.runFor(ctx, []string{"db", "update"}, io.Discard, max(r.Timeout, dbUpdateTimeout))
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
	return r.runFor(ctx, args, stdout, r.Timeout)
}

// runFor runs Grype with the private configuration, writing its stdout to stdout, for at most
// timeout (15 minutes when it is 0). Grype works in a fresh directory below the cache, also for
// its temporary files: an image's layers are unpacked there, on the cache's disk rather than in a
// /tmp that may be held in memory.
func (r *Runner) runFor(ctx context.Context, args []string, stdout io.Writer, timeout time.Duration) error {
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
		for _, prefix := range []string{"dir:", "file:", "sbom:"} {
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
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, errGrypeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = work
	cmd.Env = isolatedEnv(environ, work)
	var stderr tailBuffer
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 10 * time.Second
	err = cmd.Run()
	if err == nil {
		return nil
	}
	switch {
	case context.Cause(ctx) == errGrypeTimeout:
		return fmt.Errorf("Grype timed out after %s", timeout)
	case ctx.Err() != nil:
		return ctx.Err()
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("Grype failed: %s", msg)
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
