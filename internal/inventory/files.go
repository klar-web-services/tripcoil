package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/procfs"
)

// maxRunningFileSize is the most read of one running file. The largest real libraries are about
// 1.5 GB, but a user can run or map a sparse file of any size.
const maxRunningFileSize = 4 << 30

var runningFileCap int64 = maxRunningFileSize // lowered by tests

// maxRunReadBytes is the most read from running files in one run: the per-file cap still allows
// one sparse file per library and per hard link to it.
const maxRunReadBytes = 64 << 30

var runReadCap int64 = maxRunReadBytes // lowered by tests

var errReadBudget = errors.New("the run's read budget was spent")

// cacheSpace returns the available and total bytes of the file system that holds dir.
var cacheSpace = func(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}

// A copy leaves the cache file system a tenth free, but at most 4 GiB, so copies still work on a
// big, fairly full disk.
const (
	cacheFloorPercent = 10
	maxCacheFloor     = 4 << 30
)

var errCacheFull = errors.New("the cache file system has too little free space for a copy")

func errTooLarge() error { return fmt.Errorf("it is larger than %d bytes", runningFileCap) }

var soPattern = regexp.MustCompile(`\.so($|\.)`)

// isSharedLibrary reports whether a mapped file is a shared library (libssl.so.3,
// ld-linux-x86-64.so.2, _ssl.cpython-312-x86_64-linux-gnu.so), not a locale archive or data file
// such as /etc/ld.so.cache, which ldconfig replaces on every upgrade.
func isSharedLibrary(path string) bool {
	b := filepath.Base(path)
	return soPattern.MatchString(b) && !strings.HasSuffix(b, ".cache")
}

// within reports whether path lies below dir.
func within(path, dir string) bool { return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") }

// runningFile is a running file opened through /proc.
type runningFile struct {
	io.ReadCloser
	size    int64 // -1 when unknown
	id      procfs.FileID
	idKnown bool
	left    *int64 // what is left of the run's read budget
}

// openRunning opens a running file, refusing one larger than runningFileCap. Reading it takes
// from left.
func openRunning(open func() (io.ReadCloser, error), left *int64) (runningFile, error) {
	r, err := open()
	if err != nil {
		return runningFile{}, err
	}
	f := runningFile{ReadCloser: r, size: -1, left: left}
	if s, ok := r.(interface{ Stat() (fs.FileInfo, error) }); ok {
		fi, err := s.Stat()
		if err != nil {
			r.Close()
			return runningFile{}, err
		}
		f.size = fi.Size()
		f.id, f.idKnown = procfs.IDOf(fi)
	}
	if f.size > runningFileCap {
		r.Close()
		return runningFile{}, errTooLarge()
	}
	return f, nil
}

// readRunning copies a running file to w until ctx is cancelled. It refuses a file larger than
// what is left of the read budget and fails with over past limit, or past the budget, because the
// file can grow while it is read.
func readRunning(ctx context.Context, w io.Writer, f runningFile, limit int64, over error) error {
	if f.size > *f.left {
		return errReadBudget
	}
	if *f.left < limit {
		limit, over = *f.left, errReadBudget
	}
	n, err := io.Copy(w, io.LimitReader(ctxReader{ctx, f}, limit+1))
	*f.left -= min(n, *f.left)
	if err != nil {
		return err
	}
	if n > limit {
		return over
	}
	return nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// hashRunning hashes a running file.
func hashRunning(ctx context.Context, f runningFile) (string, error) {
	h := sha256.New()
	if err := readRunning(ctx, h, f, runningFileCap, errTooLarge()); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyToCache stores a running file as cacheDir/replaced/<sha256> and returns its hash and path.
// The Audit scans this copy, because the file on disk is a newer one.
func copyToCache(ctx context.Context, f runningFile, cacheDir string) (string, string, error) {
	dir := filepath.Join(cacheDir, "replaced")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	free, total, err := cacheSpace(dir)
	if err != nil {
		return "", "", err
	}
	floor := min(total/100*cacheFloorPercent, maxCacheFloor)
	if free <= floor {
		return "", "", errCacheFull
	}
	limit, over := runningFileCap, errTooLarge()
	if room := free - floor; room < uint64(limit) {
		limit, over = int64(room), errCacheFull
	}
	if f.size > limit {
		return "", "", over
	}
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name()) // nothing left to remove after the rename
	h := sha256.New()
	if err := readRunning(ctx, io.MultiWriter(tmp, h), f, limit, over); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(dir, sha)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", "", err
	}
	return sha, final, nil
}

// pruneCache removes the copies of earlier runs before a run copies anything: they would pile up
// and count against the free space a copy must leave. The run lock keeps other runs away.
func pruneCache(cacheDir string) {
	dir := filepath.Join(cacheDir, "replaced")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		os.Remove(filepath.Join(dir, e.Name()))
	}
}
