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

const maxRunningFileSize = 4 << 30

var runningFileCap int64 = maxRunningFileSize

const maxRunReadBytes = 64 << 30

var runReadCap int64 = maxRunReadBytes

var errReadBudget = errors.New("the run's read budget was spent")

var cacheSpace = func(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Frsize), st.Blocks * uint64(st.Frsize), nil
}

const (
	cacheFloorPercent = 10
	maxCacheFloor     = 4 << 30
)

var errCacheFull = errors.New("the cache file system has too little free space for a copy")

func errTooLarge() error { return fmt.Errorf("it is larger than %d bytes", runningFileCap) }

var soPattern = regexp.MustCompile(`\.so($|\.)`)

func isSharedLibrary(path string) bool {
	b := filepath.Base(path)
	return soPattern.MatchString(b) && !strings.HasSuffix(b, ".cache")
}

func within(path, dir string) bool { return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") }

type runningFile struct {
	io.ReadCloser
	size    int64
	id      procfs.FileID
	idKnown bool
	left    *int64
}

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

func hashRunning(ctx context.Context, f runningFile) (string, error) {
	h := sha256.New()
	if err := readRunning(ctx, h, f, runningFileCap, errTooLarge()); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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
	defer os.Remove(tmp.Name())
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

func pruneCache(cacheDir string) {
	dir := filepath.Join(cacheDir, "replaced")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		os.Remove(filepath.Join(dir, e.Name()))
	}
}
