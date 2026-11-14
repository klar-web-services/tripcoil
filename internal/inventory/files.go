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

// cacheSpace returns the available and total bytes of the file system that holds dir.
var cacheSpace = func(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}

var errCacheFull = errors.New("copying it would leave less than 10% of the cache file system free")

func errTooLarge() error { return fmt.Errorf("it is larger than %d bytes", runningFileCap) }

var soPattern = regexp.MustCompile(`\.so($|\.)`)

// isSharedLibrary reports whether a mapped file is a shared library (libssl.so.3,
// ld-linux-x86-64.so.2, _ssl.cpython-312-x86_64-linux-gnu.so), not a locale archive or data file.
func isSharedLibrary(path string) bool { return soPattern.MatchString(filepath.Base(path)) }

// within reports whether path lies below dir.
func within(path, dir string) bool { return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") }

// runningFile is a running file opened through /proc.
type runningFile struct {
	io.ReadCloser
	size    int64 // -1 when unknown
	id      procfs.FileID
	idKnown bool
}

// openRunning opens a running file, refusing one larger than runningFileCap.
func openRunning(open func() (io.ReadCloser, error)) (runningFile, error) {
	r, err := open()
	if err != nil {
		return runningFile{}, err
	}
	f := runningFile{ReadCloser: r, size: -1}
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

// readRunning copies a running file to w until ctx is cancelled. It fails past runningFileCap,
// because the file can grow while it is read.
func readRunning(ctx context.Context, w io.Writer, f runningFile) error {
	n, err := io.Copy(w, io.LimitReader(ctxReader{ctx, f}, runningFileCap+1))
	if err != nil {
		return err
	}
	if n > runningFileCap {
		return errTooLarge()
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
	if err := readRunning(ctx, h, f); err != nil {
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
	if size := uint64(max(f.size, 0)); size > free || free-size < total/10 {
		return "", "", errCacheFull
	}
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name()) // nothing left to remove after the rename
	h := sha256.New()
	if err := readRunning(ctx, io.MultiWriter(tmp, h), f); err != nil {
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

// pruneCache removes the copies that keep does not name, which would otherwise pile up. The run
// lock keeps other runs away.
func pruneCache(cacheDir string, keep map[string]bool) {
	dir := filepath.Join(cacheDir, "replaced")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); !keep[p] {
			os.Remove(p)
		}
	}
}
