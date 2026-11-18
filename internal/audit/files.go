package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/procfs"
)

const maxScanFileSize = 4 << 30

var scanFileCap int64 = maxScanFileSize

const maxRunReadBytes = 64 << 30

var runReadCap int64 = maxRunReadBytes

var errReadBudget = errors.New("the audit's read budget of 64 GiB for this run is spent")

type readBudget struct{ left int64 }

func (b *readBudget) take(n int64) error {
	if n > b.left {
		return errReadBudget
	}
	b.left -= n
	return nil
}

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

var (
	errCacheFull     = errors.New("the cache file system has too little free space for a copy")
	errRunFolderFull = errors.New("the run folder's file system has too little free space for Grype's output")
	errFileChanged   = errors.New("the file changed since the inventory")
)

func errTooLarge(name string) error {
	return fmt.Errorf("%s is larger than %d bytes", name, scanFileCap)
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

// openFile opens a regular file of a real file system, never a FIFO, a device or a kernel file
// such as /proc/kmsg, and returns it with its size. Reading it at most to that size cannot hang.
// name names the file in errors.
var openFile = func(name string, open func() (*os.File, error)) (*os.File, int64, error) {
	f, err := open()
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if fi.Size() > scanFileCap {
		f.Close()
		return nil, 0, errTooLarge(name)
	}
	return f, fi.Size(), nil
}

func openPath(path string) func() (*os.File, error) {
	return func() (*os.File, error) { return procfs.OpenRegular(path) }
}

func hashFile(ctx context.Context, reads *readBudget, path string) (string, error) {
	f, size, err := openFile(path, openPath(path))
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := reads.take(size); err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(ctxReader{ctx, f}, size))
	switch {
	case err != nil:
		return "", err
	case n != size:
		return "", errFileChanged
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readSmall(reads *readBudget, path string, limit int64) ([]byte, error) {
	f, size, err := openFile(path, openPath(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	if err := reads.take(size); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, size))
	if err == nil && int64(len(data)) != size {
		err = errFileChanged
	}
	return data, err
}

func hasRoom(dir string, size int64) error { return aboveFloor(dir, size, errCacheFull) }

func aboveFloor(dir string, size int64, full error) error {
	free, total, err := cacheSpace(dir)
	if err != nil {
		return err
	}
	floor := min(total/100*cacheFloorPercent, maxCacheFloor)
	if free <= floor || uint64(size) > free-floor {
		return full
	}
	return nil
}

func copyVerified(ctx context.Context, reads *readBudget, name string, open func() (*os.File, error), sha, dst string) error {
	f, size, err := openFile(name, open)
	if err != nil {
		return err
	}
	defer f.Close()
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := hasRoom(dir, size); err != nil {
		return err
	}
	if err := reads.take(size); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(ctxReader{ctx, f}, size))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return err
	case hex.EncodeToString(h.Sum(nil)) != sha:
		return errFileChanged
	}
	return os.Rename(tmp.Name(), dst)
}
