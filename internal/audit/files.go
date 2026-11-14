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

// maxScanFileSize is the largest file the Audit hashes or copies, as for running files.
const maxScanFileSize = 4 << 30

var scanFileCap int64 = maxScanFileSize // lowered by tests

// cacheSpace returns the available and total bytes of the file system that holds dir.
var cacheSpace = func(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}

// A copy leaves the cache file system a tenth free, but at most 4 GiB, as the Inventory's do.
const (
	cacheFloorPercent = 10
	maxCacheFloor     = 4 << 30
)

var (
	errCacheFull   = errors.New("the cache file system has too little free space for a copy")
	errFileChanged = errors.New("the file changed since the inventory")
)

func errTooLarge() error { return fmt.Errorf("it is larger than %d bytes", scanFileCap) }

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
func openFile(open func() (*os.File, error)) (*os.File, int64, error) {
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
		return nil, 0, errTooLarge()
	}
	return f, fi.Size(), nil
}

func openPath(path string) func() (*os.File, error) {
	return func() (*os.File, error) { return procfs.OpenRegular(path) }
}

// hashFile returns the SHA-256 of the regular file at path.
func hashFile(ctx context.Context, path string) (string, error) {
	f, size, err := openFile(openPath(path))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(ctxReader{ctx, f}, size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readSmall reads a small regular file, such as a lockfile, of at most max bytes.
func readSmall(path string, max int64) ([]byte, error) {
	f, size, err := openFile(openPath(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return io.ReadAll(io.LimitReader(f, size))
}

// copyVerified copies the file that open opens to dst when its content has that SHA-256. Grype
// then reads exactly the file the Inventory identified: never a FIFO, a device or a kernel file,
// nor a file that changed since.
func copyVerified(ctx context.Context, open func() (*os.File, error), sha, dst string) error {
	f, size, err := openFile(open)
	if err != nil {
		return err
	}
	defer f.Close()
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	free, total, err := cacheSpace(dir)
	if err != nil {
		return err
	}
	floor := min(total/100*cacheFloorPercent, maxCacheFloor)
	if free <= floor || uint64(size) > free-floor {
		return errCacheFull
	}
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing left to remove after the rename
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
