package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/procfs"
)

func sumOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCopyVerified(t *testing.T) {
	src := filepath.Join(t.TempDir(), "api")
	write(t, src, "go binary v1")
	dir := filepath.Join(t.TempDir(), "scan", sumOf("go binary v1"))
	dst := filepath.Join(dir, "api")
	if err := copyVerified(context.Background(), budget(), src, openPath(src), sumOf("go binary v1"), dst); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dst); string(data) != "go binary v1" {
		t.Fatalf("copy %s: %q", dst, data)
	}
	if err := copyVerified(context.Background(), budget(), src, openPath(src), sumOf("go binary v0"), filepath.Join(dir, "old")); !errors.Is(err, errFileChanged) {
		t.Fatalf("a changed file: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left behind: %v", entries)
	}
}

// Root reads files that unprivileged users control. None of these may block or run forever: a
// FIFO, a device, a link to one, a kernel file that blocks when read (/proc/kmsg, trace_pipe), a
// directory.
func TestFileReadsNeverHang(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	zero := filepath.Join(dir, "zero")
	os.Symlink("/dev/zero", zero)
	kernel := filepath.Join(dir, "kernel")
	os.Symlink("/proc/self/status", kernel)
	for _, path := range []string{fifo, "/dev/zero", zero, kernel, dir} {
		done := make(chan error, 3)
		go func() {
			done <- copyVerified(context.Background(), budget(), path, openPath(path), sumOf(""), filepath.Join(dir, "scan", "copy"))
			_, err := hashFile(context.Background(), budget(), path)
			done <- err
			_, err = readSmall(budget(), path, 1<<20)
			done <- err
		}()
		for range 3 {
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("%s was read", path)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("reading %s hangs", path)
			}
		}
	}
	if _, err := readSmall(budget(), kernel, 1<<20); !errors.Is(err, procfs.ErrPseudoFile) {
		t.Errorf("a kernel file: %v", err)
	}
}

func TestCopyVerifiedLimits(t *testing.T) {
	src := filepath.Join(t.TempDir(), "big")
	write(t, src, string(make([]byte, 100)))
	old := scanFileCap
	scanFileCap = 50
	defer func() { scanFileCap = old }()
	if err := copyVerified(context.Background(), budget(), src, openPath(src), sumOf(""), filepath.Join(t.TempDir(), "big")); err == nil || !strings.Contains(err.Error(), src) {
		t.Fatalf("copied a file above the cap: %v", err)
	}
	if _, err := hashFile(context.Background(), budget(), src); err == nil || !strings.Contains(err.Error(), src) {
		t.Fatalf("hashed a file above the cap: %v", err)
	}
	scanFileCap = old
	oldSpace := cacheSpace
	defer func() { cacheSpace = oldSpace }()
	cacheSpace = func(string) (uint64, uint64, error) { return 1000 + 50, 10000, nil } // floor 1000
	if err := copyVerified(context.Background(), budget(), src, openPath(src), sumOf(string(make([]byte, 100))), filepath.Join(t.TempDir(), "big")); !errors.Is(err, errCacheFull) {
		t.Fatalf("copy into a full cache: %v", err)
	}
	// The floor is a tenth of the file system, but at most 4 GiB.
	cacheSpace = func(string) (uint64, uint64, error) { return maxCacheFloor + 100, 1 << 50, nil }
	if err := copyVerified(context.Background(), budget(), src, openPath(src), sumOf(string(make([]byte, 100))), filepath.Join(t.TempDir(), "big")); err != nil {
		t.Fatalf("copy above a 4 GiB floor: %v", err)
	}
	cacheSpace = func(string) (uint64, uint64, error) { return maxCacheFloor + 99, 1 << 50, nil }
	if err := copyVerified(context.Background(), budget(), src, openPath(src), sumOf(string(make([]byte, 100))), filepath.Join(t.TempDir(), "big")); !errors.Is(err, errCacheFull) {
		t.Fatalf("copy into a 4 GiB floor: %v", err)
	}
	if _, err := readSmall(budget(), src, 99); err == nil {
		t.Fatal("read a file above the limit")
	}
}

// A file that shrinks after its size was read changed: what is left of it is never hashed or
// read as the file.
func TestFileShrinksWhileRead(t *testing.T) {
	src := filepath.Join(t.TempDir(), "package-lock.json")
	real := openFile
	defer func() { openFile = real }()
	openFile = func(name string, open func() (*os.File, error)) (*os.File, int64, error) {
		f, size, err := real(name, open)
		os.Truncate(src, 4)
		return f, size, err
	}
	write(t, src, "0123456789")
	if sum, err := hashFile(context.Background(), budget(), src); !errors.Is(err, errFileChanged) {
		t.Errorf("hashed %q: %v", sum, err)
	}
	write(t, src, "0123456789")
	if data, err := readSmall(budget(), src, 1<<20); !errors.Is(err, errFileChanged) {
		t.Errorf("read %q: %v", data, err)
	}
}

func TestHashFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "app.jar")
	write(t, src, "jar")
	if got, err := hashFile(context.Background(), budget(), src); err != nil || got != sumOf("jar") {
		t.Fatalf("%s %v", got, err)
	}
}

// files writes a tree of files below a new directory and returns it.
func files(t *testing.T, tree map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range tree {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// budget is a run's whole read budget.
func budget() *readBudget { return &readBudget{left: maxRunReadBytes} }
