package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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
	dir := filepath.Join(t.TempDir(), "scan")
	got, err := copyVerified(context.Background(), openPath(src), sumOf("go binary v1"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(got); got != filepath.Join(dir, sumOf("go binary v1")) || string(data) != "go binary v1" {
		t.Fatalf("copy %s: %q", got, data)
	}
	if _, err := copyVerified(context.Background(), openPath(src), sumOf("go binary v0"), dir); !errors.Is(err, errFileChanged) {
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
			_, err := copyVerified(context.Background(), openPath(path), sumOf(""), filepath.Join(dir, "scan"))
			done <- err
			_, err = hashFile(context.Background(), path)
			done <- err
			_, err = readSmall(path, 1<<20)
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
	if _, err := readSmall(kernel, 1<<20); !errors.Is(err, procfs.ErrPseudoFile) {
		t.Errorf("a kernel file: %v", err)
	}
}

func TestCopyVerifiedLimits(t *testing.T) {
	src := filepath.Join(t.TempDir(), "big")
	write(t, src, string(make([]byte, 100)))
	old := scanFileCap
	scanFileCap = 50
	defer func() { scanFileCap = old }()
	if _, err := copyVerified(context.Background(), openPath(src), sumOf(""), t.TempDir()); err == nil {
		t.Fatal("copied a file above the cap")
	}
	if _, err := hashFile(context.Background(), src); err == nil {
		t.Fatal("hashed a file above the cap")
	}
	scanFileCap = old
	oldSpace := cacheSpace
	defer func() { cacheSpace = oldSpace }()
	cacheSpace = func(string) (uint64, uint64, error) { return 1000 + 50, 10000, nil } // floor 1000
	if _, err := copyVerified(context.Background(), openPath(src), sumOf(string(make([]byte, 100))), t.TempDir()); !errors.Is(err, errCacheFull) {
		t.Fatalf("copy into a full cache: %v", err)
	}
	if _, err := readSmall(src, 99); err == nil {
		t.Fatal("read a file above the limit")
	}
}

func TestHashFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "app.jar")
	write(t, src, "jar")
	if got, err := hashFile(context.Background(), src); err != nil || got != sumOf("jar") {
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
