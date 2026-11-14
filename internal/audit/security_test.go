package audit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A user can swap a FIFO in for a directory of an app directory, over and over, while the tree is
// walked. A FIFO opened for reading waits for a writer forever, which nothing can cancel, and the
// run would hold its lock forever. Every walk must return.
func TestTreeWalkSurvivesASwappedFIFO(t *testing.T) {
	renameat2 := map[string]uintptr{"amd64": 316, "arm64": 276}[runtime.GOARCH]
	if renameat2 == 0 {
		t.Skip("no renameat2 system call number for " + runtime.GOARCH)
	}
	const renameExchange = 2
	cwd := -100 // AT_FDCWD
	dir := files(t, map[string]string{"package-lock.json": `{"lockfileVersion":3}`, "sub/a": "", "sub/b": ""})
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub, _ := syscall.BytePtrFromString(filepath.Join(dir, "sub"))
	fifo, _ := syscall.BytePtrFromString(filepath.Join(dir, "fifo"))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				syscall.Syscall6(renameat2, uintptr(cwd), uintptr(unsafe.Pointer(sub)), uintptr(cwd), uintptr(unsafe.Pointer(fifo)), renameExchange, 0)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2000 {
			fingerprintPath(context.Background(), dir)
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		for _, name := range []string{"sub", "fifo"} { // a writer releases the walk
			if f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				defer f.Close()
			}
		}
		t.Fatal("the walk hangs on a FIFO swapped in for a directory")
	}
}

// The lockfiles are read in the directory the walk reads, never through a link: a link could lead
// anywhere, such as onto a mount that hangs.
func TestAppDirKeyNeverFollowsALockfileLink(t *testing.T) {
	outside := files(t, map[string]string{"package-lock.json": `{"lockfileVersion":3}`})
	dir := files(t, map[string]string{"package.json": `{}`})
	if err := os.Symlink(filepath.Join(outside, "package-lock.json"), filepath.Join(dir, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	if k, _, err := appDirKey(context.Background(), dir, "2026-11-14", noMounts); k != "" || err != nil {
		t.Fatalf("a lockfile link: %q %v", k, err)
	}
}

// The production Scanner stops Grype at the floor that copies leave the cache file system.
func TestGrypeStopsAtTheCacheFloor(t *testing.T) {
	old := cacheSpace
	defer func() { cacheSpace = old }()
	r := NewGrype(t.TempDir()).(*grypeScanner).runner
	if r.HasRoom == nil {
		t.Fatal("Grype runs without a free-space check")
	}
	for free, room := range map[uint64]bool{1001: true, 1000: false, 0: false} {
		cacheSpace = func(string) (uint64, uint64, error) { return free, 10000, nil } // floor 1000
		if got := r.HasRoom(t.TempDir()); got != room {
			t.Errorf("%d bytes free of 10000: room %v, want %v", free, got, room)
		}
	}
}
