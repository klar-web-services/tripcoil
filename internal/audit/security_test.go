package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
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

// Grype reads a copy only as a file and an app directory only as a directory, never as an image:
// its file: source takes any file that holds a docker save archive for an image, and dir: any
// directory that holds an OCI layout, and both unpack the image's layers. Only the package
// database's staging root, which Tripcoil writes, and images are scanned otherwise.
func TestUserFilesAreScannedAsPlainFilesAndDirectories(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if len(g.catalogs) != 8 {
		t.Fatalf("cataloged %q", g.catalogs)
	}
	for _, source := range g.catalogs {
		scheme, rest, _ := strings.Cut(source, ":")
		switch {
		case scheme == "local-file" && strings.HasPrefix(rest, filepath.Join(cache, "scan")+"/"):
		case scheme == "local-directory" && strings.HasPrefix(rest, root+"/"):
		case source == "dir:"+filepath.Join(cache, "staging"), source == "docker:sha256:1111":
		default:
			t.Errorf("Grype scanned %s", source)
		}
	}
}

// A binary's copy never has a name that makes Syft unpack it, as an archive or a Java archive: a
// user can map a small archive that unpacks to gigabytes under a library's name, such as
// libx.so.1.tar.gz. Real binaries keep their names, which Syft's classifiers go by.
func TestCopyNamesAreNeverArchives(t *testing.T) {
	for name, want := range map[string]string{
		"libx.so.1.tar.gz": "libx.so.1_tar.gz",
		"libx.so.1.tgz":    "libx.so.1_tgz",
		"x.tar.gz.so":      "x_tar.gz.so",
		"x.zip.bin":        "x_zip.bin",
		"lib.7Z.so":        "lib_7Z.so",
		"x.so.RAR":         "x.so_RAR",
		"x.so.txz":         "x.so_txz",
		"x.so.tbz2":        "x.so_tbz2",
		"x.so.tzst":        "x.so_tzst",
		"x.so.tlz":         "x.so_tlz",
		"libx.so.1.jar":    "libx.so.1_jar",
		"libx.so.lpkg":     "libx.so_lpkg",
		"x.tar.tgz":        "x_tar_tgz",
		// What Syft reads as the file it is keeps its name.
		"x.tgz.bin": "x.tgz.bin", "x.so.gz": "x.so.gz", "libjar.so": "libjar.so", "libtar.so.0": "libtar.so.0",
		"libzip.so.5": "libzip.so.5", "libpython3.12.so.1.0": "libpython3.12.so.1.0", "python3.12": "python3.12",
		"node": "node", "ld-linux-x86-64.so.2": "ld-linux-x86-64.so.2", "_ssl.cpython-312-x86_64-linux-gnu.so": "_ssl.cpython-312-x86_64-linux-gnu.so",
	} {
		if got := copyName(name); got != want {
			t.Errorf("copy of %s named %s, want %s", name, got, want)
		}
	}
	// The copy Grype scans and the cache key both take the name; a jar keeps its own.
	root, cache, inv := host(t)
	write(t, filepath.Join(root, "home/u/libx.so.1.tar.gz"), "go binary v1")
	o := &inv.Origins[2] // apiO
	o.Paths = []string{"/home/u/libx.so.1.tar.gz"}
	g := hostScanner(root, cache)
	copied := "local-file:" + filepath.Join(cache, "scan", sumOf("go binary v1"), "libx.so.1_tar.gz")
	g.sboms[copied] = g.sboms["local-file:"+filepath.Join(cache, "scan", sumOf("go binary v1"), "api")]
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if !slices.Contains(g.catalogs, copied) {
		t.Fatalf("cataloged %q", g.catalogs)
	}
	au := &auditor{d: Deps{Root: root, Now: time.Now}}
	if k, _, _ := au.cacheKey(context.Background(), *o); k != keyOf("binary", o.SHA256, "libx.so.1_tar.gz") {
		t.Errorf("cache key %s", k)
	}
	if k, _, _ := au.cacheKey(context.Background(), inv.Origins[7]); k != keyOf("jar", "", "app.jar") {
		t.Errorf("jar cache key %s", k)
	}
}

// An SBOM larger than the cap fails its origin before it is read: a lockfile of 50,000 packages
// gives a 72 MB SBOM, which takes 600 MB to read.
func TestSBOMsAboveTheCapFailTheOrigin(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	shop := "local-directory:" + filepath.Join(root, "srv/shop")
	for i := range 200 {
		v := fmt.Sprintf("1.0.%d", i)
		g.sboms[shop] = append(g.sboms[shop], grype.Component{Name: "left-pad", Version: v, PURL: "pkg:npm/left-pad@" + v})
	}
	old := maxSBOMSize
	maxSBOMSize = 8192
	defer func() { maxSBOMSize = old }()
	runDir := t.TempDir()
	a := Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
	for _, o := range a.Origins {
		switch {
		case o.ID == "appdir:/srv/shop" && (o.Status != ScanFailed || o.Error != "Grype's SBOM is larger than 8192 bytes"):
			t.Errorf("shop: %+v", o)
		case o.ID != "appdir:/srv/shop" && o.Status == ScanFailed:
			t.Errorf("%s failed: %s", o.ID, o.Error)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(runDir, "raw", rawName("appdir:/srv/shop", "*"))); len(left) > 0 {
		t.Errorf("left in the run folder: %q", left)
	}
}

// The SBOMs written to the run folder leave its file system the floor, and so do cache entries
// the cache's: Grype's outputs depend on files that users control.
func TestRawFilesAndCacheEntriesKeepTheFloor(t *testing.T) {
	old := cacheSpace
	defer func() { cacheSpace = old }()
	root, cache, inv := host(t)
	runDir := t.TempDir()
	cacheSpace = func(dir string) (uint64, uint64, error) {
		if strings.HasPrefix(dir, runDir) {
			return 1000, 10000, nil // at the floor
		}
		return 1 << 40, 1 << 41, nil
	}
	a := Run(context.Background(), deps(root, cache, runDir, hostScanner(root, cache), fakeKernel{}), inv)
	for _, o := range a.Origins {
		if o.Status != Unresolved && o.Error != errRunFolderFull.Error() {
			t.Errorf("a full run folder: %s %s %q", o.ID, o.Status, o.Error)
		}
	}
	root, cache, inv = host(t)
	cacheSpace = func(dir string) (uint64, uint64, error) {
		if strings.HasPrefix(dir, filepath.Join(cache, "sbom")) {
			return 1000, 10000, nil
		}
		return 1 << 40, 1 << 41, nil
	}
	a = Run(context.Background(), deps(root, cache, t.TempDir(), hostScanner(root, cache), fakeKernel{}), inv)
	if a.Status != Complete {
		t.Errorf("a full cache only costs the cache: %s %v", a.Status, a.Errors)
	}
	if cached, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "*")); len(cached) > 0 {
		t.Errorf("cached below the floor: %q", cached)
	}
}

// A user who runs a renamed copy of root's unpackaged binary shares its origin, and the user's path
// may sort first: the copy Grype scans, and the cache key, take the name of root's file, which
// Syft's classifiers go by.
func TestCopyIsNamedAfterRootsFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("every file is root's")
	}
	var system string
	for _, p := range []string{"/usr/bin/true", "/usr/bin/env", "/usr/bin/ls"} {
		if rootOwned(p) {
			system = p
			break
		}
	}
	if system == "" {
		t.Skip("no file of root's to copy")
	}
	data, err := os.ReadFile(system)
	if err != nil {
		t.Skip(err)
	}
	mine := filepath.Join(t.TempDir(), "x")
	write(t, mine, string(data))
	o := inventory.Origin{ID: inventory.BinaryOriginID(sumOf(string(data))), Kind: inventory.OriginBinary, SHA256: sumOf(string(data)), Paths: []string{mine, system}}
	cache := t.TempDir()
	g := hostScanner("/", cache)
	copied := "local-file:" + filepath.Join(cache, "scan", o.SHA256, filepath.Base(system))
	g.sboms[copied] = []grype.Component{{Name: "coreutils", Version: "9.5", PURL: "pkg:generic/coreutils@9.5"}}
	a := Run(context.Background(), deps("/", cache, t.TempDir(), g, fakeKernel{}), &inventory.Inventory{Origins: []inventory.Origin{o}})
	if len(a.Origins) != 1 || a.Origins[0].Status != Scanned || !slices.Contains(g.catalogs, copied) {
		t.Fatalf("cataloged %q: %+v", g.catalogs, a.Origins)
	}
	au := &auditor{d: Deps{Root: "/", Now: time.Now}}
	if k, _, _ := au.cacheKey(context.Background(), o); k != keyOf("binary", o.SHA256, filepath.Base(system)) {
		t.Errorf("cache key %s", k)
	}
	// Without a file of root's, the first path names the copy.
	o.Paths = []string{mine}
	if k, _, _ := au.cacheKey(context.Background(), o); k != keyOf("binary", o.SHA256, "x") {
		t.Errorf("cache key %s", k)
	}
}
