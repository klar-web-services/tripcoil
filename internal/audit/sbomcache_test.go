package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

func TestSBOMCache(t *testing.T) {
	now := time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "sbom")
	c := sbomCache{root: root, now: func() time.Time { return now }}
	if _, ok := c.get("binary-ab"); ok {
		t.Fatal("hit in an empty cache")
	}
	if err := c.put("binary-ab", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	p, ok := c.get("binary-ab")
	if !ok || p != filepath.Join(root, grype.Version, "binary-ab.cdx.json") {
		t.Fatalf("%s %v: entries are kept per Grype version", p, ok)
	}
	old := c.path("binary-old")
	write(t, old, "{}")
	os.Chtimes(old, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour))
	used := c.path("binary-used")
	write(t, used, "{}")
	os.Chtimes(used, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour))
	if _, ok := c.get("binary-used"); !ok { // using an entry keeps it
		t.Fatal("miss")
	}
	older := filepath.Join(root, "0.120.0", "binary-ab.cdx.json") // an earlier Grype's catalog
	write(t, older, "{}")
	c.prune()
	for path, want := range map[string]bool{p: true, used: true, old: false, older: false} {
		if _, err := os.Stat(path); (err == nil) != want {
			t.Errorf("%s kept=%v, want %v", path, err == nil, want)
		}
	}
	c.remove("binary-ab")
	if _, ok := c.get("binary-ab"); ok {
		t.Fatal("a removed entry is still there")
	}
}

func TestAppDirKey(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{"name":"shop"}`)
	if key, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); key != "" || err != nil {
		t.Fatalf("a manifest without a lockfile has a key: %q %v", key, err)
	}
	write(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3}`)
	k1, files, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts)
	if k1 == "" || err != nil || len(files) != 2 || files[0] != "/package-lock.json" || files[1] != "/package.json" {
		t.Fatalf("%q %v %v", k1, files, err)
	}
	write(t, filepath.Join(dir, "package.json"), `{"name":"shop","version":"2"}`)
	if k2, _, _ := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); k2 == k1 {
		t.Fatal("a changed manifest keeps the key")
	}
	other := t.TempDir()
	write(t, filepath.Join(other, "package.json"), `{"name":"shop","version":"2"}`)
	write(t, filepath.Join(other, "package-lock.json"), `{"lockfileVersion":3}`)
	k2, _, _ := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts)
	if k3, _, _ := appDirKey(context.Background(), budget(), other, "2026-11-14", noMounts); k3 == k2 {
		t.Fatal("two directories with the same files share a key")
	}
	// A user's FIFO or link to /dev/zero as a lockfile: no key (Grype skips them), and no hang.
	for _, odd := range []func(string) error{
		func(p string) error { return syscall.Mkfifo(p, 0o600) },
		func(p string) error { return os.Symlink("/dev/zero", p) },
	} {
		d := t.TempDir()
		write(t, filepath.Join(d, "package.json"), `{}`)
		if err := odd(filepath.Join(d, "package-lock.json")); err != nil {
			t.Fatal(err)
		}
		if key, _, err := appDirKey(context.Background(), budget(), d, "2026-11-14", noMounts); key != "" || err != nil {
			t.Fatalf("an odd lockfile: %q %v", key, err)
		}
	}
}

// An app directory's key changes with any change below it, also with one that keeps the size and
// the mtime, and each day.
func TestAppDirKeyCoversTheTree(t *testing.T) {
	dir := files(t, map[string]string{"package.json": `{}`, "package-lock.json": `{"lockfileVersion":3}`, "worker/index.js": "v1"})
	key := func() string {
		t.Helper()
		k, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts)
		if k == "" || err != nil {
			t.Fatalf("%q %v", k, err)
		}
		return k
	}
	k1 := key()
	if k, _, _ := appDirKey(context.Background(), budget(), dir, "2026-11-15", noMounts); k == k1 {
		t.Fatal("the next day keeps the key")
	}
	write(t, filepath.Join(dir, "worker/package-lock.json"), `{"lockfileVersion":3}`)
	k2 := key()
	if k2 == k1 {
		t.Fatal("a nested lockfile keeps the key")
	}
	// As npm does: the same size, and the mtime set back.
	js := filepath.Join(dir, "worker/index.js")
	fi, _ := os.Stat(js)
	before := fi.Sys().(*syscall.Stat_t).Ctim
	for fi.Sys().(*syscall.Stat_t).Ctim == before { // a coarse file system clock
		write(t, js, "v2")
		os.Chtimes(js, fi.ModTime(), fi.ModTime())
		fi, _ = os.Stat(js)
		time.Sleep(time.Millisecond)
	}
	if key() == k2 {
		t.Fatal("a file rewritten with the same size and mtime keeps the key")
	}
}

func TestAppDirKeyWithoutKey(t *testing.T) {
	lock := `{"lockfileVersion":3}`
	dir := files(t, map[string]string{"package-lock.json": lock, "a/b": "", "a/c": ""})
	old := maxTreeEntries
	defer func() { maxTreeEntries = old }()
	maxTreeEntries = 5 // ., package-lock.json, a, a/b, a/c
	if k, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); k == "" || err != nil {
		t.Fatalf("at the cap: %q %v", k, err)
	}
	maxTreeEntries = 4
	if k, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); k != "" || err != nil {
		t.Fatalf("above the cap: %q %v", k, err)
	}
	maxTreeEntries = old
	// A walk that fails gives no key, and no error.
	os.Chmod(filepath.Join(dir, "a"), 0)
	defer os.Chmod(filepath.Join(dir, "a"), 0o755)
	if k, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); (k != "" && os.Geteuid() != 0) || err != nil {
		t.Fatalf("an unreadable directory: %q %v", k, err)
	}
	// Nor has a directory with a lockfile too large to hash.
	big := files(t, map[string]string{"package-lock.json": ""})
	os.Truncate(filepath.Join(big, "package-lock.json"), maxLockfile+1)
	if k, _, err := appDirKey(context.Background(), budget(), big, "2026-11-14", noMounts); k != "" || err != nil {
		t.Fatalf("a lockfile above maxLockfile: %q %v", k, err)
	}
	// Nor has a link to a directory, which the walk would not follow.
	link := filepath.Join(t.TempDir(), "app")
	os.Symlink(files(t, map[string]string{"package-lock.json": lock}), link)
	if k, _, err := appDirKey(context.Background(), budget(), link, "2026-11-14", noMounts); k != "" || err != nil {
		t.Fatalf("a link: %q %v", k, err)
	}
}

// A directory is read in chunks, and the walk stops at the cap: a huge one is never read whole.
func TestTreeFingerprintStopsAtTheCap(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "a"), 0o755)
	for i := range 30_000 {
		f, err := os.Create(filepath.Join(dir, "a", strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	old := maxTreeEntries
	defer func() { maxTreeEntries = old }()
	maxTreeEntries = 100
	allocs := testing.AllocsPerRun(1, func() {
		if _, err := fingerprintPath(context.Background(), dir); err == nil {
			t.Error("a fingerprint above the cap")
		}
	})
	if allocs > 20_000 {
		t.Fatalf("%.0f allocations: the walk read the directory of 30,000 entries whole", allocs)
	}
}

// A stopped run stops the walk: an app directory then has no key.
func TestTreeFingerprintStopsWithTheRun(t *testing.T) {
	dir := files(t, map[string]string{"package-lock.json": `{"lockfileVersion":3}`, "a/b": ""})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fingerprintPath(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("walk of a stopped run: %v", err)
	}
	if k, _, err := appDirKey(ctx, budget(), dir, "2026-11-14", noMounts); k != "" || err != nil {
		t.Fatalf("key of a stopped run: %q %v", k, err)
	}
}

// The walk does not go into a mount below the app directory, which may hang: the directory then has
// no key. The test mounts a tmpfs in a user and mount namespace of its own.
func TestTreeFingerprintStaysOnOneFileSystem(t *testing.T) {
	if dir := os.Getenv("TRIPCOIL_TEST_MOUNT"); dir != "" {
		if err := syscall.Mount("tripcoil-test", filepath.Join(dir, "data"), "tmpfs", 0, ""); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, "data/x"), "on the mount")
		if _, err := fingerprintPath(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "data is on another file system") {
			t.Fatalf("walk across a mount: %v", err)
		}
		if k, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); k != "" || err != nil {
			t.Fatalf("key across a mount: %q %v", k, err)
		}
		au := &auditor{d: Deps{Root: "/", Now: time.Now}, reads: budget()}
		if k, _, err := au.cacheKey(context.Background(), inventory.Origin{Kind: inventory.OriginAppDir, Path: dir}, ""); !au.mountBelow(dir) || k != "" || err != nil {
			t.Fatalf("mountinfo does not list the mount below %s: %q %v", dir, k, err)
		}
		return
	}
	dir := files(t, map[string]string{"package-lock.json": `{"lockfileVersion":3}`, "data/.keep": ""})
	if k, _, err := appDirKey(context.Background(), budget(), dir, "2026-11-14", noMounts); k == "" || err != nil {
		t.Fatalf("key without a mount: %q %v", k, err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTreeFingerprintStaysOnOneFileSystem$", "-test.v")
	cmd.Env = append(os.Environ(), "TRIPCOIL_TEST_MOUNT="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Skipf("no user namespace: %v", err)
	}
	if err != nil || !strings.Contains(string(out), "--- PASS: TestTreeFingerprintStaysOnOneFileSystem") {
		t.Fatalf("in a mount namespace: %v\n%s", err, out)
	}
}

// A mount point strictly below an app directory, as mountinfo lists it, gives the directory no key
// without a walk, which would lstat the mount: it may hang.
func TestAppDirMountBelow(t *testing.T) {
	lock := `{"lockfileVersion":3}`
	root := files(t, map[string]string{"srv/shop/package-lock.json": lock, "srv/shop/data/x": "", "srv/shopping/package-lock.json": lock,
		"srv/my shop/package-lock.json": lock, "srv/my shop/data/x": "", "srv/app/package-lock.json": lock})
	info := filepath.Join(t.TempDir(), "mountinfo")
	write(t, info, fmt.Sprintf(`22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
36 25 0:40 / %[1]s/srv/shop/data rw,relatime shared:80 - nfs4 server:/export rw
37 25 0:41 / %[1]s/srv/my\040shop/data rw - tmpfs tmpfs rw
38 25 8:17 / %[1]s/srv/app rw - ext4 /dev/sdb1 rw
39 25 0:42 / %[1]s/srv/application/x rw - tmpfs tmpfs rw
`, root))
	old := mountInfo
	defer func() { mountInfo = old }()
	mountInfo = info
	au := &auditor{d: Deps{Root: root, Now: func() time.Time { return now }}, reads: budget()}
	key := func(dir string) string {
		t.Helper()
		k, _, err := au.cacheKey(context.Background(), inventory.Origin{Kind: inventory.OriginAppDir, Path: dir}, "")
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	// The app directory itself may be a mount point; /srv/shop is not below /srv/shopping, nor
	// /srv/app below /srv/application.
	for dir, keyed := range map[string]bool{"/srv/shop": false, "/srv/my shop": false, "/srv/shopping": true, "/srv/app": true} {
		if k := key(dir); (k != "") != keyed {
			t.Errorf("%s: key %q", dir, k)
		}
	}
	write(t, info, "")
	if k := key("/srv/shop"); k != "" {
		t.Errorf("key %q: mountinfo is read once per Audit", k)
	}
	if mounts, err := readMountPoints(info); len(mounts) != 0 || err != nil {
		t.Errorf("an empty mountinfo: %q %v", mounts, err)
	}
	write(t, info, `40 25 0:43 / /a\011b\134c\012d\0407\777 rw - tmpfs tmpfs rw`)
	if mounts, err := readMountPoints(info); !slices.Equal(mounts, []string{"/a\tb\\c\nd 7\\777"}) || err != nil {
		t.Errorf("octal escapes: %q %v", mounts, err)
	}
}

// noMounts is a mount check that finds no mount below any directory.
func noMounts(string) bool { return false }

// fingerprintPath fingerprints the tree below dir, opened as appDirKey opens it.
func fingerprintPath(ctx context.Context, dir string) (string, error) {
	d, err := openDir(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	return treeFingerprint(ctx, d)
}
