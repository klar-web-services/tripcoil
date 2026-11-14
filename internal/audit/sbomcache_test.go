package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
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
	if key, _, err := appDirKey(dir, "2026-11-14"); key != "" || err != nil {
		t.Fatalf("a manifest without a lockfile has a key: %q %v", key, err)
	}
	write(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3}`)
	k1, files, err := appDirKey(dir, "2026-11-14")
	if k1 == "" || err != nil || len(files) != 2 || files[0] != "/package-lock.json" || files[1] != "/package.json" {
		t.Fatalf("%q %v %v", k1, files, err)
	}
	write(t, filepath.Join(dir, "package.json"), `{"name":"shop","version":"2"}`)
	if k2, _, _ := appDirKey(dir, "2026-11-14"); k2 == k1 {
		t.Fatal("a changed manifest keeps the key")
	}
	other := t.TempDir()
	write(t, filepath.Join(other, "package.json"), `{"name":"shop","version":"2"}`)
	write(t, filepath.Join(other, "package-lock.json"), `{"lockfileVersion":3}`)
	k2, _, _ := appDirKey(dir, "2026-11-14")
	if k3, _, _ := appDirKey(other, "2026-11-14"); k3 == k2 {
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
		if key, _, err := appDirKey(d, "2026-11-14"); key != "" || err != nil {
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
		k, _, err := appDirKey(dir, "2026-11-14")
		if k == "" || err != nil {
			t.Fatalf("%q %v", k, err)
		}
		return k
	}
	k1 := key()
	if k, _, _ := appDirKey(dir, "2026-11-15"); k == k1 {
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
	if k, _, err := appDirKey(dir, "2026-11-14"); k == "" || err != nil {
		t.Fatalf("at the cap: %q %v", k, err)
	}
	maxTreeEntries = 4
	if k, _, err := appDirKey(dir, "2026-11-14"); k != "" || err != nil {
		t.Fatalf("above the cap: %q %v", k, err)
	}
	maxTreeEntries = old
	// A walk that fails gives no key, and no error.
	os.Chmod(filepath.Join(dir, "a"), 0)
	defer os.Chmod(filepath.Join(dir, "a"), 0o755)
	if k, _, err := appDirKey(dir, "2026-11-14"); (k != "" && os.Geteuid() != 0) || err != nil {
		t.Fatalf("an unreadable directory: %q %v", k, err)
	}
	// Nor has a directory with a lockfile too large to hash.
	big := files(t, map[string]string{"package-lock.json": ""})
	os.Truncate(filepath.Join(big, "package-lock.json"), maxLockfile+1)
	if k, _, err := appDirKey(big, "2026-11-14"); k != "" || err != nil {
		t.Fatalf("a lockfile above maxLockfile: %q %v", k, err)
	}
	// Nor has a link to a directory, which the walk would not follow.
	link := filepath.Join(t.TempDir(), "app")
	os.Symlink(files(t, map[string]string{"package-lock.json": lock}), link)
	if k, _, err := appDirKey(link, "2026-11-14"); k != "" || err != nil {
		t.Fatalf("a link: %q %v", k, err)
	}
}
