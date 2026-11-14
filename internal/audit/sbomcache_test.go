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
	if key, _, err := appDirKey(dir); key != "" || err != nil {
		t.Fatalf("a manifest without a lockfile has a key: %q %v", key, err)
	}
	write(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3}`)
	k1, files, err := appDirKey(dir)
	if k1 == "" || err != nil || len(files) != 2 || files[0] != "/package-lock.json" || files[1] != "/package.json" {
		t.Fatalf("%q %v %v", k1, files, err)
	}
	write(t, filepath.Join(dir, "package.json"), `{"name":"shop","version":"2"}`)
	if k2, _, _ := appDirKey(dir); k2 == k1 {
		t.Fatal("a changed manifest keeps the key")
	}
	other := t.TempDir()
	write(t, filepath.Join(other, "package.json"), `{"name":"shop","version":"2"}`)
	write(t, filepath.Join(other, "package-lock.json"), `{"lockfileVersion":3}`)
	k2, _, _ := appDirKey(dir)
	if k3, _, _ := appDirKey(other); k3 == k2 {
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
		if key, _, err := appDirKey(d); key != "" || err != nil {
			t.Fatalf("an odd lockfile: %q %v", key, err)
		}
	}
}
