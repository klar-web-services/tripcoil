package audit

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/osrel"
)

// tree lists the regular files below dir.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	slices.Sort(out)
	return out
}

func TestStagePackageDBDebian(t *testing.T) {
	root := files(t, map[string]string{
		"etc/os-release": "ID=debian\n", "etc/debian_version": "12.15\n",
		"var/lib/dpkg/status": "Package: libc6\n", "var/lib/dpkg/status.d/base-files": "Package: base-files\n",
		"var/lib/dpkg/info/libc6.list": "/lib/x86_64-linux-gnu/libc.so.6\n", "etc/shadow": "root:x:",
	})
	dst := t.TempDir()
	key, err := stagePackageDB(root, osrel.Debian, dst)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := tree(t, dst), []string{"etc/debian_version", "etc/os-release", "var/lib/dpkg/status", "var/lib/dpkg/status.d/base-files"}; !slices.Equal(got, want) {
		t.Fatalf("staged %v, want %v", got, want)
	}
	if !strings.HasPrefix(key, "packages-") {
		t.Fatalf("key %q", key)
	}
	// The key follows the database.
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte("Package: libc6\nVersion: 2\n"), 0o644)
	if again, _ := stagePackageDB(root, osrel.Debian, t.TempDir()); again == key {
		t.Fatal("a changed database keeps its key")
	}
}

func TestStagePackageDBRPMOnce(t *testing.T) {
	// Fedora and SUSE: /var/lib/rpm is a link to /usr/lib/sysimage/rpm. Two copies of the database
	// would double every package.
	root := files(t, map[string]string{"usr/lib/os-release": "ID=fedora\n", "usr/lib/sysimage/rpm/rpmdb.sqlite": "db"})
	os.MkdirAll(filepath.Join(root, "var/lib"), 0o755)
	os.Symlink("../../usr/lib/sysimage/rpm", filepath.Join(root, "var/lib/rpm"))
	syscall.Mkfifo(filepath.Join(root, "usr/lib/sysimage/rpm/fifo"), 0o600)
	dst := t.TempDir()
	if _, err := stagePackageDB(root, osrel.Fedora, dst); err != nil {
		t.Fatal(err)
	}
	if got, want := tree(t, dst), []string{"etc/os-release", "var/lib/rpm/rpmdb.sqlite"}; !slices.Equal(got, want) {
		t.Fatalf("staged %v, want %v", got, want)
	}
	// Without the link, the database is staged from where it is, as /var/lib/rpm.
	os.Remove(filepath.Join(root, "var/lib/rpm"))
	dst = t.TempDir()
	if _, err := stagePackageDB(root, osrel.Fedora, dst); err != nil {
		t.Fatal(err)
	}
	if got, want := tree(t, dst), []string{"etc/os-release", "var/lib/rpm/rpmdb.sqlite"}; !slices.Equal(got, want) {
		t.Fatalf("staged %v, want %v", got, want)
	}
}

func TestStagePackageDBFailures(t *testing.T) {
	if _, err := stagePackageDB(files(t, map[string]string{"etc/os-release": "ID=alpine\n"}), osrel.Alpine, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "no package database") {
		t.Fatalf("no database: %v", err)
	}
	// Without os-release Grype would match nothing, and say nothing.
	if _, err := stagePackageDB(files(t, map[string]string{"lib/apk/db/installed": "P:musl\n"}), osrel.Alpine, t.TempDir()); err == nil {
		t.Fatal("staged without os-release")
	}
	if _, err := stagePackageDB(t.TempDir(), osrel.Unknown, t.TempDir()); err == nil {
		t.Fatal("staged an unknown distribution")
	}
}
