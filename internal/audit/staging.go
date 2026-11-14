package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

// packageDBFiles are the package database files of each package type, as globs below the host
// root, in alternatives: the first alternative with a file wins. Grype reads every installed
// package from them (spec section 6.2). Fedora's and SUSE's /var/lib/rpm is a link to
// /usr/lib/sysimage/rpm, so their database is staged once, as /var/lib/rpm.
var packageDBFiles = map[string][][]string{
	"deb":  {{"var/lib/dpkg/status", "var/lib/dpkg/status.d/*"}},
	"rpm":  {{"var/lib/rpm/*"}, {"usr/lib/sysimage/rpm/*"}},
	"apk":  {{"lib/apk/db/installed"}},
	"alpm": {{"var/lib/pacman/local/*/desc"}},
}

// releaseFiles are copied too when they exist: Grype reads Debian's point release (12.15) from
// /etc/debian_version.
var releaseFiles = map[string][]string{"deb": {"etc/debian_version"}}

// rpmReaderFile matches the files of an RPM database that readers change and that no reader needs,
// which are neither staged nor keyed: SQLite's shared-memory index, which SQLite rebuilds from the
// write-ahead log, and Berkeley DB's environment regions, which every rpm query rewrites. With
// them, the key of RHEL 8's database changed at every run, and its SBOM was never reused.
var rpmReaderFile = regexp.MustCompile(`/(rpmdb\.sqlite-shm|__db\.[0-9]+)$`)

// stagePackageDB copies os-release and the package database of the host below root into dst, a
// staging root that holds nothing else, and returns the SBOM cache key: the hash of what it
// copied. Only regular files are copied: a package database file that is not one is left out,
// and any other fails the copy. The copies must leave the cache file system its floor, and are
// charged to reads.
func stagePackageDB(reads *readBudget, root string, family osrel.Family, dst string) (string, error) {
	alternatives, ok := packageDBFiles[family.PackageType()]
	if !ok {
		return "", fmt.Errorf("%q has no package database Tripcoil can read", family)
	}
	var files []string
	for _, globs := range alternatives {
		for _, g := range globs {
			matches, err := filepath.Glob(filepath.Join(root, g))
			if err != nil {
				return "", err
			}
			for _, m := range matches {
				if family.PackageType() == "rpm" && rpmReaderFile.MatchString(m) {
					continue
				}
				rel, _ := filepath.Rel(root, m)
				files = append(files, rel)
			}
		}
		if len(files) > 0 {
			break
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no package database was found below %s", root)
	}
	database := map[string]bool{}
	for _, f := range files {
		database[f] = true
	}
	// Without os-release Grype matches nothing and says nothing, so a missing one fails the copy.
	osRelease := "etc/os-release"
	if _, err := os.Stat(filepath.Join(root, osRelease)); errors.Is(err, fs.ErrNotExist) {
		osRelease = "usr/lib/os-release"
	}
	files = append(files, osRelease)
	for _, f := range releaseFiles[family.PackageType()] {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	var staged []string
	var size int64
	for _, rel := range files {
		path := filepath.Join(root, rel)
		f, n, err := openFile(path, openPath(path))
		if errors.Is(err, procfs.ErrNotRegular) && database[rel] {
			continue // such as a directory in /var/lib/rpm
		}
		if err != nil {
			return "", err
		}
		f.Close()
		staged, size = append(staged, rel), size+n
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", err
	}
	if err := hasRoom(dst, size); err != nil {
		return "", err
	}
	if err := reads.take(size); err != nil {
		return "", err
	}
	h := sha256.New()
	for _, rel := range staged {
		target := rel
		switch {
		case rel == "usr/lib/os-release":
			target = "etc/os-release" // Grype looks for /etc/os-release first
		case strings.HasPrefix(rel, "usr/lib/sysimage/rpm/"):
			target = "var/lib/rpm/" + strings.TrimPrefix(rel, "usr/lib/sysimage/rpm/")
		}
		n, err := copyRegular(filepath.Join(root, rel), filepath.Join(dst, target), h)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "\x00%s\x00%d\x00", target, n)
	}
	return "packages-" + hex.EncodeToString(h.Sum(nil)), nil
}

// copyRegular copies the regular file src to dst, also writing its content to h.
func copyRegular(src, dst string, h io.Writer) (int64, error) {
	in, err := procfs.OpenRegular(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, scanFileCap+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > scanFileCap {
		err = errTooLarge(src)
	}
	return n, err
}
