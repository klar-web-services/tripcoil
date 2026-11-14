package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
)

// sbomMaxAge is how long a cached SBOM is kept after its last use (spec section 6.2).
const sbomMaxAge = 7 * 24 * time.Hour

// sbomCache keeps each origin's SBOM under a content key, as dir/<key>.cdx.json, where dir is
// cache/sbom/<Grype version>: a newer Grype catalogs anew, with its own catalogers and fixes.
// Cataloging is the slow part of a scan, so later runs only match the cached SBOM.
type sbomCache struct {
	root string // cache/sbom
	now  func() time.Time
}

func (c sbomCache) dir() string { return filepath.Join(c.root, grype.Version) }

func (c sbomCache) path(key string) string { return filepath.Join(c.dir(), key+".cdx.json") }

// get returns the cached SBOM of key and marks it used.
func (c sbomCache) get(key string) (string, bool) {
	p := c.path(key)
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	_ = os.Chtimes(p, c.now(), c.now())
	return p, true
}

// put stores an SBOM in the cache as key.
func (c sbomCache) put(key string, data []byte) error {
	if err := os.MkdirAll(c.dir(), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.dir(), ".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing left to remove after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path(key))
}

// remove drops an entry that cannot be read or matched, so it is built again.
func (c sbomCache) remove(key string) { os.Remove(c.path(key)) }

// prune removes SBOMs that no run used for sbomMaxAge, and those of other Grype versions.
func (c sbomCache) prune() {
	versions, _ := os.ReadDir(c.root)
	for _, v := range versions {
		if v.Name() != grype.Version {
			os.RemoveAll(filepath.Join(c.root, v.Name()))
		}
	}
	entries, _ := os.ReadDir(c.dir())
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && c.now().Sub(fi.ModTime()) > sbomMaxAge {
			os.Remove(filepath.Join(c.dir(), e.Name()))
		}
	}
}

// keyOf hashes parts into a cache key with a kind prefix, such as "image-<sha256>".
func keyOf(kind string, parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return kind + "-" + hex.EncodeToString(h[:])
}

// appLockfiles are the lockfiles that pin an app directory's packages; appManifests are hashed
// with them. Both are names Grype reads (the Inventory's app directory markers).
var (
	appLockfiles = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
		"poetry.lock", "Pipfile.lock", "uv.lock", "Gemfile.lock", "composer.lock"}
	appManifests = []string{"package.json", "pyproject.toml", "requirements.txt", "pom.xml", "build.gradle", "build.gradle.kts"}
)

// maxLockfile is the largest lockfile or manifest hashed for a key; a package-lock.json of a big
// app is a few MB.
const maxLockfile = 64 << 20

// appDirKey is the cache key of an app directory: its path and the hashes of the lockfiles and
// manifests in it, which it returns too, as Grype names locations ("/package-lock.json").
// Without a lockfile there is no key, and the directory is cataloged every run; so too when one
// of the files is not a regular file of a real file system (Grype skips those) or is too large.
func appDirKey(dir string) (string, []string, error) {
	parts := []string{dir}
	var files []string
	locked := false
	for _, name := range append(append([]string{}, appLockfiles...), appManifests...) {
		data, err := readSmall(filepath.Join(dir, name), maxLockfile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return "", nil, nil
		}
		h := sha256.Sum256(data)
		parts = append(parts, name, hex.EncodeToString(h[:]))
		files = append(files, "/"+name)
		locked = locked || slices.Contains(appLockfiles, name)
	}
	if !locked {
		return "", nil, nil
	}
	return keyOf("appdir", parts...), files, nil
}
