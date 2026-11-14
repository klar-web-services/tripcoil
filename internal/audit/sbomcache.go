package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
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

// remove drops an entry that is at fault, so it is built again.
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

// maxTreeEntries is the most entries of an app directory that its key covers.
var maxTreeEntries = 200_000 // lowered by tests

// appDirKey is the cache key of an app directory: its path, the UTC day, the fingerprint of its
// tree (see treeFingerprint) and the hashes of the lockfiles and manifests in it, which it returns
// too, as Grype names locations ("/package-lock.json"). The day bounds how stale a cached SBOM can
// be: every app directory is cataloged at least daily. Without a lockfile there is no key, and the
// directory is cataloged every run; so too when one of the files is not a regular file of a real
// file system (Grype skips those) or is too large, or when the tree cannot be fingerprinted.
func appDirKey(ctx context.Context, dir, day string) (string, []string, error) {
	parts := []string{dir, day}
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
	tree, err := treeFingerprint(ctx, dir)
	if err != nil {
		return "", nil, nil
	}
	return keyOf("appdir", append(parts, tree)...), files, nil
}

// mountInfo lists the mount points of Tripcoil's mount namespace.
var mountInfo = "/proc/self/mountinfo" // replaced by tests

// mountBelow reports whether a mount point lies strictly below dir, which then has no key: the tree
// walk must never lstat a mount point, which may hang, such as an NFS mount whose server is gone.
// The mount points are read once per Audit; the walk's device check covers a mount made since.
// dir is compared with its symbolic links resolved, as mountinfo spells mount points. When either
// cannot be read, dir counts as having a mount below it.
func (au *auditor) mountBelow(dir string) bool {
	if !au.mountsRead {
		au.mounts, au.mountsErr = readMountPoints(mountInfo)
		au.mountsRead = true
	}
	real, err := filepath.EvalSymlinks(dir)
	if au.mountsErr != nil || err != nil {
		return true
	}
	prefix := strings.TrimSuffix(real, "/") + "/"
	for _, m := range au.mounts {
		if m != real && strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

// readMountPoints lists the mount points of a mountinfo file: the fifth field of each line, whose
// space, tab, newline and backslash the kernel writes as octal escapes, such as \040.
func readMountPoints(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mount := f[4]
		var b strings.Builder
		for i := 0; i < len(mount); i++ {
			if mount[i] == '\\' && i+3 < len(mount) {
				if c, err := strconv.ParseUint(mount[i+1:i+4], 8, 8); err == nil {
					b.WriteByte(byte(c))
					i += 3
					continue
				}
			}
			b.WriteByte(mount[i])
		}
		out = append(out, b.String())
	}
	return out, nil
}

// treeFingerprint hashes the path, type, size, inode and ctime of every entry below dir, without
// following symbolic links: Grype does not follow them out of the directory either. Unlike mtime,
// ctime changes on every write or rename, and users cannot set it: npm writes package files with
// a fixed mtime. A directory of more than maxTreeEntries entries has no fingerprint. Directories
// are read in chunks, so the walk stops at the cap without reading a huge one whole. Nor has a
// directory with an entry on another file system: the walk does not go into a mount, which may
// hang, such as an NFS mount whose server is gone.
func treeFingerprint(ctx context.Context, dir string) (string, error) {
	fi, err := os.Lstat(dir)
	switch {
	case err != nil:
		return "", err
	case !fi.IsDir():
		return "", fmt.Errorf("%s is not a directory", dir) // such as a link to one
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s has no inode", dir)
	}
	w := treeWalk{ctx: ctx, dev: st.Dev, h: sha256.New(), n: 1}
	if err := w.walk(dir, ".", fi); err != nil {
		return "", err
	}
	return hex.EncodeToString(w.h.Sum(nil)), nil
}

// treeWalk is one walk of treeFingerprint.
type treeWalk struct {
	ctx context.Context
	dev uint64 // the device of the directory
	h   hash.Hash
	n   int // the entries read so far
}

// walk hashes an entry, then the entries below it, in name order.
func (w *treeWalk) walk(path, rel string, fi fs.FileInfo) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return fmt.Errorf("%s has no inode", path)
	case st.Dev != w.dev:
		return fmt.Errorf("%s is on another file system", path)
	}
	fmt.Fprintf(w.h, "%s\x00%d\x00%d\x00%d\x00%d\x00", rel, fi.Mode().Type(), fi.Size(), st.Ino, st.Ctim.Nano())
	if !fi.IsDir() {
		return nil
	}
	entries, err := w.readDir(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		fi, err := e.Info() // of the entry itself, as lstat
		if err != nil {
			return err
		}
		if err := w.walk(filepath.Join(path, e.Name()), filepath.Join(rel, e.Name()), fi); err != nil {
			return err
		}
	}
	return nil
}

// readDir reads a directory's entries, sorted by name, and fails as soon as the walk has read more
// than maxTreeEntries.
func (w *treeWalk) readDir(path string) ([]fs.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []fs.DirEntry
	for {
		if err := w.ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := f.ReadDir(4096)
		if w.n += len(chunk); w.n > maxTreeEntries {
			return nil, fmt.Errorf("the tree has more than %d entries", maxTreeEntries)
		}
		out = append(out, chunk...)
		switch {
		case errors.Is(err, io.EOF):
			slices.SortFunc(out, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
			return out, nil
		case err != nil:
			return nil, err
		}
	}
}
