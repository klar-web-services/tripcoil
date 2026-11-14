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
//
// Users control app directories and can swap any part of them while the key is computed, so the
// directory is opened once, never through a link, and everything is read relative to it: the
// lockfiles, and the tree. Neither has a key: a link to a directory, a directory with a mount
// below it (see mountBelow, which is given the opened directory's path).
func appDirKey(ctx context.Context, dir, day string, mountBelow func(string) bool) (string, []string, error) {
	d, err := openDir(dir)
	if err != nil {
		return "", nil, nil
	}
	defer d.Close()
	real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(d.Fd())))
	if err != nil || mountBelow(real) {
		return "", nil, nil
	}
	parts := []string{dir, day}
	var files []string
	locked := false
	for _, name := range append(append([]string{}, appLockfiles...), appManifests...) {
		data, err := readSmallAt(d, name, maxLockfile)
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
	tree, err := treeFingerprint(ctx, d)
	if err != nil {
		return "", nil, nil
	}
	return keyOf("appdir", append(parts, tree)...), files, nil
}

// oPath is O_PATH, which package syscall defines only on some architectures.
const oPath = 0x200000

// openDir opens a directory, but not a link to one. O_DIRECTORY fails at once on anything else,
// such as a FIFO that a user swapped in, whose open would wait for a writer forever.
func openDir(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openDirAt opens the directory name in d as openDir does, and only when it is still the entry
// that st describes: otherwise the tree changed since.
func openDirAt(d *os.File, name string, st *syscall.Stat_t) (*os.File, error) {
	path := filepath.Join(d.Name(), name)
	fd, err := syscall.Openat(int(d.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	var now syscall.Stat_t
	if err := syscall.Fstat(fd, &now); err != nil {
		f.Close()
		return nil, &fs.PathError{Op: "fstat", Path: path, Err: err}
	}
	if now.Dev != st.Dev || now.Ino != st.Ino {
		f.Close()
		return nil, fmt.Errorf("%s changed while the tree was read", path)
	}
	return f, nil
}

// lstatAt is lstat(2) of name in d. Package syscall has no fstatat(2) on amd64, and an O_PATH open
// only names the file: it never opens a FIFO or a device, nor follows a link.
func lstatAt(d *os.File, name string) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	fd, err := syscall.Openat(int(d.Fd()), name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return st, &fs.PathError{Op: "lstat", Path: filepath.Join(d.Name(), name), Err: err}
	}
	defer syscall.Close(fd)
	if err := syscall.Fstat(fd, &st); err != nil {
		return st, &fs.PathError{Op: "lstat", Path: filepath.Join(d.Name(), name), Err: err}
	}
	return st, nil
}

// readSmallAt reads the file name in d as readSmall reads a path, but never through a link.
func readSmallAt(d *os.File, name string, limit int64) ([]byte, error) {
	fd, err := syscall.Openat(int(d.Fd()), name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: filepath.Join(d.Name(), name), Err: err}
	}
	defer syscall.Close(fd)
	return readSmall("/proc/self/fd/"+strconv.Itoa(fd), limit)
}

// mountInfo lists the mount points of Tripcoil's mount namespace.
var mountInfo = "/proc/self/mountinfo" // replaced by tests

// mountBelow reports whether a mount point lies strictly below dir, which then has no key: the tree
// walk must never lstat a mount point, which may hang, such as an NFS mount whose server is gone.
// The mount points are read once per Audit; the walk's device check covers a mount made since.
// dir is the path of the opened app directory, without links, as mountinfo spells mount points
// (see appDirKey). When mountinfo cannot be read, dir counts as having a mount below it.
func (au *auditor) mountBelow(dir string) bool {
	if !au.mountsRead {
		au.mounts, au.mountsErr = readMountPoints(mountInfo)
		au.mountsRead = true
	}
	if au.mountsErr != nil {
		return true
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for _, m := range au.mounts {
		if m != dir && strings.HasPrefix(m, prefix) {
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

// treeFingerprint hashes the path, type, size, inode and ctime of every entry below the directory
// d, without following symbolic links: Grype does not follow them out of the directory either.
// Unlike mtime, ctime changes on every write or rename, and users cannot set it: npm writes package
// files with a fixed mtime. A directory of more than maxTreeEntries entries has no fingerprint.
// Directories are read in chunks, so the walk stops at the cap without reading a huge one whole.
// Nor has a directory with an entry on another file system: the walk does not go into a mount,
// which may hang, such as an NFS mount whose server is gone. Every directory is opened relative to
// its parent's descriptor, and only when it is still the directory the walk saw.
func treeFingerprint(ctx context.Context, d *os.File) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(d.Fd()), &st); err != nil {
		return "", &fs.PathError{Op: "fstat", Path: d.Name(), Err: err}
	}
	w := treeWalk{ctx: ctx, dev: st.Dev, h: sha256.New(), n: 1}
	if err := w.walk(d, ".", &st); err != nil {
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

// walk hashes the directory d, whose entry st is, then the entries below it, in name order.
func (w *treeWalk) walk(d *os.File, rel string, st *syscall.Stat_t) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	w.hash(rel, st)
	names, err := w.readDir(d)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		// As deep as a path can name: the descriptors of a directory's parents stay open.
		path := filepath.Join(d.Name(), name)
		if len(path) >= syscall.PathMax {
			return fmt.Errorf("%s is too long a path", path)
		}
		st, err := lstatAt(d, name)
		switch {
		case err != nil:
			return err
		case st.Dev != w.dev:
			return fmt.Errorf("%s is on another file system", path)
		case st.Mode&syscall.S_IFMT != syscall.S_IFDIR:
			w.hash(filepath.Join(rel, name), &st)
			continue
		}
		sub, err := openDirAt(d, name, &st)
		if err != nil {
			return err
		}
		err = w.walk(sub, filepath.Join(rel, name), &st)
		sub.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// hash adds an entry to the fingerprint.
func (w *treeWalk) hash(rel string, st *syscall.Stat_t) {
	fmt.Fprintf(w.h, "%s\x00%d\x00%d\x00%d\x00%d\x00", rel, modeType(st.Mode), st.Size, st.Ino, st.Ctim.Nano())
}

// modeType is the type of a file mode, as fs.FileMode.Type gives it for os.Lstat.
func modeType(mode uint32) fs.FileMode {
	switch mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
		return fs.ModeDevice
	case syscall.S_IFCHR:
		return fs.ModeDevice | fs.ModeCharDevice
	case syscall.S_IFDIR:
		return fs.ModeDir
	case syscall.S_IFIFO:
		return fs.ModeNamedPipe
	case syscall.S_IFLNK:
		return fs.ModeSymlink
	case syscall.S_IFSOCK:
		return fs.ModeSocket
	}
	return 0
}

// readDir reads a directory's names, sorted, and fails as soon as the walk has read more than
// maxTreeEntries.
func (w *treeWalk) readDir(d *os.File) ([]string, error) {
	var out []string
	for {
		if err := w.ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := d.Readdirnames(4096)
		if w.n += len(chunk); w.n > maxTreeEntries {
			return nil, fmt.Errorf("the tree has more than %d entries", maxTreeEntries)
		}
		out = append(out, chunk...)
		switch {
		case errors.Is(err, io.EOF):
			slices.Sort(out)
			return out, nil
		case err != nil:
			return nil, err
		}
	}
}
