package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var soPattern = regexp.MustCompile(`\.so($|\.)`)

// isSharedLibrary reports whether a mapped file is a shared library (libssl.so.3,
// ld-linux-x86-64.so.2, _ssl.cpython-312-x86_64-linux-gnu.so), not a locale archive or data file.
func isSharedLibrary(path string) bool { return soPattern.MatchString(filepath.Base(path)) }

// within reports whether path lies below dir.
func within(path, dir string) bool { return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") }

// hashReader hashes a running file opened through /proc.
func hashReader(open func() (io.ReadCloser, error)) (string, error) {
	r, err := open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyToCache stores a running file (opened through /proc) as cacheDir/replaced/<sha256> and
// returns its hash and path. The Audit scans this copy, because the file on disk is a newer one.
func copyToCache(open func() (io.ReadCloser, error), cacheDir string) (string, string, error) {
	r, err := open()
	if err != nil {
		return "", "", err
	}
	defer r.Close()
	dir := filepath.Join(cacheDir, "replaced")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name()) // nothing left to remove after the rename
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), r); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(dir, sha)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", "", err
	}
	return sha, final, nil
}
