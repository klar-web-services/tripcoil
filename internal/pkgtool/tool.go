// Package pkgtool asks the distribution's package manager which installed package owns a file,
// lists installed packages and compares versions.
package pkgtool

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Package is an installed OS package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`         // the package manager's format, without the epoch
	Epoch   string `json:"epoch,omitempty"` // rpm only, when not 0
	Arch    string `json:"arch,omitempty"`
	Type    string `json:"type"` // deb, rpm, apk or alpm, as Grype names them
}

// Tool is one distribution's package manager.
type Tool interface {
	// Type is deb, rpm, apk or alpm.
	Type() string
	// Check fails when the package manager cannot be used (missing, or no readable database).
	Check(ctx context.Context) error
	// Owners maps each path that an installed package owns to that package; unowned paths are absent.
	Owners(ctx context.Context, paths []string) (map[string]Package, error)
	// Installed lists installed packages matching pattern: a glob for dpkg, an exact name for rpm.
	// apk and pacman keep one version per package and return nil.
	Installed(ctx context.Context, pattern string) ([]Package, error)
	// Compare returns -1, 0 or 1 as version a is lower than, equal to or higher than b.
	Compare(ctx context.Context, a, b string) (int, error)
}

// New returns the tool for a package type, or nil for an unknown type.
func New(packageType string, run Runner) Tool {
	switch packageType {
	case "deb":
		return dpkg{run}
	case "rpm":
		return rpm{run}
	case "apk":
		return apk{run}
	case "alpm":
		return pacman{run: run, realpath: filepath.EvalSymlinks}
	}
	return nil
}

// versionPattern keeps a version string from carrying anything into a command line or a Lua
// expression.
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9._+~^:-]+$`)

func checkVersions(vs ...string) error {
	for _, v := range vs {
		if !versionPattern.MatchString(v) {
			return fmt.Errorf("unexpected characters in version %q", v)
		}
	}
	return nil
}

func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func firstLine(b []byte) string {
	if ls := lines(b); len(ls) > 0 {
		return ls[0]
	}
	return ""
}

// onlyUnowned reports whether a failed ownership query's stderr is explained by unowned paths: at
// least one line matches unowned and every other line matches harmless (which may be nil).
// Otherwise it also returns the first unexplained line.
func onlyUnowned(stderr []byte, unowned, harmless *regexp.Regexp) (bool, string) {
	explained := false
	for _, l := range lines(stderr) {
		switch {
		case unowned.MatchString(l):
			explained = true
		case harmless != nil && harmless.MatchString(l):
		default:
			return false, l
		}
	}
	return explained, ""
}

func chunks(paths []string, n int) [][]string {
	var out [][]string
	for len(paths) > n {
		out = append(out, paths[:n])
		paths = paths[n:]
	}
	if len(paths) > 0 {
		out = append(out, paths)
	}
	return out
}

func uniqueSorted(m map[string][]string) []string {
	set := map[string]bool{}
	for _, vs := range m {
		for _, v := range vs {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
