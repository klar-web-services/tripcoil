package pkgtool

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Epoch   string `json:"epoch,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Type    string `json:"type"`
}

type Tool interface {
	Type() string
	Check(ctx context.Context) error
	Owners(ctx context.Context, paths []string) (map[string]Package, error)
	Installed(ctx context.Context, pattern string) ([]Package, error)
	Compare(ctx context.Context, a, b string) (int, error)
}

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
