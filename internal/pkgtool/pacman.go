package pkgtool

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	pacmanOwned   = regexp.MustCompile(`^(/.+) is owned by (\S+) (\S+)$`)
	pacmanUnowned = regexp.MustCompile(`^error: (No package owns /.*|failed to read file '/.*': No such file or directory)$`)
	pacmanWarning = regexp.MustCompile(`^warning: `)
)

type pacman struct {
	run Runner
	// realpath resolves symlinks: pacman reports the path with its directory resolved, not the one
	// it was asked about. It does not resolve the last component, and neither may we.
	realpath func(string) (string, error)
}

func (pacman) Type() string { return "alpm" }

func (p pacman) Check(ctx context.Context) error {
	res, err := p.run(ctx, "pacman", "-Q", "pacman")
	if err != nil {
		return fmt.Errorf("cannot run pacman: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("pacman cannot read the package database (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

func (p pacman) Owners(ctx context.Context, paths []string) (map[string]Package, error) {
	reported := map[string]Package{}
	for _, chunk := range chunks(paths, 200) {
		res, err := p.run(ctx, "pacman", append([]string{"-Qo"}, chunk...)...)
		if err != nil {
			return nil, fmt.Errorf("cannot run pacman: %w", err)
		}
		if res.ExitCode != 0 {
			if ok, line := onlyUnowned(res.Stderr, pacmanUnowned, pacmanWarning); !ok {
				return nil, fmt.Errorf("pacman -Qo failed (exit %d): %s", res.ExitCode, line)
			}
		}
		for _, line := range lines(res.Stdout) {
			if m := pacmanOwned.FindStringSubmatch(line); m != nil {
				reported[m[1]] = Package{Name: m[2], Version: m[3], Type: "alpm"}
			}
		}
	}
	out := map[string]Package{}
	for _, path := range paths {
		if pkg, ok := reported[path]; ok {
			out[path] = pkg
			continue
		}
		if dir, err := p.realpath(filepath.Dir(path)); err == nil {
			if pkg, ok := reported[filepath.Join(dir, filepath.Base(path))]; ok {
				out[path] = pkg
			}
		}
	}
	return out, nil
}

func (pacman) Installed(context.Context, string) ([]Package, error) { return nil, nil }

func (p pacman) Compare(ctx context.Context, a, b string) (int, error) {
	if err := checkVersions(a, b); err != nil {
		return 0, err
	}
	res, err := p.run(ctx, "vercmp", a, b)
	if err != nil {
		return 0, fmt.Errorf("cannot run vercmp: %w", err)
	}
	c, err := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if err != nil {
		return 0, fmt.Errorf("unexpected vercmp output %q", strings.TrimSpace(string(res.Stdout)))
	}
	return max(-1, min(1, c)), nil
}
