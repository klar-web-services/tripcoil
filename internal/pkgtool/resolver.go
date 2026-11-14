package pkgtool

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Alias is a top-level directory that is a symlink into /usr on a merged-/usr system, such as
// /lib -> usr/lib. /proc shows the canonical path; some package databases (dpkg) hold the other.
type Alias struct {
	Canonical string // "/usr/lib/"
	Alt       string // "/lib/"
}

// DetectAliases finds the merged-/usr symlinks below root, in a fixed order.
func DetectAliases(root string) []Alias {
	var out []Alias
	for _, name := range []string{"bin", "lib", "lib32", "lib64", "libx32", "sbin"} {
		target, err := os.Readlink(filepath.Join(root, name))
		if err != nil {
			continue
		}
		if target == "usr/"+name || target == "/usr/"+name {
			out = append(out, Alias{Canonical: "/usr/" + name + "/", Alt: "/" + name + "/"})
		}
	}
	return out
}

// Resolver asks a Tool for owners and, for paths it does not know, asks again under their aliases.
type Resolver struct {
	Tool    Tool
	Aliases []Alias
}

// Owners maps each owned path (as given) to its package. A path with a newline could forge lines
// of the tool's output, so it is never asked about and counts as unowned.
func (r *Resolver) Owners(ctx context.Context, paths []string) (map[string]Package, error) {
	var ask []string
	for _, p := range paths {
		if !strings.Contains(p, "\n") {
			ask = append(ask, p)
		}
	}
	found, err := r.Tool.Owners(ctx, ask)
	if err != nil {
		return nil, err
	}
	var alts []string
	altOf := map[string]string{}
	for _, p := range ask {
		if _, ok := found[p]; ok {
			continue
		}
		for _, a := range r.Aliases {
			if rest, ok := strings.CutPrefix(p, a.Canonical); ok {
				alt := a.Alt + rest
				if _, seen := altOf[alt]; !seen {
					altOf[alt] = p
					alts = append(alts, alt)
				}
			}
		}
	}
	if len(alts) == 0 {
		return found, nil
	}
	more, err := r.Tool.Owners(ctx, alts)
	if err != nil {
		return nil, err
	}
	for alt, pkg := range more {
		found[altOf[alt]] = pkg
	}
	return found, nil
}

// Owned reports whether an installed package owns path (used for directories).
func (r *Resolver) Owned(ctx context.Context, path string) bool {
	m, err := r.Owners(ctx, []string{path})
	return err == nil && len(m) > 0
}
