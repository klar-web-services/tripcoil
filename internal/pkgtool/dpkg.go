package pkgtool

import (
	"context"
	"fmt"
	"strings"
)

const dpkgFormat = `${db:Status-Abbrev}\t${binary:Package}\t${Package}\t${Architecture}\t${Version}\n`

type dpkg struct{ run Runner }

func (dpkg) Type() string { return "deb" }

func (d dpkg) Check(ctx context.Context) error {
	res, err := d.run(ctx, "dpkg-query", "-W", "-f", dpkgFormat, "dpkg")
	if err != nil {
		return fmt.Errorf("cannot run dpkg-query: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("dpkg-query cannot read the package database (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

func (d dpkg) Owners(ctx context.Context, paths []string) (map[string]Package, error) {
	owners := map[string][]string{}
	divertedBy := map[string]string{}
	for _, chunk := range chunks(paths, 200) {
		res, err := d.run(ctx, "dpkg-query", append([]string{"-S"}, chunk...)...)
		if err != nil {
			return nil, fmt.Errorf("cannot run dpkg-query: %w", err)
		}
		if res.ExitCode != 0 && res.ExitCode != 1 {
			return nil, fmt.Errorf("dpkg-query -S failed (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
		}
		want := make(map[string]bool, len(chunk))
		for _, p := range chunk {
			want[p] = true
		}
		// A path's diversion lines come directly before its owner line.
		var divFrom, divBy string
		for _, line := range lines(res.Stdout) {
			if from, ok := strings.CutPrefix(line, "local diversion from: "); ok {
				divFrom, divBy = from, ""
				continue
			}
			if rest, ok := strings.CutPrefix(line, "diversion by "); ok {
				if by, from, ok := strings.Cut(rest, " from: "); ok {
					divFrom, divBy = from, by
				}
				continue
			}
			if strings.HasPrefix(line, "local diversion ") {
				continue
			}
			i := strings.Index(line, ": /")
			if i < 0 {
				continue
			}
			path := line[i+2:]
			from, by := divFrom, divBy
			divFrom, divBy = "", ""
			if !want[path] {
				continue
			}
			names := strings.Split(line[:i], ",")
			for j := range names {
				names[j] = strings.TrimSpace(names[j])
			}
			owners[path] = names
			if from == path {
				divertedBy[path] = by
			}
		}
	}
	out := map[string]Package{}
	if len(owners) == 0 {
		return out, nil
	}
	pkgs, err := d.query(ctx, uniqueSorted(owners))
	if err != nil {
		return nil, err
	}
	for path, names := range owners {
		if by, ok := divertedBy[path]; ok {
			var kept []string
			for _, n := range names {
				// A diversion names the package without the architecture that may qualify an owner.
				if by != "" && (n == by || strings.HasPrefix(n, by+":")) {
					kept = append(kept, n)
				}
			}
			names = kept
		}
		for _, name := range names {
			if p, ok := pkgs[name]; ok {
				out[path] = p
				break
			}
		}
	}
	return out, nil
}

func (d dpkg) query(ctx context.Context, names []string) (map[string]Package, error) {
	entries, err := d.list(ctx, names...)
	if err != nil {
		return nil, err
	}
	out := map[string]Package{}
	for _, e := range entries {
		out[e.binary] = e.pkg
	}
	return out, nil
}

type dpkgEntry struct {
	binary string
	pkg    Package
}

func (d dpkg) list(ctx context.Context, patterns ...string) ([]dpkgEntry, error) {
	res, err := d.run(ctx, "dpkg-query", append([]string{"-W", "-f", dpkgFormat}, patterns...)...)
	if err != nil {
		return nil, fmt.Errorf("cannot run dpkg-query: %w", err)
	}
	if res.ExitCode != 0 && res.ExitCode != 1 {
		return nil, fmt.Errorf("dpkg-query -W failed (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}
	var out []dpkgEntry
	for _, line := range lines(res.Stdout) {
		f := strings.Split(line, "\t")
		if len(f) != 5 || len(f[0]) < 2 || !strings.ContainsRune("iWtUF", rune(f[0][1])) {
			continue
		}
		out = append(out, dpkgEntry{binary: f[1], pkg: Package{Name: f[2], Arch: f[3], Version: f[4], Type: "deb"}})
	}
	return out, nil
}

func (d dpkg) Installed(ctx context.Context, pattern string) ([]Package, error) {
	entries, err := d.list(ctx, pattern)
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.pkg)
	}
	return out, nil
}

func (d dpkg) Compare(ctx context.Context, a, b string) (int, error) {
	if err := checkVersions(a, b); err != nil {
		return 0, err
	}
	for _, c := range []struct {
		op     string
		result int
	}{{"lt", -1}, {"eq", 0}} {
		res, err := d.run(ctx, "dpkg", "--compare-versions", a, c.op, b)
		if err != nil {
			return 0, fmt.Errorf("cannot run dpkg: %w", err)
		}
		switch res.ExitCode {
		case 0:
			return c.result, nil
		case 1:
			continue
		default:
			return 0, fmt.Errorf("dpkg --compare-versions failed (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
		}
	}
	return 1, nil
}
