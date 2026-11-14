package pkgtool

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// rpmFormat is passed to rpm --qf; rpm itself expands \t and \n.
const rpmFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n`

type rpm struct{ run Runner }

func (rpm) Type() string { return "rpm" }

func (r rpm) Check(ctx context.Context) error {
	res, err := r.run(ctx, "rpm", "-q", "--qf", rpmFormat, "rpm")
	if err != nil {
		return fmt.Errorf("cannot run rpm: %w", err)
	}
	if res.ExitCode != 0 || len(parseRPM(res.Stdout)) == 0 {
		return fmt.Errorf("rpm cannot read the package database (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

// Owners asks one path per call: with several paths, rpm's output does not say which path a
// line belongs to.
func (r rpm) Owners(ctx context.Context, paths []string) (map[string]Package, error) {
	out := map[string]Package{}
	for _, p := range paths {
		res, err := r.run(ctx, "rpm", "-qf", "--qf", rpmFormat, p)
		if err != nil {
			return nil, fmt.Errorf("cannot run rpm: %w", err)
		}
		if res.ExitCode != 0 {
			if !rpmUnowned(p, res) {
				return nil, fmt.Errorf("rpm -qf %s failed (exit %d): %s", p, res.ExitCode, firstLine(res.Stderr))
			}
			continue
		}
		if pkgs := parseRPM(res.Stdout); len(pkgs) > 0 {
			out[p] = pkgs[0]
		}
	}
	return out, nil
}

// rpmUnowned reports whether a failed rpm -qf said only that p is not owned or does not exist.
func rpmUnowned(p string, res Result) bool {
	missing := false
	for _, l := range lines(res.Stderr) {
		if l != "error: file "+p+": No such file or directory" {
			return false
		}
		missing = true
	}
	stdout := lines(res.Stdout)
	return len(stdout) == 1 && stdout[0] == "file "+p+" is not owned by any package" || len(stdout) == 0 && missing
}

func parseRPM(b []byte) []Package {
	var out []Package
	for _, line := range lines(b) {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			continue
		}
		p := Package{Name: f[0], Version: f[2] + "-" + f[3], Arch: f[4], Type: "rpm"}
		if f[1] != "0" {
			p.Epoch = f[1]
		}
		out = append(out, p)
	}
	return out
}

func (r rpm) Installed(ctx context.Context, name string) ([]Package, error) {
	res, err := r.run(ctx, "rpm", "-q", "--qf", rpmFormat, name)
	if err != nil {
		return nil, fmt.Errorf("cannot run rpm: %w", err)
	}
	if res.ExitCode != 0 {
		if ls := lines(res.Stdout); len(ls) == 1 && ls[0] == "package "+name+" is not installed" && len(lines(res.Stderr)) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("rpm -q %s failed (exit %d): %s", name, res.ExitCode, firstLine(res.Stderr))
	}
	return parseRPM(res.Stdout), nil
}

func (r rpm) Compare(ctx context.Context, a, b string) (int, error) {
	if err := checkVersions(a, b); err != nil {
		return 0, err
	}
	res, err := r.run(ctx, "rpm", "--eval", fmt.Sprintf(`%%{lua: print(rpm.vercmp("%s", "%s"))}`, a, b))
	if err != nil {
		return 0, fmt.Errorf("cannot run rpm: %w", err)
	}
	c, err := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if err != nil {
		return 0, fmt.Errorf("unexpected rpm.vercmp output %q", strings.TrimSpace(string(res.Stdout)))
	}
	return max(-1, min(1, c)), nil
}
