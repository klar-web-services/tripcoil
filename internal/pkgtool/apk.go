package pkgtool

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	apkOwned       = regexp.MustCompile(`^(/.+) is owned by (\S+)$`)
	apkNameVersion = regexp.MustCompile(`^(.+)-([^-]+-r\d+)$`)
	apkUnowned     = regexp.MustCompile(`^ERROR: /.*: Could not find owner package$`)
)

type apk struct{ run Runner }

func (apk) Type() string { return "apk" }

func (a apk) Check(ctx context.Context) error {
	res, err := a.run(ctx, "apk", "info", "-e", "apk-tools")
	if err != nil {
		return fmt.Errorf("cannot run apk: %w", err)
	}
	if res.ExitCode != 0 || strings.TrimSpace(string(res.Stdout)) != "apk-tools" {
		return fmt.Errorf("apk cannot read the package database (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

func (a apk) Owners(ctx context.Context, paths []string) (map[string]Package, error) {
	out := map[string]Package{}
	for _, chunk := range chunks(paths, 200) {
		res, err := a.run(ctx, "apk", append([]string{"info", "--who-owns"}, chunk...)...)
		if err != nil {
			return nil, fmt.Errorf("cannot run apk: %w", err)
		}
		if res.ExitCode != 0 {
			if ok, line := onlyUnowned(res.Stderr, apkUnowned, nil); !ok {
				return nil, fmt.Errorf("apk info --who-owns failed (exit %d): %s", res.ExitCode, line)
			}
		}
		for _, line := range lines(res.Stdout) {
			m := apkOwned.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			nv := apkNameVersion.FindStringSubmatch(m[2])
			if nv == nil {
				continue
			}
			out[m[1]] = Package{Name: nv[1], Version: nv[2], Type: "apk"}
		}
	}
	return out, nil
}

func (apk) Installed(context.Context, string) ([]Package, error) { return nil, nil }

func (a apk) Compare(ctx context.Context, x, y string) (int, error) {
	if err := checkVersions(x, y); err != nil {
		return 0, err
	}
	res, err := a.run(ctx, "apk", "version", "-t", x, y)
	if err != nil {
		return 0, fmt.Errorf("cannot run apk: %w", err)
	}
	switch strings.TrimSpace(string(res.Stdout)) {
	case "<":
		return -1, nil
	case "=":
		return 0, nil
	case ">":
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected apk version -t output %q", strings.TrimSpace(string(res.Stdout)))
}
