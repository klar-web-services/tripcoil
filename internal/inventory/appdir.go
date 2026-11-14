package inventory

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var interpreterPattern = regexp.MustCompile(`^(node|nodejs|bun|deno|python[0-9.]*|java|ruby[0-9.]*|php[0-9.]*|php-fpm[0-9.]*)$`)

// isInterpreter reports whether the executable runs code from an app directory.
func isInterpreter(exe string) bool { return interpreterPattern.MatchString(filepath.Base(exe)) }

// appMarkers make a directory an app directory: lockfiles and manifests Grype reads, and venvs.
var appMarkers = []string{
	"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "package.json",
	"pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "pyvenv.cfg",
	"Gemfile.lock", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts",
}

type appDir struct {
	Path string
	Jar  bool // Path is a jar file, cataloged as a file
}

type appDirFinder struct {
	root  string                                      // host root
	owned func(ctx context.Context, path string) bool // whether an installed OS package owns the file
}

// find returns the app directory of an interpreter process.
func (f appDirFinder) find(ctx context.Context, cmdline []string, cwd string) (appDir, bool) {
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return filepath.Clean(p)
		}
		return filepath.Join(cwd, p)
	}
	var starts []string
	for i := 1; i < len(cmdline); i++ {
		a := cmdline[i]
		if a == "-jar" {
			if i+1 < len(cmdline) && f.isFile(abs(cmdline[i+1])) {
				return appDir{Path: f.resolve(abs(cmdline[i+1])), Jar: true}, true
			}
			break
		}
		if a == "-m" {
			break // python -m module: the code is found through the cwd
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if p := abs(a); f.isFile(p) {
			if !strings.HasPrefix(filepath.Base(p), "ProcessContainer") { // PM2's wrapper: the app is in the cwd
				starts = append(starts, filepath.Dir(f.resolve(p)))
			}
			break
		}
	}
	// A runtime's bin/ is a start point only as a venv's: walking up from it would climb into a
	// version manager's checkout (~/.nvm has a package.json) or the home directory.
	if len(cmdline) > 0 && strings.Contains(cmdline[0], "/") && f.isFile(abs(cmdline[0])) {
		venv := filepath.Dir(filepath.Dir(abs(cmdline[0]))) // not resolved: a venv's bin/python links to the system python
		if _, err := os.Stat(filepath.Join(f.root, venv, "pyvenv.cfg")); err == nil {
			starts = append(starts, venv)
		}
	}
	// A removed working directory reads as "<path> (deleted)": its code is no longer on disk, and
	// walking up from it would find a project above it.
	if cwd != "" && !strings.HasSuffix(cwd, " (deleted)") {
		starts = append(starts, cwd)
	}
	for _, s := range starts {
		if dir, ok := f.walk(ctx, s); ok {
			return appDir{Path: dir}, true
		}
	}
	return appDir{}, false
}

func (f appDirFinder) walk(ctx context.Context, start string) (string, bool) {
	start = filepath.Clean(start)
	outer, pkgDir, inside := splitNodeModules(start)
	if !inside {
		return f.walkUp(ctx, start)
	}
	// Only the directory holding node_modules: npm puts node_modules next to the project's manifest,
	// and above it may be a home directory or a version manager's checkout (~/.nvm/versions/...).
	if m := f.marker(outer); outer != "" && m != "" && !f.owned(ctx, outer+"/"+m) {
		return outer, true
	}
	// The directory holding node_modules is not a project: a globally installed npm package (npm -g).
	if pkgDir != "" {
		if m := f.marker(pkgDir); m != "" && !f.owned(ctx, pkgDir+"/"+m) {
			return pkgDir, true
		}
	}
	return "", false
}

func (f appDirFinder) walkUp(ctx context.Context, start string) (string, bool) {
	stop := toolHome(start)
	for dir := start; dir != "/" && dir != "." && dir != "" && dir != stop; dir = filepath.Dir(dir) {
		m := f.marker(dir)
		if m == "" {
			continue
		}
		if f.owned(ctx, dir+"/"+m) {
			return "", false
		}
		return dir, true
	}
	return "", false
}

// toolHome returns the home directory (/root or /home/<name>) when p lies in a hidden directory
// directly under it, such as ~/.local or ~/.nvm, or "". A stray manifest in the home directory
// does not make it the app directory of a tool installed there.
func toolHome(p string) string {
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 4)
	n := 1
	if parts[0] == "home" {
		n = 2
	} else if parts[0] != "root" {
		return ""
	}
	if len(parts) <= n || !strings.HasPrefix(parts[n], ".") {
		return ""
	}
	return "/" + strings.Join(parts[:n], "/")
}

// splitNodeModules splits /usr/lib/node_modules/@scope/name/bin into /usr/lib and
// /usr/lib/node_modules/@scope/name, at the outermost node_modules.
func splitNodeModules(p string) (outer, pkgDir string, inside bool) {
	i := strings.Index(p+"/", "/node_modules/")
	if i < 0 {
		return "", "", false
	}
	outer = p[:i]
	rest := strings.Split(strings.TrimPrefix(p+"/", p[:i]+"/node_modules/"), "/")
	n := 1
	if strings.HasPrefix(rest[0], "@") {
		n = 2
	}
	if len(rest) <= n || rest[0] == "" || rest[n-1] == "" {
		return outer, "", true
	}
	return outer, outer + "/node_modules/" + strings.Join(rest[:n], "/"), true
}

// resolve follows symlinks within the host root.
func (f appDirFinder) resolve(p string) string {
	root, err := filepath.EvalSymlinks(f.root)
	if err != nil {
		return p
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, p))
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return p
	}
	return "/" + rel
}

func (f appDirFinder) isFile(p string) bool {
	fi, err := os.Stat(filepath.Join(f.root, p))
	return err == nil && fi.Mode().IsRegular()
}

// marker returns the first project marker in dir, or "".
func (f appDirFinder) marker(dir string) string {
	for _, m := range appMarkers {
		if _, err := os.Stat(filepath.Join(f.root, dir, m)); err == nil {
			return m
		}
	}
	return ""
}
