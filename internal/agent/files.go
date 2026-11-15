package agent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

// FindCLI resolves the agent CLI: review.command when set, otherwise name on the fixed system
// path. The file, every link on the way to it and every directory above them must be owned by
// root and writable by nobody else, so that the agent cannot change the CLI it runs in (spec
// section 8.3).
func FindCLI(command, name string) (string, error) {
	path := command
	if path == "" {
		for _, dir := range filepath.SplitList(sandbox.Path) {
			p := filepath.Join(dir, name)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				path = p
				break
			}
		}
		if path == "" {
			return "", fmt.Errorf("%s is not installed on %s; install it system-wide (for example npm install -g), or set review.command", name, sandbox.Path)
		}
	}
	final, err := checkPath(path, 0)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(final)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s is not an executable file", final)
	}
	return path, nil
}

// checkPath checks every component of path, following links, and returns the final file.
func checkPath(path string, depth int) (string, error) {
	if depth > 40 {
		return "", fmt.Errorf("%s: too many links", path)
	}
	path = filepath.Clean(path)
	cur := "/"
	if err := safe(cur); err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if err := safe(next); err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(cur, target)
			}
			rest := filepath.Join(append([]string{target}, parts[i+1:]...)...)
			return checkPath(rest, depth+1)
		}
		cur = next
	}
	return cur, nil
}

// safe accepts a file owned by root that only root can write to.
func safe(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", p)
	}
	if fi.Mode()&fs.ModeSymlink != 0 { // a link's own mode means nothing; its owner does
		if st.Uid != 0 {
			return fmt.Errorf("%s is not owned by root", p)
		}
		return nil
	}
	if st.Uid != 0 || (fi.Mode().Perm()&0o022 != 0 && !(st.Gid == 0 && fi.Mode().Perm()&0o002 == 0)) {
		return fmt.Errorf("%s must be owned by root and writable only by root (owner %d, mode %v)", p, st.Uid, fi.Mode().Perm())
	}
	return nil
}

// ResetHome deletes home and creates it again for the agent's user, with a copy of the template
// when there is one (spec section 8.2).
func ResetHome(home, template string, uid, gid int) error {
	if err := os.RemoveAll(home); err != nil {
		return err
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	if err := os.Chown(home, uid, gid); err != nil {
		return err
	}
	if _, err := os.Stat(template); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(template, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(template, p)
		if rel == "." {
			return nil
		}
		dst := filepath.Join(home, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			err = os.Mkdir(dst, info.Mode().Perm())
		case info.Mode()&fs.ModeSymlink != 0:
			var target string
			if target, err = os.Readlink(p); err == nil {
				err = os.Symlink(target, dst)
			}
		case info.Mode().IsRegular():
			err = copyFile(p, dst, info.Mode().Perm())
		default:
			return nil // no devices, sockets or pipes
		}
		if err != nil {
			return err
		}
		if err := os.Lchown(dst, uid, gid); err != nil {
			return err
		}
		if !d.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
			return os.Chmod(dst, info.Mode().Perm())
		}
		return nil
	})
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
