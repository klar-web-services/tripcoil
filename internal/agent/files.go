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

	"golang.org/x/sys/unix"

	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

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

func ResetHome(home, template string, uid, gid int, mount func(dir string) error) error {
	if err := os.RemoveAll(home); err != nil {
		return err
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	if mount != nil {
		if err := mount(home); err != nil {
			return err
		}
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
			return nil
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

func readEntries(home, name string, max int64) ([]byte, error) {
	dir, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case errors.Is(err, unix.ELOOP):
		return nil, errors.New("it is a symbolic link")
	case err != nil:
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("it is not a regular file (%v)", fi.Mode().Type())
	case fi.Size() > max:
		return nil, fmt.Errorf("it is larger than %d MiB", max>>20)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("it is larger than %d MiB", max>>20)
	}
	return data, nil
}
