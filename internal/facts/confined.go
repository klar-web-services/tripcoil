package facts

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxConfigFile bounds one configuration file Tripcoil reads on behalf of a process.
const maxConfigFile = 1 << 20

// maxDirNames bounds the names Tripcoil takes from one directory of a process.
const maxDirNames = 4096

// confined reads files as one process sees and may read them: below that process's root directory,
// where a link that points outside resolves inside, and with the process's user and groups, so
// that root reads nothing here that the process could not read itself.
type confined struct {
	// proc is /proc/<pid>, held open: it stays this process's when the pid is given out again.
	proc   *os.File
	root   *os.File
	uid    int
	gid    int
	groups []int
	// drop is false when Tripcoil is not root (tests) or the process is: there is nothing to drop.
	drop bool
}

// same is the one ID of a status line such as "Uid: 1000 1000 1000 1000" (real, effective, saved,
// file system), or -1 when they differ: a setuid program runs with its caller's command line and
// working directory, and its owner's rights.
func same(f []string) int {
	if len(f) != 5 || f[1] != f[2] || f[1] != f[3] || f[1] != f[4] {
		return -1
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return -1
	}
	return n
}

// errGone: the process ended before it could be looked at.
var errGone = errors.New("the process is gone")

func (c collector) confine(pid int) (*confined, error) {
	proc, err := os.Open(filepath.Join(c.d.Root, "proc", strconv.Itoa(pid)))
	if err != nil {
		return nil, errGone
	}
	r := &confined{proc: proc, uid: -1, gid: -1}
	status, err := r.procFile("status")
	if err != nil {
		proc.Close()
		return nil, errGone
	}
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 1 && f[0] == "Uid:":
			r.uid = same(f)
		case len(f) >= 1 && f[0] == "Gid:":
			r.gid = same(f)
		case len(f) >= 1 && f[0] == "Groups:":
			for _, g := range f[1:] {
				if n, err := strconv.Atoi(g); err == nil {
					r.groups = append(r.groups, n)
				}
			}
		}
	}
	if r.uid < 0 || r.gid < 0 {
		proc.Close()
		return nil, errors.New("it does not run as one user and group throughout")
	}
	fd, err := unix.Openat(int(proc.Fd()), "root", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		proc.Close()
		return nil, &os.PathError{Op: "open", Path: "root", Err: err}
	}
	r.root = os.NewFile(uintptr(fd), "root")
	r.drop = os.Geteuid() == 0 && r.uid != 0
	return r, nil
}

// procFile reads a file of the process's /proc directory, such as cmdline.
func (r *confined) procFile(name string) ([]byte, error) {
	fd, err := unix.Openat(int(r.proc.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxConfigFile))
}

// procLink reads a link of the process's /proc directory, such as cwd.
func (r *confined) procLink(name string) string {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(int(r.proc.Fd()), name, buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func (r *confined) close() {
	r.root.Close()
	r.proc.Close()
}

// as runs f with the process's rights for file access. It gives up root's on a thread of its own,
// which ends with the goroutine: the rights of every other thread stay as they are.
func (r *confined) as(f func() error) error {
	if !r.drop {
		return f()
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // not unlocked: Go ends a thread whose goroutine exits while locked to it
		groups := make([]uint32, len(r.groups))
		for i, g := range r.groups {
			groups[i] = uint32(g)
		}
		var p unsafe.Pointer
		if len(groups) > 0 {
			p = unsafe.Pointer(&groups[0])
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(groups)), uintptr(p), 0); errno != 0 {
			done <- fmt.Errorf("setgroups: %w", errno)
			return
		}
		// setfsgid and setfsuid return the previous value and no error: ask again to see that it took.
		unix.RawSyscall(unix.SYS_SETFSGID, uintptr(r.gid), 0, 0)
		unix.RawSyscall(unix.SYS_SETFSUID, uintptr(r.uid), 0, 0)
		gid, _, _ := unix.RawSyscall(unix.SYS_SETFSGID, ^uintptr(0), 0, 0)
		uid, _, _ := unix.RawSyscall(unix.SYS_SETFSUID, ^uintptr(0), 0, 0)
		if int(uint32(uid)) != r.uid || int(uint32(gid)) != r.gid {
			done <- errors.New("could not take the process's user for reading")
			return
		}
		done <- f()
	}()
	return <-done
}

// open opens a regular file, or a directory, below the process's root. It looks at what the path
// names before it opens it: opening a device or a FIFO can itself do something.
func (r *confined) open(path string, dir bool) (*os.File, error) {
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS}
	handle, err := unix.Openat2(int(r.root.Fd()), path, &how)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(handle)
	var st unix.Stat_t
	if err := unix.Fstat(handle, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	switch kind := st.Mode & unix.S_IFMT; {
	case dir && kind != unix.S_IFDIR:
		return nil, &os.PathError{Op: "open", Path: path, Err: unix.ENOTDIR}
	case dir:
		flags |= unix.O_DIRECTORY
	case kind != unix.S_IFREG:
		return nil, &os.PathError{Op: "open", Path: path, Err: errors.New("not a regular file")}
	case st.Size > maxConfigFile:
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("larger than %d MiB", maxConfigFile>>20)}
	}
	// The handle gives no access to the content; opening it again checks the rights to read it.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(handle), flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// isDir reports whether path is a directory the process may open.
func (r *confined) isDir(path string) bool {
	return r.as(func() error {
		f, err := r.open(path, true)
		if err == nil {
			f.Close()
		}
		return err
	}) == nil
}

// read returns a regular file's content; anything else (a directory, a FIFO, a device, a file over
// the limit) is an error.
func (r *confined) read(path string) ([]byte, error) {
	var data []byte
	err := r.as(func() error {
		f, err := r.open(path, false)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, maxConfigFile))
		return err
	})
	return data, err
}

// list returns the names in a directory.
func (r *confined) list(dir string) ([]string, error) {
	var names []string
	err := r.as(func() error {
		f, err := r.open(dir, true)
		if err != nil {
			return err
		}
		defer f.Close()
		if names, err = f.Readdirnames(maxDirNames + 1); err == io.EOF {
			err = nil
		}
		if len(names) > maxDirNames {
			return &os.PathError{Op: "read", Path: dir, Err: fmt.Errorf("more than %d entries", maxDirNames)}
		}
		return err
	})
	return names, err
}
