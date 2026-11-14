// Package procfs reads processes from the /proc tree below a host root.
package procfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// userHZ is the unit of the times in /proc/<pid>/stat; it is 100 on every Linux architecture.
const userHZ = 100

// FS reads Root/proc. Production uses Root "/".
type FS struct{ Root string }

// Mapping is one file mapped into a process, deduplicated by path.
type Mapping struct {
	// Start and End are the hex addresses as in /proc/<pid>/maps; without their zero padding,
	// they name the map_files entry.
	Start, End string
	Path       string
	Deleted    bool // the file was replaced or removed after it was mapped
}

func (f FS) proc(pid int, name string) string {
	return filepath.Join(f.Root, "proc", strconv.Itoa(pid), name)
}

// PIDs lists the process IDs, ascending.
func (f FS) PIDs() ([]int, error) {
	entries, err := os.ReadDir(filepath.Join(f.Root, "proc"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

// Exe returns the executable's path and whether it was replaced after the process started.
// A kernel thread has no executable: the error satisfies os.IsNotExist.
func (f FS) Exe(pid int) (string, bool, error) {
	target, err := os.Readlink(f.proc(pid, "exe"))
	if err != nil {
		return "", false, err
	}
	p, deleted := strings.CutSuffix(target, " (deleted)")
	return p, deleted, nil
}

// Cmdline returns the arguments, or nil when the command line is empty (a kernel thread or a
// zombie).
func (f FS) Cmdline(pid int) ([]string, error) {
	data, err := os.ReadFile(f.proc(pid, "cmdline"))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return nil, nil
	}
	return strings.Split(string(data), "\x00"), nil
}

// Cwd returns the working directory.
func (f FS) Cwd(pid int) (string, error) {
	return os.Readlink(f.proc(pid, "cwd"))
}

// UID returns the real user ID.
func (f FS) UID(pid int) (int, error) {
	data, err := os.ReadFile(f.proc(pid, "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				return strconv.Atoi(fields[0])
			}
		}
	}
	return 0, fmt.Errorf("no Uid line in %s", f.proc(pid, "status"))
}

// StartTime returns when the process started.
func (f FS) StartTime(pid int) (time.Time, error) {
	data, err := os.ReadFile(f.proc(pid, "stat"))
	if err != nil {
		return time.Time{}, err
	}
	// The command name (field 2) is in parentheses and may itself contain spaces and parentheses.
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return time.Time{}, fmt.Errorf("unexpected format of %s", f.proc(pid, "stat"))
	}
	fields := strings.Fields(string(data[i+1:])) // fields[0] is field 3; starttime is field 22
	if len(fields) < 20 {
		return time.Time{}, fmt.Errorf("unexpected format of %s", f.proc(pid, "stat"))
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	btime, err := f.bootTime()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(btime, 0).Add(time.Duration(ticks) * (time.Second / userHZ)).UTC(), nil
}

func (f FS) bootTime() (int64, error) {
	data, err := os.ReadFile(filepath.Join(f.Root, "proc", "stat"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		}
	}
	return 0, fmt.Errorf("no btime in %s", filepath.Join(f.Root, "proc", "stat"))
}

// Cgroup returns /proc/<pid>/cgroup as it is: ParseCgroup picks the path that names the systemd
// unit, and DockerContainerID searches every line.
func (f FS) Cgroup(pid int) (string, error) {
	data, err := os.ReadFile(f.proc(pid, "cgroup"))
	return string(data), err
}

// Maps returns the files mapped into the process, each path once, in the order of first mapping.
func (f FS) Maps(pid int) ([]Mapping, error) {
	data, err := os.ReadFile(f.proc(pid, "maps"))
	if err != nil {
		return nil, err
	}
	return ParseMaps(data), nil
}

// ParseMaps parses /proc/<pid>/maps, keeping only file-backed mappings.
func ParseMaps(data []byte) []Mapping {
	var out []Mapping
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line) // address perms offset dev inode [path]
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue // not file-backed: [heap], [anon:name], anonymous
		}
		path := line[strings.Index(line, " /")+1:]
		p, deleted := strings.CutSuffix(path, " (deleted)")
		if seen[p] {
			continue
		}
		seen[p] = true
		start, end, _ := strings.Cut(fields[0], "-")
		out = append(out, Mapping{Start: start, End: end, Path: p, Deleted: deleted})
	}
	return out
}

// ErrNotRegular is returned for a running file that is not a regular file.
var ErrNotRegular = errors.New("not a regular file")

// FileID identifies a file by device and inode.
type FileID struct{ Dev, Ino uint64 }

// IDOf returns a file's device and inode.
func IDOf(fi fs.FileInfo) (FileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, false
	}
	return FileID{Dev: uint64(st.Dev), Ino: st.Ino}, true
}

func (f FS) statID(path string) (FileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileID{}, err
	}
	id, ok := IDOf(fi)
	if !ok {
		return FileID{}, fmt.Errorf("cannot read the device and inode of %s", path)
	}
	return id, nil
}

// SameRootAsInit reports whether the process's root directory is PID 1's.
func (f FS) SameRootAsInit(pid int) (bool, error) {
	a, err := f.statID(f.proc(pid, "root"))
	if err != nil {
		return false, err
	}
	b, err := f.statID(f.proc(1, "root"))
	if err != nil {
		return false, err
	}
	return a == b, nil
}

// ExeFileID identifies the running executable's file (through /proc, so also in another root).
func (f FS) ExeFileID(pid int) (FileID, error) {
	return f.statID(f.proc(pid, "exe"))
}

// MapFileID identifies a mapped file (through /proc, so also in another root).
func (f FS) MapFileID(pid int, m Mapping) (FileID, error) {
	return f.statID(f.mapFile(pid, m))
}

func (f FS) mapFile(pid int, m Mapping) string {
	return filepath.Join(f.proc(pid, "map_files"), strings.TrimLeft(m.Start, "0")+"-"+strings.TrimLeft(m.End, "0"))
}

// OpenExe opens the running executable, even when it was replaced on disk.
func (f FS) OpenExe(pid int) (io.ReadCloser, error) {
	return openRegular(f.proc(pid, "exe"))
}

// OpenMapFile opens a mapped file through /proc/<pid>/map_files, even when it was replaced.
func (f FS) OpenMapFile(pid int, m Mapping) (io.ReadCloser, error) {
	return openRegular(f.mapFile(pid, m))
}

// openRegular opens a file only if it is a regular file. A process can map a FIFO or a device:
// O_NONBLOCK keeps the open of a FIFO from waiting for a writer, and nothing is read from either.
func openRegular(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	fi, err := file.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = &fs.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
