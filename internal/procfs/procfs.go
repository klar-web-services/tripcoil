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

const userHZ = 100

type FS struct{ Root string }

type Mapping struct {
	Start, End string
	Path       string
	Deleted    bool
}

func (f FS) proc(pid int, name string) string {
	return filepath.Join(f.Root, "proc", strconv.Itoa(pid), name)
}

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

func (f FS) Exe(pid int) (string, bool, error) {
	target, err := os.Readlink(f.proc(pid, "exe"))
	if err != nil {
		return "", false, err
	}
	p, deleted := strings.CutSuffix(target, " (deleted)")
	return p, deleted, nil
}

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

func (f FS) Cwd(pid int) (string, error) {
	return os.Readlink(f.proc(pid, "cwd"))
}

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

func (f FS) StartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(f.proc(pid, "stat"))
	if err != nil {
		return 0, err
	}
	// The command name (field 2) is in parentheses and may itself contain spaces and parentheses.
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, fmt.Errorf("unexpected format of %s", f.proc(pid, "stat"))
	}
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("unexpected format of %s", f.proc(pid, "stat"))
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func (f FS) StartTime(pid int) (time.Time, error) {
	ticks, err := f.StartTicks(pid)
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

func (f FS) Cgroup(pid int) (string, error) {
	data, err := os.ReadFile(f.proc(pid, "cgroup"))
	return string(data), err
}

func (f FS) Maps(pid int) ([]Mapping, error) {
	data, err := os.ReadFile(f.proc(pid, "maps"))
	if err != nil {
		return nil, err
	}
	return ParseMaps(data), nil
}

func ParseMaps(data []byte) []Mapping {
	var out []Mapping
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue
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

var ErrNotRegular = errors.New("not a regular file")

var ErrPseudoFile = errors.New("a file of a kernel file system")

// pseudoFS are the kernel file systems whose regular files are not file contents (statfs magic
// numbers): proc, sysfs, tracefs, debugfs, securityfs, cgroup, cgroup2, bpf, configfs, efivarfs,
// pstore, xenfs (/proc/xen/xenbus waits forever) and rpc_pipefs (opening an NFS upcall pipe
// registers a reader).
var pseudoFS = map[int64]bool{
	0x9fa0:     true,
	0x62656572: true,
	0x74726163: true,
	0x64626720: true,
	0x73636673: true,
	0x27e0eb:   true,
	0x63677270: true,
	0xcafe4a11: true,
	0x62656570: true,
	0xde5e81e4: true,
	0x6165676c: true,
	0xabba1974: true,
	0x67596969: true,
}

type FileID struct{ Dev, Ino uint64 }

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

func (f FS) RootDir(pid int) (string, error) {
	target, err := os.Readlink(f.proc(pid, "root"))
	if err != nil {
		return "", err
	}
	root, _ := strings.CutSuffix(target, " (deleted)")
	return root, nil
}

func (f FS) RootFileID(pid int) (FileID, error) {
	return f.statID(f.proc(pid, "root"))
}

func (f FS) ExeFileID(pid int) (FileID, error) {
	return f.statID(f.proc(pid, "exe"))
}

func (f FS) MapFileID(pid int, m Mapping) (FileID, error) {
	return f.statID(f.mapFile(pid, m))
}

func (f FS) mapFile(pid int, m Mapping) string {
	return filepath.Join(f.proc(pid, "map_files"), strings.TrimLeft(m.Start, "0")+"-"+strings.TrimLeft(m.End, "0"))
}

func (f FS) OpenExe(pid int) (io.ReadCloser, error) {
	return OpenRegular(f.proc(pid, "exe"))
}

func (f FS) OpenMapFile(pid int, m Mapping) (io.ReadCloser, error) {
	return OpenRegular(f.mapFile(pid, m))
}

const oPath = 0x200000

// OpenRegular opens a file for reading only if it is a regular file of a real file system. A
// process can map a FIFO or a device, and anyone may have put one, or a link to /proc/kmsg, at a
// path. None of them is ever opened for reading: an O_PATH descriptor only names the file, and only
// a regular file outside the kernel's file systems is reopened for reading through it, without
// blocking: a user's write lease on the file makes the open fail at once instead of stalling it.
func OpenRegular(path string) (*os.File, error) {
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, &fs.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, &fs.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	var sfs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &sfs); err != nil {
		return nil, &fs.PathError{Op: "fstatfs", Path: path, Err: err}
	}
	if pseudoFS[int64(sfs.Type)] {
		return nil, &fs.PathError{Op: "open", Path: path, Err: ErrPseudoFile}
	}
	return os.OpenFile("/proc/self/fd/"+strconv.Itoa(fd), os.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
}
