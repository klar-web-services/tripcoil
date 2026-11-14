package inventory

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

type fakeProc struct {
	cmdline   []string
	exe       string
	deleted   bool
	exeErr    error
	exeID     procfs.FileID // device and inode of the running executable; zero means unknown
	cwd       string
	uid       int
	cgroup    string // /proc/<pid>/cgroup content
	maps      []procfs.Mapping
	otherRoot bool
	exeData   string                   // what /proc/<pid>/exe reads
	mapData   map[string]string        // path -> what map_files reads
	mapIDs    map[string]procfs.FileID // path -> device and inode of the mapped file
	size      int64                    // the size an opened running file reports, if not its length
	openErr   error                    // what opening a running file returns
	onRead    func()                   // called on every read of a running file
	read      int                      // bytes read from running files
	reused    bool                     // the PID belongs to another process after the first read
	started   int                      // StartTime calls
}

type fakeSource map[int]*fakeProc

func (s fakeSource) PIDs() ([]int, error) {
	var pids []int
	for pid := range s {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

func (s fakeSource) Exe(pid int) (string, bool, error) {
	p := s[pid]
	if p.exeErr != nil {
		return "", false, p.exeErr
	}
	return p.exe, p.deleted, nil
}

func (s fakeSource) ExeFileID(pid int) (procfs.FileID, error) {
	if s[pid].exeID == (procfs.FileID{}) {
		return procfs.FileID{}, errors.New("unknown")
	}
	return s[pid].exeID, nil
}

func (s fakeSource) Cmdline(pid int) ([]string, error) { return s[pid].cmdline, nil }
func (s fakeSource) Cwd(pid int) (string, error)       { return s[pid].cwd, nil }
func (s fakeSource) UID(pid int) (int, error)          { return s[pid].uid, nil }
func (s fakeSource) StartTime(pid int) (time.Time, error) {
	t := time.Unix(1700000000+int64(pid), 0).UTC()
	if s[pid].reused && s[pid].started > 0 {
		t = t.Add(time.Hour)
	}
	s[pid].started++
	return t, nil
}
func (s fakeSource) Cgroup(pid int) (string, error)         { return s[pid].cgroup, nil }
func (s fakeSource) Maps(pid int) ([]procfs.Mapping, error) { return s[pid].maps, nil }
func (s fakeSource) SameRootAsInit(pid int) (bool, error)   { return !s[pid].otherRoot, nil }
func (s fakeSource) OpenExe(pid int) (io.ReadCloser, error) {
	return s[pid].open(s[pid].exeData, s[pid].exeID)
}
func (s fakeSource) OpenMapFile(pid int, m procfs.Mapping) (io.ReadCloser, error) {
	return s[pid].open(s[pid].mapData[m.Path], s[pid].mapIDs[m.Path])
}

func (p *fakeProc) open(data string, id procfs.FileID) (io.ReadCloser, error) {
	if p.openErr != nil {
		return nil, p.openErr
	}
	size := p.size
	if size == 0 {
		size = int64(len(data))
	}
	return &fakeFile{p: p, r: strings.NewReader(data), info: fakeInfo{size: size, id: id}}, nil
}

// fakeFile is a running file opened through /proc.
type fakeFile struct {
	p    *fakeProc
	r    io.Reader
	info fakeInfo
}

func (f *fakeFile) Read(b []byte) (int, error) {
	if f.p.onRead != nil {
		f.p.onRead()
	}
	n, err := f.r.Read(b)
	f.p.read += n
	return n, err
}
func (f *fakeFile) Close() error               { return nil }
func (f *fakeFile) Stat() (fs.FileInfo, error) { return f.info, nil }

type fakeInfo struct {
	size int64
	id   procfs.FileID
}

func (fakeInfo) Name() string       { return "" }
func (i fakeInfo) Size() int64      { return i.size }
func (fakeInfo) Mode() fs.FileMode  { return 0o755 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any         { return &syscall.Stat_t{Dev: i.id.Dev, Ino: i.id.Ino} }

type fakeTool struct {
	typ       string
	owners    map[string]pkgtool.Package
	installed map[string][]pkgtool.Package
	checkErr  error
	ownersErr error
	asked     *[]string // the paths Owners was asked about
}

func (f fakeTool) Type() string                { return f.typ }
func (f fakeTool) Check(context.Context) error { return f.checkErr }
func (f fakeTool) Owners(_ context.Context, paths []string) (map[string]pkgtool.Package, error) {
	if f.asked != nil {
		*f.asked = append(*f.asked, paths...)
	}
	if f.ownersErr != nil {
		return nil, f.ownersErr
	}
	out := map[string]pkgtool.Package{}
	for _, p := range paths {
		if pkg, ok := f.owners[p]; ok {
			out[p] = pkg
		}
	}
	return out, nil
}
func (f fakeTool) Installed(_ context.Context, pattern string) ([]pkgtool.Package, error) {
	return f.installed[pattern], nil
}

// Compare orders versions as text; the tests pick versions whose text order is their real order.
func (f fakeTool) Compare(_ context.Context, a, b string) (int, error) {
	return strings.Compare(a, b), nil
}

// files writes content files below a new temp root.
func files(t *testing.T, content map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range content {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fileID returns the device and inode of a file below root.
func fileID(t *testing.T, root, p string) procfs.FileID {
	t.Helper()
	fi, err := os.Stat(filepath.Join(root, p))
	if err != nil {
		t.Fatal(err)
	}
	id, ok := procfs.IDOf(fi)
	if !ok {
		t.Fatal("no file ID")
	}
	return id
}
