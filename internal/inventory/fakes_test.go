package inventory

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	exeData   string            // what /proc/<pid>/exe reads
	mapData   map[string]string // path -> what map_files reads
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
	return time.Unix(1700000000+int64(pid), 0).UTC(), nil
}
func (s fakeSource) Cgroup(pid int) (string, error)         { return s[pid].cgroup, nil }
func (s fakeSource) Maps(pid int) ([]procfs.Mapping, error) { return s[pid].maps, nil }
func (s fakeSource) SameRootAsInit(pid int) (bool, error)   { return !s[pid].otherRoot, nil }
func (s fakeSource) OpenExe(pid int) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(s[pid].exeData)), nil
}
func (s fakeSource) OpenMapFile(pid int, m procfs.Mapping) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(s[pid].mapData[m.Path])), nil
}

type fakeTool struct {
	typ       string
	owners    map[string]pkgtool.Package
	installed map[string][]pkgtool.Package
	checkErr  error
	ownersErr error
}

func (f fakeTool) Type() string                { return f.typ }
func (f fakeTool) Check(context.Context) error { return f.checkErr }
func (f fakeTool) Owners(_ context.Context, paths []string) (map[string]pkgtool.Package, error) {
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
