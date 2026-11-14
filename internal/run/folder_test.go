package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func noAgentGroup(t *testing.T) {
	old := AgentGID
	AgentGID = func() (int, bool) { return 0, false }
	t.Cleanup(func() { AgentGID = old })
}

func TestLockWaitsForTheHolder(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir, func() { t.Error("the first lock must not wait") })
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan struct{})
	got := make(chan func(), 1)
	go func() {
		u, err := Lock(dir, func() { close(waited) })
		if err != nil {
			t.Error(err)
		}
		got <- u
	}()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lock did not report waiting")
	}
	select {
	case <-got:
		t.Fatal("the second lock was granted while the first was held")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case u := <-got:
		u()
	case <-time.After(5 * time.Second):
		t.Fatal("the second lock was not granted after the first was released")
	}
}

func TestLockCreatesStateRootWithMode0755(t *testing.T) {
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "state")
	unlock, err := Lock(dir, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("state root mode %v %v", fi.Mode(), err)
	}
}

func TestFolderJSONAndLatest(t *testing.T) {
	noAgentGroup(t)
	state := t.TempDir()
	dir, err := CreateFolder(state, "20261114T061500Z-3fa2")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("folder mode %v %v", fi.Mode(), err)
	}
	if _, err := CreateFolder(state, "20261114T061500Z-3fa2"); err == nil {
		t.Fatal("an existing run folder must not be reused")
	}
	p := filepath.Join(dir, "run.json")
	if err := WriteJSON(p, map[string]int{"items": 3}, 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("file mode %v %v", fi.Mode(), err)
	}
	var back map[string]int
	data, _ := os.ReadFile(p)
	if err := json.Unmarshal(data, &back); err != nil || back["items"] != 3 || data[len(data)-1] != '\n' {
		t.Fatalf("%q %v", data, err)
	}
	if _, err := CreateFolder(state, "20261114T120000Z-0001"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"20261114T061500Z-3fa2", "20261114T120000Z-0001"} {
		if err := UpdateLatest(state, "latest", id); err != nil {
			t.Fatal(err)
		}
	}
	if target, err := os.Readlink(filepath.Join(state, "runs", "latest")); err != nil || target != "20261114T120000Z-0001" {
		t.Fatalf("latest -> %q %v", target, err)
	}
}

func TestSubfolderShareAndWriteFile(t *testing.T) {
	gid := os.Getgid()
	old := AgentGID
	AgentGID = func() (int, bool) { return gid, true } // our own group, which chown always allows
	t.Cleanup(func() { AgentGID = old })
	dir := t.TempDir()
	raw, err := CreateSubfolder(dir, "raw")
	if err != nil {
		t.Fatal(err)
	}
	if again, err := CreateSubfolder(dir, "raw"); err != nil || again != raw {
		t.Fatalf("a second call: %s %v", again, err)
	}
	p := filepath.Join(raw, "a.grype.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil { // as Grype writes it
		t.Fatal(err)
	}
	if err := Share(p, 0o640); err != nil {
		t.Fatal(err)
	}
	md := filepath.Join(dir, "report.md")
	if err := WriteFile(md, []byte("# r\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{raw: 0o750, p: 0o640, md: 0o640} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != mode || int(fi.Sys().(*syscall.Stat_t).Gid) != gid {
			t.Errorf("%s: %v %v", path, fi.Mode(), err)
		}
	}
	if data, _ := os.ReadFile(md); string(data) != "# r\n" {
		t.Fatalf("report.md %q", data)
	}
}
