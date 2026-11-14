package run

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	unlock()
	select {
	case u := <-got:
		u()
	case <-time.After(5 * time.Second):
		t.Fatal("the second lock was not granted after the first was released")
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
