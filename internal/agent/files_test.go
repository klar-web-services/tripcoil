package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFindCLI(t *testing.T) {
	// sh is installed system-wide on every test machine, owned by root.
	p, err := FindCLI("", "sh")
	if err != nil || !strings.HasSuffix(p, "/sh") {
		t.Fatalf("%q %v", p, err)
	}
	if p2, err := FindCLI(p, "claude"); err != nil || p2 != p {
		t.Errorf("review.command: %q %v", p2, err)
	}
	if _, err := FindCLI("", "tripcoil-no-such-cli"); err == nil || !strings.Contains(err.Error(), "is not installed on /usr/local/sbin:") {
		t.Errorf("missing: %v", err)
	}
	// A CLI the agent's user could replace, such as one in a user's home, is refused.
	mine := filepath.Join(t.TempDir(), "claude")
	os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755)
	if _, err := FindCLI(mine, "claude"); err == nil || !strings.Contains(err.Error(), "must be owned by root") {
		t.Errorf("own file: %v", err)
	}
	// So is a link in such a folder.
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(mine, link)
	if _, err := FindCLI(link, "claude"); err == nil {
		t.Error("link accepted")
	}
	if _, err := FindCLI("/etc", "claude"); err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Errorf("directory: %v", err)
	}
}

func TestCheckPathFollowsLinks(t *testing.T) {
	// /proc/self is a link owned by root; it leads to /proc/<pid>, which is owned by this user.
	if _, err := checkPath("/proc/self/exe", 0); err == nil {
		t.Error("followed into a folder this user owns")
	}
}

func TestResetHome(t *testing.T) {
	dir := t.TempDir()
	home, tmpl := filepath.Join(dir, "home"), filepath.Join(dir, "template")
	os.MkdirAll(filepath.Join(home, "old"), 0o755)
	os.WriteFile(filepath.Join(home, "old", "marker"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(tmpl, ".codex"), 0o700)
	os.WriteFile(filepath.Join(tmpl, ".codex", "auth.json"), []byte(`{"token":"t"}`), 0o600)
	os.WriteFile(filepath.Join(tmpl, ".claude.json"), []byte("{}"), 0o644)
	os.Symlink(".claude.json", filepath.Join(tmpl, "link"))
	uid, gid := os.Getuid(), os.Getgid()
	if err := ResetHome(home, tmpl, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "old")); err == nil {
		t.Error("the last review's files are still there")
	}
	for p, mode := range map[string]os.FileMode{"": 0o700, ".codex": 0o700, ".codex/auth.json": 0o600, ".claude.json": 0o644} {
		fi, err := os.Stat(filepath.Join(home, p))
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if fi.Mode().Perm() != mode || int(st.Uid) != uid || int(st.Gid) != gid {
			t.Errorf("%s: mode %v owner %d:%d", p, fi.Mode().Perm(), st.Uid, st.Gid)
		}
	}
	if target, err := os.Readlink(filepath.Join(home, "link")); err != nil || target != ".claude.json" {
		t.Errorf("link: %q %v", target, err)
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".codex", "auth.json")); string(data) != `{"token":"t"}` {
		t.Errorf("auth.json: %q", data)
	}
	// Without a template the home is empty.
	if err := ResetHome(home, filepath.Join(dir, "none"), uid, gid); err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(home); len(es) != 0 {
		t.Errorf("home not empty: %v", es)
	}
}
