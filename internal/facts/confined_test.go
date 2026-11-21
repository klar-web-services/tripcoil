package facts

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// procRoot makes proc/<pid> of a process whose root directory is dir.
func procRoot(t *testing.T, root string, pid int, dir string) {
	t.Helper()
	p := filepath.Join("proc", itoa(pid))
	write(t, root, p+"/status", "Name:\tcaddy\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 27 \n")
	link(t, root, p+"/root", dir)
}

func itoa(n int) string {
	return string(rune('0'+n/100)) + string(rune('0'+n/10%10)) + string(rune('0'+n%10))
}

// A process's files are read below its own root: a link that points outside stays inside, and only
// regular files of a sane size are read. (That the read has the process's rights and not root's
// needs root: the integration suite checks it.)
func TestConfinedRead(t *testing.T) {
	root, guest := t.TempDir(), t.TempDir()
	procRoot(t, root, 700, guest)
	write(t, guest, "etc/caddy/Caddyfile", ":80 {\n}\n")
	write(t, guest, "etc/caddy/conf.d/a.caddy", "a")
	write(t, guest, "etc/caddy/conf.d/b.caddy", "b")
	write(t, root, "etc/shadow", "root:secret\n")
	write(t, guest, "etc/shadow", "the guest's own\n")
	link(t, guest, "etc/caddy/outside", filepath.Join(root, "etc/shadow"))
	link(t, guest, "etc/caddy/absolute", "/etc/shadow")
	link(t, guest, "etc/caddy/up", "../../../../../../etc/shadow")
	if err := syscall.Mkfifo(filepath.Join(guest, "etc/caddy/fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock, err := net.Listen("unix", filepath.Join(guest, "etc/caddy/sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	if err := os.WriteFile(filepath.Join(guest, "etc/caddy/huge"), make([]byte, maxConfigFile+1), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := (collector{ctx: context.Background(), d: Deps{Root: root}}).confine(700)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if r.uid != 1000 || r.gid != 1000 || !slices.Equal(r.groups, []int{1000, 27}) {
		t.Errorf("the process's user: %+v", r)
	}
	if data, err := r.read("/etc/caddy/Caddyfile"); err != nil || string(data) != ":80 {\n}\n" {
		t.Errorf("a file: %q %v", data, err)
	}
	for _, path := range []string{"/etc/caddy/absolute", "/etc/caddy/up"} {
		if data, err := r.read(path); err != nil || string(data) != "the guest's own\n" {
			t.Errorf("%s must resolve inside the process's root: %q %v", path, data, err)
		}
	}
	// The link names the host's file by its full path; inside the guest's root there is no such path.
	if data, err := r.read("/etc/caddy/outside"); err == nil || strings.Contains(string(data), "secret") {
		t.Errorf("a link to the outside was followed: %q %v", data, err)
	}
	for path, why := range map[string]string{"/etc/caddy/fifo": "not a regular file", "/etc/caddy": "not a regular file", "/etc/caddy/sock": "not a regular file", "/etc/caddy/huge": "larger than", "/etc/caddy/none": "no such file"} {
		if _, err := r.read(path); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want %q", path, err, why)
		}
	}
	names, err := r.list("/etc/caddy/conf.d")
	slices.Sort(names)
	if err != nil || !slices.Equal(names, []string{"a.caddy", "b.caddy"}) {
		t.Errorf("a directory: %v %v", names, err)
	}
	if _, err := r.list("/etc/caddy/Caddyfile"); err == nil {
		t.Error("a file is no directory")
	}
	if _, err := (collector{d: Deps{Root: root}}).confine(999); err == nil {
		t.Error("a process that is gone")
	}
	// A setuid program has its caller's command line and working directory and its owner's rights.
	for pid, status := range map[int]string{
		701: "Name:\tcaddy\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000\n",
		702: "Name:\tcaddy\nUid:\t0\t0\t0\t0\nGid:\t1000\t0\t0\t0\nGroups:\t0\n",
		703: "Name:\tcaddy\n",
	} {
		procRoot(t, root, pid, guest)
		write(t, root, filepath.Join("proc", itoa(pid), "status"), status)
		if _, err := (collector{d: Deps{Root: root}}).confine(pid); err == nil || !strings.Contains(err.Error(), "one user and group") {
			t.Errorf("process %d does not run as one user: %v", pid, err)
		}
	}
	for i := 0; i <= maxDirNames; i++ {
		write(t, guest, filepath.Join("big", "f"+strconv.Itoa(i)), "")
	}
	if _, err := r.list("/big"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("a directory with too many entries: %v", err)
	}
}
