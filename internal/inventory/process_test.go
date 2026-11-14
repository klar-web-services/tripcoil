package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

const containerID = "23665d1635863a96dce002582f0cc899b885bcacbd2d186b54858a079c5600d1"

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// cg is /proc/<pid>/cgroup content on a cgroup v2 host.
func cg(path string) string { return "0::" + path + "\n" }

var (
	libc    = procfs.Mapping{Start: "1", End: "2", Path: "/usr/lib/libc.so.6"}
	debian  = Distro{ID: "debian", VersionID: "12", Family: "debian"}
	pkgLibc = pkgtool.Package{Name: "libc6", Version: "2.36-9", Arch: "amd64", Type: "deb"}
)

func hostProcesses() fakeSource {
	return fakeSource{
		2: {exeErr: fs.ErrNotExist}, // kernel thread
		10: {cmdline: []string{"nginx: master process /usr/sbin/nginx"}, exe: "/usr/sbin/nginx", cgroup: cg("/system.slice/nginx.service"),
			maps: []procfs.Mapping{{Path: "/usr/sbin/nginx"}, libc, {Start: "3", End: "4", Path: "/usr/lib/libssl.so.3", Deleted: true}, {Path: "/usr/lib/locale/locale-archive"}}},
		11: {cmdline: []string{"nginx: worker process"}, exe: "/usr/sbin/nginx", uid: 33, cgroup: cg("/system.slice/nginx.service"), maps: []procfs.Mapping{libc}},
		20: {cmdline: []string{"node", "server.js", "--token", "hunter2"}, exe: "/usr/bin/node", cwd: "/srv/shop", cgroup: cg("/system.slice/shop.service"),
			maps: []procfs.Mapping{libc, {Path: "/srv/shop/node_modules/sharp/build/sharp.so"}, {Path: "/usr/lib/libnode.so.115"}}},
		30: {cmdline: []string{"/opt/api/api"}, exe: "/opt/api/api", exeData: "go binary v1",
			maps:    []procfs.Mapping{libc, {Start: "5", End: "6", Path: "/tmp/libnetty_transport.so", Deleted: true}},
			mapData: map[string]string{"/tmp/libnetty_transport.so": "netty v1"}},
		31: {cmdline: []string{"/opt/api/old"}, exe: "/opt/api/old", deleted: true, exeData: "go binary v0"},
		40: {cmdline: []string{"nginx"}, exe: "/usr/sbin/nginx", cgroup: cg("/system.slice/docker-" + containerID + ".scope")},
		50: {cmdline: []string{"lxd"}, exe: "/snap/lxd/123/bin/lxd"},
		60: {cmdline: []string{"bash"}, exe: "/usr/bin/bash", otherRoot: true},                                                  // another root, another file
		61: {cmdline: []string{"sshd: [net]"}, exe: "/usr/sbin/sshd", otherRoot: true, cgroup: cg("/system.slice/ssh.service")}, // chrooted; the test sets exeID
		62: {cmdline: []string{"sshd: /usr/sbin/sshd -D [listener]"}, exe: "/usr/sbin/sshd", cgroup: cg("/system.slice/ssh.service")},
		63: {cmdline: []string{"-bash"}, exe: "/usr/bin/bash"},
		70: {cmdline: []string{"python3", "-m", "http.server"}, exe: "/usr/bin/python3.12", cwd: "/"},
		80: {cmdline: []string{"secret-daemon"}, exeErr: fs.ErrPermission},
	}
}

func hostTool() fakeTool {
	return fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
		"/usr/sbin/nginx":         {Name: "nginx-core", Version: "1.22.1-9", Arch: "amd64", Type: "deb"},
		"/usr/lib/libc.so.6":      pkgLibc,
		"/usr/lib/libssl.so.3":    {Name: "libssl3", Version: "3.0.16-1", Arch: "amd64", Type: "deb"},
		"/usr/bin/node":           {Name: "nodejs", Version: "18.19.0", Arch: "amd64", Type: "deb"},
		"/usr/lib/libnode.so.115": {Name: "libnode115", Version: "18.19.0", Arch: "amd64", Type: "deb"},
		"/usr/bin/python3.12":     {Name: "python3.12-minimal", Version: "3.12.3", Arch: "amd64", Type: "deb"},
		"/usr/sbin/sshd":          {Name: "openssh-server", Version: "1:9.2p1-2+deb12u3", Arch: "amd64", Type: "deb"},
		"/usr/bin/bash":           {Name: "bash", Version: "5.2.15-2", Arch: "amd64", Type: "deb"},
	}}
}

func hostRoot(t *testing.T) string {
	return files(t, map[string]string{
		"etc/passwd":            "root:x:0:0::/root:/bin/sh\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
		"srv/shop/package.json": "{}",
		"srv/shop/server.js":    "",
		"opt/api/api":           "not what runs: files are read through /proc",
		"opt/api/old":           "go binary v1, installed while v0 runs",
		"usr/sbin/sshd":         "sshd",
		"usr/bin/bash":          "bash",
	})
}

func byName(items []Item, name string) Item {
	for _, it := range items {
		if it.Name == name {
			return it
		}
	}
	return Item{}
}

func originByID(origins []Origin, id string) Origin {
	for _, o := range origins {
		if o.ID == id {
			return o
		}
	}
	return Origin{}
}

func TestProcessCollector(t *testing.T) {
	root, cache := hostRoot(t), t.TempDir()
	tool := hostTool()
	src := hostProcesses()
	src[61].exeID = fileID(t, root, "usr/sbin/sshd") // the host's own sshd, run in a chroot
	c := &processCollector{src: src, root: root, resolver: &pkgtool.Resolver{Tool: tool}, distro: debian, cacheDir: cache}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, it := range res.items {
		names = append(names, it.Name)
	}
	if want := []string{"api", "bash", "bash", "lxd", "nginx", "node", "old", "python3.12", "secret-daemon", "sshd"}; !slices.Equal(names, want) {
		t.Fatalf("items %q, want %q", names, want)
	}
	if !slices.Equal(res.containerPIDs[containerID], []int{40}) {
		t.Fatalf("container PIDs %v", res.containerPIDs)
	}

	nginx := byName(res.items, "nginx")
	if len(nginx.Processes) != 2 || nginx.Processes[1].User != "www-data" || nginx.Processes[0].User != "root" {
		t.Fatalf("nginx processes %+v", nginx.Processes)
	}
	if !slices.Equal(nginx.Units, []string{"nginx.service"}) || !slices.Equal(nginx.RestartNeeded, []string{"/usr/lib/libssl.so.3"}) {
		t.Fatalf("nginx %+v", nginx)
	}
	ssl := originByID(res.origins, PackageOriginID(debian, tool.owners["/usr/lib/libssl.so.3"]))
	if !ssl.RunningOlderCopy || ssl.Kind != OriginPackage {
		t.Fatalf("libssl origin %+v", ssl)
	}
	if len(nginx.Origins) != 3 {
		t.Fatalf("nginx origins %v (the locale archive is not a library)", nginx.Origins)
	}

	node := byName(res.items, "node")
	if node.AppDir != "/srv/shop" || !slices.Contains(node.Origins, AppDirOriginID("/srv/shop")) {
		t.Fatalf("node %+v", node)
	}
	if len(node.Origins) != 4 { // app dir, nodejs, libc6, libnode115; sharp.so is covered by the app dir
		t.Fatalf("node origins %v", node.Origins)
	}
	if !slices.Equal(node.Processes[0].Cmdline, []string{"node", "server.js", "--token", "<redacted>"}) {
		t.Fatalf("cmdline not redacted: %q", node.Processes[0].Cmdline)
	}

	api := originByID(res.origins, BinaryOriginID(sum("go binary v1")))
	if api.Kind != OriginBinary || !slices.Equal(api.Paths, []string{"/opt/api/api"}) || api.Copy != "" {
		t.Fatalf("api origin %+v (the hash must be of what /proc/<pid>/exe reads)", api)
	}
	netty := originByID(res.origins, BinaryOriginID(sum("netty v1")))
	if netty.Copy == "" || !slices.Equal(netty.Paths, []string{"/tmp/libnetty_transport.so"}) {
		t.Fatalf("netty origin %+v", netty)
	}
	if rn := byName(res.items, "api").RestartNeeded; len(rn) != 0 {
		t.Fatalf("api restartNeeded %v: no newer netty file exists, so a restart changes nothing", rn)
	}
	old := originByID(res.origins, BinaryOriginID(sum("go binary v0")))
	if old.Copy != filepath.Join(cache, "replaced", sum("go binary v0")) {
		t.Fatalf("old origin %+v", old)
	}
	if data, err := os.ReadFile(old.Copy); err != nil || string(data) != "go binary v0" {
		t.Fatalf("copy %q %v", data, err)
	}
	if !slices.Equal(byName(res.items, "old").RestartNeeded, []string{"/opt/api/old"}) {
		t.Fatal("old must need a restart: a newer file is in place")
	}

	sshd := byName(res.items, "sshd")
	if len(sshd.Processes) != 2 || len(sshd.Origins) != 1 || originByID(res.origins, sshd.Origins[0]).Name != "openssh-server" {
		t.Fatalf("sshd %+v: the chrooted child runs the host's sshd", sshd)
	}
	for _, it := range res.items {
		if it.Name != "bash" {
			continue
		}
		o := originByID(res.origins, it.Origins[0])
		switch it.Processes[0].PID {
		case 60:
			if len(it.Processes) != 1 || len(it.Origins) != 1 || o.Kind != OriginUnresolved || !strings.Contains(o.Reason, "another root") {
				t.Errorf("bash in another root: %+v %+v", it, o)
			}
		case 63:
			if len(it.Processes) != 1 || o.Kind != OriginPackage || o.Name != "bash" {
				t.Errorf("host bash: %+v %+v", it, o)
			}
		default:
			t.Errorf("unexpected bash item %+v", it)
		}
	}
	for name, reason := range map[string]string{"lxd": "snap", "secret-daemon": "cannot be read"} {
		it := byName(res.items, name)
		o := originByID(res.origins, it.Origins[0])
		if len(it.Origins) != 1 || o.Kind != OriginUnresolved || !strings.Contains(o.Reason, reason) {
			t.Errorf("%s: %+v %+v", name, it, o)
		}
	}
	py := byName(res.items, "python3.12")
	if !slices.Equal(py.Notes, []string{problem.AppDirNotFound}) || slices.Contains(py.Origins, AppDirOriginID("/")) {
		t.Fatalf("python %+v", py)
	}

	libcCount := 0
	for _, o := range res.origins {
		if o.Name == "libc6" {
			libcCount++
		}
	}
	if libcCount != 1 {
		t.Fatalf("libc6 must be one shared origin, found %d", libcCount)
	}
}

func TestProcessCollectorWithoutPackageTool(t *testing.T) {
	c := &processCollector{src: fakeSource{10: hostProcesses()[10]}, root: hostRoot(t), distro: debian, cacheDir: t.TempDir()}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range res.origins {
		if o.Kind != OriginUnresolved || !strings.Contains(o.Reason, "package tool failed") {
			t.Fatalf("origin %+v", o)
		}
	}
}

func TestProcessCollectorOwnersError(t *testing.T) {
	tool := fakeTool{typ: "deb", ownersErr: errors.New("database locked")}
	c := &processCollector{src: fakeSource{10: hostProcesses()[10]}, root: hostRoot(t), resolver: &pkgtool.Resolver{Tool: tool}, distro: debian, cacheDir: t.TempDir()}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.problems) != 1 || res.problems[0].Code != problem.PackageToolFailed {
		t.Fatalf("problems %+v", res.problems)
	}
	for _, o := range res.origins {
		if o.Kind != OriginUnresolved {
			t.Fatalf("origin %+v", o)
		}
	}
}

func TestProcessCollectorRefusesUnsafeFiles(t *testing.T) {
	cases := map[string]struct {
		mutate func(p *fakeProc, cancel context.CancelFunc)
		cap    int64                                // lowers runningFileCap
		space  func(string) (uint64, uint64, error) // free and total bytes of the cache file system
		reason string
	}{
		"not a regular file": {mutate: func(p *fakeProc, _ context.CancelFunc) {
			p.openErr = &fs.PathError{Op: "open", Path: "/proc/30/exe", Err: procfs.ErrNotRegular}
		}, reason: "not a regular file"},
		"larger than the cap":           {cap: 8, reason: "larger than"},
		"grows past the cap while read": {mutate: func(p *fakeProc, _ context.CancelFunc) { p.size = 4 }, cap: 8, reason: "larger than"},
		"cache file system too full": {mutate: func(p *fakeProc, _ context.CancelFunc) { p.deleted = true },
			space: func(string) (uint64, uint64, error) { return 110, 1000, nil }, reason: "less than 10%"},
		"interrupted": {mutate: func(p *fakeProc, cancel context.CancelFunc) {
			p.exeData, p.onRead = strings.Repeat("x", 1<<20), cancel
		}, reason: "canceled"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.cap != 0 {
				old := runningFileCap
				runningFileCap = tc.cap
				t.Cleanup(func() { runningFileCap = old })
			}
			if tc.space != nil {
				old := cacheSpace
				cacheSpace = tc.space
				t.Cleanup(func() { cacheSpace = old })
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &fakeProc{cmdline: []string{"/opt/api/api"}, exe: "/opt/api/api", exeData: "go binary v1"}
			if tc.mutate != nil {
				tc.mutate(p, cancel)
			}
			cache := t.TempDir()
			c := &processCollector{src: fakeSource{30: p}, root: hostRoot(t), resolver: &pkgtool.Resolver{Tool: hostTool()}, distro: debian, cacheDir: cache}
			res, err := c.collect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			it := byName(res.items, "api")
			if len(it.Origins) != 1 {
				t.Fatalf("origins %v", it.Origins)
			}
			o := originByID(res.origins, it.Origins[0])
			if o.Kind != OriginUnresolved || !strings.Contains(o.Reason, tc.reason) || !slices.Equal(o.Paths, []string{"/opt/api/api"}) {
				t.Fatalf("origin %+v, want unresolved because %q", o, tc.reason)
			}
			if entries, _ := os.ReadDir(filepath.Join(cache, "replaced")); len(entries) != 0 {
				t.Fatalf("cache holds %v", entries)
			}
		})
	}
}

func TestProcessCollectorPrunesCache(t *testing.T) {
	cache := t.TempDir()
	dir := filepath.Join(cache, "replaced")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{sum("an old binary"), ".copy-123"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := fakeSource{31: hostProcesses()[31]}
	c := &processCollector{src: src, root: hostRoot(t), resolver: &pkgtool.Resolver{Tool: hostTool()}, distro: debian, cacheDir: cache}
	if _, err := c.collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	var names []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{sum("go binary v0")}) {
		t.Fatalf("cache %v, want only this run's copy", names)
	}
}

func TestProcessCollectorCapsLibraries(t *testing.T) {
	oldProcess, oldRun := processLibraryCap, runLibraryCap
	processLibraryCap, runLibraryCap = 2, 3
	t.Cleanup(func() { processLibraryCap, runLibraryCap = oldProcess, oldRun })
	libs := func(names ...string) []procfs.Mapping {
		var maps []procfs.Mapping
		for _, n := range names {
			maps = append(maps, procfs.Mapping{Path: "/usr/lib/" + n + ".so"})
		}
		return maps
	}
	src := fakeSource{
		10: {cmdline: []string{"many"}, exe: "/usr/bin/many", maps: libs("a", "b", "c")},
		11: {cmdline: []string{"late"}, exe: "/usr/bin/late", maps: libs("d", "e")},
		12: {cmdline: []string{"few"}, exe: "/usr/bin/few", maps: libs("a", "b")},
	}
	var asked []string
	tool := fakeTool{typ: "deb", owners: map[string]pkgtool.Package{}, asked: &asked}
	for _, n := range []string{"many", "late", "few"} {
		tool.owners["/usr/bin/"+n] = pkgtool.Package{Name: n, Version: "1", Type: "deb"}
	}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		tool.owners["/usr/lib/"+n+".so"] = pkgtool.Package{Name: "lib" + n, Version: "1", Type: "deb"}
	}
	c := &processCollector{src: src, root: hostRoot(t), resolver: &pkgtool.Resolver{Tool: tool}, distro: debian, cacheDir: t.TempDir()}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(asked)
	if want := []string{"/usr/bin/few", "/usr/bin/late", "/usr/bin/many", "/usr/lib/a.so", "/usr/lib/b.so", "/usr/lib/d.so"}; !slices.Equal(asked, want) {
		t.Fatalf("asked the package tool about %q, want %q", asked, want)
	}
	for name, reason := range map[string]string{"many": "more than 2 shared libraries", "late": "3 shared libraries", "few": ""} {
		it := byName(res.items, name)
		var unresolved []string
		for _, id := range it.Origins {
			if o := originByID(res.origins, id); o.Kind == OriginUnresolved {
				unresolved = append(unresolved, o.Reason)
			}
		}
		switch {
		case reason == "" && len(unresolved) != 0:
			t.Errorf("%s: unresolved %q", name, unresolved)
		case reason != "" && (len(unresolved) != 1 || !strings.Contains(unresolved[0], reason)):
			t.Errorf("%s: unresolved %q, want one about %q", name, unresolved, reason)
		}
	}
}

func TestProcessCollectorKeysFilesByIdentity(t *testing.T) {
	replaced := procfs.FileID{Dev: 1, Ino: 300}
	src := fakeSource{
		// A user's process with a decoy bind-mounted over /opt/api/api in its own mount namespace.
		5: {cmdline: []string{"/opt/api/api"}, exe: "/opt/api/api", uid: 1001, exeID: procfs.FileID{Dev: 1, Ino: 200}, exeData: "decoy"},
		9: {cmdline: []string{"/opt/api/api"}, exe: "/opt/api/api", exeID: procfs.FileID{Dev: 1, Ino: 100}, exeData: "vulnerable v1"},
		// Two workers of one replaced binary.
		20: {cmdline: []string{"/opt/api/old"}, exe: "/opt/api/old", deleted: true, exeID: replaced, exeData: "go binary v0"},
		21: {cmdline: []string{"/opt/api/old"}, exe: "/opt/api/old", deleted: true, exeID: replaced, exeData: "go binary v0"},
	}
	cache := t.TempDir()
	c := &processCollector{src: src, root: hostRoot(t), resolver: &pkgtool.Resolver{Tool: hostTool()}, distro: debian, cacheDir: cache}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{BinaryOriginID(sum("decoy")), BinaryOriginID(sum("vulnerable v1"))}
	slices.Sort(want)
	if got := byName(res.items, "api").Origins; !slices.Equal(got, want) {
		t.Fatalf("api origins %v, want both running files %v", got, want)
	}
	if got := byName(res.items, "old").Origins; !slices.Equal(got, []string{BinaryOriginID(sum("go binary v0"))}) {
		t.Fatalf("old origins %v", got)
	}
	if n := src[20].read + src[21].read; n != len("go binary v0") {
		t.Fatalf("read %d bytes of the replaced binary, want one read", n)
	}
	if entries, _ := os.ReadDir(filepath.Join(cache, "replaced")); len(entries) != 1 {
		t.Fatalf("cache holds %v, want one copy", entries)
	}
}

func TestProcessCollectorRestartForReplacedLibraryInAppDir(t *testing.T) {
	lib := "/srv/api/.venv/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
	root := files(t, map[string]string{"srv/api/requirements.txt": "", "srv/api/app.py": "", lib[1:]: "42.0.5"})
	src := fakeSource{7: {cmdline: []string{"python3", "app.py"}, exe: "/usr/bin/python3.12", cwd: "/srv/api",
		maps: []procfs.Mapping{{Start: "1", End: "2", Path: lib, Deleted: true}}}} // pip install -U ran
	c := &processCollector{src: src, root: root, resolver: &pkgtool.Resolver{Tool: hostTool()}, distro: debian, cacheDir: t.TempDir()}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	it := byName(res.items, "python3.12")
	if it.AppDir != "/srv/api" || !slices.Equal(it.RestartNeeded, []string{lib}) {
		t.Fatalf("appDir %q restartNeeded %v: the workers run the old %s", it.AppDir, it.RestartNeeded, filepath.Base(lib))
	}
}

func TestProcessCollectorIgnoresProcessesThatEnd(t *testing.T) {
	src := fakeSource{
		// Its PID was reused after the process list was read: the files are another process's.
		30: {cmdline: []string{"/opt/api/api"}, exe: "/opt/api/api", exeData: "another process's file", reused: true,
			maps:    []procfs.Mapping{{Start: "5", End: "6", Path: "/tmp/libnetty_transport.so"}},
			mapData: map[string]string{"/tmp/libnetty_transport.so": "another process's library"}},
		// It exited between the reads of its command line and its executable.
		90: {cmdline: []string{"worker"}, exeErr: &fs.PathError{Op: "readlink", Path: "/proc/90/exe", Err: syscall.ENOENT}},
	}
	c := &processCollector{src: src, root: hostRoot(t), resolver: &pkgtool.Resolver{Tool: hostTool()}, distro: debian, cacheDir: t.TempDir()}
	res, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.items) != 1 || res.items[0].Name != "api" {
		t.Fatalf("items %+v: a process that ended is not an item", res.items)
	}
	if len(res.items[0].Origins) != 2 {
		t.Fatalf("api origins %v", res.items[0].Origins)
	}
	for _, id := range res.items[0].Origins {
		if o := originByID(res.origins, id); o.Kind != OriginUnresolved || !strings.Contains(o.Reason, "ended during the inventory") {
			t.Errorf("origin %+v", o)
		}
	}
	if src[30].read != 0 {
		t.Fatalf("read %d bytes of another process's files", src[30].read)
	}
}
