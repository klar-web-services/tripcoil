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
