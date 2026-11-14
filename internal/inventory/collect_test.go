package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

type failingSource struct{ fakeSource }

func (failingSource) PIDs() ([]int, error) { return nil, errors.New("permission denied") }

func collectDeps(t *testing.T) Deps {
	root := kernelRoot(t, "6.1.0-28-amd64", debianProcVersion, "", "usr/lib/modules/6.1.0-28-amd64")
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool := hostTool()
	tool.owners["/usr/lib/modules/6.1.0-28-amd64/modules.builtin"] = deb("linux-image-6.1.0-28-amd64", "6.1.119-1")
	return Deps{
		Root:       root,
		Proc:       fakeSource{10: hostProcesses()[10]},
		Release:    osrel.Release{ID: "debian", VersionID: "12"},
		Tool:       tool,
		DockerHost: "unix:///nonexistent/docker.sock",
		Connect:    connect,
		CacheDir:   t.TempDir(),
		Hostname:   "web-1",
		Arch:       "amd64",
	}
}

func TestCollect(t *testing.T) {
	inv, err := Collect(context.Background(), collectDeps(t))
	if err != nil {
		t.Fatal(err)
	}
	if inv.SchemaVersion != "1" || !reflect.DeepEqual(inv.Host, Host{Hostname: "web-1", Distro: Distro{ID: "debian", VersionID: "12", IDLike: []string{}, Family: "debian"}, Arch: "amd64", Init: "systemd"}) {
		t.Fatalf("host %+v", inv.Host)
	}
	if len(inv.Items) != 2 || inv.Items[0].Kind != KindKernel || inv.Items[1].Name != "nginx" {
		t.Fatalf("items %+v", inv.Items)
	}
	if len(inv.Notices) != 1 || inv.Notices[0].Code != problem.DockerAbsent || len(inv.Errors) != 0 || inv.Status() != "ok" {
		t.Fatalf("problems: errors %+v notices %+v", inv.Errors, inv.Notices)
	}
	seen := map[string]bool{}
	for _, o := range inv.Origins {
		if seen[o.ID] {
			t.Fatalf("duplicate origin %s", o.ID)
		}
		seen[o.ID] = true
	}
	for _, it := range inv.Items {
		for _, id := range it.Origins {
			if !seen[id] {
				t.Fatalf("item %s refers to missing origin %s", it.ID, id)
			}
		}
	}
}

func TestCollectContainersWithoutDockerSocket(t *testing.T) {
	d := collectDeps(t)
	procs := hostProcesses()
	d.Proc = fakeSource{10: procs[10], 40: procs[40]} // 40 runs in a Docker container
	inv, err := Collect(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Errors) != 1 || inv.Errors[0].Code != problem.DockerUnavailable || len(inv.Notices) != 0 || inv.Status() != "partial" {
		t.Fatalf("errors %+v notices %+v status %s", inv.Errors, inv.Notices, inv.Status())
	}
}

func TestCollectWithoutPackageTool(t *testing.T) {
	for name, mutate := range map[string]func(*Deps){
		"unknown distribution": func(d *Deps) { d.Tool = nil; d.Release = osrel.Release{ID: "gentoo"} },
		"broken tool":          func(d *Deps) { tool := hostTool(); tool.checkErr = errors.New("no database"); d.Tool = tool },
	} {
		t.Run(name, func(t *testing.T) {
			d := collectDeps(t)
			mutate(&d)
			inv, err := Collect(context.Background(), d)
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Errors) != 1 || inv.Errors[0].Code != problem.PackageToolFailed || inv.Status() != "partial" {
				t.Fatalf("errors %+v", inv.Errors)
			}
		})
	}
}

func TestCollectKernelPackageToolFailure(t *testing.T) {
	d := collectDeps(t)
	d.Tool = failingInstalled{d.Tool.(fakeTool)}
	inv, err := Collect(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Errors) != 1 || inv.Errors[0].Code != problem.PackageToolFailed || inv.Status() != "partial" {
		t.Fatalf("errors %+v, status %s", inv.Errors, inv.Status())
	}
}

func TestCollectCannotListProcesses(t *testing.T) {
	d := collectDeps(t)
	d.Proc = failingSource{}
	if _, err := Collect(context.Background(), d); err == nil {
		t.Fatal("an unreadable /proc must be an error")
	}
}

func TestCollectContainersOfARunningDockerd(t *testing.T) {
	d := collectDeps(t)
	d.DockerHost = "unix://" + dockerServer(t, engine(http.StatusOK))
	d.Proc = fakeSource{
		10:   hostProcesses()[10],
		15:   {cmdline: []string{"/usr/bin/dockerd", "-H", "fd://"}, exe: "/usr/bin/dockerd", exeData: "dockerd", cgroup: cg("/system.slice/docker.service")},
		2201: {cmdline: []string{"node", "server.js"}, exe: "/usr/local/bin/node", cgroup: cg("/system.slice/docker-" + shopID + ".scope")},
	}
	inv, err := Collect(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if it := inv.Items[len(inv.Items)-1]; it.Kind != KindContainer || it.Name != "shop-web-1" || len(inv.Errors) != 0 || len(inv.Notices) != 0 {
		t.Fatalf("items %+v errors %+v notices %+v", inv.Items, inv.Errors, inv.Notices)
	}
}

func TestCollectJSONLikeTheSpec(t *testing.T) {
	inv, err := Collect(context.Background(), collectDeps(t))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Host struct {
			Distro map[string]json.RawMessage `json:"distro"`
		} `json:"host"`
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if got := string(out.Host.Distro["idLike"]); got != "[]" {
		t.Fatalf("idLike %q, want []", got)
	}
	for _, it := range out.Items {
		got, ok := it["rebootPending"]
		switch kind := string(it["kind"]); kind {
		case `"kernel"`:
			if string(got) != "false" {
				t.Fatalf("kernel rebootPending %s (present: %v), want false", got, ok)
			}
		default:
			if ok {
				t.Fatalf("%s item has rebootPending %q", kind, got)
			}
		}
	}
}

func TestCollectInterrupted(t *testing.T) {
	// Ctrl-C kills the package tool and ends the Docker requests; run.json records INTERRUPTED.
	interrupted := fmt.Errorf("cannot run dpkg-query: %w", context.Canceled)
	newerKernel := map[string][]pkgtool.Package{"linux-image-*": {deb("linux-image-6.1.0-31-amd64", "6.1.128-1")}}
	for name, mutate := range map[string]func(*Deps, *fakeTool){
		"check":     func(_ *Deps, tool *fakeTool) { tool.checkErr = interrupted },
		"owners":    func(_ *Deps, tool *fakeTool) { tool.ownersErr = interrupted },
		"installed": func(_ *Deps, tool *fakeTool) { tool.installedErr = interrupted },
		"compare":   func(_ *Deps, tool *fakeTool) { tool.installed, tool.compareErr = newerKernel, interrupted },
		"docker": func(d *Deps, _ *fakeTool) {
			d.DockerHost = "unix://" + dockerServer(t, engine(http.StatusOK))
			d.Proc = fakeSource{15: {cmdline: []string{"/usr/bin/dockerd"}, exe: "/usr/bin/dockerd", cgroup: cg("/system.slice/docker.service")}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := collectDeps(t)
			tool := d.Tool.(fakeTool)
			mutate(&d, &tool)
			d.Tool = tool
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			inv, err := Collect(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Errors) != 0 {
				t.Fatalf("errors %+v: the interruption caused them", inv.Errors)
			}
		})
	}
	// A timeout of the tool itself, in a run that goes on, is a failure.
	d := collectDeps(t)
	tool := d.Tool.(fakeTool)
	tool.ownersErr = fmt.Errorf("cannot run dpkg-query: %w", context.DeadlineExceeded)
	d.Tool = tool
	inv, err := Collect(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Errors) != 2 || inv.Errors[0].Code != problem.PackageToolFailed {
		t.Fatalf("errors %+v", inv.Errors)
	}
}

func TestCollectDockerInsideOtherContainers(t *testing.T) {
	d := collectDeps(t)
	nested := func(cgroup string) *fakeProc {
		return &fakeProc{cmdline: []string{"nginx"}, exe: "/usr/sbin/nginx", otherRoot: true, cgroup: cg(cgroup + "/system.slice/docker-" + containerID + ".scope")}
	}
	d.Proc = fakeSource{
		10: hostProcesses()[10],
		20: nested("/lxc.payload.c1"),                                   // LXD, Incus
		21: nested("/lxc/101/ns"),                                       // Proxmox
		22: nested("/machine.slice/systemd-nspawn@box.service/payload"), // systemd-nspawn
	}
	inv, err := Collect(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Errors) != 0 || inv.Status() != "ok" {
		t.Fatalf("errors %+v: their Docker is not the host's", inv.Errors)
	}
	unresolved := 0
	for _, it := range inv.Items {
		for _, p := range it.Processes {
			if p.PID < 20 {
				continue
			}
			unresolved++
			if o := originByID(inv.Origins, it.Origins[0]); len(it.Origins) != 1 || o.Kind != OriginUnresolved || !strings.Contains(o.Reason, "another root") {
				t.Errorf("process %d: item %+v origin %+v", p.PID, it, o)
			}
		}
	}
	if unresolved != 3 {
		t.Fatalf("%d of the nested processes are host process items, want 3", unresolved)
	}
}
