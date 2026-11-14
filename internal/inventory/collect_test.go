package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/osrel"
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
	if inv.SchemaVersion != "1" || !reflect.DeepEqual(inv.Host, Host{Hostname: "web-1", Distro: Distro{ID: "debian", VersionID: "12", Family: "debian"}, Arch: "amd64", Init: "systemd"}) {
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
