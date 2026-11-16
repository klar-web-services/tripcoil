//go:build live

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

// TestLiveHost inventories and audits the machine it runs on, with the pinned Grype and today's
// vulnerability data (it downloads both into a temporary cache). Run it as root:
//
//	go test -c -tags live -o live.test ./internal/integration/ && sudo ./live.test -test.v -test.run TestLiveHost
func TestLiveHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	rel, err := osrel.Read("/")
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	inv, err := inventory.Collect(context.Background(), inventory.Deps{
		Root: "/", Proc: procfs.FS{Root: "/"}, Release: rel,
		Tool:       pkgtool.New(rel.Family().PackageType(), pkgtool.Exec),
		DockerHost: os.Getenv("DOCKER_HOST"),
		Connect:    func(s string) inventory.DockerAPI { return dockerapi.New(s) },
		CacheDir:   cache, Hostname: "live", Arch: runtime.GOARCH,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Errors) != 0 {
		t.Fatalf("errors on a healthy host: %+v", inv.Errors)
	}
	kernel := inv.Items[0]
	if kernel.Kind != inventory.KindKernel || kernel.UpstreamVersion == "" || len(kernel.Origins) == 0 {
		t.Fatalf("kernel %+v", kernel)
	}
	packaged, unresolved := 0, 0
	kinds := map[string]string{}
	for _, o := range inv.Origins {
		kinds[o.ID] = o.Kind
		if o.Kind == inventory.OriginUnresolved {
			unresolved++
		}
	}
	for _, it := range inv.Items {
		for _, id := range it.Origins {
			if it.Kind == inventory.KindProcess && kinds[id] == inventory.OriginPackage {
				packaged++
				break
			}
		}
	}
	if packaged == 0 {
		t.Fatal("no process item has a package origin")
	}
	t.Logf("%s (%s): %d items, %d origins, %d process items with packages, %d unresolved origins, notices %+v",
		rel.ID, inv.Host.Distro.Family, len(inv.Items), len(inv.Origins), packaged, unresolved, inv.Notices)
	t.Logf("kernel %s running %s upstream %s reboot %v %v", kernel.Release, kernel.RunningVersion, kernel.UpstreamVersion, *kernel.RebootPending, kernel.RebootReasons)

	a := audit.Run(context.Background(), audit.Deps{Root: "/", CacheDir: cache, RunDir: t.TempDir(), Family: rel.Family(),
		MaxAge: 48 * time.Hour, Now: time.Now, Grype: audit.NewGrype(cache), Kernel: kernelcna.NewSource(cache), Proc: procfs.FS{Root: "/"}}, inv)
	if a.Status != audit.Complete {
		t.Fatalf("audit %s on a healthy host: %+v", a.Status, a.Errors)
	}
	statuses := map[string]int{}
	tiers := map[string]int{}
	for _, o := range a.Origins {
		statuses[o.Kind+" "+o.Status]++
		if o.ID == kernel.Origins[0] && o.Status != audit.Scanned {
			t.Fatalf("kernel origin %+v", o)
		}
		// Without the distribution, every package origin is unidentified and nothing matches. A
		// single binary may carry an operating system package without a distribution.
		if o.Kind == inventory.OriginPackage && strings.Contains(o.Reason, "did not recognise the distribution") {
			t.Fatalf("origin %+v", o)
		}
	}
	if statuses[inventory.OriginPackage+" "+audit.Scanned] == 0 {
		t.Fatalf("no package origin was scanned: %v", statuses)
	}
	for _, f := range a.Findings {
		tiers[f.Risk]++
	}
	t.Logf("audit: %d findings %v; origins %v; database built %s", len(a.Findings), tiers, statuses, a.Grype.DBBuilt)

	// The facts of a healthy host: everything but sshd.txt (when sshd is not installed) is collected.
	fd := facts.Deps{Root: "/", Run: facts.Exec, LookPath: facts.LookPath}
	if socket, err := dockerapi.Socket(os.Getenv("DOCKER_HOST")); err == nil {
		fd.Docker, fd.DockerSocket = dockerapi.New(socket), socket
	}
	runDir := t.TempDir()
	idx, err := facts.Collect(context.Background(), fd, inv, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Missing) != 0 || len(idx.Collected) < 6 {
		t.Fatalf("facts on a healthy host: %+v", idx)
	}
	data, _ := os.ReadFile(filepath.Join(runDir, "facts", "network.json"))
	var net facts.Network
	if err := json.Unmarshal(data, &net); err != nil {
		t.Fatal(err)
	}
	mapped := 0
	for _, s := range net.Sockets {
		if len(s.Items) > 0 {
			mapped++
		}
	}
	t.Logf("facts: %v, notes %v; %d sockets, %d mapped to items", idx.Collected, idx.Notes, len(net.Sockets), mapped)
}
