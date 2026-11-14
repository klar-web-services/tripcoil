package inventory

import (
	"context"
	"os"
	"path/filepath"
	"sort"

	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

// Deps is everything Collect reads from the host.
type Deps struct {
	Root       string        // host root, "/" in production
	Proc       Source        // /proc
	Release    osrel.Release // /etc/os-release
	Tool       pkgtool.Tool  // nil when the distribution has no supported package tool
	DockerHost string        // DOCKER_HOST
	Connect    func(socket string) DockerAPI
	CacheDir   string // where copies of replaced running files go
	Hostname   string
	Arch       string
}

// Collect inventories the host. Only an unreadable process list is an error; everything else is
// recorded in the Inventory's problems.
func Collect(ctx context.Context, d Deps) (*Inventory, error) {
	family := d.Release.Family()
	distro := Distro{ID: d.Release.ID, VersionID: d.Release.VersionID, IDLike: d.Release.IDLike, Family: string(family)}
	inv := &Inventory{SchemaVersion: "1", Host: Host{Hostname: d.Hostname, Distro: distro, Arch: d.Arch, Init: detectInit(d.Root)}}
	var problems []problem.Problem

	var resolver *pkgtool.Resolver
	switch {
	case d.Tool == nil:
		problems = append(problems, problem.New(problem.Error, problem.PackageToolFailed, "inventory",
			"%q is not a supported distribution, so the packages of running software are unknown", d.Release.ID))
	default:
		if err := d.Tool.Check(ctx); err != nil {
			problems = append(problems, problem.New(problem.Error, problem.PackageToolFailed, "inventory",
				"the package tool does not work, so the packages of running software are unknown: %v", err))
		} else {
			resolver = &pkgtool.Resolver{Tool: d.Tool, Aliases: pkgtool.DetectAliases(d.Root)}
		}
	}

	// Without a resolver the kernel collector asks no package tool, so a failed Check is not
	// recorded twice.
	kernel, kernelOrigin, kernelProblems := kernelCollector{root: d.Root, release: d.Release, resolver: resolver, distro: distro}.collect(ctx)
	problems = append(problems, kernelProblems...)
	pc := &processCollector{src: d.Proc, root: d.Root, resolver: resolver, distro: distro, cacheDir: d.CacheDir}
	procs, err := pc.collect(ctx)
	if err != nil {
		return nil, err
	}
	problems = append(problems, procs.problems...)
	containers, containerOrigins, dockerProblems := collectDocker(ctx, d.DockerHost, d.Connect, procs.containerPIDs)
	problems = append(problems, dockerProblems...)

	inv.Items = append(append([]Item{kernel}, procs.items...), containers...)
	inv.Origins = mergeOrigins([]Origin{kernelOrigin}, procs.origins, containerOrigins)
	inv.Errors, inv.Warnings, inv.Notices = problem.Split(problems)
	return inv, nil
}

// mergeOrigins joins origin lists, keeping the first of each ID, sorted by ID.
func mergeOrigins(lists ...[]Origin) []Origin {
	seen := map[string]bool{}
	var out []Origin
	for _, l := range lists {
		for _, o := range l {
			if !seen[o.ID] {
				seen[o.ID] = true
				out = append(out, o)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func detectInit(root string) string {
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(root, p)); return err == nil }
	switch {
	case exists("run/systemd/system"):
		return "systemd"
	case exists("run/openrc"), exists("sbin/openrc-run"):
		return "openrc"
	}
	return "unknown"
}
