//go:build integration

// Package integration runs Tripcoil against real distributions and the real host.
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tripcoil")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/klar-web-services/tripcoil/cmd/tripcoil")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func TestDistros(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	bin := buildBinary(t)
	cases := []struct{ image, family, pkgType, sleepExe, sleepPkg, libc string }{
		{"debian:12", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6"},
		{"debian:13", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6"},
		{"ubuntu:24.04", "ubuntu", "deb", "/usr/bin/sleep", "coreutils", "libc6"},
		// Rocky's coreutils-single is one multicall binary: sleep runs as /usr/bin/coreutils.
		{"rockylinux/rockylinux:9", "rhel", "rpm", "/usr/bin/coreutils", "coreutils", "glibc"},
		{"alpine:3.21", "alpine", "apk", "/bin/busybox", "busybox", "musl"},
		{"archlinux:latest", "arch", "alpm", "/usr/bin/sleep", "coreutils", "glibc"},
	}
	for _, tc := range cases {
		t.Run(tc.image, func(t *testing.T) {
			script := "sleep 600 & sleep 1; /usr/local/bin/tripcoil run >/tmp/run.out 2>&1; code=$?; " +
				"cat /var/lib/tripcoil/runs/latest/inventory.json || cat /tmp/run.out; exit $code"
			out, runErr := exec.Command("docker", "run", "--rm", "-v", bin+":/usr/local/bin/tripcoil:ro", tc.image, "sh", "-c", script).Output()
			var inv inventory.Inventory
			if err := json.Unmarshal(out, &inv); err != nil {
				t.Fatalf("no inventory.json (run: %v): %v\n%s", runErr, err, out)
			}
			if runErr != nil {
				t.Fatalf("tripcoil run failed: %v; errors %+v", runErr, inv.Errors)
			}
			if inv.Host.Distro.Family != tc.family {
				t.Fatalf("family %q, want %q", inv.Host.Distro.Family, tc.family)
			}
			origins := map[string]inventory.Origin{}
			for _, o := range inv.Origins {
				origins[o.ID] = o
			}
			var sleep *inventory.Item
			for i := range inv.Items {
				it := &inv.Items[i]
				for _, p := range it.Processes {
					if it.Exe == tc.sleepExe && strings.Contains(strings.Join(p.Cmdline, " "), "sleep 600") {
						sleep = it
					}
				}
			}
			if sleep == nil {
				t.Fatalf("no item runs sleep from %s: %+v", tc.sleepExe, inv.Items)
			}
			var sleepPkg, libc bool
			for _, id := range sleep.Origins {
				o := origins[id]
				if o.Kind != inventory.OriginPackage || o.Type != tc.pkgType {
					continue
				}
				sleepPkg = sleepPkg || strings.HasPrefix(o.Name, tc.sleepPkg)
				libc = libc || o.Name == tc.libc
			}
			if !sleepPkg || !libc {
				t.Fatalf("sleep's origins miss %s or %s: %v", tc.sleepPkg, tc.libc, sleep.Origins)
			}
			self := false
			for _, it := range inv.Items {
				for _, id := range it.Origins {
					self = self || (it.Exe == "/usr/local/bin/tripcoil" && origins[id].Kind == inventory.OriginBinary)
				}
			}
			if !self {
				t.Fatal("tripcoil itself must show up as an unpackaged binary")
			}
		})
	}
}
