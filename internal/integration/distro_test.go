//go:build integration

// Package integration runs Tripcoil against real distributions and the real host.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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

// isSleep600 matches exactly "sleep 600". Rocky's multicall coreutils shows it as
// "/usr/bin/coreutils --coreutils-prog-shebang=sleep /usr/bin/sleep 600".
func isSleep600(cmdline []string) bool {
	if len(cmdline) == 4 {
		if filepath.Base(cmdline[0]) != "coreutils" || cmdline[1] != "--coreutils-prog-shebang=sleep" {
			return false
		}
		cmdline = cmdline[2:]
	}
	return len(cmdline) == 2 && filepath.Base(cmdline[0]) == "sleep" && cmdline[1] == "600"
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
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-v", bin+":/usr/local/bin/tripcoil:ro", tc.image, "sh", "-c", script)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			out := stdout.Bytes()
			var inv inventory.Inventory
			if err := json.Unmarshal(out, &inv); err != nil {
				t.Fatalf("no inventory.json (run: %v): %v\nstdout: %s\nstderr: %s", runErr, err, out, stderr.Bytes())
			}
			if runErr != nil {
				t.Fatalf("tripcoil run failed: %v; errors %+v\nstderr: %s", runErr, inv.Errors, stderr.Bytes())
			}
			if len(inv.Items) == 0 || inv.Items[0].Kind != inventory.KindKernel || inv.Items[0].Release == "" {
				t.Fatalf("first item is not a kernel item with a release: %+v", inv.Items)
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
					if it.Exe == tc.sleepExe && isSleep600(p.Cmdline) {
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
				sleepPkg = sleepPkg || o.Name == tc.sleepPkg || o.Name == tc.sleepPkg+"-single"
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
